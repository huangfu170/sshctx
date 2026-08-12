//! MCP-facing request schemas and implementations.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sshctx_budget::{Page, paginate};
use sshctx_protocol::Frame;
use sshctx_ssh::RemoteBackend;
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
pub struct ToolService {
    pool: Arc<dyn RemoteBackend>,
}
impl ToolService {
    pub fn new(pool: Arc<dyn RemoteBackend>) -> Self {
        Self { pool }
    }
    pub async fn hosts(&self) -> Result<Vec<String>> {
        self.pool.aliases().await
    }
    async fn request(
        &self,
        host: &str,
        method: &str,
        params: Value,
        payload: Bytes,
        readonly: bool,
    ) -> Result<Frame<sshctx_protocol::Response>> {
        let response = self
            .pool
            .call(host, method, params, payload, readonly)
            .await?;
        if !response.header.ok {
            bail!(
                response
                    .header
                    .error
                    .unwrap_or_else(|| "remote operation failed".into())
            );
        }
        Ok(response)
    }
    async fn text(&self, host: &str, method: &str, params: Value, page: &Page) -> Result<String> {
        let response = self
            .request(host, method, params, Bytes::new(), true)
            .await?;
        let text = if response.payload.is_empty() {
            serde_json::to_string_pretty(&response.header.result)?
        } else {
            String::from_utf8_lossy(&response.payload).into_owned()
        };
        Ok(paginate(&text, page))
    }
    pub async fn stat(&self, request: PathRequest) -> Result<String> {
        self.text(
            &request.host,
            "stat",
            json!({"path":request.path}),
            &Page::default(),
        )
        .await
    }
    pub async fn read(&self, request: ReadRequest) -> Result<String> {
        self.text(&request.host, "read", json!({"path":request.path,"byte_offset":request.byte_offset,"byte_limit":request.byte_limit}), &request.page).await
    }
    pub async fn grep(&self, request: GrepRequest) -> Result<String> {
        self.text(
            &request.host,
            "grep",
            serde_json::to_value(&request)?,
            &request.page,
        )
        .await
    }
    pub async fn glob(&self, request: GlobRequest) -> Result<String> {
        self.text(
            &request.host,
            "glob",
            serde_json::to_value(&request)?,
            &request.page,
        )
        .await
    }
    pub async fn gpu_status(&self, request: HostPageRequest) -> Result<String> {
        self.text(&request.host, "gpu_status", json!({}), &request.page)
            .await
    }
    pub async fn processes(&self, request: ProcessesRequest) -> Result<String> {
        self.text(
            &request.host,
            "processes",
            json!({"pattern":request.pattern}),
            &request.page,
        )
        .await
    }
    pub async fn job_output(&self, request: JobOutputRequest) -> Result<String> {
        self.text(
            &request.host,
            "job_output",
            serde_json::to_value(&request)?,
            &request.page,
        )
        .await
    }
    pub async fn query(&self, request: QueryRequest) -> Result<String> {
        self.text(
            &request.host,
            "query",
            json!({"operations":request.operations}),
            &request.page,
        )
        .await
    }
    pub async fn exec(&self, request: ExecRequest) -> Result<String> {
        self.text_mutating(
            &request.host,
            "exec",
            serde_json::to_value(&request)?,
            &request.page,
        )
        .await
    }
    pub async fn job_start(&self, request: JobStartRequest) -> Result<String> {
        self.text_mutating(
            &request.host,
            "job_start",
            serde_json::to_value(&request)?,
            &Page::default(),
        )
        .await
    }
    pub async fn job_kill(&self, request: JobKillRequest) -> Result<String> {
        self.text_mutating(
            &request.host,
            "job_kill",
            serde_json::to_value(&request)?,
            &Page::default(),
        )
        .await
    }
    async fn text_mutating(
        &self,
        host: &str,
        method: &str,
        params: Value,
        page: &Page,
    ) -> Result<String> {
        let response = self
            .request(host, method, params, Bytes::new(), false)
            .await?;
        Ok(paginate(
            &serde_json::to_string_pretty(&response.header.result)?,
            page,
        ))
    }

    pub async fn sync_push(&self, request: SyncPushRequest) -> Result<String> {
        if request.delete {
            bail!(
                "delete=true is intentionally not accepted by the v0.1 MCP surface; reconcile deletions explicitly"
            );
        }
        let local = tokio::fs::canonicalize(&request.local_path)
            .await
            .context("canonicalize local_path")?;
        let manifest = self
            .request(
                &request.host,
                "manifest",
                json!({"path":request.remote_path}),
                Bytes::new(),
                true,
            )
            .await?;
        let remote_entries = manifest
            .header
            .result
            .get("entries")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let files = collect_local_files(&local, &request.exclude)?;
        let mut changed = 0usize;
        let mut unchanged = 0usize;
        let mut bytes = 0usize;
        for file in files {
            let relative = file
                .strip_prefix(&local)?
                .to_string_lossy()
                .replace('\\', "/");
            let content = tokio::fs::read(&file).await?;
            let hash = hex_sha256(&content);
            if remote_entries
                .get(&relative)
                .and_then(|v| v.get("sha256"))
                .and_then(Value::as_str)
                == Some(&hash)
            {
                unchanged += 1;
                continue;
            }
            let remote = format!("{}/{}", request.remote_path.trim_end_matches('/'), relative);
            self.request(
                &request.host,
                "write_atomic",
                json!({"path":remote,"sha256":hash}),
                Bytes::from(content.clone()),
                false,
            )
            .await?;
            changed += 1;
            bytes += content.len();
        }
        Ok(format!(
            "changed_files={changed}\nunchanged_files={unchanged}\ntransferred_bytes={bytes}\n(Complete: sync push finished; no remote files deleted.)"
        ))
    }

    pub async fn sync_pull(&self, request: SyncPullRequest) -> Result<String> {
        let local = PathBuf::from(&request.local_path);
        tokio::fs::create_dir_all(&local).await?;
        let canonical = tokio::fs::canonicalize(&local).await?;
        let manifest = self
            .request(
                &request.host,
                "manifest",
                json!({"path":request.remote_path}),
                Bytes::new(),
                true,
            )
            .await?;
        let entries = manifest
            .header
            .result
            .get("entries")
            .and_then(Value::as_object)
            .context("invalid manifest")?;
        let mut count = 0usize;
        let mut bytes = 0usize;
        for relative in entries.keys() {
            let destination = safe_local_join(&canonical, relative)?;
            if let Some(parent) = destination.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let remote = format!("{}/{}", request.remote_path.trim_end_matches('/'), relative);
            let response = self
                .request(
                    &request.host,
                    "read",
                    json!({"path":remote,"byte_limit":sshctx_protocol::MAX_PAYLOAD}),
                    Bytes::new(),
                    true,
                )
                .await?;
            let temp = destination.with_extension("sshctx-part");
            tokio::fs::write(&temp, &response.payload).await?;
            tokio::fs::rename(&temp, &destination).await?;
            count += 1;
            bytes += response.payload.len();
        }
        Ok(format!(
            "files={count}\ntransferred_bytes={bytes}\n(Complete: sync pull finished.)"
        ))
    }

    pub async fn transfer(&self, request: TransferRequest) -> Result<String> {
        let source_stat = self
            .request(
                &request.source_host,
                "stat",
                json!({"path":request.source_path}),
                Bytes::new(),
                true,
            )
            .await?;
        let size = source_stat
            .header
            .result
            .get("size")
            .and_then(Value::as_u64)
            .context("source size unavailable")?;
        let mut offset = 0_u64;
        let mut hasher = Sha256::new();
        while offset < size {
            let read = self.request(&request.source_host, "read", json!({"path":request.source_path,"byte_offset":offset,"byte_limit":8*1024*1024}), Bytes::new(), true).await?;
            if read.payload.is_empty() {
                bail!("source ended before advertised size");
            }
            hasher.update(&read.payload);
            self.request(
                &request.destination_host,
                "write_chunk",
                json!({"path":request.destination_path,"offset":offset}),
                read.payload.clone(),
                false,
            )
            .await?;
            offset += read.payload.len() as u64;
        }
        let hash = format!("{:x}", hasher.finalize());
        self.request(
            &request.destination_host,
            "commit_chunks",
            json!({"path":request.destination_path,"sha256":hash}),
            Bytes::new(),
            false,
        )
        .await?;
        Ok(format!(
            "transferred_bytes={size}\nsha256={hash}\n(Complete: host-to-host transfer verified.)"
        ))
    }

    pub async fn agent_update(&self, request: HostRequest) -> Result<String> {
        self.pool.reconnect(&request.host).await?;
        let response = self
            .request(&request.host, "ping", json!({}), Bytes::new(), false)
            .await?;
        Ok(paginate(
            &serde_json::to_string_pretty(&response.header.result)?,
            &Page::default(),
        ))
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn safe_local_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("unsafe manifest path");
    }
    Ok(root.join(relative))
}
fn collect_local_files(root: &Path, additional: &[String]) -> Result<Vec<PathBuf>> {
    let defaults: HashSet<&str> = [
        ".git",
        "models",
        "data",
        "outputs",
        "logs",
        "target",
        "__pycache__",
    ]
    .into_iter()
    .collect();
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .parents(true)
        .add_custom_ignore_filename(".sshctxignore");
    let mut files = Vec::new();
    for entry in builder.build() {
        let entry = entry?;
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        if relative.split('/').any(|p| defaults.contains(p))
            || additional
                .iter()
                .any(|p| relative.starts_with(p.trim_end_matches('/')))
        {
            continue;
        }
        files.push(entry.into_path());
    }
    files.sort();
    Ok(files)
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct HostRequest {
    pub host: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct HostPageRequest {
    pub host: String,
    #[serde(flatten)]
    pub page: Page,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct PathRequest {
    pub host: String,
    pub path: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ReadRequest {
    pub host: String,
    pub path: String,
    pub byte_offset: Option<u64>,
    pub byte_limit: Option<usize>,
    #[serde(flatten)]
    pub page: Page,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct GrepRequest {
    pub host: String,
    pub path: String,
    pub pattern: String,
    pub case_insensitive: Option<bool>,
    pub encoding: Option<String>,
    pub match_limit: Option<usize>,
    #[serde(flatten)]
    pub page: Page,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct GlobRequest {
    pub host: String,
    pub path: String,
    pub pattern: String,
    pub match_limit: Option<usize>,
    #[serde(flatten)]
    pub page: Page,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProcessesRequest {
    pub host: String,
    pub pattern: Option<String>,
    #[serde(flatten)]
    pub page: Page,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct JobOutputRequest {
    pub host: String,
    pub job_id: String,
    pub offset: Option<u64>,
    pub limit: Option<usize>,
    #[serde(flatten)]
    pub page: Page,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct QueryOperation {
    pub method: String,
    #[serde(default)]
    pub params: Value,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct QueryRequest {
    pub host: String,
    pub operations: Vec<QueryOperation>,
    #[serde(flatten)]
    pub page: Page,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExecRequest {
    pub host: String,
    pub cwd: String,
    pub argv: Option<Vec<String>>,
    pub command: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub timeout_ms: Option<u64>,
    #[serde(flatten)]
    pub page: Page,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct JobStartRequest {
    pub host: String,
    pub cwd: String,
    pub argv: Option<Vec<String>>,
    pub command: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct JobKillRequest {
    pub host: String,
    pub job_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct SyncPushRequest {
    pub host: String,
    pub local_path: String,
    pub remote_path: String,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub delete: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct SyncPullRequest {
    pub host: String,
    pub remote_path: String,
    pub local_path: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct TransferRequest {
    pub source_host: String,
    pub source_path: String,
    pub destination_host: String,
    pub destination_path: String,
    #[serde(default)]
    pub resume: bool,
    pub verify: Option<String>,
}
