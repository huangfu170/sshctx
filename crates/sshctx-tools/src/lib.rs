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
use tokio::io::AsyncWriteExt;

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
            self.upload_bytes(&request.host, &remote, &content, &hash)
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
        for (relative, entry) in entries {
            let destination = safe_local_join(&canonical, relative)?;
            if let Some(parent) = destination.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let remote = format!("{}/{}", request.remote_path.trim_end_matches('/'), relative);
            let expected_size = entry
                .get("size")
                .and_then(Value::as_u64)
                .context("manifest size missing")?;
            let expected_hash = entry
                .get("sha256")
                .and_then(Value::as_str)
                .context("manifest hash missing")?;
            if destination.is_file() {
                let existing = tokio::fs::read(&destination).await?;
                if existing.len() as u64 == expected_size && hex_sha256(&existing) == expected_hash
                {
                    continue;
                }
            }
            let temp = destination.with_extension("sshctx-part");
            let mut output = tokio::fs::File::create(&temp).await?;
            let mut offset = 0_u64;
            let mut hasher = Sha256::new();
            while offset < expected_size {
                let response = self
                    .request(
                        &request.host,
                        "read",
                        json!({"path":remote,"byte_offset":offset,"byte_limit":8*1024*1024}),
                        Bytes::new(),
                        true,
                    )
                    .await?;
                if response.payload.is_empty() {
                    bail!("remote file ended before manifest size");
                }
                output.write_all(&response.payload).await?;
                hasher.update(&response.payload);
                offset += response.payload.len() as u64;
            }
            output.flush().await?;
            output.sync_all().await?;
            drop(output);
            let actual_hash = format!("{:x}", hasher.finalize());
            if actual_hash != expected_hash {
                let _ = tokio::fs::remove_file(&temp).await;
                bail!("remote file changed during pull: {relative}");
            }
            tokio::fs::rename(&temp, &destination).await?;
            count += 1;
            bytes += expected_size as usize;
        }
        Ok(format!(
            "files={count}\ntransferred_bytes={bytes}\n(Complete: sync pull finished.)"
        ))
    }

    pub async fn transfer(&self, request: TransferRequest) -> Result<String> {
        if request
            .verify
            .as_deref()
            .is_some_and(|value| value != "sha256")
        {
            bail!("verify must be sha256 when provided");
        }
        let source_stat = self
            .request(
                &request.source_host,
                "stat",
                json!({"path":request.source_path}),
                Bytes::new(),
                true,
            )
            .await?;
        let kind = source_stat
            .header
            .result
            .get("kind")
            .and_then(Value::as_str)
            .context("source kind unavailable")?;
        if kind == "file" {
            let size = source_stat
                .header
                .result
                .get("size")
                .and_then(Value::as_u64)
                .context("source size unavailable")?;
            let (hash, resumed) = self
                .transfer_file(
                    &request.source_host,
                    &request.source_path,
                    &request.destination_host,
                    &request.destination_path,
                    size,
                    request.resume,
                )
                .await?;
            return Ok(format!(
                "files=1\ntransferred_bytes={size}\nresumed_bytes={resumed}\nsha256={hash}\n(Complete: host-to-host transfer verified.)"
            ));
        }
        if kind != "dir" {
            bail!("source must be a regular file or directory");
        }
        let manifest = self
            .request(
                &request.source_host,
                "manifest",
                json!({"path":request.source_path}),
                Bytes::new(),
                true,
            )
            .await?;
        let entries = manifest
            .header
            .result
            .get("entries")
            .and_then(Value::as_object)
            .context("invalid source manifest")?;
        let mut files = 0usize;
        let mut bytes = 0_u64;
        let mut resumed = 0_u64;
        for (relative, entry) in entries {
            let size = entry
                .get("size")
                .and_then(Value::as_u64)
                .context("manifest size missing")?;
            let source = format!("{}/{}", request.source_path.trim_end_matches('/'), relative);
            let destination = format!(
                "{}/{}",
                request.destination_path.trim_end_matches('/'),
                relative
            );
            let (_, resumed_file) = self
                .transfer_file(
                    &request.source_host,
                    &source,
                    &request.destination_host,
                    &destination,
                    size,
                    request.resume,
                )
                .await?;
            files += 1;
            bytes += size;
            resumed += resumed_file;
        }
        Ok(format!(
            "files={files}\ntransferred_bytes={bytes}\nresumed_bytes={resumed}\n(Complete: directory transfer verified file-by-file with SHA-256.)"
        ))
    }

    async fn upload_bytes(&self, host: &str, path: &str, content: &[u8], hash: &str) -> Result<()> {
        if content.len() <= sshctx_protocol::MAX_PAYLOAD {
            self.request(
                host,
                "write_atomic",
                json!({"path":path,"sha256":hash}),
                Bytes::copy_from_slice(content),
                false,
            )
            .await?;
            return Ok(());
        }
        let mut offset = 0usize;
        for chunk in content.chunks(8 * 1024 * 1024) {
            self.request(
                host,
                "write_chunk",
                json!({"path":path,"offset":offset,"reset":offset == 0}),
                Bytes::copy_from_slice(chunk),
                false,
            )
            .await?;
            offset += chunk.len();
        }
        self.request(
            host,
            "commit_chunks",
            json!({"path":path,"sha256":hash}),
            Bytes::new(),
            false,
        )
        .await?;
        Ok(())
    }

    async fn transfer_file(
        &self,
        source_host: &str,
        source_path: &str,
        destination_host: &str,
        destination_path: &str,
        size: u64,
        resume: bool,
    ) -> Result<(String, u64)> {
        let mut resume_offset = 0_u64;
        let mut reset_required = !resume;
        if resume {
            let status = self
                .request(
                    destination_host,
                    "chunk_status",
                    json!({"path":destination_path}),
                    Bytes::new(),
                    true,
                )
                .await?;
            let remote_offset = status
                .header
                .result
                .get("offset")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if remote_offset <= size {
                resume_offset = remote_offset;
            } else {
                reset_required = true;
            }
        }
        let mut offset = 0_u64;
        let mut hasher = Sha256::new();
        let mut first_write = true;
        if size == 0 {
            self.request(
                destination_host,
                "write_chunk",
                json!({"path":destination_path,"offset":0,"reset":true}),
                Bytes::new(),
                false,
            )
            .await?;
        }
        while offset < size {
            let read = self
                .request(
                    source_host,
                    "read",
                    json!({"path":source_path,"byte_offset":offset,"byte_limit":8*1024*1024}),
                    Bytes::new(),
                    true,
                )
                .await?;
            if read.payload.is_empty() {
                bail!("source ended before advertised size");
            }
            hasher.update(&read.payload);
            let end = offset + read.payload.len() as u64;
            if end > resume_offset {
                let start = resume_offset.saturating_sub(offset) as usize;
                let write_offset = offset + start as u64;
                self.request(destination_host, "write_chunk", json!({"path":destination_path,"offset":write_offset,"reset":reset_required && first_write}), read.payload.slice(start..), false).await?;
                first_write = false;
            }
            offset = end;
        }
        let hash = format!("{:x}", hasher.finalize());
        self.request(
            destination_host,
            "commit_chunks",
            json!({"path":destination_path,"sha256":hash}),
            Bytes::new(),
            false,
        )
        .await?;
        Ok((hash, resume_offset))
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
