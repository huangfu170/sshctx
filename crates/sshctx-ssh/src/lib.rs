//! Host configuration, remote-agent deployment, and persistent OpenSSH connections.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sshctx_protocol::{Frame, Request, Response, read_frame, write_frame};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};
use tokio::{
    io::{BufReader, BufWriter},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{Mutex, Semaphore},
    time::{Duration, timeout},
};
use uuid::Uuid;

const AGENT: &[u8] = include_bytes!("../../../remote-agent/agent.py");
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub hosts: BTreeMap<String, HostConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostConfig {
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    pub identity_file: PathBuf,
    #[serde(default = "default_python")]
    pub python: String,
    pub allowed_roots: Vec<String>,
    #[serde(default = "default_operations")]
    pub max_operations: usize,
}
fn default_port() -> u16 {
    22
}
fn default_python() -> String {
    "python3".into()
}
fn default_operations() -> usize {
    4
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        Ok(dirs::home_dir()
            .context("home directory is unavailable")?
            .join(".sshctx/config.toml"))
    }
    pub async fn load(path: Option<&Path>) -> Result<Self> {
        let path = path.map(PathBuf::from).unwrap_or(Self::path()?);
        let text = tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("read {}", path.display()))?;
        let config: Self =
            toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if self.hosts.is_empty() {
            bail!("configuration has no hosts");
        }
        for (alias, host) in &self.hosts {
            if alias.is_empty()
                || !alias
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            {
                bail!("invalid host alias {alias:?}");
            }
            if host.address.trim().is_empty() || host.username.trim().is_empty() {
                bail!("host {alias} is missing address or username");
            }
            if host.allowed_roots.is_empty()
                || host.allowed_roots.iter().any(|p| !p.starts_with('/'))
            {
                bail!("host {alias} allowed_roots must contain absolute Linux paths");
            }
            if host.max_operations == 0 {
                bail!("host {alias} max_operations must be positive");
            }
        }
        Ok(())
    }
}

struct Connection {
    child: Child,
    input: BufWriter<ChildStdin>,
    output: BufReader<ChildStdout>,
}

pub struct HostHandle {
    alias: String,
    config: HostConfig,
    connection: Mutex<Option<Connection>>,
    operations: Semaphore,
}

#[derive(Clone)]
pub struct ConnectionPool {
    hosts: Arc<BTreeMap<String, Arc<HostHandle>>>,
}

#[async_trait]
pub trait RemoteBackend: Send + Sync {
    async fn call(
        &self,
        alias: &str,
        method: &str,
        params: Value,
        payload: Bytes,
        readonly: bool,
    ) -> Result<Frame<Response>>;
    async fn aliases(&self) -> Result<Vec<String>>;
    async fn reconnect(&self, alias: &str) -> Result<()>;
}

impl ConnectionPool {
    pub fn new(config: Config) -> Self {
        let hosts = config
            .hosts
            .into_iter()
            .map(|(alias, config)| {
                let handle = Arc::new(HostHandle {
                    alias: alias.clone(),
                    operations: Semaphore::new(config.max_operations),
                    config,
                    connection: Mutex::new(None),
                });
                (alias, handle)
            })
            .collect();
        Self {
            hosts: Arc::new(hosts),
        }
    }
    pub fn aliases(&self) -> Vec<String> {
        self.hosts.keys().cloned().collect()
    }
    pub fn host_config(&self, alias: &str) -> Result<HostConfig> {
        Ok(self.host(alias)?.config.clone())
    }
    pub async fn reconnect(&self, alias: &str) -> Result<()> {
        self.host(alias)?.disconnect().await;
        Ok(())
    }
    fn host(&self, alias: &str) -> Result<Arc<HostHandle>> {
        self.hosts
            .get(alias)
            .cloned()
            .with_context(|| format!("unknown host alias {alias:?}"))
    }

    pub async fn call(
        &self,
        alias: &str,
        method: &str,
        params: Value,
        payload: Bytes,
        readonly: bool,
    ) -> Result<Frame<Response>> {
        let host = self.host(alias)?;
        let _permit = host.operations.acquire().await?;
        let request = Request {
            id: Uuid::new_v4().to_string(),
            method: method.into(),
            params,
            readonly,
        };
        match host.call_once(request.clone(), payload.clone()).await {
            Ok(response) => Ok(response),
            Err(first) if readonly => {
                host.disconnect().await;
                host.call_once(request, payload).await.with_context(|| {
                    format!("retry after connection failure; first error: {first:#}")
                })
            }
            Err(error) => {
                host.disconnect().await;
                Err(error)
            }
        }
    }
}

#[async_trait]
impl RemoteBackend for ConnectionPool {
    async fn call(
        &self,
        alias: &str,
        method: &str,
        params: Value,
        payload: Bytes,
        readonly: bool,
    ) -> Result<Frame<Response>> {
        ConnectionPool::call(self, alias, method, params, payload, readonly).await
    }
    async fn aliases(&self) -> Result<Vec<String>> {
        Ok(ConnectionPool::aliases(self))
    }
    async fn reconnect(&self, alias: &str) -> Result<()> {
        ConnectionPool::reconnect(self, alias).await
    }
}

impl HostHandle {
    async fn call_once(&self, request: Request, payload: Bytes) -> Result<Frame<Response>> {
        let mut slot = self.connection.lock().await;
        if slot.is_none() {
            *slot = Some(self.connect().await?);
        }
        let connection = slot.as_mut().expect("connection initialized");
        write_frame(
            &mut connection.input,
            &Frame {
                header: request.clone(),
                payload,
            },
        )
        .await?;
        let response: Frame<Response> = timeout(
            Duration::from_secs(24 * 60 * 60),
            read_frame(&mut connection.output),
        )
        .await
        .context("remote request timed out")??;
        if response.header.id != request.id {
            bail!("response id mismatch");
        }
        Ok(response)
    }

    async fn disconnect(&self) {
        if let Some(mut connection) = self.connection.lock().await.take() {
            let _ = connection.child.kill().await;
        }
    }

    async fn connect(&self) -> Result<Connection> {
        self.deploy_agent().await?;
        let mut command = Command::new(ssh_program());
        append_common_args(&mut command, &self.config);
        command.arg(format!("{}@{}", self.config.username, self.config.address));
        command.arg(format!(
            "{} ~/.sshctx/agent/{AGENT_VERSION}/agent.py serve --allowed-roots-json '{}'",
            self.config.python,
            serde_json::to_string(&self.config.allowed_roots)?
        ));
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .with_context(|| format!("start persistent ssh for {}", self.alias))?;
        let input = BufWriter::new(child.stdin.take().context("ssh stdin unavailable")?);
        let output = BufReader::new(child.stdout.take().context("ssh stdout unavailable")?);
        Ok(Connection {
            child,
            input,
            output,
        })
    }

    async fn deploy_agent(&self) -> Result<()> {
        let hash = hex::encode(Sha256::digest(AGENT));
        let remote_dir = format!(".sshctx/agent/{AGENT_VERSION}");
        let remote = format!("{}@{}", self.config.username, self.config.address);
        let check = format!(
            "test -f ~/{remote_dir}/agent.py && printf '%s  %s\\n' '{hash}' ~/{remote_dir}/agent.py | sha256sum -c - >/dev/null"
        );
        let mut probe = Command::new(ssh_program());
        append_common_args(&mut probe, &self.config);
        let status = probe.arg(&remote).arg(check).status().await?;
        if status.success() {
            return Ok(());
        }
        let temp = std::env::temp_dir().join(format!("sshctx-agent-{}.py", Uuid::new_v4()));
        tokio::fs::write(&temp, AGENT).await?;
        let remote_tmp = format!("~/.sshctx/agent/.agent-{}.tmp", Uuid::new_v4());
        let mut mkdir = Command::new(ssh_program());
        append_common_args(&mut mkdir, &self.config);
        let status = mkdir
            .arg(&remote)
            .arg(format!("mkdir -p ~/.sshctx/agent ~/{remote_dir}"))
            .status()
            .await?;
        if !status.success() {
            bail!("failed to create remote agent directory");
        }
        let mut scp = Command::new(scp_program());
        append_scp_args(&mut scp, &self.config);
        let status = scp
            .arg(&temp)
            .arg(format!("{remote}:{remote_tmp}"))
            .status()
            .await?;
        let _ = tokio::fs::remove_file(&temp).await;
        if !status.success() {
            bail!("failed to upload remote agent");
        }
        let mut install = Command::new(ssh_program());
        append_common_args(&mut install, &self.config);
        let status = install.arg(&remote).arg(format!("test \"$(sha256sum {remote_tmp} | cut -d' ' -f1)\" = '{hash}' && chmod 700 {remote_tmp} && mv {remote_tmp} ~/{remote_dir}/agent.py")).status().await?;
        if !status.success() {
            bail!("remote agent checksum or install failed");
        }
        Ok(())
    }
}

fn append_common_args(command: &mut Command, host: &HostConfig) {
    command
        .args([
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=3",
            "-p",
            &host.port.to_string(),
            "-i",
        ])
        .arg(&host.identity_file)
        .args(["-o", "IdentitiesOnly=yes"]);
}
fn append_scp_args(command: &mut Command, host: &HostConfig) {
    command
        .args([
            "-q",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-P",
            &host.port.to_string(),
            "-i",
        ])
        .arg(&host.identity_file)
        .args(["-o", "IdentitiesOnly=yes"]);
}
#[cfg(windows)]
fn ssh_program() -> &'static str {
    "ssh.exe"
}
#[cfg(not(windows))]
fn ssh_program() -> &'static str {
    "ssh"
}
#[cfg(windows)]
fn scp_program() -> &'static str {
    "scp.exe"
}
#[cfg(not(windows))]
fn scp_program() -> &'static str {
    "scp"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_cannot_inject_ssh_arguments() {
        let mut hosts = BTreeMap::new();
        hosts.insert(
            "bad host".into(),
            HostConfig {
                address: "x".into(),
                port: 22,
                username: "u".into(),
                identity_file: "id".into(),
                python: "python3".into(),
                allowed_roots: vec!["/tmp".into()],
                max_operations: 1,
            },
        );
        assert!(Config { hosts }.validate().is_err());
    }
}
