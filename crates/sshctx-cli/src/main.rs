use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use sshctx_runtime::{RuntimeClient, default_endpoint};
use sshctx_ssh::{Config, RemoteBackend};
use sshctx_tools::*;
use std::{path::PathBuf, process::Stdio, sync::Arc};
use tokio::{
    process::Command,
    time::{Duration, sleep},
};

#[derive(Parser)]
#[command(
    name = "sshctx",
    version,
    about = "Persistent SSH tools for MCP clients"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}
#[derive(Subcommand)]
enum Commands {
    Serve,
    RuntimeHost {
        #[arg(long)]
        endpoint: Option<String>,
    },
    Hosts,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Serve) {
        Commands::RuntimeHost { endpoint } => {
            sshctx_runtime::run_host(
                Config::load(cli.config.as_deref()).await?,
                endpoint.unwrap_or(default_endpoint()?),
            )
            .await
        }
        Commands::Serve => serve(cli.config).await,
        Commands::Hosts => {
            let client = connect_or_start(cli.config).await?;
            for host in client.aliases().await? {
                println!("{host}");
            }
            Ok(())
        }
    }
}

async fn connect_or_start(config: Option<PathBuf>) -> Result<RuntimeClient> {
    let endpoint = default_endpoint()?;
    let client = RuntimeClient::new(endpoint.clone());
    if client.aliases().await.is_ok() {
        return Ok(client);
    }
    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command.arg("runtime-host").arg("--endpoint").arg(&endpoint);
    if let Some(path) = config {
        command.arg("--config").arg(path);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.as_std_mut().creation_flags(0x08000000);
    }
    command.spawn().context("start sshctx runtime-host")?;
    for _ in 0..50 {
        if client.aliases().await.is_ok() {
            return Ok(client);
        }
        sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("runtime-host did not become ready")
}

async fn serve(config: Option<PathBuf>) -> Result<()> {
    let backend: Arc<dyn RemoteBackend> = Arc::new(connect_or_start(config).await?);
    let service = McpServer::new(ToolService::new(backend))
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;
    service.waiting().await?;
    Ok(())
}

#[derive(Clone)]
struct McpServer {
    tools: ToolService,
    router: ToolRouter<Self>,
}
impl McpServer {
    fn new(tools: ToolService) -> Self {
        Self {
            tools,
            router: Self::tool_router(),
        }
    }
}
fn success(result: Result<String>) -> CallToolResult {
    match result {
        Ok(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
        Err(error) => CallToolResult::error(vec![ContentBlock::text(format!("{error:#}"))]),
    }
}

#[tool_router]
impl McpServer {
    #[tool(
        name = "remote_hosts",
        description = "List configured SSH host aliases. Models cannot supply raw addresses, ports, keys, or SSH options.",
        annotations(
            title = "List remote hosts",
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn remote_hosts(&self) -> CallToolResult {
        success(self.tools.hosts().await.map(|h| {
            format!(
                "{}\n(Complete: {} configured hosts shown.)",
                h.join("\n"),
                h.len()
            )
        }))
    }
    #[tool(
        name = "remote_stat",
        description = "Read metadata for one allowed remote path.",
        annotations(
            title = "Stat remote path",
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn remote_stat(&self, Parameters(r): Parameters<PathRequest>) -> CallToolResult {
        success(self.tools.stat(r).await)
    }
    #[tool(
        name = "remote_read",
        description = "Read a remote file through the persistent binary-framed SSH connection. Output is deterministically paged.",
        annotations(
            title = "Read remote file",
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn remote_read(&self, Parameters(r): Parameters<ReadRequest>) -> CallToolResult {
        success(self.tools.read(r).await)
    }
    #[tool(
        name = "remote_grep",
        description = "Regex-search files below an allowed remote path.",
        annotations(
            title = "Search remote files",
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn remote_grep(&self, Parameters(r): Parameters<GrepRequest>) -> CallToolResult {
        success(self.tools.grep(r).await)
    }
    #[tool(
        name = "remote_glob",
        description = "Find remote paths by glob below an allowed root.",
        annotations(
            title = "Glob remote paths",
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn remote_glob(&self, Parameters(r): Parameters<GlobRequest>) -> CallToolResult {
        success(self.tools.glob(r).await)
    }
    #[tool(
        name = "remote_gpu_status",
        description = "Read NVIDIA GPU memory, utilization, temperature, and compute-process status.",
        annotations(
            title = "Read GPU status",
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn remote_gpu_status(
        &self,
        Parameters(r): Parameters<HostPageRequest>,
    ) -> CallToolResult {
        success(self.tools.gpu_status(r).await)
    }
    #[tool(
        name = "remote_processes",
        description = "List remote processes, optionally filtering by literal text.",
        annotations(
            title = "List remote processes",
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn remote_processes(
        &self,
        Parameters(r): Parameters<ProcessesRequest>,
    ) -> CallToolResult {
        success(self.tools.processes(r).await)
    }
    #[tool(
        name = "remote_job_output",
        description = "Resume stdout/stderr and state inspection for an sshctx background job.",
        annotations(
            title = "Read job output",
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn remote_job_output(
        &self,
        Parameters(r): Parameters<JobOutputRequest>,
    ) -> CallToolResult {
        success(self.tools.job_output(r).await)
    }
    #[tool(
        name = "remote_query",
        description = "Batch read-only stat/read/grep/glob/process/GPU/job-output operations in one SSH request.",
        annotations(
            title = "Batch remote queries",
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn remote_query(&self, Parameters(r): Parameters<QueryRequest>) -> CallToolResult {
        success(self.tools.query(r).await)
    }
    #[tool(
        name = "remote_exec",
        description = "Execute argv directly, or explicitly execute command through /bin/bash -lc. Structured binary framing avoids PowerShell/SSH/bash quote nesting.",
        annotations(
            title = "Execute remote command",
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn remote_exec(&self, Parameters(r): Parameters<ExecRequest>) -> CallToolResult {
        success(self.tools.exec(r).await)
    }
    #[tool(
        name = "remote_sync_push",
        description = "SHA-256 incremental local-to-remote sync. Honors gitignore and .sshctxignore; never deletes remote files in v0.1.",
        annotations(
            title = "Push changed files",
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn remote_sync_push(&self, Parameters(r): Parameters<SyncPushRequest>) -> CallToolResult {
        success(self.tools.sync_push(r).await)
    }
    #[tool(
        name = "remote_sync_pull",
        description = "Pull a remote tree into a local directory with atomic local file replacement.",
        annotations(
            title = "Pull remote files",
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn remote_sync_pull(&self, Parameters(r): Parameters<SyncPullRequest>) -> CallToolResult {
        success(self.tools.sync_pull(r).await)
    }
    #[tool(
        name = "remote_transfer",
        description = "Stream a file between configured hosts via the local control center and verify SHA-256 without full Windows-disk staging.",
        annotations(
            title = "Transfer between hosts",
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn remote_transfer(&self, Parameters(r): Parameters<TransferRequest>) -> CallToolResult {
        success(self.tools.transfer(r).await)
    }
    #[tool(
        name = "remote_job_start",
        description = "Start a supervised background job that survives SSH and Codex disconnects.",
        annotations(
            title = "Start remote job",
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn remote_job_start(&self, Parameters(r): Parameters<JobStartRequest>) -> CallToolResult {
        success(self.tools.job_start(r).await)
    }
    #[tool(
        name = "remote_job_kill",
        description = "Terminate only an sshctx-owned job by job ID; arbitrary PIDs are not accepted.",
        annotations(
            title = "Stop remote job",
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn remote_job_kill(&self, Parameters(r): Parameters<JobKillRequest>) -> CallToolResult {
        success(self.tools.job_kill(r).await)
    }
    #[tool(
        name = "remote_agent_update",
        description = "Disconnect a host so the versioned remote agent is checksum-verified and atomically redeployed on reconnect.",
        annotations(
            title = "Update remote agent",
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn remote_agent_update(&self, Parameters(r): Parameters<HostRequest>) -> CallToolResult {
        success(self.tools.agent_update(r).await)
    }
}

#[tool_handler(router=self.router)]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("sshctx", env!("CARGO_PKG_VERSION")))
            .with_instructions("Persistent, alias-only SSH tools. Prefer read-only structured tools and argv execution. Mutating tools require host approval. Paths are confined to configured allowed_roots.")
    }
}
