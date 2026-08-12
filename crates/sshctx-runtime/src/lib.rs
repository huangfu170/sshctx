//! Per-user local control center and thin-client IPC.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use serde_json::{Value, json};
use sshctx_protocol::{Frame, Request, Response, read_frame, write_frame};
use sshctx_ssh::{ConnectionPool, RemoteBackend};
use std::path::PathBuf;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
    time::{Duration, sleep},
};
use uuid::Uuid;

const IDLE_SECONDS: u64 = 600;

struct ActiveRequest {
    active: Arc<AtomicUsize>,
    activity: Arc<AtomicU64>,
}

struct AuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}
impl AuditLog {
    async fn append(&self, value: Value) -> Result<()> {
        let _guard = self.lock.lock().await;
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        file.write_all(serde_json::to_string(&value)?.as_bytes())
            .await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }
}
impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        self.activity.store(now(), Ordering::Relaxed);
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeClient {
    endpoint: String,
}
impl RuntimeClient {
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }
}

#[async_trait]
impl RemoteBackend for RuntimeClient {
    async fn call(
        &self,
        alias: &str,
        method: &str,
        params: Value,
        payload: Bytes,
        readonly: bool,
    ) -> Result<Frame<Response>> {
        self.exchange(
            Request {
                id: Uuid::new_v4().to_string(),
                method: "call".into(),
                params: json!({"host":alias,"method":method,"params":params,"readonly":readonly}),
                readonly,
            },
            payload,
        )
        .await
    }
    async fn aliases(&self) -> Result<Vec<String>> {
        let response = self
            .exchange(
                Request {
                    id: Uuid::new_v4().to_string(),
                    method: "hosts".into(),
                    params: json!({}),
                    readonly: true,
                },
                Bytes::new(),
            )
            .await?;
        if !response.header.ok {
            bail!(response.header.error.unwrap_or_default());
        }
        Ok(serde_json::from_value(response.header.result)?)
    }
    async fn reconnect(&self, alias: &str) -> Result<()> {
        let response = self
            .exchange(
                Request {
                    id: Uuid::new_v4().to_string(),
                    method: "reconnect".into(),
                    params: json!({"host":alias}),
                    readonly: false,
                },
                Bytes::new(),
            )
            .await?;
        if !response.header.ok {
            bail!(response.header.error.unwrap_or_default());
        }
        Ok(())
    }
}

impl RuntimeClient {
    async fn exchange(&self, request: Request, payload: Bytes) -> Result<Frame<Response>> {
        let mut stream = connect(&self.endpoint).await?;
        write_frame(
            &mut stream,
            &Frame {
                header: request,
                payload,
            },
        )
        .await?;
        Ok(read_frame(&mut stream).await?)
    }
}

pub async fn run_host(config: sshctx_ssh::Config, endpoint: String) -> Result<()> {
    let pool = Arc::new(ConnectionPool::new(config));
    let last_activity = Arc::new(AtomicU64::new(now()));
    let active = Arc::new(AtomicUsize::new(0));
    let audit = Arc::new(AuditLog {
        path: dirs::home_dir()
            .context("home directory unavailable")?
            .join(".sshctx/audit.jsonl"),
        lock: Mutex::new(()),
    });
    let idle = Arc::clone(&last_activity);
    let idle_active = Arc::clone(&active);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(30)).await;
            if idle_active.load(Ordering::Relaxed) == 0
                && now().saturating_sub(idle.load(Ordering::Relaxed)) >= IDLE_SECONDS
            {
                std::process::exit(0);
            }
        }
    });
    listen(endpoint, pool, last_activity, active, audit).await
}

async fn handle<S>(
    mut stream: S,
    pool: Arc<ConnectionPool>,
    activity: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
    audit: Arc<AuditLog>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    active.fetch_add(1, Ordering::Relaxed);
    let _active_request = ActiveRequest {
        active,
        activity: Arc::clone(&activity),
    };
    activity.store(now(), Ordering::Relaxed);
    let frame: Frame<Request> = read_frame(&mut stream).await?;
    let audit_base = audit_fields(&frame.header);
    audit.append(json!({"timestamp":now(),"stage":"start","request_id":frame.header.id,"readonly":frame.header.readonly,"operation":audit_base.clone()})).await?;
    let id = frame.header.id.clone();
    let result: Result<Frame<Response>> = async {
        match frame.header.method.as_str() {
            "hosts" => Ok(ok(id, serde_json::to_value(pool.aliases())?)),
            "reconnect" => {
                let host = frame.header.params["host"]
                    .as_str()
                    .context("missing host")?;
                pool.reconnect(host).await?;
                Ok(ok(id, json!({"reconnected":host})))
            }
            "call" => {
                let host = frame.header.params["host"]
                    .as_str()
                    .context("missing host")?;
                let method = frame.header.params["method"]
                    .as_str()
                    .context("missing method")?;
                let params = frame
                    .header
                    .params
                    .get("params")
                    .cloned()
                    .unwrap_or(Value::Null);
                let readonly = frame.header.params["readonly"].as_bool().unwrap_or(false);
                pool.call(host, method, params, frame.payload, readonly)
                    .await
            }
            _ => bail!("unknown runtime method"),
        }
    }
    .await;
    let (ok, exit_code, error): (bool, Option<Value>, Option<String>) = match &result {
        Ok(response) => (
            response.header.ok,
            response.header.result.get("exit_code").cloned(),
            response.header.error.clone(),
        ),
        Err(error) => (false, None, Some(error.to_string())),
    };
    let completion = json!({"timestamp":now(),"stage":"complete","request_id":frame.header.id,"ok":ok,"exit_code":exit_code,"error":error.as_deref().map(redact_error),"operation":audit_base});
    if let Err(audit_error) = audit.append(completion).await {
        eprintln!("sshctx audit completion failed: {audit_error:#}");
    }
    let response = result.unwrap_or_else(|error| Frame {
        header: Response {
            id: frame.header.id,
            ok: false,
            result: Value::Null,
            error: Some(format!("{error:#}")),
            metadata: Default::default(),
        },
        payload: Bytes::new(),
    });
    write_frame(&mut stream, &response).await?;
    Ok(())
}
fn ok(id: String, result: Value) -> Frame<Response> {
    Frame {
        header: Response {
            id,
            ok: true,
            result,
            error: None,
            metadata: Default::default(),
        },
        payload: Bytes::new(),
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn audit_fields(request: &Request) -> Value {
    if request.method != "call" {
        return json!({"runtime_method":request.method});
    }
    let params = request.params.get("params").unwrap_or(&Value::Null);
    let argv = params.get("argv").and_then(Value::as_array);
    let command_summary = if let Some(argv) = argv {
        json!({"program":argv.first().and_then(Value::as_str),"argc":argv.len()})
    } else if let Some(command) = params.get("command").and_then(Value::as_str) {
        json!({"shell":true,"characters":command.chars().count()})
    } else {
        Value::Null
    };
    json!({"host":request.params.get("host"),"type":request.params.get("method"),"cwd":params.get("cwd"),"path":params.get("path"),"command":command_summary})
}
fn redact_error(error: &str) -> String {
    error.chars().take(500).collect()
}

pub fn default_endpoint() -> Result<String> {
    #[cfg(windows)]
    {
        Ok(r"\\.\pipe\sshctx-runtime-v1".into())
    }
    #[cfg(unix)]
    {
        Ok(dirs::home_dir()
            .context("home directory unavailable")?
            .join(".sshctx/runtime.sock")
            .to_string_lossy()
            .into_owned())
    }
}

#[cfg(windows)]
type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;
#[cfg(unix)]
type ClientStream = tokio::net::UnixStream;

#[cfg(windows)]
async fn connect(endpoint: &str) -> Result<ClientStream> {
    use tokio::net::windows::named_pipe::ClientOptions;
    for _ in 0..20 {
        match ClientOptions::new().open(endpoint) {
            Ok(stream) => return Ok(stream),
            Err(error) if error.raw_os_error() == Some(231) => {
                sleep(Duration::from_millis(50)).await
            }
            Err(error) => return Err(error.into()),
        }
    }
    bail!("runtime named pipe is busy")
}
#[cfg(unix)]
async fn connect(endpoint: &str) -> Result<ClientStream> {
    Ok(tokio::net::UnixStream::connect(endpoint).await?)
}

#[cfg(windows)]
async fn listen(
    endpoint: String,
    pool: Arc<ConnectionPool>,
    activity: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
    audit: Arc<AuditLog>,
) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let mut first = true;
    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(first)
            .create(&endpoint)?;
        first = false;
        server.connect().await?;
        let pool = Arc::clone(&pool);
        let activity = Arc::clone(&activity);
        let active = Arc::clone(&active);
        let audit = Arc::clone(&audit);
        tokio::spawn(async move {
            let _ = handle(server, pool, activity, active, audit).await;
        });
    }
}
#[cfg(unix)]
async fn listen(
    endpoint: String,
    pool: Arc<ConnectionPool>,
    activity: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
    audit: Arc<AuditLog>,
) -> Result<()> {
    let path = PathBuf::from(&endpoint);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if path.exists() {
        tokio::fs::remove_file(&path).await?;
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let pool = Arc::clone(&pool);
        let activity = Arc::clone(&activity);
        let active = Arc::clone(&active);
        let audit = Arc::clone(&audit);
        tokio::spawn(async move {
            let _ = handle(stream, pool, activity, active, audit).await;
        });
    }
}
