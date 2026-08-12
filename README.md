# sshctx

`sshctx` is a context-efficient MCP server for recurring SSH work. A tiny STDIO process connects Codex to a per-user control center; the control center owns one long-lived OpenSSH process per active host and speaks a binary-safe framed protocol to a versioned Python agent on Linux.

```text
Codex STDIO MCP
    -> sshctx serve
    -> Windows named pipe / Unix socket
    -> sshctx runtime-host
    -> one persistent ssh process per active host
    -> python3 ~/.sshctx/agent/0.1.0/agent.py serve
```

The project targets Windows 10/11 locally and Linux with Python 3.9+ remotely. It intentionally does not provide interactive PTY, port forwarding, public HTTP MCP, or Windows remote support.

## What it replaces

- Repeated `ssh.exe` calls for `stat`, `grep`, `find`, process checks, GPU checks, and log polling.
- PowerShell -> SSH -> bash quote nesting. `remote_exec.argv` is transported as JSON and executed directly.
- `nohup`, PID files, `pgrep`, and `tail` loops. Jobs have durable IDs, state, stdout, stderr, and exit records.
- Repeated `scp.exe` uploads. Push sync compares SHA-256 manifests and transfers changed files only.
- Server-to-server connectivity assumptions. `remote_transfer` streams through the control center without staging the complete file on Windows.

OpenSSH is still used for authentication, host-key verification, and transport. `scp` is used only when the versioned agent is missing or its SHA-256 does not match.

## Install

Build from source with Rust 1.88 or newer:

```powershell
cargo build --release -p sshctx-cli
Copy-Item target\release\sshctx.exe "$env:LOCALAPPDATA\sshctx\sshctx.exe"
```

Create `%USERPROFILE%\.sshctx\config.toml`:

```toml
[hosts.gpu102]
address = "192.168.18.102"
port = 22
username = "huangfuyuanxiang"
identity_file = "C:/Users/huangfuyuanxiang/.ssh/id_ed25519"
python = "python3"
allowed_roots = ["/data/yxhuangfu", "/tmp/sshctx"]
max_operations = 4

[hosts.data42]
address = "42.192.34.154"
port = 10996
username = "root"
identity_file = "C:/Users/huangfuyuanxiang/.ssh/id_ed25519"
python = "python3"
allowed_roots = ["/root/qwen2vl_ocr_specialization_bundle"]
max_operations = 4
```

Only aliases such as `gpu102` are exposed to MCP. A tool call cannot inject an address, port, private key, or arbitrary OpenSSH option.

Register the STDIO server in `~/.codex/config.toml`:

```toml
[mcp_servers.sshctx]
command = "C:/Users/huangfuyuanxiang/AppData/Local/sshctx/sshctx.exe"
args = ["serve"]
startup_timeout_sec = 20
tool_timeout_sec = 86400
```

`sshctx serve` starts `runtime-host` on demand. Multiple Codex tasks connect to the same Windows named pipe (or Unix-domain socket). The host exits after ten idle minutes.

## Tools

Read-only tools:

- `remote_hosts`, `remote_stat`, `remote_read`, `remote_grep`, `remote_glob`
- `remote_gpu_status`, `remote_processes`, `remote_job_output`, `remote_query`

Mutating or execution tools:

- `remote_exec`, `remote_sync_push`, `remote_sync_pull`, `remote_transfer`
- `remote_job_start`, `remote_job_kill`, `remote_agent_update`

Prefer direct argv execution:

```json
{
  "host": "gpu102",
  "cwd": "/data/yxhuangfu/SMDM/DeepSeek-Diffusion-OCR",
  "argv": [".venv/bin/python", "scripts/train.py"],
  "env": {
    "CUDA_VISIBLE_DEVICES": "9",
    "PYTORCH_CUDA_ALLOC_CONF": "expandable_segments:True"
  },
  "timeout_ms": 120000
}
```

`command` is also available and explicitly invokes `/bin/bash -lc`; exactly one of `argv` and `command` is required.

All text output is deterministic and ends in one of these forms:

```text
(Complete: all 27 lines shown.)
(Partial: lines 1-200 shown. Continue with offset=201.)
```

## Jobs

`remote_job_start` launches a detached supervisor. Closing Codex or losing SSH does not terminate the workload. Records live at:

```text
~/.sshctx/jobs/<job-id>/
├── request.json
├── state.json
├── stdout.log
├── stderr.log
└── exit.json
```

Only an sshctx job ID is accepted by `remote_job_kill`; arbitrary PIDs cannot be supplied.

## Sync and transfer

Push sync honors `.gitignore` and `.sshctxignore`, and excludes `.git`, `models`, `data`, `outputs`, `logs`, `target`, and `__pycache__` by default. Files are SHA-256 compared, uploaded over the persistent framed connection, verified, fsynced, and atomically replaced. Version 0.1 refuses `delete=true`.

Host-to-host transfer uses 8 MiB binary chunks and verifies the assembled SHA-256 on the destination. The data passes through memory in `runtime-host`; the complete file is never stored on Windows.

## Security model

- OpenSSH uses `BatchMode=yes`, `IdentitiesOnly=yes`, and `StrictHostKeyChecking=yes`.
- Every remote path is resolved on Linux and must remain under an `allowed_roots` entry. Parent symlink escapes are rejected.
- The agent listens on no port and communicates only through SSH stdin/stdout.
- Read-only requests may be retried once after reconnect. Mutations, job starts, and kills are never automatically replayed.
- MCP tool annotations distinguish read-only tools from operations that should require approval in the host.
- Secrets are not written by the remote job supervisor; environment values stay in its mode-0700 job directory. Operators should still avoid placing long-lived secrets directly in tool arguments.

## Development

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
python -m unittest discover -s remote-agent -p 'test_*.py' -v
```

See [the source repository](https://github.com/huangfu170/sshctx) for CI artifacts and releases.
