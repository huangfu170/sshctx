# sshctx-runtime

The runtime host owns the per-user SSH connection pool. On Windows it uses a named pipe; on Unix it uses a user-owned Unix-domain socket. `sshctx serve` is a thin STDIO MCP process that starts or connects to this host.

