$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    cargo build --release --locked -p sshctx-cli
    $dist = Join-Path $root 'dist'
    New-Item -ItemType Directory -Force $dist | Out-Null
    Copy-Item 'target/release/sshctx.exe' $dist
    Copy-Item 'remote-agent/agent.py' $dist
    (Get-FileHash "$dist/sshctx.exe" -Algorithm SHA256).Hash.ToLowerInvariant() + '  sshctx.exe' | Set-Content "$dist/sshctx.exe.sha256"
    (Get-FileHash "$dist/agent.py" -Algorithm SHA256).Hash.ToLowerInvariant() + '  agent.py' | Set-Content "$dist/agent.py.sha256"
} finally { Pop-Location }

