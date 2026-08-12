#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
cargo build --release --locked -p sshctx-cli
mkdir -p dist
cp target/release/sshctx dist/sshctx
cp remote-agent/agent.py dist/agent.py
(cd dist && sha256sum sshctx agent.py > SHA256SUMS)

