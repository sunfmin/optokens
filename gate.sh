#!/bin/sh
# The fast gate (factorium.toml): fmt, clippy, then slimfit runs the tests once and checks them against .slimfit/baseline.json, then docfit checks this repo's own documents.
set -eu
cd "$(dirname "$0")"
[ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH"

cargo fmt --check
cargo clippy --all-targets --quiet -- -D warnings
slimfit check
docfit check
echo "gate: ok"
