#!/bin/sh
# The fast gate (factorium.toml): fmt, clippy, then slimfit runs the tests once and checks them against .slimfit/baseline.json, then docfit checks this repo's own documents, then the version a tagless clone stamps.
set -eu
cd "$(dirname "$0")"
[ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH"

cargo fmt --check
cargo clippy --all-targets --quiet -- -D warnings
slimfit check
docfit check
# Without tags (factorium's promotion clone), a build still stamps the
# development form: Cargo.toml's version + the commit count + the hash.
tagless=$PWD/.slimfit/out/tagless
rm -rf "$tagless"
git clone --quiet --no-tags . "$tagless"
CARGO_TARGET_DIR=$PWD/.slimfit/out/tagless-target cargo build --release --quiet --manifest-path "$tagless/Cargo.toml"
want="optokens $(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)+$(git -C "$tagless" rev-list --count HEAD).g$(git -C "$tagless" rev-parse --short HEAD)"
said=$(.slimfit/out/tagless-target/release/optokens --version)
[ "$said" = "$want" ] || { echo "gate: a tagless clone says '$said', not '$want'"; exit 1; }
echo "gate: ok"
