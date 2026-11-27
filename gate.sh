#!/bin/sh
# The fast gate (factorium.toml): fmt, clippy (native and for Windows), no crate that builds C, then slimfit runs the tests once and checks them against .slimfit/baseline.json, then docfit checks this repo's own documents, then the release script short of publishing, then the version a tagless clone stamps.
set -eu
cd "$(dirname "$0")"
[ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH"

cargo fmt --check
cargo clippy --all-targets --quiet -- -D warnings
# The Windows build, checked (not linked or run: there is no Windows host), so a
# Windows-only branch cannot rot. rust-toolchain.toml installs its target.
cargo clippy --all-targets --target x86_64-pc-windows-msvc --quiet -- -D warnings
# No C on any target (ADR 0010; opcore's decision record 1): `cargo tree -i`
# prints nothing, or fails, for a crate that is not built.
for c in cc cmake; do
    if cargo tree --quiet -e build,normal --target all -i "$c" 2>/dev/null | grep -q .; then
        echo "gate: $c, which builds C, is in the dependency tree: cargo tree --target all -i $c"
        exit 1
    fi
done
slimfit check
docfit check
# The release script, as far as it goes without publishing: all five platforms
# built, each binary's arch checked, the formula and the Scoop manifest written.
sh -n packaging/release.sh
for good in v0.1.0 v1.22.333; do packaging/release.sh check-tag "$good"; done
for bad in "" v1 v1.2 1.2.3 v1.2.3.4 v1..3 v1.2.x "v1.2.3;x"; do
    if packaging/release.sh check-tag "$bad" 2>/dev/null; then echo "gate: release.sh takes \"$bad\""; exit 1; fi
done
DIST=.slimfit/out/dist packaging/release.sh dry
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
