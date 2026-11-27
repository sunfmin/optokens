#!/bin/sh
# One version of optokens, built on one Mac for every platform (ADR 0004):
# macOS natively, Linux (musl) with cargo-zigbuild and zig, Windows (msvc)
# with cargo-xwin. The platforms are macos-arm64 macos-x86_64 linux-arm64
# linux-x86_64 windows-x86_64. factorium.toml's cut step runs
# `packaging/release.sh cut $FACTORIUM_VERSION` in a worktree at the base's
# tip, then factorium tags what it left at HEAD and `brew upgrade`s the formula.
#
#   release.sh doctor         what this Mac lacks to build every platform, each
#                             with the line that installs it; installs nothing
#   release.sh check-tag <vX.Y.Z>  exit 0 if cut would take the version, 2 if not
#   release.sh dry            what the gate runs: every platform built at the
#                             development form X.Y.Z+<commits>.g<commit>[.dirty],
#                             each binary's arch checked, archived to $DIST with
#                             the formula and the Scoop manifest; publishes
#                             nothing
#   release.sh cut <vX.Y.Z>   the same at the version (OPTOKENS_RELEASE, read by
#                             build.rs; Cargo.toml is not edited), then publishes:
#                             the archives, formula and manifest to the tap's
#                             release optokens-vX.Y.Z, the formula to the tap's
#                             Formula/optokens.rb, the manifest to the bucket's
#                             bucket/optokens.json. Run again, it publishes the
#                             same again: nothing that is there is in the way.
#
# Homebrew and Scoop download from the tap (sunfmin/homebrew-tap) with no
# login. `gh` must be allowed to write to the tap and the bucket.
#
# DIST names another directory than dist/.
set -eu
cd "$(dirname "$0")/.."

NAME=optokens
REPO=https://github.com/sunfmin/optokens
TAP=sunfmin/homebrew-tap
BUCKET=sunfmin/scoop-bucket
PLATFORMS="macos-arm64 macos-x86_64 linux-arm64 linux-x86_64 windows-x86_64"
DIST=${DIST:-dist}
# The one sentence each installer shows.
DESC="Keeps an agent's secrets in a 1Password vault through a service account"
# What each installer says once: what optokens needs beyond itself (it reaches
# 1Password with no other program, ADR 0015).
NOTE="optokens needs tailscale, on a tailnet, for \`put --fields\` and \`init\`: they serve their one-time link on the tailnet only."

usage() {
    echo "usage: release.sh doctor | check-tag <vX.Y.Z> | dry | cut <vX.Y.Z>" >&2
    exit 2
}

# check_tag <tag>: a version tag vX.Y.Z, or usage.
check_tag() {
    case "$1" in
    v*[!0-9.]* | v*..* | v.* | v*.) usage ;;
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) usage ;;
    esac
    case "$1" in v*.*.*.*) usage ;; esac
}

# The Rust target that builds for a platform. Linux links musl, so one binary
# runs on any distribution.
target() {
    case "$1" in
    macos-arm64) echo aarch64-apple-darwin ;;
    macos-x86_64) echo x86_64-apple-darwin ;;
    linux-arm64) echo aarch64-unknown-linux-musl ;;
    linux-x86_64) echo x86_64-unknown-linux-musl ;;
    windows-x86_64) echo x86_64-pc-windows-msvc ;;
    esac
}

# The cargo subcommand that builds for a platform on a Mac: zig is Linux's
# linker and libc, and cargo-xwin links Windows against the MSVC CRT and the
# Windows SDK, which it downloads into its cache the first time.
builder() {
    case "$1" in
    macos-*) echo build ;;
    linux-*) echo zigbuild ;;
    windows-*) echo "xwin build" ;;
    esac
}

built() {
    case "$1" in
    windows-*) echo "target/$(target "$1")/release/$NAME.exe" ;;
    *) echo "target/$(target "$1")/release/$NAME" ;;
    esac
}

# archive <platform>: its archive's name at $version.
archive() {
    case "$1" in
    windows-*) echo "$NAME-$version-$1.zip" ;;
    *) echo "$NAME-$version-$1.tar.gz" ;;
    esac
}

# What `file` says of a binary built for a platform.
looks_like() {
    case "$1" in
    macos-arm64) echo "Mach-O 64-bit executable arm64" ;;
    macos-x86_64) echo "Mach-O 64-bit executable x86_64" ;;
    linux-arm64) echo "ELF 64-bit LSB .*ARM aarch64.*statically linked" ;;
    linux-x86_64) echo "ELF 64-bit LSB .*x86-64.*static" ;;
    windows-x86_64) echo "PE32\+ executable.*x86-64" ;;
    esac
}

# Whether this Mac runs a platform's binary: Apple Silicon runs Intel ones
# when Rosetta is installed, and no Mac runs Linux or Windows ones.
runs() {
    case "$1" in
    macos-*) arch "-${1#macos-}" /usr/bin/true 2>/dev/null ;;
    *) false ;;
    esac
}

sha() {
    shasum -a 256 "$1" | cut -d' ' -f1
}

# doctor: what this Mac lacks to build every platform, each with the line
# that installs it, on stderr; it fails when anything is missing. Then the
# toolchain rust-toolchain.toml pins (the one the gate passed, with every
# platform's target) has its own bin first on PATH: a `cargo` ahead of
# rustup's there (Homebrew's) has no other targets, and the cargo rustup's
# proxy starts still finds the `rustc` that is first on PATH.
doctor() {
    if [ "$(uname -s)" != Darwin ]; then
        echo "release: a release is built on a Mac, and this is $(uname -s)" >&2
        exit 1
    fi
    # A cut runs under factorium's daemon, whose PATH may lack ~/.cargo/bin
    # and mise's shims (zig).
    PATH="$PATH:$HOME/.cargo/bin:$HOME/.local/share/mise/shims"
    lacks=
    lack() {
        printf 'release: %s:\n    %s\n' "$1" "$2" >&2
        lacks=yes
    }
    cargo=
    if ! command -v rustup >/dev/null; then
        lack "no rustup is installed" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    elif ! cargo=$(rustup which cargo 2>/dev/null); then
        cargo=
        lack "rustup lacks the toolchain rust-toolchain.toml pins" "rustup toolchain install"
    fi
    installed=$([ -n "$cargo" ] && rustup target list --installed) || installed=
    for p in $PLATFORMS; do
        t=$(target "$p")
        echo "$installed" | grep -qx "$t" ||
            lack "the pinned toolchain has no target $t" "rustup toolchain install (rust-toolchain.toml names every target)"
    done
    command -v zig >/dev/null || lack "zig, which links Linux, is not installed (its prebuilt binary: Homebrew builds LLVM for it from source)" "mise use -g zig@0.17.1"
    command -v cargo-zigbuild >/dev/null || lack "cargo-zigbuild is not installed" "cargo install --locked cargo-zigbuild@0.24.1"
    command -v cargo-xwin >/dev/null || lack "cargo-xwin is not installed" "cargo install --locked cargo-xwin@0.24.1"
    for tool in file zip ruby gh; do
        command -v "$tool" >/dev/null || lack "$tool is not installed" "brew install $tool"
    done
    [ -z "$lacks" ] || exit 1
    PATH="$(dirname "$cargo"):$PATH"
    export PATH
}

# check <platform>: fails unless what was built for it is its binary, and,
# where this Mac runs it, `--version` says $version. One this Mac cannot run
# is checked by its arch alone; `file` prints what it saw.
check() {
    b=$(built "$1")
    said=$(file -b "$b")
    echo "$said" | grep -Eq "$(looks_like "$1")" || {
        echo "release: $b is not a $1 binary: $said" >&2
        exit 1
    }
    echo "release: $1: $said"
    if runs "$1"; then
        said=$(arch "-${1#macos-}" "$b" --version)
        [ "$said" = "$NAME $version" ] || {
            echo "release: $b --version says '$said', not '$NAME $version'" >&2
            exit 1
        }
    else
        echo "release: this Mac cannot run $1: its --version is not checked" >&2
    fi
}

# build <release or empty>: every platform built, checked and archived in
# $DIST with the formula and the manifest; answers (in $version) the version
# the binaries say. An empty release builds the development form.
build() {
    doctor
    # build.rs takes a set OPTOKENS_RELEASE, even an empty one, as the version.
    if [ -n "$1" ]; then export OPTOKENS_RELEASE="$1"; else unset OPTOKENS_RELEASE; fi
    for p in $PLATFORMS; do
        # shellcheck disable=SC2046 # the builder is words
        cargo $(builder "$p") --release --locked --quiet --target "$(target "$p")"
    done
    # The version this Mac's own binary says, which build.rs stamped in all.
    version=$("$(built macos-arm64)" --version | sed "s/^$NAME //")
    [ -z "$1" ] || [ "$version" = "$1" ] || {
        echo "release: $(built macos-arm64) --version says '$NAME $version', not '$NAME $1'" >&2
        exit 1
    }
    for p in $PLATFORMS; do check "$p"; done
    # $DIST holds this build alone: every binary is checked before any is packed.
    rm -rf "$DIST"
    mkdir -p "$DIST"
    for p in $PLATFORMS; do
        b=$(built "$p")
        case "$p" in
        windows-*) zip -jqX "$DIST/$(archive "$p")" "$b" ;;
        # Nothing of macOS's own goes in: no AppleDouble file, no xattrs.
        *) COPYFILE_DISABLE=1 tar -czf "$DIST/$(archive "$p")" --no-xattrs -C "$(dirname "$b")" "$NAME" ;;
        esac
    done
    base=https://github.com/$TAP/releases/download/$NAME-v$version
    formula >"$DIST/$NAME.rb"
    manifest >"$DIST/$NAME.json"
    ruby -c "$DIST/$NAME.rb" >/dev/null
    # The manifest is JSON, or Scoop refuses the bucket.
    ruby -rjson -e 'JSON.parse(File.read(ARGV[0]))' "$DIST/$NAME.json"
}

# url_sha <platform>: the formula's url and sha256 lines for it.
url_sha() {
    printf '      url "%s"\n      sha256 "%s"\n' "$base/$(archive "$1")" "$(sha "$DIST/$(archive "$1")")"
}

formula() {
    cat <<FORMULA
class Optokens < Formula
  desc "$DESC"
  homepage "$REPO"
  version "$version"

  on_macos do
    on_arm do
$(url_sha macos-arm64)
    end
    on_intel do
$(url_sha macos-x86_64)
    end
  end
  on_linux do
    on_arm do
$(url_sha linux-arm64)
    end
    on_intel do
$(url_sha linux-x86_64)
    end
  end

  def install
    bin.install "$NAME"
  end

  def caveats
    <<~EOS
      $NOTE
    EOS
  end

  test do
    assert_equal "$NAME #{version}", shell_output("#{bin}/$NAME --version").strip
  end
end
FORMULA
}

# Scoop runs no check of its own, and this Mac checked the binary by its arch.
manifest() {
    cat <<MANIFEST
{
    "version": "$version",
    "description": "$DESC",
    "homepage": "$REPO",
    "license": "Proprietary",

    "architecture": {
        "64bit": {
            "url": "$base/$(archive windows-x86_64)",
            "hash": "$(sha "$DIST/$(archive windows-x86_64)")"
        }
    },
    "bin": "$NAME.exe",
    "notes": "$(echo "$NOTE" | sed 's/`//g')"
}
MANIFEST
}

# push_file <repo> <path> <file> <message>: <repo>'s <path> is <file>, by a
# commit when it differs.
push_file() {
    clone=$(mktemp -d)
    gh repo clone "$1" "$clone" -- --quiet --depth 1
    mkdir -p "$clone/$(dirname "$2")"
    cp "$3" "$clone/$2"
    git -C "$clone" add "$2"
    if git -C "$clone" diff --cached --quiet; then
        echo "release: $1's $2 is $4 already"
    else
        git -C "$clone" commit --quiet -m "$4"
        git -C "$clone" push --quiet origin HEAD
        echo "release: $1's $2 is $4"
    fi
    rm -rf "$clone"
}


case "${1:-}" in
doctor)
    [ $# -eq 1 ] || usage
    doctor
    echo "release: this Mac builds every platform"
    exit 0
    ;;
check-tag)
    [ $# -eq 2 ] || usage
    check_tag "$2"
    exit 0
    ;;
dry)
    [ $# -eq 1 ] || usage
    build ""
    case "$version" in
    *[!0-9a-z.+]* | *+*+*) dev=no ;;
    [0-9]*.[0-9]*.[0-9]*+[0-9]*.g[0-9a-f]*) dev=yes ;;
    *) dev=no ;;
    esac
    [ "$dev" = yes ] || {
        echo "release: $NAME --version says '$version', not X.Y.Z+<commits>.g<commit>[.dirty]" >&2
        exit 1
    }
    echo "release: dry ok ($NAME $version, five platforms, $DIST)"
    exit 0
    ;;

cut) [ $# -eq 2 ] || usage ;;
*) usage ;;
esac
check_tag "$2"
started=$(date +%s)
command -v gh >/dev/null || {
    echo "release: cut publishes with gh: brew install gh" >&2
    exit 1
}

build "${2#v}"
release=$NAME-v$version
archives=$(for p in $PLATFORMS; do echo "$DIST/$(archive "$p")"; done)
# A release that is there already takes the archives again, so a cut that
# failed half way is run a second time. The archives are there before the
# formula and the manifest that download them.
# shellcheck disable=SC2086 # the archives are paths without spaces
if gh release view "$release" -R "$TAP" >/dev/null 2>&1; then
    gh release upload "$release" -R "$TAP" --clobber $archives "$DIST/$NAME.rb" "$DIST/$NAME.json"
else
    gh release create "$release" -R "$TAP" --title "$NAME $version" \
        --notes "The binaries the formula and the Scoop manifest \`$NAME\` install." \
        $archives "$DIST/$NAME.rb" "$DIST/$NAME.json"
fi
push_file "$TAP" "Formula/$NAME.rb" "$DIST/$NAME.rb" "$NAME $version"
push_file "$BUCKET" "bucket/$NAME.json" "$DIST/$NAME.json" "$NAME $version"
echo "release: $NAME $2 is published ($(($(date +%s) - started))s)"
