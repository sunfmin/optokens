#!/bin/sh
# One version of optokens for five platforms (ADR 0004), released as the
# sibling tools are (ADR 0022, after slimfit ADR 0013): macOS is one universal
# binary this repo builds and sunfmin/homebrew-tap's release workflow signs
# with Developer ID, notarizes and publishes; Linux (musl, with cargo-zigbuild
# and zig) and Windows (msvc, with cargo-xwin) are built and published from
# this Mac. factorium.toml's cut step runs `packaging/release.sh cut
# $FACTORIUM_VERSION` in a worktree at the base's tip, then factorium tags what
# it left at HEAD and upgrades the formula.
#
#   release.sh doctor         what this Mac lacks to build every platform, each
#                             with the line that installs it; installs nothing
#   release.sh check-tag <vX.Y.Z>  exit 0 if cut would take the version, 2 if not
#   release.sh build <vX.Y.Z> <outdir>
#                             the tap's contract (its .github/workflows/README.md):
#                             aarch64 and x86_64 macOS built with the version
#                             stamped (OPTOKENS_RELEASE, read by build.rs;
#                             Cargo.toml is not edited), `lipo -create`d into
#                             <outdir>/optokens, and the formula
#                             <outdir>/optokens.rb: macOS's url and sha256 left
#                             as @URL@ and @SHA256@ for the tap to fill in,
#                             Linux's those of the archives the cut put on the
#                             tap's release optokens-vX.Y.Z, downloaded here.
#                             Signs nothing, needs no secret
#   release.sh dry            what the gate runs: every platform built at the
#                             development form X.Y.Z+<commits>.g<commit>[.dirty],
#                             each binary checked; the Linux and Windows
#                             archives and the Scoop manifest in $DIST, the
#                             universal binary and the formula (Linux's sha256
#                             from $DIST) in $DIST/macos; publishes nothing
#   release.sh cut <vX.Y.Z>   Linux and Windows built, checked and put on the
#                             tap's release optokens-vX.Y.Z; then build; the tag
#                             pushed to origin; the tap's release.yml run on it
#                             and waited for, bounded (RELEASE_WAIT_LIMIT seconds
#                             from the cut's start, default 2400; RELEASE_POLL
#                             seconds between polls, default 5 for the run to
#                             appear, 15 for it to end); the macOS archive the
#                             tap's formula now names downloaded, and the cut
#                             failed unless `signed` takes its binary; then the
#                             Scoop manifest pushed to the bucket. A cut that
#                             ends early cancels the run it dispatched, then
#                             takes away the tag it pushed. Run again, it
#                             publishes the same again
#   release.sh signed <file>  exit 0 if the file is universal and its signature
#                             verifies, with Developer ID Application authority
#                             and a TeamIdentifier; else 1, saying why
#   release.sh push-file <repo> <path> <file> <message>
#                             the manifest's push alone: <repo>'s <path> is
#                             <file>, rebased and pushed again while another
#                             cut beats it; packaging/push_file_test.sh races it
#
# Homebrew and Scoop download from the tap (sunfmin/homebrew-tap) with no
# login. `gh` must be allowed to push this repo's tags, upload to the tap's
# releases, run its workflow and push to the bucket. This Mac holds no signing
# secret: the tap's are the only copies.
#
# DIST names another directory than dist/.
set -eu
cd "$(dirname "$0")/.."

# A cut runs under factorium's daemon, whose PATH may lack rustup's
# ~/.cargo/bin and mise's shims (zig). Last, so what is on PATH comes first;
# toolchain puts the pinned toolchain's own bin first.
PATH="$PATH:$HOME/.cargo/bin:$HOME/.local/share/mise/shims"
export PATH

NAME=optokens
REPO=https://github.com/sunfmin/optokens
TAP=sunfmin/homebrew-tap
BUCKET=sunfmin/scoop-bucket
# The universal macOS binary's slices, lipo's order.
MAC_TARGETS="aarch64-apple-darwin x86_64-apple-darwin"
# The platforms built and published from this Mac.
PLATFORMS="linux-arm64 linux-x86_64 windows-x86_64"
DIST=${DIST:-dist}
# The one sentence each installer shows.
DESC="Keeps an agent's secrets in a 1Password vault through a service account"
# What each installer says once: what optokens needs beyond itself (it reaches
# 1Password with no other program, ADR 0015).
NOTE="optokens needs tailscale, on a tailnet, for \`put --fields\` and \`init\`: they serve their one-time link on the tailnet only."

usage() {
    echo "usage: release.sh doctor | check-tag <vX.Y.Z> | build <vX.Y.Z> <outdir> | dry | cut <vX.Y.Z> | signed <file> | push-file <repo> <path> <file> <message>" >&2
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
    linux-arm64) echo "ELF 64-bit LSB .*ARM aarch64.*statically linked" ;;
    linux-x86_64) echo "ELF 64-bit LSB .*x86-64.*static" ;;
    windows-x86_64) echo "PE32\+ executable.*x86-64" ;;
    esac
}

sha() {
    shasum -a 256 "$1" | cut -d' ' -f1
}

# release <release or empty>: build.rs takes a set OPTOKENS_RELEASE, even an
# empty one, as the version; an empty release builds the development form.
release() {
    if [ -n "$1" ]; then export OPTOKENS_RELEASE="$1"; else unset OPTOKENS_RELEASE; fi
}

# toolchain: the toolchain rust-toolchain.toml pins (the one the gate passed),
# with its targets, its own bin first on PATH: a `cargo` ahead of rustup's
# there (Homebrew's) has no other targets, and the cargo rustup's proxy starts
# still finds the `rustc` that is first on PATH. Installs it when it is
# missing (into ~/.rustup): the tap's runner has none.
toolchain() {
    command -v rustup >/dev/null || {
        echo "release: building needs rustup: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
        exit 1
    }
    rustup toolchain install --no-self-update >/dev/null
    PATH="$(dirname "$(rustup which cargo)"):$PATH"
    export PATH
}

# doctor: what this Mac lacks to build every platform, each with the line
# that installs it, on stderr; it fails when anything is missing.
doctor() {
    if [ "$(uname -s)" != Darwin ]; then
        echo "release: a release is built on a Mac, and this is $(uname -s)" >&2
        exit 1
    fi
    lacks=
    lack() {
        printf 'release: %s:\n    %s\n' "$1" "$2" >&2
        lacks=yes
    }
    if ! command -v rustup >/dev/null; then
        lack "no rustup is installed" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    else
        installed=$(rustup target list --installed 2>/dev/null) || installed=
        for t in $MAC_TARGETS $(for p in $PLATFORMS; do target "$p"; done); do
            echo "$installed" | grep -qx "$t" ||
                lack "the pinned toolchain has no target $t" "rustup toolchain install (rust-toolchain.toml names every target)"
        done
    fi
    command -v zig >/dev/null || lack "zig, which links Linux, is not installed (its prebuilt binary: Homebrew builds LLVM for it from source)" "mise use -g zig@0.17.1"
    command -v cargo-zigbuild >/dev/null || lack "cargo-zigbuild is not installed" "cargo install --locked cargo-zigbuild@0.24.1"
    command -v cargo-xwin >/dev/null || lack "cargo-xwin is not installed" "cargo install --locked cargo-xwin@0.24.1"
    for tool in file zip ruby gh curl lipo codesign; do
        command -v "$tool" >/dev/null || lack "$tool is not installed" "brew install $tool"
    done
    [ -z "$lacks" ] || exit 1
}

# universal <release or empty> <outdir>: aarch64 and x86_64 macOS built and
# lipo'd into <outdir>/optokens, which must say <release>; answers (in
# $version) the version it says.
universal() {
    toolchain
    release "$1"
    slices=
    for t in $MAC_TARGETS; do
        cargo build --release --locked --quiet --target "$t"
        slices="$slices target/$t/release/$NAME"
    done
    rm -rf "$2"
    mkdir -p "$2"
    # shellcheck disable=SC2086 # the slices are paths without spaces
    lipo -create -output "$2/$NAME" $slices
    archs=$(lipo -archs "$2/$NAME")
    [ "$archs" = "x86_64 arm64" ] || {
        echo "release: $2/$NAME holds '$archs', not 'x86_64 arm64'" >&2
        exit 1
    }
    version=$("$2/$NAME" --version | sed "s/^$NAME //")
    [ -z "$1" ] || [ "$version" = "$1" ] || {
        echo "release: $2/$NAME --version says '$NAME $version', not '$NAME $1'" >&2
        exit 1
    }
    base=https://github.com/$TAP/releases/download/$NAME-v$version
    echo "release: macos-universal: $(file -b "$2/$NAME" | head -n1), $NAME $version"
}

# others: Linux and Windows built at $version (OPTOKENS_RELEASE as set),
# each binary's arch checked (no Mac runs them), and archived in $DIST with
# the Scoop manifest.
others() {
    toolchain
    for p in $PLATFORMS; do
        # shellcheck disable=SC2046 # the builder is words
        cargo $(builder "$p") --release --locked --quiet --target "$(target "$p")"
    done
    for p in $PLATFORMS; do
        b=$(built "$p")
        said=$(file -b "$b")
        echo "$said" | grep -Eq "$(looks_like "$p")" || {
            echo "release: $b is not a $p binary: $said" >&2
            exit 1
        }
        echo "release: $p: $said (no Mac runs it: its --version is not checked)"
    done
    mkdir -p "$DIST"
    for p in $PLATFORMS; do
        b=$(built "$p")
        case "$p" in
        windows-*) rm -f "$DIST/$(archive "$p")" && zip -jqX "$DIST/$(archive "$p")" "$b" ;;
        # Nothing of macOS's own goes in: no AppleDouble file, no xattrs.
        *) COPYFILE_DISABLE=1 tar -czf "$DIST/$(archive "$p")" --no-xattrs -C "$(dirname "$b")" "$NAME" ;;
        esac
    done
    manifest >"$DIST/$NAME.json"
    # The manifest is JSON, or Scoop refuses the bucket.
    ruby -rjson -e 'JSON.parse(File.read(ARGV[0]))' "$DIST/$NAME.json"
}

# fetch_linux <dir>: the Linux archives of $version, from the tap's release,
# in <dir>.
fetch_linux() {
    for p in linux-arm64 linux-x86_64; do
        curl -fsSL --retry 3 -o "$1/$(archive "$p")" "$base/$(archive "$p")" || {
            echo "release: $base/$(archive "$p") cannot be downloaded: a cut puts the Linux archives on the tap's release before it runs the tap's workflow" >&2
            exit 1
        }
    done
}

# url_sha <platform> <dir>: the formula's url and sha256 lines for its
# archive in <dir>.
url_sha() {
    printf '      url "%s"\n      sha256 "%s"\n' "$base/$(archive "$1")" "$(sha "$2/$(archive "$1")")"
}

# formula <dir>: the formula, Linux's archives read from <dir>. macOS's url
# and sha256 are the tap's to fill in, as are the archive's name and where it
# lies.
formula() {
    cat <<FORMULA
class Optokens < Formula
  desc "$DESC"
  homepage "$REPO"
  version "$version"

  on_macos do
    url "@URL@"
    sha256 "@SHA256@"
  end
  on_linux do
    on_arm do
$(url_sha linux-arm64 "$1")
    end
    on_intel do
$(url_sha linux-x86_64 "$1")
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

# build <version> <outdir>: the tap's contract, the universal binary and the
# formula, Linux's archives downloaded from the tap's release.
build() {
    universal "$1" "$2"
    fetched=$(mktemp -d)
    fetch_linux "$fetched"
    formula "$fetched" >"$2/$NAME.rb"
    rm -rf "$fetched"
    ruby -c "$2/$NAME.rb" >/dev/null
}

# signed <file>: fails, saying why, unless the file is universal, its
# signature verifies, and `codesign -dv` names Developer ID Application
# authority and a TeamIdentifier.
signed() {
    archs=$(lipo -archs "$1" 2>&1) || archs=
    said=$(codesign -dv --verbose=4 "$1" 2>&1) || said="$said"
    if [ "$archs" = "x86_64 arm64" ] && codesign --verify --strict "$1" 2>/dev/null &&
        echo "$said" | grep -q '^Authority=Developer ID Application: ' &&
        echo "$said" | grep -Eqx 'TeamIdentifier=[A-Z0-9]{10}'; then
        echo "release: $1 is universal and signed: $(echo "$said" | grep -m1 '^Authority='), $(echo "$said" | grep '^TeamIdentifier=')"
        return 0
    fi
    echo "release: $1 is not a universal binary signed with Developer ID Application: lipo -archs says '$archs', codesign -dv --verbose=4 says:" >&2
    echo "$said" | grep -E '^(Authority|TeamIdentifier|Signature|CodeDirectory)|not signed' >&2 || true
    return 1
}

# push_file <repo> <path> <file> <message>: <repo>'s <path> is <file>, by a
# commit when it differs. Other repos' cuts push their own files to the same
# tap and bucket; a push one of them beat is rebased onto it and pushed again,
# up to 5 tries. The rebase fetches what is new since the depth-1 clone, whose
# one commit it shares.
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
        branch=$(git -C "$clone" symbolic-ref --short HEAD)
        tries=1
        until err=$(git -C "$clone" push --quiet origin HEAD 2>&1); do
            [ "$tries" -lt 5 ] || {
                echo "$err" >&2
                echo "release: $1 took no push of $2 in $tries tries" >&2
                exit 1
            }
            echo "release: $1 moved under the push of $2, rebasing (try $tries)" >&2
            sleep "$tries"
            git -C "$clone" pull --rebase --quiet origin "$branch"
            tries=$((tries + 1))
        done
        echo "release: $1's $2 is $4"
    fi
    rm -rf "$clone"
}

# push_tag <tag>: origin has <tag> on HEAD. factorium's own tag step tags
# HEAD after the cut and fails on a tag origin already holds, so a tag this
# cut pushed is taken away again when the cut ends, however it ends (end_cut).
push_tag() {
    head=$(git rev-parse HEAD)
    # An annotated tag's peeled line (^{}) comes after it: the last line is the commit.
    there=$(git ls-remote origin "refs/tags/$1" "refs/tags/$1^{}" | tail -n1 | cut -f1)
    if [ -z "$there" ]; then
        git push --quiet origin "$head:refs/tags/$1"
        pushed=yes
    elif [ "$there" != "$head" ]; then
        echo "release: origin's $1 is on $there, not HEAD ($head)" >&2
        exit 1
    fi
}

# latest_run <tag>: the id of the newest run of the tap's release.yml on
# optokens <tag>, or nothing.
latest_run() {
    gh run list -R "$TAP" --workflow release.yml --event workflow_dispatch --limit 50 \
        --json databaseId,displayTitle \
        --jq "[.[] | select(.displayTitle == \"$NAME $1\") | .databaseId] | max // empty"
}

# end_cut, on the cut's exit: a run it dispatched that has not completed is
# cancelled first, so no run is left building a tag that is gone; then the
# tag it pushed is taken away; then what it downloaded.
end_cut() {
    if [ "$dispatched" = yes ] && [ "$ended" != yes ]; then
        [ -n "$run" ] || run=$(latest_run "$tag") || run=
        if [ -n "$run" ] && [ "$run" != "$before" ]; then
            gh run cancel "$run" -R "$TAP" >/dev/null ||
                echo "release: could not cancel run $run: gh run cancel $run -R $TAP" >&2
        else
            echo "release: no release.yml run of $NAME $tag in $TAP found to cancel" >&2
        fi
    fi
    [ "$pushed" != yes ] || git push --quiet origin ":refs/tags/$tag"
    [ -z "$published" ] || rm -rf "$published"
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
build)
    [ $# -eq 3 ] || usage
    check_tag "$2"
    build "${2#v}" "$3"
    echo "release: built $NAME $version, universal, and its formula in $3"
    exit 0
    ;;
dry)
    [ $# -eq 1 ] || usage
    doctor
    # $DIST holds this build alone.
    rm -rf "$DIST"
    universal "" "$DIST/macos"
    others
    formula "$DIST" >"$DIST/macos/$NAME.rb"
    ruby -c "$DIST/macos/$NAME.rb" >/dev/null
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
signed)
    [ $# -eq 2 ] || usage
    signed "$2" || exit 1
    exit 0
    ;;
push-file)
    [ $# -eq 5 ] || usage
    push_file "$2" "$3" "$4" "$5"
    exit 0
    ;;
cut) [ $# -eq 2 ] || usage ;;
*) usage ;;
esac
check_tag "$2"
tag=$2
started=$(date +%s)
limit=${RELEASE_WAIT_LIMIT:-2400}
pushed= dispatched= ended= run= before= published=
trap end_cut EXIT
doctor

# Linux and Windows, built here and put on the tap's release first: the
# formula `build` writes (here, then on the tap's runner) downloads Linux's.
version=${tag#v}
base=https://github.com/$TAP/releases/download/$NAME-v$version
release "$version"
rm -rf "$DIST"
others
rel=$NAME-v$version
archives=$(for p in $PLATFORMS; do echo "$DIST/$(archive "$p")"; done)
# A release that is there already takes the archives again, so a cut that
# failed half way is run a second time; the tap's run adds macOS's archive.
# shellcheck disable=SC2086 # the archives are paths without spaces
if gh release view "$rel" -R "$TAP" >/dev/null 2>&1; then
    gh release upload "$rel" -R "$TAP" --clobber $archives
else
    gh release create "$rel" -R "$TAP" --title "$NAME $version" \
        --notes "The binaries the formula and the Scoop manifest \`$NAME\` install: macOS universal, Developer ID signed and notarized by this tap's release workflow; Linux and Windows built by optokens' cut." \
        $archives
fi

# Built here as the tap's runner will: a tag goes out only on a commit that
# builds at its version.
build "$version" "$DIST/macos"
before=$(latest_run "$tag")
push_tag "$tag"
gh workflow run release.yml -R "$TAP" -f repo="$NAME" -f "tag=$tag"
dispatched=yes

while :; do
    found=$(latest_run "$tag") || {
        echo "release: gh run list failed; trying again" >&2
        found=
    }
    [ -n "$found" ] && [ "$found" != "$before" ] && run=$found && break
    [ $(($(date +%s) - started)) -lt "$limit" ] || {
        echo "release: no release.yml run of $NAME $tag in $TAP after ${limit}s" >&2
        exit 1
    }
    sleep "${RELEASE_POLL:-5}"
done
echo "release: waiting for https://github.com/$TAP/actions/runs/$run"
while :; do
    state=$(gh run view "$run" -R "$TAP" --json status,conclusion --jq '.status + " " + .conclusion') || {
        echo "release: gh run view $run failed; trying again" >&2
        state=
    }
    case "$state" in
    "completed success")
        ended=yes
        break
        ;;
    completed*)
        ended=yes
        echo "release: run $run of $NAME $tag ended '$state'" >&2
        gh run view "$run" -R "$TAP" --log-failed >&2 || true
        exit 1
        ;;
    esac
    [ $(($(date +%s) - started)) -lt "$limit" ] || {
        echo "release: run $run of $NAME $tag still '$state' after ${limit}s: gh run view $run -R $TAP" >&2
        exit 1
    }
    sleep "${RELEASE_POLL:-15}"
done

# What Homebrew installs on a Mac now: the archive the tap's formula names,
# at its sha256, holding a universal binary signed with Developer ID.
published=$(mktemp -d)
gh api "repos/$TAP/contents/Formula/$NAME.rb" -H 'Accept: application/vnd.github.raw' >"$published/$NAME.rb"
grep -qF "version \"$version\"" "$published/$NAME.rb" || {
    echo "release: $TAP's Formula/$NAME.rb is not $NAME $version after run $run" >&2
    exit 1
}
url=$(sed -n 's/^ *url "\(.*\)"$/\1/p' "$published/$NAME.rb" | head -n1)
want=$(sed -n 's/^ *sha256 "\(.*\)"$/\1/p' "$published/$NAME.rb" | head -n1)
curl -fsSL --retry 3 -o "$published/macos.tar.gz" "$url"
[ "$(sha "$published/macos.tar.gz")" = "$want" ] || {
    echo "release: $url is not the sha256 $want the formula names" >&2
    exit 1
}
tar -xzf "$published/macos.tar.gz" -C "$published" "$NAME"
signed "$published/$NAME" || {
    echo "release: the cut fails: the macOS binary $TAP's run $run published is not Developer ID signed" >&2
    exit 1
}
push_file "$BUCKET" "bucket/$NAME.json" "$DIST/$NAME.json" "$NAME $version"
echo "release: $NAME $tag is published ($(($(date +%s) - started))s)"
