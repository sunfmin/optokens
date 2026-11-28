#!/bin/sh
# The race of two cuts on one tap (the v0.1.13 cut, 2026-11-28, failed on it): release.sh push-file clones
# a bare repo, another cut pushes its own formula before this one pushes, and
# this one's formula still lands, on top of the other's. A stand-in `gh` clones
# the bare repo and, once, pushes the other cut's commit right after the clone.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

git init --quiet --bare -b main "$work/tap.git"
git clone --quiet "file://$work/tap.git" "$work/seed" 2>/dev/null
echo seed >"$work/seed/README"
git -C "$work/seed" add README
git -C "$work/seed" commit --quiet -m seed
git -C "$work/seed" push --quiet origin HEAD

mkdir "$work/bin"
cat >"$work/bin/gh" <<GH
#!/bin/sh
# gh repo clone <repo> <dir> -- <git clone args>
[ "\$1 \$2" = "repo clone" ] || { echo "stand-in gh: \$*" >&2; exit 2; }
dir=\$4
shift 5
git clone "\$@" "file://$work/tap.git" "\$dir"
if [ ! -e "$work/raced" ]; then
    touch "$work/raced"
    git clone --quiet "file://$work/tap.git" "$work/other"
    mkdir -p "$work/other/Formula"
    echo other >"$work/other/Formula/other.rb"
    git -C "$work/other" add Formula/other.rb
    git -C "$work/other" commit --quiet -m "other 1.0.0"
    git -C "$work/other" push --quiet origin HEAD
fi
GH
chmod +x "$work/bin/gh"

echo mine >"$work/optokens.rb"
PATH="$work/bin:$PATH" packaging/release.sh push-file sunfmin/homebrew-tap \
    Formula/optokens.rb "$work/optokens.rb" "optokens 9.9.9" 2>"$work/err" || {
    cat "$work/err" >&2
    echo "push_file_test: the push the other cut beat did not land" >&2
    exit 1
}
[ -e "$work/raced" ] || { echo "push_file_test: the other cut never raced" >&2; exit 1; }
grep -q 'rebasing' "$work/err" || { echo "push_file_test: the push was never rejected, so nothing raced" >&2; exit 1; }
got=$(git -C "$work/tap.git" log --format=%s main | tr '\n' ',')
[ "$got" = "optokens 9.9.9,other 1.0.0,seed," ] || {
    echo "push_file_test: the tap's history is '$got'" >&2
    exit 1
}
[ "$(git -C "$work/tap.git" show main:Formula/optokens.rb)" = mine ] || {
    echo "push_file_test: the tap's Formula/optokens.rb is not this cut's" >&2
    exit 1
}
echo "push_file_test: ok"
