#!/bin/sh
# The end-to-end check against a real 1Password vault and the real `op`:
# put -> list -> get -> env -> put again (upsert) -> `op read op://` -> a put over the item retitled as
# an earlier optokens titled it -> a put of two pipes -> rm, each answer checked, the item and its field
# types checked in the vault through `op item get`, and `ps` sampled during the put for the value. Outside the gate: it needs the network and a token.
#
#   scripts/e2e.sh <mytokens-profile> [vault]
#
# The Profile holds OP_SERVICE_ACCOUNT_TOKEN, a service account's token for
# the vault (default `sesame-scratch`). The token stays in this process's
# environment. The script writes only the item `e2e-<n>` and removes
# it on any exit; it refuses to run unless optokens resolves the vault named.
set -eu

profile=${1:?usage: scripts/e2e.sh <mytokens-profile> [vault]}
vault=${2:-sesame-scratch}
cd "$(dirname "$0")/.."
[ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH"

say() { printf '\n$ %s\n' "$*"; }
fail() { printf 'e2e: FAIL: %s\n' "$*" >&2; exit 1; }
check() { # <what> <jq filter that must be true> <json>
    printf '%s' "$3" | jq -e "$2" >/dev/null || fail "$1"
    printf 'ok: %s\n' "$1"
}

cargo build --quiet
bin=$PWD/target/debug/optokens
# What follows has the token: from here on nothing prints a value.
eval "$(mytokens env "$profile")"
[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ] || fail "Profile $profile has no OP_SERVICE_ACCOUNT_TOKEN"
export OP_SERVICE_ACCOUNT_TOKEN

export XDG_CONFIG_HOME="$HOME/.config/optokens-e2e"
mkdir -p "$XDG_CONFIG_HOME/optokens"
printf '%s\n' "$vault" >"$XDG_CONFIG_HOME/optokens/vault"

say optokens doctor
doctor=$("$bin" doctor || true)
printf '%s\n' "$doctor" | jq -c '.found | {op, token, vault}'
resolved=$(printf '%s' "$doctor" | jq -r '.found.vault.name')
[ "$resolved" = "$vault" ] || fail "optokens would use the vault '$resolved', not '$vault': refusing to write"
op vault get "$vault" --format json | jq -e --arg v "$vault" '.name == $v' >/dev/null ||
    fail "the token cannot read the vault '$vault'"

service=e2e-$(date +%s)
title=$service
name=$service/default
cleanup() {
    rc=$?
    "$bin" rm "$service" >/dev/null 2>&1 || op item delete "$title" --vault "$vault" >/dev/null 2>&1 || true
    left=$(op item list --vault "$vault" --format json | jq -r '[.[] | select(.title | startswith("e2e-"))] | length')
    printf '\ne2e: items titled e2e-* left in %s: %s\n' "$vault" "$left"
    [ "$rc" = 0 ] && [ "$left" = 0 ] && echo "e2e: ok"
    [ "$left" = 0 ] || rc=1
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

value=$(openssl rand -hex 16)
# optokens <args>: its stdout into $out; on a failure, what it said and its code.
run() {
    out=$("$bin" "$@") || { rc=$?; printf '%s\n' "$out"; fail "optokens $* exited $rc"; }
}
mask() { jq -c '(.fields.TOKEN? // empty) |= "***"'; }
# The field types of the vault's item ($item): --set plain, stdin concealed.
types() { # <when>
    map=$(printf '%s' "$item" | jq -c '[.fields[] | select(.section) | {(.section.label + "." + .label): .type}] | add')
    echo "$map"
    check "types $1: A STRING, TOKEN CONCEALED, metadata STRING" \
        '. == {"fields.A":"STRING","fields.TOKEN":"CONCEALED","optokens.service":"STRING","optokens.account":"STRING","optokens.kind":"STRING","optokens.shape":"STRING","optokens.description":"STRING"}' "$map"
}

# ps sampled in a loop for as long as the put runs: the value must never show.
# `case` is the shell's own, so the value is in no process's argv here either.
argv_watch() {
    samples=0 seen_op=0 hits=0
    while [ ! -e "$XDG_CONFIG_HOME/put.done" ]; do
        args=$(ps -axo args)
        samples=$((samples + 1))
        case $args in *"op item"*) seen_op=$((seen_op + 1)) ;; esac
        case $args in *"$value"*) hits=$((hits + 1)) ;; esac
    done
    printf '%s %s %s\n' "$samples" "$seen_op" "$hits"
}
rm -f "$XDG_CONFIG_HOME/put.done"
argv_watch >"$XDG_CONFIG_HOME/argv" &
watcher=$!

say "openssl rand -hex 16 | optokens put $service --description 'optokens e2e' --set A=1 --field-from-stdin TOKEN"
out=$(printf '%s' "$value" | "$bin" put "$service" --description "optokens e2e" --set "A=1" --field-from-stdin TOKEN) ||
    { rc=$?; printf '%s\n' "$out"; fail "put exited $rc"; }
touch "$XDG_CONFIG_HOME/put.done"
wait "$watcher"
echo "$out"
check "put created it" '.secret == "'"$name"'" and .changed and .kind == "static" and .fields == ["A","TOKEN"]' "$out"
read -r samples seen_op hits <"$XDG_CONFIG_HOME/argv"
rm -f "$XDG_CONFIG_HOME/argv" "$XDG_CONFIG_HOME/put.done"
printf 'argv check: %s ps samples during the put, %s with an `op item` process, %s with the value\n' "$samples" "$seen_op" "$hits"
[ "$seen_op" -gt 0 ] || fail "argv check: no sample caught op running"
[ "$hits" = 0 ] || fail "argv check: the value was in a command line"

say "op item get $title --vault $vault --format json  (values masked)"
item=$(op item get "$title" --vault "$vault" --format json)
printf '%s' "$item" | jq -c '{title, category, tags, sections: [.sections[]? | .label], fields: [.fields[] | select(.section) | {section: .section.label, label, type, value: (if .type == "CONCEALED" then "***" else .value end)}]}'
check "the item is titled, tagged, a secure note" '.title == "'"$title"'" and .category == "SECURE_NOTE" and (.tags | index("optokens"))' "$item"
check "values in section fields, metadata in section optokens" '
  [.fields[] | select(.section) | [.section.label, .label]] | sort
  == [["fields","A"],["fields","TOKEN"],["optokens","account"],["optokens","description"],["optokens","kind"],["optokens","service"],["optokens","shape"]]' "$item"
check "service, account default, kind static, shape fields, the description" '
  [.fields[] | select(.section.label == "optokens") | {(.label): .value}] | add
  == {"service":"'"$service"'","account":"default","kind":"static","shape":"fields","description":"optokens e2e"}' "$item"
printf '%s' "$item" | jq -e --arg v "$value" '[.fields[] | select(.section.label == "fields" and .label == "TOKEN")][0].value == $v' >/dev/null ||
    fail "the vault's TOKEN is not the value piped in"
echo "ok: the vault's TOKEN is the value piped in"
types "after the put"

say "optokens list"
run list
printf '%s' "$out" | jq -c --arg s "$service" '{secrets: [.secrets[] | select(.service == $s)], total: (.secrets | length)}'
check "list shows it, no value" '[.secrets[] | select(.service == "'"$service"'")] == [{"service":"'"$service"'","account":"default","kind":"static","description":"optokens e2e","fields":["A","TOKEN"]}]' "$out"

say "optokens get $service --field TOKEN  (compared, not printed)"
got=$("$bin" get "$service" --field TOKEN) || fail "get --field TOKEN exited $?"
[ "$got" = "$value" ] || fail "get --field TOKEN is not the value"
echo "ok: get --field TOKEN is the value"

say "optokens get $service --json  (TOKEN masked)"
run get "$service" --json
printf '%s' "$out" | mask
check "get --json" '.service == "'"$service"'" and .account == "default" and .kind == "static" and .description == "optokens e2e" and .fields.A == "1" and (.fields | keys_unsorted) == ["A","TOKEN"]' "$out"
printf '%s' "$out" | jq -e --arg v "$value" '.fields.TOKEN == $v' >/dev/null || fail "get --json TOKEN is not the value"

say "optokens env $service  (TOKEN masked)"
run env "$service"
printf '%s\n' "$out" | sed "s/^export TOKEN=.*/export TOKEN='***'/"
[ "$(A=; TOKEN=; eval "$out"; printf '%s|%s' "$A" "$TOKEN")" = "1|$value" ] || fail "env's exports do not give A and TOKEN"
echo "ok: eval of env sets A=1 and TOKEN to the value"

say "optokens put $service --set A=2"
run put "$service" --set "A=2"
echo "$out"
check "put again changed A" '.changed and .fields == ["A","TOKEN"]' "$out"
run get "$service" --json
printf '%s' "$out" | mask
printf '%s' "$out" | jq -e --arg v "$value" '.fields.A == "2" and .fields.TOKEN == $v' >/dev/null || fail "upsert lost TOKEN or did not set A"
echo "ok: A is 2, TOKEN kept"
say "op item get $title --vault $vault --format json  (types)"
item=$(op item get "$title" --vault "$vault" --format json)
types "after the upsert"
run put "$service" --set "A=2"
check "the same put again writes nothing" '.changed == false' "$out"

say "op read op://$vault/$title/fields/A"
read_a=$(op read "op://$vault/$title/fields/A")
echo "$read_a"
[ "$read_a" = 2 ] || fail "op read op://$vault/$title/fields/A is '$read_a', not 2"
echo "ok: op:// reads a Field of the item put wrote"

id=$(printf '%s' "$item" | jq -r .id)
say "op item edit $id --title $name, its service and account deleted  (as an earlier optokens wrote it)"
op item edit "$id" --vault "$vault" --title "$name" 'optokens.service[delete]' 'optokens.account[delete]' >/dev/null
item=$(op item get "$id" --vault "$vault" --format json)
check "the item is titled $name, no service or account" '.title == "'"$name"'" and ([.fields[] | select(.section.label == "optokens") | .label] | index("service") == null)' "$item"
run get "$service" --field A
[ "$out" = 2 ] || fail "get of the old-titled item is not A=2"
echo "ok: get finds the old-titled item"
say "optokens put $service --set A=2  (over the old-titled item)"
run put "$service" --set "A=2"
echo "$out"
check "put over the old title rewrites it" '.changed and .fields == ["A","TOKEN"]' "$out"
item=$(op item get "$id" --vault "$vault" --format json)
check "the same item, retitled $title, its service and account back" '.id == "'"$id"'" and .title == "'"$title"'"' "$item"
types "after the retitle"
run get "$service" --json
printf '%s' "$out" | jq -e --arg v "$value" '.fields.A == "2" and .fields.TOKEN == $v and .description == "optokens e2e"' >/dev/null ||
    fail "the retitle changed a value or the description"
echo "ok: A, TOKEN and the description are as they were"

pipe1=$(openssl rand -hex 16) pipe2=$(openssl rand -base64 24)
say "optokens put $service --field-from-pipe PIPE1=<(printf ...) --field-from-pipe PIPE2=<(printf ...)  (bash; values from openssl rand)"
# The values reach bash in its environment, which it drops before it runs
# optokens: only its builtin printf holds them, and argv only /dev/fd/N.
out=$(P1=$pipe1 P2=$pipe2 /bin/bash -c 'a=$P1 b=$P2; unset P1 P2; "$0" put "$1" --field-from-pipe PIPE1=<(printf "%s\n" "$a") --field-from-pipe PIPE2=<(printf %s "$b")' "$bin" "$service") ||
    { rc=$?; printf '%s\n' "$out"; fail "the two-pipe put exited $rc"; }
echo "$out"
check "the two-pipe put added both" '.changed and .fields == ["A","TOKEN","PIPE1","PIPE2"]' "$out"
item=$(op item get "$title" --vault "$vault" --format json)
check "PIPE1 and PIPE2 are CONCEALED in the vault" \
    '[.fields[] | select(.section.label == "fields" and (.label | startswith("PIPE"))) | .type] == ["CONCEALED","CONCEALED"]' "$item"
printf '%s' "$item" | jq -e --arg a "$pipe1" --arg b "$pipe2" \
    '([.fields[] | select(.section.label == "fields") | {(.label): .value}] | add) as $f | $f.PIPE1 == $a and $f.PIPE2 == $b' >/dev/null ||
    fail "the vault's PIPE1 or PIPE2 is not the value its pipe carried"
echo "ok: the vault's PIPE1 and PIPE2 are the values their pipes carried"

say "optokens rm $service"
run rm "$service"
echo "$out"
check "rm removed it" '.secret == "'"$name"'" and .changed' "$out"
run rm "$service"
check "rm again is no fault" '.changed == false' "$out"
if "$bin" get "$service" --json >/dev/null 2>"$XDG_CONFIG_HOME/get.err"; then fail "get still finds it"; fi
check "get then refuses not_found" '.error[0].kind == "not_found"' "$(cat "$XDG_CONFIG_HOME/get.err")"
rm -f "$XDG_CONFIG_HOME/get.err"
