#!/bin/sh
# The end-to-end check against a real 1Password vault, optokens reaching it
# through opcore and the script checking it through the real `op`:
# put (a Meta among it) -> list -> get -> env -> put again (upsert) -> `op read op://` -> a put over the item retitled as
# an earlier optokens titled it -> a put over the Description in the section, as before the notes -> a put of two pipes
# -> a put over mytokens' tags and section -> put --description "" -> staged puts and an rm, `status`, a Field both this
# host and the vault changed, one `push` -> rm, each answer checked, the item and its field
# types checked in the vault through `op item get`, `ps` sampled during the put for the value, and the config directory
# (the sealed Copy) searched for it. Outside the gate: it needs the network and a token.
#
#   scripts/e2e.sh <optokens-profile> [vault]
#
# The optokens Profile (read by the installed optokens) holds
# OP_SERVICE_ACCOUNT_TOKEN, a service account's token for
# the vault (default `sesame-scratch`). The token stays in this process's
# environment. The script writes only the items `e2e-<n>`, `e2e-<n>-new` and
# `e2e-<n>-gone` and removes them on any exit; it refuses to run unless optokens resolves the vault named.
set -eu

profile=${1:?usage: scripts/e2e.sh <optokens-profile> [vault]}
vault=${2:-sesame-scratch}
cd "$(dirname "$0")/.."
[ -d "$HOME/.cargo/bin" ] && PATH="$HOME/.cargo/bin:$PATH"

say() { printf '\n$ %s\n' "$*"; }
fail() { printf 'e2e: FAIL: %s\n' "$*" >&2; exit 1; }
check() { # <what> <jq filter that must be true> <json>
    printf '%s' "$3" | jq -e "$2" >/dev/null || fail "$1"
    printf 'ok: %s\n' "$1"
}

# Release: the 1Password Core runs in wasmi, minutes per sign-in in a debug build.
cargo build --release --quiet
bin=$PWD/target/release/optokens
# What follows has the token: from here on nothing prints a value.
# The installed optokens, before XDG_CONFIG_HOME moves to the scratch config;
# without OP_SERVICE_ACCOUNT_TOKEN, which it would take over its own token file.
OP_SERVICE_ACCOUNT_TOKEN=$(env -u OP_SERVICE_ACCOUNT_TOKEN optokens get "$profile" --field OP_SERVICE_ACCOUNT_TOKEN) ||
    fail "the optokens Profile $profile has no OP_SERVICE_ACCOUNT_TOKEN"
[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ] || fail "Profile $profile has no OP_SERVICE_ACCOUNT_TOKEN"
export OP_SERVICE_ACCOUNT_TOKEN

export XDG_CONFIG_HOME="$HOME/.config/optokens-e2e"
mkdir -p "$XDG_CONFIG_HOME/optokens"
printf '%s\n' "$vault" >"$XDG_CONFIG_HOME/optokens/vault"

say optokens doctor
doctor=$("$bin" doctor || true)
printf '%s\n' "$doctor" | jq -c '.found | {token, vault}'
resolved=$(printf '%s' "$doctor" | jq -r '.found.vault.name')
[ "$resolved" = "$vault" ] || fail "optokens would use the vault '$resolved', not '$vault': refusing to write"
op vault get "$vault" --format json | jq -e --arg v "$vault" '.name == $v' >/dev/null ||
    fail "the token cannot read the vault '$vault'"

service=e2e-$(date +%s)
title=$service
name=$service/default
new=$service-new
gone=$service-gone
cleanup() {
    rc=$?
    for s in "$service" "$new" "$gone"; do
        "$bin" rm --now "$s" >/dev/null 2>&1 || op item delete "$s" --vault "$vault" >/dev/null 2>&1 || true
    done
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
        '. == {"fields.A":"STRING","fields.TOKEN":"CONCEALED","optokens.service":"STRING","optokens.account":"STRING","optokens.kind":"STRING","optokens.shape":"STRING","optokens.meta":"STRING"}' "$map"
}

# ps sampled in a loop for as long as the put runs: the value must never show.
# `case` is the shell's own, so the value is in no process's argv here either.
argv_watch() {
    samples=0 seen_put=0 hits=0
    while [ ! -e "$XDG_CONFIG_HOME/put.done" ]; do
        args=$(ps -axo args)
        samples=$((samples + 1))
        case $args in *"$bin put"*) seen_put=$((seen_put + 1)) ;; esac
        case $args in *"$value"*) hits=$((hits + 1)) ;; esac
    done
    printf '%s %s %s\n' "$samples" "$seen_put" "$hits"
}
rm -f "$XDG_CONFIG_HOME/put.done"
argv_watch >"$XDG_CONFIG_HOME/argv" &
watcher=$!

say "openssl rand -hex 16 | optokens put $service --description 'optokens e2e' --meta '{ \"e2e\": 1 }' --set A=1 --field-from-stdin TOKEN"
out=$(printf '%s' "$value" | "$bin" put --now "$service" --description "optokens e2e" --meta '{ "e2e": 1 }' --set "A=1" --field-from-stdin TOKEN) ||
    { rc=$?; printf '%s\n' "$out"; fail "put exited $rc"; }
touch "$XDG_CONFIG_HOME/put.done"
wait "$watcher"
echo "$out"
check "put created it" '.secret == "'"$name"'" and .changed and .kind == "static" and .fields == ["A","TOKEN"]' "$out"
read -r samples seen_put hits <"$XDG_CONFIG_HOME/argv"
rm -f "$XDG_CONFIG_HOME/argv" "$XDG_CONFIG_HOME/put.done"
printf 'argv check: %s ps samples during the put, %s with the put running, %s with the value\n' "$samples" "$seen_put" "$hits"
[ "$seen_put" -gt 0 ] || fail "argv check: no sample caught the put running"
[ "$hits" = 0 ] || fail "argv check: the value was in a command line"
! grep -rqF -e "$value" -e "$OP_SERVICE_ACCOUNT_TOKEN" "$XDG_CONFIG_HOME/optokens" || fail "the value or the token is in the config directory in plaintext"
echo "ok: the config directory holds neither the value nor the token in plaintext"

say "op item get $title --vault $vault --format json  (values masked)"
item=$(op item get "$title" --vault "$vault" --format json)
printf '%s' "$item" | jq -c '{title, category, tags, sections: [.sections[]? | .label], fields: [.fields[] | select(.section) | {section: .section.label, label, type, value: (if .type == "CONCEALED" then "***" else .value end)}]}'
check "the item is titled, tagged, a secure note" '.title == "'"$title"'" and .category == "SECURE_NOTE" and (.tags | index("optokens"))' "$item"
check "values in section fields, metadata in section optokens" '
  [.fields[] | select(.section) | [.section.label, .label]] | sort
  == [["fields","A"],["fields","TOKEN"],["optokens","account"],["optokens","kind"],["optokens","meta"],["optokens","service"],["optokens","shape"]]' "$item"
check "service, account default, kind static, shape fields, the Meta compact" '
  [.fields[] | select(.section.label == "optokens") | {(.label): .value}] | add
  == {"service":"'"$service"'","account":"default","kind":"static","shape":"fields","meta":"{\"e2e\":1}"}' "$item"
# notes <item json>: the item's notes, the Description's home.
notes() { printf '%s' "$1" | jq -c '[.fields[] | select(.purpose == "NOTES") | .value]'; }
check "the description is the notes" '[.fields[] | select(.purpose == "NOTES") | .value] == ["optokens e2e"]' "$item"
say "op item list --vault $vault --format json  (this item's title and additional_information)"
listed=$(op item list --vault "$vault" --format json | jq -c --arg t "$title" '[.[] | select(.title == $t) | {title, additional_information}]')
echo "$listed"
check "1Password's list shows the description under the title" '. == [{"title":"'"$title"'","additional_information":"optokens e2e"}]' "$listed"
printf '%s' "$item" | jq -e --arg v "$value" '[.fields[] | select(.section.label == "fields" and .label == "TOKEN")][0].value == $v' >/dev/null ||
    fail "the vault's TOKEN is not the value piped in"
echo "ok: the vault's TOKEN is the value piped in"
types "after the put"

say "optokens list"
run list
printf '%s' "$out" | jq -c --arg s "$service" '{secrets: [.secrets[] | select(.service == $s)], total: (.secrets | length)}'
check "list shows it, no value" '[.secrets[] | select(.service == "'"$service"'")] == [{"service":"'"$service"'","account":"default","kind":"static","description":"optokens e2e","meta":{"e2e":1},"fields":["A","TOKEN"]}]' "$out"

say "optokens get $service --field TOKEN  (compared, not printed)"
got=$("$bin" get "$service" --field TOKEN) || fail "get --field TOKEN exited $?"
[ "$got" = "$value" ] || fail "get --field TOKEN is not the value"
echo "ok: get --field TOKEN is the value"

say "optokens get $service --json  (TOKEN masked)"
run get "$service" --json
printf '%s' "$out" | mask
check "get --json" '.service == "'"$service"'" and .account == "default" and .kind == "static" and .description == "optokens e2e" and .meta == {"e2e":1} and .fields.A == "1" and (.fields | keys_unsorted) == ["A","TOKEN"]' "$out"
printf '%s' "$out" | jq -e --arg v "$value" '.fields.TOKEN == $v' >/dev/null || fail "get --json TOKEN is not the value"

say "optokens env $service  (TOKEN masked)"
run env "$service"
printf '%s\n' "$out" | sed "s/^export TOKEN=.*/export TOKEN='***'/"
[ "$(A=; TOKEN=; eval "$out"; printf '%s|%s' "$A" "$TOKEN")" = "1|$value" ] || fail "env's exports do not give A and TOKEN"
echo "ok: eval of env sets A=1 and TOKEN to the value"

say "optokens put $service --set A=2"
run put --now "$service" --set "A=2"
echo "$out"
check "put again changed A" '.changed and .fields == ["A","TOKEN"]' "$out"
run get "$service" --json
printf '%s' "$out" | mask
printf '%s' "$out" | jq -e --arg v "$value" '.fields.A == "2" and .fields.TOKEN == $v' >/dev/null || fail "upsert lost TOKEN or did not set A"
echo "ok: A is 2, TOKEN kept"
say "op item get $title --vault $vault --format json  (types)"
item=$(op item get "$title" --vault "$vault" --format json)
types "after the upsert"
run put --now "$service" --set "A=2"
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
run put --now "$service" --set "A=2"
echo "$out"
check "put over the old title rewrites it" '.changed and .fields == ["A","TOKEN"]' "$out"
item=$(op item get "$id" --vault "$vault" --format json)
check "the same item, retitled $title, its service and account back" '.id == "'"$id"'" and .title == "'"$title"'"' "$item"
types "after the retitle"
run get "$service" --json
printf '%s' "$out" | jq -e --arg v "$value" '.fields.A == "2" and .fields.TOKEN == $v and .description == "optokens e2e" and .meta == {"e2e":1}' >/dev/null ||
    fail "the retitle changed a value, the description or the Meta"
echo "ok: A, TOKEN, the description and the Meta are as they were"

say "op item edit $id < its template, the description in section optokens, the notes another's  (as optokens wrote it before the notes)"
op item get "$id" --vault "$vault" --format json |
    jq '.fields |= map(if .purpose == "NOTES" then .value = "another note" else . end)
        | .fields += [{"id":"optokens.description","section":{"id":"optokens"},"type":"STRING","label":"description","value":"optokens e2e"}]' |
    op item edit "$id" --vault "$vault" --format json >/dev/null
item=$(op item get "$id" --vault "$vault" --format json)
echo "notes: $(notes "$item"), section optokens: $(printf '%s' "$item" | jq -c '[.fields[] | select(.section.label == "optokens") | .label]')"
check "the description is in the section" '[.fields[] | select(.section.label == "optokens" and .label == "description") | .value] == ["optokens e2e"]' "$item"
run list
check "list reads the section's description" '[.secrets[] | select(.service == "'"$service"'") | .description] == ["optokens e2e"]' "$out"
say "optokens put $service --set A=2  (over it: the same Secret)"
run put --now "$service" --set "A=2"
echo "$out"
check "put rewrites the earlier layout" '.changed' "$out"
item=$(op item get "$id" --vault "$vault" --format json)
echo "notes: $(notes "$item"), section optokens: $(printf '%s' "$item" | jq -c '[.fields[] | select(.section.label == "optokens") | .label]')"
check "the description moved into the notes, the section field gone" \
    '([.fields[] | select(.purpose == "NOTES") | .value] == ["optokens e2e"]) and ([.fields[] | select(.section.label == "optokens" and .label == "description")] == [])' "$item"
run get "$service" --json
check "get --json gives the same description" '.description == "optokens e2e"' "$out"

pipe1=$(openssl rand -hex 16) pipe2=$(openssl rand -base64 24)
say "optokens put $service --field-from-pipe PIPE1=<(printf ...) --field-from-pipe PIPE2=<(printf ...)  (bash; values from openssl rand)"
# The values reach bash in its environment, which it drops before it runs
# optokens: only its builtin printf holds them, and argv only /dev/fd/N.
out=$(P1=$pipe1 P2=$pipe2 /bin/bash -c 'a=$P1 b=$P2; unset P1 P2; "$0" put --now "$1" --field-from-pipe PIPE1=<(printf "%s\n" "$a") --field-from-pipe PIPE2=<(printf %s "$b")' "$bin" "$service") ||
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

say "op item edit $id < its template, tagged mytokens and mytokens-digest-e2e, with a section mytokens  (as mytokens writes it)"
# A whole template on stdin, as mytokens writes: an assignment such as
# 'mytokens.origin[text]=e2e' makes op itself reorder the fields.
op item get "$id" --vault "$vault" --format json |
    jq '.tags += ["mytokens","mytokens-digest-e2e"] | .sections += [{"id":"mytokens","label":"mytokens"}]
        | .fields += [{"id":"mytokens.origin","section":{"id":"mytokens"},"type":"STRING","label":"origin","value":"e2e"}]' |
    op item edit "$id" --vault "$vault" --format json >/dev/null
item=$(op item get "$id" --vault "$vault" --format json)
printf '%s' "$item" | jq -c '{tags, sections: [.sections[]? | .label]}'
run list
check "a section optokens does not know is read past" '[.secrets[] | select(.service == "'"$service"'") | .fields] == [["A","TOKEN","PIPE1","PIPE2"]]' "$out"
say "optokens put $service --set A=3, then --set NEW=4"
run put --now "$service" --set "A=3"
check "put changed A, the order kept" '.changed and .fields == ["A","TOKEN","PIPE1","PIPE2"]' "$out"
run put --now "$service" --set "NEW=4"
check "a new Field goes last" '.changed and .fields == ["A","TOKEN","PIPE1","PIPE2","NEW"]' "$out"
item=$(op item get "$id" --vault "$vault" --format json)
printf '%s' "$item" | jq -c '{tags, sections: [.sections[]? | .label], mytokens: [.fields[] | select(.section.label == "mytokens") | {(.label): .value}]}'
check "put kept the tags it does not own" '(.tags | sort) == ["mytokens","mytokens-digest-e2e","optokens"]' "$item"
check "put kept the section mytokens and its field" '[.fields[] | select(.section.label == "mytokens") | {(.label): .value}] == [{"origin":"e2e"}]' "$item"
check "the vault's fields in their order" '[.fields[] | select(.section.label == "fields") | .label] == ["A","TOKEN","PIPE1","PIPE2","NEW"]' "$item"
run env "$service"
[ "$(printf '%s\n' "$out" | sed 's/=.*//')" = "$(printf 'export %s\n' A TOKEN PIPE1 PIPE2 NEW)" ] || fail "env does not print A TOKEN PIPE1 PIPE2 NEW in order"
echo "ok: env prints A TOKEN PIPE1 PIPE2 NEW in order"

say "optokens put $service --description ''"
run put --now "$service" --description ""
check "an empty description clears it" '.changed' "$out"
item=$(op item get "$id" --vault "$vault" --format json)
echo "notes: $(notes "$item")"
check "the notes are empty" '[.fields[] | select(.purpose == "NOTES") | .value // ""] == [""]' "$item"
run list
check "list shows no description" '[.secrets[] | select(.service == "'"$service"'") | .description] == [null]' "$out"

say "optokens put --now $gone --set G=1  (there to be removed by a staged rm)"
run put --now "$gone" --set "G=1"
check "put --now created $gone" '.changed and .pending == false' "$out"
say "optokens put $service --set A=5; put $service --set B=6; put $new --set X=1; rm $gone  (staged)"
for args in "put $service --set A=5" "put $service --set B=6" "put $new --set X=1" "rm $gone"; do
    # shellcheck disable=SC2086 # each a word list of names and KEY=value, no spaces in them
    run $args
    check "$args is staged" '.pending == true' "$out"
done
read_a=$(op read "op://$vault/$title/fields/A")
[ "$read_a" = 3 ] || fail "a staged put reached the vault: A is '$read_a', not 3"
! op item get "$new" --vault "$vault" >/dev/null 2>&1 || fail "a staged put of $new created it in the vault"
op item get "$gone" --vault "$vault" >/dev/null 2>&1 || fail "a staged rm of $gone removed it from the vault"
echo "ok: the vault holds none of the staged changes"
run get "$service" --field A
[ "$out" = 5 ] || fail "get on this host does not show the staged A=5"
echo "ok: get on this host shows the staged change"
say "optokens status"
run status
echo "$out"
check "status lists the four staged changes, oldest first" '[.pending[] | [.secret, .item, .change]] == [["'"$name"'","'"$title"'","edit"],["'"$name"'","'"$title"'","edit"],["'"$new"'/default","'"$new"'","create"],[null,"'"$gone"'","delete"]]' "$out"
say "op item edit $id fields.A=9 fields.NEW=8  (another host changes A, which this host staged, and NEW, which it did not)"
op item edit "$id" --vault "$vault" 'fields.A=9' 'fields.NEW=8' >/dev/null
say "optokens push"
out=$("$bin" push 2>"$XDG_CONFIG_HOME/push.err") || { rc=$?; cat "$XDG_CONFIG_HOME/push.err"; fail "push exited $rc"; }
pushed_err=$(cat "$XDG_CONFIG_HOME/push.err")
rm -f "$XDG_CONFIG_HOME/push.err"
echo "$out"
printf '%s
' "$pushed_err"
check "push sent all four, none left" '. == {"pushed":4,"pending":0}' "$out"
printf '%s
' "$pushed_err" | grep '^warning:' | grep -qF "$service" || fail "push named no Field both changed in a warning: line"
echo "ok: push named the Field both changed in a warning: line"
item=$(op item get "$id" --vault "$vault" --format json)
check "the vault's item: A this host's, B added, NEW the other host's" \
    '([.fields[] | select(.section.label == "fields") | {(.label): .value}] | add) as $f | $f.A == "5" and $f.B == "6" and $f.NEW == "8"' "$item"
item=$(op item get "$new" --vault "$vault" --format json)
check "the vault holds $new, X=1" '[.fields[] | select(.section.label == "fields") | {(.label): .value}] == [{"X":"1"}]' "$item"
! op item get "$gone" --vault "$vault" >/dev/null 2>&1 || fail "push did not remove $gone"
echo "ok: push removed $gone"
run status
check "status is empty after the push" '.pending == []' "$out"
run get "$service" --field NEW
[ "$out" = 8 ] || fail "the push's Sync did not bring the other host's NEW=8 into the Copy"
echo "ok: the push's Sync brought the other host's NEW into the Copy"
run rm --now "$new"
check "rm --now removed $new" '.changed' "$out"

say "optokens rm $service"
run rm --now "$service"
echo "$out"
check "rm removed it" '.secret == "'"$name"'" and .changed' "$out"
run rm --now "$service"
check "rm again is no fault" '.changed == false' "$out"
if "$bin" get "$service" --json >/dev/null 2>"$XDG_CONFIG_HOME/get.err"; then fail "get still finds it"; fi
check "get then refuses not_found" '.error[0].kind == "not_found"' "$(cat "$XDG_CONFIG_HOME/get.err")"
rm -f "$XDG_CONFIG_HOME/get.err"
