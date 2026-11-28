# optokens

Keeps an agent's secrets in a 1Password vault through a service account, and takes the secret values a person enters only through a one-time link served on the tailnet. It works on a Linux, macOS or Windows server with no desktop. It is a simpler sibling of mytokens and uses the same commands and words: Secret, Field, Profile, one-time link.

It reaches 1Password through [opcore](https://github.com/sunfmin/opcore), which runs 1Password's SDK Core inside it: no 1Password CLI is needed. What each command spends of the service account's reads and writes and the account's daily requests is `docs/budget.md`. Install on macOS or Linux with `brew install sunfmin/tap/optokens`; on Windows with `scoop bucket add sunfmin https://github.com/sunfmin/scoop-bucket` and then `scoop install optokens`. `put --fields` and `init` also need `tailscale`. A release is cut by `packaging/release.sh`.

The manual is `optokens --help`, and it is the only copy.

Build and check: `./gate.sh`.

End to end, against a real 1Password vault, checked there through the real `op` (outside the gate: it needs the network and a token): `scripts/e2e.sh <mytokens-profile> [vault]`. The Profile holds `OP_SERVICE_ACCOUNT_TOKEN` for the vault, `sesame-scratch` unless named; the script refuses unless optokens resolves that vault, writes only the item `e2e-<n>`, and removes it on any exit.

Several generated secrets go into one `put` as `--field-from-pipe Label=<(command)`, one per value; never `Label=$(command)`, which puts the value itself on the command line (and is refused).
