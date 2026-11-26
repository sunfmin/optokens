# optokens

Keeps an agent's secrets in a 1Password vault through a service account, and takes the secret values a person enters only through a one-time link served on the tailnet. It works on a Linux, macOS or Windows server with no desktop. It is a simpler sibling of mytokens and uses the same commands and words: Secret, Field, Profile, one-time link.

Install on macOS or Linux with `brew install sunfmin/tap/optokens`, which installs the 1Password CLI `op` with it; on Windows with `scoop bucket add sunfmin https://github.com/sunfmin/scoop-bucket` and then `scoop install optokens`. `put --fields` and `init` also need `tailscale`. A release is cut by `packaging/release.sh`.

The manual is `optokens --help`, and it is the only copy.

Build and check: `./gate.sh`.
