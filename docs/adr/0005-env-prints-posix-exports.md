# `env` prints POSIX `export` lines on every OS

`env` prints `export NAME='value'` lines on every OS, for sh, bash and zsh, Git Bash and WSL on Windows included, as mytokens prints them (ADR 0001). There is no PowerShell form yet: `env --shell powershell` is added when someone needs it.

Undo: add the form; the POSIX one stays the default.
