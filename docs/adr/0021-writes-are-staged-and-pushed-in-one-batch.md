# Writes are staged on this host and pushed in one batch

Felix, 2026-11-28: 「用户积累了一定的更改之后，一定要用批量处理更新上去，尽量减少使用次数」. Builds on decision record 19 and opcore's decision record 6. Supersedes decision record 20 for `put`, `mv` and `rm`, which now stage; their `--now` and `init`'s probe keep its write through.

## Context

Each process that reaches 1Password spends one of the account's 1000 requests a day. With a Sync before every write, ten `put`s were ten processes, ten requests and ten writes.

## Decision

- `put`, `mv` and `rm` stage their change on this host, sealed in `copy.pending` beside the Copy, reaching no 1Password, and answer at once with `"pending": true`. A write is based on the Copy as held, its staged changes made; a value entered on the one-time link is staged the same way. `get`, `env` and `list` on this host show the change at once.
- `optokens push` sends every staged change in one process, one sign-in, its reads and writes the account's requests (decision record 23): each Secret's changes folded into one write (opcore's push), each made on the item as 1Password holds it then, then the pull of a Sync. `--fresh`, and a read of a Secret the Copy lacks, push the same way when anything is staged.
- `--now` on `put`, `mv` and `rm` syncs first and writes through, as decision record 20 has every write do: for a change another host needs right away. Changes staged before it are pushed by its Sync. It spends what a write did before.
- `list` marks a Secret with staged changes; each read warns on stderr of how many wait and that `optokens push` sends them. `optokens status` lists them: Secret, change, when.
- Changes reach 1Password and other hosts only at a push. Until then they live only on this host: a host lost before a push loses them.
- A staged write sees only what this host's Copy holds: a Secret another host made since its last Sync is created again by a staged `put`, and an untagged item of its title is not seen. `list --fresh` first, or `--now`, sees them.

## Considered Options

- A write through on every `put` when 1Password answers: one request a write, the cost this removes.
- `list --pending` beside `status`: two homes for one list.

Undo: every write's `--now` taken as given (`Writes::Now` in `src/commands.rs`'s `to_write` and `moved`).
