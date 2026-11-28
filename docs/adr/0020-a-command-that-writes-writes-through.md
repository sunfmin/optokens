# A command that writes writes through

opcore 7278bfd (its decision record 6) stages every write of a Copy on demand: it reaches no 1Password until the tool pushes. optokens' `put`, `rm` and `mv` promise one write that reaches 1Password, or waits only when it cannot (decision records 16 and 17); staging them, an `optokens push` and a `--now` are a change of their own, on Felix's words of 2026-11-28 that opcore's record 6 quotes.

## Decision

- `put`, `rm`, `mv` and `init`'s probe open the Store `For::Writing` (`src/store.rs`): the Copy with a Life that never ends, which opcore writes through. Each syncs first, so its reads are as on demand: a Life that never ends syncs only with no Copy yet.
- `get`, `env` and `list` open it `For::Reading`: on demand, as decision record 19 says.
- Each command's cost is unchanged (`docs/budget.md`).

## Considered Options

- Stage, then `Copy::push` in the same command: a second `ItemsList` and `ItemsGetAll` after the Sync the command made, and a write 1Password refuses answers `Ok`, its refusal only a warning, so `put` could no longer refuse it.

Undo: open every Store on demand; writes then stage.
