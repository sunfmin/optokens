# The Copy syncs on demand

Supersedes decision record 15's Life of the Copy. Felix, 2026-11-28: 「那个副本按需连接，不用固定时间连，用户想同步了再去连一下」.

With a Life, every read past it reached 1Password and spent one of the account's daily requests, for no question the person asked; the account's 1000 ran out on 2026-11-27 (decision record 17).

## Decision

- `list`, `get` and `env` answer from the Copy with no network, however old it is, except a `get` or `env` of a Secret the Copy lacks, which syncs once, or no Copy yet.
- optokens reaches 1Password only with `--fresh`, at a write (`put`, `rm`, `mv`), at a Secret the Copy lacks, or with no Copy yet: opcore's Copy on demand (`Syncs::OnDemand`, opcore's decision record 5).
- A Secret the Copy lacks syncs once a process, then is answered or refused `not_found`. When that Sync fails, the read answers from the Copy with a warning naming why and the Copy's age.
- `--fresh` stays the way to see a change another host made: until then a read answers as the Copy holds it.
- Writes that wait (decision records 16 and 17) are pushed by the next Sync: `--fresh`, the next write, or a Secret the Copy lacks. While any wait, each read warns on stderr of how many, their file, and `optokens list --fresh`, which pushes them now (`store::PUSH`).

## Considered Options

- A longer Life: still one request per process past it.
- No Sync at a Secret the Copy lacks: one made on another host reads as absent until the person thinks of `--fresh`.

Undo: pass a Life to the Copy again in `src/store.rs`.

Note, 2026-11-28 (measured on `sesame-scratch` with `op service-account ratelimit`, opcore's decision record 7): the account's daily requests count each read and write the token spends, not one per process, so a read past the Life spent its reads, a Sync's at least one. The decision stands: on demand, the reads no one asked for are not made.
