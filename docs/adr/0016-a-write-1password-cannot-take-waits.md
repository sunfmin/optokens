# A write 1Password cannot take after its Sync waits, and says so

Felix, 2026-11-27, opcore's decision record 3, the day the account's daily requests ran out: 「写入，应该让他能写，之后有额度了，同步上去就行了」. optokens#33 moves opcore's pin onto it.

## Decision

- `put`, `mv` and `rm` still sync first and fail when the Sync fails (decision record 15): no write is based on an item this process has not seen in the vault, and a `put` of a new name cannot make a second item of a title another host made.
- After that Sync, a write opcore answers as waiting (the rate limit, the network, 1Password down) is no failure: it waits sealed in `copy.pending`, opcore's warning goes to stderr, and the answer carries `"pending": true` (`false` for every write that went through, or no write). An agent that reads only stdout still learns that the vault does not hold it yet.
- `init --check`'s probe that waits is refused at its check (`probe_written`, `probe_removed`): a write that reached only the local file proves no grant. The next check's Sync pushes it and that check writes over it.
- `copy.pending` is sealed under the token as the Copy is, so decision record 2's invariant stands; it is never rebuilt, so the account topic says not to delete it.

## Considered Options

- A write whose Sync fails for the same reasons waits too, on the Copy as held: what Felix's words ask for, and what a rate-limited day needs most. Not taken in this bump: it gives up "a write is never based on a stale item", and a `put` of a name another host made since could create a second item; it is the owner's call, kept for its own issue.
- Answer a write that waits as `vault_failed`: the write is in the log and will land, so a refusal would lie, and an agent's retry would queue it twice.

Undo: drop `pending` from the answers and `Written` from `store.rs`; writes then answer as before, opcore still queueing them.
