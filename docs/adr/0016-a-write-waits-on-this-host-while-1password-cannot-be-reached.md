# A write waits on this host while 1Password cannot be reached

Felix, 2026-11-27, the day the 1Password account's daily requests ran out
(1000 of 1000, 14 h to reset) and no Secret could be stored on any host:
「写入，应该让他能写，之后有额度了，同步上去就行了」.

## Decision

- `put` and `rm` sync first, as before (decision record 15). When the Sync
  or the write cannot reach 1Password (its rate limit, the network,
  1Password unavailable: opcore's `Error::is_transient`), the write goes
  on from the Copy as held and is kept on this host as an opcore pending
  write (opcore's decision record 3), sealed in `copy.pending` beside the
  Copy. It answers as usual, plus `"pending": true`, and stderr says why
  and that the next command that reaches 1Password writes it.
- A pending `put` holds what it changes of the item as read, so its replay
  merges over the vault's item as it is then: a Field another host changed
  meanwhile is kept; one both changed takes this host's value, with a
  `warning:` naming it.
- `get`, `env` and `list` on this host answer the pending result at once;
  `list` marks such a Secret `"pending": true`. Another host sees the write
  only once a Sync here has pushed it.
- Every Sync pushes the pending writes (opcore does), and opcore's warnings
  (a write dropped as refused, a Field overwritten) reach stderr.
- Any other refusal (`bad_name`, a vault the token cannot see) fails as
  before. A Copy that never synced cannot take a write: it fails.
- `init --check`'s probe counts a write that waits as a failed check.

## Considered Options

- Fail and tell the agent to retry later, the old way: no Secret can be
  stored for as long as a daily budget is out.
- Keep the whole merged Secret and write it over the vault's item: loses a
  Field another host changed meanwhile.

Undo: `Store::sync_to_write` refuses every failed Sync again.
