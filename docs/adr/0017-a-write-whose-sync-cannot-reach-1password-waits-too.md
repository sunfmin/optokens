# A write whose Sync cannot reach 1Password waits too

Felix, 2026-11-27, the day the 1Password account's daily requests ran out
(1000 of 1000, 14 h to reset) and no Secret could be stored on any host:
「写入，应该让他能写，之后有额度了，同步上去就行了」. Decision record 16 kept
this option for its own decision; this is it.

## Decision

- `put` and `rm` still sync first. When that Sync cannot reach 1Password
  (opcore's `Error::is_transient`: the rate limit, the network, 1Password
  down), they go on from the Copy as held, and their write waits in
  `copy.pending` as decision record 16 says. Stderr adds `1Password could
  not be reached (<why>); stored on this host and written to the vault by
  the next command that reaches it`.
- A pending `put` holds what it changes of the item as read, so its push
  merges over the vault's item as it is then: a Field another host changed
  meanwhile is kept; one both changed takes this host's value, with a
  `warning:` naming it (opcore's decision record 3).
- `list` marks a Secret whose write waits `"pending": true`. Another host
  sees the write only once a Sync here has pushed it.
- A Copy that never synced cannot take a write: it fails, as it cannot tell
  a new name from one another host made. `mv` and `--fresh` still fail.
- Any other failed Sync (`bad_name` is refused before it; a vault the token
  cannot see) is refused as before.

## Considered Options

- Fail until 1Password can be reached, decision record 16's way: no Secret
  can be stored for as long as a daily budget is out.
- Keep the whole merged Secret and write it over the vault's item: loses a
  Field another host changed meanwhile.

Undo: `put` and `rm` call `opened(env, true)` again instead of `to_write`.
