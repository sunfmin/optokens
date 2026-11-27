# Reach 1Password through opcore: a sealed Copy, no `op`

Supersedes decision record 2. Felix, 2026-11-27, control session: optokens moves onto the shared crate opcore (github.com/sunfmin/opcore, its decision records 1 and 2), with items as the SDK's typed structs (「应该直接用结构体，不应该用 Json」), and no data migration of the vault.

Through `op`, `optokens list` of a vault of 82 items ran over 60 s and spent 82 of the service account's 1000 reads an hour: one `op item get` per item.

## Decision

- optokens reaches 1Password only through opcore, which runs 1Password's SDK Core inside optokens. No `op`, and no child process reaches 1Password: `doctor` looks for no `op`, and neither the formula nor the Scoop manifest depends on one.
- Its Copy is opcore's, of the items tagged `optokens`: the file `copy` in the config directory, beside the token file, with a Life of 5 minutes (`store::LIFE`). `list`, `get` and `env` answer from it, with no network within its Life; `--fresh` syncs first. Past its Life, a read whose Sync fails answers from the Copy with a warning on stderr, and syncs again only a Life later (opcore's decision record 2); `--fresh` and the writes fail. `put` and `rm` sync, then write once: the Copy keeps what the write answered, with no read back. `rm` deletes, as `op item delete` did, not archives.
- A Sync is one list and one batch get of the items that changed, signed in to the vault id the Copy keeps: only its first Sync, or one whose kept id no longer names the vault, lists the vaults. Its list also names the untagged items, kept in memory only, so a title one of them holds is still refused (`not_optokens`).
- The vault's layout does not change (decision records 9, 11, 13 and 14): `src/item.rs` lays it out on opcore's structs, and items `op`, mytokens and optokens wrote read the same. The Core answers fields sorted by id, so a value's id, `fields.<n>`, keeps its order.
- Decision record 2's invariant stands: a secret's value is never in any process's command line and never in a file in plaintext. No child process exists; the token reaches the Core in memory; the Copy and its temporary file are sealed (opcore's decision record 2).
- A failure of 1Password is `vault_failed`, with the fix its kind needs (a grant, the rate limit, an out-of-date Core).
- The tests run the real binary on a stand-in Core (`src/standin.rs`), built only without `--release` and used only when `OPTOKENS_STANDIN_STATE` names its state.

## Considered Options

- opcore's Copy: chosen. A warm `list` makes no call; a Sync spends no read.
- `op` with a sealed copy optokens keeps itself, the first plan: each changed item still costs an `op item get`, a read.

Undo: an `op`-backed Store behind the same interface; the module op.rs that built every `op` command line is in the history.
