# optokens

`optokens --help` is the manual and its only copy; keep it true whenever behaviour changes.
`./gate.sh` is done.

## Invariants

- A secret's value is never in any process's argv and never written to a file in plaintext: optokens starts no process to reach 1Password (opcore runs its Core inside optokens, and `src/store.rs` is the one way to it), and the Copy, with its temporary file, is sealed.
