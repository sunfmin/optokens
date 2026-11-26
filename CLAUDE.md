# optokens

`optokens --help` is the manual and its only copy; keep it true whenever behaviour changes.
`./gate.sh` is done.

## Invariants

- A secret's value is never in any process's argv and never written to a temporary file: it reaches `op` only on its stdin, and leaves it only on its stdout (`src/op.rs` builds every `op` command line).
