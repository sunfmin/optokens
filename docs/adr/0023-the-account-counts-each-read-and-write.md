# The account's daily requests count each read and write

opcore's decision record 7 (opcore fa61126), measured on `sesame-scratch` 2026-11-28. This repo moves opcore's pin onto it. Amends decision records 19 and 21, which took a process that reaches 1Password to spend one of the account's 1000 requests a day.

## Context

Measured with `op service-account ratelimit`: `put --now` of a new Secret spent 2 reads, 1 write and 3 of the account's requests; a push of 3 creates, 1 edit and 2 deletes 5, 3 and 8; the first Sync on a new host 1, 0 and 1. `VaultsList` spends no read of its own.

## Decision

- The account's daily requests are counted as the reads plus the writes a command spends. `tests/budget.rs` asserts each scenario's reads and writes and derives the account's column of `docs/budget.md` from them; optokens keeps no count of its own.
- Staging and the push of decision record 21 stand, now counted in reads and writes rather than processes: a push's batch calls save the account a request for each read and write they fold.

## Considered Options

- One account request per process: what each step above disproved.

Undo: give `tests/budget.rs`'s Budget its own account count again, read from opcore's decision record 1.
