# Every command's Budget is measured on the stand-in and recorded

Felix, 2026-11-28: 「先用模拟的都测好，记录好使用了多少额度」. End to end against a real 1Password is left out.

## Decision

- Every command's scenario on the stand-in Core asserts its Core calls and the reads, writes and account requests they spend, and `docs/budget.md` is their table: `tests/budget.rs` generates it, fails when it is stale, and `UPDATE_BUDGET=1` rewrites it.
- Each method's cost is read from opcore's decision record 1, in the opcore source `Cargo.lock` pins, where opcore measured it on the real Core; optokens keeps no copy of the numbers, so an opcore bump that changes them changes the table.
- The stand-in marks each call it refuses `failed`, and a refused call spends nothing, as opcore's stand-in counts.

## Considered Options

- A cost table of optokens' own beside the stand-in: chosen against, a second home of opcore's numbers that drifts unseen.
- opcore exporting its cost table from the library: opcore's tests keep it (their stand-in), not its library, and the record is the measured source either way.
- The stand-in summing the Budget into its state file: it would need the costs at run time inside the binary; the tests sum the calls it already records instead.
