# No Flux: unit tests and proptest check the pure code

agent-cli checks pure crates with Flux. optokens checks its pure code with unit tests and proptest instead, because no sibling Rust CLI on this host runs Flux (docfit, slimfit, truefit and stablehand have no verify.sh), and the rust-cli-coder role says the siblings' way holds.

## Considered Options

- Flux, per agent-cli.
- The siblings' way: chosen.

Undo: add a verify.sh and its step in the gate.
