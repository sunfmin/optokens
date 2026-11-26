# The one-time link's TLS is rustls with the graviola provider, pure Rust

A link served over HTTPS needs TLS in optokens. rustls does it; its crypto provider is graviola (`rustls-graviola`), which is Rust and assembly with no C, so every target builds with no C toolchain: the gate clippy-checks `x86_64-pc-windows-msvc` with plain `cargo`, which cannot compile *ring*'s C (it finds no `assert.h`, tried 2026-11-26), and aws-lc-rs needs a C toolchain and cmake.

The certificate and key come from `tailscale cert --cert-file - --key-file -`, on its stdout, never through a file. Its key is P-256 in SEC1, which graviola loads; a key it cannot load means plain HTTP with that reason, as any other failure of `tailscale cert` does.

## Considered Options

- rustls with *ring*: rejected, the gate's Windows check cannot build its C.
- rustls with aws-lc-rs: rejected for the same reason, and cmake.
- rustls with graviola: chosen.

Undo: the provider is named once, in `src/serve.rs`; swap it there and in `Cargo.toml`.
