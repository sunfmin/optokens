# macOS is signed and notarized by the tap's workflow

Felix, 2026-11-28, in the control session: 「这个为什么没有用 CI 来，和其他都统一吧」. Follows slimfit's decision record 13 (owner, 2026-11-22: 「把所有的工具都变成 universal」「把公开的工具全部在 GitHub CI 上签」), which every public tool factorium cuts keeps.

## Context

A cut built and published everything from the cutting host, its macOS binary aarch64 only and signed ad hoc by the linker. The macOS application firewall refused its one-time links, and an Intel Mac could not run it.

## Decision

Invariant: **the Developer ID identity and the notary key live only in sunfmin/homebrew-tap, and only its `release` workflow signs.** optokens holds no signing secret.

- `packaging/release.sh build <tag> <outdir>` keeps the tap's contract (the README beside its release workflow): `aarch64-apple-darwin` and `x86_64-apple-darwin` lipo'd into one universal binary, and the formula, macOS's url and sha256 left for the tap to fill in.
- Linux and Windows stay as decision record 4 has them, built and published from the cutting host: the tap's workflow takes only Mach-O files, so it needs no change. The cut puts their archives on the tap's release `optokens-vX.Y.Z` before it runs the workflow; `build`, there as here, downloads the Linux archives for the formula's sha256. The Scoop manifest goes to the bucket last.
- The cut pushes the tag, runs the workflow, waits for it, then downloads the archive the tap's formula names and fails unless `release.sh signed` takes its binary: universal, verified, `Authority=Developer ID Application` and a TeamIdentifier. The gate shows `signed` refusing the dry build's ad hoc signature.

## Considered Options

- Signing on the cutting host with the `developer-id-p12` Secret: a second copy of the identity, and nothing notarizes.
- Linux and Windows built by the tap's workflow too: its runner lacks zig and cargo-xwin, and every sibling's run would change.

Undo: revert the change that made this record; the tap's formula then goes back to the host's next cut.
