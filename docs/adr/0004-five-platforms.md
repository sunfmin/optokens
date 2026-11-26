# Five platforms: macOS, Linux and Windows

Felix, 2026-11-26, in the control session: 「语言你定，要能在 Linux（x86_64 / arm64）和 macOS 上用一个二进制跑。」 and then 「把 Windows 也做上。」

optokens is built for agent-cli's five platforms: macOS arm64 and x86_64, Linux arm64 and x86_64 (musl), and Windows x86_64 (msvc). There is no Windows host to run the tests on, so the gate checks the Windows build with clippy for `x86_64-pc-windows-msvc`, and a Windows-only branch cannot rot unbuilt.

## Considered Options

- Only the four macOS and Linux targets the first spec named.
- All five: chosen, as Felix asked, and agent-cli's default.

Undo: drop the Windows target from the gate and the toolchain, and the Scoop manifest from the release script.
