# Reach 1Password through the `op` CLI; values only over its pipes

Superseded by decision record 15: optokens reaches 1Password through opcore, with no `op`. Its invariant, no value in a command line or a temporary file, stands there.

Felix, 2026-11-26, in the control session: 「只走 1Password 服务账号。」 and 「硬要求：密钥的值永远不出现在任何进程的命令行参数里（`ps` 看不到），也不写进临时文件。写个测试证明这一点。」

optokens reaches 1Password through the official `op` CLI, not an SDK. A Secret's values go in and out only over `op`'s stdin and stdout (JSON item templates), and the service account's token goes only in the child's environment. A secret value is never in any process's command line and never in a temporary file. Each command that handles a value has a test that proves it, against the stand-in for `op`, which records each call's arguments.

## Considered Options

- The `op` CLI: chosen, because agent-cli reaches other systems through their own CLIs (no SDKs), one module per command, so a stand-in can take `op`'s place in tests.
- The 1Password SDK.

Undo: swap the one `op` module for an SDK-backed one behind the same store seam.
