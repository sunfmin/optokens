# The token: the environment, else a file only its owner may read

Felix, 2026-11-26, in the control session: 「token 从环境变量 `OP_SERVICE_ACCOUNT_TOKEN` 读；没有就读 `~/.config/optokens/token`（权限必须是 0600，否则拒绝并说明原因）。」

The token is `OP_SERVICE_ACCOUNT_TOKEN` when set, else `$XDG_CONFIG_HOME/optokens/token` (default `~/.config/optokens/token`). One function finds it, and every command calls it. The vault is the one `$XDG_CONFIG_HOME/optokens/vault` names, else `optokens`.

On Unix a token file whose mode is not 0600 is refused, naming its mode and `chmod 600 <path>`. On Windows the rule means the file's DACL grants access to nobody but its owner, SYSTEM and the Administrators group, an inherited entry included. Any other entry is refused, naming it and the `icacls` line that strips it (or `optokens init`, which writes the file with that DACL). Only the check differs by OS, behind one function. On Windows the config directory is `%APPDATA%\optokens` unless `XDG_CONFIG_HOME` is set.

## Considered Options

- Skip the check on Windows.
- Check the DACL: chosen, because the owner's rule refuses a file others can read, and on Windows the DACL says who can.

Undo: the one function's Windows branch.
