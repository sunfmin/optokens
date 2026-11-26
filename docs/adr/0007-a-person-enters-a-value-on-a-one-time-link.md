# A person enters a value on a one-time link, and the command waits for it

Felix, 2026-11-26, in the control session: 「录入密钥只用一次性网页链接，所以在没有桌面的 Linux / macOS 服务器上也能直接用。」 and 「不要的（1Password 本身就负责同步）：mytokens 的 sync、server *、onepassword *、host、macOS 弹窗、Keychain、--level、parent kind。」

`put --fields` and `init` print a one-time link and wait for its one submission, departing from agent-cli's "never ask": the owner's spec makes the link the way in for a secret a person knows, and there is no popup or terminal prompt to fall back on. The help names this departure.
