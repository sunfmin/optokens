# Every command prints one JSON object, but `get` and `env` keep mytokens' raw stdout

Felix, 2026-11-26, in the control session: 「要保留的命令（用法和输出尽量跟 mytokens 一样，agent 换过去不用改习惯）：put / get / env / list / rm …」 and 「本机有 `agent-cli` skill 的话照它做（Rust、stdout 输出一个 JSON 对象、--help 就是唯一的手册、Homebrew 发版）」.

Every command prints one JSON object on stdout; a failure is `{"error": …}` with a non-zero exit. The two exceptions are `get`, which prints the raw value as mytokens does, and `env`, which prints `export NAME='value'` lines. They send their errors to stderr and leave stdout empty on an error, so `$(…)` and `eval` never capture an error. The top-level help names both exceptions.

## Considered Options

- mytokens' text output and stderr errors for all five of mytokens' commands.
- agent-cli's JSON everywhere except `get` and `env`: chosen. An independent reviewer, consulted, chose it too. Agents depend on `get` inside `$(…)` and `env` inside `eval`; that is what must not break. Nobody parses `stored x/y`, and `list` as JSON is easier to read.
- JSON everywhere, `get` and `env` included.

Undo: change the two commands' printers; the rule is named in one place in the help.
