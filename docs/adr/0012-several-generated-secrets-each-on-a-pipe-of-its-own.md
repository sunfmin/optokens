# Several generated secrets come in on a pipe each, named by its path

Felix asked, 2026-11-26, that one `put` store several generated secrets: stdin is one stream, so `--field-from-stdin` carries one, and two `put`s of one Secret at once may lose one's change. Decided by the tech lead for Felix: 「Chose: A, because it keeps optokens' rule as it is (a value only on pipes and in a child's environment, never in argv or a temp file): the shell puts only `/dev/fd/N` in argv.」

`put --field-from-pipe "<Label>=<path>"`, repeatable, split on the first `=` as `--set` is, is written `Label=<(command)`: the shell runs the command and puts only its pipe's path on the command line. `put` opens the path and refuses it, before reading anything, unless it is a pipe once links are followed (`/dev/fd/N`, on Linux `/proc/self/fd/N`). A file, a terminal or a missing path is `not_a_pipe`, a refusal that names the Label and never the path: after a mistaken `Label=$(command)` the path is the value. Each pipe is read to its end in turn, one trailing newline dropped, and the Field is stored `CONCEALED` (decision record 11). On Windows, which has no `<(command)`, the path must be a named pipe, `\\.\pipe\<name>`.

## Considered Options

- `--field-from-pipe "Label=<path>"`, the path a pipe from `<(command)`: chosen.
- One JSON object of Label → value on stdin. Rejected: it needs a JSON writer in the shell, where `jq --arg` or `$(…)` in a command's arguments puts the value in argv.
- `--field-from-env "Label=VAR"`. Rejected: the value sits in optokens' own environment, which the same user's `ps -E` shows for the whole run.
- A file path as a fallback. Rejected: a value in a file is a value in a temporary file.

Undo: drop the flag; `--field-from-stdin` and repeated `put`s still store the same values.
