# A Field's type in the vault follows how its value came in

Felix, 2026-11-26: 「Chose: B, because a value given on the command line is not secret by optokens' own rule, and hiding it only makes the vault harder to read.」 (B: a Field's type follows how its value came in: not secret → `STRING`, secret → `CONCEALED`.)

Each field of the section `fields` (decision record 9) has the type of the way its value came in:

| How the value comes in | Type |
|---|---|
| `--set "NAME=value"` | `STRING` |
| a Field in `--show`, typed into a visible input of the one-time link | `STRING` |
| `--field-from-stdin <Label>` | `CONCEALED` |
| a Field in `--fields` not in `--show`, and a bare `put`'s single value | `CONCEALED` |

`read` takes each Field's type from its field: `STRING` or `CONCEALED`; any other type in the section `fields` is refused by name (`not_optokens`). `put` merges: a Field it sets takes the type of the way it came in, so `--set` over a concealed Field makes it `STRING` and `--field-from-stdin` over a plain one makes it `CONCEALED`; a Field it does not name keeps its type. A type is a change only for a Field this `put` sets, so a `put` that changes neither value nor type writes nothing. The section `optokens` stays `STRING`.

The type changes only how 1Password shows a field: `get`, `env` and `list` give out the same as before. Items written when every value was `CONCEALED` read back as they are; nothing migrates them.

## Considered Options

- Every value `CONCEALED`. Rejected: a URL or a user name given on the command line is not secret by optokens' own rule, and hiding it makes the vault harder to read.
- The type follows how the value came in: chosen.

Undo: template every value as `CONCEALED` again; items written as `STRING` read back the same.
