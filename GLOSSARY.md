# optokens

Keeps an agent's secrets in a 1Password vault through a service account; a person enters a value only through a One-time link. The words are mytokens', less what optokens does not have.

## Language

**Secret**:
A machine-usable credential (an API token, an API key, a connection string) that an agent retrieves and injects into a shell command at call time. It has one or more Fields, and is one item in the Vault, rotated, listed and removed as a unit.
_Avoid_: Password (a human-facing web login, out of scope).

**Field**:
A labeled value inside a Secret, addressed by its label. Most Secrets have one; a composite credential (an access key ID and its secret key) has several that rotate together.
_Avoid_: sub-secret, key/value pair.

**Description**:
An agent-written note of what a Secret is for, set when it is first `put` and shown by `list`: its reader is a later agent recalling the Secret's purpose. Stored as the vault item's notes, which 1Password shows in its list.
_Avoid_: comment, label.

**Meta**:
Structured data about a Secret for a program to read (a Cloudflare `account_id`, an API's endpoint), one JSON object, set by `put --meta` and shown by `list` and `get --json`. Distinct from the Description, prose for a later agent.
_Avoid_: metadata (optokens' own fields of an item: its kind, shape, name), notes.

**Service**:
The API or tool a Secret authenticates to, or a Profile points a tool at, named by a stable slug (`cloudflare`, `github`); the slug is how a Secret is looked up.

**Profile**:
A Secret whose Fields are environment variables, labeled by their names, that `env` prints as `export` lines to `eval`. A project Profile, named by the project, holds all of one project's environment variables.
_Avoid_: environment, env file, config set.

**One-time link**:
How optokens takes a value a person knows: a page served on the host's tailnet address only, behind a fresh token, good for one submission of one Secret within a few minutes. The value goes from the browser into the Vault, never through the agent.
_Avoid_: magic link, share link.

## Storage

**Vault**:
The 1Password vault optokens keeps its Secrets in: the one the vault file names, else `optokens`.

**Service account**:
The 1Password service account optokens reaches the Vault as, through opcore. Its token is `OP_SERVICE_ACCOUNT_TOKEN`, else the token file, which only its owner may read.
_Avoid_: API key, login.

**Copy**:
opcore's sealed copy of the Vault's items tagged `optokens`, the file `copy` beside the token file: `list`, `get` and `env` answer from it with no network however old it is; it syncs only at `--fresh`, a push, a Secret it lacks, or when there is none yet (decision record 19). Derived from the Vault, never its truth.
_Avoid_: cache.

**Staged change**:
What a `put`, `mv` or `rm` changes, kept on this host without reaching 1Password (decision record 21): opcore keeps it sealed in `copy.pending` beside the Copy, reads show it, `status` lists it, and the next Push sends it. The command answers `pending: true`. Unlike the Copy, never derived: the file is its only record until pushed.
_Avoid_: pending write (opcore's word for the same record), queue, draft.

**Push**:
Sending every Staged change to the Vault in one process, one of the account's requests, each Secret's changes folded into one write, then a Sync: `optokens push`, a write's `--now`, `--fresh`. A change 1Password cannot take now stays staged.
_Avoid_: flush, upload.
