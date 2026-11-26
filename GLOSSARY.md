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
An agent-written note of what a Secret is for, set when it is first `put` and shown by `list`: its reader is a later agent recalling the Secret's purpose.
_Avoid_: comment, label.

**Service**:
The API or tool a Secret authenticates to, or a Profile points a tool at, named by a stable slug (`cloudflare`, `github`); the slug is how a Secret is looked up.

**Profile**:
A Secret whose Fields are environment variables, labeled by their names, that `env` prints as `export` lines to `eval`. A project Profile, named by the project, holds all of one project's environment variables.
_Avoid_: environment, env file, config set.

**One-time link**:
How optokens takes a value a person knows: a page served on the host's tailnet address only, behind a fresh token, good for one submission of one Secret within a few minutes. The value goes from the browser into `op`, never through the agent.
_Avoid_: magic link, share link.

## Storage

**Vault**:
The 1Password vault optokens keeps its Secrets in: the one the vault file names, else `optokens`.

**Service account**:
The 1Password service account optokens reaches the Vault as, through `op`. Its token is `OP_SERVICE_ACCOUNT_TOKEN`, else the token file, which only its owner may read.
_Avoid_: API key, login.
