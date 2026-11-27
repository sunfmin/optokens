//! The command line, read against the manual: its commands, the manual's
//! pages, and what optokens exits with.

use crate::account;
use crate::commands;
use crate::doctor::{self, Finding, World};
use crate::init;
use crate::item;
use crate::refusal::Refusal;
use crate::secret;
use agent_help::{Help, Topic};
use clap::{FromArgMatches, Parser, Subcommand};
use serde_json::{Value, json};

/// The command ran and answered.
pub(crate) const EXIT_OK: i32 = 0;
/// The command could not run: a bad command line, or a refusal.
pub(crate) const EXIT_ERROR: i32 = 2;

/// Keeps an agent's secrets in a 1Password vault through a service account, and takes the values a person enters only through a one-time link, so it works on a Linux, macOS or Windows server with no desktop.
///
/// A CLI for AI coding agents, a simpler sibling of mytokens with its commands and words: a Secret is a named credential of one or more Fields; a Profile is a Secret whose Fields are environment variables. Run `optokens <command> --help` before a command's first run, and `optokens doctor` first on a new host.
///
/// ## What it needs
///
/// - A 1Password service account's token, with access to the vault: see [the token and the vault](help:account).
/// - For a one-time link, `tailscale` with a tailnet address: the link is served on the tailnet only.
///
/// ## Rules to know first
///
/// - A secret's value is never in any process's command line (`ps` does not show it) and never in a file in plaintext: optokens runs no program to reach 1Password (it runs 1Password's own SDK Core inside itself), and its Copy of the vault is sealed.
/// - `get`, `env` and `list` answer from the Copy, the sealed copy of the vault's Secrets in the config directory, with no network within {const:LIFE_MINUTES} minutes of its last Sync. Past that, when the Sync fails (no network, 1Password down), they still answer from the Copy, with one line on stderr, `warning: 1Password could not be synced (<why>); answering from the local copy synced <age> ago`, and try no Sync again for {const:LIFE_MINUTES} minutes. Give `--fresh` right after a Secret was changed on another host. `--fresh` and `mv` always sync first, and fail when the Sync fails. `put` and `rm` sync first too; when 1Password cannot be reached (its rate limit, the network, 1Password unavailable), the write is kept on this host, sealed beside the Copy, answered at once with `"pending": true`, and written to the vault by the next command here that syncs. Until then `get`, `env` and `list` on this host show it, and another host does not.
/// - A command that takes a value a person knows waits for it to be submitted on a one-time link, which it prints first: it does not answer until the person submits it, or the link expires. Every other command asks nothing.
///
/// ## Output
///
/// Every command prints one JSON object on stdout and exits {const:EXIT_OK}. A command that cannot run exits {const:EXIT_ERROR} with `{"error": [{"fault": "...", "fix": "..."}, ...]}`: every fault it found, each with the command or edit that fixes it. Do every fix, then run the command again.
///
/// Two commands keep mytokens' raw stdout instead, for the shell: `get` prints the value alone, for `$(optokens get ...)`, and `env` prints `export NAME='value'` lines, for `eval "$(optokens env ...)"`. Both print their error object on stderr and leave stdout empty, so a `$(...)` or an `eval` never captures an error.
#[derive(Parser)]
#[command(
    name = "optokens",
    version = env!("OPTOKENS_VERSION"),
    verbatim_doc_comment,
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Says whether this host can run optokens: the service account's token and vault, and `tailscale` for one-time links, each finding with its fix.
    ///
    /// ## When to run it
    ///
    /// First on a new host, and whenever a command refuses for a reason outside it. It takes a few seconds at most: each program it runs has {const:BOUND} to answer.
    ///
    /// ## What it reads and writes
    ///
    /// It finds `tailscale` on `PATH` and runs `tailscale ip` and `tailscale status --json`, without the token in their environment. It finds the token and the vault as every command does ([the token and the vault](help:account)), reading the token file's mode or access list but never printing the token. It writes nothing, and runs no `tailscale cert`, which would write a certificate.
    ///
    /// ## What it answers
    ///
    /// - `found`: what it found, each `null` where it found nothing: `token` (`from`, `env` or `file`, and `at`, the variable or the file), `vault` (`name`, and `file`, the vault file, `null` for the default), `tailscale` (`path`, `address`, the first of `tailscale ip`), `cert` (`domains`, the names `tailscale cert` can get a certificate for).
    /// - `findings`: each one off, in this order, with `kind`, `fault` (what was found, and where) and `fix` (what to do). Empty when nothing is off.
    /// - `next`: the first finding's fix, or that there is nothing to fix.
    ///
    /// For example, on a host whose token file others may read:
    ///
    /// ```json
    /// {
    ///   "found": {
    ///     "token": null,
    ///     "vault": { "name": "optokens", "file": null },
    ///     "tailscale": { "path": "/usr/bin/tailscale", "address": "100.64.0.7" },
    ///     "cert": { "domains": ["build.tail1234.ts.net"] }
    ///   },
    ///   "findings": [
    ///     { "kind": "token_file_open", "fault": "the token file `/home/ci/.config/optokens/token` has mode 0644, not 0600: others may read the token", "fix": "chmod 600 /home/ci/.config/optokens/token" }
    ///   ],
    ///   "next": "chmod 600 /home/ci/.config/optokens/token"
    /// }
    /// ```
    ///
    /// The kinds of finding about the service account, which every command that reaches 1Password may refuse with:
    ///
    /// {table:account}
    ///
    /// And about the programs optokens runs:
    ///
    /// {table:doctor}
    ///
    /// ## What it may refuse
    ///
    /// It exits {const:EXIT_OK} whenever it ran: findings are an answer, not an error. It exits {const:EXIT_ERROR} only on a bad command line.
    ///
    /// ## What trips you up
    ///
    /// - It does not sign in: a token that is there but revoked, or without access to the vault, is not a finding.
    /// - `cert` says the tailnet offers this host a certificate, not that this user may get it: on Linux `tailscale cert` needs root or the user set as the operator (`tailscale set --operator=$USER`).
    #[command(next_help_heading = "Run first, on a new host", verbatim_doc_comment)]
    Doctor,
    /// Sets this host up: takes the 1Password service account's token on a one-time link, never in a terminal, writes it and the vault's name where every command finds them, and checks that the service account can read and write the vault.
    ///
    /// ## When to run it
    ///
    /// Once on a new host, after `optokens doctor` finds `tailscale`, and again to replace the token or change the vault. `init --check` alone, after a check failed and its grant was fixed, or to see that the stored token still reaches the vault.
    ///
    /// ## The one-time link
    ///
    /// It serves one page, as `put --fields` does (`optokens put --help`): only on this host's tailnet address, HTTPS when `tailscale cert` gives a certificate, for one submission within {const:LINK_MINUTES} minutes. On stderr, while it waits, `` optokens: open this link to enter the 1Password service account token for the vault `<vault>` (it works once, within {const:LINK_MINUTES} minutes): `` and the URL on the next line. Hand that URL to the person who holds the token. The page has one password input, "{const:INIT_LABEL}".
    ///
    /// ## What it writes
    ///
    /// - The token file, `{const:TOKEN_FILE}` in the config directory ([the token and the vault](help:account)), holding the token alone: mode 0600 on Unix; on Windows an access list granting only its owner, SYSTEM and the Administrators group, set before the token is written.
    /// - The vault file, `{const:VAULT_FILE}` beside it, naming the vault (`--vault`, else `{const:DEFAULT_VAULT}`), only its owner may read too.
    /// - The config directory, made with mode 0700 on Unix when it is not there, and set to 0700 when it is.
    ///
    /// Each file is written whole under a fresh name in that directory, then renamed over the old one: never a temporary file elsewhere. Run again, it replaces both: the same input gives the same files.
    ///
    /// ## What it checks
    ///
    /// With the new token, each in this order until one fails: one Sync of the Copy, one create, a read from the Copy, one delete.
    ///
    /// {table:init}
    ///
    /// ## What it answers
    ///
    /// - `token`: `from` (`file`, or with `--check` maybe `env`) and `at`, the token file or the variable.
    /// - `vault`: `name`, and `file`, the vault file (`null` with `--check` and no vault file).
    /// - `checks`: the checks made, every one passed.
    ///
    /// ```json
    /// { "token": { "from": "file", "at": "/home/ci/.config/optokens/token" }, "vault": { "name": "optokens", "file": "/home/ci/.config/optokens/vault" }, "checks": ["vault_listed", "vault_read", "probe_written", "probe_read_back", "probe_removed"] }
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// Before it serves the link: a `--vault` that is empty or not one line, `no_config_dir` ([the token and the vault](help:account)), and without a tailnet to serve the link on, `tailscale_missing` or `no_tailnet_address` (`optokens doctor --help`). Then `link_expired`, when no one submitted the link in time, and nothing is written. Then the first check that failed, its `kind` the check's name and its fix the grant to give. The token file and the vault file are then kept: once the grant is given, `optokens init --check` checks again with no new link. `--check` refuses also with the service account's faults ([the token and the vault](help:account)).
    ///
    /// ## What trips you up
    ///
    /// - It does not answer until the person submits the link, or it expires: run it where it may wait {const:LINK_MINUTES} minutes, and read the link from its stderr.
    /// - Never ask for the token in the chat, nor pipe it in: give the person the link.
    /// - `{const:TOKEN_ENV}`, when set, wins over the token file it writes: unset it for later commands to use the file.
    #[command(next_help_heading = "Run first, on a new host", verbatim_doc_comment)]
    Init(init::InitArgs),
    /// Shows one topic of this manual, or all of it.
    ///
    /// `optokens help account` shows where optokens finds the service account's token and the vault; `optokens help all` shows the whole manual.
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    Help {
        /// The topic, or `all`.
        #[arg(verbatim_doc_comment)]
        topic: Option<String>,
    },
    /// Stores a Secret, or changes it: sets the Fields it names and keeps the rest. A value a person knows is entered on a one-time link it serves on the tailnet.
    ///
    /// ## When to run it
    ///
    /// When a command needs a credential or a Profile that `optokens list` does not show, or one of its Fields must change. Run it once per Secret: two `put`s of one Secret at once may lose one's change.
    ///
    /// ## What it reads and writes
    ///
    /// It syncs the Copy with the vault first, so it never writes over a stale item, reads the Secret from it, merges into it what this `put` names, and writes it back as one item, only when that changes it: one write, whose answer the Copy keeps. When 1Password cannot be reached (its rate limit, the network, 1Password unavailable), it merges into the Copy as held instead, and the write is kept on this host until the vault takes it: see `pending` below. A Field not named is kept. `--set "NAME=value"` sets a Field that is not secret, split on the first `=`, stored as plain text; repeat it. `--field-from-stdin <Label>` sets one Field to all of stdin, one trailing newline dropped, stored concealed: for a secret a command makes and pipes in, such as `openssl rand -base64 32 | optokens put deploy-db --set "Username=svc" --field-from-stdin Password`. `--field-from-pipe <Label>=<(command)` sets a Field to all the command prints, one trailing newline dropped, stored concealed; repeat it to store several generated secrets in one `put`, such as `optokens put deploy-db --set "Username=svc" --field-from-pipe Password=<(openssl rand -base64 32) --field-from-pipe SigningKey=<(openssl rand -hex 32)`. The shell (bash, zsh) runs each command and puts only its pipe's path, `/dev/fd/N`, on the command line; `put` reads each pipe to its end and refuses any path that is not a pipe, a file among them. On Windows, PowerShell has no `<(command)`: the path must be a named pipe, `\\.\pipe\<name>`, or use one `put --field-from-stdin` per value. `--description` replaces the description, the item's notes (`--description ""` clears it); alone, for a stored Secret, it changes nothing else. `--meta '<json>'` replaces the Secret's Meta, structured data about it for a program to read (a Cloudflare `account_id`), one JSON object; a `put` without it keeps the stored one, and alone, for a stored Secret, it changes nothing else. Anything but one JSON object is refused (`bad_meta`). A new Secret is `static` unless `--kind profile`. A Profile's labels are environment variables' names, for `env`. How a Secret is laid out in the vault: [Secrets in the vault](help:secrets).
    ///
    /// ## The one-time link
    ///
    /// `--fields "<Label>,..."` names the Fields a person enters, and a bare `put <service>` (no `--set`, `--field-from-stdin`, `--field-from-pipe` or `--fields`) the Secret's one value, with no label. For these `put` serves one page and waits:
    ///
    /// - **Where**: only on this host's tailnet address, from `tailscale ip`, on a port the OS picks. With no `tailscale`, or no tailnet address on this host, it stores nothing, reads no vault, and says what is missing.
    /// - **How**: HTTPS, with the certificate `tailscale cert` gives for the host's tailnet name; when that fails, plain HTTP on the tailnet, which WireGuard encrypts, with the reason and its fix printed first.
    /// - **For how long**: one submission, within {const:LINK_MINUTES} minutes; a link is a fresh random token.
    /// - **What it prints**: on stderr, while it waits, `optokens: open this link to enter the secret for <service> / <account> (it works once, within {const:LINK_MINUTES} minutes):` and the URL on the next line. Hand that URL to the person: delivering it is not optokens' job. Stdout keeps only the final JSON answer.
    /// - **The page**: the Secret, its description, a password input per Field asked (a plain text input for each `--show` label), and each stored Field this `put` keeps as "already set", never its value. A second submission, or one after expiry, answers 410.
    ///
    /// A value submitted goes from the page straight into the item 1Password stores, never to optokens' stdout or stderr, a log, a command line or a file. After the submission, or at expiry, `put` stops serving and answers.
    ///
    /// ## What it answers
    ///
    /// - `secret`: `<service>/<account>`.
    /// - `changed`: whether it wrote; `false` when the Secret already held all it was given.
    /// - `kind`: `static` or `profile`.
    /// - `fields`: the Secret's labels now, `null` for a single value.
    /// - `pending`: `true` only when 1Password could not be reached. The write is kept on this host, sealed, and stderr says `1Password could not be reached (<why>); {const:WAITS}`. It holds only what this `put` names (its Fields, `--description`, `--meta`), so when it is written, a Field another host changed meanwhile is kept; one both changed takes this value, named in a `warning:` line. `get`, `env` and `list` on this host show it at once; another host sees it only after that write. A value entered on the one-time link waits the same way. Any refusal but "cannot be reached" (`bad_name`, a vault the token cannot see) still fails.
    ///
    /// ```json
    /// { "secret": "deploy-db/default", "changed": true, "kind": "static", "fields": ["Username", "Password"] }
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// Every fault it finds, before it serves a link or writes anything: `bad_name`, `bad_set`, `bad_meta`, `bad_show`, `duplicate_label`, `not_env_name`, `kind_change`, `shape_change`, `stdin_terminal`, `stdin_empty`, `stdin_not_text`, `not_a_pipe`, `pipe_empty`, `pipe_not_text`, the service account's faults ([the token and the vault](help:account)), and the vault's (`not_optokens`, `ambiguous`, `vault_failed`); then `link_expired`, when no one submitted the link in time. Each is in [Secrets in the vault](help:secrets), with its fix. Without a tailnet to serve the link on, `tailscale_missing` or `no_tailnet_address`, as `optokens doctor --help` lists them, and a fault naming a tailnet address that is on no interface of this host.
    ///
    /// ## What trips you up
    ///
    /// - `put --fields` or a bare `put` does not answer until the person submits the link, or it expires: run it where it may wait {const:LINK_MINUTES} minutes, and read the link from its stderr.
    /// - Never pipe in, or `--set`, a value a person typed or pasted into the chat: give them the link.
    /// - `--set` puts its value on the command line, where `ps` shows it: only for a value that is not secret (a URL, a model, a user name).
    /// - `--field-from-pipe Label=$(command)` is wrong: `$(…)` puts the value itself on the command line, and `put` refuses it as `not_a_pipe`. Write `Label=<(command)`, unquoted or as `"Label="<(command)`. A file is refused too, such as the temporary one zsh's `=(command)` makes.
    /// - `put` never drops a Field, nor changes a kind, nor turns a single value into Fields or back: `rm`, then `put` the Secret again.
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    Put(commands::PutArgs),
    /// Prints a Secret's value alone, with no newline, for `$(optokens get ...)`; or with `--json` the whole Secret.
    ///
    /// ## When to run it
    ///
    /// Inside the command that needs the value, such as `curl -H "Authorization: Bearer $(optokens get cloudflare)" ...`, so the value is used, not shown.
    ///
    /// ## What it reads and writes
    ///
    /// It reads the Secret from the Copy, with no network within {const:LIFE_MINUTES} minutes of its last Sync, and writes nothing but the Copy. Past that, or with `--fresh`, it syncs first: give `--fresh` right after the Secret was changed on another host. Past that, a Sync that fails still answers from the Copy, with a `warning:` line on stderr; with `--fresh`, it fails (`vault_failed`).
    ///
    /// ## What it answers
    ///
    /// The single value, or the Field `--field` names, raw on stdout with no newline. A Secret of labelled Fields needs `--field`. With `--json`, one JSON object: `service`, `account`, `kind`, `description` (or `null`), `meta`, the Meta (or `null`), and `fields`, each label with its value (or `value`, for a single value):
    ///
    /// ```json
    /// { "service": "aws", "account": "ci", "kind": "static", "description": "CI deploy", "meta": { "region": "us-east-1" }, "fields": { "Access Key ID": "AKIA...", "Secret Access Key": "..." } }
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// `bad_name`, `not_found`, `no_such_field`, the service account's faults ([the token and the vault](help:account)), and the vault's (`not_optokens`, `ambiguous`, `vault_failed`), in [Secrets in the vault](help:secrets). Its error object goes to stderr, stdout left empty.
    ///
    /// ## What trips you up
    ///
    /// - Never `echo` it, print it, or run it under `set -x`: the value would be in the transcript.
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    Get {
        /// The Secret's service.
        #[arg(verbatim_doc_comment)]
        service: String,
        /// The Secret's account.
        #[arg(long, default_value = secret::DEFAULT_ACCOUNT, verbatim_doc_comment)]
        account: String,
        /// The label of the Field to print.
        #[arg(
            long,
            value_name = "Label",
            conflicts_with = "json",
            verbatim_doc_comment
        )]
        field: Option<String>,
        /// The whole Secret as one JSON object.
        #[arg(long, verbatim_doc_comment)]
        json: bool,
        /// Syncs with the vault first: right after the Secret was changed on another host.
        #[arg(long, verbatim_doc_comment)]
        fresh: bool,
    },
    /// Prints a Profile's Fields as `export NAME='value'` lines, for `(eval "$(optokens env <project>)"; <command>)`.
    ///
    /// ## When to run it
    ///
    /// To run a command with a Profile's environment variables. Scope it to a subshell, `( ... )`, so the values leave with it.
    ///
    /// ## What it reads and writes
    ///
    /// It reads the Secret from the Copy, with no network within {const:LIFE_MINUTES} minutes of its last Sync, and writes nothing but the Copy. Past that, or with `--fresh`, it syncs first: give `--fresh` right after the Secret was changed on another host. Past that, a Sync that fails still answers from the Copy, with a `warning:` line on stderr; with `--fresh`, it fails (`vault_failed`).
    ///
    /// ## What it answers
    ///
    /// One line per Field, in the Secret's order, its value in single quotes, each `'` in it written `'\''`, on every OS (for sh, bash and zsh, Git Bash and WSL included):
    ///
    /// ```sh
    /// export ANTHROPIC_BASE_URL='https://open.bigmodel.cn/api/anthropic'
    /// export ANTHROPIC_AUTH_TOKEN='...'
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// `bad_name`, `not_found`, `not_env` (a single value, or a label that is not a variable's name), the service account's faults ([the token and the vault](help:account)), and the vault's (`not_optokens`, `ambiguous`, `vault_failed`), in [Secrets in the vault](help:secrets). Its error object goes to stderr, stdout left empty, so `eval` runs nothing.
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    Env {
        /// The Secret's service: a Profile's project or provider.
        #[arg(verbatim_doc_comment)]
        service: String,
        /// The Secret's account.
        #[arg(long, default_value = secret::DEFAULT_ACCOUNT, verbatim_doc_comment)]
        account: String,
        /// Syncs with the vault first: right after the Profile was changed on another host.
        #[arg(long, verbatim_doc_comment)]
        fresh: bool,
    },
    /// Lists every Secret in the vault, with its kind, description, Meta and Field labels, never a value.
    ///
    /// ## When to run it
    ///
    /// Before `put`, to see whether a Secret is there, and to recall what each is for.
    ///
    /// ## What it reads and writes
    ///
    /// It reads every item tagged `optokens` from the Copy, synced first only past its Life of {const:LIFE_MINUTES} minutes or with `--fresh`, and writes nothing but the Copy. A Sync also writes to the vault each `put` and `rm` that waits on this host, in order, each on the vault's item as it is now; on stderr, a `warning:` line names a Field it overwrote that another host had changed, and one the vault refused, which is dropped. Past its Life, a Sync that fails still answers from the Copy, with a `warning:` line on stderr; with `--fresh`, it fails (`vault_failed`). Items without the tag are not optokens' and not listed.
    ///
    /// ## What it answers
    ///
    /// `secrets`, by service, then account, each with `service`, `account`, `kind`, `description` (or `null`), `meta`, the Meta (or `null`), and `fields`, its labels (`null` for a single value), and `pending: true` for a Secret whose `put` waits on this host for 1Password (a removal that waits hides its Secret):
    ///
    /// ```json
    /// { "secrets": [ { "service": "glm", "account": "default", "kind": "profile", "description": "Claude Code to GLM", "meta": null, "fields": ["ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"] } ] }
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// The service account's faults ([the token and the vault](help:account)), `vault_failed`, and `not_optokens` for each tagged item that is not optokens' layout, in [Secrets in the vault](help:secrets).
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    List {
        /// Syncs with the vault first: right after a Secret was changed, added or removed on another host.
        #[arg(long, verbatim_doc_comment)]
        fresh: bool,
    },
    /// Renames a Secret in place: the same item in the vault, under a new service or account.
    ///
    /// ## When to run it
    ///
    /// When a Secret's service or account is named wrong or changes, instead of `get`, `put` under the new name and `rm`: the item keeps its id and its 1Password history, and no value passes through the agent.
    ///
    /// ## What it reads and writes
    ///
    /// It syncs the Copy with the vault once, finds the Secret's item, sees that the new name holds nothing, and edits that one item: its title and its section `optokens` name the new Secret. Its Fields, their types, its kind, description, Meta, and what optokens does not own of it are kept: one write, whose answer the Copy keeps. `--to-account` is the new account, `--account`'s when not given: `optokens mv glm glm --to-account work` moves only the account.
    ///
    /// ## What it answers
    ///
    /// `secret`, the new `<service>/<account>`, and `from`, the old, and `pending: true` when its edit waits on this host behind a `put` or `rm` of the Secret that waits for 1Password:
    ///
    /// ```json
    /// { "secret": "claude/ultra", "from": "agent-account/default" }
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// `bad_name`, `not_found` (no Secret to move), `exists` (the new name is already a Secret, the old one among them), the service account's faults ([the token and the vault](help:account)), and the vault's (`not_optokens`, also for an item without the tag `optokens` titled as the new name; `ambiguous`; `vault_failed`), in [Secrets in the vault](help:secrets). A refusal writes nothing.
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    Mv {
        /// The Secret's service.
        #[arg(verbatim_doc_comment)]
        service: String,
        /// Its new service.
        #[arg(verbatim_doc_comment)]
        new_service: String,
        /// The Secret's account.
        #[arg(long, default_value = secret::DEFAULT_ACCOUNT, verbatim_doc_comment)]
        account: String,
        /// Its new account; `--account`'s when not given.
        #[arg(long, verbatim_doc_comment)]
        to_account: Option<String>,
    },
    /// Removes a Secret: its item in the vault, every Field with it.
    ///
    /// ## When to run it
    ///
    /// When a credential is retired, or before a `put` that would change a Secret's kind or shape, or drop a Field.
    ///
    /// ## What it reads and writes
    ///
    /// It syncs the Copy with the vault, finds the Secret's item and deletes it for good (not archived): one delete. When 1Password cannot be reached (its rate limit, the network, 1Password unavailable), it finds the Secret in the Copy as held, and the removal is kept on this host, answered with `"pending": true` and the stderr line `put` gives: `get`, `env` and `list` here no longer show the Secret, and the next command here that syncs deletes it in the vault. Another host sees it until then.
    ///
    /// ## What it answers
    ///
    /// `secret`, `<service>/<account>`, and `changed`: `false` when there was no such Secret, which is no fault, so it can run again. `pending`: `true` only when the removal waits on this host for 1Password.
    ///
    /// ```json
    /// { "secret": "cloudflare/default", "changed": true }
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// `bad_name`, the service account's faults ([the token and the vault](help:account)), and the vault's (`not_optokens`, `ambiguous`, `vault_failed`), in [Secrets in the vault](help:secrets).
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    Rm {
        /// The Secret's service.
        #[arg(verbatim_doc_comment)]
        service: String,
        /// The Secret's account.
        #[arg(long, default_value = secret::DEFAULT_ACCOUNT, verbatim_doc_comment)]
        account: String,
    },
}

/// Where optokens finds the 1Password service account's token, and the vault it keeps Secrets in: every command that reaches 1Password reads them the same way.
///
/// ## The token
///
/// 1. `{const:TOKEN_ENV}`, when it is set and not empty.
/// 2. Otherwise the token file, `{const:TOKEN_FILE}` in the config directory: `$XDG_CONFIG_HOME/optokens`, else `~/.config/optokens`; on Windows `%APPDATA%\optokens` unless `XDG_CONFIG_HOME` is set. It holds the token alone; surrounding whitespace is dropped.
///
/// Only its owner may read the token file. On Unix its mode must be exactly 0600: any other mode is refused, naming the mode and the `chmod 600 <path>` that fixes it. On Windows its access list may grant access only to its owner, SYSTEM and the Administrators group, inherited entries included: any other entry is refused, naming it and the `icacls` line that removes it.
///
/// ## The vault
///
/// The vault file, `{const:VAULT_FILE}` in the same directory, names the vault on its one line. Without it the vault is `{const:DEFAULT_VAULT}`.
///
/// ## What trips you up
///
/// - `{const:TOKEN_ENV}` wins whenever it is set: a token file is then not read, nor its mode checked.
/// - The token is never on a command line nor in another process: optokens hands it to the 1Password Core it runs inside itself.
/// - The Copy, `{const:COPY_FILE}` beside the token file, is sealed with a key derived from the token: another token's Copy does not open, and is rebuilt by a Sync.
#[derive(Topic)]
#[topic(name = "account")]
struct AccountTopic;

/// How optokens keeps a Secret in the vault, and every fault a command about a Secret may refuse with.
///
/// ## One item per Secret
///
/// A Secret is one item of the vault, of the category `{const:CATEGORY}`, titled `<service>`, or `<service>.<account>` when the account is not `{const:DEFAULT_ACCOUNT}`, and tagged `{const:TAG}`. The title holds no `/`, so `op read "op://<vault>/<title>/{const:VALUES}/<Label>"` reads a Field. Its values are the fields of the section `{const:VALUES}`, each labelled with its Field's label (a single value is one field, `{const:SINGLE}`). Its service (`{const:SERVICE}`), its account (`{const:ACCOUNT}`), its kind, whether it is a single value, and its Meta (`{const:META_FIELD}`, one JSON object written compact, absent when it has none) are the fields of the section `{const:META}`, so a Field may be called `kind` or `description` without a clash. An item without `{const:META_FIELD}`, as one written before Meta, is a Secret with no Meta; one whose `{const:META_FIELD}` is not a JSON object is refused (`not_optokens`).
///
/// Its description is the item's notes, whole, which 1Password shows under the title in its list: a Secret without one has empty notes, and notes written in 1Password are its description. An item an earlier optokens or mytokens wrote keeps the description as a field `{const:DESCRIPTION}` of the section `{const:META}`: when that field is there and not empty, it is the description, and the next `put` moves it into the notes (the notes it overwrites are in 1Password's item history).
///
/// optokens takes a Secret's name from the fields `{const:SERVICE}` and `{const:ACCOUNT}`, never from the title: a service may hold a `.`, so `a.b` is the title of both `a.b` and `a --account b`, each found by its own section. An item an earlier optokens titled `<service>/<account>`, without those fields, is still read by its title; the next `put` of that Secret rewrites it, the same item, under its new title.
///
/// ## Which Fields are concealed
///
/// A Field's type in the vault follows how its value came in, and `put` sets it each time it sets the Field; a Field it does not name keeps its type:
///
/// - `{const:STRING}`, plain text: `--set "NAME=value"`, and a `--show` Field typed visibly on the link. A value on the command line is not secret.
/// - `{const:CONCEALED}`, shown like a password: `--field-from-stdin <Label>`, `--field-from-pipe <Label>=<(command)`, a `--fields` Field not in `--show`, and a bare `put`'s single value. Store a secret this way.
///
/// The type changes only how 1Password shows the field: `get`, `env` and `list` give out the same either way. An item with another type in the section `{const:VALUES}` is refused (`not_optokens`).
///
/// optokens reads only items tagged `{const:TAG}`. An item of a Secret's title (new or old) without the tag, or one whose section `{const:META}` is not this layout, is refused by name (`not_optokens`), never guessed at. Edit a Secret's values with optokens, not in 1Password. What optokens does not own is read past and kept by every `put`: the item's other tags (mytokens' `mytokens` and `mytokens-digest-<hash>`), and its other sections and their fields. `put` keeps the order of the fields in `{const:VALUES}`, which is the order `env` prints, and adds a new Field after them.
///
/// ## The faults
///
/// {table:secret}
#[derive(Topic)]
#[topic(name = "secrets")]
struct SecretsTopic;

pub(crate) fn help() -> Help {
    Help::new(<Cli as clap::CommandFactory>::command())
        .topic::<AccountTopic>()
        .topic::<SecretsTopic>()
        .table::<account::Fault>("account")
        .table::<Finding>("doctor")
        .table::<secret::Fault>("secret")
        .table::<init::Check>("init")
        .constant("INIT_LABEL", init::LABEL)
        .constant("BOUND", format!("{}s", doctor::BOUND.as_secs()))
        .constant("TOKEN_ENV", account::TOKEN_ENV)
        .constant("TOKEN_FILE", account::TOKEN_FILE)
        .constant("VAULT_FILE", account::VAULT_FILE)
        .constant("DEFAULT_VAULT", account::DEFAULT_VAULT)
        .constant("CATEGORY", format!("{:?}", item::CATEGORY))
        .constant("TAG", item::TAG)
        .constant("SERVICE", item::SERVICE)
        .constant("ACCOUNT", item::ACCOUNT)
        .constant("DEFAULT_ACCOUNT", secret::DEFAULT_ACCOUNT)
        .constant("VALUES", item::VALUES)
        .constant("META", item::META)
        .constant("SINGLE", item::SINGLE)
        .constant("META_FIELD", item::META_FIELD)
        .constant("DESCRIPTION", item::DESCRIPTION)
        .constant("STRING", item::STRING)
        .constant("CONCEALED", item::CONCEALED)
        .constant("LINK_MINUTES", crate::link::LIFETIME.as_secs() / 60)
        .constant("LIFE_MINUTES", crate::store::LIFE.as_secs() / 60)
        .constant("COPY_FILE", crate::store::COPY_FILE)
        .constant("WAITS", crate::store::WAITS)
        .constant("EXIT_OK", EXIT_OK)
        .constant("EXIT_ERROR", EXIT_ERROR)
}

/// What a command prints on stdout and stderr, as is, and exits with.
#[derive(Debug)]
pub(crate) struct Answer {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

impl Answer {
    /// One JSON object on stdout.
    pub fn json(value: &Value) -> Answer {
        Answer::text(pretty(value))
    }

    /// Text on stdout, ending in one newline.
    fn text(text: String) -> Answer {
        Answer::raw(format!("{}\n", text.trim_end()))
    }

    /// Stdout exactly as given: `get`'s value, `env`'s lines.
    pub fn raw(stdout: String) -> Answer {
        Answer {
            stdout,
            stderr: String::new(),
            code: EXIT_OK,
        }
    }

    /// A command that could not run: every fault with its fix, as `error`, on stdout, exit EXIT_ERROR.
    pub fn refused(faults: Vec<Refusal>) -> Answer {
        Answer {
            code: EXIT_ERROR,
            ..Answer::json(&json!({ "error": faults }))
        }
    }

    /// As [`Answer::refused`], but on stderr, stdout left empty: for `get`
    /// and `env`, whose stdout a `$(...)` or an `eval` captures.
    pub fn refused_on_stderr(faults: Vec<Refusal>) -> Answer {
        let refused = Answer::refused(faults);
        Answer {
            stdout: String::new(),
            stderr: refused.stdout,
            code: refused.code,
        }
    }
}

/// The command line's answer. `--help`, `--version` and a command line clap
/// refuses print and exit here, as clap does.
pub(crate) fn run(args: impl IntoIterator<Item = std::ffi::OsString>) -> Answer {
    let args: Vec<_> = args.into_iter().collect();
    let help = help();
    let command = help
        .clap()
        .expect("the manual is whole: checked by its test");
    let cli = match command
        .try_get_matches_from(&args)
        .and_then(|m| Cli::from_arg_matches(&m))
    {
        Ok(cli) => cli,
        Err(e) if !e.use_stderr() => e.exit(),
        Err(e) => {
            let refusal = vec![Refusal::new(e.to_string().trim(), "run `optokens --help`")];
            // `get` and `env` keep stdout empty, whatever refuses them.
            let raw = args.get(1).is_some_and(|c| c == "get" || c == "env");
            return if raw {
                Answer::refused_on_stderr(refusal)
            } else {
                Answer::refused(refusal)
            };
        }
    };
    let env = account::Env::current();
    match cli.command {
        Cmd::Doctor => Answer::json(&doctor::doctor(&World::current())),
        Cmd::Init(args) => init::init(&env, args),
        Cmd::Help { topic: None } => Answer::text(help.index().expect("checked")),
        Cmd::Help { topic: Some(topic) } => match help.topic_help(&topic) {
            Ok(markdown) => Answer::text(markdown),
            Err(e) => Answer::refused(vec![Refusal::new(
                e.to_string().trim(),
                "run `optokens --help` for the topics",
            )]),
        },
        Cmd::Put(args) => {
            let stdin = std::io::stdin();
            let terminal = std::io::IsTerminal::is_terminal(&stdin);
            commands::put(&env, args, terminal, || {
                let mut bytes = Vec::new();
                let _ = std::io::Read::read_to_end(&mut stdin.lock(), &mut bytes);
                bytes
            })
        }
        Cmd::Get {
            service,
            account,
            field,
            json,
            fresh,
        } => commands::get(&env, &service, &account, field.as_deref(), json, fresh),
        Cmd::Env {
            service,
            account,
            fresh,
        } => commands::env(&env, &service, &account, fresh),
        Cmd::List { fresh } => commands::list(&env, fresh),
        Cmd::Mv {
            service,
            new_service,
            account,
            to_account,
        } => {
            let to_account = to_account.as_deref().unwrap_or(&account);
            commands::mv(&env, (&service, &account), (&new_service, to_account))
        }
        Cmd::Rm { service, account } => commands::rm(&env, &service, &account),
    }
}

pub(crate) fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("json")
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_manual_is_whole() {
        agent_help::check(&super::help()).unwrap();
        <super::Cli as clap::CommandFactory>::command().debug_assert();
        let manual = super::help().manual().unwrap();
        assert!(!manual.contains("{const:"), "{manual}");
    }
}
