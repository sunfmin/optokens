//! The command line, read against the manual: its commands, the manual's
//! pages, and what optokens exits with.

use crate::account;
use crate::commands;
use crate::doctor::{self, Finding, World};
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
/// - The 1Password CLI, `op`, on `PATH`: optokens reaches 1Password only through it.
/// - A 1Password service account's token, with access to the vault: see [the token and the vault](help:account).
/// - For a one-time link, `tailscale` with a tailnet address: the link is served on the tailnet only.
///
/// ## Rules to know first
///
/// - A secret's value is never in any process's command line (`ps` does not show it) and never in a temporary file: it travels only over pipes and in a child's environment.
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
    /// Says whether this host can run optokens: `op`, the service account's token and vault, and `tailscale` for one-time links, each finding with its fix.
    ///
    /// ## When to run it
    ///
    /// First on a new host, and whenever a command refuses for a reason outside it. It takes a few seconds at most: each program it runs has {const:BOUND} to answer.
    ///
    /// ## What it reads and writes
    ///
    /// It finds `op` and `tailscale` on `PATH` and runs `op --version`, `tailscale ip` and `tailscale status --json`, none of them with the token in its environment. It finds the token and the vault as every command does ([the token and the vault](help:account)), reading the token file's mode or access list but never printing the token. It writes nothing, and runs no `tailscale cert`, which would write a certificate.
    ///
    /// ## What it answers
    ///
    /// - `found`: what it found, each `null` where it found nothing: `op` (`path`, `version`), `token` (`from`, `env` or `file`, and `at`, the variable or the file), `vault` (`name`, and `file`, the vault file, `null` for the default), `tailscale` (`path`, `address`, the first of `tailscale ip`), `cert` (`domains`, the names `tailscale cert` can get a certificate for).
    /// - `findings`: each one off, in this order, with `kind`, `fault` (what was found, and where) and `fix` (what to do). Empty when nothing is off.
    /// - `next`: the first finding's fix, or that there is nothing to fix.
    ///
    /// For example, on a host whose token file others may read:
    ///
    /// ```json
    /// {
    ///   "found": {
    ///     "op": { "path": "/usr/local/bin/op", "version": "2.30.0" },
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
    /// Shows one topic of this manual, or all of it.
    ///
    /// `optokens help account` shows where optokens finds the service account's token and the vault; `optokens help all` shows the whole manual.
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    Help {
        /// The topic, or `all`.
        #[arg(verbatim_doc_comment)]
        topic: Option<String>,
    },
    /// Stores a Secret, or changes it: sets the Fields it names and keeps the rest.
    ///
    /// ## When to run it
    ///
    /// When a command needs a credential or a Profile that `optokens list` does not show, or one of its Fields must change. Run it once per Secret: two `put`s of one Secret at once may lose one's change.
    ///
    /// ## What it reads and writes
    ///
    /// It reads the Secret from the vault, merges into it what this `put` names, and writes it back as one item, only when that changes it. `--set "NAME=value"` sets a Field that is not secret, split on the first `=`; repeat it. `--field-from-stdin <Label>` sets one Field to all of stdin, one trailing newline dropped: for a value a command makes and pipes in, such as `openssl rand -base64 32 | optokens put deploy-db --set "Username=svc" --field-from-stdin Password`. `--description` replaces the description. A new Secret is `static` unless `--kind profile`. A Profile's labels are environment variables' names, for `env`. How a Secret is laid out in the vault: [Secrets in the vault](help:secrets).
    ///
    /// ## What it answers
    ///
    /// - `secret`: `<service>/<account>`.
    /// - `changed`: whether it wrote; `false` when the Secret already held all it was given.
    /// - `kind`: `static` or `profile`.
    /// - `fields`: the Secret's labels now, `null` for a single value.
    ///
    /// ```json
    /// { "secret": "deploy-db/default", "changed": true, "kind": "static", "fields": ["Username", "Password"] }
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// Every fault it finds, before it writes anything: `bad_name`, `bad_set`, `duplicate_label`, `not_env_name`, `kind_change`, `shape_change`, `needs_link`, `stdin_terminal`, `stdin_empty`, `stdin_not_text`, the service account's faults ([the token and the vault](help:account)), and the vault's (`not_optokens`, `ambiguous`, `op_failed`). Each is in [Secrets in the vault](help:secrets), with its fix.
    ///
    /// ## What trips you up
    ///
    /// - A value a person knows is entered with `--fields` on a one-time link, which this optokens does not serve yet: `--fields`, `--show` and a bare `put <service>` are refused. Never pipe in, or `--set`, a value a person typed or pasted into the chat.
    /// - `--set` puts its value on the command line, where `ps` shows it: only for a value that is not secret (a URL, a model, a user name).
    /// - `put` never drops a Field, nor changes a kind or a single value into Fields: `rm`, then `put` the Secret again.
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
    /// It reads the Secret from the vault and writes nothing.
    ///
    /// ## What it answers
    ///
    /// The single value, or the Field `--field` names, raw on stdout with no newline. A Secret of labelled Fields needs `--field`. With `--json`, one JSON object: `service`, `account`, `kind`, `description` (or `null`), and `fields`, each label with its value (or `value`, for a single value):
    ///
    /// ```json
    /// { "service": "aws", "account": "ci", "kind": "static", "description": "CI deploy", "fields": { "Access Key ID": "AKIA...", "Secret Access Key": "..." } }
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// `bad_name`, `not_found`, `no_such_field`, the service account's faults ([the token and the vault](help:account)), and the vault's (`not_optokens`, `ambiguous`, `op_failed`), in [Secrets in the vault](help:secrets). Its error object goes to stderr, stdout left empty.
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
    },
    /// Prints a Profile's Fields as `export NAME='value'` lines, for `(eval "$(optokens env <project>)"; <command>)`.
    ///
    /// ## When to run it
    ///
    /// To run a command with a Profile's environment variables. Scope it to a subshell, `( ... )`, so the values leave with it.
    ///
    /// ## What it reads and writes
    ///
    /// It reads the Secret from the vault and writes nothing.
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
    /// `bad_name`, `not_found`, `not_env` (a single value, or a label that is not a variable's name), the service account's faults ([the token and the vault](help:account)), and the vault's (`not_optokens`, `ambiguous`, `op_failed`), in [Secrets in the vault](help:secrets). Its error object goes to stderr, stdout left empty, so `eval` runs nothing.
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    Env {
        /// The Secret's service: a Profile's project or provider.
        #[arg(verbatim_doc_comment)]
        service: String,
        /// The Secret's account.
        #[arg(long, default_value = secret::DEFAULT_ACCOUNT, verbatim_doc_comment)]
        account: String,
    },
    /// Lists every Secret in the vault, with its kind, description and Field labels, never a value.
    ///
    /// ## When to run it
    ///
    /// Before `put`, to see whether a Secret is there, and to recall what each is for.
    ///
    /// ## What it reads and writes
    ///
    /// It reads every item tagged `optokens` in the vault, and writes nothing. Items without the tag are not optokens' and not listed.
    ///
    /// ## What it answers
    ///
    /// `secrets`, in title order, each with `service`, `account`, `kind`, `description` (or `null`) and `fields`, its labels (`null` for a single value):
    ///
    /// ```json
    /// { "secrets": [ { "service": "glm", "account": "default", "kind": "profile", "description": "Claude Code to GLM", "fields": ["ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"] } ] }
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// The service account's faults ([the token and the vault](help:account)), `op_failed`, and `not_optokens` for each tagged item that is not optokens' layout, in [Secrets in the vault](help:secrets).
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    List,
    /// Removes a Secret: its item in the vault, every Field with it.
    ///
    /// ## When to run it
    ///
    /// When a credential is retired, or before a `put` that would change a Secret's kind or shape, or drop a Field.
    ///
    /// ## What it reads and writes
    ///
    /// It finds the Secret's item in the vault and deletes it.
    ///
    /// ## What it answers
    ///
    /// `secret`, `<service>/<account>`, and `changed`: `false` when there was no such Secret, which is no fault, so it can run again.
    ///
    /// ```json
    /// { "secret": "cloudflare/default", "changed": true }
    /// ```
    ///
    /// ## What it may refuse
    ///
    /// `bad_name`, the service account's faults ([the token and the vault](help:account)), and the vault's (`not_optokens`, `ambiguous`, `op_failed`), in [Secrets in the vault](help:secrets).
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
/// - The token is handed to `op` only in its environment, never on a command line.
#[derive(Topic)]
#[topic(name = "account")]
struct AccountTopic;

/// How optokens keeps a Secret in the vault, and every fault a command about a Secret may refuse with.
///
/// ## One item per Secret
///
/// A Secret is one item of the vault, of the category `{const:CATEGORY}`, titled `<service>/<account>` and tagged `{const:TAG}`. Its values are the fields of the section `{const:VALUES}`, each labelled with its Field's label (a single value is one field, `{const:SINGLE}`). Its kind, its description and whether it is a single value are the fields of the section `{const:META}`, so a Field may be called `kind` or `description` without a clash.
///
/// optokens reads only items tagged `{const:TAG}`. An item of a Secret's title without the tag, or one whose section `{const:META}` is not this layout, is refused by name (`not_optokens`), never guessed at. Edit a Secret with optokens, not in 1Password.
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
        .constant("BOUND", format!("{}s", doctor::BOUND.as_secs()))
        .constant("TOKEN_ENV", account::TOKEN_ENV)
        .constant("TOKEN_FILE", account::TOKEN_FILE)
        .constant("VAULT_FILE", account::VAULT_FILE)
        .constant("DEFAULT_VAULT", account::DEFAULT_VAULT)
        .constant("CATEGORY", item::CATEGORY)
        .constant("TAG", item::TAG)
        .constant("VALUES", item::VALUES)
        .constant("META", item::META)
        .constant("SINGLE", item::SINGLE)
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
        } => commands::get(&env, &service, &account, field.as_deref(), json),
        Cmd::Env { service, account } => commands::env(&env, &service, &account),
        Cmd::List => commands::list(&env),
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
