//! The command line, read against the manual: its commands, the manual's
//! pages, and what optokens exits with.

use crate::account;
use crate::doctor::{self, Finding, World};
use crate::refusal::Refusal;
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

pub(crate) fn help() -> Help {
    Help::new(<Cli as clap::CommandFactory>::command())
        .topic::<AccountTopic>()
        .table::<account::Fault>("account")
        .table::<Finding>("doctor")
        .constant("BOUND", format!("{}s", doctor::BOUND.as_secs()))
        .constant("TOKEN_ENV", account::TOKEN_ENV)
        .constant("TOKEN_FILE", account::TOKEN_FILE)
        .constant("VAULT_FILE", account::VAULT_FILE)
        .constant("DEFAULT_VAULT", account::DEFAULT_VAULT)
        .constant("EXIT_OK", EXIT_OK)
        .constant("EXIT_ERROR", EXIT_ERROR)
}

/// The command line's answer and exit code. `--help`, `--version` and a
/// command line clap refuses print and exit here, as clap does.
pub(crate) fn run(args: impl IntoIterator<Item = std::ffi::OsString>) -> (String, i32) {
    let help = help();
    let command = help
        .clap()
        .expect("the manual is whole: checked by its test");
    let cli = match command
        .try_get_matches_from(args)
        .and_then(|m| Cli::from_arg_matches(&m))
    {
        Ok(cli) => cli,
        Err(e) if !e.use_stderr() => e.exit(),
        Err(e) => {
            return refused(Refusal::new(e.to_string().trim(), "run `optokens --help`"));
        }
    };
    match cli.command {
        Cmd::Doctor => (pretty(&doctor::doctor(&World::current())), EXIT_OK),
        Cmd::Help { topic: None } => (help.index().expect("checked"), EXIT_OK),
        Cmd::Help { topic: Some(topic) } => match help.topic_help(&topic) {
            Ok(markdown) => (markdown, EXIT_OK),
            Err(e) => refused(Refusal::new(
                e.to_string().trim(),
                "run `optokens --help` for the topics",
            )),
        },
    }
}

/// A command that could not run: its fault and fix, as the one entry of `error`, exit {EXIT_ERROR}.
fn refused(refusal: Refusal) -> (String, i32) {
    (pretty(&json!({ "error": [refusal] })), EXIT_ERROR)
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
