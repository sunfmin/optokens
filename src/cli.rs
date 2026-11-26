//! The command line, read against the manual: its commands, the manual's
//! pages, and what optokens exits with.

use agent_help::Help;
use clap::{FromArgMatches, Parser, Subcommand};
use serde::Serialize;
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
/// - A 1Password service account's token, with access to the vault.
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
    /// Shows one topic of this manual, or all of it.
    ///
    /// `optokens help all` shows the whole manual.
    #[command(next_help_heading = "Run by the agent", verbatim_doc_comment)]
    Help {
        /// The topic, or `all`.
        #[arg(verbatim_doc_comment)]
        topic: Option<String>,
    },
}

pub(crate) fn help() -> Help {
    Help::new(<Cli as clap::CommandFactory>::command())
        .constant("EXIT_OK", EXIT_OK)
        .constant("EXIT_ERROR", EXIT_ERROR)
}

/// One fault a command found, with the line that fixes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Refusal {
    pub fault: String,
    pub fix: String,
}

pub(crate) fn refusal(fault: &str, fix: &str) -> Refusal {
    Refusal {
        fault: fault.to_string(),
        fix: fix.to_string(),
    }
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
            return refused(vec![refusal(e.to_string().trim(), "run `optokens --help`")]);
        }
    };
    match cli.command {
        Cmd::Help { topic: None } => (help.index().expect("checked"), EXIT_OK),
        Cmd::Help { topic: Some(topic) } => match help.topic_help(&topic) {
            Ok(markdown) => (markdown, EXIT_OK),
            Err(e) => refused(vec![refusal(
                e.to_string().trim(),
                "run `optokens --help` for the topics",
            )]),
        },
    }
}

/// A command that could not run: every fault and its fix, exit {EXIT_ERROR}.
fn refused(refusals: Vec<Refusal>) -> (String, i32) {
    (pretty(&json!({ "error": refusals })), EXIT_ERROR)
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
