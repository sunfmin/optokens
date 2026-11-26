//! optokens: keeps an agent's secrets in a 1Password vault through a service account, entered through a one-time link.
//! `optokens --help` is the manual and its only copy.

mod access;
mod account;
mod cli;
mod doctor;
mod op;
mod program;
mod refusal;
mod tailscale;

// build.rs runs it to stamp the version; compiled here too, for its tests.
#[cfg_attr(not(test), allow(dead_code))]
mod version;

use std::io::Write;

agent_help::binary!("optokens");

fn main() {
    let (answer, code) = cli::run(std::env::args_os());
    // A reader that closes early (`| head`) ends the answer quietly: println! would panic.
    let _ = writeln!(std::io::stdout().lock(), "{}", answer.trim_end());
    std::process::exit(code);
}
