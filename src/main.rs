//! optokens: keeps an agent's secrets in a 1Password vault through a service account, entered through a one-time link.
//! `optokens --help` is the manual and its only copy.

mod access;
mod account;
mod cli;
mod commands;
mod doctor;
mod item;
// The one-time link's rules; put and init, not built yet, serve them.
#[cfg_attr(not(test), allow(dead_code, unused_imports))]
mod link;
mod op;
mod program;
mod refusal;
mod secret;
mod store;
mod tailscale;

// build.rs runs it to stamp the version; compiled here too, for its tests.
#[cfg_attr(not(test), allow(dead_code))]
mod version;

use std::io::Write;

agent_help::binary!("optokens");

fn main() {
    let answer = cli::run(std::env::args_os());
    // A reader that closes early (`| head`) ends the answer quietly: print! would panic.
    let _ = std::io::stdout().lock().write_all(answer.stdout.as_bytes());
    let _ = std::io::stderr().lock().write_all(answer.stderr.as_bytes());
    std::process::exit(answer.code);
}
