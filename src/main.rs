//! optokens: keeps an agent's secrets in a 1Password vault through a service account, entered through a one-time link.
//! `optokens --help` is the manual and its only copy.

mod cli;

// build.rs runs it to stamp the version; compiled here too, for its tests.
#[cfg_attr(not(test), allow(dead_code))]
mod version;

agent_help::binary!("optokens");

fn main() {
    let (answer, code) = cli::run(std::env::args_os());
    println!("{}", answer.trim_end());
    std::process::exit(code);
}
