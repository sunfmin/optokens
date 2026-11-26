//! A stand-in for the CLIs optokens runs, for its tests: one binary, linked
//! under each one's name (`op`, `tailscale`) into a directory placed first on
//! `PATH`. Its state is one JSON file, named by `OPTOKENS_STANDIN_STATE`:
//! what each program answers, the faults to inject, and every call it got.

#[allow(dead_code)]
#[path = "../src/op.rs"]
mod op;
#[allow(dead_code)]
#[path = "../src/tailscale.rs"]
mod tailscale;

use serde_json::{Value, json};
use std::path::Path;

/// The environment variable that names the state file.
const STATE: &str = "OPTOKENS_STANDIN_STATE";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let program = Path::new(&args[0])
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string();
    let args = &args[1..];
    let state_path = std::env::var_os(STATE).expect("OPTOKENS_STANDIN_STATE names the state file");
    let mut state: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    // Records the call: its program, its arguments, and whether the token was in its environment.
    let call = json!({ "program": program, "args": args, "token_in_env": std::env::var_os(op::TOKEN_ENV).is_some() });
    match state["calls"].as_array_mut() {
        Some(calls) => calls.push(call),
        None => state["calls"] = json!([call]),
    }
    std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

    let me = &state[program.as_str()];
    if let Some(ms) = me["hang_ms"].as_u64() {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    if let Some(code) = me["exit"].as_i64() {
        eprintln!("{}", me["stderr"].as_str().unwrap_or("injected failure"));
        std::process::exit(code as i32);
    }
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let answer = match (program.as_str(), words.as_slice()) {
        (op::PROGRAM, w) if w == op::VERSION => {
            me["version"].as_str().unwrap_or("2.30.0").to_string()
        }
        (tailscale::PROGRAM, w) if w == tailscale::IP => me["ip"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        (tailscale::PROGRAM, w) if w == tailscale::STATUS => {
            json!({ "BackendState": "Running", tailscale::CERT_DOMAINS: me["cert_domains"] })
                .to_string()
        }
        _ => {
            // As the real CLI does with what it does not take.
            eprintln!("{program}: unknown command {args:?}");
            std::process::exit(64);
        }
    };
    println!("{answer}");
}
