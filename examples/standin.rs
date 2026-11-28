//! A stand-in for `tailscale`, the one CLI optokens runs to serve a link, and
//! for `socketfilterfw` and `codesign`, which doctor asks about macOS's
//! firewall, for its tests: linked under its name into a directory placed
//! first on `PATH`. Its state
//! is one JSON file, named by `OPTOKENS_STANDIN_STATE`, which the stand-in
//! Core (`src/standin.rs`) shares: what it answers, the faults to inject, and
//! every call it got, with whether the token was in its environment.

#[allow(dead_code)]
#[path = "../src/firewall.rs"]
mod firewall;
#[allow(dead_code)]
#[path = "../src/tailscale.rs"]
mod tailscale;

use serde_json::{Value, json};
use std::path::Path;

/// The environment variable that names the state file.
const STATE: &str = "OPTOKENS_STANDIN_STATE";
/// The token's variable, which no program optokens runs may get.
const TOKEN_ENV: &str = "OP_SERVICE_ACCOUNT_TOKEN";

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
    // Records the call: its program, its arguments, whether the token was in its environment.
    let call = json!({ "program": program, "args": args, "token_in_env": std::env::var_os(TOKEN_ENV).is_some() });
    match state["calls"].as_array_mut() {
        Some(calls) => calls.push(call),
        None => state["calls"] = json!([call]),
    }
    std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();

    let me = state[program.as_str()].clone();
    if let Some(ms) = me["hang_ms"].as_u64() {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    if let Some(code) = me["exit"].as_i64() {
        eprintln!("{}", me["stderr"].as_str().unwrap_or("injected failure"));
        std::process::exit(code as i32);
    }
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let answer = match (program.as_str(), words.as_slice()) {
        (tailscale::PROGRAM, w) if w == tailscale::IP => me["ip"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        // The certificate and key as PEM (`cert.pem`), or a failure (`cert.error`).
        (tailscale::PROGRAM, w)
            if w.len() == tailscale::CERT.len() + 1 && w.starts_with(tailscale::CERT) =>
        {
            match me["cert"]["pem"].as_str() {
                Some(pem) => pem.to_string(),
                None => {
                    eprintln!(
                        "{}",
                        me["cert"]["error"]
                            .as_str()
                            .unwrap_or("Access denied: cert access denied")
                    );
                    std::process::exit(1);
                }
            }
        }
        (tailscale::PROGRAM, w) if w == tailscale::STATUS => {
            json!({ "BackendState": "Running", tailscale::CERT_DOMAINS: me["cert_domains"] })
                .to_string()
        }
        // `socketfilterfw`: `state` (default 1), `allow_signed` (default
        // true), and `apps`, each `{ "path", "block" }`, as macOS 26 prints
        // them; `app_blocked` (true or false) answers `--getappblocked` as
        // macOS 27 does, and without it that is refused as unknown.
        (_, w) if program == "socketfilterfw" && w == firewall::GLOBAL_STATE => {
            let state = me["state"].as_u64().unwrap_or(1);
            let word = if state == 0 { "disabled" } else { "enabled" };
            format!("Firewall is {word}. (State = {state})")
        }
        (_, w) if program == "socketfilterfw" && w == firewall::ALLOW_SIGNED => {
            let word = if me["allow_signed"].as_bool().unwrap_or(true) {
                "ENABLED"
            } else {
                "DISABLED"
            };
            format!(
                "Automatically allow built-in signed software ENABLED.\nAutomatically allow downloaded signed software {word}."
            )
        }
        (_, [flag, path])
            if program == "socketfilterfw"
                && *flag == firewall::APP_BLOCKED
                && me["app_blocked"].is_boolean() =>
        {
            let word = if me["app_blocked"] == true {
                "blocked"
            } else {
                "permitted"
            };
            format!("Incoming connection to {path} is {word}.")
        }
        (_, w) if program == "socketfilterfw" && w == firewall::LIST_APPS => {
            let apps = me["apps"].as_array().cloned().unwrap_or_default();
            let mut out = format!("Total number of apps = {} \n", apps.len());
            for (i, app) in apps.iter().enumerate() {
                let rule = if app["block"] == true {
                    "Block"
                } else {
                    "Allow"
                };
                out += &format!(
                    "{} : {} \n             ({rule} incoming connections)\n",
                    i + 1,
                    app["path"].as_str().unwrap()
                );
            }
            out
        }
        // `codesign -dv <path>`, on stderr: `team` names the Developer ID's
        // team; without it the signature is ad hoc.
        (_, [flag, path]) if program == "codesign" && *flag == firewall::SIGNATURE => {
            match me["team"].as_str() {
                Some(team) => eprintln!(
                    "Executable={}\nAuthority=Developer ID Application: Someone ({team})\nTeamIdentifier={team}",
                    path
                ),
                None => eprintln!(
                    "Executable={}\nSignature=adhoc\nTeamIdentifier=not set",
                    path
                ),
            }
            String::new()
        }
        // As the real CLI does with what it does not take.
        _ => {
            eprintln!("{program}: unknown command {args:?}");
            std::process::exit(64);
        }
    };
    println!("{answer}");
}
