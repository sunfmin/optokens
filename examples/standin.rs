//! A stand-in for the CLIs optokens runs, for its tests: one binary, linked
//! under each one's name (`op`, `tailscale`) into a directory placed first on
//! `PATH`. Its state is one JSON file, named by `OPTOKENS_STANDIN_STATE`:
//! what each program answers, the faults to inject, the vault's items, and
//! every call it got. Each call of `op` also records what it could see: every
//! process's command line (`ps`) and every file under `TMPDIR`.

#[path = "standin/keep.rs"]
mod keep;
#[allow(dead_code)]
#[path = "../src/op.rs"]
mod op;
#[allow(dead_code)]
#[path = "../src/tailscale.rs"]
mod tailscale;

use keep::keep;

use serde_json::{Value, json};
use std::io::Read;
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
    // Records the call: its program, its arguments, whether the token was in its environment.
    let mut call = json!({ "program": program, "args": args, "token_in_env": std::env::var_os(op::TOKEN_ENV).is_some() });
    if program == op::PROGRAM {
        call["seen"] = seen();
    }
    match state["calls"].as_array_mut() {
        Some(calls) => calls.push(call),
        None => state["calls"] = json!([call]),
    }
    let save = |state: &Value| {
        std::fs::write(&state_path, serde_json::to_string_pretty(state).unwrap()).unwrap()
    };
    save(&state);

    let me = state[program.as_str()].clone();
    if let Some(ms) = me["hang_ms"].as_u64() {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    // A fault injected for every call, or for one verb of `op item` (`fail.edit`).
    let verb = words.get(1).copied().unwrap_or_default();
    if let Some(code) = me["exit"].as_i64().or(me["fail"][verb].as_i64()) {
        eprintln!("{}", me["stderr"].as_str().unwrap_or("injected failure"));
        std::process::exit(code as i32);
    }
    let answer = match (program.as_str(), words.as_slice()) {
        (op::PROGRAM, w) if w == op::VERSION => {
            me["version"].as_str().unwrap_or("2.30.0").to_string()
        }
        // The vaults the service account sees: `op.vaults`, else `optokens`.
        (op::PROGRAM, [op::VAULT, op::LIST, ..]) => {
            signed_in(&me);
            let names = me["vaults"].as_array().cloned();
            let names = names.unwrap_or_else(|| vec![json!("optokens")]);
            let vaults: Vec<Value> = names
                .iter()
                .enumerate()
                .map(|(i, n)| json!({ "id": format!("v{i}"), "name": n }))
                .collect();
            json!(vaults).to_string()
        }
        (op::PROGRAM, [op::ITEM, ..]) => {
            signed_in(&me);
            if let (Some(vaults), Some(vault)) = (me["vaults"].as_array(), flag(&words, "--vault"))
                && !vaults.iter().any(|v| v == vault)
            {
                eprintln!("[ERROR] \"{vault}\" isn't a vault in this account.");
                std::process::exit(1);
            }
            let answer = item(&mut state, &words[1..]);
            save(&state);
            answer
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
        _ => unknown(&program, args),
    };
    println!("{answer}");
}

/// With `op.token` set, `op` refuses any other token in its environment, as
/// 1Password refuses a token it did not issue.
fn signed_in(me: &Value) {
    if let Some(token) = me["token"].as_str()
        && std::env::var(op::TOKEN_ENV).ok().as_deref() != Some(token)
    {
        eprintln!("[ERROR] invalid service account token");
        std::process::exit(1);
    }
}

/// The word after `name` in `words`.
fn flag<'a>(words: &[&'a str], name: &str) -> Option<&'a str> {
    let at = words.iter().position(|w| *w == name)?;
    words.get(at + 1).copied()
}

fn unknown(program: &str, args: &[String]) -> ! {
    // As the real CLI does with what it does not take.
    eprintln!("{program}: unknown command {args:?}");
    std::process::exit(64);
}

/// Every process's command line, and every file under `TMPDIR` with what it holds.
fn seen() -> Value {
    let ps = std::process::Command::new("/bin/ps")
        .args(["-A", "-ww", "-o", "args="])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_else(|e| format!("ps failed: {e}"));
    let mut files = Vec::new();
    if let Some(tmp) = std::env::var_os("TMPDIR") {
        walk(Path::new(&tmp), &mut files);
    }
    json!({ "ps": ps, "tmp": files })
}

fn walk(dir: &Path, files: &mut Vec<Value>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, files);
        } else {
            let text = std::fs::read(&path).map(|b| String::from_utf8_lossy(&b).into_owned());
            files.push(json!({ "path": path, "text": text.unwrap_or_default() }));
        }
    }
}

/// `op item ...` against the items in `state.op.items`, as `op` keeps them.
fn item(state: &mut Value, words: &[&str]) -> String {
    let vault = flag(words, "--vault")
        .expect("every item call names the vault")
        .to_string();
    let missing = |id: &str| -> ! {
        eprintln!("[ERROR] \"{id}\" isn't an item in the \"{vault}\" vault.");
        std::process::exit(1)
    };
    if state["op"]["items"].is_null() {
        state["op"]["items"] = json!([]);
    }
    // `op.lose_writes`: a create answers as stored, but nothing is kept.
    let lose = state["op"]["lose_writes"] == true;
    let items = state["op"]["items"].as_array_mut().unwrap();
    let position = |items: &Vec<Value>, id: &str| {
        items
            .iter()
            .position(|i| i["id"] == id && i["vault"]["name"] == vault.as_str())
    };
    match words {
        [op::LIST, ..] => {
            // In no promised order: newest first.
            let summaries: Vec<Value> = items
                .iter()
                .rev()
                .filter(|i| i["vault"]["name"] == vault.as_str())
                .map(|i| json!({ "id": i["id"], "title": i["title"], "tags": i["tags"], "category": i["category"], "vault": i["vault"] }))
                .collect();
            json!(summaries).to_string()
        }
        [op::GET, id, ..] => match position(items, id) {
            Some(i) => items[i].to_string(),
            None => missing(id),
        },
        [op::CREATE, ..] => {
            let id = format!("id{}", items.len() + 1);
            let item = keep(&stdin_template(), &id, &vault);
            if !lose {
                items.push(item.clone());
            }
            item.to_string()
        }
        [op::EDIT, id, ..] => match position(items, id) {
            Some(i) => {
                items[i] = keep(&stdin_template(), id, &vault);
                items[i].to_string()
            }
            None => missing(id),
        },
        [op::DELETE, id, ..] => match position(items, id) {
            Some(i) => {
                items.remove(i);
                String::new()
            }
            None => missing(id),
        },
        _ => unknown(
            op::PROGRAM,
            &words.iter().map(|w| w.to_string()).collect::<Vec<_>>(),
        ),
    }
}

fn stdin_template() -> Value {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).unwrap();
    serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("[ERROR] invalid JSON in piped input: {e}");
        std::process::exit(1)
    })
}
