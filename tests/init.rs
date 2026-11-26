//! `init`, the real binary: the token through the one-time link, the files it
//! writes, and its checks of the vault against the stand-in `op`, whose
//! `op.token` makes it refuse any other token.
#![cfg(unix)]

mod common;

use common::link::start;
use common::{Host, Ran};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// The token a person enters: it must reach `op`'s environment and the token
/// file, and nothing else.
const TOKEN: &str = "ops_MARKER-9d2e-the-new-token";

/// A host on the tailnet (127.0.0.1, no certificate) whose `op` takes
/// [`TOKEN`] alone, its state's `op` merged with `op`.
fn host(op: Value) -> Host {
    let mut state = json!({ "op": { "token": TOKEN },
        "tailscale": { "ip": ["127.0.0.1"], "cert": { "error": "Access denied" } } });
    for (k, v) in op.as_object().unwrap() {
        state["op"][k] = v.clone();
    }
    Host::new(&["op", "tailscale"], state)
}

/// `init args`, its link submitted with [`TOKEN`]: what it printed before
/// the link, and how it ended.
fn init(host: &Host, args: &[&str], env: &[(&str, &str)]) -> (String, Ran) {
    let waiting = start(host, &[&["init"], args].concat(), env);
    let (status, page) = waiting.request("GET", "");
    assert_eq!(status, 200);
    assert!(
        page.contains(r#"<label for="f0">1Password service account token</label>"#)
            && page.contains(r#"name="f0" type="password""#),
        "{page}"
    );
    assert_eq!(waiting.request("POST", &format!("f0={TOKEN}%0A")).0, 200);
    let said = waiting.said.clone();
    (said, waiting.finish())
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn kinds(answer: &Value) -> Vec<&str> {
    let faults = answer["error"].as_array().unwrap();
    faults
        .iter()
        .map(|f| f["kind"].as_str().unwrap_or("-"))
        .collect()
}

/// Each `op` call's first two words.
fn op_verbs(host: &Host) -> Vec<String> {
    let calls = host.calls();
    let calls = calls.as_array().into_iter().flatten();
    calls
        .filter(|c| c["program"] == "op")
        .map(|c| {
            format!(
                "{} {}",
                c["args"][0].as_str().unwrap(),
                c["args"][1].as_str().unwrap()
            )
        })
        .collect()
}

/// The config directory's files, by name.
fn files(host: &Host) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(host.config())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn the_token_is_written_owner_only_and_checked_with_op_and_a_second_run_is_the_same() {
    let host = host(json!({}));
    // An older, open token file and directory, which init replaces.
    let old = host.token_file(0o644);
    std::fs::set_permissions(host.config(), std::fs::Permissions::from_mode(0o755)).unwrap();
    // The environment's token is another: the checks must use the new one.
    let env = [("OP_SERVICE_ACCOUNT_TOKEN", "ops_old")];
    let (said, ran) = init(&host, &[], &env);
    assert!(
        said.ends_with("optokens: open this link to enter the 1Password service account token for the vault `optokens` (it works once, within 10 minutes):\n"),
        "{said}"
    );
    assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
    let config = host.config();
    let token_file = config.join("token");
    assert_eq!(token_file, old);
    assert_eq!(
        ran.json(),
        json!({
            "token": { "from": "file", "at": token_file },
            "vault": { "name": "optokens", "file": config.join("vault") },
            "checks": ["vault_listed", "vault_read", "probe_written", "probe_read_back", "probe_removed"],
        })
    );
    assert_eq!(mode(&config), 0o700);
    assert_eq!(mode(&token_file), 0o600);
    assert_eq!(mode(&config.join("vault")), 0o600);
    assert_eq!(
        std::fs::read_to_string(&token_file).unwrap(),
        format!("{TOKEN}\n")
    );
    assert_eq!(
        std::fs::read_to_string(config.join("vault")).unwrap(),
        "optokens\n"
    );
    assert_eq!(files(&host), ["token", "vault"], "no file left beside them");
    assert_eq!(
        op_verbs(&host),
        [
            "vault list",
            "item list",
            "item create",
            "item list",
            "item get",
            "item delete"
        ]
    );
    assert_eq!(
        host.state()["op"]["items"],
        json!([]),
        "the probe is removed"
    );
    let probe = host
        .calls()
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["args"][1] == "create")
        .cloned();
    assert_eq!(
        probe.unwrap()["args"],
        json!([
            "item", "create", "--vault", "optokens", "--format", "json", "-"
        ])
    );

    // The token is in no output, no command line, no temporary file.
    assert!(
        !ran.stdout.contains("MARKER") && !ran.stderr.contains("MARKER"),
        "{}",
        ran.stderr
    );
    for call in host.calls().as_array().unwrap() {
        assert!(!call["args"].to_string().contains("MARKER"), "{call}");
        if call["program"] == "op" {
            assert_eq!(call["token_in_env"], true, "{call}");
            let ps = call["seen"]["ps"].as_str().unwrap();
            assert!(ps.contains("op ") && !ps.contains("MARKER"), "{ps}");
            assert!(
                !call["seen"]["tmp"].to_string().contains("MARKER"),
                "{call}"
            );
        } else {
            assert_eq!(
                call["token_in_env"], false,
                "tailscale gets no token: {call}"
            );
        }
    }

    // Again, with the same input: the same world.
    let (_, again) = init(&host, &[], &env);
    assert_eq!(again.code, 0, "{}", again.stdout);
    assert_eq!(again.json(), ran.json());
    assert_eq!(files(&host), ["token", "vault"]);
    assert_eq!((mode(&config), mode(&token_file)), (0o700, 0o600));
    assert_eq!(
        std::fs::read_to_string(&token_file).unwrap(),
        format!("{TOKEN}\n")
    );
}

#[test]
fn a_vault_the_service_account_cannot_see_is_refused_and_the_token_kept_for_check() {
    let host = host(json!({ "vaults": ["Private"] }));
    let (_, ran) = init(&host, &["--vault", "team"], &[]);
    assert_eq!(ran.code, 2, "{}", ran.stdout);
    assert_eq!(kinds(&ran.json()), ["vault_listed"]);
    let token_file = host.config().join("token");
    let fault = ran.json()["error"][0]["fault"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        fault,
        format!(
            "check `vault_listed`: `op vault list` does not show the vault `team`: it does not exist, or the service account has no access to it; the token file `{}` and the vault file are written and kept, so once it is fixed `optokens init --check` checks again with no new link",
            token_file.display()
        )
    );
    assert_eq!(
        ran.json()["error"][0]["fix"],
        "in 1Password's web UI, under Developer → Service Accounts, give the service account read and write on the vault `team` (create the vault first if it is not there), then run `optokens init --check`"
    );
    assert_eq!(op_verbs(&host), ["vault list"]);
    assert_eq!(mode(&token_file), 0o600);
    assert_eq!(
        std::fs::read_to_string(host.config().join("vault")).unwrap(),
        "team\n"
    );

    // The grant given: `--check` alone, with the files init kept, no link.
    let mut state = host.state();
    state["op"]["vaults"] = json!(["Private", "team"]);
    state["calls"] = Value::Null;
    host.set_state(&state);
    let check = host.run(&["init", "--check"], &[], None);
    assert_eq!(check.code, 0, "{}", check.stdout);
    assert_eq!(check.json()["vault"]["name"], "team");
    assert_eq!(check.json()["token"]["from"], "file");
    let calls = host.calls();
    assert!(
        calls
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["program"] == "op"),
        "no `tailscale`, so no second link: {calls}"
    );
}

#[test]
fn no_write_grant_is_refused_at_the_probe_and_a_probe_left_behind_is_written_over() {
    let host = host(
        json!({ "fail": { "create": 1 }, "stderr": "[ERROR] You do not have permission to perform this action" }),
    );
    let (_, ran) = init(&host, &[], &[]);
    assert_eq!(ran.code, 2);
    assert_eq!(kinds(&ran.json()), ["probe_written"]);
    let fault = ran.json()["error"][0]["fault"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        fault.starts_with("check `probe_written`: `op item create --vault optokens --format json -`: it exited 1: [ERROR] You do not have permission"),
        "{fault}"
    );
    assert_eq!(op_verbs(&host), ["vault list", "item list", "item create"]);

    // Written, but not removed: the probe stays, and the next check writes over it.
    let mut state = host.state();
    state["op"]["fail"] = json!({ "delete": 1 });
    host.set_state(&state);
    let left = host.run(
        &["init", "--check"],
        &[("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)],
        None,
    );
    assert_eq!(kinds(&left.json()), ["probe_removed"]);
    assert_eq!(host.state()["op"]["items"].as_array().unwrap().len(), 1);
    state = host.state();
    state["op"]["fail"] = Value::Null;
    state["calls"] = Value::Null;
    host.set_state(&state);
    let check = host.run(
        &["init", "--check"],
        &[("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)],
        None,
    );
    assert_eq!(check.code, 0, "{}", check.stdout);
    assert_eq!(
        check.json()["token"],
        json!({ "from": "env", "at": "OP_SERVICE_ACCOUNT_TOKEN" })
    );
    assert_eq!(
        op_verbs(&host),
        [
            "vault list",
            "item list",
            "item get",
            "item edit",
            "item list",
            "item get",
            "item delete"
        ]
    );
    assert_eq!(host.state()["op"]["items"], json!([]));
}

#[test]
fn nothing_is_written_before_a_submission_nor_when_init_is_refused() {
    let host = host(json!({}));
    let waiting = start(
        &host,
        &["init"],
        &[("OPTOKENS_TEST_LINK_LIFETIME_MS", "300")],
    );
    let ran = waiting.finish();
    assert_eq!(ran.code, 2);
    assert_eq!(kinds(&ran.json()), ["link_expired"]);
    assert_eq!(
        ran.json()["error"][0]["fault"],
        "no value was submitted on the one-time link for `optokens init` before it expired, so nothing was stored"
    );
    assert_eq!(
        ran.json()["error"][0]["fix"],
        "run the same `optokens init` again, and open its new link sooner"
    );
    assert!(!host.config().exists());
    assert!(op_verbs(&host).is_empty());

    let bare = Host::new(&["op"], json!({}));
    let refused = bare.run(&["init", "--vault", " "], &[], None);
    assert_eq!(refused.code, 2);
    assert_eq!(kinds(&refused.json()), ["-", "tailscale_missing"]);
    assert_eq!(
        refused.json()["error"][0]["fault"],
        "`--vault \" \"`: a vault's name is one line, not empty"
    );
    assert_eq!(bare.calls(), Value::Null);
    let both = bare.run(&["init", "--check", "--vault", "team"], &[], None);
    assert_eq!(both.code, 2);
    let none = bare.run(&["init", "--check"], &[], None);
    assert_eq!(kinds(&none.json()), ["no_token"]);
}
