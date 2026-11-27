//! `optokens doctor`, the real binary, with `tailscale` replaced by the
//! stand-in of `examples/standin.rs` placed first on `PATH`, and no `op`:
//! optokens needs none.
#![cfg(unix)]

mod common;

use common::Host;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn healthy() -> Value {
    json!({
        "tailscale": { "ip": ["100.64.0.7", "fd7a:115c:a1e0::7"], "cert_domains": ["build.tail1234.ts.net"] },
    })
}

fn kinds(answer: &Value) -> Vec<&str> {
    answer["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap())
        .collect()
}

#[test]
fn a_healthy_host_has_no_findings_and_no_program_is_given_the_token() {
    let host = Host::new(&["tailscale"], healthy());
    let (code, answer) = host.doctor(&[("OP_SERVICE_ACCOUNT_TOKEN", "ops_from_env")]);
    assert_eq!(code, 0);
    assert_eq!(answer["findings"], json!([]), "{answer}");
    let bin = host.dir.path().join("bin");
    assert_eq!(
        answer["found"],
        json!({

            "token": { "from": "env", "at": "OP_SERVICE_ACCOUNT_TOKEN" },
            "vault": { "name": "optokens", "file": null },
            "tailscale": { "path": bin.join("tailscale"), "address": "100.64.0.7" },
            "cert": { "domains": ["build.tail1234.ts.net"] },
        })
    );
    assert_eq!(answer["next"], "nothing to fix: this host can run optokens");
    assert!(!answer.to_string().contains("ops_from_env"), "{answer}");
    let calls = host.calls();
    let args: Vec<_> = calls
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["program"].clone(), c["args"].clone()))
        .collect();
    assert_eq!(
        args,
        [
            (json!("tailscale"), json!(["ip"])),
            (json!("tailscale"), json!(["status", "--json"])),
        ]
    );
    assert!(
        calls
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["token_in_env"] == false),
        "{calls}"
    );
}

#[test]
fn a_token_file_at_0644_is_refused_with_its_chmod_and_left_as_it_is() {
    let host = Host::new(&["tailscale"], healthy());
    let file = host.token_file(0o644);
    let (code, answer) = host.doctor(&[]);
    assert_eq!(code, 0);
    assert_eq!(kinds(&answer), ["token_file_open"], "{answer}");
    let finding = &answer["findings"][0];
    assert_eq!(finding["fix"], format!("chmod 600 {}", file.display()));
    assert!(
        finding["fault"]
            .as_str()
            .unwrap()
            .contains("has mode 0644, not 0600"),
        "{finding}"
    );
    assert_eq!(answer["next"], finding["fix"]);
    assert_eq!(answer["found"]["token"], Value::Null);
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "doctor changes nothing");
    assert!(!answer.to_string().contains("ops_from_file"), "{answer}");
}

#[test]
fn a_token_file_that_cannot_be_opened_is_unreadable_not_missing() {
    let host = Host::new(&["tailscale"], healthy());
    let file = host.token_file(0o000);
    let (_, answer) = host.doctor(&[]);
    assert_eq!(kinds(&answer), ["unreadable"], "{answer}");
    let fault = answer["findings"][0]["fault"].as_str().unwrap();
    assert!(
        fault.starts_with(&format!(
            "cannot read `{}`: Permission denied",
            file.display()
        )),
        "{fault}"
    );
}

#[test]
fn a_token_file_at_0600_is_found_and_the_vault_file_names_the_vault() {
    let host = Host::new(&["tailscale"], healthy());
    let file = host.token_file(0o600);
    std::fs::write(host.config().join("vault"), "team\n").unwrap();
    let (_, answer) = host.doctor(&[]);
    assert_eq!(answer["findings"], json!([]), "{answer}");
    assert_eq!(
        answer["found"]["token"],
        json!({ "from": "file", "at": file })
    );
    assert_eq!(
        answer["found"]["vault"],
        json!({ "name": "team", "file": host.config().join("vault") })
    );
}

#[test]
fn xdg_config_home_holds_the_token_file_when_set() {
    let host = Host::new(&["tailscale"], healthy());
    let xdg = host.dir.path().join("xdg");
    std::fs::create_dir_all(xdg.join("optokens")).unwrap();
    let file = xdg.join("optokens/token");
    std::fs::write(&file, "ops").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let (_, answer) = host.doctor(&[("XDG_CONFIG_HOME", xdg.to_str().unwrap())]);
    assert_eq!(
        answer["findings"][0]["fix"],
        format!("chmod 600 {}", file.display())
    );
}

#[test]
fn a_bare_host_names_each_fix() {
    let host = Host::new(&[], json!({}));
    let (code, answer) = host.doctor(&[]);
    assert_eq!(code, 0);
    assert_eq!(
        kinds(&answer),
        ["no_token", "tailscale_missing"],
        "{answer}"
    );
    let token = host.config().join("token");
    assert_eq!(
        answer["findings"][0]["fix"],
        format!(
            "set OP_SERVICE_ACCOUNT_TOKEN to the service account's token, or write it alone into {} and run `chmod 600 {}`",
            token.display(),
            token.display()
        )
    );
    assert_eq!(answer["next"], answer["findings"][0]["fix"]);
}

#[test]
fn a_tailscale_that_hangs_is_cut_off_at_the_bound() {
    let mut state = healthy();
    state["tailscale"]["hang_ms"] = json!(20_000);
    let host = Host::new(&["tailscale"], state);
    let start = Instant::now();
    let (_, answer) = host.doctor(&[("OP_SERVICE_ACCOUNT_TOKEN", "x")]);
    assert!(
        start.elapsed() < Duration::from_secs(8),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(
        kinds(&answer),
        ["no_tailnet_address", "no_cert"],
        "{answer}"
    );
    assert!(
        answer["findings"][0]["fault"]
            .as_str()
            .unwrap()
            .ends_with("it did not answer within 3s"),
        "{answer}"
    );
}

#[test]
fn a_host_off_its_tailnet_and_without_certs_says_so() {
    let host = Host::new(
        &["tailscale"],
        json!({ "tailscale": { "exit": 1, "stderr": "Tailscale is stopped." } }),
    );
    let (_, answer) = host.doctor(&[("OP_SERVICE_ACCOUNT_TOKEN", "x")]);
    assert_eq!(
        kinds(&answer),
        ["no_tailnet_address", "no_cert"],
        "{answer}"
    );
    assert_eq!(answer["findings"][0]["fix"], "run `tailscale up`");
    assert_eq!(
        answer["findings"][0]["fault"],
        "`tailscale ip`: it exited 1: Tailscale is stopped."
    );
    let host = Host::new(
        &["tailscale"],
        json!({ "tailscale": { "ip": ["100.64.0.7"], "cert_domains": [] } }),
    );
    let (_, answer) = host.doctor(&[("OP_SERVICE_ACCOUNT_TOKEN", "x")]);
    assert_eq!(kinds(&answer), ["no_cert"], "{answer}");
    assert_eq!(answer["found"]["cert"], Value::Null);
}
