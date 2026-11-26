//! `optokens doctor`, the real binary, with `op` and `tailscale` replaced by
//! the stand-in of `examples/standin.rs` placed first on `PATH`.
#![cfg(unix)]

use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// A host for one test: a home, a bin directory of stand-ins, their state.
struct Host {
    dir: tempfile::TempDir,
}

fn standin() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_optokens"))
        .parent()
        .unwrap()
        .join("examples/standin")
}

impl Host {
    /// `programs` linked to the stand-in, which answers as `state` says.
    fn new(programs: &[&str], state: Value) -> Host {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        for program in programs {
            std::os::unix::fs::symlink(standin(), dir.path().join("bin").join(program)).unwrap();
        }
        let host = Host { dir };
        std::fs::write(host.state_file(), state.to_string()).unwrap();
        host
    }

    fn state_file(&self) -> PathBuf {
        self.dir.path().join("state.json")
    }

    fn calls(&self) -> Value {
        let state: Value =
            serde_json::from_str(&std::fs::read_to_string(self.state_file()).unwrap()).unwrap();
        state["calls"].clone()
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("home/.config/optokens")
    }

    /// The token file, written with `mode`.
    fn token_file(&self, mode: u32) -> PathBuf {
        std::fs::create_dir_all(self.config()).unwrap();
        let path = self.config().join("token");
        std::fs::write(&path, "ops_from_file\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// `optokens doctor` with only `env` and the stand-ins: its exit code and answer.
    fn doctor(&self, env: &[(&str, &str)]) -> (i32, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_optokens"))
            .arg("doctor")
            .env_clear()
            .env("PATH", self.dir.path().join("bin"))
            .env("HOME", self.dir.path().join("home"))
            .env("OPTOKENS_STANDIN_STATE", self.state_file())
            .envs(env.iter().copied())
            .output()
            .unwrap();
        let stdout = String::from_utf8(out.stdout).unwrap();
        let answer = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
        (out.status.code().unwrap(), answer)
    }
}

fn healthy() -> Value {
    json!({
        "op": { "version": "2.30.0" },
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
    let host = Host::new(&["op", "tailscale"], healthy());
    let (code, answer) = host.doctor(&[("OP_SERVICE_ACCOUNT_TOKEN", "ops_from_env")]);
    assert_eq!(code, 0);
    assert_eq!(answer["findings"], json!([]), "{answer}");
    let bin = host.dir.path().join("bin");
    assert_eq!(
        answer["found"],
        json!({
            "op": { "path": bin.join("op"), "version": "2.30.0" },
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
            (json!("op"), json!(["--version"])),
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
    let host = Host::new(&["op", "tailscale"], healthy());
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
    let host = Host::new(&["op", "tailscale"], healthy());
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
    let host = Host::new(&["op", "tailscale"], healthy());
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
    let host = Host::new(&["op", "tailscale"], healthy());
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
        ["op_missing", "no_token", "tailscale_missing"],
        "{answer}"
    );
    let token = host.config().join("token");
    assert_eq!(
        answer["findings"][1]["fix"],
        format!(
            "set OP_SERVICE_ACCOUNT_TOKEN to the service account's token, or write it alone into {} and run `chmod 600 {}`",
            token.display(),
            token.display()
        )
    );
    assert_eq!(answer["next"], answer["findings"][0]["fix"]);
    assert!(
        answer["next"]
            .as_str()
            .unwrap()
            .contains("brew install 1password-cli")
    );
}

#[test]
fn an_op_that_hangs_is_cut_off_at_the_bound() {
    let mut state = healthy();
    state["op"]["hang_ms"] = json!(20_000);
    let host = Host::new(&["op", "tailscale"], state);
    let start = Instant::now();
    let (_, answer) = host.doctor(&[("OP_SERVICE_ACCOUNT_TOKEN", "x")]);
    assert!(
        start.elapsed() < Duration::from_secs(8),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(kinds(&answer), ["op_unanswered"], "{answer}");
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
        &["op", "tailscale"],
        json!({ "op": {}, "tailscale": { "exit": 1, "stderr": "Tailscale is stopped." } }),
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
        &["op", "tailscale"],
        json!({ "op": {}, "tailscale": { "ip": ["100.64.0.7"], "cert_domains": [] } }),
    );
    let (_, answer) = host.doctor(&[("OP_SERVICE_ACCOUNT_TOKEN", "x")]);
    assert_eq!(kinds(&answer), ["no_cert"], "{answer}");
    assert_eq!(answer["found"]["cert"], Value::Null);
}
