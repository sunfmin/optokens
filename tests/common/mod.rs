//! A host for one test of the real binary: a home, a bin directory of
//! stand-ins (`examples/standin.rs`, for `tailscale`) placed first on `PATH`,
//! and the state they share with the stand-in Core the binary runs on
//! (`src/standin.rs`), its vault's items as the Core answers them.
#![allow(dead_code)] // each test file uses part of it

pub mod link;

use serde_json::{Value, json};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct Host {
    pub dir: tempfile::TempDir,
}

/// What one run of optokens did: its exit code, stdout and stderr.
pub struct Ran {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Ran {
    /// Stdout as the one JSON object it holds.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("{e}: {}", self.stdout))
    }

    /// Stderr as the one JSON object it holds.
    pub fn error(&self) -> Value {
        serde_json::from_str(&self.stderr).unwrap_or_else(|e| panic!("{e}: {}", self.stderr))
    }
}

/// What a finished run printed, and how it exited.
pub fn ran(out: std::process::Output) -> Ran {
    Ran {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn standin() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_optokens"))
        .parent()
        .unwrap()
        .join("examples/standin")
}

impl Host {
    /// `programs` linked to the stand-in, which answers as `state` says.
    pub fn new(programs: &[&str], state: Value) -> Host {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["bin", "home", "tmp"] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        for program in programs {
            std::os::unix::fs::symlink(standin(), dir.path().join("bin").join(program)).unwrap();
        }
        let host = Host { dir };
        host.set_state(&state);
        host
    }

    pub fn state_file(&self) -> PathBuf {
        self.dir.path().join("state.json")
    }

    pub fn state(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.state_file()).unwrap()).unwrap()
    }

    pub fn set_state(&self, state: &Value) {
        std::fs::write(self.state_file(), state.to_string()).unwrap();
    }

    /// Each value's field type in the vault's item `title`, by its label:
    /// `{ "Label": "Concealed" }`.
    #[allow(dead_code)] // not every test binary looks at types
    pub fn field_types(&self, title: &str) -> Value {
        let items = self.items();
        let item = items
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["title"] == title)
            .unwrap_or_else(|| panic!("no item {title}: {items}"))
            .clone();
        item["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["sectionId"] == "fields")
            .map(|f| {
                (
                    f["title"].as_str().unwrap().to_string(),
                    f["fieldType"].clone(),
                )
            })
            .collect()
    }

    /// The vault's items, as the Core answers them.
    pub fn items(&self) -> Value {
        let items = self.state()["core"]["items"].clone();
        if items.is_null() { json!([]) } else { items }
    }

    pub fn calls(&self) -> Value {
        self.state()["calls"].clone()
    }

    /// The Core's calls since the last [`Host::forget_calls`], by method.
    pub fn core_calls(&self) -> Vec<String> {
        let calls = self.calls();
        calls
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["program"] == "core")
            .map(|c| c["method"].as_str().unwrap().to_string())
            .collect()
    }

    /// Drops the calls recorded so far.
    pub fn forget_calls(&self) {
        let mut state = self.state();
        state["calls"] = Value::Null;
        self.set_state(&state);
    }

    /// Every file under the config directory, with what it holds: for a
    /// test that no value is in any of them.
    pub fn config_files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(self.config())
            .into_iter()
            .flatten()
            .flatten()
        {
            files.push((
                entry.path(),
                std::fs::read(entry.path()).unwrap_or_default(),
            ));
        }
        files
    }

    /// The Copy dropped, as on a host that never synced.
    pub fn cold(&self) {
        let _ = std::fs::remove_file(self.config().join("copy"));
    }

    pub fn config(&self) -> PathBuf {
        self.dir.path().join("home/.config/optokens")
    }

    /// The token file, written with `mode`.
    pub fn token_file(&self, mode: u32) -> PathBuf {
        std::fs::create_dir_all(self.config()).unwrap();
        let path = self.config().join("token");
        std::fs::write(&path, "ops_from_file\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// optokens `args` with only `env`, the stand-ins and this host's home
    /// and `TMPDIR`; `stdin` piped in, else empty.
    pub fn run(&self, args: &[&str], env: &[(&str, &str)], stdin: Option<&[u8]>) -> Ran {
        let mut child = self.spawn(args, env);
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(stdin.unwrap_or_default()).unwrap();
        drop(pipe);
        ran(child.wait_with_output().unwrap())
    }

    /// optokens `args` started as [`Host::run`] starts it, its stdin, stdout
    /// and stderr piped, for a test that talks to it while it runs.
    pub fn spawn(&self, args: &[&str], env: &[(&str, &str)]) -> std::process::Child {
        self.command(env!("CARGO_BIN_EXE_optokens"), args, env)
    }

    /// `script` run by `/bin/bash -c` as [`Host::run`] runs optokens, which
    /// it finds as `"$0"`: for `<(command)`. `env` reaches bash too, so a
    /// value in it reaches a builtin `printf` without a command line.
    pub fn bash(&self, script: &str, env: &[(&str, &str)]) -> Ran {
        let optokens = env!("CARGO_BIN_EXE_optokens");
        let child = self.command("/bin/bash", &["-c", script, optokens], env);
        ran(child.wait_with_output().unwrap())
    }

    fn command(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> std::process::Child {
        Command::new(program)
            .args(args)
            .env_clear()
            // A coverage run's profile path: without it the run writes `default_*.profraw` here and counts none of it.
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
            .env("PATH", self.dir.path().join("bin"))
            .env("HOME", self.dir.path().join("home"))
            .env("TMPDIR", self.dir.path().join("tmp"))
            .env("OPTOKENS_STANDIN_STATE", self.state_file())
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// `optokens doctor` with only `env` and the stand-ins: its exit code and answer.
    pub fn doctor(&self, env: &[(&str, &str)]) -> (i32, Value) {
        let ran = self.run(&["doctor"], env, None);
        (ran.code, ran.json())
    }
}

/// A vault item as the Core answers one optokens wrote, `fields` sorted by
/// id as the Core sorts them, in the vault `optokens` (`v0`).
pub fn stored(id: &str, title: &str, tags: Value, fields: Value) -> Value {
    let mut fields = fields.as_array().unwrap().clone();
    fields.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    json!({ "id": id, "title": title, "category": "SecureNote", "vaultId": "v0", "version": 1,
            "tags": tags, "notes": "", "fields": fields, "websites": [], "files": [],
            "sections": [{ "id": "fields", "title": "fields" }, { "id": "optokens", "title": "optokens" }, { "id": "", "title": "" }],
            "createdAt": "t", "updatedAt": "t1" })
}

/// The `i`th value of the section `fields`, plain text, as optokens and
/// mytokens write it.
pub fn value(i: usize, label: &str, value: &str) -> Value {
    json!({ "id": format!("fields.{i}"), "title": label, "sectionId": "fields", "fieldType": "Text", "value": value })
}

/// A field of the section `optokens`.
pub fn meta(label: &str, value: &str) -> Value {
    json!({ "id": format!("optokens.{label}"), "title": label, "sectionId": "optokens", "fieldType": "Text", "value": value })
}

impl Host {
    /// The item `title` changed by another host: its Field `label` set to
    /// `value`, its version and `updatedAt` raised, as 1Password does.
    pub fn change(&self, title: &str, label: &str, value: &str) {
        let mut state = self.state();
        let items = state["core"]["items"].as_array_mut().unwrap();
        let item = items.iter_mut().find(|i| i["title"] == title).unwrap();
        let n = item["version"].as_u64().unwrap() + 1;
        item["version"] = json!(n);
        item["updatedAt"] = json!(format!("t{n}"));
        let fields = item["fields"].as_array_mut().unwrap();
        let field = fields.iter_mut().find(|f| f["title"] == label).unwrap();
        field["value"] = json!(value);
        self.set_state(&state);
    }
}

/// What a Copy's first Sync calls: a sign-in, the vault's id, one list.
pub const FIRST_SYNC: [&str; 3] = ["init_client", "VaultsList", "ItemsList"];

/// What a Sync calls once the Copy keeps its vault's id: a sign-in, one list.
pub const SYNC: [&str; 2] = ["init_client", "ItemsList"];

/// [`FIRST_SYNC`] and then `more`.
pub fn first_synced(more: &[&str]) -> Vec<String> {
    FIRST_SYNC
        .iter()
        .chain(more)
        .map(|c| c.to_string())
        .collect()
}

/// [`SYNC`] and then `more`.
pub fn synced(more: &[&str]) -> Vec<String> {
    SYNC.iter().chain(more).map(|c| c.to_string()).collect()
}
