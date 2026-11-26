//! A host for one test of the real binary: a home, a bin directory of
//! stand-ins (`examples/standin.rs`) placed first on `PATH`, and their state.
#![allow(dead_code)] // each test file uses part of it

use serde_json::Value;
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

    pub fn calls(&self) -> Value {
        self.state()["calls"].clone()
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_optokens"))
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
            .unwrap();
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(stdin.unwrap_or_default()).unwrap();
        drop(pipe);
        let out = child.wait_with_output().unwrap();
        Ran {
            code: out.status.code().unwrap(),
            stdout: String::from_utf8(out.stdout).unwrap(),
            stderr: String::from_utf8(out.stderr).unwrap(),
        }
    }

    /// `optokens doctor` with only `env` and the stand-ins: its exit code and answer.
    pub fn doctor(&self, env: &[(&str, &str)]) -> (i32, Value) {
        let ran = self.run(&["doctor"], env, None);
        (ran.code, ran.json())
    }
}
