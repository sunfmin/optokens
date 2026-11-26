//! Running another CLI: finding it on `PATH`, and running it within a bound.

use std::ffi::OsStr;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// `name` in the first directory of `path` that holds it as a file.
pub fn find(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let names = if cfg!(windows) {
        vec![format!("{name}.exe"), name.to_string()]
    } else {
        vec![name.to_string()]
    };
    std::env::split_paths(path?)
        .flat_map(|dir| names.iter().map(move |n| dir.join(n)))
        .find(|p| p.is_file())
}

/// What a finished program printed, and its exit code.
#[derive(Debug)]
pub struct Ran {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Ran {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }
}

/// Runs `command`, its stdin empty, and waits at most `bound` for it to
/// exit; past that it is killed and refused, naming the bound.
pub fn bounded(mut command: Command, bound: Duration) -> Result<Ran, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run it: {e}"))?;
    let pipe = |mut p: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = p.read_to_string(&mut text);
            text
        })
    };
    let out = pipe(Box::new(child.stdout.take().expect("piped")));
    let err = pipe(Box::new(child.stderr.take().expect("piped")));
    let start = Instant::now();
    let status = loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => break status,
            None if start.elapsed() >= bound => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("it did not answer within {}s", bound.as_secs()));
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    Ok(Ran {
        code: status.code(),
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}
