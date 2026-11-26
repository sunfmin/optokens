//! The real binary: its streams and exit code, as a caller sees them.

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_optokens"))
        .args(args)
        .output()
        .expect("the binary runs")
}

#[test]
fn help_goes_to_stdout_and_exits_zero() {
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("optokens:"));
    assert!(out.stderr.is_empty());
}

#[test]
fn a_refusal_goes_to_stderr_and_exits_two() {
    let out = run(&["nope"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("optokens --help"));
}
