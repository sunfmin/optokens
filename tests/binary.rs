//! The real binary: its manual, its version, and how it refuses a command line.

use std::process::Command;

fn optokens(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_optokens"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[test]
fn help_is_the_index_and_help_all_the_whole_manual() {
    let (code, index, err) = optokens(&["--help"]);
    assert_eq!((code, err.as_str()), (0, ""));
    assert!(
        index.starts_with("# `optokens`\n\nKeeps an agent's secrets in a 1Password vault through a service account"),
        "{index}"
    );
    assert!(index.contains("`optokens help all`"), "{index}");
    assert_eq!(optokens(&["-h"]).1, index);
    let (code, all, _) = optokens(&["help", "all"]);
    assert_eq!(code, 0);
    assert!(all.contains("## Output"), "{all}");
    assert!(
        all.contains("`get` prints the value alone")
            && all.contains("`env` prints `export NAME='value'` lines"),
        "the manual names both exceptions to one JSON object: {all}"
    );
}

#[test]
fn version_is_stamped_by_build_rs() {
    let (code, out, _) = optokens(&["--version"]);
    assert_eq!(code, 0);
    let version = out.trim().strip_prefix("optokens ").expect(&out);
    // Built in this repository: the development form `1.2.3+<commits>.g<hash>[.dirty]`,
    // its release from the nearest version tag (a cut tags, Cargo.toml stays), else
    // from Cargo.toml's version.
    let (release, build) = version.split_once('+').expect(version);
    let numbers: Vec<&str> = release.split('.').collect();
    let digits = |s: &str, radix| !s.is_empty() && s.chars().all(|c: char| c.is_digit(radix));
    assert!(
        numbers.len() == 3 && numbers.iter().all(|n| digits(n, 10)),
        "{version}"
    );
    let build = build.strip_suffix(".dirty").unwrap_or(build);
    let (commits, hash) = build.split_once(".g").expect(version);
    assert!(digits(commits, 10) && digits(hash, 16), "{version}");
}

#[test]
fn an_unknown_command_is_refused_with_its_fix() {
    let (code, out, _) = optokens(&["nope"]);
    assert_eq!(code, 2);
    let answer: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(answer["error"][0]["fix"], "run `optokens --help`");
}

#[test]
fn an_unknown_topic_is_refused_naming_the_topics() {
    let (code, out, _) = optokens(&["help", "nope"]);
    assert_eq!(code, 2);
    let answer: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        answer["error"][0]["fix"],
        "run `optokens --help` for the topics"
    );
}

#[test]
fn put_help_says_what_the_link_serves_where_for_how_long_and_what_it_answers() {
    let (code, help, _) = optokens(&["put", "--help"]);
    assert_eq!(code, 0);
    for said in [
        "only on this host's tailnet address, from `tailscale ip`",
        "HTTPS, with the certificate `tailscale cert` gives",
        "plain HTTP on the tailnet",
        "one submission, within 10 minutes",
        "on stderr, while it waits, `optokens: open this link to enter the secret for <service> / <account> (it works once, within 10 minutes):`",
        "Stdout keeps only the final JSON answer",
        "## What it answers",
        "`link_expired`",
    ] {
        assert!(help.contains(said), "put --help lacks {said:?}: {help}");
    }
    assert!(
        !help.contains("OPTOKENS_TEST"),
        "the test's lifetime is not in the manual"
    );
}
