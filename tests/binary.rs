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
    let release = env!("CARGO_PKG_VERSION");
    assert!(
        version == release || version.starts_with(&format!("{release}+")),
        "{version}"
    );
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
