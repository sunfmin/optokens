//! macOS's application firewall, as `socketfilterfw` and `codesign` report
//! it: the one module that builds their command lines and reads their
//! answers. None of these queries needs root. The tests' stand-in shares
//! these constants.

/// Where macOS keeps the firewall's CLI, which is on no `PATH`.
pub const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
/// Where macOS keeps `codesign`.
pub const CODESIGN: &str = "/usr/bin/codesign";
/// What prints whether the firewall is on: `Firewall is enabled. (State = 1)`.
pub const GLOBAL_STATE: &[&str] = &["--getglobalstate"];
/// What prints whether signed software is let in without a prompt.
pub const ALLOW_SIGNED: &[&str] = &["--getallowsigned"];
/// What prints each program the firewall has a rule for, and the rule.
pub const LIST_APPS: &[&str] = &["--listapps"];
/// What prints a binary's signature, on stderr, for the path that follows.
pub const SIGNATURE: &str = "-dv";

/// The firewall's rule for one program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Allow,
    Block,
}

/// Whether `--getglobalstate` says the firewall is on (state 1 or 2).
pub fn enabled(stdout: &str) -> bool {
    stdout
        .split_once("State = ")
        .and_then(|(_, rest)| rest.chars().next())
        .is_some_and(|c| c != '0')
}

/// Whether `--getallowsigned` says downloaded signed software is let in.
pub fn allows_downloaded_signed(stdout: &str) -> bool {
    stdout
        .lines()
        .any(|l| l.contains("downloaded signed software") && l.contains("ENABLED"))
}

/// The rule `--listapps` gives `path`: each program is a line `N : <path>`
/// and the next line its rule in parentheses.
pub fn rule(stdout: &str, path: &str) -> Option<Rule> {
    let mut lines = stdout.lines();
    while let Some(line) = lines.next() {
        let Some((n, listed)) = line.split_once(" : ") else {
            continue;
        };
        if n.trim().parse::<u32>().is_err() || listed.trim_end() != path {
            continue;
        }
        let next = lines.next().unwrap_or_default();
        return Some(if next.contains("Block") {
            Rule::Block
        } else {
            Rule::Allow
        });
    }
    None
}

/// The team `codesign -dv` names on its stderr: none for an ad-hoc signature,
/// which is not "signed software" to the firewall.
pub fn team(stderr: &str) -> Option<String> {
    if stderr.lines().any(|l| l.trim() == "Signature=adhoc") {
        return None;
    }
    stderr
        .lines()
        .find_map(|l| l.trim().strip_prefix("TeamIdentifier="))
        .filter(|t| *t != "not set")
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answers_of_macos_26_are_read() {
        assert!(enabled("Firewall is enabled. (State = 1)\n"));
        assert!(enabled(
            "Firewall is blocking all non-essential incoming connections. (State = 2)"
        ));
        assert!(!enabled("Firewall is disabled. (State = 0)\n"));
        assert!(!enabled(""));
        let signed = "Automatically allow built-in signed software ENABLED.\nAutomatically allow downloaded signed software ENABLED.\n";
        assert!(allows_downloaded_signed(signed));
        assert!(!allows_downloaded_signed(
            "Automatically allow built-in signed software ENABLED.\nAutomatically allow downloaded signed software DISABLED.\n"
        ));
        let apps = "Total number of apps = 2 \n1 : /opt/a b/optokens \n             (Block incoming connections)\n2 : /usr/bin/nc \n             (Allow incoming connections)\n";
        assert_eq!(rule(apps, "/opt/a b/optokens"), Some(Rule::Block));
        assert_eq!(rule(apps, "/usr/bin/nc"), Some(Rule::Allow));
        assert_eq!(rule(apps, "/usr/bin"), None);
        let adhoc = "Executable=/x\nSignature=adhoc\nTeamIdentifier=not set\n";
        assert_eq!(team(adhoc), None);
        assert_eq!(team("Executable=/x\nTeamIdentifier=not set\n"), None);
        let id = "Authority=Developer ID Application: A (HL27PWAKDF)\nTeamIdentifier=HL27PWAKDF\n";
        assert_eq!(team(id).as_deref(), Some("HL27PWAKDF"));
    }
}
