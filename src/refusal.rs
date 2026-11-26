//! A fault a command found, with the line that fixes it: what `{"error": [...]}`
//! lists, and what `optokens doctor` finds.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Refusal {
    /// The finding's name in a table of the manual, where it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    pub fault: String,
    pub fix: String,
}

impl Refusal {
    pub fn new(fault: impl Into<String>, fix: impl Into<String>) -> Refusal {
        Refusal {
            kind: None,
            fault: fault.into(),
            fix: fix.into(),
        }
    }

    /// A refusal named by `kind`, a variant of a table of the manual.
    pub fn of(
        kind: &impl agent_help::Table,
        fault: impl Into<String>,
        fix: impl Into<String>,
    ) -> Refusal {
        Refusal {
            kind: Some(kind.entry().name),
            ..Refusal::new(fault, fix)
        }
    }
}

/// `path` as one word of a POSIX shell command line.
pub(crate) fn quoted(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._-+:=@%,".contains(c);
    if !text.is_empty() && text.chars().all(plain) {
        text
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::quoted;
    use std::path::Path;

    #[test]
    fn a_path_is_quoted_only_when_the_shell_would_split_or_expand_it() {
        assert_eq!(
            quoted(Path::new("/home/a/.config/optokens/token")),
            "/home/a/.config/optokens/token"
        );
        assert_eq!(
            quoted(Path::new("/tmp/my dir/token")),
            "'/tmp/my dir/token'"
        );
        assert_eq!(quoted(Path::new("/tmp/it's")), r"'/tmp/it'\''s'");
        assert_eq!(quoted(Path::new("/tmp/$x")), "'/tmp/$x'");
    }
}
