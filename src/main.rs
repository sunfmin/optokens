//! optokens: keeps an agent's secrets in a 1Password vault through a service account, entered through a one-time link.
//! `optokens --help` is the manual and its only copy.

const MANUAL: &str = "optokens: keeps an agent's secrets in a 1Password vault through a service account, entered through a one-time link.\n\nNo command is built yet: see the repo's open issues.\n";

fn answer(args: &[String]) -> (i32, String) {
    match args.first().map(String::as_str) {
        None | Some("--help") | Some("-h") | Some("help") => (0, MANUAL.to_string()),
        Some("--version") | Some("-V") => (0, format!("optokens {}\n", env!("CARGO_PKG_VERSION"))),
        Some(other) => (
            2,
            format!(
                "{{\"error\":[{{\"fault\":\"no command `{other}`\",\"fix\":\"run `optokens --help`\"}}]}}\n"
            ),
        ),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (code, out) = answer(&args);
    if code == 0 {
        print!("{out}");
    } else {
        eprint!("{out}");
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_is_the_manual() {
        assert_eq!(answer(&[]), (0, MANUAL.to_string()));
        assert_eq!(answer(&["--help".into()]).1, MANUAL);
    }

    #[test]
    fn an_unknown_command_is_refused_with_its_fix() {
        let (code, out) = answer(&["nope".into()]);
        assert_eq!(code, 2);
        assert!(out.contains("optokens --help"));
    }

    #[test]
    fn version_names_the_crate_version() {
        assert_eq!(
            answer(&["--version".into()]).1,
            format!("optokens {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}
