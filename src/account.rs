//! Where optokens finds its 1Password service account: the token, and the
//! vault. Every command that reaches 1Password calls [`token`] and [`vault`],
//! and nothing else reads them; `init` writes them with [`save`].

use crate::access;
use crate::refusal::{Refusal, quoted};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The environment variable that holds the service account's token, as `op` reads it.
pub const TOKEN_ENV: &str = "OP_SERVICE_ACCOUNT_TOKEN";
/// The vault when no vault file names one.
pub const DEFAULT_VAULT: &str = "optokens";
/// The token file and the vault file, in the config directory.
pub const TOKEN_FILE: &str = "token";
pub const VAULT_FILE: &str = "vault";

/// Why optokens cannot find its service account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, agent_help::Help)]
pub enum Fault {
    /// Neither `OP_SERVICE_ACCOUNT_TOKEN` nor the token file is there. Fix: set `OP_SERVICE_ACCOUNT_TOKEN` to the service account's token, or write it into the token file, alone, with mode 0600.
    NoToken,
    /// Others may read the token file: on Unix its mode is not 0600; on Windows its access list grants someone besides its owner, SYSTEM and the Administrators group. Fix: the `chmod 600` (Unix) or `icacls` (Windows) line the finding names.
    TokenFileOpen,
    /// The token (in `OP_SERVICE_ACCOUNT_TOKEN` or the token file) or the vault file is there but cannot be read: not a file, not UTF-8, or empty. Fix: write it again, as the finding says.
    Unreadable,
    /// There is no directory to look in: none of `XDG_CONFIG_HOME`, `HOME` (on Windows, `APPDATA`) is set. Fix: set `HOME`, or `XDG_CONFIG_HOME`.
    NoConfigDir,
}

/// What the lookup reads of the environment, passed in so a test sets it.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub token: Option<OsString>,
    pub xdg_config_home: Option<OsString>,
    pub home: Option<OsString>,
    pub appdata: Option<OsString>,
    /// Whether this is Windows, where the config directory is in `APPDATA`.
    pub windows: bool,
}

impl Env {
    pub fn current() -> Env {
        let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
        Env {
            token: var(TOKEN_ENV),
            xdg_config_home: var("XDG_CONFIG_HOME"),
            home: var("HOME"),
            appdata: var("APPDATA"),
            windows: cfg!(windows),
        }
    }
}

/// optokens' config directory: `$XDG_CONFIG_HOME/optokens`; without it,
/// `~/.config/optokens`, on Windows `%APPDATA%\optokens`.
pub fn config_dir(env: &Env) -> Result<PathBuf, Refusal> {
    let base = match &env.xdg_config_home {
        Some(xdg) => Some(PathBuf::from(xdg)),
        None if env.windows => env.appdata.as_ref().map(PathBuf::from),
        None => env.home.as_ref().map(|h| Path::new(h).join(".config")),
    };
    base.map(|b| b.join("optokens")).ok_or_else(|| {
        let names = if env.windows {
            "XDG_CONFIG_HOME nor APPDATA"
        } else {
            "XDG_CONFIG_HOME nor HOME"
        };
        Refusal::of(
            &Fault::NoConfigDir,
            format!(
                "neither {names} is set: there is no config directory to find the token file in"
            ),
            "set HOME (or XDG_CONFIG_HOME) to the user's directories",
        )
    })
}

/// Where the token came from: never the token itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Env,
    File(PathBuf),
}

impl Source {
    /// The variable's name or the file's path.
    pub fn name(&self) -> String {
        match self {
            Source::Env => TOKEN_ENV.to_string(),
            Source::File(path) => path.display().to_string(),
        }
    }

    /// `from`, `env` or `file`, and `at`, its [`Source::name`].
    pub fn json(&self) -> serde_json::Value {
        let from = match self {
            Source::Env => "env",
            Source::File(_) => "file",
        };
        serde_json::json!({ "from": from, "at": self.name() })
    }
}

/// The service account's token. Its `Debug` hides the value.
pub struct Token {
    value: String,
    pub source: Source,
}

impl Token {
    /// The value, for the one place that hands it to opcore (`Store::new`).
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token(from {})", self.source.name())
    }
}

/// The service account's token: `OP_SERVICE_ACCOUNT_TOKEN` when set, else
/// the token file, which only its owner may read.
pub fn token(env: &Env) -> Result<Token, Refusal> {
    if let Some(value) = &env.token {
        let value = value.clone().into_string().map_err(|_| {
            Refusal::of(
                &Fault::Unreadable,
                format!("{TOKEN_ENV} is not UTF-8 text"),
                format!("set {TOKEN_ENV} to the service account's token as 1Password shows it"),
            )
        })?;
        return Ok(Token {
            value,
            source: Source::Env,
        });
    }
    let path = config_dir(env)?.join(TOKEN_FILE);
    let Some(value) = read(&path, true)? else {
        return Err(Refusal::of(
            &Fault::NoToken,
            format!(
                "{TOKEN_ENV} is not set and there is no token file `{}`",
                path.display()
            ),
            format!(
                "set {TOKEN_ENV} to the service account's token, or write it alone into {} and run `chmod 600 {}`",
                quoted(&path),
                quoted(&path)
            ),
        ));
    };
    Ok(Token {
        value,
        source: Source::File(path),
    })
}

/// The token and the vault, refused with every fault either has.
pub fn find(env: &Env) -> Result<(Token, Vault), Vec<Refusal>> {
    match (token(env), vault(env)) {
        (Ok(token), Ok(vault)) => Ok((token, vault)),
        (token, vault) => Err([token.err(), vault.err()].into_iter().flatten().collect()),
    }
}

/// The vault optokens keeps its Secrets in, and the file that named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    pub name: String,
    pub file: Option<PathBuf>,
}

/// The vault the vault file names, or [`DEFAULT_VAULT`] without one.
pub fn vault(env: &Env) -> Result<Vault, Refusal> {
    let path = config_dir(env)?.join(VAULT_FILE);
    Ok(match read(&path, false)? {
        Some(name) => Vault {
            name,
            file: Some(path),
        },
        None => Vault {
            name: DEFAULT_VAULT.to_string(),
            file: None,
        },
    })
}

/// Writes `token` into the token file and `vault` into the vault file, each
/// replacing what was there: the config directory made with mode 0700, the
/// token file only its owner may read. Each file is written whole under a
/// fresh name in that directory, opened with `create_new`, then renamed over
/// the old one, so a reader sees the old file or the new, never a part.
pub fn save(env: &Env, token: &str, vault: &str) -> Result<(Token, Vault), Refusal> {
    let dir = config_dir(env)?;
    let token_file = dir.join(TOKEN_FILE);
    let vault_file = dir.join(VAULT_FILE);
    let cannot = |path: &Path, e: std::io::Error| {
        Refusal::new(
            format!("cannot write `{}`: {e}", path.display()),
            format!(
                "make {} a directory this user can write, then run `optokens init` again",
                quoted(&dir)
            ),
        )
    };
    make_private_dir(&dir).map_err(|e| cannot(&dir, e))?;
    replace(&token_file, token).map_err(|e| cannot(&token_file, e))?;
    replace(&vault_file, vault).map_err(|e| cannot(&vault_file, e))?;
    Ok((
        Token {
            value: token.to_string(),
            source: Source::File(token_file),
        },
        Vault {
            name: vault.to_string(),
            file: Some(vault_file),
        },
    ))
}

#[cfg(unix)]
fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    // Exactly 0700 whatever the umask, and for a directory already there.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// `path` replaced by `text` and a newline, in a file only its owner may
/// read, made so before anything is written into it.
fn replace(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let fresh = path.with_file_name(format!(".{name}.{}", crate::link::random_hex(8)));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&fresh).and_then(|mut file| {
        access::restrict(&file)?;
        file.write_all(format!("{text}\n").as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&fresh, path)
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&fresh);
    }
    written
}

/// The trimmed text of `path`, `None` when there is no such file; with
/// `private`, refused unless only its owner may read it, checked on the file
/// opened, so it cannot change between the check and the read.
fn read(path: &Path, private: bool) -> Result<Option<String>, Refusal> {
    let unreadable = |why: String| {
        Refusal::of(
            &Fault::Unreadable,
            format!("cannot read `{}`: {why}", path.display()),
            format!(
                "write {} again, holding only the value on one line",
                quoted(path)
            ),
        )
    };
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(unreadable(e.to_string())),
    };
    let meta = file.metadata().map_err(|e| unreadable(e.to_string()))?;
    if !meta.is_file() {
        return Err(unreadable("it is not a file".to_string()));
    }
    if private {
        access::private(&file, &meta, path)?;
    }
    let text = std::io::read_to_string(file).map_err(|e| unreadable(e.to_string()))?;
    let text = text.trim();
    if text.is_empty() {
        return Err(unreadable("it is empty".to_string()));
    }
    Ok(Some(text.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(xdg: Option<&str>, home: Option<&str>) -> Env {
        Env {
            xdg_config_home: xdg.map(OsString::from),
            home: home.map(OsString::from),
            ..Env::default()
        }
    }

    #[test]
    fn the_config_dir_is_xdg_config_home_else_dot_config_in_home() {
        assert_eq!(
            config_dir(&env(Some("/x"), Some("/h"))).unwrap(),
            Path::new("/x/optokens")
        );
        assert_eq!(
            config_dir(&env(None, Some("/h"))).unwrap(),
            Path::new("/h/.config/optokens")
        );
        let none = config_dir(&env(None, None)).unwrap_err();
        assert_eq!(none.kind, Some("no_config_dir"));
        assert_eq!(
            none.fix,
            "set HOME (or XDG_CONFIG_HOME) to the user's directories"
        );
    }

    #[test]
    fn on_windows_the_config_dir_is_in_appdata_unless_xdg_config_home_is_set() {
        let windows = Env {
            appdata: Some(r"C:\Users\ci\AppData\Roaming".into()),
            windows: true,
            ..env(None, Some("/h"))
        };
        assert_eq!(
            config_dir(&windows).unwrap(),
            Path::new(r"C:\Users\ci\AppData\Roaming").join("optokens")
        );
        let xdg = Env {
            xdg_config_home: Some("/x".into()),
            ..windows.clone()
        };
        assert_eq!(config_dir(&xdg).unwrap(), Path::new("/x/optokens"));
        let none = Env {
            appdata: None,
            ..windows
        };
        assert_eq!(
            config_dir(&none).unwrap_err().fault,
            "neither XDG_CONFIG_HOME nor APPDATA is set: there is no config directory to find the token file in"
        );
    }

    #[test]
    fn the_token_from_the_environment_wins_and_debug_hides_it() {
        let env = Env {
            token: Some("ops_secret".into()),
            ..env(Some("/nowhere"), None)
        };
        let token = token(&env).unwrap();
        assert_eq!(token.value(), "ops_secret");
        assert_eq!(token.source, Source::Env);
        assert_eq!(format!("{token:?}"), "Token(from OP_SERVICE_ACCOUNT_TOKEN)");
    }

    #[cfg(unix)]
    #[test]
    fn a_token_in_the_environment_that_is_not_utf8_is_refused_as_unreadable() {
        use std::os::unix::ffi::OsStringExt;
        let env = Env {
            token: Some(OsString::from_vec(vec![b'o', b'p', 0xff])),
            ..env(Some("/nowhere"), None)
        };
        let refused = token(&env).unwrap_err();
        assert_eq!(refused.kind, Some("unreadable"));
        assert_eq!(refused.fault, "OP_SERVICE_ACCOUNT_TOKEN is not UTF-8 text");
        assert_eq!(
            refused.fix,
            "set OP_SERVICE_ACCOUNT_TOKEN to the service account's token as 1Password shows it"
        );
    }

    #[test]
    fn without_a_vault_file_the_vault_is_optokens() {
        let dir = tempfile::tempdir().unwrap();
        let env = env(Some(dir.path().to_str().unwrap()), None);
        assert_eq!(
            vault(&env).unwrap(),
            Vault {
                name: "optokens".into(),
                file: None
            }
        );
        std::fs::create_dir(dir.path().join("optokens")).unwrap();
        let file = dir.path().join("optokens/vault");
        std::fs::write(&file, "team\n").unwrap();
        assert_eq!(
            vault(&env).unwrap(),
            Vault {
                name: "team".into(),
                file: Some(file.clone())
            }
        );
        std::fs::write(&file, "\n").unwrap();
        assert_eq!(vault(&env).unwrap_err().kind, Some("unreadable"));
    }
}
