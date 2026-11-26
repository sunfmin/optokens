//! The 1Password CLI, `op`: the one module that builds its command lines.
//! The tests' stand-in shares these constants.

/// The program's name on `PATH`.
pub const PROGRAM: &str = "op";
/// What prints its version.
pub const VERSION: &[&str] = &["--version"];
/// The environment variable `op` reads a service account's token from: the
/// only way optokens hands it the token.
pub const TOKEN_ENV: &str = "OP_SERVICE_ACCOUNT_TOKEN";
