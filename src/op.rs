//! The 1Password CLI, `op`: the one module that builds its command lines.
//! The tests' stand-in shares these constants.
//!
//! A command line holds the vault's name and an item's id, never a value:
//! an item's values go to `op` only as the JSON template on its stdin, and
//! come back only on its stdout.

/// The program's name on `PATH`.
pub const PROGRAM: &str = "op";
/// What prints its version.
pub const VERSION: &[&str] = &["--version"];
/// The environment variable `op` reads a service account's token from: the
/// only way optokens hands it the token.
pub const TOKEN_ENV: &str = "OP_SERVICE_ACCOUNT_TOKEN";

/// `op item <verb>`.
pub const ITEM: &str = "item";
pub const LIST: &str = "list";
pub const GET: &str = "get";
pub const CREATE: &str = "create";
pub const EDIT: &str = "edit";
pub const DELETE: &str = "delete";
/// The argument by which `op item create` reads its template from stdin.
pub const STDIN: &str = "-";

/// One call of `op`, before it is a command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call<'a> {
    /// Every item's summary in the vault, without values.
    List,
    /// One item, its values with it.
    Get(&'a str),
    /// A new item, from the template on stdin.
    Create,
    /// The item, replaced by the template on stdin.
    Edit(&'a str),
    /// The item, deleted.
    Delete(&'a str),
}

/// `call`'s command line in `vault`.
pub fn args(call: Call, vault: &str) -> Vec<String> {
    let json = ["--format", "json"];
    let (verb, item, tail): (&str, Option<&str>, &[&str]) = match call {
        Call::List => (LIST, None, &json),
        Call::Get(id) => (GET, Some(id), &json),
        Call::Create => (CREATE, None, &["--format", "json", STDIN]),
        Call::Edit(id) => (EDIT, Some(id), &json),
        Call::Delete(id) => (DELETE, Some(id), &[]),
    };
    let mut args = vec![ITEM.to_string(), verb.to_string()];
    args.extend(item.map(String::from));
    args.extend(["--vault".to_string(), vault.to_string()]);
    args.extend(tail.iter().map(|s| s.to_string()));
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_call_is_an_item_command_in_the_vault_with_no_value() {
        let line = |call| args(call, "team").join(" ");
        assert_eq!(line(Call::List), "item list --vault team --format json");
        assert_eq!(
            line(Call::Get("id1")),
            "item get id1 --vault team --format json"
        );
        assert_eq!(
            line(Call::Create),
            "item create --vault team --format json -"
        );
        assert_eq!(
            line(Call::Edit("id1")),
            "item edit id1 --vault team --format json"
        );
        assert_eq!(line(Call::Delete("id1")), "item delete id1 --vault team");
    }
}
