//! `put`, `get`, `env`, `list` and `rm`: each reads what it needs, lets
//! `secret` decide, and reaches the vault through `store`.

use crate::account::Env;
use crate::cli::Answer;
use crate::refusal::Refusal;
use crate::secret::{self, Kind, Name, Put};
use crate::store::Store;
use serde_json::{Value, json};

// `put`'s command line; its help is the manual's.
#[derive(clap::Args)]
pub struct PutArgs {
    /// The service the Secret is for, a slug such as `cloudflare`.
    #[arg(verbatim_doc_comment)]
    service: String,
    /// The account, when the service has several.
    #[arg(long, default_value = secret::DEFAULT_ACCOUNT, verbatim_doc_comment)]
    account: String,
    /// The kind of a new Secret; a stored Secret's kind never changes.
    #[arg(long, value_enum, verbatim_doc_comment)]
    kind: Option<Kind>,
    /// What the Secret is for, for a later agent that reads `list`.
    #[arg(long, verbatim_doc_comment)]
    description: Option<String>,
    /// `NAME=value`: a Field that is not secret; repeat it for several.
    #[arg(long, value_name = "NAME=value", verbatim_doc_comment)]
    set: Vec<String>,
    /// The label of the one Field whose value is all of stdin, piped in by a command.
    #[arg(long, value_name = "Label", verbatim_doc_comment)]
    field_from_stdin: Option<String>,
    /// Fields a person enters on a one-time link: refused, as this optokens does not serve the link yet.
    #[arg(long, value_name = "Label,...", verbatim_doc_comment)]
    fields: Option<String>,
    /// Fields of `--fields` shown as typed: refused with `--fields`.
    #[arg(long, value_name = "Label,...", verbatim_doc_comment)]
    show: Option<String>,
}

/// Upserts the Fields `args` names. `terminal` is whether stdin is one, and
/// `read` reads it whole: only for `--field-from-stdin`, never a terminal.
pub fn put(env: &Env, args: PutArgs, terminal: bool, read: impl FnOnce() -> Vec<u8>) -> Answer {
    match put_secret(env, args, terminal, read) {
        Ok(answer) => Answer::json(&answer),
        Err(faults) => Answer::refused(faults),
    }
}

fn put_secret(
    env: &Env,
    args: PutArgs,
    terminal: bool,
    read: impl FnOnce() -> Vec<u8>,
) -> Result<Value, Vec<Refusal>> {
    let mut faults = Vec::new();
    let name = Name::new(&args.service, &args.account)
        .map_err(|r| faults.push(r))
        .ok();
    let mut fields = Vec::new();
    for set in &args.set {
        match secret::parse_set(set) {
            Ok(field) => fields.push(field),
            Err(refusal) => faults.push(refusal),
        }
    }
    if args.fields.is_some() || args.show.is_some() {
        faults.push(Refusal::of(
            &secret::Fault::NeedsLink,
            "`--fields` and `--show` take values a person enters on a one-time link, which this optokens does not serve yet",
            secret::NEEDS_LINK_FIX,
        ));
    }
    if let Some(label) = &args.field_from_stdin {
        match secret::stdin_value(terminal, read) {
            Ok(value) => fields.push((label.clone(), value)),
            Err(refusal) => faults.push(refusal),
        }
    }
    let (Some(name), true) = (name, faults.is_empty()) else {
        return Err(faults);
    };
    let put = Put {
        kind: args.kind,
        description: args.description,
        fields,
    };
    let store = Store::open(env)?;
    let found = store.find(&name).map_err(|r| vec![r])?;
    let existing = found.as_ref().map(|f| &f.secret);
    let merged = secret::merge(&name, existing, &put)?;
    let changed = existing != Some(&merged);
    if changed {
        store
            .write(found.as_ref().map(|f| f.id.as_str()), &name, &merged)
            .map_err(|r| vec![r])?;
    }
    Ok(json!({
        "secret": name.title(),
        "changed": changed,
        "kind": merged.kind.name(),
        "fields": merged.labels(),
    }))
}

/// `name`'s Secret from the vault, or the refusal that it is not there.
fn found(env: &Env, service: &str, account: &str) -> Result<(Name, secret::Secret), Vec<Refusal>> {
    let name = Name::new(service, account).map_err(|r| vec![r])?;
    let store = Store::open(env)?;
    match store.find(&name).map_err(|r| vec![r])? {
        Some(found) => Ok((name, found.secret)),
        None => Err(vec![Refusal::of(
            &secret::Fault::NotFound,
            format!("the vault has no Secret `{}`", name.title()),
            "run `optokens list` to see what it has, or `optokens put` it",
        )]),
    }
}

/// The value alone, or with `json` the whole Secret; errors on stderr.
pub fn get(env: &Env, service: &str, account: &str, field: Option<&str>, json: bool) -> Answer {
    let (name, secret) = match found(env, service, account) {
        Ok(found) => found,
        Err(faults) => return Answer::refused_on_stderr(faults),
    };
    if json {
        return Answer::json(&secret::to_json(&name, &secret));
    }
    match secret::value(&name, &secret, field) {
        Ok(value) => Answer::raw(value.to_string()),
        Err(refusal) => Answer::refused_on_stderr(vec![refusal]),
    }
}

/// `export NAME='value'` lines; errors on stderr.
pub fn env(env: &Env, service: &str, account: &str) -> Answer {
    let exports = found(env, service, account)
        .and_then(|(name, secret)| secret::exports(&name, &secret).map_err(|r| vec![r]));
    match exports {
        Ok(lines) => Answer::raw(lines),
        Err(faults) => Answer::refused_on_stderr(faults),
    }
}

/// Every Secret, never a value.
pub fn list(env: &Env) -> Answer {
    match Store::open(env).and_then(|store| store.all()) {
        Ok(all) => Answer::json(&json!({
            "secrets": all.iter().map(|(n, s)| secret::summary(n, s)).collect::<Vec<_>>(),
        })),
        Err(faults) => Answer::refused(faults),
    }
}

/// Removes the Secret; nothing to remove is no fault.
pub fn rm(env: &Env, service: &str, account: &str) -> Answer {
    let removed = Name::new(service, account)
        .map_err(|r| vec![r])
        .and_then(|name| {
            let store = Store::open(env)?;
            let found = store.find(&name).map_err(|r| vec![r])?;
            if let Some(found) = &found {
                store.delete(&found.id).map_err(|r| vec![r])?;
            }
            Ok((name, found.is_some()))
        });
    match removed {
        Ok((name, changed)) => Answer::json(&json!({ "secret": name.title(), "changed": changed })),
        Err(faults) => Answer::refused(faults),
    }
}
