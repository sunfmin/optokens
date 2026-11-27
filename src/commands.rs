//! `put`, `get`, `env`, `list` and `rm`: each reads what it needs, lets
//! `secret` decide, and reaches the vault through `store`.

use crate::account::Env;
use crate::cli::Answer;
use crate::item;
use crate::link::{self, Input, Link, Token};
use crate::pipe;
use crate::refusal::Refusal;
use crate::secret::{self, Field, Kind, Name, Put, Visibility};
use crate::serve::Endpoint;
use crate::store::Store;
use serde_json::{Value, json};
use std::time::{Duration, SystemTime};

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
    /// Structured data about the Secret for a program to read, one JSON object such as `{"account_id":"..."}`: it replaces the stored Meta.
    #[arg(long, value_name = "JSON", verbatim_doc_comment)]
    meta: Option<String>,
    /// `NAME=value`: a Field that is not secret, stored as plain text; repeat it for several.
    #[arg(long, value_name = "NAME=value", verbatim_doc_comment)]
    set: Vec<String>,
    /// The label of the one Field whose value is all of stdin, piped in by a command: stored concealed, for a secret.
    #[arg(long, value_name = "Label", verbatim_doc_comment)]
    field_from_stdin: Option<String>,
    /// A Field whose value is all a command prints, its path a pipe, `Label=<(command)`: stored concealed; repeat it for several.
    #[arg(long, value_name = "Label=path", verbatim_doc_comment)]
    field_from_pipe: Vec<String>,
    /// The labels of the Fields a person enters on the one-time link, comma-separated.
    #[arg(long, value_name = "Label,...", verbatim_doc_comment)]
    fields: Option<String>,
    /// Labels of `--fields` whose inputs show what is typed: for values that are not secret.
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

/// A comma-separated list of labels, each trimmed.
fn labels(list: &str) -> Vec<String> {
    list.split(',').map(|l| l.trim().to_string()).collect()
}

/// The environment variable a test sets to shorten a link's lifetime, in
/// milliseconds; the manual does not list it.
const TEST_LIFETIME: &str = "OPTOKENS_TEST_LINK_LIFETIME_MS";

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
    let meta = match args.meta.as_deref().map(secret::parse_meta) {
        Some(Ok(meta)) => Some(meta),
        Some(Err(refusal)) => {
            faults.push(refusal);
            None
        }
        None => None,
    };
    let asked = args.fields.as_deref().map(labels).unwrap_or_default();
    let shown = args.show.as_deref().map(labels).unwrap_or_default();
    let unasked: Vec<&String> = shown.iter().filter(|l| !asked.contains(l)).collect();
    if !unasked.is_empty() {
        faults.push(Refusal::of(
            &secret::Fault::BadShow,
            format!(
                "`--show` names {}, which `--fields` does not",
                unasked
                    .iter()
                    .map(|l| format!("`{l}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "name each `--show` label in `--fields` too",
        ));
    }
    if let Some(label) = &args.field_from_stdin {
        match secret::stdin_value(terminal, read) {
            Ok(value) => fields.push(Field::new(label, &value, Visibility::Concealed)),
            Err(refusal) => faults.push(refusal),
        }
    }
    // The pipes are read to their ends in turn, not at once: each
    // `<(command)` writes only to its own pipe and waits on no other, so the
    // one being read ends while the others' writers wait on theirs.
    for (i, arg) in args.field_from_pipe.iter().enumerate() {
        match secret::pipe_field(i + 1, arg, pipe::read) {
            Ok(field) => fields.push(field),
            Err(refusal) => faults.push(refusal),
        }
    }
    // A bare `put` names no Field: its one value is entered on the link,
    // unless it is a `--description` or `--meta` alone for a stored Secret.
    let annotated = args.description.is_some() || args.meta.is_some();
    let bare = args.set.is_empty()
        && args.field_from_stdin.is_none()
        && args.field_from_pipe.is_empty()
        && asked.is_empty();
    let path = std::env::var_os("PATH");
    let mut endpoint = None;
    if !asked.is_empty() || (bare && !annotated) {
        match Endpoint::open(path.as_deref()) {
            Ok(opened) => endpoint = Some(opened),
            Err(refusal) => faults.push(refusal),
        }
    }
    let (Some(name), true) = (name, faults.is_empty()) else {
        return Err(faults);
    };
    // A write is never based on a stale item: the Copy syncs first.
    let mut store = opened(env, true)?;
    let found = store.find(&name).map_err(|r| vec![r])?;
    let existing = found.as_ref().map(|f| &f.secret);
    let single = bare && (!annotated || existing.is_none());
    if single && endpoint.is_none() {
        endpoint = Some(Endpoint::open(path.as_deref()).map_err(|r| vec![r])?);
    }
    let mut put = Put {
        kind: args.kind,
        description: args.description,
        meta,
        fields,
        value: single.then(String::new),
    };
    // A Field typed into a visible input is no secret; any other is.
    put.fields.extend(asked.iter().map(|l| {
        let visibility = match shown.contains(l) {
            true => Visibility::Plain,
            false => Visibility::Concealed,
        };
        Field::new(l, "", visibility)
    }));
    // Every fault is refused before the link is served: its values fill
    // the placeholders of what is merged.
    let mut merged = secret::merge(&name, existing, &put)?;
    if let Some(endpoint) = endpoint {
        let link = link_for(&name, existing, &put, &asked);
        let what = format!("the secret for {} / {}", name.service(), name.account());
        let mut values = endpoint.serve(link, &what, "put").map_err(|r| vec![r])?;
        match &mut merged.values {
            secret::Values::Single(value) => {
                *value = values.pop_first().map(|(_, v)| v).unwrap_or_default()
            }
            secret::Values::Fields(fields) => {
                for field in fields.iter_mut() {
                    if let Some(entered) = values.remove(&field.label) {
                        field.value = entered;
                    }
                }
            }
        }
    }
    // An item an earlier optokens wrote is rewritten in this layout, in place.
    let stale = found.as_ref().is_some_and(|f| !f.current);
    let changed = existing != Some(&merged) || stale;
    if changed {
        store
            .write(found.as_ref(), &name, &merged)
            .map_err(|r| vec![r])?;
    }
    Ok(json!({
        "secret": name.to_string(),
        "changed": changed,
        "kind": merged.kind.name(),
        "fields": merged.labels(),
    }))
}

/// The link that asks for the `asked` Fields (a plain one's input showing
/// what is typed), or the bare `put`'s one value, and shows each stored Field
/// this `put` keeps as already set.
fn link_for(name: &Name, existing: Option<&secret::Secret>, put: &Put, asked: &[String]) -> Link {
    let kept = match existing.map(|e| &e.values) {
        Some(secret::Values::Fields(stored)) => stored
            .iter()
            .filter(|f| !put.fields.iter().any(|p| p.label == f.label))
            .map(|f| link::Field {
                label: f.label.clone(),
                input: Input::AlreadySet,
            })
            .collect(),
        _ => Vec::new(),
    };
    let fields: Vec<link::Field> = if put.value.is_some() {
        vec![link::Field {
            label: item::SINGLE.to_string(),
            input: Input::Password,
        }]
    } else {
        put.fields
            .iter()
            .filter(|f| asked.contains(&f.label))
            .map(|f| link::Field {
                label: f.label.clone(),
                input: match f.visibility {
                    Visibility::Plain => Input::Text,
                    Visibility::Concealed => Input::Password,
                },
            })
            .chain(kept)
            .collect()
    };
    let description = put
        .description
        .as_deref()
        .or_else(|| existing.and_then(|e| e.description.as_deref()));
    fresh_link(&name.to_string(), description, fields)
}

/// A link made now, with a fresh token, for [`link::LIFETIME`] (a test's
/// `OPTOKENS_TEST_LINK_LIFETIME_MS` shortens it).
pub fn fresh_link(title: &str, description: Option<&str>, fields: Vec<link::Field>) -> Link {
    let lifetime = std::env::var(TEST_LIFETIME)
        .ok()
        .and_then(|ms| ms.parse().ok())
        .map_or(link::LIFETIME, Duration::from_millis);
    Link::new(
        title,
        description,
        fields,
        Token::fresh(),
        SystemTime::now(),
        lifetime,
    )
}

/// The vault's Store, synced first when `fresh` (`--fresh`, and before a write).
fn opened(env: &Env, fresh: bool) -> Result<Store, Vec<Refusal>> {
    let mut store = Store::open(env)?;
    if fresh {
        store.sync().map_err(|r| vec![r])?;
    }
    Ok(store)
}

/// `name`'s Secret from the vault, or the refusal that it is not there.
fn found(
    env: &Env,
    service: &str,
    account: &str,
    fresh: bool,
) -> Result<(Name, secret::Secret), Vec<Refusal>> {
    let name = Name::new(service, account).map_err(|r| vec![r])?;
    let mut store = opened(env, fresh)?;
    match store.find(&name).map_err(|r| vec![r])? {
        Some(found) => Ok((name, found.secret)),
        None => Err(vec![Refusal::of(
            &secret::Fault::NotFound,
            format!("the vault has no Secret `{name}`"),
            "run `optokens list` to see what it has, or `optokens put` it",
        )]),
    }
}

/// The value alone, or with `json` the whole Secret; errors on stderr.
pub fn get(
    env: &Env,
    service: &str,
    account: &str,
    field: Option<&str>,
    json: bool,
    fresh: bool,
) -> Answer {
    let (name, secret) = match found(env, service, account, fresh) {
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
pub fn env(env: &Env, service: &str, account: &str, fresh: bool) -> Answer {
    let exports = found(env, service, account, fresh)
        .and_then(|(name, secret)| secret::exports(&name, &secret).map_err(|r| vec![r]));
    match exports {
        Ok(lines) => Answer::raw(lines),
        Err(faults) => Answer::refused_on_stderr(faults),
    }
}

/// Every Secret, never a value.
pub fn list(env: &Env, fresh: bool) -> Answer {
    match opened(env, fresh).and_then(|mut store| store.all()) {
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
            let mut store = opened(env, true)?;
            let found = store.find(&name).map_err(|r| vec![r])?;
            if let Some(found) = &found {
                store.delete(&found.item.id).map_err(|r| vec![r])?;
            }
            Ok((name, found.is_some()))
        });
    match removed {
        Ok((name, changed)) => {
            Answer::json(&json!({ "secret": name.to_string(), "changed": changed }))
        }
        Err(faults) => Answer::refused(faults),
    }
}
