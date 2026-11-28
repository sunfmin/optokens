//! A Secret and what `put`, `get`, `env` and `list` decide about it: pure,
//! no I/O. The effect code reads the command line, stdin and the vault, and
//! passes in what it read.

use crate::refusal::Refusal;
use serde_json::{Map, Value, json};

/// The account a Secret is under when `--account` is not given.
pub const DEFAULT_ACCOUNT: &str = "default";

/// Why a command about a Secret refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, agent_help::Help)]
pub enum Fault {
    /// The service or the account is empty or holds a `/`, which an `op://` reference to the vault item's title cannot carry. Fix: name it with a slug, such as `cloudflare`.
    BadName,
    /// A `--set` is not `NAME=value`, or a Field's label is empty. Fix: write it as `--set "NAME=value"`; the first `=` splits it.
    BadSet,
    /// One `put` names a Field's label twice. Fix: name each label once.
    DuplicateLabel,
    /// A Profile's label is not an environment variable's name (letters, digits and `_`, not starting with a digit). Fix: rename the Field, such as `API_TOKEN`.
    NotEnvName,
    /// `--kind` differs from the stored Secret's kind: `put` never changes a kind. Fix: `optokens rm` the Secret, then `put` it again with the new kind.
    KindChange,
    /// `put` would turn a single value into labelled Fields, or labelled Fields into a single value (a bare `put`), which it never does. Fix: `optokens rm` the Secret, then `put` it again in its new shape.
    ShapeChange,
    /// `--meta` is not one JSON object. Fix: give it as one, such as `--meta '{"account_id":"..."}'`.
    BadMeta,
    /// `--show` names a label `--fields` does not, or is given without `--fields`. Fix: name each `--show` label in `--fields` too.
    BadShow,
    /// No value was submitted on the one-time link before it expired, so nothing was stored. Fix: run the same `put` or `init` again, and open its new link sooner. When no connection reached the link at all, the fault says so and the fix names `optokens doctor` first: macOS's firewall, or the tailnet's ACL, keeps the device out.
    LinkExpired,
    /// `--field-from-stdin` was given, but stdin is a terminal: a person would type into a prompt that shows nothing. Fix: pipe the value a command makes into `put`; a value a person knows waits for the one-time link.
    StdinTerminal,
    /// `--field-from-stdin` read nothing, or a lone newline. Fix: pipe the value in, such as `openssl rand -base64 32 | optokens put …`.
    StdinEmpty,
    /// What `--field-from-stdin` read is not UTF-8 text. Fix: pipe it through `base64` first.
    StdinNotText,
    /// A `--field-from-pipe` is not `Label=<path>`, or its path is missing, a file, a terminal, or anything but a pipe, or cannot be read. The refusal names the Label, never the path, which after a mistaken `Label=$(command)` is the secret itself. Fix: give a command's output through `Label=<(command)`, never a file.
    NotAPipe,
    /// A `--field-from-pipe` read nothing, or a lone newline. Fix: see that the command in `<(command)` prints the value.
    PipeEmpty,
    /// What a `--field-from-pipe` read is not UTF-8 text. Fix: pipe it through `base64` first, `<(command | base64)`.
    PipeNotText,
    /// No Secret of that service and account is in the vault. Fix: `optokens list` to see what is there, or `optokens put` it.
    NotFound,
    /// `mv`'s new name is already a Secret in the vault, perhaps the one it would move. Fix: `optokens rm` that Secret first, or `mv` onto another name.
    Exists,
    /// `get` cannot pick the value: `--field` names no Field of the Secret, a Secret of labelled Fields was asked for without `--field`, or a single value was asked for with one. Fix: the `get` line the finding names.
    NoSuchField,
    /// `env` has nothing to export: the Secret is a single value, or a label is not an environment variable's name. Fix: `optokens get` its value instead.
    NotEnv,
    /// An item in the vault has the Secret's title (or its earlier `<service>/<account>`) but is not one optokens wrote: it has no `optokens` tag, or its `optokens` section is not optokens' layout. optokens never guesses at it. Fix: rename or move that item in 1Password, or `optokens rm` it if optokens wrote it.
    NotOptokens,
    /// Two items in the vault are the same Secret. Fix: delete one of them in 1Password.
    Ambiguous,
    /// 1Password refused or failed a call (no such vault, no grant, its rate limit), the network failed, or 1Password answered what optokens' Core cannot read, or a write met the writes another token left waiting. Fix: the one the finding names: `optokens init --check` for a grant, waiting for the budget `op service-account ratelimit` shows ran out for a rate limit (the token's refills within the hour, the account's within the day), updating optokens for an answer it cannot read, running with the token that wrote the waiting writes.
    VaultFailed,
}

/// What a Secret is for: a credential, or a Profile of environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Kind {
    /// A credential: one value, or labelled Fields.
    #[value(verbatim_doc_comment)]
    Static,
    /// A Profile: Fields labelled by environment variables' names, for `env`.
    #[value(verbatim_doc_comment)]
    Profile,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Static => "static",
            Kind::Profile => "profile",
        }
    }
}

/// A Secret's values: a single value (always concealed), or labelled Fields
/// in their order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Values {
    Single(String),
    Fields(Vec<Field>),
}

/// One labelled value of a Secret, and how the vault shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub label: String,
    pub value: String,
    pub visibility: Visibility,
}

impl Field {
    pub fn new(label: &str, value: &str, visibility: Visibility) -> Field {
        Field {
            label: label.into(),
            value: value.into(),
            visibility,
        }
    }
}

/// How the vault shows a Field: it follows how the value came in, and only
/// changes how 1Password shows it, never what optokens gives out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Hidden like a password: a value piped in (`--field-from-stdin`,
    /// `--field-from-pipe`), or
    /// typed into a hidden input of the one-time link.
    Concealed,
    /// Plain text: a value given on the command line (`--set`), or typed into
    /// a visible input of the link (`--show`); neither is secret.
    Plain,
}

/// A Secret, less its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    pub kind: Kind,
    pub description: Option<String>,
    pub meta: Option<Meta>,
    pub values: Values,
}

impl Secret {
    /// The Fields' labels, `None` for a single value.
    pub fn labels(&self) -> Option<Vec<&str>> {
        match &self.values {
            Values::Single(_) => None,
            Values::Fields(fields) => Some(fields.iter().map(|f| f.label.as_str()).collect()),
        }
    }
}

/// A Secret's name: its service and account, ordered by service, then account.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name {
    service: String,
    account: String,
}

impl Name {
    /// Refused when either is empty or holds a `/`.
    pub fn new(service: &str, account: &str) -> Result<Name, Refusal> {
        let bad = |s: &str| s.is_empty() || s.contains('/');
        if bad(service) || bad(account) {
            return Err(Refusal::of(
                &Fault::BadName,
                format!(
                    "`{service}/{account}`: a service and an account are each non-empty and hold no `/`"
                ),
                "name the service and the account each with a slug, such as `cloudflare`",
            ));
        }
        Ok(Name {
            service: service.into(),
            account: account.into(),
        })
    }

    /// The vault item's title: `<service>`, or `<service>.<account>` when
    /// the account is not the default. It holds no `/`, so `op://` reaches it;
    /// a service may hold a `.`, so the title alone never says the name.
    pub fn title(&self) -> String {
        if self.account == DEFAULT_ACCOUNT {
            self.service.clone()
        } else {
            format!("{}.{}", self.service, self.account)
        }
    }

    /// The name an earlier optokens' title holds, or `None` when it holds none.
    pub fn from_old_title(title: &str) -> Option<Name> {
        let (service, account) = title.split_once('/')?;
        Name::new(service, account).ok()
    }

    /// `--account <account>` as a command line needs it: empty for the default.
    fn flag(&self) -> String {
        if self.account == DEFAULT_ACCOUNT {
            String::new()
        } else {
            format!(" --account {}", shell_word(&self.account))
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn account(&self) -> &str {
        &self.account
    }
}

/// How answers and refusals name a Secret, and the title an earlier
/// optokens gave its item: `<service>/<account>`.
impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.service, self.account)
    }
}

/// Structured data about a Secret, for a program to read (a Cloudflare
/// `account_id`): one JSON object, apart from its Description.
pub type Meta = Map<String, Value>;

/// `--meta`: one JSON object, else refused.
pub fn parse_meta(raw: &str) -> Result<Meta, Refusal> {
    match serde_json::from_str(raw) {
        Ok(Value::Object(meta)) => Ok(meta),
        read => Err(Refusal::of(
            &Fault::BadMeta,
            match read {
                Ok(_) => format!("`--meta` is `{raw}`, which is JSON but not one object"),
                Err(e) => format!("`--meta` is `{raw}`, which is not JSON: {e}"),
            },
            r#"give it as one JSON object, such as `--meta '{"account_id":"..."}'`"#,
        )),
    }
}

/// What one `put` names: the kind, description and Meta it gives, and its Fields'
/// values in order (each `--set`, then `--field-from-stdin`, then each
/// `--field-from-pipe`, then `--fields`),
/// or the single value of a bare `put`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Put {
    pub kind: Option<Kind>,
    pub description: Option<String>,
    pub meta: Option<Meta>,
    pub fields: Vec<Field>,
    /// A bare `put`'s one value, with no label.
    pub value: Option<String>,
}

/// `--set "NAME=value"`, split on the first `=`: a plain Field, since its
/// value is on the command line.
pub fn parse_set(set: &str) -> Result<Field, Refusal> {
    match set.split_once('=') {
        Some((label, value)) if !label.is_empty() => {
            Ok(Field::new(label, value, Visibility::Plain))
        }
        _ => Err(bad_set(format!(
            "`--set` takes `NAME=value`, and `{}` names no label before an `=`",
            set.split('=').next().unwrap_or_default()
        ))),
    }
}

fn bad_set(fault: String) -> Refusal {
    Refusal::of(
        &Fault::BadSet,
        fault,
        "write each as `--set \"NAME=value\"`",
    )
}

/// Why what came in on a pipe is no value.
enum NoText {
    Empty,
    NotText,
}

/// What a pipe carried, as text: one trailing `\n` dropped.
fn piped_text(mut bytes: Vec<u8>) -> Result<String, NoText> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(NoText::Empty);
    }
    String::from_utf8(bytes).map_err(|_| NoText::NotText)
}

/// What `--field-from-stdin` read, as the Field's value: one trailing `\n`
/// dropped. Refused when stdin is a terminal (checked first, so nothing is
/// read), empty, or not UTF-8.
pub fn stdin_value(terminal: bool, read: impl FnOnce() -> Vec<u8>) -> Result<String, Refusal> {
    if terminal {
        return Err(Refusal::of(
            &Fault::StdinTerminal,
            "`--field-from-stdin` reads a value a command pipes in, and stdin is a terminal",
            "pipe the value a command makes into `optokens put`; a value a person knows is entered on the one-time link",
        ));
    }
    piped_text(read()).map_err(|no| match no {
        NoText::Empty => Refusal::of(
            &Fault::StdinEmpty,
            "`--field-from-stdin` read no value from stdin",
            "pipe the value in, such as `openssl rand -base64 32 | optokens put <service> --field-from-stdin <Label>`",
        ),
        NoText::NotText => Refusal::of(
            &Fault::StdinNotText,
            "what `--field-from-stdin` read is not UTF-8 text",
            "pipe it through `base64` first",
        ),
    })
}

/// The `n`th (from 1) `--field-from-pipe "Label=<path>"`, split on the first
/// `=`, as a concealed Field of what `read` read at the path: `None` when the
/// path is no pipe, before anything is read. A refusal names the Label and
/// never the path, which after a mistaken `Label=$(command)` is the secret.
pub fn pipe_field(
    n: usize,
    arg: &str,
    read: impl FnOnce(&str) -> Option<Vec<u8>>,
) -> Result<Field, Refusal> {
    let not_a_pipe = |fault: String| {
        Refusal::of(
            &Fault::NotAPipe,
            fault,
            "give a command's output through `--field-from-pipe <Label>=<(command)`, never a file",
        )
    };
    let Some((label, path)) = arg.split_once('=').filter(|(l, _)| !l.is_empty()) else {
        return Err(not_a_pipe(format!(
            "`--field-from-pipe` number {n} names no `Label=` before its pipe"
        )));
    };
    let Some(bytes) = read(path) else {
        return Err(not_a_pipe(format!(
            "`--field-from-pipe {label}=` names no pipe that can be read"
        )));
    };
    match piped_text(bytes) {
        Ok(value) => Ok(Field::new(label, &value, Visibility::Concealed)),
        Err(NoText::Empty) => Err(Refusal::of(
            &Fault::PipeEmpty,
            format!("`--field-from-pipe {label}=` read no value"),
            "see that the command in `<(command)` prints the value",
        )),
        Err(NoText::NotText) => Err(Refusal::of(
            &Fault::PipeNotText,
            format!("what `--field-from-pipe {label}=` read is not UTF-8 text"),
            "pipe it through `base64` first, `<(command | base64)`",
        )),
    }
}

/// Whether `label` can be an environment variable's name.
pub fn is_env_name(label: &str) -> bool {
    let mut chars = label.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The Secret after `put` upserts into `existing`: the Fields it names are
/// set, value and visibility, the rest kept as they were, in their order. Every fault found is refused at once.
pub fn merge(name: &Name, existing: Option<&Secret>, put: &Put) -> Result<Secret, Vec<Refusal>> {
    let mut faults = Vec::new();
    let shown = name.to_string();
    let kind = match (existing, put.kind) {
        (Some(e), Some(k)) if e.kind != k => {
            faults.push(Refusal::of(
                &Fault::KindChange,
                format!(
                    "`{shown}` is a {} Secret, and `--kind {}` would change it",
                    e.kind.name(),
                    k.name()
                ),
                format!(
                    "run `optokens rm {}{}`, then `put` it again with `--kind {}`",
                    shell_word(name.service()),
                    name.flag(),
                    k.name()
                ),
            ));
            e.kind
        }
        (Some(e), _) => e.kind,
        (None, k) => k.unwrap_or(Kind::Static),
    };
    let again = format!(
        "run `optokens rm {}{}`, then `put` it again in its new shape",
        shell_word(name.service()),
        name.flag()
    );
    match (
        existing.map(|e| &e.values),
        put.fields.is_empty(),
        &put.value,
    ) {
        (Some(Values::Single(_)), false, _) => faults.push(Refusal::of(
            &Fault::ShapeChange,
            format!("`{shown}` is a single value, and `put` never turns it into labelled Fields"),
            again,
        )),
        (Some(Values::Fields(_)), _, Some(_)) => faults.push(Refusal::of(
            &Fault::ShapeChange,
            format!("`{shown}` has labelled Fields, and a bare `put` would make it a single value"),
            format!(
                "name the Fields to change, `optokens put {}{} --fields <Label>,...`; or {again}",
                shell_word(name.service()),
                name.flag()
            ),
        )),
        _ => {}
    }
    if kind == Kind::Profile && put.value.is_some() {
        faults.push(Refusal::of(
            &Fault::NotEnvName,
            format!("`{shown}` is a Profile, whose Fields are environment variables' names, and a bare `put` stores one value with no name"),
            format!("name its Fields: `optokens put {}{} --fields NAME,...`", shell_word(name.service()), name.flag()),
        ));
    }
    for (i, Field { label, .. }) in put.fields.iter().enumerate() {
        let before = || put.fields[..i].iter().filter(|f| f.label == *label);
        if label.is_empty() {
            faults.push(bad_set("a Field's label is empty".into()));
        } else if before().next().is_some() {
            // Refused once per label, however often it is named.
            if before().count() == 1 {
                faults.push(Refusal::of(
                    &Fault::DuplicateLabel,
                    format!("`put {shown}` names the Field `{label}` twice"),
                    format!("name `{label}` once"),
                ));
            }
        } else if kind == Kind::Profile && !is_env_name(label) {
            faults.push(Refusal::of(
                &Fault::NotEnvName,
                format!("`{label}` is not an environment variable's name, and a Profile's Fields are"),
                "label it with letters, digits and `_`, not starting with a digit, such as `API_TOKEN`",
            ));
        }
    }
    if !faults.is_empty() {
        return Err(faults);
    }
    let values = match (existing.map(|e| &e.values), &put.value) {
        (_, Some(value)) | (Some(Values::Single(value)), None) => Values::Single(value.clone()),
        stored => {
            let mut fields = match stored.0 {
                Some(Values::Fields(fields)) => fields.clone(),
                _ => Vec::new(),
            };
            for named in &put.fields {
                match fields.iter_mut().find(|f| f.label == named.label) {
                    Some(field) => *field = named.clone(),
                    None => fields.push(named.clone()),
                }
            }
            Values::Fields(fields)
        }
    };
    Ok(Secret {
        kind,
        // An empty one clears it: the notes it is stored as are then empty.
        description: match &put.description {
            Some(given) => Some(given.clone()).filter(|d| !d.is_empty()),
            None => existing.and_then(|e| e.description.clone()),
        },
        meta: put
            .meta
            .clone()
            .or_else(|| existing.and_then(|e| e.meta.clone())),
        values,
    })
}

/// The value `get` prints: the single value, or the Field `field` names.
pub fn value<'a>(name: &Name, secret: &'a Secret, field: Option<&str>) -> Result<&'a str, Refusal> {
    let get = format!("optokens get {}{}", shell_word(name.service()), name.flag());
    let shown = name.to_string();
    match (&secret.values, field) {
        (Values::Single(value), None) => Ok(value),
        (Values::Single(_), Some(label)) => Err(Refusal::of(
            &Fault::NoSuchField,
            format!("`{shown}` is a single value, with no Field `{label}`"),
            format!("run `{get}` without `--field`"),
        )),
        (Values::Fields(fields), Some(label)) => fields
            .iter()
            .find(|f| f.label == label)
            .map(|f| f.value.as_str())
            .ok_or_else(|| {
                Refusal::of(
                    &Fault::NoSuchField,
                    format!(
                        "`{shown}` has no Field `{label}`; its Fields are {}",
                        list_labels(fields)
                    ),
                    format!("run `{get} --field {}`", shell_word(&fields[0].label)),
                )
            }),
        (Values::Fields(fields), None) => Err(Refusal::of(
            &Fault::NoSuchField,
            format!(
                "`{shown}` has labelled Fields, {}: `get` prints one",
                list_labels(fields)
            ),
            format!(
                "run `{get} --field {}`, or `{get} --json` for them all",
                shell_word(&fields[0].label)
            ),
        )),
    }
}

fn list_labels(fields: &[Field]) -> String {
    fields
        .iter()
        .map(|f| format!("`{}`", f.label))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The whole Secret, as `get --json` prints it.
pub fn to_json(name: &Name, secret: &Secret) -> Value {
    let mut answer = head(name, secret);
    match &secret.values {
        Values::Single(value) => answer["value"] = json!(value),
        Values::Fields(fields) => {
            answer["fields"] = Value::Object(
                fields
                    .iter()
                    .map(|f| (f.label.clone(), json!(f.value)))
                    .collect(),
            )
        }
    }
    answer
}

/// One Secret as `list` shows it: never a value.
pub fn summary(name: &Name, secret: &Secret) -> Value {
    let mut answer = head(name, secret);
    answer["fields"] = json!(secret.labels());
    answer
}

/// What `get --json` and `list` both say of a Secret first.
fn head(name: &Name, secret: &Secret) -> Value {
    json!({
        "service": name.service(),
        "account": name.account(),
        "kind": secret.kind.name(),
        "description": secret.description,
        "meta": secret.meta,
    })
}

/// `env`'s lines: `export NAME='value'`, one per Field.
pub fn exports(name: &Name, secret: &Secret) -> Result<String, Refusal> {
    let get = format!("optokens get {}{}", shell_word(name.service()), name.flag());
    let shown = name.to_string();
    let fields = match &secret.values {
        Values::Single(_) => {
            return Err(Refusal::of(
                &Fault::NotEnv,
                format!("`{shown}` is a single value, with no variable's name to export it as"),
                format!("run `{get}`"),
            ));
        }
        Values::Fields(fields) => fields,
    };
    let bad: Vec<&str> = fields
        .iter()
        .map(|f| f.label.as_str())
        .filter(|l| !is_env_name(l))
        .collect();
    if !bad.is_empty() {
        return Err(Refusal::of(
            &Fault::NotEnv,
            format!(
                "`{shown}` has Fields that are not environment variables' names: {}",
                bad.iter()
                    .map(|l| format!("`{l}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            format!("run `{get} --field <Label>` for each"),
        ));
    }
    Ok(fields
        .iter()
        .map(|f| format!("export {}={}\n", f.label, single_quoted(&f.value)))
        .collect())
}

/// `value` in single quotes for a POSIX shell, each `'` as `'\''`.
pub fn single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// `word` as one word of a POSIX shell command line: as is when nothing in
/// it is special to the shell.
fn shell_word(word: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._-+:=@%,".contains(c);
    if !word.is_empty() && word.chars().all(plain) {
        word.to_string()
    } else {
        single_quoted(word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn name() -> Name {
        Name::new("glm", "default").unwrap()
    }

    /// Concealed Fields.
    fn concealed(pairs: &[(&str, &str)]) -> Vec<Field> {
        pairs
            .iter()
            .map(|(l, v)| Field::new(l, v, Visibility::Concealed))
            .collect()
    }

    fn fields(pairs: &[(&str, &str)]) -> Values {
        Values::Fields(concealed(pairs))
    }

    fn put(kind: Option<Kind>, pairs: &[(&str, &str)]) -> Put {
        Put {
            kind,
            description: None,
            meta: None,
            fields: concealed(pairs),
            value: None,
        }
    }

    fn kinds(faults: &[Refusal]) -> Vec<&str> {
        faults.iter().map(|f| f.kind.unwrap()).collect()
    }

    #[test]
    fn put_upserts_the_fields_it_names_and_keeps_the_rest_in_order() {
        let stored = Secret {
            kind: Kind::Profile,
            description: Some("Claude Code to GLM".into()),
            meta: None,
            values: fields(&[
                ("ANTHROPIC_BASE_URL", "https://a"),
                ("ANTHROPIC_MODEL", "glm-4.6"),
            ]),
        };
        let merged = merge(
            &name(),
            Some(&stored),
            &put(
                None,
                &[("ANTHROPIC_MODEL", "glm-5"), ("ANTHROPIC_AUTH_TOKEN", "t")],
            ),
        )
        .unwrap();
        assert_eq!(
            merged,
            Secret {
                kind: Kind::Profile,
                description: Some("Claude Code to GLM".into()),
                meta: None,
                values: fields(&[
                    ("ANTHROPIC_BASE_URL", "https://a"),
                    ("ANTHROPIC_MODEL", "glm-5"),
                    ("ANTHROPIC_AUTH_TOKEN", "t")
                ]),
            }
        );
    }

    #[test]
    fn a_new_secret_is_static_unless_put_says_profile() {
        let made = merge(&name(), None, &put(None, &[("Token", "t")])).unwrap();
        assert_eq!(made.kind, Kind::Static);
        assert_eq!(made.description, None);
        let described = Put {
            description: Some("d".into()),
            meta: None,
            ..put(Some(Kind::Profile), &[("A", "1")])
        };
        assert_eq!(
            merge(&name(), None, &described).unwrap().kind,
            Kind::Profile
        );
        let profile = Secret {
            kind: Kind::Profile,
            description: None,
            meta: None,
            values: fields(&[("A", "1")]),
        };
        let same = merge(
            &name(),
            Some(&profile),
            &put(Some(Kind::Profile), &[("B", "2")]),
        );
        assert_eq!(
            same.unwrap().kind,
            Kind::Profile,
            "naming the stored kind is no change"
        );
    }

    #[test]
    fn a_description_alone_changes_only_an_existing_secret() {
        let stored = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: Values::Single("v".into()),
        };
        let described = Put {
            description: Some("new".into()),
            meta: None,
            ..Put::default()
        };
        assert_eq!(
            merge(&name(), Some(&stored), &described).unwrap(),
            Secret {
                description: Some("new".into()),
                meta: None,
                ..stored.clone()
            }
        );
        assert_eq!(
            merge(&name(), Some(&stored), &Put::default()).unwrap(),
            stored,
            "a put of nothing changes nothing"
        );
        let described = Secret {
            description: Some("old".into()),
            ..stored.clone()
        };
        let cleared = Put {
            description: Some(String::new()),
            ..Put::default()
        };
        assert_eq!(
            merge(&name(), Some(&described), &cleared).unwrap(),
            stored,
            "an empty description clears it"
        );
    }

    #[test]
    fn meta_is_one_json_object_a_put_replaces_or_keeps() {
        let meta = |j: Value| j.as_object().cloned();
        assert_eq!(
            parse_meta(r#"{"account_id":"a"}"#).ok(),
            meta(json!({ "account_id": "a" }))
        );
        for bad in ["", "x", "[1]", "null", "1", "{"] {
            let refused = parse_meta(bad).unwrap_err();
            assert_eq!(refused.kind, Some("bad_meta"), "{bad}");
            assert!(
                refused
                    .fault
                    .starts_with(&format!("`--meta` is `{bad}`, which is"))
            );
        }
        assert!(
            parse_meta("[1]")
                .unwrap_err()
                .fault
                .ends_with("JSON but not one object")
        );
        let stored = Secret {
            kind: Kind::Static,
            description: None,
            meta: meta(json!({ "a": 1 })),
            values: Values::Single("v".into()),
        };
        assert_eq!(
            merge(&name(), Some(&stored), &Put::default()).unwrap(),
            stored,
            "a put without --meta keeps it"
        );
        let replaced = Put {
            meta: meta(json!({ "b": 2 })),
            ..Put::default()
        };
        assert_eq!(
            merge(&name(), Some(&stored), &replaced).unwrap().meta,
            meta(json!({ "b": 2 }))
        );
    }

    #[test]
    fn a_bare_put_sets_or_replaces_a_single_value_and_never_fields() {
        let bare = |v: &str| Put {
            value: Some(v.into()),
            ..Put::default()
        };
        let made = merge(&name(), None, &bare("v1")).unwrap();
        assert_eq!(made.values, Values::Single("v1".into()));
        assert_eq!(made.kind, Kind::Static);
        let rotated = merge(&name(), Some(&made), &bare("v2")).unwrap();
        assert_eq!(rotated.values, Values::Single("v2".into()));
        let aws = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: fields(&[("A", "1")]),
        };
        let faults = merge(&Name::new("aws", "ci").unwrap(), Some(&aws), &bare("v")).unwrap_err();
        assert_eq!(kinds(&faults), ["shape_change"]);
        assert_eq!(
            faults[0].fix,
            "name the Fields to change, `optokens put aws --account ci --fields <Label>,...`; or run `optokens rm aws --account ci`, then `put` it again in its new shape"
        );
        let profile = Put {
            kind: Some(Kind::Profile),
            ..bare("v")
        };
        let faults = merge(&name(), None, &profile).unwrap_err();
        assert_eq!(kinds(&faults), ["not_env_name"]);
        assert_eq!(
            faults[0].fix,
            "name its Fields: `optokens put glm --fields NAME,...`"
        );
    }

    #[test]
    fn put_refuses_every_fault_at_once_with_its_fix() {
        let stored = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: Values::Single("v".into()),
        };
        let faults = merge(
            &name(),
            Some(&stored),
            &put(
                Some(Kind::Profile),
                &[("1BAD", "x"), ("A", "1"), ("A", "2"), ("A", "3")],
            ),
        )
        .unwrap_err();
        assert_eq!(
            kinds(&faults),
            ["kind_change", "shape_change", "duplicate_label"]
        );
        assert_eq!(
            faults[0].fix,
            "run `optokens rm glm`, then `put` it again with `--kind profile`"
        );
        let faults = merge(
            &Name::new("glm", "work").unwrap(),
            None,
            &put(Some(Kind::Profile), &[("1BAD", "x"), ("", "y")]),
        )
        .unwrap_err();
        assert_eq!(kinds(&faults), ["not_env_name", "bad_set"]);
        assert_eq!(
            faults[0].fault,
            "`1BAD` is not an environment variable's name, and a Profile's Fields are"
        );
        let single = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: Values::Single("v".into()),
        };
        let faults = merge(
            &Name::new("glm", "work").unwrap(),
            Some(&single),
            &put(None, &[("A", "1")]),
        )
        .unwrap_err();
        assert_eq!(
            faults[0].fix,
            "run `optokens rm glm --account work`, then `put` it again in its new shape"
        );
    }

    #[test]
    fn a_set_splits_on_the_first_equals_sign() {
        assert_eq!(
            parse_set("URL=https://x?a=b").unwrap(),
            Field::new("URL", "https://x?a=b", Visibility::Plain)
        );
        assert_eq!(
            parse_set("EMPTY=").unwrap(),
            Field::new("EMPTY", "", Visibility::Plain)
        );
        let refused = parse_set("NOEQUALS").unwrap_err();
        assert_eq!(refused.kind, Some("bad_set"));
        assert_eq!(refused.fix, "write each as `--set \"NAME=value\"`");
        assert_eq!(parse_set("=v").unwrap_err().kind, Some("bad_set"));
    }

    #[test]
    fn stdin_drops_one_trailing_newline_and_refuses_a_terminal_unread() {
        assert_eq!(stdin_value(false, || b"abc\n\n".to_vec()).unwrap(), "abc\n");
        assert_eq!(stdin_value(false, || b"a b".to_vec()).unwrap(), "a b");
        let refused = stdin_value(true, || panic!("a terminal is never read")).unwrap_err();
        assert_eq!(refused.kind, Some("stdin_terminal"));
        assert_eq!(
            stdin_value(false, || b"\n".to_vec()).unwrap_err().kind,
            Some("stdin_empty")
        );
        assert_eq!(
            stdin_value(false, Vec::new).unwrap_err().kind,
            Some("stdin_empty")
        );
        assert_eq!(
            stdin_value(false, || vec![0xff, 0xfe]).unwrap_err().kind,
            Some("stdin_not_text")
        );
    }

    #[test]
    fn a_pipe_is_named_by_its_label_and_never_by_its_path() {
        let read = |want: &'static str, got: Option<&'static [u8]>| {
            move |path: &str| {
                assert_eq!(path, want);
                got.map(<[u8]>::to_vec)
            }
        };
        assert_eq!(
            pipe_field(1, "Key=/dev/fd/11", read("/dev/fd/11", Some(b"k=v\n"))).unwrap(),
            Field::new("Key", "k=v", Visibility::Concealed)
        );
        let secret = "Key=s3cr3t-value";
        let refused = pipe_field(1, secret, read("s3cr3t-value", None)).unwrap_err();
        assert_eq!(refused.kind, Some("not_a_pipe"));
        assert!(!format!("{refused:?}").contains("s3cr3t"), "{refused:?}");
        let unlabelled = pipe_field(2, "s3cr3t", |_| panic!("never read")).unwrap_err();
        assert_eq!(unlabelled.kind, Some("not_a_pipe"));
        assert!(!format!("{unlabelled:?}").contains("s3cr3t"));
        assert!(pipe_field(3, "=/dev/fd/3", |_| panic!("never read")).is_err());
        let kind = |bytes: &'static [u8]| {
            pipe_field(1, "K=p", read("p", Some(bytes)))
                .unwrap_err()
                .kind
        };
        assert_eq!(kind(b"\n"), Some("pipe_empty"));
        assert_eq!(kind(&[0xff]), Some("pipe_not_text"));
    }

    #[test]
    fn a_name_is_two_slugs_without_a_slash() {
        assert_eq!(Name::new("a", "b").unwrap().to_string(), "a/b");
        assert_eq!(Name::new("a", "b").unwrap().title(), "a.b");
        assert_eq!(
            Name::new("name.com", "default").unwrap().title(),
            "name.com"
        );
        assert_eq!(
            Name::from_old_title("a/b"),
            Some(Name::new("a", "b").unwrap())
        );
        assert_eq!(Name::from_old_title("a/b/c"), None);
        assert_eq!(Name::from_old_title("ab"), None);
        assert_eq!(Name::new("", "b").unwrap_err().kind, Some("bad_name"));
        assert_eq!(Name::new("a/x", "b").unwrap_err().kind, Some("bad_name"));
    }

    #[test]
    fn get_picks_the_single_value_or_the_named_field() {
        let single = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: Values::Single("v".into()),
        };
        assert_eq!(value(&name(), &single, None).unwrap(), "v");
        assert_eq!(
            value(&name(), &single, Some("X")).unwrap_err().fix,
            "run `optokens get glm` without `--field`"
        );
        let aws = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: fields(&[("Access Key ID", "id"), ("Secret", "s")]),
        };
        let aws_name = Name::new("aws", "ci").unwrap();
        assert_eq!(value(&aws_name, &aws, Some("Secret")).unwrap(), "s");
        let bare = value(&aws_name, &aws, None).unwrap_err();
        assert_eq!(
            bare.fix,
            "run `optokens get aws --account ci --field 'Access Key ID'`, or `optokens get aws --account ci --json` for them all"
        );
        let missing = value(&aws_name, &aws, Some("Nope")).unwrap_err();
        assert_eq!(
            missing.fault,
            "`aws/ci` has no Field `Nope`; its Fields are `Access Key ID`, `Secret`"
        );
    }

    #[test]
    fn env_exports_each_field_single_quoted() {
        let profile = Secret {
            kind: Kind::Profile,
            description: None,
            meta: None,
            values: fields(&[("A", "it's $HOME"), ("B", "")]),
        };
        assert_eq!(
            exports(&name(), &profile).unwrap(),
            "export A='it'\\''s $HOME'\nexport B=''\n"
        );
        let aws = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: fields(&[("Access Key ID", "x")]),
        };
        assert_eq!(exports(&name(), &aws).unwrap_err().kind, Some("not_env"));
        let single = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: Values::Single("v".into()),
        };
        assert_eq!(
            exports(&name(), &single).unwrap_err().fix,
            "run `optokens get glm`"
        );
    }

    #[test]
    fn get_json_and_list_show_kind_description_and_meta_and_list_no_value() {
        let s = Secret {
            kind: Kind::Profile,
            description: Some("d".into()),
            meta: json!({ "m": 1 }).as_object().cloned(),
            values: fields(&[("B", "2"), ("A", "1")]),
        };
        assert_eq!(
            to_json(&name(), &s),
            json!({ "service": "glm", "account": "default", "kind": "profile", "description": "d", "meta": { "m": 1 }, "fields": { "A": "1", "B": "2" } })
        );
        assert_eq!(
            summary(&name(), &s),
            json!({ "service": "glm", "account": "default", "kind": "profile", "description": "d", "meta": { "m": 1 }, "fields": ["B", "A"] })
        );
        let single = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: Values::Single("v".into()),
        };
        assert_eq!(to_json(&name(), &single)["value"], "v");
        assert_eq!(summary(&name(), &single)["meta"], Value::Null);
        assert_eq!(summary(&name(), &single)["fields"], Value::Null);
    }

    /// What `sh -c` makes of `export NAME=<quoted>; printf %s "$NAME"`.
    fn through_sh(value: &str) -> String {
        let script = format!("export V={}; printf %s \"$V\"", single_quoted(value));
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    }

    proptest! {
        #[test]
        fn any_value_single_quoted_is_read_back_by_sh_as_it_was(value in "[^\u{0}]{0,40}") {
            prop_assume!(cfg!(unix));
            prop_assert_eq!(through_sh(&value), value);
        }

        #[test]
        fn a_merge_holds_every_field_put_named_and_every_one_it_kept(
            stored in proptest::collection::vec(("[A-Z]{1,3}", ".{0,5}", any::<bool>()), 0..5),
            named in proptest::collection::vec(("[A-Z]{1,3}", ".{0,5}", any::<bool>()), 1..5),
        ) {
            let dedup = |v: Vec<(String, String, bool)>| {
                let mut out: Vec<Field> = Vec::new();
                for (l, val, plain) in v {
                    let visibility = if plain { Visibility::Plain } else { Visibility::Concealed };
                    if !out.iter().any(|o| o.label == l) { out.push(Field::new(&l, &val, visibility)); }
                }
                out
            };
            let (stored, named) = (dedup(stored), dedup(named));
            let existing = (!stored.is_empty()).then(|| Secret { kind: Kind::Static, description: None, meta: None, values: Values::Fields(stored.clone()) });
            let merged = merge(&name(), existing.as_ref(), &Put { fields: named.clone(), ..Put::default() }).unwrap();
            let Values::Fields(merged) = merged.values else { panic!("fields") };
            for f in &named { prop_assert!(merged.contains(f)); }
            for f in &stored {
                if !named.iter().any(|n| n.label == f.label) { prop_assert!(merged.contains(f)); }
            }
            prop_assert_eq!(merged.len(), stored.len() + named.iter().filter(|n| !stored.iter().any(|s| s.label == n.label)).count());
        }
    }
}
