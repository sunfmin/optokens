//! How a Secret is laid out as an item of the vault, and read back: pure.
//!
//! One Secret is one item, titled as [`Name::title`] says and tagged
//! [`TAG`]. Its values are the fields of the section [`VALUES`], each
//! labelled with its Field's label ([`SINGLE`] for a single value) and typed
//! by its visibility ([`CONCEALED`] or [`STRING`]); its service, account,
//! kind, shape and Meta (compact JSON, [`META_FIELD`]) are the fields of the
//! section [`META`]; its Description is the item's notes ([`NOTES`]), what
//! 1Password shows under the title in its list. The
//! name is read from that section, never from the title; an item an earlier
//! optokens wrote, titled `<service>/<account>` without them, is read by its
//! title. An item that is not this shape is refused by name, never guessed at;
//! its other tags, sections and fields are another program's, read past and
//! kept by [`template`] over the stored item.

use crate::refusal::Refusal;
use crate::secret::Visibility::{Concealed, Plain};
use crate::secret::{Fault, Field, Kind, Name, Secret, Values};
use serde_json::{Map, Value, json};

/// The tag on every item optokens writes.
pub const TAG: &str = "optokens";
/// The item's category: one with no fields of its own to fill.
pub const CATEGORY: &str = "SECURE_NOTE";
/// The section of the Secret's values.
pub const VALUES: &str = "fields";
/// The section of what optokens knows of the Secret.
pub const META: &str = "optokens";
/// [`META`]'s fields.
pub const SERVICE: &str = "service";
pub const ACCOUNT: &str = "account";
pub const KIND: &str = "kind";
/// Where an earlier layout kept the Description, before the notes: read,
/// never written.
pub const DESCRIPTION: &str = "description";
pub const SHAPE: &str = "shape";
/// The Secret's Meta, one JSON object written compact; absent when it has none.
pub const META_FIELD: &str = "meta";
/// [`SHAPE`]'s values: a single value, or labelled Fields.
pub const SHAPE_SINGLE: &str = "value";
pub const SHAPE_FIELDS: &str = "fields";
/// The label of a single value's one field in [`VALUES`].
pub const SINGLE: &str = "value";
/// The field types: a concealed value, shown like a password, and plain text.
pub const CONCEALED: &str = "CONCEALED";
pub const STRING: &str = "STRING";
/// The `purpose` of the item's notes field, which holds the Description.
pub const NOTES: &str = "NOTES";
/// The id and label 1Password gives the notes field.
pub const NOTES_ID: &str = "notesPlain";

/// The item template that `op item create` and `op item edit` read on stdin:
/// over `stored`, the item as `op` printed it, it keeps what optokens does
/// not own (every tag, section and field beside [`TAG`], [`VALUES`],
/// [`META`] and the notes), as an edit template replaces the whole item.
pub fn template(name: &Name, secret: &Secret, stored: Option<&Value>) -> Value {
    let field = |section: &str, id: String, visibility, label: &str, value: &str| {
        let kind = if visibility == Plain {
            STRING
        } else {
            CONCEALED
        };
        json!({ "id": id, "section": { "id": section }, "type": kind, "label": label, "value": value })
    };
    let single;
    let (shape, values) = match &secret.values {
        Values::Single(value) => {
            single = [Field::new(SINGLE, value, Concealed)];
            (SHAPE_SINGLE, &single[..])
        }
        Values::Fields(fields) => (SHAPE_FIELDS, &fields[..]),
    };
    let notes = secret.description.as_deref().unwrap_or_default();
    let mut fields = vec![
        json!({ "id": NOTES_ID, "type": STRING, "purpose": NOTES, "label": NOTES_ID, "value": notes }),
    ];
    fields.extend(values.iter().enumerate().map(|(i, f)| {
        field(
            VALUES,
            format!("{VALUES}.{i}"),
            f.visibility,
            &f.label,
            &f.value,
        )
    }));
    let data = secret
        .meta
        .as_ref()
        .map(|m| Value::Object(m.clone()).to_string());
    let meta = [
        Some((SERVICE, name.service())),
        Some((ACCOUNT, name.account())),
        Some((KIND, secret.kind.name())),
        Some((SHAPE, shape)),
        data.as_deref().map(|m| (META_FIELD, m)),
    ];
    fields.extend(
        meta.into_iter()
            .flatten()
            .map(|(l, v)| field(META, format!("{META}.{l}"), Plain, l, v)),
    );
    let mut tags = vec![json!(TAG)];
    let mut sections = vec![
        json!({ "id": VALUES, "label": VALUES }),
        json!({ "id": META, "label": META }),
    ];
    if let Some(stored) = stored {
        let all = |key: &str| stored[key].as_array().into_iter().flatten();
        tags.extend(all("tags").filter(|t| *t != TAG).cloned());
        let ours = |label: Option<&str>| label.is_some_and(|l| [VALUES, META].contains(&l));
        sections.extend(
            all("sections")
                .filter(|s| !ours(s["label"].as_str()))
                .cloned(),
        );
        let labels = section_labels(stored);
        fields.extend(
            all("fields")
                .filter(|f| !ours(section_of(f, &labels)) && !is_notes(f))
                .cloned(),
        );
    }
    json!({
        "title": name.title(),
        "category": CATEGORY,
        "tags": tags,
        "sections": sections,
        "fields": fields,
    })
}

/// Whether `field` is the item's notes.
fn is_notes(field: &Value) -> bool {
    field["purpose"] == NOTES
}

/// Each section's label by its id, as op names a field's section by either.
fn section_labels(item: &Value) -> Map<String, Value> {
    item["sections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| Some((s["id"].as_str()?.to_string(), s["label"].clone())))
        .collect()
}

/// The label of `field`'s section; `None` for the category's own fields.
fn section_of<'a>(field: &'a Value, labels: &'a Map<String, Value>) -> Option<&'a str> {
    let section = &field["section"];
    if section.is_null() {
        return None;
    }
    Some(
        section["label"]
            .as_str()
            .or_else(|| labels.get(section["id"].as_str()?)?.as_str())
            .unwrap_or_default(),
    )
}

/// The Secret an item holds, as `op item get --format json` prints it.
/// Refused, naming the item, when it is not optokens' layout.
pub fn read(item: &Value) -> Result<(Name, Secret), Refusal> {
    let title = item["title"].as_str().unwrap_or_default();
    layout(item).map_err(|why| {
        Refusal::of(
            &Fault::NotOptokens,
            format!("the vault's item `{title}` is not a Secret optokens wrote: {why}"),
            format!("rename or move the item `{title}` in 1Password, or delete it there if it is one optokens wrote and then changed"),
        )
    })
}

fn layout(item: &Value) -> Result<(Name, Secret), String> {
    let title = item["title"].as_str().unwrap_or_default();
    if !tagged(item) {
        return Err(format!("it has no tag `{TAG}`"));
    }
    let labels = section_labels(item);
    let (mut values, mut meta, mut notes) = (Vec::new(), Vec::new(), None);
    for field in item["fields"].as_array().ok_or("it has no fields")? {
        if is_notes(field) {
            notes = field["value"].as_str();
        }
        // The category's own fields, and a section another program keeps
        // (mytokens'), are never optokens': read past, kept by a `put`.
        let Some(section) = section_of(field, &labels) else {
            continue;
        };
        let label = field["label"].as_str().unwrap_or_default().to_string();
        // op leaves `value` out of a field that is empty.
        let value = field["value"].as_str().unwrap_or_default().to_string();
        match section {
            VALUES => {
                let visibility = match field["type"].as_str() {
                    Some(CONCEALED) => Concealed,
                    Some(STRING) => Plain,
                    other => {
                        return Err(format!(
                            "its field `{label}` in section `{VALUES}` is of type {other:?}, neither `{CONCEALED}` nor `{STRING}`"
                        ));
                    }
                };
                values.push(Field::new(&label, &value, visibility))
            }
            META => meta.push((label, value)),
            _ => {}
        }
    }
    let one = |key: &str| -> Result<Option<String>, String> {
        let mut found = meta.iter().filter(|(l, _)| l == key);
        let first = found.next().map(|(_, v)| v.clone());
        match found.next() {
            Some(_) => Err(format!("its section `{META}` has `{key}` twice")),
            None => Ok(first),
        }
    };
    if let Some((stray, _)) = meta.iter().find(|(l, _)| {
        ![SERVICE, ACCOUNT, KIND, SHAPE, DESCRIPTION, META_FIELD].contains(&l.as_str())
    }) {
        return Err(format!("its section `{META}` has a field `{stray}`"));
    }
    let name = match (one(SERVICE)?, one(ACCOUNT)?) {
        (Some(service), Some(account)) => Name::new(&service, &account).map_err(|_| {
            format!("its `{SERVICE}` `{service}` and `{ACCOUNT}` `{account}` are not a Secret's name")
        })?,
        (None, None) => Name::from_old_title(title).ok_or(format!(
            "its section `{META}` has no `{SERVICE}` and `{ACCOUNT}`, and its title is not `<service>/<account>`"
        ))?,
        _ => return Err(format!("its section `{META}` has one of `{SERVICE}` and `{ACCOUNT}` without the other")),
    };
    let kind = one(KIND)?.ok_or(format!("its section `{META}` has no `{KIND}`"))?;
    let kind = <Kind as clap::ValueEnum>::from_str(&kind, false)
        .map_err(|_| format!("its `{KIND}` is `{kind}`, neither static nor profile"))?;
    // An item an earlier layout wrote keeps it in the section: that one is
    // what optokens (or mytokens) last wrote, the notes another program's.
    let description = one(DESCRIPTION)?
        .filter(|d| !d.is_empty())
        .or_else(|| notes.filter(|n| !n.is_empty()).map(String::from));
    // An item written before Meta has no field of it: a Secret with none.
    let meta = match one(META_FIELD)? {
        None => None,
        Some(data) => match serde_json::from_str::<Value>(&data) {
            Ok(Value::Object(meta)) => Some(meta),
            _ => return Err(format!("its `{META_FIELD}` is not a JSON object")),
        },
    };
    let values = match one(SHAPE)?.as_deref() {
        Some(SHAPE_SINGLE) => match values.as_slice() {
            [field] if field.label == SINGLE => Values::Single(field.value.clone()),
            _ => {
                return Err(format!(
                    "it is a single value, but its section `{VALUES}` is not one field `{SINGLE}`"
                ));
            }
        },
        Some(SHAPE_FIELDS) => {
            if values.is_empty() {
                return Err(format!("its section `{VALUES}` has no field"));
            }
            for (i, Field { label, .. }) in values.iter().enumerate() {
                if label.is_empty() || values[..i].iter().any(|f| f.label == *label) {
                    return Err(format!(
                        "its section `{VALUES}` has the label `{label}` empty or twice"
                    ));
                }
            }
            Values::Fields(values)
        }
        other => {
            return Err(format!(
                "its `{SHAPE}` is {other:?}, neither `{SHAPE_SINGLE}` nor `{SHAPE_FIELDS}`"
            ));
        }
    };
    Ok((
        name,
        Secret {
            kind,
            description,
            meta,
            values,
        },
    ))
}

fn tagged(item: &Value) -> bool {
    item["tags"]
        .as_array()
        .is_some_and(|tags| tags.iter().any(|t| t == TAG))
}

/// The ids of the items among `op item list --format json`'s summaries that
/// may hold `name`'s Secret: those titled [`Name::title`] or
/// its earlier title, `<service>/<account>`. Which one does is for [`read`] to say, as another
/// Secret's title may be the same (`a.b` is `a.b/default` and `a/b`). An item
/// of either title without the tag is refused.
pub fn candidates(summaries: &Value, name: &Name) -> Result<Vec<String>, Refusal> {
    let titles = [name.title(), name.to_string()];
    let mut ids = Vec::new();
    for item in summaries.as_array().into_iter().flatten() {
        if !titles.iter().any(|t| item["title"] == t.as_str()) {
            continue;
        }
        if !tagged(item) {
            return Err(read(item).expect_err("an item without the tag is refused"));
        }
        ids.push(item["id"].as_str().unwrap_or_default().to_string());
    }
    Ok(ids)
}

/// Refused when more than one item, `ids`, holds `name`'s Secret.
pub fn unique(name: &Name, ids: &[&str]) -> Result<(), Refusal> {
    if ids.len() < 2 {
        return Ok(());
    }
    Err(Refusal::of(
        &Fault::Ambiguous,
        format!(
            "the vault has {} items of the Secret `{name}` tagged `{TAG}`: {}",
            ids.len(),
            ids.join(", ")
        ),
        format!(
            "delete all but one of the items {} in 1Password",
            ids.join(", ")
        ),
    ))
}

/// Whether `item`, read as `name`'s, is in this optokens' layout: titled
/// [`Name::title`], its name in [`META`], no [`DESCRIPTION`] there. `put`
/// rewrites one that is not.
pub fn current(item: &Value, name: &Name) -> bool {
    let has = |label: &str| {
        item["fields"].as_array().into_iter().flatten().any(|f| {
            f["label"] == label && (f["section"]["label"] == META || f["section"]["id"] == META)
        })
    };
    item["title"] == name.title().as_str() && has(SERVICE) && has(ACCOUNT) && !has(DESCRIPTION)
}

/// The ids of the items optokens wrote, by their tag.
pub fn ours(summaries: &Value) -> Vec<String> {
    summaries
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| tagged(item))
        .map(|item| item["id"].as_str().unwrap_or_default().to_string())
        .collect()
}

// What `op` keeps of a template, as the stand-in keeps it: for the round trip.
#[cfg(test)]
#[path = "../examples/standin/keep.rs"]
mod standin;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The item as `op` keeps it.
    fn stored(template: &Value) -> Value {
        super::standin::keep(template, "abc123", "optokens")
    }

    fn secret() -> (Name, Secret) {
        (
            Name::new("aws", "ci").unwrap(),
            Secret {
                kind: Kind::Static,
                description: Some("CI deploy".into()),
                meta: json!({ "region": "us-east-1", "n": [1] })
                    .as_object()
                    .cloned(),
                values: Values::Fields(vec![
                    Field::new("Access Key ID", "AKIA", Plain),
                    Field::new("Secret", "s", Concealed),
                ]),
            },
        )
    }

    #[test]
    fn the_template_is_one_tagged_item_with_values_and_metadata_in_their_sections() {
        let (name, secret) = secret();
        assert_eq!(
            template(&name, &secret, None),
            json!({
                "title": "aws.ci",
                "category": "SECURE_NOTE",
                "tags": ["optokens"],
                "sections": [{ "id": "fields", "label": "fields" }, { "id": "optokens", "label": "optokens" }],
                "fields": [
                    { "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": "CI deploy" },
                    { "id": "fields.0", "section": { "id": "fields" }, "type": "STRING", "label": "Access Key ID", "value": "AKIA" },
                    { "id": "fields.1", "section": { "id": "fields" }, "type": "CONCEALED", "label": "Secret", "value": "s" },
                    { "id": "optokens.service", "section": { "id": "optokens" }, "type": "STRING", "label": "service", "value": "aws" },
                    { "id": "optokens.account", "section": { "id": "optokens" }, "type": "STRING", "label": "account", "value": "ci" },
                    { "id": "optokens.kind", "section": { "id": "optokens" }, "type": "STRING", "label": "kind", "value": "static" },
                    { "id": "optokens.shape", "section": { "id": "optokens" }, "type": "STRING", "label": "shape", "value": "fields" },
                    { "id": "optokens.meta", "section": { "id": "optokens" }, "type": "STRING", "label": "meta", "value": r#"{"n":[1],"region":"us-east-1"}"# },
                ],
            })
        );
    }

    #[test]
    fn a_field_called_kind_never_collides_with_the_metadata() {
        let name = Name::new("p", "default").unwrap();
        let secret = Secret {
            kind: Kind::Profile,
            description: None,
            meta: None,
            values: Values::Fields(vec![
                Field::new("kind", "x", Plain),
                Field::new("description", "y", Concealed),
            ]),
        };
        assert_eq!(
            read(&stored(&template(&name, &secret, None))).unwrap(),
            (name, secret)
        );
    }

    #[test]
    fn an_item_not_in_optokens_layout_is_refused_by_name() {
        let (name, secret) = secret();
        let good = stored(&template(&name, &secret, None));
        let why = |edit: &dyn Fn(&mut Value)| {
            let mut item = good.clone();
            edit(&mut item);
            let refused = read(&item).unwrap_err();
            assert_eq!(refused.kind, Some("not_optokens"));
            let title = item["title"].as_str().unwrap();
            assert!(
                refused
                    .fix
                    .starts_with(&format!("rename or move the item `{title}`")),
                "{refused:?}"
            );
            refused.fault
        };
        assert_eq!(
            why(&|i| i["tags"] = json!([])),
            "the vault's item `aws.ci` is not a Secret optokens wrote: it has no tag `optokens`"
        );
        assert!(
            why(&|i| i["fields"][5]["value"] = json!("parent"))
                .ends_with("its `kind` is `parent`, neither static nor profile")
        );
        assert!(
            why(&|i| i["fields"][6]["value"] = json!("value"))
                .ends_with("its section `fields` is not one field `value`")
        );
        let single = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: Values::Single("v".into()),
        };
        let mut renamed = stored(&template(&name, &single, None));
        renamed["fields"][1]["label"] = json!("Token");
        assert!(
            read(&renamed)
                .unwrap_err()
                .fault
                .ends_with("its section `fields` is not one field `value`")
        );
        assert!(
            why(&|i| i["fields"][5]["label"] = json!("level"))
                .ends_with("its section `optokens` has a field `level`")
        );
        assert!(why(&|i| i["fields"][2]["type"] = json!("URL")).ends_with(
            "its field `Secret` in section `fields` is of type Some(\"URL\"), neither `CONCEALED` nor `STRING`"
        ));
        assert!(
            why(&|i| {
                i["fields"][1].as_object_mut().unwrap().remove("type");
            })
            .ends_with("is of type None, neither `CONCEALED` nor `STRING`")
        );
        assert!(
            why(&|i| i["fields"][2]["label"] = json!("Access Key ID"))
                .ends_with("has the label `Access Key ID` empty or twice")
        );
        assert!(
            why(&|i| {
                i["fields"].as_array_mut().unwrap().remove(4);
            })
            .ends_with("has one of `service` and `account` without the other")
        );
        for data in ["[1]", "{", "\"s\""] {
            assert!(
                why(&|i| i["fields"][7]["value"] = json!(data))
                    .ends_with("its `meta` is not a JSON object")
            );
        }
        assert!(
            why(&|i| i["fields"][3]["value"] = json!("a/b"))
                .ends_with("its `service` `a/b` and `account` `ci` are not a Secret's name")
        );
    }

    #[test]
    fn a_put_over_an_item_keeps_the_tags_sections_and_fields_optokens_does_not_own() {
        let (name, secret) = secret();
        let mut item = stored(&template(&name, &secret, None));
        item["tags"] = json!(["mytokens", "optokens", "mytokens-digest-abc"]);
        item["sections"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "id": "m", "label": "mytokens" }));
        let theirs = json!({ "id": "m.origin", "section": { "id": "m" }, "type": "STRING", "label": "origin", "value": "laptop" });
        item["fields"].as_array_mut().unwrap().push(theirs.clone());
        assert_eq!(
            read(&item).unwrap(),
            (name.clone(), secret.clone()),
            "a section optokens does not know is read past"
        );
        let over = template(&name, &secret, Some(&item));
        assert_eq!(
            over["tags"],
            json!(["optokens", "mytokens", "mytokens-digest-abc"])
        );
        assert_eq!(
            over["sections"][2],
            json!({ "id": "m", "label": "mytokens" })
        );
        assert_eq!(over["sections"].as_array().unwrap().len(), 3);
        let fields = over["fields"].as_array().unwrap();
        let fresh = template(&name, &secret, None)["fields"].clone();
        assert_eq!(
            fields[..fields.len() - 1],
            fresh.as_array().unwrap()[..],
            "the notes are optokens' own, the Description"
        );
        assert_eq!(fields[fields.len() - 1], theirs);
        assert_eq!(read(&stored(&over)).unwrap(), (name, secret));
    }

    #[test]
    fn a_field_naming_its_section_by_id_alone_is_read_and_rewritten_as_optokens() {
        let (name, secret) = secret();
        let mut item = stored(&template(&name, &secret, None));
        for f in item["fields"].as_array_mut().unwrap() {
            if let Some(section) = f["section"].as_object_mut() {
                section.remove("label");
            }
        }
        assert_eq!(read(&item).unwrap(), (name.clone(), secret.clone()));
        assert_eq!(
            template(&name, &secret, Some(&item)),
            template(&name, &secret, None),
            "optokens' own fields are rewritten, not kept twice"
        );
    }

    #[test]
    fn the_description_is_the_notes_and_none_is_empty_notes() {
        let (name, secret) = secret();
        let notes = |item: &Value| {
            let notes: Vec<&Value> = item["fields"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|f| f["purpose"] == NOTES)
                .collect();
            assert_eq!(notes.len(), 1, "one notes field: {item}");
            notes[0]["value"].clone()
        };
        let laid = template(&name, &secret, None);
        assert_eq!(notes(&laid), "CI deploy");
        assert!(
            !laid["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["label"] == DESCRIPTION),
            "no `description` in the section `optokens`"
        );
        let bare = Secret {
            description: None,
            ..secret.clone()
        };
        assert_eq!(notes(&template(&name, &bare, None)), "");
        let mut noted = stored(&template(&name, &bare, None));
        noted["fields"][0]["value"] = json!("line one\nline two");
        assert_eq!(
            read(&noted).unwrap().1.description.as_deref(),
            Some("line one\nline two"),
            "the whole notes, written in 1Password, are the Description"
        );
    }

    /// An item in the layout before the notes: its Description a field
    /// `description` of the section `optokens`, its notes `notes`.
    fn sectioned(name: &Name, secret: &Secret, notes: &str) -> Value {
        let mut item = stored(&template(name, secret, None));
        let fields = item["fields"].as_array_mut().unwrap();
        fields[0]["value"] = json!(notes);
        if let Some(d) = &secret.description {
            fields.push(json!({ "id": "optokens.description", "section": { "id": META, "label": META }, "type": STRING, "label": DESCRIPTION, "value": d }));
        }
        item
    }

    #[test]
    fn an_item_with_the_description_in_its_section_is_read_by_it_and_rewritten_into_the_notes() {
        let (name, secret) = secret();
        for notes in ["", "another program's note"] {
            let item = sectioned(&name, &secret, notes);
            assert_eq!(read(&item).unwrap(), (name.clone(), secret.clone()));
            assert!(!current(&item, &name), "a `put` rewrites it");
            let over = template(&name, &secret, Some(&item));
            assert_eq!(over, template(&name, &secret, None));
            assert_eq!(
                read(&stored(&over)).unwrap(),
                (name.clone(), secret.clone())
            );
        }
        let bare = Secret {
            description: None,
            ..secret.clone()
        };
        assert_eq!(
            read(&sectioned(&name, &bare, "a note"))
                .unwrap()
                .1
                .description
                .as_deref(),
            Some("a note"),
            "without one in the section, the notes are the Description"
        );
    }

    /// An item as an earlier optokens wrote it: titled `<service>/<account>`,
    /// no name in its section.
    fn old(name: &Name, secret: &Secret) -> Value {
        let mut item = stored(&template(name, secret, None));
        item["title"] = json!(name.to_string());
        item["fields"]
            .as_array_mut()
            .unwrap()
            .retain(|f| f["label"] != SERVICE && f["label"] != ACCOUNT);
        item
    }

    #[test]
    fn the_name_is_read_from_the_section_never_split_from_the_title() {
        let (_, secret) = secret();
        let dotted = Name::new("name.com", "default").unwrap();
        let item = stored(&template(&dotted, &secret, None));
        assert_eq!(item["title"], "name.com");
        assert_eq!(read(&item).unwrap(), (dotted.clone(), secret.clone()));
        assert!(current(&item, &dotted));
        let account = Name::new("name", "com").unwrap();
        assert_eq!(account.title(), "name.com");
        assert_ne!(read(&item).unwrap().0, account);
    }

    #[test]
    fn an_item_an_earlier_optokens_wrote_is_read_by_its_title_and_is_not_current() {
        let (name, secret) = secret();
        let item = old(&name, &secret);
        assert_eq!(item["title"], "aws/ci");
        assert_eq!(read(&item).unwrap(), (name.clone(), secret.clone()));
        assert!(!current(&item, &name));
        let mut titled = stored(&template(&name, &secret, None));
        assert!(current(&titled, &name));
        titled["title"] = json!("aws/ci");
        assert!(
            !current(&titled, &name),
            "an old title with the new section is rewritten"
        );
        let mut untitled = item.clone();
        untitled["title"] = json!("aws");
        assert!(read(&untitled).unwrap_err().fault.ends_with(
            "its section `optokens` has no `service` and `account`, and its title is not `<service>/<account>`"
        ));
    }

    #[test]
    fn current_reads_the_name_only_from_the_section_named_optokens_by_its_label_or_id() {
        let (name, secret) = secret();
        let item = stored(&template(&name, &secret, None));
        let with_sections = |section: Value, meta: &[&str]| {
            let mut item = item.clone();
            for f in item["fields"].as_array_mut().unwrap() {
                if meta.contains(&f["label"].as_str().unwrap()) {
                    f["section"] = section.clone();
                }
            }
            item
        };
        let name_fields = [SERVICE, ACCOUNT];
        assert!(
            current(
                &with_sections(json!({ "id": "x7k2", "label": META }), &name_fields),
                &name
            ),
            "a section `optokens` by its label, its id opaque, holds the name"
        );
        assert!(
            current(&with_sections(json!({ "id": META }), &name_fields), &name),
            "a section `optokens` by its id alone holds the name"
        );
        let elsewhere = json!({ "id": VALUES, "label": VALUES });
        assert!(
            !current(&with_sections(elsewhere, &name_fields), &name),
            "Fields `service` and `account` among the values are no name, whatever else the section `optokens` holds"
        );
    }

    #[test]
    fn candidates_are_the_tagged_items_of_either_title_and_a_stranger_is_refused() {
        let name = Name::new("aws", "ci").unwrap();
        let item =
            |id: &str, title: &str, tags: Value| json!({ "id": id, "title": title, "tags": tags });
        let list = json!([
            item("1", "aws.ci", json!(["optokens"])),
            item("2", "gh", json!(["optokens"])),
            item("3", "aws/ci", json!(["optokens", "x"])),
            item("5", "aws", json!(["optokens"]))
        ]);
        assert_eq!(candidates(&list, &name).unwrap(), ["1", "3"]);
        assert!(candidates(&json!([]), &name).unwrap().is_empty());
        for title in ["aws.ci", "aws/ci"] {
            let stranger = json!([item("3", title, Value::Null)]);
            assert_eq!(
                candidates(&stranger, &name).unwrap_err().kind,
                Some("not_optokens")
            );
        }
        assert!(unique(&name, &["1"]).is_ok());
        let refused = unique(&name, &["1", "4"]).unwrap_err();
        assert_eq!(refused.kind, Some("ambiguous"));
        assert_eq!(
            refused.fault,
            "the vault has 2 items of the Secret `aws/ci` tagged `optokens`: 1, 4"
        );
        let mixed = json!([
            item("9", "z/default", json!(["optokens"])),
            item("8", "other", json!([])),
            item("7", "a/default", json!(["optokens"]))
        ]);
        assert_eq!(ours(&mixed), ["9", "7"]);
    }

    fn any_secret() -> impl Strategy<Value = (Name, Secret)> {
        let label = "[^/]{1,8}";
        (
            "[a-z0-9.-]{1,8}",
            "[a-z0-9.-]{1,8}",
            prop_oneof![Just(Kind::Static), Just(Kind::Profile)],
            proptest::option::of(".{1,12}"),
            proptest::option::of(
                proptest::collection::btree_map(
                    ".{0,6}",
                    prop_oneof![
                        any::<i64>().prop_map(Value::from),
                        ".{0,8}".prop_map(Value::from),
                        proptest::collection::vec(any::<bool>(), 0..3).prop_map(Value::from),
                    ],
                    0..4,
                )
                .prop_map(|m| m.into_iter().collect::<Map<String, Value>>()),
            ),
            prop_oneof![
                ".{0,12}".prop_map(Values::Single),
                proptest::collection::btree_map(
                    label,
                    (".{0,12}", prop_oneof![Just(Plain), Just(Concealed)]),
                    1..5
                )
                .prop_map(|m| Values::Fields(
                    m.into_iter()
                        .rev()
                        .map(|(l, (v, vis))| Field::new(&l, &v, vis))
                        .collect()
                )),
            ],
        )
            .prop_map(|(service, account, kind, description, meta, values)| {
                (
                    Name::new(&service, &account).unwrap(),
                    Secret {
                        kind,
                        description,
                        meta,
                        values,
                    },
                )
            })
    }

    proptest! {
        #[test]
        fn any_secret_laid_out_and_read_back_is_equal((name, secret) in any_secret()) {
            prop_assert_eq!(read(&stored(&template(&name, &secret, None))).unwrap(), (name.clone(), secret.clone()));
            prop_assert_eq!(read(&old(&name, &secret)).unwrap(), (name, secret));
        }
    }
}
