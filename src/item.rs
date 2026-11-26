//! How a Secret is laid out as an item of the vault, and read back: pure.
//!
//! One Secret is one item, titled as [`Name::title`] says and tagged
//! [`TAG`]. Its values are the fields of the section [`VALUES`], each
//! labelled with its Field's label ([`SINGLE`] for a single value) and typed
//! by its visibility ([`CONCEALED`] or [`STRING`]); its service, account,
//! kind, description and shape are the fields of the section [`META`]. The
//! name is read from that section, never from the title; an item an earlier
//! optokens wrote, titled `<service>/<account>` without them, is read by its
//! title. An item that is not this shape is refused by name, never guessed at.

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
pub const DESCRIPTION: &str = "description";
pub const SHAPE: &str = "shape";
/// [`SHAPE`]'s values: a single value, or labelled Fields.
pub const SHAPE_SINGLE: &str = "value";
pub const SHAPE_FIELDS: &str = "fields";
/// The label of a single value's one field in [`VALUES`].
pub const SINGLE: &str = "value";
/// The field types: a concealed value, shown like a password, and plain text.
pub const CONCEALED: &str = "CONCEALED";
pub const STRING: &str = "STRING";

/// The item template that `op item create` and `op item edit` read on stdin.
pub fn template(name: &Name, secret: &Secret) -> Value {
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
    let mut fields: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(i, f)| {
            field(
                VALUES,
                format!("{VALUES}.{i}"),
                f.visibility,
                &f.label,
                &f.value,
            )
        })
        .collect();
    let meta = [
        Some((SERVICE, name.service())),
        Some((ACCOUNT, name.account())),
        Some((KIND, secret.kind.name())),
        Some((SHAPE, shape)),
        secret.description.as_deref().map(|d| (DESCRIPTION, d)),
    ];
    fields.extend(
        meta.into_iter()
            .flatten()
            .map(|(l, v)| field(META, format!("{META}.{l}"), Plain, l, v)),
    );
    json!({
        "title": name.title(),
        "category": CATEGORY,
        "tags": [TAG],
        "sections": [{ "id": VALUES, "label": VALUES }, { "id": META, "label": META }],
        "fields": fields,
    })
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
    // A section by its id, as op names it in each field: its label.
    let labels: Map<String, Value> = item["sections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| Some((s["id"].as_str()?.to_string(), s["label"].clone())))
        .collect();
    let (mut values, mut meta) = (Vec::new(), Vec::new());
    for field in item["fields"].as_array().ok_or("it has no fields")? {
        let section = &field["section"];
        if section.is_null() {
            continue; // the category's own fields, never optokens'
        }
        let section = section["label"]
            .as_str()
            .or_else(|| labels.get(section["id"].as_str()?)?.as_str())
            .unwrap_or_default();
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
            other => return Err(format!("it has a section `{other}`")),
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
    if let Some((stray, _)) = meta
        .iter()
        .find(|(l, _)| ![SERVICE, ACCOUNT, KIND, SHAPE, DESCRIPTION].contains(&l.as_str()))
    {
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
    let description = one(DESCRIPTION)?;
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
/// [`Name::old_title`]. Which one does is for [`read`] to say, as another
/// Secret's title may be the same (`a.b` is `a.b/default` and `a/b`). An item
/// of either title without the tag is refused.
pub fn candidates(summaries: &Value, name: &Name) -> Result<Vec<String>, Refusal> {
    let titles = [name.title(), name.old_title()];
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
/// [`Name::title`], its name in [`META`]. `put` rewrites one that is not.
pub fn current(item: &Value, name: &Name) -> bool {
    let has = |label: &str| {
        item["fields"].as_array().into_iter().flatten().any(|f| {
            f["label"] == label && (f["section"]["label"] == META || f["section"]["id"] == META)
        })
    };
    item["title"] == name.title().as_str() && has(SERVICE) && has(ACCOUNT)
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
            template(&name, &secret),
            json!({
                "title": "aws.ci",
                "category": "SECURE_NOTE",
                "tags": ["optokens"],
                "sections": [{ "id": "fields", "label": "fields" }, { "id": "optokens", "label": "optokens" }],
                "fields": [
                    { "id": "fields.0", "section": { "id": "fields" }, "type": "STRING", "label": "Access Key ID", "value": "AKIA" },
                    { "id": "fields.1", "section": { "id": "fields" }, "type": "CONCEALED", "label": "Secret", "value": "s" },
                    { "id": "optokens.service", "section": { "id": "optokens" }, "type": "STRING", "label": "service", "value": "aws" },
                    { "id": "optokens.account", "section": { "id": "optokens" }, "type": "STRING", "label": "account", "value": "ci" },
                    { "id": "optokens.kind", "section": { "id": "optokens" }, "type": "STRING", "label": "kind", "value": "static" },
                    { "id": "optokens.shape", "section": { "id": "optokens" }, "type": "STRING", "label": "shape", "value": "fields" },
                    { "id": "optokens.description", "section": { "id": "optokens" }, "type": "STRING", "label": "description", "value": "CI deploy" },
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
            values: Values::Fields(vec![
                Field::new("kind", "x", Plain),
                Field::new("description", "y", Concealed),
            ]),
        };
        assert_eq!(
            read(&stored(&template(&name, &secret))).unwrap(),
            (name, secret)
        );
    }

    #[test]
    fn an_item_not_in_optokens_layout_is_refused_by_name() {
        let (name, secret) = secret();
        let good = stored(&template(&name, &secret));
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
            values: Values::Single("v".into()),
        };
        let mut renamed = stored(&template(&name, &single));
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
        assert!(
            why(&|i| i["fields"][1]["section"] = json!({ "id": "x", "label": "other" }))
                .ends_with("it has a section `other`")
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
        assert!(
            why(&|i| i["fields"][3]["value"] = json!("a/b"))
                .ends_with("its `service` `a/b` and `account` `ci` are not a Secret's name")
        );
    }

    /// An item as an earlier optokens wrote it: titled `<service>/<account>`,
    /// no name in its section.
    fn old(name: &Name, secret: &Secret) -> Value {
        let mut item = stored(&template(name, secret));
        item["title"] = json!(name.old_title());
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
        let item = stored(&template(&dotted, &secret));
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
        let mut titled = stored(&template(&name, &secret));
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
            proptest::option::of(".{0,12}"),
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
            .prop_map(|(service, account, kind, description, values)| {
                (
                    Name::new(&service, &account).unwrap(),
                    Secret {
                        kind,
                        description,
                        values,
                    },
                )
            })
    }

    proptest! {
        #[test]
        fn any_secret_laid_out_and_read_back_is_equal((name, secret) in any_secret()) {
            prop_assert_eq!(read(&stored(&template(&name, &secret))).unwrap(), (name.clone(), secret.clone()));
            prop_assert_eq!(read(&old(&name, &secret)).unwrap(), (name, secret));
        }
    }
}
