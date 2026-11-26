//! How a Secret is laid out as an item of the vault, and read back: pure.
//!
//! One Secret is one item, titled `<service>/<account>` and tagged
//! [`TAG`]. Its values are the fields of the section [`VALUES`], each
//! labelled with its Field's label ([`SINGLE`] for a single value); its kind,
//! description and shape are the fields of the section [`META`]. An item
//! that is not this shape is refused by name, never guessed at.

use crate::refusal::Refusal;
use crate::secret::{Fault, Kind, Name, Secret, Values};
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
pub const KIND: &str = "kind";
pub const DESCRIPTION: &str = "description";
pub const SHAPE: &str = "shape";
/// [`SHAPE`]'s values: a single value, or labelled Fields.
pub const SHAPE_SINGLE: &str = "value";
pub const SHAPE_FIELDS: &str = "fields";
/// The label of a single value's one field in [`VALUES`].
pub const SINGLE: &str = "value";

/// The item template that `op item create` and `op item edit` read on stdin.
pub fn template(name: &Name, secret: &Secret) -> Value {
    let field = |section: &str, id: String, kind: &str, label: &str, value: &str| json!({ "id": id, "section": { "id": section }, "type": kind, "label": label, "value": value });
    let (shape, values) = match &secret.values {
        Values::Single(value) => (SHAPE_SINGLE, vec![(SINGLE, value.as_str())]),
        Values::Fields(fields) => (
            SHAPE_FIELDS,
            fields
                .iter()
                .map(|(l, v)| (l.as_str(), v.as_str()))
                .collect(),
        ),
    };
    let mut fields: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(i, (l, v))| field(VALUES, format!("{VALUES}.{i}"), "CONCEALED", l, v))
        .collect();
    let meta = [
        Some((KIND, secret.kind.name())),
        Some((SHAPE, shape)),
        secret.description.as_deref().map(|d| (DESCRIPTION, d)),
    ];
    fields.extend(
        meta.into_iter()
            .flatten()
            .map(|(l, v)| field(META, format!("{META}.{l}"), "STRING", l, v)),
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
    let name = Name::from_title(title).ok_or("its title is not `<service>/<account>`")?;
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
            VALUES => values.push((label, value)),
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
        .find(|(l, _)| ![KIND, SHAPE, DESCRIPTION].contains(&l.as_str()))
    {
        return Err(format!("its section `{META}` has a field `{stray}`"));
    }
    let kind = one(KIND)?.ok_or(format!("its section `{META}` has no `{KIND}`"))?;
    let kind = Kind::parse(&kind).ok_or(format!(
        "its `{KIND}` is `{kind}`, neither static nor profile"
    ))?;
    let description = one(DESCRIPTION)?;
    let values = match one(SHAPE)?.as_deref() {
        Some(SHAPE_SINGLE) => match values.as_slice() {
            [(label, value)] if label == SINGLE => Values::Single(value.clone()),
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
            for (i, (label, _)) in values.iter().enumerate() {
                if label.is_empty() || values[..i].iter().any(|(l, _)| l == label) {
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

/// The id of `name`'s item among `op item list --format json`'s summaries:
/// `None` when there is none. An item of that title without the tag, or two
/// with it, are refused.
pub fn find(summaries: &Value, name: &Name) -> Result<Option<String>, Refusal> {
    let title = name.title();
    let mut ours = Vec::new();
    for item in summaries.as_array().into_iter().flatten() {
        if item["title"] != title.as_str() {
            continue;
        }
        if !tagged(item) {
            return Err(read(item).expect_err("an item without the tag is refused"));
        }
        ours.push(item["id"].as_str().unwrap_or_default().to_string());
    }
    match ours.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(id.clone())),
        ids => Err(Refusal::of(
            &Fault::Ambiguous,
            format!(
                "the vault has {} items `{title}` tagged `{TAG}`: {}",
                ids.len(),
                ids.join(", ")
            ),
            format!("delete all but one of the items `{title}` in 1Password"),
        )),
    }
}

/// The ids of the items optokens wrote, by their tag, in title order.
pub fn ours(summaries: &Value) -> Vec<String> {
    let mut items: Vec<&Value> = summaries
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| tagged(item))
        .collect();
    items.sort_by_key(|item| item["title"].as_str().unwrap_or_default().to_string());
    items
        .iter()
        .map(|item| item["id"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The item as `op` keeps it: ids given, the category's notes field
    /// added, sections named in each field, and an empty value left out.
    fn stored(template: &Value) -> Value {
        let mut item = template.clone();
        item["id"] = json!("abc123");
        item["vault"] = json!({ "id": "v1", "name": "optokens" });
        let mut fields = vec![
            json!({ "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain" }),
        ];
        for f in template["fields"].as_array().unwrap() {
            let mut f = f.clone();
            let id = f["section"]["id"].clone();
            f["section"] = json!({ "id": id, "label": id });
            if f["value"] == "" {
                f.as_object_mut().unwrap().remove("value");
            }
            fields.push(f);
        }
        item["fields"] = json!(fields);
        item
    }

    fn secret() -> (Name, Secret) {
        (
            Name::new("aws", "ci").unwrap(),
            Secret {
                kind: Kind::Static,
                description: Some("CI deploy".into()),
                values: Values::Fields(vec![
                    ("Access Key ID".into(), "AKIA".into()),
                    ("Secret".into(), "s".into()),
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
                "title": "aws/ci",
                "category": "SECURE_NOTE",
                "tags": ["optokens"],
                "sections": [{ "id": "fields", "label": "fields" }, { "id": "optokens", "label": "optokens" }],
                "fields": [
                    { "id": "fields.0", "section": { "id": "fields" }, "type": "CONCEALED", "label": "Access Key ID", "value": "AKIA" },
                    { "id": "fields.1", "section": { "id": "fields" }, "type": "CONCEALED", "label": "Secret", "value": "s" },
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
                ("kind".into(), "x".into()),
                ("description".into(), "y".into()),
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
            "the vault's item `aws/ci` is not a Secret optokens wrote: it has no tag `optokens`"
        );
        assert!(
            why(&|i| i["fields"][3]["value"] = json!("parent"))
                .ends_with("its `kind` is `parent`, neither static nor profile")
        );
        assert!(
            why(&|i| i["fields"][4]["value"] = json!("value"))
                .ends_with("its section `fields` is not one field `value`")
        );
        assert!(
            why(&|i| i["fields"][3]["label"] = json!("level"))
                .ends_with("its section `optokens` has a field `level`")
        );
        assert!(
            why(&|i| i["fields"][1]["section"] = json!({ "id": "x", "label": "other" }))
                .ends_with("it has a section `other`")
        );
        assert!(
            why(&|i| i["fields"][2]["label"] = json!("Access Key ID"))
                .ends_with("has the label `Access Key ID` empty or twice")
        );
        assert!(
            why(&|i| i["title"] = json!("aws")).ends_with("its title is not `<service>/<account>`")
        );
    }

    #[test]
    fn find_takes_the_one_tagged_item_and_refuses_a_stranger_or_two() {
        let name = Name::new("aws", "ci").unwrap();
        let item =
            |id: &str, title: &str, tags: Value| json!({ "id": id, "title": title, "tags": tags });
        let list = json!([
            item("1", "aws/ci", json!(["optokens"])),
            item("2", "gh/default", json!(["optokens"]))
        ]);
        assert_eq!(find(&list, &name).unwrap(), Some("1".into()));
        assert_eq!(find(&json!([]), &name).unwrap(), None);
        let stranger = json!([item("3", "aws/ci", Value::Null)]);
        assert_eq!(
            find(&stranger, &name).unwrap_err().kind,
            Some("not_optokens")
        );
        let two = json!([
            item("1", "aws/ci", json!(["optokens"])),
            item("4", "aws/ci", json!(["optokens", "x"]))
        ]);
        let refused = find(&two, &name).unwrap_err();
        assert_eq!(
            refused.fault,
            "the vault has 2 items `aws/ci` tagged `optokens`: 1, 4"
        );
        let mixed = json!([
            item("9", "z/default", json!(["optokens"])),
            item("8", "other", json!([])),
            item("7", "a/default", json!(["optokens"]))
        ]);
        assert_eq!(ours(&mixed), ["7", "9"]);
    }

    fn any_secret() -> impl Strategy<Value = (Name, Secret)> {
        let label = "[^/]{1,8}";
        (
            "[a-z0-9-]{1,8}",
            "[a-z0-9-]{1,8}",
            prop_oneof![Just(Kind::Static), Just(Kind::Profile)],
            proptest::option::of(".{0,12}"),
            prop_oneof![
                ".{0,12}".prop_map(Values::Single),
                proptest::collection::btree_map(label, ".{0,12}", 1..5)
                    .prop_map(|m| Values::Fields(m.into_iter().rev().collect())),
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
            prop_assert_eq!(read(&stored(&template(&name, &secret))).unwrap(), (name, secret));
        }
    }
}
