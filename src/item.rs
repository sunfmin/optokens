//! How a Secret is laid out as an item of the vault, and read back: pure,
//! on opcore's structs (the 1Password SDK's model, `opcore::item`, which
//! says how each reads in `op`).
//!
//! One Secret is one item, titled as [`Name::title`] says and tagged
//! [`TAG`]. Its values are the fields of the section [`VALUES`], each titled
//! with its Field's label ([`SINGLE`] for a single value) and typed by its
//! visibility (`Concealed` or `Text`, `op`'s [`CONCEALED`] and [`STRING`]);
//! its service, account, kind, shape and Meta (compact JSON, [`META_FIELD`])
//! are the fields of the section [`META`]; its Description is the item's
//! notes, what 1Password shows under the title in its list. The name is read
//! from that section, never from the title; an item an earlier optokens
//! wrote, titled `<service>/<account>` without them, is read by its title. An
//! item that is not this shape is refused by name, never guessed at; its
//! other tags, sections and fields are another program's, read past and kept
//! by [`template`] over the stored item. Items `op`, mytokens and optokens
//! wrote read the same.

use crate::refusal::Refusal;
use crate::secret::Visibility::{Concealed, Plain};
use crate::secret::{Fault, Field, Kind, Name, Secret, Values};
use opcore::{Category, FieldType, Item, ItemField, ItemParams, ItemSection, Listed};
use serde_json::Value;

/// The tag on every item optokens writes.
pub const TAG: &str = "optokens";
/// The item's category: one with no fields of its own to fill.
pub const CATEGORY: Category = Category::SecureNote;
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
/// The field types as `op` and 1Password's own apps name them: a concealed
/// value, shown like a password (`FieldType::Concealed`), and plain text
/// (`FieldType::Text`).
pub const CONCEALED: &str = "CONCEALED";
pub const STRING: &str = "STRING";

/// The item a `put` writes, made or edited: over `stored`, the item as the
/// vault holds it, it keeps what optokens does not own (every tag, section
/// and field beside [`TAG`], [`VALUES`] and [`META`]), as an edit replaces
/// the item's tags, sections, fields and notes whole.
pub fn template(name: &Name, secret: &Secret, stored: Option<&Item>) -> ItemParams {
    let field = |section: &str, id: String, visibility, label: &str, value: &str| ItemField {
        id,
        title: label.into(),
        section_id: Some(section.into()),
        field_type: match visibility {
            Plain => FieldType::Text,
            Concealed => FieldType::Concealed,
        },
        value: value.into(),
        ..Default::default()
    };
    let single;
    let (shape, values) = match &secret.values {
        Values::Single(value) => {
            single = [Field::new(SINGLE, value, Concealed)];
            (SHAPE_SINGLE, &single[..])
        }
        Values::Fields(fields) => (SHAPE_FIELDS, &fields[..]),
    };
    let mut fields: Vec<ItemField> = values
        .iter()
        .enumerate()
        .map(|(i, f)| field(VALUES, value_id(i), f.visibility, &f.label, &f.value))
        .collect();
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
    let mut tags = vec![TAG.to_string()];
    let section = |id: &str| ItemSection {
        id: id.into(),
        title: id.into(),
    };
    let mut sections = vec![section(VALUES), section(META)];
    if let Some(stored) = stored {
        tags.extend(stored.tags.iter().filter(|t| *t != TAG).cloned());
        let ours = |s: Option<&str>| s.is_some_and(|s| [VALUES, META].contains(&s));
        // 1Password's unnamed section (id `""`) is its own: it adds it again.
        sections.extend(
            stored
                .sections
                .iter()
                .filter(|s| !s.id.is_empty() && !ours(Some(label(s))))
                .cloned(),
        );
        fields.extend(
            stored
                .fields
                .iter()
                .filter(|f| !ours(section_of(f, stored)))
                .cloned(),
        );
    }
    ItemParams {
        category: CATEGORY,
        title: name.title(),
        fields,
        sections,
        notes: secret.description.clone().unwrap_or_default(),
        tags,
    }
}

/// The id of the `i`th value's field. The Core answers fields sorted by id,
/// so [`read`] puts them back in this order by `i`.
fn value_id(i: usize) -> String {
    format!("{VALUES}.{i}")
}

/// A section's name: its title, or its id when it has none (as `op` names
/// a field's section by either).
fn label(section: &ItemSection) -> &str {
    if section.title.is_empty() {
        &section.id
    } else {
        &section.title
    }
}

/// The name of `field`'s section in `item`; `None` for a field in none.
fn section_of<'a>(field: &'a ItemField, item: &'a Item) -> Option<&'a str> {
    let id = field.section_id.as_deref().filter(|id| !id.is_empty())?;
    Some(item.sections.iter().find(|s| s.id == id).map_or(id, label))
}

/// The refusal of the item `title`, which is not optokens' layout, `why`.
fn not_optokens(title: &str, why: &str) -> Refusal {
    Refusal::of(
        &Fault::NotOptokens,
        format!("the vault's item `{title}` is not a Secret optokens wrote: {why}"),
        format!(
            "rename or move the item `{title}` in 1Password, or delete it there if it is one optokens wrote and then changed"
        ),
    )
}

/// The Secret an item holds. Refused, naming the item, when it is not
/// optokens' layout.
pub fn read(item: &Item) -> Result<(Name, Secret), Refusal> {
    layout(item).map_err(|why| not_optokens(&item.title, &why))
}

fn layout(item: &Item) -> Result<(Name, Secret), String> {
    if !item.tags.iter().any(|t| t == TAG) {
        return Err(format!("it has no tag `{TAG}`"));
    }
    let (mut values, mut meta) = (Vec::new(), Vec::new());
    for field in &item.fields {
        // The category's own fields, and a section another program keeps
        // (mytokens'), are never optokens': read past, kept by a `put`.
        let label = field.title.clone();
        match section_of(field, item) {
            Some(VALUES) => {
                let visibility = match field.field_type {
                    FieldType::Concealed => Concealed,
                    FieldType::Text => Plain,
                    other => {
                        return Err(format!(
                            "its field `{label}` in section `{VALUES}` is of type {other:?}, neither `{CONCEALED}` nor `{STRING}`"
                        ));
                    }
                };
                values.push((&field.id, Field::new(&label, &field.value, visibility)))
            }
            Some(META) => meta.push((label, field.value.clone())),
            _ => {}
        }
    }
    // In the order they were written, which the Core's (by id) is not past
    // ten; fields another program wrote without optokens' ids keep its order.
    let index = |id: &str| {
        id.strip_prefix(&format!("{VALUES}."))?
            .parse::<usize>()
            .ok()
    };
    if values.iter().all(|(id, _)| index(id).is_some()) {
        values.sort_by_key(|(id, _)| index(id));
    }
    let values: Vec<Field> = values.into_iter().map(|(_, f)| f).collect();
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
        (None, None) => Name::from_old_title(&item.title).ok_or(format!(
            "its section `{META}` has no `{SERVICE}` and `{ACCOUNT}`, and its title is not `<service>/<account>`"
        ))?,
        _ => return Err(format!("its section `{META}` has one of `{SERVICE}` and `{ACCOUNT}` without the other")),
    };
    let kind = one(KIND)?.ok_or(format!("its section `{META}` has no `{KIND}`"))?;
    let kind = <Kind as clap::ValueEnum>::from_str(&kind, false)
        .map_err(|_| format!("its `{KIND}` is `{kind}`, neither static nor profile"))?;
    // An item an earlier layout wrote keeps it in the section: that one is
    // what optokens (or mytokens) last wrote, the notes another program's.
    let notes = Some(item.notes.clone()).filter(|n| !n.is_empty());
    let description = one(DESCRIPTION)?.filter(|d| !d.is_empty()).or(notes);
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

/// The items among `items`, optokens' (tagged [`TAG`]), that may hold
/// `name`'s Secret: those titled [`Name::title`] or its earlier title,
/// `<service>/<account>`. Which one does is for [`read`] to say, as another
/// Secret's title may be the same (`a.b` is `a.b/default` and `a/b`). An item
/// of either title among `others`, the vault's items without the tag, is
/// refused.
pub fn candidates<'a>(
    items: &'a [Item],
    others: &[Listed],
    name: &Name,
) -> Result<Vec<&'a Item>, Refusal> {
    let titles = [name.title(), name.to_string()];
    let titled = |title: &str| titles.iter().any(|t| t == title);
    if let Some(other) = others.iter().find(|o| titled(&o.title)) {
        return Err(not_optokens(
            &other.title,
            &format!("it has no tag `{TAG}`"),
        ));
    }
    Ok(items.iter().filter(|i| titled(&i.title)).collect())
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
pub fn current(item: &Item, name: &Name) -> bool {
    let has = |title: &str| {
        item.fields
            .iter()
            .any(|f| f.title == title && section_of(f, item) == Some(META))
    };
    item.title == name.title() && has(SERVICE) && has(ACCOUNT) && !has(DESCRIPTION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::{Map, json};

    /// The item as the Core keeps it.
    fn stored(template: &ItemParams) -> Item {
        crate::standin::keep(template, "abc123", "v", 1)
    }

    /// The field titled `title`, of the section `section`, in `item`.
    fn field<'a>(item: &'a mut Item, section: &str, title: &str) -> &'a mut ItemField {
        let at = item
            .fields
            .iter()
            .position(|f| f.title == title && f.section_id.as_deref() == Some(section))
            .unwrap_or_else(|| panic!("no field {section}.{title}"));
        &mut item.fields[at]
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
        let f = |section: &str, id: &str, kind: &str, title: &str, value: &str| json!({ "id": id, "title": title, "sectionId": section, "fieldType": kind, "value": value });
        assert_eq!(
            serde_json::to_value(template(&name, &secret, None)).unwrap(),
            json!({
                "title": "aws.ci",
                "category": "SecureNote",
                "tags": ["optokens"],
                "sections": [{ "id": "fields", "title": "fields" }, { "id": "optokens", "title": "optokens" }],
                "notes": "CI deploy",
                "fields": [
                    f("fields", "fields.0", "Text", "Access Key ID", "AKIA"),
                    f("fields", "fields.1", "Concealed", "Secret", "s"),
                    f("optokens", "optokens.service", "Text", "service", "aws"),
                    f("optokens", "optokens.account", "Text", "account", "ci"),
                    f("optokens", "optokens.kind", "Text", "kind", "static"),
                    f("optokens", "optokens.shape", "Text", "shape", "fields"),
                    f("optokens", "optokens.meta", "Text", "meta", r#"{"n":[1],"region":"us-east-1"}"#),
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
    fn eleven_fields_and_more_read_back_in_the_order_they_were_written() {
        let name = Name::new("many", "default").unwrap();
        let labels: Vec<String> = (0..12).map(|i| format!("L{}", 11 - i)).collect();
        let secret = Secret {
            kind: Kind::Profile,
            description: None,
            meta: None,
            values: Values::Fields(labels.iter().map(|l| Field::new(l, l, Plain)).collect()),
        };
        let item = stored(&template(&name, &secret, None));
        assert_eq!(item.fields[0].id, "fields.0");
        assert_eq!(item.fields[2].id, "fields.10", "the Core sorts by id");
        assert_eq!(read(&item).unwrap(), (name, secret));
    }

    #[test]
    fn an_item_not_in_optokens_layout_is_refused_by_name() {
        let (name, secret) = secret();
        let good = stored(&template(&name, &secret, None));
        let why = |edit: &dyn Fn(&mut Item)| {
            let mut item = good.clone();
            edit(&mut item);
            let refused = read(&item).unwrap_err();
            assert_eq!(refused.kind, Some("not_optokens"));
            assert!(
                refused
                    .fix
                    .starts_with(&format!("rename or move the item `{}`", item.title)),
                "{refused:?}"
            );
            refused.fault
        };
        assert_eq!(
            why(&|i| i.tags.clear()),
            "the vault's item `aws.ci` is not a Secret optokens wrote: it has no tag `optokens`"
        );
        assert!(
            why(&|i| field(i, META, KIND).value = "parent".into())
                .ends_with("its `kind` is `parent`, neither static nor profile")
        );
        assert!(
            why(&|i| field(i, META, SHAPE).value = "value".into())
                .ends_with("its section `fields` is not one field `value`")
        );
        let single = Secret {
            kind: Kind::Static,
            description: None,
            meta: None,
            values: Values::Single("v".into()),
        };
        let mut renamed = stored(&template(&name, &single, None));
        field(&mut renamed, VALUES, SINGLE).title = "Token".into();
        assert!(
            read(&renamed)
                .unwrap_err()
                .fault
                .ends_with("its section `fields` is not one field `value`")
        );
        assert!(
            why(&|i| field(i, META, KIND).title = "level".into())
                .ends_with("its section `optokens` has a field `level`")
        );
        assert!(
            why(&|i| field(i, VALUES, "Secret").field_type = FieldType::Url).ends_with(
                "its field `Secret` in section `fields` is of type Url, neither `CONCEALED` nor `STRING`"
            )
        );
        assert!(
            why(&|i| field(i, VALUES, "Secret").title = "Access Key ID".into())
                .ends_with("has the label `Access Key ID` empty or twice")
        );
        assert!(
            why(&|i| i.fields.retain(|f| f.title != ACCOUNT))
                .ends_with("has one of `service` and `account` without the other")
        );
        for data in ["[1]", "{", "\"s\""] {
            assert!(
                why(&|i| field(i, META, META_FIELD).value = data.into())
                    .ends_with("its `meta` is not a JSON object")
            );
        }
        assert!(
            why(&|i| field(i, META, SERVICE).value = "a/b".into())
                .ends_with("its `service` `a/b` and `account` `ci` are not a Secret's name")
        );
    }

    #[test]
    fn a_put_over_an_item_keeps_the_tags_sections_and_fields_optokens_does_not_own() {
        let (name, secret) = secret();
        let mut item = stored(&template(&name, &secret, None));
        item.tags = ["mytokens", "optokens", "mytokens-digest-abc"]
            .map(String::from)
            .to_vec();
        item.sections.push(ItemSection {
            id: "m".into(),
            title: "mytokens".into(),
        });
        let theirs = ItemField {
            id: "m.origin".into(),
            title: "origin".into(),
            section_id: Some("m".into()),
            value: "laptop".into(),
            ..Default::default()
        };
        item.fields.push(theirs.clone());
        assert_eq!(
            read(&item).unwrap(),
            (name.clone(), secret.clone()),
            "a section optokens does not know is read past"
        );
        let over = template(&name, &secret, Some(&item));
        assert_eq!(over.tags, ["optokens", "mytokens", "mytokens-digest-abc"]);
        assert_eq!(
            over.sections[2..],
            [ItemSection {
                id: "m".into(),
                title: "mytokens".into()
            }],
            "1Password's unnamed section is not sent back"
        );
        let fresh = template(&name, &secret, None).fields;
        assert!(over.fields[..fresh.len()] == fresh[..]);
        assert!(over.fields[fresh.len()..] == [theirs]);
        assert_eq!(over.notes, "CI deploy", "the notes are optokens' own");
        assert_eq!(read(&stored(&over)).unwrap(), (name, secret));
    }

    #[test]
    fn a_section_named_by_its_id_or_by_its_title_alone_is_optokens() {
        let (name, secret) = secret();
        let laid = stored(&template(&name, &secret, None));
        let mut untitled = laid.clone();
        for s in &mut untitled.sections {
            s.title.clear();
        }
        let mut opaque = laid.clone();
        for s in opaque.sections.iter_mut().filter(|s| !s.id.is_empty()) {
            s.id = format!("x7k2-{}", s.title);
        }
        for f in &mut opaque.fields {
            if let Some(id) = f.section_id.as_mut().filter(|id| !id.is_empty()) {
                *id = format!("x7k2-{id}");
            }
        }
        for item in [untitled, opaque] {
            assert_eq!(read(&item).unwrap(), (name.clone(), secret.clone()));
            assert!(current(&item, &name));
            assert!(
                template(&name, &secret, Some(&item)) == template(&name, &secret, None),
                "optokens' own fields are rewritten, not kept twice"
            );
        }
    }

    #[test]
    fn the_description_is_the_notes_and_none_is_empty_notes() {
        let (name, secret) = secret();
        let laid = template(&name, &secret, None);
        assert_eq!(laid.notes, "CI deploy");
        assert!(
            !laid.fields.iter().any(|f| f.title == DESCRIPTION),
            "no `description` in the section `optokens`"
        );
        let bare = Secret {
            description: None,
            ..secret.clone()
        };
        assert_eq!(template(&name, &bare, None).notes, "");
        let mut noted = stored(&template(&name, &bare, None));
        noted.notes = "line one\nline two".into();
        assert_eq!(
            read(&noted).unwrap().1.description.as_deref(),
            Some("line one\nline two"),
            "the whole notes, written in 1Password, are the Description"
        );
    }

    /// An item in the layout before the notes: its Description a field
    /// `description` of the section `optokens`, its notes `notes`.
    fn sectioned(name: &Name, secret: &Secret, notes: &str) -> Item {
        let mut item = stored(&template(name, secret, None));
        item.notes = notes.into();
        if let Some(d) = &secret.description {
            item.fields.push(ItemField {
                id: "optokens.description".into(),
                title: DESCRIPTION.into(),
                section_id: Some(META.into()),
                value: d.clone(),
                ..Default::default()
            });
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
            assert!(over == template(&name, &secret, None));
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
    fn old(name: &Name, secret: &Secret) -> Item {
        let mut item = stored(&template(name, secret, None));
        item.title = name.to_string();
        item.fields.retain(|f| {
            !(f.section_id.as_deref() == Some(META)
                && [SERVICE, ACCOUNT].contains(&f.title.as_str()))
        });
        item
    }

    #[test]
    fn the_name_is_read_from_the_section_never_split_from_the_title() {
        let (_, secret) = secret();
        let dotted = Name::new("name.com", "default").unwrap();
        let item = stored(&template(&dotted, &secret, None));
        assert_eq!(item.title, "name.com");
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
        assert_eq!(item.title, "aws/ci");
        assert_eq!(read(&item).unwrap(), (name.clone(), secret.clone()));
        assert!(!current(&item, &name));
        let mut titled = stored(&template(&name, &secret, None));
        assert!(current(&titled, &name));
        titled.title = "aws/ci".into();
        assert!(
            !current(&titled, &name),
            "an old title with the new section is rewritten"
        );
        let mut untitled = item.clone();
        untitled.title = "aws".into();
        assert!(read(&untitled).unwrap_err().fault.ends_with(
            "its section `optokens` has no `service` and `account`, and its title is not `<service>/<account>`"
        ));
    }

    #[test]
    fn current_reads_the_name_only_from_the_section_optokens() {
        let (name, secret) = secret();
        let mut elsewhere = stored(&template(&name, &secret, None));
        for f in &mut elsewhere.fields {
            if [SERVICE, ACCOUNT].contains(&f.title.as_str()) {
                f.section_id = Some(VALUES.into());
            }
        }
        assert!(
            !current(&elsewhere, &name),
            "Fields `service` and `account` among the values are no name"
        );
    }

    #[test]
    fn candidates_are_the_tagged_items_of_either_title_and_a_stranger_is_refused() {
        let name = Name::new("aws", "ci").unwrap();
        let item = |id: &str, title: &str| Item {
            id: id.into(),
            title: title.into(),
            tags: vec![TAG.into()],
            ..Default::default()
        };
        let items = [
            item("1", "aws.ci"),
            item("2", "gh"),
            item("3", "aws/ci"),
            item("5", "aws"),
        ];
        let ids = |found: Vec<&Item>| found.iter().map(|i| i.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(candidates(&items, &[], &name).unwrap()), ["1", "3"]);
        assert!(candidates(&[], &[], &name).unwrap().is_empty());
        for title in ["aws.ci", "aws/ci"] {
            let stranger = Listed {
                id: "9".into(),
                title: title.into(),
                tags: vec![],
                updated_at: "t".into(),
            };
            assert_eq!(
                candidates(&items, &[stranger], &name).unwrap_err().fault,
                format!(
                    "the vault's item `{title}` is not a Secret optokens wrote: it has no tag `optokens`"
                )
            );
        }
        assert!(unique(&name, &["1"]).is_ok());
        let refused = unique(&name, &["1", "4"]).unwrap_err();
        assert_eq!(refused.kind, Some("ambiguous"));
        assert_eq!(
            refused.fault,
            "the vault has 2 items of the Secret `aws/ci` tagged `optokens`: 1, 4"
        );
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
                    1..14
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
