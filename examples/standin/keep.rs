//! What `op` keeps of an item template it is handed: shared by the stand-in
//! and the layout's round-trip tests, so both see the item as `op` stores it.

use serde_json::{Value, json};

/// The item `op` keeps of a template: its id and vault given, the category's
/// notes field added, each field's section named by its label, and an empty
/// value left out.
pub fn keep(template: &Value, id: &str, vault: &str) -> Value {
    let mut item = template.clone();
    item["id"] = json!(id);
    item["vault"] = json!({ "id": format!("v-{vault}"), "name": vault });
    let labels: serde_json::Map<String, Value> = template["sections"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| (s["id"].as_str().unwrap().to_string(), s["label"].clone()))
        .collect();
    let mut fields = vec![
        json!({ "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain" }),
    ];
    for f in template["fields"].as_array().into_iter().flatten() {
        let mut f = f.clone();
        if let Some(section) = f["section"]["id"].as_str() {
            f["section"] = json!({ "id": section, "label": labels[section] });
        }
        if f["value"] == "" {
            f.as_object_mut().unwrap().remove("value");
        }
        fields.push(f);
    }
    item["fields"] = json!(fields);
    item
}
