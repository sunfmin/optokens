//! A stand-in for 1Password's Core, for the tests of the real binary: built
//! only without `--release`, and used only when `OPTOKENS_STANDIN_STATE`
//! names its state file. It answers the Core's calls as Core v0.4.1 does
//! (opcore's own stand-in, `tests/stand`, is its model), on a vault kept in
//! that file, which the tailscale stand-in (`examples/standin.rs`) shares:
//!
//! - `core.items`: the vault's items, as the Core answers them;
//! - `core.vaults`: the titles `VaultsList` answers (default `optokens`);
//! - `core.token`: the one token it signs in (default any);
//! - `core.fail`: `{ "<Method>": "<message>" }`, the Core's error for that call;
//! - `core.garble_writes`: a create answers its item with the values of its
//!   section `fields` emptied;
//! - `core.hang_ms`: each item call waits this long before it answers;
//! - `calls`: every call, `{ "program": "core", "method", "ids", "seen" }`, where
//!   `seen` is what any process could see then: every command line (`ps`)
//!   and every file under `TMPDIR`.
//!
//! As the real Core does, it answers an item's fields sorted by id, a field
//! in no section with the section id `""`, and that unnamed section.
use opcore::core::{Core, Failure};
use opcore::{Item, ItemParams};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// The environment variable that names the state file.
pub const STATE: &str = "OPTOKENS_STANDIN_STATE";

pub struct Standin {
    path: PathBuf,
}

impl Standin {
    /// The stand-in, when `STATE` names its file.
    pub fn from_env() -> Option<Standin> {
        std::env::var_os(STATE).map(|p| Standin { path: p.into() })
    }

    fn load(&self) -> Value {
        let text = std::fs::read_to_string(&self.path).expect("the stand-in's state");
        serde_json::from_str(&text).expect("the stand-in's state is JSON")
    }

    fn save(&self, state: &Value) {
        std::fs::write(&self.path, serde_json::to_string_pretty(state).unwrap()).unwrap();
    }

    /// Records the call `method` (with the ids it names, `ids`), and answers
    /// the error injected for it.
    fn record(&self, state: &mut Value, method: &str, ids: &Value) -> Result<(), Failure> {
        let call = json!({ "program": "core", "method": method, "ids": ids, "seen": seen() });
        match state["calls"].as_array_mut() {
            Some(calls) => calls.push(call),
            None => state["calls"] = json!([call]),
        }
        match state["core"]["fail"][method].as_str() {
            Some(message) => Err(error("Unknown", message)),
            None => Ok(()),
        }
    }
}

fn error(name: &str, message: &str) -> Failure {
    Failure::Error(json!({ "name": name, "message": message }).to_string())
}

impl Core for Standin {
    fn init_client(&mut self, config: &str) -> Result<String, Failure> {
        let mut state = self.load();
        let recorded = self.record(&mut state, "init_client", &Value::Null);
        self.save(&state);
        recorded?;
        let config: Value = serde_json::from_str(config).unwrap();
        let given = &config["serviceAccountToken"];
        if let Some(token) = state["core"]["token"].as_str()
            && given != token
        {
            return Err(error("Unauthorized", "invalid service account token"));
        }
        Ok("7".into())
    }

    fn invoke(&mut self, invocation: &str) -> Result<String, Failure> {
        let inv: Value = serde_json::from_str(invocation).unwrap();
        let method = inv["invocation"]["parameters"]["name"]
            .as_str()
            .unwrap()
            .to_string();
        let p = &inv["invocation"]["parameters"]["parameters"];
        let mut state = self.load();
        let recorded = self.record(&mut state, &method, &p["item_ids"]);
        let answer = recorded.map(|()| answer(&mut state, &method, p));
        self.save(&state);
        if let Some(ms) = state["core"]["hang_ms"].as_u64() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
        answer.map(|a| a.to_string())
    }

    fn release_client(&mut self, _id: &str) {}
}

/// The answer to `method` called with `p`, on the vault in `state`.
fn answer(state: &mut Value, method: &str, p: &Value) -> Value {
    if method == "VaultsList" {
        let titles = state["core"]["vaults"].as_array().cloned();
        let titles = titles.unwrap_or_else(|| vec![json!("optokens")]);
        return titles
            .iter()
            .enumerate()
            .map(|(i, t)| json!({ "id": format!("v{i}"), "title": t }))
            .collect();
    }
    if !state["core"]["items"].is_array() {
        state["core"]["items"] = json!([]);
    }
    let garble = state["core"]["garble_writes"] == true;
    let next = state["core"]["next_id"].as_u64().unwrap_or(1);
    let items = state["core"]["items"].as_array_mut().unwrap();
    let ids = || -> Vec<String> {
        p["item_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_str().unwrap().to_string())
            .collect()
    };
    match method {
        "ItemsList" => items
            .iter()
            .filter(|i| i["vaultId"] == p["vault_id"])
            .map(|i| {
                json!({ "id": i["id"], "title": i["title"], "category": i["category"],
                        "vaultId": i["vaultId"], "websites": [], "tags": i["tags"],
                        "createdAt": i["createdAt"], "updatedAt": i["updatedAt"], "state": "active" })
            })
            .collect(),
        "ItemsGetAll" => {
            let each: Vec<Value> = ids()
                .iter()
                .map(|id| match items.iter().find(|i| i["id"] == id.as_str()) {
                    Some(i) => json!({ "content": i }),
                    None => json!({ "error": { "type": "itemNotFound" } }),
                })
                .collect();
            json!({ "individualResponses": each })
        }
        "ItemsCreateAll" => {
            let mut each = Vec::new();
            for (n, given) in p["params"].as_array().unwrap().iter().enumerate() {
                let params: ItemParams = params(given);
                let id = format!("{:0>26}", next + n as u64);
                let vault = given["vaultId"].as_str().unwrap_or_default();
                let item = serde_json::to_value(keep(&params, &id, vault, 1)).unwrap();
                items.push(item.clone());
                let mut answered = item;
                if garble {
                    for f in answered["fields"].as_array_mut().unwrap() {
                        if f["sectionId"] == "fields" {
                            f["value"] = json!("");
                        }
                    }
                }
                each.push(json!({ "content": answered }));
            }
            state["core"]["next_id"] = json!(next + each.len() as u64);
            json!({ "individualResponses": each })
        }
        "ItemsPut" => {
            let mut put: Item = serde_json::from_value(p["item"].clone()).unwrap();
            let at = items.iter().position(|i| i["id"] == put.id.as_str());
            let at = at.expect("a Put names an item of the vault");
            assert_eq!(
                items[at]["version"], put.version,
                "a Put names the version it replaces"
            );
            put.version += 1;
            put.updated_at = format!("t{}", put.version);
            sort(&mut put);
            items[at] = serde_json::to_value(&put).unwrap();
            items[at].clone()
        }
        "ItemsDeleteAll" => {
            let ids = ids();
            items.retain(|i| !ids.iter().any(|id| i["id"] == id.as_str()));
            let each: serde_json::Map<String, Value> = ids
                .into_iter()
                .map(|id| (id, json!({ "content": {} })))
                .collect();
            json!({ "individualResponses": each })
        }
        other => panic!("the stand-in has no {other}"),
    }
}

/// `ItemParams` as the Core reads them; it serializes only.
fn params(given: &Value) -> ItemParams {
    let mut given = given.clone();
    for (key, empty) in [
        ("fields", json!([])),
        ("sections", json!([])),
        ("tags", json!([])),
        ("notes", json!("")),
    ] {
        if given.get(key).is_none() {
            given[key] = empty;
        }
    }
    let item: Item = serde_json::from_value(json!({
        "id": "", "title": given["title"], "category": given["category"], "vaultId": "",
        "version": 0, "tags": given["tags"], "notes": given["notes"],
        "fields": given["fields"], "sections": given["sections"],
        "createdAt": "", "updatedAt": "",
    }))
    .unwrap();
    ItemParams {
        category: item.category,
        title: item.title,
        fields: item.fields,
        sections: item.sections,
        notes: item.notes,
        tags: item.tags,
    }
}

/// The item the Core keeps of `params`, made as `id` at `version` in `vault`.
pub fn keep(params: &ItemParams, id: &str, vault: &str, version: u32) -> Item {
    let mut item = Item {
        id: id.into(),
        title: params.title.clone(),
        category: params.category,
        vault_id: vault.into(),
        version,
        tags: params.tags.clone(),
        notes: params.notes.clone(),
        fields: params.fields.clone(),
        sections: params.sections.clone(),
        created_at: "t".into(),
        updated_at: format!("t{version}"),
        ..Default::default()
    };
    sort(&mut item);
    item
}

/// As the Core answers an item: its fields by id, each in no section with
/// the section `""`, and that unnamed section among its sections.
fn sort(item: &mut Item) {
    item.fields.sort_by(|a, b| a.id.cmp(&b.id));
    for f in &mut item.fields {
        f.section_id.get_or_insert_with(String::new);
    }
    if !item.sections.iter().any(|s| s.id.is_empty()) {
        item.sections.push(opcore::ItemSection::default());
    }
}

/// Every process's command line, and every file under `TMPDIR` with what it holds.
fn seen() -> Value {
    let ps = std::process::Command::new("/bin/ps")
        .args(["-A", "-ww", "-o", "args="])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_else(|e| format!("ps failed: {e}"));
    let mut files = Vec::new();
    if let Some(tmp) = std::env::var_os("TMPDIR") {
        walk(Path::new(&tmp), &mut files);
    }
    json!({ "ps": ps, "tmp": files })
}

fn walk(dir: &Path, files: &mut Vec<Value>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, files);
        } else {
            let text = std::fs::read(&path).map(|b| String::from_utf8_lossy(&b).into_owned());
            files.push(json!({ "path": path, "text": text.unwrap_or_default() }));
        }
    }
}
