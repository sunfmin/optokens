//! What each command spends of the service account's Budget, on the
//! stand-in Core: each scenario asserts its Core calls and its reads,
//! writes and account requests, and `docs/budget.md` is the table of them
//! all, which this test fails on when it is stale.
#![cfg(unix)]

mod common;

use common::budget::Budget;
use common::{Host, first_synced, synced};
use serde_json::{Value, json};
use std::path::Path;

const TOKEN: (&str, &str) = ("OP_SERVICE_ACCOUNT_TOKEN", "ops_test_token");
/// A Copy past its Life at once.
const STALE: (&str, &str) = ("OPTOKENS_TEST_COPY_LIFE_MS", "0");
const FILE: &str = "docs/budget.md";

struct Row {
    command: &'static str,
    calls: Vec<String>,
    spent: Budget,
}

/// Runs `args` on `host` (with `env` besides the token), asserts it exits
/// 0, called `calls` and spent `spent`, and answers its row.
fn row(
    host: &Host,
    command: &'static str,
    args: &[&str],
    env: &[(&str, &str)],
    calls: Vec<String>,
    spent: Budget,
) -> Row {
    host.forget_calls();
    let ran = host.run(args, &[&[TOKEN][..], env].concat(), None);
    assert_eq!(ran.code, 0, "{command}: {} {}", ran.stdout, ran.stderr);
    let made = Row {
        command,
        calls: host.core_calls(),
        spent: host.budget(),
    };
    assert_eq!(made.calls, calls, "{command}");
    assert_eq!(made.spent, spent, "{command}");
    made
}

fn fail(host: &Host, fail: Value) {
    let mut state = host.state();
    state["core"]["fail"] = fail;
    host.set_state(&state);
}

/// Every command's scenarios, in the order they run on two hosts.
fn rows() -> Vec<Row> {
    let [create, edit, delete] = [
        synced(&["ItemsCreateAll"]),
        synced(&["ItemsGetAll", "ItemsPut"]),
        synced(&["ItemsDeleteAll"]),
    ];
    let host = Host::new(&[], json!({ "core": {} }));
    let mut rows = vec![
        row(
            &host,
            "`list`, the first Sync on a new host",
            &["list"],
            &[],
            first_synced(&[]),
            Budget::new(2, 0, 1),
        ),
        row(
            &host,
            "`put` of a new Secret",
            &["put", "db", "--set", "A=1"],
            &[],
            create.clone(),
            Budget::new(2, 1, 1),
        ),
        row(
            &host,
            "`put` of what the Secret holds",
            &["put", "db", "--set", "A=1"],
            &[],
            synced(&[]),
            Budget::new(1, 0, 1),
        ),
        row(
            &host,
            "`put` of a changed Field",
            &["put", "db", "--set", "A=2"],
            &[],
            edit.clone(),
            Budget::new(3, 1, 1),
        ),
    ];
    for (command, args) in [
        ("`list` within the Copy's Life", &["list"][..]),
        (
            "`get` within the Copy's Life",
            &["get", "db", "--field", "A"],
        ),
        ("`env` within the Copy's Life", &["env", "db"]),
    ] {
        rows.push(row(&host, command, args, &[], vec![], Budget::default()));
    }
    for (command, args) in [
        (
            "`list` past the Copy's Life, nothing changed",
            &["list"][..],
        ),
        (
            "`get` past the Copy's Life, nothing changed",
            &["get", "db", "--field", "A"],
        ),
        (
            "`env` past the Copy's Life, nothing changed",
            &["env", "db"],
        ),
    ] {
        rows.push(row(
            &host,
            command,
            args,
            &[STALE],
            synced(&[]),
            Budget::new(1, 0, 1),
        ));
    }
    host.change("db", "A", "3");
    rows.push(row(
        &host,
        "`get --fresh`, the Secret changed on another host",
        &["get", "db", "--field", "A", "--fresh"],
        &[],
        synced(&["ItemsGetAll"]),
        Budget::new(1, 0, 1),
    ));
    rows.push(row(
        &host,
        "`mv`",
        &["mv", "db", "web"],
        &[],
        edit.clone(),
        Budget::new(3, 1, 1),
    ));
    fail(
        &host,
        json!({ "ItemsPut": { "name": "RateLimitExceeded", "message": "rate limit exceeded" } }),
    );
    rows.push(row(
        &host,
        "`put` of a changed Field while 1Password refuses writes (it waits)",
        &["put", "web", "--set", "A=4"],
        &[],
        edit.clone(),
        Budget::new(1, 0, 1),
    ));
    fail(&host, Value::Null);
    rows.push(row(
        &host,
        "`list --fresh` that pushes that waiting write",
        &["list", "--fresh"],
        &[],
        synced(&["ItemsPut"]),
        Budget::new(3, 1, 1),
    ));
    rows.push(row(
        &host,
        "`rm`",
        &["rm", "web"],
        &[],
        delete,
        Budget::new(2, 1, 1),
    ));
    rows.push(row(
        &host,
        "`doctor`",
        &["doctor"],
        &[],
        vec![],
        Budget::default(),
    ));
    let new = Host::new(&[], json!({ "core": {} }));
    rows.push(row(
        &new,
        "`put` of a new Secret, the first Sync on a new host",
        &["put", "db", "--set", "A=1"],
        &[],
        first_synced(&["ItemsCreateAll"]),
        Budget::new(3, 1, 1),
    ));
    rows
}

/// The calls in order, a run of one method as one entry with its count.
fn calls(calls: &[String]) -> String {
    let mut runs: Vec<(&str, usize)> = Vec::new();
    for c in calls {
        match runs.last_mut() {
            Some((m, n)) if m == c => *n += 1,
            _ => runs.push((c, 1)),
        }
    }
    if runs.is_empty() {
        return "none".into();
    }
    let run = |(m, n): &(&str, usize)| match n {
        1 => format!("`{m}`"),
        n => format!("`{m}` ×{n}"),
    };
    runs.iter().map(run).collect::<Vec<_>>().join(", ")
}

fn table(rows: &[Row]) -> String {
    let mut t = String::from(
        "# Budget per command\n\n\
         Generated by `tests/budget.rs`, which fails when this file differs from \
         what its scenarios spend on the stand-in Core; \
         `UPDATE_BUDGET=1 cargo test --test budget` rewrites it. Each method's cost \
         is opcore's decision record 1, in the opcore source `Cargo.lock` pins, read \
         by `tests/common/budget.rs`. Each command is a new process: its first vault \
         call after signing in spends one read and one of the account's daily \
         requests more. A call 1Password refuses spends nothing.\n\n\
         | Command | Core calls | Reads | Writes | Account requests |\n\
         |---|---|---|---|---|\n",
    );
    for r in rows {
        t.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            r.command,
            calls(&r.calls),
            r.spent.reads,
            r.spent.writes,
            r.spent.account
        ));
    }
    t
}

#[test]
fn docs_budget_md_is_what_each_command_spends() {
    let made = table(&rows());
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FILE);
    if std::env::var_os("UPDATE_BUDGET").is_some() {
        std::fs::write(&path, &made).unwrap();
    }
    let kept = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        kept == made,
        "{FILE} is not what the commands spend: run `UPDATE_BUDGET=1 cargo test --test budget` \
         and commit it.\n--- {FILE}\n{kept}\n--- the scenarios\n{made}"
    );
}
