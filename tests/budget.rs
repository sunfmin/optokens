//! What each command spends of the service account's Budget, on the
//! stand-in Core: each scenario asserts its Core calls and its reads and
//! writes, which the account's daily requests count each of, and `docs/budget.md` is the table of them
//! all, which this test fails on when it is stale. Each method's cost is
//! read from opcore's decision record 1, the one home of the numbers, in
//! the opcore source this build compiles (found by `cargo metadata`).
#![cfg(unix)]

mod common;

use common::{Host, meta, stored, value};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const TOKEN: (&str, &str) = ("OP_SERVICE_ACCOUNT_TOKEN", "ops_test_token");
/// A year, in seconds: how old an old Copy is made.
const YEAR: u64 = 365 * 86400;
const FILE: &str = "docs/budget.md";

/// Reads and writes. The account's daily requests count each of them
/// (opcore's decision record 7), so its column is their sum.
type Budget = [u32; 2];

/// opcore's decision record 1: each method's cost, and what a sign-in's
/// first vault call spends besides it.
struct Costs {
    each: Vec<(String, Budget)>,
    first_call: Budget,
}

/// opcore's decision record 1, in the source `Cargo.lock` pins.
fn adr() -> PathBuf {
    let out = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked"])
        .args([
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: Value = serde_json::from_slice(&out.stdout).unwrap();
    let packages = meta["packages"].as_array().unwrap();
    let opcore = packages.iter().find(|p| p["name"] == "opcore").unwrap();
    let manifest = PathBuf::from(opcore["manifest_path"].as_str().unwrap());
    let dir = manifest.parent().unwrap().join("docs/adr");
    std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("0001-")
        })
        .unwrap_or_else(|| panic!("no decision record 1 in {}", dir.display()))
}

/// The record's table (`| `Method` … | reads | writes | … |`, a parenthesis
/// saying how a row was measured) and its line `A sign-in's first vault
/// call: N read; …`.
fn costs() -> Costs {
    let adr = std::fs::read_to_string(adr()).unwrap();
    let mut each = Vec::new();
    for line in adr.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let cost = [cells[2].parse().unwrap(), cells[3].parse().unwrap()];
        let methods = cells[1].split('(').next().unwrap().split('`');
        for m in methods.skip(1).step_by(2) {
            each.push((m.to_string(), cost));
        }
    }
    let lead = "A sign-in's first vault call:";
    let line = adr.lines().find_map(|l| l.strip_prefix(lead)).unwrap();
    let reads = line.split_whitespace().next().unwrap().parse().unwrap();
    assert!(!each.is_empty(), "opcore's decision record 1 has no table");
    Costs {
        each,
        first_call: [reads, 0],
    }
}

/// What `calls` (the stand-in's records) spent: each call the stand-in did
/// not refuse, its method's cost, and each sign-in's first vault call
/// `first_call` more, as opcore's stand-in counts.
fn spent(costs: &Costs, calls: &Value) -> Budget {
    let mut spent = [0; 2];
    let mut add = |b: Budget| (0..2).for_each(|i| spent[i] += b[i]);
    let mut first = false;
    for call in calls.as_array().into_iter().flatten() {
        let method = call["method"].as_str().unwrap();
        if call["program"] != "core" || call["failed"] == true {
            continue;
        }
        if method == "init_client" {
            first = true;
        } else if std::mem::take(&mut first) {
            add(costs.first_call);
        }
        let cost = costs.each.iter().find(|(m, _)| m == method);
        add(cost.unwrap_or_else(|| panic!("no cost of {method}")).1);
    }
    spent
}

struct Row {
    command: String,
    calls: Vec<String>,
    spent: Budget,
}

/// A scenario: what the row says, the arguments, whether the Copy is made a
/// year old first, the Core calls it makes, and what they spend.
type Step<'a> = (&'a str, &'a str, bool, &'a str, Budget);

/// Runs each step on `host`, asserting it exits 0 with its calls and
/// Budget, and answers its rows.
fn steps(costs: &Costs, host: &Host, steps: &[Step]) -> Vec<Row> {
    let mut rows = Vec::new();
    for &(command, args, old, calls, budget) in steps {
        if old {
            host.age_copy(YEAR);
        }
        host.forget_calls();
        let args: Vec<&str> = args.split_whitespace().collect();
        let ran = host.run(&args, &[TOKEN], None);
        assert_eq!(ran.code, 0, "{command}: {} {}", ran.stdout, ran.stderr);
        let row = Row {
            command: command.into(),
            calls: host.core_calls(),
            spent: spent(costs, &host.calls()),
        };
        assert_eq!(
            row.calls,
            calls.split_whitespace().collect::<Vec<_>>(),
            "{command}"
        );
        assert_eq!(row.spent, budget, "{command}");
        rows.push(row);
    }
    rows
}

fn fail(host: &Host, fail: Value) {
    let mut state = host.state();
    state["core"]["fail"] = fail;
    host.set_state(&state);
}

const SYNC: &str = "init_client ItemsList";
/// A `--now` write's Sync, then its edit, written through.
const EDIT: &str = "init_client ItemsList ItemsGetAll ItemsPut";

/// Every command's scenarios, in the order they run on two hosts.
fn rows() -> Vec<Row> {
    let costs = costs();
    let host = Host::new(&[], json!({ "core": {} }));
    let first_list = "init_client VaultsList ItemsList";
    let create = "init_client ItemsList ItemsCreateAll";
    let mut rows = steps(
        &costs,
        &host,
        &[
            (
                "`list`, the first Sync on a new host",
                "list",
                false,
                first_list,
                [1, 0],
            ),
            (
                "`put --now` of a new Secret",
                "put db --set A=1 --now",
                false,
                create,
                [2, 1],
            ),
            (
                "`put --now` of what the Secret holds",
                "put db --set A=1 --now",
                false,
                SYNC,
                [1, 0],
            ),
            (
                "`put --now` of a changed Field",
                "put db --set A=2 --now",
                false,
                EDIT,
                [3, 1],
            ),
        ],
    );
    for (name, args) in [
        ("list", "list"),
        ("get", "get db --field A"),
        ("env", "env db"),
    ] {
        let command = format!("`{name}` from an old Copy");
        rows.extend(steps(
            &costs,
            &host,
            &[(&command, args, true, "", [0, 0])],
        ));
    }
    host.add(stored(
        "api1",
        "api",
        json!(["optokens"]),
        json!([
            value(0, "K", "1"),
            meta("service", "api"),
            meta("account", "default"),
            meta("kind", "static"),
            meta("shape", "fields")
        ]),
    ));
    let lacks = "`get` of a Secret the Copy lacks, made on another host";
    let got = "init_client ItemsList ItemsGetAll";
    rows.extend(steps(
        &costs,
        &host,
        &[(lacks, "get api --field K", true, got, [1, 0])],
    ));
    host.change("db", "A", "3");
    let changed = "`get --fresh`, the Secret changed on another host";
    rows.extend(steps(
        &costs,
        &host,
        &[
            (changed, "get db --field A --fresh", false, got, [1, 0]),
            ("`mv --now`", "mv db web --now", false, EDIT, [3, 1]),
        ],
    ));
    let limited = json!({ "name": "RateLimitExceeded", "message": "rate limit exceeded" });
    fail(&host, json!({ "ItemsPut": limited }));
    let waits = "`put --now` of a changed Field while 1Password refuses writes (it stays staged)";
    rows.extend(steps(
        &costs,
        &host,
        &[(waits, "put web --set A=4 --now", false, EDIT, [1, 0])],
    ));
    fail(&host, Value::Null);
    let push = "`list --fresh` that pushes that staged write";
    let delete = "init_client ItemsList ItemsDeleteAll";
    rows.extend(steps(
        &costs,
        &host,
        &[
            (push, "list --fresh", false, EDIT, [3, 1]),
            ("`rm --now`", "rm web --now", false, delete, [2, 1]),
            ("`doctor`", "doctor", false, "", [0, 0]),
        ],
    ));
    rows.extend(staged(&costs, &host));
    let new = Host::new(&[], json!({ "core": {} }));
    let first = "`put --now` of a new Secret, the first Sync on a new host";
    let first_put = "init_client VaultsList ItemsList ItemsCreateAll";
    rows.extend(steps(
        &costs,
        &new,
        &[(first, "put db --set A=1 --now", false, first_put, [2, 1])],
    ));
    rows
}

/// Changes staged, then pushed in one batch: 5 `put`s (3 new Secrets, 2
/// changes of one there) and 2 `rm`s.
fn staged(costs: &Costs, host: &Host) -> Vec<Row> {
    for (service, value) in [("s1", "1"), ("s2", "1"), ("s3", "1")] {
        let args = ["put", service, "--set", &format!("A={value}"), "--now"];
        assert_eq!(host.run(&args, &[TOKEN], None).code, 0);
    }
    let puts =
        "put n1 --set A=1, put n2 --set A=1, put n3 --set A=1, put s1 --set A=2, put s1 --set A=3";
    let mut rows = Vec::new();
    host.forget_calls();
    for args in puts.split(", ").chain(["rm s2", "rm s3"]) {
        let args: Vec<&str> = args.split_whitespace().collect();
        let ran = host.run(&args, &[TOKEN], None);
        assert_eq!(
            (ran.code, &ran.json()["pending"]),
            (0, &json!(true)),
            "{args:?}"
        );
    }
    rows.push(Row {
        command: "5 `put`s (3 new Secrets, 2 changes of one there) and 2 `rm`s, staged".into(),
        calls: host.core_calls(),
        spent: spent(costs, &host.calls()),
    });
    assert_eq!(rows[0].calls, Vec::<String>::new());
    rows.extend(steps(
        costs,
        host,
        &[(
            "`push` of those, each Secret's changes folded into one write",
            "push",
            false,
            "init_client ItemsList ItemsGetAll ItemsCreateAll ItemsPut ItemsDeleteAll",
            [5, 3],
        )],
    ));
    rows
}

/// The calls in order, a run of one method as one entry with its count.
fn calls(calls: &[String]) -> String {
    let run = |run: &[String]| match run.len() {
        1 => format!("`{}`", run[0]),
        n => format!("`{}` ×{n}", run[0]),
    };
    let runs: Vec<String> = calls.chunk_by(|a, b| a == b).map(run).collect();
    if runs.is_empty() {
        "none".into()
    } else {
        runs.join(", ")
    }
}

fn table(rows: &[Row]) -> String {
    let mut t = String::from(
        "# Budget per command\n\n\
         Generated by `tests/budget.rs`, which fails when this file differs from \
         what its scenarios spend on the stand-in Core; \
         `UPDATE_BUDGET=1 cargo test --test budget` rewrites it. Each method's cost \
         is opcore's decision record 1, in the opcore source `Cargo.lock` pins. \
         Each command is a new process: its first vault \
         call after signing in spends one read more. The account's daily \
         requests count each read and each write, so fewer calls, not fewer \
         processes, save them. A call 1Password refuses spends nothing.\n\n\
         | Command | Core calls | Reads | Writes | Account requests |\n\
         |---|---|---|---|---|\n",
    );
    for r in rows {
        let [reads, writes] = r.spent;
        let account = reads + writes;
        let calls = calls(&r.calls);
        t.push_str(&format!(
            "| {} | {calls} | {reads} | {writes} | {account} |\n",
            r.command
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
