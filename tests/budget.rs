//! What each command spends of the service account's Budget, on the
//! stand-in Core: each scenario asserts its Core calls and its reads,
//! writes and account requests, and `docs/budget.md` is the table of them
//! all, which this test fails on when it is stale. Each method's cost is
//! read from opcore's decision record 1, the one home of the numbers, in
//! the opcore source this build compiles (found by `cargo metadata`).
#![cfg(unix)]

mod common;

use common::Host;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const TOKEN: (&str, &str) = ("OP_SERVICE_ACCOUNT_TOKEN", "ops_test_token");
/// A Copy past its Life at once.
const STALE: (&str, &str) = ("OPTOKENS_TEST_COPY_LIFE_MS", "0");
const FILE: &str = "docs/budget.md";

/// Reads, writes and account requests.
type Budget = [u32; 3];

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
/// saying how a row was measured) and its line `Each sign-in's first vault
/// call: N read, M of the account's …`.
fn costs() -> Costs {
    let adr = std::fs::read_to_string(adr()).unwrap();
    let mut each = Vec::new();
    for line in adr.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let cost = [cells[2].parse().unwrap(), cells[3].parse().unwrap(), 0];
        let methods = cells[1].split('(').next().unwrap().split('`');
        for m in methods.skip(1).step_by(2) {
            each.push((m.to_string(), cost));
        }
    }
    let lead = "Each sign-in's first vault call:";
    let line = adr.lines().find_map(|l| l.strip_prefix(lead)).unwrap();
    let n: Vec<u32> = (line.split(',').take(2))
        .map(|part| part.split_whitespace().next().unwrap().parse().unwrap())
        .collect();
    assert!(!each.is_empty(), "opcore's decision record 1 has no table");
    Costs {
        each,
        first_call: [n[0], 0, n[1]],
    }
}

/// What `calls` (the stand-in's records) spent: each call the stand-in did
/// not refuse, its method's cost, and each sign-in's first vault call
/// `first_call` more, as opcore's stand-in counts.
fn spent(costs: &Costs, calls: &Value) -> Budget {
    let mut spent = [0; 3];
    let mut add = |b: Budget| (0..3).for_each(|i| spent[i] += b[i]);
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

/// A scenario: what the row says, the arguments, whether the Copy is past
/// its Life, the Core calls it makes, and what they spend.
type Step<'a> = (&'a str, &'a str, bool, &'a str, Budget);

/// Runs each step on `host`, asserting it exits 0 with its calls and
/// Budget, and answers its rows.
fn steps(costs: &Costs, host: &Host, steps: &[Step]) -> Vec<Row> {
    let mut rows = Vec::new();
    for &(command, args, stale, calls, budget) in steps {
        host.forget_calls();
        let env = [TOKEN, STALE];
        let args: Vec<&str> = args.split_whitespace().collect();
        let ran = host.run(&args, &env[..1 + stale as usize], None);
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
                [2, 0, 1],
            ),
            (
                "`put` of a new Secret",
                "put db --set A=1",
                false,
                create,
                [2, 1, 1],
            ),
            (
                "`put` of what the Secret holds",
                "put db --set A=1",
                false,
                SYNC,
                [1, 0, 1],
            ),
            (
                "`put` of a changed Field",
                "put db --set A=2",
                false,
                EDIT,
                [3, 1, 1],
            ),
        ],
    );
    for (stale, when, calls, budget) in [
        (false, "within the Copy's Life", "", [0, 0, 0]),
        (
            true,
            "past the Copy's Life, nothing changed",
            SYNC,
            [1, 0, 1],
        ),
    ] {
        for (name, args) in [
            ("list", "list"),
            ("get", "get db --field A"),
            ("env", "env db"),
        ] {
            let command = format!("`{name}` {when}");
            rows.extend(steps(
                &costs,
                &host,
                &[(&command, args, stale, calls, budget)],
            ));
        }
    }
    host.change("db", "A", "3");
    let changed = "`get --fresh`, the Secret changed on another host";
    let got = "init_client ItemsList ItemsGetAll";
    rows.extend(steps(
        &costs,
        &host,
        &[
            (changed, "get db --field A --fresh", false, got, [1, 0, 1]),
            ("`mv`", "mv db web", false, EDIT, [3, 1, 1]),
        ],
    ));
    let limited = json!({ "name": "RateLimitExceeded", "message": "rate limit exceeded" });
    fail(&host, json!({ "ItemsPut": limited }));
    let waits = "`put` of a changed Field while 1Password refuses writes (it waits)";
    rows.extend(steps(
        &costs,
        &host,
        &[(waits, "put web --set A=4", false, EDIT, [1, 0, 1])],
    ));
    fail(&host, Value::Null);
    let push = "`list --fresh` that pushes that waiting write";
    let delete = "init_client ItemsList ItemsDeleteAll";
    rows.extend(steps(
        &costs,
        &host,
        &[
            (
                push,
                "list --fresh",
                false,
                "init_client ItemsList ItemsPut",
                [3, 1, 1],
            ),
            ("`rm`", "rm web", false, delete, [2, 1, 1]),
            ("`doctor`", "doctor", false, "", [0, 0, 0]),
        ],
    ));
    let new = Host::new(&[], json!({ "core": {} }));
    let first = "`put` of a new Secret, the first Sync on a new host";
    let first_put = "init_client VaultsList ItemsList ItemsCreateAll";
    rows.extend(steps(
        &costs,
        &new,
        &[(first, "put db --set A=1", false, first_put, [3, 1, 1])],
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
         call after signing in spends one read and one of the account's daily \
         requests more. A call 1Password refuses spends nothing.\n\n\
         | Command | Core calls | Reads | Writes | Account requests |\n\
         |---|---|---|---|---|\n",
    );
    for r in rows {
        let [reads, writes, account] = r.spent;
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
