//! What the Core calls a test's runs made spend of the service account's
//! Budget, and of the account's daily requests: each method's cost read
//! from opcore's decision record 1, the one home of the numbers, in the
//! opcore source this build compiles (found by `cargo metadata`).
use serde_json::Value;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Reads, writes and account requests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Budget {
    pub reads: u32,
    pub writes: u32,
    pub account: u32,
}

impl Budget {
    pub const fn new(reads: u32, writes: u32, account: u32) -> Budget {
        Budget {
            reads,
            writes,
            account,
        }
    }
}

impl std::ops::AddAssign for Budget {
    fn add_assign(&mut self, b: Budget) {
        self.reads += b.reads;
        self.writes += b.writes;
        self.account += b.account;
    }
}

/// opcore's decision record 1: each method's cost, and what a sign-in's
/// first vault call spends besides it.
struct Costs {
    each: Vec<(String, Budget)>,
    first_call: Budget,
}

/// What `calls` (the stand-in's records) spent: each call the stand-in
/// did not refuse, its method's cost, and each sign-in's first vault call
/// one read and one account request more, as opcore's stand-in counts.
pub fn spent(calls: &[Value]) -> Budget {
    let costs = costs();
    let mut spent = Budget::default();
    let mut first = false;
    for call in calls.iter().filter(|c| c["program"] == "core") {
        let method = call["method"].as_str().unwrap();
        if call["failed"] == true {
            continue;
        }
        if method == "init_client" {
            first = true;
        } else if std::mem::take(&mut first) {
            spent += costs.first_call;
        }
        spent += costs
            .each
            .iter()
            .find(|(m, _)| m == method)
            .unwrap_or_else(|| panic!("opcore's decision record 1 measures no {method}"))
            .1;
    }
    spent
}

fn costs() -> &'static Costs {
    static COSTS: OnceLock<Costs> = OnceLock::new();
    COSTS.get_or_init(|| parse(&std::fs::read_to_string(adr()).unwrap()))
}

/// opcore's decision record 1, in the source `Cargo.lock` pins.
fn adr() -> PathBuf {
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: Value = serde_json::from_slice(&out.stdout).unwrap();
    let opcore = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "opcore")
        .expect("opcore among the packages");
    let dir = PathBuf::from(opcore["manifest_path"].as_str().unwrap())
        .parent()
        .unwrap()
        .join("docs/adr");
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
fn parse(adr: &str) -> Costs {
    let mut each = Vec::new();
    for line in adr.lines().filter(|l| l.starts_with("| `")) {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let cost = Budget::new(cells[2].parse().unwrap(), cells[3].parse().unwrap(), 0);
        let methods = cells[1].split('(').next().unwrap().split('`');
        for m in methods.skip(1).step_by(2) {
            each.push((m.to_string(), cost));
        }
    }
    let lead = "Each sign-in's first vault call:";
    let line = adr
        .lines()
        .find_map(|l| l.strip_prefix(lead))
        .unwrap_or_else(|| panic!("opcore's decision record 1 has no line `{lead}`"));
    let n: Vec<u32> = line
        .split(',')
        .take(2)
        .map(|part| part.split_whitespace().next().unwrap().parse().unwrap())
        .collect();
    assert!(!each.is_empty(), "opcore's decision record 1 has no table");
    Costs {
        each,
        first_call: Budget::new(n[0], 0, n[1]),
    }
}
