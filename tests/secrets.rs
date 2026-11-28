//! `put`, `get`, `env`, `list` and `rm`, the real binary, on the stand-in
//! Core of `src/standin.rs`, which keeps the vault's items in its state file
//! as the Core answers them, and records each call.
#![cfg(unix)]

mod common;

use common::{FIRST_SYNC, Host, Ran, SYNC, first_synced, meta, stored, synced, value};
use serde_json::{Value, json};

const TOKEN: (&str, &str) = ("OP_SERVICE_ACCOUNT_TOKEN", "ops_test_token");
/// A year, in seconds: how old a Copy long synced is made.
const YEAR: u64 = 365 * 86400;

fn host() -> Host {
    Host::new(&[], json!({ "core": {} }))
}

fn run(host: &Host, args: &[&str]) -> Ran {
    host.run(args, &[TOKEN], None)
}

fn piped(host: &Host, args: &[&str], stdin: &str) -> Ran {
    host.run(args, &[TOKEN], Some(stdin.as_bytes()))
}

/// The Core's calls since the last time this was asked.
fn calls(host: &Host) -> Vec<String> {
    let calls = host.core_calls();
    host.forget_calls();
    calls
}

fn kinds(error: &Value) -> Vec<&str> {
    error["error"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap_or("-"))
        .collect()
}

fn seeded(items: Value) -> Host {
    Host::new(&[], json!({ "core": { "items": items } }))
}

/// No file under the config directory holds any of `known` in plaintext:
/// the Copy is sealed.
fn sealed(host: &Host, known: &[&str]) {
    for (path, bytes) in host.config_files() {
        for k in known.iter().chain([&TOKEN.1]) {
            assert!(
                !bytes.windows(k.len()).any(|w| w == k.as_bytes()),
                "`{k}` is in {}",
                path.display()
            );
        }
    }
}

#[test]
fn put_list_get_env_rm_a_profile() {
    let host = host();
    let known = ["Claude Code to GLM", "tok'en $HOME", "glm-4.6", "bigmodel"];
    let put = piped(
        &host,
        &[
            "put",
            "--now",
            "glm",
            "--kind",
            "profile",
            "--description",
            "Claude Code to GLM",
            "--set",
            "ANTHROPIC_BASE_URL=https://open.bigmodel.cn/api/anthropic?a=b",
            "--field-from-stdin",
            "ANTHROPIC_AUTH_TOKEN",
        ],
        "tok'en $HOME\n",
    );
    assert_eq!((put.code, put.stderr.as_str()), (0, ""));
    assert_eq!(
        put.json(),
        json!({ "secret": "glm/default", "changed": true, "pending": false, "kind": "profile",
                "fields": ["ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"] })
    );
    assert_eq!(
        calls(&host),
        first_synced(&["ItemsCreateAll"]),
        "a Sync, then one write, no read back"
    );
    sealed(&host, &known);

    assert_eq!(
        host.field_types("glm"),
        json!({ "ANTHROPIC_BASE_URL": "Text", "ANTHROPIC_AUTH_TOKEN": "Concealed" }),
        "--set is plain, stdin concealed"
    );

    // The same put again writes nothing.
    let again = piped(
        &host,
        &[
            "put",
            "--now",
            "glm",
            "--field-from-stdin",
            "ANTHROPIC_AUTH_TOKEN",
        ],
        "tok'en $HOME",
    );
    assert_eq!(again.json()["changed"], false);
    assert_eq!(
        calls(&host),
        SYNC,
        "the Copy holds what the create answered: nothing to get"
    );

    // One Field changes, the other is kept.
    let model = run(
        &host,
        &["put", "--now", "glm", "--set", "ANTHROPIC_MODEL=glm-4.6"],
    );
    assert_eq!(
        model.json()["fields"],
        json!([
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_MODEL"
        ])
    );
    assert_eq!(calls(&host), synced(&["ItemsGetAll", "ItemsPut"]));
    sealed(&host, &known);

    // From the Copy, list, get and env call nothing.
    let list = run(&host, &["list"]);
    assert_eq!(list.code, 0);
    assert_eq!(
        list.json(),
        json!({ "secrets": [{ "service": "glm", "account": "default", "kind": "profile", "description": "Claude Code to GLM", "meta": null,
                              "fields": ["ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_MODEL"] }] })
    );
    assert!(!list.stdout.contains("tok'en"), "{}", list.stdout);

    let get = run(&host, &["get", "glm", "--field", "ANTHROPIC_AUTH_TOKEN"]);
    assert_eq!(
        (get.code, get.stdout.as_str(), get.stderr.as_str()),
        (0, "tok'en $HOME", "")
    );
    let whole = run(&host, &["get", "glm", "--json"]);
    assert_eq!(
        whole.json(),
        json!({ "service": "glm", "account": "default", "kind": "profile", "description": "Claude Code to GLM", "meta": null,
                "fields": { "ANTHROPIC_BASE_URL": "https://open.bigmodel.cn/api/anthropic?a=b",
                            "ANTHROPIC_AUTH_TOKEN": "tok'en $HOME", "ANTHROPIC_MODEL": "glm-4.6" } })
    );

    let env = run(&host, &["env", "glm"]);
    assert_eq!(
        env.stdout,
        "export ANTHROPIC_BASE_URL='https://open.bigmodel.cn/api/anthropic?a=b'\nexport ANTHROPIC_AUTH_TOKEN='tok'\\''en $HOME'\nexport ANTHROPIC_MODEL='glm-4.6'\n"
    );
    let evaluated = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("{}printf %s \"$ANTHROPIC_AUTH_TOKEN\"", env.stdout))
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(evaluated.stdout).unwrap(), "tok'en $HOME");
    assert_eq!(
        calls(&host),
        Vec::<String>::new(),
        "no Core call, no sign-in"
    );

    let rm = run(&host, &["rm", "--now", "glm"]);
    assert_eq!(
        rm.json(),
        json!({ "secret": "glm/default", "changed": true, "pending": false })
    );
    assert_eq!(calls(&host), synced(&["ItemsDeleteAll"]));
    assert_eq!(host.items(), json!([]), "deleted, not archived");
    assert_eq!(
        run(&host, &["rm", "--now", "glm"]).json(),
        json!({ "secret": "glm/default", "changed": false, "pending": false })
    );
    assert_eq!(calls(&host), SYNC);
    assert_eq!(run(&host, &["list"]).json(), json!({ "secrets": [] }));

    let gone = run(&host, &["get", "glm"]);
    assert_eq!((gone.code, gone.stdout.as_str()), (2, ""));
    assert_eq!(kinds(&gone.error()), ["not_found"]);
    assert_eq!(
        gone.error()["error"][0]["fix"],
        "run `optokens list` to see what it has, or `optokens put` it"
    );
    sealed(&host, &known);
}

/// The Copy answers alone however old it is; `--fresh` syncs, listing once
/// and getting only what changed; a Secret the Copy lacks syncs once.
#[test]
fn the_copy_answers_however_old_and_a_sync_gets_only_what_changed() {
    let item = |id: &str, service: &str, v: &str| {
        stored(
            id,
            service,
            json!(["optokens"]),
            json!([
                value(0, "value", v),
                meta("service", service),
                meta("account", "default"),
                meta("kind", "static"),
                meta("shape", "value")
            ]),
        )
    };
    let host = seeded(json!([item("a1", "a", "A-1"), item("b1", "b", "B-1")]));
    let cold = run(&host, &["list"]);
    assert_eq!(cold.json()["secrets"].as_array().unwrap().len(), 2);
    assert_eq!(
        calls(&host),
        first_synced(&["ItemsGetAll"]),
        "a cold Copy gets all"
    );
    assert_eq!(
        host.state()["core"]["released"],
        json!(["7"]),
        "the Client signed in is released"
    );

    for args in [&["list"][..], &["get", "a"], &["env", "a"]] {
        run(&host, args);
    }
    assert_eq!(calls(&host), Vec::<String>::new(), "a warm Copy: no call");

    // Synced a year ago: still no call.
    host.age_copy(YEAR);
    for args in [&["list"][..], &["get", "a"], &["env", "a"]] {
        assert_eq!(run(&host, args).code, 2 * (args[0] == "env") as i32);
    }
    assert_eq!(calls(&host), Vec::<String>::new(), "an old Copy: no call");

    // One item changed on another host: read as held until `--fresh`, whose
    // Sync lists once and gets it alone.
    host.change("a", "value", "A-2");
    assert_eq!(run(&host, &["get", "a"]).stdout, "A-1", "as held");
    assert_eq!(calls(&host), Vec::<String>::new());
    let changed = run(&host, &["get", "a", "--fresh"]);
    assert_eq!(changed.stdout, "A-2");
    let got: Vec<Value> = host
        .calls()
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["ids"].clone())
        .collect();
    assert_eq!(calls(&host), synced(&["ItemsGetAll"]));
    assert_eq!(
        got[SYNC.len()],
        json!(["a1"]),
        "the one item changed, alone"
    );

    // A Secret made on another host since: one Sync, then its value.
    host.add(item("c1", "c", "C-1"));
    assert_eq!(run(&host, &["get", "c"]).stdout, "C-1");
    assert_eq!(calls(&host), synced(&["ItemsGetAll"]), "a miss syncs once");
    assert_eq!(run(&host, &["get", "c"]).stdout, "C-1");
    assert_eq!(calls(&host), Vec::<String>::new(), "then the Copy holds it");

    // A Secret that exists nowhere: one Sync, then `not_found`.
    let nowhere = run(&host, &["get", "zz"]);
    assert_eq!((nowhere.code, nowhere.stdout.as_str()), (2, ""));
    assert_eq!(kinds(&nowhere.error()), ["not_found"]);
    assert_eq!(calls(&host), SYNC);

    // `--fresh` always syncs.
    host.change("b", "value", "B-2");
    for args in [
        &["get", "b", "--fresh"][..],
        &["env", "b", "--fresh"],
        &["list", "--fresh"],
    ] {
        let ran = run(&host, args);
        assert_eq!(
            ran.code,
            2 * (args[0] == "env") as i32,
            "{args:?}: {}",
            ran.stdout
        );
    }
    assert_eq!(
        calls(&host),
        [synced(&["ItemsGetAll"]), synced(&[]), synced(&[])].concat()
    );
    assert_eq!(run(&host, &["get", "b"]).stdout, "B-2");
    sealed(&host, &["A-1", "A-2", "B-1", "B-2", "C-1"]);
}

/// With 1Password unreachable, reads of what the Copy holds answer with no
/// call and no warning; a Secret it lacks tries one Sync, which fails, and
/// is refused `not_found` after one warning naming why and how old the Copy
/// is; `--fresh` and `mv` fail. A Copy that never synced has nothing to
/// answer.
#[test]
fn a_miss_whose_sync_fails_answers_from_the_copy_with_a_warning() {
    let host = host();
    assert_eq!(run(&host, &["put", "--now", "db", "--set", "A=1"]).code, 0);
    let mut state = host.state();
    state["core"]["fail"] = json!({ "ItemsList": "network unreachable" });
    host.set_state(&state);
    host.age_copy(YEAR);
    calls(&host);

    let get = run(&host, &["get", "db", "--field", "A"]);
    assert_eq!(
        (get.code, get.stdout.as_str(), get.stderr.as_str()),
        (0, "1", "")
    );
    let env = run(&host, &["env", "db"]);
    assert_eq!(
        (env.code, env.stdout.as_str(), env.stderr.as_str()),
        (0, "export A='1'\n", "")
    );
    let list = run(&host, &["list"]);
    assert_eq!((list.code, list.stderr.as_str()), (0, ""));
    assert_eq!(list.json()["secrets"][0]["service"], "db");
    assert_eq!(calls(&host), Vec::<String>::new());

    let miss = run(&host, &["get", "web"]);
    assert_eq!((miss.code, miss.stdout.as_str()), (2, ""));
    let (warning, error) = miss.stderr.split_once('\n').unwrap();
    assert!(
        warning.starts_with(
            "warning: 1Password could not be synced (network unreachable); answering from the local copy synced 365d0h ago"
        ),
        "{}",
        miss.stderr
    );
    let error: Value = serde_json::from_str(error).unwrap();
    assert_eq!(kinds(&error), ["not_found"]);

    let fresh = run(&host, &["get", "db", "--fresh"]);
    assert_eq!((fresh.code, fresh.stdout.as_str()), (2, ""));
    assert_eq!(kinds(&fresh.error()), ["vault_failed"]);
    // `mv` syncs first and fails; a `put` goes on from the Copy (decision
    // record 17), and here its write reaches 1Password: nothing waits.
    let mv = run(&host, &["mv", "--now", "db", "db2"]);
    assert_eq!(kinds(&mv.json()), ["vault_failed"]);
    let put = run(&host, &["put", "--now", "db", "--set", "A=2"]);
    assert_eq!(
        (put.code, &put.json()["pending"]),
        (0, &json!(false)),
        "{}",
        put.stderr
    );
    assert_eq!(run(&host, &["get", "db", "--field", "A"]).stdout, "2");

    let cold = Host::new(
        &[],
        json!({ "core": { "fail": { "ItemsList": "network unreachable" } } }),
    );
    let never = run(&cold, &["get", "db"]);
    assert_eq!((never.code, never.stdout.as_str()), (2, ""));
    assert_eq!(kinds(&never.error()), ["vault_failed"]);
}

/// The Copy keeps its vault's id; when that id no longer names the vault,
/// one `VaultsList` finds it again and the Sync goes on.
#[test]
fn a_copy_whose_vault_id_changed_finds_the_vault_again() {
    let host = host();
    assert_eq!(run(&host, &["put", "--now", "db", "--set", "A=1"]).code, 0);
    let mut state = host.state();
    state["core"]["vaults"] = json!([{ "id": "v9", "title": "optokens" }]);
    for item in state["core"]["items"].as_array_mut().unwrap() {
        item["vaultId"] = json!("v9");
    }
    host.set_state(&state);
    calls(&host);

    let get = run(&host, &["get", "db", "--field", "A", "--fresh"]);
    assert_eq!(
        (get.code, get.stdout.as_str(), get.stderr.as_str()),
        (0, "1", "")
    );
    assert_eq!(
        calls(&host),
        ["init_client", "ItemsList", "VaultsList", "ItemsList"],
        "the list on the old id fails, the vault is found again, the list retried"
    );
    run(&host, &["get", "db", "--fresh"]);
    assert_eq!(calls(&host), SYNC, "the new id is kept");
}

/// A Field's type follows the way this put set it, both ways; one it does not
/// name keeps its own, and a stored item reads back as it was.
#[test]
fn a_fields_type_follows_how_its_value_came_in() {
    let concealed = |i: usize, label: &str, v: &str| {
        let mut f = value(i, label, v);
        f["fieldType"] = json!("Concealed");
        f
    };
    let host = seeded(json!([stored(
        "id1",
        "app/default",
        json!(["optokens"]),
        json!([
            concealed(0, "URL", "https://a"),
            concealed(1, "TOKEN", "t"),
            value(2, "USER", "u"),
            meta("kind", "static"),
            meta("shape", "fields")
        ])
    )]));
    let types = || host.field_types("app");
    assert_eq!(
        run(&host, &["get", "app", "--json"]).json()["fields"],
        json!({ "URL": "https://a", "TOKEN": "t", "USER": "u" })
    );
    assert_eq!(
        run(&host, &["put", "--now", "app", "--set", "URL=https://a"]).json()["changed"],
        true,
        "--set of the same value turns a concealed Field plain"
    );
    assert_eq!(
        types(),
        json!({ "URL": "Text", "TOKEN": "Concealed", "USER": "Text" })
    );
    assert_eq!(
        run(&host, &["put", "--now", "app", "--set", "URL=https://a"]).json()["changed"],
        false,
        "nor type nor value changes: nothing is written"
    );
    let piped_in = piped(
        &host,
        &["put", "--now", "app", "--field-from-stdin", "URL"],
        "https://b",
    );
    assert_eq!(piped_in.json()["changed"], true);
    assert_eq!(
        types(),
        json!({ "URL": "Concealed", "TOKEN": "Concealed", "USER": "Text" })
    );
    assert_eq!(
        run(&host, &["get", "app", "--json"]).json()["fields"],
        json!({ "URL": "https://b", "TOKEN": "t", "USER": "u" }),
        "a type changes nothing optokens gives out"
    );
}

#[test]
fn an_account_and_a_vault_file_name_where_it_goes() {
    let host = Host::new(&[], json!({ "core": { "vaults": ["optokens", "team"] } }));
    std::fs::create_dir_all(host.config()).unwrap();
    std::fs::write(host.config().join("vault"), "team\n").unwrap();
    let put = piped(
        &host,
        &[
            "put",
            "--now",
            "aws",
            "--account",
            "ci",
            "--set",
            "Access Key ID=AKIA",
            "--field-from-stdin",
            "Secret Access Key",
        ],
        "s3cr3t",
    );
    assert_eq!(put.json()["secret"], "aws/ci");
    assert_eq!(host.items()[0]["vaultId"], "v1", "in the vault `team`");
    assert_eq!(host.items()[0]["title"], "aws.ci");
    assert_eq!(
        run(
            &host,
            &[
                "get",
                "aws",
                "--account",
                "ci",
                "--field",
                "Secret Access Key"
            ]
        )
        .stdout,
        "s3cr3t"
    );
    let bare = run(&host, &["get", "aws", "--account", "ci"]);
    assert_eq!(kinds(&bare.error()), ["no_such_field"]);
    assert_eq!(
        bare.error()["error"][0]["fix"],
        "run `optokens get aws --account ci --field 'Access Key ID'`, or `optokens get aws --account ci --json` for them all"
    );
    let env = run(&host, &["env", "aws", "--account", "ci"]);
    assert_eq!((env.code, env.stdout.as_str()), (2, ""));
    assert_eq!(kinds(&env.error()), ["not_env"]);
}

#[test]
fn a_single_value_is_got_bare_and_never_exported() {
    let host = seeded(json!([stored(
        "x1",
        "cloudflare/default",
        json!(["optokens"]),
        json!([
            value(0, "value", "cf-token"),
            meta("kind", "static"),
            meta("shape", "value"),
        ])
    )]));
    let get = run(&host, &["get", "cloudflare"]);
    assert_eq!((get.code, get.stdout.as_str()), (0, "cf-token"));
    assert_eq!(
        run(&host, &["get", "cloudflare", "--json"]).json(),
        json!({ "service": "cloudflare", "account": "default", "kind": "static", "description": null, "meta": null, "value": "cf-token" })
    );
    assert_eq!(
        run(&host, &["list"]).json()["secrets"][0]["fields"],
        Value::Null
    );
    let env = run(&host, &["env", "cloudflare"]);
    assert_eq!(
        env.error()["error"][0]["fix"],
        "run `optokens get cloudflare`"
    );
    let shape = piped(
        &host,
        &["put", "--now", "cloudflare", "--field-from-stdin", "Token"],
        "x",
    );
    assert_eq!(kinds(&shape.json()), ["shape_change"]);
    let pipe = host.bash(
        r#""$0" put --now cloudflare --field-from-pipe Token=<(printf x)"#,
        &[TOKEN],
    );
    assert_eq!(kinds(&pipe.json()), ["shape_change"]);
    let described = run(
        &host,
        &["put", "--now", "cloudflare", "--description", "DNS edits"],
    );
    assert_eq!(
        described.json(),
        json!({ "secret": "cloudflare/default", "changed": true, "pending": false, "kind": "static", "fields": null })
    );
    assert_eq!(run(&host, &["get", "cloudflare"]).stdout, "cf-token");
}

/// The owner's promise: a secret's value is never in any process's command
/// line, and never in a file in plaintext. optokens runs no program to reach
/// 1Password; the stand-in Core records, on each call, every process's
/// command line (`ps`) and every file under `TMPDIR`, and the config
/// directory holds only sealed bytes.
#[test]
fn a_value_is_in_no_command_line_and_no_temporary_file() {
    const MARKER: &str = "MARKER-7f3a9c-never-in-argv";
    let host = host();
    host.watch();
    let put = piped(
        &host,
        &[
            "put",
            "--now",
            "db",
            "--set",
            "User=svc",
            "--field-from-stdin",
            "Password",
        ],
        &format!("{MARKER}\n"),
    );
    assert_eq!(put.code, 0, "{}", put.stdout);
    let rotate = piped(
        &host,
        &["put", "--now", "db", "--field-from-stdin", "Password"],
        &format!("{MARKER}-2"),
    );
    assert_eq!(rotate.json()["changed"], true);
    assert_eq!(
        run(&host, &["get", "db", "--field", "Password"]).stdout,
        format!("{MARKER}-2")
    );
    assert!(run(&host, &["env", "db"]).stdout.contains(MARKER));
    // The values reach bash in its environment, which it drops before it
    // runs optokens: only its builtin `printf` holds them.
    let pipes = host.bash(
        r#"a=$A b=$B; unset A B; "$0" put --now db --field-from-pipe Key=<(printf %s "$a") --field-from-pipe Salt=<(printf %s "$b")"#,
        &[TOKEN, ("A", &format!("{MARKER}-a")), ("B", &format!("{MARKER}-b"))],
    );
    assert_eq!(
        pipes.json()["fields"],
        json!(["User", "Password", "Key", "Salt"])
    );
    assert_eq!(
        run(&host, &["get", "db", "--field", "Salt"]).stdout,
        format!("{MARKER}-b")
    );
    sealed(&host, &[MARKER]);

    let methods = host.core_calls();
    assert!(
        methods.contains(&"ItemsCreateAll".to_string())
            && methods.contains(&"ItemsPut".to_string()),
        "{methods:?}"
    );
    let calls = host.calls();
    let calls = calls.as_array().unwrap();
    assert!(calls.len() >= 7, "{calls:?}");
    for call in calls {
        let ps = call["seen"]["ps"].as_str().unwrap();
        // ps saw the processes: optokens itself among them.
        assert!(ps.contains("optokens"), "{ps}");
        assert!(!ps.contains("MARKER"), "a value in a command line: {ps}");
        assert!(!ps.contains(TOKEN.1), "the token in a command line: {ps}");
        assert!(
            !call["seen"]["tmp"].to_string().contains("MARKER"),
            "a value in a temporary file: {call}"
        );
    }
}

#[test]
fn two_pipes_are_stored_concealed_in_one_put_and_one_write() {
    let host = host();
    let put = host.bash(
        r#""$0" put --now deploy-db --set User=svc --field-from-pipe Password=<(printf 'p w\n') --field-from-pipe "SigningKey="<(printf k)"#,
        &[TOKEN],
    );
    assert_eq!(put.code, 0, "{}{}", put.stdout, put.stderr);
    assert_eq!(
        put.json()["fields"],
        json!(["User", "Password", "SigningKey"])
    );
    assert_eq!(calls(&host), first_synced(&["ItemsCreateAll"]));
    assert_eq!(
        host.field_types("deploy-db"),
        json!({ "User": "Text", "Password": "Concealed", "SigningKey": "Concealed" })
    );
    assert_eq!(
        run(&host, &["get", "deploy-db", "--json"]).json()["fields"],
        json!({ "User": "svc", "Password": "p w", "SigningKey": "k" })
    );
}

/// A file, a missing path, a terminal-less mistake (`Label=$(command)`, the
/// value itself as the path) and an empty pipe are each refused by Label,
/// before the vault is read, and no path is ever printed.
#[test]
fn a_pipe_that_is_no_pipe_or_empty_is_refused_before_the_vault() {
    const MARKER: &str = "MARKER-5d1e-path";
    let host = host();
    let file = host.dir.path().join(format!("tmp/{MARKER}-file"));
    std::fs::write(&file, "a value in a file").unwrap();
    let refused = host.bash(
        &format!(
            r#""$0" put db --field-from-pipe File={} --field-from-pipe Gone=/nonexistent/{MARKER} --field-from-pipe Inline={MARKER}-value --field-from-pipe Empty=<(printf '\n') --field-from-pipe {MARKER}"#,
            file.display()
        ),
        &[TOKEN],
    );
    assert_eq!(
        kinds(&refused.json()),
        [
            "not_a_pipe",
            "not_a_pipe",
            "not_a_pipe",
            "pipe_empty",
            "not_a_pipe"
        ]
    );
    assert_eq!(
        refused.json()["error"][0]["fault"],
        "`--field-from-pipe File=` names no pipe that can be read"
    );
    assert_eq!(
        refused.json()["error"][4]["fault"],
        "`--field-from-pipe` number 5 names no `Label=` before its pipe",
        "an unlabelled pipe is named by its place, counted from 1"
    );
    assert!(
        !refused.stdout.contains(MARKER) && !refused.stderr.contains(MARKER),
        "{}{}",
        refused.stdout,
        refused.stderr
    );
    assert_eq!(
        host.calls(),
        Value::Null,
        "no refusal before the vault calls the Core"
    );
    let twice = host.bash(
        r#"printf s | "$0" put db --set A=1 --field-from-stdin B --field-from-pipe A=<(printf x) --field-from-pipe B=<(printf y)"#,
        &[TOKEN],
    );
    assert_eq!(kinds(&twice.json()), ["duplicate_label", "duplicate_label"]);
    assert!(!host.core_calls().contains(&"ItemsCreateAll".to_string()));
}

#[test]
fn put_refuses_every_fault_before_it_reaches_the_vault() {
    let host = host();
    let empty = piped(
        &host,
        &["put", "db", "--field-from-stdin", "Password"],
        "\n",
    );
    assert_eq!((empty.code, kinds(&empty.json())), (2, vec!["stdin_empty"]));
    let many = piped(
        &host,
        &[
            "put",
            "a/b",
            "--set",
            "NOEQUALS",
            "--fields",
            "Token",
            "--field-from-stdin",
            "P",
        ],
        "",
    );
    assert_eq!(
        kinds(&many.json()),
        ["bad_name", "bad_set", "stdin_empty", "tailscale_missing"]
    );
    assert_eq!(
        host.calls(),
        Value::Null,
        "no refusal before the vault calls the Core"
    );
    // A bare put asks for its value on the link: without a tailnet, the vault is not read.
    let link = run(&host, &["put", "cloudflare"]);
    assert_eq!(kinds(&link.json()), ["tailscale_missing"]);
    assert_eq!(host.calls(), Value::Null);
    // A `--description` alone for a Secret not stored asks for its value too, after reading the vault.
    let described = run(&host, &["put", "cloudflare", "--description", "DNS"]);
    assert_eq!(kinds(&described.json()), ["tailscale_missing"]);
    let names = run(
        &host,
        &[
            "put", "p", "--kind", "profile", "--set", "1X=a", "--set", "A=1", "--set", "A=2",
        ],
    );
    assert_eq!(kinds(&names.json()), ["not_env_name", "duplicate_label"]);
    assert_eq!(
        calls(&host),
        FIRST_SYNC,
        "the first Sync for the described put, with no Copy yet; none for the refused names, a staged put"
    );
    assert_eq!(run(&host, &["put", "p", "--set", "A=1"]).code, 0);
    let kind = run(&host, &["put", "p", "--kind", "profile", "--set", "A=1"]);
    assert_eq!(
        kind.json()["error"][0]["fix"],
        "run `optokens rm p`, then `put` it again with `--kind profile`"
    );
}

#[test]
fn without_a_token_nothing_reaches_1password() {
    let host = host();
    let put = host.run(&["put", "db", "--set", "A=1"], &[], None);
    assert_eq!(kinds(&put.json()), ["no_token"]);
    let get = host.run(&["get", "db"], &[], None);
    assert_eq!((get.code, get.stdout.as_str()), (2, ""));
    assert_eq!(kinds(&get.error()), ["no_token"]);
    assert_eq!(host.calls(), Value::Null);
}

/// An item as an earlier optokens wrote it: titled `<service>/<account>`, no
/// name in its section, its Description in its section, its notes another's.
fn old_bark(id: &str) -> Value {
    let mut item = stored(
        id,
        "bark/default",
        json!(["optokens"]),
        json!([
            value(0, "URL", "https://push/x"),
            meta("kind", "static"),
            meta("shape", "fields"),
            meta("description", "phone push")
        ]),
    );
    item["notes"] = json!("an old note");
    item
}

#[test]
fn a_secret_titled_with_a_slash_is_found_by_every_command_and_put_retitles_it_in_place() {
    let host = seeded(json!([old_bark("o1")]));
    let got = run(&host, &["get", "bark", "--field", "URL"]);
    assert_eq!((got.code, got.stdout.as_str()), (0, "https://push/x"));
    assert_eq!(
        run(&host, &["env", "bark"]).stdout,
        "export URL='https://push/x'\n"
    );
    assert_eq!(
        run(&host, &["list"]).json(),
        json!({ "secrets": [{ "service": "bark", "account": "default", "kind": "static",
                              "description": "phone push", "meta": null, "fields": ["URL"] }] })
    );
    let items = || host.items();
    assert_eq!(
        items()[0]["title"],
        "bark/default",
        "reading rewrites nothing"
    );

    // A put that changes no value still rewrites the item, under its new title.
    host.forget_calls();
    let put = run(
        &host,
        &["put", "--now", "bark", "--set", "URL=https://push/x"],
    );
    assert_eq!(
        put.json(),
        json!({ "secret": "bark/default", "changed": true, "pending": false, "kind": "static", "fields": ["URL"] })
    );
    assert_eq!(calls(&host).last().unwrap(), "ItemsPut");
    assert_eq!(items().as_array().unwrap().len(), 1);
    assert_eq!(items()[0]["id"], "o1");
    assert_eq!(items()[0]["title"], "bark");
    assert_eq!(
        run(&host, &["get", "bark", "--json"]).json(),
        json!({ "service": "bark", "account": "default", "kind": "static",
                "description": "phone push", "meta": null, "fields": { "URL": "https://push/x" } })
    );
    let meta: Vec<(String, String)> = items()[0]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["sectionId"] == "optokens")
        .map(|f| {
            (
                f["title"].as_str().unwrap().into(),
                f["value"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        meta,
        [
            ("account", "default"),
            ("kind", "static"),
            ("service", "bark"),
            ("shape", "fields"),
        ]
        .map(|(l, v)| (l.to_string(), v.to_string())),
        "by id, as the Core answers them"
    );
    assert_eq!(
        items()[0]["notes"],
        "phone push",
        "the Description moves into the notes"
    );
    assert_eq!(
        run(
            &host,
            &["put", "--now", "bark", "--set", "URL=https://push/x"]
        )
        .json()["changed"],
        false
    );

    // Both titles of one Secret are two items of it, refused; `--fresh`
    // sees the one another host added since the last Sync.
    let mut state = host.state();
    state["core"]["items"]
        .as_array_mut()
        .unwrap()
        .push(old_bark("o2"));
    host.set_state(&state);
    assert_eq!(run(&host, &["get", "bark", "--field", "URL"]).code, 0);
    let two = run(&host, &["get", "bark", "--fresh"]);
    assert_eq!(kinds(&two.error()), ["ambiguous"]);
    assert_eq!(
        two.error()["error"][0]["fault"],
        "the vault has 2 items of the Secret `bark/default` tagged `optokens`: o1, o2"
    );
}

#[test]
fn a_title_two_secrets_share_holds_each_by_its_section() {
    let host = host();
    for (args, value) in [
        (
            &["put", "--now", "name.com", "--set", "K=dotted"][..],
            "dotted",
        ),
        (
            &[
                "put",
                "--now",
                "name",
                "--account",
                "com",
                "--set",
                "K=account",
            ][..],
            "account",
        ),
    ] {
        assert_eq!(run(&host, args).json()["changed"], true, "{value}");
    }
    let titles: Vec<Value> = host
        .items()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].clone())
        .collect();
    assert_eq!(titles, ["name.com", "name.com"]);
    assert_eq!(
        run(&host, &["get", "name.com", "--field", "K"]).stdout,
        "dotted"
    );
    assert_eq!(
        run(&host, &["get", "name", "--account", "com", "--field", "K"]).stdout,
        "account"
    );
    assert_eq!(
        run(&host, &["list"]).json()["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| format!(
                "{}/{}",
                s["service"].as_str().unwrap(),
                s["account"].as_str().unwrap()
            ))
            .collect::<Vec<_>>(),
        ["name/com", "name.com/default"]
    );
    assert_eq!(
        run(&host, &["rm", "--now", "name.com"]).json()["changed"],
        true
    );
    assert_eq!(
        run(&host, &["get", "name", "--account", "com", "--field", "K"]).stdout,
        "account"
    );
}

#[test]
fn an_item_optokens_did_not_write_is_refused_by_name() {
    let host = seeded(json!([
        stored(
            "s1",
            "github/default",
            json!(["personal"]),
            json!([value(0, "value", "x")])
        ),
        stored(
            "s2",
            "bad/default",
            json!(["optokens"]),
            json!([
                meta("kind", "parent"),
                meta("shape", "value"),
                value(0, "value", "x")
            ])
        ),
    ]));
    let put = run(&host, &["put", "--now", "github", "--set", "A=1"]);
    assert_eq!(kinds(&put.json()), ["not_optokens"]);
    assert_eq!(
        put.json()["error"][0]["fault"],
        "the vault's item `github/default` is not a Secret optokens wrote: it has no tag `optokens`"
    );
    let list = run(&host, &["list"]);
    assert_eq!(list.code, 2);
    assert_eq!(
        list.json()["error"][0]["fault"],
        "the vault's item `bad/default` is not a Secret optokens wrote: its `kind` is `parent`, neither static nor profile"
    );
    assert_eq!(
        kinds(&run(&host, &["get", "bad"]).error()),
        ["not_optokens"]
    );
    let methods = host.core_calls();
    assert!(
        !methods
            .iter()
            .any(|m| m == "ItemsCreateAll" || m == "ItemsPut"),
        "{methods:?}"
    );
}

#[test]
fn a_failing_1password_call_is_refused_with_what_it_said() {
    let host = Host::new(
        &[],
        json!({ "core": { "fail": { "ItemsCreateAll": "You do not have permission" } } }),
    );
    let put = run(&host, &["put", "--now", "db", "--set", "A=1"]);
    assert_eq!(put.code, 2);
    assert_eq!(kinds(&put.json()), ["vault_failed"]);
    assert_eq!(
        put.json()["error"][0]["fault"],
        "1Password: You do not have permission"
    );
    assert_eq!(
        put.json()["error"][0]["fix"],
        "run `optokens init --check`, and see that the service account can reach the vault `optokens`"
    );
    let unknown = Host::new(&[], json!({ "core": { "token": "ops_another" } }));
    let get = run(&unknown, &["get", "db"]);
    assert_eq!((get.code, get.stdout.as_str()), (2, ""));
    assert_eq!(kinds(&get.error()), ["vault_failed"]);
    assert!(
        !get.stderr.contains(TOKEN.1),
        "the token is never in an error: {}",
        get.stderr
    );
}

#[test]
fn a_bad_command_line_of_get_keeps_stdout_empty() {
    let host = host();
    let get = run(&host, &["get", "x", "--field", "A", "--json"]);
    assert_eq!((get.code, get.stdout.as_str()), (2, ""));
    assert_eq!(get.error()["error"][0]["fix"], "run `optokens --help`");
    let env = run(&host, &["env"]);
    assert_eq!((env.code, env.stdout.as_str()), (2, ""));
    assert_eq!(env.error()["error"][0]["fix"], "run `optokens --help`");
    let put = run(&host, &["put", "x", "--nope"]);
    assert_eq!((put.code, put.stderr.as_str()), (2, ""));
    assert_eq!(put.json()["error"][0]["fix"], "run `optokens --help`");
}

/// Meta is one JSON object in the section `optokens`, stored compact: `put
/// --meta` sets it, a later `put` without it keeps it, `get --json` and
/// `list` show it, `get` and `env` never; anything but an object is refused.
#[test]
fn meta_is_one_json_object_put_keeps_and_get_json_and_list_show() {
    let host = host();
    let put = run(
        &host,
        &[
            "put",
            "--now",
            "cloudflare",
            "--kind",
            "profile",
            "--meta",
            r#"{ "account_id": "acc1", "zone": { "id": 7 } }"#,
            "--set",
            "CF_API_TOKEN=t",
        ],
    );
    assert_eq!((put.code, put.stderr.as_str()), (0, ""));
    let item = &host.items()[0];
    let stored: Vec<&Value> = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["title"] == "meta")
        .collect();
    assert_eq!(stored.len(), 1, "{item}");
    assert_eq!(stored[0]["sectionId"], "optokens");
    assert_eq!(
        stored[0]["value"], r#"{"account_id":"acc1","zone":{"id":7}}"#,
        "compact JSON"
    );
    let meta = json!({ "account_id": "acc1", "zone": { "id": 7 } });

    // A later put without --meta keeps it.
    assert_eq!(
        run(&host, &["put", "--now", "cloudflare", "--set", "CF_ZONE=z"]).code,
        0
    );
    assert_eq!(
        run(&host, &["list"]).json()["secrets"][0]["meta"],
        meta,
        "kept by a put without --meta"
    );
    let whole = run(&host, &["get", "cloudflare", "--json"]).json();
    assert_eq!(whole["meta"], meta);
    let got = run(&host, &["get", "cloudflare", "--field", "CF_ZONE"]);
    assert_eq!(got.stdout, "z");
    let env = run(&host, &["env", "cloudflare"]);
    assert_eq!(env.stdout, "export CF_API_TOKEN='t'\nexport CF_ZONE='z'\n");

    // A --meta alone for a stored Secret replaces it and changes nothing else.
    let alone = run(
        &host,
        &["put", "--now", "cloudflare", "--meta", r#"{"x":1}"#],
    );
    assert_eq!(alone.json()["changed"], true);
    assert_eq!(
        run(&host, &["list"]).json()["secrets"][0]["meta"],
        json!({ "x": 1 })
    );
    assert_eq!(
        run(
            &host,
            &["put", "--now", "cloudflare", "--meta", r#"{"x": 1}"#]
        )
        .json()["changed"],
        false
    );

    // Anything but a JSON object is refused before the vault.
    let calls = host.calls().as_array().unwrap().len();
    for bad in ["not-json", "[1]", "\"s\"", "null", "{"] {
        let refused = run(&host, &["put", "--now", "cloudflare", "--meta", bad]);
        assert_eq!(
            (refused.code, kinds(&refused.json())),
            (2, vec!["bad_meta"]),
            "{bad}"
        );
        assert!(
            refused.json()["error"][0]["fix"]
                .as_str()
                .unwrap()
                .contains("--meta '{"),
            "{}",
            refused.stdout
        );
    }
    assert_eq!(host.calls().as_array().unwrap().len(), calls);
}

/// An item written before Meta, with no `meta` field, is a Secret with no
/// Meta; one whose `meta` is no JSON object is not optokens' layout.
#[test]
fn an_item_without_meta_has_none_and_a_bad_meta_is_refused_by_name() {
    let item = |m: Option<&str>| {
        let mut fields = vec![
            value(0, "value", "cf-token"),
            meta("service", "cloudflare"),
            meta("account", "default"),
            meta("kind", "static"),
            meta("shape", "value"),
        ];
        fields.extend(m.map(|m| meta("meta", m)));
        stored("x1", "cloudflare", json!(["optokens"]), json!(fields))
    };
    let host = seeded(json!([item(None)]));
    assert_eq!(
        run(&host, &["list"]).json()["secrets"][0]["meta"],
        Value::Null
    );
    assert_eq!(
        run(&host, &["get", "cloudflare", "--json"]).json()["meta"],
        Value::Null
    );
    let bad = seeded(json!([item(Some("[1]"))]));
    let refused = run(&bad, &["list"]);
    assert_eq!(kinds(&refused.json()), ["not_optokens"]);
    assert!(
        refused.json()["error"][0]["fault"]
            .as_str()
            .unwrap()
            .ends_with("its `meta` is not a JSON object"),
        "{}",
        refused.stdout
    );
}

/// mytokens writes Secrets in this layout too, tagged its own way and with
/// sections of its own: `put` keeps every tag and section it does not own,
/// and the order of the Fields; a new Field goes last.
#[test]
fn put_keeps_the_tags_sections_and_field_order_it_does_not_own() {
    let mut item = stored(
        "m1",
        "deploy",
        json!(["optokens", "mytokens", "mytokens-digest-abc"]),
        json!([
            value(0, "C", "3"),
            value(1, "A", "1"),
            value(2, "B", "2"),
            meta("service", "deploy"),
            meta("account", "default"),
            meta("kind", "profile"),
            meta("shape", "fields"),
            { "id": "mytokens.origin", "title": "origin", "sectionId": "mytokens", "fieldType": "Text", "value": "laptop" },
        ]),
    );
    item["notes"] = json!("a note");
    item["sections"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "id": "mytokens", "title": "mytokens" }));
    let host = seeded(json!([item]));
    assert_eq!(
        run(&host, &["get", "deploy", "--json"]).json()["fields"],
        json!({ "C": "3", "A": "1", "B": "2" }),
        "a section optokens does not know is read past, not refused"
    );
    for put in [["--set", "A=10"], ["--set", "D=4"]] {
        let args = [&["put", "--now", "deploy"][..], &put[..]].concat();
        assert_eq!(run(&host, &args).json()["changed"], true);
    }
    let item = &host.items()[0];
    assert_eq!(
        item["tags"],
        json!(["optokens", "mytokens", "mytokens-digest-abc"])
    );
    let held: Vec<(Value, Value)> = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["sectionId"] != "optokens")
        .map(|f| (f["sectionId"].clone(), f["title"].clone()))
        .collect();
    assert_eq!(
        held,
        [
            (json!("fields"), json!("C")),
            (json!("fields"), json!("A")),
            (json!("fields"), json!("B")),
            (json!("fields"), json!("D")),
            (json!("mytokens"), json!("origin")),
        ]
    );
    assert_eq!(
        item["notes"], "a note",
        "the notes are the Description, kept"
    );
    assert_eq!(
        run(&host, &["env", "deploy"]).stdout,
        "export C='3'\nexport A='10'\nexport B='2'\nexport D='4'\n"
    );
}

#[test]
fn mv_renames_a_secret_in_place_with_one_sync_and_one_write() {
    let host = host();
    let put = piped(
        &host,
        &[
            "put",
            "--now",
            "agent-account",
            "--kind",
            "profile",
            "--description",
            "Claude Code, Felix's ultra",
            "--meta",
            r#"{"plan":"ultra"}"#,
            "--set",
            "HARNESS=claude-code",
            "--field-from-stdin",
            "CLAUDE_CODE_OAUTH_TOKEN",
        ],
        "sk-oauth",
    );
    assert_eq!(put.code, 0, "{}", put.stdout);
    let before = run(&host, &["get", "agent-account", "--json"]).json();
    let id = host.items()[0]["id"].clone();
    host.forget_calls();

    let mv = run(
        &host,
        &[
            "mv",
            "--now",
            "agent-account",
            "claude",
            "--to-account",
            "ultra",
        ],
    );
    assert_eq!(
        (mv.code, mv.json()),
        (
            0,
            json!({ "secret": "claude/ultra", "from": "agent-account/default", "pending": false })
        )
    );
    let methods = calls(&host);
    assert_eq!(
        methods.iter().filter(|m| m.as_str() == "ItemsList").count(),
        1,
        "one Sync: {methods:?}"
    );
    let writes = ["ItemsPut", "ItemsCreateAll", "ItemsDeleteAll"];
    assert_eq!(
        methods
            .iter()
            .filter(|m| writes.contains(&m.as_str()))
            .collect::<Vec<_>>(),
        ["ItemsPut"],
        "one write, an edit: {methods:?}"
    );

    let items = host.items();
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(items[0]["id"], id, "the same item");
    assert_eq!(items[0]["title"], "claude.ultra");
    let mut after = run(&host, &["get", "claude", "--account", "ultra", "--json"]).json();
    assert_eq!(after["service"], "claude");
    assert_eq!(after["account"], "ultra");
    for key in ["service", "account"] {
        after[key] = before[key].clone();
    }
    assert_eq!(after, before, "every Field, its kind, description and Meta");
    assert_eq!(
        host.field_types("claude.ultra"),
        json!({ "HARNESS": "Text", "CLAUDE_CODE_OAUTH_TOKEN": "Concealed" })
    );
    assert_eq!(
        kinds(&run(&host, &["get", "agent-account"]).error()),
        ["not_found"]
    );
    assert_eq!(
        kinds(&run(&host, &["mv", "--now", "agent-account", "x"]).json()),
        ["not_found"]
    );
}

#[test]
fn mv_onto_a_secret_or_an_untagged_title_refuses_and_writes_nothing() {
    let host = host();
    for service in ["a", "b"] {
        let put = run(
            &host,
            &["put", "--now", service, "--set", &format!("K={service}")],
        );
        assert_eq!(put.code, 0, "{}", put.stdout);
    }
    let mut state = host.state();
    state["core"]["items"].as_array_mut().unwrap().push(stored(
        "s1",
        "github",
        json!(["personal"]),
        json!([value(0, "value", "x")]),
    ));
    host.set_state(&state);
    let items = host.items();
    host.forget_calls();

    let taken = run(&host, &["mv", "--now", "a", "b"]);
    assert_eq!(taken.code, 2);
    assert_eq!(kinds(&taken.json()), ["exists"]);
    let stranger = run(&host, &["mv", "--now", "a", "github"]);
    assert_eq!(kinds(&stranger.json()), ["not_optokens"]);
    let itself = run(&host, &["mv", "--now", "a", "a"]);
    assert_eq!(kinds(&itself.json()), ["exists"]);
    assert_eq!(
        kinds(&run(&host, &["mv", "--now", "a", "x/y"]).json()),
        ["bad_name"]
    );

    let methods = host.core_calls();
    assert!(
        !methods
            .iter()
            .any(|m| ["ItemsPut", "ItemsCreateAll", "ItemsDeleteAll"].contains(&m.as_str())),
        "{methods:?}"
    );
    assert_eq!(host.items(), items);
}

/// 1Password's rate limit is refused with a fix that sends the agent to
/// `op service-account ratelimit` and says the account's budget is daily:
/// waiting an hour does not refill it.
#[test]
fn a_rate_limit_is_refused_with_a_fix_that_names_both_budgets() {
    let host = host();
    assert_eq!(run(&host, &["put", "--now", "db", "--set", "A=1"]).code, 0);
    let mut state = host.state();
    state["core"]["fail"] = json!({
        "ItemsList": { "name": "RateLimitExceeded", "message": "rate limit exceeded" }
    });
    host.set_state(&state);

    let fresh = run(&host, &["get", "db", "--fresh"]);
    assert_eq!((fresh.code, fresh.stdout.as_str()), (2, ""));
    let error = fresh.error();
    assert_eq!(kinds(&error), ["vault_failed"]);
    let fix = error["error"][0]["fix"].as_str().unwrap();
    assert!(fix.contains("`op service-account ratelimit`"), "{fix}");
    assert!(
        fix.contains("the account's") && fix.contains("day"),
        "{fix}"
    );
    assert!(!fix.contains("hourly budget of reads and writes"), "{fix}");
}

/// After a Sync, a write 1Password cannot take now (network, rate limit,
/// down) waits, sealed in `copy.pending`: the command answers `pending:
/// true` with a `warning:` line, reads show the write, and the next Sync
/// that reaches the vault once its backoff is over pushes it.
#[test]
fn a_write_the_vault_cannot_take_now_waits_and_the_next_sync_pushes_it() {
    let host = host();
    assert_eq!(run(&host, &["put", "--now", "db", "--set", "A=1"]).code, 0);
    let mut state = host.state();
    state["core"]["fail"] = json!({
        "ItemsPut": "error sending request",
        "ItemsCreateAll": { "name": "RateLimitExceeded", "message": "rate limit exceeded" },
        "ItemsDeleteAll": "error sending request"
    });
    host.set_state(&state);

    let put = run(&host, &["put", "--now", "db", "--set", "A=SECRET-TWO"]);
    assert_eq!(put.code, 0, "{}", put.stdout);
    assert_eq!(put.json()["changed"], true);
    assert_eq!(put.json()["pending"], true);
    assert!(
        put.stderr
            .starts_with("warning: 1Password could not take the edit of "),
        "{}",
        put.stderr
    );
    let made = run(&host, &["put", "--now", "web", "--set", "B=SECRET-WEB"]);
    assert_eq!((made.code, &made.json()["pending"]), (0, &json!(true)));
    let gone = run(&host, &["rm", "--now", "web"]);
    assert_eq!((gone.code, &gone.json()["pending"]), (0, &json!(true)));
    assert_eq!(
        run(&host, &["get", "db", "--field", "A"]).stdout,
        "SECRET-TWO"
    );
    assert_eq!(run(&host, &["get", "web", "--field", "B"]).code, 2);
    assert_eq!(
        host.items().as_array().unwrap().len(),
        1,
        "the vault holds the old item only"
    );
    sealed(&host, &["SECRET-TWO", "SECRET-WEB"]);
    let another = [(TOKEN.0, "ops_another")];
    let other = host.run(&["get", "db", "--field", "A"], &another, None);
    assert_eq!(
        (other.code, other.stdout.as_str()),
        (0, "1"),
        "another token reads the vault without what waits: {}",
        other.stderr
    );
    assert!(other.stderr.contains("copy.pending"), "{}", other.stderr);
    let refused = host.run(&["put", "--now", "db", "--set", "A=4"], &another, None);
    assert_eq!(refused.code, 2, "another token's write is refused");
    assert_eq!(kinds(&refused.json()), ["vault_failed"]);
    assert!(
        refused.stdout.contains("copy.pending"),
        "{}",
        refused.stdout
    );

    let mut state = host.state();
    state["core"]["fail"] = Value::Null;
    host.set_state(&state);
    // A write that waits is due again after opcore's first backoff (1s after
    // its failed push); a Sync before then leaves it waiting.
    std::thread::sleep(std::time::Duration::from_secs(1));
    let list = run(&host, &["list", "--fresh"]);
    assert_eq!(list.code, 0, "{}", list.stderr);
    let fresh = run(&host, &["get", "db", "--field", "A", "--fresh"]);
    assert_eq!(fresh.stdout, "SECRET-TWO", "pushed: {}", fresh.stderr);
    assert_eq!(
        host.items().as_array().unwrap().len(),
        1,
        "web made and removed"
    );
    let again = run(&host, &["put", "--now", "db", "--set", "A=3"]);
    assert_eq!(again.json()["pending"], false);
    assert!(
        !host.config().join("copy.pending").exists(),
        "the push of the last waiting write removes the file"
    );
    let theirs = host.run(&["put", "--now", "db", "--set", "A=5"], &another, None);
    assert_eq!((theirs.code, &theirs.json()["pending"]), (0, &json!(false)));
}

/// While 1Password cannot be reached (here its rate limit), `put --now` and `rm --now`
/// are kept on this host as pending writes, answered at once with
/// `"pending": true`; reads on this host show them, `list` marks them, and
/// the next command that syncs pushes them, keeping a Field another host
/// changed meanwhile. A refusal that is not "cannot reach" still fails.
#[test]
fn put_and_rm_wait_on_this_host_while_1password_cannot_be_reached() {
    let host = host();
    let ran = |args: &[&str]| run(&host, args);
    for put in [
        &["put", "--now", "db", "--set", "A=1", "--set", "B=2"][..],
        &["put", "--now", "gone", "--set", "X=1"],
        &["put", "--now", "kept", "--set", "K=1"],
    ] {
        assert_eq!(run(&host, put).code, 0);
    }
    let mut state = host.state();
    let limited = json!({ "name": "RateLimitExceeded", "message": "rate limit exceeded" });
    let methods = [
        "ItemsList",
        "ItemsGetAll",
        "ItemsPut",
        "ItemsCreateAll",
        "ItemsDeleteAll",
    ];
    state["core"]["fail"] = methods
        .iter()
        .map(|m| (m.to_string(), limited.clone()))
        .collect();
    host.set_state(&state);

    let line = "1Password could not be reached (";
    let tail = "); the change stays staged on this host until a push reaches 1Password";
    let edit = ran(&["put", "--now", "db", "--set", "A=10"]);
    assert_eq!(edit.code, 0, "{}{}", edit.stdout, edit.stderr);
    assert_eq!(edit.json()["pending"], true, "{}", edit.stdout);
    assert!(
        edit.stderr.contains(line) && edit.stderr.contains(tail),
        "{}",
        edit.stderr
    );
    let new = host.run(
        &["put", "--now", "new", "--field-from-stdin", "TOKEN"],
        &[TOKEN],
        Some(b"s3cr3t-pending\n"),
    );
    assert_eq!(new.code, 0, "{}{}", new.stdout, new.stderr);
    assert_eq!(new.json()["pending"], true);
    let rm = ran(&["rm", "--now", "gone"]);
    assert_eq!(rm.code, 0, "{}{}", rm.stdout, rm.stderr);
    assert_eq!(
        rm.json(),
        json!({ "secret": "gone/default", "changed": true, "pending": true })
    );
    let bad = ran(&["put", "--now", "a/b", "--set", "A=1"]);
    assert_eq!(kinds(&bad.json()), ["bad_name"]);
    sealed(&host, &["s3cr3t-pending"]);

    assert_eq!(ran(&["get", "db", "--field", "A"]).stdout, "10");
    assert_eq!(ran(&["get", "gone"]).code, 2);
    assert_eq!(
        ran(&["env", "new"]).stdout,
        "export TOKEN='s3cr3t-pending'\n"
    );
    let listed = ran(&["list"]).json();
    let marks: Vec<(&str, &Value)> = listed["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["service"].as_str().unwrap(), &s["pending"]))
        .collect();
    assert_eq!(
        marks,
        [
            ("db", &json!(true)),
            ("kept", &Value::Null),
            ("new", &json!(true))
        ]
    );

    // Another host changes B meanwhile; then 1Password is reachable again.
    host.change("db", "B", "from-another-host");
    let mut state = host.state();
    state["core"]["fail"] = Value::Null;
    host.set_state(&state);
    let pushed = ran(&["list", "--fresh"]);
    assert_eq!(pushed.code, 0, "{}", pushed.stderr);
    let secrets = pushed.json()["secrets"].clone();
    assert!(
        secrets
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s.get("pending").is_none()),
        "{secrets}"
    );
    let items = host.items();
    let titles: Vec<&Value> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| &i["title"])
        .collect();
    assert_eq!(titles, [&json!("db"), &json!("kept"), &json!("new")]);
    let db = run(&host, &["get", "db", "--json", "--fresh"]).json();
    assert_eq!(db["fields"]["A"], "10");
    assert_eq!(db["fields"]["B"], "from-another-host");
    assert_eq!(
        run(&host, &["get", "new", "--field", "TOKEN"]).stdout,
        "s3cr3t-pending"
    );
    let mut state = host.state();
    state["core"]["fail"] = json!({ "ItemsList": "You do not have permission" });
    host.set_state(&state);
    let denied = ran(&["put", "--now", "db", "--set", "A=11"]);
    assert_eq!(denied.code, 2, "{}{}", denied.stdout, denied.stderr);
    assert_eq!(kinds(&denied.json()), ["vault_failed"]);
    assert!(!host.config().join("copy.pending").exists());
}

/// A write that waits is pushed by the next `--now` write, with no
/// `--fresh`; until then every read warns of it, naming `optokens push`.
#[test]
fn a_waiting_write_is_pushed_by_the_next_put() {
    let host = host();
    assert_eq!(run(&host, &["put", "--now", "db", "--set", "A=1"]).code, 0);
    let mut state = host.state();
    state["core"]["fail"] = json!({ "ItemsPut": "error sending request" });
    host.set_state(&state);
    let put = run(&host, &["put", "--now", "db", "--set", "A=2"]);
    assert_eq!((put.code, &put.json()["pending"]), (0, &json!(true)));
    let mut state = host.state();
    state["core"]["fail"] = Value::Null;
    host.set_state(&state);
    calls(&host);

    let get = run(&host, &["get", "db", "--field", "A"]);
    assert_eq!(get.stdout, "2");
    assert!(
        get.stderr
            .starts_with("warning: 1 pending write(s) wait in `")
            && get
                .stderr
                .contains("copy.pending`; `optokens push` pushes them"),
        "{}",
        get.stderr
    );
    assert_eq!(calls(&host), Vec::<String>::new(), "a read pushes nothing");

    let next = run(&host, &["put", "--now", "web", "--set", "B=1"]);
    assert_eq!((next.code, &next.json()["pending"]), (0, &json!(false)));
    assert!(!host.config().join("copy.pending").exists(), "pushed");
    let items = host.items();
    let titles: Vec<&Value> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| &i["title"])
        .collect();
    assert_eq!(titles, [&json!("db"), &json!("web")]);
    let db = host.run(&["get", "db", "--field", "A", "--fresh"], &[TOKEN], None);
    assert_eq!((db.stdout.as_str(), db.stderr.as_str()), ("2", ""));
}

/// `put`, `mv` and `rm` stage their change on this host with no Core call
/// and answer `pending: true`; reads on this host show it at once, `list`
/// marks it and warns, naming `optokens push`, and `status` lists each
/// change. `push` sends them all in one process, each Secret's changes
/// folded into one write: two `put`s of one Secret are one `ItemsPut`, a
/// new Secret and its `rm` reach 1Password not at all.
#[test]
fn writes_are_staged_and_push_sends_them_in_one_batch() {
    let host = host();
    for service in ["kept", "changed", "gone", "moved"] {
        assert_eq!(
            run(&host, &["put", "--now", service, "--set", "A=1"]).code,
            0
        );
    }
    calls(&host);
    let staged = [
        &["put", "changed", "--set", "A=2"][..],
        &["put", "changed", "--set", "B=3"],
        &["put", "new", "--set", "N=1"],
        &["put", "brief", "--set", "X=1"],
        &["rm", "brief"],
        &["rm", "gone"],
        &["mv", "moved", "renamed"],
    ];
    for args in staged {
        let ran = run(&host, args);
        assert_eq!(ran.code, 0, "{args:?}: {}{}", ran.stdout, ran.stderr);
        assert_eq!(ran.json()["pending"], true, "{args:?}: {}", ran.stdout);
        assert!(
            ran.stderr.contains("`optokens push` pushes it"),
            "{}",
            ran.stderr
        );
    }
    assert_eq!(calls(&host), Vec::<String>::new(), "staged: no Core call");
    sealed(&host, &[]);

    let changed = run(&host, &["get", "changed", "--json"]).json();
    assert_eq!(changed["fields"], json!({ "A": "2", "B": "3" }));
    assert_eq!(run(&host, &["get", "renamed", "--field", "A"]).stdout, "1");
    let listed = run(&host, &["list"]);
    let secrets = listed.json()["secrets"].clone();
    let marks: Vec<(&str, &Value)> = secrets
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["service"].as_str().unwrap(), &s["pending"]))
        .collect();
    let mark = &json!(true);
    assert_eq!(
        marks,
        [
            ("changed", mark),
            ("kept", &Value::Null),
            ("new", mark),
            ("renamed", mark)
        ]
    );
    assert!(
        listed.stderr.contains("pending write(s) wait in `")
            && listed.stderr.contains("`optokens push` pushes them"),
        "{}",
        listed.stderr
    );
    let status = run(&host, &["status"]).json();
    let changes: Vec<(&Value, &str, &str)> = status["pending"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                &p["secret"],
                p["item"].as_str().unwrap(),
                p["change"].as_str().unwrap(),
            )
        })
        .collect();
    let (changed, new, renamed) = (
        json!("changed/default"),
        json!("new/default"),
        json!("renamed/default"),
    );
    assert_eq!(
        changes,
        [
            (&changed, "changed", "edit"),
            (&changed, "changed", "edit"),
            (&new, "new", "create"),
            (&Value::Null, "brief", "create"),
            (&Value::Null, "brief", "delete"),
            (&Value::Null, "gone", "delete"),
            (&renamed, "renamed", "edit"),
        ]
    );
    let at = status["pending"][0]["at"].as_str().unwrap();
    assert!(
        at.starts_with("20") && at.ends_with('Z') && at.len() == 20,
        "{at}"
    );
    assert_eq!(
        calls(&host),
        Vec::<String>::new(),
        "reads and status: no Core call"
    );

    let pushed = run(&host, &["push"]);
    assert_eq!(pushed.code, 0, "{}", pushed.stderr);
    assert_eq!(pushed.json(), json!({ "pushed": 7, "pending": 0 }));
    let made = calls(&host);
    let count = |m: &str| made.iter().filter(|c| *c == m).count();
    assert_eq!(made[..2], ["init_client", "ItemsList"], "{made:?}");
    assert_eq!(
        (
            count("init_client"),
            count("ItemsCreateAll"),
            count("ItemsPut"),
            count("ItemsDeleteAll")
        ),
        (1, 1, 2, 1),
        "{made:?}"
    );
    assert!(!host.config().join("copy.pending").exists(), "all sent");
    let items = host.items();
    let titles: Vec<&str> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["kept", "changed", "renamed", "new"]);
    let fresh = run(&host, &["get", "changed", "--json", "--fresh"]).json();
    assert_eq!(fresh["fields"], json!({ "A": "2", "B": "3" }));
    assert_eq!(run(&host, &["status"]).json(), json!({ "pending": [] }));
    calls(&host);
    let again = run(&host, &["push"]);
    assert_eq!(again.json(), json!({ "pushed": 0, "pending": 0 }));
    assert_eq!(
        calls(&host),
        Vec::<String>::new(),
        "nothing staged: no call"
    );
}

/// `--fresh` on a read pushes what is staged before it syncs.
#[test]
fn fresh_pushes_what_is_staged() {
    let host = host();
    assert_eq!(run(&host, &["put", "--now", "db", "--set", "A=1"]).code, 0);
    assert_eq!(
        run(&host, &["put", "db", "--set", "A=2"]).json()["pending"],
        true
    );
    assert_eq!(host.field_value("db", "A"), "1", "staged, not sent");
    calls(&host);
    let got = run(&host, &["get", "db", "--field", "A", "--fresh"]);
    assert_eq!((got.code, got.stdout.as_str()), (0, "2"), "{}", got.stderr);
    assert_eq!(calls(&host), synced(&["ItemsGetAll", "ItemsPut"]));
    assert_eq!(host.field_value("db", "A"), "2");
    assert!(!host.config().join("copy.pending").exists());
}
