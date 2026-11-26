//! `put`, `get`, `env`, `list` and `rm`, the real binary, with `op` replaced
//! by the stand-in of `examples/standin.rs`, which keeps the vault's items in
//! its state file as `op` keeps them.
#![cfg(unix)]

mod common;

use common::{Host, Ran};
use serde_json::{Value, json};

const TOKEN: (&str, &str) = ("OP_SERVICE_ACCOUNT_TOKEN", "ops_test_token");

fn host() -> Host {
    Host::new(&["op"], json!({ "op": {} }))
}

fn run(host: &Host, args: &[&str]) -> Ran {
    host.run(args, &[TOKEN], None)
}

fn piped(host: &Host, args: &[&str], stdin: &str) -> Ran {
    host.run(args, &[TOKEN], Some(stdin.as_bytes()))
}

/// Each `op` call's arguments, joined.
fn op_lines(host: &Host) -> Vec<String> {
    host.calls()
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            c["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

fn kinds(error: &Value) -> Vec<&str> {
    error["error"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap_or("-"))
        .collect()
}

/// A vault item as `op item get` prints one optokens wrote, by hand.
fn stored(id: &str, title: &str, tags: Value, fields: Value) -> Value {
    json!({ "id": id, "title": title, "tags": tags, "category": "SECURE_NOTE",
            "vault": { "id": "v", "name": "optokens" },
            "sections": [{ "id": "fields", "label": "fields" }, { "id": "optokens", "label": "optokens" }],
            "fields": fields })
}

fn field(section: &str, label: &str, value: &str) -> Value {
    json!({ "id": format!("{section}.{label}"), "section": { "id": section, "label": section }, "type": "STRING", "label": label, "value": value })
}

fn seeded(items: Value) -> Host {
    Host::new(&["op"], json!({ "op": { "items": items } }))
}

#[test]
fn put_list_get_env_rm_a_profile() {
    let host = host();
    let put = piped(
        &host,
        &[
            "put",
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
        json!({ "secret": "glm/default", "changed": true, "kind": "profile",
                "fields": ["ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"] })
    );
    assert_eq!(
        op_lines(&host),
        [
            "item list --vault optokens --format json",
            "item create --vault optokens --format json -"
        ]
    );

    assert_eq!(
        host.field_types("glm/default"),
        json!({ "ANTHROPIC_BASE_URL": "STRING", "ANTHROPIC_AUTH_TOKEN": "CONCEALED" }),
        "--set is plain, stdin concealed"
    );

    // The same put again writes nothing.
    let again = piped(
        &host,
        &["put", "glm", "--field-from-stdin", "ANTHROPIC_AUTH_TOKEN"],
        "tok'en $HOME",
    );
    assert_eq!(again.json()["changed"], false);
    assert_eq!(
        op_lines(&host)[2..],
        [
            "item list --vault optokens --format json",
            "item get id1 --vault optokens --format json"
        ]
    );

    // One Field changes, the other is kept.
    let model = run(&host, &["put", "glm", "--set", "ANTHROPIC_MODEL=glm-4.6"]);
    assert_eq!(
        model.json()["fields"],
        json!([
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_MODEL"
        ])
    );
    assert_eq!(
        op_lines(&host).last().unwrap(),
        "item edit id1 --vault optokens --format json"
    );

    let list = run(&host, &["list"]);
    assert_eq!(list.code, 0);
    assert_eq!(
        list.json(),
        json!({ "secrets": [{ "service": "glm", "account": "default", "kind": "profile", "description": "Claude Code to GLM",
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
        json!({ "service": "glm", "account": "default", "kind": "profile", "description": "Claude Code to GLM",
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

    let rm = run(&host, &["rm", "glm"]);
    assert_eq!(
        rm.json(),
        json!({ "secret": "glm/default", "changed": true })
    );
    assert_eq!(
        op_lines(&host).last().unwrap(),
        "item delete id1 --vault optokens"
    );
    assert_eq!(
        run(&host, &["rm", "glm"]).json(),
        json!({ "secret": "glm/default", "changed": false })
    );
    assert_eq!(run(&host, &["list"]).json(), json!({ "secrets": [] }));

    let gone = run(&host, &["get", "glm"]);
    assert_eq!((gone.code, gone.stdout.as_str()), (2, ""));
    assert_eq!(kinds(&gone.error()), ["not_found"]);
    assert_eq!(
        gone.error()["error"][0]["fix"],
        "run `optokens list` to see what it has, or `optokens put` it"
    );

    let calls = host.calls();
    assert!(
        calls
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["token_in_env"] == true),
        "{calls}"
    );
}

/// A Field's type follows the way this put set it, both ways; one it does not
/// name keeps its own, and a stored item reads back as it was.
#[test]
fn a_fields_type_follows_how_its_value_came_in() {
    let concealed = |label: &str, value: &str| {
        let mut f = field("fields", label, value);
        f["type"] = json!("CONCEALED");
        f
    };
    let host = seeded(json!([stored(
        "id1",
        "app/default",
        json!(["optokens"]),
        json!([
            concealed("URL", "https://a"),
            concealed("TOKEN", "t"),
            field("fields", "USER", "u"),
            field("optokens", "kind", "static"),
            field("optokens", "shape", "fields")
        ])
    )]));
    let types = || host.field_types("app/default");
    assert_eq!(
        run(&host, &["get", "app", "--json"]).json()["fields"],
        json!({ "URL": "https://a", "TOKEN": "t", "USER": "u" })
    );
    assert_eq!(
        run(&host, &["put", "app", "--set", "URL=https://a"]).json()["changed"],
        true,
        "--set of the same value turns a concealed Field plain"
    );
    assert_eq!(
        types(),
        json!({ "URL": "STRING", "TOKEN": "CONCEALED", "USER": "STRING" })
    );
    assert_eq!(
        run(&host, &["put", "app", "--set", "URL=https://a"]).json()["changed"],
        false,
        "nor type nor value changes: nothing is written"
    );
    let piped_in = piped(
        &host,
        &["put", "app", "--field-from-stdin", "URL"],
        "https://b",
    );
    assert_eq!(piped_in.json()["changed"], true);
    assert_eq!(
        types(),
        json!({ "URL": "CONCEALED", "TOKEN": "CONCEALED", "USER": "STRING" })
    );
    assert_eq!(
        run(&host, &["get", "app", "--json"]).json()["fields"],
        json!({ "URL": "https://b", "TOKEN": "t", "USER": "u" }),
        "a type changes nothing optokens gives out"
    );
}

#[test]
fn an_account_and_a_vault_file_name_where_it_goes() {
    let host = host();
    std::fs::create_dir_all(host.config()).unwrap();
    std::fs::write(host.config().join("vault"), "team\n").unwrap();
    let put = piped(
        &host,
        &[
            "put",
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
    assert_eq!(
        op_lines(&host)[1],
        "item create --vault team --format json -"
    );
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
            field("fields", "value", "cf-token"),
            field("optokens", "kind", "static"),
            field("optokens", "shape", "value"),
        ])
    )]));
    let get = run(&host, &["get", "cloudflare"]);
    assert_eq!((get.code, get.stdout.as_str()), (0, "cf-token"));
    assert_eq!(
        run(&host, &["get", "cloudflare", "--json"]).json(),
        json!({ "service": "cloudflare", "account": "default", "kind": "static", "description": null, "value": "cf-token" })
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
        &["put", "cloudflare", "--field-from-stdin", "Token"],
        "x",
    );
    assert_eq!(kinds(&shape.json()), ["shape_change"]);
    let pipe = host.bash(
        r#""$OPTOKENS" put cloudflare --field-from-pipe Token=<(printf x)"#,
        &[TOKEN],
    );
    assert_eq!(kinds(&pipe.json()), ["shape_change"]);
    let described = run(&host, &["put", "cloudflare", "--description", "DNS edits"]);
    assert_eq!(
        described.json(),
        json!({ "secret": "cloudflare/default", "changed": true, "kind": "static", "fields": null })
    );
    assert_eq!(run(&host, &["get", "cloudflare"]).stdout, "cf-token");
}

/// The owner's promise: a secret's value is never in any process's command
/// line, and never in a temporary file. The stand-in `op` records, on each
/// call, its own arguments, every process's command line (`ps`), and every
/// file under `TMPDIR`.
#[test]
fn a_value_is_in_no_command_line_and_no_temporary_file() {
    const MARKER: &str = "MARKER-7f3a9c-never-in-argv";
    let host = host();
    let put = piped(
        &host,
        &[
            "put",
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
        &["put", "db", "--field-from-stdin", "Password"],
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
        r#"a=$A b=$B; unset A B; "$OPTOKENS" put db --field-from-pipe Key=<(printf %s "$a") --field-from-pipe Salt=<(printf %s "$b")"#,
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

    let calls = host.calls();
    let calls = calls.as_array().unwrap();
    assert!(calls.len() >= 7, "{calls:?}");
    let verbs: Vec<String> = op_lines(&host)
        .iter()
        .map(|l| l.split(' ').take(2).collect::<Vec<_>>().join(" "))
        .collect();
    assert!(
        verbs.contains(&"item create".to_string()) && verbs.contains(&"item edit".to_string()),
        "{verbs:?}"
    );
    for call in calls {
        assert!(
            !call["args"].to_string().contains("MARKER"),
            "a value in op's arguments: {call}"
        );
        let ps = call["seen"]["ps"].as_str().unwrap();
        // ps saw the processes: this very call of the stand-in among them.
        assert!(
            ps.contains(&format!("op {}", call["args"][0].as_str().unwrap())),
            "{ps}"
        );
        assert!(!ps.contains("MARKER"), "a value in a command line: {ps}");
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
        r#""$OPTOKENS" put deploy-db --set User=svc --field-from-pipe Password=<(printf 'p w\n') --field-from-pipe "SigningKey="<(printf k)"#,
        &[TOKEN],
    );
    assert_eq!(put.code, 0, "{}{}", put.stdout, put.stderr);
    assert_eq!(
        put.json()["fields"],
        json!(["User", "Password", "SigningKey"])
    );
    assert_eq!(
        op_lines(&host),
        [
            "item list --vault optokens --format json",
            "item create --vault optokens --format json -"
        ]
    );
    assert_eq!(
        host.field_types("deploy-db/default"),
        json!({ "User": "STRING", "Password": "CONCEALED", "SigningKey": "CONCEALED" })
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
            r#""$OPTOKENS" put db --field-from-pipe File={} --field-from-pipe Gone=/nonexistent/{MARKER} --field-from-pipe Inline={MARKER}-value --field-from-pipe Empty=<(printf '\n') --field-from-pipe {MARKER}"#,
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
    assert!(
        !refused.stdout.contains(MARKER) && !refused.stderr.contains(MARKER),
        "{}{}",
        refused.stdout,
        refused.stderr
    );
    assert_eq!(
        host.calls(),
        Value::Null,
        "no refusal before the vault calls op"
    );
    let twice = host.bash(
        r#"printf s | "$OPTOKENS" put db --set A=1 --field-from-stdin B --field-from-pipe A=<(printf x) --field-from-pipe B=<(printf y)"#,
        &[TOKEN],
    );
    assert_eq!(kinds(&twice.json()), ["duplicate_label", "duplicate_label"]);
    assert!(!op_lines(&host).iter().any(|l| l.contains("create")));
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
        "no refusal before the vault calls op"
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
        op_lines(&host),
        ["item list --vault optokens --format json"; 2],
        "one list for the described put, one for the refused names"
    );
    assert_eq!(run(&host, &["put", "p", "--set", "A=1"]).code, 0);
    let kind = run(&host, &["put", "p", "--kind", "profile", "--set", "A=1"]);
    assert_eq!(
        kind.json()["error"][0]["fix"],
        "run `optokens rm p`, then `put` it again with `--kind profile`"
    );
}

#[test]
fn without_a_token_nothing_reaches_op() {
    let host = host();
    let put = host.run(&["put", "db", "--set", "A=1"], &[], None);
    assert_eq!(kinds(&put.json()), ["no_token"]);
    let get = host.run(&["get", "db"], &[], None);
    assert_eq!((get.code, get.stdout.as_str()), (2, ""));
    assert_eq!(kinds(&get.error()), ["no_token"]);
    assert_eq!(host.calls(), Value::Null);
}

#[test]
fn an_item_optokens_did_not_write_is_refused_by_name() {
    let host = seeded(json!([
        stored(
            "s1",
            "github/default",
            json!(["personal"]),
            json!([field("fields", "value", "x")])
        ),
        stored(
            "s2",
            "bad/default",
            json!(["optokens"]),
            json!([
                field("optokens", "kind", "parent"),
                field("optokens", "shape", "value"),
                field("fields", "value", "x")
            ])
        ),
    ]));
    let put = run(&host, &["put", "github", "--set", "A=1"]);
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
    assert!(
        !op_lines(&host)
            .iter()
            .any(|l| l.starts_with("item create") || l.starts_with("item edit"))
    );
}

#[test]
fn an_op_that_fails_is_refused_with_what_it_said() {
    let host = Host::new(
        &["op"],
        json!({ "op": { "fail": { "create": 1 }, "stderr": "[ERROR] You do not have permission" } }),
    );
    let put = run(&host, &["put", "db", "--set", "A=1"]);
    assert_eq!(put.code, 2);
    assert_eq!(kinds(&put.json()), ["op_failed"]);
    assert_eq!(
        put.json()["error"][0]["fault"],
        "`op item create --vault optokens --format json -`: it exited 1: [ERROR] You do not have permission"
    );
    assert_eq!(
        put.json()["error"][0]["fix"],
        "run `optokens doctor`, and see that the service account can reach the vault `optokens`"
    );
    let missing = Host::new(&[], json!({}));
    let get = run(&missing, &["get", "db"]);
    assert_eq!(kinds(&get.error()), ["op_failed"]);
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
