//! `put` through the one-time link, the real binary: `tailscale` and `op`
//! replaced by the stand-in of `examples/standin.rs`. `tailscale ip` answers
//! a loopback address, so the test reads the link from put's stderr and
//! submits the form to it as a browser would.
#![cfg(unix)]

mod common;

use common::{Host, Ran};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::Child;
use std::sync::Arc;

const TOKEN: (&str, &str) = ("OP_SERVICE_ACCOUNT_TOKEN", "ops_test_token");
const DOMAIN: &str = "host.tail1234.ts.net";
/// A self-signed certificate and key for [`DOMAIN`], as `tailscale cert` prints them.
const PEM: &str = include_str!("fixtures/tailnet-cert.pem");

/// A host whose `tailscale` has the address 127.0.0.1, and `cert` as given.
fn tailnet(cert: Value, items: Value) -> Host {
    Host::new(
        &["op", "tailscale"],
        json!({ "op": { "items": items },
                "tailscale": { "ip": ["127.0.0.1"], "cert_domains": [DOMAIN], "cert": cert } }),
    )
}

fn no_cert() -> Value {
    json!({ "error": "Access denied: cert access denied" })
}

/// A `put` waiting on its link: the URL, and what it printed on stderr before it.
struct Waiting {
    child: Child,
    url: String,
    said: String,
    stderr: BufReader<std::process::ChildStderr>,
}

fn start(host: &Host, args: &[&str], env: &[(&str, &str)]) -> Waiting {
    let mut child = host.spawn(args, &[&[TOKEN], env].concat());
    drop(child.stdin.take());
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut said = String::new();
    let url = loop {
        let mut line = String::new();
        if stderr.read_line(&mut line).unwrap() == 0 {
            break None;
        }
        if line.starts_with("http") {
            break Some(line.trim().to_string());
        }
        said.push_str(&line);
    };
    match url {
        Some(url) => Waiting {
            child,
            url,
            said,
            stderr,
        },
        None => {
            let out = child.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            panic!("put ended before it printed a link: {said}{stdout}");
        }
    }
}

impl Waiting {
    fn finish(mut self) -> Ran {
        let mut rest = String::new();
        self.stderr.read_to_string(&mut rest).unwrap();
        let out = self.child.wait_with_output().unwrap();
        Ran {
            stderr: format!("{}{}\n{rest}", self.said, self.url),
            ..common::ran(out)
        }
    }

    /// The URL's port and path.
    fn port_and_path(&self) -> (u16, String) {
        let rest = self.url.split_once("://").unwrap().1;
        let (authority, path) = rest.split_at(rest.find('/').unwrap());
        let port = authority.rsplit_once(':').unwrap().1.parse().unwrap();
        (port, path.to_string())
    }

    /// One request to the link, over TLS when it is HTTPS: its status and body.
    fn request(&self, method: &str, body: &str) -> (u16, String) {
        let (port, path) = self.port_and_path();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut response = Vec::new();
        if self.url.starts_with("https://") {
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls_graviola::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned))
            .with_no_client_auth();
            let name = DOMAIN.try_into().unwrap();
            let connection = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
            let mut tls = rustls::StreamOwned::new(connection, tcp);
            tls.write_all(request.as_bytes()).unwrap();
            let _ = tls.read_to_end(&mut response);
        } else {
            let mut tcp = tcp;
            tcp.write_all(request.as_bytes()).unwrap();
            tcp.read_to_end(&mut response).unwrap();
        }
        let response = String::from_utf8(response).unwrap();
        let status = response[9..12].parse().unwrap();
        let body = response.split_once("\r\n\r\n").unwrap().1.to_string();
        (status, body)
    }
}

/// Trusts exactly the fixture's certificate, and checks the server holds its key.
#[derive(Debug)]
struct Pinned;

fn fixture_der() -> Vec<u8> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    CertificateDer::from_pem_slice(PEM.as_bytes())
        .unwrap()
        .to_vec()
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        name: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        assert_eq!(name.to_str(), DOMAIN);
        assert_eq!(end_entity.as_ref(), fixture_der().as_slice());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = rustls_graviola::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, &algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let algorithms = rustls_graviola::default_provider().signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, &algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls_graviola::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn kinds(answer: &Value) -> Vec<&str> {
    answer["error"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap_or("-"))
        .collect()
}

/// Each `op` call's first two words.
fn op_verbs(host: &Host) -> Vec<String> {
    host.calls()
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["program"] == "op")
        .map(|c| {
            let args = c["args"].as_array().unwrap();
            format!(
                "{} {}",
                args[0].as_str().unwrap(),
                args[1].as_str().unwrap()
            )
        })
        .collect()
}

fn get(host: &Host, args: &[&str]) -> Ran {
    host.run(args, &[TOKEN], None)
}

/// The owner's promise, through the link: a value submitted reaches `op`
/// only on its stdin. It is in no command line (`ps`, as the stand-in `op`
/// sees it on each call), no temporary file, and neither of put's outputs.
#[test]
fn fields_over_plain_http_store_once_and_a_second_post_is_gone() {
    const MARKER: &str = "MARKER-5c1e-through-the-link";
    let host = tailnet(no_cert(), json!([]));
    let waiting = start(
        &host,
        &[
            "put",
            "db",
            "--fields",
            "Password, User",
            "--show",
            "User",
            "--set",
            "Host=db.internal",
            "--description",
            "CI database",
        ],
        &[("USER", "ci-runner")],
    );
    assert!(
        waiting.said.contains("optokens: plain HTTP on the tailnet, which WireGuard encrypts, because `tailscale cert` failed: it exited 1: Access denied: cert access denied. For HTTPS, an admin runs `sudo tailscale set --operator=ci-runner` once"),
        "{}",
        waiting.said
    );
    assert!(
        waiting.said.ends_with(
            "optokens: open this link to enter the secret for db / default (it works once, within 10 minutes):\n"
        ),
        "{}",
        waiting.said
    );
    let (port, path) = waiting.port_and_path();
    assert_eq!(waiting.url, format!("http://127.0.0.1:{port}{path}"));
    assert_eq!(path.len(), 33, "{path}");
    assert_eq!(
        op_verbs(&host),
        ["item list"],
        "the vault is read before the link"
    );

    let (status, page) = waiting.request("GET", "");
    assert_eq!(status, 200);
    assert!(
        page.contains("<h1>db/default</h1>") && page.contains("CI database"),
        "{page}"
    );
    assert!(page.contains(r#"name="f0" type="password""#), "{page}");
    assert!(page.contains(r#"name="f1" type="text""#), "{page}");

    // `op` slow to store, so the link is still served when the second POST comes.
    let mut state = host.state();
    state["op"]["hang_ms"] = json!(1500);
    host.set_state(&state);
    let form = format!("f0={MARKER}&f1=svc");
    let (status, sent) = waiting.request("POST", &form);
    assert_eq!(status, 200, "{sent}");
    assert!(sent.contains("This link no longer works."), "{sent}");
    let (again, said) = waiting.request("POST", "f0=other&f1=other");
    assert_eq!(again, 410);
    assert_eq!(
        said,
        "This link was already used. Nothing more is accepted.\n"
    );

    let put = waiting.finish();
    assert_eq!(put.code, 0, "{}{}", put.stdout, put.stderr);
    assert_eq!(
        put.json(),
        json!({ "secret": "db/default", "changed": true, "kind": "static", "fields": ["Host", "Password", "User"] })
    );
    assert!(
        !put.stdout.contains(MARKER) && !put.stderr.contains(MARKER),
        "{}",
        put.stderr
    );
    let mut state = host.state();
    state["op"]["hang_ms"] = Value::Null;
    host.set_state(&state);
    let stored = get(&host, &["get", "db", "--json"]);
    assert_eq!(
        stored.json()["fields"],
        json!({ "Host": "db.internal", "Password": MARKER, "User": "svc" })
    );
    assert_eq!(stored.json()["description"], "CI database");

    let calls = host.calls();
    for call in calls
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["program"] == "op")
    {
        assert!(!call["args"].to_string().contains(MARKER), "{call}");
        let ps = call["seen"]["ps"].as_str().unwrap();
        assert!(ps.contains("op item"), "{ps}");
        assert!(!ps.contains(MARKER), "a value in a command line: {ps}");
        assert!(!call["seen"]["tmp"].to_string().contains(MARKER), "{call}");
    }
    assert!(op_verbs(&host).contains(&"item create".to_string()));
}

#[test]
fn a_bare_put_over_https_stores_one_value() {
    let host = tailnet(json!({ "pem": PEM }), json!([]));
    let waiting = start(&host, &["put", "cloudflare"], &[]);
    assert_eq!(
        waiting.said,
        "optokens: open this link to enter the secret for cloudflare / default (it works once, within 10 minutes):\n"
    );
    let (port, path) = waiting.port_and_path();
    assert_eq!(waiting.url, format!("https://{DOMAIN}:{port}{path}"));
    let (status, page) = waiting.request("GET", "");
    assert_eq!(status, 200);
    assert!(page.contains(r#"<label for="f0">value</label>"#), "{page}");
    let (empty, again) = waiting.request("POST", "f0=");
    assert_eq!(empty, 400);
    assert!(again.contains("Every field needs a value."), "{again}");
    assert_eq!(waiting.request("POST", "f0=cf%2Btoken").0, 200);
    let put = waiting.finish();
    assert_eq!(put.code, 0, "{}", put.stderr);
    assert_eq!(
        put.json(),
        json!({ "secret": "cloudflare/default", "changed": true, "kind": "static", "fields": null })
    );
    assert_eq!(get(&host, &["get", "cloudflare"]).stdout, "cf+token");
    let cert = host
        .calls()
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["args"][0] == "cert")
        .cloned();
    assert_eq!(
        cert.unwrap()["args"],
        json!(["cert", "--cert-file", "-", "--key-file", "-", DOMAIN])
    );
}

#[test]
fn a_field_not_named_is_kept_and_shown_only_as_already_set() {
    let host = tailnet(no_cert(), json!([]));
    let first = host.run(
        &[
            "put",
            "aws",
            "--set",
            "Access Key ID=AKIA-kept",
            "--field-from-stdin",
            "Secret",
        ],
        &[TOKEN],
        Some(b"old-secret"),
    );
    assert_eq!(first.code, 0, "{}", first.stdout);
    let waiting = start(&host, &["put", "aws", "--fields", "Secret"], &[]);
    let (_, page) = waiting.request("GET", "");
    assert!(page.contains("<b>Access Key ID</b>: already set"), "{page}");
    assert!(
        !page.contains("AKIA-kept") && !page.contains("old-secret"),
        "{page}"
    );
    assert_eq!(waiting.request("POST", "f0=new-secret").0, 200);
    let put = waiting.finish();
    assert_eq!(put.json()["fields"], json!(["Access Key ID", "Secret"]));
    assert_eq!(
        get(&host, &["get", "aws", "--json"]).json()["fields"],
        json!({ "Access Key ID": "AKIA-kept", "Secret": "new-secret" })
    );
}

#[test]
fn a_link_not_submitted_in_time_stores_nothing() {
    let host = tailnet(no_cert(), json!([]));
    let waiting = start(
        &host,
        &["put", "db", "--fields", "Password"],
        &[("OPTOKENS_TEST_LINK_LIFETIME_MS", "300")],
    );
    let put = waiting.finish();
    assert_eq!(put.code, 2, "{}", put.stdout);
    assert_eq!(kinds(&put.json()), ["link_expired"]);
    assert_eq!(
        put.json()["error"][0]["fault"],
        "no value was submitted on the one-time link for `db/default` before it expired, so nothing was stored"
    );
    assert_eq!(
        put.json()["error"][0]["fix"],
        "run the same `optokens put` again, and open its new link sooner"
    );
    assert_eq!(op_verbs(&host), ["item list"]);
}

#[test]
fn without_a_tailnet_nothing_is_stored_and_the_vault_is_not_read() {
    let missing = Host::new(&["op"], json!({}));
    let put = get(&missing, &["put", "db", "--fields", "Password"]);
    assert_eq!(put.code, 2);
    assert_eq!(kinds(&put.json()), ["tailscale_missing"]);
    assert_eq!(
        put.json()["error"][0]["fault"],
        "no one-time link can be served, so nothing is stored: `tailscale` is not on PATH"
    );
    assert_eq!(missing.calls(), Value::Null);

    let down = Host::new(&["op", "tailscale"], json!({ "tailscale": { "ip": [] } }));
    let bare = get(&down, &["put", "db"]);
    assert_eq!(kinds(&bare.json()), ["no_tailnet_address"]);
    assert_eq!(bare.json()["error"][0]["fix"], "run `tailscale up`");

    // An address of the tailnet that is on no interface of this host.
    let elsewhere = Host::new(
        &["op", "tailscale"],
        json!({ "tailscale": { "ip": ["192.0.2.7"] } }),
    );
    let put = get(&elsewhere, &["put", "db", "--fields", "Password"]);
    assert_eq!(put.code, 2);
    assert_eq!(
        put.json()["error"][0]["fault"],
        "no one-time link can be served, so nothing is stored: the tailnet address 192.0.2.7 is on no interface of this host"
    );
    for host in [&down, &elsewhere] {
        assert!(op_verbs(host).is_empty(), "{}", host.calls());
    }
}

#[test]
fn every_fault_of_the_command_line_is_refused_before_the_link() {
    let host = Host::new(&["op"], json!({}));
    let put = get(
        &host,
        &["put", "a/b", "--show", "User", "--set", "NOEQUALS"],
    );
    assert_eq!(kinds(&put.json()), ["bad_name", "bad_set", "bad_show"]);
    let both = get(&host, &["put", "p", "--fields", "Token", "--show", "User"]);
    assert_eq!(kinds(&both.json()), ["bad_show", "tailscale_missing"]);
    assert_eq!(
        both.json()["error"][0]["fault"],
        "`--show` names `User`, which `--fields` does not"
    );
    assert_eq!(
        both.json()["error"][0]["fix"],
        "name each `--show` label in `--fields` too"
    );
    let tailnet = tailnet(no_cert(), json!([]));
    let named = get(
        &tailnet,
        &[
            "put", "p", "--kind", "profile", "--fields", "1X,A", "--set", "A=1",
        ],
    );
    assert_eq!(kinds(&named.json()), ["not_env_name", "duplicate_label"]);
    assert!(
        !tailnet.calls().to_string().contains("\"cert\""),
        "no link is served for a refused put"
    );
}
