//! The link's rules with no socket: the clock is an argument, so expiry needs no wait.

use super::*;
use proptest::prelude::*;
use std::net::IpAddr;
use std::time::UNIX_EPOCH;

fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

fn field(label: &str, input: Input) -> Field {
    Field {
        label: label.into(),
        input,
    }
}

fn link_of(fields: Vec<Field>, description: Option<&str>) -> Link {
    Link::new(
        "svc",
        "default",
        description,
        fields,
        Token::fresh(),
        t0(),
        LIFETIME,
    )
}

fn link() -> Link {
    link_of(vec![field("Token", Input::Password)], Some("CI deploy"))
}

fn get(target: &str) -> Request<'_> {
    Request {
        method: "GET",
        target,
        body: b"",
    }
}

fn post<'a>(target: &'a str, body: &'a str) -> Request<'a> {
    Request {
        method: "POST",
        target,
        body: body.as_bytes(),
    }
}

fn values(pairs: &[(&str, &str)]) -> Option<Values> {
    Some(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

#[test]
fn a_token_is_32_lowercase_hex_digits_fresh_each_time_and_the_whole_path() {
    let tokens: std::collections::BTreeSet<String> = (0..1000).map(|_| Token::fresh().0).collect();
    assert_eq!(tokens.len(), 1000, "a token repeated");
    for t in &tokens {
        assert_eq!(t.len(), 32, "{t}");
        assert!(t.chars().all(|c| "0123456789abcdef".contains(c)), "{t}");
    }
    let link = link();
    assert_eq!(link.path(), format!("/{}", link.token.0));
    assert_eq!(LIFETIME, Duration::from_secs(600));
}

#[test]
fn the_right_token_submits_once_then_every_request_is_gone() {
    let mut link = link();
    let path = link.path();
    let (first, submitted) = link.handle(&post(&path, "f0=s3cr%26t+x"), t0());
    assert_eq!(first.status, 200);
    assert!(
        first.body.contains("<h1>svc/default</h1>"),
        "{}",
        first.body
    );
    assert!(
        first.body.contains("This link no longer works."),
        "{}",
        first.body
    );
    assert!(!first.body.contains("s3cr"), "the value is echoed");
    assert_eq!(submitted, values(&[("Token", "s3cr&t x")]));
    for request in [post(&path, "f0=other"), get(&path)] {
        let (again, submitted) = link.handle(&request, t0());
        assert_eq!((again.status, submitted), (410, None));
        assert!(again.body.contains("already used"), "{}", again.body);
    }
}

#[test]
fn it_expires_at_exactly_ten_minutes_and_stores_nothing() {
    let mut link = link();
    let path = link.path();
    let just_before = t0() + LIFETIME - Duration::from_nanos(1);
    assert_eq!(link.handle(&get(&path), just_before).0.status, 200);
    let (late, submitted) = link.handle(&post(&path, "f0=late"), t0() + LIFETIME);
    assert_eq!((late.status, submitted), (410, None));
    assert!(
        late.body.contains("expired. Nothing was stored"),
        "{}",
        late.body
    );
}

#[test]
fn a_wrong_path_is_not_found_and_tells_a_stranger_nothing() {
    let mut link = link();
    let path = link.path();
    let mut wrong = path.clone();
    let last = if wrong.pop() == Some('0') { '1' } else { '0' };
    wrong.push(last);
    for target in [
        wrong.as_str(),
        "/",
        "/favicon.ico",
        &format!("{path}x"),
        &path[..32],
    ] {
        let (r, submitted) = link.handle(&post(target, "f0=evil"), t0());
        assert_eq!((r.status, submitted), (404, None), "{target}");
        assert!(!r.body.contains("svc"), "{target}");
    }
    assert_eq!(
        link.handle(&post(&path, "f0=good"), t0()).1,
        values(&[("Token", "good")])
    );
}

#[test]
fn paths_differing_in_several_bytes_are_not_the_same() {
    // Each pair's byte differences cancel under XOR: only an OR of them catches both.
    assert!(!same(b"ab", b"ba"));
    assert!(!same(b"/01", b"/10"));
    assert!(same(b"/ab", b"/ab"));
    assert!(!same(b"/ab", b"/abc"));
}

#[test]
fn another_method_is_not_allowed_and_uses_nothing() {
    let mut link = link();
    let path = link.path();
    for method in ["PUT", "DELETE", "HEAD"] {
        let request = Request {
            method,
            target: &path,
            body: b"f0=x",
        };
        let (r, submitted) = link.handle(&request, t0());
        assert_eq!((r.status, submitted), (405, None), "{method}");
    }
    assert!(!link.used);
}

#[test]
fn an_empty_field_asks_again_without_using_the_link() {
    let mut link = link_of(
        vec![
            field("Access Key ID", Input::Text),
            field("Secret", Input::Password),
        ],
        None,
    );
    let path = link.path();
    for body in ["f0=AKIA&f1=", "f0=AKIA"] {
        let (r, submitted) = link.handle(&post(&path, body), t0());
        assert_eq!((r.status, submitted), (400, None), "{body}");
        assert!(r.body.contains("Every field needs a value."), "{body}");
        assert!(r.body.contains("<form"), "{body}");
    }
    assert!(!link.used);
    assert_eq!(
        link.handle(&post(&path, "f0=AKIA&f1=s"), t0()).1,
        values(&[("Access Key ID", "AKIA"), ("Secret", "s")])
    );
}

#[test]
fn the_page_names_the_secret_and_has_an_input_per_asked_field() {
    let mut link = link_of(
        vec![
            field("Access Key ID", Input::Text),
            field("Secret <Key>", Input::Password),
            field("Region", Input::AlreadySet),
        ],
        Some("deploy & <b>sync</b>"),
    );
    let path = link.path();
    let (page, _) = link.handle(&get(&format!("{path}?x=1")), t0());
    assert_eq!(page.status, 200);
    assert_eq!(page.content_type, "text/html; charset=utf-8");
    let body = &page.body;
    assert!(body.contains("<h1>svc/default</h1>"), "{body}");
    assert!(
        body.contains("deploy &amp; &lt;b&gt;sync&lt;/b&gt;"),
        "{body}"
    );
    assert!(
        body.contains(r#"<label for="f0">Access Key ID</label>"#),
        "{body}"
    );
    assert!(
        body.contains(r#"<label for="f1">Secret &lt;Key&gt;</label>"#),
        "{body}"
    );
    assert!(body.contains(r#"name="f0" type="text""#), "{body}");
    assert!(body.contains(r#"name="f1" type="password""#), "{body}");
    assert!(body.contains("<b>Region</b>: already set"), "{body}");
    assert!(!body.contains(r#"name="f2""#), "{body}");
    assert_eq!(body.matches("<input").count(), 2, "{body}");
    assert!(body.contains(&format!(r#"action="{path}""#)), "{body}");
    assert!(body.contains("expires 10 minutes after"), "{body}");
    // Only the asked Fields come back: a posted value for the set one is not taken.
    assert_eq!(
        link.handle(&post(&path, "f0=a&f1=b&f2=c"), t0()).1,
        values(&[("Access Key ID", "a"), ("Secret <Key>", "b")])
    );
}

#[test]
fn every_piece_of_text_is_escaped() {
    assert_eq!(
        page::escape(r#"<a href="x">'&'</a>"#),
        "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
    );
    let mut link = Link::new(
        "<s>",
        "a&b",
        None,
        vec![field("\"", Input::Password)],
        Token::fresh(),
        t0(),
        LIFETIME,
    );
    let path = link.path();
    let body = link.handle(&get(&path), t0()).0.body;
    assert!(body.contains("<h1>&lt;s&gt;/a&amp;b</h1>"), "{body}");
    assert!(body.contains(r#"<label for="f0">&quot;</label>"#), "{body}");
    assert!(!body.contains("class=\"about\""), "{body}");
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn it_listens_on_the_tailnet_address_only_ipv4_first() {
    let interfaces = [
        ip("127.0.0.1"),
        ip("192.168.1.5"),
        ip("fd7a:115c::1"),
        ip("100.64.0.7"),
    ];
    let answer = "100.64.0.7\nfd7a:115c::1\n";
    assert_eq!(
        listen_address(&interfaces, Some(answer)),
        Ok(ip("100.64.0.7"))
    );
    assert_eq!(
        listen_address(&interfaces, Some("fd7a:115c::1\n100.64.0.7\n")),
        Ok(ip("100.64.0.7"))
    );
    assert_eq!(
        listen_address(&interfaces[..3], Some(answer)),
        Ok(ip("fd7a:115c::1"))
    );
}

#[test]
fn without_tailscale_or_a_tailnet_address_nothing_is_stored_and_it_says_what_is_missing() {
    let interfaces = [ip("127.0.0.1"), ip("192.168.1.5")];
    let cases = [
        (None, "`tailscale` is not on PATH", "install Tailscale"),
        (
            Some(""),
            "`tailscale ip`: it printed no address",
            "`tailscale up`",
        ),
        (
            Some("100.64.0.7\n"),
            "the tailnet address 100.64.0.7 is on no interface",
            "userspace-networking",
        ),
    ];
    for (answer, missing, fix) in cases {
        let refusal = listen_address(&interfaces, answer).unwrap_err();
        assert!(
            refusal
                .fault
                .starts_with("no one-time link can be served, so nothing is stored: "),
            "{refusal:?}"
        );
        assert!(refusal.fault.contains(missing), "{refusal:?}");
        assert!(refusal.fix.contains(fix), "{refusal:?}");
    }
}

#[test]
fn a_certificate_means_https_else_plain_http_with_why_and_the_fix() {
    assert_eq!(scheme::<&str>(Ok("cert"), "felix"), Scheme::Https("cert"));
    let Scheme::Http { reason } =
        scheme::<&str>(Err("Access denied: cert access denied".into()), "felix")
    else {
        panic!("not plain HTTP");
    };
    assert!(reason.contains("plain HTTP on the tailnet"), "{reason}");
    assert!(
        reason.contains("Access denied: cert access denied"),
        "{reason}"
    );
    assert!(
        reason.contains("`sudo tailscale set --operator=felix`"),
        "{reason}"
    );
    assert!(reason.contains("HTTPS Certificates"), "{reason}");
}

proptest! {
    #[test]
    fn any_other_path_is_not_found_and_consumes_nothing(target in "/[0-9a-f]{0,40}", body in ".*") {
        let mut link = link();
        let path = link.path();
        prop_assume!(target.split('?').next() != Some(path.as_str()));
        let (r, submitted) = link.handle(&post(&target, &body), t0());
        prop_assert_eq!((r.status, submitted), (404, None));
        prop_assert!(!link.used);
    }

    #[test]
    fn before_ten_minutes_it_answers_from_then_on_it_is_gone(secs in 0u64..1200) {
        let mut link = link();
        let path = link.path();
        let status = link.handle(&get(&path), t0() + Duration::from_secs(secs)).0.status;
        prop_assert_eq!(status, if secs < 600 { 200 } else { 410 });
    }

    #[test]
    fn a_submitted_value_comes_back_whole(value in ".{1,40}") {
        let mut link = link();
        let path = link.path();
        let body: String = form_urlencoded::Serializer::new(String::new()).append_pair("f0", &value).finish();
        let (sent, submitted) = link.handle(&post(&path, &body), t0());
        prop_assert_eq!(sent.status, 200);
        prop_assert_eq!(submitted, values(&[("Token", &value)]));
    }

    #[test]
    fn escaped_text_has_no_markup(text in ".*") {
        let escaped = page::escape(&text);
        prop_assert!(!escaped.contains(['<', '>', '"', '\'']));
    }
}
