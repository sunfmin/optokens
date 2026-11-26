//! The one-time link's rules, with no sockets (ADR 0008): a fresh token, one
//! submission of the one Secret it was made for, until it expires. What serves
//! it hands [`Link::handle`] each request and the time, and sends the response
//! it answers; the values come back once. Where it listens and over which
//! scheme are [`listen_address`] and [`scheme`].

mod endpoint;
mod page;

pub use endpoint::{Scheme, listen_address, nothing_stored, scheme};

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

/// How long a link takes a submission: the code, the page and the help say this one.
pub const LIFETIME: Duration = Duration::from_secs(10 * 60);

/// 128 bits from the OS's CSPRNG, as 32 lowercase hex digits: the whole of a link's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    pub fn fresh() -> Token {
        Token(random_hex(16))
    }
}

/// `bytes` bytes from the OS's CSPRNG, as lowercase hex digits.
pub fn random_hex(bytes: usize) -> String {
    let mut random = vec![0u8; bytes];
    getrandom::fill(&mut random).expect("the OS gives no random bytes");
    random.iter().map(|b| format!("{b:02x}")).collect()
}

/// A Field of the Secret, as the page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub label: String,
    pub input: Input,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// A secret value: a password input.
    Password,
    /// A `--show` Field: a plain text input.
    Text,
    /// Shown, not asked for, its value never on the page.
    AlreadySet,
}

/// The parts of a request the link reads.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    /// The request target: the path, with any query.
    pub target: &'a str,
    /// `application/x-www-form-urlencoded`, as a browser posts a form.
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl Response {
    fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            content_type: "text/plain; charset=utf-8",
            body: format!("{body}\n"),
        }
    }

    /// A request that could not be read, refused with `status`.
    pub fn bad(status: u16) -> Response {
        Response::text(status, "Bad request.")
    }

    fn html(status: u16, body: String) -> Response {
        Response {
            status,
            content_type: "text/html; charset=utf-8",
            body,
        }
    }
}

/// A submission: each asked Field's label and the value entered for it.
pub type Values = BTreeMap<String, String>;

/// One-time link for what one command asks: a Secret's Fields, or `init`'s token.
#[derive(Debug)]
pub struct Link {
    /// What the page is for: a Secret's `<service>/<account>`.
    title: String,
    description: Option<String>,
    fields: Vec<Field>,
    token: Token,
    expires: SystemTime,
    used: bool,
}

impl Link {
    /// A link titled `title` (a Secret's `<service>/<account>`), made at
    /// `made` with `token`, that takes a submission for `lifetime`:
    /// [`LIFETIME`], but in a test.
    pub fn new(
        title: &str,
        description: Option<&str>,
        fields: Vec<Field>,
        token: Token,
        made: SystemTime,
        lifetime: Duration,
    ) -> Link {
        Link {
            title: title.to_string(),
            description: description.map(String::from),
            fields,
            token,
            expires: made + lifetime,
            used: false,
        }
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    /// When it stops taking a submission.
    pub fn expires(&self) -> SystemTime {
        self.expires
    }

    /// The path the link serves: `/` and its token.
    pub fn path(&self) -> String {
        format!("/{}", self.token.0)
    }

    /// One request in, one response out, and the values for the first complete
    /// POST with the right token before expiry; never again after it.
    pub fn handle(&mut self, request: &Request, now: SystemTime) -> (Response, Option<Values>) {
        let path = request.target.split('?').next().unwrap_or_default();
        if !same(path.as_bytes(), self.path().as_bytes()) {
            return (Response::text(404, "Not found."), None);
        }
        if self.used {
            let gone = "This link was already used. Nothing more is accepted.";
            return (Response::text(410, gone), None);
        }
        if now >= self.expires {
            let gone = "This link expired. Nothing was stored.";
            return (Response::text(410, gone), None);
        }
        match request.method {
            "GET" => (Response::html(200, page::form(self, None)), None),
            "POST" => self.submit(request.body),
            _ => (Response::text(405, "Method not allowed."), None),
        }
    }

    fn submit(&mut self, body: &[u8]) -> (Response, Option<Values>) {
        let form: BTreeMap<String, String> = form_urlencoded::parse(body).into_owned().collect();
        let values: Values = self
            .asked()
            .map(|(i, f)| {
                let value = form.get(&page::input_name(i)).cloned().unwrap_or_default();
                (f.label.clone(), value)
            })
            .collect();
        if values.values().any(String::is_empty) {
            let again = page::form(self, Some("Every field needs a value."));
            return (Response::html(400, again), None);
        }
        self.used = true;
        (Response::html(200, page::sent(self)), Some(values))
    }

    /// The Fields the page asks for, by their index.
    fn asked(&self) -> impl Iterator<Item = (usize, &Field)> {
        let asked = |(_, f): &(usize, &Field)| f.input != Input::AlreadySet;
        self.fields.iter().enumerate().filter(asked)
    }
}

/// Equal, in a time that depends on the lengths only: no early exit on the
/// first byte that differs, so timing says nothing of the token.
fn same(a: &[u8], b: &[u8]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y));
    a.len() == b.len() && std::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests;
