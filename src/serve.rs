//! Serving a one-time link (ADR 0008): it binds only the tailnet address
//! `tailscale ip` names, gets a certificate from `tailscale cert` or says why
//! it serves plain HTTP, prints the link on stderr, and answers each request
//! with what [`Link::handle`] decides. The values submitted come back to the
//! caller in memory, and are never printed, logged or written to a file.

use crate::doctor::{no_tailnet_address, tailscale_missing};
use crate::link::{self, Link, Request, Response, Scheme, Values};
use crate::program;
use crate::refusal::Refusal;
use crate::secret::Fault;
use crate::tailscale;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime};

/// How long `tailscale ip` and `status` have to answer.
const ASK_BOUND: Duration = Duration::from_secs(10);
/// How long `tailscale cert` has: it may reach Let's Encrypt.
const CERT_BOUND: Duration = Duration::from_secs(60);
/// How long one connection may take to send its request or read the answer.
const IO_BOUND: Duration = Duration::from_secs(10);
/// The most of a request's head, and of its body, read.
const HEAD_MAX: usize = 16 * 1024;
const BODY_MAX: usize = 64 * 1024;

/// The tailnet address, bound, and the `tailscale` that named it.
pub struct Endpoint {
    tailscale: PathBuf,
    listener: TcpListener,
}

impl Endpoint {
    /// Binds the tailnet address `tailscale ip` names that is on this host,
    /// IPv4 first; an address is on this host when it can be bound. Refused,
    /// naming what is missing, when there is none.
    pub fn open(path: Option<&OsStr>) -> Result<Endpoint, Refusal> {
        let Some(tailscale) = program::find(tailscale::PROGRAM, path) else {
            return Err(link::nothing_stored(tailscale_missing()));
        };
        let answer = ask(&tailscale, tailscale::IP, ASK_BOUND)
            .map_err(|why| link::nothing_stored(no_tailnet_address(&why)))?;
        let listener = link::listen_address(|a| TcpListener::bind((a, 0)).ok(), Some(&answer))?;
        Ok(Endpoint {
            tailscale,
            listener,
        })
    }

    /// Serves `link` until its one submission, which it answers, or its
    /// expiry, refused as `link_expired` with the fix of running `command`
    /// again. It prints the link on stderr first, saying it is to enter
    /// `what`, with why it is plain HTTP when it is. Later requests are
    /// answered "already used" until optokens exits.
    pub fn serve(self, link: Link, what: &str, command: &str) -> Result<Values, Refusal> {
        let address = self.listener.local_addr().map_err(io_refusal)?;
        let port = address.port();
        let (url, tls) = match link::scheme(certificate(&self.tailscale), &user()) {
            Scheme::Https((domain, config)) => (
                format!("https://{domain}:{port}{}", link.path()),
                Some(config),
            ),
            Scheme::Http { reason } => {
                eprintln!("optokens: {reason}");
                (format!("http://{address}{}", link.path()), None)
            }
        };
        eprintln!(
            "optokens: open this link to enter {what} (it works once, within {} minutes):\n{url}",
            link::LIFETIME.as_secs() / 60
        );
        let expires = link.expires();
        let title = link.title().to_string();
        let (sent, values) = mpsc::channel();
        let link = Arc::new(Mutex::new(link));
        let listener = self.listener;
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (link, sent, tls) = (link.clone(), sent.clone(), tls.clone());
                std::thread::spawn(move || {
                    if let Some(values) = answer(stream, &link, tls) {
                        let _ = sent.send(values);
                    }
                });
            }
        });
        let left = expires
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        // A submission handled at the very end is taken, never dropped.
        values
            .recv_timeout(left)
            .or_else(|_| values.try_recv())
            .map_err(|_| {
                Refusal::of(
                    &Fault::LinkExpired,
                    format!(
                        "no value was submitted on the one-time link for `{title}` before it expired, so nothing was stored"
                    ),
                    format!("run the same `optokens {command}` again, and open its new link sooner"),
                )
            })
    }
}

fn io_refusal(e: std::io::Error) -> Refusal {
    link::nothing_stored(Refusal::new(
        format!("the bound tailnet address: {e}"),
        "run `optokens doctor`",
    ))
}

/// `tailscale <args>`'s stdout, or why it gave none.
fn ask(tailscale: &Path, args: &[&str], bound: Duration) -> Result<String, String> {
    let mut command = Command::new(tailscale);
    command.args(args).env_remove(crate::account::TOKEN_ENV);
    let ran = program::bounded(command, None, bound)?;
    if ran.status.success() {
        Ok(ran.stdout)
    } else {
        let code = ran
            .status
            .code()
            .map_or("on a signal".to_string(), |c| c.to_string());
        Err(format!("it exited {code}: {}", ran.stderr.trim()))
    }
}

/// The user optokens runs as, for the operator fix.
fn user() -> String {
    ["USER", "USERNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|u| !u.is_empty()))
        .unwrap_or_else(|| "$USER".into())
}

/// This host's tailnet name and a TLS configuration with its certificate from
/// `tailscale cert`, which prints both on its stdout; or why not.
fn certificate(tailscale: &Path) -> Result<(String, Arc<ServerConfig>), String> {
    let status = ask(tailscale, tailscale::STATUS, ASK_BOUND)
        .map_err(|why| format!("`tailscale status --json`: {why}"))?;
    let domain = tailscale::cert_domains(&status)
        .map_err(|why| format!("`tailscale status --json`: {why}"))?
        .into_iter()
        .next()
        .ok_or_else(|| {
            format!(
                "`tailscale status --json` lists no `{}`, so there is no name to get one for",
                tailscale::CERT_DOMAINS
            )
        })?;
    let args: Vec<&str> = tailscale::CERT.iter().copied().chain([&*domain]).collect();
    let pem = ask(tailscale, &args, CERT_BOUND)?;
    let chain: Vec<CertificateDer> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("its certificate does not parse: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| format!("its key does not parse: {e}"))?;
    let config = ServerConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
        .with_safe_default_protocol_versions()
        .and_then(|b| b.with_no_client_auth().with_single_cert(chain, key))
        .map_err(|e| format!("its certificate cannot serve TLS: {e}"))?;
    Ok((domain, Arc::new(config)))
}

/// One connection: its one request read, answered and closed; the values,
/// when it was the submission.
fn answer(stream: TcpStream, link: &Mutex<Link>, tls: Option<Arc<ServerConfig>>) -> Option<Values> {
    let _ = stream.set_read_timeout(Some(IO_BOUND));
    let _ = stream.set_write_timeout(Some(IO_BOUND));
    match tls {
        None => exchange(stream, link),
        Some(config) => {
            let connection = rustls::ServerConnection::new(config).ok()?;
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let values = exchange(&mut stream, link);
            stream.conn.send_close_notify();
            let _ = stream.flush();
            values
        }
    }
}

fn exchange(mut stream: impl Read + Write, link: &Mutex<Link>) -> Option<Values> {
    let (response, values) = match read_request(&mut stream) {
        Ok((method, target, body)) => {
            let request = Request {
                method: &method,
                target: &target,
                body: &body,
            };
            let mut link = link.lock().unwrap_or_else(|e| e.into_inner());
            link.handle(&request, SystemTime::now())
        }
        Err(status) => (Response::bad(status), None),
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nConnection: close\r\n\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len()
    );
    let _ = stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(response.body.as_bytes()))
        .and_then(|_| stream.flush());
    values
}

/// The request's method, target and body; or the status refusing it.
fn read_request(stream: &mut impl Read) -> Result<(String, String, Vec<u8>), u16> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        if data.len() > HEAD_MAX {
            return Err(431);
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(400),
            Ok(n) => data.extend_from_slice(&chunk[..n]),
        }
    };
    let head = std::str::from_utf8(&data[..end]).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(target)) = (first.next(), first.next()) else {
        return Err(400);
    };
    let length = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.trim().parse::<usize>().map_err(|_| 400u16))
        .transpose()?
        .unwrap_or(0);
    if length > BODY_MAX {
        return Err(413);
    }
    let mut body = data[end + 4..].to_vec();
    let have = body.len().min(length);
    body.resize(length, 0);
    stream.read_exact(&mut body[have..]).map_err(|_| 400u16)?;
    Ok((method.to_string(), target.to_string(), body))
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A connection that yields its bytes in the given reads, and keeps what is written.
    struct Conn {
        reads: VecDeque<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Conn {
        fn new(reads: Vec<Vec<u8>>) -> Conn {
            Conn {
                reads: reads.into(),
                written: Vec::new(),
            }
        }
    }

    impl Read for Conn {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(mut next) = self.reads.pop_front() else {
                return Ok(0);
            };
            let n = next.len().min(buf.len());
            buf[..n].copy_from_slice(&next[..n]);
            if n < next.len() {
                self.reads.push_front(next.split_off(n));
            }
            Ok(n)
        }
    }

    impl Write for Conn {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn post(length: usize, body: &[u8]) -> Vec<Vec<u8>> {
        let head = format!("POST /x HTTP/1.1\r\nContent-Length: {length}\r\n\r\n");
        vec![head.into_bytes(), body.to_vec()]
    }

    #[test]
    fn a_head_past_its_limit_is_refused_whatever_the_reads_size() {
        // Reads of 5000 bytes step over the limit, never onto it.
        let reads = vec![vec![b'a'; 5000]; 5];
        assert_eq!(read_request(&mut Conn::new(reads)), Err(431));
    }

    #[test]
    fn a_head_buffered_exactly_at_its_limit_is_still_read_on() {
        // Reads of 4096 bytes land on the limit; the next one ends the head.
        let mut head = b"GET /x HTTP/1.1\r\nX-Pad: ".to_vec();
        head.resize(HEAD_MAX, b'p');
        let mut reads: Vec<Vec<u8>> = head.chunks(4096).map(<[u8]>::to_vec).collect();
        reads.push(b"\r\n\r\n".to_vec());
        let (method, target, body) = read_request(&mut Conn::new(reads)).unwrap();
        assert_eq!((method.as_str(), target.as_str()), ("GET", "/x"));
        assert!(body.is_empty());
    }

    #[test]
    fn a_body_up_to_its_limit_is_read_whole_across_reads_and_one_past_is_refused() {
        let body = vec![b'v'; BODY_MAX];
        let (method, target, read) = read_request(&mut Conn::new(post(BODY_MAX, &body))).unwrap();
        assert_eq!((method.as_str(), target.as_str()), ("POST", "/x"));
        assert_eq!(read, body);
        let over = post(BODY_MAX + 1, &[b'v'; BODY_MAX + 1]);
        assert_eq!(read_request(&mut Conn::new(over)), Err(413));
        let short = post(10, b"abc");
        assert_eq!(read_request(&mut Conn::new(short)), Err(400));
    }

    #[test]
    fn a_body_of_64_kib_is_read() {
        // The limit written out, not derived from BODY_MAX, so a smaller limit fails here.
        let body = vec![b'v'; 64 * 1024];
        let (_, _, read) = read_request(&mut Conn::new(post(body.len(), &body))).unwrap();
        assert_eq!(read.len(), 64 * 1024);
    }

    #[test]
    fn each_answer_has_its_status_line_and_closes() {
        let link = Mutex::new(Link::new(
            "svc/default",
            None,
            Vec::new(),
            link::Token::fresh(),
            SystemTime::now(),
            link::LIFETIME,
        ));
        for (request, line) in [
            (
                b"GET /nope HTTP/1.1\r\n\r\n".to_vec(),
                "HTTP/1.1 404 Not Found\r\n",
            ),
            (b"garbage".to_vec(), "HTTP/1.1 400 Bad Request\r\n"),
        ] {
            let mut conn = Conn::new(vec![request]);
            assert_eq!(exchange(&mut conn, &link), None);
            let written = String::from_utf8(conn.written).unwrap();
            assert!(written.starts_with(line), "{written}");
            assert!(written.contains("Connection: close\r\n"), "{written}");
        }
        let gone = [
            (405, "Method Not Allowed"),
            (410, "Gone"),
            (413, "Content Too Large"),
            (431, "Request Header Fields Too Large"),
            (200, "OK"),
        ];
        for (status, phrase) in gone {
            assert_eq!(reason(status), phrase);
        }
    }
}
