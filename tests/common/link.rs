//! Driving a command that serves a one-time link, as a browser would: its
//! link read from stderr, and requests to it, over TLS when it is HTTPS.

use super::{Host, Ran};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::Child;
use std::sync::Arc;

pub const DOMAIN: &str = "host.tail1234.ts.net";
/// A self-signed certificate and key for [`DOMAIN`], as `tailscale cert` prints them.
pub const PEM: &str = include_str!("../fixtures/tailnet-cert.pem");

/// A `put` waiting on its link: the URL, and what it printed on stderr before it.
pub struct Waiting {
    child: Child,
    pub url: String,
    pub said: String,
    stderr: BufReader<std::process::ChildStderr>,
}

/// optokens `args` with `env`, read until it prints its link.
pub fn start(host: &Host, args: &[&str], env: &[(&str, &str)]) -> Waiting {
    let mut child = host.spawn(args, env);
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
    pub fn finish(mut self) -> Ran {
        let mut rest = String::new();
        self.stderr.read_to_string(&mut rest).unwrap();
        let out = self.child.wait_with_output().unwrap();
        Ran {
            stderr: format!("{}{}\n{rest}", self.said, self.url),
            ..super::ran(out)
        }
    }

    /// The URL's port and path.
    pub fn port_and_path(&self) -> (u16, String) {
        let rest = self.url.split_once("://").unwrap().1;
        let (authority, path) = rest.split_at(rest.find('/').unwrap());
        let port = authority.rsplit_once(':').unwrap().1.parse().unwrap();
        (port, path.to_string())
    }

    /// One request to the link, over TLS when it is HTTPS: its status and body.
    pub fn request(&self, method: &str, body: &str) -> (u16, String) {
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
