//! `optokens doctor`: whether this host can run optokens. It reads `PATH`,
//! the service account's token and vault, and `tailscale`, changes nothing,
//! and answers each finding with its fix. 1Password needs no program: opcore
//! runs its Core inside optokens (ADR 0015).

use crate::account::{self, Env};
use crate::program::{self, Ran};
use crate::refusal::Refusal;
use crate::tailscale;
use serde_json::{Value, json};
use std::ffi::OsString;
use std::process::Command;
use std::time::Duration;

/// How long `tailscale` has to answer each command doctor runs.
pub const BOUND: Duration = Duration::from_secs(3);

/// What `optokens doctor` can find about the programs optokens runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, agent_help::Help)]
pub enum Finding {
    /// `tailscale` is not on `PATH`: no one-time link can be served. Fix: install Tailscale and put its CLI on `PATH`.
    TailscaleMissing,
    /// `tailscale ip` gave no address: this host is not on its tailnet. Fix: `tailscale up`.
    NoTailnetAddress,
    /// The tailnet has no HTTPS certificates for this host (`tailscale status --json` lists no `CertDomains`), so `tailscale cert` cannot be used and a link is served without TLS. Fix: turn on MagicDNS and HTTPS Certificates in the tailnet's DNS settings of the Tailscale admin console.
    NoCert,
}

/// `tailscale` is not on `PATH`.
pub fn tailscale_missing() -> Refusal {
    Refusal::of(
        &Finding::TailscaleMissing,
        "`tailscale` is not on PATH",
        "install Tailscale (https://tailscale.com/download) and put `tailscale` on PATH",
    )
}

/// `tailscale ip` gave no address, `why`.
pub fn no_tailnet_address(why: &str) -> Refusal {
    Refusal::of(
        &Finding::NoTailnetAddress,
        format!("`tailscale ip`: {why}"),
        "run `tailscale up`",
    )
}

/// What doctor reads of the world: the environment and `PATH`.
pub struct World {
    pub env: Env,
    pub path: Option<OsString>,
}

impl World {
    pub fn current() -> World {
        World {
            env: Env::current(),
            path: std::env::var_os("PATH"),
        }
    }
}

/// Doctor's answer: what it found, and each finding with its fix.
pub fn doctor(world: &World) -> Value {
    let mut findings = Vec::new();
    let token = match account::token(&world.env) {
        Ok(token) => token.source.json(),
        Err(refusal) => {
            findings.push(refusal);
            Value::Null
        }
    };
    let vault = match account::vault(&world.env) {
        Ok(vault) => json!({ "name": vault.name, "file": vault.file }),
        Err(refusal) => {
            findings.push(refusal);
            Value::Null
        }
    };
    let (address, cert) = check_tailscale(world, &mut findings);
    let next = findings.first().map_or_else(
        || "nothing to fix: this host can run optokens".to_string(),
        |f| f.fix.clone(),
    );
    json!({
        "found": { "token": token, "vault": vault, "tailscale": address, "cert": cert },
        "findings": findings,
        "next": next,
    })
}

/// `name`'s run of `args` within [`BOUND`], its environment without the token.
fn run(path: &std::path::Path, args: &[&str]) -> Result<Ran, String> {
    let mut command = Command::new(path);
    command.args(args).env_remove(account::TOKEN_ENV);
    let ran = program::bounded(command, BOUND)?;
    if ran.status.success() {
        Ok(ran)
    } else {
        Err(format!(
            "it exited {}: {}",
            ran.status
                .code()
                .map_or("on a signal".to_string(), |c| c.to_string()),
            ran.stderr.trim()
        ))
    }
}

/// The tailnet address and the cert domains, or null for each not found.
fn check_tailscale(world: &World, findings: &mut Vec<Refusal>) -> (Value, Value) {
    let Some(path) = program::find(tailscale::PROGRAM, world.path.as_deref()) else {
        findings.push(tailscale_missing());
        return (Value::Null, Value::Null);
    };
    let address = run(&path, tailscale::IP).and_then(|ran| {
        tailscale::addresses(&ran.stdout)
            .next()
            .ok_or("it printed no address".into())
    });
    let address = address
        .map_err(|why| findings.push(no_tailnet_address(&why)))
        .ok();
    let address = json!({ "path": path, "address": address });
    let domains =
        run(&path, tailscale::STATUS).and_then(|ran| tailscale::cert_domains(&ran.stdout));
    let cert = match domains {
        Ok(domains) if !domains.is_empty() => json!({ "domains": domains }),
        Ok(_) | Err(_) => {
            let why = domains
                .err()
                .unwrap_or_else(|| format!("it lists no `{}`", tailscale::CERT_DOMAINS));
            findings.push(Refusal::of(
                &Finding::NoCert,
                format!("`tailscale status --json`: {why}, so `tailscale cert` cannot be used"),
                tailscale::HTTPS_FIX,
            ));
            Value::Null
        }
    };
    (address, cert)
}
