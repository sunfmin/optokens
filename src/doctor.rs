//! `optokens doctor`: whether this host can run optokens. It reads `PATH`,
//! the service account's token and vault, `tailscale`, and on macOS the
//! application firewall, changes nothing, and answers each finding with its
//! fix. 1Password needs no program: opcore
//! runs its Core inside optokens (ADR 0015).

use crate::account::{self, Env};
use crate::firewall::{self, Rule};
use crate::program::{self, Ran};
use crate::refusal::{Refusal, quoted};
use crate::tailscale;
use serde_json::{Value, json};
use std::ffi::OsString;
use std::path::PathBuf;
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
    /// macOS's application firewall refuses connections to this optokens binary: it has a rule blocking it (`socketfilterfw --listapps`), or no rule while its signature is not one the firewall lets in by itself (ad hoc, or no Developer ID while only signed software is let in), and with no one at the desktop to answer its prompt, each connection is refused. One-time links cannot then be reached from other devices. A `brew upgrade` moves the binary to a new path, which has no rule. Fix: the `sudo socketfilterfw --add <path> --unblockapp <path>` line it gives, or a release signed with a Developer ID.
    FirewallBlocks,
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
    /// On macOS, what doctor reads the firewall with.
    pub firewall: Option<Firewall>,
}

/// The firewall's CLI, `codesign`, and this binary's real path.
pub struct Firewall {
    pub socketfilterfw: PathBuf,
    pub codesign: PathBuf,
    pub binary: PathBuf,
}

/// The environment variable a test sets to the directory that holds its
/// stand-ins for `socketfilterfw` and `codesign`; the manual does not list it.
const TEST_TOOLS: &str = "OPTOKENS_TEST_MACOS_TOOLS";

impl World {
    pub fn current() -> World {
        World {
            env: Env::current(),
            path: std::env::var_os("PATH"),
            firewall: cfg!(target_os = "macos").then(Firewall::current).flatten(),
        }
    }
}

impl Firewall {
    fn current() -> Option<Firewall> {
        let (socketfilterfw, codesign) = match std::env::var_os(TEST_TOOLS) {
            Some(dir) => {
                let dir = PathBuf::from(dir);
                (dir.join("socketfilterfw"), dir.join("codesign"))
            }
            None => (firewall::SOCKETFILTERFW.into(), firewall::CODESIGN.into()),
        };
        let binary = std::env::current_exe().ok()?.canonicalize().ok()?;
        Some(Firewall {
            socketfilterfw,
            codesign,
            binary,
        })
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
    let firewall = world
        .firewall
        .as_ref()
        .map_or(Value::Null, |f| check_firewall(f, &mut findings));
    let next = findings.first().map_or_else(
        || "nothing to fix: this host can run optokens".to_string(),
        |f| f.fix.clone(),
    );
    json!({
        "found": { "token": token, "vault": vault, "tailscale": address, "cert": cert, "firewall": firewall },
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

/// Whether macOS's firewall lets connections reach this binary: null when
/// there is no `socketfilterfw` to ask, else `enabled`, and when it is on,
/// the `binary`, its `rule` and the `team` that signed it.
fn check_firewall(fw: &Firewall, findings: &mut Vec<Refusal>) -> Value {
    if !fw.socketfilterfw.is_file() {
        return Value::Null;
    }
    let ask = |args: &[&str]| run(&fw.socketfilterfw, args).map(|ran| ran.stdout);
    let Ok(state) = ask(firewall::GLOBAL_STATE) else {
        return Value::Null;
    };
    if !firewall::enabled(&state) {
        return json!({ "enabled": false });
    }
    let binary = fw.binary.display().to_string();
    let rule = ask(firewall::LIST_APPS)
        .ok()
        .and_then(|apps| firewall::rule(&apps, &binary));
    let team = run(
        &fw.codesign,
        &[firewall::SIGNATURE, &[binary.as_str()]].concat(),
    )
    .ok()
    .and_then(|ran| firewall::team(&ran.stderr));
    let fault = match rule {
        Some(Rule::Allow) => None,
        Some(Rule::Block) => Some(format!(
            "macOS's firewall has a rule blocking incoming connections to `{binary}` (`socketfilterfw --listapps`)"
        )),
        None => {
            let signed =
                ask(firewall::ALLOW_SIGNED).is_ok_and(|s| firewall::allows_downloaded_signed(&s));
            match (&team, signed) {
                (Some(_), true) => None,
                (Some(team), false) => Some(format!(
                    "macOS's firewall is on, has no rule for `{binary}`, and lets no downloaded software in by itself, though team {team} signed it"
                )),
                (None, _) => Some(format!(
                    "macOS's firewall is on, has no rule for `{binary}`, and lets in by itself only software signed with a Developer ID, which it is not (ad hoc, or unsigned)"
                )),
            }
        }
    };
    if let Some(fault) = fault {
        let path = quoted(&fw.binary);
        findings.push(Refusal::of(
            &Finding::FirewallBlocks,
            format!(
                "{fault}: with no one at the desktop to answer its prompt, each connection is refused, so one-time links cannot be reached from other devices"
            ),
            format!(
                "run `sudo {} --add {path} --unblockapp {path}`, or install a release signed with a Developer ID",
                firewall::SOCKETFILTERFW
            ),
        ));
    }
    let rule = rule.map(|r| match r {
        Rule::Allow => "allow",
        Rule::Block => "block",
    });
    json!({ "enabled": true, "binary": fw.binary, "rule": rule, "team": team })
}
