//! The vault, through `op`: finding, reading, writing and removing Secrets.
//! It runs the command lines `op` builds, hands `op` the token only in its
//! environment and a Secret's values only on its stdin, and reads them back
//! only from its stdout.

use crate::account::{self, Env, Token};
use crate::item;
use crate::op::{self, Call};
use crate::program;
use crate::refusal::Refusal;
use crate::secret::{Fault, Name, Secret};
use serde_json::Value;
use std::process::Command;
use std::time::Duration;

/// How long `op` has to answer each call: it reaches 1Password's servers.
pub const OP_BOUND: Duration = Duration::from_secs(60);

pub struct Store {
    token: Token,
    vault: String,
}

/// A Secret found in the vault: its item's id, the item as `op` printed it,
/// what it holds, and whether the item is in this optokens' layout
/// ([`item::current`]).
pub struct Found {
    pub id: String,
    pub item: Value,
    pub secret: Secret,
    pub current: bool,
}

impl Store {
    /// The service account's vault, refused with every fault the token and
    /// the vault file have.
    pub fn open(env: &Env) -> Result<Store, Vec<Refusal>> {
        let (token, vault) = account::find(env)?;
        Ok(Store::new(token, vault.name))
    }

    /// The vault `vault`, reached with `token`: `init`'s, before any lookup.
    pub fn new(token: Token, vault: String) -> Store {
        Store { token, vault }
    }

    pub fn vault(&self) -> &str {
        &self.vault
    }

    /// Whether `op vault list` shows the vault to the service account.
    pub fn has_vault(&self) -> Result<bool, Refusal> {
        let list = self.json(Call::Vaults)?;
        let named = |v: &Value| v["name"] == self.vault.as_str();
        Ok(list.as_array().is_some_and(|all| all.iter().any(named)))
    }

    /// `call`'s stdout, `input` on its stdin.
    fn run(&self, call: Call, input: Option<Vec<u8>>) -> Result<String, Refusal> {
        let args = op::args(call, &self.vault);
        let mut command = Command::new(op::PROGRAM);
        command.args(&args).env(op::TOKEN_ENV, self.token.value());
        let line = format!("{} {}", op::PROGRAM, args.join(" "));
        let failed = |why: String| {
            Refusal::of(
                &Fault::OpFailed,
                format!("`{line}`: {why}"),
                format!(
                    "run `optokens doctor`, and see that the service account can reach the vault `{}`",
                    self.vault
                ),
            )
        };
        let ran = program::bounded(command, input, OP_BOUND).map_err(failed)?;
        if !ran.status.success() {
            let code = ran
                .status
                .code()
                .map_or("on a signal".to_string(), |c| c.to_string());
            return Err(failed(format!("it exited {code}: {}", ran.stderr.trim())));
        }
        Ok(ran.stdout)
    }

    fn json(&self, call: Call) -> Result<Value, Refusal> {
        let stdout = self.run(call, None)?;
        serde_json::from_str(&stdout).map_err(|e| {
            Refusal::of(
                &Fault::OpFailed,
                format!("`op` answered what is not JSON: {e}"),
                "run `optokens doctor`, and update `op`",
            )
        })
    }

    /// `name`'s Secret, `None` when the vault has none: the one item of its
    /// title, or its earlier title, whose section names it.
    pub fn find(&self, name: &Name) -> Result<Option<Found>, Refusal> {
        let mut found = Vec::new();
        for id in item::candidates(&self.json(Call::List)?, name)? {
            let item = self.json(Call::Get(&id))?;
            let (held, secret) = item::read(&item)?;
            if held == *name {
                let current = item::current(&item, name);
                found.push(Found {
                    id,
                    item,
                    secret,
                    current,
                });
            }
        }
        let ids: Vec<&str> = found.iter().map(|f| f.id.as_str()).collect();
        item::unique(name, &ids)?;
        Ok(found.pop())
    }

    /// Every Secret in the vault, by service, then account; refused with every item that is
    /// not optokens' layout.
    pub fn all(&self) -> Result<Vec<(Name, Secret)>, Vec<Refusal>> {
        let list = self.json(Call::List).map_err(|r| vec![r])?;
        let (mut found, mut faults) = (Vec::new(), Vec::new());
        for id in item::ours(&list) {
            match self.json(Call::Get(&id)).and_then(|i| item::read(&i)) {
                Ok(secret) => found.push(secret),
                Err(refusal) => faults.push(refusal),
            }
        }
        if faults.is_empty() {
            found.sort_by(|(a, _), (b, _)| a.cmp(b));
            Ok(found)
        } else {
            Err(faults)
        }
    }

    /// Writes `secret` as `name`'s item: over the item `found`, keeping what
    /// optokens does not own of it, or a new one.
    pub fn write(
        &self,
        found: Option<&Found>,
        name: &Name,
        secret: &Secret,
    ) -> Result<(), Refusal> {
        let stored = found.map(|f| &f.item);
        let template = item::template(name, secret, stored)
            .to_string()
            .into_bytes();
        let call = found.map_or(Call::Create, |f| Call::Edit(&f.id));
        self.run(call, Some(template)).map(drop)
    }

    pub fn delete(&self, id: &str) -> Result<(), Refusal> {
        self.run(Call::Delete(id), None).map(drop)
    }
}
