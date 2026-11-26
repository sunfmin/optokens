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

/// A Secret found in the vault: its item's id, and what it holds.
pub struct Found {
    pub id: String,
    pub secret: Secret,
}

impl Store {
    /// The service account's vault, refused with every fault the token and
    /// the vault file have.
    pub fn open(env: &Env) -> Result<Store, Vec<Refusal>> {
        match (account::token(env), account::vault(env)) {
            (Ok(token), Ok(vault)) => Ok(Store {
                token,
                vault: vault.name,
            }),
            (token, vault) => Err([token.err(), vault.err()].into_iter().flatten().collect()),
        }
    }

    /// The vault `vault`, reached with `token`: `init`'s, before any lookup.
    pub fn new(token: Token, vault: String) -> Store {
        Store { token, vault }
    }

    pub fn vault(&self) -> &str {
        &self.vault
    }

    /// The names of every vault the service account can see.
    pub fn vaults(&self) -> Result<Vec<String>, Refusal> {
        let list = self.json(Call::Vaults)?;
        Ok(list
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v["name"].as_str().map(String::from))
            .collect())
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

    /// `name`'s Secret, `None` when the vault has none.
    pub fn find(&self, name: &Name) -> Result<Option<Found>, Refusal> {
        let Some(id) = item::find(&self.json(Call::List)?, name)? else {
            return Ok(None);
        };
        let (_, secret) = item::read(&self.json(Call::Get(&id))?)?;
        Ok(Some(Found { id, secret }))
    }

    /// Every Secret in the vault, by title; refused with every item that is
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
            Ok(found)
        } else {
            Err(faults)
        }
    }

    /// Writes `secret` as `name`'s item: over the item `id`, or a new one.
    pub fn write(&self, id: Option<&str>, name: &Name, secret: &Secret) -> Result<(), Refusal> {
        let template = item::template(name, secret).to_string().into_bytes();
        let call = id.map_or(Call::Create, Call::Edit);
        self.run(call, Some(template)).map(drop)
    }

    pub fn delete(&self, id: &str) -> Result<(), Refusal> {
        self.run(Call::Delete(id), None).map(drop)
    }
}
