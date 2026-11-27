//! The vault, through opcore (ADR 0015): finding, reading, writing and
//! removing Secrets. It keeps opcore's sealed Copy of the items tagged
//! `optokens` in the config directory, answers from it with no network
//! within its [`LIFE`], and writes through the Copy's Client, which keeps
//! what each write answered. No child process, no command line: a value
//! leaves this process only inside the Core's encrypted requests.

use crate::account::{self, Env, Token};
use crate::item;
use crate::refusal::Refusal;
use crate::secret::{Fault, Name, Secret};
use opcore::core::{Core, Failure, Wasm};
use opcore::{Copy, Error, Item};
use std::path::Path;
use std::time::Duration;

/// How long the Copy answers with no Sync. `--fresh` syncs within it.
pub const LIFE: Duration = Duration::from_secs(5 * 60);
/// The Copy's file, in the config directory beside the token file.
pub const COPY_FILE: &str = "copy";

pub struct Store {
    copy: Copy<Backend>,
    vault: String,
}

/// A Secret found in the vault: its item as the Copy holds it, what it
/// holds, and whether the item is in this optokens' layout
/// ([`item::current`]).
pub struct Found {
    pub item: Item,
    pub secret: Secret,
    pub current: bool,
}

impl Store {
    /// The service account's vault, refused with every fault the token, the
    /// vault file and the config directory have.
    pub fn open(env: &Env) -> Result<Store, Vec<Refusal>> {
        let (token, vault) = account::find(env)?;
        let dir = account::config_dir(env).map_err(|r| vec![r])?;
        Ok(Store::new(&token, vault.name, &dir))
    }

    /// The vault `vault`, reached with `token`, its Copy in `dir`.
    pub fn new(token: &Token, vault: String, dir: &Path) -> Store {
        let copy = Copy::with_core(
            Backend::current(),
            &dir.join(COPY_FILE),
            token.value(),
            &vault,
            item::TAG,
            life(),
        );
        Store { copy, vault }
    }

    pub fn vault(&self) -> &str {
        &self.vault
    }

    /// Makes the Copy the vault's again: `--fresh`, and before a write.
    /// opcore's error as it is, so `init` tells `Error::NoVault` apart.
    pub fn sync(&mut self) -> Result<(), Error> {
        self.copy.sync()
    }

    /// The Copy's items, synced first if past its Life.
    fn items(&mut self) -> Result<Vec<Item>, Refusal> {
        let items = self.copy.items().map(|i| i.into_iter().cloned().collect());
        items.map_err(|e| self.refused(e))
    }

    /// `name`'s Secret, `None` when the vault has none: the one item of its
    /// title, or its earlier title, whose section names it. Refused when an
    /// item without the tag holds either title, as a Sync of this process
    /// saw it (`put` and `rm` sync first).
    pub fn find(&mut self, name: &Name) -> Result<Option<Found>, Refusal> {
        let items = self.items()?;
        let others = self.copy.others().unwrap_or_default();
        let mut found = Vec::new();
        for item in item::candidates(&items, others, name)? {
            let (held, secret) = item::read(item)?;
            if held == *name {
                found.push(Found {
                    current: item::current(item, name),
                    item: item.clone(),
                    secret,
                });
            }
        }
        let ids: Vec<&str> = found.iter().map(|f| f.item.id.as_str()).collect();
        item::unique(name, &ids)?;
        Ok(found.pop())
    }

    /// Every Secret in the vault, by service, then account; refused with every item that is
    /// not optokens' layout.
    pub fn all(&mut self) -> Result<Vec<(Name, Secret)>, Vec<Refusal>> {
        let items = self.items().map_err(|r| vec![r])?;
        let (found, faults): (Vec<_>, Vec<_>) =
            items.iter().map(item::read).partition(Result::is_ok);
        if !faults.is_empty() {
            return Err(faults.into_iter().filter_map(Result::err).collect());
        }
        let mut found: Vec<_> = found.into_iter().filter_map(Result::ok).collect();
        found.sort_by(|(a, _), (b, _)| a.cmp(b));
        Ok(found)
    }

    /// Writes `secret` as `name`'s item: over the item `found`, keeping what
    /// optokens does not own of it, or a new one. One write; the Copy keeps
    /// what it answered.
    pub fn write(
        &mut self,
        found: Option<&Found>,
        name: &Name,
        secret: &Secret,
    ) -> Result<(), Refusal> {
        let template = item::template(name, secret, found.map(|f| &f.item));
        let written = match found {
            Some(f) => self.copy.edit(&f.item.id, &template).map(drop),
            None => self.copy.create_all(&[template]).map(drop),
        };
        written.map_err(|e| self.refused(e))
    }

    /// Deletes the item `id` for good (not archived), as `op item delete` did.
    pub fn delete(&mut self, id: &str) -> Result<(), Refusal> {
        self.copy.delete_all(&[id]).map_err(|e| self.refused(e))
    }

    /// opcore's error `e` as the refusal `vault_failed`, with its fix.
    pub fn refused(&self, e: Error) -> Refusal {
        let fix = match e {
            Error::RateLimited(_) => "wait for the service account's hourly budget of reads and writes to refill (`op service-account ratelimit` shows it), then run the command again".to_string(),
            Error::OutOfDate(_) => "update optokens (`brew upgrade optokens`): its 1Password Core may be older than 1Password's servers".to_string(),
            Error::NoVault(_) | Error::NoItem(_) | Error::Failed(_) => format!(
                "run `optokens init --check`, and see that the service account can reach the vault `{}`",
                self.vault
            ),
        };
        Refusal::of(&Fault::VaultFailed, format!("1Password: {e}"), fix)
    }
}

/// The environment variable a test sets to shorten the Copy's Life, in
/// milliseconds, in a build without `--release`; the manual does not list it.
#[cfg(debug_assertions)]
const TEST_LIFE: &str = "OPTOKENS_TEST_COPY_LIFE_MS";

/// [`LIFE`], or a test's.
fn life() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var(TEST_LIFE).ok().and_then(|ms| ms.parse().ok()) {
        return Duration::from_millis(ms);
    }
    LIFE
}

/// The Core the Copy signs in on: 1Password's, made only when it first
/// signs in (a Copy within its Life never does), or, in a build without
/// `--release` whose `OPTOKENS_STANDIN_STATE` is set, the tests' stand-in.
pub enum Backend {
    Wasm(Option<Box<Wasm>>),
    #[cfg(debug_assertions)]
    Standin(crate::standin::Standin),
}

impl Backend {
    fn current() -> Backend {
        #[cfg(debug_assertions)]
        if let Some(standin) = crate::standin::Standin::from_env() {
            return Backend::Standin(standin);
        }
        Backend::Wasm(None)
    }

    fn core(&mut self) -> Result<&mut dyn Core, Failure> {
        match self {
            Backend::Wasm(made) => {
                if made.is_none() {
                    *made = Some(Box::new(Wasm::new()?));
                }
                Ok(made.as_deref_mut().expect("made"))
            }
            #[cfg(debug_assertions)]
            Backend::Standin(standin) => Ok(standin),
        }
    }
}

impl Core for Backend {
    fn init_client(&mut self, config: &str) -> Result<String, Failure> {
        self.core()?.init_client(config)
    }

    fn invoke(&mut self, invocation: &str) -> Result<String, Failure> {
        self.core()?.invoke(invocation)
    }

    fn release_client(&mut self, id: &str) {
        match self {
            Backend::Wasm(Some(wasm)) => wasm.release_client(id),
            Backend::Wasm(None) => {}
            #[cfg(debug_assertions)]
            Backend::Standin(standin) => standin.release_client(id),
        }
    }
}
