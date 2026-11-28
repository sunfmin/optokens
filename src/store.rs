//! The vault, through opcore (ADR 0015): finding, reading, writing and
//! removing Secrets. It keeps opcore's sealed Copy of the items tagged
//! `optokens` in the config directory, answers from it with no network on
//! demand (ADR 0019), and stages each write there (ADR 0020): it reaches
//! 1Password only at a push (`push`, a write's `--now`, `--fresh`), a
//! Secret the Copy lacks, or with no Copy yet. No child process, no command line: a value
//! leaves this process only inside the Core's encrypted requests.

use crate::account::{self, Env, Token};
use crate::item;
use crate::refusal::Refusal;
use crate::secret::{Fault, Name, Secret};
use opcore::core::{Core, Failure, Wasm};
use opcore::{Copy, Error, Item, Syncs};
use std::path::Path;

/// The command a warning names to push the changes staged on this host.
pub const PUSH: &str = "optokens push";
/// The Copy's file, in the config directory beside the token file.
pub const COPY_FILE: &str = "copy";
/// What stderr says of a `--now` write whose Sync could not reach
/// 1Password, after why.
pub const WAITS: &str = "the change stays staged on this host until a push reaches 1Password";

pub struct Store {
    copy: Copy<Backend>,
    vault: String,
    /// Why this process's Sync could not reach 1Password, when a `--now`
    /// write went on without it ([`Store::sync_to_write`]).
    unreached: Option<String>,
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
    pub fn open(env: &Env, writes: Writes) -> Result<Store, Vec<Refusal>> {
        let (token, vault) = account::find(env)?;
        let dir = account::config_dir(env).map_err(|r| vec![r])?;
        Ok(Store::new(&token, vault.name, &dir, writes))
    }

    /// The vault `vault`, reached with `token`, its Copy in `dir`, its
    /// writes staged or through.
    pub fn new(token: &Token, vault: String, dir: &Path, writes: Writes) -> Store {
        // opcore stages each write on demand, and writes through with a
        // Life (its decision record 6). A `--now` command syncs first, so
        // its Life never ends: no read of it syncs again.
        let syncs = match writes {
            Writes::Staged => Syncs::OnDemand { push: PUSH.into() },
            Writes::Now => Syncs::Life(std::time::Duration::MAX),
        };
        let copy = Copy::with_core(
            Backend::current(),
            &dir.join(COPY_FILE),
            token.value(),
            &vault,
            item::TAG,
            syncs,
        );
        Store {
            copy,
            vault,
            unreached: None,
        }
    }

    pub fn vault(&self) -> &str {
        &self.vault
    }

    /// Makes the Copy the vault's again, pushing what is staged first:
    /// `--fresh`, and before a `--now` write. opcore's error as it is, so `init` tells `Error::NoVault` apart.
    pub fn sync(&mut self) -> Result<(), Error> {
        self.copy.sync()
    }

    /// The Sync before a `--now` `put` or `rm`. When it cannot reach
    /// 1Password (the rate limit, the network, 1Password down), the write
    /// goes on from the Copy as held and stays staged (decision record 17);
    /// any other failure is refused.
    pub fn sync_to_write(&mut self) -> Result<(), Refusal> {
        match self.copy.sync() {
            Err(e) if e.is_transient() => {
                self.unreached = Some(e.to_string());
                Ok(())
            }
            synced => synced.map_err(|e| self.refused(e)),
        }
    }

    /// The Copy's items, synced first only when there is no Copy yet.
    fn items(&mut self) -> Result<Vec<Item>, Refusal> {
        let items = self.copy.items().map(|i| i.into_iter().cloned().collect());
        items.map_err(|e| self.refused(e))
    }

    /// `name`'s Secret, `None` when the vault has none: the one item of its
    /// title, or its earlier title, whose section names it. Refused when an
    /// item without the tag holds either title, as a Sync of this process
    /// saw it. A Secret the Copy lacks
    /// syncs once a process (opcore's miss rule), then is looked for again;
    /// that Sync failing answers from the Copy, with opcore's warning.
    pub fn find(&mut self, name: &Name) -> Result<Option<Found>, Refusal> {
        match self.held(name)? {
            None => {
                // Only for its Sync: an error it meets, the Copy's read,
                // the look again meets too, and refuses.
                let _ = self.copy.find(&name.title());
                self.held(name)
            }
            found => Ok(found),
        }
    }

    /// `name`'s Secret as the Copy holds it, its staged changes made, with
    /// no Sync but a first one: what a write is based on (ADR 0020).
    pub fn held(&mut self, name: &Name) -> Result<Option<Found>, Refusal> {
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

    /// Every Secret in the vault, by service, then account, each with
    /// whether a change of it is staged on this host; refused with every item
    /// that is not optokens' layout.
    pub fn all(&mut self) -> Result<Vec<(Name, Secret, bool)>, Vec<Refusal>> {
        let items = self.items().map_err(|r| vec![r])?;
        let pending = self.copy.pending().map_err(|e| vec![self.refused(e)])?;
        let waits = |i: &Item| pending.iter().any(|p| p.id == i.id);
        let (found, faults): (Vec<_>, Vec<_>) = items
            .iter()
            .map(|i| item::read(i).map(|(n, s)| (n, s, waits(i))))
            .partition(Result::is_ok);
        if !faults.is_empty() {
            return Err(faults.into_iter().filter_map(Result::err).collect());
        }
        let mut found: Vec<_> = found.into_iter().filter_map(Result::ok).collect();
        found.sort_by(|(a, ..), (b, ..)| a.cmp(b));
        Ok(found)
    }

    /// Writes `secret` as `name`'s item: over the item `found`, keeping what
    /// optokens does not own of it, or a new one. Staged, or with
    /// [`Writes::Now`] one write, whose answer the Copy keeps, or which
    /// waits staged when 1Password cannot take it now ([`Written`]).
    pub fn write(
        &mut self,
        found: Option<&Found>,
        name: &Name,
        secret: &Secret,
    ) -> Result<Written, Refusal> {
        let template = item::template(name, secret, found.map(|f| &f.item));
        self.written(|copy| match found {
            Some(f) => copy.edit(&f.item.id, &template).map(drop),
            None => copy.create_all(&[template]).map(drop),
        })
    }

    /// Deletes the item `id` for good (not archived), as `op item delete`
    /// did: staged, or through as [`Store::write`] writes.
    pub fn delete(&mut self, id: &str) -> Result<Written, Refusal> {
        self.written(|copy| copy.delete_all(&[id]))
    }

    /// `write` on the Copy, refused with its error, or how it went: a write
    /// staged is the one this call warned of.
    fn written(
        &mut self,
        write: impl FnOnce(&mut Copy<Backend>) -> Result<(), Error>,
    ) -> Result<Written, Refusal> {
        let before = self.copy.write_warnings().len();
        write(&mut self.copy).map_err(|e| self.refused(e))?;
        Ok(match self.copy.write_warnings().get(before..) {
            Some([.., why]) => {
                if let Some(unreached) = &self.unreached {
                    eprintln!("1Password could not be reached ({unreached}); {WAITS}");
                }
                Written::Waits(why.clone())
            }
            _ => Written::Through,
        })
    }

    /// Sends every change staged on this host to 1Password in one process,
    /// one of the account's requests, each Secret's changes folded into one
    /// write, then pulls (opcore's push): how many changes went, how many
    /// still wait.
    pub fn push(&mut self) -> Result<Pushed, Refusal> {
        let pending = |copy: &mut Copy<Backend>| copy.pending().map(|p| p.len());
        let pushed = pending(&mut self.copy).and_then(|before| {
            self.copy.push()?;
            let left = pending(&mut self.copy)?;
            Ok(Pushed {
                sent: before.saturating_sub(left),
                left,
            })
        });
        pushed.map_err(|e| self.refused(e))
    }

    /// Each change staged on this host, oldest first: its Secret
    /// (`None` for one a staged removal hides), the item's title, the
    /// change (`create`, `edit` or `delete`) and when it was made. No
    /// network but a first Sync.
    pub fn staged(&mut self) -> Result<Vec<Staged>, Refusal> {
        let pending = self.copy.pending().map_err(|e| self.refused(e))?;
        let items = match pending.is_empty() {
            true => Vec::new(),
            false => self.items()?,
        };
        let secret = |id: &str| {
            let item = items.iter().find(|i| i.id == id)?;
            item::read(item).ok().map(|(name, _)| name)
        };
        let mut staged: Vec<Staged> = (pending.iter())
            .map(|p| Staged {
                secret: secret(&p.id),
                title: p.title.clone(),
                change: p.write,
                at: p.at,
            })
            .collect();
        staged.sort_by_key(|s| s.at);
        Ok(staged)
    }

    /// opcore's error `e` as the refusal `vault_failed`, with its fix.
    pub fn refused(&self, e: Error) -> Refusal {
        let fix = match &e {
            Error::RateLimited(_) => "wait for 1Password's budget to refill, then run the command again: `op service-account ratelimit` shows which ran out and when it resets (the token's reads and writes refill within the hour, the account's requests within the day)".to_string(),
            Error::OutOfDate(_) => "update optokens (`brew upgrade optokens`): its 1Password Core may be older than 1Password's servers".to_string(),
            Error::OtherToken(path) => format!(
                "run with the token that staged the changes in `{path}`: its next push sends them and the file goes; if that token is gone for good, move the file aside, losing what waits in it"
            ),
            Error::NoVault(_) | Error::NoItem(_) | Error::Failed(_) => format!(
                "run `optokens init --check`, and see that the service account can reach the vault `{}`",
                self.vault
            ),
        };
        Refusal::of(&Fault::VaultFailed, format!("1Password: {e}"), fix)
    }
}

/// When a write reaches 1Password (decision record 20).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Writes {
    /// Staged on this host until a push: `put`, `mv` and `rm`, and every
    /// read's Store, whose `--fresh` pushes.
    Staged,
    /// Through, after the Sync the command makes first: `--now`, and
    /// `init`'s probe.
    Now,
}

/// How a write went: into the vault, or staged in the Copy's pending file,
/// sealed, for the next push (opcore's ADR 0003): always with
/// [`Writes::Staged`], and with [`Writes::Now`] when 1Password cannot take
/// it now (network, rate limit, down).
#[derive(Debug, PartialEq)]
pub enum Written {
    Through,
    /// opcore's warning, also on stderr: which write, why, where it waits.
    Waits(String),
}

impl Written {
    pub fn waits(&self) -> bool {
        matches!(self, Written::Waits(_))
    }
}

/// What a push did: how many staged changes it sent (each Secret's folded
/// into one write), and how many still wait.
#[derive(Debug, PartialEq)]
pub struct Pushed {
    pub sent: usize,
    pub left: usize,
}

/// A change staged on this host ([`Store::staged`]).
pub struct Staged {
    pub secret: Option<Name>,
    pub title: String,
    pub change: &'static str,
    pub at: std::time::SystemTime,
}

/// The Core the Copy signs in on: 1Password's, made only when it first
/// signs in (a read the Copy answers never does), or, in a build without
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
