//! `optokens init`: takes the service account's token on a one-time link,
//! writes it and the vault's name where every command finds them, then checks
//! with that token, through `op`, that the service account reads and writes
//! the vault.

use crate::account::{self, Env, Source, Vault};
use crate::cli::Answer;
use crate::commands::fresh_link;
use crate::link::{self, Input};
use crate::refusal::Refusal;
use crate::secret::{DEFAULT_ACCOUNT, Kind, Name, Secret, Values};
use crate::serve::Endpoint;
use crate::store::Store;
use agent_help::Table;
use serde_json::{Value, json};

// `init`'s command line; its help is the manual's.
#[derive(clap::Args)]
pub struct InitArgs {
    /// The vault optokens keeps its Secrets in, as 1Password names it.
    #[arg(long, default_value = account::DEFAULT_VAULT, verbatim_doc_comment)]
    vault: String,
    /// Only the checks, with the token and the vault every command finds: no link, nothing written.
    #[arg(long, conflicts_with = "vault", verbatim_doc_comment)]
    check: bool,
}

/// The one Field the link asks for.
pub const LABEL: &str = "1Password service account token";
/// The probe item's service; its account is the default.
pub const PROBE: &str = "optokens-init-probe";

/// What `init` checks with the token, in this order; the first that fails is
/// its refusal's `kind`, and no later check is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, agent_help::Help)]
pub enum Check {
    /// `op vault list` shows the vault: it exists, and the service account has access to it. Fix: create the vault in 1Password if it is not there, and give the service account read and write on it, in 1Password's web UI under Developer → Service Accounts.
    VaultListed,
    /// `op item list` reads the vault's items. Fix: give the service account read on the vault, as for `vault_listed`.
    VaultRead,
    /// `op item create` writes the probe item `optokens-init-probe/default`, tagged `optokens` (`op item edit`, over one an earlier `init` left). Fix: give the service account write on the vault, as for `vault_listed`.
    ProbeWritten,
    /// The probe item, read back, holds what was written. Fix: run `optokens init --check` again.
    ProbeReadBack,
    /// `op item delete` removes the probe item. Fix: give the service account write on the vault, as for `vault_listed`.
    ProbeRemoved,
}

pub fn init(env: &Env, args: InitArgs) -> Answer {
    match run(env, args) {
        Ok(answer) => Answer::json(&answer),
        Err(faults) => Answer::refused(faults),
    }
}

fn run(env: &Env, args: InitArgs) -> Result<Value, Vec<Refusal>> {
    if args.check {
        let (token, vault) = match (account::token(env), account::vault(env)) {
            (Ok(token), Ok(vault)) => (token, vault),
            (token, vault) => {
                return Err([token.err(), vault.err()].into_iter().flatten().collect());
            }
        };
        let source = token.source.clone();
        checks(&Store::new(token, vault.name.clone())).map_err(|r| vec![r])?;
        return Ok(answer(&source, &vault));
    }
    let mut faults = Vec::new();
    let vault = args.vault.trim();
    if vault.is_empty() || vault.chars().any(char::is_control) {
        faults.push(Refusal::new(
            format!(
                "`--vault {:?}`: a vault's name is one line, not empty",
                args.vault
            ),
            "name the vault as 1Password shows it, such as `--vault optokens`",
        ));
    }
    if let Err(refusal) = account::config_dir(env) {
        faults.push(refusal);
    }
    let endpoint = Endpoint::open(std::env::var_os("PATH").as_deref())
        .map_err(|r| faults.push(r))
        .ok();
    let (Some(endpoint), true) = (endpoint, faults.is_empty()) else {
        return Err(faults);
    };
    let field = link::Field {
        label: LABEL.to_string(),
        input: Input::Password,
    };
    let about = format!(
        "The token of the 1Password service account optokens reaches the vault `{vault}` as. It is written to this host's token file, which only its owner may read."
    );
    let link = fresh_link("optokens init", Some(&about), vec![field]);
    let what = format!("the 1Password service account token for the vault `{vault}`");
    let values = endpoint.serve(link, &what, "init").map_err(|r| vec![r])?;
    let token = values.into_values().next().unwrap_or_default();
    let (token, vault) = account::save(env, token.trim(), vault).map_err(|r| vec![r])?;
    let source = token.source.clone();
    checks(&Store::new(token, vault.name.clone())).map_err(|refusal| {
        vec![Refusal {
            fault: format!(
                "{}; the token file `{}` and the vault file are written and kept, so once it is fixed `optokens init --check` checks again with no new link",
                refusal.fault,
                source.name()
            ),
            ..refusal
        }]
    })?;
    Ok(answer(&source, &vault))
}

fn answer(source: &Source, vault: &Vault) -> Value {
    json!({
        "token": source.json(),
        "vault": { "name": vault.name, "file": vault.file },
        "checks": Check::ENTRIES.iter().map(|e| e.name).collect::<Vec<_>>(),
    })
}

/// Each [`Check`] in order, with `store`'s token, until one fails.
fn checks(store: &Store) -> Result<(), Refusal> {
    let vault = store.vault();
    let failed = |check: Check, fault: &str| {
        Refusal::of(
            &check,
            format!("check `{}`: {fault}", check.entry().name),
            format!(
                "in 1Password's web UI, under Developer → Service Accounts, give the service account read and write on the vault `{vault}` (create the vault first if it is not there), then run `optokens init --check`"
            ),
        )
    };
    let by = |check| move |refusal: Refusal| failed(check, &refusal.fault);
    let listed = store.vaults().map_err(by(Check::VaultListed))?;
    if !listed.iter().any(|name| name == vault) {
        return Err(failed(
            Check::VaultListed,
            &format!(
                "`op vault list` does not show the vault `{vault}`: it does not exist, or the service account has no access to it"
            ),
        ));
    }
    let probe = Name::new(PROBE, DEFAULT_ACCOUNT).expect("a valid name");
    let left = store.find(&probe).map_err(by(Check::VaultRead))?;
    let secret = Secret {
        kind: Kind::Static,
        description: Some("optokens init's probe of read and write: it removes it at once".into()),
        values: Values::Single(link::random_hex(16)),
    };
    store
        .write(left.as_ref().map(|f| f.id.as_str()), &probe, &secret)
        .map_err(by(Check::ProbeWritten))?;
    let back = store.find(&probe).map_err(by(Check::ProbeReadBack))?;
    let Some(back) = back.filter(|found| found.secret == secret) else {
        return Err(failed(
            Check::ProbeReadBack,
            "the probe item read back is not what was written",
        ));
    };
    store.delete(&back.id).map_err(by(Check::ProbeRemoved))
}
