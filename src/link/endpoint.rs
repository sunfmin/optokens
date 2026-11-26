//! Where a link listens and over which scheme, from what `tailscale` answered.

use crate::doctor::{no_tailnet_address, tailscale_missing};
use crate::refusal::Refusal;
use crate::tailscale;
use std::net::IpAddr;

/// What listens on the one tailnet address `tailscale ip` answered (`None`:
/// no `tailscale`) that `bind` can bind, so is on this host, IPv4 first. Never
/// another interface's; with none, nothing is stored.
pub fn listen_address<L>(
    mut bind: impl FnMut(IpAddr) -> Option<L>,
    tailscale_ip: Option<&str>,
) -> Result<L, Refusal> {
    let Some(answer) = tailscale_ip else {
        return Err(nothing_stored(tailscale_missing()));
    };
    let mut tailnet: Vec<IpAddr> = tailscale::addresses(answer).collect();
    let Some(&first) = tailnet.first() else {
        return Err(nothing_stored(no_tailnet_address("it printed no address")));
    };
    tailnet.sort_by_key(IpAddr::is_ipv6);
    tailnet.into_iter().find_map(&mut bind).ok_or_else(|| {
        nothing_stored(Refusal::new(
            format!("the tailnet address {first} is on no interface of this host"),
            "run tailscaled with its TUN device, not `--tun=userspace-networking`",
        ))
    })
}

/// `refusal`, said as the reason no link is served and nothing stored.
pub fn nothing_stored(refusal: Refusal) -> Refusal {
    Refusal {
        fault: format!(
            "no one-time link can be served, so nothing is stored: {}",
            refusal.fault
        ),
        ..refusal
    }
}

/// HTTPS with the certificate, or plain HTTP on the tailnet and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scheme<C> {
    Https(C),
    /// The reason is printed beside the link, with the fix for HTTPS.
    Http {
        reason: String,
    },
}

/// The scheme, from what `tailscale cert` gave (its certificate, or its error)
/// for `user`, the user optokens runs as.
pub fn scheme<C>(cert: Result<C, String>, user: &str) -> Scheme<C> {
    match cert {
        Ok(cert) => Scheme::Https(cert),
        Err(why) => Scheme::Http {
            reason: format!(
                "plain HTTP on the tailnet, which WireGuard encrypts, because `tailscale cert` failed: {why}. For HTTPS, an admin runs `sudo tailscale set --operator={user}` once, and must {}",
                tailscale::HTTPS_FIX
            ),
        },
    }
}
