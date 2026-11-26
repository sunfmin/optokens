//! The Tailscale CLI, `tailscale`: the one module that builds its command
//! lines and reads its answers. The tests' stand-in shares these constants.

use std::net::IpAddr;

/// The program's name on `PATH`.
pub const PROGRAM: &str = "tailscale";
/// What prints this host's tailnet addresses, one a line.
pub const IP: &[&str] = &["ip"];
/// What prints the tailnet's state as JSON.
pub const STATUS: &[&str] = &["status", "--json"];
/// The key of `status --json` listing the names `tailscale cert` can get a
/// certificate for: empty unless the tailnet has HTTPS certificates on.
pub const CERT_DOMAINS: &str = "CertDomains";

/// What turns on certificates for `tailscale cert`, said wherever one is missing.
pub const HTTPS_FIX: &str =
    "turn on MagicDNS and HTTPS Certificates in the DNS settings of the Tailscale admin console";

/// The addresses `tailscale ip` printed, in its order.
pub fn addresses(stdout: &str) -> Vec<IpAddr> {
    stdout
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

/// The names `tailscale cert` can get a certificate for, from `status --json`.
pub fn cert_domains(status: &str) -> Result<Vec<String>, String> {
    let status: serde_json::Value =
        serde_json::from_str(status).map_err(|e| format!("its JSON does not parse: {e}"))?;
    Ok(status[CERT_DOMAINS]
        .as_array()
        .map(|d| {
            d.iter()
                .filter_map(|n| n.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_addresses_and_the_cert_domains_are_read_from_its_answers() {
        let both: Vec<IpAddr> = vec![
            "100.73.216.32".parse().unwrap(),
            "fd7a:115c::1".parse().unwrap(),
        ];
        assert_eq!(addresses("100.73.216.32\n fd7a:115c::1 \n"), both);
        assert_eq!(addresses("\nnot an address\n"), Vec::<IpAddr>::new());
        assert_eq!(
            cert_domains(r#"{"CertDomains": ["a.tail.ts.net"]}"#).unwrap(),
            ["a.tail.ts.net"]
        );
        assert_eq!(
            cert_domains(r#"{"CertDomains": null}"#).unwrap(),
            Vec::<String>::new()
        );
        assert!(cert_domains("not json").is_err());
    }
}
