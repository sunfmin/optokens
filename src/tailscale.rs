//! The Tailscale CLI, `tailscale`: the one module that builds its command
//! lines and reads its answers. The tests' stand-in shares these constants.

/// The program's name on `PATH`.
pub const PROGRAM: &str = "tailscale";
/// What prints this host's tailnet addresses, one a line.
pub const IP: &[&str] = &["ip"];
/// What prints the tailnet's state as JSON.
pub const STATUS: &[&str] = &["status", "--json"];
/// The key of `status --json` listing the names `tailscale cert` can get a
/// certificate for: empty unless the tailnet has HTTPS certificates on.
pub const CERT_DOMAINS: &str = "CertDomains";

/// The first address `tailscale ip` printed.
pub fn address(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(String::from)
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
    fn the_first_address_and_the_cert_domains_are_read_from_its_answers() {
        assert_eq!(
            address("100.73.216.32\nfd7a:115c::1\n").as_deref(),
            Some("100.73.216.32")
        );
        assert_eq!(address("\n"), None);
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
