//! Target domain and scope validation. Owner: Amirah.
//!
//! Checks that the `--domain` argument is a well-formed DNS domain name before
//! any network activity happens.This is a syntax check only: the tool does not
//! try to decide which domains are "allowed" (that is the user's responsibility
//! under the Rules of Engagement). Authorisation itself is confirmed by the
//! ethics gate in `ethics.rs`.

/// Maximum length of one DNS label (RFC 1035).
const MAX_LABEL_LEN: usize = 63;
/// Maximum length of a full domain name (RFC 1035).
const MAX_DOMAIN_LEN: usize = 253;

/// Check the domain is well formed. Returns a clear error message on failure so
/// `main` can print it and exit without a panic.
pub fn validate_domain(domain: &str) -> Result<(), String> {
    let domain = domain.trim().trim_end_matches('.');

    if domain.is_empty() {
        return Err("domain is empty".to_string());
    }
    if domain.len() > MAX_DOMAIN_LEN {
        return Err(format!(
            "domain is too long ({} characters, maximum {MAX_DOMAIN_LEN})",
            domain.len()
        ));
    }
    if domain.contains("://") {
        return Err("domain must be a hostname like example.com, not a URL (drop https://)".to_string());
    }
    if domain.contains('/') || domain.contains(' ') {
        return Err("domain must not contain spaces or slashes".to_string());
    }
    if domain.contains('*') {
        return Err("domain must be a concrete hostname, not a wildcard".to_string());
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Err("domain must be a name like example.com, not an IP address".to_string());
    }

    // A real target needs at least two labels ("example.com"), so a bare
    // "localhost" or a single word is rejected.
    if !domain.contains('.') {
        return Err("domain must contain at least one dot (e.g. example.com)".to_string());
    }

    for label in domain.split('.') {
        if !is_valid_label(label) {
            return Err(format!("invalid label '{label}' in domain '{domain}'"));
        }
    }

    Ok(())
}

/// One DNS label: 1-63 characters of letters, digits or hyphens, and it must not
/// start or end with a hyphen (RFC 1035).
fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_normal_domain() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("  Example.COM.  ").is_ok());
        assert!(validate_domain("sub.example.co.uk").is_ok());
        assert!(validate_domain("my-site.example.com").is_ok());
    }

    #[test]
    fn rejects_empty_and_whitespace() {
        assert!(validate_domain("").is_err());
        assert!(validate_domain("   ").is_err());
    }

    #[test]
    fn rejects_a_single_word() {
        assert!(validate_domain("localhost").is_err());
    }

    #[test]
    fn rejects_urls() {
        assert!(validate_domain("https://example.com").is_err());
        assert!(validate_domain("example.com/path").is_err());
    }

    #[test]
    fn rejects_ip_addresses() {
        assert!(validate_domain("192.0.2.1").is_err());
        assert!(validate_domain("2001:db8::1").is_err());
    }

    #[test]
    fn rejects_wildcards() {
        assert!(validate_domain("*.example.com").is_err());
    }

    #[test]
    fn rejects_bad_labels() {
        assert!(validate_domain("-bad.example.com").is_err());
        assert!(validate_domain("bad-.example.com").is_err());
        assert!(validate_domain("a b.example.com").is_err());
        assert!(validate_domain("under_score.example.com").is_err());
        assert!(validate_domain("a..b.example.com").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let label = "a".repeat(64);
        assert!(validate_domain(&format!("{label}.example.com")).is_err());
        let long = vec!["a"; 130].join(".");
        assert!(validate_domain(&long).is_err());
    }
}