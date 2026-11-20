//! Wildcard DNS detection. Owner: Farzana.
//!
//! A domain with wildcard DNS (`*.example.com`) answers for every name, even ones
//! that do not exist, so a brute force would "find" every word in the wordlist.
//! To spot this we first resolve a few random names that cannot be real. Whatever
//! they resolve to is the wildcard answer (the baseline). Each finding is then
//! compared against that baseline.

use crate::dns_bruteforce::{self, BruteForceConfig};
use crate::finding::{Finding, WildcardStatus};
use rand::distr::{Alphanumeric, SampleString};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Number of random hostnames probed to build the baseline. More than one, because
/// round-robin wildcards can return a different IP for each name.
const PROBES: usize = 3;
/// Length of each random label. Long enough that a real host with this name is
/// practically impossible.
const LABEL_LEN: usize = 16;

/// Look up random hostnames under `domain` to learn what a wildcard answer looks like.
/// Returns the IPs/CNAME values the wildcard resolves to (empty = no wildcard).
///
/// `stop` is the same kill switch the brute force uses: once Ctrl+C sets it, no new
/// probe starts and whatever was learned so far is returned.
pub async fn baseline(domain: &str, stop: Arc<AtomicBool>) -> Vec<String> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    let candidates: Vec<String> = (0..PROBES)
        .map(|_| format!("{}.{domain}", random_label()))
        .collect();

    let report = match dns_bruteforce::run(candidates, &BruteForceConfig::default(), stop).await {
        Ok(report) => report,
        Err(e) => {
            // Without a baseline we cannot detect a wildcard. Results will then be
            // treated as genuine, so warn the user.
            eprintln!("[warning] wildcard check failed, results may include wildcard noise: {e}");
            return Vec::new();
        }
    };

    // A probe that timed out or failed tells us nothing, so the baseline may be
    // incomplete (or empty while the domain really has a wildcard). Say so instead of
    // silently treating every result as genuine.
    // When the user pressed Ctrl+C the scan is ending anyway, so no warning is needed.
    if !report.stopped {
        if let Some(message) = probe_warning(report.timeouts, report.errors) {
            eprintln!("{message}");
        }
    }

    let mut values: Vec<String> = report.findings.into_iter().map(|f| f.value).collect();
    values.sort();
    values.dedup();
    values
}

/// Warning shown when some wildcard probes timed out or failed, or `None` when all
/// probes got a clear answer. It also explains the `[timeout]` / `[error]` lines that
/// the brute force engine printed for the random probe names.
fn probe_warning(timeouts: usize, errors: usize) -> Option<String> {
    let failed = timeouts + errors;
    if failed == 0 {
        return None;
    }
    Some(format!(
        "[warning] wildcard check incomplete: {failed} of {PROBES} random probe names \
         timed out or failed (the random-looking hostnames above are these probes). \
         Results may include wildcard noise."
    ))
}

/// Compare a finding with the baseline and classify it.
///
/// - No baseline (domain has no wildcard): `LikelyGenuine`.
/// - Value is exactly one of the wildcard answers: `LikelyWildcard`.
/// - IP is in the same network as a wildcard answer (same /24 for IPv4, same /64
///   for IPv6): `Uncertain`, since it may be another IP from the wildcard's
///   round-robin pool, or a real host in the same hosting network.
/// - Anything else: `LikelyGenuine`, because the name points somewhere the wildcard does not.
pub fn classify(finding: &Finding, baseline: &[String]) -> WildcardStatus {
    if baseline.is_empty() {
        return WildcardStatus::LikelyGenuine;
    }

    let value = finding.value.trim_end_matches('.').to_lowercase();
    if baseline
        .iter()
        .any(|b| b.trim_end_matches('.').eq_ignore_ascii_case(&value))
    {
        return WildcardStatus::LikelyWildcard;
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        let near_wildcard = baseline
            .iter()
            .filter_map(|b| b.parse::<IpAddr>().ok())
            .any(|b| same_network(ip, b));
        if near_wildcard {
            return WildcardStatus::Uncertain;
        }
    }

    WildcardStatus::LikelyGenuine
}

/// Random lower-case alphanumeric DNS label, e.g. "k3x9q0zt7m2bw8ra".
fn random_label() -> String {
    Alphanumeric
        .sample_string(&mut rand::rng(), LABEL_LEN)
        .to_lowercase()
}

/// True when both addresses share a /24 (IPv4) or /64 (IPv6) prefix.
fn same_network(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..3] == b.octets()[..3],
        (IpAddr::V6(a), IpAddr::V6(b)) => a.segments()[..4] == b.segments()[..4],
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::RecordType;

    fn finding(record_type: RecordType, value: &str) -> Finding {
        Finding {
            hostname: "www.example.com".into(),
            record_type,
            value: value.into(),
            wildcard: None,
            risk: None,
        }
    }

    fn base(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn no_wildcard_means_genuine() {
        let f = finding(RecordType::A, "192.0.2.10");
        assert_eq!(classify(&f, &[]), WildcardStatus::LikelyGenuine);
    }

    #[test]
    fn exact_ip_match_is_wildcard() {
        let f = finding(RecordType::A, "192.0.2.10");
        let b = base(&["192.0.2.10", "192.0.2.11"]);
        assert_eq!(classify(&f, &b), WildcardStatus::LikelyWildcard);
    }

    #[test]
    fn cname_match_ignores_case_and_trailing_dot() {
        let f = finding(RecordType::Cname, "Parking.Example.net");
        let b = base(&["parking.example.net."]);
        assert_eq!(classify(&f, &b), WildcardStatus::LikelyWildcard);
    }

    #[test]
    fn same_ipv4_subnet_is_uncertain() {
        let f = finding(RecordType::A, "192.0.2.99");
        let b = base(&["192.0.2.10"]);
        assert_eq!(classify(&f, &b), WildcardStatus::Uncertain);
    }

    #[test]
    fn same_ipv6_prefix_is_uncertain() {
        let f = finding(RecordType::Aaaa, "2001:db8:1:2::99");
        let b = base(&["2001:db8:1:2::1"]);
        assert_eq!(classify(&f, &b), WildcardStatus::Uncertain);
    }

    #[test]
    fn different_ip_is_genuine() {
        let f = finding(RecordType::A, "198.51.100.7");
        let b = base(&["192.0.2.10"]);
        assert_eq!(classify(&f, &b), WildcardStatus::LikelyGenuine);
    }

    #[test]
    fn different_cname_is_genuine() {
        let f = finding(RecordType::Cname, "app.hosting.example.org");
        let b = base(&["parking.example.net"]);
        assert_eq!(classify(&f, &b), WildcardStatus::LikelyGenuine);
    }

    #[test]
    fn random_labels_are_valid_and_differ() {
        let a = random_label();
        let b = random_label();
        assert_eq!(a.len(), LABEL_LEN);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        assert_ne!(a, b);
    }

    #[test]
    fn no_warning_when_all_probes_answered() {
        assert_eq!(probe_warning(0, 0), None);
    }

    #[test]
    fn warning_counts_timeouts_and_errors() {
        let message = probe_warning(2, 1).expect("warning expected");
        assert!(message.starts_with("[warning] wildcard check incomplete"));
        assert!(message.contains("3 of 3 random probe names"));
    }

    /// Kill switch already set: no probe is sent, so the baseline is empty.
    /// No network needed, because no lookup starts.
    #[tokio::test]
    async fn stop_flag_prevents_any_probe() {
        let stop = Arc::new(AtomicBool::new(true));
        assert!(baseline("example.com", stop).await.is_empty());
    }

    /// example.com has no wildcard, so the baseline should be empty.
    /// Needs internet access. Run with `cargo test baseline_ -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn baseline_empty_for_domain_without_wildcard() {
        let stop = Arc::new(AtomicBool::new(false));
        assert!(baseline("example.com", stop).await.is_empty());
    }
}
