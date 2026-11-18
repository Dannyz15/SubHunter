//! Wildcard DNS detection. Owner: Farzana.

use crate::finding::{Finding, WildcardStatus};

/// Look up random hostnames under `domain` to learn what a wildcard answer looks like.
/// Returns the IPs/CNAME values the wildcard resolves to (empty = no wildcard).
pub async fn baseline(_domain: &str) -> Vec<String> {
    todo!("Farzana: random hostname lookup")
}

/// Compare a finding with the baseline and classify it.
pub fn classify(_finding: &Finding, _baseline: &[String]) -> WildcardStatus {
    todo!("Farzana: genuine / wildcard / uncertain")
}
