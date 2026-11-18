//! Hostname risk analysis. Owner: Ainin.

use crate::finding::Risk;

/// Inspect the hostname for patterns such as admin, dev, staging, vpn, test
/// and return a risk indicator with a plain-language reason.
pub fn assess(_hostname: &str) -> Risk {
    todo!("Ainin: pattern matching and reasons")
}
