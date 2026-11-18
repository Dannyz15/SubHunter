//! CSV report export. Owner: Ainin.

use crate::finding::Finding;
use std::path::Path;

/// Write findings to CSV with columns:
/// hostname, record_type, value, wildcard_status, risk_level, risk_reason.
pub fn write_csv(_findings: &[Finding], _path: &Path) -> Result<(), String> {
    todo!("Ainin: csv writer")
}
