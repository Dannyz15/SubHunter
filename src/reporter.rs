//! CSV report export. Owner: Ainin.
//!
//! Writes the findings to a local CSV file only. Nothing is uploaded or sent
//! anywhere (data handling safeguard). The default location `output/` is listed
//! in `.gitignore`, so scan results are never committed by mistake.

use crate::finding::{Finding, RecordType, WildcardStatus};
use serde::Serialize;
use std::fs;
use std::path::Path;

/// One CSV row. The field names become the header line.
#[derive(Serialize)]
struct Row<'a> {
    hostname: &'a str,
    record_type: &'static str,
    value: String,
    wildcard_status: &'static str,
    risk_level: &'a str,
    risk_reason: String,
}

/// Write findings to CSV with columns:
/// hostname, record_type, value, wildcard_status, risk_level, risk_reason.
/// The parent folder is created when it does not exist yet.
pub fn write_csv(findings: &[Finding], path: &Path) -> Result<(), String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create folder '{}': {e}", dir.display()))?;
    }

    let mut writer = csv::Writer::from_path(path)
        .map_err(|e| format!("cannot create report '{}': {e}", path.display()))?;

    for finding in findings {
        writer
            .serialize(to_row(finding))
            .map_err(|e| format!("cannot write report row: {e}"))?;
    }
    // An empty scan still gets a header line, so the user sees a valid (empty) report.
    if findings.is_empty() {
        writer
            .write_record([
                "hostname",
                "record_type",
                "value",
                "wildcard_status",
                "risk_level",
                "risk_reason",
            ])
            .map_err(|e| format!("cannot write report header: {e}"))?;
    }

    writer
        .flush()
        .map_err(|e| format!("cannot save report '{}': {e}", path.display()))
}

/// Turn one finding into a CSV row with readable text for every column.
fn to_row(finding: &Finding) -> Row<'_> {
    let (risk_level, risk_reason) = match &finding.risk {
        Some(risk) => (risk.level.as_str(), risk.reason.as_str()),
        None => ("not_assessed", ""),
    };
    Row {
        hostname: &finding.hostname,
        record_type: record_type_name(finding.record_type),
        value: safe_cell(&finding.value),
        wildcard_status: wildcard_name(finding.wildcard),
        risk_level,
        risk_reason: safe_cell(risk_reason),
    }
}

/// DNS spelling of the record type ("AAAA", not Rust's "Aaaa").
pub(crate) fn record_type_name(kind: RecordType) -> &'static str {
    match kind {
        RecordType::A => "A",
        RecordType::Aaaa => "AAAA",
        RecordType::Cname => "CNAME",
    }
}

pub(crate) fn wildcard_name(status: Option<WildcardStatus>) -> &'static str {
    match status {
        Some(WildcardStatus::LikelyGenuine) => "likely_genuine",
        Some(WildcardStatus::LikelyWildcard) => "likely_wildcard",
        Some(WildcardStatus::Uncertain) => "uncertain",
        None => "not_checked",
    }
}

/// Characters that can make a spreadsheet treat a cell as a formula (OWASP CSV
/// injection list): = + - @, plus tab and carriage return.
const FORMULA_START: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// Protect against CSV (formula) injection: a value from DNS that starts with one
/// of `FORMULA_START` could run as a formula when the report is opened in Excel,
/// so a leading quote is added to force it to be shown as plain text.
fn safe_cell(value: &str) -> String {
    if value.starts_with(FORMULA_START) {
        format!("'{value}")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Risk;
    use std::path::PathBuf;

    fn finding(host: &str, kind: RecordType, value: &str) -> Finding {
        Finding {
            hostname: host.into(),
            record_type: kind,
            value: value.into(),
            wildcard: None,
            risk: None,
        }
    }

    /// A unique file in the system temp folder, inside a sub folder that does not exist yet.
    fn temp_report(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("subhunter-test-{}-{name}", std::process::id()))
            .join("report.csv")
    }

    #[test]
    fn writes_header_and_rows() {
        let mut dev = finding("dev.example.com", RecordType::A, "192.0.2.10");
        dev.wildcard = Some(WildcardStatus::LikelyGenuine);
        dev.risk = Some(Risk {
            level: "medium".into(),
            reason: "Development host, may expose code; check it".into(),
        });
        let www = finding("www.example.com", RecordType::Aaaa, "2001:db8::1");

        let path = temp_report("rows");
        write_csv(&[dev, www], &path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        fs::remove_dir_all(path.parent().unwrap()).unwrap();

        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "hostname,record_type,value,wildcard_status,risk_level,risk_reason"
        );
        // The reason contains a comma, so the csv crate quotes it.
        assert_eq!(
            lines[1],
            "dev.example.com,A,192.0.2.10,likely_genuine,medium,\"Development host, may expose code; check it\""
        );
        assert_eq!(
            lines[2],
            "www.example.com,AAAA,2001:db8::1,not_checked,not_assessed,"
        );
    }

    #[test]
    fn empty_scan_still_has_header() {
        let path = temp_report("empty");
        write_csv(&[], &path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
        assert_eq!(
            text.trim(),
            "hostname,record_type,value,wildcard_status,risk_level,risk_reason"
        );
    }

    #[test]
    fn names_match_dns_spelling() {
        assert_eq!(record_type_name(RecordType::Aaaa), "AAAA");
        assert_eq!(record_type_name(RecordType::Cname), "CNAME");
        assert_eq!(wildcard_name(Some(WildcardStatus::Uncertain)), "uncertain");
    }

    #[test]
    fn formula_values_are_neutralised() {
        assert_eq!(safe_cell("=1+1"), "'=1+1");
        assert_eq!(safe_cell("@cmd"), "'@cmd");
        assert_eq!(safe_cell("192.0.2.1"), "192.0.2.1");
    }

    #[test]
    fn tab_and_carriage_return_are_neutralised() {
        assert_eq!(safe_cell("\t=1+1"), "'\t=1+1");
        assert_eq!(safe_cell("\r=1+1"), "'\r=1+1");
        // Only a leading tab or CR matters; one in the middle is left alone.
        assert_eq!(safe_cell("a\tb"), "a\tb");
    }

    #[test]
    fn bad_path_returns_error() {
        // A folder cannot be opened as a file, so this must fail without a panic.
        let dir = std::env::temp_dir();
        assert!(write_csv(&[], &dir).is_err());
    }

    /// Demo of the whole pipeline on example.com: wordlist, brute force, wildcard,
    /// risk, then the CSV in `output/report.csv` (git-ignored).
    /// Needs internet access. Run with
    /// `cargo test demo_report -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn demo_report_example_com() {
        use crate::dns_bruteforce::{self, BruteForceConfig};
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        let domain = "example.com";
        let words = crate::wordlist::load(Path::new("wordlists/small.txt")).unwrap();
        let candidates = crate::wordlist::build_candidates(&words, domain);
        let stop = Arc::new(AtomicBool::new(false));

        let baseline = crate::wildcard::baseline(domain, Arc::clone(&stop)).await;
        let mut report = dns_bruteforce::run(candidates, &BruteForceConfig::default(), stop)
            .await
            .unwrap();
        for f in &mut report.findings {
            f.wildcard = Some(crate::wildcard::classify(f, &baseline));
            f.risk = Some(crate::risk::assess(&f.hostname, domain));
        }

        let path = Path::new("output/report.csv");
        write_csv(&report.findings, path).unwrap();
        println!("{}", fs::read_to_string(path).unwrap());
        assert!(path.exists());
    }
}
