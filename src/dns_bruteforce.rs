//! DNS brute force engine. Owner: Danial.
//!
//! Resolves every candidate hostname for A, AAAA and CNAME records.
//! Lookups run concurrently but are capped (semaphore) and paced (interval),
//! so the scan never floods the resolver. A shared stop flag acts as the kill switch.

use crate::finding::{Finding, RecordType};
use hickory_resolver::TokioResolver;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::{RData, RecordType as DnsType};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Tuning for the brute force. The defaults are deliberately conservative (safe defaults).
#[derive(Debug, Clone)]
pub struct BruteForceConfig {
    /// Maximum number of hostnames being resolved at the same time.
    pub concurrency: usize,
    /// Minimum gap between starting two hostnames (rate limit).
    pub delay: Duration,
    /// Time allowed for one DNS query before it counts as a timeout.
    pub timeout: Duration,
    /// Number of tries per query.
    pub attempts: usize,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            concurrency: 10,
            delay: Duration::from_millis(50),
            timeout: Duration::from_secs(3),
            attempts: 2,
        }
    }
}

/// Everything the brute force produced, including counters for the report.
#[derive(Debug, Default)]
pub struct BruteForceReport {
    pub findings: Vec<Finding>,
    pub queried: usize,
    pub resolved: usize,
    pub timeouts: usize,
    pub errors: usize,
    /// True when the kill switch ended the scan early.
    pub stopped: bool,
}

/// What happened to one hostname.
enum HostOutcome {
    Found(Vec<Finding>),
    NotFound,
    Timeout,
    Error(String),
}

/// Resolve every candidate hostname and return a Finding per A / AAAA / CNAME record.
/// `stop` is the kill switch: once it is set no new lookups start, the lookups already
/// running are allowed to finish, and the results found so far are returned.
pub async fn run(
    candidates: Vec<String>,
    config: &BruteForceConfig,
    stop: Arc<AtomicBool>,
) -> Result<BruteForceReport, String> {
    let resolver = Arc::new(build_resolver(config)?);
    let permits = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let mut pacer = tokio::time::interval(config.delay.max(Duration::from_millis(1)));
    let mut tasks = JoinSet::new();
    let mut report = BruteForceReport::default();

    for host in candidates {
        if stop.load(Ordering::SeqCst) {
            report.stopped = true;
            break;
        }
        pacer.tick().await;
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| format!("semaphore closed: {e}"))?;

        let resolver = Arc::clone(&resolver);
        tasks.spawn(async move {
            let outcome = resolve_host(&resolver, &host).await;
            drop(permit);
            (host, outcome)
        });
        report.queried += 1;

        while let Some(done) = tasks.try_join_next() {
            record_outcome(&mut report, done);
        }
    }

    while let Some(done) = tasks.join_next().await {
        record_outcome(&mut report, done);
    }
    Ok(report)
}

/// Build a resolver from the system DNS settings with our timeout and attempts.
fn build_resolver(config: &BruteForceConfig) -> Result<TokioResolver, String> {
    let mut builder = TokioResolver::builder_tokio()
        .map_err(|e| format!("cannot read system DNS configuration: {e}"))?;
    let options = builder.options_mut();
    options.timeout = config.timeout;
    options.attempts = config.attempts.max(1);
    builder
        .build()
        .map_err(|e| format!("cannot create DNS resolver: {e}"))
}

/// Query A, AAAA and CNAME for one hostname and turn the answers into findings.
async fn resolve_host(resolver: &TokioResolver, host: &str) -> HostOutcome {
    // A trailing dot makes the name fully qualified, so no search domains are tried.
    let fqdn = format!("{host}.");
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let mut timed_out = false;
    let mut last_error = None;

    for query in [DnsType::A, DnsType::AAAA, DnsType::CNAME] {
        match resolver.lookup(fqdn.as_str(), query).await {
            Ok(lookup) => {
                for record in lookup.answers() {
                    let Some((kind, value)) = convert(&record.data) else {
                        continue;
                    };
                    if seen.insert((kind, value.clone())) {
                        findings.push(Finding {
                            hostname: host.to_string(),
                            record_type: kind,
                            value,
                            wildcard: None,
                            risk: None,
                        });
                    }
                }
            }
            Err(e) if e.is_no_records_found() => {}
            Err(NetError::Timeout) => timed_out = true,
            Err(e) => last_error = Some(e.to_string()),
        }
    }

    if !findings.is_empty() {
        HostOutcome::Found(findings)
    } else if timed_out {
        HostOutcome::Timeout
    } else if let Some(message) = last_error {
        HostOutcome::Error(message)
    } else {
        HostOutcome::NotFound
    }
}

/// Map a DNS answer to our record type and a printable value. Other types are ignored.
fn convert(data: &RData) -> Option<(RecordType, String)> {
    match data {
        RData::A(ip) => Some((RecordType::A, ip.0.to_string())),
        RData::AAAA(ip) => Some((RecordType::Aaaa, ip.0.to_string())),
        RData::CNAME(target) => Some((
            RecordType::Cname,
            target.0.to_string().trim_end_matches('.').to_string(),
        )),
        _ => None,
    }
}

/// Add one finished lookup to the report.
fn record_outcome(
    report: &mut BruteForceReport,
    done: Result<(String, HostOutcome), tokio::task::JoinError>,
) {
    match done {
        Ok((_, HostOutcome::Found(mut findings))) => {
            report.resolved += 1;
            report.findings.append(&mut findings);
        }
        Ok((_, HostOutcome::NotFound)) => {}
        Ok((host, HostOutcome::Timeout)) => {
            report.timeouts += 1;
            eprintln!("[timeout] {host}");
        }
        Ok((host, HostOutcome::Error(message))) => {
            report.errors += 1;
            eprintln!("[error] {host}: {message}");
        }
        Err(e) => {
            report.errors += 1;
            eprintln!("[error] lookup task failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME};
    use hickory_resolver::proto::rr::Name;
    use std::str::FromStr;

    #[test]
    fn convert_maps_supported_records() {
        let a = RData::A(A::new(192, 0, 2, 1));
        assert_eq!(convert(&a), Some((RecordType::A, "192.0.2.1".into())));

        let aaaa = RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(convert(&aaaa), Some((RecordType::Aaaa, "2001:db8::1".into())));

        let cname = RData::CNAME(CNAME(Name::from_str("target.example.com.").unwrap()));
        assert_eq!(
            convert(&cname),
            Some((RecordType::Cname, "target.example.com".into()))
        );
    }

    #[tokio::test]
    async fn stop_flag_prevents_any_lookup() {
        let stop = Arc::new(AtomicBool::new(true));
        let candidates = vec!["www.example.com".to_string()];
        let report = run(candidates, &BruteForceConfig::default(), stop)
            .await
            .unwrap();
        assert!(report.stopped);
        assert_eq!(report.queried, 0);
        assert!(report.findings.is_empty());
    }

    /// Needs internet access. Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn resolves_real_and_missing_names() {
        let stop = Arc::new(AtomicBool::new(false));
        let candidates = vec![
            "www.example.com".to_string(),
            "this-name-should-not-exist-7f3a.example.com".to_string(),
        ];
        let report = run(candidates, &BruteForceConfig::default(), stop)
            .await
            .unwrap();
        assert_eq!(report.queried, 2);
        assert_eq!(report.resolved, 1);
        assert!(report.findings.iter().all(|f| f.hostname == "www.example.com"));
    }

    /// Demo run of the full wordlist module + brute force on example.com.
    /// Needs internet access. Run with
    /// `cargo test demo_small_wordlist -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore]
    async fn demo_small_wordlist() {
        let words = crate::wordlist::load(std::path::Path::new("wordlists/small.txt")).unwrap();
        let candidates = crate::wordlist::build_candidates(&words, "example.com");
        let stop = Arc::new(AtomicBool::new(false));
        let report = run(candidates, &BruteForceConfig::default(), stop)
            .await
            .unwrap();

        println!(
            "queried={} resolved={} timeouts={} errors={}",
            report.queried, report.resolved, report.timeouts, report.errors
        );
        for f in &report.findings {
            println!("{:<28} {:<6?} {}", f.hostname, f.record_type, f.value);
        }
        assert_eq!(report.queried, words.len());
    }
}
