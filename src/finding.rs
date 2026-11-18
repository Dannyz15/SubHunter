//! Shared data types passed between modules.
//! Owner: Amirah (agree on changes with the team before editing).

use serde::Serialize;

/// DNS record type found for a hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
}

/// Result of wildcard classification (Farzana).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum WildcardStatus {
    LikelyGenuine,
    LikelyWildcard,
    Uncertain,
}

/// Risk indicator assigned by risk analysis (Ainin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Risk {
    pub level: String,  // e.g. "high", "medium", "low", "none"
    pub reason: String, // human readable explanation
}

/// One resolved subdomain. Created by dns_bruteforce, then enriched by
/// wildcard and risk, then written out by reporter.
#[derive(Debug, Clone)]
pub struct Finding {
    pub hostname: String,
    pub record_type: RecordType,
    pub value: String,
    pub wildcard: Option<WildcardStatus>,
    pub risk: Option<Risk>,
}
