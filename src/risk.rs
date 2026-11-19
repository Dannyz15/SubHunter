//! Hostname risk analysis. Owner: Ainin.
//!
//! Looks at the subdomain part of a hostname (the labels in front of the target
//! domain) and flags words that often point to sensitive systems, such as admin
//! panels, remote access, development copies or databases. These are hints based
//! on the name only, not confirmed vulnerabilities.

use crate::finding::Risk;

pub const HIGH: &str = "high";
pub const MEDIUM: &str = "medium";
pub const LOW: &str = "low";
pub const NONE: &str = "none";

/// One hostname pattern: the words that trigger it, its level and the reason shown to the user.
struct Pattern {
    words: &'static [&'static str],
    level: &'static str,
    reason: &'static str,
}

/// Known patterns, checked against every word of the subdomain.
const PATTERNS: &[Pattern] = &[
    Pattern {
        words: &[
            "admin",
            "administrator",
            "cpanel",
            "phpmyadmin",
            "dashboard",
            "manage",
            "manager",
        ],
        level: HIGH,
        reason: "Administration panel may give control over the site if exposed",
    },
    Pattern {
        words: &["vpn", "remote", "rdp", "ssh", "citrix", "gateway"],
        level: HIGH,
        reason: "Remote access entry point into the internal network",
    },
    Pattern {
        words: &[
            "db", "database", "mysql", "sql", "postgres", "mongo", "redis",
        ],
        level: HIGH,
        reason: "Database host should not be reachable from the internet",
    },
    Pattern {
        words: &["backup", "backups", "bak", "old", "legacy", "archive"],
        level: HIGH,
        reason: "Backup or old system may hold copies of data or unpatched software",
    },
    Pattern {
        words: &["internal", "intranet", "private", "corp"],
        level: HIGH,
        reason: "Internal system appears to be published in public DNS",
    },
    Pattern {
        words: &[
            "dev",
            "develop",
            "development",
            "staging",
            "stage",
            "stg",
            "uat",
            "qa",
            "preprod",
        ],
        level: MEDIUM,
        reason: "Development or staging host may expose unfinished code or debug features",
    },
    Pattern {
        words: &["test", "testing", "demo", "sandbox", "beta", "debug"],
        level: MEDIUM,
        reason: "Test system is often less protected than production",
    },
    Pattern {
        words: &["git", "gitlab", "jenkins", "ci", "jira", "svn"],
        level: MEDIUM,
        reason: "Source code or build server may leak code or credentials",
    },
    Pattern {
        words: &["ftp", "sftp", "files", "upload", "uploads"],
        level: MEDIUM,
        reason: "File transfer service may allow access to stored files",
    },
    Pattern {
        words: &["api"],
        level: LOW,
        reason: "API endpoint, worth checking for missing authentication",
    },
    Pattern {
        words: &["mail", "webmail", "smtp", "imap", "pop", "mx"],
        level: LOW,
        reason: "Mail service login page may be a target for password guessing",
    },
    Pattern {
        words: &["portal", "login", "auth", "sso"],
        level: LOW,
        reason: "Login page may be a target for password guessing",
    },
];

/// Inspect the subdomain part of `hostname` (everything in front of `domain`) and
/// return a risk indicator. When several patterns match, the highest level wins
/// and all matching reasons are listed.
pub fn assess(hostname: &str, domain: &str) -> Risk {
    let mut level = NONE;
    let mut reasons: Vec<&str> = Vec::new();

    for word in words(subdomain_part(hostname, domain)) {
        for pattern in PATTERNS {
            if pattern.words.contains(&word.as_str()) && !reasons.contains(&pattern.reason) {
                reasons.push(pattern.reason);
                if rank(pattern.level) > rank(level) {
                    level = pattern.level;
                }
            }
        }
    }

    Risk {
        level: level.to_string(),
        reason: reasons.join("; "),
    }
}

/// Remove the target domain from the end, so "dev.api.example.com" with domain
/// "example.com" gives "dev.api". This stops a domain such as "test.dev" from
/// marking every result as risky.
fn subdomain_part<'a>(hostname: &'a str, domain: &str) -> &'a str {
    let host = hostname.trim_end_matches('.');
    let domain = domain.trim().trim_end_matches('.');
    // Compare bytes, so a non-ASCII hostname can never cause a slicing panic.
    let cut = host.len().saturating_sub(domain.len());
    if host.len() > domain.len()
        && host.as_bytes()[cut..].eq_ignore_ascii_case(domain.as_bytes())
        && host.is_char_boundary(cut)
    {
        let rest = &host[..cut];
        if let Some(prefix) = rest.strip_suffix('.') {
            return prefix;
        }
    }
    host
}

/// Split a subdomain into lower-case words on dots and hyphens, and drop trailing
/// digits, so "Dev-API2.test01" gives ["dev", "api", "test"].
fn words(subdomain: &str) -> Vec<String> {
    subdomain
        .split(['.', '-'])
        .map(|w| {
            w.trim_end_matches(|c: char| c.is_ascii_digit())
                .to_ascii_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect()
}

/// Order of the levels, so the highest one can be kept.
fn rank(level: &str) -> u8 {
    match level {
        HIGH => 3,
        MEDIUM => 2,
        LOW => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_is_high() {
        let risk = assess("admin.example.com", "example.com");
        assert_eq!(risk.level, HIGH);
        assert!(risk.reason.contains("Administration panel"));
    }

    #[test]
    fn vpn_is_high_and_dev_is_medium() {
        assert_eq!(assess("vpn.example.com", "example.com").level, HIGH);
        assert_eq!(assess("dev.example.com", "example.com").level, MEDIUM);
        assert_eq!(assess("staging.example.com", "example.com").level, MEDIUM);
        assert_eq!(assess("test.example.com", "example.com").level, MEDIUM);
    }

    #[test]
    fn ordinary_name_has_no_risk() {
        let risk = assess("www.example.com", "example.com");
        assert_eq!(risk.level, NONE);
        assert!(risk.reason.is_empty());
    }

    #[test]
    fn numbers_hyphens_and_case_are_handled() {
        assert_eq!(assess("Dev01.example.com", "example.com").level, MEDIUM);
        assert_eq!(assess("my-admin2.example.com", "example.com").level, HIGH);
    }

    #[test]
    fn highest_level_wins_and_all_reasons_are_listed() {
        let risk = assess("dev.admin.example.com", "example.com");
        assert_eq!(risk.level, HIGH);
        assert!(risk.reason.contains("Administration panel"));
        assert!(risk.reason.contains("Development or staging"));
    }

    #[test]
    fn whole_words_only() {
        // "badminton" contains "admin" and "devices" contains "dev", but neither is the word.
        assert_eq!(assess("badminton.example.com", "example.com").level, NONE);
        assert_eq!(assess("devices.example.com", "example.com").level, NONE);
    }

    #[test]
    fn target_domain_words_are_ignored() {
        // The domain itself is "test.dev", so only "www" is checked.
        assert_eq!(assess("www.test.dev", "test.dev").level, NONE);
        assert_eq!(assess("admin.test.dev.", "Test.Dev").level, HIGH);
    }

    #[test]
    fn subdomain_part_strips_domain() {
        assert_eq!(
            subdomain_part("dev.api.example.com", "example.com"),
            "dev.api"
        );
        assert_eq!(
            subdomain_part("notexample.com", "example.com"),
            "notexample.com"
        );
    }
}
