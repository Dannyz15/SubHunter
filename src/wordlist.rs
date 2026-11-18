//! Read and process the wordlist. Owner: Danial.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Maximum length of one DNS label (RFC 1035).
const MAX_LABEL_LEN: usize = 63;
/// Maximum length of a full hostname (RFC 1035).
const MAX_HOSTNAME_LEN: usize = 253;

/// Load a wordlist file.
/// Each line is trimmed and lower-cased. Blank lines and `#` comments are skipped,
/// and duplicates are removed while keeping the original order.
pub fn load(path: &Path) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("cannot read wordlist '{}': {}", path.display(), e))?;

    let words = clean(&content);
    if words.is_empty() {
        return Err(format!("wordlist '{}' has no usable entries", path.display()));
    }
    Ok(words)
}

/// Clean raw wordlist text. Kept separate from `load` so it can be unit tested without files.
fn clean(content: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut words = Vec::new();

    for line in content.lines() {
        let word = line.trim().to_lowercase();
        if word.is_empty() || word.starts_with('#') {
            continue;
        }
        if seen.insert(word.clone()) {
            words.push(word);
        }
    }
    words
}

/// Build candidate hostnames, e.g. word "www" + domain "example.com" -> "www.example.com".
/// Words that would produce an invalid hostname are skipped so no bad query is sent.
pub fn build_candidates(words: &[String], domain: &str) -> Vec<String> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();

    words
        .iter()
        .filter(|word| is_valid_prefix(word))
        .map(|word| format!("{word}.{domain}"))
        .filter(|host| host.len() <= MAX_HOSTNAME_LEN)
        .collect()
}

/// A prefix may hold several labels ("dev.api"). Each label must be 1-63 characters
/// of letters, digits or hyphens, and must not start or end with a hyphen.
fn is_valid_prefix(prefix: &str) -> bool {
    prefix.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_skips_blanks_comments_and_duplicates() {
        let raw = "www\n\n  # comment\nMail\nwww\n  dev  \n";
        assert_eq!(clean(raw), vec!["www", "mail", "dev"]);
    }

    #[test]
    fn candidates_are_joined_with_domain() {
        let words = vec!["www".to_string(), "dev.api".to_string()];
        assert_eq!(
            build_candidates(&words, "Example.com."),
            vec!["www.example.com", "dev.api.example.com"]
        );
    }

    #[test]
    fn invalid_words_are_rejected() {
        let words: Vec<String> = ["-bad", "bad-", "a b", "under_score", "a..b", "ok"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(build_candidates(&words, "example.com"), vec!["ok.example.com"]);
    }

    #[test]
    fn overlong_label_is_rejected() {
        let words = vec!["a".repeat(64), "a".repeat(63)];
        let result = build_candidates(&words, "example.com");
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn missing_file_returns_error() {
        assert!(load(Path::new("does/not/exist.txt")).is_err());
    }
}
