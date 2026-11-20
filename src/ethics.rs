//! Legal disclaimer and authorisation confirmation. Owner: Amirah.
//!
//! Before any DNS query is sent, the user is shown the legal disclaimer (matching
//! the README) and must retype the target domain to confirm they are authorised
//! to test it. The tool does not try to decide who is authorised; it only makes
//! sure the user has stopped and confirmed the target by name.

use std::io::{self, Write};

/// Normalise a domain for comparison: trim, drop a trailing dot, lower-case.
fn normalise(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_lowercase()
}

/// Pure check: does `input` confirm `domain`?
/// True only when both name the same host after normalising (case and trailing dot
/// ignored). A prefix does not count: "example" does not confirm "example.com".
fn confirmed(input: &str, domain: &str) -> bool {
    let input = normalise(input);
    let domain = normalise(domain);
    !input.is_empty() && input == domain
}

/// Print the Computer Crimes Act disclaimer and require the user to retype the
/// target domain. Returns true only when the typed text matches `domain`.
pub fn confirm_authorisation(domain: &str) -> bool {
    println!("------------------------------------------------------------");
    println!("SubHunter is for education and authorised security testing only.");
    println!();
    println!("- Only run it against domains you own or have explicit written");
    println!("  permission to test.");
    println!("- Unauthorised scanning or enumeration may be an offence under the");
    println!("  Computer Crimes Act 1997 (Malaysia) and similar laws in other");
    println!("  countries.");
    println!("- The authors accept no liability for misuse or for any damage");
    println!("  caused by this tool. You are solely responsible for how you use it.");
    println!("------------------------------------------------------------");
    print!("Type the domain again to confirm you are authorised to test it: ");
    // The prompt must appear before we block on stdin, so flush it now.
    let _ = io::stdout().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        println!("\nCould not read confirmation; refusing to continue.");
        return false;
    }

    if confirmed(&input, domain) {
        true
    } else {
        println!("Confirmation did not match '{domain}'. No scan was run.");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_confirms() {
        assert!(confirmed("example.com", "example.com"));
    }

    #[test]
    fn case_and_trailing_dot_are_ignored() {
        assert!(confirmed("  Example.COM.  ", "example.com"));
        assert!(confirmed("example.com", "Example.com."));
    }

    #[test]
    fn empty_input_does_not_confirm() {
        assert!(!confirmed("", "example.com"));
        assert!(!confirmed("   ", "example.com"));
    }

    #[test]
    fn a_prefix_does_not_confirm() {
        assert!(!confirmed("example", "example.com"));
        assert!(!confirmed("example.co", "example.com"));
    }

    #[test]
    fn a_different_domain_does_not_confirm() {
        assert!(!confirmed("evil.com", "example.com"));
    }
}
