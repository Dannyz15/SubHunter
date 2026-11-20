//! SubHunter entry point. Owner: Amirah.
//! Flow: CLI -> validate -> wordlist -> ethics confirm -> wildcard -> brute force -> risk -> CSV.

mod cli;
mod dns_bruteforce;
mod ethics;
mod finding;
mod reporter;
mod risk;
mod validator;
mod wildcard;
mod wordlist;

use clap::Parser;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::main]
async fn main() -> ExitCode {
    let args = cli::Args::parse();

    // 1. Validate the domain syntax
    if let Err(e) = validator::validate_domain(&args.domain) {
        eprintln!("[error] {e}");
        return ExitCode::FAILURE;
    }

    // 2. Load the wordlist and build candidates (moved up so bad paths fail before the disclaimer)
    let words = match wordlist::load(&args.wordlist) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[error] {e}");
            return ExitCode::FAILURE;
        }
    };
    let candidates = wordlist::build_candidates(&words, &args.domain);
    if candidates.is_empty() {
        eprintln!("[error] no valid candidate hostnames could be built from the wordlist");
        return ExitCode::FAILURE;
    }

    // 3. Legal disclaimer and authorisation
    if !ethics::confirm_authorisation(&args.domain) {
        return ExitCode::FAILURE;
    }

    // 4. Set up the shared kill switch and Ctrl+C handler
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        if let Err(e) = ctrlc::set_handler(move || {
            eprintln!("\n[!] Ctrl+C received. Finishing current lookups and saving results...");
            stop.store(true, Ordering::SeqCst);
        }) {
            eprintln!("[error] failed to set Ctrl+C handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    println!("[*] Target: {}", args.domain);
    println!("[*] Wordlist: {} words loaded", words.len());

    // 5. Wildcard baseline
    println!("[*] Checking for wildcard DNS...");
    let baseline = wildcard::baseline(&args.domain, Arc::clone(&stop)).await;

    // 6. Check stop flag right after baseline (Danial's PR #2 review note)
    if stop.load(Ordering::SeqCst) {
        println!("[!] Scan stopped before starting the main brute force.");
        return ExitCode::SUCCESS;
    }

    // 7. Brute force
    let config = dns_bruteforce::BruteForceConfig::default();
    let mut report = match dns_bruteforce::run(candidates, &config, Arc::clone(&stop)).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[error] {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "[*] Brute force finished: {} queried, {} resolved, {} timeouts, {} errors{}",
        report.queried,
        report.resolved,
        report.timeouts,
        report.errors,
        if report.stopped {
            " (stopped early)"
        } else {
            ""
        }
    );

    // 8. Classify and assess
    println!("[*] Classifying results...");
    for f in &mut report.findings {
        f.wildcard = Some(wildcard::classify(f, &baseline));
        f.risk = Some(risk::assess(&f.hostname, &args.domain));
    }

    // 9. Save the CSV
    if let Err(e) = reporter::write_csv(&report.findings, &args.output) {
        eprintln!("[error] {e}");
        return ExitCode::FAILURE;
    }
    println!("[+] Report saved to: {}", args.output.display());

    // 10. Print a summary table to the terminal (Danial's PR #5 review note)
    if !report.findings.is_empty() {
        println!("\n[*] Found subdomains:");
        println!(
            "{:<30} {:<6} {:<20} {:<15} {:<8}",
            "HOSTNAME", "TYPE", "VALUE", "WILDCARD", "RISK"
        );
        for f in &report.findings {
            let wc = format!("{:?}", f.wildcard.as_ref().unwrap());
            let rk = f.risk.as_ref().map(|r| r.level.as_str()).unwrap_or("none");
            println!(
                "{:<30} {:<6?} {:<20} {:<15} {:<8}",
                f.hostname, f.record_type, f.value, wc, rk
            );
        }
    }

    ExitCode::SUCCESS
}
