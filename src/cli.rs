//! Command line arguments. Owner: Amirah.

use clap::Parser;
use std::path::PathBuf;

/// SubHunter - educational subdomain enumerator. Use only on domains you own or are authorised to test.
#[derive(Parser, Debug)]
#[command(name = "subhunter", version)]
pub struct Args {
    /// Target domain (e.g. example.com)
    #[arg(short, long)]
    pub domain: String,

    /// Path to the wordlist file
    #[arg(short, long)]
    pub wordlist: PathBuf,

    /// Output CSV file
    #[arg(short, long, default_value = "output/report.csv")]
    pub output: PathBuf,
}
