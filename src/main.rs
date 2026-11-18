//! SubHunter entry point. Owner: Amirah.
//! Flow: CLI -> validate -> ethics confirm -> wordlist -> brute force -> wildcard -> risk -> CSV.

mod cli;
mod dns_bruteforce;
mod ethics;
mod finding;
mod reporter;
mod risk;
mod validator;
mod wildcard;
mod wordlist;

fn main() {
    // Skeleton only. Modules are wired together once each member's part is done.
    println!("SubHunter skeleton - not implemented yet");
}
