//! Thin wrapper — delegates to cochranblock_mail::run_tests().
//! Use `cochranblock-mail-test` or `cochranblock-mail test` subcommand.

// Unlicense — cochranblock.org
// Contributors: GotEmCoach, Claude Sonnet 4.6

fn main() {
    if let Err(e) = cochranblock_mail::run_tests() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
