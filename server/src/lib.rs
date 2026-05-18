pub mod assets;
pub mod config;
pub mod imap;
pub mod server;
pub mod smtp;
pub mod spam;
pub mod store;
pub mod webmail;

/// Quality gate: clippy + full test suite + release build check.
/// Called by `cochranblock-mail-test` binary and `cochranblock-mail test` subcommand.
#[cfg(feature = "tests")]
pub fn run_tests() -> anyhow::Result<()> {
    use std::path::Path;
    use std::process::Command;
    use std::time::Instant;

    let project = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("server crate should have workspace parent");

    fn step(label: &str) {
        println!("cochranblock-mail-test: {label}...");
    }

    fn run(project: &Path, args: &[&str]) -> anyhow::Result<bool> {
        let status = Command::new("cargo")
            .current_dir(project)
            .args(args)
            .status()?;
        Ok(status.success())
    }

    let total = Instant::now();

    // ── 1. clippy ────────────────────────────────────────────────────────
    step("cargo clippy -p cochranblock-mail -p cochranblock-mail-shared");
    if !run(project, &[
        "clippy",
        "-p", "cochranblock-mail",
        "-p", "cochranblock-mail-shared",
        "--", "-D", "warnings",
    ])? {
        anyhow::bail!("clippy failed — fix warnings before shipping");
    }

    // ── 2. unit + doc tests ──────────────────────────────────────────────
    step("cargo test -p cochranblock-mail -p cochranblock-mail-shared");
    if !run(project, &[
        "test",
        "-p", "cochranblock-mail",
        "-p", "cochranblock-mail-shared",
    ])? {
        anyhow::bail!("tests failed");
    }

    // ── 3. release build check ───────────────────────────────────────────
    step("cargo check -p cochranblock-mail --release");
    if !run(project, &["check", "-p", "cochranblock-mail", "--release"])? {
        anyhow::bail!("release build check failed");
    }

    println!(
        "\ncochranblock-mail-test: all gates passed in {:.1}s",
        total.elapsed().as_secs_f64()
    );
    Ok(())
}
