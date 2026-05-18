pub mod assets;
pub mod config;
pub mod imap;
pub mod server;
pub mod smtp;
pub mod spam;
pub mod store;
pub mod webmail;

#[cfg(feature = "tests")]
pub mod e2e;

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

    // ── 4. end-to-end integration test ──────────────────────────────────
    step("e2e: live SMTP/IMAP/HTTP integration test");
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(crate::e2e::run())?;

    // ── 5. PDF proof-of-action + push to Mac Mini ────────────────────────
    let screenshots_dir = project.join("screenshots");
    let pdf_out = screenshots_dir.join("e2e_report.pdf");
    let pdf_script = format!(r#"
from PIL import Image
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import os

shots_dir = "{}"
out = "{}"
files = [
    ("e2e_01_login.png",   "Login — credentials"),
    ("e2e_02_totp.png",    "Login — TOTP verify"),
    ("e2e_03_inbox.png",   "Inbox — E2E email delivered"),
    ("e2e_04_message.png", "Email read view"),
]
c = canvas.Canvas(out)
for fname, title in files:
    path = os.path.join(shots_dir, fname)
    if not os.path.exists(path):
        continue
    img = Image.open(path)
    w, h = img.size
    margin, title_h = 36, 20
    max_w = 612 - 2*margin
    max_h = 792 - 2*margin - title_h
    scale = min(max_w/w, max_h/h)
    dw, dh = w*scale, h*scale
    c.setPageSize((612, 792))
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, 792-margin, title)
    c.drawImage(ImageReader(path), margin, 792-margin-title_h-dh, dw, dh)
    c.showPage()
c.save()
print("wrote", out)
"#,
        screenshots_dir.display(),
        pdf_out.display()
    );
    if let Ok(out) = Command::new("python3").arg("-c").arg(&pdf_script).output() {
        if out.status.success() {
            println!("cochranblock-mail-test: PDF → {}", pdf_out.display());
            // Push to Mac Mini and open.
            let mm_path = "/Users/mcochran/cochranblock-mail/screenshots/e2e_report.pdf";
            Command::new("ssh").args(["mm", "mkdir -p /Users/mcochran/cochranblock-mail/screenshots"]).status().ok();
            if Command::new("scp").args([pdf_out.to_str().unwrap_or(""), &format!("mm:{mm_path}")]).status().map(|s| s.success()).unwrap_or(false) {
                Command::new("ssh").args(["mm", &format!("open {mm_path}")]).status().ok();
                println!("cochranblock-mail-test: opened PDF on Mac Mini ✓");
            }
        }
    }

    println!(
        "\ncochranblock-mail-test: all gates passed in {:.1}s",
        total.elapsed().as_secs_f64()
    );
    Ok(())
}
