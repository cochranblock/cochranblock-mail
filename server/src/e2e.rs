//! End-to-end integration test: spins up the full server stack in-process,
//! authenticates via TOTP login, delivers a real SMTP message, reads it back
//! via IMAP, verifies via HTTP API, and screenshots login/inbox/read views.

use crate::config::Config;
use crate::imap::session::ImapSession;
use crate::smtp::session::SmtpSession;
use crate::store::MailStore;
use crate::webmail::router;
use shared::LoginResponse;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use totp_rs::{Algorithm, Secret, TOTP};

const E2E_PASS: &str = "e2e-test-pass";
// 20 bytes / 160 bits base32 — SHA1-TOTP minimum.
const E2E_TOTP_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

// ── Harness ───────────────────────────────────────────────────────────────────

struct Harness {
    smtp_port: u16,
    imap_port: u16,
    http_port: u16,
    store: Arc<MailStore>,
}

impl Harness {
    async fn start() -> anyhow::Result<Self> {
        let dir_path = std::env::temp_dir()
            .join(format!("cochranblock-e2e-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir_path)?;
        let db = dir_path.join("e2e.redb");
        let store = Arc::new(MailStore::open(&db)?);

        let config = Arc::new(Config {
            domain: "cochranblock.test".to_string(),
            smtp_port: 0,
            smtp_submission_port: 0,
            imap_port: 0,
            http_port: 0,
            tls_cert: PathBuf::from("/tmp"),
            tls_key: PathBuf::from("/tmp"),
            mail_dir: dir_path.clone(),
            db_path: db,
            session_ttl_secs: 3600,
            secure_cookies: false,
            totp_encryption_key: None,
        });

        let smtp_l = TcpListener::bind("127.0.0.1:0").await?;
        let smtp_port = smtp_l.local_addr()?.port();

        let imap_l = TcpListener::bind("127.0.0.1:0").await?;
        let imap_port = imap_l.local_addr()?.port();

        let http_l = TcpListener::bind("127.0.0.1:0").await?;
        let http_port = http_l.local_addr()?.port();

        {
            let c = Arc::clone(&config);
            let s = Arc::clone(&store);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, peer)) = smtp_l.accept().await else { break };
                    let c2 = Arc::clone(&c);
                    let s2 = Arc::clone(&s);
                    tokio::spawn(async move {
                        SmtpSession::new(stream, peer, c2, s2, false).run().await.ok();
                    });
                }
            });
        }

        {
            let c = Arc::clone(&config);
            let s = Arc::clone(&store);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, peer)) = imap_l.accept().await else { break };
                    let c2 = Arc::clone(&c);
                    let s2 = Arc::clone(&s);
                    tokio::spawn(async move {
                        ImapSession::new(stream, peer, c2, s2).run().await.ok();
                    });
                }
            });
        }

        {
            let app = router::build(Arc::clone(&config), Arc::clone(&store));
            tokio::spawn(async move {
                axum::serve(http_l, app).await.ok();
            });
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        Ok(Self { smtp_port, imap_port, http_port, store })
    }
}

// ── Raw protocol helpers ──────────────────────────────────────────────────────

async fn read_line(r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
    let mut s = String::new();
    r.read_line(&mut s).await.unwrap_or_default();
    s.trim_end_matches(|c: char| c == '\r' || c == '\n').to_string()
}

async fn read_until_tagged(
    r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    tag: &str,
) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        let line = read_line(r).await;
        let done = line.starts_with(tag);
        lines.push(line);
        if done { break; }
    }
    lines
}

async fn http_get(port: u16, path: &str, cookie: Option<&str>) -> anyhow::Result<(u16, String)> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await?;
    let cookie_hdr = cookie.map(|c| format!("Cookie: {c}\r\n")).unwrap_or_default();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n{cookie_hdr}\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let raw = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = raw.lines().next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw.splitn(2, "\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((status, body))
}

/// Returns `(status, set-cookie value, body)`.
async fn http_post(
    port: u16,
    path: &str,
    json: &str,
    cookie: Option<&str>,
) -> anyhow::Result<(u16, String, String)> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).await?;
    let cookie_hdr = cookie.map(|c| format!("Cookie: {c}\r\n")).unwrap_or_default();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n{cookie_hdr}\r\n{json}",
        json.len()
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let raw = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = raw.lines().next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let set_cookie = raw.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .map(|l| l[11..].trim().to_string())
        .unwrap_or_default();
    let body = raw.splitn(2, "\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((status, set_cookie, body))
}

fn make_totp() -> TOTP {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(E2E_TOTP_SECRET.to_string()).to_bytes().expect("valid base32"),
        Some("cochranblock.test".to_string()),
        "alice@cochranblock.test".to_string(),
    )
    .expect("valid TOTP config")
}

fn chromium_screenshot(url: &str, out: &std::path::Path) -> String {
    let result = std::process::Command::new("chromium")
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--window-size=1280,900",
            "--virtual-time-budget=10000",
            "--run-all-compositor-stages-before-draw",
            &format!("--screenshot={}", out.display()),
            url,
        ])
        .output();

    match result {
        Ok(o) if o.status.success() => {
            let kb = std::fs::metadata(out).map(|m| m.len()).unwrap_or(0) as f64 / 1024.0;
            format!("{} ({:.1} KB) ✓", out.file_name().unwrap_or_default().to_string_lossy(), kb)
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            format!("chromium failed: {}", err.lines().next().unwrap_or("?"))
        }
        Err(e) => format!("chromium unavailable: {e}"),
    }
}

// ── Main entry point ──────────────────────────────────────────────────────────

pub async fn run() -> anyhow::Result<()> {
    let screenshots_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("screenshots");
    std::fs::create_dir_all(&screenshots_dir)?;

    println!("\n━━━ cochranblock-mail e2e ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // ── [1] Setup ─────────────────────────────────────────────────────────────
    print!("  [1/10] setup: store + alice (TOTP={E2E_TOTP_SECRET}) ... ");
    let h = Harness::start().await?;
    h.store.create_user("alice", "alice@cochranblock.test", E2E_PASS)?;
    h.store.set_totp_secret("alice", E2E_TOTP_SECRET)?;
    h.store.ensure_standard_mailboxes("alice")?;
    println!("ok");

    // ── [2] Servers ───────────────────────────────────────────────────────────
    println!(
        "  [2/10] servers: smtp=:{smtp}  imap=:{imap}  http=:{http}",
        smtp = h.smtp_port, imap = h.imap_port, http = h.http_port
    );

    // ── [3] SMTP: deliver test email ─────────────────────────────────────────
    print!("  [3/10] smtp: EHLO → MAIL FROM → RCPT TO → DATA → ");
    {
        let (r, w) = TcpStream::connect(format!("127.0.0.1:{}", h.smtp_port))
            .await?
            .into_split();
        let mut r = BufReader::new(r);
        let mut w = w;

        let banner = read_line(&mut r).await;
        anyhow::ensure!(banner.starts_with("220"), "banner: {banner}");

        w.write_all(b"EHLO external.test\r\n").await?;
        loop {
            let l = read_line(&mut r).await;
            if l.starts_with("250 ") { break; }
            anyhow::ensure!(!l.is_empty(), "EHLO EOF");
        }

        w.write_all(b"MAIL FROM:<sender@external.test>\r\n").await?;
        let l = read_line(&mut r).await;
        anyhow::ensure!(l.starts_with("250"), "MAIL FROM: {l}");

        w.write_all(b"RCPT TO:<alice@cochranblock.test>\r\n").await?;
        let l = read_line(&mut r).await;
        anyhow::ensure!(l.starts_with("250"), "RCPT TO: {l}");

        w.write_all(b"DATA\r\n").await?;
        let l = read_line(&mut r).await;
        anyhow::ensure!(l.starts_with("354"), "DATA: {l}");

        w.write_all(
            b"From: External Sender <sender@external.test>\r\n\
              To: alice@cochranblock.test\r\n\
              Subject: E2E Test Email\r\n\
              Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n\
              Message-ID: <e2e-001@external.test>\r\n\
              \r\n\
              This is the end-to-end test email body.\r\n\
              Sent via SMTP, retrieved via IMAP, displayed in webmail.\r\n\
              .\r\n",
        )
        .await?;
        let l = read_line(&mut r).await;
        anyhow::ensure!(l.starts_with("250"), "DATA .: {l}");

        w.write_all(b"QUIT\r\n").await?;
        println!("250 OK");
    }

    // ── [4] IMAP: verify delivery ─────────────────────────────────────────────
    print!("  [4/10] imap: LOGIN → SELECT INBOX → ");
    {
        let (r, w) = TcpStream::connect(format!("127.0.0.1:{}", h.imap_port))
            .await?
            .into_split();
        let mut r = BufReader::new(r);
        let mut w = w;

        let greeting = read_line(&mut r).await;
        anyhow::ensure!(greeting.starts_with("* OK"), "greeting: {greeting}");

        w.write_all(format!("t1 LOGIN alice {E2E_PASS}\r\n").as_bytes()).await?;
        let resp = read_line(&mut r).await;
        anyhow::ensure!(resp.contains("OK"), "LOGIN: {resp}");

        w.write_all(b"t2 SELECT INBOX\r\n").await?;
        let lines = read_until_tagged(&mut r, "t2").await;
        let exists = lines.iter().find(|l| l.contains("EXISTS")).cloned().unwrap_or_default();
        anyhow::ensure!(exists.contains("1 EXISTS"), "expected 1 EXISTS: {lines:?}");
        print!("1 EXISTS → FETCH → ");

        w.write_all(b"t3 FETCH 1 (RFC822.HEADER)\r\n").await?;
        let lines = read_until_tagged(&mut r, "t3").await;
        anyhow::ensure!(
            lines.iter().any(|l| l.contains("E2E Test Email")),
            "subject missing: {lines:?}"
        );

        w.write_all(b"t4 LOGOUT\r\n").await?;
        println!("Subject: E2E Test Email ✓");
    }

    // ── [5] HTTP: full TOTP login flow ────────────────────────────────────────
    print!("  [5/10] http login: POST /api/auth/login → TotpRequired → ");
    let session_cookie = {
        let login_body = format!(
            r#"{{"username":"alice","password":"{E2E_PASS}"}}"#
        );
        let (status, _, body) =
            http_post(h.http_port, "/api/auth/login", &login_body, None).await?;
        anyhow::ensure!(status == 200, "login status={status} body={body}");

        let resp: LoginResponse = serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("parse login response: {e} body={body}"))?;
        let partial_token = match resp {
            LoginResponse::TotpRequired { partial_token } => partial_token,
            other => anyhow::bail!("expected TotpRequired, got {other:?}"),
        };

        let code = make_totp().generate_current()?;
        print!("code={code} → POST /api/auth/totp/verify → ");

        let verify_body = format!(
            r#"{{"partial_token":"{partial_token}","code":"{code}"}}"#
        );
        let (status, set_cookie, body) =
            http_post(h.http_port, "/api/auth/totp/verify", &verify_body, None).await?;
        anyhow::ensure!(status == 200, "totp/verify status={status} body={body}");

        // Extract token from "cbmail_session=TOKEN; Path=..."
        let token = set_cookie
            .split(';')
            .next()
            .and_then(|kv| kv.trim().split_once('='))
            .map(|(_, v)| v.to_string())
            .ok_or_else(|| anyhow::anyhow!("no session cookie in: {set_cookie}"))?;

        println!("session issued ✓");
        format!("cbmail_session={token}")
    };

    // ── [6] HTTP: mailboxes ───────────────────────────────────────────────────
    print!("  [6/10] http: GET /api/mailboxes → ");
    let (status, body) = http_get(h.http_port, "/api/mailboxes", Some(&session_cookie)).await?;
    anyhow::ensure!(status == 200, "mailboxes status={status}");
    anyhow::ensure!(body.contains("INBOX"), "INBOX missing: {body}");
    println!("INBOX listed ✓");

    // ── [7] HTTP: messages ────────────────────────────────────────────────────
    print!("  [7/10] http: GET /api/messages?mailbox=INBOX → ");
    let (status, body) =
        http_get(h.http_port, "/api/messages?mailbox=INBOX", Some(&session_cookie)).await?;
    anyhow::ensure!(status == 200, "messages status={status}");
    anyhow::ensure!(body.contains("E2E Test Email"), "subject missing: {body}");
    println!("E2E Test Email found ✓");

    // Extract session token for screenshot injection.
    let token = session_cookie
        .split_once('=')
        .map(|(_, v)| v)
        .unwrap_or("");

    // ── [8] Screenshot: login page ────────────────────────────────────────────
    print!("  [8/11] screenshot: login page → ");
    let login_url = format!("http://127.0.0.1:{}/login", h.http_port);
    let out = screenshots_dir.join("e2e_01_login.png");
    println!("{}", chromium_screenshot(&login_url, &out));

    // ── [9] Screenshot: TOTP verify page ─────────────────────────────────────
    print!("  [9/11] screenshot: TOTP verify page → ");
    let partial = h.store.create_partial_session("alice", false)?;
    let totp_url = format!(
        "http://127.0.0.1:{}/login?partial_token={}",
        h.http_port, partial.token
    );
    let out = screenshots_dir.join("e2e_02_totp.png");
    println!("{}", chromium_screenshot(&totp_url, &out));

    // ── [10] Screenshot: inbox ────────────────────────────────────────────────
    print!("  [10/11] screenshot: inbox → ");
    let inbox_url = format!(
        "http://127.0.0.1:{}/test/inject-session?token={}&redirect=/mail/INBOX",
        h.http_port, token
    );
    let out = screenshots_dir.join("e2e_03_inbox.png");
    println!("{}", chromium_screenshot(&inbox_url, &out));

    // ── [11] Screenshot: email read view ──────────────────────────────────────
    print!("  [11/11] screenshot: email read view → ");
    let read_url = format!(
        "http://127.0.0.1:{}/test/inject-session?token={}&redirect=/mail/INBOX/1",
        h.http_port, token
    );
    let out = screenshots_dir.join("e2e_04_message.png");
    println!("{}", chromium_screenshot(&read_url, &out));

    println!("━━━ ALL PASS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    Ok(())
}
