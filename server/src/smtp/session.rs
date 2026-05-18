// ── Tests ─────────────────────────────────────────────────────────────────────
//
// Each test binds a random-port TcpListener, spawns an SmtpSession in a task,
// connects a client, and drives the SMTP conversation explicitly.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::MailStore;
    use std::{net::SocketAddr, path::PathBuf};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    fn smtp_config() -> Arc<Config> {
        Arc::new(Config {
            domain: "cochranblock.test".to_string(),
            smtp_port: 0,
            smtp_submission_port: 0,
            imap_port: 0,
            http_port: 0,
            tls_cert: PathBuf::from("/tmp"),
            tls_key: PathBuf::from("/tmp"),
            mail_dir: PathBuf::from("/tmp"),
            db_path: PathBuf::from("/tmp/test.redb"),
            frontend_dist: PathBuf::from("/tmp"),
            session_ttl_secs: 86400,
            secure_cookies: false,
            totp_encryption_key: None,
        })
    }

    async fn start() -> (SocketAddr, Arc<MailStore>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(MailStore::open_temp().unwrap());
        let (s, c) = (Arc::clone(&store), smtp_config());
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            SmtpSession::new(stream, peer, c, s, false).run().await.ok();
        });
        (addr, store)
    }

    async fn connect(addr: SocketAddr) -> (BufReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf) {
        let (r, w) = TcpStream::connect(addr).await.unwrap().into_split();
        (BufReader::new(r), w)
    }

    async fn read_line(r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
        let mut s = String::new();
        r.read_line(&mut s).await.unwrap();
        s.trim_end_matches(|c: char| c == '\r' || c == '\n').to_string()
    }

    // Read multi-line SMTP response; returns the last (final) line.
    async fn read_response(r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
        loop {
            let line = read_line(r).await;
            // Continuation lines have a '-' as the 4th character.
            if line.len() < 4 || line.as_bytes()[3] != b'-' {
                return line;
            }
        }
    }

    #[tokio::test]
    async fn banner_is_220_with_domain() {
        let (addr, _store) = start().await;
        let (mut r, _w) = connect(addr).await;
        let banner = read_line(&mut r).await;
        assert!(banner.starts_with("220 cochranblock.test"), "banner: {banner}");
    }

    #[tokio::test]
    async fn ehlo_returns_250() {
        let (addr, _store) = start().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await; // banner
        w.write_all(b"EHLO client.example.com\r\n").await.unwrap();
        let last = read_response(&mut r).await;
        assert!(last.starts_with("250 "), "EHLO final line: {last}");
    }

    #[tokio::test]
    async fn relay_denied_for_external_rcpt() {
        let (addr, _store) = start().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await; // banner
        w.write_all(b"EHLO x\r\n").await.unwrap();
        read_response(&mut r).await;
        w.write_all(b"MAIL FROM:<sender@cochranblock.test>\r\n").await.unwrap();
        read_line(&mut r).await; // 250
        w.write_all(b"RCPT TO:<user@external.example.com>\r\n").await.unwrap();
        let resp = read_line(&mut r).await;
        assert!(resp.starts_with("550"), "expected relay-denial 550, got: {resp}");
    }

    #[tokio::test]
    async fn full_delivery_stores_in_inbox() {
        let (addr, store) = start().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await; // banner
        w.write_all(b"EHLO client.example.com\r\n").await.unwrap();
        read_response(&mut r).await;
        w.write_all(b"MAIL FROM:<sender@example.com>\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"RCPT TO:<mailtest@cochranblock.test>\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"DATA\r\n").await.unwrap();
        read_line(&mut r).await; // 354
        w.write_all(
            b"From: sender@example.com\r\nTo: mailtest@cochranblock.test\r\n\
              Subject: SMTP Integration\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
              \r\nThis is the body.\r\n.\r\n",
        )
        .await
        .unwrap();
        let queued = read_line(&mut r).await;
        assert!(queued.starts_with("250"), "DATA .: {queued}");

        let (msgs, total) = store.list_messages("mailtest", "INBOX", 0).unwrap();
        assert_eq!(total, 1, "message should be stored");
        assert_eq!(msgs[0].subject, "SMTP Integration");
    }

    #[tokio::test]
    async fn dot_stuffing_is_unstuffed_per_rfc5321() {
        let (addr, store) = start().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await; // banner
        w.write_all(b"EHLO x\r\n").await.unwrap();
        read_response(&mut r).await;
        w.write_all(b"MAIL FROM:<a@example.com>\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"RCPT TO:<dottest@cochranblock.test>\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"DATA\r\n").await.unwrap();
        read_line(&mut r).await;
        // "..leading dot" — server must strip one leading dot
        w.write_all(
            b"Subject: Dot test\r\n\r\n..leading dot line\r\n.\r\n",
        )
        .await
        .unwrap();
        read_line(&mut r).await; // 250

        let raw = store.fetch_raw("dottest", "INBOX", 1).unwrap().unwrap();
        let body = String::from_utf8(raw).unwrap();
        assert!(
            body.contains(".leading dot line"),
            "dot unstuffing should remove exactly one leading dot; body:\n{body}"
        );
        assert!(
            !body.contains("..leading dot line"),
            "double-dot should have been stripped to single; body:\n{body}"
        );
    }

    #[tokio::test]
    async fn rset_clears_envelope_before_data() {
        let (addr, store) = start().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await; // banner
        w.write_all(b"EHLO x\r\n").await.unwrap();
        read_response(&mut r).await;
        w.write_all(b"MAIL FROM:<a@example.com>\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"RCPT TO:<rsettest@cochranblock.test>\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"RSET\r\n").await.unwrap();
        let rset = read_line(&mut r).await;
        assert!(rset.starts_with("250"), "RSET: {rset}");

        // No message should have been stored since we RSET before DATA.
        let (_, total) = store.list_messages("rsettest", "INBOX", 0).unwrap();
        assert_eq!(total, 0, "RSET should prevent delivery");
    }

    async fn start_submission() -> (SocketAddr, Arc<MailStore>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(MailStore::open_temp().unwrap());
        // Add a real user so AUTH PLAIN can verify credentials.
        store.create_user("submituser", "s@cochranblock.test", "secret").unwrap();
        let (s, c) = (Arc::clone(&store), smtp_config());
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            SmtpSession::new(stream, peer, c, s, true).run().await.ok();
        });
        (addr, store)
    }

    #[tokio::test]
    async fn submission_requires_auth_before_mail_from() {
        let (addr, _store) = start_submission().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await; // banner
        w.write_all(b"EHLO x\r\n").await.unwrap();
        read_response(&mut r).await;
        // No AUTH — MAIL FROM should be rejected with 530
        w.write_all(b"MAIL FROM:<s@cochranblock.test>\r\n").await.unwrap();
        let resp = read_line(&mut r).await;
        assert!(resp.starts_with("530"), "expected 530 auth required, got: {resp}");
    }

    #[tokio::test]
    async fn submission_auth_plain_valid_credentials_accepted() {
        use base64::Engine as _;
        let (addr, _store) = start_submission().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await;
        w.write_all(b"EHLO x\r\n").await.unwrap();
        read_response(&mut r).await;
        // AUTH PLAIN \0submituser\0secret
        let cred = base64::engine::general_purpose::STANDARD
            .encode(b"\x00submituser\x00secret");
        w.write_all(format!("AUTH PLAIN {cred}\r\n").as_bytes()).await.unwrap();
        let resp = read_line(&mut r).await;
        assert!(resp.starts_with("235"), "expected 235 auth ok, got: {resp}");
    }

    #[tokio::test]
    async fn submission_auth_plain_wrong_password_is_535() {
        use base64::Engine as _;
        let (addr, _store) = start_submission().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await;
        w.write_all(b"EHLO x\r\n").await.unwrap();
        read_response(&mut r).await;
        let cred = base64::engine::general_purpose::STANDARD
            .encode(b"\x00submituser\x00wrongpass");
        w.write_all(format!("AUTH PLAIN {cred}\r\n").as_bytes()).await.unwrap();
        let resp = read_line(&mut r).await;
        assert!(resp.starts_with("535"), "expected 535 auth failed, got: {resp}");
    }

    #[tokio::test]
    async fn data_too_large_returns_552() {
        let (addr, _store) = start().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await;
        w.write_all(b"EHLO x\r\n").await.unwrap();
        read_response(&mut r).await;
        w.write_all(b"MAIL FROM:<a@example.com>\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"RCPT TO:<sizetest@cochranblock.test>\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"DATA\r\n").await.unwrap();
        read_line(&mut r).await; // 354
        // Send exactly MAX_MESSAGE_SIZE + 1 bytes in the body (one long line).
        let big_line = vec![b'x'; 26_214_401];
        w.write_all(&big_line).await.unwrap();
        w.write_all(b"\r\n.\r\n").await.unwrap();
        let resp = read_line(&mut r).await;
        assert!(resp.starts_with("552"), "expected 552 too large, got: {resp}");
    }
}

use base64::Engine as _;
use crate::config::Config;
use crate::smtp::command::SmtpCommand;
use crate::store::MailStore;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Maximum message body size: matches the SIZE advertised in EHLO (25 MiB).
const MAX_MESSAGE_SIZE: usize = 26_214_400;

pub struct SmtpSession {
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    store: Arc<MailStore>,
    greeted: bool,
    /// True when this connection arrived on the submission port (587).
    is_submission: bool,
    /// Set after a successful AUTH PLAIN on the submission port.
    authenticated: bool,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
}

impl SmtpSession {
    pub fn new(
        stream: TcpStream,
        peer: SocketAddr,
        config: Arc<Config>,
        store: Arc<MailStore>,
        is_submission: bool,
    ) -> Self {
        Self {
            stream,
            peer,
            config,
            store,
            greeted: false,
            is_submission,
            authenticated: false,
            mail_from: None,
            rcpt_to: Vec::new(),
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let banner = format!("220 {} ESMTP cochranblock-mail\r\n", self.config.domain);
        self.stream.write_all(banner.as_bytes()).await?;

        let stream = &mut self.stream;
        let (reader, mut writer) = stream.split();
        let mut lines = BufReader::new(reader).lines();

        while let Some(line) = lines.next_line().await? {
            tracing::debug!(peer = %self.peer, "<< {line}");
            match SmtpCommand::parse(&line) {
                SmtpCommand::Ehlo(host) => {
                    tracing::info!(peer = %self.peer, "EHLO {host}");
                    self.greeted = true;
                    let auth_line = if self.is_submission { "250-AUTH PLAIN\r\n" } else { "" };
                    writer
                        .write_all(
                            format!(
                                "250-{}\r\n250-SIZE {MAX_MESSAGE_SIZE}\r\n250-8BITMIME\r\n{auth_line}250 ENHANCEDSTATUSCODES\r\n",
                                self.config.domain
                            )
                            .as_bytes(),
                        )
                        .await?;
                }
                SmtpCommand::Helo(host) => {
                    tracing::info!(peer = %self.peer, "HELO {host}");
                    self.greeted = true;
                    writer
                        .write_all(format!("250 {}\r\n", self.config.domain).as_bytes())
                        .await?;
                }
                SmtpCommand::AuthPlain(payload) => {
                    if !self.is_submission {
                        writer.write_all(b"503 5.5.1 AUTH not available on port 25\r\n").await?;
                        continue;
                    }
                    let b64 = if payload.is_empty() {
                        // RFC 4616: server challenges with "334 ", client sends base64 next
                        writer.write_all(b"334 \r\n").await?;
                        lines.next_line().await?.unwrap_or_default()
                    } else {
                        payload
                    };
                    match decode_auth_plain(&b64) {
                        Some((username, password)) => {
                            match self.store.verify_password(&username, &password) {
                                Ok(true) => {
                                    tracing::info!(peer = %self.peer, username, "AUTH PLAIN ok");
                                    self.authenticated = true;
                                    writer.write_all(b"235 2.7.0 Authentication successful\r\n").await?;
                                }
                                _ => {
                                    tracing::warn!(peer = %self.peer, username, "AUTH PLAIN failed");
                                    writer.write_all(b"535 5.7.8 Authentication credentials invalid\r\n").await?;
                                }
                            }
                        }
                        None => {
                            writer.write_all(b"501 5.5.4 Malformed AUTH input\r\n").await?;
                        }
                    }
                }
                SmtpCommand::MailFrom(addr) => {
                    if !self.greeted {
                        writer.write_all(b"503 5.5.1 EHLO/HELO required\r\n").await?;
                        continue;
                    }
                    if self.is_submission && !self.authenticated {
                        writer.write_all(b"530 5.7.0 Authentication required\r\n").await?;
                        continue;
                    }
                    self.mail_from = Some(addr);
                    self.rcpt_to.clear();
                    writer.write_all(b"250 2.1.0 Ok\r\n").await?;
                }
                SmtpCommand::RcptTo(addr) => {
                    let domain_suffix = format!("@{}", self.config.domain);
                    if addr.to_ascii_lowercase().ends_with(&domain_suffix) {
                        let local = addr.split('@').next().unwrap_or("").to_string();
                        self.rcpt_to.push(local);
                        writer.write_all(b"250 2.1.5 Ok\r\n").await?;
                    } else {
                        writer.write_all(b"550 5.7.1 Relay denied\r\n").await?;
                    }
                }
                SmtpCommand::Data => {
                    writer.write_all(b"354 End data with <CR LF>.<CR LF>\r\n").await?;
                    let mut body = Vec::new();
                    let mut too_large = false;
                    while let Some(data_line) = lines.next_line().await? {
                        if data_line == "." {
                            break;
                        }
                        // RFC 5321 §4.5.2: un-stuff leading dots.
                        let line_bytes = data_line.strip_prefix('.').unwrap_or(&data_line);
                        if body.len() + line_bytes.len() + 2 > MAX_MESSAGE_SIZE {
                            too_large = true;
                            // drain remaining lines so the session stays in sync
                            while let Some(drain) = lines.next_line().await? {
                                if drain == "." { break; }
                            }
                            break;
                        }
                        body.extend_from_slice(line_bytes.as_bytes());
                        body.extend_from_slice(b"\r\n");
                    }

                    if too_large {
                        self.mail_from = None;
                        self.rcpt_to.clear();
                        writer.write_all(b"552 5.3.4 Message exceeds maximum size\r\n").await?;
                        continue;
                    }

                    let rcpt = std::mem::take(&mut self.rcpt_to);
                    self.mail_from = None;

                    for mailbox in &rcpt {
                        match self.store.deliver(mailbox, "INBOX", &body) {
                            Ok(uid) => tracing::info!(mailbox, uid, "delivered"),
                            Err(e) => tracing::error!(mailbox, "deliver failed: {e}"),
                        }
                    }
                    writer.write_all(b"250 2.0.0 Ok: queued\r\n").await?;
                }
                SmtpCommand::Rset => {
                    self.mail_from = None;
                    self.rcpt_to.clear();
                    writer.write_all(b"250 2.0.0 Ok\r\n").await?;
                }
                SmtpCommand::Noop => {
                    writer.write_all(b"250 2.0.0 Ok\r\n").await?;
                }
                SmtpCommand::Quit => {
                    writer.write_all(b"221 2.0.0 Bye\r\n").await?;
                    break;
                }
                SmtpCommand::Unknown(cmd) => {
                    tracing::warn!(peer = %self.peer, "unknown: {cmd}");
                    writer.write_all(b"500 5.5.2 Error: bad syntax\r\n").await?;
                }
            }
        }
        Ok(())
    }
}

/// Decode an AUTH PLAIN base64 blob: `\0authcid\0passwd` or `authzid\0authcid\0passwd`.
/// Returns (username, password) on success.
fn decode_auth_plain(b64: &str) -> Option<(String, String)> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
    // Split on NUL bytes; format is [authzid NUL] authcid NUL passwd
    let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
    match parts.as_slice() {
        // "\0username\0password" → parts[0]="" parts[1]=username parts[2]=password
        [_, authcid, passwd] if !authcid.is_empty() => Some((
            String::from_utf8(authcid.to_vec()).ok()?,
            String::from_utf8(passwd.to_vec()).ok()?,
        )),
        _ => None,
    }
}
