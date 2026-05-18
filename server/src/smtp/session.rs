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
        })
    }

    async fn start() -> (SocketAddr, Arc<MailStore>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = Arc::new(MailStore::open_temp().unwrap());
        let (s, c) = (Arc::clone(&store), smtp_config());
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            SmtpSession::new(stream, peer, c, s).run().await.ok();
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
}

use crate::config::Config;
use crate::smtp::command::SmtpCommand;
use crate::store::MailStore;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub struct SmtpSession {
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    store: Arc<MailStore>,
    greeted: bool,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
}

impl SmtpSession {
    pub fn new(
        stream: TcpStream,
        peer: SocketAddr,
        config: Arc<Config>,
        store: Arc<MailStore>,
    ) -> Self {
        Self { stream, peer, config, store, greeted: false, mail_from: None, rcpt_to: Vec::new() }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let banner = format!("220 {} ESMTP cochranblock-mail\r\n", self.config.domain);
        self.stream.write_all(banner.as_bytes()).await?;

        // Split so we can hold mutable writer alongside the reader.
        // SAFETY: TcpStream::split is safe — reader and writer are independent.
        let stream = &mut self.stream;
        let (reader, mut writer) = stream.split();
        let mut lines = BufReader::new(reader).lines();

        while let Some(line) = lines.next_line().await? {
            tracing::debug!(peer = %self.peer, "<< {line}");
            match SmtpCommand::parse(&line) {
                SmtpCommand::Ehlo(host) => {
                    tracing::info!(peer = %self.peer, "EHLO {host}");
                    self.greeted = true;
                    writer
                        .write_all(
                            format!(
                                "250-{}\r\n250-SIZE 26214400\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n",
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
                SmtpCommand::MailFrom(addr) => {
                    if !self.greeted {
                        writer.write_all(b"503 5.5.1 EHLO/HELO required\r\n").await?;
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
                    while let Some(data_line) = lines.next_line().await? {
                        if data_line == "." {
                            break;
                        }
                        // RFC 5321 §4.5.2: un-stuff leading dots.
                        let line_bytes = data_line.strip_prefix('.').unwrap_or(&data_line);
                        body.extend_from_slice(line_bytes.as_bytes());
                        body.extend_from_slice(b"\r\n");
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
