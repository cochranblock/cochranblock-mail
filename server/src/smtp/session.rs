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
        Self { stream, peer, config, store, mail_from: None, rcpt_to: Vec::new() }
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
                    writer
                        .write_all(format!("250 {}\r\n", self.config.domain).as_bytes())
                        .await?;
                }
                SmtpCommand::MailFrom(addr) => {
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
                        let line_bytes = if data_line.starts_with('.') {
                            &data_line[1..]
                        } else {
                            &data_line
                        };
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
