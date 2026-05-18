use crate::config::Config;
use crate::store::MailStore;
use crate::smtp::command::SmtpCommand;
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
        Self {
            stream,
            peer,
            config,
            store,
            mail_from: None,
            rcpt_to: Vec::new(),
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.write(&format!("220 {} ESMTP cochranblock-mail\r\n", self.config.domain)).await?;

        let (reader, mut writer) = self.stream.split();
        let mut lines = BufReader::new(reader).lines();

        while let Some(line) = lines.next_line().await? {
            tracing::debug!(peer = %self.peer, "<< {line}");
            match SmtpCommand::parse(&line) {
                SmtpCommand::Ehlo(host) => {
                    tracing::info!(peer = %self.peer, "EHLO {host}");
                    writer.write_all(format!(
                        "250-{}\r\n250-SIZE 26214400\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n",
                        self.config.domain
                    ).as_bytes()).await?;
                }
                SmtpCommand::Helo(host) => {
                    tracing::info!(peer = %self.peer, "HELO {host}");
                    writer.write_all(format!("250 {}\r\n", self.config.domain).as_bytes()).await?;
                }
                SmtpCommand::MailFrom(addr) => {
                    self.mail_from = Some(addr.clone());
                    self.rcpt_to.clear();
                    writer.write_all(b"250 2.1.0 Ok\r\n").await?;
                }
                SmtpCommand::RcptTo(addr) => {
                    let local = addr.split('@').next().unwrap_or("");
                    // accept only @our domain
                    if addr.to_ascii_lowercase().ends_with(&format!("@{}", self.config.domain)) {
                        self.rcpt_to.push(local.to_string());
                        writer.write_all(b"250 2.1.5 Ok\r\n").await?;
                    } else {
                        writer.write_all(b"550 5.7.1 Relay denied\r\n").await?;
                    }
                }
                SmtpCommand::Data => {
                    writer.write_all(b"354 End data with <CR LF>.<CR LF>\r\n").await?;
                    let mut body = String::new();
                    while let Some(data_line) = lines.next_line().await? {
                        if data_line == "." {
                            break;
                        }
                        body.push_str(&data_line);
                        body.push_str("\r\n");
                    }
                    let uid = chrono::Utc::now().timestamp() as u32;
                    for mailbox in &self.rcpt_to {
                        if let Err(e) = self.store.deliver(mailbox, uid, body.as_bytes()) {
                            tracing::error!(mailbox, "deliver failed: {e}");
                        } else {
                            tracing::info!(mailbox, uid, "delivered");
                        }
                    }
                    self.mail_from = None;
                    self.rcpt_to.clear();
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
                    tracing::warn!(peer = %self.peer, "unknown command: {cmd}");
                    writer.write_all(b"500 5.5.2 Error: bad syntax\r\n").await?;
                }
            }
        }
        Ok(())
    }

    async fn write(&mut self, s: &str) -> anyhow::Result<()> {
        self.stream.write_all(s.as_bytes()).await?;
        Ok(())
    }
}
