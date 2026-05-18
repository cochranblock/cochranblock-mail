use crate::config::Config;
use crate::imap::command::ImapCommand;
use crate::store::MailStore;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Debug, PartialEq)]
enum State {
    NotAuthenticated,
    Authenticated { user: String },
    Selected { user: String, mailbox: String },
}

pub struct ImapSession {
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    store: Arc<MailStore>,
    state: State,
}

impl ImapSession {
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
            state: State::NotAuthenticated,
        }
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        self.stream.write_all(b"* OK cochranblock-mail IMAP4rev1 ready\r\n").await?;

        // owned split so we can freely mutate self.state without borrow conflicts
        let (reader, mut writer) = self.stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let peer = self.peer;
        let config = Arc::clone(&self.config);
        let admin_user = config.admin_user.clone();
        let admin_hash = config.admin_pass_hash.clone();
        let mut state = State::NotAuthenticated;

        while let Some(line) = lines.next_line().await? {
            tracing::debug!(%peer, "<< {line}");
            let Some(cmd) = ImapCommand::parse(&line) else {
                continue;
            };
            match cmd.verb.as_str() {
                "CAPABILITY" => {
                    writer.write_all(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n").await?;
                    writer.write_all(format!("{} OK CAPABILITY completed\r\n", cmd.tag).as_bytes()).await?;
                }
                "LOGIN" => {
                    if let Some(args) = cmd.args.first() {
                        let mut parts = args.splitn(2, ' ');
                        let user = parts.next().unwrap_or("").trim_matches('"').to_string();
                        let pass = parts.next().unwrap_or("").trim_matches('"').to_string();
                        let hash = format!("{:x}", Sha256::digest(pass.as_bytes()));
                        if user == admin_user && hash == admin_hash {
                            state = State::Authenticated { user };
                            writer.write_all(format!("{} OK LOGIN completed\r\n", cmd.tag).as_bytes()).await?;
                        } else {
                            writer.write_all(format!("{} NO LOGIN failed\r\n", cmd.tag).as_bytes()).await?;
                        }
                    }
                }
                "SELECT" => {
                    if let State::Authenticated { user } | State::Selected { user, .. } = &state {
                        let mailbox = cmd.args.first().cloned().unwrap_or_default();
                        let mailbox = mailbox.trim_matches('"').to_string();
                        let user = user.clone();
                        writer.write_all(b"* 0 EXISTS\r\n* 0 RECENT\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n").await?;
                        writer.write_all(format!("{} OK [READ-WRITE] SELECT completed\r\n", cmd.tag).as_bytes()).await?;
                        state = State::Selected { user, mailbox };
                    } else {
                        writer.write_all(format!("{} NO Not authenticated\r\n", cmd.tag).as_bytes()).await?;
                    }
                }
                "LOGOUT" => {
                    writer.write_all(b"* BYE cochranblock-mail logging out\r\n").await?;
                    writer.write_all(format!("{} OK LOGOUT completed\r\n", cmd.tag).as_bytes()).await?;
                    break;
                }
                "NOOP" => {
                    writer.write_all(format!("{} OK NOOP completed\r\n", cmd.tag).as_bytes()).await?;
                }
                other => {
                    tracing::warn!(%peer, "unhandled IMAP command: {other}");
                    writer.write_all(format!("{} BAD Command not implemented\r\n", cmd.tag).as_bytes()).await?;
                }
            }
        }
        Ok(())
    }
}
