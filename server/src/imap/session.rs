use crate::config::Config;
use crate::imap::command::ImapCommand;
use crate::store::MailStore;
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
}

impl ImapSession {
    pub fn new(
        stream: TcpStream,
        peer: SocketAddr,
        config: Arc<Config>,
        store: Arc<MailStore>,
    ) -> Self {
        Self { stream, peer, config, store }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let (reader, mut writer) = self.stream.into_split();
        writer
            .write_all(
                format!("* OK {} IMAP4rev1 ready\r\n", self.config.domain).as_bytes(),
            )
            .await?;

        let mut lines = BufReader::new(reader).lines();
        let peer = self.peer;
        let store = Arc::clone(&self.store);
        let mut state = State::NotAuthenticated;

        while let Some(line) = lines.next_line().await? {
            tracing::debug!(%peer, "<< {line}");
            let Some(cmd) = ImapCommand::parse(&line) else { continue };

            match cmd.verb.as_str() {
                "CAPABILITY" => {
                    writer.write_all(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n").await?;
                    writer
                        .write_all(
                            format!("{} OK CAPABILITY completed\r\n", cmd.tag).as_bytes(),
                        )
                        .await?;
                }

                "LOGIN" => {
                    if let Some(args) = cmd.args.first() {
                        let mut parts = args.splitn(2, ' ');
                        let user = parts.next().unwrap_or("").trim_matches('"').to_string();
                        let pass = parts.next().unwrap_or("").trim_matches('"').to_string();

                        let ok = store.verify_password(&user, &pass).unwrap_or(false);
                        if ok {
                            writer
                                .write_all(
                                    format!("{} OK LOGIN completed\r\n", cmd.tag).as_bytes(),
                                )
                                .await?;
                            state = State::Authenticated { user };
                        } else {
                            writer
                                .write_all(
                                    format!("{} NO [AUTHENTICATIONFAILED] LOGIN failed\r\n", cmd.tag)
                                        .as_bytes(),
                                )
                                .await?;
                        }
                    }
                }

                "SELECT" | "EXAMINE" => {
                    if let State::Authenticated { user } | State::Selected { user, .. } = &state {
                        let mailbox_name = cmd.args.first().cloned().unwrap_or_default();
                        let mailbox_name = mailbox_name.trim_matches('"').to_string();
                        let user = user.clone();

                        let mbox_state = store
                            .get_mailbox_state(&user, &mailbox_name)
                            .unwrap_or_default();

                        writer
                            .write_all(
                                format!(
                                    "* {} EXISTS\r\n* 0 RECENT\r\n\
                                     * OK [UIDVALIDITY {}] UIDs valid\r\n\
                                     * OK [UIDNEXT {}] Predicted next UID\r\n\
                                     * FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n\
                                     {} OK [READ-WRITE] SELECT completed\r\n",
                                    mbox_state.message_count,
                                    mbox_state.uid_validity,
                                    mbox_state.uid_next,
                                    cmd.tag
                                )
                                .as_bytes(),
                            )
                            .await?;
                        state = State::Selected { user, mailbox: mailbox_name };
                    } else {
                        writer
                            .write_all(
                                format!("{} NO Not authenticated\r\n", cmd.tag).as_bytes(),
                            )
                            .await?;
                    }
                }

                "LIST" => {
                    if let State::Authenticated { user } | State::Selected { user, .. } = &state {
                        let mboxes = store.list_mailboxes(user).unwrap_or_default();
                        for (name, _) in &mboxes {
                            writer
                                .write_all(
                                    format!("* LIST () \"/\" \"{name}\"\r\n").as_bytes(),
                                )
                                .await?;
                        }
                        writer
                            .write_all(format!("{} OK LIST completed\r\n", cmd.tag).as_bytes())
                            .await?;
                    } else {
                        writer
                            .write_all(
                                format!("{} NO Not authenticated\r\n", cmd.tag).as_bytes(),
                            )
                            .await?;
                    }
                }

                "STATUS" => {
                    if let State::Authenticated { user } | State::Selected { user, .. } = &state {
                        let mailbox_name = cmd.args.first().cloned().unwrap_or_default();
                        let mailbox_name = mailbox_name.trim_matches('"').to_string();
                        let s = store
                            .get_mailbox_state(user, &mailbox_name)
                            .unwrap_or_default();
                        writer
                            .write_all(
                                format!(
                                    "* STATUS \"{mailbox_name}\" (MESSAGES {} UNSEEN {} UIDNEXT {})\r\n\
                                     {} OK STATUS completed\r\n",
                                    s.message_count, s.unread_count, s.uid_next, cmd.tag
                                )
                                .as_bytes(),
                            )
                            .await?;
                    } else {
                        writer
                            .write_all(
                                format!("{} NO Not authenticated\r\n", cmd.tag).as_bytes(),
                            )
                            .await?;
                    }
                }

                "LOGOUT" => {
                    writer.write_all(b"* BYE cochranblock-mail logging out\r\n").await?;
                    writer
                        .write_all(format!("{} OK LOGOUT completed\r\n", cmd.tag).as_bytes())
                        .await?;
                    break;
                }

                "NOOP" | "CHECK" => {
                    writer
                        .write_all(format!("{} OK {} completed\r\n", cmd.tag, cmd.verb).as_bytes())
                        .await?;
                }

                other => {
                    tracing::warn!(%peer, "unhandled IMAP command: {other}");
                    writer
                        .write_all(
                            format!("{} BAD Command not implemented: {other}\r\n", cmd.tag)
                                .as_bytes(),
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }
}
