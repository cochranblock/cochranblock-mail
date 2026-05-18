// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::MailStore;
    use std::{net::SocketAddr, path::PathBuf};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    fn imap_config() -> Arc<Config> {
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
        let (s, c) = (Arc::clone(&store), imap_config());
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            ImapSession::new(stream, peer, c, s).run().await.ok();
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

    /// Read lines until we see one that starts with `tag`.
    async fn read_until_tagged(r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>, tag: &str) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            let line = read_line(r).await;
            let done = line.starts_with(tag);
            lines.push(line);
            if done { break; }
        }
        lines
    }

    #[tokio::test]
    async fn greeting_is_ok_with_domain() {
        let (addr, _) = start().await;
        let (mut r, _w) = connect(addr).await;
        let greeting = read_line(&mut r).await;
        assert!(greeting.starts_with("* OK"), "greeting: {greeting}");
        assert!(greeting.contains("cochranblock.test"), "domain missing: {greeting}");
        assert!(greeting.contains("IMAP4rev1"), "protocol missing: {greeting}");
    }

    #[tokio::test]
    async fn capability_returns_imap4rev1() {
        let (addr, _) = start().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await; // greeting
        w.write_all(b"a1 CAPABILITY\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "a1").await;
        assert!(lines.iter().any(|l| l.starts_with("* CAPABILITY")), "missing untagged CAPABILITY: {lines:?}");
        assert!(lines.iter().any(|l| l.contains("IMAP4rev1")), "missing IMAP4rev1: {lines:?}");
        assert!(lines.last().unwrap().contains("OK"), "tagged OK missing: {lines:?}");
    }

    #[tokio::test]
    async fn login_valid_credentials_is_ok() {
        let (addr, store) = start().await;
        store.create_user("alice", "alice@t.test", "secret").unwrap();
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await; // greeting
        w.write_all(b"t1 LOGIN alice secret\r\n").await.unwrap();
        let resp = read_line(&mut r).await;
        assert!(resp.contains("OK"), "valid login should get OK: {resp}");
    }

    #[tokio::test]
    async fn login_wrong_password_is_no() {
        let (addr, store) = start().await;
        store.create_user("bob", "bob@t.test", "correct").unwrap();
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await;
        w.write_all(b"t1 LOGIN bob wrong\r\n").await.unwrap();
        let resp = read_line(&mut r).await;
        assert!(resp.contains("NO"), "wrong password should get NO: {resp}");
    }

    #[tokio::test]
    async fn select_before_login_is_no() {
        let (addr, _) = start().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await;
        w.write_all(b"t1 SELECT INBOX\r\n").await.unwrap();
        let resp = read_line(&mut r).await;
        assert!(resp.contains("NO"), "SELECT before LOGIN should get NO: {resp}");
    }

    #[tokio::test]
    async fn select_after_login_includes_exists_count() {
        let (addr, store) = start().await;
        store.create_user("carol", "carol@t.test", "pass").unwrap();
        store.ensure_standard_mailboxes("carol").unwrap();
        let msg = b"From: x@x.com\r\nTo: carol@t.test\r\nSubject: S\r\nDate: Mon, 01 Jan 2024 12:00:00 +0000\r\n\r\nB\r\n";
        store.deliver("carol", "INBOX", msg).unwrap();

        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await;
        w.write_all(b"t1 LOGIN carol pass\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"t2 SELECT INBOX\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "t2").await;
        let has_exists = lines.iter().any(|l| l.contains("1 EXISTS"));
        assert!(has_exists, "expected '1 EXISTS' in SELECT response: {lines:?}");
        assert!(lines.last().unwrap().contains("OK"), "tagged OK missing: {lines:?}");
    }

    #[tokio::test]
    async fn list_returns_mailboxes_after_login() {
        let (addr, store) = start().await;
        store.create_user("dave", "dave@t.test", "pass").unwrap();
        store.ensure_standard_mailboxes("dave").unwrap();

        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await;
        w.write_all(b"t1 LOGIN dave pass\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"t2 LIST \"\" \"*\"\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "t2").await;
        let has_inbox = lines.iter().any(|l| l.contains("INBOX"));
        assert!(has_inbox, "LIST should include INBOX: {lines:?}");
        assert!(lines.last().unwrap().contains("OK"), "{lines:?}");
    }

    #[tokio::test]
    async fn logout_sends_bye_and_ok() {
        let (addr, _) = start().await;
        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await;
        w.write_all(b"t1 LOGOUT\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "t1").await;
        assert!(lines.iter().any(|l| l.starts_with("* BYE")), "* BYE missing: {lines:?}");
        assert!(lines.last().unwrap().contains("OK"), "tagged OK missing: {lines:?}");
    }
}

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
