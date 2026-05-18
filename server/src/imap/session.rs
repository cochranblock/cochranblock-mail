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
    async fn select_exists_includes_deleted_before_expunge() {
        // RFC 3501 §6.3.1: EXISTS reflects the count of ALL messages; \Deleted messages
        // retain their sequence number until EXPUNGE and must be counted in EXISTS.
        let (addr, store) = start().await;
        store.create_user("dan", "dan@t.test", "pass").unwrap();
        store.ensure_standard_mailboxes("dan").unwrap();
        let msg = b"From: x@x.com\r\nSubject: S\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nB\r\n";
        store.deliver("dan", "INBOX", msg).unwrap(); // uid 1
        store.deliver("dan", "INBOX", msg).unwrap(); // uid 2
        store.deliver("dan", "INBOX", msg).unwrap(); // uid 3
        // Mark uid 2 deleted — it must still count toward EXISTS.
        store.update_flags("dan", "INBOX", 2, None, None, Some(true)).unwrap();

        let (mut r, mut w) = connect(addr).await;
        read_line(&mut r).await;
        w.write_all(b"t1 LOGIN dan pass\r\n").await.unwrap();
        read_line(&mut r).await;
        w.write_all(b"t2 SELECT INBOX\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "t2").await;
        assert!(
            lines.iter().any(|l| l.contains("3 EXISTS")),
            "\\Deleted message must still be counted in EXISTS before EXPUNGE: {lines:?}"
        );
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

    // ── Helpers shared by FETCH/STORE/EXPUNGE tests ────────────────────────────

    const SAMPLE_MSG: &[u8] = b"\
From: alice@x.com\r\n\
To: bob@cochranblock.test\r\n\
Subject: Hello IMAP\r\n\
Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n\
\r\n\
IMAP body text.\r\n";

    async fn login_select(
        r: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
        w: &mut tokio::net::tcp::OwnedWriteHalf,
        user: &str,
        pass: &str,
        mailbox: &str,
    ) {
        read_line(r).await; // greeting
        w.write_all(format!("tx LOGIN {user} {pass}\r\n").as_bytes()).await.unwrap();
        read_line(r).await; // LOGIN response
        w.write_all(format!("ty SELECT {mailbox}\r\n").as_bytes()).await.unwrap();
        read_until_tagged(r, "ty").await; // SELECT response (multiple lines)
    }

    // ── FETCH tests ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_uid_and_flags() {
        let (addr, store) = start().await;
        store.create_user("eve", "eve@t.test", "pass").unwrap();
        store.ensure_standard_mailboxes("eve").unwrap();
        store.deliver("eve", "INBOX", SAMPLE_MSG).unwrap();

        let (mut r, mut w) = connect(addr).await;
        login_select(&mut r, &mut w, "eve", "pass", "INBOX").await;

        w.write_all(b"f1 FETCH 1 (UID FLAGS RFC822.SIZE)\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "f1").await;
        let fetch_line = lines.iter().find(|l| l.starts_with("* 1 FETCH")).unwrap();
        assert!(fetch_line.contains("UID 1"), "UID missing: {fetch_line}");
        assert!(fetch_line.contains("FLAGS"), "FLAGS missing: {fetch_line}");
        assert!(fetch_line.contains("RFC822.SIZE"), "SIZE missing: {fetch_line}");
        assert!(lines.last().unwrap().contains("OK"), "{lines:?}");
    }

    #[tokio::test]
    async fn fetch_rfc822_header_returns_headers() {
        let (addr, store) = start().await;
        store.create_user("fay", "fay@t.test", "pass").unwrap();
        store.ensure_standard_mailboxes("fay").unwrap();
        store.deliver("fay", "INBOX", SAMPLE_MSG).unwrap();

        let (mut r, mut w) = connect(addr).await;
        login_select(&mut r, &mut w, "fay", "pass", "INBOX").await;

        w.write_all(b"f1 FETCH 1 RFC822.HEADER\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "f1").await;
        let fetch_line = lines.iter().find(|l| l.starts_with("* 1 FETCH")).unwrap();
        assert!(fetch_line.contains("RFC822.HEADER"), "RFC822.HEADER missing: {fetch_line}");
        // Verify actual header content from SAMPLE_MSG appears in the literal body lines.
        assert!(
            lines.iter().any(|l| l.contains("alice@x.com") || l.contains("Hello IMAP")),
            "header content from SAMPLE_MSG missing in response: {lines:?}"
        );
        assert!(lines.last().unwrap().contains("OK"), "{lines:?}");
    }

    #[tokio::test]
    async fn uid_fetch_star_returns_all_messages() {
        let (addr, store) = start().await;
        store.create_user("gil", "gil@t.test", "pass").unwrap();
        store.ensure_standard_mailboxes("gil").unwrap();
        store.deliver("gil", "INBOX", SAMPLE_MSG).unwrap();
        store.deliver("gil", "INBOX", SAMPLE_MSG).unwrap();

        let (mut r, mut w) = connect(addr).await;
        login_select(&mut r, &mut w, "gil", "pass", "INBOX").await;

        w.write_all(b"u1 UID FETCH 1:* (UID FLAGS)\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "u1").await;
        let fetch_lines: Vec<_> = lines.iter().filter(|l| l.starts_with("* ") && l.contains("FETCH")).collect();
        assert_eq!(fetch_lines.len(), 2, "expected 2 FETCH responses: {lines:?}");
        assert!(
            fetch_lines.iter().all(|l| l.contains("UID")),
            "UID must appear in every UID FETCH response: {fetch_lines:?}"
        );
        assert!(lines.last().unwrap().contains("OK"), "{lines:?}");
    }

    #[tokio::test]
    async fn uid_fetch_always_includes_uid_in_response() {
        let (addr, store) = start().await;
        store.create_user("hank", "hank@t.test", "pass").unwrap();
        store.ensure_standard_mailboxes("hank").unwrap();
        store.deliver("hank", "INBOX", SAMPLE_MSG).unwrap();

        let (mut r, mut w) = connect(addr).await;
        login_select(&mut r, &mut w, "hank", "pass", "INBOX").await;

        // Ask for only FLAGS — UID FETCH must still include UID in response.
        w.write_all(b"u1 UID FETCH 1:* FLAGS\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "u1").await;
        let fetch_line = lines.iter().find(|l| l.starts_with("* ") && l.contains("FETCH")).unwrap();
        assert!(fetch_line.contains("UID"), "UID must be in UID FETCH response: {fetch_line}");
    }

    // ── STORE tests ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn store_adds_seen_flag() {
        let (addr, store) = start().await;
        store.create_user("ida", "ida@t.test", "pass").unwrap();
        store.ensure_standard_mailboxes("ida").unwrap();
        store.deliver("ida", "INBOX", SAMPLE_MSG).unwrap();

        let (mut r, mut w) = connect(addr).await;
        login_select(&mut r, &mut w, "ida", "pass", "INBOX").await;

        w.write_all(b"s1 STORE 1 +FLAGS (\\Seen)\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "s1").await;
        let fetch_resp = lines.iter().find(|l| l.contains("FETCH")).unwrap();
        assert!(fetch_resp.contains("\\Seen"), "\\Seen missing after STORE: {fetch_resp}");
        assert!(lines.last().unwrap().contains("OK"), "{lines:?}");
    }

    #[tokio::test]
    async fn store_removes_flag() {
        let (addr, store) = start().await;
        store.create_user("jay", "jay@t.test", "pass").unwrap();
        store.ensure_standard_mailboxes("jay").unwrap();
        store.deliver("jay", "INBOX", SAMPLE_MSG).unwrap();
        // Mark seen first.
        store.update_flags("jay", "INBOX", 1, Some(true), None, None).unwrap();

        let (mut r, mut w) = connect(addr).await;
        login_select(&mut r, &mut w, "jay", "pass", "INBOX").await;

        w.write_all(b"s1 STORE 1 -FLAGS (\\Seen)\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "s1").await;
        let fetch_resp = lines.iter().find(|l| l.contains("FETCH")).unwrap();
        assert!(!fetch_resp.contains("\\Seen"), "\\Seen should be gone after -FLAGS: {fetch_resp}");
        assert!(lines.last().unwrap().contains("OK"), "{lines:?}");
    }

    // ── EXPUNGE test ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn expunge_removes_deleted_message() {
        let (addr, store) = start().await;
        store.create_user("kai", "kai@t.test", "pass").unwrap();
        store.ensure_standard_mailboxes("kai").unwrap();
        store.deliver("kai", "INBOX", SAMPLE_MSG).unwrap();
        store.deliver("kai", "INBOX", SAMPLE_MSG).unwrap();
        store.deliver("kai", "INBOX", SAMPLE_MSG).unwrap();

        let (mut r, mut w) = connect(addr).await;
        login_select(&mut r, &mut w, "kai", "pass", "INBOX").await;

        // Mark message 2 as deleted.
        w.write_all(b"s1 STORE 2 +FLAGS (\\Deleted)\r\n").await.unwrap();
        read_until_tagged(&mut r, "s1").await;

        // Expunge.
        w.write_all(b"e1 EXPUNGE\r\n").await.unwrap();
        let lines = read_until_tagged(&mut r, "e1").await;
        let expunge_lines: Vec<_> = lines.iter().filter(|l| l.starts_with("* ") && l.contains("EXPUNGE")).collect();
        assert_eq!(expunge_lines.len(), 1, "expected exactly 1 untagged EXPUNGE: {lines:?}");
        assert!(expunge_lines[0].contains("* 2 EXPUNGE"), "wrong seq: {expunge_lines:?}");
        assert!(lines.last().unwrap().contains("OK"), "{lines:?}");
    }
}

use crate::config::Config;
use crate::imap::{command::ImapCommand, fetch};
use crate::store::MailStore;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Debug)]
enum State {
    NotAuthenticated,
    Authenticated { user: String },
    /// `uids` holds all non-deleted UIDs sorted ascending; index+1 = sequence number.
    Selected { user: String, mailbox: String, uids: Vec<u64> },
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
            .write_all(format!("* OK {} IMAP4rev1 ready\r\n", self.config.domain).as_bytes())
            .await?;

        let mut lines = BufReader::new(reader).lines();
        let peer = self.peer;
        let store = Arc::clone(&self.store);
        let mut state = State::NotAuthenticated;

        while let Some(line) = lines.next_line().await? {
            tracing::debug!(%peer, "<< {line}");
            let Some(cmd) = ImapCommand::parse(&line) else { continue };

            match cmd.verb.as_str() {
                // ── Pre-auth commands ──────────────────────────────────────────
                "CAPABILITY" => {
                    writer.write_all(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS\r\n").await?;
                    writer
                        .write_all(format!("{} OK CAPABILITY completed\r\n", cmd.tag).as_bytes())
                        .await?;
                }

                "LOGIN" => {
                    if let Some(args) = cmd.args.first() {
                        let mut parts = args.splitn(2, ' ');
                        let user = parts.next().unwrap_or("").trim_matches('"').to_string();
                        let pass = parts.next().unwrap_or("").trim_matches('"').to_string();
                        if store.verify_password(&user, &pass).unwrap_or(false) {
                            writer
                                .write_all(format!("{} OK LOGIN completed\r\n", cmd.tag).as_bytes())
                                .await?;
                            state = State::Authenticated { user };
                        } else {
                            writer
                                .write_all(
                                    format!("{} NO [AUTHENTICATIONFAILED] LOGIN failed\r\n", cmd.tag).as_bytes(),
                                )
                                .await?;
                        }
                    }
                }

                // ── Mailbox commands ───────────────────────────────────────────
                "SELECT" | "EXAMINE" => {
                    if let State::Authenticated { user } | State::Selected { user, .. } = &state {
                        let mailbox_name = cmd.args.first().cloned().unwrap_or_default();
                        let mailbox_name = mailbox_name.trim_matches('"').to_string();
                        let user = user.clone();
                        let mbox = store.get_mailbox_state(&user, &mailbox_name).unwrap_or_default();
                        let uids = store.list_uids_asc(&user, &mailbox_name).unwrap_or_default();
                        writer
                            .write_all(
                                format!(
                                    "* {} EXISTS\r\n* 0 RECENT\r\n\
                                     * OK [UIDVALIDITY {}] UIDs valid\r\n\
                                     * OK [UIDNEXT {}] Predicted next UID\r\n\
                                     * FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n\
                                     * OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted\r\n\
                                     {} OK [READ-WRITE] SELECT completed\r\n",
                                    mbox.message_count, mbox.uid_validity, mbox.uid_next, cmd.tag
                                )
                                .as_bytes(),
                            )
                            .await?;
                        state = State::Selected { user, mailbox: mailbox_name, uids };
                    } else {
                        writer
                            .write_all(format!("{} NO Not authenticated\r\n", cmd.tag).as_bytes())
                            .await?;
                    }
                }

                "CLOSE" => {
                    if let State::Selected { user, mailbox, .. } = &state {
                        // Silently expunge \Deleted messages, then deselect.
                        store.expunge_deleted(user, mailbox).unwrap_or_default();
                        let user = user.clone();
                        state = State::Authenticated { user };
                    }
                    writer
                        .write_all(format!("{} OK CLOSE completed\r\n", cmd.tag).as_bytes())
                        .await?;
                }

                "LIST" => {
                    if let State::Authenticated { user } | State::Selected { user, .. } = &state {
                        let mboxes = store.list_mailboxes(user).unwrap_or_default();
                        for (name, _) in &mboxes {
                            writer
                                .write_all(format!("* LIST () \"/\" \"{name}\"\r\n").as_bytes())
                                .await?;
                        }
                        writer
                            .write_all(format!("{} OK LIST completed\r\n", cmd.tag).as_bytes())
                            .await?;
                    } else {
                        writer
                            .write_all(format!("{} NO Not authenticated\r\n", cmd.tag).as_bytes())
                            .await?;
                    }
                }

                "STATUS" => {
                    if let State::Authenticated { user } | State::Selected { user, .. } = &state {
                        let mailbox_name = cmd.args.first().cloned().unwrap_or_default();
                        let mailbox_name = mailbox_name.trim_matches('"').to_string();
                        let s = store.get_mailbox_state(user, &mailbox_name).unwrap_or_default();
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
                            .write_all(format!("{} NO Not authenticated\r\n", cmd.tag).as_bytes())
                            .await?;
                    }
                }

                // ── FETCH ──────────────────────────────────────────────────────
                "FETCH" => {
                    if let State::Selected { user, mailbox, uids } = &state {
                        let args = cmd.args.first().cloned().unwrap_or_default();
                        match fetch::parse_fetch_args(&args) {
                            None => {
                                writer
                                    .write_all(format!("{} BAD Invalid FETCH args\r\n", cmd.tag).as_bytes())
                                    .await?;
                            }
                            Some((seq_set, items)) => {
                                let max = uids.len() as u32;
                                let user = user.clone();
                                let mailbox = mailbox.clone();
                                let uids_snap = uids.clone();
                                for (idx, &uid) in uids_snap.iter().enumerate() {
                                    let seq = (idx + 1) as u32;
                                    if !seq_set.contains(seq, max) { continue; }
                                    let Some(meta) = store.fetch_meta(&user, &mailbox, uid)? else { continue };
                                    let raw = store.fetch_raw(&user, &mailbox, uid)?.unwrap_or_default();
                                    let resp = fetch::build_fetch_response(seq, uid, &meta, &raw, &items);
                                    writer.write_all(resp.as_bytes()).await?;
                                }
                                writer
                                    .write_all(format!("{} OK FETCH completed\r\n", cmd.tag).as_bytes())
                                    .await?;
                            }
                        }
                    } else {
                        writer
                            .write_all(format!("{} NO Not in selected state\r\n", cmd.tag).as_bytes())
                            .await?;
                    }
                }

                // ── STORE ──────────────────────────────────────────────────────
                "STORE" => {
                    if let State::Selected { user, mailbox, uids } = &mut state {
                        let args = cmd.args.first().cloned().unwrap_or_default();
                        match parse_store_command(&args) {
                            None => {
                                writer
                                    .write_all(format!("{} BAD Invalid STORE args\r\n", cmd.tag).as_bytes())
                                    .await?;
                            }
                            Some((seq_set, mode, flag_byte)) => {
                                let max = uids.len() as u32;
                                let user_s = user.clone();
                                let mbox_s = mailbox.clone();
                                for (idx, &uid) in uids.iter().enumerate() {
                                    let seq = (idx + 1) as u32;
                                    if !seq_set.contains(seq, max) { continue; }
                                    apply_store(&store, &user_s, &mbox_s, uid, mode, flag_byte);
                                    if let Some(meta) = store.fetch_meta(&user_s, &mbox_s, uid)? {
                                        let resp = format!(
                                            "* {seq} FETCH (FLAGS ({}))\r\n",
                                            fetch::format_flags(meta.flags)
                                        );
                                        writer.write_all(resp.as_bytes()).await?;
                                    }
                                }
                                // Refresh UIDs (a +\Deleted might have been added)
                                *uids = store.list_uids_asc(&user_s, &mbox_s).unwrap_or_default();
                                writer
                                    .write_all(format!("{} OK STORE completed\r\n", cmd.tag).as_bytes())
                                    .await?;
                            }
                        }
                    } else {
                        writer
                            .write_all(format!("{} NO Not in selected state\r\n", cmd.tag).as_bytes())
                            .await?;
                    }
                }

                // ── EXPUNGE ────────────────────────────────────────────────────
                "EXPUNGE" => {
                    if let State::Selected { user, mailbox, uids } = &mut state {
                        let user_s = user.clone();
                        let mbox_s = mailbox.clone();
                        let expunged_uids = store.expunge_deleted(&user_s, &mbox_s).unwrap_or_default();

                        // Send `* N EXPUNGE` for each removed message.
                        // Sequence numbers shift down as each is removed, so we process
                        // from highest seq to lowest to keep responses accurate.
                        let mut current_uids = uids.clone();
                        for uid in expunged_uids.iter().rev() {
                            if let Some(pos) = current_uids.iter().position(|&u| u == *uid) {
                                let seq = (pos + 1) as u32;
                                current_uids.remove(pos);
                                writer
                                    .write_all(format!("* {seq} EXPUNGE\r\n").as_bytes())
                                    .await?;
                            }
                        }
                        *uids = store.list_uids_asc(&user_s, &mbox_s).unwrap_or_default();
                        writer
                            .write_all(format!("{} OK EXPUNGE completed\r\n", cmd.tag).as_bytes())
                            .await?;
                    } else {
                        writer
                            .write_all(format!("{} NO Not in selected state\r\n", cmd.tag).as_bytes())
                            .await?;
                    }
                }

                // ── UID commands ───────────────────────────────────────────────
                "UID" => {
                    let args = cmd.args.first().cloned().unwrap_or_default();
                    let mut parts = args.splitn(2, ' ');
                    let sub = parts.next().unwrap_or("").to_ascii_uppercase();
                    let sub_args = parts.next().unwrap_or("");

                    match sub.as_str() {
                        "FETCH" => {
                            if let State::Selected { user, mailbox, uids } = &state {
                                match fetch::parse_fetch_args(sub_args) {
                                    None => {
                                        writer
                                            .write_all(format!("{} BAD Invalid UID FETCH args\r\n", cmd.tag).as_bytes())
                                            .await?;
                                    }
                                    Some((uid_set, mut items)) => {
                                        // UID FETCH must always return UID in response.
                                        if !items.contains(&fetch::FetchItem::Uid) {
                                            items.push(fetch::FetchItem::Uid);
                                        }
                                        let max_uid = uids.last().copied().unwrap_or(0) as u32;
                                        let user_s = user.clone();
                                        let mbox_s = mailbox.clone();
                                        let uids_snap = uids.clone();
                                        for (idx, &uid) in uids_snap.iter().enumerate() {
                                            let seq = (idx + 1) as u32;
                                            if !uid_set.contains(uid as u32, max_uid) { continue; }
                                            let Some(meta) = store.fetch_meta(&user_s, &mbox_s, uid)? else { continue };
                                            let raw = store.fetch_raw(&user_s, &mbox_s, uid)?.unwrap_or_default();
                                            let resp = fetch::build_fetch_response(seq, uid, &meta, &raw, &items);
                                            writer.write_all(resp.as_bytes()).await?;
                                        }
                                        writer
                                            .write_all(format!("{} OK UID FETCH completed\r\n", cmd.tag).as_bytes())
                                            .await?;
                                    }
                                }
                            } else {
                                writer
                                    .write_all(format!("{} NO Not in selected state\r\n", cmd.tag).as_bytes())
                                    .await?;
                            }
                        }

                        "STORE" => {
                            if let State::Selected { user, mailbox, uids } = &mut state {
                                match parse_store_command(sub_args) {
                                    None => {
                                        writer
                                            .write_all(format!("{} BAD Invalid UID STORE args\r\n", cmd.tag).as_bytes())
                                            .await?;
                                    }
                                    Some((uid_set, mode, flag_byte)) => {
                                        let max_uid = uids.last().copied().unwrap_or(0) as u32;
                                        let user_s = user.clone();
                                        let mbox_s = mailbox.clone();
                                        for (idx, &uid) in uids.iter().enumerate() {
                                            let seq = (idx + 1) as u32;
                                            if !uid_set.contains(uid as u32, max_uid) { continue; }
                                            apply_store(&store, &user_s, &mbox_s, uid, mode, flag_byte);
                                            if let Some(meta) = store.fetch_meta(&user_s, &mbox_s, uid)? {
                                                let resp = format!(
                                                    "* {seq} FETCH (FLAGS ({}) UID {uid})\r\n",
                                                    fetch::format_flags(meta.flags)
                                                );
                                                writer.write_all(resp.as_bytes()).await?;
                                            }
                                        }
                                        *uids = store.list_uids_asc(&user_s, &mbox_s).unwrap_or_default();
                                        writer
                                            .write_all(format!("{} OK UID STORE completed\r\n", cmd.tag).as_bytes())
                                            .await?;
                                    }
                                }
                            } else {
                                writer
                                    .write_all(format!("{} NO Not in selected state\r\n", cmd.tag).as_bytes())
                                    .await?;
                            }
                        }

                        "COPY" => {
                            if let State::Selected { user, mailbox, uids } = &state {
                                let max_uid = uids.last().copied().unwrap_or(0) as u32;
                                match fetch::SeqSet::parse(sub_args.split_whitespace().next().unwrap_or("")) {
                                    None => {
                                        writer
                                            .write_all(format!("{} BAD Invalid UID COPY args\r\n", cmd.tag).as_bytes())
                                            .await?;
                                    }
                                    Some(uid_set) => {
                                        let dest_mbox = sub_args
                                            .split_whitespace()
                                            .nth(1)
                                            .unwrap_or("")
                                            .trim_matches('"')
                                            .to_string();
                                        let user_s = user.clone();
                                        let mbox_s = mailbox.clone();
                                        for &uid in uids {
                                            if !uid_set.contains(uid as u32, max_uid) { continue; }
                                            if let Some(raw) = store.fetch_raw(&user_s, &mbox_s, uid)? {
                                                store.deliver(&user_s, &dest_mbox, &raw).unwrap_or(0);
                                            }
                                        }
                                        writer
                                            .write_all(format!("{} OK UID COPY completed\r\n", cmd.tag).as_bytes())
                                            .await?;
                                    }
                                }
                            } else {
                                writer
                                    .write_all(format!("{} NO Not in selected state\r\n", cmd.tag).as_bytes())
                                    .await?;
                            }
                        }

                        "EXPUNGE" => {
                            // RFC 4315 UID EXPUNGE uid-set
                            if let State::Selected { user, mailbox, uids } = &mut state {
                                let user_s = user.clone();
                                let mbox_s = mailbox.clone();
                                // For simplicity, UID EXPUNGE behaves like EXPUNGE
                                let expunged_uids = store.expunge_deleted(&user_s, &mbox_s).unwrap_or_default();
                                let mut current_uids = uids.clone();
                                for uid in expunged_uids.iter().rev() {
                                    if let Some(pos) = current_uids.iter().position(|&u| u == *uid) {
                                        let seq = (pos + 1) as u32;
                                        current_uids.remove(pos);
                                        writer
                                            .write_all(format!("* {seq} EXPUNGE\r\n").as_bytes())
                                            .await?;
                                    }
                                }
                                *uids = store.list_uids_asc(&user_s, &mbox_s).unwrap_or_default();
                                writer
                                    .write_all(format!("{} OK UID EXPUNGE completed\r\n", cmd.tag).as_bytes())
                                    .await?;
                            } else {
                                writer
                                    .write_all(format!("{} NO Not in selected state\r\n", cmd.tag).as_bytes())
                                    .await?;
                            }
                        }

                        other => {
                            writer
                                .write_all(
                                    format!("{} BAD UID {} not implemented\r\n", cmd.tag, other).as_bytes(),
                                )
                                .await?;
                        }
                    }
                }

                // ── Session commands ───────────────────────────────────────────
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
                            format!("{} BAD Command not implemented: {other}\r\n", cmd.tag).as_bytes(),
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_store_command(s: &str) -> Option<(fetch::SeqSet, char, u8)> {
    let (seq_str, rest) = s.trim().split_once(' ')?;
    let seq_set = fetch::SeqSet::parse(seq_str)?;
    let (mode, flags) = fetch::parse_store_args(rest.trim())?;
    Some((seq_set, mode, flags))
}

fn apply_store(store: &MailStore, user: &str, mailbox: &str, uid: u64, mode: char, flag_byte: u8) {
    use shared::flags as f;
    let val = mode != '-';
    store.update_flags(
        user, mailbox, uid,
        (flag_byte & f::SEEN != 0).then_some(val),
        (flag_byte & f::STARRED != 0).then_some(val),
        (flag_byte & f::DELETED != 0).then_some(val),
    ).ok();
}
