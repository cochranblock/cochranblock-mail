#![allow(clippy::result_large_err)]

use super::{MailStore, StoreError, MAILBOXES, MESSAGE_META, MESSAGES};
use redb::ReadableTable;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared::flags;

pub const PAGE_SIZE: u32 = 50;

// Standard mailbox names.
pub const INBOX: &str = "INBOX";
pub const SENT: &str = "Sent";
pub const DRAFTS: &str = "Drafts";
pub const TRASH: &str = "Trash";
pub const SPAM: &str = "Spam";

pub const STANDARD_MAILBOXES: &[&str] = &[INBOX, SENT, DRAFTS, TRASH, SPAM];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxState {
    pub uid_validity: u32,
    pub uid_next: u64,
    pub message_count: u64,
    pub unread_count: u64,
}

impl Default for MailboxState {
    fn default() -> Self {
        Self {
            uid_validity: 1,
            uid_next: 1,
            message_count: 0,
            unread_count: 0,
        }
    }
}

fn mailbox_key(username: &str, mailbox: &str) -> String {
    format!("{username}/{mailbox}")
}

fn message_key(username: &str, mailbox: &str, uid: u64) -> String {
    format!("{username}/{mailbox}/{uid:016x}")
}

impl MailStore {
    // ── Mailbox management ────────────────────────────────────────────────────

    pub fn ensure_standard_mailboxes(&self, username: &str) -> Result<(), StoreError> {
        for &mbox in STANDARD_MAILBOXES {
            let key = mailbox_key(username, mbox);
            let tx = self.db.begin_write()?;
            {
                let mut table = tx.open_table(MAILBOXES)?;
                if table.get(key.as_str())?.is_none() {
                    let state = serde_json::to_string(&MailboxState::default())?;
                    table.insert(key.as_str(), state.as_str())?;
                }
            }
            tx.commit()?;
        }
        Ok(())
    }

    pub fn get_mailbox_state(
        &self,
        username: &str,
        mailbox: &str,
    ) -> Result<MailboxState, StoreError> {
        let key = mailbox_key(username, mailbox);
        let tx = self.db.begin_read()?;
        let table = tx.open_table(MAILBOXES)?;
        match table.get(key.as_str())? {
            Some(val) => Ok(serde_json::from_str(val.value())?),
            None => Ok(MailboxState::default()),
        }
    }

    pub fn list_mailboxes(
        &self,
        username: &str,
    ) -> Result<Vec<(String, MailboxState)>, StoreError> {
        let prefix = format!("{username}/");
        let tx = self.db.begin_read()?;
        let table = tx.open_table(MAILBOXES)?;
        let mut result = Vec::new();
        for entry in table.iter()? {
            let (key, val) = entry?;
            if key.value().starts_with(&prefix) {
                let mailbox_name = key.value()[prefix.len()..].to_string();
                let state: MailboxState = serde_json::from_str(val.value())?;
                result.push((mailbox_name, state));
            }
        }
        Ok(result)
    }

    // ── Message delivery ──────────────────────────────────────────────────────

    /// Deliver an inbound RFC 5322 message. Returns the assigned UID.
    pub fn deliver(
        &self,
        username: &str,
        mailbox: &str,
        raw: &[u8],
    ) -> Result<u64, StoreError> {
        let meta = extract_meta(username, mailbox, raw);
        let mbox_key = mailbox_key(username, mailbox);

        let tx = self.db.begin_write()?;
        let uid = {
            let mut mbox_table = tx.open_table(MAILBOXES)?;
            let mut state: MailboxState = match mbox_table.get(mbox_key.as_str())? {
                Some(v) => serde_json::from_str(v.value())?,
                None => MailboxState::default(),
            };
            let uid = state.uid_next;
            state.uid_next += 1;
            state.message_count += 1;
            if meta.flags & flags::SEEN == 0 {
                state.unread_count += 1;
            }
            let state_str = serde_json::to_string(&state)?;
            mbox_table.insert(mbox_key.as_str(), state_str.as_str())?;
            uid
        };

        let msg_key = message_key(username, mailbox, uid);
        let compressed = zstd::encode_all(raw, 3).unwrap_or_else(|_| raw.to_vec());

        {
            let mut msg_table = tx.open_table(MESSAGES)?;
            msg_table.insert(msg_key.as_str(), compressed.as_slice())?;
        }

        let full_meta = shared::MessageMeta {
            uid,
            mailbox: mailbox.to_string(),
            from: meta.from,
            to: meta.to,
            subject: meta.subject,
            date: meta.date,
            flags: meta.flags,
            size: raw.len(),
            snippet: meta.snippet,
        };
        {
            let mut meta_table = tx.open_table(MESSAGE_META)?;
            let meta_str = serde_json::to_string(&full_meta)?;
            meta_table.insert(msg_key.as_str(), meta_str.as_str())?;
        }

        tx.commit()?;
        Ok(uid)
    }

    // ── Message retrieval ─────────────────────────────────────────────────────

    pub fn fetch_raw(
        &self,
        username: &str,
        mailbox: &str,
        uid: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = message_key(username, mailbox, uid);
        let tx = self.db.begin_read()?;
        let table = tx.open_table(MESSAGES)?;
        match table.get(key.as_str())? {
            None => Ok(None),
            Some(v) => {
                let raw = zstd::decode_all(v.value()).unwrap_or_else(|_| v.value().to_vec());
                Ok(Some(raw))
            }
        }
    }

    pub fn fetch_meta(
        &self,
        username: &str,
        mailbox: &str,
        uid: u64,
    ) -> Result<Option<shared::MessageMeta>, StoreError> {
        let key = message_key(username, mailbox, uid);
        let tx = self.db.begin_read()?;
        let table = tx.open_table(MESSAGE_META)?;
        match table.get(key.as_str())? {
            None => Ok(None),
            Some(v) => Ok(Some(serde_json::from_str(v.value())?)),
        }
    }

    /// Returns a page of messages sorted newest-first.
    pub fn list_messages(
        &self,
        username: &str,
        mailbox: &str,
        page: u32,
    ) -> Result<(Vec<shared::MessageMeta>, u64), StoreError> {
        let prefix = format!("{username}/{mailbox}/");
        let tx = self.db.begin_read()?;
        let table = tx.open_table(MESSAGE_META)?;

        let mut all: Vec<shared::MessageMeta> = Vec::new();
        for entry in table.iter()? {
            let (key, val) = entry?;
            if key.value().starts_with(&prefix) {
                let meta: shared::MessageMeta = serde_json::from_str(val.value())?;
                if !meta.is_deleted() {
                    all.push(meta);
                }
            }
        }

        let total = all.len() as u64;
        // Sort newest-first by date; break ties by UID descending (higher = later delivered).
        all.sort_by(|a, b| b.date.cmp(&a.date).then(b.uid.cmp(&a.uid)));

        let start = (page as usize) * (PAGE_SIZE as usize);
        let page_msgs = all.into_iter().skip(start).take(PAGE_SIZE as usize).collect();
        Ok((page_msgs, total))
    }

    // ── Flag updates ──────────────────────────────────────────────────────────

    pub fn update_flags(
        &self,
        username: &str,
        mailbox: &str,
        uid: u64,
        seen: Option<bool>,
        starred: Option<bool>,
        deleted: Option<bool>,
    ) -> Result<(), StoreError> {
        let key = message_key(username, mailbox, uid);
        let tx = self.db.begin_write()?;
        {
            // Open once as mutable. Read into owned String immediately so we can
            // call insert() on the same table handle without a borrow conflict.
            let mut meta_table = tx.open_table(MESSAGE_META)?;
            let existing_json = meta_table
                .get(key.as_str())?
                .map(|v| v.value().to_string())
                .ok_or_else(|| StoreError::NotFound(key.clone()))?;
            let mut meta: shared::MessageMeta = serde_json::from_str(&existing_json)?;
            let was_seen = meta.is_seen();

            if let Some(s) = seen {
                if s { meta.flags |= flags::SEEN; } else { meta.flags &= !flags::SEEN; }
            }
            if let Some(s) = starred {
                if s { meta.flags |= flags::STARRED; } else { meta.flags &= !flags::STARRED; }
            }
            if let Some(d) = deleted {
                if d { meta.flags |= flags::DELETED; } else { meta.flags &= !flags::DELETED; }
            }

            let new_seen = meta.is_seen();
            let meta_str = serde_json::to_string(&meta)?;
            meta_table.insert(key.as_str(), meta_str.as_str())?;

            // Keep mailbox unread count in sync.
            if was_seen != new_seen {
                let mbox_key = mailbox_key(username, mailbox);
                let mut mbox_table = tx.open_table(MAILBOXES)?;
                // Read existing state, clone to owned string, then drop the borrow
                // before calling insert() to avoid overlapping borrows.
                let existing_json: Option<String> = mbox_table
                    .get(mbox_key.as_str())?
                    .map(|v| v.value().to_string());
                if let Some(json) = existing_json {
                    let mut state: MailboxState = serde_json::from_str(&json)?;
                    if new_seen && state.unread_count > 0 {
                        state.unread_count -= 1;
                    } else if !new_seen {
                        state.unread_count += 1;
                    }
                    let state_str = serde_json::to_string(&state)?;
                    mbox_table.insert(mbox_key.as_str(), state_str.as_str())?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}

// ── Message parsing helpers ───────────────────────────────────────────────────

struct RawMeta {
    from: String,
    to: Vec<String>,
    subject: String,
    date: DateTime<Utc>,
    flags: u8,
    snippet: String,
}

fn extract_meta(username: &str, mailbox: &str, raw: &[u8]) -> RawMeta {
    let _ = (username, mailbox); // may be used for future per-mailbox defaults
    let parsed = mailparse::parse_mail(raw);
    match parsed {
        Ok(msg) => {
            let from = header_val(&msg, "From").unwrap_or_default();
            let to = header_val(&msg, "To")
                .map(|s| s.split(',').map(|a| a.trim().to_string()).collect())
                .unwrap_or_default();
            let subject = header_val(&msg, "Subject").unwrap_or_else(|| "(no subject)".into());
            let date = header_val(&msg, "Date")
                .and_then(|d| chrono::DateTime::parse_from_rfc2822(&d).ok())
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);
            let snippet = body_snippet(&msg);
            RawMeta { from, to, subject, date, flags: 0, snippet }
        }
        Err(_) => RawMeta {
            from: String::new(),
            to: vec![],
            subject: "(unparseable)".into(),
            date: Utc::now(),
            flags: 0,
            snippet: String::new(),
        },
    }
}

fn header_val(msg: &mailparse::ParsedMail, name: &str) -> Option<String> {
    msg.headers
        .iter()
        .find(|h| h.get_key_ref().eq_ignore_ascii_case(name))
        .map(|h| h.get_value())
}

fn body_snippet(msg: &mailparse::ParsedMail) -> String {
    // Walk the MIME tree looking for text/plain first, then text/html.
    let text = find_body(msg, "text/plain")
        .or_else(|| find_body(msg, "text/html"));
    text.map(|t| {
        let clean: String = t.chars().filter(|c| !c.is_control() || *c == ' ').take(200).collect();
        clean.trim().to_string()
    })
    .unwrap_or_default()
}

fn find_body(msg: &mailparse::ParsedMail, mime_type: &str) -> Option<String> {
    let ct = msg.ctype.mimetype.to_ascii_lowercase();
    if ct == mime_type {
        return msg.get_body().ok();
    }
    for sub in &msg.subparts {
        if let Some(found) = find_body(sub, mime_type) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn open_store() -> MailStore {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.redb");
        std::mem::forget(dir);
        MailStore::open(&path).unwrap()
    }

    const TEST_MSG: &[u8] = b"\
From: alice@example.com\r\n\
To: bob@cochranblock.org\r\n\
Subject: Hello world\r\n\
Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
This is the body of the email.\r\n";

    #[test]
    fn deliver_assigns_sequential_uids() {
        let store = open_store();
        let uid1 = store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        let uid2 = store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        assert_eq!(uid1, 1);
        assert_eq!(uid2, 2);
    }

    #[test]
    fn fetch_raw_roundtrips_message() {
        let store = open_store();
        let uid = store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        let raw = store.fetch_raw("alice", "INBOX", uid).unwrap().unwrap();
        assert_eq!(raw, TEST_MSG);
    }

    #[test]
    fn fetch_meta_extracts_headers() {
        let store = open_store();
        let uid = store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        let meta = store.fetch_meta("alice", "INBOX", uid).unwrap().unwrap();
        assert_eq!(meta.subject, "Hello world");
        assert!(meta.from.contains("alice@example.com"));
    }

    #[test]
    fn fetch_nonexistent_returns_none() {
        let store = open_store();
        assert!(store.fetch_raw("alice", "INBOX", 999).unwrap().is_none());
        assert!(store.fetch_meta("alice", "INBOX", 999).unwrap().is_none());
    }

    #[test]
    fn list_messages_newest_first() {
        let store = open_store();
        for _ in 0..3 {
            store.deliver("alice", "INBOX", TEST_MSG).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let (msgs, total) = store.list_messages("alice", "INBOX", 0).unwrap();
        assert_eq!(total, 3);
        assert_eq!(msgs.len(), 3);
        // highest uid = most recently delivered = newest
        assert!(msgs[0].uid >= msgs[1].uid);
        assert!(msgs[1].uid >= msgs[2].uid);
    }

    #[test]
    fn list_messages_pagination() {
        let store = open_store();
        for _ in 0..(PAGE_SIZE + 5) as usize {
            store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        }
        let (page0, total) = store.list_messages("alice", "INBOX", 0).unwrap();
        let (page1, _) = store.list_messages("alice", "INBOX", 1).unwrap();
        assert_eq!(total, (PAGE_SIZE + 5) as u64);
        assert_eq!(page0.len(), PAGE_SIZE as usize);
        assert_eq!(page1.len(), 5);
    }

    #[test]
    fn mailbox_unread_count_increments_on_deliver() {
        let store = open_store();
        store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        let state = store.get_mailbox_state("alice", "INBOX").unwrap();
        assert_eq!(state.unread_count, 2);
    }

    #[test]
    fn mark_seen_decrements_unread() {
        let store = open_store();
        let uid = store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        store.update_flags("alice", "INBOX", uid, Some(true), None, None).unwrap();
        let state = store.get_mailbox_state("alice", "INBOX").unwrap();
        assert_eq!(state.unread_count, 0);
    }

    #[test]
    fn deleted_messages_excluded_from_list() {
        let store = open_store();
        let uid = store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        store.update_flags("alice", "INBOX", uid, None, None, Some(true)).unwrap();
        let (msgs, total) = store.list_messages("alice", "INBOX", 0).unwrap();
        // total reflects non-deleted visible messages
        assert_eq!(msgs.len(), 1);
        assert_eq!(total, 1);
    }

    #[test]
    fn ensure_standard_mailboxes_idempotent() {
        let store = open_store();
        store.ensure_standard_mailboxes("alice").unwrap();
        store.ensure_standard_mailboxes("alice").unwrap(); // second call must not error
        let mboxes = store.list_mailboxes("alice").unwrap();
        assert_eq!(mboxes.len(), STANDARD_MAILBOXES.len());
    }
}
