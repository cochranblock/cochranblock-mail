#![allow(clippy::result_large_err)]

use super::{enc, dec, MailStore, StoreError, MAILBOXES, MESSAGE_META, MESSAGES, ATTACHMENT_META, ATTACHMENTS};
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
                    let state = enc(&MailboxState::default())?;
                    table.insert(key.as_str(), state.as_slice())?;
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
            Some(val) => Ok(dec(val.value())?),
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
                let state: MailboxState = dec(val.value())?;
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
        let meta = extract_meta(raw);
        let mbox_key = mailbox_key(username, mailbox);

        let tx = self.db.begin_write()?;
        let uid = {
            let mut mbox_table = tx.open_table(MAILBOXES)?;
            let mut state: MailboxState = match mbox_table.get(mbox_key.as_str())? {
                Some(v) => dec(v.value())?,
                None => MailboxState::default(),
            };
            let uid = state.uid_next;
            state.uid_next += 1;
            state.message_count += 1;
            if meta.flags & flags::SEEN == 0 {
                state.unread_count += 1;
            }
            let state_bytes = enc(&state)?;
            mbox_table.insert(mbox_key.as_str(), state_bytes.as_slice())?;
            uid
        };

        let msg_key = message_key(username, mailbox, uid);
        // Skip compression when it wouldn't shrink the message (common for tiny emails).
        let compressed = zstd::encode_all(raw, 3)
            .ok()
            .filter(|c| c.len() < raw.len())
            .unwrap_or_else(|| raw.to_vec());

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
            let meta_bytes = enc(&full_meta)?;
            meta_table.insert(msg_key.as_str(), meta_bytes.as_slice())?;
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
            Some(v) => Ok(Some(dec(v.value())?)),
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
                let meta: shared::MessageMeta = dec(val.value())?;
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

    /// Returns all non-deleted UIDs in a mailbox, sorted ascending (seq 1 = oldest).
    pub fn list_uids_asc(&self, username: &str, mailbox: &str) -> Result<Vec<u64>, StoreError> {
        let prefix = format!("{username}/{mailbox}/");
        let tx = self.db.begin_read()?;
        let table = tx.open_table(MESSAGE_META)?;
        let mut uids = Vec::new();
        for entry in table.iter()? {
            let (key, val) = entry?;
            if key.value().starts_with(&prefix) {
                let meta: shared::MessageMeta = dec(val.value())?;
                // \Deleted messages keep their sequence number until EXPUNGE.
                uids.push(meta.uid);
            }
        }
        uids.sort_unstable();
        Ok(uids)
    }

    /// Permanently remove all messages with `\Deleted` flag from the mailbox.
    /// Returns their UIDs sorted ascending (callers send `* N EXPUNGE` in reverse).
    pub fn expunge_deleted(&self, username: &str, mailbox: &str) -> Result<Vec<u64>, StoreError> {
        let prefix = format!("{username}/{mailbox}/");
        let mbox_key = mailbox_key(username, mailbox);

        // Phase 1 — collect keys to delete (read-only; no write transaction yet).
        let to_delete: Vec<(String, bool)> = {
            let rtx = self.db.begin_read()?;
            let rtable = rtx.open_table(MESSAGE_META)?;
            let mut v = Vec::new();
            for entry in rtable.iter()? {
                let (key, val) = entry?;
                if key.value().starts_with(&prefix) {
                    let meta: shared::MessageMeta = dec(val.value())?;
                    if meta.is_deleted() {
                        v.push((key.value().to_string(), meta.is_seen()));
                    }
                }
            }
            v
        };

        if to_delete.is_empty() {
            return Ok(vec![]);
        }

        // Phase 2 — delete them in a single write transaction.
        let mut expunged = Vec::new();
        let tx = self.db.begin_write()?;
        {
            let mut meta_table = tx.open_table(MESSAGE_META)?;
            let mut msg_table = tx.open_table(MESSAGES)?;
            let mut att_meta_table = tx.open_table(ATTACHMENT_META)?;
            let mut att_table = tx.open_table(ATTACHMENTS)?;

            for (key, _was_seen) in &to_delete {
                if let Some(uid_hex) = key.split('/').next_back()
                    && let Ok(uid) = u64::from_str_radix(uid_hex, 16)
                {
                    expunged.push(uid);
                }
                meta_table.remove(key.as_str())?;
                msg_table.remove(key.as_str())?;
                delete_attachments_for_msg(&mut att_meta_table, &mut att_table, key)?;
            }

            // Update mailbox state counts.
            let mut mbox_table = tx.open_table(MAILBOXES)?;
            let stored = mbox_table.get(mbox_key.as_str())?.map(|v| v.value().to_vec());
            if let Some(stored) = stored {
                let mut state: MailboxState = dec(&stored)?;
                let n = to_delete.len() as u64;
                let unread_removed = to_delete.iter().filter(|(_, was_seen)| !was_seen).count() as u64;
                state.message_count = state.message_count.saturating_sub(n);
                state.unread_count = state.unread_count.saturating_sub(unread_removed);
                let updated = enc(&state)?;
                mbox_table.insert(mbox_key.as_str(), updated.as_slice())?;
            }
        }
        tx.commit()?;
        expunged.sort_unstable();
        Ok(expunged)
    }

    // ── Attachments ───────────────────────────────────────────────────────────

    /// Parse raw RFC 5322 bytes, extract attachment parts, zstd-compress, and store.
    /// Called immediately after `deliver()`. No-ops silently if the message has no attachments.
    pub fn store_attachments_from_raw(
        &self,
        username: &str,
        mailbox: &str,
        uid: u64,
        raw: &[u8],
    ) -> Result<(), StoreError> {
        let Ok(msg) = mailparse::parse_mail(raw) else { return Ok(()) };
        let mut collected = Vec::new();
        collect_attachments(&msg, &mut collected, &mut 0u32);
        if collected.is_empty() {
            return Ok(());
        }
        self.store_attachments(username, mailbox, uid, collected)
    }

    pub fn store_attachments(
        &self,
        username: &str,
        mailbox: &str,
        uid: u64,
        attachments: Vec<(shared::AttachmentMeta, Vec<u8>)>,
    ) -> Result<(), StoreError> {
        let msg_key = message_key(username, mailbox, uid);
        let tx = self.db.begin_write()?;
        {
            let mut att_meta_table = tx.open_table(ATTACHMENT_META)?;
            let mut att_table = tx.open_table(ATTACHMENTS)?;

            let metas: Vec<shared::AttachmentMeta> =
                attachments.iter().map(|(m, _)| m.clone()).collect();
            let meta_bytes = enc(&metas)?;
            att_meta_table.insert(msg_key.as_str(), meta_bytes.as_slice())?;

            for (meta, body) in &attachments {
                let att_key = format!("{msg_key}/{}", meta.part);
                let compressed = zstd::encode_all(body.as_slice(), 3)
                    .ok()
                    .filter(|c| c.len() < body.len())
                    .unwrap_or_else(|| body.clone());
                att_table.insert(att_key.as_str(), compressed.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_attachments(
        &self,
        username: &str,
        mailbox: &str,
        uid: u64,
    ) -> Result<Vec<shared::AttachmentMeta>, StoreError> {
        let key = message_key(username, mailbox, uid);
        let tx = self.db.begin_read()?;
        let table = tx.open_table(ATTACHMENT_META)?;
        match table.get(key.as_str())? {
            None => Ok(vec![]),
            Some(v) => dec(v.value()),
        }
    }

    pub fn get_attachment(
        &self,
        username: &str,
        mailbox: &str,
        uid: u64,
        part: u32,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let att_key = format!("{}/{part}", message_key(username, mailbox, uid));
        let tx = self.db.begin_read()?;
        let table = tx.open_table(ATTACHMENTS)?;
        match table.get(att_key.as_str())? {
            None => Ok(None),
            Some(v) => {
                let raw = zstd::decode_all(v.value()).unwrap_or_else(|_| v.value().to_vec());
                Ok(Some(raw))
            }
        }
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
            let existing_bytes = meta_table
                .get(key.as_str())?
                .map(|v| v.value().to_vec())
                .ok_or_else(|| StoreError::NotFound(key.clone()))?;
            let mut meta: shared::MessageMeta = dec(&existing_bytes)?;
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
            let meta_bytes = enc(&meta)?;
            meta_table.insert(key.as_str(), meta_bytes.as_slice())?;

            // Keep mailbox unread count in sync.
            if was_seen != new_seen {
                let mbox_key = mailbox_key(username, mailbox);
                let mut mbox_table = tx.open_table(MAILBOXES)?;
                let existing_bytes: Option<Vec<u8>> = mbox_table
                    .get(mbox_key.as_str())?
                    .map(|v| v.value().to_vec());
                if let Some(bytes) = existing_bytes {
                    let mut state: MailboxState = dec(&bytes)?;
                    if new_seen && state.unread_count > 0 {
                        state.unread_count -= 1;
                    } else if !new_seen {
                        state.unread_count += 1;
                    }
                    let state_bytes = enc(&state)?;
                    mbox_table.insert(mbox_key.as_str(), state_bytes.as_slice())?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}

// ── Attachment cleanup helper ─────────────────────────────────────────────────

fn delete_attachments_for_msg(
    att_meta_table: &mut redb::Table<&str, &[u8]>,
    att_table: &mut redb::Table<&str, &[u8]>,
    msg_key: &str,
) -> Result<(), StoreError> {
    let Some(meta_bytes) = att_meta_table.get(msg_key)?.map(|v| v.value().to_vec()) else {
        return Ok(());
    };
    if let Ok(metas) = dec::<Vec<shared::AttachmentMeta>>(&meta_bytes) {
        for meta in &metas {
            let att_key = format!("{msg_key}/{}", meta.part);
            att_table.remove(att_key.as_str())?;
        }
    }
    att_meta_table.remove(msg_key)?;
    Ok(())
}

// ── MIME attachment extraction helpers ────────────────────────────────────────

fn collect_attachments(
    part: &mailparse::ParsedMail,
    out: &mut Vec<(shared::AttachmentMeta, Vec<u8>)>,
    counter: &mut u32,
) {
    let mime = part.ctype.mimetype.to_ascii_lowercase();
    if mime.starts_with("multipart/") {
        for sub in &part.subparts {
            collect_attachments(sub, out, counter);
        }
        return;
    }

    // Inline text/plain and text/html are body content, not attachments.
    // A part is an attachment when it has an explicit attachment disposition,
    // a filename, or a non-text MIME type.
    let disp_header = part
        .headers
        .iter()
        .find(|h| h.get_key_ref().eq_ignore_ascii_case("content-disposition"))
        .map(|h| h.get_value());
    let explicit_attach = disp_header
        .as_deref()
        .map(|d| d.trim().to_ascii_lowercase().starts_with("attachment"))
        .unwrap_or(false);
    let has_filename = disp_header.as_deref().map(|d| param_value(d, "filename").is_some()).unwrap_or(false)
        || part.ctype.params.contains_key("name");
    let non_text = !mime.starts_with("text/") && !mime.is_empty();

    if !explicit_attach && !has_filename && !non_text {
        return;
    }

    let Ok(body) = part.get_body_raw() else { return };
    *counter += 1;
    let part_num = *counter;
    let filename = extract_filename(part, part_num);
    let meta = shared::AttachmentMeta {
        part: part_num,
        filename,
        content_type: part.ctype.mimetype.clone(),
        size: body.len() as u32,
    };
    out.push((meta, body));
}

fn extract_filename(part: &mailparse::ParsedMail, part_num: u32) -> String {
    for header in &part.headers {
        if header.get_key_ref().eq_ignore_ascii_case("content-disposition")
            && let Some(name) = param_value(&header.get_value(), "filename")
        {
            return name;
        }
    }
    if let Some(name) = part.ctype.params.get("name") {
        return name.clone();
    }
    let ext = match part.ctype.mimetype.to_ascii_lowercase().as_str() {
        "application/pdf" => "pdf",
        "image/jpeg" | "image/jpg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "text/calendar" => "ics",
        "application/zip" => "zip",
        "application/gzip" => "gz",
        "application/json" => "json",
        "application/xml" | "text/xml" => "xml",
        "application/msword" => "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        "application/vnd.ms-excel" => "xls",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => "xlsx",
        _ => "bin",
    };
    format!("attachment_{part_num}.{ext}")
}

fn param_value(header_val: &str, key: &str) -> Option<String> {
    for segment in header_val.split(';') {
        let segment = segment.trim();
        // Handle filename*=charset''value (RFC 5987) by extracting after the last '
        if let Some(rest) = segment.strip_prefix(&format!("{key}*=")) {
            let val = rest.splitn(3, '\'').nth(2).unwrap_or(rest).trim_matches('"');
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
        if let Some(rest) = segment.strip_prefix(&format!("{key}=")) {
            let val = rest.trim_matches('"');
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
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

fn extract_meta(raw: &[u8]) -> RawMeta {
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
        // Deliver messages with out-of-UID-order dates so the test actually exercises
        // date-based sorting rather than trivially passing via UID order.
        let make = |date: &str| -> Vec<u8> {
            format!("From: x@x.com\r\nSubject: s\r\nDate: {date}\r\n\r\nBody\r\n").into_bytes()
        };
        store.deliver("alice", "INBOX", &make("Mon, 01 Jan 2024 00:00:00 +0000")).unwrap(); // uid 1
        store.deliver("alice", "INBOX", &make("Fri, 01 Mar 2024 00:00:00 +0000")).unwrap(); // uid 2
        store.deliver("alice", "INBOX", &make("Thu, 01 Feb 2024 00:00:00 +0000")).unwrap(); // uid 3
        let (msgs, total) = store.list_messages("alice", "INBOX", 0).unwrap();
        assert_eq!(total, 3);
        assert_eq!(msgs.len(), 3);
        // Date order: Mar(uid 2) > Feb(uid 3) > Jan(uid 1) — differs from UID order
        assert_eq!(msgs[0].uid, 2, "newest-by-date (Mar) first: {msgs:?}");
        assert_eq!(msgs[1].uid, 3, "middle-by-date (Feb) second: {msgs:?}");
        assert_eq!(msgs[2].uid, 1, "oldest-by-date (Jan) last: {msgs:?}");
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
    fn list_uids_asc_includes_deleted() {
        // RFC 3501: \Deleted messages keep their sequence number until EXPUNGE.
        let store = open_store();
        store.deliver("alice", "INBOX", TEST_MSG).unwrap(); // uid 1
        store.deliver("alice", "INBOX", TEST_MSG).unwrap(); // uid 2
        store.update_flags("alice", "INBOX", 1, None, None, Some(true)).unwrap();
        let uids = store.list_uids_asc("alice", "INBOX").unwrap();
        assert_eq!(uids, vec![1, 2], "\\Deleted messages must retain seq number until EXPUNGE");
    }

    // ── Attachment tests ───────────────────────────────────────────────────────

    const MIME_WITH_PDF: &[u8] = b"\
From: sender@example.com\r\n\
To: alice@cochranblock.org\r\n\
Subject: Report\r\n\
Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"boundary42\"\r\n\
\r\n\
--boundary42\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
See attached report.\r\n\
--boundary42\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQKdGVzdA==\r\n\
--boundary42--\r\n";

    #[test]
    fn store_and_list_attachments_roundtrip() {
        let store = open_store();
        let uid = store.deliver("alice", "INBOX", MIME_WITH_PDF).unwrap();
        store.store_attachments_from_raw("alice", "INBOX", uid, MIME_WITH_PDF).unwrap();

        let metas = store.list_attachments("alice", "INBOX", uid).unwrap();
        assert_eq!(metas.len(), 1, "expected 1 attachment");
        assert_eq!(metas[0].part, 1);
        assert_eq!(metas[0].filename, "report.pdf");
        assert_eq!(metas[0].content_type, "application/pdf");
    }

    #[test]
    fn get_attachment_returns_decoded_bytes() {
        let store = open_store();
        let uid = store.deliver("alice", "INBOX", MIME_WITH_PDF).unwrap();
        store.store_attachments_from_raw("alice", "INBOX", uid, MIME_WITH_PDF).unwrap();

        let bytes = store.get_attachment("alice", "INBOX", uid, 1).unwrap();
        assert!(bytes.is_some(), "attachment blob should exist");
        // base64 "%PDF-1.4\ntest" decodes to specific bytes
        assert!(bytes.unwrap().starts_with(b"%PDF"), "decoded bytes should start with PDF magic");
    }

    #[test]
    fn get_attachment_missing_part_returns_none() {
        let store = open_store();
        let uid = store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        assert!(store.get_attachment("alice", "INBOX", uid, 99).unwrap().is_none());
    }

    #[test]
    fn plain_text_message_has_no_attachments() {
        let store = open_store();
        let uid = store.deliver("alice", "INBOX", TEST_MSG).unwrap();
        store.store_attachments_from_raw("alice", "INBOX", uid, TEST_MSG).unwrap();
        let metas = store.list_attachments("alice", "INBOX", uid).unwrap();
        assert!(metas.is_empty(), "plain text message must not produce attachments");
    }

    #[test]
    fn expunge_deletes_attachment_data() {
        let store = open_store();
        let uid = store.deliver("alice", "INBOX", MIME_WITH_PDF).unwrap();
        store.store_attachments_from_raw("alice", "INBOX", uid, MIME_WITH_PDF).unwrap();
        store.update_flags("alice", "INBOX", uid, None, None, Some(true)).unwrap();
        store.expunge_deleted("alice", "INBOX").unwrap();

        assert!(store.list_attachments("alice", "INBOX", uid).unwrap().is_empty());
        assert!(store.get_attachment("alice", "INBOX", uid, 1).unwrap().is_none());
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
