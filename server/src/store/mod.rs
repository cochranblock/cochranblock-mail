#![allow(clippy::result_large_err)]

mod error;
pub mod messages;
pub mod sessions;
pub mod users;

pub use error::StoreError;

use redb::{Database, TableDefinition};
use std::path::Path;
use std::sync::Arc;

// ── Table definitions ─────────────────────────────────────────────────────────

/// Raw RFC 5322 message bytes (zstd-compressed). key = "username/mailbox/uid_hex".
pub(crate) const MESSAGES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("messages");

/// JSON-encoded MessageMeta. key = "username/mailbox/uid_hex".
pub(crate) const MESSAGE_META: TableDefinition<&str, &str> =
    TableDefinition::new("message_meta");

/// JSON-encoded MailboxState. key = "username/mailboxname".
pub(crate) const MAILBOXES: TableDefinition<&str, &str> =
    TableDefinition::new("mailboxes");

/// JSON-encoded UserRecord. key = username.
pub(crate) const USERS: TableDefinition<&str, &str> =
    TableDefinition::new("users");

/// JSON-encoded SessionRecord. key = session token (UUID).
pub(crate) const SESSIONS: TableDefinition<&str, &str> =
    TableDefinition::new("sessions");

/// JSON-encoded SessionRecord for partial (post-password, pre-TOTP) sessions.
pub(crate) const PARTIAL_SESSIONS: TableDefinition<&str, &str> =
    TableDefinition::new("partial_sessions");

/// Ephemeral key-value scratch space (pending TOTP secrets, etc.). key = arbitrary string.
pub(crate) const SCRATCH: TableDefinition<&str, &str> = TableDefinition::new("scratch");

// ── MailStore ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct MailStore {
    pub(crate) db: Arc<Database>,
    pub(crate) totp_key: Option<[u8; 32]>,
}

impl MailStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(path)?;
        {
            let tx = db.begin_write()?;
            tx.open_table(MESSAGES)?;
            tx.open_table(MESSAGE_META)?;
            tx.open_table(MAILBOXES)?;
            tx.open_table(USERS)?;
            tx.open_table(SESSIONS)?;
            tx.open_table(PARTIAL_SESSIONS)?;
            tx.open_table(SCRATCH)?;
            tx.commit()?;
        }
        Ok(Self { db: Arc::new(db), totp_key: None })
    }

    /// Enable at-rest encryption for TOTP secrets. Call this before any secrets
    /// are written; existing plaintext secrets remain readable as a fallback.
    pub fn with_encryption(mut self, key: [u8; 32]) -> Self {
        self.totp_key = Some(key);
        self
    }

    // ── Scratch helpers (ephemeral key-value) ─────────────────────────────────

    pub fn set_pending_totp_secret(&self, key: &str, secret: &str) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        { let mut t = tx.open_table(SCRATCH)?; t.insert(key, secret)?; }
        tx.commit()?;
        Ok(())
    }

    pub fn get_pending_totp_secret(&self, key: &str) -> Result<Option<String>, StoreError> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(SCRATCH)?;
        Ok(t.get(key)?.map(|v| v.value().to_string()))
    }

    pub fn delete_pending_totp_secret(&self, key: &str) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        { let mut t = tx.open_table(SCRATCH)?; t.remove(key)?; }
        tx.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub fn open_temp() -> Result<Self, StoreError> {
        let dir = tempfile::tempdir().map_err(|e| StoreError::Io(e))?;
        let path = dir.path().join("test.redb");
        // We intentionally leak the TempDir so the db file lives for the test.
        std::mem::forget(dir);
        Self::open(&path)
    }
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

    #[test]
    fn scratch_set_and_get_roundtrip() {
        let store = open_store();
        store.set_pending_totp_secret("__pending_totp__/tok123", "JBSWY3DPEHPK3PXP").unwrap();
        let got = store.get_pending_totp_secret("__pending_totp__/tok123").unwrap();
        assert_eq!(got.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn scratch_delete_removes_entry() {
        let store = open_store();
        store.set_pending_totp_secret("__pending_totp__/tokdel", "VALUE").unwrap();
        store.delete_pending_totp_secret("__pending_totp__/tokdel").unwrap();
        assert!(store.get_pending_totp_secret("__pending_totp__/tokdel").unwrap().is_none());
    }

    #[test]
    fn scratch_get_nonexistent_returns_none() {
        let store = open_store();
        assert!(store.get_pending_totp_secret("key_that_was_never_set").unwrap().is_none());
    }
}
