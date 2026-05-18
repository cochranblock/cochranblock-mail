#![allow(clippy::result_large_err)]

use super::{MailStore, StoreError, PARTIAL_SESSIONS, SESSIONS};
use redb::ReadableTable;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub token: String,
    pub username: String,
    pub expires_at: i64,
}

/// A partial session exists after password-check passes but before TOTP is verified.
/// It encodes which auth step comes next.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSessionRecord {
    pub token: String,
    pub username: String,
    /// True if this is the very first TOTP setup (user must enroll).
    pub needs_setup: bool,
    pub expires_at: i64,
}

impl MailStore {
    // ── Full sessions ─────────────────────────────────────────────────────────

    pub fn create_session(
        &self,
        username: &str,
        ttl_secs: i64,
    ) -> Result<SessionRecord, StoreError> {
        let token = Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now().timestamp() + ttl_secs;
        let record = SessionRecord { token: token.clone(), username: username.to_string(), expires_at };
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(SESSIONS)?;
            let serialized = serde_json::to_string(&record)?;
            table.insert(token.as_str(), serialized.as_str())?;
        }
        tx.commit()?;
        Ok(record)
    }

    pub fn get_session(&self, token: &str) -> Result<Option<SessionRecord>, StoreError> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(SESSIONS)?;
        match table.get(token)? {
            None => Ok(None),
            Some(val) => {
                let rec: SessionRecord = serde_json::from_str(val.value())?;
                if rec.expires_at < chrono::Utc::now().timestamp() {
                    Ok(None) // expired — treat as missing; reaper handles cleanup
                } else {
                    Ok(Some(rec))
                }
            }
        }
    }

    pub fn delete_session(&self, token: &str) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(SESSIONS)?;
            table.remove(token)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delete_all_sessions_for(&self, username: &str) -> Result<usize, StoreError> {
        let tx = self.db.begin_write()?;
        let mut to_delete: Vec<String> = Vec::new();
        {
            let table = tx.open_table(SESSIONS)?;
            for entry in table.iter()? {
                let (key, val) = entry?;
                let rec: SessionRecord = serde_json::from_str(val.value())?;
                if rec.username == username {
                    to_delete.push(key.value().to_string());
                }
            }
        }
        let count = to_delete.len();
        {
            let mut table = tx.open_table(SESSIONS)?;
            for token in &to_delete {
                table.remove(token.as_str())?;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    // ── Partial sessions ──────────────────────────────────────────────────────

    pub fn create_partial_session(
        &self,
        username: &str,
        needs_setup: bool,
    ) -> Result<PartialSessionRecord, StoreError> {
        let token = Uuid::new_v4().to_string();
        // Partial sessions are short-lived: 5 minutes to complete TOTP.
        let expires_at = chrono::Utc::now().timestamp() + 300;
        let record = PartialSessionRecord {
            token: token.clone(),
            username: username.to_string(),
            needs_setup,
            expires_at,
        };
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(PARTIAL_SESSIONS)?;
            let serialized = serde_json::to_string(&record)?;
            table.insert(token.as_str(), serialized.as_str())?;
        }
        tx.commit()?;
        Ok(record)
    }

    pub fn consume_partial_session(
        &self,
        token: &str,
    ) -> Result<Option<PartialSessionRecord>, StoreError> {
        let tx = self.db.begin_write()?;
        // Open once as mutable; read into owned value then delete in the same handle.
        let mut table = tx.open_table(PARTIAL_SESSIONS)?;
        let record: Option<PartialSessionRecord> = match table.get(token)? {
            None => None,
            Some(guard) => {
                let rec: PartialSessionRecord = serde_json::from_str(guard.value())?;
                drop(guard); // release borrow before mutating
                if rec.expires_at < chrono::Utc::now().timestamp() {
                    None
                } else {
                    Some(rec)
                }
            }
        };
        if record.is_some() {
            table.remove(token)?;
        }
        drop(table);
        tx.commit()?;
        Ok(record)
    }

    // ── Expired session cleanup ───────────────────────────────────────────────

    pub fn prune_expired_sessions(&self) -> Result<usize, StoreError> {
        let now = chrono::Utc::now().timestamp();
        let tx = self.db.begin_write()?;
        let expired: Vec<String> = {
            let table = tx.open_table(SESSIONS)?;
            let mut v = Vec::new();
            for entry in table.iter()? {
                let (key, val) = entry?;
                let rec: SessionRecord = serde_json::from_str(val.value())?;
                if rec.expires_at < now {
                    v.push(key.value().to_string());
                }
            }
            v
        };
        let count = expired.len();
        if count > 0 {
            let mut table = tx.open_table(SESSIONS)?;
            for token in &expired {
                table.remove(token.as_str())?;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn prune_expired_partial_sessions(&self) -> Result<usize, StoreError> {
        let now = chrono::Utc::now().timestamp();
        let tx = self.db.begin_write()?;
        let expired: Vec<String> = {
            let table = tx.open_table(PARTIAL_SESSIONS)?;
            let mut v = Vec::new();
            for entry in table.iter()? {
                let (key, val) = entry?;
                let rec: PartialSessionRecord = serde_json::from_str(val.value())?;
                if rec.expires_at < now {
                    v.push(key.value().to_string());
                }
            }
            v
        };
        let count = expired.len();
        if count > 0 {
            let mut table = tx.open_table(PARTIAL_SESSIONS)?;
            for token in &expired {
                table.remove(token.as_str())?;
            }
        }
        tx.commit()?;
        Ok(count)
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
    fn create_and_fetch_session() {
        let store = open_store();
        let sess = store.create_session("alice", 3600).unwrap();
        assert!(!sess.token.is_empty());
        let fetched = store.get_session(&sess.token).unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().username, "alice");
    }

    #[test]
    fn session_not_found_returns_none() {
        let store = open_store();
        let result = store.get_session("nonexistent-token").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_session_removes_it() {
        let store = open_store();
        let sess = store.create_session("bob", 3600).unwrap();
        store.delete_session(&sess.token).unwrap();
        assert!(store.get_session(&sess.token).unwrap().is_none());
    }

    #[test]
    fn expired_session_returns_none() {
        let store = open_store();
        // TTL of -1 means it expires immediately (in the past).
        let sess = store.create_session("carol", -1).unwrap();
        assert!(store.get_session(&sess.token).unwrap().is_none());
    }

    #[test]
    fn delete_all_sessions_for_user() {
        let store = open_store();
        store.create_session("dave", 3600).unwrap();
        store.create_session("dave", 3600).unwrap();
        store.create_session("eve", 3600).unwrap();
        let count = store.delete_all_sessions_for("dave").unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn partial_session_is_single_use() {
        let store = open_store();
        let partial = store.create_partial_session("frank", false).unwrap();
        let first = store.consume_partial_session(&partial.token).unwrap();
        assert!(first.is_some());
        // Second consume must return None — already consumed.
        let second = store.consume_partial_session(&partial.token).unwrap();
        assert!(second.is_none());
    }

    #[test]
    fn partial_session_needs_setup_flag_preserved() {
        let store = open_store();
        let partial = store.create_partial_session("grace", true).unwrap();
        let consumed = store.consume_partial_session(&partial.token).unwrap().unwrap();
        assert!(consumed.needs_setup);
    }

    #[test]
    fn session_tokens_are_unique() {
        let store = open_store();
        let s1 = store.create_session("harry", 3600).unwrap();
        let s2 = store.create_session("harry", 3600).unwrap();
        assert_ne!(s1.token, s2.token);
    }
}
