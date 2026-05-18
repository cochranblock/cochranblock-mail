use redb::{Database, TableDefinition};
use std::path::Path;
use thiserror::Error;

// key: "mailbox/uid" → value: raw RFC 5322 message bytes (zstd-compressed)
const MESSAGES: TableDefinition<&str, &[u8]> = TableDefinition::new("messages");
// key: "mailbox" → value: JSON metadata (uidvalidity, uidnext, flags)
const MAILBOXES: TableDefinition<&str, &str> = TableDefinition::new("mailboxes");

pub struct MailStore {
    db: Database,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("redb: {0}")]
    Db(#[from] redb::Error),
    #[error("redb open: {0}")]
    Open(#[from] redb::DatabaseError),
    #[error("redb transaction: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("redb table: {0}")]
    Table(#[from] redb::TableError),
    #[error("redb commit: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("redb storage: {0}")]
    Storage(#[from] redb::StorageError),
}

impl MailStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let db = Database::create(path)?;
        // ensure tables exist
        let tx = db.begin_write()?;
        tx.open_table(MESSAGES)?;
        tx.open_table(MAILBOXES)?;
        tx.commit()?;
        Ok(Self { db })
    }

    pub fn deliver(&self, mailbox: &str, uid: u32, raw: &[u8]) -> Result<(), StoreError> {
        let key = format!("{}/{}", mailbox, uid);
        let compressed = zstd::encode_all(raw, 3).unwrap_or_else(|_| raw.to_vec());
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(MESSAGES)?;
            table.insert(key.as_str(), compressed.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn fetch(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>, StoreError> {
        let key = format!("{}/{}", mailbox, uid);
        let tx = self.db.begin_read()?;
        let table = tx.open_table(MESSAGES)?;
        match table.get(key.as_str())? {
            Some(v) => {
                let raw = zstd::decode_all(v.value()).unwrap_or_else(|_| v.value().to_vec());
                Ok(Some(raw))
            }
            None => Ok(None),
        }
    }
}
