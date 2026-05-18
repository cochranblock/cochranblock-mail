use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("redb database error: {0}")]
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
    #[error("codec: {0}")]
    Codec(#[from] postcard::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
}
