#![allow(clippy::result_large_err)]

use super::{MailStore, StoreError, USERS};
use redb::ReadableTable;
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::SaltString,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    pub email: String,
    /// argon2id PHC string.
    pub password_hash: String,
    /// Base32-encoded TOTP secret, None until user completes setup.
    pub totp_secret: Option<String>,
    pub created_at: i64,
}

impl MailStore {
    pub fn create_user(
        &self,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<UserRecord, StoreError> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                StoreError::Db(redb::Error::Io(std::io::Error::other(e.to_string())))
            })?
            .to_string();

        let record = UserRecord {
            username: username.to_string(),
            email: email.to_string(),
            password_hash: hash,
            totp_secret: None,
            created_at: chrono::Utc::now().timestamp(),
        };

        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(USERS)?;
            if table.get(username)?.is_some() {
                return Err(StoreError::AlreadyExists(username.to_string()));
            }
            let serialized = serde_json::to_string(&record)?;
            table.insert(username, serialized.as_str())?;
        }
        tx.commit()?;
        Ok(record)
    }

    pub fn get_user(&self, username: &str) -> Result<UserRecord, StoreError> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(USERS)?;
        let val = table
            .get(username)?
            .ok_or_else(|| StoreError::NotFound(username.to_string()))?;
        Ok(serde_json::from_str(val.value())?)
    }

    pub fn verify_password(&self, username: &str, password: &str) -> Result<bool, StoreError> {
        let user = match self.get_user(username) {
            Ok(u) => u,
            Err(StoreError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        let parsed = PasswordHash::new(&user.password_hash).map_err(|e| {
            StoreError::Db(redb::Error::Io(std::io::Error::other(e.to_string())))
        })?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    pub fn set_totp_secret(
        &self,
        username: &str,
        secret_base32: &str,
    ) -> Result<(), StoreError> {
        let mut user = self.get_user(username)?;
        user.totp_secret = Some(secret_base32.to_string());
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(USERS)?;
            let serialized = serde_json::to_string(&user)?;
            table.insert(username, serialized.as_str())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_users(&self) -> Result<Vec<UserRecord>, StoreError> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(USERS)?;
        let mut users = Vec::new();
        for entry in table.iter()? {
            let (_, val) = entry?;
            users.push(serde_json::from_str::<UserRecord>(val.value())?);
        }
        Ok(users)
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
    fn create_and_fetch_user() {
        let store = open_store();
        let user = store
            .create_user("alice", "alice@cochranblock.org", "hunter2")
            .unwrap();
        assert_eq!(user.username, "alice");
        assert!(user.totp_secret.is_none());

        let fetched = store.get_user("alice").unwrap();
        assert_eq!(fetched.email, "alice@cochranblock.org");
    }

    #[test]
    fn duplicate_user_errors() {
        let store = open_store();
        store.create_user("bob", "bob@cochranblock.org", "pass").unwrap();
        let result = store.create_user("bob", "bob@cochranblock.org", "pass");
        assert!(matches!(result, Err(StoreError::AlreadyExists(_))));
    }

    #[test]
    fn get_nonexistent_user_errors() {
        let store = open_store();
        let result = store.get_user("nobody");
        assert!(matches!(result, Err(StoreError::NotFound(_))));
    }

    #[test]
    fn correct_password_verifies() {
        let store = open_store();
        store.create_user("carol", "carol@cochranblock.org", "correct").unwrap();
        assert!(store.verify_password("carol", "correct").unwrap());
    }

    #[test]
    fn wrong_password_fails() {
        let store = open_store();
        store.create_user("dave", "dave@cochranblock.org", "correct").unwrap();
        assert!(!store.verify_password("dave", "wrong").unwrap());
    }

    #[test]
    fn missing_user_password_check_returns_false() {
        let store = open_store();
        assert!(!store.verify_password("ghost", "anything").unwrap());
    }

    #[test]
    fn set_and_get_totp_secret() {
        let store = open_store();
        store.create_user("eve", "eve@cochranblock.org", "pass").unwrap();
        store.set_totp_secret("eve", "JBSWY3DPEHPK3PXP").unwrap();
        let user = store.get_user("eve").unwrap();
        assert_eq!(user.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn list_users_returns_all() {
        let store = open_store();
        store.create_user("u1", "u1@c.org", "p").unwrap();
        store.create_user("u2", "u2@c.org", "p").unwrap();
        let list = store.list_users().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn password_hash_is_not_plaintext() {
        let store = open_store();
        store.create_user("frank", "f@c.org", "mysecret").unwrap();
        let user = store.get_user("frank").unwrap();
        assert!(!user.password_hash.contains("mysecret"));
        assert!(user.password_hash.starts_with("$argon2"));
    }
}
