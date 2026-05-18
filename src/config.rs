use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub domain: String,
    pub smtp_port: u16,
    pub smtp_submission_port: u16,
    pub imap_port: u16,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub mail_dir: PathBuf,
    pub db_path: PathBuf,
    pub admin_user: String,
    pub admin_pass_hash: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    Missing(&'static str),
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            domain: env("MAIL_DOMAIN")?,
            smtp_port: env_or("SMTP_PORT", "25").parse().unwrap_or(25),
            smtp_submission_port: env_or("SMTP_SUBMISSION_PORT", "587").parse().unwrap_or(587),
            imap_port: env_or("IMAP_PORT", "993").parse().unwrap_or(993),
            tls_cert: PathBuf::from(env_or("TLS_CERT", "/etc/cochranblock-mail/cert.pem")),
            tls_key: PathBuf::from(env_or("TLS_KEY", "/etc/cochranblock-mail/key.pem")),
            mail_dir: PathBuf::from(env_or("MAIL_DIR", "/var/lib/cochranblock-mail/messages")),
            db_path: PathBuf::from(env_or("MAIL_DB", "/var/lib/cochranblock-mail/mail.redb")),
            admin_user: env("MAIL_ADMIN_USER")?,
            admin_pass_hash: env("MAIL_ADMIN_PASS_HASH")?,
        })
    }
}

fn env(key: &'static str) -> Result<String, ConfigError> {
    std::env::var(key).map_err(|_| ConfigError::Missing(key))
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
