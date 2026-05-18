use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub domain: String,
    pub smtp_port: u16,
    pub smtp_submission_port: u16,
    pub imap_port: u16,
    pub http_port: u16,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub mail_dir: PathBuf,
    pub db_path: PathBuf,
    /// Frontend static assets directory (built by trunk).
    pub frontend_dist: PathBuf,
    /// Session TTL in seconds (default 86400 = 24h).
    pub session_ttl_secs: i64,
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
            http_port: env_or("HTTP_PORT", "8080").parse().unwrap_or(8080),
            tls_cert: PathBuf::from(env_or("TLS_CERT", "/etc/cochranblock-mail/cert.pem")),
            tls_key: PathBuf::from(env_or("TLS_KEY", "/etc/cochranblock-mail/key.pem")),
            mail_dir: PathBuf::from(env_or("MAIL_DIR", "/var/lib/cochranblock-mail/messages")),
            db_path: PathBuf::from(env_or("MAIL_DB", "/var/lib/cochranblock-mail/mail.redb")),
            frontend_dist: PathBuf::from(env_or("FRONTEND_DIST", "frontend/dist")),
            session_ttl_secs: env_or("SESSION_TTL_SECS", "86400").parse().unwrap_or(86400),
        })
    }
}

fn env(key: &'static str) -> Result<String, ConfigError> {
    std::env::var(key).map_err(|_| ConfigError::Missing(key))
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_or_returns_default_when_unset() {
        let key = "__CBMAIL_TEST_NONEXISTENT__";
        // SAFETY: test-only; single-threaded test isolation.
        unsafe { std::env::remove_var(key); }
        assert_eq!(env_or(key, "fallback"), "fallback");
    }

    #[test]
    fn env_or_returns_value_when_set() {
        let key = "__CBMAIL_TEST_SET__";
        // SAFETY: test-only; single-threaded test isolation.
        unsafe {
            std::env::set_var(key, "custom_value");
            assert_eq!(env_or(key, "fallback"), "custom_value");
            std::env::remove_var(key);
        }
    }

    #[test]
    fn config_missing_domain_errors() {
        // SAFETY: test-only; single-threaded test isolation.
        unsafe { std::env::remove_var("MAIL_DOMAIN"); }
        assert!(Config::from_env().is_err());
    }
}
