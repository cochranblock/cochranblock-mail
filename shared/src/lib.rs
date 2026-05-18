// Unlicense — cochranblock.org
// Contributors: GotEmCoach, Claude Sonnet 4.6

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Auth ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginResponse {
    /// Credentials valid, TOTP enrolled — need TOTP code to complete login.
    TotpRequired { partial_token: String },
    /// Credentials valid, TOTP not yet enrolled — must set up authenticator.
    TotpSetupRequired { partial_token: String },
    /// Bad credentials.
    Unauthorized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSetupResponse {
    /// Base64-encoded PNG QR code for scanning with an authenticator app.
    pub qr_png_base64: String,
    /// Human-readable base32 secret (for manual entry in authenticator).
    pub secret_base32: String,
    /// New partial token to use when calling /totp/confirm.
    pub partial_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpVerifyRequest {
    pub partial_token: String,
    pub code: String,
}

/// Returned on successful TOTP — frontend stores this in a session cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSuccess {
    pub username: String,
}

// ── Mailboxes ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxInfo {
    pub name: String,
    pub total: u64,
    pub unread: u64,
}

// ── Messages ─────────────────────────────────────────────────────────────────

/// Flags encoded as bitfield u8.
pub mod flags {
    pub const SEEN: u8 = 0x01;
    pub const STARRED: u8 = 0x02;
    pub const DELETED: u8 = 0x04;
    pub const DRAFT: u8 = 0x08;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMeta {
    pub uid: u64,
    pub mailbox: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub date: DateTime<Utc>,
    pub flags: u8,
    pub size: usize,
    pub snippet: String,
}

impl MessageMeta {
    pub fn is_seen(&self) -> bool {
        self.flags & flags::SEEN != 0
    }
    pub fn is_starred(&self) -> bool {
        self.flags & flags::STARRED != 0
    }
    pub fn is_deleted(&self) -> bool {
        self.flags & flags::DELETED != 0
    }
    pub fn is_draft(&self) -> bool {
        self.flags & flags::DRAFT != 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFull {
    pub meta: MessageMeta,
    pub body_text: String,
    pub body_html: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesPage {
    pub messages: Vec<MessageMeta>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRequest {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub body: String,
    /// If Some, this is a reply — include the original message-id in References.
    pub in_reply_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagUpdate {
    pub mailbox: String,
    pub seen: Option<bool>,
    pub starred: Option<bool>,
    pub deleted: Option<bool>,
}

// ── Generic responses ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into() }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_bitfield_roundtrip() {
        let mut f: u8 = 0;
        f |= flags::SEEN;
        f |= flags::STARRED;
        assert!(f & flags::SEEN != 0);
        assert!(f & flags::STARRED != 0);
        assert!(f & flags::DELETED == 0);
        assert!(f & flags::DRAFT == 0);
    }

    #[test]
    fn message_meta_flag_helpers() {
        let meta = MessageMeta {
            uid: 1,
            mailbox: "INBOX".into(),
            from: "alice@example.com".into(),
            to: vec!["bob@cochranblock.org".into()],
            subject: "Test".into(),
            date: Utc::now(),
            flags: flags::SEEN | flags::STARRED,
            size: 512,
            snippet: "Hello world".into(),
        };
        assert!(meta.is_seen());
        assert!(meta.is_starred());
        assert!(!meta.is_deleted());
        assert!(!meta.is_draft());
    }

    #[test]
    fn login_response_serde_totp_required() {
        let r = LoginResponse::TotpRequired { partial_token: "tok123".into() };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("totp_required"));
        let back: LoginResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn login_response_serde_setup_required() {
        let r = LoginResponse::TotpSetupRequired { partial_token: "tok456".into() };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("totp_setup_required"));
        let back: LoginResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn login_response_serde_unauthorized() {
        let r = LoginResponse::Unauthorized;
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("unauthorized"));
        let back: LoginResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn send_request_serde() {
        let req = SendRequest {
            to: vec!["alice@example.com".into()],
            cc: vec![],
            subject: "Hello".into(),
            body: "World".into(),
            in_reply_to: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SendRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to, req.to);
        assert_eq!(back.subject, req.subject);
    }

    #[test]
    fn flag_update_partial_serde() {
        let upd = FlagUpdate {
            mailbox: "INBOX".into(),
            seen: Some(true),
            starred: None,
            deleted: None,
        };
        let json = serde_json::to_string(&upd).unwrap();
        let back: FlagUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seen, Some(true));
        assert!(back.starred.is_none());
    }
}
