use crate::webmail::session::{AppState, AuthUser};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use mailparse::parse_mail;
use serde::Deserialize;
use shared::{ApiError, FlagUpdate, MailboxInfo, MessageFull, MessagesPage, SendRequest};

// ── GET /api/mailboxes ────────────────────────────────────────────────────────

pub async fn list_mailboxes(
    State(state): State<AppState>,
    user: AuthUser,
) -> impl IntoResponse {
    match state.store.list_mailboxes(&user.username) {
        Ok(mboxes) => {
            let infos: Vec<MailboxInfo> = mboxes
                .into_iter()
                .map(|(name, state)| MailboxInfo {
                    name,
                    total: state.message_count,
                    unread: state.unread_count,
                })
                .collect();
            (StatusCode::OK, Json(infos)).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new("store_error", "failed to list mailboxes")),
        )
            .into_response(),
    }
}

// ── GET /api/messages?mailbox=INBOX&page=0 ────────────────────────────────────

#[derive(Deserialize)]
pub struct ListParams {
    pub mailbox: Option<String>,
    pub page: Option<u32>,
}

pub async fn list_messages(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<ListParams>,
) -> impl IntoResponse {
    let mailbox = params.mailbox.as_deref().unwrap_or("INBOX");
    let page = params.page.unwrap_or(0);

    match state.store.list_messages(&user.username, mailbox, page) {
        Ok((messages, total)) => {
            let resp = MessagesPage {
                messages,
                total,
                page,
                page_size: crate::store::messages::PAGE_SIZE,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new("store_error", "failed to list messages")),
        )
            .into_response(),
    }
}

// ── GET /api/messages/:uid?mailbox=INBOX ──────────────────────────────────────

#[derive(Deserialize)]
pub struct GetMessageParams {
    pub mailbox: Option<String>,
}

pub async fn get_message(
    State(state): State<AppState>,
    user: AuthUser,
    Path(uid_str): Path<String>,
    Query(params): Query<GetMessageParams>,
) -> impl IntoResponse {
    let uid: u64 = match uid_str.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("bad_uid", "uid must be a u64")),
            )
                .into_response();
        }
    };
    let mailbox = params.mailbox.as_deref().unwrap_or("INBOX");

    let meta = match state.store.fetch_meta(&user.username, mailbox, uid) {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiError::new("not_found", "message not found")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("store_error", "failed to fetch metadata")),
            )
                .into_response();
        }
    };

    let raw = match state.store.fetch_raw(&user.username, mailbox, uid) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiError::new("not_found", "message body not found")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("store_error", "failed to fetch raw message")),
            )
                .into_response();
        }
    };

    let (body_text, body_html) = extract_bodies(&raw);

    // Mark as read on open.
    state
        .store
        .update_flags(&user.username, mailbox, uid, Some(true), None, None)
        .ok();

    let full = MessageFull { meta, body_text, body_html };
    (StatusCode::OK, Json(full)).into_response()
}

// ── POST /api/messages ────────────────────────────────────────────────────────

pub async fn send_message(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<SendRequest>,
) -> impl IntoResponse {
    if body.to.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("missing_to", "at least one recipient required")),
        )
            .into_response();
    }

    let domain = &state.config.domain;
    let from = format!("{}@{}", user.username, domain);
    let date = chrono::Utc::now().to_rfc2822();
    let message_id = format!("<{}@{}>", uuid::Uuid::new_v4(), domain);

    // Sanitize all user-controlled header fields against CRLF injection.
    let subject = sanitize_header(&body.subject);
    let to_addrs = body.to.iter().map(|a| sanitize_header(a)).collect::<Vec<_>>().join(", ");
    let in_reply_to_header = body
        .in_reply_to
        .as_ref()
        .map(|id| {
            let id = sanitize_header(id);
            format!("In-Reply-To: {id}\r\nReferences: {id}\r\n")
        })
        .unwrap_or_default();

    let cc_header = if body.cc.is_empty() {
        String::new()
    } else {
        let cc = body.cc.iter().map(|a| sanitize_header(a)).collect::<Vec<_>>().join(", ");
        format!("Cc: {cc}\r\n")
    };

    let raw = format!(
        "From: {from}\r\nTo: {to_addrs}\r\n{cc_header}Subject: {subject}\r\nDate: {date}\r\n\
         Message-ID: {message_id}\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n{in_reply_to_header}\r\n{body_text}\r\n",
        body_text = body.body,
    );

    // Deliver a copy to Sent.
    if state.store.deliver(&user.username, "Sent", raw.as_bytes()).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new("store_error", "failed to save sent message")),
        )
            .into_response();
    }

    // Deliver to local recipients on the same domain.
    for addr in &body.to {
        let addr_lower = addr.to_ascii_lowercase();
        if addr_lower.ends_with(&format!("@{domain}")) {
            let local = addr_lower.split('@').next().unwrap_or("").to_string();
            if !local.is_empty() {
                state.store.deliver(&local, "INBOX", raw.as_bytes()).ok();
            }
        }
    }

    (StatusCode::OK, Json(serde_json::json!({"ok": true, "message_id": message_id}))).into_response()
}

// ── PATCH /api/messages/:uid ──────────────────────────────────────────────────

pub async fn update_flags(
    State(state): State<AppState>,
    user: AuthUser,
    Path(uid_str): Path<String>,
    Json(body): Json<FlagUpdate>,
) -> impl IntoResponse {
    let uid: u64 = match uid_str.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("bad_uid", "uid must be a u64")),
            )
                .into_response();
        }
    };

    match state.store.update_flags(
        &user.username,
        &body.mailbox,
        uid,
        body.seen,
        body.starred,
        body.deleted,
    ) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(crate::store::StoreError::NotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(ApiError::new("not_found", "message not found")),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new("store_error", "failed to update flags")),
        )
            .into_response(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Strip CR and LF from a value destined for an RFC 5322 header field,
/// preventing header-injection attacks.
fn sanitize_header(value: &str) -> String {
    value.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

// ── Body extraction helpers ───────────────────────────────────────────────────

fn extract_bodies(raw: &[u8]) -> (String, Option<String>) {
    match parse_mail(raw) {
        Err(_) => (String::from_utf8_lossy(raw).into_owned(), None),
        Ok(msg) => {
            let text = find_body_part(&msg, "text/plain");
            let html = find_body_part(&msg, "text/html");
            (text.unwrap_or_default(), html)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::MailStore;
    use crate::webmail::{auth, rate_limit::RateLimiter, session::{AppState, SESSION_COOKIE}};
    use axum::{Router, routing};
    use axum_test::TestServer;
    use shared::{
        FlagUpdate, LoginRequest, LoginResponse, MailboxInfo, MessageFull, MessagesPage,
        SendRequest, TotpSetupResponse, TotpVerifyRequest,
    };
    use std::{path::PathBuf, sync::Arc};

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            domain: "cochranblock.test".to_string(),
            smtp_port: 0,
            smtp_submission_port: 0,
            imap_port: 0,
            http_port: 0,
            tls_cert: PathBuf::from("/tmp"),
            tls_key: PathBuf::from("/tmp"),
            mail_dir: PathBuf::from("/tmp"),
            db_path: PathBuf::from("/tmp/test.redb"),
            frontend_dist: PathBuf::from("/tmp"),
            session_ttl_secs: 86400,
            secure_cookies: false,
            totp_encryption_key: None,
        })
    }

    fn build_server() -> (TestServer, Arc<MailStore>) {
        let store = Arc::new(MailStore::open_temp().unwrap());
        let config = test_config();
        let rate_limiter = Arc::new(RateLimiter::new(5, 300, 900));
        let state = AppState { store: Arc::clone(&store), config, rate_limiter };
        let app = Router::new()
            .route("/api/auth/login", routing::post(auth::login))
            .route("/api/auth/totp/setup", routing::get(auth::totp_setup))
            .route("/api/auth/totp/confirm", routing::post(auth::totp_confirm))
            .route("/api/auth/totp/verify", routing::post(auth::totp_verify))
            .route("/api/auth/session", routing::delete(auth::logout))
            .route("/api/mailboxes", routing::get(list_mailboxes))
            .route("/api/messages", routing::get(list_messages))
            .route("/api/messages", routing::post(send_message))
            .route("/api/messages/{uid}", routing::get(get_message))
            .route("/api/messages/{uid}", routing::patch(update_flags))
            .with_state(state);
        (TestServer::new(app), store)
    }

    fn session_token_from_response(resp: &axum_test::TestResponse) -> Option<String> {
        resp.iter_headers_by_name("set-cookie").find_map(|v| {
            let s = v.to_str().ok()?;
            let pair = s.split(';').next()?;
            let (k, v) = pair.split_once('=')?;
            (k.trim() == SESSION_COOKIE).then(|| v.to_string())
        })
    }

    async fn enroll(server: &TestServer, store: &MailStore, username: &str) -> String {
        store.create_user(username, &format!("{username}@t.test"), "testpass").unwrap();
        store.ensure_standard_mailboxes(username).unwrap();

        let partial_token = match server
            .post("/api/auth/login")
            .json(&LoginRequest { username: username.to_string(), password: "testpass".to_string() })
            .await
            .json::<LoginResponse>()
        {
            LoginResponse::TotpSetupRequired { partial_token } => partial_token,
            other => panic!("{other:?}"),
        };

        let setup: TotpSetupResponse = server
            .get(&format!("/api/auth/totp/setup?partial_token={partial_token}"))
            .await
            .json();

        let code = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6, 1, 30,
            totp_rs::Secret::Encoded(setup.secret_base32).to_bytes().unwrap(),
            Some("cochranblock.test".to_string()),
            format!("{username}@cochranblock.test"),
        )
        .unwrap()
        .generate_current()
        .unwrap();

        let resp = server
            .post("/api/auth/totp/confirm")
            .json(&TotpVerifyRequest { partial_token: setup.partial_token, code })
            .await;
        session_token_from_response(&resp).expect("no session after enrollment")
    }

    const TEST_MSG: &[u8] = b"From: sender@example.com\r\n\
To: user@cochranblock.test\r\n\
Subject: Hello world\r\n\
Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Message body here.\r\n";

    // ── mailboxes ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mailboxes_requires_auth() {
        let (server, _) = build_server();
        server.get("/api/mailboxes").await.assert_status_unauthorized();
    }

    #[tokio::test]
    async fn list_mailboxes_returns_standard_boxes() {
        let (server, store) = build_server();
        let token = enroll(&server, &store, "alice").await;
        let boxes: Vec<MailboxInfo> = server
            .get("/api/mailboxes")
            .add_header("cookie", format!("{SESSION_COOKIE}={token}"))
            .await
            .json();
        let names: Vec<&str> = boxes.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"INBOX"), "INBOX missing: {names:?}");
        assert!(names.contains(&"Sent"), "Sent missing: {names:?}");
        assert!(names.contains(&"Trash"), "Trash missing: {names:?}");
    }

    // ── messages ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_messages_empty_inbox() {
        let (server, store) = build_server();
        let token = enroll(&server, &store, "bob").await;
        let page: MessagesPage = server
            .get("/api/messages?mailbox=INBOX")
            .add_header("cookie", format!("{SESSION_COOKIE}={token}"))
            .await
            .json();
        assert_eq!(page.total, 0);
        assert!(page.messages.is_empty());
    }

    #[tokio::test]
    async fn delivered_message_appears_in_inbox() {
        let (server, store) = build_server();
        let token = enroll(&server, &store, "carol").await;
        store.deliver("carol", "INBOX", TEST_MSG).unwrap();

        let page: MessagesPage = server
            .get("/api/messages?mailbox=INBOX")
            .add_header("cookie", format!("{SESSION_COOKIE}={token}"))
            .await
            .json();
        assert_eq!(page.total, 1);
        assert_eq!(page.messages[0].subject, "Hello world");
    }

    #[tokio::test]
    async fn get_nonexistent_message_is_404() {
        let (server, store) = build_server();
        let token = enroll(&server, &store, "dave").await;
        server
            .get("/api/messages/99999?mailbox=INBOX")
            .add_header("cookie", format!("{SESSION_COOKIE}={token}"))
            .await
            .assert_status_not_found();
    }

    #[tokio::test]
    async fn get_message_auto_marks_as_read() {
        let (server, store) = build_server();
        let token = enroll(&server, &store, "eve").await;
        let uid = store.deliver("eve", "INBOX", TEST_MSG).unwrap();

        // Fetching the message triggers the seen side-effect.
        server
            .get(&format!("/api/messages/{uid}?mailbox=INBOX"))
            .add_header("cookie", format!("{SESSION_COOKIE}={token}"))
            .await
            .assert_status_ok();

        // Verify via store — the handler returns pre-update meta but must persist the flag.
        let meta = store.fetch_meta("eve", "INBOX", uid).unwrap().unwrap();
        assert!(meta.is_seen(), "GET /messages/:uid must persist SEEN flag in store");
    }

    #[tokio::test]
    async fn send_message_saves_copy_in_sent() {
        let (server, store) = build_server();
        let token = enroll(&server, &store, "frank").await;

        server
            .post("/api/messages")
            .add_header("cookie", format!("{SESSION_COOKIE}={token}"))
            .json(&SendRequest {
                to: vec!["nobody@external.example".to_string()],
                cc: vec![],
                subject: "Send test".to_string(),
                body: "Body text.".to_string(),
                in_reply_to: None,
            })
            .await
            .assert_status_ok();

        let (msgs, total) = store.list_messages("frank", "Sent", 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(msgs[0].subject, "Send test");
    }

    #[tokio::test]
    async fn send_to_local_user_delivers_to_their_inbox() {
        let (server, store) = build_server();
        let sender_token = enroll(&server, &store, "grace").await;
        // Create recipient without going through enrollment (store-direct).
        store.create_user("harry", "harry@cochranblock.test", "pass").unwrap();
        store.ensure_standard_mailboxes("harry").unwrap();

        server
            .post("/api/messages")
            .add_header("cookie", format!("{SESSION_COOKIE}={sender_token}"))
            .json(&SendRequest {
                to: vec!["harry@cochranblock.test".to_string()],
                cc: vec![],
                subject: "Local delivery".to_string(),
                body: "Hi Harry".to_string(),
                in_reply_to: None,
            })
            .await
            .assert_status_ok();

        let (msgs, total) = store.list_messages("harry", "INBOX", 0).unwrap();
        assert_eq!(total, 1, "local recipient should receive a copy");
        assert_eq!(msgs[0].subject, "Local delivery");
    }

    #[tokio::test]
    async fn update_flags_marks_starred_and_persists() {
        let (server, store) = build_server();
        let token = enroll(&server, &store, "iris").await;
        let uid = store.deliver("iris", "INBOX", TEST_MSG).unwrap();

        server
            .patch(&format!("/api/messages/{uid}"))
            .add_header("cookie", format!("{SESSION_COOKIE}={token}"))
            .json(&FlagUpdate { mailbox: "INBOX".to_string(), seen: None, starred: Some(true), deleted: None })
            .await
            .assert_status_ok();

        let meta = store.fetch_meta("iris", "INBOX", uid).unwrap().unwrap();
        assert!(meta.is_starred(), "STARRED flag should be set after PATCH");
    }
}

fn find_body_part(msg: &mailparse::ParsedMail, mime: &str) -> Option<String> {
    if msg.ctype.mimetype.eq_ignore_ascii_case(mime) {
        return msg.get_body().ok();
    }
    for sub in &msg.subparts {
        if let Some(found) = find_body_part(sub, mime) {
            return Some(found);
        }
    }
    None
}
