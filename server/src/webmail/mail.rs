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

    let in_reply_to_header = body
        .in_reply_to
        .as_ref()
        .map(|id| format!("In-Reply-To: {id}\r\nReferences: {id}\r\n"))
        .unwrap_or_default();

    let cc_header = if body.cc.is_empty() {
        String::new()
    } else {
        format!("Cc: {}\r\n", body.cc.join(", "))
    };

    let raw = format!(
        "From: {from}\r\nTo: {to}\r\n{cc_header}Subject: {subject}\r\nDate: {date}\r\n\
         Message-ID: {message_id}\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n{in_reply_to_header}\r\n{body_text}\r\n",
        to = body.to.join(", "),
        subject = body.subject,
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
