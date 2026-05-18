use gloo_net::http::Request;
use shared::*;

const BASE: &str = "/api";

#[derive(Debug, Clone)]
pub enum ApiError {
    Network(String),
    Server(ApiError_),
    Parse(String),
}

// Avoid name collision with shared::ApiError
type ApiError_ = shared::ApiError;

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Network(e) => write!(f, "Network error: {e}"),
            ApiError::Server(e) => write!(f, "{}", e.message),
            ApiError::Parse(e) => write!(f, "Parse error: {e}"),
        }
    }
}

impl From<gloo_net::Error> for ApiError {
    fn from(e: gloo_net::Error) -> Self {
        ApiError::Network(e.to_string())
    }
}

// ── Auth ─────────────────────────────────────────────────────────────────────

pub async fn login(username: &str, password: &str) -> Result<LoginResponse, ApiError> {
    let resp = Request::post(&format!("{BASE}/auth/login"))
        .json(&LoginRequest { username: username.into(), password: password.into() })
        .map_err(|e| ApiError::Parse(e.to_string()))?
        .send()
        .await?;
    resp.json::<LoginResponse>().await.map_err(|e| ApiError::Parse(e.to_string()))
}

pub async fn totp_setup(partial_token: &str) -> Result<TotpSetupResponse, ApiError> {
    let resp = Request::get(&format!("{BASE}/auth/totp/setup?partial_token={partial_token}"))
        .send()
        .await?;
    if resp.ok() {
        resp.json::<TotpSetupResponse>().await.map_err(|e| ApiError::Parse(e.to_string()))
    } else {
        let err = resp.json::<ApiError_>().await.map_err(|e| ApiError::Parse(e.to_string()))?;
        Err(ApiError::Server(err))
    }
}

pub async fn totp_confirm(partial_token: &str, code: &str) -> Result<AuthSuccess, ApiError> {
    let resp = Request::post(&format!("{BASE}/auth/totp/confirm"))
        .json(&TotpVerifyRequest { partial_token: partial_token.into(), code: code.into() })
        .map_err(|e| ApiError::Parse(e.to_string()))?
        .send()
        .await?;
    if resp.ok() {
        resp.json::<AuthSuccess>().await.map_err(|e| ApiError::Parse(e.to_string()))
    } else {
        let err = resp.json::<ApiError_>().await.map_err(|e| ApiError::Parse(e.to_string()))?;
        Err(ApiError::Server(err))
    }
}

pub async fn totp_verify(partial_token: &str, code: &str) -> Result<AuthSuccess, ApiError> {
    let resp = Request::post(&format!("{BASE}/auth/totp/verify"))
        .json(&TotpVerifyRequest { partial_token: partial_token.into(), code: code.into() })
        .map_err(|e| ApiError::Parse(e.to_string()))?
        .send()
        .await?;
    if resp.ok() {
        resp.json::<AuthSuccess>().await.map_err(|e| ApiError::Parse(e.to_string()))
    } else {
        let err = resp.json::<ApiError_>().await.map_err(|e| ApiError::Parse(e.to_string()))?;
        Err(ApiError::Server(err))
    }
}

pub async fn logout() -> Result<(), ApiError> {
    Request::delete(&format!("{BASE}/auth/session")).send().await?;
    Ok(())
}

// ── Mail ─────────────────────────────────────────────────────────────────────

pub async fn list_mailboxes() -> Result<Vec<MailboxInfo>, ApiError> {
    let resp = Request::get(&format!("{BASE}/mailboxes")).send().await?;
    resp.json().await.map_err(|e| ApiError::Parse(e.to_string()))
}

pub async fn list_messages(mailbox: &str, page: u32) -> Result<MessagesPage, ApiError> {
    let resp = Request::get(&format!("{BASE}/messages?mailbox={mailbox}&page={page}"))
        .send()
        .await?;
    resp.json().await.map_err(|e| ApiError::Parse(e.to_string()))
}

pub async fn get_message(mailbox: &str, uid: u64) -> Result<MessageFull, ApiError> {
    let resp = Request::get(&format!("{BASE}/messages/{uid}?mailbox={mailbox}"))
        .send()
        .await?;
    if resp.ok() {
        resp.json().await.map_err(|e| ApiError::Parse(e.to_string()))
    } else {
        let err = resp.json::<ApiError_>().await.map_err(|e| ApiError::Parse(e.to_string()))?;
        Err(ApiError::Server(err))
    }
}

pub async fn send_message(req: SendRequest) -> Result<(), ApiError> {
    let resp = Request::post(&format!("{BASE}/messages"))
        .json(&req)
        .map_err(|e| ApiError::Parse(e.to_string()))?
        .send()
        .await?;
    if resp.ok() { Ok(()) } else {
        let err = resp.json::<ApiError_>().await.map_err(|e| ApiError::Parse(e.to_string()))?;
        Err(ApiError::Server(err))
    }
}

pub async fn update_flags(uid: u64, update: FlagUpdate) -> Result<(), ApiError> {
    let resp = Request::patch(&format!("{BASE}/messages/{uid}"))
        .json(&update)
        .map_err(|e| ApiError::Parse(e.to_string()))?
        .send()
        .await?;
    if resp.ok() { Ok(()) } else {
        let err = resp.json::<ApiError_>().await.map_err(|e| ApiError::Parse(e.to_string()))?;
        Err(ApiError::Server(err))
    }
}
