use crate::webmail::session::{AppState, AuthUser, SESSION_COOKIE};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use shared::{
    ApiError, AuthSuccess, LoginRequest, LoginResponse, TotpSetupResponse, TotpVerifyRequest,
};
use totp_rs::{Algorithm, Secret, TOTP};

// ── TOTP helpers ──────────────────────────────────────────────────────────────

fn build_totp(username: &str, secret_base32: &str, domain: &str) -> Result<TOTP, String> {
    let secret = Secret::Encoded(secret_base32.to_string());
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|e| e.to_string())?,
        Some(domain.to_string()),
        format!("{username}@{domain}"),
    )
    .map_err(|e| e.to_string())
}

fn generate_totp_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

// ── POST /api/auth/login ──────────────────────────────────────────────────────

pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    let store = &state.store;

    let ok = match store.verify_password(&body.username, &body.password) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse::Unauthorized),
            )
                .into_response();
        }
    };

    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(LoginResponse::Unauthorized)).into_response();
    }

    let user = match store.get_user(&body.username) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse::Unauthorized),
            )
                .into_response();
        }
    };

    let needs_setup = user.totp_secret.is_none();
    let partial = match store.create_partial_session(&body.username, needs_setup) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse::Unauthorized),
            )
                .into_response();
        }
    };

    let resp = if needs_setup {
        LoginResponse::TotpSetupRequired { partial_token: partial.token }
    } else {
        LoginResponse::TotpRequired { partial_token: partial.token }
    };

    (StatusCode::OK, Json(resp)).into_response()
}

// ── GET /api/auth/totp/setup ──────────────────────────────────────────────────

pub async fn totp_setup(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let partial_token = match params.get("partial_token") {
        Some(t) => t.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("missing_token", "partial_token query param required")),
            )
                .into_response();
        }
    };

    let partial = match state.store.consume_partial_session(&partial_token) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new("invalid_token", "partial session expired or invalid")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("store_error", "internal error")),
            )
                .into_response();
        }
    };

    if !partial.needs_setup {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("already_enrolled", "TOTP already set up for this account")),
        )
            .into_response();
    }

    let secret_base32 = generate_totp_secret();
    let domain = &state.config.domain;

    let totp = match build_totp(&partial.username, &secret_base32, domain) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("totp_error", e)),
            )
                .into_response();
        }
    };

    let qr_base64 = match totp.get_qr_base64() {
        Ok(q) => q,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("qr_error", e.to_string())),
            )
                .into_response();
        }
    };

    // Issue a fresh partial session tagged with the pending secret so the
    // confirm endpoint can retrieve it without storing secrets in the URL.
    // We abuse the partial_token->username mapping and stash the secret in
    // a second key: "setup:<token>".
    let new_partial = match state.store.create_partial_session(&partial.username, true) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("store_error", "internal error")),
            )
                .into_response();
        }
    };

    // Stash the pending TOTP secret keyed off the new partial token so confirm
    // can look it up.  We use the USERS table via a separate temp key pattern.
    // Simpler approach: encode secret in a second partial session value.
    // We extend the PartialSessionRecord concept by re-using create_partial_session
    // but also writing the secret into a well-known key in USERS table.
    // Actually cleanest: store the secret directly in the partial session.
    // Let's encode it as username+"__pending_secret__" in a dedicated store call.
    let pending_key = format!("__pending_totp__/{}", new_partial.token);
    if state.store.set_pending_totp_secret(&pending_key, &secret_base32).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new("store_error", "internal error")),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(TotpSetupResponse {
            qr_png_base64: qr_base64,
            secret_base32,
            partial_token: new_partial.token,
        }),
    )
        .into_response()
}

// ── POST /api/auth/totp/confirm ───────────────────────────────────────────────

pub async fn totp_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<TotpVerifyRequest>,
) -> impl IntoResponse {
    let partial = match state.store.consume_partial_session(&body.partial_token) {
        Ok(Some(p)) if p.needs_setup => p,
        Ok(Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("wrong_flow", "use /totp/verify for existing enrollment")),
            )
                .into_response();
        }
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new("invalid_token", "partial session expired or invalid")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("store_error", "internal error")),
            )
                .into_response();
        }
    };

    let pending_key = format!("__pending_totp__/{}", body.partial_token);
    let secret_base32 = match state.store.get_pending_totp_secret(&pending_key) {
        Ok(Some(s)) => s,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new("invalid_token", "pending TOTP secret not found")),
            )
                .into_response();
        }
    };
    state.store.delete_pending_totp_secret(&pending_key).ok();

    let totp = match build_totp(&partial.username, &secret_base32, &state.config.domain) {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("totp_error", "failed to build TOTP")),
            )
                .into_response();
        }
    };

    let valid = totp.check_current(&body.code).unwrap_or(false);
    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError::new("invalid_code", "TOTP code is incorrect")),
        )
            .into_response();
    }

    // Enroll the secret permanently.
    if state.store.set_totp_secret(&partial.username, &secret_base32).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new("store_error", "failed to save TOTP secret")),
        )
            .into_response();
    }

    // Ensure standard mailboxes exist for new user.
    state.store.ensure_standard_mailboxes(&partial.username).ok();

    issue_session(&state, &partial.username, jar).await
}

// ── POST /api/auth/totp/verify ────────────────────────────────────────────────

pub async fn totp_verify(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<TotpVerifyRequest>,
) -> impl IntoResponse {
    let partial = match state.store.consume_partial_session(&body.partial_token) {
        Ok(Some(p)) if !p.needs_setup => p,
        Ok(Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("wrong_flow", "use /totp/confirm to enroll TOTP first")),
            )
                .into_response();
        }
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError::new("invalid_token", "partial session expired or invalid")),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("store_error", "internal error")),
            )
                .into_response();
        }
    };

    let user = match state.store.get_user(&partial.username) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("store_error", "user not found")),
            )
                .into_response();
        }
    };

    let secret = match &user.totp_secret {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError::new("not_enrolled", "TOTP not set up for this account")),
            )
                .into_response();
        }
    };

    let totp = match build_totp(&partial.username, &secret, &state.config.domain) {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("totp_error", "failed to build TOTP")),
            )
                .into_response();
        }
    };

    let valid = totp.check_current(&body.code).unwrap_or(false);
    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError::new("invalid_code", "TOTP code is incorrect")),
        )
            .into_response();
    }

    issue_session(&state, &partial.username, jar).await
}

// ── DELETE /api/auth/session ──────────────────────────────────────────────────

pub async fn logout(
    State(state): State<AppState>,
    _user: AuthUser,
    jar: CookieJar,
) -> impl IntoResponse {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        state.store.delete_session(cookie.value()).ok();
    }
    let removed = jar.remove(Cookie::from(SESSION_COOKIE));
    (StatusCode::OK, removed, Json(serde_json::json!({"ok": true})))
}

// ── Shared: issue full session cookie ─────────────────────────────────────────

async fn issue_session(
    state: &AppState,
    username: &str,
    jar: CookieJar,
) -> axum::response::Response {
    let sess = match state.store.create_session(username, state.config.session_ttl_secs) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError::new("store_error", "failed to create session")),
            )
                .into_response();
        }
    };

    let cookie = Cookie::build((SESSION_COOKIE, sess.token))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .build();

    let updated_jar = jar.add(cookie);
    (
        StatusCode::OK,
        updated_jar,
        Json(AuthSuccess { username: username.to_string() }),
    )
        .into_response()
}
