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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::MailStore;
    use crate::webmail::{mail, session::AppState};
    use axum::{Router, routing};
    use axum_test::TestServer;
    use shared::{LoginRequest, LoginResponse, TotpSetupResponse, TotpVerifyRequest};
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
        })
    }

    fn build_server() -> (TestServer, Arc<MailStore>) {
        let store = Arc::new(MailStore::open_temp().unwrap());
        let config = test_config();
        let state = AppState { store: Arc::clone(&store), config };
        let app = Router::new()
            .route("/api/auth/login", routing::post(login))
            .route("/api/auth/totp/setup", routing::get(totp_setup))
            .route("/api/auth/totp/confirm", routing::post(totp_confirm))
            .route("/api/auth/totp/verify", routing::post(totp_verify))
            .route("/api/auth/session", routing::delete(logout))
            .route("/api/mailboxes", routing::get(mail::list_mailboxes))
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

    /// Drive the full enrollment flow for a freshly created user; returns the session token.
    async fn enroll(server: &TestServer, store: &MailStore, username: &str) -> String {
        store.create_user(username, &format!("{username}@t.test"), "testpass").unwrap();

        let partial_token = match server
            .post("/api/auth/login")
            .json(&LoginRequest { username: username.to_string(), password: "testpass".to_string() })
            .await
            .json::<LoginResponse>()
        {
            LoginResponse::TotpSetupRequired { partial_token } => partial_token,
            other => panic!("expected TotpSetupRequired, got {other:?}"),
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

        let confirm = server
            .post("/api/auth/totp/confirm")
            .json(&TotpVerifyRequest { partial_token: setup.partial_token, code })
            .await;
        confirm.assert_status_ok();
        session_token_from_response(&confirm).expect("session cookie not set after enrollment")
    }

    // ── login ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn login_wrong_password_is_401() {
        let (server, store) = build_server();
        store.create_user("alice", "alice@t.test", "correct").unwrap();
        server
            .post("/api/auth/login")
            .json(&LoginRequest { username: "alice".into(), password: "wrong".into() })
            .await
            .assert_status_unauthorized();
    }

    #[tokio::test]
    async fn login_unknown_user_is_401() {
        let (server, _store) = build_server();
        server
            .post("/api/auth/login")
            .json(&LoginRequest { username: "ghost".into(), password: "pass".into() })
            .await
            .assert_status_unauthorized();
    }

    #[tokio::test]
    async fn login_new_user_returns_totp_setup_required() {
        let (server, store) = build_server();
        store.create_user("bob", "bob@t.test", "pass").unwrap();
        let resp = server
            .post("/api/auth/login")
            .json(&LoginRequest { username: "bob".into(), password: "pass".into() })
            .await;
        resp.assert_status_ok();
        assert!(matches!(resp.json::<LoginResponse>(), LoginResponse::TotpSetupRequired { .. }));
    }

    #[tokio::test]
    async fn login_enrolled_user_returns_totp_required() {
        let (server, store) = build_server();
        store.create_user("carol", "carol@t.test", "pass").unwrap();
        store.set_totp_secret("carol", "JBSWY3DPEHPK3PXP").unwrap();
        let resp = server
            .post("/api/auth/login")
            .json(&LoginRequest { username: "carol".into(), password: "pass".into() })
            .await;
        resp.assert_status_ok();
        assert!(matches!(resp.json::<LoginResponse>(), LoginResponse::TotpRequired { .. }));
    }

    // ── totp/setup ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn totp_setup_rejects_bogus_partial_token() {
        let (server, _) = build_server();
        server
            .get("/api/auth/totp/setup?partial_token=not_real")
            .await
            .assert_status_unauthorized();
    }

    #[tokio::test]
    async fn totp_setup_partial_token_is_single_use() {
        let (server, store) = build_server();
        store.create_user("dave", "dave@t.test", "pass").unwrap();
        let partial_token = match server
            .post("/api/auth/login")
            .json(&LoginRequest { username: "dave".into(), password: "pass".into() })
            .await
            .json::<LoginResponse>()
        {
            LoginResponse::TotpSetupRequired { partial_token } => partial_token,
            other => panic!("{other:?}"),
        };
        // First call consumes the partial token.
        server
            .get(&format!("/api/auth/totp/setup?partial_token={partial_token}"))
            .await
            .assert_status_ok();
        // Second call with the same token must fail.
        server
            .get(&format!("/api/auth/totp/setup?partial_token={partial_token}"))
            .await
            .assert_status_unauthorized();
    }

    // ── totp/confirm ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn totp_confirm_wrong_code_is_401() {
        let (server, store) = build_server();
        store.create_user("eve", "eve@t.test", "pass").unwrap();
        let partial_token = match server
            .post("/api/auth/login")
            .json(&LoginRequest { username: "eve".into(), password: "pass".into() })
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
        server
            .post("/api/auth/totp/confirm")
            .json(&TotpVerifyRequest { partial_token: setup.partial_token, code: "000000".into() })
            .await
            .assert_status_unauthorized();
    }

    #[tokio::test]
    async fn full_enrollment_issues_session_cookie() {
        let (server, store) = build_server();
        let token = enroll(&server, &store, "frank").await;
        assert!(!token.is_empty());
    }

    // ── totp/verify ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn totp_verify_valid_code_issues_session() {
        let (server, store) = build_server();
        store.create_user("grace", "grace@t.test", "pass").unwrap();
        let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"; // 32 chars = 20 bytes for SHA1
        store.set_totp_secret("grace", secret).unwrap();

        let partial_token = match server
            .post("/api/auth/login")
            .json(&LoginRequest { username: "grace".into(), password: "pass".into() })
            .await
            .json::<LoginResponse>()
        {
            LoginResponse::TotpRequired { partial_token } => partial_token,
            other => panic!("{other:?}"),
        };

        let code = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6, 1, 30,
            totp_rs::Secret::Encoded(secret.to_string()).to_bytes().unwrap(),
            Some("cochranblock.test".to_string()),
            "grace@cochranblock.test".to_string(),
        )
        .expect("TOTP construction")
        .generate_current()
        .unwrap();

        let resp = server
            .post("/api/auth/totp/verify")
            .json(&TotpVerifyRequest { partial_token, code })
            .await;
        resp.assert_status_ok();
        assert!(session_token_from_response(&resp).is_some(), "no session cookie after verify");
    }

    #[tokio::test]
    async fn totp_verify_wrong_code_is_401() {
        let (server, store) = build_server();
        store.create_user("henry", "henry@t.test", "pass").unwrap();
        store.set_totp_secret("henry", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();

        let partial_token = match server
            .post("/api/auth/login")
            .json(&LoginRequest { username: "henry".into(), password: "pass".into() })
            .await
            .json::<LoginResponse>()
        {
            LoginResponse::TotpRequired { partial_token } => partial_token,
            other => panic!("{other:?}"),
        };
        server
            .post("/api/auth/totp/verify")
            .json(&TotpVerifyRequest { partial_token, code: "000000".into() })
            .await
            .assert_status_unauthorized();
    }

    // ── session / logout ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn protected_route_without_cookie_is_401() {
        let (server, _) = build_server();
        server.get("/api/mailboxes").await.assert_status_unauthorized();
    }

    #[tokio::test]
    async fn logout_invalidates_session() {
        let (server, store) = build_server();
        let token = enroll(&server, &store, "iris").await;
        let cookie_hdr = format!("{SESSION_COOKIE}={token}");

        // Session works before logout.
        server
            .get("/api/mailboxes")
            .add_header("cookie", cookie_hdr.clone())
            .await
            .assert_status_ok();

        // Logout.
        server
            .delete("/api/auth/session")
            .add_header("cookie", cookie_hdr.clone())
            .await
            .assert_status_ok();

        // Same token must now be rejected.
        server
            .get("/api/mailboxes")
            .add_header("cookie", cookie_hdr)
            .await
            .assert_status_unauthorized();
    }
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
