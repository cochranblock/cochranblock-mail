use crate::store::MailStore;
use crate::webmail::{auth, mail, rate_limit::RateLimiter, session::AppState};
#[cfg(feature = "tests")]
use crate::webmail::session::SESSION_COOKIE;
use axum::{
    Router,
    extract::Request,
    http::{StatusCode, header, HeaderValue},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

async fn hsts(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    res.headers_mut().insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
    );
    res
}

pub fn build(config: Arc<crate::config::Config>, store: Arc<MailStore>) -> Router {
    let rate_limiter = Arc::new(RateLimiter::new(5, 300, 900));
    let state = AppState { store, config: Arc::clone(&config), rate_limiter };

    let api = Router::new()
        // Auth
        .route("/auth/login", post(auth::login))
        .route("/auth/totp/setup", get(auth::totp_setup))
        .route("/auth/totp/confirm", post(auth::totp_confirm))
        .route("/auth/totp/verify", post(auth::totp_verify))
        .route("/auth/session", delete(auth::logout))
        // Mail
        .route("/mailboxes", get(mail::list_mailboxes))
        .route("/messages", get(mail::list_messages))
        .route("/messages", post(mail::send_message))
        .route("/messages/{uid}", get(mail::get_message))
        .route("/messages/{uid}", patch(mail::update_flags))
        .with_state(state);

    let app = Router::new()
        .nest("/api", api)
        .fallback(serve_asset)
        .layer(middleware::from_fn(hsts))
        .layer(CorsLayer::permissive());

    #[cfg(feature = "tests")]
    let app = app.route("/test/inject-session", get(inject_session));

    app
}

/// Test-only: sets the session cookie then redirects to the SPA inbox.
/// Allows headless chromium to screenshot the webmail as an authenticated user.
#[cfg(feature = "tests")]
async fn inject_session(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let token = params.get("token").cloned().unwrap_or_default();
    let redirect = params.get("redirect").cloned().unwrap_or_else(|| "/".to_string());
    let mut headers = axum::http::HeaderMap::new();
    if let Ok(v) = axum::http::HeaderValue::from_str(
        &format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly")
    ) {
        headers.insert(axum::http::header::SET_COOKIE, v);
    }
    if let Ok(v) = axum::http::HeaderValue::try_from(redirect) {
        headers.insert(axum::http::header::LOCATION, v);
    }
    (StatusCode::FOUND, headers)
}

async fn serve_asset(uri: axum::http::Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match crate::assets::Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [(header::CONTENT_TYPE, mime.as_ref().to_owned())],
                content.data,
            )
                .into_response()
        }
        None => {
            // SPA fallback: serve index.html for client-side routing
            match crate::assets::Assets::get("index.html") {
                Some(content) => (
                    [(header::CONTENT_TYPE, "text/html".to_owned())],
                    content.data,
                )
                    .into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
    }
}
