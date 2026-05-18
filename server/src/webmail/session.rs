use crate::config::Config;
use crate::store::MailStore;
use crate::webmail::rate_limit::RateLimiter;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
};
use axum_extra::extract::CookieJar;
use std::sync::Arc;

pub const SESSION_COOKIE: &str = "cbmail_session";

/// Authenticated identity extracted from a valid session cookie.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub username: String,
}

/// Axum extractor: pulls `AuthUser` from the session cookie.
/// Returns 401 if cookie is missing or session is invalid/expired.
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    Arc<MailStore>: FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = <Arc<MailStore>>::from_ref(state);
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_string())
            .ok_or((StatusCode::UNAUTHORIZED, "missing session cookie"))?;

        match store.get_session(&token) {
            Ok(Some(sess)) => Ok(AuthUser { username: sess.username }),
            Ok(None) => Err((StatusCode::UNAUTHORIZED, "session expired or invalid")),
            Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "store error")),
        }
    }
}

/// App state passed to all handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<MailStore>,
    pub config: Arc<Config>,
    pub rate_limiter: Arc<RateLimiter>,
}

impl FromRef<AppState> for Arc<MailStore> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.store)
    }
}

impl FromRef<AppState> for Arc<Config> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.config)
    }
}
