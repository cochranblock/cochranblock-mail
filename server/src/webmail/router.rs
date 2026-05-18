use crate::config::Config;
use crate::store::MailStore;
use crate::webmail::{auth, mail, session::AppState};
use axum::{
    Router,
    routing::{delete, get, patch, post},
};
use std::sync::Arc;
use tower_http::{cors::CorsLayer, services::ServeDir};

pub fn build(config: Arc<Config>, store: Arc<MailStore>) -> Router {
    let state = AppState { store, config: Arc::clone(&config) };

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

    let frontend_dist = config.frontend_dist.clone();

    Router::new()
        .nest("/api", api)
        // Serve the Leptos WASM bundle and static assets.
        .nest_service("/", ServeDir::new(&frontend_dist).append_index_html_on_directories(true))
        .layer(CorsLayer::permissive())
}
