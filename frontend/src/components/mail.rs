use crate::api;
use crate::components::{
    compose::ComposeModal, message_list::MessageList, message_view::MessageView, sidebar::Sidebar,
};
use crate::state::AuthState;
use leptos::prelude::*;
use leptos_router::{
    hooks::{use_navigate, use_params_map},
};

#[component]
pub fn MailShell() -> impl IntoView {
    let auth = expect_context::<RwSignal<AuthState>>();
    let navigate = use_navigate();
    let params = use_params_map();

    // Redirect to login if not authenticated.
    // On mount: check if the session cookie is valid by requesting mailboxes.
    let auth_check = Resource::new(
        move || auth.get(),
        move |state| async move {
            match state {
                AuthState::Loading => {
                    // Try to fetch mailboxes; if it fails with 401 we're not logged in.
                    match api::list_mailboxes().await {
                        Ok(_) => Some("ok".to_string()),
                        Err(_) => None,
                    }
                }
                AuthState::LoggedIn(_) => Some("ok".to_string()),
                AuthState::LoggedOut => None,
            }
        },
    );

    let mailbox = Signal::derive(move || {
        params.with(|p| p.get("mailbox").unwrap_or_else(|| "INBOX".into()))
    });

    let uid = Signal::derive(move || {
        params.with(|p| p.get("uid").and_then(|s| s.parse::<u64>().ok()))
    });

    let selected_uid = RwSignal::new(Option::<u64>::None);
    let compose_open = RwSignal::new(false);

    // Sync URL uid param to selected_uid.
    Effect::new(move |_| {
        selected_uid.set(uid.get());
    });

    let nav_for_redirect = navigate.clone();
    Effect::new(move |_| {
        if let Some(None) = auth_check.get() {
            auth.set(AuthState::LoggedOut);
            nav_for_redirect("/login", Default::default());
        }
    });

    // Derive username from auth state for avatar display.
    let username_initial = move || {
        auth.get()
            .username()
            .and_then(|u| u.chars().next())
            .unwrap_or('?')
            .to_ascii_uppercase()
            .to_string()
    };

    let nav_logout = navigate.clone();
    let on_logout = move |_| {
        let nav = nav_logout.clone();
        spawn_local(async move {
            api::logout().await.ok();
            auth.set(AuthState::LoggedOut);
            nav("/login", Default::default());
        });
    };

    view! {
        <div class="app-shell">
            // ── Top bar ───────────────────────────────────────────────────────
            <header class="topbar">
                <div class="topbar-logo">
                    <span>"CB"</span>" Mail"
                </div>
                <div class="topbar-search">
                    <span>"🔍"</span>
                    <input type="search" placeholder="Search mail" />
                </div>
                <div class="topbar-right">
                    <div
                        class="avatar"
                        title="Sign out"
                        on:click=on_logout
                        style="cursor:pointer"
                    >
                        {username_initial}
                    </div>
                </div>
            </header>

            // ── Sidebar ───────────────────────────────────────────────────────
            <Sidebar
                active_mailbox=mailbox
                compose_open=compose_open
            />

            // ── Main content area ────────────────────────────────────────────
            <main style="overflow:hidden;display:flex;flex-direction:column">
                {move || match uid.get() {
                    None => view! {
                        <MessageList
                            mailbox=mailbox
                            selected_uid=selected_uid
                        />
                    }.into_any(),
                    Some(uid_val) => view! {
                        <MessageView
                            mailbox=mailbox
                            uid=Signal::derive(move || uid_val)
                        />
                    }.into_any(),
                }}
            </main>

            // ── Compose modal ─────────────────────────────────────────────────
            {move || compose_open.get().then(|| view! {
                <ComposeModal on_close=move || compose_open.set(false) />
            })}
        </div>
    }
}
