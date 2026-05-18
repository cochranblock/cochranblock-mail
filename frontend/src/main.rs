mod api;
mod components;
mod state;

use leptos::prelude::*;
use leptos_router::{
    components::{Router, Route, Routes},
    path,
};
use components::{login::LoginPage, mail::MailShell};
use state::AuthState;

fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    // Global auth state: None = loading, Some(None) = logged out, Some(Some(u)) = logged in.
    let auth = RwSignal::new(AuthState::Loading);

    provide_context(auth);

    view! {
        <Router>
            <Routes fallback=|| view! { <p class="loading">"Page not found."</p> }>
                <Route path=path!("/login") view=LoginPage />
                <Route path=path!("/mail/:mailbox") view=MailShell />
                <Route path=path!("/mail/:mailbox/:uid") view=MailShell />
                <Route path=path!("/") view=RootRedirect />
            </Routes>
        </Router>
    }
}

#[component]
fn RootRedirect() -> impl IntoView {
    use leptos_router::hooks::use_navigate;
    let navigate = use_navigate();
    Effect::new(move |_| {
        navigate("/mail/INBOX", Default::default());
    });
    view! { <div class="loading"><div class="spinner"></div>" Loading..."</div> }
}
