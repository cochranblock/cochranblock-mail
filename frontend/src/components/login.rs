use crate::api;
use crate::components::totp_setup::TotpSetupPage;
use crate::state::AuthState;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use shared::LoginResponse;

#[derive(Debug, Clone, PartialEq)]
enum LoginStep {
    Credentials,
    TotpVerify { partial_token: String },
    TotpSetup { partial_token: String },
}

#[component]
pub fn LoginPage() -> impl IntoView {
    let auth = expect_context::<RwSignal<AuthState>>();
    let navigate = use_navigate();

    let step = RwSignal::new(LoginStep::Credentials);
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let totp_code = RwSignal::new(String::new());
    let error = RwSignal::new(Option::<String>::None);
    let loading = RwSignal::new(false);

    let nav = navigate.clone();
    let on_submit_credentials = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        let u = username.get();
        let p = password.get();
        if u.is_empty() || p.is_empty() {
            error.set(Some("Username and password are required.".into()));
            return;
        }
        loading.set(true);
        error.set(None);

        let nav = nav.clone();
        spawn_local(async move {
            match api::login(&u, &p).await {
                Err(e) => {
                    error.set(Some(e.to_string()));
                    loading.set(false);
                }
                Ok(LoginResponse::Unauthorized) => {
                    error.set(Some("Invalid username or password.".into()));
                    loading.set(false);
                }
                Ok(LoginResponse::TotpRequired { partial_token }) => {
                    step.set(LoginStep::TotpVerify { partial_token });
                    loading.set(false);
                }
                Ok(LoginResponse::TotpSetupRequired { partial_token }) => {
                    step.set(LoginStep::TotpSetup { partial_token });
                    loading.set(false);
                }
            }
        });
    };

    let nav2 = navigate.clone();
    let on_submit_totp = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        let code = totp_code.get();
        if code.len() != 6 {
            error.set(Some("TOTP code must be 6 digits.".into()));
            return;
        }
        let LoginStep::TotpVerify { partial_token } = step.get() else { return };
        loading.set(true);
        error.set(None);

        let nav = nav2.clone();
        spawn_local(async move {
            match api::totp_verify(&partial_token, &code).await {
                Ok(success) => {
                    auth.set(AuthState::LoggedIn(success.username));
                    nav("/mail/INBOX", Default::default());
                }
                Err(e) => {
                    error.set(Some(e.to_string()));
                    loading.set(false);
                }
            }
        });
    };

    view! {
        <div class="login-page">
            {move || match step.get() {
                LoginStep::Credentials => view! {
                    <div class="login-card">
                        <div class="login-logo">
                            <span>"CB"</span>" Mail"
                        </div>
                        <h1 class="login-title">"Sign in"</h1>
                        <p class="login-subtitle">"to your cochranblock.org account"</p>

                        {move || error.get().map(|e| view! {
                            <div class="error-msg">{e}</div>
                        })}

                        <form on:submit=on_submit_credentials>
                            <div class="form-field">
                                <label>"Username"</label>
                                <input
                                    type="text"
                                    autocomplete="username"
                                    placeholder="you"
                                    prop:value=move || username.get()
                                    on:input=move |ev| username.set(event_target_value(&ev))
                                />
                            </div>
                            <div class="form-field">
                                <label>"Password"</label>
                                <input
                                    type="password"
                                    autocomplete="current-password"
                                    prop:value=move || password.get()
                                    on:input=move |ev| password.set(event_target_value(&ev))
                                />
                            </div>
                            <button
                                type="submit"
                                class="btn btn-primary btn-full"
                                disabled=move || loading.get()
                            >
                                {move || if loading.get() { "Signing in…" } else { "Next" }}
                            </button>
                        </form>
                    </div>
                }.into_any(),

                LoginStep::TotpVerify { .. } => view! {
                    <div class="login-card">
                        <div class="login-logo"><span>"CB"</span>" Mail"</div>
                        <h1 class="login-title">"Two-factor auth"</h1>
                        <p class="login-subtitle">"Enter the 6-digit code from your authenticator app."</p>

                        {move || error.get().map(|e| view! {
                            <div class="error-msg">{e}</div>
                        })}

                        <form on:submit=on_submit_totp>
                            <div class="form-field">
                                <label>"Code"</label>
                                <input
                                    type="text"
                                    inputmode="numeric"
                                    maxlength="6"
                                    autocomplete="one-time-code"
                                    placeholder="000000"
                                    prop:value=move || totp_code.get()
                                    on:input=move |ev| totp_code.set(event_target_value(&ev))
                                />
                            </div>
                            <button
                                type="submit"
                                class="btn btn-primary btn-full"
                                disabled=move || loading.get()
                            >
                                {move || if loading.get() { "Verifying…" } else { "Verify" }}
                            </button>
                        </form>
                    </div>
                }.into_any(),

                LoginStep::TotpSetup { partial_token } => view! {
                    <TotpSetupPage
                        partial_token=partial_token
                    />
                }.into_any(),
            }}
        </div>
    }
}
