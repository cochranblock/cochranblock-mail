use crate::api;
use crate::state::AuthState;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;

#[component]
pub fn TotpSetupPage(partial_token: String) -> impl IntoView {
    let auth = expect_context::<RwSignal<AuthState>>();
    let navigate = use_navigate();

    let code = RwSignal::new(String::new());
    let error = RwSignal::new(Option::<String>::None);
    let loading = RwSignal::new(false);

    // Fetch QR code when component mounts.
    let token_for_fetch = partial_token.clone();
    let setup_data = LocalResource::new(
        move || {
            let token = token_for_fetch.clone();
            async move { api::totp_setup(&token).await }
        },
    );

    let token_for_submit = partial_token.clone();
    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        let c = code.get();
        if c.len() != 6 {
            error.set(Some("Code must be 6 digits.".into()));
            return;
        }

        // We need the new partial_token returned by the setup endpoint.
        let new_token = setup_data
            .get()
            .and_then(|r| r.ok())
            .map(|d| d.partial_token)
            .unwrap_or_default();

        if new_token.is_empty() {
            error.set(Some("Setup data not loaded. Please refresh.".into()));
            return;
        }

        loading.set(true);
        error.set(None);
        let nav = navigate.clone();

        spawn_local(async move {
            match api::totp_confirm(&new_token, &c).await {
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
        <div class="login-card totp-card">
            <div class="login-logo"><span>"CB"</span>" Mail"</div>
            <h1 class="login-title">"Set up two-factor auth"</h1>
            <p class="login-subtitle">
                "Scan the QR code with your authenticator app\n(Google Authenticator, Authy, 1Password, etc.)"
            </p>

            <Suspense fallback=|| view! { <div class="loading"><div class="spinner"></div>" Loading QR code…"</div> }>
                {move || setup_data.get().map(|result| match result {
                    Err(e) => view! {
                        <div class="error-msg">"Failed to load QR code: "{e.to_string()}</div>
                    }.into_any(),
                    Ok(data) => view! {
                        <img
                            class="totp-qr"
                            src=format!("data:image/png;base64,{}", data.qr_png_base64)
                            alt="TOTP QR code"
                        />
                        <p style="font-size:13px;color:var(--color-text-secondary)">
                            "Or enter the code manually:"
                        </p>
                        <code class="totp-secret">{data.secret_base32}</code>
                    }.into_any()
                })}
            </Suspense>

            {move || error.get().map(|e| view! {
                <div class="error-msg">{e}</div>
            })}

            <p style="font-size:13px;margin-bottom:16px">
                "After scanning, enter the 6-digit code to confirm setup:"
            </p>
            <form on:submit=on_submit>
                <div class="form-field">
                    <label>"Verification code"</label>
                    <input
                        type="text"
                        inputmode="numeric"
                        maxlength="6"
                        autocomplete="one-time-code"
                        placeholder="000000"
                        prop:value=move || code.get()
                        on:input=move |ev| code.set(event_target_value(&ev))
                    />
                </div>
                <button
                    type="submit"
                    class="btn btn-primary btn-full"
                    disabled=move || loading.get()
                >
                    {move || if loading.get() { "Confirming…" } else { "Confirm & Sign in" }}
                </button>
            </form>
        </div>
    }
}
