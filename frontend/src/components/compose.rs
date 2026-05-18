use crate::api;
use leptos::prelude::*;
use shared::SendRequest;

#[component]
pub fn ComposeModal(
    #[prop(default = String::new())] initial_to: String,
    #[prop(default = String::new())] initial_subject: String,
    on_close: impl Fn() + Clone + 'static,
) -> impl IntoView {
    let to = RwSignal::new(initial_to);
    let cc = RwSignal::new(String::new());
    let subject = RwSignal::new(initial_subject);
    let body = RwSignal::new(String::new());
    let error = RwSignal::new(Option::<String>::None);
    let sending = RwSignal::new(false);

    let close = on_close.clone();
    let on_send = move |ev: web_sys::MouseEvent| {
        ev.prevent_default();
        let to_val = to.get();
        if to_val.trim().is_empty() {
            error.set(Some("Recipient (To) is required.".into()));
            return;
        }
        sending.set(true);
        error.set(None);
        let close = close.clone();

        let req = SendRequest {
            to: to_val.split(',').map(|s| s.trim().to_string()).collect(),
            cc: cc.get().split(',').filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string()).collect(),
            subject: subject.get(),
            body: body.get(),
            in_reply_to: None,
        };

        spawn_local(async move {
            match api::send_message(req).await {
                Ok(()) => close(),
                Err(e) => {
                    error.set(Some(e.to_string()));
                    sending.set(false);
                }
            }
        });
    };

    let close2 = on_close.clone();
    view! {
        <div class="compose-overlay" on:click=move |ev| {
            if ev.target() == ev.current_target() { close2(); }
        }>
            <div class="compose-window">
                <div class="compose-header">
                    "New Message"
                    <button class="compose-close" on:click=move |_| on_close()>"×"</button>
                </div>

                <div class="compose-fields">
                    <div class="compose-field">
                        <label>"To"</label>
                        <input
                            type="text"
                            placeholder="Recipients"
                            prop:value=move || to.get()
                            on:input=move |ev| to.set(event_target_value(&ev))
                        />
                    </div>
                    <div class="compose-field">
                        <label>"Cc"</label>
                        <input
                            type="text"
                            placeholder="CC"
                            prop:value=move || cc.get()
                            on:input=move |ev| cc.set(event_target_value(&ev))
                        />
                    </div>
                    <div class="compose-field">
                        <label>"Subject"</label>
                        <input
                            type="text"
                            placeholder="Subject"
                            prop:value=move || subject.get()
                            on:input=move |ev| subject.set(event_target_value(&ev))
                        />
                    </div>
                </div>

                {move || error.get().map(|e| view! {
                    <div class="error-msg" style="margin:4px 16px">{e}</div>
                })}

                <textarea
                    class="compose-body"
                    placeholder="Write your message…"
                    prop:value=move || body.get()
                    on:input=move |ev| body.set(event_target_value(&ev))
                />

                <div class="compose-footer">
                    <button
                        class="btn btn-primary"
                        on:click=on_send
                        disabled=move || sending.get()
                    >
                        {move || if sending.get() { "Sending…" } else { "Send" }}
                    </button>
                </div>
            </div>
        </div>
    }
}
