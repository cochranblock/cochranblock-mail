use crate::api;
use crate::components::compose::ComposeModal;
use leptos::prelude::*;
use shared::{AttachmentMeta, FlagUpdate, MessageFull, SendRequest};

fn format_full_date(date: &chrono::DateTime<chrono::Utc>) -> String {
    date.format("%a, %b %d, %Y, %I:%M %p").to_string()
}

fn sender_initial(from: &str) -> char {
    from.chars().find(|c| c.is_alphabetic()).unwrap_or('?').to_ascii_uppercase()
}

fn format_size(bytes: u32) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn attachment_icon(content_type: &str) -> &'static str {
    let ct = content_type.to_ascii_lowercase();
    if ct.starts_with("image/") { "🖼" }
    else if ct == "application/pdf" { "📄" }
    else if ct.starts_with("video/") { "🎞" }
    else if ct.starts_with("audio/") { "🎵" }
    else if ct.contains("zip") || ct.contains("gzip") || ct.contains("tar") { "🗜" }
    else { "📎" }
}

#[component]
pub fn MessageView(
    mailbox: Signal<String>,
    uid: Signal<u64>,
) -> impl IntoView {
    let reply_open = RwSignal::new(false);
    let reply_data = RwSignal::new(Option::<(String, String)>::None); // (to, subject)

    let msg_res = LocalResource::new(
        move || {
            let mbox = mailbox.get();
            let uid = uid.get();
            async move { api::get_message(&mbox, uid).await }
        },
    );

    view! {
        <div class="message-view">
            <Suspense fallback=|| view! {
                <div class="loading"><div class="spinner"></div>" Loading message…"</div>
            }>
                {move || msg_res.get().map(|result| match result {
                    Err(e) => view! {
                        <div class="empty-state">"Error loading message: "{e.to_string()}</div>
                    }.into_any(),
                    Ok(msg) => {
                        let initial = sender_initial(&msg.meta.from);
                        let date_str = format_full_date(&msg.meta.date);
                        let from = msg.meta.from.clone();
                        let subject = msg.meta.subject.clone();
                        let to = msg.meta.to.join(", ");
                        let has_html = msg.body_html.is_some();
                        let attachments = msg.attachments.clone();
                        let uid_val = msg.meta.uid;
                        let mailbox_val = msg.meta.mailbox.clone();

                        let from_for_reply = msg.meta.from.clone();
                        let subject_for_reply = msg.meta.subject.clone();

                        view! {
                            <h1 class="message-view-subject">{msg.meta.subject.clone()}</h1>

                            <div class="message-view-meta">
                                <div class="avatar" style="font-size:16px">{initial.to_string()}</div>
                                <div>
                                    <div class="message-view-from">{from.clone()}</div>
                                    <div class="message-view-to">"to "{to}</div>
                                </div>
                                <div class="message-view-date">{date_str}</div>
                            </div>

                            {if has_html {
                                let html = msg.body_html.unwrap_or_default();
                                view! {
                                    // Sandbox the HTML to prevent script execution.
                                    <iframe
                                        class="message-body-html"
                                        sandbox="allow-same-origin"
                                        srcdoc=html
                                    />
                                }.into_any()
                            } else {
                                view! {
                                    <div class="message-body">{msg.body_text.clone()}</div>
                                }.into_any()
                            }}

                            {if !attachments.is_empty() {
                                let items = attachments.into_iter().map(|att| {
                                    let url = format!(
                                        "/api/messages/{uid_val}/attachment/{}?mailbox={mailbox_val}",
                                        att.part
                                    );
                                    let icon = attachment_icon(&att.content_type);
                                    let label = format!("{} {} ({})", icon, att.filename, format_size(att.size));
                                    view! {
                                        <a
                                            class="attachment-link"
                                            href=url
                                            download=att.filename.clone()
                                        >
                                            {label}
                                        </a>
                                    }
                                }).collect::<Vec<_>>();
                                view! {
                                    <div class="attachments">
                                        <div class="attachments-label">"Attachments"</div>
                                        {items}
                                    </div>
                                }.into_any()
                            } else {
                                view! { <span /> }.into_any()
                            }}

                            <div class="reply-actions">
                                <button
                                    class="btn btn-outlined"
                                    on:click=move |_| {
                                        reply_data.set(Some((
                                            from_for_reply.clone(),
                                            format!("Re: {}", subject_for_reply),
                                        )));
                                        reply_open.set(true);
                                    }
                                >"↩ Reply"</button>
                                <button
                                    class="btn btn-outlined"
                                    on:click=move |_| {
                                        reply_data.set(Some((
                                            String::new(),
                                            format!("Fwd: {}", subject),
                                        )));
                                        reply_open.set(true);
                                    }
                                >"→ Forward"</button>
                            </div>

                            {move || reply_open.get().then(|| {
                                let (to, subj) = reply_data.get().unwrap_or_default();
                                view! {
                                    <ComposeModal
                                        initial_to=to
                                        initial_subject=subj
                                        on_close=move || reply_open.set(false)
                                    />
                                }
                            })}
                        }.into_any()
                    }
                })}
            </Suspense>
        </div>
    }
}
