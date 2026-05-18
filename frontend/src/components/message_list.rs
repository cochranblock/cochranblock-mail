use crate::api;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_navigate;
use shared::{FlagUpdate, MessageMeta, flags};

fn format_date(date: &chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let diff = now.signed_duration_since(*date);
    if diff.num_days() == 0 {
        date.format("%H:%M").to_string()
    } else if diff.num_days() < 365 {
        date.format("%b %d").to_string()
    } else {
        date.format("%Y").to_string()
    }
}

fn sender_display(from: &str) -> &str {
    // "Alice Smith <alice@example.com>" → "Alice Smith"
    // "alice@example.com" → "alice@example.com"
    if let Some(name_end) = from.find('<') {
        let name = from[..name_end].trim();
        if !name.is_empty() { return name; }
    }
    from.trim()
}

#[component]
pub fn MessageList(
    mailbox: Signal<String>,
    selected_uid: RwSignal<Option<u64>>,
) -> impl IntoView {
    let page = RwSignal::new(0u32);
    let navigate = use_navigate();

    let messages_res = LocalResource::new(
        move || {
            let mbox = mailbox.get();
            let p = page.get();
            async move { api::list_messages(&mbox, p).await }
        },
    );

    view! {
        <div class="message-pane">
            <div class="message-list-header">
                <span style="font-size:14px;font-weight:500;color:var(--color-text-secondary)">
                    {move || mailbox.get()}
                </span>
            </div>

            <div class="message-list">
                <Suspense fallback=|| view! {
                    <div class="loading"><div class="spinner"></div>" Loading messages…"</div>
                }>
                    {move || messages_res.get().map(|result| match result {
                        Err(_) => view! {
                            <div class="empty-state">"Failed to load messages."</div>
                        }.into_any(),
                        Ok(page_data) if page_data.messages.is_empty() => view! {
                            <div class="empty-state">
                                <span style="font-size:48px">"📭"</span>
                                <span>"No messages"</span>
                            </div>
                        }.into_any(),
                        Ok(page_data) => {
                            let mbox = mailbox.get();
                            view! {
                                <div>
                                    {page_data.messages.into_iter().map(|msg| {
                                        let uid = msg.uid;
                                        let is_selected = move || selected_uid.get() == Some(uid);
                                        let mbox_for_nav = mbox.clone();
                                        let nav = navigate.clone();
                                        let mbox_for_star = mbox.clone();

                                        let on_click = move |_| {
                                            selected_uid.set(Some(uid));
                                            nav(&format!("/mail/{}/{}", mbox_for_nav, uid), Default::default());
                                        };

                                        let is_unread = msg.flags & flags::SEEN == 0;
                                        let is_starred = msg.flags & flags::STARRED != 0;
                                        let sender = sender_display(&msg.from).to_string();
                                        let date_str = format_date(&msg.date);
                                        let subject = msg.subject.clone();
                                        let snippet = msg.snippet.clone();
                                        let mbox_star = mbox_for_star.clone();

                                        let on_star = move |ev: web_sys::MouseEvent| {
                                            ev.stop_propagation();
                                            let new_starred = !is_starred;
                                            let mbox_s = mbox_star.clone();
                                            spawn_local(async move {
                                                api::update_flags(uid, FlagUpdate {
                                                    mailbox: mbox_s,
                                                    seen: None,
                                                    starred: Some(new_starred),
                                                    deleted: None,
                                                }).await.ok();
                                            });
                                        };

                                        view! {
                                            <div
                                                class=move || format!(
                                                    "message-row {} {}",
                                                    if is_unread { "unread" } else { "read" },
                                                    if is_selected() { "selected" } else { "" }
                                                )
                                                on:click=on_click
                                            >
                                                <button
                                                    class=move || format!("msg-star{}", if is_starred { " starred" } else { "" })
                                                    on:click=on_star
                                                    title="Star"
                                                >
                                                    {if is_starred { "★" } else { "☆" }}
                                                </button>
                                                <span class="msg-sender">{sender}</span>
                                                <span class="msg-subject-snippet">
                                                    {subject}
                                                    <span class="msg-snippet">{snippet}</span>
                                                </span>
                                                <span class="msg-date">{date_str}</span>
                                            </div>
                                        }
                                    }).collect::<Vec<_>>()}
                                </div>
                            }.into_any()
                        }
                    })}
                </Suspense>
            </div>

            // Pagination
            {move || messages_res.get().and_then(|r| r.ok()).map(|data| {
                let total_pages = data.total.div_ceil(data.page_size as u64) as u32;
                view! {
                    <div class="pagination">
                        <span>
                            {data.page * data.page_size + 1}
                            "-"
                            {std::cmp::min((data.page + 1) * data.page_size, data.total as u32)}
                            " of "
                            {data.total}
                        </span>
                        <button
                            disabled=move || page.get() == 0
                            on:click=move |_| page.update(|p| *p = p.saturating_sub(1))
                        >"‹"</button>
                        <button
                            disabled=move || page.get() + 1 >= total_pages
                            on:click=move |_| page.update(|p| *p += 1)
                        >"›"</button>
                    </div>
                }
            })}
        </div>
    }
}
