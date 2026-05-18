use crate::api;
use crate::components::compose::ComposeModal;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use shared::MailboxInfo;

static MAILBOX_ICONS: &[(&str, &str)] = &[
    ("INBOX", "📥"),
    ("Sent", "📤"),
    ("Drafts", "📝"),
    ("Spam", "⚠️"),
    ("Trash", "🗑️"),
];

fn icon_for(name: &str) -> &'static str {
    MAILBOX_ICONS.iter().find(|(n, _)| *n == name).map(|(_, i)| *i).unwrap_or("📁")
}

#[component]
pub fn Sidebar(
    active_mailbox: Signal<String>,
    compose_open: RwSignal<bool>,
) -> impl IntoView {
    let mailboxes = Resource::new(
        || (),
        |_| async { api::list_mailboxes().await.unwrap_or_default() },
    );

    view! {
        <nav class="sidebar">
            <button class="compose-btn" on:click=move |_| compose_open.set(true)>
                <span style="font-size:18px">"✏️"</span>
                "Compose"
            </button>

            <Suspense fallback=|| view! { <div style="padding:16px;font-size:13px;color:#888">"Loading…"</div> }>
                {move || mailboxes.get().map(|mboxes| {
                    // Ensure standard order.
                    let order = ["INBOX", "Sent", "Drafts", "Spam", "Trash"];
                    let mut sorted: Vec<MailboxInfo> = mboxes;
                    sorted.sort_by_key(|m| {
                        order.iter().position(|o| *o == m.name).unwrap_or(usize::MAX)
                    });

                    view! {
                        <div>
                            {sorted.into_iter().map(|mbox| {
                                let name = mbox.name.clone();
                                let active = active_mailbox.clone();
                                let is_active = move || active.get() == name;
                                let nav = use_navigate();
                                let name_for_click = mbox.name.clone();
                                let name_for_render = mbox.name.clone();
                                let icon = icon_for(&mbox.name);
                                view! {
                                    <div
                                        class=move || format!("sidebar-item{}", if is_active() { " active" } else { "" })
                                        on:click=move |_| {
                                            nav(&format!("/mail/{}", name_for_click), Default::default());
                                        }
                                    >
                                        <span>{icon}</span>
                                        <span>{name_for_render.clone()}</span>
                                        {(mbox.unread > 0).then(|| view! {
                                            <span class="sidebar-badge">{mbox.unread}</span>
                                        })}
                                    </div>
                                }
                            }).collect::<Vec<_>>()}
                        </div>
                    }
                })}
            </Suspense>
        </nav>
    }
}
