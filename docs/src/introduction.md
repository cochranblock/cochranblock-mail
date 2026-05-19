# cochranblock-mail

Sovereign SMTP/IMAP server. One Rust binary, zero cloud, zero SaaS.

## What It Is

cochranblock-mail is a full mail server written in Rust — SMTP for sending and receiving, IMAP for client access, a webmail frontend, and zstd-compressed attachment storage. No Postfix, no Dovecot, no cloud relay. The entire stack is one binary.

## Architecture

| Component | Description |
|-----------|-------------|
| SMTP server | Receive inbound mail, relay outbound |
| IMAP server | Client access — folder management, BODYSTRUCTURE, attachments |
| Attachment store | zstd-compressed storage, HTTP download endpoint |
| Webmail frontend | Browser-based mail client |
| `shared/` | Types and logic shared between server components |

## Build

```bash
cargo build --release
./target/release/cochranblock-mail
```

Requires: TLS certificate, DNS MX record pointing at the host.
<!-- COCHRANBLOCK-BRAND-FOOTER:START -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
