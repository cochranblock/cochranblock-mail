# Proof of Artifacts — cochranblock-mail

## Purpose
This document records the concrete artifacts produced during the initial development session of `cochranblock-mail`. It establishes that the described artifacts exist and were produced by the named author on the recorded date.

**Author:** Michael Cochran (GotEmCoach)  
**Date:** 2026-05-17  
**Repository:** https://github.com/cochranblock/cochranblock-mail

---

## Artifact Registry

### A1 — Rust Workspace
- **Type:** Source code
- **Path:** `/` (workspace root)
- **Contents:** Three-crate workspace: `server`, `shared`, `frontend`
- **Rust edition:** 2024
- **Status:** Compiles clean on 2026-05-17

### A2 — SMTP Server
- **Type:** Network protocol implementation
- **Path:** `server/src/smtp/`
- **Capabilities:** RFC 5321 SMTP, EHLO/HELO, MAIL FROM, RCPT TO (local delivery only), DATA with dot-unstuffing, RSET, NOOP, QUIT
- **Tests:** 13 unit tests

### A3 — IMAP Server
- **Type:** Network protocol implementation
- **Path:** `server/src/imap/`
- **Capabilities:** IMAP4rev1, AUTH=PLAIN (argon2id), SELECT/EXAMINE, LIST, STATUS, NOOP, LOGOUT
- **Tests:** 7 unit tests

### A4 — Embedded Mail Store
- **Type:** Storage system
- **Path:** `server/src/store/`
- **Implementation:** redb (embedded key-value), zstd compression, separate metadata index
- **Tables:** messages, message_meta, mailboxes, users, sessions, partial_sessions, scratch
- **Tests:** 31 unit tests (users, sessions, messages)

### A5 — TOTP MFA Authentication System
- **Type:** Security implementation
- **Path:** `server/src/webmail/auth.rs`
- **Algorithm:** TOTP-SHA1, 6 digits, 30-second window
- **QR generation:** PNG via `qrcodegen-image`
- **Flow:** password check → partial session (5 min TTL) → QR setup OR TOTP verify → full session (24h TTL)
- **Password storage:** argon2id PHC string format

### A6 — REST API
- **Type:** HTTP API
- **Path:** `server/src/webmail/`
- **Endpoints:**
  - `POST /api/auth/login`
  - `GET /api/auth/totp/setup`
  - `POST /api/auth/totp/confirm`
  - `POST /api/auth/totp/verify`
  - `DELETE /api/auth/session`
  - `GET /api/mailboxes`
  - `GET /api/messages`
  - `GET /api/messages/:uid`
  - `POST /api/messages`
  - `PATCH /api/messages/:uid`

### A7 — Leptos WASM Frontend
- **Type:** Web application (WebAssembly)
- **Path:** `frontend/src/`
- **Framework:** Leptos 0.8.19 (CSR)
- **Build tool:** Trunk
- **Components:** Login, TotpSetup, Sidebar, MessageList, MessageView, Compose
- **Style:** Gmail-inspired CSS (dark sidebar, white content, red compose button)

### A8 — Shared Type Library
- **Type:** API contract
- **Path:** `shared/src/lib.rs`
- **Tests:** 7 serialization roundtrip tests

### A9 — CLI Tooling
- **Type:** Command-line interface
- **Path:** `server/src/bin/main.rs`
- **Commands:** `cochranblock-mail` (serve), `cochranblock-mail user add`, `cochranblock-mail user list`

---

## Test Evidence

```
test result: ok. 51 passed; 0 failed; 0 ignored; 0 measured (server)
test result: ok. 7 passed;  0 failed; 0 ignored; 0 measured (shared)
Total: 58 tests, 0 failures
Date: 2026-05-17
```

---

## Build Reproducibility

```sh
# Clone and build:
git clone https://github.com/cochranblock/cochranblock-mail
cd cochranblock-mail
cargo build --release -p cochranblock-mail

# Run tests:
cargo test -p cochranblock-mail -p shared

# Build frontend (requires trunk):
cd frontend && trunk build --release
```

---

*This artifact register was created and committed at time of initial invention.*
