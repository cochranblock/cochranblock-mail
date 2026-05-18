# Proof of Artifacts — cochranblock-mail

## Purpose
This document records the concrete artifacts produced during development of `cochranblock-mail`. It establishes that the described artifacts exist and were produced by the named author on the recorded dates.

**Author:** Michael Cochran (GotEmCoach)  
**Repository:** https://github.com/cochranblock/cochranblock-mail

---

## Artifact Registry

### A1 — Rust Workspace
- **Type:** Source code
- **Path:** `/` (workspace root)
- **Contents:** Three-crate workspace: `server`, `shared`, `frontend`
- **Rust edition:** 2024
- **Status:** Compiles clean, clippy -D warnings clean, release check clean

### A2 — SMTP Server
- **Type:** Network protocol implementation
- **Path:** `server/src/smtp/`
- **Capabilities:**
  - RFC 5321 SMTP on port 25 (MX — inbound delivery, no auth required)
  - RFC 4616 AUTH PLAIN on port 587 (submission — requires auth before MAIL FROM)
  - EHLO/HELO, MAIL FROM, RCPT TO (local delivery only, relay denied), DATA with RFC 5321 dot-unstuffing
  - 26 MiB DATA size limit (matches advertised `SIZE` in EHLO), RSET, NOOP, QUIT
  - EHLO enforcement: MAIL FROM rejected 503 before greeting
  - Submission AUTH: MAIL FROM rejected 530 until AUTH PLAIN succeeds
- **Tests:** 18 unit tests (protocol flow, relay denial, dot-unstuffing, AUTH PLAIN valid/invalid, DATA size limit)

### A3 — IMAP Server
- **Type:** Network protocol implementation
- **Path:** `server/src/imap/`
- **Capabilities:** IMAP4rev1, AUTH=PLAIN (argon2id), SELECT/EXAMINE, LIST, STATUS, NOOP, LOGOUT
- **Tests:** 8 unit tests

### A4 — Embedded Mail Store
- **Type:** Storage system
- **Path:** `server/src/store/`
- **Implementation:** redb (embedded key-value), zstd compression, separate metadata index
- **Tables:** messages, message_meta, mailboxes, users, sessions, partial_sessions, scratch
- **Security:** TOTP secrets encrypted at rest with ChaCha20-Poly1305 AEAD when `TOTP_ENCRYPTION_KEY` env var is set; plaintext fallback for dev
- **Maintenance:** Hourly background reaper prunes expired sessions and partial sessions
- **Tests:** 34 unit tests (users, sessions, messages, TOTP encryption roundtrip)

### A5 — TOTP MFA Authentication System
- **Type:** Security implementation
- **Path:** `server/src/webmail/auth.rs`
- **Algorithm:** TOTP-SHA1, 6 digits, 30-second window
- **QR generation:** PNG via `qrcodegen-image`
- **Flow:** password check → partial session (5 min TTL) → QR setup OR TOTP verify → full session (24h TTL)
- **Password storage:** argon2id PHC string format
- **Rate limiting:** 5 failed attempts per 5-minute window triggers 15-minute lockout on login (by username) and TOTP verify (by partial token)
- **Header injection prevention:** CRLF stripped from all user-supplied RFC 5322 header fields

### A6 — REST API
- **Type:** HTTP API
- **Path:** `server/src/webmail/`
- **Security:** `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on all responses
- **Endpoints:**
  - `POST /api/auth/login`
  - `GET /api/auth/totp/setup`
  - `POST /api/auth/totp/confirm`
  - `POST /api/auth/totp/verify`
  - `DELETE /api/auth/session`
  - `GET /api/mailboxes`
  - `GET /api/messages`
  - `GET /api/messages/{uid}`
  - `POST /api/messages`
  - `PATCH /api/messages/{uid}`
- **Tests:** 21 unit tests

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

### A10 — Rate Limiter
- **Type:** Security primitive
- **Path:** `server/src/webmail/rate_limit.rs`
- **Implementation:** Pure Rust (`std::sync::Mutex<HashMap>`) — no external middleware dependencies
- **Policy:** 5 attempts / 5-minute window / 15-minute lockout per key
- **Tests:** 5 unit tests

---

## Security Properties

| Threat | Mitigation |
|--------|-----------|
| Password brute force | argon2id + rate limiter (5 attempts / 15-min lockout) |
| TOTP brute force | Rate limiter on verify endpoint (1M codes, 30-sec window) |
| TOTP secret exfiltration | ChaCha20-Poly1305 encryption at rest |
| Header injection | CRLF stripped from all user-supplied RFC 5322 fields |
| Open relay | RCPT TO restricted to local domain; submission port requires AUTH |
| Oversized message DoS | 26 MiB hard limit; excess drained without buffering |
| Cookie theft | HttpOnly, SameSite=Strict, Secure (configurable for dev), 24h TTL |
| HTTPS downgrade | HSTS preload (max-age=31536000; includeSubDomains) |
| Session accumulation | Hourly reaper prunes expired rows from redb |

---

## Test Evidence

```
test result: ok. 101 passed; 0 failed; 0 ignored; 0 measured (server)
test result: ok. 7 passed;  0 failed; 0 ignored; 0 measured (shared)
Total: 108 tests, 0 failures
Date: 2026-05-18
Clippy: -D warnings clean
Release check: clean
```

---

## Commit History (key milestones)

| Date | Commit | Description |
|------|--------|-------------|
| 2026-05-17 | `76d2e9a` | Initial invention — SMTP + IMAP + HTTP + TOTP + redb + Leptos WASM (58 tests) |
| 2026-05-17 | `d0765d4` | Fix all 36 clippy warnings |
| 2026-05-17 | `2d4f82a` | Add 38 integration tests; fix axum 0.8 path syntax (latent production bug) |
| 2026-05-18 | `4388606` | Engineering audit: header injection fix, SMTP state machine, session reaper, secure cookies |
| 2026-05-18 | `a516ceb` | Security hardening: rate limiting, SMTP AUTH, TOTP encryption, HSTS, DATA size limit |

---

## Build Reproducibility

```sh
# Clone and build:
git clone https://github.com/cochranblock/cochranblock-mail
cd cochranblock-mail
cargo build --release -p cochranblock-mail

# Run tests (108 total):
cargo test -p cochranblock-mail -p cochranblock-mail-shared

# Quality gate:
cargo clippy -p cochranblock-mail -- -D warnings
cargo check -p cochranblock-mail --release

# Build frontend (requires trunk):
cd frontend && trunk build --release
```

---

*Updated 2026-05-18 to reflect security hardening session.*
<!-- COCHRANBLOCK-BRAND-FOOTER:START - generated by cochranblock/scripts/brand-stamp.sh -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
