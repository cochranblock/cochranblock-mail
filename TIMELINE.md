# Timeline of Invention — cochranblock-mail

## Project: Sovereign SMTP/IMAP/HTTP Mail Server + WASM Webmail

**Author:** Michael Cochran (GotEmCoach)  
**Domain:** cochranblock.org  
**License:** Unlicense (public domain)

---

## 2026-05-17 — Initial invention

### Conception
- Michael Cochran conceived and initiated development of `cochranblock-mail`, a sovereign, zero-cloud email server for `cochranblock.org`.
- Goal: replace all third-party email infrastructure with a single self-hosted Rust binary — SMTP, IMAP, HTTP webmail, and TOTP MFA in one process.

### Architecture decisions (recorded at time of invention)
1. **Single binary**: SMTP (port 25/587) + IMAP (993) + HTTP webmail (8080) run concurrently via `tokio::try_join!`.
2. **Storage**: `redb` embedded key-value database — no Postgres, no SQLite, no external services.
3. **Message compression**: All RFC 5322 messages stored zstd-compressed. Metadata indexed separately for O(1) inbox listing.
4. **Authentication**: `argon2id` password hashing (replaces sha2); TOTP via `totp-rs` with QR PNG generation.
5. **Sessions**: UUID v4 tokens, 24h TTL, stored in redb. Partial sessions (post-password, pre-TOTP) expire after 5 minutes.
6. **Frontend**: Rust → WASM via Leptos 0.8 (CSR), built with Trunk. Gmail-inspired layout, served by the same HTTP server.
7. **Multi-user**: Per-user mailboxes with standard folders (INBOX, Sent, Drafts, Trash, Spam). CLI `user add` subcommand for provisioning.

### First working test suite
- 51 server unit tests across: config, SMTP parsing, IMAP parsing, store/users, store/sessions, store/messages
- 7 shared type tests (serialization roundtrips, flag bitfield)
- All 58 tests pass on first merge.

### Workspace crates
| Crate | Purpose |
|-------|---------|
| `cochranblock-mail` (server) | SMTP + IMAP + HTTP server, CLI |
| `shared` | API types shared between server and WASM frontend |
| `cochranblock-mail-frontend` | Leptos 0.8 CSR WASM webmail UI |

### Key source files
- `server/src/store/` — redb schema, user/session/message CRUD
- `server/src/webmail/auth.rs` — full TOTP MFA flow (setup + verify)
- `server/src/webmail/mail.rs` — REST mail API
- `frontend/src/components/` — Leptos UI components (login, inbox, compose, message view)

---

## 2026-05-18 — Security hardening, spam engine, and e2e proof

### Session 1 — Engineering audit (commit `4388606`)
Michael Cochran ran a systematic audit of the 2026-05-17 codebase and identified six correctness and security issues:

1. **Header injection** — RFC 5322 header fields (`From`, `To`, `Subject`, `Reply-To`) were written verbatim from user input. Fixed by stripping all `\r` and `\n` characters before constructing message headers.
2. **SMTP state machine** — `MAIL FROM` was accepted before `EHLO`. Fixed by enforcing EHLO-first in the command dispatcher; violators receive `503 Bad sequence of commands`.
3. **Session reaper** — expired sessions accumulated in redb with no eviction. Fixed by spawning a Tokio background task that wakes hourly and deletes all sessions whose TTL has elapsed.
4. **Secure cookies** — session cookie lacked `HttpOnly`, `SameSite=Strict`, and `Secure` flags. Fixed; `Secure` is configurable off for local dev via `INSECURE_COOKIES=1`.
5. **SMTP dot-unstuffing** — RFC 5321 §4.5.2 requires stripping the leading dot from lines beginning with `..`. The original implementation skipped this. Fixed in `SmtpSession::collect_data`.
6. **IMAP fetch correctness** — `RFC822.HEADER` response was missing the mandatory blank line separating headers from body. Fixed in `format_rfc822_header`.

### Session 2 — Security hardening (commit `a516ceb`)
Designed and implemented five independent security layers:

1. **Rate limiter** (A10) — Pure-Rust `Mutex<HashMap>` implementation (no external middleware). Policy: 5 failed attempts per 5-minute window → 15-minute lockout, keyed by username (login) or partial token (TOTP verify). Covered by 5 unit tests.
2. **SMTP submission AUTH** — Port 587 now requires `AUTH PLAIN` before `MAIL FROM`. Unauthenticated `MAIL FROM` on the submission port returns `530 Authentication required`. The MX port (25) remains unauthenticated for inbound delivery.
3. **TOTP secret encryption at rest** — TOTP secrets optionally encrypted with ChaCha20-Poly1305 AEAD using a key from `TOTP_ENCRYPTION_KEY` env var. Plaintext fallback for dev. Roundtrip covered by unit tests.
4. **HSTS** — `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` injected as axum middleware on all responses.
5. **DATA size limit** — 26 MiB hard cap enforced during SMTP `DATA` collection; excess bytes are drained and discarded (no unbounded allocation), then a `552 Message too large` response is sent.

### Session 3 — Spam detection engine (commit `fba5bff`, A11)
Designed and implemented a score-based spam classifier:

- Scoring heuristics: SPF/DKIM header signals, `From`/`Reply-To` domain mismatch, keyword lists (pharmaceutical, financial, urgency), structural indicators (all-caps subject, excessive punctuation, missing `Date` header, suspicious `X-Mailer`).
- Configurable threshold: messages above the threshold are quarantined to the Spam mailbox or rejected at SMTP `DATA` depending on operator configuration.
- 24 unit tests covering threshold behavior, header parsing, keyword detection, boundary cases.
- Brought server unit test total from 132 → 156.

### Session 4 — Brand assets (commit `79acd3a`)
- Added SDVOSB Certified badge to the webmail UI.
- Converted external CDN SVG references to local assets to remove third-party dependencies and ensure offline availability.

### Session 5 — End-to-end integration test + Chromium proof (commit `8c12bb0`, A12)
Designed and implemented a full-stack integration test that exercises every protocol layer in a single automated run:

**Architecture decisions:**
1. **In-process harness** — SMTP, IMAP, and HTTP servers bind to OS-assigned ephemeral ports inside the test process. No external daemons, no port conflicts, no cleanup scripts.
2. **Known TOTP secret** — test user `alice` is created with a deterministic base32 secret (`GEZDGNBVGY3TQOJQ…`), allowing the harness to generate a valid TOTP code in-process via `totp-rs` at the moment of verification.
3. **Screenshot injection** — an authenticated Chromium session requires a valid session cookie. A feature-gated `/test/inject-session?token=T&redirect=R` route sets the cookie server-side and issues a redirect; Chromium follows it into the SPA as a fully authenticated user.
4. **Deep-link TOTP verify** — `?partial_token=TOKEN` on `/login` routes the Leptos SPA directly to the TOTP verify step, enabling a screenshot of the second factor page without scripted interaction.
5. **PDF proof export** — screenshots are assembled into a PDF via Python (`reportlab`) and pushed to the Mac Mini via scp/ssh for visual review.

**Protocol steps verified (10 assertions):**
- SMTP: banner → EHLO → MAIL FROM → RCPT TO → DATA → `250 OK`
- IMAP: LOGIN → SELECT INBOX → `1 EXISTS` → FETCH RFC822.HEADER → subject match
- HTTP: login → `TotpRequired` → TOTP verify → session cookie → `/api/mailboxes` (INBOX) → `/api/messages` (subject match)

**Screenshots captured:** login page, TOTP verify page, inbox (E2E email visible), message read view.

---

*This document records design decisions and invention dates for provenance purposes.*
<!-- COCHRANBLOCK-BRAND-FOOTER:START - generated by cochranblock/scripts/brand-stamp.sh -->

---

<sub>&#9656; **THE COCHRAN BLOCK, LLC** &#183; CAGE `1CQ66` &#183; UEI `W7X3HAQL9CF9` &#183; UNLICENSE &#183; [cochranblock.org](https://cochranblock.org)</sub>
<!-- COCHRANBLOCK-BRAND-FOOTER:END -->
