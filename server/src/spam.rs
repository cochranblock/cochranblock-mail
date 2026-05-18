/// Score-based spam detector. Pure Rust, no external process.
///
/// Each rule contributes a signed score. Total >= SPAM_THRESHOLD → deliver to Spam folder.
/// Score and matched rules are injected as X-Spam-* headers for client visibility.
pub const SPAM_THRESHOLD: f32 = 5.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ham,
    Spam,
}

#[derive(Debug, Clone)]
pub struct SpamResult {
    pub verdict: Verdict,
    pub score: f32,
    pub rules: Vec<&'static str>,
}

impl SpamResult {
    pub fn is_spam(&self) -> bool {
        self.verdict == Verdict::Spam
    }
}

/// Check a raw RFC 5322 message. `is_external` is true when the message arrived on port 25
/// (i.e., from an untrusted external sender, not an authenticated submission).
pub fn check(raw: &[u8], local_domain: &str, rcpt_count: usize, is_external: bool) -> SpamResult {
    let text = String::from_utf8_lossy(raw);
    let (headers_raw, body) = split_message(&text);

    let from = header_value(headers_raw, "from").unwrap_or_default();
    let subject = header_value(headers_raw, "subject").unwrap_or_default();
    let content_type = header_value(headers_raw, "content-type").unwrap_or_default();
    let msg_id = header_value(headers_raw, "message-id");
    let date = header_value(headers_raw, "date");

    let mut score = 0.0f32;
    let mut rules: Vec<&'static str> = Vec::new();

    macro_rules! fire {
        ($rule:expr, $points:expr) => {{
            rules.push($rule);
            score += $points;
        }};
    }

    // ── Required-header checks ────────────────────────────────────────────────

    if from.is_empty() {
        fire!("MISSING_FROM", 3.0);
    }
    if date.is_none() {
        fire!("MISSING_DATE", 1.5);
    }
    if msg_id.is_none() {
        fire!("MISSING_MSGID", 1.5);
    }

    // ── Sender impersonation ──────────────────────────────────────────────────

    // External message claiming to be from the local domain is spoofing.
    if is_external {
        let domain_suffix = format!("@{local_domain}");
        if from.to_ascii_lowercase().contains(&domain_suffix) {
            fire!("IMPERSONATED_LOCAL_SENDER", 5.0);
        }
    }

    // ── Subject heuristics ────────────────────────────────────────────────────

    if !subject.is_empty() {
        let upper_ratio = subject
            .chars()
            .filter(|c| c.is_alphabetic())
            .map(|c| if c.is_uppercase() { 1u32 } else { 0 })
            .sum::<u32>() as f32
            / subject.chars().filter(|c| c.is_alphabetic()).count().max(1) as f32;
        if upper_ratio >= 0.7 && subject.len() > 4 {
            fire!("SUBJECT_ALL_CAPS", 2.0);
        }

        let punct_count = subject.chars().filter(|&c| c == '!' || c == '$').count();
        if punct_count >= 3 {
            fire!("SUBJECT_EXCESSIVE_PUNCT", 2.0);
        }

        let subj_lower = subject.to_ascii_lowercase();
        let matched_phrases = SPAM_SUBJECT_PHRASES
            .iter()
            .filter(|&&p| subj_lower.contains(p))
            .count();
        if matched_phrases >= 1 {
            fire!("SUBJECT_SPAM_PHRASE", 2.5 * matched_phrases as f32);
        }

        // Leetspeak / obfuscation: common substitutions in subject
        let leet = normalize_leet(&subj_lower);
        let leet_hits = SPAM_SUBJECT_PHRASES
            .iter()
            .filter(|&&p| leet.contains(p))
            .count();
        if leet_hits > matched_phrases {
            fire!("SUBJECT_OBFUSCATED", 3.0);
        }
    }

    // ── Body heuristics ───────────────────────────────────────────────────────

    let body_lower = body.to_ascii_lowercase();

    let body_hits = SPAM_BODY_PHRASES
        .iter()
        .filter(|&&p| body_lower.contains(p))
        .count();
    if body_hits >= 2 {
        fire!("BODY_SPAM_PHRASES", 1.5 * body_hits as f32);
    }

    // ── MIME structure checks ─────────────────────────────────────────────────

    let ct_lower = content_type.to_ascii_lowercase();
    if ct_lower.contains("text/html") && !ct_lower.contains("multipart") {
        // HTML-only message with no text/plain alternative.
        if !body_lower.contains("text/plain") {
            fire!("HTML_ONLY", 1.5);
        }
    }

    // ── Envelope checks ───────────────────────────────────────────────────────

    if rcpt_count > 20 {
        fire!("EXCESS_RECIPIENTS", 2.0);
    }

    // ── Verdict ───────────────────────────────────────────────────────────────

    let verdict = if score >= SPAM_THRESHOLD { Verdict::Spam } else { Verdict::Ham };
    SpamResult { verdict, score, rules }
}

/// Format X-Spam-* headers to prepend to the message.
pub fn spam_headers(result: &SpamResult) -> String {
    let status = if result.is_spam() { "Yes" } else { "No" };
    let rules = if result.rules.is_empty() {
        "none".to_string()
    } else {
        result.rules.join(",")
    };
    format!(
        "X-Spam-Status: {status}\r\nX-Spam-Score: {:.2}\r\nX-Spam-Rules: {rules}\r\n",
        result.score
    )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn split_message(text: &str) -> (&str, &str) {
    // RFC 5322: headers and body separated by the first blank line.
    if let Some(pos) = text.find("\r\n\r\n") {
        (&text[..pos], &text[pos + 4..])
    } else if let Some(pos) = text.find("\n\n") {
        (&text[..pos], &text[pos + 2..])
    } else {
        (text, "")
    }
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}:");
    for line in headers.lines() {
        if line.to_ascii_lowercase().starts_with(&prefix) {
            return Some(line[prefix.len()..].trim().to_string());
        }
    }
    None
}

/// Collapse common leet-speak substitutions to plain ASCII for phrase matching.
fn normalize_leet(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | '!' => 'i',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '@' => 'a',
            _ => c,
        })
        .collect()
}

// ── Rule lexicons ─────────────────────────────────────────────────────────────

const SPAM_SUBJECT_PHRASES: &[&str] = &[
    "free money",
    "click here",
    "act now",
    "limited time",
    "you have been selected",
    "claim your prize",
    "earn extra cash",
    "work from home",
    "make money fast",
    "lose weight",
    "enlarge",
    "casino",
    "lottery",
    "100% free",
    "risk free",
    "no cost",
    "guaranteed",
    "no credit check",
    "pre-approved",
    "congratulations",
    "winner",
    "urgent",
];

const SPAM_BODY_PHRASES: &[&str] = &[
    "unsubscribe",
    "click here",
    "buy now",
    "free offer",
    "limited time offer",
    "act now",
    "call now",
    "order now",
    "make money",
    "earn cash",
    "work from home",
    "free gift",
    "no obligation",
    "risk free",
    "satisfaction guaranteed",
    "you have been selected",
    "claim your",
    "dear friend",
    "dear valued",
    "this is not spam",
    "remove yourself",
    "to be removed",
    "to unsubscribe",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(headers: &str, body: &str) -> Vec<u8> {
        format!("{headers}\r\n\r\n{body}").into_bytes()
    }

    fn full_headers(subject: &str) -> String {
        format!(
            "From: sender@example.com\r\nTo: user@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <test@example.com>\r\nSubject: {subject}"
        )
    }

    // ── Ham baseline ─────────────────────────────────────────────────────────

    #[test]
    fn clean_message_is_ham() {
        let raw = msg(&full_headers("Hello from a friend"), "Hi there, how are you?");
        let result = check(&raw, "example.com", 1, false);
        assert_eq!(result.verdict, Verdict::Ham, "rules: {:?}", result.rules);
    }

    // ── Missing header rules ──────────────────────────────────────────────────

    #[test]
    fn missing_from_fires() {
        let raw = msg(
            "To: u@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <x>\r\nSubject: hi",
            "hello",
        );
        let r = check(&raw, "example.com", 1, false);
        assert!(r.rules.contains(&"MISSING_FROM"));
    }

    #[test]
    fn missing_date_fires() {
        let raw = msg(
            "From: a@b.com\r\nTo: u@example.com\r\nMessage-ID: <x>\r\nSubject: hi",
            "hello",
        );
        let r = check(&raw, "example.com", 1, false);
        assert!(r.rules.contains(&"MISSING_DATE"));
    }

    #[test]
    fn missing_msgid_fires() {
        let raw = msg(
            "From: a@b.com\r\nTo: u@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nSubject: hi",
            "hello",
        );
        let r = check(&raw, "example.com", 1, false);
        assert!(r.rules.contains(&"MISSING_MSGID"));
    }

    #[test]
    fn all_three_missing_headers_exceeds_threshold() {
        // MISSING_FROM=3, MISSING_DATE=1.5, MISSING_MSGID=1.5 → 6.0 ≥ 5.0
        let raw = msg("Subject: hi", "hello");
        let r = check(&raw, "example.com", 1, false);
        assert_eq!(r.verdict, Verdict::Spam);
    }

    // ── Sender impersonation ─────────────────────────────────────────────────

    #[test]
    fn impersonated_local_sender_is_spam() {
        let raw = msg(
            &full_headers("hi"),
            "body"
        );
        // From sender@example.com claiming local domain, arriving externally.
        let raw2 = msg(
            "From: admin@cochranblock.test\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <x>\r\nSubject: hi",
            "hello",
        );
        let r = check(&raw2, "cochranblock.test", 1, true);
        assert!(r.rules.contains(&"IMPERSONATED_LOCAL_SENDER"), "rules: {:?}", r.rules);
        assert_eq!(r.verdict, Verdict::Spam);
    }

    #[test]
    fn authenticated_local_sender_not_flagged() {
        let raw = msg(
            "From: admin@cochranblock.test\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <x>\r\nSubject: hi",
            "hello",
        );
        let r = check(&raw, "cochranblock.test", 1, false); // is_external=false
        assert!(!r.rules.contains(&"IMPERSONATED_LOCAL_SENDER"));
    }

    // ── Subject rules ────────────────────────────────────────────────────────

    #[test]
    fn all_caps_subject_fires() {
        let raw = msg(&full_headers("YOU WON A FREE PRIZE"), "details inside");
        let r = check(&raw, "example.com", 1, false);
        assert!(r.rules.contains(&"SUBJECT_ALL_CAPS"), "rules: {:?}", r.rules);
    }

    #[test]
    fn mixed_case_subject_does_not_fire() {
        let raw = msg(&full_headers("Hello World From Alice"), "details");
        let r = check(&raw, "example.com", 1, false);
        assert!(!r.rules.contains(&"SUBJECT_ALL_CAPS"));
    }

    #[test]
    fn excessive_punct_fires() {
        let raw = msg(&full_headers("Act now!!! $$$"), "buy");
        let r = check(&raw, "example.com", 1, false);
        assert!(r.rules.contains(&"SUBJECT_EXCESSIVE_PUNCT"), "rules: {:?}", r.rules);
    }

    #[test]
    fn spam_phrase_in_subject_fires() {
        let raw = msg(&full_headers("Free money — click here today"), "body");
        let r = check(&raw, "example.com", 1, false);
        assert!(r.rules.contains(&"SUBJECT_SPAM_PHRASE"), "rules: {:?}", r.rules);
    }

    #[test]
    fn obfuscated_subject_fires() {
        // "fr33 m0n3y" → normalize_leet → "free money"
        let raw = msg(&full_headers("fr33 m0n3y"), "body");
        let r = check(&raw, "example.com", 1, false);
        assert!(r.rules.contains(&"SUBJECT_OBFUSCATED"), "rules: {:?}", r.rules);
    }

    // ── Body rules ───────────────────────────────────────────────────────────

    #[test]
    fn body_spam_phrases_fires_at_two_hits() {
        let raw = msg(
            &full_headers("hello"),
            "Click here to claim your free gift. This is a limited time offer. Act now and unsubscribe later.",
        );
        let r = check(&raw, "example.com", 1, false);
        assert!(r.rules.contains(&"BODY_SPAM_PHRASES"), "rules: {:?}", r.rules);
    }

    #[test]
    fn single_body_phrase_does_not_fire() {
        let raw = msg(&full_headers("hello"), "Please unsubscribe if you don't want this.");
        let r = check(&raw, "example.com", 1, false);
        assert!(!r.rules.contains(&"BODY_SPAM_PHRASES"));
    }

    // ── MIME structure ───────────────────────────────────────────────────────

    #[test]
    fn html_only_message_fires() {
        let raw = msg(
            "From: a@b.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nMessage-ID: <x>\r\nSubject: hi\r\nContent-Type: text/html; charset=utf-8",
            "<html><body>Buy now!</body></html>",
        );
        let r = check(&raw, "example.com", 1, false);
        assert!(r.rules.contains(&"HTML_ONLY"), "rules: {:?}", r.rules);
    }

    // ── Envelope checks ──────────────────────────────────────────────────────

    #[test]
    fn excess_recipients_fires() {
        let raw = msg(&full_headers("newsletter"), "content");
        let r = check(&raw, "example.com", 25, false);
        assert!(r.rules.contains(&"EXCESS_RECIPIENTS"), "rules: {:?}", r.rules);
    }

    #[test]
    fn twenty_recipients_is_ok() {
        let raw = msg(&full_headers("newsletter"), "content");
        let r = check(&raw, "example.com", 20, false);
        assert!(!r.rules.contains(&"EXCESS_RECIPIENTS"));
    }

    // ── Headers output ───────────────────────────────────────────────────────

    #[test]
    fn spam_headers_contains_yes_for_spam() {
        let result = SpamResult {
            verdict: Verdict::Spam,
            score: 7.5,
            rules: vec!["SUBJECT_ALL_CAPS", "MISSING_DATE"],
        };
        let h = spam_headers(&result);
        assert!(h.contains("X-Spam-Status: Yes"));
        assert!(h.contains("X-Spam-Score: 7.50"));
        assert!(h.contains("SUBJECT_ALL_CAPS"));
    }

    #[test]
    fn spam_headers_contains_no_for_ham() {
        let result = SpamResult { verdict: Verdict::Ham, score: 1.0, rules: vec![] };
        let h = spam_headers(&result);
        assert!(h.contains("X-Spam-Status: No"));
    }

    // ── Score threshold ──────────────────────────────────────────────────────

    #[test]
    fn score_just_below_threshold_is_ham() {
        // Manually construct a result just below the threshold.
        let r = SpamResult {
            verdict: if 4.9 >= SPAM_THRESHOLD { Verdict::Spam } else { Verdict::Ham },
            score: 4.9,
            rules: vec![],
        };
        assert_eq!(r.verdict, Verdict::Ham);
    }

    #[test]
    fn score_at_threshold_is_spam() {
        let r = SpamResult {
            verdict: if SPAM_THRESHOLD >= SPAM_THRESHOLD { Verdict::Spam } else { Verdict::Ham },
            score: SPAM_THRESHOLD,
            rules: vec![],
        };
        assert_eq!(r.verdict, Verdict::Spam);
    }

    // ── Leet normalization ───────────────────────────────────────────────────

    #[test]
    fn normalize_leet_converts_digits() {
        assert_eq!(normalize_leet("fr33 m0n3y"), "free money");
        assert_eq!(normalize_leet("v14gr4"), "viagra");
        assert_eq!(normalize_leet("c4s1n0"), "casino");
    }
}
