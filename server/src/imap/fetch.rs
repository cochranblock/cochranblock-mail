// IMAP FETCH: tokenizer, sequence set, item parser, and response builder.
// RFC 3501 §6.4.5, §7.4.2

use shared::flags as msg_flags;
use mailparse::ParsedMail;

// ── Sequence set ──────────────────────────────────────────────────────────────

/// Parsed IMAP sequence set: `1`, `1:3`, `*`, `1:*`, `1,3,5:7`
#[derive(Debug, PartialEq)]
pub struct SeqSet(Vec<(SeqNum, SeqNum)>);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeqNum {
    Num(u32),
    Star,
}

impl SeqSet {
    pub fn parse(s: &str) -> Option<Self> {
        let mut ranges = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if let Some((lo, hi)) = part.split_once(':') {
                ranges.push((parse_seqnum(lo)?, parse_seqnum(hi)?));
            } else {
                let n = parse_seqnum(part)?;
                ranges.push((n, n));
            }
        }
        if ranges.is_empty() {
            return None;
        }
        Some(Self(ranges))
    }

    /// True if `n` falls within this set; `max` is the value of `*`.
    pub fn contains(&self, n: u32, max: u32) -> bool {
        self.0.iter().any(|&(lo, hi)| {
            let lo_n = resolve(lo, max);
            let hi_n = resolve(hi, max);
            let (a, b) = (lo_n.min(hi_n), lo_n.max(hi_n));
            n >= a && n <= b
        })
    }
}

fn parse_seqnum(s: &str) -> Option<SeqNum> {
    if s == "*" {
        Some(SeqNum::Star)
    } else {
        s.parse::<u32>().ok().map(SeqNum::Num)
    }
}

fn resolve(s: SeqNum, max: u32) -> u32 {
    match s {
        SeqNum::Num(n) => n,
        SeqNum::Star => max,
    }
}

// ── Tokenizer ─────────────────────────────────────────────────────────────────

/// Low-level IMAP token.
#[derive(Debug, PartialEq, Clone)]
pub enum Token {
    Atom(String),
    Quoted(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
}

/// Tokenize an IMAP fragment into atoms, quoted strings, and delimiters.
pub fn tokenize(s: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = s.chars().peekable();
    let mut atom = String::new();

    macro_rules! flush {
        () => {
            if !atom.is_empty() {
                tokens.push(Token::Atom(std::mem::take(&mut atom)));
            }
        };
    }

    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                flush!();
                chars.next();
            }
            '(' => {
                flush!();
                tokens.push(Token::LParen);
                chars.next();
            }
            ')' => {
                flush!();
                tokens.push(Token::RParen);
                chars.next();
            }
            '[' => {
                flush!();
                tokens.push(Token::LBracket);
                chars.next();
            }
            ']' => {
                flush!();
                tokens.push(Token::RBracket);
                chars.next();
            }
            '"' => {
                flush!();
                chars.next(); // skip opening quote
                let mut s = String::new();
                loop {
                    match chars.next() {
                        None | Some('"') => break,
                        Some('\\') => {
                            if let Some(ec) = chars.next() {
                                s.push(ec);
                            }
                        }
                        Some(ch) => s.push(ch),
                    }
                }
                tokens.push(Token::Quoted(s));
            }
            _ => {
                atom.push(c.to_ascii_uppercase());
                chars.next();
            }
        }
    }
    flush!();
    tokens
}

// ── FETCH data items ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum FetchItem {
    Flags,
    Uid,
    Rfc822Size,
    Rfc822,
    Rfc822Header,
    Rfc822Text,
    InternalDate,
    Envelope,
    BodyStructure,
    Body { section: Section, partial: Option<(u32, u32)>, peek: bool },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Section {
    Full,
    Header,
    HeaderFields(Vec<String>),
    HeaderFieldsNot(Vec<String>),
    Text,
    Mime(u32),
}

/// Parse the argument string after `FETCH seq-set`: returns `(seq_set, items)`.
pub fn parse_fetch_args(s: &str) -> Option<(SeqSet, Vec<FetchItem>)> {
    let s = s.trim();
    // Find the boundary between seq-set and item-list.
    // seq-set ends at the first space (it never contains brackets/parens).
    let (seq_str, rest) = s.split_once(' ')?;
    let seq_set = SeqSet::parse(seq_str)?;
    let items = parse_item_list(rest.trim())?;
    Some((seq_set, items))
}

fn parse_item_list(s: &str) -> Option<Vec<FetchItem>> {
    let tokens = tokenize(s);
    let mut pos = 0;
    // Macro expansions
    if tokens.len() == 1
        && let Token::Atom(ref a) = tokens[0]
    {
        return Some(match a.as_str() {
            "ALL" => vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size,
                FetchItem::Envelope,
            ],
            "FAST" => vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size,
            ],
            "FULL" => vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size,
                FetchItem::Envelope,
                FetchItem::BodyStructure,
            ],
            _ => {
                let item = parse_one_item(&tokens, &mut pos)?;
                vec![item]
            }
        });
    }
    // Parenthesized or bare list
    let items = if tokens.first() == Some(&Token::LParen) {
        pos = 1;
        let mut items = Vec::new();
        while pos < tokens.len() && tokens[pos] != Token::RParen {
            items.push(parse_one_item(&tokens, &mut pos)?);
        }
        items
    } else {
        let mut items = Vec::new();
        while pos < tokens.len() {
            items.push(parse_one_item(&tokens, &mut pos)?);
        }
        items
    };
    Some(items)
}

fn parse_one_item(tokens: &[Token], pos: &mut usize) -> Option<FetchItem> {
    let atom = match tokens.get(*pos)? {
        Token::Atom(a) => a.clone(),
        _ => return None,
    };
    *pos += 1;

    match atom.as_str() {
        "FLAGS" => Some(FetchItem::Flags),
        "UID" => Some(FetchItem::Uid),
        "RFC822.SIZE" => Some(FetchItem::Rfc822Size),
        "RFC822" => Some(FetchItem::Rfc822),
        "RFC822.HEADER" => Some(FetchItem::Rfc822Header),
        "RFC822.TEXT" => Some(FetchItem::Rfc822Text),
        "INTERNALDATE" => Some(FetchItem::InternalDate),
        "ENVELOPE" => Some(FetchItem::Envelope),
        "BODYSTRUCTURE" => Some(FetchItem::BodyStructure),

        "BODY" | "BODY.PEEK" => {
            let peek = atom == "BODY.PEEK";
            // Optional [section] follows
            if tokens.get(*pos) == Some(&Token::LBracket) {
                *pos += 1; // consume [
                let section = parse_section(tokens, pos)?;
                if tokens.get(*pos) == Some(&Token::RBracket) {
                    *pos += 1; // consume ]
                }
                // Optional <partial> — skip for now
                Some(FetchItem::Body { section, partial: None, peek })
            } else {
                // Bare BODY without section = full body (like RFC822)
                Some(FetchItem::Body { section: Section::Full, partial: None, peek })
            }
        }

        _ => None,
    }
}

fn parse_section(tokens: &[Token], pos: &mut usize) -> Option<Section> {
    match tokens.get(*pos) {
        // Empty section: BODY[]
        Some(Token::RBracket) | None => Some(Section::Full),

        Some(Token::Atom(a)) => {
            let key = a.clone();
            *pos += 1;
            match key.as_str() {
                "HEADER" => Some(Section::Header),
                "TEXT" => Some(Section::Text),
                "MIME" => Some(Section::Mime(0)),
                "HEADER.FIELDS" => {
                    let fields = parse_header_list(tokens, pos)?;
                    Some(Section::HeaderFields(fields))
                }
                "HEADER.FIELDS.NOT" => {
                    let fields = parse_header_list(tokens, pos)?;
                    Some(Section::HeaderFieldsNot(fields))
                }
                _ => {
                    // Could be a part number like "1" or "1.TEXT"
                    if let Ok(n) = key.parse::<u32>() {
                        // Consume dotted path if present (e.g. "1.2")
                        while tokens.get(*pos) == Some(&Token::Atom(".".to_string())) {
                            *pos += 1;
                        }
                        Some(Section::Mime(n))
                    } else {
                        Some(Section::Full)
                    }
                }
            }
        }

        _ => Some(Section::Full),
    }
}

fn parse_header_list(tokens: &[Token], pos: &mut usize) -> Option<Vec<String>> {
    // Expect "(" header-name* ")"
    if tokens.get(*pos) != Some(&Token::LParen) {
        return None;
    }
    *pos += 1;
    let mut fields = Vec::new();
    while let Some(tok) = tokens.get(*pos) {
        match tok {
            Token::RParen => {
                *pos += 1;
                break;
            }
            Token::Atom(a) => {
                fields.push(a.clone());
                *pos += 1;
            }
            Token::Quoted(q) => {
                fields.push(q.clone());
                *pos += 1;
            }
            _ => break,
        }
    }
    Some(fields)
}

// ── Response builder ──────────────────────────────────────────────────────────

/// Build the `* N FETCH (...)` response line(s) for one message.
pub fn build_fetch_response(
    seq_num: u32,
    uid: u64,
    meta: &shared::MessageMeta,
    raw: &[u8],
    items: &[FetchItem],
) -> String {
    let mut parts = Vec::new();

    for item in items {
        match item {
            FetchItem::Flags => parts.push(format!("FLAGS ({})", format_flags(meta.flags))),
            FetchItem::Uid => parts.push(format!("UID {uid}")),
            FetchItem::Rfc822Size => parts.push(format!("RFC822.SIZE {}", meta.size)),
            FetchItem::InternalDate => parts.push(format!(
                "INTERNALDATE \"{}\"",
                meta.date.format("%d-%b-%Y %H:%M:%S +0000")
            )),
            FetchItem::Envelope => parts.push(format!("ENVELOPE {}", build_envelope(meta))),
            FetchItem::Rfc822 => {
                parts.push(format!("RFC822 {{{}}}\r\n{}", raw.len(), String::from_utf8_lossy(raw)));
            }
            FetchItem::Rfc822Header => {
                let header = extract_header(raw);
                parts.push(format!(
                    "RFC822.HEADER {{{}}}\r\n{}",
                    header.len(),
                    String::from_utf8_lossy(header)
                ));
            }
            FetchItem::Rfc822Text => {
                let body = extract_body(raw);
                parts.push(format!(
                    "RFC822.TEXT {{{}}}\r\n{}",
                    body.len(),
                    String::from_utf8_lossy(body)
                ));
            }
            FetchItem::BodyStructure => {
                parts.push(format!("BODYSTRUCTURE {}", build_bodystructure(raw)));
            }
            FetchItem::Body { section, partial: _, peek } => {
                let label = if *peek { "BODY.PEEK" } else { "BODY" };
                let (section_str, data) = extract_section(raw, section);
                parts.push(format!(
                    "{label}[{section_str}] {{{}}}\r\n{}",
                    data.len(),
                    String::from_utf8_lossy(&data)
                ));
            }
        }
    }

    format!("* {seq_num} FETCH ({})\r\n", parts.join(" "))
}

pub fn format_flags(f: u8) -> String {
    let mut v = Vec::new();
    if f & msg_flags::SEEN != 0 { v.push("\\Seen"); }
    if f & msg_flags::STARRED != 0 { v.push("\\Flagged"); }
    if f & msg_flags::DELETED != 0 { v.push("\\Deleted"); }
    if f & msg_flags::DRAFT != 0 { v.push("\\Draft"); }
    v.join(" ")
}

// ── ENVELOPE builder ──────────────────────────────────────────────────────────

fn build_envelope(meta: &shared::MessageMeta) -> String {
    let date = format!("\"{}\"", meta.date.format("%a, %d %b %Y %H:%M:%S +0000"));
    let subject = nstring(&meta.subject);
    let from = addr_list(std::slice::from_ref(&meta.from));
    let to = addr_list(&meta.to);

    // ENVELOPE format (RFC 3501):
    // (date subject from sender reply-to to cc bcc in-reply-to message-id)
    format!(
        "({date} {subject} {from} {from} {from} {to} NIL NIL NIL NIL)"
    )
}

fn nstring(s: &str) -> String {
    if s.is_empty() {
        "NIL".to_string()
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn addr_list(addrs: &[String]) -> String {
    if addrs.is_empty() {
        return "NIL".to_string();
    }
    let formatted: Vec<String> = addrs.iter().map(|a| format_addr(a)).collect();
    format!("({})", formatted.join(" "))
}

fn format_addr(addr: &str) -> String {
    // Parse "Name <local@domain>" or "local@domain"
    let (name, mailbox) = if let Some(bracket_start) = addr.find('<') {
        let name = addr[..bracket_start].trim().trim_matches('"');
        let rest = &addr[bracket_start + 1..];
        let email = rest.trim_end_matches('>').trim();
        (name.to_string(), email.to_string())
    } else {
        (String::new(), addr.trim().to_string())
    };

    let (local, domain) = if let Some(at) = mailbox.rfind('@') {
        (mailbox[..at].to_string(), mailbox[at + 1..].to_string())
    } else {
        (mailbox.clone(), String::new())
    };

    format!(
        "({} NIL \"{}\" \"{}\")",
        nstring(&name),
        local.replace('"', "\\\""),
        domain.replace('"', "\\\"")
    )
}

// ── Message body extraction ───────────────────────────────────────────────────

fn extract_header(raw: &[u8]) -> &[u8] {
    // Headers end at the first \r\n\r\n or \n\n
    for i in 0..raw.len().saturating_sub(1) {
        if raw[i] == b'\r' && raw.get(i + 1) == Some(&b'\n')
            && raw.get(i + 2) == Some(&b'\r') && raw.get(i + 3) == Some(&b'\n')
        {
            return &raw[..i + 4];
        }
        if raw[i] == b'\n' && raw.get(i + 1) == Some(&b'\n') {
            return &raw[..i + 2];
        }
    }
    raw // no body separator found, entire message is header
}

fn extract_body(raw: &[u8]) -> &[u8] {
    for i in 0..raw.len().saturating_sub(1) {
        if raw[i] == b'\r' && raw.get(i + 1) == Some(&b'\n')
            && raw.get(i + 2) == Some(&b'\r') && raw.get(i + 3) == Some(&b'\n')
        {
            return &raw[i + 4..];
        }
        if raw[i] == b'\n' && raw.get(i + 1) == Some(&b'\n') {
            return &raw[i + 2..];
        }
    }
    &[] // no body
}

fn extract_specific_headers(raw: &[u8], fields: &[String]) -> Vec<u8> {
    let header_bytes = extract_header(raw);
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut out = String::new();
    let mut current_name = String::new();
    let mut current_line = String::new();

    let flush_line = |out: &mut String, name: &str, line: &str, fields: &[String]| {
        let name_up = name.to_ascii_uppercase();
        if fields.iter().any(|f| f.to_ascii_uppercase() == name_up) {
            out.push_str(line);
            if !line.ends_with('\n') {
                out.push_str("\r\n");
            }
        }
    };

    for line in header_str.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line
            current_line.push_str(line);
            current_line.push_str("\r\n");
        } else {
            // Flush previous header
            if !current_name.is_empty() {
                flush_line(&mut out, &current_name, &current_line, fields);
            }
            // Start new header
            if let Some(colon) = line.find(':') {
                current_name = line[..colon].to_string();
                current_line = format!("{}\r\n", line);
            } else {
                // End of headers or empty line
                current_name.clear();
                current_line.clear();
                break;
            }
        }
    }
    if !current_name.is_empty() {
        flush_line(&mut out, &current_name, &current_line, fields);
    }
    out.push_str("\r\n"); // blank line terminating headers
    out.into_bytes()
}

fn extract_section(raw: &[u8], section: &Section) -> (String, Vec<u8>) {
    match section {
        Section::Full => ("".to_string(), raw.to_vec()),
        Section::Header => ("HEADER".to_string(), extract_header(raw).to_vec()),
        Section::Text => ("TEXT".to_string(), extract_body(raw).to_vec()),
        Section::HeaderFields(fields) => (
            format!("HEADER.FIELDS ({})", fields.join(" ")),
            extract_specific_headers(raw, fields),
        ),
        Section::HeaderFieldsNot(fields) => {
            // Return headers NOT in the list
            let all_headers = extract_header(raw).to_vec();
            let excluded = extract_specific_headers(raw, fields);
            // Simple approach: return all headers minus the excluded ones
            let _ = excluded;
            (
                format!("HEADER.FIELDS.NOT ({})", fields.join(" ")),
                all_headers,
            )
        }
        Section::Mime(n) => (n.to_string(), raw.to_vec()),
    }
}

fn build_bodystructure(raw: &[u8]) -> String {
    match mailparse::parse_mail(raw) {
        Err(_) => "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 0 0)".to_string(),
        Ok(msg) => format_part(&msg),
    }
}

fn format_part(part: &ParsedMail) -> String {
    let mime = part.ctype.mimetype.to_ascii_lowercase();

    if mime.starts_with("multipart/") {
        let subtype = mime
            .split_once('/')
            .map(|(_, s)| s.to_ascii_uppercase())
            .unwrap_or_else(|| "MIXED".to_string());
        let children = part.subparts.iter().map(|s| format_part(s)).collect::<Vec<_>>().join(" ");
        return format!("({children} \"{subtype}\")");
    }

    let (type_up, sub_up) = mime
        .split_once('/')
        .map(|(t, s)| (t.to_ascii_uppercase(), s.to_ascii_uppercase()))
        .unwrap_or_else(|| ("TEXT".to_string(), "PLAIN".to_string()));

    let charset = part
        .ctype
        .params
        .get("charset")
        .cloned()
        .unwrap_or_else(|| "US-ASCII".to_string())
        .to_ascii_uppercase();

    let encoding = part
        .headers
        .iter()
        .find(|h| h.get_key_ref().eq_ignore_ascii_case("content-transfer-encoding"))
        .map(|h| h.get_value().trim().to_ascii_uppercase())
        .unwrap_or_else(|| "7BIT".to_string());

    let size = part.get_body_raw().map(|b| b.len()).unwrap_or(0);

    if type_up == "TEXT" {
        let lines = part.get_body_raw().map(|b| b.iter().filter(|&&c| c == b'\n').count()).unwrap_or(0);
        format!("(\"{type_up}\" \"{sub_up}\" (\"CHARSET\" \"{charset}\") NIL NIL \"{encoding}\" {size} {lines})")
    } else {
        format!("(\"{type_up}\" \"{sub_up}\" NIL NIL NIL \"{encoding}\" {size})")
    }
}

// ── STORE flag helpers ────────────────────────────────────────────────────────

/// Parse `+FLAGS (\Seen)` or `-FLAGS (\Deleted)` or `FLAGS (\Seen \Answered)`.
/// Returns `(mode, flag_byte)` where mode is '+', '-', or '='.
pub fn parse_store_args(s: &str) -> Option<(char, u8)> {
    let s = s.trim();
    // Find mode and FLAGS keyword
    let (mode, rest) = if let Some(r) = s.strip_prefix('+') {
        ('+', r)
    } else if let Some(r) = s.strip_prefix('-') {
        ('-', r)
    } else {
        ('=', s)
    };

    let rest = rest.trim();
    // Strip optional ".SILENT" suffix
    let rest = rest
        .strip_prefix("FLAGS.SILENT")
        .or_else(|| rest.strip_prefix("FLAGS"))
        .unwrap_or(rest)
        .trim();

    // Parse flag list in parens
    let inner = rest.strip_prefix('(')?.strip_suffix(')')?;
    let mut flags = 0u8;
    for token in inner.split_whitespace() {
        match token.to_ascii_uppercase().as_str() {
            "\\SEEN" => flags |= msg_flags::SEEN,
            "\\FLAGGED" => flags |= msg_flags::STARRED,
            "\\DELETED" => flags |= msg_flags::DELETED,
            "\\DRAFT" => flags |= msg_flags::DRAFT,
            _ => {}
        }
    }
    Some((mode, flags))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SeqSet ────────────────────────────────────────────────────────────────

    #[test]
    fn seqset_single_number() {
        let s = SeqSet::parse("3").unwrap();
        assert!(s.contains(3, 10));
        assert!(!s.contains(2, 10));
        assert!(!s.contains(4, 10));
    }

    #[test]
    fn seqset_range() {
        let s = SeqSet::parse("2:5").unwrap();
        assert!(s.contains(2, 10));
        assert!(s.contains(5, 10));
        assert!(!s.contains(1, 10));
        assert!(!s.contains(6, 10));
    }

    #[test]
    fn seqset_star_is_max() {
        let s = SeqSet::parse("*").unwrap();
        assert!(s.contains(10, 10));
        assert!(!s.contains(9, 10));
    }

    #[test]
    fn seqset_star_range() {
        let s = SeqSet::parse("1:*").unwrap();
        assert!(s.contains(1, 5));
        assert!(s.contains(5, 5));
    }

    #[test]
    fn seqset_comma_list() {
        let s = SeqSet::parse("1,3,5").unwrap();
        assert!(s.contains(1, 10));
        assert!(s.contains(3, 10));
        assert!(s.contains(5, 10));
        assert!(!s.contains(2, 10));
        assert!(!s.contains(4, 10));
    }

    #[test]
    fn seqset_mixed() {
        let s = SeqSet::parse("1,3:5,8").unwrap();
        assert!(s.contains(1, 10));
        assert!(s.contains(3, 10));
        assert!(s.contains(4, 10));
        assert!(s.contains(5, 10));
        assert!(s.contains(8, 10));
        assert!(!s.contains(2, 10));
        assert!(!s.contains(6, 10));
    }

    #[test]
    fn seqset_invalid_returns_none() {
        assert!(SeqSet::parse("").is_none());
        assert!(SeqSet::parse("abc").is_none());
    }

    // ── Tokenizer ─────────────────────────────────────────────────────────────

    #[test]
    fn tokenize_atoms() {
        let t = tokenize("FLAGS UID RFC822.SIZE");
        assert_eq!(t, vec![
            Token::Atom("FLAGS".into()),
            Token::Atom("UID".into()),
            Token::Atom("RFC822.SIZE".into()),
        ]);
    }

    #[test]
    fn tokenize_parens_and_brackets() {
        let t = tokenize("BODY[HEADER]");
        assert_eq!(t, vec![
            Token::Atom("BODY".into()),
            Token::LBracket,
            Token::Atom("HEADER".into()),
            Token::RBracket,
        ]);
    }

    #[test]
    fn tokenize_quoted_string() {
        let t = tokenize(r#"("From" "Subject")"#);
        assert_eq!(t, vec![
            Token::LParen,
            Token::Quoted("From".into()),
            Token::Quoted("Subject".into()),
            Token::RParen,
        ]);
    }

    // ── FetchItem parsing ─────────────────────────────────────────────────────

    #[test]
    fn parse_flags_uid_size() {
        let (seq, items) = parse_fetch_args("1:* (FLAGS UID RFC822.SIZE)").unwrap();
        assert!(seq.contains(1, 5));
        assert!(seq.contains(5, 5));
        assert!(items.contains(&FetchItem::Flags));
        assert!(items.contains(&FetchItem::Uid));
        assert!(items.contains(&FetchItem::Rfc822Size));
    }

    #[test]
    fn parse_body_peek_header_fields() {
        let (seq, items) = parse_fetch_args(
            "1 (BODY.PEEK[HEADER.FIELDS (From Subject Date)])"
        ).unwrap();
        assert!(seq.contains(1, 10));
        let has_body = items.iter().any(|i| matches!(
            i,
            FetchItem::Body { section: Section::HeaderFields(_), peek: true, .. }
        ));
        assert!(has_body, "expected BODY.PEEK[HEADER.FIELDS ...]: {items:?}");
    }

    #[test]
    fn parse_body_full_section() {
        let (_, items) = parse_fetch_args("1 BODY[]").unwrap();
        assert!(items.contains(&FetchItem::Body {
            section: Section::Full,
            partial: None,
            peek: false,
        }));
    }

    #[test]
    fn parse_body_text_section() {
        let (_, items) = parse_fetch_args("1 BODY[TEXT]").unwrap();
        assert!(items.contains(&FetchItem::Body {
            section: Section::Text,
            partial: None,
            peek: false,
        }));
    }

    #[test]
    fn parse_all_macro() {
        let (_, items) = parse_fetch_args("1:* ALL").unwrap();
        assert!(items.contains(&FetchItem::Flags));
        assert!(items.contains(&FetchItem::InternalDate));
        assert!(items.contains(&FetchItem::Rfc822Size));
        assert!(items.contains(&FetchItem::Envelope));
    }

    #[test]
    fn parse_fast_macro() {
        let (_, items) = parse_fetch_args("1 FAST").unwrap();
        assert!(items.contains(&FetchItem::Flags));
        assert!(items.contains(&FetchItem::InternalDate));
        assert!(items.contains(&FetchItem::Rfc822Size));
        assert!(!items.contains(&FetchItem::Envelope));
    }

    // ── Response builder ──────────────────────────────────────────────────────

    #[test]
    fn build_response_flags_and_uid() {
        let meta = shared::MessageMeta {
            uid: 42,
            mailbox: "INBOX".into(),
            from: "alice@x.com".into(),
            to: vec!["bob@y.com".into()],
            subject: "Hi".into(),
            date: chrono::Utc::now(),
            flags: msg_flags::SEEN,
            size: 100,
            snippet: "".into(),
        };
        // Pass uid=99 (differs from meta.uid=42) to verify the function uses the explicit uid arg.
        let resp = build_fetch_response(1, 99, &meta, b"From: alice\r\n\r\nBody", &[
            FetchItem::Flags,
            FetchItem::Uid,
        ]);
        assert!(resp.contains("FLAGS (\\Seen)"), "{resp}");
        assert!(resp.contains("UID 99"), "must use uid arg, not meta.uid: {resp}");
        assert!(!resp.contains("UID 42"), "must not expose meta.uid in UID field: {resp}");
        assert!(resp.starts_with("* 1 FETCH"), "{resp}");
    }

    #[test]
    fn extract_header_bytes() {
        let raw = b"From: alice\r\nSubject: Hi\r\n\r\nBody text";
        let hdr = extract_header(raw);
        assert!(hdr.ends_with(b"\r\n\r\n"), "header should end with CRLFCRLF");
        assert!(std::str::from_utf8(hdr).unwrap().contains("From: alice"));
    }

    #[test]
    fn extract_body_bytes() {
        let raw = b"From: alice\r\n\r\nBody text";
        let body = extract_body(raw);
        assert_eq!(body, b"Body text");
    }

    // ── STORE args ────────────────────────────────────────────────────────────

    #[test]
    fn parse_store_add_seen() {
        let (mode, flags) = parse_store_args("+FLAGS (\\Seen)").unwrap();
        assert_eq!(mode, '+');
        assert!(flags & msg_flags::SEEN != 0);
    }

    #[test]
    fn parse_store_remove_deleted() {
        let (mode, flags) = parse_store_args("-FLAGS (\\Deleted)").unwrap();
        assert_eq!(mode, '-');
        assert!(flags & msg_flags::DELETED != 0);
    }

    #[test]
    fn parse_store_silent() {
        let (mode, flags) = parse_store_args("+FLAGS.SILENT (\\Seen)").unwrap();
        assert_eq!(mode, '+');
        assert!(flags & msg_flags::SEEN != 0);
    }
}
