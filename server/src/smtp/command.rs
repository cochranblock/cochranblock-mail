#[derive(Debug)]
pub enum SmtpCommand {
    Ehlo(String),
    Helo(String),
    MailFrom(String),
    RcptTo(String),
    Data,
    Quit,
    Noop,
    Rset,
    Unknown(String),
}

impl SmtpCommand {
    pub fn parse(line: &str) -> Self {
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            SmtpCommand::Ehlo(line[4..].trim().to_string())
        } else if upper.starts_with("HELO") {
            SmtpCommand::Helo(line[4..].trim().to_string())
        } else if upper.starts_with("MAIL FROM:") {
            SmtpCommand::MailFrom(extract_angle(&line[10..]))
        } else if upper.starts_with("RCPT TO:") {
            SmtpCommand::RcptTo(extract_angle(&line[8..]))
        } else if upper.starts_with("DATA") {
            SmtpCommand::Data
        } else if upper.starts_with("QUIT") {
            SmtpCommand::Quit
        } else if upper.starts_with("NOOP") {
            SmtpCommand::Noop
        } else if upper.starts_with("RSET") {
            SmtpCommand::Rset
        } else {
            SmtpCommand::Unknown(line.to_string())
        }
    }
}

fn extract_angle(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('<') && s.ends_with('>') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ehlo() {
        let cmd = SmtpCommand::parse("EHLO mail.example.com");
        assert!(matches!(cmd, SmtpCommand::Ehlo(h) if h == "mail.example.com"));
    }

    #[test]
    fn parse_helo() {
        let cmd = SmtpCommand::parse("HELO mail.example.com");
        assert!(matches!(cmd, SmtpCommand::Helo(h) if h == "mail.example.com"));
    }

    #[test]
    fn parse_mail_from_with_angles() {
        let cmd = SmtpCommand::parse("MAIL FROM:<alice@example.com>");
        assert!(matches!(cmd, SmtpCommand::MailFrom(a) if a == "alice@example.com"));
    }

    #[test]
    fn parse_mail_from_without_angles() {
        let cmd = SmtpCommand::parse("MAIL FROM: alice@example.com");
        assert!(matches!(cmd, SmtpCommand::MailFrom(a) if a == "alice@example.com"));
    }

    #[test]
    fn parse_rcpt_to_with_angles() {
        let cmd = SmtpCommand::parse("RCPT TO:<bob@cochranblock.org>");
        assert!(matches!(cmd, SmtpCommand::RcptTo(a) if a == "bob@cochranblock.org"));
    }

    #[test]
    fn parse_data() {
        let cmd = SmtpCommand::parse("DATA");
        assert!(matches!(cmd, SmtpCommand::Data));
    }

    #[test]
    fn parse_quit() {
        let cmd = SmtpCommand::parse("QUIT");
        assert!(matches!(cmd, SmtpCommand::Quit));
    }

    #[test]
    fn parse_noop() {
        let cmd = SmtpCommand::parse("NOOP");
        assert!(matches!(cmd, SmtpCommand::Noop));
    }

    #[test]
    fn parse_rset() {
        let cmd = SmtpCommand::parse("RSET");
        assert!(matches!(cmd, SmtpCommand::Rset));
    }

    #[test]
    fn parse_unknown() {
        let cmd = SmtpCommand::parse("STARTTLS");
        assert!(matches!(cmd, SmtpCommand::Unknown(_)));
    }

    #[test]
    fn parse_case_insensitive_commands() {
        assert!(matches!(SmtpCommand::parse("quit"), SmtpCommand::Quit));
        assert!(matches!(SmtpCommand::parse("Quit"), SmtpCommand::Quit));
        assert!(matches!(SmtpCommand::parse("NOOP"), SmtpCommand::Noop));
    }

    #[test]
    fn extract_angle_strips_brackets() {
        assert_eq!(extract_angle("<user@host.com>"), "user@host.com");
    }

    #[test]
    fn extract_angle_passthrough_no_brackets() {
        assert_eq!(extract_angle("user@host.com"), "user@host.com");
    }

    #[test]
    fn extract_angle_trims_whitespace() {
        assert_eq!(extract_angle("  <user@host.com>  "), "user@host.com");
    }
}
