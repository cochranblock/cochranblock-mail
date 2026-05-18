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
