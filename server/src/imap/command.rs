#[derive(Debug)]
pub struct ImapCommand {
    pub tag: String,
    pub verb: String,
    pub args: Vec<String>,
}

impl ImapCommand {
    pub fn parse(line: &str) -> Option<Self> {
        let mut parts = line.splitn(3, ' ');
        let tag = parts.next()?.to_string();
        // Reject empty tags (including whitespace-only lines).
        if tag.trim().is_empty() { return None; }
        let verb = parts.next()?.to_ascii_uppercase();
        if verb.trim().is_empty() { return None; }
        let rest = parts.next().unwrap_or("").to_string();
        let args = if rest.is_empty() {
            vec![]
        } else {
            vec![rest]
        };
        Some(Self { tag, verb, args })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_capability() {
        let cmd = ImapCommand::parse("a1 CAPABILITY").unwrap();
        assert_eq!(cmd.tag, "a1");
        assert_eq!(cmd.verb, "CAPABILITY");
        assert!(cmd.args.is_empty());
    }

    #[test]
    fn parse_login() {
        let cmd = ImapCommand::parse("a1 LOGIN alice hunter2").unwrap();
        assert_eq!(cmd.tag, "a1");
        assert_eq!(cmd.verb, "LOGIN");
        assert_eq!(cmd.args[0], "alice hunter2");
    }

    #[test]
    fn parse_select() {
        let cmd = ImapCommand::parse("a2 SELECT INBOX").unwrap();
        assert_eq!(cmd.verb, "SELECT");
        assert_eq!(cmd.args[0], "INBOX");
    }

    #[test]
    fn parse_logout() {
        let cmd = ImapCommand::parse("a3 LOGOUT").unwrap();
        assert_eq!(cmd.verb, "LOGOUT");
        assert!(cmd.args.is_empty());
    }

    #[test]
    fn verb_is_uppercased() {
        let cmd = ImapCommand::parse("a1 login user pass").unwrap();
        assert_eq!(cmd.verb, "LOGIN");
    }

    #[test]
    fn returns_none_for_empty_line() {
        assert!(ImapCommand::parse("").is_none());
        assert!(ImapCommand::parse("   ").is_none());
    }

    #[test]
    fn returns_none_for_missing_verb() {
        assert!(ImapCommand::parse("onlytag").is_none());
    }
}
