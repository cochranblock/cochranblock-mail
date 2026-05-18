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
        let verb = parts.next()?.to_ascii_uppercase();
        let rest = parts.next().unwrap_or("").to_string();
        let args = if rest.is_empty() {
            vec![]
        } else {
            vec![rest]
        };
        Some(Self { tag, verb, args })
    }
}
