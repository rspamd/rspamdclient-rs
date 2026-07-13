//! Commands that can be sent to the server

/// Commands that can be sent to the server
pub enum RspamdCommand {
    Scan,
    Learnspam,
    Learnham,
    FuzzyAdd,
    FuzzyDel,
}

/// Ephemeral endpoint representation
pub struct RspamdEndpoint<'a> {
    pub url: &'a str,
    pub command: RspamdCommand,
    pub need_body: bool,
}

/// Represents a request to the Rspamd server
impl<'a> RspamdEndpoint<'a> {
    /// Create a new endpoint from a command
    pub fn from_command(command: RspamdCommand) -> RspamdEndpoint<'a> {
        match command {
            RspamdCommand::Scan => Self {
                url: "/checkv2",
                command,
                need_body: true,
            },
            RspamdCommand::Learnspam => Self {
                url: "/learnspam",
                command,
                need_body: true,
            },
            RspamdCommand::Learnham => Self {
                url: "/learnham",
                command,
                need_body: true,
            },
            RspamdCommand::FuzzyAdd => Self {
                url: "/fuzzyadd",
                command,
                need_body: true,
            },
            RspamdCommand::FuzzyDel => Self {
                url: "/fuzzydel",
                command,
                need_body: true,
            },
        }
    }
}
