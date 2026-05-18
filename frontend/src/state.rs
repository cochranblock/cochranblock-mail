/// Global authentication state.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    /// Initial state — checking cookie validity with the server.
    Loading,
    /// Not authenticated.
    LoggedOut,
    /// Authenticated with this username.
    LoggedIn(String),
}

impl AuthState {
    pub fn username(&self) -> Option<&str> {
        if let AuthState::LoggedIn(u) = self { Some(u) } else { None }
    }

    pub fn is_logged_in(&self) -> bool {
        matches!(self, AuthState::LoggedIn(_))
    }
}
