use crate::config::Config;
use crate::store::MailStore;
use crate::smtp::session::SmtpSession;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct SmtpListener {
    config: Arc<Config>,
    store: Arc<MailStore>,
    is_submission: bool,
}

impl SmtpListener {
    pub fn new(config: Arc<Config>, store: Arc<MailStore>) -> Self {
        Self { config, store, is_submission: false }
    }

    pub fn new_submission(config: Arc<Config>, store: Arc<MailStore>) -> Self {
        Self { config, store, is_submission: true }
    }

    pub async fn listen(self) -> anyhow::Result<()> {
        let port = if self.is_submission {
            self.config.smtp_submission_port
        } else {
            self.config.smtp_port
        };
        let addr = format!("0.0.0.0:{port}");
        let listener = TcpListener::bind(&addr).await?;
        let is_submission = self.is_submission;
        loop {
            let (stream, peer) = listener.accept().await?;
            let config = Arc::clone(&self.config);
            let store = Arc::clone(&self.store);
            tokio::spawn(async move {
                let mut session = SmtpSession::new(stream, peer, config, store, is_submission);
                if let Err(e) = session.run().await {
                    tracing::warn!(%peer, "SMTP session error: {e}");
                }
            });
        }
    }
}
