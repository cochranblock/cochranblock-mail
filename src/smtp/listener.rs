use crate::config::Config;
use crate::store::MailStore;
use crate::smtp::session::SmtpSession;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct SmtpListener {
    config: Arc<Config>,
    store: Arc<MailStore>,
}

impl SmtpListener {
    pub fn new(config: Arc<Config>, store: Arc<MailStore>) -> Self {
        Self { config, store }
    }

    pub async fn listen(self) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.smtp_port);
        let listener = TcpListener::bind(&addr).await?;
        loop {
            let (stream, peer) = listener.accept().await?;
            let config = Arc::clone(&self.config);
            let store = Arc::clone(&self.store);
            tokio::spawn(async move {
                let mut session = SmtpSession::new(stream, peer, config, store);
                if let Err(e) = session.run().await {
                    tracing::warn!(%peer, "SMTP session error: {e}");
                }
            });
        }
    }
}
