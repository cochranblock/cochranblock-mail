use crate::config::Config;
use crate::store::MailStore;
use crate::imap::session::ImapSession;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct ImapListener {
    config: Arc<Config>,
    store: Arc<MailStore>,
}

impl ImapListener {
    pub fn new(config: Arc<Config>, store: Arc<MailStore>) -> Self {
        Self { config, store }
    }

    pub async fn listen(self) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.imap_port);
        let listener = TcpListener::bind(&addr).await?;
        loop {
            let (stream, peer) = listener.accept().await?;
            let config = Arc::clone(&self.config);
            let store = Arc::clone(&self.store);
            tokio::spawn(async move {
                let session = ImapSession::new(stream, peer, config, store);
                if let Err(e) = session.run().await {
                    tracing::warn!(%peer, "IMAP session error: {e}");
                }
            });
        }
    }
}
