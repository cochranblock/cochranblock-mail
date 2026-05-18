use crate::config::Config;
use crate::imap::ImapListener;
use crate::smtp::SmtpListener;
use crate::store::MailStore;
use crate::webmail::router;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct Server {
    config: Config,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let store = Arc::new(MailStore::open(&self.config.db_path)?);
        let config = Arc::new(self.config);

        let smtp = SmtpListener::new(Arc::clone(&config), Arc::clone(&store));
        let imap = ImapListener::new(Arc::clone(&config), Arc::clone(&store));

        let http_addr = format!("0.0.0.0:{}", config.http_port);
        let http_listener = TcpListener::bind(&http_addr).await?;
        let app = router::build(Arc::clone(&config), Arc::clone(&store));

        tracing::info!("SMTP listening on :{}", config.smtp_port);
        tracing::info!("SMTP submission on :{}", config.smtp_submission_port);
        tracing::info!("IMAP listening on :{}", config.imap_port);
        tracing::info!("HTTP webmail on :{}", config.http_port);

        // Prune expired sessions every hour so the database doesn't grow unboundedly.
        let reaper = Arc::clone(&store);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                match reaper.prune_expired_sessions() {
                    Ok(n) if n > 0 => tracing::debug!(n, "pruned expired sessions"),
                    Err(e) => tracing::warn!("session reaper: {e}"),
                    _ => {}
                }
                match reaper.prune_expired_partial_sessions() {
                    Ok(n) if n > 0 => tracing::debug!(n, "pruned expired partial sessions"),
                    Err(e) => tracing::warn!("partial session reaper: {e}"),
                    _ => {}
                }
            }
        });

        tokio::try_join!(
            smtp.listen(),
            imap.listen(),
            async {
                axum::serve(http_listener, app).await.map_err(anyhow::Error::from)
            },
        )?;

        Ok(())
    }
}
