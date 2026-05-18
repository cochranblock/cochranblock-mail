use crate::config::Config;
use crate::smtp::SmtpListener;
use crate::imap::ImapListener;
use crate::store::MailStore;
use std::sync::Arc;

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

        tracing::info!("SMTP listening on :{}", config.smtp_port);
        tracing::info!("SMTP submission on :{}", config.smtp_submission_port);
        tracing::info!("IMAP listening on :{}", config.imap_port);

        tokio::try_join!(
            smtp.listen(),
            imap.listen(),
        )?;

        Ok(())
    }
}
