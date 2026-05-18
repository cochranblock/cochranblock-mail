use clap::Parser;
use cochranblock_mail::{config::Config, server::Server};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Parser)]
#[command(name = "cochranblock-mail", about = "Sovereign mail server for cochranblock.org")]
struct Args {
    #[arg(long, default_value = ".env")]
    env: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    dotenvy::from_filename(&args.env).ok();

    fmt().with_env_filter(EnvFilter::from_default_env()).init();

    let config = Config::from_env()?;
    tracing::info!(
        smtp_port = config.smtp_port,
        imap_port = config.imap_port,
        domain = %config.domain,
        "cochranblock-mail starting"
    );

    Server::new(config).run().await
}
