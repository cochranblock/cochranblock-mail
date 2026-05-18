use clap::{Parser, Subcommand};
use cochranblock_mail::{config::Config, server::Server, store::MailStore};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Parser)]
#[command(
    name = "cochranblock-mail",
    about = "Sovereign SMTP/IMAP/HTTP mail server for cochranblock.org"
)]
struct Args {
    #[arg(long, default_value = ".env", help = "Path to .env file")]
    env: String,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run quality gate: clippy + tests + release build check.
    Test,
    /// Manage user accounts.
    User {
        #[command(subcommand)]
        action: UserAction,
    },
}

#[derive(Subcommand)]
enum UserAction {
    /// Create a new user account.
    Add {
        username: String,
        #[arg(long)]
        email: Option<String>,
        /// Provide password on CLI (insecure); omit to be prompted interactively.
        #[arg(long)]
        password: Option<String>,
    },
    /// List all users.
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    dotenvy::from_filename(&args.env).ok();

    fmt().with_env_filter(EnvFilter::from_default_env()).init();

    match args.cmd {
        None => {
            let config = Config::from_env()?;
            tracing::info!(
                smtp = config.smtp_port,
                imap = config.imap_port,
                http = config.http_port,
                domain = %config.domain,
                "cochranblock-mail starting"
            );
            Server::new(config).run().await
        }

        Some(Cmd::Test) => {
            #[cfg(feature = "tests")]
            return cochranblock_mail::run_tests();
            #[cfg(not(feature = "tests"))]
            anyhow::bail!(
                "rebuild with --features tests to use this subcommand, \
                 or run `cochranblock-mail-test` directly"
            )
        }

        Some(Cmd::User { action }) => {
            let config = Config::from_env()?;
            let store = MailStore::open(&config.db_path)?;
            match action {
                UserAction::Add { username, email, password } => {
                    let email = email.unwrap_or_else(|| format!("{}@{}", username, config.domain));
                    let password = match password {
                        Some(p) => p,
                        None => rpassword::prompt_password(format!("Password for {username}: "))
                            .map_err(|e| anyhow::anyhow!("password prompt: {e}"))?,
                    };
                    let user = store.create_user(&username, &email, &password)?;
                    store.ensure_standard_mailboxes(&username)?;
                    println!("Created: {} <{}>", user.username, user.email);
                    println!("TOTP: not enrolled (user prompted on first login)");
                    Ok(())
                }
                UserAction::List => {
                    let users = store.list_users()?;
                    if users.is_empty() {
                        println!("No users.");
                    } else {
                        println!("{:<20} {:<40} TOTP", "USERNAME", "EMAIL");
                        println!("{}", "-".repeat(70));
                        for u in users {
                            println!(
                                "{:<20} {:<40} {}",
                                u.username,
                                u.email,
                                if u.totp_secret.is_some() { "enrolled" } else { "pending" }
                            );
                        }
                    }
                    Ok(())
                }
            }
        }
    }
}
