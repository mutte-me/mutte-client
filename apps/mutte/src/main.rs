mod app;
mod platform;
mod theme;

use anyhow::{Context, Result};
use app::{App, Connection};
use clap::Parser;
use mutte_client::{Client, Session};
use mutte_core::Device;
use mutte_protocol::Profile;
use mutte_store::{StoredSession, Vault, VaultKey, migrate_legacy_config};
use platform::{device_name, open_browser};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(version, about = "A quiet, encrypted, terminal-first chat")]
struct Args {
    #[arg(long, env = "MUTTE_SERVER", default_value = "https://api.mutte.me")]
    server: Url,
    /// Open the visual shell without linking a passkey.
    #[arg(long)]
    demo: bool,
    /// Print the verification link without opening a browser.
    #[arg(long)]
    no_browser: bool,
    /// Name shown to the account when this terminal requests authorization.
    #[arg(long, env = "MUTTE_DEVICE_NAME")]
    device_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.demo {
        let mut terminal = ratatui::try_init()?;
        let result = App::new(
            Profile {
                id: Uuid::nil(),
                handle: "nightowl".into(),
                display_name: "Night Owl".into(),
                bio: "building quietly after midnight".into(),
                status: "🌙".into(),
            },
            true,
        )
        .run(&mut terminal, None)
        .await;
        ratatui::restore();
        return result;
    }

    migrate_legacy_config().context("migrate legacy OMT local data to Mutte")?;
    let vault_key = VaultKey::load_or_create().context("unlock encrypted local vault")?;
    let device_storage_key = vault_key
        .device_storage_key()
        .context("derive encrypted MLS storage key")?;
    let message_storage_key = vault_key
        .message_storage_key()
        .context("derive encrypted message storage key")?;
    let device = Device::load_or_create(&device_storage_key)
        .context("initialize encrypted local MLS identity")?;
    let mut vault =
        Vault::open(&message_storage_key).context("open encrypted local message vault")?;
    vault
        .migrate_legacy_conversations()
        .context("migrate legacy conversation metadata into encrypted vault")?;
    vault
        .migrate_legacy_session()
        .context("migrate legacy session into encrypted vault")?;
    let server = args.server.clone();
    let api = Client::new(args.server)?;
    let session = match vault.load_session(&server) {
        Some(stored) if stored.device_id == device.id() => {
            let mut session = Session {
                access_token: stored.access_token,
                device_id: stored.device_id,
                profile: stored.profile,
            };
            match api.validate(&session).await {
                Ok(profile) => {
                    session.profile = profile;
                    session
                }
                Err(_) => {
                    authorize(&api, &device, args.no_browser, args.device_name.as_deref()).await?
                }
            }
        }
        _ => authorize(&api, &device, args.no_browser, args.device_name.as_deref()).await?,
    };
    vault.save_session(
        &server,
        &StoredSession {
            access_token: session.access_token.clone(),
            device_id: session.device_id,
            profile: session.profile.clone(),
        },
    )?;
    // Every online start advertises a fresh pool of one-time KeyPackages so a
    // trusted account device can add this terminal to several existing groups.
    // Claimed older packages remain decryptable because their private material
    // is retained locally.
    api.publish_key_packages(&session, device.key_packages(32)?)
        .await
        .context("publish fresh device key package pool")?;

    let app = App::connected(session.profile.clone(), vault)?;
    let mut terminal = ratatui::try_init()?;
    let result = app
        .run(
            &mut terminal,
            Some(Connection {
                api: &api,
                session: &session,
                device: &device,
                open_browser: !args.no_browser,
            }),
        )
        .await;
    ratatui::restore();
    result
}

async fn authorize(
    api: &Client,
    device: &Device,
    no_browser: bool,
    requested_device_name: Option<&str>,
) -> Result<Session> {
    let authorization = api
        .start_device(
            device.id(),
            device_name(requested_device_name)?,
            device.key_package()?,
        )
        .await
        .context("start device authorization; is mutte-relay running?")?;
    println!();
    println!("  Mutte · LINK THIS TERMINAL");
    println!();
    println!("  {}", authorization.verification_url);
    println!();
    println!(
        "  device code  {}",
        authorization.device_id.to_string()[..8].to_ascii_uppercase()
    );
    println!("  waiting for account approval…");
    if !no_browser && let Err(error) = open_browser(&authorization.verification_url) {
        eprintln!("  could not open browser automatically: {error}");
    }
    api.wait_for_approval(&authorization).await
}
