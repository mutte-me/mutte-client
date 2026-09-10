mod app;
mod attachment_picker;
mod conversation_layout;
mod file_preview;
mod notifications;
mod platform;
mod session_control;
mod terminal_session;
mod theme;
mod wordmark;

use std::{
    io::{self, Write},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use app::{App, Connection};
use clap::{Parser, ValueEnum};
use mutte_client::{
    Client, DeviceApprovalOutcome, DeviceAuthorizationHandoffLost, EmailAuthorizationInput,
    EmailFinishOutcome, EmailStartOutcome, RelayRejection, Session, authentication_required,
    device_authorization_handoff_lost, request_conflicted,
};
use mutte_core::Device;
use mutte_protocol::{DeviceAuthorization, Profile, error_code};
use mutte_store::{
    StoredSession, Vault, VaultKey, migrate_legacy_config, terminal_legacy_local_identity_path,
    terminal_local_identity_path,
};
use platform::{device_name, open_browser};
use secrecy::SecretString;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum AuthMode {
    /// Open the existing passkey and email authorization page.
    #[default]
    Browser,
    /// Complete sign-up or sign-in with an emailed one-time link in this terminal.
    Email,
}

#[derive(Debug, Parser)]
#[command(version, about = "A quiet, encrypted, terminal-first chat")]
struct Args {
    #[arg(long, env = "MUTTE_SERVER", default_value = "https://api.mutte.me")]
    server: Url,
    /// Open the visual shell without linking an account or device.
    #[arg(long)]
    demo: bool,
    /// Privacy-safe new-message alerts. Numeric unread counts are always shown.
    #[arg(long, value_enum)]
    notifications: Option<notifications::NotificationMode>,
    /// Print browser-assisted authorization links instead of opening them.
    #[arg(long)]
    no_browser: bool,
    /// Choose how a newly unlinked terminal is authorized.
    #[arg(long, value_enum, default_value_t)]
    auth: AuthMode,
    /// Name shown to the account when this terminal requests authorization.
    #[arg(long, env = "MUTTE_DEVICE_NAME")]
    device_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.demo {
        let mut terminal = terminal_session::TerminalSession::new()?;
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
        .with_notifications(args.notifications)
        .run(terminal.terminal(), None)
        .await;
        drop(terminal);
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
    let server = args.server.clone();
    let device_path = terminal_local_identity_path(&server)
        .context("scope the encrypted MLS identity to the relay origin")?;
    let mut legacy_vault =
        Vault::open(&message_storage_key).context("open encrypted local message vault")?;
    legacy_vault
        .migrate_legacy_conversations()
        .context("migrate legacy conversation metadata into encrypted vault")?;
    legacy_vault
        .migrate_legacy_session()
        .context("migrate legacy session into encrypted vault")?;
    let legacy_device_path =
        terminal_legacy_local_identity_path().context("locate the released terminal identity")?;
    copy_released_identity_if_bound(
        &legacy_vault,
        &server,
        &legacy_device_path,
        &device_path,
        &device_storage_key,
    )
    .context("copy the relay-bound released terminal identity")?;
    let mut device = Device::load_or_create_at(&device_path, &device_storage_key)
        .context("initialize encrypted local MLS identity")?;
    session_control::finish(
        &server,
        &mut device,
        &device_path,
        &device_storage_key,
        &message_storage_key,
        &mut legacy_vault,
    )
    .context("finish local sign-out before loading any saved sign-in")?;
    let api = Client::new(args.server)?;
    let active_vault = Vault::load_active_terminal(&server, device.id(), &message_storage_key)
        .context("load relay-scoped terminal vault")?;
    let stored_session = active_vault
        .as_ref()
        .and_then(|vault| vault.load_session(&server))
        .or_else(|| legacy_vault.load_session(&server));
    let session = match stored_session {
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
                Err(error) if authentication_required(&error) => {
                    rotate_local_device(&mut device, &device_path, &device_storage_key)
                        .context("replace the expired relay-scoped device identity")?;
                    authorize(
                        &api,
                        &mut device,
                        &device_path,
                        &device_storage_key,
                        args.auth,
                        args.no_browser,
                        args.device_name.as_deref(),
                    )
                    .await?
                }
                Err(error) => {
                    return Err(error)
                        .context("validate the saved session; local credentials were preserved");
                }
            }
        }
        _ => {
            authorize(
                &api,
                &mut device,
                &device_path,
                &device_storage_key,
                args.auth,
                args.no_browser,
                args.device_name.as_deref(),
            )
            .await?
        }
    };
    let mut vault = match active_vault {
        Some(vault)
            if vault.load_session(&server).is_some_and(|stored| {
                stored.device_id == session.device_id && stored.profile.id == session.profile.id
            }) =>
        {
            vault
        }
        _ => match legacy_vault
            .migrate_legacy_terminal_if_bound(&server, session.profile.id, session.device_id)
            .context("migrate released terminal history into relay-scoped vault")?
        {
            Some(vault) => vault,
            None => Vault::open_terminal_scoped(
                &server,
                session.profile.id,
                session.device_id,
                &message_storage_key,
            )
            .context("open relay-scoped terminal message vault")?,
        },
    };
    vault.save_session(
        &server,
        &StoredSession {
            access_token: session.access_token.clone(),
            device_id: session.device_id,
            profile: session.profile.clone(),
        },
    )?;
    vault
        .activate_terminal_scope(&server, session.profile.id, session.device_id)
        .context("remember active relay-scoped terminal vault")?;
    // Every online start advertises a fresh pool of one-time KeyPackages so a
    // trusted account device can add this terminal to several existing groups.
    // Claimed older packages remain decryptable because their private material
    // is retained locally.
    api.publish_key_packages(&session, device.key_packages(32)?)
        .await
        .context("publish fresh device key package pool")?;

    let app =
        App::connected(session.profile.clone(), vault)?.with_notifications(args.notifications);
    let mut terminal = terminal_session::TerminalSession::new()?;
    let result = app
        .run(
            terminal.terminal(),
            Some(Connection {
                api: &api,
                session: &session,
                device: &device,
                open_browser: !args.no_browser,
            }),
        )
        .await;
    drop(terminal);
    session_control::finish(
        &server,
        &mut device,
        &device_path,
        &device_storage_key,
        &message_storage_key,
        &mut legacy_vault,
    )
    .context("sign-out is unfinished; the next launch will finish it before opening Mutte")?;
    result
}

async fn authorize(
    api: &Client,
    device: &mut Device,
    device_path: &Path,
    device_storage_key: &[u8; 32],
    auth_mode: AuthMode,
    no_browser: bool,
    requested_device_name: Option<&str>,
) -> Result<Session> {
    let requested_name = device_name(requested_device_name)?;
    loop {
        let authorization = match api
            .start_device(device.id(), requested_name.clone(), device.key_package()?)
            .await
        {
            Ok(authorization) => authorization,
            Err(error) if request_conflicted(&error) => {
                rotate_local_device(device, device_path, device_storage_key)
                    .context("replace an already-linked local device identity")?;
                api.start_device(device.id(), requested_name.clone(), device.key_package()?)
                    .await
                    .context("start device authorization with the replacement identity")?
            }
            Err(error) => {
                return Err(error).context("start device authorization; is mutte-relay running?");
            }
        };
        println!();
        println!("  Mutte · LINK THIS TERMINAL");
        println!();
        let approval = match auth_mode {
            AuthMode::Browser => {
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
            AuthMode::Email => {
                println!(
                    "  device code  {}",
                    authorization.device_id.to_string()[..8].to_ascii_uppercase()
                );
                let verification_url = Url::parse(&authorization.verification_url)
                    .context("relay returned an invalid verification URL")?;
                authorize_with_email(api, &authorization, &verification_url).await
            }
        };
        match approval {
            Ok(session) => return Ok(session),
            Err(error) if device_authorization_handoff_lost(&error) => {
                eprintln!(
                    "  Approval completed, but its one-time session handoff was already consumed."
                );
                eprintln!("  Replacing this unusable device identity and starting a fresh link.");
                rotate_local_device(device, device_path, device_storage_key)
                    .context("replace identity after a lost one-time session handoff")?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn rotate_local_device(
    device: &mut Device,
    device_path: &Path,
    device_storage_key: &[u8; 32],
) -> Result<()> {
    Device::retire_at(device_path).context("retire encrypted local MLS identity")?;
    *device = Device::load_or_create_at(device_path, device_storage_key)
        .context("create replacement encrypted local MLS identity")?;
    Ok(())
}

async fn authorize_with_email(
    api: &Client,
    authorization: &DeviceAuthorization,
    verification_url: &Url,
) -> Result<Session> {
    println!("  Continue without a browser using a one-time email link.");
    println!("  Existing email accounts must use their exact handle.");
    println!();

    loop {
        ensure_authorization_live(authorization)?;
        let input = prompt_email_authorization_input()?;
        if !request_email_link(api, authorization, &input).await? {
            continue;
        }

        loop {
            ensure_authorization_live(authorization)?;
            match prompt_magic_link_action(verification_url)? {
                action @ (EmailPromptAction::EditDetails | EmailPromptAction::CheckApproval) => {
                    let edit_details = matches!(action, EmailPromptAction::EditDetails);
                    match check_email_prompt_approval(api, authorization, edit_details).await? {
                        EmailPromptOutcome::Approved(session) => return Ok(session),
                        EmailPromptOutcome::EditDetails => {
                            println!("  Update the account details and request another link.");
                            println!();
                            break;
                        }
                        EmailPromptOutcome::Continue => {}
                    }
                }
                EmailPromptAction::Token(token) => {
                    if let Some(session) =
                        finish_email_authorization(api, authorization, &token).await?
                    {
                        return Ok(session);
                    }
                }
            }
        }
    }
}

enum EmailPromptOutcome {
    Approved(Session),
    EditDetails,
    Continue,
}

async fn check_email_prompt_approval(
    api: &Client,
    authorization: &DeviceAuthorization,
    edit_details: bool,
) -> Result<EmailPromptOutcome> {
    // An email link may have been opened in a browser while the hidden input
    // prompt was waiting. Collect that one-time handoff before requesting a
    // replacement link; never discard its session or run a competing poll.
    match api.check_approval(authorization).await? {
        DeviceApprovalOutcome::Approved(session) => Ok(EmailPromptOutcome::Approved(session)),
        DeviceApprovalOutcome::ApprovedSessionUnavailable => {
            Err(DeviceAuthorizationHandoffLost.into())
        }
        DeviceApprovalOutcome::Expired => bail!("device authorization expired"),
        DeviceApprovalOutcome::Pending if edit_details => Ok(EmailPromptOutcome::EditDetails),
        DeviceApprovalOutcome::Pending => {
            println!("  This terminal is still waiting for approval.");
            println!("  Paste the one-time link, or type done after approving it in a browser.");
            Ok(EmailPromptOutcome::Continue)
        }
        DeviceApprovalOutcome::Ambiguous { .. } => {
            eprintln!("  Device approval could not be confirmed; this link remains open.");
            eprintln!("  Type done to retry before requesting another email.");
            Ok(EmailPromptOutcome::Continue)
        }
        DeviceApprovalOutcome::RateLimited { retry_after } => {
            wait_for_rate_limit(authorization, retry_after, "check device approval").await?;
            println!("  Type done to check approval again.");
            Ok(EmailPromptOutcome::Continue)
        }
        DeviceApprovalOutcome::Rejected(rejection) => {
            Err(rejection_error("check device authorization", &rejection))
        }
    }
}

fn prompt_email_authorization_input() -> Result<EmailAuthorizationInput> {
    let handle = prompt_handle()?;
    let display_name = prompt_bounded(
        "  display name (new accounts; Enter to use handle): ",
        48,
        true,
    )?;
    let display_name = if display_name.is_empty() {
        handle.clone()
    } else {
        display_name
    };
    let bio = prompt_bounded("  bio (new accounts; optional): ", 160, true)?;
    let email = prompt_required("  email: ")?;
    Ok(EmailAuthorizationInput {
        handle,
        display_name,
        bio,
        email,
    })
}

async fn request_email_link(
    api: &Client,
    authorization: &DeviceAuthorization,
    input: &EmailAuthorizationInput,
) -> Result<bool> {
    loop {
        ensure_authorization_live(authorization)?;
        match api.start_email(authorization.device_id, input).await? {
            EmailStartOutcome::LinkSent => {
                println!();
                println!("  Check your email and copy the full one-time link without opening it.");
                println!("  Already approved it in a browser? Type done below to finish.");
                println!("  If no link arrives, press Enter to correct details and resend.");
                return Ok(true);
            }
            EmailStartOutcome::RateLimited { retry_after } => {
                wait_for_rate_limit(authorization, retry_after, "request another email link")
                    .await?;
            }
            EmailStartOutcome::Rejected(rejection)
                if rejection.status == 400 && rejection.code == error_code::BAD_REQUEST =>
            {
                eprintln!("  The relay rejected those details: {}", rejection.message);
                eprintln!("  Correct them without restarting this device link.");
                println!();
                return Ok(false);
            }
            EmailStartOutcome::Rejected(rejection) => {
                return Err(rejection_error("request email authorization", &rejection));
            }
            EmailStartOutcome::Ambiguous { reason } => {
                eprintln!("  Email delivery could not be confirmed: {reason}");
                eprintln!(
                    "  Keep this device link open. Paste a link if it arrives, or press Enter to edit and resend."
                );
                return Ok(true);
            }
        }
    }
}

async fn finish_email_authorization(
    api: &Client,
    authorization: &DeviceAuthorization,
    token: &SecretString,
) -> Result<Option<Session>> {
    loop {
        ensure_authorization_live(authorization)?;
        match api.finish_email(token).await? {
            EmailFinishOutcome::Confirmed => {
                println!("  Email confirmed; completing terminal link…");
                return api.wait_for_approval(authorization).await.map(Some);
            }
            EmailFinishOutcome::RateLimited { retry_after } => {
                wait_for_rate_limit(authorization, retry_after, "verify the email link").await?;
            }
            EmailFinishOutcome::Rejected(rejection)
                if rejection.status == 400 && rejection.code == error_code::BAD_REQUEST =>
            {
                match recover_ambiguous_approval(api, authorization).await? {
                    ApprovalRecovery::Approved(session) => return Ok(Some(session)),
                    ApprovalRecovery::SessionUnavailable => {
                        return Err(DeviceAuthorizationHandoffLost.into());
                    }
                    ApprovalRecovery::Expired => bail!("device authorization expired"),
                    ApprovalRecovery::Pending => {
                        eprintln!(
                            "  That link was rejected; this device is still waiting for approval."
                        );
                    }
                    ApprovalRecovery::Unconfirmed => {
                        eprintln!(
                            "  That link was rejected and device approval could not be confirmed yet."
                        );
                    }
                }
                eprintln!(
                    "  Paste a fresh link, retry the same link if its result was uncertain, or press Enter to edit and resend."
                );
                return Ok(None);
            }
            EmailFinishOutcome::Rejected(rejection) => {
                return Err(rejection_error("verify email authorization", &rejection));
            }
            EmailFinishOutcome::Ambiguous { reason } => {
                eprintln!("  Email verification response was interrupted: {reason}");
                match recover_ambiguous_approval(api, authorization).await? {
                    ApprovalRecovery::Approved(session) => return Ok(Some(session)),
                    ApprovalRecovery::SessionUnavailable => {
                        return Err(DeviceAuthorizationHandoffLost.into());
                    }
                    ApprovalRecovery::Expired => bail!("device authorization expired"),
                    ApprovalRecovery::Pending => {
                        eprintln!("  The protected device status is still pending.");
                    }
                    ApprovalRecovery::Unconfirmed => {
                        eprintln!(
                            "  The relay could not confirm device status during the recovery check."
                        );
                    }
                }
                eprintln!(
                    "  The same device link remains open; paste the link again or press Enter to edit and resend."
                );
                return Ok(None);
            }
        }
    }
}

enum ApprovalRecovery {
    Pending,
    Approved(Session),
    SessionUnavailable,
    Expired,
    Unconfirmed,
}

async fn recover_ambiguous_approval(
    api: &Client,
    authorization: &DeviceAuthorization,
) -> Result<ApprovalRecovery> {
    const GRACE: Duration = Duration::from_secs(4);
    const POLL_INTERVAL: Duration = Duration::from_secs(1);

    let deadline = tokio::time::Instant::now() + GRACE;
    let mut saw_pending = false;
    loop {
        ensure_authorization_live(authorization)?;
        match api.check_approval(authorization).await? {
            DeviceApprovalOutcome::Pending => saw_pending = true,
            DeviceApprovalOutcome::Approved(session) => {
                return Ok(ApprovalRecovery::Approved(session));
            }
            DeviceApprovalOutcome::ApprovedSessionUnavailable => {
                return Ok(ApprovalRecovery::SessionUnavailable);
            }
            DeviceApprovalOutcome::Expired => return Ok(ApprovalRecovery::Expired),
            DeviceApprovalOutcome::Rejected(rejection) => {
                return Err(rejection_error("check device authorization", &rejection));
            }
            DeviceApprovalOutcome::RateLimited { retry_after } => {
                wait_for_rate_limit(authorization, retry_after, "check device approval").await?;
                return Ok(if saw_pending {
                    ApprovalRecovery::Pending
                } else {
                    ApprovalRecovery::Unconfirmed
                });
            }
            DeviceApprovalOutcome::Ambiguous { .. } => {}
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(if saw_pending {
                ApprovalRecovery::Pending
            } else {
                ApprovalRecovery::Unconfirmed
            });
        }
        tokio::time::sleep(POLL_INTERVAL.min(deadline - now)).await;
    }
}

fn ensure_authorization_live(authorization: &DeviceAuthorization) -> Result<()> {
    if chrono::Utc::now() >= authorization.expires_at {
        bail!("device authorization expired");
    }
    Ok(())
}

async fn wait_for_rate_limit(
    authorization: &DeviceAuthorization,
    delay: Duration,
    operation: &str,
) -> Result<()> {
    let remaining = (authorization.expires_at - chrono::Utc::now())
        .to_std()
        .unwrap_or_default();
    if remaining.is_zero() || delay >= remaining {
        bail!("device authorization expires before it is safe to {operation}");
    }
    let seconds = delay
        .as_secs()
        .saturating_add(u64::from(delay.subsec_nanos() > 0));
    println!("  Rate limited; retrying in {seconds}s…");
    tokio::time::sleep(delay).await;
    Ok(())
}

fn rejection_error(operation: &str, rejection: &RelayRejection) -> anyhow::Error {
    anyhow::anyhow!(
        "{operation}: {} ({}; HTTP {})",
        rejection.message,
        rejection.code,
        rejection.status
    )
}

fn prompt_handle() -> Result<String> {
    loop {
        let value = prompt_required("  handle: ")?;
        match normalize_handle(&value) {
            Ok(handle) => return Ok(handle),
            Err(error) => eprintln!("  {error}"),
        }
    }
}

fn prompt_required(label: &str) -> Result<String> {
    loop {
        let value = prompt_line(label)?;
        if !value.is_empty() {
            return Ok(value);
        }
        eprintln!("  a value is required");
    }
}

fn prompt_bounded(label: &str, maximum_characters: usize, optional: bool) -> Result<String> {
    loop {
        let value = prompt_line(label)?;
        if value.is_empty() && !optional {
            eprintln!("  a value is required");
        } else if value.chars().count() > maximum_characters {
            eprintln!("  use at most {maximum_characters} characters");
        } else {
            return Ok(value);
        }
    }
}

fn prompt_line(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush().context("show authorization prompt")?;
    let mut value = String::new();
    if io::stdin()
        .read_line(&mut value)
        .context("read authorization input")?
        == 0
    {
        bail!("authorization input ended before completion");
    }
    Ok(value.trim().to_owned())
}

enum EmailPromptAction {
    Token(SecretString),
    EditDetails,
    CheckApproval,
}

fn prompt_magic_link_action(verification_url: &Url) -> Result<EmailPromptAction> {
    loop {
        let raw = Zeroizing::new(
            rpassword::prompt_password(
                "  paste one-time link (hidden; done checks approval; Enter edits details): ",
            )
            .context("read one-time email link")?,
        );
        match parse_email_prompt_action(&raw, verification_url) {
            Ok(action) => return Ok(action),
            Err(error) => eprintln!("  {error}"),
        }
    }
}

fn parse_email_prompt_action(value: &str, verification_url: &Url) -> Result<EmailPromptAction> {
    if value.trim().is_empty() || value.trim().eq_ignore_ascii_case("edit") {
        return Ok(EmailPromptAction::EditDetails);
    }
    if value.trim().eq_ignore_ascii_case("done") {
        return Ok(EmailPromptAction::CheckApproval);
    }
    parse_magic_link_token(value, verification_url).map(EmailPromptAction::Token)
}

fn parse_magic_link_token(value: &str, verification_url: &Url) -> Result<SecretString> {
    let value = value.trim();
    if value.is_empty() {
        bail!("paste the full one-time link or its token");
    }

    let token = if value.contains("://") {
        let (link, fragment) = value
            .split_once('#')
            .context("one-time link is missing its token")?;
        let url = Url::parse(link).context("one-time link is not a valid URL")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.origin() != verification_url.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/auth/email/verify"
            || url.query().is_some()
        {
            bail!("paste a Mutte account authorization link");
        }
        fragment
            .strip_prefix("token=")
            .filter(|token| !token.contains('&'))
            .context("one-time link is missing its token")?
    } else {
        value.strip_prefix("token=").unwrap_or(value)
    };

    if !(40..=128).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("one-time email token has an invalid format");
    }
    Ok(SecretString::from(token.to_owned()))
}

fn normalize_handle(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let handle = trimmed
        .strip_prefix('@')
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if !(3..=24).contains(&handle.len())
        || !handle.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
    {
        bail!("handle must be 3–24 lowercase letters, numbers, or underscores");
    }
    Ok(handle)
}

fn copy_released_identity_if_bound(
    legacy_vault: &Vault,
    server: &Url,
    legacy_device_path: &Path,
    scoped_device_path: &Path,
    device_storage_key: &[u8; 32],
) -> Result<bool> {
    if scoped_device_path.exists() {
        return Ok(false);
    }
    let Some(stored) = legacy_vault.load_session(server) else {
        return Ok(false);
    };
    Device::copy_to_if_device_id_matches(
        legacy_device_path,
        scoped_device_path,
        device_storage_key,
        stored.device_id,
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use secrecy::ExposeSecret;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    fn test_token() -> String {
        "aB0_-".repeat(8) + "xyz"
    }

    fn verification_url() -> Url {
        Url::parse("https://api.mutte.me/auth?device=2fbb20f1-5992-4b08-811e-39a66ecf68dc").unwrap()
    }

    #[test]
    fn browser_authorization_remains_the_cli_default() {
        let args = Args::try_parse_from(["mutte"]).unwrap();
        assert_eq!(args.auth, AuthMode::Browser);
        assert!(!args.no_browser);

        let args = Args::try_parse_from(["mutte", "--no-browser"]).unwrap();
        assert_eq!(args.auth, AuthMode::Browser);
        assert!(args.no_browser);

        let args = Args::try_parse_from(["mutte", "--auth", "email"]).unwrap();
        assert_eq!(args.auth, AuthMode::Email);

        let args = Args::try_parse_from(["mutte", "--auth", "email", "--no-browser"]).unwrap();
        assert_eq!(args.auth, AuthMode::Email);
        assert!(args.no_browser);
    }

    #[test]
    fn magic_link_parser_accepts_full_links_and_raw_tokens() {
        let token = test_token();
        let verification_url = verification_url();
        let raw = parse_magic_link_token(&token, &verification_url).unwrap();
        assert_eq!(raw.expose_secret(), &token);

        let prefixed =
            parse_magic_link_token(&format!("token={token}"), &verification_url).unwrap();
        assert_eq!(prefixed.expose_secret(), &token);

        let link = format!("https://api.mutte.me/auth/email/verify#token={token}");
        let parsed = parse_magic_link_token(&link, &verification_url).unwrap();
        assert_eq!(parsed.expose_secret(), &token);
    }

    #[test]
    fn empty_or_explicit_edit_input_keeps_the_pending_device_link() {
        assert!(matches!(
            parse_email_prompt_action("", &verification_url()).unwrap(),
            EmailPromptAction::EditDetails
        ));
        assert!(matches!(
            parse_email_prompt_action("  EDIT  ", &verification_url()).unwrap(),
            EmailPromptAction::EditDetails
        ));
    }

    #[test]
    fn done_checks_browser_approval_without_requiring_the_email_token() {
        for input in ["done", "  DONE  "] {
            assert!(matches!(
                parse_email_prompt_action(input, &verification_url()).unwrap(),
                EmailPromptAction::CheckApproval
            ));
        }
        assert!(parse_email_prompt_action("not done", &verification_url()).is_err());
    }

    // Every request to this fixture must be the device-secret-protected GET.
    // It rejects accidental email resends/finishes and caps each test in time.
    async fn approval_fixture(
        body: &'static str,
    ) -> (Client, DeviceAuthorization, tokio::task::JoinHandle<()>) {
        approval_response_fixture(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ))
        .await
    }

    async fn approval_response_fixture(
        response: String,
    ) -> (Client, DeviceAuthorization, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let authorization = DeviceAuthorization {
            device_id: Uuid::new_v4(),
            device_secret: "test-device-secret".into(),
            verification_url: format!("http://{address}/auth"),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        };
        let expected_path = format!("GET /v1/devices/{} HTTP/1.1\r\n", authorization.device_id);
        let server = tokio::spawn(async move {
            let mut request_count = 0;
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                request_count += 1;
                assert_eq!(
                    request_count, 1,
                    "a prompt action must check the handoff once"
                );
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0; 1024];
                    let count = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(count, 0, "request ended before its headers");
                    request.extend_from_slice(&chunk[..count]);
                    if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        break;
                    }
                    assert!(request.len() < 8192, "unexpectedly large test request");
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with(&expected_path));
                assert!(request.contains("x-mutte-device-secret: test-device-secret\r\n"));
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (
            Client::new(Url::parse(&format!("http://{address}/")).unwrap()).unwrap(),
            authorization,
            server,
        )
    }

    async fn stop_approval_fixture(server: tokio::task::JoinHandle<()>) {
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn browser_approved_session_is_collected_before_check_or_edit() {
        for edit_details in [false, true] {
            let (api, authorization, server) = approval_fixture(
                r#"{"state":"approved","access_token":"test-session","profile":{"id":"00000000-0000-0000-0000-000000000001","handle":"terminal_test","display_name":"Terminal test","bio":"","status":"quiet"}}"#,
            )
            .await;
            let outcome = tokio::time::timeout(
                Duration::from_secs(8),
                check_email_prompt_approval(&api, &authorization, edit_details),
            )
            .await
            .unwrap()
            .unwrap();
            let EmailPromptOutcome::Approved(session) = outcome else {
                panic!("the approved handoff must not be discarded to edit details");
            };
            assert_eq!(session.device_id, authorization.device_id);
            assert_eq!(session.profile.handle, "terminal_test");
            assert_eq!(session.access_token.expose_secret(), "test-session");
            stop_approval_fixture(server).await;
        }
    }

    #[tokio::test]
    async fn pending_browser_check_keeps_prompt_and_pending_edit_can_change_details() {
        for edit_details in [false, true] {
            let (api, authorization, server) = approval_fixture(r#"{"state":"pending"}"#).await;
            let outcome = tokio::time::timeout(
                Duration::from_secs(8),
                check_email_prompt_approval(&api, &authorization, edit_details),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                matches!(outcome, EmailPromptOutcome::EditDetails),
                edit_details
            );
            stop_approval_fixture(server).await;
        }
    }

    #[tokio::test]
    async fn unconfirmed_browser_check_never_starts_edit_or_resend() {
        let (api, authorization, server) = approval_fixture("not json").await;
        let outcome = tokio::time::timeout(
            Duration::from_secs(8),
            check_email_prompt_approval(&api, &authorization, true),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(outcome, EmailPromptOutcome::Continue));
        stop_approval_fixture(server).await;
    }

    #[tokio::test]
    async fn browser_approval_without_session_uses_existing_lost_handoff_recovery() {
        let (api, authorization, server) = approval_fixture(r#"{"state":"approved"}"#).await;
        let error = check_email_prompt_approval(&api, &authorization, true)
            .await
            .err()
            .expect("an already-consumed handoff cannot link this terminal");
        assert!(device_authorization_handoff_lost(&error));
        stop_approval_fixture(server).await;
    }

    #[tokio::test]
    async fn expired_browser_approval_cannot_edit_or_resend() {
        let (api, authorization, server) = approval_fixture(r#"{"state":"expired"}"#).await;
        let error = check_email_prompt_approval(&api, &authorization, true)
            .await
            .err()
            .expect("expired authorization must not request another email");
        assert_eq!(error.to_string(), "device authorization expired");
        stop_approval_fixture(server).await;
    }

    #[tokio::test]
    async fn rate_limited_browser_check_waits_and_keeps_prompt_without_resend() {
        let (api, authorization, server) = approval_response_fixture(
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        let started = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(8),
            check_email_prompt_approval(&api, &authorization, true),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(outcome, EmailPromptOutcome::Continue));
        assert!(started.elapsed() >= Duration::from_secs(1));
        stop_approval_fixture(server).await;
    }

    #[tokio::test]
    async fn rejected_browser_check_cannot_edit_or_resend() {
        let (api, authorization, server) = approval_response_fixture(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        let error = check_email_prompt_approval(&api, &authorization, true)
            .await
            .err()
            .expect("rejected authorization must not request another email");
        assert!(error.to_string().contains("HTTP 401"));
        stop_approval_fixture(server).await;
    }

    #[test]
    fn magic_link_parser_rejects_other_links_and_malformed_tokens() {
        let token = test_token();
        let verification_url = verification_url();
        assert!(parse_magic_link_token("too-short", &verification_url).is_err());
        assert!(parse_magic_link_token(&format!("{token}.invalid"), &verification_url).is_err());
        assert!(
            parse_magic_link_token(
                &format!("https://api.mutte.me/auth/revoke/email/verify#token={token}"),
                &verification_url
            )
            .is_err()
        );
        assert!(
            parse_magic_link_token("https://api.mutte.me/auth/email/verify", &verification_url,)
                .is_err()
        );
        assert!(
            parse_magic_link_token(
                &format!("https://other.example/auth/email/verify#token={token}"),
                &verification_url,
            )
            .is_err()
        );
        assert!(
            parse_magic_link_token(
                &format!("https://api.mutte.me/auth/email/verify?token={token}#token={token}"),
                &verification_url
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_handle_normalization_matches_the_relay() {
        assert_eq!(normalize_handle("  @Night_Owl  ").unwrap(), "night_owl");
        assert!(normalize_handle("@@night_owl").is_err());
        assert!(normalize_handle("no").is_err());
        assert!(normalize_handle("not/a/handle").is_err());
    }

    #[test]
    fn released_identity_copy_requires_the_encrypted_vault_origin_binding() {
        let root =
            std::env::temp_dir().join(format!("mutte-terminal-bound-identity-{}", Uuid::new_v4()));
        let identity_key = [91u8; 32];
        let vault_key = [92u8; 32];
        let legacy_device_path = root.join("device.json");
        let production_target = root.join("production").join("device.json");
        let staging_target = root.join("staging").join("device.json");
        let production = Url::parse("https://api.mutte.me").unwrap();
        let staging = Url::parse("https://api-staging.mutte.me").unwrap();
        let device = Device::load_or_create_at(&legacy_device_path, &identity_key).unwrap();
        let mut vault = Vault::open_at(root.join("vault.json"), &vault_key).unwrap();
        vault
            .save_session(
                &production,
                &StoredSession {
                    access_token: SecretString::from("released-token"),
                    device_id: device.id(),
                    profile: Profile {
                        id: Uuid::new_v4(),
                        handle: "released_user".into(),
                        display_name: "Released User".into(),
                        bio: String::new(),
                        status: "quiet".into(),
                    },
                },
            )
            .unwrap();

        assert!(
            !copy_released_identity_if_bound(
                &vault,
                &staging,
                &legacy_device_path,
                &staging_target,
                &identity_key,
            )
            .unwrap()
        );
        assert!(!staging_target.exists());
        assert!(
            copy_released_identity_if_bound(
                &vault,
                &production,
                &legacy_device_path,
                &production_target,
                &identity_key,
            )
            .unwrap()
        );
        let copied = Device::load_or_create_at(&production_target, &identity_key).unwrap();
        assert_eq!(copied.id(), device.id());
        drop(copied);
        drop(device);
        drop(vault);
        std::fs::remove_dir_all(root).unwrap();
    }
}
