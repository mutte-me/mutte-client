//! Crash-safe local sign-out. The intent is durable before any credential edit.
use anyhow::{Context, Result, ensure};
use mutte_core::Device;
use mutte_store::Vault;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};
use url::Url;
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
struct Intent {
    version: u8,
    device_id: Uuid,
    account_id: Uuid,
}
fn intent_path(identity: &Path) -> PathBuf {
    identity.with_extension("signout.json")
}
pub fn request(identity: &Path, device_id: Uuid, account_id: Uuid) -> Result<()> {
    let path = intent_path(identity);
    let temporary = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&serde_json::to_vec(&Intent {
        version: 1,
        device_id,
        account_id,
    })?)?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    sync_parent(&path)
}
pub fn pending(identity: &Path) -> Result<Option<(Uuid, Uuid)>> {
    let bytes = match fs::read(intent_path(identity)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let intent: Intent = serde_json::from_slice(&bytes)?;
    ensure!(
        intent.version == 1,
        "Unknown sign-out intent; session remains closed"
    );
    Ok(Some((intent.device_id, intent.account_id)))
}
pub fn finish(
    server: &Url,
    device: &mut Device,
    identity: &Path,
    device_key: &[u8; 32],
    message_key: &[u8; 32],
    legacy: &mut Vault,
) -> Result<()> {
    let Some((old_id, account_id)) = pending(identity)? else {
        return Ok(());
    };
    // Use the intent's explicit account path: an already-cleared session no
    // longer satisfies the active-vault locator's authentication checks.
    let mut vault = Vault::open_terminal_scoped(server, account_id, old_id, message_key)?;
    finish_with_vault(server, device, identity, device_key, &mut vault, legacy)
}
fn finish_with_vault(
    server: &Url,
    device: &mut Device,
    identity: &Path,
    device_key: &[u8; 32],
    vault: &mut Vault,
    legacy: &mut Vault,
) -> Result<()> {
    let Some((old_id, account_id)) = pending(identity)? else {
        return Ok(());
    };
    if let Some(session) = vault.load_session(server) {
        ensure!(
            session.profile.id == account_id && session.device_id == old_id,
            "Sign-out vault binding mismatch"
        );
    }
    vault.clear_session_for(server, old_id)?;
    legacy.clear_session_for(server, old_id)?;
    if device.id() == old_id {
        Device::retire_at(identity).context("retire signed-out identity")?;
        *device = Device::load_or_create_at(identity, device_key)?;
    }
    fs::remove_file(intent_path(identity))?;
    sync_parent(identity)
}
fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path.parent().context("Invalid sign-out path")?)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_sign_out_clears_both_sessions_and_rotates_only_once() {
        let root = std::env::temp_dir().join(format!("mutte-signout-recovery-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let identity = root.join("device.json");
        let mut device = Device::load_or_create_at(&identity, &[3; 32]).unwrap();
        let old_id = device.id();
        let account_id = Uuid::new_v4();
        let server = Url::parse("https://relay.test").unwrap();
        let profile = mutte_protocol::Profile {
            id: account_id,
            handle: "mira".into(),
            display_name: "Mira".into(),
            bio: String::new(),
            status: String::new(),
        };
        let session = mutte_store::StoredSession {
            access_token: secrecy::SecretString::from("local-test-token"),
            device_id: old_id,
            profile,
        };
        let mut vault = Vault::open_at(root.join("vault.json"), &[4; 32]).unwrap();
        let mut legacy = Vault::open_at(root.join("legacy.json"), &[4; 32]).unwrap();
        vault.save_session(&server, &session).unwrap();
        legacy.save_session(&server, &session).unwrap();
        let conversation = Uuid::new_v4();
        vault
            .upsert_conversation(mutte_store::VaultConversation {
                id: conversation,
                peer_handle: "friend".into(),
                unread: 2,
            })
            .unwrap();
        request(&identity, old_id, account_id).unwrap();
        // Simulate termination after the first credential was cleared.
        vault.clear_session_for(&server, old_id).unwrap();
        finish_with_vault(
            &server,
            &mut device,
            &identity,
            &[3; 32],
            &mut vault,
            &mut legacy,
        )
        .unwrap();
        assert!(vault.load_session(&server).is_none());
        assert!(legacy.load_session(&server).is_none());
        assert_eq!(vault.conversations()[0].id, conversation);
        assert_ne!(device.id(), old_id);
        let replacement = device.id();
        // Simulate a crash after rotation but before removing the intent.
        request(&identity, old_id, account_id).unwrap();
        finish_with_vault(
            &server,
            &mut device,
            &identity,
            &[3; 32],
            &mut vault,
            &mut legacy,
        )
        .unwrap();
        assert_eq!(device.id(), replacement);
        assert!(pending(&identity).unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn sign_out_intent_survives_restart_and_unknown_versions_fail_closed() {
        let root = std::env::temp_dir().join(format!("mutte-signout-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let identity = root.join("device.json");
        let id = Uuid::new_v4();
        assert!(pending(&identity).unwrap().is_none());
        request(&identity, id, id).unwrap();
        assert_eq!(pending(&identity).unwrap(), Some((id, id)));
        fs::write(
            intent_path(&identity),
            "{\"version\":2,\"device_id\":\"00000000-0000-0000-0000-000000000001\"}",
        )
        .unwrap();
        assert!(pending(&identity).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
