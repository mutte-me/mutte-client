//! Encrypted local state for Mutte clients.
//!
//! This crate owns durable messages, receipts, attachment journals, encrypted
//! relay sessions, and the desktop vault-key adapter. It contains no network
//! transport or TUI code.

pub mod attachment;

use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{DateTime, Utc};
use directories::ProjectDirs;
use hkdf::Hkdf;
use keyring::{Entry, Error as KeyringError};
use mutte_protocol::{
    AttachmentMetadata, CiphertextEnvelope, EnvelopeKind, HISTORY_SYNC_VERSION, HistoryMessage,
    HistorySyncPayload, MAX_RECEIPT_MESSAGE_IDS, ReceiptKind,
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const KEY_META_FORMAT: &str = "mutte-vault-key/v1";
const LEGACY_KEY_META_FORMAT: &str = "omt-vault-key/v1";
const VAULT_FORMAT: &str = "mutte-vault/v1";
const VAULT_AAD: &[u8] = b"mutte-vault/v1";
const LEGACY_VAULT_FORMAT: &str = "omt-vault/v1";
const LEGACY_VAULT_AAD: &[u8] = b"omt-vault/v1";
const KEYRING_SERVICE: &str = "chat.mutte.vault";
const LEGACY_KEYRING_SERVICE: &str = "chat.omt.vault";
// Keep the original v1 KDF domain so an existing master key continues to
// derive the same encrypted device and vault keys after the product rename.
const MASTER_KEY_SALT: &[u8] = b"omt-local-storage/v1";
const DEVICE_KEY_INFO: &[u8] = b"encrypted OpenMLS device state";
const VAULT_KEY_INFO: &[u8] = b"encrypted messages, session, inbox, and outbox";
const HISTORY_TRANSCRIPT_DOMAIN: &[u8] = b"mutte history transcript v1\0";
const HISTORY_CHUNK_DOMAIN: &[u8] = b"mutte history chunk v1\0";
const MAX_HISTORY_MESSAGES: usize = 10_000;
const MAX_HISTORY_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_HISTORY_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_HISTORY_CHUNK_BYTES: usize = 256 * 1024;
const MAX_HISTORY_CHUNKS: usize = 1_024;
const MAX_COMPLETED_HISTORY_TRANSFERS: usize = 128;
const VAULT_DATA_VERSION: u16 = 2;

pub struct VaultKey {
    secret: SecretBox<[u8; 32]>,
}

/// Supplies a random 32-byte master key from platform secure storage.
///
/// Apple Keychain, Android Keystore-backed storage, Windows Credential
/// Manager, and Linux Secret Service adapters can implement this boundary
/// without changing vault encryption or key derivation.
pub trait MasterKeyProvider {
    fn load_or_create_master_key(&self) -> Result<Zeroizing<[u8; 32]>>;
}

impl VaultKey {
    pub fn from_provider(provider: &impl MasterKeyProvider) -> Result<Self> {
        let key = provider.load_or_create_master_key()?;
        Ok(Self {
            secret: SecretBox::new(Box::new(*key)),
        })
    }

    pub fn load_or_create() -> Result<Self> {
        let path = config_dir()?.join("vault-key.json");
        if path.exists() {
            return Self::load(&path);
        }
        fs::create_dir_all(config_dir()?)?;
        set_private_dir(&config_dir()?)?;
        let vault_id = Uuid::new_v4();
        let key = Zeroizing::new(rand::random::<[u8; 32]>());
        let source = match store_in_keyring(vault_id, &key) {
            Ok(()) => KeySource::Keyring,
            Err(error) => {
                eprintln!("  OS keyring unavailable ({error}); using a password-protected vault.");
                let (derived, salt) = create_password_key()?;
                let meta = KeyMetadata {
                    format: KEY_META_FORMAT.into(),
                    vault_id,
                    source: KeySource::Password {
                        salt: URL_SAFE_NO_PAD.encode(salt),
                    },
                };
                write_private(&path, &serde_json::to_vec_pretty(&meta)?)?;
                return Ok(Self {
                    secret: SecretBox::new(Box::new(*derived)),
                });
            }
        };
        let meta = KeyMetadata {
            format: KEY_META_FORMAT.into(),
            vault_id,
            source,
        };
        write_private(&path, &serde_json::to_vec_pretty(&meta)?)?;
        Ok(Self {
            secret: SecretBox::new(Box::new(*key)),
        })
    }

    fn load(path: &Path) -> Result<Self> {
        let mut meta: KeyMetadata = serde_json::from_slice(&fs::read(path)?)?;
        let legacy = meta.format == LEGACY_KEY_META_FORMAT;
        if meta.format != KEY_META_FORMAT && !legacy {
            bail!("unsupported vault key metadata version")
        }
        let key = match &meta.source {
            KeySource::Keyring => load_from_keyring(meta.vault_id).context(
                "unlock Mutte vault from the OS keyring; make sure it is available and unlocked",
            )?,
            KeySource::Password { salt } => {
                let salt = URL_SAFE_NO_PAD.decode(salt).context("invalid vault salt")?;
                let salt: [u8; 16] = salt
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid vault salt length"))?;
                let password =
                    Zeroizing::new(rpassword::prompt_password("Mutte vault password: ")?);
                derive_password_key(password.as_bytes(), &salt)?
            }
        };
        if legacy {
            meta.format = KEY_META_FORMAT.into();
            write_private(path, &serde_json::to_vec_pretty(&meta)?)?;
        }
        Ok(Self {
            secret: SecretBox::new(Box::new(*key)),
        })
    }

    pub fn device_storage_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.derive_storage_key(DEVICE_KEY_INFO)
    }

    pub fn message_storage_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.derive_storage_key(VAULT_KEY_INFO)
    }

    fn derive_storage_key(&self, info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(MASTER_KEY_SALT), self.secret.expose_secret())
            .expand(info, key.as_mut())
            .map_err(|_| anyhow::anyhow!("derive local storage subkey"))?;
        Ok(key)
    }
}

#[derive(Deserialize, Serialize)]
struct KeyMetadata {
    format: String,
    vault_id: Uuid,
    source: KeySource,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
enum KeySource {
    Keyring,
    Password { salt: String },
}

fn store_in_keyring(vault_id: Uuid, key: &[u8; 32]) -> Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, &vault_id.to_string())?;
    entry.set_secret(key)?;
    Ok(())
}

fn load_from_keyring(vault_id: Uuid) -> Result<Zeroizing<[u8; 32]>> {
    if let Some(key) = load_keyring_secret(KEYRING_SERVICE, vault_id)? {
        return Ok(key);
    }
    let key = load_keyring_secret(LEGACY_KEYRING_SERVICE, vault_id)?
        .context("vault key is missing from the OS keyring")?;
    store_in_keyring(vault_id, &key)?;
    Ok(key)
}

fn load_keyring_secret(service: &str, vault_id: Uuid) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let entry = Entry::new(service, &vault_id.to_string())?;
    let key = match entry.get_secret() {
        Ok(key) => Zeroizing::new(key),
        Err(KeyringError::NoEntry) => return Ok(None),
        Err(error) => return Err(anyhow::Error::new(error)),
    };
    let key: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("OS keyring returned an invalid vault key"))?;
    Ok(Some(Zeroizing::new(key)))
}

fn create_password_key() -> Result<(Zeroizing<[u8; 32]>, [u8; 16])> {
    let password = Zeroizing::new(rpassword::prompt_password(
        "Create Mutte vault password (12+ characters): ",
    )?);
    if password.chars().count() < 12 {
        bail!("vault password must be at least 12 characters")
    }
    let confirmation = Zeroizing::new(rpassword::prompt_password(
        "Confirm Mutte vault password: ",
    )?);
    if *password != *confirmation {
        bail!("vault passwords do not match")
    }
    let salt = rand::random::<[u8; 16]>();
    Ok((derive_password_key(password.as_bytes(), &salt)?, salt))
}

fn derive_password_key(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|error| anyhow::anyhow!("configure Argon2id: {error}"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|error| anyhow::anyhow!("derive vault key: {error}"))?;
    Ok(key)
}

pub struct Vault {
    path: PathBuf,
    key: SecretBox<[u8; 32]>,
    data: VaultData,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
struct VaultData {
    version: u16,
    conversations: Vec<VaultConversation>,
    messages: Vec<VaultMessage>,
    outbox: Vec<OutboxItem>,
    session: Option<VaultSession>,
    verifications: Vec<VerificationRecord>,
    pending_device_revocation: Option<PendingDeviceRevocation>,
    outbound_history_transfers: Vec<OutboundHistoryTransfer>,
    inbound_history_transfers: Vec<InboundHistoryTransfer>,
    outbound_attachments: Vec<OutboundAttachment>,
    pending_receipts: Vec<PendingReceipt>,
    settings: VaultSettings,
}

#[derive(Deserialize)]
struct LegacyConversation {
    id: Uuid,
    peer_handle: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct VaultSession {
    server: Url,
    #[serde(with = "secret_string")]
    access_token: SecretString,
    device_id: Uuid,
    profile: mutte_protocol::Profile,
}

/// Relay credentials recovered from the encrypted vault.
///
/// This storage-owned value intentionally avoids depending on the network
/// client's session type. A frontend performs the small explicit conversion at
/// its composition boundary.
#[derive(Clone)]
pub struct StoredSession {
    pub access_token: SecretString,
    pub device_id: Uuid,
    pub profile: mutte_protocol::Profile,
}

mod secret_string {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.expose_secret())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(SecretString::from(String::deserialize(deserializer)?))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VaultConversation {
    pub id: Uuid,
    pub peer_handle: String,
    pub unread: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Pending,
    Sent,
    Delivered,
    Read,
    Received,
    Cancelled,
}

impl DeliveryState {
    fn apply_receipt(self, kind: ReceiptKind) -> Self {
        match (self, kind) {
            (Self::Pending | Self::Sent, ReceiptKind::Delivered) => Self::Delivered,
            (Self::Pending | Self::Sent | Self::Delivered, ReceiptKind::Read) => Self::Read,
            _ => self,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VaultMessage {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub author: String,
    pub text: String,
    pub mine: bool,
    pub sent_at: DateTime<Utc>,
    pub delivery: DeliveryState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<VaultAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_root: Option<Uuid>,
    #[serde(default = "default_message_read")]
    pub locally_read: bool,
}

const fn default_message_read() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VaultAttachment {
    pub metadata: AttachmentMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_path: Option<PathBuf>,
    #[serde(default)]
    pub download_requested: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OutboxItem {
    pub envelope: CiphertextEnvelope,
    pub message_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ReceiptBatch>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct PendingReceipt {
    conversation_id: Uuid,
    kind: ReceiptKind,
    message_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReceiptBatch {
    pub conversation_id: Uuid,
    pub kind: ReceiptKind,
    pub message_ids: Vec<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadScope {
    Main,
    Thread(Uuid),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VaultSettings {
    pub send_read_receipts: bool,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            send_read_receipts: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VerificationRecord {
    pub conversation_id: Uuid,
    pub fingerprint: String,
    pub verified_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PendingDeviceRevocation {
    pub request_id: Uuid,
    pub target_device_id: Uuid,
    pub confirmation_url: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OutboundHistoryTransfer {
    pub transfer_id: Uuid,
    pub conversation_id: Uuid,
    pub target_device_id: Uuid,
    message_ids: Vec<Uuid>,
    message_count: u32,
    chunk_count: u32,
    transcript_hash: String,
    next_part: u32,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct InboundHistoryChunk {
    chunk_index: u32,
    chunk_hash: String,
    messages: Vec<HistoryMessage>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct InboundHistoryTransfer {
    transfer_id: Uuid,
    conversation_id: Uuid,
    source_device_id: Uuid,
    target_device_id: Uuid,
    message_count: u32,
    chunk_count: u32,
    transcript_hash: String,
    chunks: Vec<InboundHistoryChunk>,
    imported_count: u32,
    inserted_count: u32,
    completed_at: Option<DateTime<Utc>>,
    ack_envelope_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistorySyncOutcome {
    Pending,
    Imported {
        transfer_id: Uuid,
        source_device_id: Uuid,
        transcript_hash: String,
        imported_count: u32,
        inserted_count: u32,
        ack_queued: bool,
    },
    Acknowledged {
        transfer_id: Uuid,
        imported_count: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingHistoryAck {
    pub transfer_id: Uuid,
    pub conversation_id: Uuid,
    pub source_device_id: Uuid,
    pub transcript_hash: String,
    pub imported_count: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OutboundAttachment {
    pub attachment_id: Uuid,
    pub conversation_id: Uuid,
    pub message_id: Uuid,
    pub source_path: PathBuf,
    pub metadata: AttachmentMetadata,
    pub recipients: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAttachmentDownload {
    pub conversation_id: Uuid,
    pub message_id: Uuid,
    pub metadata: AttachmentMetadata,
}

#[derive(Deserialize, Serialize)]
struct EncryptedVault {
    format: String,
    nonce: String,
    ciphertext: String,
}

impl Vault {
    pub fn open(key: &[u8; 32]) -> Result<Self> {
        Self::open_at(config_dir()?.join("vault.json"), key)
    }

    pub fn open_at(path: impl Into<PathBuf>, key: &[u8; 32]) -> Result<Self> {
        let path = path.into();
        let (mut data, envelope_migrated) = if path.exists() {
            decrypt_vault(&fs::read(&path)?, key)?
        } else {
            (VaultData::default(), false)
        };
        let data_migrated = migrate_vault_data(&mut data);
        let vault = Self {
            path,
            key: SecretBox::new(Box::new(*key)),
            data,
        };
        if !vault.path.exists() || envelope_migrated || data_migrated {
            vault.persist()?;
        }
        Ok(vault)
    }

    pub fn conversations(&self) -> &[VaultConversation] {
        &self.data.conversations
    }

    pub fn messages(&self) -> &[VaultMessage] {
        &self.data.messages
    }

    pub fn outbox(&self) -> Vec<OutboxItem> {
        self.data.outbox.clone()
    }

    pub fn settings(&self) -> &VaultSettings {
        &self.data.settings
    }

    pub fn set_read_receipts(&mut self, enabled: bool) -> Result<()> {
        self.commit(|data| data.settings.send_read_receipts = enabled)
    }

    pub fn pending_receipt_batches(&self) -> Vec<ReceiptBatch> {
        let mut batches = Vec::<ReceiptBatch>::new();
        for pending in &self.data.pending_receipts {
            if let Some(batch) = batches.iter_mut().find(|batch| {
                batch.conversation_id == pending.conversation_id
                    && batch.kind == pending.kind
                    && batch.message_ids.len() < MAX_RECEIPT_MESSAGE_IDS
            }) {
                batch.message_ids.push(pending.message_id);
            } else {
                batches.push(ReceiptBatch {
                    conversation_id: pending.conversation_id,
                    kind: pending.kind,
                    message_ids: vec![pending.message_id],
                });
            }
        }
        batches
    }

    pub fn queue_receipt(
        &mut self,
        batch: ReceiptBatch,
        envelope: CiphertextEnvelope,
    ) -> Result<()> {
        validate_receipt_batch(&batch)?;
        if envelope.kind != EnvelopeKind::Application
            || envelope.conversation_id != batch.conversation_id
            || envelope.recipients.is_empty()
        {
            bail!("receipt envelope does not match its pending batch")
        }
        self.commit_fallible(|data| {
            if data
                .outbox
                .iter()
                .any(|item| item.envelope.id == envelope.id)
            {
                return Ok(());
            }
            for message_id in &batch.message_ids {
                if !data.pending_receipts.iter().any(|pending| {
                    pending.conversation_id == batch.conversation_id
                        && pending.kind == batch.kind
                        && pending.message_id == *message_id
                }) {
                    bail!("receipt batch contains a message that is no longer pending")
                }
            }
            data.pending_receipts.retain(|pending| {
                pending.conversation_id != batch.conversation_id
                    || pending.kind != batch.kind
                    || !batch.message_ids.contains(&pending.message_id)
            });
            data.outbox.push(OutboxItem {
                envelope,
                message_id: None,
                receipt: Some(batch),
            });
            Ok(())
        })
    }

    pub fn apply_receipt(
        &mut self,
        conversation_id: Uuid,
        kind: ReceiptKind,
        message_ids: &[Uuid],
    ) -> Result<Vec<(Uuid, DeliveryState)>> {
        validate_receipt_ids(message_ids)?;
        self.commit(|data| {
            let mut updated = Vec::new();
            for message in &mut data.messages {
                if message.conversation_id != conversation_id
                    || !message.mine
                    || !message_ids.contains(&message.id)
                {
                    continue;
                }
                let next = message.delivery.apply_receipt(kind);
                if next != message.delivery {
                    message.delivery = next;
                    updated.push((message.id, next));
                }
            }
            updated
        })
    }

    pub fn has_pending_control(&self, conversation_id: Uuid) -> bool {
        self.data.outbox.iter().any(|item| {
            item.envelope.conversation_id == conversation_id
                && item.envelope.kind != mutte_protocol::EnvelopeKind::Application
        })
    }

    pub fn verification(&self, conversation_id: Uuid) -> Option<&VerificationRecord> {
        self.data
            .verifications
            .iter()
            .find(|record| record.conversation_id == conversation_id)
    }

    pub fn pending_device_revocation(&self) -> Option<&PendingDeviceRevocation> {
        self.data.pending_device_revocation.as_ref()
    }

    pub fn begin_history_transfer(
        &mut self,
        conversation_id: Uuid,
        target_device_id: Uuid,
    ) -> Result<Uuid> {
        if let Some(existing) = self
            .data
            .outbound_history_transfers
            .iter()
            .find(|transfer| {
                transfer.conversation_id == conversation_id
                    && transfer.target_device_id == target_device_id
                    && transfer.completed_at.is_none()
            })
        {
            let transfer_id = existing.transfer_id;
            if existing.next_part > 0 {
                return Ok(transfer_id);
            }
            // No ciphertext has been staged yet, so a retry before the MLS Add
            // may safely refresh the snapshot with newly delivered messages.
            let messages = history_snapshot(&self.data, conversation_id, None)?;
            let chunks = history_chunks(&messages)?;
            let transcript_hash =
                history_transcript_hash(transfer_id, conversation_id, target_device_id, &messages)?;
            self.commit(|data| {
                let transfer = data
                    .outbound_history_transfers
                    .iter_mut()
                    .find(|transfer| transfer.transfer_id == transfer_id)
                    .expect("existing history transfer disappeared");
                transfer.message_ids = messages.iter().map(|message| message.id).collect();
                transfer.message_count = messages.len() as u32;
                transfer.chunk_count = chunks.len() as u32;
                transfer.transcript_hash = transcript_hash;
            })?;
            return Ok(transfer_id);
        }

        let messages = history_snapshot(&self.data, conversation_id, None)?;
        let transfer_id = Uuid::new_v4();
        let chunks = history_chunks(&messages)?;
        let transcript_hash =
            history_transcript_hash(transfer_id, conversation_id, target_device_id, &messages)?;
        let transfer = OutboundHistoryTransfer {
            transfer_id,
            conversation_id,
            target_device_id,
            message_ids: messages.iter().map(|message| message.id).collect(),
            message_count: u32::try_from(messages.len()).context("history message count")?,
            chunk_count: u32::try_from(chunks.len()).context("history chunk count")?,
            transcript_hash,
            next_part: 0,
            created_at: Utc::now(),
            completed_at: None,
        };
        self.commit(|data| {
            data.outbound_history_transfers.push(transfer);
            prune_history_transfers(data);
        })?;
        Ok(transfer_id)
    }

    pub fn outbound_history_transfers(&self) -> Vec<OutboundHistoryTransfer> {
        self.data
            .outbound_history_transfers
            .iter()
            .filter(|transfer| transfer.completed_at.is_none())
            .cloned()
            .collect()
    }

    pub fn next_history_payload(&self, transfer_id: Uuid) -> Result<Option<HistorySyncPayload>> {
        let transfer = self
            .data
            .outbound_history_transfers
            .iter()
            .find(|transfer| transfer.transfer_id == transfer_id)
            .context("unknown outbound history transfer")?;
        if transfer.completed_at.is_some() {
            return Ok(None);
        }
        let messages = history_snapshot(
            &self.data,
            transfer.conversation_id,
            Some(&transfer.message_ids),
        )?;
        let chunks = history_chunks(&messages)?;
        let transcript_hash = history_transcript_hash(
            transfer.transfer_id,
            transfer.conversation_id,
            transfer.target_device_id,
            &messages,
        )?;
        if messages.len() != transfer.message_count as usize
            || chunks.len() != transfer.chunk_count as usize
            || transcript_hash != transfer.transcript_hash
        {
            bail!("local history changed while rebuilding a transfer")
        }

        if transfer.next_part == 0 {
            return Ok(Some(HistorySyncPayload::Manifest {
                version: HISTORY_SYNC_VERSION,
                transfer_id: transfer.transfer_id,
                target_device_id: transfer.target_device_id,
                message_count: transfer.message_count,
                chunk_count: transfer.chunk_count,
                transcript_hash: transfer.transcript_hash.clone(),
            }));
        }
        let chunk_index = transfer.next_part - 1;
        let Some(messages) = chunks.get(chunk_index as usize) else {
            return Ok(None);
        };
        Ok(Some(HistorySyncPayload::Chunk {
            version: HISTORY_SYNC_VERSION,
            transfer_id: transfer.transfer_id,
            target_device_id: transfer.target_device_id,
            chunk_index,
            chunk_count: transfer.chunk_count,
            chunk_hash: history_chunk_hash(
                transfer.transfer_id,
                transfer.conversation_id,
                transfer.target_device_id,
                chunk_index,
                messages,
            )?,
            messages: messages.clone(),
        }))
    }

    pub fn queue_history_part(
        &mut self,
        transfer_id: Uuid,
        envelope: CiphertextEnvelope,
    ) -> Result<()> {
        self.commit_fallible(|data| {
            let transfer = data
                .outbound_history_transfers
                .iter_mut()
                .find(|transfer| transfer.transfer_id == transfer_id)
                .context("unknown outbound history transfer")?;
            if transfer.completed_at.is_some() {
                bail!("history transfer is already complete")
            }
            if envelope.kind != EnvelopeKind::HistorySync
                || envelope.conversation_id != transfer.conversation_id
                || envelope.recipients.as_slice() != [transfer.target_device_id]
            {
                bail!("history envelope does not match its transfer")
            }
            if transfer.next_part > transfer.chunk_count {
                bail!("all history transfer parts are already queued")
            }
            if !data
                .outbox
                .iter()
                .any(|item| item.envelope.id == envelope.id)
            {
                data.outbox.push(OutboxItem {
                    envelope,
                    message_id: None,
                    receipt: None,
                });
            }
            transfer.next_part += 1;
            Ok(())
        })
    }

    pub fn apply_history_sync(
        &mut self,
        conversation_id: Uuid,
        source_device_id: Uuid,
        local_device_id: Uuid,
        payload: HistorySyncPayload,
    ) -> Result<HistorySyncOutcome> {
        self.commit_fallible(|data| {
            apply_history_sync_to_data(
                data,
                conversation_id,
                source_device_id,
                local_device_id,
                payload,
            )
        })
    }

    pub fn pending_history_acknowledgements(&self) -> Vec<PendingHistoryAck> {
        self.data
            .inbound_history_transfers
            .iter()
            .filter(|transfer| {
                transfer.completed_at.is_some() && transfer.ack_envelope_id.is_none()
            })
            .map(|transfer| PendingHistoryAck {
                transfer_id: transfer.transfer_id,
                conversation_id: transfer.conversation_id,
                source_device_id: transfer.source_device_id,
                transcript_hash: transfer.transcript_hash.clone(),
                imported_count: transfer.imported_count,
            })
            .collect()
    }

    pub fn queue_history_ack(
        &mut self,
        transfer_id: Uuid,
        envelope: CiphertextEnvelope,
    ) -> Result<()> {
        self.commit_fallible(|data| {
            let transfer = data
                .inbound_history_transfers
                .iter_mut()
                .find(|transfer| transfer.transfer_id == transfer_id)
                .context("unknown inbound history transfer")?;
            if transfer.completed_at.is_none() {
                bail!("cannot acknowledge an incomplete history transfer")
            }
            if envelope.kind != EnvelopeKind::HistorySync
                || envelope.conversation_id != transfer.conversation_id
                || envelope.recipients.as_slice() != [transfer.source_device_id]
            {
                bail!("history acknowledgement does not match its transfer")
            }
            if transfer.ack_envelope_id.is_none() {
                transfer.ack_envelope_id = Some(envelope.id);
                data.outbox.push(OutboxItem {
                    envelope,
                    message_id: None,
                    receipt: None,
                });
            }
            Ok(())
        })
    }

    pub fn begin_attachment_upload(
        &mut self,
        conversation_id: Uuid,
        source_path: PathBuf,
        metadata: AttachmentMetadata,
        mut recipients: Vec<Uuid>,
    ) -> Result<Uuid> {
        crate::attachment::validate_metadata(&metadata)?;
        if !self
            .data
            .conversations
            .iter()
            .any(|conversation| conversation.id == conversation_id)
        {
            bail!("cannot attach a file to an unknown conversation")
        }
        if recipients.is_empty() {
            bail!("attachment has no recipient devices")
        }
        recipients.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        recipients.dedup();
        if recipients.len() > 64 {
            bail!("attachment exceeds the recipient limit")
        }
        let attachment_id = metadata.attachment_id;
        if self
            .data
            .outbound_attachments
            .iter()
            .any(|transfer| transfer.attachment_id == attachment_id)
            || self.data.messages.iter().any(|message| {
                message
                    .attachment
                    .as_ref()
                    .is_some_and(|attachment| attachment.metadata.attachment_id == attachment_id)
            })
        {
            bail!("attachment id is already present in the vault")
        }
        let transfer = OutboundAttachment {
            attachment_id,
            conversation_id,
            message_id: Uuid::new_v4(),
            source_path,
            metadata,
            recipients,
            created_at: Utc::now(),
        };
        self.commit(|data| data.outbound_attachments.push(transfer))?;
        Ok(attachment_id)
    }

    pub fn outbound_attachments(&self) -> Vec<OutboundAttachment> {
        self.data.outbound_attachments.clone()
    }

    pub fn outbound_attachment_id(&self, prefix: &str) -> Result<Uuid> {
        let prefix = normalize_id_prefix(prefix, "attachment")?;
        let matches = self
            .data
            .outbound_attachments
            .iter()
            .filter(|transfer| {
                transfer
                    .attachment_id
                    .simple()
                    .to_string()
                    .starts_with(&prefix)
            })
            .map(|transfer| transfer.attachment_id)
            .collect::<Vec<_>>();
        unique_attachment_match(&matches)
    }

    pub fn cancel_outbound_attachment(&mut self, attachment_id: Uuid) -> Result<()> {
        self.commit_fallible(|data| {
            let index = data
                .outbound_attachments
                .iter()
                .position(|transfer| transfer.attachment_id == attachment_id)
                .context("pending attachment upload is unavailable")?;
            data.outbound_attachments.remove(index);
            Ok(())
        })
    }

    pub fn queue_uploaded_attachment(
        &mut self,
        attachment_id: Uuid,
        envelope: CiphertextEnvelope,
    ) -> Result<VaultMessage> {
        self.commit_fallible(|data| {
            let index = data
                .outbound_attachments
                .iter()
                .position(|transfer| transfer.attachment_id == attachment_id)
                .context("unknown outbound attachment")?;
            let transfer = data.outbound_attachments[index].clone();
            let mut envelope_recipients = envelope.recipients.clone();
            envelope_recipients
                .sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            if envelope.kind != EnvelopeKind::Application
                || envelope.conversation_id != transfer.conversation_id
                || envelope_recipients != transfer.recipients
            {
                bail!("attachment message envelope does not match its upload")
            }
            let message = VaultMessage {
                id: transfer.message_id,
                conversation_id: transfer.conversation_id,
                author: "You".into(),
                text: format!("📎 {}", transfer.metadata.filename),
                mine: true,
                sent_at: transfer.created_at,
                delivery: DeliveryState::Pending,
                attachment: Some(VaultAttachment {
                    metadata: transfer.metadata,
                    local_path: Some(transfer.source_path),
                    download_requested: false,
                }),
                reply_to: None,
                thread_root: None,
                locally_read: true,
            };
            data.messages.push(message.clone());
            data.outbox.push(OutboxItem {
                envelope,
                message_id: Some(message.id),
                receipt: None,
            });
            data.outbound_attachments.remove(index);
            Ok(message)
        })
    }

    pub fn pending_attachment_downloads(&self) -> Vec<PendingAttachmentDownload> {
        self.data
            .messages
            .iter()
            .filter_map(|message| {
                let attachment = message.attachment.as_ref()?;
                (attachment.local_path.is_none() && attachment.download_requested).then(|| {
                    PendingAttachmentDownload {
                        conversation_id: message.conversation_id,
                        message_id: message.id,
                        metadata: attachment.metadata.clone(),
                    }
                })
            })
            .collect()
    }

    pub fn request_attachment_download(&mut self, prefix: &str) -> Result<Uuid> {
        let prefix = normalize_id_prefix(prefix, "attachment")?;
        let matches = self
            .data
            .messages
            .iter()
            .filter_map(|message| {
                let attachment = message.attachment.as_ref()?;
                attachment
                    .metadata
                    .attachment_id
                    .simple()
                    .to_string()
                    .starts_with(&prefix)
                    .then_some((
                        message.conversation_id,
                        message.id,
                        attachment.metadata.attachment_id,
                        attachment.local_path.is_some(),
                    ))
            })
            .collect::<Vec<_>>();
        let [(conversation_id, message_id, attachment_id, downloaded)] = matches.as_slice() else {
            if matches.is_empty() {
                bail!("no attachment matches that id prefix")
            }
            bail!("attachment id prefix is ambiguous")
        };
        if *downloaded {
            bail!("attachment is already downloaded")
        }
        let (conversation_id, message_id, attachment_id) =
            (*conversation_id, *message_id, *attachment_id);
        self.commit_fallible(|data| {
            let attachment = data
                .messages
                .iter_mut()
                .find(|message| {
                    message.conversation_id == conversation_id && message.id == message_id
                })
                .and_then(|message| message.attachment.as_mut())
                .context("attachment disappeared before download")?;
            attachment.download_requested = true;
            Ok(())
        })?;
        Ok(attachment_id)
    }

    pub fn cancel_attachment_download(&mut self, prefix: &str) -> Result<AttachmentMetadata> {
        let prefix = normalize_id_prefix(prefix, "attachment")?;
        let matches = self
            .data
            .messages
            .iter()
            .filter_map(|message| {
                let attachment = message.attachment.as_ref()?;
                (attachment.local_path.is_none()
                    && attachment.download_requested
                    && attachment
                        .metadata
                        .attachment_id
                        .simple()
                        .to_string()
                        .starts_with(&prefix))
                .then_some((
                    message.conversation_id,
                    message.id,
                    attachment.metadata.clone(),
                ))
            })
            .collect::<Vec<_>>();
        let [(conversation_id, message_id, metadata)] = matches.as_slice() else {
            if matches.is_empty() {
                bail!("no pending attachment download matches that id prefix")
            }
            bail!("attachment id prefix is ambiguous")
        };
        let (conversation_id, message_id, metadata) =
            (*conversation_id, *message_id, metadata.clone());
        self.commit_fallible(|data| {
            let attachment = data
                .messages
                .iter_mut()
                .find(|message| {
                    message.conversation_id == conversation_id && message.id == message_id
                })
                .and_then(|message| message.attachment.as_mut())
                .context("pending attachment download disappeared")?;
            attachment.download_requested = false;
            Ok(())
        })?;
        Ok(metadata)
    }

    pub fn complete_attachment_download(
        &mut self,
        conversation_id: Uuid,
        message_id: Uuid,
        local_path: PathBuf,
    ) -> Result<()> {
        let metadata = self
            .data
            .messages
            .iter()
            .find(|message| message.conversation_id == conversation_id && message.id == message_id)
            .and_then(|message| message.attachment.as_ref())
            .map(|attachment| attachment.metadata.clone())
            .context("attachment message is unavailable")?;
        crate::attachment::validate_source(&local_path, &metadata)
            .context("verify downloaded attachment before recording it")?;
        self.commit_fallible(|data| {
            let message = data
                .messages
                .iter_mut()
                .find(|message| {
                    message.conversation_id == conversation_id && message.id == message_id
                })
                .context("attachment message is unavailable")?;
            let attachment = message
                .attachment
                .as_mut()
                .context("message does not contain an attachment")?;
            attachment.local_path = Some(local_path);
            Ok(())
        })
    }

    pub fn history_attachment_ids(&self, transfer_id: Uuid) -> Result<Vec<Uuid>> {
        let transfer = self
            .data
            .outbound_history_transfers
            .iter()
            .find(|transfer| transfer.transfer_id == transfer_id)
            .context("unknown outbound history transfer")?;
        let message_ids = transfer.message_ids.iter().copied().collect::<HashSet<_>>();
        let mut attachments = self
            .data
            .messages
            .iter()
            .filter(|message| {
                message.conversation_id == transfer.conversation_id
                    && message_ids.contains(&message.id)
            })
            .filter_map(|message| {
                message
                    .attachment
                    .as_ref()
                    .map(|attachment| attachment.metadata.attachment_id)
            })
            .collect::<Vec<_>>();
        attachments.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        attachments.dedup();
        Ok(attachments)
    }

    pub fn save_pending_device_revocation(
        &mut self,
        pending: PendingDeviceRevocation,
    ) -> Result<()> {
        self.commit(|data| data.pending_device_revocation = Some(pending))
    }

    pub fn clear_pending_device_revocation(&mut self, request_id: Uuid) -> Result<()> {
        self.commit(|data| {
            if data
                .pending_device_revocation
                .as_ref()
                .is_some_and(|pending| pending.request_id == request_id)
            {
                data.pending_device_revocation = None;
            }
        })
    }

    pub fn verify_conversation(&mut self, conversation_id: Uuid, fingerprint: &str) -> Result<()> {
        if !self
            .data
            .conversations
            .iter()
            .any(|conversation| conversation.id == conversation_id)
        {
            bail!("cannot verify an unknown conversation")
        }
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
        {
            bail!("invalid conversation safety fingerprint")
        }
        let record = VerificationRecord {
            conversation_id,
            fingerprint: fingerprint.into(),
            verified_at: Utc::now(),
        };
        self.commit(|data| {
            if let Some(existing) = data
                .verifications
                .iter_mut()
                .find(|item| item.conversation_id == conversation_id)
            {
                *existing = record;
            } else {
                data.verifications.push(record);
            }
        })
    }

    pub fn migrate_legacy_conversations(&mut self) -> Result<usize> {
        self.migrate_legacy_conversations_at(&config_dir()?.join("conversations.json"))
    }

    pub fn migrate_legacy_session(&mut self) -> Result<bool> {
        self.migrate_legacy_session_at(&config_dir()?.join("session.json"))
    }

    pub fn load_session(&self, server: &Url) -> Option<StoredSession> {
        let stored = self
            .data
            .session
            .as_ref()
            .filter(|item| &item.server == server)?;
        Some(StoredSession {
            access_token: stored.access_token.clone(),
            device_id: stored.device_id,
            profile: stored.profile.clone(),
        })
    }

    pub fn save_session(&mut self, server: &Url, session: &StoredSession) -> Result<()> {
        let stored = VaultSession {
            server: server.clone(),
            access_token: session.access_token.clone(),
            device_id: session.device_id,
            profile: session.profile.clone(),
        };
        self.commit(|data| data.session = Some(stored))
    }

    fn migrate_legacy_conversations_at(&mut self, path: &Path) -> Result<usize> {
        let encoded = match fs::read(path) {
            Ok(encoded) => encoded,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        let legacy: Vec<LegacyConversation> =
            serde_json::from_slice(&encoded).context("read legacy conversation metadata")?;
        let imported = self.commit(|data| {
            let mut imported = 0;
            for conversation in legacy {
                if !data
                    .conversations
                    .iter()
                    .any(|item| item.id == conversation.id)
                {
                    data.conversations.push(VaultConversation {
                        id: conversation.id,
                        peer_handle: conversation.peer_handle,
                        unread: 0,
                    });
                    imported += 1;
                }
            }
            imported
        })?;
        fs::remove_file(path).context("remove migrated plaintext conversation metadata")?;
        Ok(imported)
    }

    fn migrate_legacy_session_at(&mut self, path: &Path) -> Result<bool> {
        let encoded = match fs::read(path) {
            Ok(encoded) => encoded,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let legacy: VaultSession =
            serde_json::from_slice(&encoded).context("read legacy plaintext session")?;
        self.commit(|data| {
            if data.session.is_none() {
                data.session = Some(legacy);
            }
        })?;
        fs::remove_file(path).context("remove migrated plaintext session")?;
        Ok(true)
    }

    pub fn queue_welcome(
        &mut self,
        conversation: VaultConversation,
        envelope: CiphertextEnvelope,
    ) -> Result<()> {
        self.commit(|data| {
            upsert_conversation(data, conversation);
            if !data
                .outbox
                .iter()
                .any(|item| item.envelope.id == envelope.id)
            {
                data.outbox.push(OutboxItem {
                    envelope,
                    message_id: None,
                    receipt: None,
                });
            }
        })
    }

    pub fn queue_message(
        &mut self,
        message: VaultMessage,
        envelope: CiphertextEnvelope,
    ) -> Result<()> {
        self.commit(|data| {
            if !data.messages.iter().any(|item| {
                item.conversation_id == message.conversation_id && item.id == message.id
            }) {
                data.messages.push(message.clone());
            }
            if !data
                .outbox
                .iter()
                .any(|item| item.envelope.id == envelope.id)
            {
                data.outbox.push(OutboxItem {
                    envelope,
                    message_id: Some(message.id),
                    receipt: None,
                });
            }
        })
    }

    pub fn queue_commit(&mut self, envelope: CiphertextEnvelope) -> Result<()> {
        self.commit(|data| {
            if !data
                .outbox
                .iter()
                .any(|item| item.envelope.id == envelope.id)
            {
                data.outbox.push(OutboxItem {
                    envelope,
                    message_id: None,
                    receipt: None,
                });
            }
        })
    }

    pub fn queue_control_envelopes(&mut self, envelopes: Vec<CiphertextEnvelope>) -> Result<()> {
        if envelopes
            .iter()
            .any(|envelope| envelope.kind == mutte_protocol::EnvelopeKind::Application)
        {
            bail!("chat applications must be queued with their visible message")
        }
        self.commit(|data| {
            for envelope in envelopes {
                if !data
                    .outbox
                    .iter()
                    .any(|item| item.envelope.id == envelope.id)
                {
                    data.outbox.push(OutboxItem {
                        envelope,
                        message_id: None,
                        receipt: None,
                    });
                }
            }
        })
    }

    /// Drop ciphertext created for an older MLS epoch before an epoch-changing
    /// Commit is sent. The visible message remains as an explicit cancellation.
    pub fn cancel_application_outbox(&mut self, conversation_id: Uuid) -> Result<Vec<Uuid>> {
        self.commit(|data| {
            let message_ids = data
                .outbox
                .iter()
                .filter(|item| {
                    item.envelope.conversation_id == conversation_id
                        && item.envelope.kind == mutte_protocol::EnvelopeKind::Application
                })
                .filter_map(|item| item.message_id)
                .collect::<Vec<_>>();
            let receipts = data
                .outbox
                .iter()
                .filter(|item| {
                    item.envelope.conversation_id == conversation_id
                        && item.envelope.kind == mutte_protocol::EnvelopeKind::Application
                })
                .filter_map(|item| item.receipt.clone())
                .collect::<Vec<_>>();
            data.outbox.retain(|item| {
                item.envelope.conversation_id != conversation_id
                    || item.envelope.kind != mutte_protocol::EnvelopeKind::Application
            });
            for batch in receipts {
                for message_id in batch.message_ids {
                    add_pending_receipt(
                        data,
                        PendingReceipt {
                            conversation_id: batch.conversation_id,
                            kind: batch.kind,
                            message_id,
                        },
                    );
                }
            }
            for message in &mut data.messages {
                if message.conversation_id == conversation_id && message_ids.contains(&message.id) {
                    message.delivery = DeliveryState::Cancelled;
                }
            }
            message_ids
        })
    }

    pub fn complete_outbox(&mut self, envelope_id: Uuid) -> Result<()> {
        self.commit(|data| {
            let message = data
                .outbox
                .iter()
                .find(|item| item.envelope.id == envelope_id)
                .and_then(|item| {
                    item.message_id
                        .map(|message_id| (item.envelope.conversation_id, message_id))
                });
            data.outbox.retain(|item| item.envelope.id != envelope_id);
            if let Some((conversation_id, message_id)) = message
                && let Some(message) = data.messages.iter_mut().find(|message| {
                    message.conversation_id == conversation_id && message.id == message_id
                })
            {
                message.delivery = DeliveryState::Sent;
            }
        })
    }

    pub fn store_inbound(
        &mut self,
        conversation: VaultConversation,
        message: VaultMessage,
        unread: bool,
    ) -> Result<bool> {
        if self
            .data
            .messages
            .iter()
            .any(|item| item.conversation_id == message.conversation_id && item.id == message.id)
        {
            return Ok(false);
        }
        let conversation_id = message.conversation_id;
        self.commit(|data| {
            upsert_conversation(data, conversation);
            if !message.mine {
                add_pending_receipt(
                    data,
                    PendingReceipt {
                        conversation_id,
                        kind: ReceiptKind::Delivered,
                        message_id: message.id,
                    },
                );
                if message.locally_read && data.settings.send_read_receipts {
                    add_pending_receipt(
                        data,
                        PendingReceipt {
                            conversation_id,
                            kind: ReceiptKind::Read,
                            message_id: message.id,
                        },
                    );
                }
            }
            data.messages.push(message);
            if unread
                && let Some(conversation) = data
                    .conversations
                    .iter_mut()
                    .find(|item| item.id == conversation_id)
            {
                conversation.unread = conversation.unread.saturating_add(1);
            }
            true
        })
    }

    pub fn upsert_conversation(&mut self, conversation: VaultConversation) -> Result<()> {
        self.commit(|data| upsert_conversation(data, conversation))
    }

    pub fn mark_read(&mut self, conversation_id: Uuid, scope: ReadScope) -> Result<Vec<Uuid>> {
        if !self
            .data
            .conversations
            .iter()
            .any(|item| item.id == conversation_id)
        {
            bail!("cannot mark an unknown conversation read")
        }
        self.commit(|data| {
            let message_ids = data
                .messages
                .iter_mut()
                .filter(|message| {
                    message.conversation_id == conversation_id
                        && !message.mine
                        && !message.locally_read
                        && message_in_read_scope(message, scope)
                })
                .map(|message| {
                    message.locally_read = true;
                    message.id
                })
                .collect::<Vec<_>>();
            if data.settings.send_read_receipts {
                for message_id in &message_ids {
                    add_pending_receipt(
                        data,
                        PendingReceipt {
                            conversation_id,
                            kind: ReceiptKind::Read,
                            message_id: *message_id,
                        },
                    );
                }
            }
            if let Some(conversation) = data
                .conversations
                .iter_mut()
                .find(|item| item.id == conversation_id)
            {
                conversation.unread = conversation
                    .unread
                    .saturating_sub(u16::try_from(message_ids.len()).unwrap_or(u16::MAX));
            }
            message_ids
        })
    }

    fn commit<T>(&mut self, update: impl FnOnce(&mut VaultData) -> T) -> Result<T> {
        let previous = self.data.clone();
        let output = update(&mut self.data);
        if let Err(error) = self.persist() {
            self.data = previous;
            return Err(error);
        }
        Ok(output)
    }

    fn commit_fallible<T>(
        &mut self,
        update: impl FnOnce(&mut VaultData) -> Result<T>,
    ) -> Result<T> {
        let previous = self.data.clone();
        let output = match update(&mut self.data) {
            Ok(output) => output,
            Err(error) => {
                self.data = previous;
                return Err(error);
            }
        };
        if let Err(error) = self.persist() {
            self.data = previous;
            return Err(error);
        }
        Ok(output)
    }

    fn persist(&self) -> Result<()> {
        let parent = self.path.parent().context("invalid vault path")?;
        fs::create_dir_all(parent)?;
        set_private_dir(parent)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.data)?);
        let nonce = rand::random::<[u8; 24]>();
        let cipher = XChaCha20Poly1305::new(self.key.expose_secret().into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: VAULT_AAD,
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypt local vault"))?;
        let envelope = EncryptedVault {
            format: VAULT_FORMAT.into(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        write_private(&self.path, &serde_json::to_vec_pretty(&envelope)?)
    }
}

fn history_snapshot(
    data: &VaultData,
    conversation_id: Uuid,
    message_ids: Option<&[Uuid]>,
) -> Result<Vec<HistoryMessage>> {
    if !data
        .conversations
        .iter()
        .any(|conversation| conversation.id == conversation_id)
    {
        bail!("cannot sync history for an unknown conversation")
    }

    let mut messages = if let Some(message_ids) = message_ids {
        let mut seen = HashSet::new();
        message_ids
            .iter()
            .map(|message_id| {
                if !seen.insert(*message_id) {
                    bail!("history transfer contains a duplicate message id")
                }
                let message = data
                    .messages
                    .iter()
                    .find(|message| {
                        message.conversation_id == conversation_id && message.id == *message_id
                    })
                    .context("a message captured for history sync is no longer available")?;
                Ok(normalize_history_message(message))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        let mut messages = data
            .messages
            .iter()
            .filter(|message| {
                message.conversation_id == conversation_id
                    && matches!(
                        message.delivery,
                        DeliveryState::Sent | DeliveryState::Received
                    )
            })
            .map(normalize_history_message)
            .collect::<Vec<_>>();
        messages.sort_by(|left, right| {
            left.sent_at
                .cmp(&right.sent_at)
                .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
        });
        messages
    };
    validate_history_messages(&messages)?;
    if messages.len() > MAX_HISTORY_MESSAGES {
        bail!("conversation history exceeds the message limit")
    }
    messages.shrink_to_fit();
    Ok(messages)
}

fn normalize_history_message(message: &VaultMessage) -> HistoryMessage {
    HistoryMessage {
        id: message.id,
        text: message.text.clone(),
        mine: message.mine,
        sent_at: message.sent_at,
        attachment: message
            .attachment
            .as_ref()
            .map(|attachment| attachment.metadata.clone()),
        reply_to: message.reply_to,
        thread_root: message.thread_root,
        receipt: match message.delivery {
            DeliveryState::Delivered => Some(ReceiptKind::Delivered),
            DeliveryState::Read => Some(ReceiptKind::Read),
            _ => None,
        },
    }
}

fn validate_history_messages(messages: &[HistoryMessage]) -> Result<usize> {
    if messages.len() > MAX_HISTORY_MESSAGES {
        bail!("history message count exceeds the limit")
    }
    let mut ids = HashSet::with_capacity(messages.len());
    let mut attachment_ids = HashSet::new();
    let mut total_bytes = 0usize;
    for message in messages {
        if !ids.insert(message.id) {
            bail!("history contains duplicate message ids")
        }
        if message.reply_to == Some(message.id) || message.thread_root == Some(message.id) {
            bail!("history message cannot reference itself")
        }
        if message.text.len() > MAX_HISTORY_MESSAGE_BYTES {
            bail!("history message exceeds the size limit")
        }
        if let Some(attachment) = &message.attachment {
            crate::attachment::validate_metadata(attachment)?;
            if !attachment_ids.insert(attachment.attachment_id) {
                bail!("history contains duplicate attachment ids")
            }
        }
        total_bytes = total_bytes
            .checked_add(serde_json::to_vec(message)?.len())
            .context("history size overflow")?;
        if total_bytes > MAX_HISTORY_TOTAL_BYTES {
            bail!("conversation history exceeds the total size limit")
        }
    }
    Ok(total_bytes)
}

fn history_chunks(messages: &[HistoryMessage]) -> Result<Vec<Vec<HistoryMessage>>> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_size = 2usize;
    for message in messages {
        let message_size = serde_json::to_vec(message)?.len();
        let separator_size = usize::from(!current.is_empty());
        let candidate_size = current_size
            .checked_add(separator_size)
            .and_then(|size| size.checked_add(message_size))
            .context("history chunk size overflow")?;
        if candidate_size > MAX_HISTORY_CHUNK_BYTES {
            if current.is_empty() {
                bail!("history message cannot fit in a transfer chunk")
            }
            chunks.push(std::mem::take(&mut current));
            current.push(message.clone());
            current_size = 2usize
                .checked_add(message_size)
                .context("history chunk size overflow")?;
            if current_size > MAX_HISTORY_CHUNK_BYTES {
                bail!("history message cannot fit in a transfer chunk")
            }
        } else {
            current.push(message.clone());
            current_size = candidate_size;
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    if chunks.len() > MAX_HISTORY_CHUNKS {
        bail!("conversation history exceeds the chunk limit")
    }
    Ok(chunks)
}

fn history_transcript_hash(
    transfer_id: Uuid,
    conversation_id: Uuid,
    target_device_id: Uuid,
    messages: &[HistoryMessage],
) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(HISTORY_TRANSCRIPT_DOMAIN);
    hash.update(transfer_id.as_bytes());
    hash.update(conversation_id.as_bytes());
    hash.update(target_device_id.as_bytes());
    hash.update((messages.len() as u64).to_be_bytes());
    for message in messages {
        update_history_hash(&mut hash, &serde_json::to_vec(message)?)?;
    }
    Ok(URL_SAFE_NO_PAD.encode(hash.finalize()))
}

fn history_chunk_hash(
    transfer_id: Uuid,
    conversation_id: Uuid,
    target_device_id: Uuid,
    chunk_index: u32,
    messages: &[HistoryMessage],
) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(HISTORY_CHUNK_DOMAIN);
    hash.update(transfer_id.as_bytes());
    hash.update(conversation_id.as_bytes());
    hash.update(target_device_id.as_bytes());
    hash.update(chunk_index.to_be_bytes());
    update_history_hash(&mut hash, &serde_json::to_vec(messages)?)?;
    Ok(URL_SAFE_NO_PAD.encode(hash.finalize()))
}

fn update_history_hash(hash: &mut Sha256, value: &[u8]) -> Result<()> {
    let length = u64::try_from(value.len()).context("history hash input length")?;
    hash.update(length.to_be_bytes());
    hash.update(value);
    Ok(())
}

fn validate_history_hash(value: &str) -> Result<()> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .context("history hash is not valid base64url")?;
    if decoded.len() != 32 {
        bail!("history hash has an invalid length")
    }
    Ok(())
}

fn apply_history_sync_to_data(
    data: &mut VaultData,
    conversation_id: Uuid,
    source_device_id: Uuid,
    local_device_id: Uuid,
    payload: HistorySyncPayload,
) -> Result<HistorySyncOutcome> {
    match payload {
        HistorySyncPayload::Manifest {
            version,
            transfer_id,
            target_device_id,
            message_count,
            chunk_count,
            transcript_hash,
        } => {
            validate_history_version_and_target(version, target_device_id, local_device_id)?;
            validate_history_hash(&transcript_hash)?;
            if message_count as usize > MAX_HISTORY_MESSAGES
                || chunk_count as usize > MAX_HISTORY_CHUNKS
                || (message_count == 0) != (chunk_count == 0)
            {
                bail!("history manifest exceeds protocol limits")
            }
            if let Some(existing) = data
                .inbound_history_transfers
                .iter()
                .find(|transfer| transfer.transfer_id == transfer_id)
            {
                validate_inbound_transfer(
                    existing,
                    conversation_id,
                    source_device_id,
                    target_device_id,
                    message_count,
                    chunk_count,
                    &transcript_hash,
                )?;
                return Ok(inbound_history_outcome(existing));
            }
            data.inbound_history_transfers.push(InboundHistoryTransfer {
                transfer_id,
                conversation_id,
                source_device_id,
                target_device_id,
                message_count,
                chunk_count,
                transcript_hash,
                chunks: Vec::new(),
                imported_count: 0,
                inserted_count: 0,
                completed_at: None,
                ack_envelope_id: None,
                created_at: Utc::now(),
            });
            if chunk_count == 0 {
                finalize_history_transfer(data, transfer_id)
            } else {
                Ok(HistorySyncOutcome::Pending)
            }
        }
        HistorySyncPayload::Chunk {
            version,
            transfer_id,
            target_device_id,
            chunk_index,
            chunk_count,
            chunk_hash,
            messages,
        } => {
            validate_history_version_and_target(version, target_device_id, local_device_id)?;
            validate_history_hash(&chunk_hash)?;
            if chunk_count == 0
                || chunk_count as usize > MAX_HISTORY_CHUNKS
                || chunk_index >= chunk_count
            {
                bail!("history chunk index is outside protocol limits")
            }
            let new_message_bytes = validate_history_messages(&messages)?;
            if serde_json::to_vec(&messages)?.len() > MAX_HISTORY_CHUNK_BYTES {
                bail!("history chunk exceeds the size limit")
            }
            let expected_hash = history_chunk_hash(
                transfer_id,
                conversation_id,
                target_device_id,
                chunk_index,
                &messages,
            )?;
            if expected_hash != chunk_hash {
                bail!("history chunk integrity check failed")
            }

            let transfer = data
                .inbound_history_transfers
                .iter_mut()
                .find(|transfer| transfer.transfer_id == transfer_id)
                .context("history chunk arrived before its manifest")?;
            if transfer.conversation_id != conversation_id
                || transfer.source_device_id != source_device_id
                || transfer.target_device_id != target_device_id
                || transfer.chunk_count != chunk_count
            {
                bail!("history chunk does not match its manifest")
            }
            if transfer.completed_at.is_some() {
                return Ok(inbound_history_outcome(transfer));
            }
            if let Some(existing) = transfer
                .chunks
                .iter()
                .find(|chunk| chunk.chunk_index == chunk_index)
            {
                if existing.chunk_hash != chunk_hash || existing.messages != messages {
                    bail!("conflicting replay of a history chunk")
                }
                return Ok(HistorySyncOutcome::Pending);
            }
            let mut existing_ids = transfer
                .chunks
                .iter()
                .flat_map(|chunk| chunk.messages.iter().map(|message| message.id))
                .collect::<HashSet<_>>();
            if messages
                .iter()
                .any(|message| !existing_ids.insert(message.id))
            {
                bail!("history chunks contain duplicate message ids")
            }
            let accumulated = transfer
                .chunks
                .iter()
                .try_fold(messages.len(), |count, chunk| {
                    count.checked_add(chunk.messages.len())
                })
                .context("history message count overflow")?;
            if accumulated > transfer.message_count as usize {
                bail!("history chunks exceed the declared message count")
            }
            let existing_message_bytes = transfer
                .chunks
                .iter()
                .flat_map(|chunk| &chunk.messages)
                .try_fold(0usize, |size, message| {
                size.checked_add(serde_json::to_vec(message)?.len())
                    .context("history size overflow")
            })?;
            if existing_message_bytes
                .checked_add(new_message_bytes)
                .context("history size overflow")?
                > MAX_HISTORY_TOTAL_BYTES
            {
                bail!("history chunks exceed the total size limit")
            }
            transfer.chunks.push(InboundHistoryChunk {
                chunk_index,
                chunk_hash,
                messages,
            });
            if transfer.chunks.len() == transfer.chunk_count as usize {
                finalize_history_transfer(data, transfer_id)
            } else {
                Ok(HistorySyncOutcome::Pending)
            }
        }
        HistorySyncPayload::Ack {
            version,
            transfer_id,
            source_device_id: expected_source_device_id,
            transcript_hash,
            imported_count,
        } => {
            if version != HISTORY_SYNC_VERSION {
                bail!("unsupported history sync version")
            }
            validate_history_hash(&transcript_hash)?;
            if expected_source_device_id != local_device_id {
                bail!("history acknowledgement targets another source device")
            }
            let Some(transfer) = data
                .outbound_history_transfers
                .iter_mut()
                .find(|transfer| transfer.transfer_id == transfer_id)
            else {
                return Ok(HistorySyncOutcome::Pending);
            };
            if transfer.conversation_id != conversation_id
                || transfer.target_device_id != source_device_id
                || transfer.transcript_hash != transcript_hash
                || transfer.message_count != imported_count
            {
                bail!("history acknowledgement does not match its transfer")
            }
            transfer.completed_at.get_or_insert_with(Utc::now);
            transfer.message_ids.clear();
            let outcome = HistorySyncOutcome::Acknowledged {
                transfer_id,
                imported_count,
            };
            prune_history_transfers(data);
            Ok(outcome)
        }
    }
}

fn validate_history_version_and_target(
    version: u16,
    target_device_id: Uuid,
    local_device_id: Uuid,
) -> Result<()> {
    if version != HISTORY_SYNC_VERSION {
        bail!("unsupported history sync version")
    }
    if target_device_id != local_device_id {
        bail!("history transfer targets another device")
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_inbound_transfer(
    transfer: &InboundHistoryTransfer,
    conversation_id: Uuid,
    source_device_id: Uuid,
    target_device_id: Uuid,
    message_count: u32,
    chunk_count: u32,
    transcript_hash: &str,
) -> Result<()> {
    if transfer.conversation_id != conversation_id
        || transfer.source_device_id != source_device_id
        || transfer.target_device_id != target_device_id
        || transfer.message_count != message_count
        || transfer.chunk_count != chunk_count
        || transfer.transcript_hash != transcript_hash
    {
        bail!("history manifest conflicts with an existing transfer")
    }
    Ok(())
}

fn inbound_history_outcome(transfer: &InboundHistoryTransfer) -> HistorySyncOutcome {
    if transfer.completed_at.is_none() {
        return HistorySyncOutcome::Pending;
    }
    HistorySyncOutcome::Imported {
        transfer_id: transfer.transfer_id,
        source_device_id: transfer.source_device_id,
        transcript_hash: transfer.transcript_hash.clone(),
        imported_count: transfer.imported_count,
        inserted_count: transfer.inserted_count,
        ack_queued: transfer.ack_envelope_id.is_some(),
    }
}

fn finalize_history_transfer(
    data: &mut VaultData,
    transfer_id: Uuid,
) -> Result<HistorySyncOutcome> {
    let transfer_index = data
        .inbound_history_transfers
        .iter()
        .position(|transfer| transfer.transfer_id == transfer_id)
        .context("unknown inbound history transfer")?;
    if data.inbound_history_transfers[transfer_index]
        .completed_at
        .is_some()
    {
        return Ok(inbound_history_outcome(
            &data.inbound_history_transfers[transfer_index],
        ));
    }
    let transfer = data.inbound_history_transfers[transfer_index].clone();
    let mut chunks = transfer.chunks.clone();
    chunks.sort_by_key(|chunk| chunk.chunk_index);
    if chunks.len() != transfer.chunk_count as usize
        || chunks
            .iter()
            .enumerate()
            .any(|(index, chunk)| chunk.chunk_index as usize != index)
    {
        bail!("history transfer is missing chunks")
    }
    let messages = chunks
        .into_iter()
        .flat_map(|chunk| chunk.messages)
        .collect::<Vec<_>>();
    validate_history_messages(&messages)?;
    if messages.len() != transfer.message_count as usize {
        bail!("history transcript message count does not match its manifest")
    }
    if history_transcript_hash(
        transfer_id,
        transfer.conversation_id,
        transfer.target_device_id,
        &messages,
    )? != transfer.transcript_hash
    {
        bail!("history transcript integrity check failed")
    }

    let peer_handle = data
        .conversations
        .iter()
        .find(|conversation| conversation.id == transfer.conversation_id)
        .map(|conversation| conversation.peer_handle.clone())
        .unwrap_or_else(|| "encrypted-peer".into());
    let mut inserted_count = 0u32;
    for message in messages {
        if data.messages.iter().any(|existing| {
            existing.conversation_id == transfer.conversation_id && existing.id == message.id
        }) {
            continue;
        }
        data.messages.push(VaultMessage {
            id: message.id,
            conversation_id: transfer.conversation_id,
            author: if message.mine {
                "You · synced history".into()
            } else {
                format!("@{peer_handle}")
            },
            text: message.text,
            mine: message.mine,
            sent_at: message.sent_at,
            delivery: if message.mine {
                match message.receipt {
                    Some(ReceiptKind::Delivered) => DeliveryState::Delivered,
                    Some(ReceiptKind::Read) => DeliveryState::Read,
                    None => DeliveryState::Sent,
                }
            } else {
                DeliveryState::Received
            },
            attachment: message.attachment.map(|metadata| VaultAttachment {
                metadata,
                local_path: None,
                download_requested: false,
            }),
            reply_to: message.reply_to,
            thread_root: message.thread_root,
            locally_read: true,
        });
        inserted_count = inserted_count.saturating_add(1);
    }
    data.messages.sort_by(|left, right| {
        left.conversation_id
            .as_bytes()
            .cmp(right.conversation_id.as_bytes())
            .then_with(|| left.sent_at.cmp(&right.sent_at))
            .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
    });

    let transfer = &mut data.inbound_history_transfers[transfer_index];
    transfer.imported_count = transfer.message_count;
    transfer.inserted_count = inserted_count;
    transfer.completed_at = Some(Utc::now());
    transfer.chunks.clear();
    let outcome = inbound_history_outcome(transfer);
    prune_history_transfers(data);
    Ok(outcome)
}

fn prune_history_transfers(data: &mut VaultData) {
    while data
        .outbound_history_transfers
        .iter()
        .filter(|transfer| transfer.completed_at.is_some())
        .count()
        > MAX_COMPLETED_HISTORY_TRANSFERS
    {
        if let Some(index) = data
            .outbound_history_transfers
            .iter()
            .position(|transfer| transfer.completed_at.is_some())
        {
            data.outbound_history_transfers.remove(index);
        }
    }
    while data
        .inbound_history_transfers
        .iter()
        .filter(|transfer| transfer.completed_at.is_some() && transfer.ack_envelope_id.is_some())
        .count()
        > MAX_COMPLETED_HISTORY_TRANSFERS
    {
        if let Some(index) = data.inbound_history_transfers.iter().position(|transfer| {
            transfer.completed_at.is_some() && transfer.ack_envelope_id.is_some()
        }) {
            data.inbound_history_transfers.remove(index);
        }
    }
}

fn validate_receipt_batch(batch: &ReceiptBatch) -> Result<()> {
    validate_receipt_ids(&batch.message_ids)
}

fn normalize_id_prefix(prefix: &str, label: &str) -> Result<String> {
    let prefix = prefix.trim().trim_start_matches('#').to_ascii_lowercase();
    if prefix.len() < 4 || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} id prefix must contain at least four hexadecimal characters")
    }
    Ok(prefix)
}

fn unique_attachment_match(matches: &[Uuid]) -> Result<Uuid> {
    match matches {
        [attachment_id] => Ok(*attachment_id),
        [] => bail!("no pending attachment upload matches that id prefix"),
        _ => bail!("attachment id prefix is ambiguous"),
    }
}

fn validate_receipt_ids(message_ids: &[Uuid]) -> Result<()> {
    if message_ids.is_empty() || message_ids.len() > MAX_RECEIPT_MESSAGE_IDS {
        bail!("receipt message count is outside protocol limits")
    }
    let mut unique = HashSet::with_capacity(message_ids.len());
    if message_ids
        .iter()
        .any(|message_id| message_id.is_nil() || !unique.insert(*message_id))
    {
        bail!("receipt contains an invalid or duplicate message id")
    }
    Ok(())
}

fn add_pending_receipt(data: &mut VaultData, pending: PendingReceipt) {
    if !data.pending_receipts.contains(&pending)
        && !data.outbox.iter().any(|item| {
            item.receipt.as_ref().is_some_and(|batch| {
                batch.conversation_id == pending.conversation_id
                    && batch.kind == pending.kind
                    && batch.message_ids.contains(&pending.message_id)
            })
        })
    {
        data.pending_receipts.push(pending);
    }
}

fn message_in_read_scope(message: &VaultMessage, scope: ReadScope) -> bool {
    match scope {
        ReadScope::Main => message.thread_root.is_none(),
        ReadScope::Thread(root) => message.id == root || message.thread_root == Some(root),
    }
}

fn upsert_conversation(data: &mut VaultData, conversation: VaultConversation) {
    if let Some(existing) = data
        .conversations
        .iter_mut()
        .find(|item| item.id == conversation.id)
    {
        if existing.peer_handle == "encrypted-peer" {
            existing.peer_handle = conversation.peer_handle;
        }
        return;
    }
    data.conversations.push(conversation);
}

fn decrypt_vault(encoded: &[u8], key: &[u8; 32]) -> Result<(VaultData, bool)> {
    let envelope: EncryptedVault = serde_json::from_slice(encoded)?;
    let (aad, migrated) = match envelope.format.as_str() {
        VAULT_FORMAT => (VAULT_AAD, false),
        LEGACY_VAULT_FORMAT => (LEGACY_VAULT_AAD, true),
        _ => bail!("unsupported encrypted vault version"),
    };
    let nonce = URL_SAFE_NO_PAD.decode(envelope.nonce)?;
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid vault nonce"))?;
    let ciphertext = URL_SAFE_NO_PAD.decode(envelope.ciphertext)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("vault authentication failed or key changed"))?,
    );
    Ok((serde_json::from_slice(&plaintext)?, migrated))
}

fn migrate_vault_data(data: &mut VaultData) -> bool {
    if data.version >= VAULT_DATA_VERSION {
        return false;
    }
    // v1 stored only a per-conversation unread count. Reconstruct the best
    // deterministic per-message approximation by marking the newest peer
    // records unread; older records stay read instead of generating retroactive
    // read receipts after an upgrade.
    for conversation in &data.conversations {
        let mut remaining = usize::from(conversation.unread);
        for message in data
            .messages
            .iter_mut()
            .rev()
            .filter(|message| message.conversation_id == conversation.id && !message.mine)
        {
            message.locally_read = remaining == 0;
            remaining = remaining.saturating_sub(1);
        }
    }
    data.version = VAULT_DATA_VERSION;
    true
}

fn config_dir() -> Result<PathBuf> {
    let project =
        ProjectDirs::from("chat", "mutte", "mutte").context("unable to locate config directory")?;
    Ok(project.config_dir().to_path_buf())
}

fn legacy_config_dir() -> Result<PathBuf> {
    let project = ProjectDirs::from("chat", "omt", "omt")
        .context("unable to locate legacy config directory")?;
    Ok(project.config_dir().to_path_buf())
}

pub fn migrate_legacy_config() -> Result<()> {
    migrate_config_dir(&legacy_config_dir()?, &config_dir()?)
}

fn migrate_config_dir(legacy: &Path, current: &Path) -> Result<()> {
    if current.exists() || !legacy.exists() {
        return Ok(());
    }
    let parent = current.parent().context("invalid Mutte config directory")?;
    fs::create_dir_all(parent)?;
    fs::rename(legacy, current).context("move legacy OMT config directory to Mutte")?;
    set_private_dir(current)?;
    sync_parent(parent)?;
    Ok(())
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let temporary = path.with_extension("json.tmp");
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(data)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    sync_parent(path.parent().context("invalid private file path")?)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_config_directory_moves_without_overwriting_mutte_data() {
        let root = std::env::temp_dir().join(format!("mutte-config-rebrand-{}", Uuid::new_v4()));
        let legacy = root.join("omt");
        let current = root.join("mutte");
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("marker"), b"legacy").unwrap();

        migrate_config_dir(&legacy, &current).unwrap();
        assert!(!legacy.exists());
        assert_eq!(fs::read(current.join("marker")).unwrap(), b"legacy");

        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("marker"), b"do-not-overwrite").unwrap();
        migrate_config_dir(&legacy, &current).unwrap();
        assert_eq!(fs::read(current.join("marker")).unwrap(), b"legacy");
        assert!(legacy.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_encrypted_vault_is_rewrapped_for_mutte() {
        let root = std::env::temp_dir().join(format!("mutte-vault-rebrand-{}", Uuid::new_v4()));
        let path = root.join("vault.json");
        let key = [41u8; 32];
        let conversation_id = Uuid::new_v4();
        let mut vault = Vault::open_at(&path, &key).unwrap();
        vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "legacy-peer".into(),
                unread: 2,
            })
            .unwrap();
        drop(vault);

        let (data, migrated) = decrypt_vault(&fs::read(&path).unwrap(), &key).unwrap();
        assert!(!migrated);
        let plaintext = Zeroizing::new(serde_json::to_vec(&data).unwrap());
        let nonce = rand::random::<[u8; 24]>();
        let ciphertext = XChaCha20Poly1305::new((&key).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: LEGACY_VAULT_AAD,
                },
            )
            .unwrap();
        fs::write(
            &path,
            serde_json::to_vec_pretty(&EncryptedVault {
                format: LEGACY_VAULT_FORMAT.into(),
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            })
            .unwrap(),
        )
        .unwrap();

        let migrated = Vault::open_at(&path, &key).expect("migrate encrypted vault");
        assert_eq!(migrated.conversations()[0].id, conversation_id);
        let rewritten: EncryptedVault = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(rewritten.format, VAULT_FORMAT);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn encrypted_vault_survives_restart_without_plaintext_leak() {
        let root = std::env::temp_dir().join(format!("mutte-vault-{}", Uuid::new_v4()));
        let path = root.join("vault.json");
        let key = [42u8; 32];
        let conversation_id = Uuid::new_v4();
        let message_id = Uuid::new_v4();
        let envelope = CiphertextEnvelope {
            id: Uuid::new_v4(),
            conversation_id,
            sender_device_id: Uuid::new_v4(),
            sender_handle: "alice".into(),
            recipients: vec![Uuid::new_v4()],
            kind: mutte_protocol::EnvelopeKind::Application,
            mutation_id: None,
            ciphertext: "opaque".into(),
            created_at: Utc::now(),
        };
        let mut vault = Vault::open_at(&path, &key).expect("create vault");
        vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "alice".into(),
                unread: 0,
            })
            .expect("store conversation");
        vault
            .queue_message(
                VaultMessage {
                    id: message_id,
                    conversation_id,
                    author: "You".into(),
                    text: "plaintext-marker-1d7e".into(),
                    mine: true,
                    sent_at: Utc::now(),
                    delivery: DeliveryState::Pending,
                    attachment: None,
                    reply_to: None,
                    thread_root: None,
                    locally_read: true,
                },
                envelope.clone(),
            )
            .expect("queue message");
        assert!(
            !fs::read(&path)
                .unwrap()
                .windows(21)
                .any(|window| { window == b"plaintext-marker-1d7e" })
        );
        drop(vault);

        assert!(Vault::open_at(&path, &[41u8; 32]).is_err());

        let mut vault = Vault::open_at(&path, &key).expect("reload vault");
        assert_eq!(vault.messages()[0].text, "plaintext-marker-1d7e");
        assert_eq!(vault.outbox().len(), 1);
        vault.complete_outbox(envelope.id).expect("complete outbox");
        assert_eq!(vault.messages()[0].delivery, DeliveryState::Sent);
        assert!(vault.outbox().is_empty());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn inbound_store_is_idempotent() {
        let root = std::env::temp_dir().join(format!("mutte-vault-inbox-{}", Uuid::new_v4()));
        let path = root.join("vault.json");
        let key = [43u8; 32];
        let conversation = VaultConversation {
            id: Uuid::new_v4(),
            peer_handle: "bob".into(),
            unread: 0,
        };
        let message = VaultMessage {
            id: Uuid::new_v4(),
            conversation_id: conversation.id,
            author: "@bob".into(),
            text: "once".into(),
            mine: false,
            sent_at: Utc::now(),
            delivery: DeliveryState::Received,
            attachment: None,
            reply_to: None,
            thread_root: None,
            locally_read: false,
        };
        let mut vault = Vault::open_at(&path, &key).expect("create vault");
        assert!(
            vault
                .store_inbound(conversation.clone(), message.clone(), true)
                .expect("first store")
        );
        drop(vault);
        let mut vault = Vault::open_at(&path, &key).expect("restart vault");
        assert!(
            !vault
                .store_inbound(conversation, message, true)
                .expect("duplicate store")
        );
        assert_eq!(vault.messages().len(), 1);
        assert_eq!(vault.conversations()[0].unread, 1);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn encrypted_history_transfer_resumes_imports_once_and_acknowledges() {
        let root = std::env::temp_dir().join(format!("mutte-history-{}", Uuid::new_v4()));
        let sender_path = root.join("sender-vault.json");
        let receiver_path = root.join("receiver-vault.json");
        let sender_key = [51u8; 32];
        let receiver_key = [52u8; 32];
        let conversation_id = Uuid::new_v4();
        let source_device_id = Uuid::new_v4();
        let target_device_id = Uuid::new_v4();
        let conversation = VaultConversation {
            id: conversation_id,
            peer_handle: "bob".into(),
            unread: 0,
        };
        let mut sender = Vault::open_at(&sender_path, &sender_key).unwrap();
        sender.upsert_conversation(conversation.clone()).unwrap();
        let mut expected_ids = Vec::new();
        for index in 0..5 {
            let id = Uuid::new_v4();
            expected_ids.push(id);
            let envelope_id = Uuid::new_v4();
            sender
                .queue_message(
                    VaultMessage {
                        id,
                        conversation_id,
                        author: "You".into(),
                        text: format!("history-{index}-{}", "x".repeat(60 * 1024)),
                        mine: true,
                        sent_at: Utc::now() + chrono::Duration::seconds(index),
                        delivery: DeliveryState::Pending,
                        attachment: None,
                        reply_to: None,
                        thread_root: None,
                        locally_read: true,
                    },
                    CiphertextEnvelope {
                        id: envelope_id,
                        conversation_id,
                        sender_device_id: source_device_id,
                        sender_handle: "alice".into(),
                        recipients: vec![target_device_id],
                        kind: EnvelopeKind::Application,
                        mutation_id: None,
                        ciphertext: "opaque".into(),
                        created_at: Utc::now(),
                    },
                )
                .unwrap();
            sender.complete_outbox(envelope_id).unwrap();
        }
        // Pending text is deliberately not captured in the immutable transfer.
        sender
            .queue_message(
                VaultMessage {
                    id: Uuid::new_v4(),
                    conversation_id,
                    author: "You".into(),
                    text: "not-yet-sent".into(),
                    mine: true,
                    sent_at: Utc::now(),
                    delivery: DeliveryState::Pending,
                    attachment: None,
                    reply_to: None,
                    thread_root: None,
                    locally_read: true,
                },
                CiphertextEnvelope {
                    id: Uuid::new_v4(),
                    conversation_id,
                    sender_device_id: source_device_id,
                    sender_handle: "alice".into(),
                    recipients: vec![target_device_id],
                    kind: EnvelopeKind::Application,
                    mutation_id: None,
                    ciphertext: "opaque-pending".into(),
                    created_at: Utc::now(),
                },
            )
            .unwrap();

        let transfer_id = sender
            .begin_history_transfer(conversation_id, target_device_id)
            .unwrap();
        let mut parts = Vec::new();
        while let Some(payload) = sender.next_history_payload(transfer_id).unwrap() {
            parts.push(payload);
            sender
                .queue_history_part(
                    transfer_id,
                    CiphertextEnvelope {
                        id: Uuid::new_v4(),
                        conversation_id,
                        sender_device_id: source_device_id,
                        sender_handle: "alice".into(),
                        recipients: vec![target_device_id],
                        kind: EnvelopeKind::HistorySync,
                        mutation_id: None,
                        ciphertext: "mls-ciphertext".into(),
                        created_at: Utc::now(),
                    },
                )
                .unwrap();
        }
        assert!(parts.len() >= 3, "manifest plus multiple chunks");
        assert!(sender.next_history_payload(transfer_id).unwrap().is_none());

        let mut receiver = Vault::open_at(&receiver_path, &receiver_key).unwrap();
        receiver.upsert_conversation(conversation).unwrap();
        assert_eq!(
            receiver
                .apply_history_sync(
                    conversation_id,
                    source_device_id,
                    target_device_id,
                    parts[0].clone(),
                )
                .unwrap(),
            HistorySyncOutcome::Pending
        );
        assert_eq!(
            receiver
                .apply_history_sync(
                    conversation_id,
                    source_device_id,
                    target_device_id,
                    parts[1].clone(),
                )
                .unwrap(),
            HistorySyncOutcome::Pending
        );
        drop(receiver);

        let mut receiver = Vault::open_at(&receiver_path, &receiver_key).unwrap();
        let mut imported = None;
        for payload in &parts[2..] {
            imported = Some(
                receiver
                    .apply_history_sync(
                        conversation_id,
                        source_device_id,
                        target_device_id,
                        payload.clone(),
                    )
                    .unwrap(),
            );
        }
        assert!(matches!(
            imported,
            Some(HistorySyncOutcome::Imported {
                imported_count: 5,
                inserted_count: 5,
                ack_queued: false,
                ..
            })
        ));
        assert_eq!(receiver.messages().len(), 5);
        assert!(
            receiver
                .messages()
                .iter()
                .all(|message| message.text != "not-yet-sent")
        );
        assert_eq!(
            receiver
                .messages()
                .iter()
                .map(|message| message.id)
                .collect::<Vec<_>>(),
            expected_ids
        );

        let acknowledgement = receiver.pending_history_acknowledgements().remove(0);
        receiver
            .queue_history_ack(
                transfer_id,
                CiphertextEnvelope {
                    id: Uuid::new_v4(),
                    conversation_id,
                    sender_device_id: target_device_id,
                    sender_handle: "alice".into(),
                    recipients: vec![source_device_id],
                    kind: EnvelopeKind::HistorySync,
                    mutation_id: None,
                    ciphertext: "encrypted-ack".into(),
                    created_at: Utc::now(),
                },
            )
            .unwrap();
        drop(receiver);
        let receiver = Vault::open_at(&receiver_path, &receiver_key).unwrap();
        assert!(receiver.pending_history_acknowledgements().is_empty());
        assert_eq!(receiver.outbox().len(), 1);

        assert_eq!(
            sender
                .apply_history_sync(
                    conversation_id,
                    target_device_id,
                    source_device_id,
                    HistorySyncPayload::Ack {
                        version: HISTORY_SYNC_VERSION,
                        transfer_id,
                        source_device_id,
                        transcript_hash: acknowledgement.transcript_hash,
                        imported_count: acknowledgement.imported_count,
                    },
                )
                .unwrap(),
            HistorySyncOutcome::Acknowledged {
                transfer_id,
                imported_count: 5,
            }
        );
        assert!(sender.outbound_history_transfers().is_empty());
        drop(sender);
        assert!(
            Vault::open_at(&sender_path, &sender_key)
                .unwrap()
                .outbound_history_transfers()
                .is_empty()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn history_chunk_tampering_rolls_back_without_importing_messages() {
        let root = std::env::temp_dir().join(format!("mutte-history-tamper-{}", Uuid::new_v4()));
        let path = root.join("vault.json");
        let key = [53u8; 32];
        let conversation_id = Uuid::new_v4();
        let source_device_id = Uuid::new_v4();
        let target_device_id = Uuid::new_v4();
        let transfer_id = Uuid::new_v4();
        let messages = vec![HistoryMessage {
            id: Uuid::new_v4(),
            text: "authentic".into(),
            mine: false,
            sent_at: Utc::now(),
            attachment: None,
            reply_to: None,
            thread_root: None,
            receipt: None,
        }];
        let transcript_hash =
            history_transcript_hash(transfer_id, conversation_id, target_device_id, &messages)
                .unwrap();
        let chunk_hash =
            history_chunk_hash(transfer_id, conversation_id, target_device_id, 0, &messages)
                .unwrap();
        let mut vault = Vault::open_at(&path, &key).unwrap();
        vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "alice".into(),
                unread: 0,
            })
            .unwrap();
        vault
            .apply_history_sync(
                conversation_id,
                source_device_id,
                target_device_id,
                HistorySyncPayload::Manifest {
                    version: HISTORY_SYNC_VERSION,
                    transfer_id,
                    target_device_id,
                    message_count: 1,
                    chunk_count: 1,
                    transcript_hash,
                },
            )
            .unwrap();
        let mut tampered = messages;
        tampered[0].text = "tampered".into();
        assert!(
            vault
                .apply_history_sync(
                    conversation_id,
                    source_device_id,
                    target_device_id,
                    HistorySyncPayload::Chunk {
                        version: HISTORY_SYNC_VERSION,
                        transfer_id,
                        target_device_id,
                        chunk_index: 0,
                        chunk_count: 1,
                        chunk_hash,
                        messages: tampered,
                    },
                )
                .is_err()
        );
        assert!(vault.messages().is_empty());
        drop(vault);
        assert!(Vault::open_at(&path, &key).unwrap().messages().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attachment_journal_and_history_backfill_survive_restart() {
        let root = std::env::temp_dir().join(format!("mutte-vault-attach-{}", Uuid::new_v4()));
        let source = root.join("quiet.txt");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, b"encrypted attachment fixture").unwrap();
        let prepared = crate::attachment::prepare(&source).unwrap();
        let attachment_id = prepared.metadata.attachment_id;
        let conversation_id = Uuid::new_v4();
        let sender_device_id = Uuid::new_v4();
        let peer_device_id = Uuid::new_v4();
        let new_device_id = Uuid::new_v4();
        let sender_path = root.join("sender.json");
        let receiver_path = root.join("receiver.json");
        let conversation = VaultConversation {
            id: conversation_id,
            peer_handle: "bob".into(),
            unread: 0,
        };
        let mut sender = Vault::open_at(&sender_path, &[61u8; 32]).unwrap();
        sender.upsert_conversation(conversation.clone()).unwrap();
        sender
            .begin_attachment_upload(
                conversation_id,
                prepared.source_path.clone(),
                prepared.metadata.clone(),
                vec![peer_device_id],
            )
            .unwrap();
        drop(sender);

        let mut sender = Vault::open_at(&sender_path, &[61u8; 32]).unwrap();
        assert_eq!(sender.outbound_attachments().len(), 1);
        let message = sender
            .queue_uploaded_attachment(
                attachment_id,
                CiphertextEnvelope {
                    id: Uuid::new_v4(),
                    conversation_id,
                    sender_device_id,
                    sender_handle: "alice".into(),
                    recipients: vec![peer_device_id],
                    kind: EnvelopeKind::Application,
                    mutation_id: None,
                    ciphertext: "opaque-mls-metadata".into(),
                    created_at: Utc::now(),
                },
            )
            .unwrap();
        sender
            .complete_outbox(sender.outbox()[0].envelope.id)
            .unwrap();
        assert!(sender.outbound_attachments().is_empty());
        assert_eq!(
            message.attachment.as_ref().unwrap().local_path.as_ref(),
            Some(&prepared.source_path)
        );
        let cancelled = crate::attachment::prepare(&source).unwrap();
        sender
            .begin_attachment_upload(
                conversation_id,
                cancelled.source_path,
                cancelled.metadata.clone(),
                vec![peer_device_id],
            )
            .unwrap();
        assert_eq!(
            sender
                .outbound_attachment_id(&cancelled.metadata.attachment_id.simple().to_string()[..8])
                .unwrap(),
            cancelled.metadata.attachment_id
        );
        sender
            .cancel_outbound_attachment(cancelled.metadata.attachment_id)
            .unwrap();
        assert!(sender.outbound_attachments().is_empty());

        let transfer_id = sender
            .begin_history_transfer(conversation_id, new_device_id)
            .unwrap();
        assert_eq!(
            sender.history_attachment_ids(transfer_id).unwrap(),
            vec![attachment_id]
        );
        let mut parts = Vec::new();
        while let Some(payload) = sender.next_history_payload(transfer_id).unwrap() {
            parts.push(payload);
            sender
                .queue_history_part(
                    transfer_id,
                    CiphertextEnvelope {
                        id: Uuid::new_v4(),
                        conversation_id,
                        sender_device_id,
                        sender_handle: "alice".into(),
                        recipients: vec![new_device_id],
                        kind: EnvelopeKind::HistorySync,
                        mutation_id: None,
                        ciphertext: "opaque-history".into(),
                        created_at: Utc::now(),
                    },
                )
                .unwrap();
        }
        let mut receiver = Vault::open_at(&receiver_path, &[62u8; 32]).unwrap();
        receiver.upsert_conversation(conversation).unwrap();
        for part in parts {
            receiver
                .apply_history_sync(conversation_id, sender_device_id, new_device_id, part)
                .unwrap();
        }
        assert!(receiver.pending_attachment_downloads().is_empty());
        receiver
            .request_attachment_download(&attachment_id.simple().to_string()[..8])
            .unwrap();
        let pending = receiver.pending_attachment_downloads();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].metadata, prepared.metadata);
        assert_eq!(
            receiver
                .cancel_attachment_download(&attachment_id.simple().to_string()[..8])
                .unwrap(),
            prepared.metadata
        );
        assert!(receiver.pending_attachment_downloads().is_empty());
        receiver
            .request_attachment_download(&attachment_id.simple().to_string()[..8])
            .unwrap();
        let downloaded = root.join("downloaded.txt");
        fs::write(&downloaded, b"encrypted attachment fixture").unwrap();
        receiver
            .complete_attachment_download(conversation_id, message.id, downloaded.clone())
            .unwrap();
        drop(receiver);
        let receiver = Vault::open_at(&receiver_path, &[62u8; 32]).unwrap();
        assert!(receiver.pending_attachment_downloads().is_empty());
        assert_eq!(
            receiver.messages()[0]
                .attachment
                .as_ref()
                .unwrap()
                .local_path
                .as_ref(),
            Some(&downloaded)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn encrypted_receipts_are_durable_scoped_monotonic_and_epoch_safe() {
        let root = std::env::temp_dir().join(format!("mutte-vault-receipts-{}", Uuid::new_v4()));
        let path = root.join("vault.json");
        let key = [101u8; 32];
        let conversation_id = Uuid::new_v4();
        let local_device = Uuid::new_v4();
        let peer_device = Uuid::new_v4();
        let root_message_id = Uuid::new_v4();
        let thread_message_id = Uuid::new_v4();
        let outgoing_id = Uuid::new_v4();
        let conversation = VaultConversation {
            id: conversation_id,
            peer_handle: "bob".into(),
            unread: 0,
        };
        let mut vault = Vault::open_at(&path, &key).unwrap();
        vault.upsert_conversation(conversation.clone()).unwrap();

        let outgoing_envelope = CiphertextEnvelope {
            id: Uuid::new_v4(),
            conversation_id,
            sender_device_id: local_device,
            sender_handle: "alice".into(),
            recipients: vec![peer_device],
            kind: EnvelopeKind::Application,
            mutation_id: None,
            ciphertext: "outgoing-ciphertext".into(),
            created_at: Utc::now(),
        };
        vault
            .queue_message(
                VaultMessage {
                    id: outgoing_id,
                    conversation_id,
                    author: "You".into(),
                    text: "status target".into(),
                    mine: true,
                    sent_at: Utc::now(),
                    delivery: DeliveryState::Pending,
                    attachment: None,
                    reply_to: None,
                    thread_root: None,
                    locally_read: true,
                },
                outgoing_envelope.clone(),
            )
            .unwrap();
        vault.complete_outbox(outgoing_envelope.id).unwrap();

        for (id, text, reply_to, thread_root) in [
            (root_message_id, "root", None, None),
            (
                thread_message_id,
                "thread reply",
                Some(root_message_id),
                Some(root_message_id),
            ),
        ] {
            vault
                .store_inbound(
                    conversation.clone(),
                    VaultMessage {
                        id,
                        conversation_id,
                        author: "@bob".into(),
                        text: text.into(),
                        mine: false,
                        sent_at: Utc::now(),
                        delivery: DeliveryState::Received,
                        attachment: None,
                        reply_to,
                        thread_root,
                        locally_read: false,
                    },
                    true,
                )
                .unwrap();
        }
        assert_eq!(vault.pending_receipt_batches().len(), 1);
        assert_eq!(
            vault.pending_receipt_batches()[0].kind,
            ReceiptKind::Delivered
        );
        assert_eq!(
            vault.mark_read(conversation_id, ReadScope::Main).unwrap(),
            vec![root_message_id]
        );
        assert_eq!(vault.conversations()[0].unread, 1);
        drop(vault);

        let mut vault = Vault::open_at(&path, &key).unwrap();
        let delivered = vault
            .pending_receipt_batches()
            .into_iter()
            .find(|batch| batch.kind == ReceiptKind::Delivered)
            .unwrap();
        assert_eq!(delivered.message_ids.len(), 2);
        let receipt_envelope = CiphertextEnvelope {
            id: Uuid::new_v4(),
            conversation_id,
            sender_device_id: local_device,
            sender_handle: "alice".into(),
            recipients: vec![peer_device],
            kind: EnvelopeKind::Application,
            mutation_id: None,
            ciphertext: "encrypted-delivery-receipt".into(),
            created_at: Utc::now(),
        };
        vault
            .queue_receipt(delivered.clone(), receipt_envelope)
            .unwrap();
        assert_eq!(vault.outbox().len(), 1);
        assert!(
            vault
                .pending_receipt_batches()
                .iter()
                .all(|batch| batch.kind != ReceiptKind::Delivered)
        );
        assert!(
            vault
                .cancel_application_outbox(conversation_id)
                .unwrap()
                .is_empty()
        );
        assert!(
            vault.pending_receipt_batches().iter().any(|batch| {
                batch.kind == ReceiptKind::Delivered && batch.message_ids.len() == 2
            })
        );

        assert_eq!(
            vault
                .apply_receipt(conversation_id, ReceiptKind::Delivered, &[outgoing_id])
                .unwrap(),
            vec![(outgoing_id, DeliveryState::Delivered)]
        );
        assert_eq!(
            vault
                .apply_receipt(conversation_id, ReceiptKind::Read, &[outgoing_id])
                .unwrap(),
            vec![(outgoing_id, DeliveryState::Read)]
        );
        assert!(
            vault
                .apply_receipt(conversation_id, ReceiptKind::Delivered, &[outgoing_id])
                .unwrap()
                .is_empty()
        );
        let normalized = normalize_history_message(
            vault
                .messages()
                .iter()
                .find(|message| message.id == thread_message_id)
                .unwrap(),
        );
        assert_eq!(normalized.reply_to, Some(root_message_id));
        assert_eq!(normalized.thread_root, Some(root_message_id));
        assert_eq!(
            vault
                .mark_read(conversation_id, ReadScope::Thread(root_message_id))
                .unwrap(),
            vec![thread_message_id]
        );
        assert_eq!(vault.conversations()[0].unread, 0);
        vault.set_read_receipts(false).unwrap();
        assert!(!vault.settings().send_read_receipts);
        drop(vault);

        let mut vault = Vault::open_at(&path, &key).unwrap();
        assert!(!vault.settings().send_read_receipts);
        assert_eq!(
            vault
                .messages()
                .iter()
                .find(|message| message.id == outgoing_id)
                .unwrap()
                .delivery,
            DeliveryState::Read
        );
        assert_eq!(
            normalize_history_message(
                vault
                    .messages()
                    .iter()
                    .find(|message| message.id == outgoing_id)
                    .unwrap()
            )
            .receipt,
            Some(ReceiptKind::Read)
        );
        let legacy_unread_id = Uuid::new_v4();
        vault.data.version = 0;
        vault.data.conversations[0].unread = 1;
        vault.data.messages.push(VaultMessage {
            id: legacy_unread_id,
            conversation_id,
            author: "@bob".into(),
            text: "legacy unread".into(),
            mine: false,
            sent_at: Utc::now(),
            delivery: DeliveryState::Received,
            attachment: None,
            reply_to: None,
            thread_root: None,
            locally_read: true,
        });
        vault.persist().unwrap();
        drop(vault);
        let vault = Vault::open_at(&path, &key).unwrap();
        assert_eq!(vault.data.version, VAULT_DATA_VERSION);
        assert!(
            !vault
                .messages()
                .iter()
                .find(|message| message.id == legacy_unread_id)
                .unwrap()
                .locally_read
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verification_record_is_encrypted_persistent_and_replaceable() {
        let root = std::env::temp_dir().join(format!("mutte-vault-verify-{}", Uuid::new_v4()));
        let path = root.join("vault.json");
        let key = [46u8; 32];
        let conversation_id = Uuid::new_v4();
        let mut vault = Vault::open_at(&path, &key).expect("create vault");
        vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "bob".into(),
                unread: 0,
            })
            .unwrap();
        let first = "A".repeat(64);
        vault
            .verify_conversation(conversation_id, &first)
            .expect("verify conversation");
        assert!(
            !fs::read(&path)
                .unwrap()
                .windows(first.len())
                .any(|window| window == first.as_bytes())
        );
        drop(vault);

        let mut vault = Vault::open_at(&path, &key).expect("restart vault");
        assert_eq!(
            vault.verification(conversation_id).unwrap().fingerprint,
            first
        );
        let changed = "B".repeat(64);
        vault
            .verify_conversation(conversation_id, &changed)
            .expect("replace verification");
        assert_eq!(vault.data.verifications.len(), 1);
        assert_eq!(
            vault.verification(conversation_id).unwrap().fingerprint,
            changed
        );
        assert!(
            vault
                .verify_conversation(conversation_id, &"a".repeat(64))
                .is_err()
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn failed_persistence_rolls_back_in_memory_state() {
        let root = std::env::temp_dir().join(format!("mutte-vault-rollback-{}", Uuid::new_v4()));
        let path = root.join("vault.json");
        let mut vault = Vault::open_at(&path, &[44u8; 32]).expect("create vault");
        let blocker = root.join("not-a-directory");
        fs::write(&blocker, b"block").expect("create blocker");
        vault.path = blocker.join("vault.json");

        assert!(
            vault
                .upsert_conversation(VaultConversation {
                    id: Uuid::new_v4(),
                    peer_handle: "rollback-marker".into(),
                    unread: 0,
                })
                .is_err()
        );
        assert!(vault.conversations().is_empty());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn plaintext_state_is_migrated_then_removed() {
        let root = std::env::temp_dir().join(format!("mutte-vault-migrate-{}", Uuid::new_v4()));
        let path = root.join("vault.json");
        let conversations_path = root.join("conversations.json");
        let session_path = root.join("session.json");
        let conversation_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let server = Url::parse("https://chat.example.test").unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(
            &conversations_path,
            serde_json::to_vec(&serde_json::json!([{
                "id": conversation_id,
                "peer_handle": "migration-peer-marker"
            }]))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &session_path,
            serde_json::to_vec(&serde_json::json!({
                "server": server,
                "access_token": "migration-token-marker",
                "device_id": device_id,
                "profile": {
                    "id": Uuid::new_v4(),
                    "handle": "migrated",
                    "display_name": "Migrated",
                    "bio": "",
                    "status": "quiet"
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let mut vault = Vault::open_at(&path, &[45u8; 32]).expect("create vault");
        assert_eq!(
            vault
                .migrate_legacy_conversations_at(&conversations_path)
                .expect("migrate conversations"),
            1
        );
        assert!(
            vault
                .migrate_legacy_session_at(&session_path)
                .expect("migrate session")
        );
        assert!(!conversations_path.exists());
        assert!(!session_path.exists());
        let session = vault.load_session(&server).expect("load migrated session");
        assert_eq!(session.device_id, device_id);
        assert_eq!(
            session.access_token.expose_secret(),
            "migration-token-marker"
        );
        let encrypted = fs::read(&path).unwrap();
        assert!(
            !encrypted
                .windows(22)
                .any(|window| { window == b"migration-token-marker" })
        );
        assert!(
            !encrypted
                .windows(21)
                .any(|window| { window == b"migration-peer-marker" })
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn epoch_change_cancels_only_application_outbox_and_persists_revocation() {
        let root = std::env::temp_dir().join(format!("mutte-vault-revoke-{}", Uuid::new_v4()));
        let path = root.join("vault.json");
        let key = [44u8; 32];
        let conversation_id = Uuid::new_v4();
        let message_id = Uuid::new_v4();
        let application = CiphertextEnvelope {
            id: Uuid::new_v4(),
            conversation_id,
            sender_device_id: Uuid::new_v4(),
            sender_handle: "alice".into(),
            recipients: vec![Uuid::new_v4()],
            kind: mutte_protocol::EnvelopeKind::Application,
            mutation_id: None,
            ciphertext: "old-epoch".into(),
            created_at: Utc::now(),
        };
        let commit = CiphertextEnvelope {
            id: Uuid::new_v4(),
            conversation_id,
            sender_device_id: application.sender_device_id,
            sender_handle: "alice".into(),
            recipients: application.recipients.clone(),
            kind: mutte_protocol::EnvelopeKind::Commit,
            mutation_id: Some(Uuid::new_v4()),
            ciphertext: "new-epoch".into(),
            created_at: Utc::now(),
        };
        let revocation = PendingDeviceRevocation {
            request_id: Uuid::new_v4(),
            target_device_id: Uuid::new_v4(),
            confirmation_url: "https://relay.invalid/auth/revoke#secret".into(),
            expires_at: Utc::now(),
        };
        let mut vault = Vault::open_at(&path, &key).unwrap();
        vault
            .queue_message(
                VaultMessage {
                    id: message_id,
                    conversation_id,
                    author: "You".into(),
                    text: "do not retry me".into(),
                    mine: true,
                    sent_at: Utc::now(),
                    delivery: DeliveryState::Pending,
                    attachment: None,
                    reply_to: None,
                    thread_root: None,
                    locally_read: true,
                },
                application,
            )
            .unwrap();
        vault.queue_commit(commit.clone()).unwrap();
        vault
            .save_pending_device_revocation(revocation.clone())
            .unwrap();

        assert_eq!(
            vault.cancel_application_outbox(conversation_id).unwrap(),
            vec![message_id]
        );
        assert_eq!(vault.messages()[0].delivery, DeliveryState::Cancelled);
        assert_eq!(vault.outbox().len(), 1);
        assert_eq!(vault.outbox()[0].envelope.id, commit.id);
        assert!(vault.has_pending_control(conversation_id));
        vault.complete_outbox(commit.id).unwrap();
        assert!(!vault.has_pending_control(conversation_id));
        drop(vault);

        let mut vault = Vault::open_at(&path, &key).unwrap();
        assert_eq!(vault.pending_device_revocation(), Some(&revocation));
        assert_eq!(vault.messages()[0].delivery, DeliveryState::Cancelled);
        vault
            .clear_pending_device_revocation(revocation.request_id)
            .unwrap();
        assert!(vault.pending_device_revocation().is_none());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn platform_master_key_provider_derives_stable_isolated_subkeys() {
        struct TestProvider;

        impl MasterKeyProvider for TestProvider {
            fn load_or_create_master_key(&self) -> Result<Zeroizing<[u8; 32]>> {
                Ok(Zeroizing::new([91; 32]))
            }
        }

        let first = VaultKey::from_provider(&TestProvider).unwrap();
        let second = VaultKey::from_provider(&TestProvider).unwrap();
        assert_eq!(
            first.device_storage_key().unwrap(),
            second.device_storage_key().unwrap()
        );
        assert_eq!(
            first.message_storage_key().unwrap(),
            second.message_storage_key().unwrap()
        );
        assert_ne!(
            *first.device_storage_key().unwrap(),
            *first.message_storage_key().unwrap()
        );
    }
}
