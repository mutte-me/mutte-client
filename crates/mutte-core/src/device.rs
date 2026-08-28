use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::RwLock,
};

use ::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{DateTime, Utc};
use directories::ProjectDirs;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider;
use openmls_traits::OpenMlsProvider;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const DEVICE_FILE_FORMAT: &str = "mutte-device/v1";
const DEVICE_FILE_AAD: &[u8] = b"mutte-device/v1";
const LEGACY_DEVICE_FILE_FORMAT: &str = "omt-device/v1";
const LEGACY_DEVICE_FILE_AAD: &[u8] = b"omt-device/v1";
// The v1 safety-code domain is protocol state, not UI branding. Keeping it
// stable preserves accepted fingerprints across the OMT -> Mutte rename.
const SAFETY_CODE_DOMAIN: &[u8] = b"OMT MLS member safety code v1\0";

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("unable to locate the user configuration directory")]
    NoConfigDirectory,
    #[error("device identity is corrupt: {0}")]
    Corrupt(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("OpenMLS operation failed: {0}")]
    Mls(String),
    #[error("device identity encryption failed")]
    Encryption,
}

#[derive(Deserialize, Serialize)]
struct EncryptedIdentity {
    format: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct IdentityFormatProbe {
    format: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct StoredIdentity {
    device_id: Uuid,
    credential: Vec<u8>,
    signer: SignatureKeyPair,
    #[serde(default)]
    mls_storage: Vec<StoredMlsValue>,
    #[serde(default)]
    pending_applications: Vec<PendingApplication>,
    #[serde(default)]
    pending_commits: Vec<PendingCommit>,
    #[serde(default)]
    pending_removals: Vec<ConversationRemoval>,
    #[serde(default)]
    pending_additions: Vec<ConversationAddition>,
}

#[derive(Serialize)]
struct StoredIdentityRef<'a> {
    device_id: Uuid,
    credential: &'a [u8],
    signer: &'a SignatureKeyPair,
    mls_storage: Vec<StoredMlsValue>,
    pending_applications: &'a [PendingApplication],
    pending_commits: &'a [PendingCommit],
    pending_removals: &'a [ConversationRemoval],
    pending_additions: &'a [ConversationAddition],
}

#[derive(Clone, Deserialize, Serialize)]
struct StoredMlsValue {
    key: String,
    value: String,
}

/// An application message that has been decrypted and durably staged, but not
/// yet acknowledged to the relay. Keeping this beside the MLS ratchet state
/// makes inbound processing crash-safe.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PendingApplication {
    pub delivery_id: i64,
    pub conversation_id: Uuid,
    pub sender_device_id: Uuid,
    pub sender_handle: String,
    pub plaintext: Vec<u8>,
    #[serde(default)]
    pub kind: PendingApplicationKind,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PendingApplicationKind {
    #[default]
    Chat,
    DeviceSync,
    HistorySync,
}

/// The durable result of an MLS Commit that has advanced the local epoch but
/// has not yet been acknowledged to the relay.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PendingCommit {
    pub delivery_id: i64,
    pub conversation_id: Uuid,
    pub sender_device_id: Uuid,
    #[serde(default)]
    pub added_devices: Vec<Uuid>,
    pub removed_devices: Vec<Uuid>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationBootstrap {
    pub welcome: String,
    pub recipient_devices: Vec<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConversationRemoval {
    #[serde(default)]
    pub mutation_id: Option<Uuid>,
    pub envelope_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub conversation_id: Uuid,
    pub commit: String,
    pub recipient_devices: Vec<Uuid>,
    pub removed_device: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConversationAddition {
    #[serde(default)]
    pub mutation_id: Option<Uuid>,
    pub commit_envelope_id: Uuid,
    pub welcome_envelope_id: Uuid,
    pub sync_envelope_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub conversation_id: Uuid,
    pub commit: String,
    pub welcome: String,
    pub sync_message: String,
    pub existing_recipient_devices: Vec<Uuid>,
    pub added_device: Uuid,
}

/// A deterministic fingerprint of the authenticated MLS member signing keys.
/// Both endpoints of the same group compute the same value. It deliberately
/// excludes relay-controlled profile fields and the group id, so a repeated
/// 1:1 relationship between the same device set has a stable comparison code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationSafetyCode {
    fingerprint: [u8; 32],
    member_devices: Vec<Uuid>,
}

impl ConversationSafetyCode {
    pub fn fingerprint(&self) -> String {
        let mut encoded = String::with_capacity(64);
        for byte in self.fingerprint {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02X}").expect("writing to a String cannot fail");
        }
        encoded
    }

    pub fn member_devices(&self) -> &[Uuid] {
        &self.member_devices
    }
}

/// A local device identity. All serialized signing, KeyPackage, group, ratchet,
/// and pending-inbox state is authenticated and encrypted at rest.
pub struct Device {
    id: Uuid,
    credential: CredentialWithKey,
    signer: SignatureKeyPair,
    provider: Provider,
    path: PathBuf,
    pending_applications: RwLock<Vec<PendingApplication>>,
    pending_commits: RwLock<Vec<PendingCommit>>,
    pending_removals: RwLock<Vec<ConversationRemoval>>,
    pending_additions: RwLock<Vec<ConversationAddition>>,
    storage_key: SecretBox<[u8; 32]>,
}

impl Device {
    pub fn load_or_create(storage_key: &[u8; 32]) -> Result<Self, DeviceError> {
        let project =
            ProjectDirs::from("chat", "mutte", "mutte").ok_or(DeviceError::NoConfigDirectory)?;
        Self::load_or_create_at(project.config_dir().join("device.json"), storage_key)
    }

    pub fn load_or_create_at(
        path: impl Into<PathBuf>,
        storage_key: &[u8; 32],
    ) -> Result<Self, DeviceError> {
        let path = path.into();
        if path.exists() {
            return Self::load(path, storage_key);
        }
        let provider = Provider::new().map_err(|error| DeviceError::Mls(error.to_string()))?;
        let id = Uuid::new_v4();
        let credential = Credential::new(CredentialType::Basic, id.as_bytes().to_vec());
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|error| DeviceError::Mls(error.to_string()))?;
        signer
            .store(provider.storage())
            .map_err(|error| DeviceError::Mls(error.to_string()))?;
        let credential = CredentialWithKey {
            credential,
            signature_key: signer.public().into(),
        };
        let device = Self {
            id,
            credential,
            signer,
            provider,
            path,
            pending_applications: RwLock::new(Vec::new()),
            pending_commits: RwLock::new(Vec::new()),
            pending_removals: RwLock::new(Vec::new()),
            pending_additions: RwLock::new(Vec::new()),
            storage_key: SecretBox::new(Box::new(*storage_key)),
        };
        device.persist()?;
        Ok(device)
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn key_package(&self) -> Result<String, DeviceError> {
        Ok(self.key_packages(1)?.remove(0))
    }

    pub fn key_packages(&self, count: usize) -> Result<Vec<String>, DeviceError> {
        if !(1..=64).contains(&count) {
            return Err(DeviceError::Corrupt(
                "key package batch must contain between 1 and 64 packages".into(),
            ));
        }
        let mut packages = Vec::with_capacity(count);
        for _ in 0..count {
            let bundle = KeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    &self.provider,
                    &self.signer,
                    self.credential.clone(),
                )
                .map_err(|error| DeviceError::Mls(error.to_string()))?;
            let bytes = bundle
                .key_package()
                .tls_serialize_detached()
                .map_err(mls_error)?;
            packages.push(URL_SAFE_NO_PAD.encode(bytes));
        }
        self.persist()?;
        Ok(packages)
    }

    /// Creates a two-party MLS conversation and returns the Welcome to fan out
    /// to every claimed device KeyPackage belonging to the peer.
    pub fn create_conversation(
        &self,
        conversation_id: Uuid,
        peer_key_packages: &[(Uuid, String)],
    ) -> Result<ConversationBootstrap, DeviceError> {
        if peer_key_packages.is_empty() {
            return Err(DeviceError::Corrupt(
                "the peer has no available device key packages".into(),
            ));
        }
        if self.has_conversation(conversation_id)? {
            return Err(DeviceError::Corrupt(
                "conversation id already exists locally".into(),
            ));
        }
        let mut packages = Vec::with_capacity(peer_key_packages.len());
        let mut recipients = Vec::with_capacity(peer_key_packages.len());
        for (device_id, encoded) in peer_key_packages {
            let package = decode_key_package(encoded, &self.provider)?;
            let credential_device = uuid_from_credential(package.leaf_node().credential())?;
            if credential_device != *device_id {
                return Err(DeviceError::Corrupt(
                    "key package credential does not match its device record".into(),
                ));
            }
            packages.push(package);
            recipients.push(*device_id);
        }

        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let mut group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            group_id(conversation_id),
            self.credential.clone(),
        )
        .map_err(mls_error)?;
        let (_, welcome, _) = group
            .add_members(&self.provider, &self.signer, &packages)
            .map_err(mls_error)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(mls_error)?;
        let welcome = welcome.tls_serialize_detached().map_err(mls_error)?;
        self.persist()?;
        Ok(ConversationBootstrap {
            welcome: URL_SAFE_NO_PAD.encode(welcome),
            recipient_devices: recipients,
        })
    }

    /// Joins a conversation from a Welcome. Returns `false` when this Welcome
    /// was already processed, allowing a redelivered mailbox item to be acked.
    pub fn join_conversation(
        &self,
        conversation_id: Uuid,
        expected_sender: Uuid,
        encoded_welcome: &str,
    ) -> Result<bool, DeviceError> {
        if self.has_conversation(conversation_id)? {
            // A prior write may have failed after OpenMLS updated its in-memory
            // provider. Re-confirm durability before a redelivery can be acked.
            self.persist()?;
            return Ok(false);
        }
        let message = decode_mls_message(encoded_welcome)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(DeviceError::Corrupt("expected an MLS Welcome".into()));
        };
        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            None,
        )
        .map_err(mls_error)?;
        if staged.group_context().group_id().as_slice() != conversation_id.as_bytes() {
            return Err(DeviceError::Corrupt(
                "Welcome group id does not match its envelope".into(),
            ));
        }
        let sender =
            uuid_from_credential(staged.welcome_sender().map_err(mls_error)?.credential())?;
        if sender != expected_sender {
            return Err(DeviceError::Corrupt(
                "Welcome sender does not match its envelope".into(),
            ));
        }
        staged.into_group(&self.provider).map_err(mls_error)?;
        self.persist()?;
        Ok(true)
    }

    pub fn has_conversation(&self, conversation_id: Uuid) -> Result<bool, DeviceError> {
        Ok(
            MlsGroup::load(self.provider.storage(), &group_id(conversation_id))
                .map_err(mls_error)?
                .is_some(),
        )
    }

    /// Returns authenticated MLS member device ids, excluding this device.
    pub fn recipient_devices(&self, conversation_id: Uuid) -> Result<Vec<Uuid>, DeviceError> {
        let group = self.load_group(conversation_id)?;
        let mut recipients = Vec::new();
        for member in group.members() {
            let device_id = uuid_from_credential(&member.credential)?;
            if device_id != self.id {
                recipients.push(device_id);
            }
        }
        if recipients.is_empty() {
            return Err(DeviceError::Corrupt(
                "conversation has no recipient devices".into(),
            ));
        }
        Ok(recipients)
    }

    pub fn conversation_contains_device(
        &self,
        conversation_id: Uuid,
        device_id: Uuid,
    ) -> Result<bool, DeviceError> {
        let group = self.load_group(conversation_id)?;
        for member in group.members() {
            if uuid_from_credential(&member.credential)? == device_id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Removes one device with a proposal-by-value Commit, advances the local
    /// epoch, and returns the opaque Commit for every remaining peer device.
    pub fn remove_device(
        &self,
        conversation_id: Uuid,
        target_device: Uuid,
        mutation_id: Uuid,
    ) -> Result<ConversationRemoval, DeviceError> {
        if target_device == self.id {
            return Err(DeviceError::Corrupt(
                "a device cannot commit its own removal".into(),
            ));
        }
        if let Some(pending) = self
            .pending_removals
            .read()
            .map_err(|_| DeviceError::Corrupt("pending removal lock poisoned".into()))?
            .iter()
            .find(|item| {
                item.conversation_id == conversation_id && item.removed_device == target_device
            })
            .cloned()
        {
            return Ok(pending);
        }
        let mut group = self.load_group(conversation_id)?;
        let mut target_index = None;
        let mut recipients = Vec::new();
        for member in group.members() {
            let member_device = uuid_from_credential(&member.credential)?;
            if member_device == target_device {
                target_index = Some(member.index);
            } else if member_device != self.id {
                recipients.push(member_device);
            }
        }
        let target_index = target_index.ok_or_else(|| {
            DeviceError::Corrupt("revoked device is not an MLS conversation member".into())
        })?;
        recipients.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        recipients.dedup();
        let (commit, _, _) = group
            .remove_members(&self.provider, &self.signer, &[target_index])
            .map_err(mls_error)?;
        let bytes = commit.tls_serialize_detached().map_err(mls_error)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(mls_error)?;
        if group
            .members()
            .map(|member| uuid_from_credential(&member.credential))
            .collect::<Result<Vec<_>, _>>()?
            .contains(&target_device)
        {
            return Err(DeviceError::Corrupt(
                "MLS removal did not remove the requested device".into(),
            ));
        }
        let removal = ConversationRemoval {
            mutation_id: Some(mutation_id),
            envelope_id: Uuid::new_v4(),
            created_at: Utc::now(),
            conversation_id,
            commit: URL_SAFE_NO_PAD.encode(bytes),
            recipient_devices: recipients,
            removed_device: target_device,
        };
        self.pending_removals
            .write()
            .map_err(|_| DeviceError::Corrupt("pending removal lock poisoned".into()))?
            .push(removal.clone());
        self.persist()?;
        Ok(removal)
    }

    /// Adds one authenticated same-account device to an existing conversation,
    /// advances the epoch, and stages the Commit, Welcome, and encrypted sync
    /// payload as one recoverable outbound operation.
    pub fn add_device(
        &self,
        conversation_id: Uuid,
        target_device: Uuid,
        mutation_id: Uuid,
        encoded_key_package: &str,
        sync_payload: &[u8],
    ) -> Result<ConversationAddition, DeviceError> {
        if target_device == self.id {
            return Err(DeviceError::Corrupt(
                "a device cannot add itself to its own group".into(),
            ));
        }
        if let Some(pending) = self
            .pending_additions
            .read()
            .map_err(|_| DeviceError::Corrupt("pending addition lock poisoned".into()))?
            .iter()
            .find(|item| {
                item.conversation_id == conversation_id && item.added_device == target_device
            })
            .cloned()
        {
            return Ok(pending);
        }
        let mut group = self.load_group(conversation_id)?;
        let mut existing_recipients = Vec::new();
        for member in group.members() {
            let member_device = uuid_from_credential(&member.credential)?;
            if member_device == target_device {
                return Err(DeviceError::Corrupt(
                    "target device is already a conversation member".into(),
                ));
            }
            if member_device != self.id {
                existing_recipients.push(member_device);
            }
        }
        existing_recipients.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        existing_recipients.dedup();
        let package = decode_key_package(encoded_key_package, &self.provider)?;
        if uuid_from_credential(package.leaf_node().credential())? != target_device {
            return Err(DeviceError::Corrupt(
                "key package credential does not match target device".into(),
            ));
        }
        let (commit, welcome, _) = group
            .add_members(&self.provider, &self.signer, &[package])
            .map_err(mls_error)?;
        let commit = commit.tls_serialize_detached().map_err(mls_error)?;
        let welcome = welcome.tls_serialize_detached().map_err(mls_error)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(mls_error)?;
        if !group
            .members()
            .map(|member| uuid_from_credential(&member.credential))
            .collect::<Result<Vec<_>, _>>()?
            .contains(&target_device)
        {
            return Err(DeviceError::Corrupt(
                "MLS addition did not add the requested device".into(),
            ));
        }
        let sync_message = group
            .create_message(&self.provider, &self.signer, sync_payload)
            .map_err(mls_error)?
            .tls_serialize_detached()
            .map_err(mls_error)?;
        let addition = ConversationAddition {
            mutation_id: Some(mutation_id),
            commit_envelope_id: Uuid::new_v4(),
            welcome_envelope_id: Uuid::new_v4(),
            sync_envelope_id: Uuid::new_v4(),
            created_at: Utc::now(),
            conversation_id,
            commit: URL_SAFE_NO_PAD.encode(commit),
            welcome: URL_SAFE_NO_PAD.encode(welcome),
            sync_message: URL_SAFE_NO_PAD.encode(sync_message),
            existing_recipient_devices: existing_recipients,
            added_device: target_device,
        };
        self.pending_additions
            .write()
            .map_err(|_| DeviceError::Corrupt("pending addition lock poisoned".into()))?
            .push(addition.clone());
        self.persist()?;
        Ok(addition)
    }

    /// Computes a user-comparable code from the MLS-authenticated member
    /// device ids and Ed25519 signature keys in the current ratchet tree.
    pub fn conversation_safety_code(
        &self,
        conversation_id: Uuid,
    ) -> Result<ConversationSafetyCode, DeviceError> {
        let group = self.load_group(conversation_id)?;
        let mut members = group
            .members()
            .map(|member| {
                let device_id = uuid_from_credential(&member.credential)?;
                if member.signature_key.len() != 32 {
                    return Err(DeviceError::Corrupt(
                        "MLS member has an invalid Ed25519 signature key".into(),
                    ));
                }
                Ok((device_id, member.signature_key))
            })
            .collect::<Result<Vec<_>, DeviceError>>()?;
        if members.len() < 2 {
            return Err(DeviceError::Corrupt(
                "conversation safety code requires at least two MLS members".into(),
            ));
        }
        members.sort_by(|left, right| {
            left.0
                .as_bytes()
                .cmp(right.0.as_bytes())
                .then_with(|| left.1.cmp(&right.1))
        });
        let mut identifiers = HashSet::with_capacity(members.len());
        if members
            .iter()
            .any(|(device_id, _)| !identifiers.insert(*device_id))
        {
            return Err(DeviceError::Corrupt(
                "conversation contains a duplicate MLS device identity".into(),
            ));
        }
        let fingerprint = safety_fingerprint(&members);
        Ok(ConversationSafetyCode {
            fingerprint,
            member_devices: members
                .into_iter()
                .map(|(device_id, _)| device_id)
                .collect(),
        })
    }

    pub fn encrypt_application(
        &self,
        conversation_id: Uuid,
        plaintext: &[u8],
    ) -> Result<String, DeviceError> {
        let mut group = self.load_group(conversation_id)?;
        let message = group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(mls_error)?;
        let bytes = message.tls_serialize_detached().map_err(mls_error)?;
        // Persist the advanced sender ratchet before the ciphertext can leave
        // the process. A failed send safely burns one generation.
        self.persist()?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Decrypts and durably stages one relay delivery. Repeating an id returns
    /// the staged plaintext without touching the MLS ratchet again.
    pub fn decrypt_application(
        &self,
        delivery_id: i64,
        conversation_id: Uuid,
        expected_sender: Uuid,
        sender_handle: &str,
        encoded_message: &str,
    ) -> Result<PendingApplication, DeviceError> {
        self.decrypt_application_kind(
            delivery_id,
            conversation_id,
            expected_sender,
            sender_handle,
            encoded_message,
            PendingApplicationKind::Chat,
        )
    }

    pub fn decrypt_device_sync(
        &self,
        delivery_id: i64,
        conversation_id: Uuid,
        expected_sender: Uuid,
        sender_handle: &str,
        encoded_message: &str,
    ) -> Result<PendingApplication, DeviceError> {
        self.decrypt_application_kind(
            delivery_id,
            conversation_id,
            expected_sender,
            sender_handle,
            encoded_message,
            PendingApplicationKind::DeviceSync,
        )
    }

    pub fn decrypt_history_sync(
        &self,
        delivery_id: i64,
        conversation_id: Uuid,
        expected_sender: Uuid,
        sender_handle: &str,
        encoded_message: &str,
    ) -> Result<PendingApplication, DeviceError> {
        self.decrypt_application_kind(
            delivery_id,
            conversation_id,
            expected_sender,
            sender_handle,
            encoded_message,
            PendingApplicationKind::HistorySync,
        )
    }

    fn decrypt_application_kind(
        &self,
        delivery_id: i64,
        conversation_id: Uuid,
        expected_sender: Uuid,
        sender_handle: &str,
        encoded_message: &str,
        kind: PendingApplicationKind,
    ) -> Result<PendingApplication, DeviceError> {
        if let Some(pending) = self
            .pending_applications
            .read()
            .map_err(|_| DeviceError::Corrupt("pending inbox lock poisoned".into()))?
            .iter()
            .find(|item| item.delivery_id == delivery_id)
            .cloned()
        {
            // A previous persistence attempt may have failed after the in-memory
            // ratchet advanced. Re-confirm durability before allowing an ack.
            self.persist()?;
            return Ok(pending);
        }
        let mut group = self.load_group(conversation_id)?;
        let protocol_message = decode_mls_message(encoded_message)?
            .try_into_protocol_message()
            .map_err(mls_error)?;
        let processed = group
            .process_message(&self.provider, protocol_message)
            .map_err(mls_error)?;
        let sender = uuid_from_credential(processed.credential())?;
        if sender != expected_sender {
            return Err(DeviceError::Corrupt(
                "application sender does not match its envelope".into(),
            ));
        }
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            return Err(DeviceError::Corrupt(
                "unsupported MLS handshake message in application envelope".into(),
            ));
        };
        let pending = PendingApplication {
            delivery_id,
            conversation_id,
            sender_device_id: sender,
            sender_handle: sender_handle.to_owned(),
            plaintext: application.into_bytes(),
            kind,
        };
        self.pending_applications
            .write()
            .map_err(|_| DeviceError::Corrupt("pending inbox lock poisoned".into()))?
            .push(pending.clone());
        self.persist()?;
        Ok(pending)
    }

    /// Processes and durably stages a membership Commit before it may be
    /// acknowledged. A repeated relay delivery is returned from the durable
    /// staging record without applying the Commit twice.
    pub fn process_commit(
        &self,
        delivery_id: i64,
        conversation_id: Uuid,
        expected_sender: Uuid,
        encoded_commit: &str,
    ) -> Result<PendingCommit, DeviceError> {
        if let Some(pending) = self
            .pending_commits
            .read()
            .map_err(|_| DeviceError::Corrupt("pending commit lock poisoned".into()))?
            .iter()
            .find(|item| item.delivery_id == delivery_id)
            .cloned()
        {
            self.persist()?;
            return Ok(pending);
        }
        let mut group = self.load_group(conversation_id)?;
        let before = group
            .members()
            .map(|member| uuid_from_credential(&member.credential))
            .collect::<Result<HashSet<_>, _>>()?;
        let protocol_message = decode_mls_message(encoded_commit)?
            .try_into_protocol_message()
            .map_err(mls_error)?;
        let processed = group
            .process_message(&self.provider, protocol_message)
            .map_err(mls_error)?;
        let sender = uuid_from_credential(processed.credential())?;
        if sender != expected_sender {
            return Err(DeviceError::Corrupt(
                "commit sender does not match its envelope".into(),
            ));
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(DeviceError::Corrupt(
                "expected an MLS Commit in commit envelope".into(),
            ));
        };
        group
            .merge_staged_commit(&self.provider, *staged)
            .map_err(mls_error)?;
        let after = group
            .members()
            .map(|member| uuid_from_credential(&member.credential))
            .collect::<Result<HashSet<_>, _>>()?;
        let mut removed_devices = before.difference(&after).copied().collect::<Vec<_>>();
        removed_devices.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut added_devices = after.difference(&before).copied().collect::<Vec<_>>();
        added_devices.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if removed_devices.is_empty() && added_devices.is_empty() {
            return Err(DeviceError::Corrupt(
                "commit envelope did not change device membership".into(),
            ));
        }
        let pending = PendingCommit {
            delivery_id,
            conversation_id,
            sender_device_id: sender,
            added_devices,
            removed_devices,
        };
        self.pending_commits
            .write()
            .map_err(|_| DeviceError::Corrupt("pending commit lock poisoned".into()))?
            .push(pending.clone());
        self.persist()?;
        Ok(pending)
    }

    pub fn pending_applications(&self) -> Result<Vec<PendingApplication>, DeviceError> {
        Ok(self
            .pending_applications
            .read()
            .map_err(|_| DeviceError::Corrupt("pending inbox lock poisoned".into()))?
            .clone())
    }

    pub fn pending_commits(&self) -> Result<Vec<PendingCommit>, DeviceError> {
        Ok(self
            .pending_commits
            .read()
            .map_err(|_| DeviceError::Corrupt("pending commit lock poisoned".into()))?
            .clone())
    }

    pub fn pending_removals(&self) -> Result<Vec<ConversationRemoval>, DeviceError> {
        Ok(self
            .pending_removals
            .read()
            .map_err(|_| DeviceError::Corrupt("pending removal lock poisoned".into()))?
            .clone())
    }

    pub fn pending_additions(&self) -> Result<Vec<ConversationAddition>, DeviceError> {
        Ok(self
            .pending_additions
            .read()
            .map_err(|_| DeviceError::Corrupt("pending addition lock poisoned".into()))?
            .clone())
    }

    /// Completes the handoff from encrypted MLS state to the encrypted client
    /// outbox. Calling this after the outbox write makes removal Commit
    /// creation recoverable without ever creating two different Commits.
    pub fn complete_removal(&self, envelope_id: Uuid) -> Result<(), DeviceError> {
        self.pending_removals
            .write()
            .map_err(|_| DeviceError::Corrupt("pending removal lock poisoned".into()))?
            .retain(|item| item.envelope_id != envelope_id);
        self.persist()
    }

    pub fn complete_addition(&self, sync_envelope_id: Uuid) -> Result<(), DeviceError> {
        self.pending_additions
            .write()
            .map_err(|_| DeviceError::Corrupt("pending addition lock poisoned".into()))?
            .retain(|item| item.sync_envelope_id != sync_envelope_id);
        self.persist()
    }

    pub fn complete_delivery(&self, delivery_id: i64) -> Result<(), DeviceError> {
        self.pending_applications
            .write()
            .map_err(|_| DeviceError::Corrupt("pending inbox lock poisoned".into()))?
            .retain(|item| item.delivery_id != delivery_id);
        self.persist()
    }

    pub fn complete_commit_delivery(&self, delivery_id: i64) -> Result<(), DeviceError> {
        self.pending_commits
            .write()
            .map_err(|_| DeviceError::Corrupt("pending commit lock poisoned".into()))?
            .retain(|item| item.delivery_id != delivery_id);
        self.persist()
    }

    pub fn storage_path(&self) -> &Path {
        &self.path
    }

    fn load(path: PathBuf, storage_key: &[u8; 32]) -> Result<Self, DeviceError> {
        let bytes = fs::read(&path)?;
        let probe: IdentityFormatProbe = serde_json::from_slice(&bytes)?;
        let (stored, migrated) = match probe.format {
            Some(format) if format == DEVICE_FILE_FORMAT => {
                let encrypted: EncryptedIdentity = serde_json::from_slice(&bytes)?;
                (
                    decrypt_identity(encrypted, storage_key, DEVICE_FILE_AAD)?,
                    false,
                )
            }
            Some(format) if format == LEGACY_DEVICE_FILE_FORMAT => {
                let encrypted: EncryptedIdentity = serde_json::from_slice(&bytes)?;
                (
                    decrypt_identity(encrypted, storage_key, LEGACY_DEVICE_FILE_AAD)?,
                    true,
                )
            }
            Some(_) => {
                return Err(DeviceError::Corrupt(
                    "unsupported encrypted identity version".into(),
                ));
            }
            None => (serde_json::from_slice::<StoredIdentity>(&bytes)?, true),
        };
        let provider = Provider::new().map_err(|error| DeviceError::Mls(error.to_string()))?;
        restore_storage(&provider, stored.mls_storage)?;
        let credential = Credential::new(CredentialType::Basic, stored.credential);
        let signer = stored.signer;
        signer
            .store(provider.storage())
            .map_err(|error| DeviceError::Corrupt(error.to_string()))?;
        let credential = CredentialWithKey {
            credential,
            signature_key: signer.public().into(),
        };
        let pending_commits = stored.pending_commits;
        let pending_removals = stored.pending_removals;
        let pending_additions = stored.pending_additions;
        let device = Self {
            id: stored.device_id,
            credential,
            signer,
            provider,
            path,
            pending_applications: RwLock::new(stored.pending_applications),
            pending_commits: RwLock::new(pending_commits),
            pending_removals: RwLock::new(pending_removals),
            pending_additions: RwLock::new(pending_additions),
            storage_key: SecretBox::new(Box::new(*storage_key)),
        };
        if migrated {
            device.persist()?;
        }
        Ok(device)
    }

    fn persist(&self) -> Result<(), DeviceError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| DeviceError::Corrupt("invalid identity path".into()))?;
        fs::create_dir_all(parent)?;
        set_private_dir(parent)?;
        let pending = self
            .pending_applications
            .read()
            .map_err(|_| DeviceError::Corrupt("pending inbox lock poisoned".into()))?;
        let pending_commits = self
            .pending_commits
            .read()
            .map_err(|_| DeviceError::Corrupt("pending commit lock poisoned".into()))?;
        let pending_removals = self
            .pending_removals
            .read()
            .map_err(|_| DeviceError::Corrupt("pending removal lock poisoned".into()))?;
        let pending_additions = self
            .pending_additions
            .read()
            .map_err(|_| DeviceError::Corrupt("pending addition lock poisoned".into()))?;
        let stored = StoredIdentityRef {
            device_id: self.id,
            credential: self.credential.credential.serialized_content(),
            signer: &self.signer,
            mls_storage: snapshot_storage(&self.provider)?,
            pending_applications: &pending,
            pending_commits: &pending_commits,
            pending_removals: &pending_removals,
            pending_additions: &pending_additions,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&stored)?);
        let nonce = rand::random::<[u8; 24]>();
        let cipher = XChaCha20Poly1305::new(self.storage_key.expose_secret().into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: DEVICE_FILE_AAD,
                },
            )
            .map_err(|_| DeviceError::Encryption)?;
        let encoded = serde_json::to_vec_pretty(&EncryptedIdentity {
            format: DEVICE_FILE_FORMAT.into(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })?;
        let temporary = self.path.with_extension("json.tmp");
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        fs::rename(temporary, &self.path)?;
        sync_parent(parent)?;
        Ok(())
    }

    fn load_group(&self, conversation_id: Uuid) -> Result<MlsGroup, DeviceError> {
        MlsGroup::load(self.provider.storage(), &group_id(conversation_id))
            .map_err(mls_error)?
            .ok_or_else(|| DeviceError::Corrupt("unknown encrypted conversation".into()))
    }
}

fn safety_fingerprint(members: &[(Uuid, Vec<u8>)]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SAFETY_CODE_DOMAIN);
    digest.update((members.len() as u32).to_be_bytes());
    for (device_id, signature_key) in members {
        digest.update(device_id.as_bytes());
        digest.update((signature_key.len() as u32).to_be_bytes());
        digest.update(signature_key);
    }
    digest.finalize().into()
}

fn group_id(conversation_id: Uuid) -> GroupId {
    GroupId::from_slice(conversation_id.as_bytes())
}

fn decrypt_identity(
    encrypted: EncryptedIdentity,
    storage_key: &[u8; 32],
    aad: &[u8],
) -> Result<StoredIdentity, DeviceError> {
    let nonce = URL_SAFE_NO_PAD
        .decode(encrypted.nonce)
        .map_err(|error| DeviceError::Corrupt(error.to_string()))?;
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| DeviceError::Corrupt("invalid identity nonce".into()))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(encrypted.ciphertext)
        .map_err(|error| DeviceError::Corrupt(error.to_string()))?;
    let cipher = XChaCha20Poly1305::new(storage_key.into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| {
                DeviceError::Corrupt("identity authentication failed or vault key changed".into())
            })?,
    );
    Ok(serde_json::from_slice(&plaintext)?)
}

fn decode_key_package(encoded: &str, provider: &Provider) -> Result<KeyPackage, DeviceError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| DeviceError::Corrupt(error.to_string()))?;
    let input = KeyPackageIn::tls_deserialize_exact(&bytes)
        .map_err(|error| DeviceError::Corrupt(error.to_string()))?;
    let package = input
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|error| DeviceError::Corrupt(error.to_string()))?;
    if package.ciphersuite() != CIPHERSUITE {
        return Err(DeviceError::Corrupt(
            "unsupported MLS ciphersuite".to_owned(),
        ));
    }
    Ok(package)
}

fn decode_mls_message(encoded: &str) -> Result<MlsMessageIn, DeviceError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| DeviceError::Corrupt(error.to_string()))?;
    MlsMessageIn::tls_deserialize_exact(&bytes)
        .map_err(|error| DeviceError::Corrupt(error.to_string()))
}

fn uuid_from_credential(credential: &Credential) -> Result<Uuid, DeviceError> {
    Uuid::from_slice(credential.serialized_content())
        .map_err(|_| DeviceError::Corrupt("MLS credential is not a device id".into()))
}

fn snapshot_storage(provider: &Provider) -> Result<Vec<StoredMlsValue>, DeviceError> {
    let values = provider
        .storage()
        .values
        .read()
        .map_err(|_| DeviceError::Corrupt("MLS storage lock poisoned".into()))?;
    Ok(values
        .iter()
        .map(|(key, value)| StoredMlsValue {
            key: URL_SAFE_NO_PAD.encode(key),
            value: URL_SAFE_NO_PAD.encode(value),
        })
        .collect())
}

fn restore_storage(provider: &Provider, values: Vec<StoredMlsValue>) -> Result<(), DeviceError> {
    let decoded = values
        .into_iter()
        .map(|item| {
            Ok((
                URL_SAFE_NO_PAD
                    .decode(item.key)
                    .map_err(|error| DeviceError::Corrupt(error.to_string()))?,
                URL_SAFE_NO_PAD
                    .decode(item.value)
                    .map_err(|error| DeviceError::Corrupt(error.to_string()))?,
            ))
        })
        .collect::<Result<HashMap<_, _>, DeviceError>>()?;
    *provider
        .storage()
        .values
        .write()
        .map_err(|_| DeviceError::Corrupt("MLS storage lock poisoned".into()))? = decoded;
    Ok(())
}

fn mls_error(error: impl std::fmt::Debug) -> DeviceError {
    DeviceError::Mls(format!("{error:?}"))
}

/// Parses and cryptographically validates a public MLS KeyPackage before it is
/// admitted to the relay directory.
pub fn validate_key_package(encoded: &str) -> Result<(), DeviceError> {
    let provider = Provider::new().map_err(|error| DeviceError::Mls(error.to_string()))?;
    decode_key_package(encoded, &provider)?;
    Ok(())
}

/// Validates a KeyPackage and binds its BasicCredential to the relay device id.
pub fn validate_key_package_for_device(encoded: &str, device_id: Uuid) -> Result<(), DeviceError> {
    let provider = Provider::new().map_err(|error| DeviceError::Mls(error.to_string()))?;
    let package = decode_key_package(encoded, &provider)?;
    if uuid_from_credential(package.leaf_node().credential())? != device_id {
        return Err(DeviceError::Corrupt(
            "key package credential does not match device id".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), std::io::Error> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_survives_restart_and_emits_key_package() {
        let root = std::env::temp_dir().join(format!("mutte-core-{}", Uuid::new_v4()));
        let path = root.join("device.json");
        let key = [7u8; 32];
        let first = Device::load_or_create_at(&path, &key).expect("create identity");
        let first_id = first.id();
        let package = first.key_package().expect("generate key package");
        assert!(!package.is_empty());
        validate_key_package(&package).expect("validate key package");
        drop(first);
        let stored = fs::read(&path).expect("read encrypted identity");
        assert!(
            !stored
                .windows(credential_marker(first_id).len())
                .any(|window| { window == credential_marker(first_id) })
        );
        assert!(Device::load_or_create_at(&path, &[8u8; 32]).is_err());
        let second = Device::load_or_create_at(&path, &key).expect("reload identity");
        assert_eq!(first_id, second.id());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn rejects_invalid_key_package() {
        assert!(validate_key_package("QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB").is_err());
    }

    #[test]
    fn safety_fingerprint_changes_when_a_signing_key_is_substituted() {
        let alice = Uuid::from_u128(1);
        let bob = Uuid::from_u128(2);
        let original = safety_fingerprint(&[(alice, vec![1; 32]), (bob, vec![2; 32])]);
        let substituted = safety_fingerprint(&[(alice, vec![1; 32]), (bob, vec![3; 32])]);
        assert_eq!(
            ConversationSafetyCode {
                fingerprint: original,
                member_devices: vec![alice, bob],
            }
            .fingerprint(),
            "6F63197D9416A7883C349211C504439CA6470550C394A7DC8B3C54DD4309C42C"
        );
        assert_ne!(original, substituted);
    }

    #[test]
    fn plaintext_identity_is_migrated_on_open() {
        let root = std::env::temp_dir().join(format!("mutte-core-migrate-{}", Uuid::new_v4()));
        let path = root.join("device.json");
        let key = [9u8; 32];
        let device = Device::load_or_create_at(&path, &key).expect("create identity");
        let id = device.id();
        drop(device);
        let encrypted: EncryptedIdentity =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let legacy = decrypt_identity(encrypted, &key, DEVICE_FILE_AAD).expect("decrypt fixture");
        fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let migrated = Device::load_or_create_at(&path, &key).expect("migrate identity");
        assert_eq!(migrated.id(), id);
        assert!(serde_json::from_slice::<EncryptedIdentity>(&fs::read(&path).unwrap()).is_ok());
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn legacy_encrypted_identity_is_rewrapped_for_mutte() {
        let root = std::env::temp_dir().join(format!("mutte-core-rebrand-{}", Uuid::new_v4()));
        let path = root.join("device.json");
        let key = [10u8; 32];
        let device = Device::load_or_create_at(&path, &key).expect("create identity");
        let id = device.id();
        drop(device);

        let encrypted: EncryptedIdentity =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let stored = decrypt_identity(encrypted, &key, DEVICE_FILE_AAD).unwrap();
        let plaintext = Zeroizing::new(serde_json::to_vec(&stored).unwrap());
        let nonce = rand::random::<[u8; 24]>();
        let ciphertext = XChaCha20Poly1305::new((&key).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: LEGACY_DEVICE_FILE_AAD,
                },
            )
            .unwrap();
        fs::write(
            &path,
            serde_json::to_vec_pretty(&EncryptedIdentity {
                format: LEGACY_DEVICE_FILE_FORMAT.into(),
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            })
            .unwrap(),
        )
        .unwrap();

        let migrated = Device::load_or_create_at(&path, &key).expect("migrate identity");
        assert_eq!(migrated.id(), id);
        let rewritten: EncryptedIdentity =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(rewritten.format, DEVICE_FILE_FORMAT);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn two_devices_exchange_messages_offline_across_restarts() {
        let root = std::env::temp_dir().join(format!("mutte-core-e2e-{}", Uuid::new_v4()));
        let alice_path = root.join("alice.json");
        let bob_path = root.join("bob.json");
        let alice_key = [11u8; 32];
        let bob_key = [12u8; 32];
        let alice = Device::load_or_create_at(&alice_path, &alice_key).expect("create alice");
        let bob = Device::load_or_create_at(&bob_path, &bob_key).expect("create bob");
        let alice_id = alice.id();
        let bob_id = bob.id();
        let bob_package = bob.key_package().expect("bob key package");
        let conversation_id = Uuid::new_v4();

        let bootstrap = alice
            .create_conversation(conversation_id, &[(bob_id, bob_package)])
            .expect("create conversation");
        assert_eq!(bootstrap.recipient_devices, vec![bob_id]);
        bob.join_conversation(conversation_id, alice_id, &bootstrap.welcome)
            .expect("bob joins");
        let alice_safety = alice
            .conversation_safety_code(conversation_id)
            .expect("alice safety code");
        let bob_safety = bob
            .conversation_safety_code(conversation_id)
            .expect("bob safety code");
        assert_eq!(alice_safety, bob_safety);
        assert_eq!(alice_safety.member_devices().len(), 2);
        assert_eq!(alice_safety.fingerprint().len(), 64);

        let encrypted = alice
            .encrypt_application(conversation_id, b"quiet hello")
            .expect("alice encrypts");
        let pending = bob
            .decrypt_application(41, conversation_id, alice_id, "alice", &encrypted)
            .expect("bob decrypts");
        assert_eq!(pending.plaintext, b"quiet hello");
        assert!(
            !fs::read(&bob_path)
                .expect("read bob identity")
                .windows(b"quiet hello".len())
                .any(|window| window == b"quiet hello")
        );
        drop(alice);
        drop(bob);

        let alice = Device::load_or_create_at(&alice_path, &alice_key).expect("reload alice");
        let bob = Device::load_or_create_at(&bob_path, &bob_key).expect("reload bob");
        assert_eq!(
            alice
                .conversation_safety_code(conversation_id)
                .expect("reloaded alice safety code"),
            bob.conversation_safety_code(conversation_id)
                .expect("reloaded bob safety code")
        );
        assert_eq!(bob.pending_applications().expect("pending").len(), 1);
        let duplicate = bob
            .decrypt_application(41, conversation_id, alice_id, "alice", &encrypted)
            .expect("delivery retry is idempotent");
        assert_eq!(duplicate.plaintext, b"quiet hello");
        bob.complete_delivery(41).expect("complete delivery");

        let reply = bob
            .encrypt_application(conversation_id, b"received")
            .expect("bob encrypts reply");
        let received = alice
            .decrypt_application(7, conversation_id, bob_id, "bob", &reply)
            .expect("alice decrypts reply");
        assert_eq!(received.plaintext, b"received");
        assert_eq!(
            alice
                .recipient_devices(conversation_id)
                .expect("alice recipients"),
            vec![bob_id]
        );

        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn remove_commit_survives_restart_and_excludes_revoked_device_from_future_epoch() {
        let root = std::env::temp_dir().join(format!("mutte-core-remove-{}", Uuid::new_v4()));
        let alice_path = root.join("alice.json");
        let current_path = root.join("bob-current.json");
        let old_path = root.join("bob-old.json");
        let alice_key = [21u8; 32];
        let current_key = [22u8; 32];
        let old_key = [23u8; 32];
        let alice = Device::load_or_create_at(&alice_path, &alice_key).unwrap();
        let current = Device::load_or_create_at(&current_path, &current_key).unwrap();
        let old = Device::load_or_create_at(&old_path, &old_key).unwrap();
        let conversation_id = Uuid::new_v4();
        let bootstrap = alice
            .create_conversation(
                conversation_id,
                &[
                    (current.id(), current.key_package().unwrap()),
                    (old.id(), old.key_package().unwrap()),
                ],
            )
            .unwrap();
        current
            .join_conversation(conversation_id, alice.id(), &bootstrap.welcome)
            .unwrap();
        old.join_conversation(conversation_id, alice.id(), &bootstrap.welcome)
            .unwrap();
        let before = current.conversation_safety_code(conversation_id).unwrap();
        assert_eq!(before.member_devices().len(), 3);

        let mutation_id = Uuid::new_v4();
        let removal = current
            .remove_device(conversation_id, old.id(), mutation_id)
            .unwrap();
        assert_eq!(removal.mutation_id, Some(mutation_id));
        assert_eq!(removal.removed_device, old.id());
        assert_eq!(removal.recipient_devices, vec![alice.id()]);
        assert_eq!(current.pending_removals().unwrap(), vec![removal.clone()]);
        assert!(
            !current
                .conversation_contains_device(conversation_id, old.id())
                .unwrap()
        );
        drop(current);
        let current = Device::load_or_create_at(&current_path, &current_key).unwrap();
        assert_eq!(
            current
                .remove_device(conversation_id, old.id(), mutation_id)
                .unwrap(),
            removal
        );
        current.complete_removal(removal.envelope_id).unwrap();
        assert!(current.pending_removals().unwrap().is_empty());
        let staged = alice
            .process_commit(91, conversation_id, current.id(), &removal.commit)
            .unwrap();
        assert_eq!(staged.removed_devices, vec![old.id()]);
        assert_eq!(alice.pending_commits().unwrap(), vec![staged.clone()]);
        drop(alice);

        let alice = Device::load_or_create_at(&alice_path, &alice_key).unwrap();
        assert_eq!(alice.pending_commits().unwrap(), vec![staged.clone()]);
        assert_eq!(
            alice
                .process_commit(91, conversation_id, current.id(), &removal.commit)
                .unwrap(),
            staged
        );
        alice.complete_commit_delivery(91).unwrap();
        assert!(alice.pending_commits().unwrap().is_empty());
        let after_alice = alice.conversation_safety_code(conversation_id).unwrap();
        let after_current = current.conversation_safety_code(conversation_id).unwrap();
        assert_eq!(after_alice, after_current);
        assert_ne!(before, after_alice);
        assert_eq!(after_alice.member_devices().len(), 2);

        let future = current
            .encrypt_application(conversation_id, b"future epoch only")
            .unwrap();
        assert_eq!(
            alice
                .decrypt_application(92, conversation_id, current.id(), "bob", &future)
                .unwrap()
                .plaintext,
            b"future epoch only"
        );
        assert!(
            old.decrypt_application(92, conversation_id, current.id(), "bob", &future)
                .is_err()
        );

        drop(alice);
        drop(current);
        drop(old);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn add_commit_welcome_and_encrypted_sync_survive_restart() {
        let root = std::env::temp_dir().join(format!("mutte-core-add-{}", Uuid::new_v4()));
        let alice_path = root.join("alice.json");
        let bob_path = root.join("bob.json");
        let new_path = root.join("bob-new.json");
        let alice_key = [31u8; 32];
        let bob_key = [32u8; 32];
        let new_key = [33u8; 32];
        let alice = Device::load_or_create_at(&alice_path, &alice_key).unwrap();
        let bob = Device::load_or_create_at(&bob_path, &bob_key).unwrap();
        let bob_new = Device::load_or_create_at(&new_path, &new_key).unwrap();
        let conversation_id = Uuid::new_v4();
        let bootstrap = alice
            .create_conversation(conversation_id, &[(bob.id(), bob.key_package().unwrap())])
            .unwrap();
        bob.join_conversation(conversation_id, alice.id(), &bootstrap.welcome)
            .unwrap();
        let before = alice.conversation_safety_code(conversation_id).unwrap();
        let package_pool = bob_new.key_packages(3).unwrap();
        assert_eq!(package_pool.len(), 3);
        assert_ne!(package_pool[0], package_pool[1]);

        let mutation_id = Uuid::new_v4();
        let addition = alice
            .add_device(
                conversation_id,
                bob_new.id(),
                mutation_id,
                &package_pool[0],
                b"encrypted-peer-handle",
            )
            .unwrap();
        assert_eq!(addition.existing_recipient_devices, vec![bob.id()]);
        assert_eq!(addition.mutation_id, Some(mutation_id));
        assert_eq!(alice.pending_additions().unwrap(), vec![addition.clone()]);
        drop(alice);

        let alice = Device::load_or_create_at(&alice_path, &alice_key).unwrap();
        assert_eq!(
            alice
                .add_device(
                    conversation_id,
                    bob_new.id(),
                    mutation_id,
                    &package_pool[0],
                    b"ignored-on-idempotent-retry",
                )
                .unwrap(),
            addition
        );
        alice.complete_addition(addition.sync_envelope_id).unwrap();
        assert!(alice.pending_additions().unwrap().is_empty());

        let commit = bob
            .process_commit(101, conversation_id, alice.id(), &addition.commit)
            .unwrap();
        assert_eq!(commit.added_devices, vec![bob_new.id()]);
        assert!(commit.removed_devices.is_empty());
        bob.complete_commit_delivery(101).unwrap();
        assert!(
            bob_new
                .join_conversation(conversation_id, alice.id(), &addition.welcome)
                .unwrap()
        );
        let sync = bob_new
            .decrypt_device_sync(
                102,
                conversation_id,
                alice.id(),
                "bob",
                &addition.sync_message,
            )
            .unwrap();
        assert_eq!(sync.kind, PendingApplicationKind::DeviceSync);
        assert_eq!(sync.plaintext, b"encrypted-peer-handle");
        bob_new.complete_delivery(102).unwrap();

        let after = alice.conversation_safety_code(conversation_id).unwrap();
        assert_ne!(before, after);
        assert_eq!(
            after,
            bob.conversation_safety_code(conversation_id).unwrap()
        );
        assert_eq!(
            after,
            bob_new.conversation_safety_code(conversation_id).unwrap()
        );
        assert_eq!(after.member_devices().len(), 3);
        let future = bob
            .encrypt_application(conversation_id, b"future multi-device")
            .unwrap();
        assert_eq!(
            alice
                .decrypt_application(103, conversation_id, bob.id(), "bob", &future)
                .unwrap()
                .plaintext,
            b"future multi-device"
        );
        assert_eq!(
            bob_new
                .decrypt_application(103, conversation_id, bob.id(), "bob", &future)
                .unwrap()
                .plaintext,
            b"future multi-device"
        );

        drop(alice);
        drop(bob);
        drop(bob_new);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    fn credential_marker(id: Uuid) -> Vec<u8> {
        serde_json::to_string(id.as_bytes()).unwrap().into_bytes()
    }
}
