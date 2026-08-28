//! Wire types shared by the terminal client and the ciphertext relay.

use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "mutte/0.8-alpha";
pub const CHAT_APPLICATION_VERSION: u16 = 1;
pub const MAX_RECEIPT_MESSAGE_IDS: usize = 128;
pub const HISTORY_SYNC_VERSION: u16 = 1;
pub const ATTACHMENT_VERSION: u16 = 1;
pub const ATTACHMENT_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_ATTACHMENT_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_ATTACHMENT_CHUNKS: u32 = 128;
pub const ATTACHMENT_CHUNK_OVERHEAD: u64 = 24 + 16;
pub const PUSH_CONTRACT_VERSION: u16 = 1;

/// Stable machine-readable relay error codes. Clients must render unknown
/// future codes as a generic error instead of failing to decode the response.
pub mod error_code {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const CONFLICT: &str = "conflict";
    pub const INTERNAL_ERROR: &str = "internal_error";
    pub const PASSKEY_VERIFICATION_FAILED: &str = "passkey_verification_failed";
    pub const QUOTA_EXCEEDED: &str = "quota_exceeded";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const SERVICE_UNAVAILABLE: &str = "service_unavailable";
    pub const UNAUTHORIZED: &str = "unauthorized";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Health {
    pub status: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceStart {
    /// The UUID embedded in the MLS BasicCredential.
    pub device_id: Uuid,
    pub device_name: String,
    /// TLS-serialized MLS KeyPackage, base64url encoded.
    pub key_package: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceAuthorization {
    pub device_id: Uuid,
    pub device_secret: String,
    pub verification_url: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationState {
    Pending,
    Approved,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceStatus {
    pub state: AuthorizationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub id: Uuid,
    pub handle: String,
    pub display_name: String,
    pub bio: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ProfilePatch {
    pub bio: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPackageRecord {
    pub device_id: Uuid,
    pub device_name: String,
    pub key_package: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountDeviceKeyPackageClaim {
    pub target_device_id: Uuid,
    pub count: u16,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountDeviceState {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountDevice {
    pub device_id: Uuid,
    pub device_name: String,
    pub state: AccountDeviceState,
    pub current: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceList {
    pub devices: Vec<AccountDevice>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountDeviceEventKind {
    Added,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountDeviceEvent {
    pub delivery_id: i64,
    pub event_id: Uuid,
    pub kind: AccountDeviceEventKind,
    pub target_device_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountDeviceEventBatch {
    pub events: Vec<AccountDeviceEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountDeviceEventAck {
    pub delivery_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConversationMutationStart {
    pub conversation_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConversationMutationAuthorization {
    pub conversation_id: Uuid,
    pub mutation_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConversationMutationRelease {
    pub conversation_id: Uuid,
    pub mutation_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRevocationStart {
    pub target_device_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRevocationAuthorization {
    pub request_id: Uuid,
    pub target_device_id: Uuid,
    pub confirmation_url: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRevocationState {
    Pending,
    Approved,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRevocationStatus {
    pub state: DeviceRevocationState,
    pub target_device_id: Uuid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    /// An MLS Welcome used to establish the conversation on a new device.
    Welcome,
    /// An encrypted MLS application message.
    Application,
    /// A signed and encrypted MLS Commit that advances the group epoch.
    Commit,
    /// An MLS application message carrying encrypted local conversation
    /// metadata to another device on the same account.
    DeviceSync,
    /// An MLS application message carrying a versioned, target-bound history
    /// manifest, history chunk, or completion acknowledgement.
    HistorySync,
}

/// A normalized historical chat record transferred only inside an MLS
/// `HistorySync` application message. Presentation-only author strings and
/// device-local unread flags are deliberately excluded; only the latest peer
/// receipt for an own-account message is retained.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryMessage {
    pub id: Uuid,
    pub text: String,
    pub mine: bool,
    pub sent_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<AttachmentMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_root: Option<Uuid>,
    /// The latest peer receipt known to the source account device. This is
    /// transferred only inside target-bound MLS history sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ReceiptKind>,
}

/// Versioned plaintext carried only inside an MLS Application message. The
/// relay sees the outer opaque MLS ciphertext, never these variants or ids.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChatApplicationPayload {
    Message {
        version: u16,
        id: Uuid,
        text: String,
        sent_at: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attachment: Option<AttachmentMetadata>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        thread_root: Option<Uuid>,
    },
    Receipt {
        version: u16,
        receipt_id: Uuid,
        kind: ReceiptKind,
        message_ids: Vec<Uuid>,
        sent_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Delivered,
    Read,
}

/// Secret attachment metadata carried only inside an MLS application or
/// history-sync payload. `file_key` and `plaintext_hash` are base64url values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentMetadata {
    pub version: u16,
    pub attachment_id: Uuid,
    pub filename: String,
    pub plaintext_size: u64,
    pub chunk_count: u32,
    pub file_key: String,
    pub plaintext_hash: String,
}

/// Relay-visible declaration for an opaque encrypted attachment. It contains
/// no filename, media type, plaintext hash, or file key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentStart {
    pub attachment_id: Uuid,
    pub recipients: Vec<Uuid>,
    pub chunk_count: u32,
    pub ciphertext_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentChunkUpload {
    pub chunk_index: u32,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentStatus {
    pub attachment_id: Uuid,
    pub uploaded_chunks: Vec<u32>,
    pub complete: bool,
    /// Present only when object storage was explicitly requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<PresignedObjectRequest>,
}

/// A short-lived, operation-specific request for a private opaque object.
/// The URL is a bearer secret and must never be logged or persisted by clients.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresignedObjectRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentObjectDownload {
    pub attachment_id: Uuid,
    pub download: PresignedObjectRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentChunkData {
    pub attachment_id: Uuid,
    pub chunk_index: u32,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentRecipientGrant {
    pub target_device_id: Uuid,
}

/// Versioned plaintext carried inside MLS encryption for same-account history
/// transfer. Hashes are base64url-encoded SHA-256 values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HistorySyncPayload {
    Manifest {
        version: u16,
        transfer_id: Uuid,
        target_device_id: Uuid,
        message_count: u32,
        chunk_count: u32,
        transcript_hash: String,
    },
    Chunk {
        version: u16,
        transfer_id: Uuid,
        target_device_id: Uuid,
        chunk_index: u32,
        chunk_count: u32,
        chunk_hash: String,
        messages: Vec<HistoryMessage>,
    },
    Ack {
        version: u16,
        transfer_id: Uuid,
        source_device_id: Uuid,
        transcript_hash: String,
        imported_count: u32,
    },
}

/// The relay stores and forwards this object without inspecting `ciphertext`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextEnvelope {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub sender_device_id: Uuid,
    /// Validated against the authenticated relay principal before storage.
    pub sender_handle: String,
    pub recipients: Vec<Uuid>,
    pub kind: EnvelopeKind,
    /// Required for membership Commit envelopes. The relay atomically consumes
    /// the matching exclusive mutation lease when accepting the Commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_id: Option<Uuid>,
    /// TLS-serialized MLS protocol message, base64url encoded.
    pub ciphertext: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxMessage {
    /// Relay-local delivery cursor. A message remains pending until this id is
    /// explicitly acknowledged by its recipient device.
    pub delivery_id: i64,
    pub envelope: CiphertextEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageBatch {
    pub messages: Vec<MailboxMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageAck {
    pub delivery_ids: Vec<i64>,
}

/// A deliberately metadata-minimal hint carried over the authenticated
/// WebSocket. Clients always fetch and authenticate the normal mailbox after a
/// hint, so polling remains a complete fallback transport.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RealtimeEvent {
    MailboxReady,
}

/// Provider-specific addressing for a client installation. The token is
/// sensitive routing data and is accepted only on write; relay responses never
/// echo it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PushRegistrationUpsert {
    pub installation_id: Uuid,
    pub provider: PushProvider,
    pub environment: PushEnvironment,
    pub token: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PushProvider {
    Apns,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PushEnvironment {
    Development,
    Production,
}

/// The metadata-minimal payload sent through a mobile push provider. Receipt
/// of this hint never acknowledges or replaces the durable mailbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PushPayload {
    MailboxChanged { version: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPackagePublish {
    /// Fresh TLS-serialized MLS KeyPackages, base64url encoded. Each package
    /// may be claimed for exactly one group join.
    pub key_packages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiError {
    /// Stable machine-readable category. Clients must not branch on `error`.
    pub code: String,
    /// Safe human-readable summary suitable for display or diagnostics.
    pub error: String,
    /// Correlates the response with privacy-filtered relay logs.
    pub request_id: Uuid,
}
