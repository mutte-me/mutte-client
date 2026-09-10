use std::{
    collections::{HashSet, VecDeque},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Local, Utc};
use mutte_core::{
    ConversationAddition, ConversationRemoval, ConversationSafetyCode, Device, PendingApplication,
    PendingApplicationKind, PendingCommit,
};
use mutte_protocol::{
    AccountDevice, AccountDeviceEventKind, AccountDeviceState, AttachmentChunkUpload,
    AttachmentMetadata, AttachmentStart, CHAT_APPLICATION_VERSION, ChatApplicationPayload,
    CiphertextEnvelope, DeviceRevocationState, EnvelopeKind, HISTORY_SYNC_VERSION,
    HistorySyncPayload, MAX_RECEIPT_MESSAGE_IDS, MailboxMessage, Profile,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Client, ClientEvent, Session, authentication_required};
use mutte_store::{
    ConversationPreferences, DeliveryState, HistorySyncOutcome, NotificationMode,
    OutboundAttachment, PendingDeviceRevocation, ReadScope, UNRESOLVED_PEER_HANDLE, Vault,
    VaultAttachment, VaultConversation, VaultMessage,
};

#[derive(Clone, Debug)]
pub struct MessageSnapshot {
    pub id: Uuid,
    pub author: String,
    pub text: String,
    pub mine: bool,
    pub timestamp: DateTime<Local>,
    pub delivery: DeliveryState,
    pub attachment: Option<VaultAttachment>,
    pub reply_to: Option<Uuid>,
    pub thread_root: Option<Uuid>,
    pub locally_read: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageReaction {
    pub emoji: String,
    pub count: u8,
    pub mine: bool,
}

#[derive(Clone, Debug)]
pub struct ConversationSnapshot {
    pub conversation_id: Option<Uuid>,
    pub name: String,
    pub handle: String,
    pub status: String,
    pub unread: u16,
    pub messages: Vec<MessageSnapshot>,
    pub verification: VerificationState,
    pub active_thread: Option<Uuid>,
    /// Number of rendered lines to stay above the newest content. Zero keeps
    /// the conversation pinned to the live tail.
    pub scroll_back: u16,
}

/// Several distinct MLS histories may share a handle after device recovery.
/// Snapshot ordering is not evidence of identity or trust.
#[derive(Debug)]
pub struct DirectConversationChoiceRequired;

impl std::fmt::Display for DirectConversationChoiceRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "multiple conversations use this handle; choose one from the conversation list",
        )
    }
}

impl std::error::Error for DirectConversationChoiceRequired {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationState {
    NotApplicable,
    Unverified,
    Verified,
    Changed,
    Unavailable,
}

#[derive(Clone, Debug)]
pub struct VerificationPanel {
    pub conversation_id: Uuid,
    pub peer_handle: String,
    pub fingerprint: String,
    pub member_count: usize,
    pub state: VerificationState,
}

#[derive(Clone, Debug)]
pub struct DevicePanel {
    pub devices: Vec<AccountDevice>,
    pub status: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientPaths {
    /// Frontend-owned sandbox directory for decrypted attachment downloads.
    /// `None` selects Mutte's desktop data directory.
    pub downloads_directory: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub enum ClientCommand {
    ExecuteText(String),
    StartDirect {
        handle: String,
    },
    SendMessage {
        conversation_id: Uuid,
        text: String,
        reply_to: Option<Uuid>,
        thread_root: Option<Uuid>,
    },
    OpenThread {
        conversation_id: Uuid,
        message_id: Uuid,
    },
    CloseThread {
        conversation_id: Uuid,
    },
    MarkRead {
        conversation_id: Uuid,
        thread_root: Option<Uuid>,
    },
    /// Declare the conversation scope that a frontend is actively rendering.
    /// Inbound messages are only auto-read while this lifecycle is active.
    SetVisibleConversation {
        conversation_id: Uuid,
        thread_root: Option<Uuid>,
    },
    /// End the active rendering lifecycle without changing the last selection.
    ClearVisibleConversation,
    SetReadReceipts(bool),
    SetNotificationMode {
        conversation_id: Uuid,
        mode: NotificationMode,
    },
    SetConversationQuiet {
        conversation_id: Uuid,
        quiet: bool,
    },
    RestoreConversationAttention {
        conversation_id: Uuid,
        quiet: bool,
        mode: NotificationMode,
    },
    SetThreadFollowed {
        conversation_id: Uuid,
        thread_root: Uuid,
        followed: bool,
    },
    SendAttachment {
        conversation_id: Uuid,
        path: PathBuf,
    },
    SendAttachmentInScope {
        conversation_id: Uuid,
        path: PathBuf,
        reply_to: Option<Uuid>,
        thread_root: Option<Uuid>,
    },
    ToggleReaction {
        conversation_id: Uuid,
        message_id: Uuid,
        emoji: String,
    },
    RequestAttachment {
        prefix: String,
    },
    CancelUpload {
        prefix: String,
    },
    CancelDownload {
        prefix: String,
    },
    ListDevices,
    SyncDevice {
        prefix: String,
    },
    RevokeDevice {
        prefix: String,
    },
    ShowVerification {
        conversation_id: Uuid,
    },
    ConfirmVerification,
}

pub struct MutteClient {
    pub profile: Profile,
    pub conversations: Vec<ConversationSnapshot>,
    pub selected: usize,
    pub demo: bool,
    pub notice: String,
    vault: Option<Vault>,
    pub verification_panel: Option<VerificationPanel>,
    pub device_panel: Option<DevicePanel>,
    pub pending_device_revocation: Option<PendingDeviceRevocation>,
    visible_conversation: Option<VisibleConversation>,
    events: VecDeque<ClientEvent>,
    paths: ClientPaths,
    demo_attention: std::collections::HashMap<Uuid, ConversationPreferences>,
    demo_read_receipts: bool,
    attachment_cancellation: Option<std::sync::Arc<crate::AttachmentCancellation>>,
    active_attachment_transfers: std::sync::Arc<crate::ActiveAttachmentTransfers>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VisibleConversation {
    conversation_id: Uuid,
    thread_root: Option<Uuid>,
}

#[derive(Clone, Copy)]
pub struct Connection<'a> {
    pub api: &'a Client,
    pub session: &'a Session,
    pub device: &'a Device,
    pub open_browser: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyChatPayload {
    id: Uuid,
    text: String,
    sent_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attachment: Option<AttachmentMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IncomingChatApplication {
    Current(ChatApplicationPayload),
    Legacy(LegacyChatPayload),
}

#[derive(Debug, Deserialize, Serialize)]
struct DeviceSyncPayload {
    peer_handle: String,
}

impl MutteClient {
    fn execute_demo_attention(&mut self, command: &ClientCommand) -> Result<bool> {
        if let ClientCommand::SetReadReceipts(enabled) = command {
            self.demo_read_receipts = *enabled;
            return Ok(true);
        }
        let id = match command {
            ClientCommand::SetNotificationMode {
                conversation_id, ..
            }
            | ClientCommand::SetConversationQuiet {
                conversation_id, ..
            }
            | ClientCommand::RestoreConversationAttention {
                conversation_id, ..
            }
            | ClientCommand::SetThreadFollowed {
                conversation_id, ..
            } => *conversation_id,
            _ => return Ok(false),
        };
        let index = self.chat_index(id).context("Conversation unavailable")?;
        let mut preferences = self.conversation_preferences(id)?;
        match command {
            ClientCommand::SetNotificationMode { mode, .. } => {
                preferences.notification_mode = *mode;
                if *mode != NotificationMode::Off {
                    preferences.quiet = false;
                }
            }
            ClientCommand::SetConversationQuiet { quiet, .. } => {
                preferences.quiet = *quiet;
                if *quiet {
                    preferences.notification_mode = NotificationMode::Off;
                }
            }
            ClientCommand::RestoreConversationAttention { quiet, mode, .. } => {
                if *quiet && *mode != NotificationMode::Off {
                    bail!("Quiet requires notifications Off");
                }
                preferences.quiet = *quiet;
                preferences.notification_mode = *mode;
            }
            ClientCommand::SetThreadFollowed {
                thread_root,
                followed,
                ..
            } => {
                if !self.conversations[index]
                    .messages
                    .iter()
                    .any(|m| m.id == *thread_root && m.thread_root.is_none())
                {
                    bail!("Discussion unavailable");
                }
                if *followed {
                    preferences.followed_threads.insert(*thread_root);
                } else {
                    preferences.followed_threads.remove(thread_root);
                }
            }
            _ => unreachable!(),
        }
        self.demo_attention.insert(id, preferences);
        self.publish_state(Some(id));
        Ok(true)
    }
    pub fn load_personal_state(&self) -> Result<crate::personal::PersonalState> {
        let mut state = match self.vault.as_ref() {
            Some(vault) => match vault.load_personal_document()? {
                Some(bytes) => serde_json::from_slice::<crate::personal::PersonalState>(&bytes)?,
                None => crate::personal::PersonalState::default(),
            },
            None if self.demo => crate::personal::PersonalState::default(),
            None => anyhow::bail!("encrypted storage is unavailable"),
        };
        state.validate()?;
        state.recover();
        Ok(state)
    }
    pub fn save_personal_state(&self, state: &crate::personal::PersonalState) -> Result<()> {
        state.validate()?;
        match &self.vault {
            Some(vault) => {
                vault.save_personal_document(&zeroize::Zeroizing::new(serde_json::to_vec(state)?))
            }
            None if self.demo => Ok(()),
            None => anyhow::bail!("encrypted storage is unavailable"),
        }
    }
    pub fn new(profile: Profile, demo: bool) -> Self {
        let now = Local::now();
        let conversations = if demo {
            vec![
                ConversationSnapshot {
                    conversation_id: Some(Uuid::new_v4()),
                    name: "Mira Chen".into(),
                    handle: "mira".into(),
                    status: "● online".into(),
                    unread: 2,
                    verification: VerificationState::Unverified,
                    messages: vec![
                        MessageSnapshot {
                            id: Uuid::new_v4(),
                            author: "Mira".into(),
                            text: "The midnight build passed. Even the weird ARM runner.".into(),
                            mine: false,
                            timestamp: now,
                            delivery: DeliveryState::Received,
                            attachment: None,
                            reply_to: None,
                            thread_root: None,
                            locally_read: true,
                        },
                        MessageSnapshot {
                            id: Uuid::new_v4(),
                            author: "You".into(),
                            text: "beautiful. shipping quietly?".into(),
                            mine: true,
                            timestamp: now,
                            delivery: DeliveryState::Sent,
                            attachment: None,
                            reply_to: None,
                            thread_root: None,
                            locally_read: true,
                        },
                        MessageSnapshot {
                            id: Uuid::new_v4(),
                            author: "Mira".into(),
                            text: "quietly, but with excellent typography ✦".into(),
                            mine: false,
                            timestamp: now,
                            delivery: DeliveryState::Received,
                            attachment: None,
                            reply_to: None,
                            thread_root: None,
                            locally_read: true,
                        },
                    ],
                    active_thread: None,
                    scroll_back: 0,
                },
                ConversationSnapshot {
                    conversation_id: Some(Uuid::new_v4()),
                    name: "omarchy-lab".into(),
                    handle: "3 members".into(),
                    status: "encrypted room".into(),
                    unread: 0,
                    verification: VerificationState::Unverified,
                    messages: vec![MessageSnapshot {
                        id: Uuid::new_v4(),
                        author: "Nico".into(),
                        text: "Welcome to the TUI-first corner of the internet.".into(),
                        mine: false,
                        timestamp: now,
                        delivery: DeliveryState::Received,
                        attachment: None,
                        reply_to: None,
                        thread_root: None,
                        locally_read: true,
                    }],
                    active_thread: None,
                    scroll_back: 0,
                },
                ConversationSnapshot {
                    conversation_id: Some(Uuid::new_v4()),
                    name: "Eli".into(),
                    handle: "eli".into(),
                    status: "away".into(),
                    unread: 0,
                    verification: VerificationState::Unverified,
                    messages: vec![],
                    active_thread: None,
                    scroll_back: 0,
                },
            ]
        } else {
            vec![ConversationSnapshot {
                conversation_id: None,
                name: "Welcome to Mutte".into(),
                handle: "system".into(),
                status: "security first".into(),
                unread: 0,
                verification: VerificationState::NotApplicable,
                messages: vec![
                    MessageSnapshot {
                        id: Uuid::new_v4(),
                        author: "Mutte".into(),
                        text: format!(
                            "Authentication accepted. This device is linked as @{}.",
                            profile.handle
                        ),
                        mine: false,
                        timestamp: now,
                        delivery: DeliveryState::Received,
                        attachment: None,
                        reply_to: None,
                        thread_root: None,
                        locally_read: true,
                    },
                    MessageSnapshot {
                        id: Uuid::new_v4(),
                        author: "Mutte".into(),
                        text: "Your MLS identity is ready. Type /dm handle to claim the peer's one-time KeyPackage and start an encrypted chat.".into(),
                        mine: false,
                        timestamp: now,
                        delivery: DeliveryState::Received,
                        attachment: None,
                        reply_to: None,
                        thread_root: None,
                        locally_read: true,
                    },
                ],
                active_thread: None,
                scroll_back: 0,
            }]
        };
        Self {
            profile,
            conversations,
            selected: 0,
            demo,
            notice: "mailbox ready".into(),
            vault: None,
            verification_panel: None,
            device_panel: None,
            pending_device_revocation: None,
            visible_conversation: None,
            events: VecDeque::new(),
            paths: ClientPaths::default(),
            demo_attention: Default::default(),
            demo_read_receipts: false,
            attachment_cancellation: None,
            active_attachment_transfers: Default::default(),
        }
    }

    pub fn active_attachment_transfers(&self) -> std::sync::Arc<crate::ActiveAttachmentTransfers> {
        self.active_attachment_transfers.clone()
    }

    pub fn connected(profile: Profile, vault: Vault) -> Result<Self> {
        Self::connected_with_paths(profile, vault, ClientPaths::default())
    }

    pub fn connected_with_paths(
        profile: Profile,
        mut vault: Vault,
        paths: ClientPaths,
    ) -> Result<Self> {
        if let Some(directory) = &paths.downloads_directory {
            vault.reconcile_download_cache(directory)?;
        }
        let mut app = Self::new(profile, false);
        app.paths = paths;
        let conversations = vault.conversations().to_vec();
        let messages = vault.messages().to_vec();
        for stored in conversations {
            app.conversations.push(ConversationSnapshot {
                conversation_id: Some(stored.id),
                name: format!("@{}", stored.peer_handle),
                handle: stored.peer_handle,
                status: "encrypted · restored".into(),
                unread: stored.unread,
                verification: VerificationState::Unverified,
                messages: messages
                    .iter()
                    .filter(|message| message.conversation_id == stored.id)
                    .map(|message| MessageSnapshot {
                        id: message.id,
                        author: message.author.clone(),
                        text: message.text.clone(),
                        mine: message.mine,
                        timestamp: message.sent_at.with_timezone(&Local),
                        delivery: message.delivery,
                        attachment: message.attachment.clone(),
                        reply_to: message.reply_to,
                        thread_root: message.thread_root,
                        locally_read: message.locally_read,
                    })
                    .collect(),
                active_thread: None,
                scroll_back: 0,
            });
        }
        app.pending_device_revocation = vault.pending_device_revocation().cloned();
        app.vault = Some(vault);
        for stored in app.vault.as_ref().unwrap().conversations().to_vec() {
            app.reload_chat_history(stored.id)?;
        }
        app.prepare_attachment_queue()?;
        Ok(app)
    }

    /// Restore interrupted cryptographic and transfer work before a frontend
    /// begins processing user commands.
    pub async fn start(&mut self, connection: &Connection<'_>) -> Result<()> {
        self.finish_queued_cancellations()?;
        let result = self.start_inner(connection).await;
        self.finish_queued_cancellations()?;
        result
    }

    async fn start_inner(&mut self, connection: &Connection<'_>) -> Result<()> {
        self.refresh_verification_states(connection.device);
        if let Err(error) = self.restore_pending_membership(connection).await {
            self.record_recoverable_network_error(error, "pending membership change")?;
        }
        if let Err(error) = self.restore_pending(connection).await {
            self.record_recoverable_network_error(error, "pending inbox")?;
        }
        if let Err(error) = self.resume_attachment_uploads(connection).await {
            self.record_recoverable_network_error(error, "attachment upload waiting")?;
        }
        if let Err(error) = self.resume_history_sync(connection).await {
            self.record_recoverable_network_error(error, "history sync waiting")?;
        }
        if let Err(error) = self.queue_pending_receipts(connection.device) {
            self.notice = format!("encrypted receipts waiting: {error}");
        }
        if let Err(error) = self.resume_attachment_downloads(connection).await {
            self.record_recoverable_network_error(error, "attachment download waiting")?;
        }
        if let Err(error) = self.poll_device_revocation(connection).await {
            self.record_recoverable_network_error(error, "device removal")?;
        }
        if let Err(error) = self.flush_outbox(connection).await {
            self.record_recoverable_network_error(error, "outbox waiting")?;
        }
        self.events
            .push_back(ClientEvent::ConnectionChanged { connected: true });
        self.publish_state(None);
        Ok(())
    }

    /// Fetch and process the durable mailbox. WebSocket events are only hints
    /// that tell a frontend when to call this method early.
    pub async fn synchronize(&mut self, connection: &Connection<'_>) -> Result<()> {
        self.finish_queued_cancellations()?;
        let result = self.sync_mailbox(connection).await;
        self.finish_queued_cancellations()?;
        match result {
            Ok(()) => {
                self.events
                    .push_back(ClientEvent::ConnectionChanged { connected: true });
                self.publish_state(None);
                Ok(())
            }
            Err(error) => {
                self.events
                    .push_back(ClientEvent::ConnectionChanged { connected: false });
                Err(error)
            }
        }
    }

    /// Scope a one-use signal to one explicit transfer. Never abort unrelated
    /// mailbox, MLS, or outbox operations.
    pub async fn execute_cancellable_attachment(
        &mut self,
        connection: &Connection<'_>,
        command: ClientCommand,
        cancellation: std::sync::Arc<crate::AttachmentCancellation>,
    ) -> Result<()> {
        if !matches!(
            command,
            ClientCommand::SendAttachment { .. } | ClientCommand::RequestAttachment { .. }
        ) {
            bail!("cancellation is restricted to an explicit attachment operation");
        }
        cancellation.start()?;
        if cancellation.is_cancelled() {
            return Ok(());
        }
        self.attachment_cancellation = Some(cancellation.clone());
        let result = self.execute(Some(connection), command).await;
        cancellation.finish();
        self.attachment_cancellation = None;
        result
    }

    /// Execute a typed client operation. `ExecuteText` exists for command-line
    /// frontends; native clients should use the structured variants.
    pub async fn execute(
        &mut self,
        connection: Option<&Connection<'_>>,
        command: ClientCommand,
    ) -> Result<()> {
        self.finish_queued_cancellations()?;
        let result = self.execute_inner(connection, command).await;
        self.finish_queued_cancellations()?;
        result
    }

    async fn execute_inner(
        &mut self,
        connection: Option<&Connection<'_>>,
        command: ClientCommand,
    ) -> Result<()> {
        if self.demo && self.execute_demo_attention(&command)? {
            return Ok(());
        }
        let flush_read_receipts = matches!(
            &command,
            ClientCommand::MarkRead { .. } | ClientCommand::SetVisibleConversation { .. }
        );
        match command {
            ClientCommand::ExecuteText(input) => {
                self.submit(connection, input).await?;
            }
            ClientCommand::StartDirect { handle } => {
                if self.demo {
                    self.submit(None, format!("/dm {handle}")).await?;
                } else {
                    let connection = connection.context("network session is unavailable")?;
                    self.start_direct_chat(connection, handle, false).await?;
                }
            }
            ClientCommand::SendMessage {
                conversation_id,
                text,
                reply_to,
                thread_root,
            } => {
                if self.demo {
                    self.select_conversation(conversation_id)?;
                    self.validate_message(&text, reply_to, thread_root)?;
                    self.append_demo_message(text, reply_to, thread_root);
                } else {
                    let connection = connection.context("network session is unavailable")?;
                    self.select_conversation(conversation_id)?;
                    self.send_chat_message(connection, text, reply_to, thread_root)
                        .await?;
                }
            }
            ClientCommand::OpenThread {
                conversation_id,
                message_id,
            } => {
                let device = if self.demo {
                    None
                } else {
                    Some(connection.context("MLS device is unavailable")?.device)
                };
                self.select_conversation(conversation_id)?;
                let root = {
                    let message = self
                        .conversations
                        .get(self.selected)
                        .and_then(|chat| chat.messages.iter().find(|item| item.id == message_id))
                        .context("thread root is unavailable in this conversation")?;
                    message.thread_root.unwrap_or(message.id)
                };
                self.conversations[self.selected].scroll_back = 0;
                if self.demo {
                    self.set_selected_thread(Some(root))?;
                } else {
                    self.set_selected_visible(Some(root), device)?;
                }
            }
            ClientCommand::CloseThread { conversation_id } => {
                let device = if self.demo {
                    None
                } else {
                    Some(connection.context("MLS device is unavailable")?.device)
                };
                self.select_conversation(conversation_id)?;
                self.conversations[self.selected].scroll_back = 0;
                if self.demo {
                    self.set_selected_thread(None)?;
                } else {
                    self.set_selected_visible(None, device)?;
                }
            }
            ClientCommand::MarkRead {
                conversation_id,
                thread_root,
            } => {
                self.select_conversation(conversation_id)?;
                self.set_selected_thread(thread_root)?;
                if self
                    .visible_conversation
                    .is_some_and(|visible| visible.conversation_id == conversation_id)
                {
                    self.visible_conversation = Some(VisibleConversation {
                        conversation_id,
                        thread_root,
                    });
                }
                self.mark_selected_read(connection.map(|item| item.device))?;
            }
            ClientCommand::SetVisibleConversation {
                conversation_id,
                thread_root,
            } => {
                self.select_conversation(conversation_id)?;
                self.set_selected_visible(thread_root, connection.map(|item| item.device))?;
            }
            ClientCommand::ClearVisibleConversation => {
                self.visible_conversation = None;
            }
            ClientCommand::SetReadReceipts(enabled) => {
                self.vault_mut()?.set_read_receipts(enabled)?;
            }
            ClientCommand::SetNotificationMode {
                conversation_id,
                mode,
            } => {
                self.vault_mut()?
                    .set_notification_mode(conversation_id, mode)?;
                self.publish_state(Some(conversation_id));
            }
            ClientCommand::SetConversationQuiet {
                conversation_id,
                quiet,
            } => {
                self.vault_mut()?
                    .set_conversation_quiet(conversation_id, quiet)?;
                self.publish_state(Some(conversation_id));
            }
            ClientCommand::RestoreConversationAttention {
                conversation_id,
                quiet,
                mode,
            } => {
                self.vault_mut()?
                    .restore_conversation_attention(conversation_id, quiet, mode)?;
                self.publish_state(Some(conversation_id));
            }
            ClientCommand::SetThreadFollowed {
                conversation_id,
                thread_root,
                followed,
            } => {
                let index = self
                    .chat_index(conversation_id)
                    .context("conversation is unavailable")?;
                if !self.conversations[index].messages.iter().any(|message| {
                    message.id == thread_root
                        && message.thread_root.is_none()
                        && !is_reaction_message(message)
                }) {
                    bail!("discussion is not available on this device")
                }
                self.vault_mut()?
                    .set_thread_followed(conversation_id, thread_root, followed)?;
                self.publish_state(Some(conversation_id));
            }
            ClientCommand::SendAttachment {
                conversation_id,
                path,
            } => {
                let connection = connection.context("network session is unavailable")?;
                self.select_conversation(conversation_id)?;
                let thread_root = self.conversations[self.selected].active_thread;
                self.send_attachment(connection, &path, None, thread_root)
                    .await?;
            }
            ClientCommand::SendAttachmentInScope {
                conversation_id,
                path,
                reply_to,
                thread_root,
            } => {
                let connection = connection.context("network session is unavailable")?;
                self.select_conversation(conversation_id)?;
                self.send_attachment(connection, &path, reply_to, thread_root)
                    .await?;
            }
            ClientCommand::ToggleReaction {
                conversation_id,
                message_id,
                emoji,
            } => {
                let connection = connection.context("network session is unavailable")?;
                self.select_conversation(conversation_id)?;
                self.toggle_reaction(connection, message_id, &emoji).await?;
            }
            ClientCommand::RequestAttachment { prefix } => {
                self.submit(connection, format!("/download {prefix}"))
                    .await?;
            }
            ClientCommand::CancelUpload { prefix } => {
                self.submit(connection, format!("/cancel-upload {prefix}"))
                    .await?;
            }
            ClientCommand::CancelDownload { prefix } => {
                self.submit(connection, format!("/cancel-download {prefix}"))
                    .await?;
            }
            ClientCommand::ListDevices => {
                self.show_devices(connection.context("network session is unavailable")?)
                    .await?;
            }
            ClientCommand::SyncDevice { prefix } => {
                self.sync_device(
                    connection.context("network session is unavailable")?,
                    &prefix,
                )
                .await?;
            }
            ClientCommand::RevokeDevice { prefix } => {
                self.start_device_revocation(
                    connection.context("network session is unavailable")?,
                    &prefix,
                )
                .await?;
            }
            ClientCommand::ShowVerification { conversation_id } => {
                let connection = connection.context("MLS device is unavailable")?;
                self.select_conversation(conversation_id)?;
                self.show_verification(connection.device)?;
            }
            ClientCommand::ConfirmVerification => {
                self.confirm_verification(connection.context("MLS device is unavailable")?.device)?;
            }
        }
        if flush_read_receipts
            && !self.demo
            && let Some(connection) = connection
            && let Err(error) = self.flush_receipt_outbox(connection).await
        {
            self.record_recoverable_network_error(error, "encrypted receipts waiting")?;
        }
        let conversation_id = self
            .conversations
            .get(self.selected)
            .and_then(|chat| chat.conversation_id);
        self.publish_state(conversation_id);
        Ok(())
    }

    pub fn conversation_preferences(
        &self,
        conversation_id: Uuid,
    ) -> Result<ConversationPreferences> {
        if self.demo {
            self.chat_index(conversation_id)
                .context("Conversation unavailable")?;
            return Ok(self
                .demo_attention
                .get(&conversation_id)
                .cloned()
                .unwrap_or_default());
        }
        self.vault
            .as_ref()
            .context("encrypted storage is unavailable")?
            .conversation_preferences(conversation_id)
    }

    pub fn message_notification_eligible(
        &self,
        conversation_id: Uuid,
        message: &MessageSnapshot,
    ) -> bool {
        !message.mine
            && !message.locally_read
            && self
                .conversation_preferences(conversation_id)
                .is_ok_and(|preferences| {
                    preferences.allows_notification(
                        message.thread_root,
                        mentions_handle(&message.text, &self.profile.handle),
                    )
                })
    }

    fn select_conversation(&mut self, conversation_id: Uuid) -> Result<()> {
        self.selected = self
            .chat_index(conversation_id)
            .context("unknown encrypted conversation")?;
        Ok(())
    }

    fn set_selected_thread(&mut self, thread_root: Option<Uuid>) -> Result<()> {
        if thread_root.is_some_and(|root| {
            !self.conversations[self.selected]
                .messages
                .iter()
                .any(|message| message.id == root && message.thread_root.is_none())
        }) {
            bail!("thread root is unavailable in this conversation")
        }
        self.conversations[self.selected].active_thread = thread_root;
        Ok(())
    }

    fn set_selected_visible(
        &mut self,
        thread_root: Option<Uuid>,
        device: Option<&Device>,
    ) -> Result<()> {
        self.set_selected_thread(thread_root)?;
        let conversation_id = self.conversations[self.selected]
            .conversation_id
            .context("selected item is not an encrypted conversation")?;
        self.mark_selected_read(device)?;
        self.visible_conversation = Some(VisibleConversation {
            conversation_id,
            thread_root,
        });
        Ok(())
    }

    fn publish_state(&mut self, conversation_id: Option<Uuid>) {
        self.events
            .push_back(ClientEvent::StateChanged { conversation_id });
        self.events.push_back(ClientEvent::Notice {
            message: self.notice.clone(),
        });
    }

    async fn submit(&mut self, connection: Option<&Connection<'_>>, input: String) -> Result<()> {
        let input = input.trim().to_owned();
        if input.is_empty() {
            return Ok(());
        }
        if input == "/quit" {
            self.events.push_back(ClientEvent::QuitRequested);
            return Ok(());
        }
        if self.demo {
            self.submit_demo(input);
            return Ok(());
        }
        if input.len() > 64 * 1024 {
            bail!("message exceeds the 64 KiB alpha limit");
        }
        let connection = connection.context("network session is unavailable")?;
        if input == "/help" {
            self.events.push_back(ClientEvent::HelpRequested);
            self.notice = "command palette opened".into();
            return Ok(());
        }
        if input == "/verify" {
            self.show_verification(connection.device)?;
            return Ok(());
        }
        if input == "/devices" {
            self.show_devices(connection).await?;
            return Ok(());
        }
        if input == "/read-receipts" {
            self.notice = format!(
                "encrypted read receipts are {}",
                if self.vault_mut()?.settings().send_read_receipts {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            return Ok(());
        }
        if let Some(value) = input.strip_prefix("/read-receipts ").map(str::trim) {
            let enabled = match value {
                "on" => true,
                "off" => false,
                _ => bail!("use /read-receipts on or /read-receipts off"),
            };
            self.vault_mut()?.set_read_receipts(enabled)?;
            self.notice = if enabled {
                "encrypted read receipts enabled".into()
            } else {
                "read receipts disabled; delivery receipts remain enabled".into()
            };
            return Ok(());
        }
        if let Some(prefix) = input.strip_prefix("/revoke ").map(str::trim) {
            self.start_device_revocation(connection, prefix).await?;
            return Ok(());
        }
        if let Some(prefix) = input.strip_prefix("/sync-device ").map(str::trim) {
            self.sync_device(connection, prefix).await?;
            return Ok(());
        }
        if let Some(path) = input
            .strip_prefix("/send ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let thread_root = self.conversations[self.selected].active_thread;
            self.send_attachment(connection, Path::new(path), None, thread_root)
                .await?;
            return Ok(());
        }
        if let Some(prefix) = input
            .strip_prefix("/cancel-upload ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let attachment_id = self
                .vault
                .as_ref()
                .context("encrypted vault is unavailable")?
                .outbound_attachment_id(prefix)?;
            let conversation_id = self
                .vault
                .as_ref()
                .unwrap()
                .outbound_attachments()
                .iter()
                .find(|transfer| transfer.attachment_id == attachment_id)
                .context("pending upload is unavailable")?
                .conversation_id;
            connection
                .api
                .delete_attachment(connection.session, attachment_id)
                .await?;
            self.vault_mut()?
                .cancel_outbound_attachment(attachment_id)?;
            self.reload_chat_history(conversation_id)?;
            self.notice = format!("cancelled encrypted upload #{}", short_id(attachment_id));
            return Ok(());
        }
        if let Some(prefix) = input
            .strip_prefix("/cancel-download ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let metadata = self.vault_mut()?.cancel_attachment_download(prefix)?;
            if let Some(directory) = &self.paths.downloads_directory {
                mutte_store::attachment::cancel_partial_download_at(directory, &metadata)?;
            } else {
                mutte_store::attachment::cancel_partial_download(&metadata)?;
            }
            self.notice = format!(
                "cancelled encrypted download #{}",
                short_id(metadata.attachment_id)
            );
            return Ok(());
        }
        if let Some(prefix) = input
            .strip_prefix("/download ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let attachment_id = self.vault_mut()?.request_attachment_download(prefix)?;
            self.notice = format!(
                "downloading encrypted attachment {:8}…",
                attachment_id.simple()
            );
            let download = self
                .vault_mut()?
                .pending_attachment_downloads()
                .into_iter()
                .find(|item| item.metadata.attachment_id == attachment_id);
            if let Some(download) = download {
                self.resume_attachment_download(connection, &download)
                    .await?;
            }
            if !self
                .attachment_cancellation
                .as_ref()
                .is_some_and(|control| control.is_cancelled())
            {
                self.notice = "attachment downloaded and verified".into();
            }
            return Ok(());
        }
        if input == "/thread close" || input == "/thread main" {
            self.conversations[self.selected].scroll_back = 0;
            self.set_selected_visible(None, Some(connection.device))?;
            self.notice = "returned to the main conversation".into();
            return Ok(());
        }
        if let Some(prefix) = input
            .strip_prefix("/thread ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let root = {
                let message = self.resolve_message_prefix(prefix)?;
                message.thread_root.unwrap_or(message.id)
            };
            self.conversations[self.selected].scroll_back = 0;
            self.set_selected_visible(Some(root), Some(connection.device))?;
            self.notice = format!("opened encrypted thread #{}", short_id(root));
            return Ok(());
        }
        if let Some(arguments) = input.strip_prefix("/reply ").map(str::trim) {
            let (prefix, text) = arguments
                .split_once(char::is_whitespace)
                .map(|(prefix, text)| (prefix, text.trim()))
                .filter(|(_, text)| !text.is_empty())
                .context("use /reply MESSAGE_ID message")?;
            let (target_id, target_thread) = {
                let target = self.resolve_message_prefix(prefix)?;
                (target.id, target.thread_root)
            };
            let thread_root = self.conversations[self.selected]
                .active_thread
                .or(target_thread);
            self.send_chat_message(connection, text.into(), Some(target_id), thread_root)
                .await?;
            return Ok(());
        }
        if let Some(handle) = input
            .strip_prefix("/dm ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            self.start_direct_chat(connection, handle.to_owned(), true)
                .await?;
            return Ok(());
        }
        let input = if let Some(literal) = input.strip_prefix("//") {
            format!("/{literal}")
        } else {
            if input.starts_with('/') {
                bail!("unknown command; use /help or Ctrl+K")
            }
            input
        };
        let active_thread = self.conversations[self.selected].active_thread;
        self.send_chat_message(connection, input, active_thread, active_thread)
            .await
    }

    async fn start_direct_chat(
        &mut self,
        connection: &Connection<'_>,
        handle: String,
        make_visible: bool,
    ) -> Result<()> {
        let handle = normalize_direct_handle(&handle)?;
        if let Some(index) = self.direct_conversation_index(&handle)? {
            self.selected = index;
            if make_visible {
                self.set_selected_visible(None, Some(connection.device))?;
            } else {
                self.set_selected_thread(None)?;
            }
            self.notice = format!("already chatting with @{handle}");
            return Ok(());
        }

        self.notice = format!("claiming @{handle}'s one-time device keys…");
        let records = connection
            .api
            .claim_key_packages(connection.session, &handle)
            .await?;
        let packages = records
            .iter()
            .map(|record| (record.device_id, record.key_package.clone()))
            .collect::<Vec<_>>();
        let conversation_id = Uuid::new_v4();
        let bootstrap = connection
            .device
            .create_conversation(conversation_id, &packages)?;
        let envelope = CiphertextEnvelope {
            id: Uuid::new_v4(),
            conversation_id,
            sender_device_id: connection.device.id(),
            sender_handle: self.profile.handle.clone(),
            recipients: bootstrap.recipient_devices,
            kind: EnvelopeKind::Welcome,
            mutation_id: None,
            ciphertext: bootstrap.welcome,
            created_at: Utc::now(),
        };
        self.vault_mut()?.queue_welcome(
            VaultConversation {
                id: conversation_id,
                peer_handle: handle.clone(),
                unread: 0,
            },
            envelope.clone(),
        )?;
        self.conversations.push(ConversationSnapshot {
            conversation_id: Some(conversation_id),
            name: format!("@{handle}"),
            handle: handle.clone(),
            status: format!("encrypted · {} device(s)", records.len()),
            unread: 0,
            verification: VerificationState::Unverified,
            messages: vec![],
            active_thread: None,
            scroll_back: 0,
        });
        self.selected = self.conversations.len() - 1;
        if make_visible {
            self.visible_conversation = Some(VisibleConversation {
                conversation_id,
                thread_root: None,
            });
        }
        self.refresh_chat_verification(self.selected, connection.device);
        match connection
            .api
            .send_message(connection.session, &envelope)
            .await
        {
            Ok(()) => {
                self.vault_mut()?.complete_outbox(envelope.id)?;
                self.notice = format!("encrypted chat with @{handle} ready");
            }
            Err(error) if authentication_required(&error) => return Err(error),
            Err(error) => {
                self.notice = format!("welcome queued for retry: {error}");
            }
        }
        Ok(())
    }

    /// Read-only resolution: never claims keys, changes trust, or marks read.
    pub fn direct_conversation_index(&self, handle: &str) -> Result<Option<usize>> {
        let handle = normalize_direct_handle(handle)?;
        let mut matches = self.conversations.iter().enumerate().filter(|(_, chat)| {
            chat.conversation_id.is_some() && chat.handle.eq_ignore_ascii_case(&handle)
        });
        let first = matches.next().map(|(index, _)| index);
        if matches.next().is_some() {
            bail!(DirectConversationChoiceRequired);
        }
        Ok(first)
    }

    fn validate_message(
        &self,
        text: &str,
        reply_to: Option<Uuid>,
        thread_root: Option<Uuid>,
    ) -> Result<()> {
        if text.is_empty() {
            bail!("message cannot be empty")
        }
        if text.len() > 64 * 1024 {
            bail!("message exceeds the 64 KiB alpha limit")
        }
        if reply_to.is_some_and(|message_id| {
            !self.conversations[self.selected]
                .messages
                .iter()
                .any(|message| message.id == message_id)
        }) {
            bail!("reply target is unavailable in this conversation")
        }
        if thread_root.is_some_and(|message_id| {
            !self.conversations[self.selected]
                .messages
                .iter()
                .any(|message| message.id == message_id && message.thread_root.is_none())
        }) {
            bail!("thread root is unavailable in this conversation")
        }
        Ok(())
    }

    async fn send_chat_message(
        &mut self,
        connection: &Connection<'_>,
        text: String,
        reply_to: Option<Uuid>,
        thread_root: Option<Uuid>,
    ) -> Result<()> {
        let conversation_id = self.conversations[self.selected]
            .conversation_id
            .context("open a chat first with /dm handle")?;
        self.ensure_sending_allowed(self.selected, connection.device)?;
        self.validate_message(&text, reply_to, thread_root)?;
        let message_id = Uuid::new_v4();
        let sent_at = Utc::now();
        let payload = ChatApplicationPayload::Message {
            version: CHAT_APPLICATION_VERSION,
            id: message_id,
            text: text.clone(),
            sent_at,
            attachment: None,
            reply_to,
            thread_root,
        };
        let ciphertext = connection
            .device
            .encrypt_application(conversation_id, &serde_json::to_vec(&payload)?)?;
        let envelope = CiphertextEnvelope {
            id: Uuid::new_v4(),
            conversation_id,
            sender_device_id: connection.device.id(),
            sender_handle: self.profile.handle.clone(),
            recipients: connection.device.recipient_devices(conversation_id)?,
            kind: EnvelopeKind::Application,
            mutation_id: None,
            ciphertext,
            created_at: sent_at,
        };
        self.vault_mut()?.queue_message(
            VaultMessage {
                id: message_id,
                conversation_id,
                author: "You".into(),
                text: text.clone(),
                mine: true,
                sent_at,
                delivery: DeliveryState::Pending,
                attachment: None,
                reply_to,
                thread_root,
                locally_read: true,
            },
            envelope.clone(),
        )?;
        self.conversations[self.selected]
            .messages
            .push(MessageSnapshot {
                id: message_id,
                author: "You".into(),
                text,
                mine: true,
                timestamp: sent_at.with_timezone(&Local),
                delivery: DeliveryState::Pending,
                attachment: None,
                reply_to,
                thread_root,
                locally_read: true,
            });
        match connection
            .api
            .send_message(connection.session, &envelope)
            .await
        {
            Ok(()) => {
                self.vault_mut()?.complete_outbox(envelope.id)?;
                self.mark_message_sent(conversation_id, message_id);
                self.notice = "encrypted message sent".into();
            }
            Err(error) if authentication_required(&error) => return Err(error),
            Err(error) => {
                self.notice = format!("encrypted message queued for retry: {error}");
            }
        }
        Ok(())
    }

    async fn toggle_reaction(
        &mut self,
        connection: &Connection<'_>,
        message_id: Uuid,
        emoji: &str,
    ) -> Result<()> {
        validate_reaction(emoji)?;
        let target = self.conversations[self.selected]
            .messages
            .iter()
            .find(|message| message.id == message_id && !is_reaction_message(message))
            .cloned()
            .context("reaction target is unavailable in this conversation")?;
        let remove = reactions_for(&self.conversations[self.selected].messages, message_id)
            .iter()
            .any(|reaction| reaction.emoji == emoji && reaction.mine);
        let fallback = if remove {
            format!("Reaction removed: {emoji}")
        } else {
            format!("Reaction: {emoji}")
        };
        let thread_root = target.thread_root.or_else(|| {
            (self.conversations[self.selected].active_thread == Some(target.id))
                .then_some(target.id)
        });
        self.send_chat_message(connection, fallback, Some(target.id), thread_root)
            .await
    }

    async fn send_attachment(
        &mut self,
        connection: &Connection<'_>,
        path: &Path,
        reply_to: Option<Uuid>,
        thread_root: Option<Uuid>,
    ) -> Result<()> {
        let conversation_id = self.conversations[self.selected]
            .conversation_id
            .context("open a chat before sending an attachment")?;
        self.ensure_sending_allowed(self.selected, connection.device)?;
        self.validate_message("attachment", reply_to, thread_root)?;
        let prepared = mutte_store::attachment::prepare(path)?;
        let recipients = connection.device.recipient_devices(conversation_id)?;
        let attachment_id = self.vault_mut()?.begin_attachment_upload_scoped(
            conversation_id,
            prepared.source_path,
            prepared.metadata,
            recipients,
            reply_to,
            thread_root,
        )?;
        self.reload_chat_history(conversation_id)?;
        self.notice = "encrypting and uploading attachment…".into();
        self.resume_attachment_upload(connection, attachment_id)
            .await?;
        if self
            .attachment_cancellation
            .as_ref()
            .is_some_and(|control| control.is_cancelled())
        {
            return Ok(());
        }
        match self.flush_outbox(connection).await {
            Ok(()) => self.notice = "encrypted attachment sent".into(),
            Err(error) if authentication_required(&error) => return Err(error),
            Err(error) => self.notice = format!("attachment message queued for retry: {error}"),
        }
        Ok(())
    }

    fn prepare_attachment_queue(&self) -> Result<()> {
        let Some(vault) = &self.vault else {
            return Ok(());
        };
        self.active_attachment_transfers.prepare_pending(
            vault
                .outbound_attachments()
                .iter()
                .map(|item| (item.attachment_id, crate::AttachmentDirection::Upload))
                .chain(vault.pending_attachment_downloads().iter().map(|item| {
                    (
                        item.metadata.attachment_id,
                        crate::AttachmentDirection::Download,
                    )
                })),
        )
    }

    fn cancel_upload_locally(&mut self, attachment_id: Uuid) -> Result<()> {
        let conversation = self
            .vault_mut()?
            .outbound_attachments()
            .into_iter()
            .find(|item| item.attachment_id == attachment_id)
            .context("pending upload missing")?
            .conversation_id;
        self.vault_mut()?
            .cancel_outbound_attachment(attachment_id)?;
        self.reload_chat_history(conversation)?;
        // Unannounced encrypted relay chunks expire under relay retention.
        // Do not delay local cancellation waiting on that same network.
        self.notice = "upload cancelled".into();
        Ok(())
    }

    fn cancel_download_locally(
        &mut self,
        attachment_id: Uuid,
        conversation_id: Uuid,
    ) -> Result<()> {
        let metadata = self
            .vault_mut()?
            .cancel_attachment_download(&attachment_id.to_string())?;
        if let Some(directory) = &self.paths.downloads_directory {
            mutte_store::attachment::cancel_partial_download_at(directory, &metadata)?;
        } else {
            mutte_store::attachment::cancel_partial_download(&metadata)?;
        }
        self.reload_chat_history(conversation_id)?;
        self.notice = "download cancelled".into();
        Ok(())
    }

    fn finish_queued_cancellations(&mut self) -> Result<()> {
        // No network: accepted queue intents must also be persisted after an
        // earlier transfer fails authentication and stops subsequent requests.
        self.prepare_attachment_queue()?;
        for (id, direction) in self.active_attachment_transfers.cancelled_pending()? {
            match direction {
                crate::AttachmentDirection::Upload => self.cancel_upload_locally(id)?,
                crate::AttachmentDirection::Download => {
                    let item = self
                        .vault_mut()?
                        .pending_attachment_downloads()
                        .into_iter()
                        .find(|item| item.metadata.attachment_id == id)
                        .context("pending download missing")?;
                    self.cancel_download_locally(id, item.conversation_id)?;
                }
            }
        }
        self.prepare_attachment_queue()
    }

    async fn resume_attachment_uploads(&mut self, connection: &Connection<'_>) -> Result<usize> {
        self.prepare_attachment_queue()?;
        let transfers = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .outbound_attachments();
        let mut first_error = None;
        for transfer in &transfers {
            if let Err(error) = self
                .resume_attachment_upload(connection, transfer.attachment_id)
                .await
            {
                if authentication_required(&error) {
                    self.finish_queued_cancellations()?;
                    return Err(error);
                }
                first_error.get_or_insert(error);
            }
        }
        self.finish_queued_cancellations()?;
        match first_error {
            Some(error) => Err(error),
            None => Ok(transfers.len()),
        }
    }

    async fn resume_attachment_upload(
        &mut self,
        connection: &Connection<'_>,
        attachment_id: Uuid,
    ) -> Result<()> {
        let control = self.attachment_cancellation.clone().unwrap_or_default();
        let _lease = self.active_attachment_transfers.register(
            attachment_id,
            crate::AttachmentDirection::Upload,
            control.clone(),
            self.attachment_cancellation.is_some(),
        )?;
        let result = control
            .run(self.resume_attachment_upload_inner(connection, attachment_id, &control))
            .await;
        control.finish();
        let result = if control.is_cancelled() {
            Err(crate::AttachmentCancelled.into())
        } else {
            result
        };
        match result {
            Err(error) if error.is::<crate::AttachmentCancelled>() => {
                self.cancel_upload_locally(attachment_id)?;
                Ok(())
            }
            result => result,
        }
    }

    async fn resume_attachment_upload_inner(
        &mut self,
        connection: &Connection<'_>,
        attachment_id: Uuid,
        control: &crate::AttachmentCancellation,
    ) -> Result<()> {
        let transfer = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .outbound_attachments()
            .into_iter()
            .find(|transfer| transfer.attachment_id == attachment_id)
            .context("unknown outbound attachment")?;
        self.active_attachment_transfers.report_progress(
            attachment_id,
            crate::AttachmentDirection::Upload,
            control,
            0,
            transfer.metadata.plaintext_size,
            crate::TransferPhase::Preparing,
        );
        mutte_store::attachment::validate_source(&transfer.source_path, &transfer.metadata)?;
        let status = connection
            .api
            .start_attachment(
                connection.session,
                &AttachmentStart {
                    attachment_id,
                    recipients: transfer.recipients.clone(),
                    chunk_count: transfer.metadata.chunk_count,
                    ciphertext_size: mutte_store::attachment::ciphertext_size(&transfer.metadata)?,
                },
            )
            .await?;
        if status.attachment_id != attachment_id {
            bail!("relay returned status for another attachment")
        }
        let uploaded = status.uploaded_chunks.into_iter().collect::<HashSet<_>>();
        if uploaded.len() > transfer.metadata.chunk_count as usize
            || uploaded
                .iter()
                .any(|index| *index >= transfer.metadata.chunk_count)
        {
            bail!("relay returned invalid attachment upload progress")
        }
        let total_bytes = transfer.metadata.plaintext_size;
        let mut completed_bytes: u64 = uploaded
            .iter()
            .map(|index| attachment_chunk_bytes(total_bytes, *index))
            .sum();
        let mut completed_chunks = uploaded.len() as u32;
        if status.complete {
            completed_bytes = total_bytes;
        }
        self.active_attachment_transfers.report_progress(
            attachment_id,
            crate::AttachmentDirection::Upload,
            control,
            completed_bytes,
            total_bytes,
            crate::TransferPhase::Transferring,
        );
        if !status.complete {
            for chunk_index in 0..transfer.metadata.chunk_count {
                if uploaded.contains(&chunk_index) {
                    continue;
                }
                let ciphertext = mutte_store::attachment::encrypt_chunk(
                    &transfer.source_path,
                    &transfer.metadata,
                    chunk_index,
                )?;
                connection
                    .api
                    .upload_attachment_chunk(
                        connection.session,
                        attachment_id,
                        &AttachmentChunkUpload {
                            chunk_index,
                            ciphertext,
                        },
                    )
                    .await?;
                completed_bytes += attachment_chunk_bytes(total_bytes, chunk_index);
                completed_chunks += 1;
                self.active_attachment_transfers.report_progress(
                    attachment_id,
                    crate::AttachmentDirection::Upload,
                    control,
                    completed_bytes,
                    total_bytes,
                    crate::TransferPhase::Transferring,
                );
                self.events.push_back(ClientEvent::AttachmentProgress {
                    attachment_id,
                    completed_chunks,
                    total_chunks: transfer.metadata.chunk_count,
                });
            }
            self.active_attachment_transfers.report_progress(
                attachment_id,
                crate::AttachmentDirection::Upload,
                control,
                total_bytes,
                total_bytes,
                crate::TransferPhase::Finalizing,
            );
            connection
                .api
                .complete_attachment(connection.session, attachment_id)
                .await?;
        }

        self.active_attachment_transfers.report_progress(
            attachment_id,
            crate::AttachmentDirection::Upload,
            control,
            total_bytes,
            total_bytes,
            crate::TransferPhase::Finalizing,
        );
        control.begin_commit()?;
        let payload = attachment_message_payload(&transfer);
        let ciphertext = connection
            .device
            .encrypt_application(transfer.conversation_id, &serde_json::to_vec(&payload)?)?;
        let envelope = CiphertextEnvelope {
            id: Uuid::new_v4(),
            conversation_id: transfer.conversation_id,
            sender_device_id: connection.device.id(),
            sender_handle: self.profile.handle.clone(),
            recipients: transfer.recipients,
            kind: EnvelopeKind::Application,
            mutation_id: None,
            ciphertext,
            created_at: transfer.created_at,
        };
        self.vault_mut()?
            .queue_uploaded_attachment(attachment_id, envelope)?;
        self.reload_chat_history(transfer.conversation_id)?;
        Ok(())
    }

    async fn resume_attachment_downloads(&mut self, connection: &Connection<'_>) -> Result<usize> {
        self.prepare_attachment_queue()?;
        let pending = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .pending_attachment_downloads();
        let mut first_error = None;
        for download in &pending {
            if let Err(error) = self.resume_attachment_download(connection, download).await {
                // A missing/expired/corrupt file is local to that transfer.
                // Session failure still stops all further network requests.
                if authentication_required(&error) {
                    self.finish_queued_cancellations()?;
                    return Err(error);
                }
                first_error.get_or_insert(error);
            }
        }
        self.finish_queued_cancellations()?;
        match first_error {
            Some(error) => Err(error),
            None => Ok(pending.len()),
        }
    }

    async fn resume_attachment_download(
        &mut self,
        connection: &Connection<'_>,
        download: &mutte_store::PendingAttachmentDownload,
    ) -> Result<()> {
        let control = self.attachment_cancellation.clone().unwrap_or_default();
        let _lease = self.active_attachment_transfers.register(
            download.metadata.attachment_id,
            crate::AttachmentDirection::Download,
            control.clone(),
            self.attachment_cancellation.is_some(),
        )?;
        let result = control
            .run(self.resume_attachment_download_inner(connection, download, &control))
            .await;
        control.finish();
        let result = if control.is_cancelled() {
            Err(crate::AttachmentCancelled.into())
        } else {
            result
        };
        match result {
            Err(error) if error.is::<crate::AttachmentCancelled>() => {
                self.cancel_download_locally(
                    download.metadata.attachment_id,
                    download.conversation_id,
                )?;
                Ok(())
            }
            result => result,
        }
    }

    async fn resume_attachment_download_inner(
        &mut self,
        connection: &Connection<'_>,
        download: &mutte_store::PendingAttachmentDownload,
        control: &crate::AttachmentCancellation,
    ) -> Result<()> {
        let attachment_id = download.metadata.attachment_id;
        let total_bytes = download.metadata.plaintext_size;
        self.active_attachment_transfers.report_progress(
            attachment_id,
            crate::AttachmentDirection::Download,
            control,
            0,
            total_bytes,
            crate::TransferPhase::Preparing,
        );
        let downloads_directory = self.paths.downloads_directory.clone();
        let existing = if let Some(directory) = &downloads_directory {
            mutte_store::attachment::existing_download_at(directory, &download.metadata)?
        } else {
            mutte_store::attachment::existing_download(&download.metadata)?
        };
        let local_path = if let Some(path) = existing {
            self.active_attachment_transfers.report_progress(
                attachment_id,
                crate::AttachmentDirection::Download,
                control,
                total_bytes,
                total_bytes,
                crate::TransferPhase::Finalizing,
            );
            control.begin_commit()?;
            path
        } else {
            let mut writer = if let Some(directory) = &downloads_directory {
                mutte_store::attachment::AttachmentDownload::resume_at(
                    directory,
                    &download.metadata,
                )?
            } else {
                mutte_store::attachment::AttachmentDownload::resume(&download.metadata)?
            };
            self.active_attachment_transfers.report_progress(
                attachment_id,
                crate::AttachmentDirection::Download,
                control,
                (writer.next_chunk() as u64 * mutte_protocol::ATTACHMENT_CHUNK_BYTES as u64)
                    .min(total_bytes),
                total_bytes,
                crate::TransferPhase::Transferring,
            );
            while writer.next_chunk() < download.metadata.chunk_count {
                let chunk_index = writer.next_chunk();
                let chunk = connection
                    .api
                    .attachment_chunk(
                        connection.session,
                        download.metadata.attachment_id,
                        chunk_index,
                    )
                    .await?;
                if chunk.attachment_id != download.metadata.attachment_id
                    || chunk.chunk_index != chunk_index
                {
                    bail!("relay returned the wrong attachment chunk")
                }
                writer.write_chunk(chunk_index, &chunk.ciphertext)?;
                self.active_attachment_transfers.report_progress(
                    attachment_id,
                    crate::AttachmentDirection::Download,
                    control,
                    (writer.next_chunk() as u64 * mutte_protocol::ATTACHMENT_CHUNK_BYTES as u64)
                        .min(total_bytes),
                    total_bytes,
                    crate::TransferPhase::Transferring,
                );
                self.events.push_back(ClientEvent::AttachmentProgress {
                    attachment_id: download.metadata.attachment_id,
                    completed_chunks: chunk_index + 1,
                    total_chunks: download.metadata.chunk_count,
                });
            }
            self.active_attachment_transfers.report_progress(
                attachment_id,
                crate::AttachmentDirection::Download,
                control,
                total_bytes,
                total_bytes,
                crate::TransferPhase::Finalizing,
            );
            control.begin_commit()?;
            writer.finish()?
        };
        self.vault_mut()?.complete_attachment_download(
            download.conversation_id,
            download.message_id,
            local_path,
        )?;
        self.reload_chat_history(download.conversation_id)?;
        Ok(())
    }

    fn submit_demo(&mut self, input: String) {
        if input == "/quit" {
            self.events.push_back(ClientEvent::QuitRequested);
        } else if input == "/help" {
            self.events.push_back(ClientEvent::HelpRequested);
            self.notice = "action menu opened".into();
        } else if input == "/verify" {
            self.notice = "safety codes are available in a real encrypted chat".into();
        } else if let Some(handle) = input.strip_prefix("/dm ").map(str::trim) {
            if handle.is_empty() {
                self.notice = "enter a handle after /dm".into();
                return;
            }
            self.conversations.push(ConversationSnapshot {
                conversation_id: Some(Uuid::new_v4()),
                name: format!("@{handle}"),
                handle: handle.into(),
                status: "demo encrypted chat".into(),
                unread: 0,
                verification: VerificationState::Unverified,
                messages: vec![],
                active_thread: None,
                scroll_back: 0,
            });
            self.selected = self.conversations.len() - 1;
            self.notice = format!("demo chat with @{handle} ready");
        } else if input.starts_with('/') {
            self.notice = "link an account to use this encrypted action".into();
        } else {
            let active_thread = self.conversations[self.selected].active_thread;
            self.append_demo_message(input, active_thread, active_thread);
        }
    }

    fn append_demo_message(
        &mut self,
        text: String,
        reply_to: Option<Uuid>,
        thread_root: Option<Uuid>,
    ) {
        self.conversations[self.selected]
            .messages
            .push(MessageSnapshot {
                id: Uuid::new_v4(),
                author: "You".into(),
                text,
                mine: true,
                timestamp: Local::now(),
                delivery: DeliveryState::Sent,
                attachment: None,
                reply_to,
                thread_root,
                locally_read: true,
            });
    }

    async fn show_devices(&mut self, connection: &Connection<'_>) -> Result<()> {
        let list = connection.api.account_devices(connection.session).await?;
        self.device_panel = Some(DevicePanel {
            devices: list.devices,
            status: match &self.pending_device_revocation {
                Some(pending) => format!(
                    "Removal {:8} is waiting for browser approval.",
                    pending.target_device_id.simple()
                ),
                None => {
                    "Use /sync-device PREFIX to add a new device to local chats, or /revoke PREFIX."
                        .into()
                }
            },
        });
        self.notice = "account devices loaded".into();
        Ok(())
    }

    async fn start_device_revocation(
        &mut self,
        connection: &Connection<'_>,
        prefix: &str,
    ) -> Result<()> {
        if self.pending_device_revocation.is_some() {
            bail!("finish the pending device removal before starting another")
        }
        let list = connection.api.account_devices(connection.session).await?;
        let target = resolve_account_device(&list.devices, prefix)?;
        if target.current {
            bail!("this terminal cannot revoke itself")
        }
        if target.state == AccountDeviceState::Revoked {
            bail!("that device is already revoked")
        }
        let authorization = connection
            .api
            .start_device_revocation(connection.session, target.device_id)
            .await?;
        let pending = PendingDeviceRevocation {
            request_id: authorization.request_id,
            target_device_id: authorization.target_device_id,
            confirmation_url: authorization.confirmation_url,
            expires_at: authorization.expires_at,
        };
        self.vault_mut()?
            .save_pending_device_revocation(pending.clone())?;
        self.pending_device_revocation = Some(pending.clone());
        self.device_panel = Some(DevicePanel {
            devices: list.devices,
            status: if connection.open_browser {
                format!(
                    "Confirm removal of {} in the browser. Mutte is waiting…",
                    target.device_name
                )
            } else {
                format!("Open to confirm: {}", pending.confirmation_url)
            },
        });
        if connection.open_browser {
            self.events.push_back(ClientEvent::AuthenticationRequired {
                url: pending.confirmation_url.clone(),
            });
        }
        self.notice = "device removal awaiting step-up approval".into();
        Ok(())
    }

    async fn sync_device(&mut self, connection: &Connection<'_>, prefix: &str) -> Result<()> {
        let list = connection.api.account_devices(connection.session).await?;
        let target = resolve_account_device(&list.devices, prefix)?;
        if target.current {
            bail!("this terminal is already the current device")
        }
        if target.state == AccountDeviceState::Revoked {
            bail!("create and link a fresh device identity; revoked identities cannot be reused")
        }
        let stored_conversations = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .conversations()
            .to_vec();
        let mut conversations = Vec::new();
        for conversation in stored_conversations {
            if connection.device.has_conversation(conversation.id)?
                && !connection
                    .device
                    .conversation_contains_device(conversation.id, target.device_id)?
            {
                if self
                    .vault
                    .as_ref()
                    .is_some_and(|vault| vault.has_pending_control(conversation.id))
                {
                    bail!(
                        "finish the queued membership change for @{} before syncing another device",
                        conversation.peer_handle
                    )
                }
                conversations.push(conversation);
            }
        }
        if conversations.is_empty() {
            bail!("no local encrypted chat needs that device")
        }
        self.device_panel = None;
        self.notice = format!(
            "synchronizing {} into {} chat(s)…",
            target.device_name,
            conversations.len()
        );
        let mut cancelled = 0usize;
        for conversation in &conversations {
            let peer_handle = normalize_synced_handle(&conversation.peer_handle)
                .context("local conversation is missing authenticated peer metadata")?;
            // Capture before obtaining a relay mutation lease. A retry refreshes
            // this journal until the first encrypted history part is staged.
            let history_transfer_id = self
                .vault_mut()?
                .begin_history_transfer(conversation.id, target.device_id)?;
            let authorization = connection
                .api
                .acquire_conversation_mutation(connection.session, conversation.id)
                .await?;
            // Claim one package only when this group is ready to consume it.
            // A crash can therefore strand at most one one-time package.
            let records = connection
                .api
                .claim_account_device_key_packages(connection.session, target.device_id, 1)
                .await;
            let mut records = match records {
                Ok(records) => records,
                Err(error) => {
                    connection
                        .api
                        .release_conversation_mutation(
                            connection.session,
                            conversation.id,
                            authorization.mutation_id,
                        )
                        .await?;
                    return Err(error);
                }
            };
            let Some(record) = records.pop() else {
                connection
                    .api
                    .release_conversation_mutation(
                        connection.session,
                        conversation.id,
                        authorization.mutation_id,
                    )
                    .await?;
                bail!("relay omitted the claimed device key package")
            };
            if record.device_id != target.device_id {
                connection
                    .api
                    .release_conversation_mutation(
                        connection.session,
                        conversation.id,
                        authorization.mutation_id,
                    )
                    .await?;
                bail!("relay returned a key package for the wrong account device")
            }
            let cancelled_ids = self
                .vault_mut()?
                .cancel_application_outbox(conversation.id)?;
            cancelled += cancelled_ids.len();
            self.mark_messages_cancelled(conversation.id, &cancelled_ids);
            let sync_payload = serde_json::to_vec(&DeviceSyncPayload { peer_handle })?;
            let addition = connection.device.add_device(
                conversation.id,
                target.device_id,
                authorization.mutation_id,
                &record.key_package,
                &sync_payload,
            )?;
            self.stage_addition(connection.device, &addition)?;
            self.grant_history_attachments(connection, history_transfer_id, target.device_id)
                .await?;
            self.queue_history_transfer(connection.device, history_transfer_id)?;
            if let Some(index) = self.chat_index(conversation.id) {
                self.refresh_chat_verification(index, connection.device);
            }
        }
        self.refresh_verification_states(connection.device);
        match self.flush_outbox(connection).await {
            Ok(()) => {
                self.notice = format!(
                    "synced {} into {} chat(s) with encrypted history · cancelled {cancelled} stale send(s) · run /verify",
                    target.device_name,
                    conversations.len()
                );
            }
            Err(error) if authentication_required(&error) => return Err(error),
            Err(error) => {
                self.notice = format!("device sync queued for retry: {error}");
            }
        }
        self.device_panel = Some(DevicePanel {
            devices: list.devices,
            status: format!(
                "Added {} to {} local encrypted chat(s). Encrypted history is transferring.",
                target.device_name,
                conversations.len()
            ),
        });
        Ok(())
    }

    async fn restore_pending_membership(&mut self, connection: &Connection<'_>) -> Result<()> {
        for addition in connection.device.pending_additions()? {
            self.stage_addition(connection.device, &addition)?;
            if addition.existing_recipient_devices.is_empty() {
                let mutation_id = addition
                    .mutation_id
                    .context("pending device addition has no mutation lease")?;
                connection
                    .api
                    .release_conversation_mutation(
                        connection.session,
                        addition.conversation_id,
                        mutation_id,
                    )
                    .await?;
            }
        }
        for removal in connection.device.pending_removals()? {
            let staged = self.stage_removal(connection.device, &removal)?;
            if !staged {
                let mutation_id = removal
                    .mutation_id
                    .context("pending device removal has no mutation lease")?;
                connection
                    .api
                    .release_conversation_mutation(
                        connection.session,
                        removal.conversation_id,
                        mutation_id,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    fn stage_addition(&mut self, device: &Device, addition: &ConversationAddition) -> Result<()> {
        let mut envelopes = Vec::with_capacity(3);
        if !addition.existing_recipient_devices.is_empty() {
            let mutation_id = addition
                .mutation_id
                .context("pending device addition has no mutation lease")?;
            envelopes.push(CiphertextEnvelope {
                id: addition.commit_envelope_id,
                conversation_id: addition.conversation_id,
                sender_device_id: device.id(),
                sender_handle: self.profile.handle.clone(),
                recipients: addition.existing_recipient_devices.clone(),
                kind: EnvelopeKind::Commit,
                mutation_id: Some(mutation_id),
                ciphertext: addition.commit.clone(),
                created_at: addition.created_at,
            });
        }
        envelopes.push(CiphertextEnvelope {
            id: addition.welcome_envelope_id,
            conversation_id: addition.conversation_id,
            sender_device_id: device.id(),
            sender_handle: self.profile.handle.clone(),
            recipients: vec![addition.added_device],
            kind: EnvelopeKind::Welcome,
            mutation_id: None,
            ciphertext: addition.welcome.clone(),
            created_at: addition.created_at,
        });
        envelopes.push(CiphertextEnvelope {
            id: addition.sync_envelope_id,
            conversation_id: addition.conversation_id,
            sender_device_id: device.id(),
            sender_handle: self.profile.handle.clone(),
            recipients: vec![addition.added_device],
            kind: EnvelopeKind::DeviceSync,
            mutation_id: None,
            ciphertext: addition.sync_message.clone(),
            created_at: addition.created_at,
        });
        self.vault_mut()?.queue_control_envelopes(envelopes)?;
        device.complete_addition(addition.sync_envelope_id)?;
        Ok(())
    }

    async fn resume_history_sync(&mut self, connection: &Connection<'_>) -> Result<usize> {
        let transfers = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .outbound_history_transfers();
        let mut queued = 0usize;
        for transfer in transfers {
            if connection
                .device
                .has_conversation(transfer.conversation_id)?
                && connection.device.conversation_contains_device(
                    transfer.conversation_id,
                    transfer.target_device_id,
                )?
            {
                self.grant_history_attachments(
                    connection,
                    transfer.transfer_id,
                    transfer.target_device_id,
                )
                .await?;
                queued += self.queue_history_transfer(connection.device, transfer.transfer_id)?;
            }
        }
        queued += self.queue_pending_history_acknowledgements(connection.device)?;
        Ok(queued)
    }

    async fn grant_history_attachments(
        &self,
        connection: &Connection<'_>,
        transfer_id: Uuid,
        target_device_id: Uuid,
    ) -> Result<()> {
        let attachment_ids = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .history_attachment_ids(transfer_id)?;
        for attachment_id in attachment_ids {
            connection
                .api
                .grant_attachment_recipient(connection.session, attachment_id, target_device_id)
                .await?;
        }
        Ok(())
    }

    fn queue_history_transfer(&mut self, device: &Device, transfer_id: Uuid) -> Result<usize> {
        let transfer = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .outbound_history_transfers()
            .into_iter()
            .find(|transfer| transfer.transfer_id == transfer_id)
            .context("unknown outbound history transfer")?;
        let mut queued = 0usize;
        while let Some(payload) = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .next_history_payload(transfer_id)?
        {
            let ciphertext = device
                .encrypt_application(transfer.conversation_id, &serde_json::to_vec(&payload)?)?;
            let envelope = CiphertextEnvelope {
                id: Uuid::new_v4(),
                conversation_id: transfer.conversation_id,
                sender_device_id: device.id(),
                sender_handle: self.profile.handle.clone(),
                recipients: vec![transfer.target_device_id],
                kind: EnvelopeKind::HistorySync,
                mutation_id: None,
                ciphertext,
                created_at: Utc::now(),
            };
            self.vault_mut()?
                .queue_history_part(transfer_id, envelope)?;
            queued += 1;
        }
        Ok(queued)
    }

    fn queue_pending_history_acknowledgements(&mut self, device: &Device) -> Result<usize> {
        let pending = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .pending_history_acknowledgements();
        let mut queued = 0usize;
        for acknowledgement in pending {
            let payload = HistorySyncPayload::Ack {
                version: HISTORY_SYNC_VERSION,
                transfer_id: acknowledgement.transfer_id,
                source_device_id: acknowledgement.source_device_id,
                transcript_hash: acknowledgement.transcript_hash,
                imported_count: acknowledgement.imported_count,
            };
            let ciphertext = device.encrypt_application(
                acknowledgement.conversation_id,
                &serde_json::to_vec(&payload)?,
            )?;
            let envelope = CiphertextEnvelope {
                id: Uuid::new_v4(),
                conversation_id: acknowledgement.conversation_id,
                sender_device_id: device.id(),
                sender_handle: self.profile.handle.clone(),
                recipients: vec![acknowledgement.source_device_id],
                kind: EnvelopeKind::HistorySync,
                mutation_id: None,
                ciphertext,
                created_at: Utc::now(),
            };
            self.vault_mut()?
                .queue_history_ack(acknowledgement.transfer_id, envelope)?;
            queued += 1;
        }
        Ok(queued)
    }

    fn stage_removal(&mut self, device: &Device, removal: &ConversationRemoval) -> Result<bool> {
        if removal.recipient_devices.is_empty() {
            device.complete_removal(removal.envelope_id)?;
            return Ok(false);
        }
        let mutation_id = removal
            .mutation_id
            .context("pending device removal has no mutation lease")?;
        let envelope = CiphertextEnvelope {
            id: removal.envelope_id,
            conversation_id: removal.conversation_id,
            sender_device_id: device.id(),
            sender_handle: self.profile.handle.clone(),
            recipients: removal.recipient_devices.clone(),
            kind: EnvelopeKind::Commit,
            mutation_id: Some(mutation_id),
            ciphertext: removal.commit.clone(),
            created_at: removal.created_at,
        };
        self.vault_mut()?.queue_commit(envelope)?;
        device.complete_removal(removal.envelope_id)?;
        Ok(true)
    }

    async fn poll_device_revocation(&mut self, connection: &Connection<'_>) -> Result<()> {
        let Some(pending) = self.pending_device_revocation.clone() else {
            return Ok(());
        };
        let status = connection
            .api
            .device_revocation_status(connection.session, pending.request_id)
            .await?;
        if status.target_device_id != pending.target_device_id {
            bail!("relay returned a mismatched device-removal target")
        }
        match status.state {
            DeviceRevocationState::Pending => Ok(()),
            DeviceRevocationState::Expired => {
                self.vault_mut()?
                    .clear_pending_device_revocation(pending.request_id)?;
                self.pending_device_revocation = None;
                if let Some(panel) = &mut self.device_panel {
                    panel.status = "Removal request expired. Run /revoke again.".into();
                }
                self.notice = "device removal expired".into();
                Ok(())
            }
            DeviceRevocationState::Approved => {
                self.vault_mut()?
                    .clear_pending_device_revocation(pending.request_id)?;
                self.pending_device_revocation = None;
                let devices = connection
                    .api
                    .account_devices(connection.session)
                    .await?
                    .devices;
                self.device_panel = Some(DevicePanel {
                    devices,
                    status: "Device revoked. Encrypted chats are reconciling automatically.".into(),
                });
                self.notice = "device revoked · reconciling durable account event".into();
                Ok(())
            }
        }
    }

    async fn sync_account_device_events(&mut self, connection: &Connection<'_>) -> Result<()> {
        let batch = connection
            .api
            .account_device_events(connection.session)
            .await?;
        if batch.events.is_empty() {
            return Ok(());
        }
        let devices = connection
            .api
            .account_devices(connection.session)
            .await?
            .devices;
        for event in batch.events {
            match event.kind {
                AccountDeviceEventKind::Added => {
                    if let Some(device) = devices
                        .iter()
                        .find(|device| device.device_id == event.target_device_id)
                    {
                        self.notice = format!(
                            "new device {} linked · run /sync-device {} to add it to chats",
                            device.device_name,
                            short_device_id(device.device_id)
                        );
                    } else {
                        self.notice = "a new account device was linked · open /devices".into();
                    }
                }
                AccountDeviceEventKind::Revoked => {
                    self.reconcile_revoked_device(connection, event.target_device_id, &devices)
                        .await?;
                }
            }
            connection
                .api
                .acknowledge_account_device_event(connection.session, event.delivery_id)
                .await
                .context("acknowledge reconciled account device event")?;
        }
        Ok(())
    }

    async fn reconcile_revoked_device(
        &mut self,
        connection: &Connection<'_>,
        target_device_id: Uuid,
        devices: &[AccountDevice],
    ) -> Result<()> {
        let pending_removals = connection.device.pending_removals()?;
        let mut rotated = 0usize;
        for removal in pending_removals
            .iter()
            .filter(|removal| removal.removed_device == target_device_id)
        {
            let staged = self.stage_removal(connection.device, removal)?;
            if !staged {
                let mutation_id = removal
                    .mutation_id
                    .context("pending device removal has no mutation lease")?;
                connection
                    .api
                    .release_conversation_mutation(
                        connection.session,
                        removal.conversation_id,
                        mutation_id,
                    )
                    .await?;
            }
            rotated += 1;
        }

        let active_devices = devices
            .iter()
            .filter(|device| device.state == AccountDeviceState::Active)
            .map(|device| device.device_id)
            .collect::<std::collections::HashSet<_>>();
        let conversations = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .conversations()
            .to_vec();
        let mut cancelled = 0usize;
        for conversation in conversations {
            if !connection.device.has_conversation(conversation.id)?
                || !connection
                    .device
                    .conversation_contains_device(conversation.id, target_device_id)?
            {
                continue;
            }
            let code = connection
                .device
                .conversation_safety_code(conversation.id)?;
            if elected_account_committer(code.member_devices(), &active_devices)
                != Some(connection.device.id())
            {
                continue;
            }
            if self
                .vault
                .as_ref()
                .is_some_and(|vault| vault.has_pending_control(conversation.id))
            {
                bail!(
                    "conversation with @{} still has a queued membership change",
                    conversation.peer_handle
                )
            }

            let authorization = connection
                .api
                .acquire_conversation_mutation(connection.session, conversation.id)
                .await?;
            let cancelled_ids = self
                .vault_mut()?
                .cancel_application_outbox(conversation.id)?;
            cancelled += cancelled_ids.len();
            self.mark_messages_cancelled(conversation.id, &cancelled_ids);
            let removal = connection.device.remove_device(
                conversation.id,
                target_device_id,
                authorization.mutation_id,
            )?;
            let staged = self.stage_removal(connection.device, &removal)?;
            if !staged {
                connection
                    .api
                    .release_conversation_mutation(
                        connection.session,
                        conversation.id,
                        authorization.mutation_id,
                    )
                    .await?;
            }
            rotated += 1;
        }
        self.refresh_verification_states(connection.device);
        self.notice = format!(
            "revoked device reconciled · {rotated} chat epoch(s) rotated · {cancelled} stale send(s) cancelled · run /verify"
        );
        Ok(())
    }

    async fn sync_mailbox(&mut self, connection: &Connection<'_>) -> Result<()> {
        self.poll_device_revocation(connection).await?;
        if let Err(error) = self.sync_account_device_events(connection).await {
            self.record_recoverable_network_error(error, "device reconciliation waiting")?;
        }
        if let Err(error) = self.resume_attachment_uploads(connection).await {
            self.record_recoverable_network_error(error, "attachment upload waiting")?;
        }
        if let Err(error) = self.resume_history_sync(connection).await {
            self.record_recoverable_network_error(error, "history sync waiting")?;
        }
        if let Err(error) = self.queue_pending_receipts(connection.device) {
            self.notice = format!("encrypted receipts waiting: {error}");
        }
        if let Err(error) = self.flush_outbox(connection).await {
            self.record_recoverable_network_error(error, "outbox waiting")?;
        }
        let batch = connection.api.messages(connection.session).await?;
        let count = batch.messages.len();
        for message in batch.messages {
            self.process_mailbox_message(connection, message).await?;
        }
        // Acknowledging the mailbox only confirms relay consumption. Publish
        // the encrypted device receipt now rather than waiting for a new poll.
        // Large file downloads must not hold these already-durable receipts.
        if let Err(error) = self.flush_receipt_outbox(connection).await {
            self.record_recoverable_network_error(error, "encrypted receipts waiting")?;
        }
        if let Err(error) = self.resume_attachment_downloads(connection).await {
            self.record_recoverable_network_error(error, "attachment download waiting")?;
        }
        if count > 0 {
            self.notice = format!("received {count} encrypted delivery(s)");
        }
        Ok(())
    }

    fn record_recoverable_network_error(
        &mut self,
        error: anyhow::Error,
        context: &str,
    ) -> Result<()> {
        if authentication_required(&error) {
            return Err(error);
        }
        self.notice = format!("{context}: {error}");
        Ok(())
    }

    async fn flush_outbox(&mut self, connection: &Connection<'_>) -> Result<()> {
        self.flush_outbox_matching(connection, false).await
    }

    async fn flush_receipt_outbox(&mut self, connection: &Connection<'_>) -> Result<()> {
        self.flush_outbox_matching(connection, true).await
    }

    async fn flush_outbox_matching(
        &mut self,
        connection: &Connection<'_>,
        receipts_only: bool,
    ) -> Result<()> {
        let pending = self
            .vault_mut()?
            .outbox()
            .into_iter()
            .filter(|item| !receipts_only || item.receipt.is_some())
            .collect::<Vec<_>>();
        let count = pending.len();
        for item in pending {
            if item.envelope.kind == EnvelopeKind::Application {
                self.ensure_conversation_sending_allowed(
                    item.envelope.conversation_id,
                    connection.device,
                )?;
            }
            connection
                .api
                .send_message(connection.session, &item.envelope)
                .await?;
            self.vault_mut()?.complete_outbox(item.envelope.id)?;
            if let Some(message_id) = item.message_id {
                self.mark_message_sent(item.envelope.conversation_id, message_id);
            }
        }
        if count > 0 {
            self.notice = format!("sent {count} queued encrypted delivery(s)");
        }
        Ok(())
    }

    async fn process_mailbox_message(
        &mut self,
        connection: &Connection<'_>,
        message: MailboxMessage,
    ) -> Result<()> {
        let envelope = message.envelope;
        match envelope.kind {
            EnvelopeKind::Welcome => {
                connection.device.join_conversation(
                    envelope.conversation_id,
                    envelope.sender_device_id,
                    &envelope.ciphertext,
                )?;
                let index = self.ensure_chat(envelope.conversation_id, &envelope.sender_handle)?;
                self.refresh_chat_verification(index, connection.device);
                connection
                    .api
                    .acknowledge(connection.session, message.delivery_id)
                    .await?;
            }
            EnvelopeKind::Application => {
                let pending = connection.device.decrypt_application(
                    message.delivery_id,
                    envelope.conversation_id,
                    envelope.sender_device_id,
                    &envelope.sender_handle,
                    &envelope.ciphertext,
                )?;
                self.present_pending(&pending)?;
                self.queue_pending_receipts(connection.device)?;
                if let Some(index) = self.chat_index(pending.conversation_id) {
                    self.refresh_chat_verification(index, connection.device);
                }
                connection
                    .api
                    .acknowledge(connection.session, message.delivery_id)
                    .await?;
                connection.device.complete_delivery(message.delivery_id)?;
            }
            EnvelopeKind::Commit => {
                let pending = connection.device.process_commit(
                    message.delivery_id,
                    envelope.conversation_id,
                    envelope.sender_device_id,
                    &envelope.ciphertext,
                )?;
                self.apply_pending_commit(&pending, connection.device)?;
                connection
                    .api
                    .acknowledge(connection.session, message.delivery_id)
                    .await?;
                connection
                    .device
                    .complete_commit_delivery(message.delivery_id)?;
            }
            EnvelopeKind::DeviceSync => {
                let pending = connection.device.decrypt_device_sync(
                    message.delivery_id,
                    envelope.conversation_id,
                    envelope.sender_device_id,
                    &envelope.sender_handle,
                    &envelope.ciphertext,
                )?;
                self.present_device_sync(&pending)?;
                connection
                    .api
                    .acknowledge(connection.session, message.delivery_id)
                    .await?;
                connection.device.complete_delivery(message.delivery_id)?;
            }
            EnvelopeKind::HistorySync => {
                let pending = connection.device.decrypt_history_sync(
                    message.delivery_id,
                    envelope.conversation_id,
                    envelope.sender_device_id,
                    &envelope.sender_handle,
                    &envelope.ciphertext,
                )?;
                self.present_history_sync(&pending, connection.device)?;
                if let Some(index) = self.chat_index(pending.conversation_id) {
                    self.refresh_chat_verification(index, connection.device);
                }
                connection
                    .api
                    .acknowledge(connection.session, message.delivery_id)
                    .await?;
                connection.device.complete_delivery(message.delivery_id)?;
            }
        }
        Ok(())
    }

    async fn restore_pending(&mut self, connection: &Connection<'_>) -> Result<()> {
        for pending in connection.device.pending_commits()? {
            self.apply_pending_commit(&pending, connection.device)?;
            connection
                .api
                .acknowledge(connection.session, pending.delivery_id)
                .await?;
            connection
                .device
                .complete_commit_delivery(pending.delivery_id)?;
        }
        for pending in connection.device.pending_applications()? {
            match pending.kind {
                PendingApplicationKind::Chat => {
                    self.present_pending(&pending)?;
                    self.queue_pending_receipts(connection.device)?;
                }
                PendingApplicationKind::DeviceSync => self.present_device_sync(&pending)?,
                PendingApplicationKind::HistorySync => {
                    self.present_history_sync(&pending, connection.device)?
                }
            }
            if let Some(index) = self.chat_index(pending.conversation_id) {
                self.refresh_chat_verification(index, connection.device);
            }
            connection
                .api
                .acknowledge(connection.session, pending.delivery_id)
                .await?;
            connection.device.complete_delivery(pending.delivery_id)?;
        }
        Ok(())
    }

    fn queue_pending_receipts(&mut self, device: &Device) -> Result<usize> {
        let batches = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .pending_receipt_batches();
        let mut queued = 0usize;
        for batch in &batches {
            if batch.message_ids.is_empty() || batch.message_ids.len() > MAX_RECEIPT_MESSAGE_IDS {
                bail!("pending receipt batch exceeds protocol limits")
            }
            if self
                .vault
                .as_ref()
                .is_some_and(|vault| vault.has_pending_control(batch.conversation_id))
            {
                continue;
            }
            let sent_at = Utc::now();
            let payload = ChatApplicationPayload::Receipt {
                version: CHAT_APPLICATION_VERSION,
                receipt_id: Uuid::new_v4(),
                kind: batch.kind,
                message_ids: batch.message_ids.clone(),
                sent_at,
            };
            let ciphertext = device
                .encrypt_application(batch.conversation_id, &serde_json::to_vec(&payload)?)?;
            let envelope = CiphertextEnvelope {
                id: Uuid::new_v4(),
                conversation_id: batch.conversation_id,
                sender_device_id: device.id(),
                sender_handle: self.profile.handle.clone(),
                recipients: device.recipient_devices(batch.conversation_id)?,
                kind: EnvelopeKind::Application,
                mutation_id: None,
                ciphertext,
                created_at: sent_at,
            };
            self.vault_mut()?.queue_receipt(batch.clone(), envelope)?;
            queued += 1;
        }
        Ok(queued)
    }

    fn present_device_sync(&mut self, pending: &PendingApplication) -> Result<()> {
        if pending.kind != PendingApplicationKind::DeviceSync {
            bail!("expected encrypted device-sync metadata")
        }
        let payload: DeviceSyncPayload = serde_json::from_slice(&pending.plaintext)
            .context("decrypted device-sync payload is invalid")?;
        let handle = normalize_synced_handle(&payload.peer_handle)?;
        let index = self.ensure_chat(pending.conversation_id, &handle)?;
        self.conversations[index].status = "encrypted · synced to this device".into();
        self.notice = format!("encrypted chat with @{handle} synchronized");
        Ok(())
    }

    fn present_history_sync(
        &mut self,
        pending: &PendingApplication,
        device: &Device,
    ) -> Result<()> {
        if pending.kind != PendingApplicationKind::HistorySync {
            bail!("expected encrypted history-sync application")
        }
        if pending.sender_handle != self.profile.handle {
            bail!("history sync must come from another authenticated account device")
        }
        let payload: HistorySyncPayload = serde_json::from_slice(&pending.plaintext)
            .context("decrypted history-sync payload is invalid")?;
        let outcome = self.vault_mut()?.apply_history_sync(
            pending.conversation_id,
            pending.sender_device_id,
            device.id(),
            payload,
        )?;
        match outcome {
            HistorySyncOutcome::Pending => {
                self.notice = "receiving encrypted conversation history…".into();
            }
            HistorySyncOutcome::Imported {
                inserted_count,
                imported_count,
                ..
            } => {
                self.reload_chat_history(pending.conversation_id)?;
                self.queue_pending_history_acknowledgements(device)?;
                self.notice = format!(
                    "encrypted history restored · {inserted_count}/{imported_count} new message(s)"
                );
            }
            HistorySyncOutcome::Acknowledged { imported_count, .. } => {
                self.notice =
                    format!("encrypted history sync complete · {imported_count} message(s)");
            }
        }
        Ok(())
    }

    fn reload_chat_history(&mut self, conversation_id: Uuid) -> Result<()> {
        let mut messages = self
            .vault
            .as_ref()
            .context("encrypted vault is unavailable")?
            .messages()
            .iter()
            .filter(|message| message.conversation_id == conversation_id)
            .map(|message| MessageSnapshot {
                id: message.id,
                author: message.author.clone(),
                text: message.text.clone(),
                mine: message.mine,
                timestamp: message.sent_at.with_timezone(&Local),
                delivery: message.delivery,
                attachment: message.attachment.clone(),
                reply_to: message.reply_to,
                thread_root: message.thread_root,
                locally_read: message.locally_read,
            })
            .collect::<Vec<_>>();
        for transfer in self
            .vault
            .as_ref()
            .unwrap()
            .outbound_attachments()
            .into_iter()
            .filter(|transfer| transfer.conversation_id == conversation_id)
        {
            messages.push(MessageSnapshot {
                id: transfer.message_id,
                author: "You".into(),
                text: format!("📎 {}", transfer.metadata.filename),
                mine: true,
                timestamp: transfer.created_at.with_timezone(&Local),
                delivery: DeliveryState::Pending,
                attachment: Some(VaultAttachment {
                    metadata: transfer.metadata,
                    local_path: Some(transfer.source_path),
                    download_requested: false,
                }),
                reply_to: transfer.reply_to,
                thread_root: transfer.thread_root,
                locally_read: true,
            });
        }
        messages.sort_by_key(|message| (message.timestamp, message.id));
        let index = self
            .chat_index(conversation_id)
            .context("history belongs to an unknown local chat")?;
        self.conversations[index].messages = messages;
        self.conversations[index].status = "encrypted · history restored".into();
        Ok(())
    }

    /// Inspect transfer state without exposing file keys to frontend controls.
    pub fn attachment_send_pending(
        &self,
        conversation_id: Uuid,
        path: &Path,
        reply_to: Option<Uuid>,
        thread_root: Option<Uuid>,
    ) -> bool {
        self.vault.as_ref().is_some_and(|vault| {
            vault.outbound_attachments().iter().any(|transfer| {
                transfer.conversation_id == conversation_id
                    && transfer.source_path == path
                    && transfer.reply_to == reply_to
                    && transfer.thread_root == thread_root
            }) || vault.messages().iter().any(|message| {
                message.conversation_id == conversation_id
                    && message.mine
                    && message.delivery == DeliveryState::Pending
                    && message.reply_to == reply_to
                    && message.thread_root == thread_root
                    && message
                        .attachment
                        .as_ref()
                        .is_some_and(|attachment| attachment.local_path.as_deref() == Some(path))
            })
        })
    }

    fn apply_pending_commit(&mut self, pending: &PendingCommit, device: &Device) -> Result<()> {
        let cancelled_ids = self
            .vault_mut()?
            .cancel_application_outbox(pending.conversation_id)?;
        self.mark_messages_cancelled(pending.conversation_id, &cancelled_ids);
        let change = match (pending.added_devices.len(), pending.removed_devices.len()) {
            (added, 0) => format!("{added} device(s) added"),
            (0, removed) => format!("{removed} device(s) removed"),
            (added, removed) => format!("{added} added · {removed} removed"),
        };
        if let Some(index) = self.chat_index(pending.conversation_id) {
            self.refresh_chat_verification(index, device);
            self.conversations[index].status = format!("encrypted · epoch rotated · {change}");
        }
        self.notice = format!(
            "membership changed ({change}) · {} stale send(s) cancelled · run /verify",
            cancelled_ids.len()
        );
        Ok(())
    }

    fn present_pending(&mut self, pending: &PendingApplication) -> Result<()> {
        if pending.kind != PendingApplicationKind::Chat {
            bail!("expected encrypted chat application")
        }
        let payload: IncomingChatApplication = serde_json::from_slice(&pending.plaintext)
            .context("decrypted application payload is invalid")?;
        match payload {
            IncomingChatApplication::Current(ChatApplicationPayload::Message {
                version,
                id,
                text,
                sent_at,
                attachment,
                reply_to,
                thread_root,
            }) => {
                if version != CHAT_APPLICATION_VERSION {
                    bail!("unsupported encrypted chat application version")
                }
                self.present_chat_message(
                    pending,
                    id,
                    text,
                    sent_at,
                    attachment,
                    reply_to,
                    thread_root,
                )
            }
            IncomingChatApplication::Current(ChatApplicationPayload::Receipt {
                version,
                receipt_id,
                kind,
                message_ids,
                sent_at: _,
            }) => {
                if version != CHAT_APPLICATION_VERSION || receipt_id.is_nil() {
                    bail!("invalid encrypted receipt version or id")
                }
                if pending.sender_handle == self.profile.handle {
                    return Ok(());
                }
                let updates =
                    self.vault_mut()?
                        .apply_receipt(pending.conversation_id, kind, &message_ids)?;
                self.apply_receipt_updates(pending.conversation_id, &updates);
                Ok(())
            }
            IncomingChatApplication::Legacy(payload) => self.present_chat_message(
                pending,
                payload.id,
                payload.text,
                payload.sent_at,
                payload.attachment,
                None,
                None,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn present_chat_message(
        &mut self,
        pending: &PendingApplication,
        id: Uuid,
        text: String,
        sent_at: DateTime<Utc>,
        attachment: Option<AttachmentMetadata>,
        reply_to: Option<Uuid>,
        thread_root: Option<Uuid>,
    ) -> Result<()> {
        if id.is_nil() || reply_to == Some(id) || thread_root == Some(id) {
            bail!("encrypted chat message contains invalid references")
        }
        if text.len() > 64 * 1024 {
            bail!("decrypted chat message exceeds the size limit")
        }
        if let Some(attachment) = &attachment {
            mutte_store::attachment::validate_metadata(attachment)?;
        }
        let index = self.ensure_chat(pending.conversation_id, &pending.sender_handle)?;
        let mine = pending.sender_handle == self.profile.handle;
        let author = if mine {
            "You · another device".into()
        } else {
            format!("@{}", pending.sender_handle)
        };
        let visible = self
            .visible_conversation
            .filter(|visible| visible.conversation_id == pending.conversation_id)
            .is_some_and(|visible| match visible.thread_root {
                Some(root) => id == root || thread_root == Some(root),
                None => thread_root.is_none(),
            });
        let unread = !mine && !visible;
        let peer_handle = self.conversations[index].handle.clone();
        let current_unread = self.conversations[index].unread;
        let inserted = self.vault_mut()?.store_inbound(
            VaultConversation {
                id: pending.conversation_id,
                peer_handle,
                unread: current_unread,
            },
            VaultMessage {
                id,
                conversation_id: pending.conversation_id,
                author: author.clone(),
                text: text.clone(),
                mine,
                sent_at,
                delivery: DeliveryState::Received,
                attachment: attachment.clone().map(|metadata| VaultAttachment {
                    metadata,
                    local_path: None,
                    download_requested: false,
                }),
                reply_to,
                thread_root,
                locally_read: !unread,
            },
            unread,
        )?;
        if !inserted {
            return Ok(());
        }
        self.conversations[index].messages.push(MessageSnapshot {
            id,
            author,
            text,
            mine,
            timestamp: sent_at.with_timezone(&Local),
            delivery: DeliveryState::Received,
            attachment: attachment.map(|metadata| VaultAttachment {
                metadata,
                local_path: None,
                download_requested: false,
            }),
            reply_to,
            thread_root,
            locally_read: !unread,
        });
        if unread {
            self.conversations[index].unread = self.conversations[index].unread.saturating_add(1);
        }
        self.events.push_back(ClientEvent::MessageReceived {
            conversation_id: pending.conversation_id,
            message_id: id,
        });
        Ok(())
    }

    fn apply_receipt_updates(&mut self, conversation_id: Uuid, updates: &[(Uuid, DeliveryState)]) {
        let Some(index) = self.chat_index(conversation_id) else {
            return;
        };
        for (message_id, delivery) in updates {
            if let Some(message) = self.conversations[index]
                .messages
                .iter_mut()
                .find(|message| message.id == *message_id)
            {
                message.delivery = *delivery;
                self.events.push_back(ClientEvent::DeliveryChanged {
                    conversation_id,
                    message_id: *message_id,
                });
            }
        }
    }

    fn ensure_chat(&mut self, conversation_id: Uuid, sender_handle: &str) -> Result<usize> {
        if let Some(index) = self
            .conversations
            .iter()
            .position(|chat| chat.conversation_id == Some(conversation_id))
        {
            if self.conversations[index].handle == UNRESOLVED_PEER_HANDLE
                && sender_handle != self.profile.handle
            {
                let unread = self.conversations[index].unread;
                self.vault_mut()?.upsert_conversation(VaultConversation {
                    id: conversation_id,
                    peer_handle: sender_handle.into(),
                    unread,
                })?;
                self.conversations[index].handle = sender_handle.into();
                self.conversations[index].name = format!("@{sender_handle}");
            }
            return Ok(index);
        }
        let peer_handle = if sender_handle == self.profile.handle {
            UNRESOLVED_PEER_HANDLE
        } else {
            sender_handle
        };
        self.vault_mut()?.upsert_conversation(VaultConversation {
            id: conversation_id,
            peer_handle: peer_handle.into(),
            unread: 0,
        })?;
        self.conversations.push(ConversationSnapshot {
            conversation_id: Some(conversation_id),
            name: format!("@{peer_handle}"),
            handle: peer_handle.into(),
            status: "encrypted · MLS 1.0".into(),
            unread: 0,
            verification: VerificationState::Unverified,
            messages: Vec::new(),
            active_thread: None,
            scroll_back: 0,
        });
        Ok(self.conversations.len() - 1)
    }

    fn chat_index(&self, conversation_id: Uuid) -> Option<usize> {
        self.conversations
            .iter()
            .position(|chat| chat.conversation_id == Some(conversation_id))
    }

    fn resolve_message_prefix(&self, prefix: &str) -> Result<&MessageSnapshot> {
        let prefix = prefix.trim().trim_start_matches('#').to_ascii_lowercase();
        if prefix.len() < 4 || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("message id prefix must contain at least four hexadecimal characters")
        }
        let matches = self.conversations[self.selected]
            .messages
            .iter()
            .filter(|message| message.id.simple().to_string().starts_with(&prefix))
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [message] => Ok(message),
            [] => bail!("no message matches that id prefix in this conversation"),
            _ => bail!("message id prefix is ambiguous"),
        }
    }

    fn verification_state(&self, conversation_id: Uuid, fingerprint: &str) -> VerificationState {
        match self
            .vault
            .as_ref()
            .and_then(|vault| vault.verification(conversation_id))
        {
            Some(record) if record.fingerprint == fingerprint => VerificationState::Verified,
            Some(_) => VerificationState::Changed,
            None => VerificationState::Unverified,
        }
    }

    fn refresh_chat_verification(&mut self, index: usize, device: &Device) -> VerificationState {
        let Some(conversation_id) = self.conversations[index].conversation_id else {
            self.conversations[index].verification = VerificationState::NotApplicable;
            return VerificationState::NotApplicable;
        };
        let state = match device.conversation_safety_code(conversation_id) {
            Ok(code) => self.verification_state(conversation_id, &code.fingerprint()),
            Err(_) => VerificationState::Unavailable,
        };
        self.conversations[index].verification = state;
        state
    }

    fn refresh_verification_states(&mut self, device: &Device) {
        let mut changed = false;
        for index in 0..self.conversations.len() {
            changed |= self.refresh_chat_verification(index, device) == VerificationState::Changed;
        }
        if changed {
            self.notice = "⚠ verified device keys changed; queued sends are paused".into();
        }
    }

    fn ensure_sending_allowed(&mut self, index: usize, device: &Device) -> Result<()> {
        if let Some(conversation_id) = self.conversations[index].conversation_id
            && self
                .vault
                .as_ref()
                .is_some_and(|vault| vault.has_pending_control(conversation_id))
        {
            bail!("membership update is queued; wait for its encrypted delivery")
        }
        match self.refresh_chat_verification(index, device) {
            VerificationState::Changed => {
                bail!("verified device keys changed; run /verify and compare the new code")
            }
            VerificationState::Unavailable | VerificationState::NotApplicable => {
                bail!("authenticated MLS device keys are unavailable for this chat")
            }
            VerificationState::Unverified | VerificationState::Verified => Ok(()),
        }
    }

    fn ensure_conversation_sending_allowed(
        &mut self,
        conversation_id: Uuid,
        device: &Device,
    ) -> Result<()> {
        let index = self
            .chat_index(conversation_id)
            .context("queued message belongs to an unknown conversation")?;
        self.ensure_sending_allowed(index, device)
    }

    fn show_verification(&mut self, device: &Device) -> Result<()> {
        let conversation_id = self.conversations[self.selected]
            .conversation_id
            .context("open an encrypted chat before running /verify")?;
        let code = device.conversation_safety_code(conversation_id)?;
        let fingerprint = code.fingerprint();
        let state = self.verification_state(conversation_id, &fingerprint);
        self.conversations[self.selected].verification = state;
        self.verification_panel = Some(VerificationPanel {
            conversation_id,
            peer_handle: self.conversations[self.selected].handle.clone(),
            fingerprint,
            member_count: code.member_devices().len(),
            state,
        });
        self.notice = match state {
            VerificationState::Verified => "safety code is verified".into(),
            VerificationState::Changed => {
                "⚠ device keys changed; compare the new safety code".into()
            }
            _ => "compare this safety code through another trusted channel".into(),
        };
        Ok(())
    }

    fn confirm_verification(&mut self, device: &Device) -> Result<()> {
        let (conversation_id, expected) = self
            .verification_panel
            .as_ref()
            .map(|panel| (panel.conversation_id, panel.fingerprint.clone()))
            .context("open /verify before confirming")?;
        let code: ConversationSafetyCode = device.conversation_safety_code(conversation_id)?;
        let fingerprint = code.fingerprint();
        if fingerprint != expected {
            if let Some(panel) = &mut self.verification_panel {
                panel.fingerprint = fingerprint;
                panel.member_count = code.member_devices().len();
                panel.state = VerificationState::Changed;
            }
            if let Some(index) = self.chat_index(conversation_id) {
                self.conversations[index].verification = VerificationState::Changed;
            }
            bail!("device keys changed while the code was open; compare the refreshed code")
        }
        self.vault_mut()?
            .verify_conversation(conversation_id, &fingerprint)?;
        if let Some(index) = self.chat_index(conversation_id) {
            self.conversations[index].verification = VerificationState::Verified;
        }
        if let Some(panel) = &mut self.verification_panel {
            panel.state = VerificationState::Verified;
        }
        self.notice = "✓ safety code marked as verified on this device".into();
        Ok(())
    }

    fn mark_selected_read(&mut self, device: Option<&Device>) -> Result<()> {
        let Some(conversation_id) = self.conversations[self.selected].conversation_id else {
            return Ok(());
        };
        let scope = self.conversations[self.selected]
            .active_thread
            .map_or(ReadScope::Main, ReadScope::Thread);
        let message_ids = self.vault_mut()?.mark_read(conversation_id, scope)?;
        if message_ids.is_empty() {
            return Ok(());
        }
        let chat = &mut self.conversations[self.selected];
        for message in &mut chat.messages {
            if message_ids.contains(&message.id) {
                message.locally_read = true;
            }
        }
        chat.unread = chat
            .unread
            .saturating_sub(u16::try_from(message_ids.len()).unwrap_or(u16::MAX));
        if let Some(device) = device {
            self.queue_pending_receipts(device)?;
        }
        Ok(())
    }

    fn mark_message_sent(&mut self, conversation_id: Uuid, message_id: Uuid) {
        let mut changed = false;
        for chat in &mut self.conversations {
            if chat.conversation_id != Some(conversation_id) {
                continue;
            }
            if let Some(message) = chat
                .messages
                .iter_mut()
                .find(|message| message.id == message_id)
            {
                message.delivery = DeliveryState::Sent;
                changed = true;
                break;
            }
        }
        if changed {
            self.events.push_back(ClientEvent::DeliveryChanged {
                conversation_id,
                message_id,
            });
        }
    }

    fn mark_messages_cancelled(&mut self, conversation_id: Uuid, message_ids: &[Uuid]) {
        for chat in &mut self.conversations {
            if chat.conversation_id != Some(conversation_id) {
                continue;
            }
            for message in &mut chat.messages {
                if message_ids.contains(&message.id) {
                    message.delivery = DeliveryState::Cancelled;
                }
            }
        }
    }

    fn vault_mut(&mut self) -> Result<&mut Vault> {
        self.vault
            .as_mut()
            .context("encrypted vault is unavailable")
    }

    pub fn take_events(&mut self) -> Vec<ClientEvent> {
        self.events.drain(..).collect()
    }

    /// Returns the device-local preference used when the shared engine queues
    /// encrypted read receipts. Native frontends expose the same setting
    /// without reaching into the encrypted vault themselves.
    pub fn read_receipts_enabled(&self) -> bool {
        if self.demo {
            return self.demo_read_receipts;
        }
        self.vault
            .as_ref()
            .is_some_and(|vault| vault.settings().send_read_receipts)
    }
}

fn resolve_account_device(devices: &[AccountDevice], prefix: &str) -> Result<AccountDevice> {
    let normalized = prefix.replace('-', "").to_ascii_lowercase();
    if normalized.len() < 8 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("use at least 8 hexadecimal characters from /devices")
    }
    let matches = devices
        .iter()
        .filter(|device| {
            device
                .device_id
                .simple()
                .to_string()
                .starts_with(&normalized)
        })
        .collect::<Vec<_>>();
    let [target] = matches.as_slice() else {
        if matches.is_empty() {
            bail!("no account device matches that prefix")
        }
        bail!("device prefix is ambiguous; enter more characters")
    };
    Ok((*target).clone())
}

fn short_device_id(device_id: Uuid) -> String {
    device_id.simple().to_string()[..8].to_ascii_uppercase()
}

fn short_id(id: Uuid) -> String {
    id.simple().to_string()[..8].to_ascii_uppercase()
}

fn elected_account_committer(
    member_devices: &[Uuid],
    active_account_devices: &std::collections::HashSet<Uuid>,
) -> Option<Uuid> {
    member_devices
        .iter()
        .copied()
        .filter(|device_id| active_account_devices.contains(device_id))
        .min_by(|left, right| left.as_bytes().cmp(right.as_bytes()))
}

fn normalize_synced_handle(value: &str) -> Result<String> {
    let handle = value.trim().to_ascii_lowercase();
    if !(3..=24).contains(&handle.len())
        || !handle.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
    {
        bail!("encrypted device sync contains an invalid peer handle")
    }
    Ok(handle)
}

fn mentions_handle(text: &str, handle: &str) -> bool {
    if handle.is_empty() {
        return false;
    }
    text.match_indices('@').any(|(index, _)| {
        if text[..index]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '@')
        {
            return false;
        }
        let token: String = text[index + 1..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        token.eq_ignore_ascii_case(handle)
    })
}

fn normalize_direct_handle(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let without_optional_prefix = trimmed.strip_prefix('@').unwrap_or(trimmed);
    let handle = without_optional_prefix.to_ascii_lowercase();
    if !(3..=24).contains(&handle.len())
        || !handle.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
    {
        bail!("handle must be 3–24 lowercase letters, numbers, or underscores")
    }
    Ok(handle)
}

fn parse_reaction(message: &MessageSnapshot) -> Option<(&str, bool)> {
    message.reply_to?;
    if message.text.contains(['\r', '\n']) {
        return None;
    }
    let (emoji, active) = message
        .text
        .strip_prefix("Reaction: ")
        .map(|emoji| (emoji, true))
        .or_else(|| {
            message
                .text
                .strip_prefix("Reaction removed: ")
                .map(|emoji| (emoji, false))
        })?;
    validate_reaction(emoji).ok()?;
    Some((emoji, active))
}

fn validate_reaction(emoji: &str) -> Result<()> {
    if emoji.is_empty()
        || emoji.len() > 64
        || emoji.chars().count() > 12
        || emoji
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || emoji
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        bail!("choose one emoji reaction")
    }
    Ok(())
}

pub fn is_reaction_message(message: &MessageSnapshot) -> bool {
    parse_reaction(message).is_some()
}

pub fn is_reaction_for_known_message(
    messages: &[MessageSnapshot],
    message: &MessageSnapshot,
) -> bool {
    is_reaction_message(message)
        && message.reply_to.is_some_and(|target_id| {
            messages
                .iter()
                .any(|target| target.id == target_id && !is_reaction_message(target))
        })
}

pub fn reactions_for(messages: &[MessageSnapshot], target_id: Uuid) -> Vec<MessageReaction> {
    let mut events = messages
        .iter()
        .filter_map(|message| {
            (message.reply_to == Some(target_id)
                && !(message.mine && message.delivery == DeliveryState::Cancelled))
                .then(|| {
                    parse_reaction(message)
                        .map(|(emoji, active)| (message, emoji.to_owned(), active))
                })
                .flatten()
        })
        .collect::<Vec<_>>();
    events.sort_by_key(|(message, _, _)| (message.timestamp, message.id));
    let mut state = std::collections::HashMap::<(bool, String), bool>::new();
    for (message, emoji, active) in events {
        state.insert((message.mine, emoji), active);
    }
    let mut totals = std::collections::HashMap::<String, (u8, bool)>::new();
    for ((mine, emoji), active) in state {
        if active {
            let total = totals.entry(emoji).or_default();
            total.0 = total.0.saturating_add(1);
            total.1 |= mine;
        }
    }
    let preferred = ["👍", "❤️", "😂", "😮", "😢", "👎"];
    let mut reactions = totals
        .into_iter()
        .map(|(emoji, (count, mine))| MessageReaction { emoji, count, mine })
        .collect::<Vec<_>>();
    reactions.sort_by(|left, right| {
        let rank = |emoji: &str| {
            preferred
                .iter()
                .position(|item| *item == emoji)
                .unwrap_or(usize::MAX)
        };
        rank(&left.emoji)
            .cmp(&rank(&right.emoji))
            .then_with(|| left.emoji.cmp(&right.emoji))
    });
    reactions
}

fn attachment_message_payload(transfer: &OutboundAttachment) -> ChatApplicationPayload {
    ChatApplicationPayload::Message {
        version: CHAT_APPLICATION_VERSION,
        id: transfer.message_id,
        text: format!("📎 {}", transfer.metadata.filename),
        sent_at: transfer.created_at,
        attachment: Some(transfer.metadata.clone()),
        reply_to: transfer.reply_to,
        thread_root: transfer.thread_root,
    }
}

fn attachment_chunk_bytes(total_bytes: u64, index: u32) -> u64 {
    total_bytes
        .saturating_sub(index as u64 * mutte_protocol::ATTACHMENT_CHUNK_BYTES as u64)
        .min(mutte_protocol::ATTACHMENT_CHUNK_BYTES as u64)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use mutte_protocol::HISTORY_SYNC_VERSION;
    use url::Url;

    use super::*;

    #[test]
    fn mentions_match_exact_handles_without_emails_or_longer_names() {
        for text in ["@sam", "Hello (@SAM)!", "\n@sam: welcome"] {
            assert!(mentions_handle(text, "sam"), "{text}");
        }
        for text in ["sam", "user@sam", "@@sam", "@sam_other", "@samuel", "@samé"] {
            assert!(!mentions_handle(text, "sam"), "{text}");
        }
        assert!(!mentions_handle("@", ""));
    }

    #[tokio::test]
    async fn personal_attention_commands_are_offline_durable_and_do_not_mark_messages_read() {
        let root = std::env::temp_dir().join(format!("mutte-engine-attention-{}", Uuid::new_v4()));
        let id = Uuid::new_v4();
        let message_id = Uuid::new_v4();
        let mut vault = Vault::open_at(root.join("vault.json"), &[31; 32]).unwrap();
        vault
            .store_inbound(
                VaultConversation {
                    id,
                    peer_handle: "alice".into(),
                    unread: 0,
                },
                stored_message(message_id, id, "Meet here", false, DeliveryState::Received),
                true,
            )
            .unwrap();
        let mut app = MutteClient::connected(profile("sam"), vault).unwrap();
        app.execute(
            None,
            ClientCommand::SetThreadFollowed {
                conversation_id: id,
                thread_root: message_id,
                followed: true,
            },
        )
        .await
        .unwrap();
        app.execute(
            None,
            ClientCommand::SetConversationQuiet {
                conversation_id: id,
                quiet: true,
            },
        )
        .await
        .unwrap();
        app.execute(
            None,
            ClientCommand::SetConversationQuiet {
                conversation_id: id,
                quiet: false,
            },
        )
        .await
        .unwrap();
        let preferences = app.conversation_preferences(id).unwrap();
        assert_eq!(
            preferences.notification_mode,
            mutte_store::NotificationMode::Off
        );
        assert!(preferences.followed_threads.contains(&message_id));
        let chat = &app.conversations[app.chat_index(id).unwrap()];
        assert!(!chat.messages[0].locally_read);
        assert_eq!(chat.unread, 1);
        assert!(
            app.execute(
                None,
                ClientCommand::SetThreadFollowed {
                    conversation_id: id,
                    thread_root: Uuid::new_v4(),
                    followed: true,
                }
            )
            .await
            .is_err()
        );
        let reopened = Vault::open_at(root.join("vault.json"), &[31; 32]).unwrap();
        assert_eq!(reopened.conversation_preferences(id).unwrap(), preferences);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn direct_handle_validation_matches_the_relay_and_native_clients() {
        assert_eq!(
            normalize_direct_handle("  @Quiet_Cat  ").unwrap(),
            "quiet_cat"
        );
        assert!(normalize_direct_handle("@@quiet_cat").is_err());
        assert!(normalize_direct_handle("no").is_err());
        assert!(normalize_direct_handle("not/a/handle").is_err());
    }

    #[test]
    fn reaction_fallbacks_aggregate_toggle_and_ignore_cancelled_events() {
        let app = MutteClient::new(profile("nightowl"), true);
        let target = app.conversations[0].messages[0].clone();
        let mut own_add = target.clone();
        own_add.id = Uuid::from_u128(10);
        own_add.mine = true;
        own_add.text = "Reaction: 👍".into();
        own_add.reply_to = Some(target.id);
        own_add.timestamp += chrono::Duration::seconds(1);
        let mut peer_add = own_add.clone();
        peer_add.id = Uuid::from_u128(11);
        peer_add.mine = false;
        peer_add.timestamp += chrono::Duration::seconds(1);
        let mut peer_remove = peer_add.clone();
        peer_remove.id = Uuid::from_u128(12);
        peer_remove.text = "Reaction removed: 👍".into();
        peer_remove.timestamp += chrono::Duration::seconds(1);
        let messages = vec![target.clone(), peer_remove, own_add.clone(), peer_add];

        assert!(is_reaction_message(&own_add));
        assert_eq!(
            reactions_for(&messages, target.id),
            vec![MessageReaction {
                emoji: "👍".into(),
                count: 1,
                mine: true
            }]
        );
        let mut cancelled = own_add;
        cancelled.delivery = DeliveryState::Cancelled;
        assert!(reactions_for(&[target.clone(), cancelled], target.id).is_empty());
        let mut ordinary = target;
        ordinary.text = "I reacted 👍".into();
        ordinary.reply_to = Some(Uuid::new_v4());
        assert!(!is_reaction_message(&ordinary));
        let mut dangling = messages[2].clone();
        dangling.reply_to = Some(Uuid::new_v4());
        assert!(is_reaction_message(&dangling));
        assert!(!is_reaction_for_known_message(&messages, &dangling));
        assert!(validate_reaction("letters").is_err());
        assert!(validate_reaction("❤️").is_ok());
    }

    fn profile(handle: &str) -> Profile {
        Profile {
            id: Uuid::new_v4(),
            handle: handle.into(),
            display_name: handle.into(),
            bio: String::new(),
            status: "quiet".into(),
        }
    }

    fn conversation(root: &Path, name: &str, key: u8) -> (Device, Uuid) {
        let device =
            Device::load_or_create_at(root.join(format!("{name}-device.json")), &[key; 32])
                .unwrap();
        (device, Uuid::new_v4())
    }

    fn stored_message(
        id: Uuid,
        conversation_id: Uuid,
        text: &str,
        mine: bool,
        delivery: DeliveryState,
    ) -> VaultMessage {
        VaultMessage {
            id,
            conversation_id,
            author: if mine { "You".into() } else { "@alice".into() },
            text: text.into(),
            mine,
            sent_at: Utc::now(),
            delivery,
            attachment: None,
            reply_to: None,
            thread_root: None,
            locally_read: mine,
        }
    }

    fn application_envelope(
        conversation_id: Uuid,
        sender: &Device,
        sender_handle: &str,
        recipients: Vec<Uuid>,
        ciphertext: String,
    ) -> CiphertextEnvelope {
        CiphertextEnvelope {
            id: Uuid::new_v4(),
            conversation_id,
            sender_device_id: sender.id(),
            sender_handle: sender_handle.into(),
            recipients,
            kind: EnvelopeKind::Application,
            mutation_id: None,
            ciphertext,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn connected_engine_restores_encrypted_history_without_tui_state() {
        let root = std::env::temp_dir().join(format!("mutte-client-restore-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("vault.json");
        let conversation_id = Uuid::new_v4();
        let message_id = Uuid::new_v4();
        let mut vault = Vault::open_at(&path, &[11; 32]).unwrap();
        vault
            .store_inbound(
                VaultConversation {
                    id: conversation_id,
                    peer_handle: "alice".into(),
                    unread: 0,
                },
                stored_message(
                    message_id,
                    conversation_id,
                    "durable ciphertext",
                    false,
                    DeliveryState::Received,
                ),
                true,
            )
            .unwrap();
        drop(vault);

        let engine =
            MutteClient::connected(profile("bob"), Vault::open_at(&path, &[11; 32]).unwrap())
                .unwrap();
        let restored = engine
            .conversations
            .iter()
            .find(|item| item.conversation_id == Some(conversation_id))
            .unwrap();
        assert_eq!(restored.handle, "alice");
        assert_eq!(restored.unread, 1);
        assert_eq!(restored.messages[0].id, message_id);
        assert_eq!(restored.messages[0].delivery, DeliveryState::Received);
        drop(engine);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn typed_commands_and_events_work_without_a_terminal() {
        let mut engine = MutteClient::new(profile("nightowl"), true);
        engine
            .execute(
                None,
                ClientCommand::StartDirect {
                    handle: "mira".into(),
                },
            )
            .await
            .unwrap();
        engine
            .execute(
                None,
                ClientCommand::ExecuteText("hello from headless".into()),
            )
            .await
            .unwrap();
        let chat = engine.conversations.last().unwrap();
        assert_eq!(chat.handle, "mira");
        assert_eq!(chat.messages.last().unwrap().text, "hello from headless");
        assert!(engine.take_events().iter().any(|event| matches!(
            event,
            ClientEvent::StateChanged {
                conversation_id: Some(_)
            }
        )));
        engine
            .execute(None, ClientCommand::ExecuteText("/quit".into()))
            .await
            .unwrap();
        assert!(engine.take_events().contains(&ClientEvent::QuitRequested));
    }

    #[test]
    fn queued_attachment_scope_survives_restart_and_keeps_one_stable_message() {
        let root = std::env::temp_dir().join(format!("mutte-attachment-scope-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let source = root.join("thread file.txt");
        fs::write(&source, b"encrypted thread attachment fixture").unwrap();
        let path = root.join("vault.json");
        let key = [81; 32];
        let conversation_id = Uuid::new_v4();
        let thread_root = Uuid::new_v4();
        let peer = Uuid::new_v4();
        let mut vault = Vault::open_at(&path, &key).unwrap();
        vault
            .store_inbound(
                VaultConversation {
                    id: conversation_id,
                    peer_handle: "alice".into(),
                    unread: 0,
                },
                stored_message(
                    thread_root,
                    conversation_id,
                    "Thread root",
                    false,
                    DeliveryState::Received,
                ),
                true,
            )
            .unwrap();
        let prepared = mutte_store::attachment::prepare(&source).unwrap();
        assert!(
            vault
                .begin_attachment_upload_scoped(
                    conversation_id,
                    prepared.source_path.clone(),
                    prepared.metadata.clone(),
                    vec![peer],
                    Some(Uuid::new_v4()),
                    Some(thread_root)
                )
                .is_err()
        );
        assert!(vault.outbound_attachments().is_empty());
        let attachment_id = vault
            .begin_attachment_upload_scoped(
                conversation_id,
                prepared.source_path.clone(),
                prepared.metadata,
                vec![peer],
                Some(thread_root),
                Some(thread_root),
            )
            .unwrap();
        let transfer = vault.outbound_attachments().pop().unwrap();
        let message_id = transfer.message_id;
        // Pre-upgrade journals omit both fields; they still decode as main-chat
        // attachments without changing the encrypted vault format/version.
        let mut legacy = serde_json::to_value(&transfer).unwrap();
        legacy.as_object_mut().unwrap().remove("reply_to");
        legacy.as_object_mut().unwrap().remove("thread_root");
        let legacy: OutboundAttachment = serde_json::from_value(legacy).unwrap();
        assert_eq!((legacy.reply_to, legacy.thread_root), (None, None));
        let payload = serde_json::to_value(attachment_message_payload(&transfer)).unwrap();
        assert_eq!(payload["reply_to"], thread_root.to_string());
        assert_eq!(payload["thread_root"], thread_root.to_string());
        assert_eq!(payload["id"], message_id.to_string());
        drop(vault);
        let mut engine =
            MutteClient::connected(profile("bob"), Vault::open_at(&path, &key).unwrap()).unwrap();
        let index = engine.chat_index(conversation_id).unwrap();
        let queued = engine.conversations[index]
            .messages
            .iter()
            .find(|message| message.id == message_id)
            .unwrap();
        assert_eq!(queued.delivery, DeliveryState::Pending);
        assert_eq!(
            (queued.reply_to, queued.thread_root),
            (Some(thread_root), Some(thread_root))
        );
        assert!(engine.attachment_send_pending(
            conversation_id,
            &prepared.source_path,
            Some(thread_root),
            Some(thread_root)
        ));
        let envelope_id = Uuid::new_v4();
        engine
            .vault_mut()
            .unwrap()
            .queue_uploaded_attachment(
                attachment_id,
                CiphertextEnvelope {
                    id: envelope_id,
                    conversation_id,
                    sender_device_id: Uuid::new_v4(),
                    sender_handle: "bob".into(),
                    recipients: vec![peer],
                    kind: EnvelopeKind::Application,
                    mutation_id: None,
                    ciphertext: "synthetic-envelope".into(),
                    created_at: Utc::now(),
                },
            )
            .unwrap();
        engine.reload_chat_history(conversation_id).unwrap();
        let matching = engine.conversations[index]
            .messages
            .iter()
            .filter(|message| message.id == message_id)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        assert_eq!(
            (matching[0].reply_to, matching[0].thread_root),
            (Some(thread_root), Some(thread_root))
        );
        assert!(engine.attachment_send_pending(
            conversation_id,
            &prepared.source_path,
            Some(thread_root),
            Some(thread_root)
        ));
        engine
            .vault_mut()
            .unwrap()
            .complete_outbox(envelope_id)
            .unwrap();
        assert!(!engine.attachment_send_pending(
            conversation_id,
            &prepared.source_path,
            Some(thread_root),
            Some(thread_root)
        ));
        drop(engine);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn ios_poll_wire_crosses_mls_and_replays_from_encrypted_vault() {
        use crate::polls::{PollState, PollWire};
        let root = std::env::temp_dir().join(format!("mutte-poll-mls-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let (alice, conversation_id) = conversation(&root, "alice", 41);
        let bob = Device::load_or_create_at(root.join("bob-device.json"), &[42; 32]).unwrap();
        let bootstrap = alice
            .create_conversation(conversation_id, &[(bob.id(), bob.key_package().unwrap())])
            .unwrap();
        bob.join_conversation(conversation_id, alice.id(), &bootstrap.welcome)
            .unwrap();
        let path = root.join("alice-vault.json");
        let mut vault = Vault::open_at(&path, &[43; 32]).unwrap();
        vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "bob".into(),
                unread: 0,
            })
            .unwrap();
        let session_a = Session {
            access_token: secrecy::SecretString::from("test-token"),
            device_id: alice.id(),
            profile: profile("alice"),
        };
        let session_b = Session {
            access_token: secrecy::SecretString::from("test-token"),
            device_id: bob.id(),
            profile: profile("bob"),
        };
        let api = Client::new(Url::parse("http://127.0.0.1:9/").unwrap()).unwrap();
        let connection_a = Connection {
            api: &api,
            session: &session_a,
            device: &alice,
            open_browser: false,
        };
        let connection_b = Connection {
            api: &api,
            session: &session_b,
            device: &bob,
            open_browser: false,
        };
        let mut sender = MutteClient::connected(session_a.profile.clone(), vault).unwrap();
        let receiver_path = root.join("bob-vault.json");
        let mut receiver = MutteClient::connected(
            session_b.profile.clone(),
            Vault::open_at(&receiver_path, &[44; 32]).unwrap(),
        )
        .unwrap();
        sender
            .execute(
                Some(&connection_a),
                ClientCommand::SendMessage {
                    conversation_id,
                    text: "Discussion root".into(),
                    reply_to: None,
                    thread_root: None,
                },
            )
            .await
            .unwrap();
        let thread = sender.conversations[sender.selected]
            .messages
            .last()
            .unwrap()
            .id;
        // Exact payload produced by the released Swift implementation.
        let ios_wire = "Mutte poll · v1\n{\"kind\":\"create\",\"multiple\":false,\"options\":[\"Friday\",\"Saturday\"],\"question\":\"When?\",\"version\":1}";
        sender
            .execute(
                Some(&connection_a),
                ClientCommand::SendMessage {
                    conversation_id,
                    text: ios_wire.into(),
                    reply_to: Some(thread),
                    thread_root: Some(thread),
                },
            )
            .await
            .unwrap();
        let poll_id = sender.conversations[sender.selected]
            .messages
            .last()
            .unwrap()
            .id;
        let mut a_seen = HashSet::new();
        let mut b_seen = HashSet::new();
        fn deliver(
            sender: &MutteClient,
            receiver: &mut MutteClient,
            device: &Device,
            sender_device: Uuid,
            handle: &str,
            seen: &mut HashSet<Uuid>,
        ) {
            for item in sender.vault.as_ref().unwrap().outbox() {
                if !seen.insert(item.envelope.id) {
                    continue;
                }
                let pending = device
                    .decrypt_application(
                        seen.len() as i64,
                        item.envelope.conversation_id,
                        sender_device,
                        handle,
                        &item.envelope.ciphertext,
                    )
                    .unwrap();
                receiver.present_pending(&pending).unwrap();
            }
        }
        deliver(
            &sender,
            &mut receiver,
            &bob,
            alice.id(),
            "alice",
            &mut a_seen,
        );
        for text in [PollWire::vote(vec![1]).unwrap(), PollWire::close()] {
            receiver
                .execute(
                    Some(&connection_b),
                    ClientCommand::SendMessage {
                        conversation_id,
                        text,
                        reply_to: Some(poll_id),
                        thread_root: Some(thread),
                    },
                )
                .await
                .unwrap();
        }
        deliver(&receiver, &mut sender, &alice, bob.id(), "bob", &mut b_seen);
        let chat = &sender.conversations[sender.chat_index(conversation_id).unwrap()];
        let state = PollState::fold(
            chat.messages.iter().find(|m| m.id == poll_id).unwrap(),
            &chat.messages,
        )
        .unwrap();
        assert!(!state.closed, "peer cannot close a creator's poll");
        assert_eq!(state.voters(1), vec!["@bob"]);
        sender
            .execute(
                Some(&connection_a),
                ClientCommand::SendMessage {
                    conversation_id,
                    text: PollWire::close(),
                    reply_to: Some(poll_id),
                    thread_root: Some(thread),
                },
            )
            .await
            .unwrap();
        deliver(
            &sender,
            &mut receiver,
            &bob,
            alice.id(),
            "alice",
            &mut a_seen,
        );
        drop(receiver);
        let restored = MutteClient::connected(
            session_b.profile.clone(),
            Vault::open_at(&receiver_path, &[44; 32]).unwrap(),
        )
        .unwrap();
        let chat = &restored.conversations[restored.chat_index(conversation_id).unwrap()];
        let state = PollState::fold(
            chat.messages.iter().find(|m| m.id == poll_id).unwrap(),
            &chat.messages,
        )
        .unwrap();
        assert!(state.closed);
        assert_eq!(state.voters(1), vec!["You"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn selected_reply_and_thread_commands_keep_encrypted_metadata_and_offline_outbox() {
        let root = std::env::temp_dir().join(format!("mutte-selected-reply-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let (alice, conversation_id) = conversation(&root, "alice", 41);
        let bob = Device::load_or_create_at(root.join("bob-device.json"), &[42; 32]).unwrap();
        let bootstrap = alice
            .create_conversation(conversation_id, &[(bob.id(), bob.key_package().unwrap())])
            .unwrap();
        bob.join_conversation(conversation_id, alice.id(), &bootstrap.welcome)
            .unwrap();
        let root_id = Uuid::new_v4();
        let path = root.join("alice-vault.json");
        let mut vault = Vault::open_at(&path, &[43; 32]).unwrap();
        vault
            .store_inbound(
                VaultConversation {
                    id: conversation_id,
                    peer_handle: "bob".into(),
                    unread: 0,
                },
                stored_message(
                    root_id,
                    conversation_id,
                    "original message",
                    false,
                    DeliveryState::Received,
                ),
                false,
            )
            .unwrap();
        let own_profile = profile("alice");
        let session = Session {
            access_token: secrecy::SecretString::from("test-token".to_owned()),
            device_id: alice.id(),
            profile: own_profile.clone(),
        };
        // No real account or relay: failed delivery must retain encrypted outbox entries.
        let api = Client::new(Url::parse("http://127.0.0.1:9/").unwrap()).unwrap();
        let connection = Connection {
            api: &api,
            session: &session,
            device: &alice,
            open_browser: false,
        };
        let mut engine = MutteClient::connected(own_profile.clone(), vault).unwrap();
        for thread_root in [None, Some(root_id)] {
            if thread_root.is_some() {
                engine
                    .execute(
                        Some(&connection),
                        ClientCommand::OpenThread {
                            conversation_id,
                            message_id: root_id,
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    engine.conversations[engine.selected].active_thread,
                    Some(root_id)
                );
            }
            engine
                .execute(
                    Some(&connection),
                    ClientCommand::SendMessage {
                        conversation_id,
                        text: "selected-message reply".into(),
                        reply_to: Some(root_id),
                        thread_root,
                    },
                )
                .await
                .unwrap();
            let sent = engine.conversations[engine.selected]
                .messages
                .last()
                .unwrap();
            assert_eq!(sent.reply_to, Some(root_id));
            assert_eq!(sent.thread_root, thread_root);
            assert_eq!(sent.delivery, DeliveryState::Pending);
            assert!(engine.notice.contains("queued"));
        }
        let mut receiver = MutteClient::connected(
            profile("bob"),
            Vault::open_at(root.join("bob-vault.json"), &[44; 32]).unwrap(),
        )
        .unwrap();
        let outbox = engine.vault.as_ref().unwrap().outbox();
        // Opening the thread also queues encrypted delivery/read receipts.
        assert_eq!(
            outbox
                .iter()
                .filter(|item| item.message_id.is_some())
                .count(),
            2
        );
        for (index, item) in outbox.iter().enumerate() {
            let pending = bob
                .decrypt_application(
                    index as i64 + 1,
                    conversation_id,
                    alice.id(),
                    "alice",
                    &item.envelope.ciphertext,
                )
                .unwrap();
            receiver.present_pending(&pending).unwrap();
        }
        let received =
            &receiver.conversations[receiver.chat_index(conversation_id).unwrap()].messages;
        assert_eq!(received.len(), 2);
        assert!(
            received
                .iter()
                .all(|message| message.reply_to == Some(root_id)
                    && message.text == "selected-message reply")
        );
        assert_eq!(
            received
                .iter()
                .filter(|message| message.thread_root == Some(root_id))
                .count(),
            1
        );
        engine
            .execute(
                Some(&connection),
                ClientCommand::CloseThread { conversation_id },
            )
            .await
            .unwrap();
        assert_eq!(engine.conversations[engine.selected].active_thread, None);
        drop(engine);
        let restored =
            MutteClient::connected(own_profile, Vault::open_at(&path, &[43; 32]).unwrap()).unwrap();
        assert_eq!(
            restored
                .vault
                .as_ref()
                .unwrap()
                .outbox()
                .iter()
                .filter(|item| item.message_id.is_some())
                .count(),
            2
        );
        let messages =
            &restored.conversations[restored.chat_index(conversation_id).unwrap()].messages;
        assert_eq!(
            messages
                .iter()
                .filter(|message| message.reply_to == Some(root_id))
                .count(),
            2
        );
        drop(restored);
        drop(receiver);
        drop(alice);
        drop(bob);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn typed_demo_actions_reject_unavailable_and_nested_roots() {
        let mut engine = MutteClient::new(profile("demo"), true);
        let conversation_id = engine.conversations[0].conversation_id.unwrap();
        let root_id = engine.conversations[0].messages[0].id;
        for command in [
            ClientCommand::SendMessage {
                conversation_id,
                text: "reply".into(),
                reply_to: Some(Uuid::new_v4()),
                thread_root: None,
            },
            ClientCommand::OpenThread {
                conversation_id,
                message_id: Uuid::new_v4(),
            },
            ClientCommand::SendMessage {
                conversation_id,
                text: String::new(),
                reply_to: Some(root_id),
                thread_root: None,
            },
            ClientCommand::SendMessage {
                conversation_id,
                text: "a".repeat(64 * 1024 + 1),
                reply_to: Some(root_id),
                thread_root: None,
            },
        ] {
            assert!(engine.execute(None, command).await.is_err());
        }
        engine
            .execute(
                None,
                ClientCommand::SendMessage {
                    conversation_id,
                    text: "thread reply".into(),
                    reply_to: Some(root_id),
                    thread_root: Some(root_id),
                },
            )
            .await
            .unwrap();
        let reply_id = engine.conversations[0].messages.last().unwrap().id;
        assert!(
            engine
                .execute(
                    None,
                    ClientCommand::SendMessage {
                        conversation_id,
                        text: "nested".into(),
                        reply_to: Some(reply_id),
                        thread_root: Some(reply_id)
                    }
                )
                .await
                .is_err()
        );
        engine
            .execute(
                None,
                ClientCommand::OpenThread {
                    conversation_id,
                    message_id: reply_id,
                },
            )
            .await
            .unwrap();
        assert_eq!(engine.conversations[0].active_thread, Some(root_id));
    }

    #[tokio::test]
    async fn typed_start_direct_does_not_make_a_conversation_visible() {
        let root = std::env::temp_dir().join(format!("mutte-client-direct-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let (device, conversation_id) = conversation(&root, "local", 17);
        let message_id = Uuid::new_v4();
        let mut vault = Vault::open_at(root.join("vault.json"), &[18; 32]).unwrap();
        vault
            .store_inbound(
                VaultConversation {
                    id: conversation_id,
                    peer_handle: "alice".into(),
                    unread: 0,
                },
                stored_message(
                    message_id,
                    conversation_id,
                    "still unread",
                    false,
                    DeliveryState::Received,
                ),
                true,
            )
            .unwrap();
        let own_profile = profile("bob");
        let session = Session {
            access_token: secrecy::SecretString::from("test-token".to_owned()),
            device_id: device.id(),
            profile: own_profile.clone(),
        };
        let api = Client::new(Url::parse("http://127.0.0.1:9/").unwrap()).unwrap();
        let connection = Connection {
            api: &api,
            session: &session,
            device: &device,
            open_browser: false,
        };
        let mut engine = MutteClient::connected(own_profile, vault).unwrap();

        engine
            .execute(
                Some(&connection),
                ClientCommand::StartDirect {
                    handle: "@ALICE".into(),
                },
            )
            .await
            .unwrap();

        let chat = &engine.conversations[engine.selected];
        assert_eq!(chat.conversation_id, Some(conversation_id));
        assert_eq!(chat.unread, 1);
        assert!(!chat.messages[0].locally_read);
        assert_eq!(engine.visible_conversation, None);

        // A recovered peer can introduce another independent local history.
        // Both structured and terminal entry must stop before any key claim,
        // selection, read marking, or verification mutation.
        let duplicate_id = Uuid::new_v4();
        engine.ensure_chat(duplicate_id, "ALICE").unwrap();
        let selected = engine.selected;
        let trust_before = engine
            .conversations
            .iter()
            .map(|chat| chat.verification)
            .collect::<Vec<_>>();
        for command in [
            ClientCommand::StartDirect {
                handle: "@ALICE".into(),
            },
            ClientCommand::ExecuteText("/dm alice".into()),
        ] {
            let error = engine
                .execute(Some(&connection), command)
                .await
                .unwrap_err();
            assert!(error.is::<DirectConversationChoiceRequired>());
            assert_eq!(engine.selected, selected);
            assert_eq!(engine.visible_conversation, None);
            assert_eq!(engine.conversations[selected].unread, 1);
            assert!(!engine.conversations[selected].messages[0].locally_read);
            assert_eq!(
                engine
                    .conversations
                    .iter()
                    .map(|chat| chat.verification)
                    .collect::<Vec<_>>(),
                trust_before
            );
        }
        assert_eq!(engine.direct_conversation_index("new_peer").unwrap(), None);

        drop(engine);
        drop(device);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn encrypted_device_sync_replaces_placeholder_peer_metadata() {
        let root = std::env::temp_dir().join(format!("mutte-client-sync-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("vault.json");
        let conversation_id = Uuid::new_v4();
        let mut engine =
            MutteClient::connected(profile("alice"), Vault::open_at(&path, &[12; 32]).unwrap())
                .unwrap();
        let index = engine.ensure_chat(conversation_id, "alice").unwrap();
        assert_eq!(engine.conversations[index].handle, UNRESOLVED_PEER_HANDLE);
        engine
            .present_device_sync(&PendingApplication {
                delivery_id: 1,
                conversation_id,
                sender_device_id: Uuid::new_v4(),
                sender_handle: "alice".into(),
                plaintext: serde_json::to_vec(&DeviceSyncPayload {
                    peer_handle: "bob_1".into(),
                })
                .unwrap(),
                kind: PendingApplicationKind::DeviceSync,
            })
            .unwrap();
        assert_eq!(engine.conversations[index].handle, "bob_1");
        assert!(engine.conversations[index].status.contains("synced"));
        drop(engine);
        let reopened = Vault::open_at(&path, &[12; 32]).unwrap();
        assert_eq!(reopened.conversations()[0].peer_handle, "bob_1");
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn mls_delivery_and_read_receipts_advance_headless_snapshot() {
        check_receipt_progression(true, false).await;
    }

    #[tokio::test]
    async fn immediate_delivery_does_not_bypass_disabled_read_receipts() {
        check_receipt_progression(false, false).await;
    }

    #[tokio::test]
    async fn rejected_receipt_retries_with_same_id_after_restart() {
        check_receipt_progression(true, true).await;
    }

    #[tokio::test]
    async fn expired_download_does_not_block_another_requested_file() {
        check_download_failure_isolation(false, false, false).await;
    }

    #[tokio::test]
    async fn cancelling_stalled_upload_removes_retry_journal_without_sending() {
        check_stalled_transfer_cancellation(true, false, false).await;
    }

    #[tokio::test]
    async fn cancelling_stalled_download_clears_request_and_partial_file() {
        check_stalled_transfer_cancellation(false, false, false).await;
    }

    #[tokio::test]
    async fn automatically_resumed_upload_can_be_interrupted_by_exact_id() {
        check_stalled_transfer_cancellation(true, true, false).await;
    }

    #[tokio::test]
    async fn automatically_resumed_download_can_be_interrupted_by_exact_id() {
        check_stalled_transfer_cancellation(false, true, false).await;
    }

    #[tokio::test]
    async fn queued_upload_cancels_while_another_upload_is_stalled() {
        check_stalled_transfer_cancellation(true, true, true).await;
    }

    #[tokio::test]
    async fn queued_download_cancels_while_another_download_is_stalled() {
        check_stalled_transfer_cancellation(false, true, true).await;
    }

    async fn check_stalled_transfer_cancellation(upload: bool, automatic: bool, queued: bool) {
        let root = std::env::temp_dir().join(format!("mutte-cancel-network-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("fixture.txt");
        fs::write(
            &source,
            vec![0x42; mutte_protocol::ATTACHMENT_CHUNK_BYTES + 3],
        )
        .unwrap();
        let prepared = mutte_store::attachment::prepare(&source).unwrap();
        let id = prepared.metadata.attachment_id;
        let (device, conversation_id) = conversation(&root, "bob", 49);
        let path = root.join("vault.json");
        let mut vault = Vault::open_at(&path, &[50; 32]).unwrap();
        let conversation = VaultConversation {
            id: conversation_id,
            peer_handle: "alice".into(),
            unread: 0,
        };
        vault.upsert_conversation(conversation.clone()).unwrap();
        if upload {
            vault
                .begin_attachment_upload(
                    conversation_id,
                    prepared.source_path,
                    prepared.metadata.clone(),
                    vec![Uuid::new_v4()],
                )
                .unwrap();
        } else {
            let mut message = stored_message(
                Uuid::new_v4(),
                conversation_id,
                "fixture",
                false,
                DeliveryState::Received,
            );
            message.attachment = Some(VaultAttachment {
                metadata: prepared.metadata.clone(),
                local_path: None,
                download_requested: true,
            });
            vault
                .store_inbound(conversation.clone(), message, true)
                .unwrap();
        }
        let queued_id = if queued {
            let file = mutte_store::attachment::prepare(&source).unwrap();
            let id = file.metadata.attachment_id;
            if upload {
                vault
                    .begin_attachment_upload(
                        conversation_id,
                        file.source_path,
                        file.metadata,
                        vec![Uuid::new_v4()],
                    )
                    .unwrap();
            } else {
                let mut message = stored_message(
                    Uuid::new_v4(),
                    conversation_id,
                    "queued",
                    false,
                    DeliveryState::Received,
                );
                message.attachment = Some(VaultAttachment {
                    metadata: file.metadata,
                    local_path: None,
                    download_requested: true,
                });
                vault
                    .store_inbound(conversation.clone(), message, true)
                    .unwrap();
            }
            Some(id)
        } else {
            None
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = Client::new(
            Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap(),
        )
        .unwrap();
        let (started, accepted) = tokio::sync::oneshot::channel();
        let sparse_upload = upload && automatic && !queued;
        let relay = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut socket, _) = listener.accept().await.unwrap();
            if sparse_upload {
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).await.unwrap();
                    headers.push(byte[0]);
                    assert!(headers.len() < 16384);
                }
                let headers = String::from_utf8(headers).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                socket.read_exact(&mut body).await.unwrap();
                let request: AttachmentStart = serde_json::from_slice(&body).unwrap();
                assert_eq!(request.attachment_id, id);
                // The final three-byte chunk already exists; chunk zero does not.
                let body = serde_json::json!({ "attachment_id": id, "uploaded_chunks": [1], "complete": false }).to_string();
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                drop(socket);
                let (_chunk_socket, _) = listener.accept().await.unwrap();
                started.send(()).unwrap();
                std::future::pending::<()>().await;
            } else {
                started.send(()).unwrap();
                std::future::pending::<()>().await;
            }
        });
        let session = Session {
            access_token: secrecy::SecretString::from("test-token"),
            device_id: device.id(),
            profile: profile("bob"),
        };
        let connection = Connection {
            api: &api,
            session: &session,
            device: &device,
            open_browser: false,
        };
        let paths = ClientPaths {
            downloads_directory: Some(root.join("Downloads")),
        };
        if !upload {
            let mut partial = mutte_store::attachment::AttachmentDownload::resume_at(
                paths.downloads_directory.as_ref().unwrap(),
                &prepared.metadata,
            )
            .unwrap();
            let first =
                mutte_store::attachment::encrypt_chunk(&source, &prepared.metadata, 0).unwrap();
            partial.write_chunk(0, &first).unwrap();
            drop(partial);
            assert!(
                paths
                    .downloads_directory
                    .as_ref()
                    .unwrap()
                    .join(format!(".{id}.part"))
                    .exists()
            );
        }
        let mut engine =
            MutteClient::connected_with_paths(profile("bob"), vault, paths.clone()).unwrap();
        let control = std::sync::Arc::new(crate::AttachmentCancellation::default());
        if !automatic {
            engine.attachment_cancellation = Some(control.clone());
        }
        let active = engine.active_attachment_transfers();
        let finished = std::sync::atomic::AtomicBool::new(false);
        let run = async {
            let result = async {
                if automatic {
                    if upload {
                        engine
                            .resume_attachment_uploads(&connection)
                            .await
                            .map(|_| ())
                    } else {
                        engine
                            .resume_attachment_downloads(&connection)
                            .await
                            .map(|_| ())
                    }
                } else if upload {
                    engine.resume_attachment_upload(&connection, id).await
                } else {
                    let item = engine
                        .vault
                        .as_ref()
                        .unwrap()
                        .pending_attachment_downloads()[0]
                        .clone();
                    engine.resume_attachment_download(&connection, &item).await
                }
            }
            .await;
            finished.store(true, std::sync::atomic::Ordering::SeqCst);
            result
        };
        let cancel = async {
            accepted.await.unwrap();
            let progress = active.progress();
            assert_eq!(
                progress.len(),
                1,
                "queued files are not reported as actively transferring"
            );
            assert_eq!(progress[0].attachment_id, id);
            assert_eq!(progress[0].explicit, !automatic);
            assert_eq!(progress[0].total_bytes, prepared.metadata.plaintext_size);
            assert_eq!(
                progress[0].completed_bytes,
                if sparse_upload {
                    3
                } else if upload {
                    0
                } else {
                    mutte_protocol::ATTACHMENT_CHUNK_BYTES as u64
                }
            );
            if automatic {
                let direction = if upload {
                    crate::AttachmentDirection::Upload
                } else {
                    crate::AttachmentDirection::Download
                };
                assert!(!active.cancel(Uuid::new_v4(), direction));
                if let Some(queued_id) = queued_id {
                    assert!(active.cancel(queued_id, direction));
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                    assert!(
                        !finished.load(std::sync::atomic::Ordering::SeqCst),
                        "cancelling the queue must not cancel the first transfer"
                    );
                }
                assert!(active.cancel(id, direction));
            } else {
                assert!(control.cancel());
            }
        };
        let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(run, cancel)
        })
        .await
        .unwrap();
        result.unwrap();
        drop(engine);
        let restored = MutteClient::connected_with_paths(
            profile("bob"),
            Vault::open_at(&path, &[50; 32]).unwrap(),
            paths.clone(),
        )
        .unwrap();
        let vault = restored.vault.as_ref().unwrap();
        assert!(vault.outbound_attachments().is_empty());
        assert!(vault.pending_attachment_downloads().is_empty());
        assert!(vault.outbox().is_empty());
        if !upload {
            assert!(
                vault.messages()[0]
                    .attachment
                    .as_ref()
                    .unwrap()
                    .local_path
                    .is_none()
            );
            assert!(!vault.messages()[0].locally_read);
            assert!(
                !paths
                    .downloads_directory
                    .unwrap()
                    .join(format!(".{id}.part"))
                    .exists()
            );
        }
        relay.abort();
        drop(restored);
        drop(device);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn missing_upload_source_does_not_block_a_completed_transfer() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        let root = std::env::temp_dir().join(format!("mutte-upload-isolation-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let (alice, conversation_id) = conversation(&root, "alice", 43);
        let bob = Device::load_or_create_at(root.join("bob-device.json"), &[44; 32]).unwrap();
        alice
            .create_conversation(conversation_id, &[(bob.id(), bob.key_package().unwrap())])
            .unwrap();
        let path = root.join("vault.json");
        let mut vault = Vault::open_at(&path, &[45; 32]).unwrap();
        vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "bob".into(),
                unread: 0,
            })
            .unwrap();
        let mut ids = Vec::new();
        for name in ["missing.txt", "completed.txt"] {
            let source = root.join(name);
            fs::write(&source, name).unwrap();
            let prepared = mutte_store::attachment::prepare(&source).unwrap();
            ids.push(
                vault
                    .begin_attachment_upload(
                        conversation_id,
                        prepared.source_path,
                        prepared.metadata,
                        vec![bob.id()],
                    )
                    .unwrap(),
            );
        }
        fs::remove_file(root.join("missing.txt")).unwrap();
        let complete_id = ids[1];
        let message_id = vault.outbound_attachments()[1].message_id;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = Client::new(
            Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap(),
        )
        .unwrap();
        let relay = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16 * 1024);
            }
            let headers = String::from_utf8(request).unwrap();
            assert_eq!(
                headers.lines().next().unwrap(),
                "POST /v1/attachments HTTP/1.1"
            );
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await.unwrap();
            let start: AttachmentStart = serde_json::from_slice(&body).unwrap();
            assert_eq!(start.attachment_id, complete_id);
            let body = serde_json::json!({ "attachment_id": complete_id, "uploaded_chunks": [0], "complete": true }).to_string();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        });
        let session = Session {
            access_token: secrecy::SecretString::from("test-token"),
            device_id: alice.id(),
            profile: profile("alice"),
        };
        let connection = Connection {
            api: &api,
            session: &session,
            device: &alice,
            open_browser: false,
        };
        let mut engine = MutteClient::connected(profile("alice"), vault).unwrap();
        assert!(engine.resume_attachment_uploads(&connection).await.is_err());
        drop(engine);
        let vault = Vault::open_at(&path, &[45; 32]).unwrap();
        assert_eq!(vault.outbound_attachments().len(), 1);
        assert_eq!(vault.outbound_attachments()[0].attachment_id, ids[0]);
        assert_eq!(vault.outbox().len(), 1);
        assert_eq!(
            vault
                .messages()
                .iter()
                .filter(|message| message.id == message_id)
                .count(),
            1
        );
        assert_eq!(
            vault
                .messages()
                .iter()
                .find(|message| message.id == message_id)
                .unwrap()
                .delivery,
            DeliveryState::Pending
        );
        relay.abort();
        drop(vault);
        drop(alice);
        drop(bob);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn download_authentication_failure_stops_remaining_requests() {
        check_download_failure_isolation(true, false, false).await;
    }

    #[tokio::test]
    async fn cancelling_resumed_download_does_not_cancel_the_next_file() {
        check_download_failure_isolation(false, true, false).await;
    }

    #[tokio::test]
    async fn queued_cancellation_is_persisted_when_first_transfer_loses_authentication() {
        check_download_failure_isolation(true, false, true).await;
    }

    async fn check_download_failure_isolation(
        authentication_failure: bool,
        cancel_first: bool,
        cancel_second: bool,
    ) {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        let root =
            std::env::temp_dir().join(format!("mutte-download-isolation-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let (device, conversation_id) = conversation(&root, "bob", 41);
        let vault_path = root.join("vault.json");
        let downloads = root.join("Downloads");
        let mut vault = Vault::open_at(&vault_path, &[42; 32]).unwrap();
        let mut files = Vec::new();
        for name in ["expired.txt", "available.txt"] {
            let source = root.join(name);
            fs::write(&source, name.as_bytes()).unwrap();
            let prepared = mutte_store::attachment::prepare(&source).unwrap();
            let mut message = stored_message(
                Uuid::new_v4(),
                conversation_id,
                name,
                false,
                DeliveryState::Received,
            );
            message.attachment = Some(VaultAttachment {
                metadata: prepared.metadata.clone(),
                local_path: None,
                download_requested: true,
            });
            vault
                .store_inbound(
                    VaultConversation {
                        id: conversation_id,
                        peer_handle: "alice".into(),
                        unread: 0,
                    },
                    message,
                    true,
                )
                .unwrap();
            files.push(prepared);
        }
        let expired_id = files[0].metadata.attachment_id;
        let available_id = files[1].metadata.attachment_id;
        let ciphertext =
            mutte_store::attachment::encrypt_chunk(&files[1].source_path, &files[1].metadata, 0)
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = Client::new(
            Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap(),
        )
        .unwrap();
        let active = std::sync::Arc::new(crate::ActiveAttachmentTransfers::default());
        let interrupt = active.clone();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = requests.clone();
        let relay = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 16 * 1024);
                }
                let headers = String::from_utf8(request).unwrap();
                let line = headers.lines().next().unwrap();
                let (status, body) = if line
                    == format!("GET /v1/attachments/{expired_id}/chunks/0 HTTP/1.1")
                {
                    captured.lock().unwrap().push(expired_id);
                    if cancel_second {
                        assert!(
                            interrupt.cancel(available_id, crate::AttachmentDirection::Download)
                        );
                    }
                    if cancel_first {
                        assert!(interrupt.cancel(expired_id, crate::AttachmentDirection::Download));
                        continue;
                    }
                    (
                        if authentication_failure {
                            "401 Unauthorized"
                        } else {
                            "410 Gone"
                        },
                        String::new(),
                    )
                } else {
                    assert_eq!(
                        line,
                        format!("GET /v1/attachments/{available_id}/chunks/0 HTTP/1.1")
                    );
                    captured.lock().unwrap().push(available_id);
                    ("200 OK", serde_json::json!({ "attachment_id": available_id, "chunk_index": 0, "ciphertext": ciphertext }).to_string())
                };
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        let session = Session {
            access_token: secrecy::SecretString::from("test-token"),
            device_id: device.id(),
            profile: profile("bob"),
        };
        let connection = Connection {
            api: &api,
            session: &session,
            device: &device,
            open_browser: false,
        };
        let paths = ClientPaths {
            downloads_directory: Some(downloads),
        };
        let mut engine =
            MutteClient::connected_with_paths(profile("bob"), vault, paths.clone()).unwrap();
        engine.active_attachment_transfers = active;
        let result = engine.resume_attachment_downloads(&connection).await;
        if cancel_first {
            result.unwrap();
        } else {
            assert_eq!(
                authentication_required(&result.unwrap_err()),
                authentication_failure
            );
        }
        let expected = if authentication_failure {
            vec![expired_id]
        } else {
            vec![expired_id, available_id]
        };
        assert_eq!(*requests.lock().unwrap(), expected);
        drop(engine);
        let engine = MutteClient::connected_with_paths(
            profile("bob"),
            Vault::open_at(&vault_path, &[42; 32]).unwrap(),
            paths,
        )
        .unwrap();
        let vault = engine.vault.as_ref().unwrap();
        assert_eq!(
            vault.pending_attachment_downloads().len(),
            if authentication_failure {
                if cancel_second { 1 } else { 2 }
            } else if cancel_first {
                0
            } else {
                1
            }
        );
        if !authentication_failure {
            let available = vault.messages()[1].attachment.as_ref().unwrap();
            assert_eq!(
                fs::read(available.local_path.as_ref().unwrap()).unwrap(),
                b"available.txt"
            );
            assert!(!available.download_requested);
            assert!(!vault.messages()[1].locally_read);
        }
        drop(engine);
        drop(device);
        relay.abort();
        fs::remove_dir_all(root).unwrap();
    }

    async fn check_receipt_progression(read_receipts: bool, reject_once: bool) {
        let root = std::env::temp_dir().join(format!("mutte-client-receipts-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let (alice, conversation_id) = conversation(&root, "alice", 21);
        let bob = Device::load_or_create_at(root.join("bob-device.json"), &[22; 32]).unwrap();
        let bootstrap = alice
            .create_conversation(conversation_id, &[(bob.id(), bob.key_package().unwrap())])
            .unwrap();
        bob.join_conversation(conversation_id, alice.id(), &bootstrap.welcome)
            .unwrap();
        let message_id = Uuid::new_v4();
        let payload = ChatApplicationPayload::Message {
            version: CHAT_APPLICATION_VERSION,
            id: message_id,
            text: "receipt progression".into(),
            sent_at: Utc::now(),
            attachment: None,
            reply_to: None,
            thread_root: None,
        };
        let envelope = application_envelope(
            conversation_id,
            &alice,
            "alice",
            vec![bob.id()],
            alice
                .encrypt_application(conversation_id, &serde_json::to_vec(&payload).unwrap())
                .unwrap(),
        );
        let mut alice_vault = Vault::open_at(root.join("alice-vault.json"), &[23; 32]).unwrap();
        alice_vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "bob".into(),
                unread: 0,
            })
            .unwrap();
        alice_vault
            .queue_message(
                stored_message(
                    message_id,
                    conversation_id,
                    "receipt progression",
                    true,
                    DeliveryState::Sent,
                ),
                envelope.clone(),
            )
            .unwrap();
        alice_vault.complete_outbox(envelope.id).unwrap();
        let mut bob_vault = Vault::open_at(root.join("bob-vault.json"), &[24; 32]).unwrap();
        bob_vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "alice".into(),
                unread: 0,
            })
            .unwrap();
        let mut alice_engine = MutteClient::connected(profile("alice"), alice_vault).unwrap();
        let mut bob_engine = MutteClient::connected(profile("bob"), bob_vault).unwrap();

        let (api, sent, relay) = receipt_test_relay(
            vec![MailboxMessage {
                delivery_id: 10,
                envelope: envelope.clone(),
            }],
            reject_once,
        )
        .await;
        let session = Session {
            access_token: secrecy::SecretString::from("test-token"),
            device_id: bob.id(),
            profile: profile("bob"),
        };
        let connection = Connection {
            api: &api,
            session: &session,
            device: &bob,
            open_browser: false,
        };
        bob_engine.synchronize(&connection).await.unwrap();
        if reject_once {
            assert!(sent.lock().unwrap().is_empty());
            let queued = bob_engine.vault.as_ref().unwrap().outbox();
            assert_eq!(queued.len(), 1);
            let receipt_id = queued[0].envelope.id;
            drop(bob_engine);
            bob_engine = MutteClient::connected(
                profile("bob"),
                Vault::open_at(root.join("bob-vault.json"), &[24; 32]).unwrap(),
            )
            .unwrap();
            bob_engine.synchronize(&connection).await.unwrap();
            assert_eq!(sent.lock().unwrap()[0].id, receipt_id);
            assert_eq!(
                bob_engine.conversations[bob_engine.chat_index(conversation_id).unwrap()]
                    .messages
                    .len(),
                1
            );
        }
        let delivered = sent.lock().unwrap().clone();
        assert_eq!(delivered.len(), 1);
        assert!(
            bob_engine.vault.as_ref().unwrap().outbox().is_empty(),
            "the receipt must reach the relay in the receiving sync, without another poll"
        );
        assert!(
            !bob_engine.conversations[bob_engine.chat_index(conversation_id).unwrap()].messages[0]
                .locally_read
        );
        for (offset, item) in delivered.iter().enumerate() {
            let receipt = alice
                .decrypt_application(
                    20 + offset as i64,
                    conversation_id,
                    bob.id(),
                    "bob",
                    &item.ciphertext,
                )
                .unwrap();
            alice_engine.present_pending(&receipt).unwrap();
        }
        let alice_index = alice_engine.chat_index(conversation_id).unwrap();
        assert_eq!(
            alice_engine.conversations[alice_index].messages[0].delivery,
            DeliveryState::Delivered
        );

        bob_engine
            .vault_mut()
            .unwrap()
            .set_read_receipts(read_receipts)
            .unwrap();
        bob_engine
            .execute(
                Some(&connection),
                ClientCommand::SetVisibleConversation {
                    conversation_id,
                    thread_root: None,
                },
            )
            .await
            .unwrap();
        let read = sent.lock().unwrap().clone();
        if !read_receipts {
            assert_eq!(
                read.len(),
                1,
                "visibility must not send a disabled read receipt"
            );
            assert!(bob_engine.vault.as_ref().unwrap().outbox().is_empty());
            drop(alice_engine);
            drop(bob_engine);
            drop(alice);
            drop(bob);
            relay.abort();
            fs::remove_dir_all(root).unwrap();
            return;
        }
        assert_eq!(
            read.len(),
            2,
            "read receipt must flush when the current scope becomes visible"
        );
        let receipt = alice
            .decrypt_application(30, conversation_id, bob.id(), "bob", &read[1].ciphertext)
            .unwrap();
        alice_engine.present_pending(&receipt).unwrap();
        assert_eq!(
            alice_engine.conversations[alice_index].messages[0].delivery,
            DeliveryState::Read
        );
        assert!(alice_engine.take_events().iter().any(|event| matches!(
            event,
            ClientEvent::DeliveryChanged {
                message_id: id,
                ..
            } if *id == message_id
        )));
        drop(alice_engine);
        drop(bob_engine);
        drop(alice);
        drop(bob);
        relay.abort();
        fs::remove_dir_all(root).unwrap();
    }

    async fn receipt_test_relay(
        messages: Vec<MailboxMessage>,
        reject_once: bool,
    ) -> (
        Client,
        std::sync::Arc<std::sync::Mutex<Vec<CiphertextEnvelope>>>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = Client::new(
            Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap(),
        )
        .unwrap();
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = sent.clone();
        let task = tokio::spawn(async move {
            let mut messages = messages;
            let mut reject_once = reject_once;
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    let mut byte = [0u8];
                    socket.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break request.len();
                    }
                    assert!(request.len() < 16 * 1024);
                };
                let headers = String::from_utf8(request.clone()).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                request.resize(header_end + length, 0);
                socket.read_exact(&mut request[header_end..]).await.unwrap();
                let first = headers.lines().next().unwrap();
                let (status, body) = if first.starts_with("GET /v1/account-device-events ") {
                    ("200 OK", r#"{"events":[]}"#.to_owned())
                } else if first.starts_with("GET /v1/messages ") {
                    (
                        "200 OK",
                        serde_json::json!({"messages": std::mem::take(&mut messages)}).to_string(),
                    )
                } else if first.starts_with("POST /v1/messages/ack ") {
                    ("204 No Content", String::new())
                } else if first.starts_with("POST /v1/messages ") {
                    if std::mem::take(&mut reject_once) {
                        ("503 Service Unavailable", String::new())
                    } else {
                        captured
                            .lock()
                            .unwrap()
                            .push(serde_json::from_slice(&request[header_end..]).unwrap());
                        ("204 No Content", String::new())
                    }
                } else {
                    panic!("unexpected receipt test request: {first}")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (api, sent, task)
    }

    #[tokio::test]
    async fn explicit_visibility_and_thread_scoped_reads_are_enforced() {
        let root = std::env::temp_dir().join(format!("mutte-client-thread-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let (alice, conversation_id) = conversation(&root, "alice", 31);
        let bob = Device::load_or_create_at(root.join("bob-device.json"), &[32; 32]).unwrap();
        let bootstrap = alice
            .create_conversation(conversation_id, &[(bob.id(), bob.key_package().unwrap())])
            .unwrap();
        bob.join_conversation(conversation_id, alice.id(), &bootstrap.welcome)
            .unwrap();
        let mut vault = Vault::open_at(root.join("bob-vault.json"), &[33; 32]).unwrap();
        vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "alice".into(),
                unread: 0,
            })
            .unwrap();
        let mut engine = MutteClient::connected(profile("bob"), vault).unwrap();
        engine.select_conversation(conversation_id).unwrap();
        let root_id = Uuid::new_v4();
        let reply_id = Uuid::new_v4();
        for (delivery_id, id, text, thread_root) in [
            (1, root_id, "root", None),
            (2, reply_id, "thread reply", Some(root_id)),
        ] {
            let payload = ChatApplicationPayload::Message {
                version: CHAT_APPLICATION_VERSION,
                id,
                text: text.into(),
                sent_at: Utc::now(),
                attachment: None,
                reply_to: (id == reply_id).then_some(root_id),
                thread_root,
            };
            let ciphertext = alice
                .encrypt_application(conversation_id, &serde_json::to_vec(&payload).unwrap())
                .unwrap();
            let pending = bob
                .decrypt_application(
                    delivery_id,
                    conversation_id,
                    alice.id(),
                    "alice",
                    &ciphertext,
                )
                .unwrap();
            engine.present_pending(&pending).unwrap();
        }
        let index = engine.chat_index(conversation_id).unwrap();
        assert!(!engine.conversations[index].messages[0].locally_read);
        assert!(!engine.conversations[index].messages[1].locally_read);
        assert_eq!(engine.conversations[index].unread, 2);

        engine
            .execute(
                None,
                ClientCommand::SetVisibleConversation {
                    conversation_id,
                    thread_root: None,
                },
            )
            .await
            .unwrap();
        assert!(engine.conversations[index].messages[0].locally_read);
        assert!(!engine.conversations[index].messages[1].locally_read);
        assert_eq!(engine.conversations[index].unread, 1);

        engine
            .execute(None, ClientCommand::ClearVisibleConversation)
            .await
            .unwrap();
        let after_leaving_id = Uuid::new_v4();
        let payload = ChatApplicationPayload::Message {
            version: CHAT_APPLICATION_VERSION,
            id: after_leaving_id,
            text: "arrived after leaving".into(),
            sent_at: Utc::now(),
            attachment: None,
            reply_to: None,
            thread_root: None,
        };
        let ciphertext = alice
            .encrypt_application(conversation_id, &serde_json::to_vec(&payload).unwrap())
            .unwrap();
        let pending = bob
            .decrypt_application(3, conversation_id, alice.id(), "alice", &ciphertext)
            .unwrap();
        engine.present_pending(&pending).unwrap();
        assert_eq!(
            engine.selected, index,
            "selection remains intentionally stale"
        );
        assert!(
            !engine.conversations[index]
                .messages
                .iter()
                .find(|message| message.id == after_leaving_id)
                .unwrap()
                .locally_read
        );
        assert_eq!(engine.conversations[index].unread, 2);

        engine
            .execute(
                None,
                ClientCommand::SetVisibleConversation {
                    conversation_id,
                    thread_root: Some(root_id),
                },
            )
            .await
            .unwrap();
        assert!(engine.conversations[index].messages[1].locally_read);
        assert_eq!(engine.conversations[index].unread, 1);

        let visible_reply_id = Uuid::new_v4();
        let payload = ChatApplicationPayload::Message {
            version: CHAT_APPLICATION_VERSION,
            id: visible_reply_id,
            text: "visible thread reply".into(),
            sent_at: Utc::now(),
            attachment: None,
            reply_to: Some(root_id),
            thread_root: Some(root_id),
        };
        let ciphertext = alice
            .encrypt_application(conversation_id, &serde_json::to_vec(&payload).unwrap())
            .unwrap();
        let pending = bob
            .decrypt_application(4, conversation_id, alice.id(), "alice", &ciphertext)
            .unwrap();
        engine.present_pending(&pending).unwrap();
        assert!(
            engine.conversations[index]
                .messages
                .iter()
                .find(|message| message.id == visible_reply_id)
                .unwrap()
                .locally_read
        );
        assert_eq!(engine.conversations[index].unread, 1);
        drop(engine);
        drop(alice);
        drop(bob);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn headless_history_import_survives_restart_and_queues_ack() {
        let root = std::env::temp_dir().join(format!("mutte-client-history-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let (source, conversation_id) = conversation(&root, "source", 41);
        let target = Device::load_or_create_at(root.join("target-device.json"), &[42; 32]).unwrap();
        let bootstrap = source
            .create_conversation(
                conversation_id,
                &[(target.id(), target.key_package().unwrap())],
            )
            .unwrap();
        target
            .join_conversation(conversation_id, source.id(), &bootstrap.welcome)
            .unwrap();
        let mut sender = Vault::open_at(root.join("sender-vault.json"), &[43; 32]).unwrap();
        sender
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "peer".into(),
                unread: 0,
            })
            .unwrap();
        let message_id = Uuid::new_v4();
        sender
            .store_inbound(
                VaultConversation {
                    id: conversation_id,
                    peer_handle: "peer".into(),
                    unread: 0,
                },
                stored_message(
                    message_id,
                    conversation_id,
                    "history after restart",
                    false,
                    DeliveryState::Received,
                ),
                false,
            )
            .unwrap();
        let transfer_id = sender
            .begin_history_transfer(conversation_id, target.id())
            .unwrap();
        let mut payloads = Vec::new();
        while let Some(payload) = sender.next_history_payload(transfer_id).unwrap() {
            payloads.push(payload);
            sender
                .queue_history_part(
                    transfer_id,
                    CiphertextEnvelope {
                        id: Uuid::new_v4(),
                        conversation_id,
                        sender_device_id: source.id(),
                        sender_handle: "same_account".into(),
                        recipients: vec![target.id()],
                        kind: EnvelopeKind::HistorySync,
                        mutation_id: None,
                        ciphertext: "opaque-test-envelope".into(),
                        created_at: Utc::now(),
                    },
                )
                .unwrap();
        }
        assert!(matches!(
            payloads.first(),
            Some(HistorySyncPayload::Manifest {
                version: HISTORY_SYNC_VERSION,
                ..
            })
        ));
        let receiver_path = root.join("receiver-vault.json");
        let mut receiver_vault = Vault::open_at(&receiver_path, &[44; 32]).unwrap();
        receiver_vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "peer".into(),
                unread: 0,
            })
            .unwrap();
        let mut engine = MutteClient::connected(profile("same_account"), receiver_vault).unwrap();
        let manifest = PendingApplication {
            delivery_id: 1,
            conversation_id,
            sender_device_id: source.id(),
            sender_handle: "same_account".into(),
            plaintext: serde_json::to_vec(&payloads[0]).unwrap(),
            kind: PendingApplicationKind::HistorySync,
        };
        engine.present_history_sync(&manifest, &target).unwrap();
        drop(engine);

        let mut engine = MutteClient::connected(
            profile("same_account"),
            Vault::open_at(&receiver_path, &[44; 32]).unwrap(),
        )
        .unwrap();
        for (index, payload) in payloads.iter().enumerate().skip(1) {
            engine
                .present_history_sync(
                    &PendingApplication {
                        delivery_id: 2 + index as i64,
                        conversation_id,
                        sender_device_id: source.id(),
                        sender_handle: "same_account".into(),
                        plaintext: serde_json::to_vec(payload).unwrap(),
                        kind: PendingApplicationKind::HistorySync,
                    },
                    &target,
                )
                .unwrap();
        }
        let conversation = engine
            .conversations
            .iter()
            .find(|item| item.conversation_id == Some(conversation_id))
            .unwrap();
        assert!(
            conversation
                .messages
                .iter()
                .any(|item| item.id == message_id)
        );
        assert!(
            engine
                .vault
                .as_ref()
                .unwrap()
                .outbox()
                .iter()
                .any(|item| item.envelope.kind == EnvelopeKind::HistorySync)
        );
        drop(engine);
        drop(sender);
        drop(source);
        drop(target);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn safety_code_verification_survives_engine_restart() {
        let root = std::env::temp_dir().join(format!("mutte-client-verify-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let (alice, conversation_id) = conversation(&root, "alice", 51);
        let bob = Device::load_or_create_at(root.join("bob-device.json"), &[52; 32]).unwrap();
        let bootstrap = alice
            .create_conversation(conversation_id, &[(bob.id(), bob.key_package().unwrap())])
            .unwrap();
        bob.join_conversation(conversation_id, alice.id(), &bootstrap.welcome)
            .unwrap();
        let path = root.join("vault.json");
        let mut vault = Vault::open_at(&path, &[53; 32]).unwrap();
        vault
            .upsert_conversation(VaultConversation {
                id: conversation_id,
                peer_handle: "bob".into(),
                unread: 0,
            })
            .unwrap();
        let mut engine = MutteClient::connected(profile("alice"), vault).unwrap();
        engine.select_conversation(conversation_id).unwrap();
        engine.refresh_chat_verification(engine.selected, &alice);
        engine.show_verification(&alice).unwrap();
        engine.confirm_verification(&alice).unwrap();
        assert_eq!(
            engine.conversations[engine.selected].verification,
            VerificationState::Verified
        );
        drop(engine);

        let mut engine =
            MutteClient::connected(profile("alice"), Vault::open_at(&path, &[53; 32]).unwrap())
                .unwrap();
        let index = engine.chat_index(conversation_id).unwrap();
        assert_eq!(
            engine.refresh_chat_verification(index, &alice),
            VerificationState::Verified
        );
        drop(engine);
        drop(alice);
        drop(bob);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn revocation_committer_is_smallest_active_account_member() {
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        let revoked = Uuid::from_u128(3);
        let peer = Uuid::from_u128(4);
        let members = [peer, revoked, second, first];
        let active = HashSet::from([Uuid::nil(), second, first]);
        assert_eq!(elected_account_committer(&members, &active), Some(first));
    }
}
