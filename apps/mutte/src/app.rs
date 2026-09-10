use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{HashMap, VecDeque},
    ops::{Deref, DerefMut},
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent, MouseEventKind,
};
use mutte_client::personal::{HeldText, HoldPhase, PersonalState};
use mutte_client::polls::{PollState, is_poll_event};
use mutte_client::{
    ClientCommand, ClientEvent, ConversationSnapshot, DirectConversationChoiceRequired,
    MessageSnapshot, MutteClient, VerificationState, is_reaction_for_known_message,
    is_reaction_message, reactions_for,
};
use mutte_protocol::{AccountDeviceState, Profile};
use mutte_store::Vault;
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap},
};
use uuid::Uuid;
#[path = "personal_ui.rs"]
mod personal_ui;
use personal_ui::PersonalUi;

use crate::{
    attachment_picker::{AttachmentPicker, ChosenFile, PickerAction, format_bytes, modal_area},
    conversation_layout::{
        LANE_MAX_WIDTH, LayoutOptions, Transcript, TranscriptViewport, delivery_label,
        truncate_cells, wrap_cells,
    },
    file_preview::{PreviewDialog, PreviewReturn},
    notifications::{
        self, NotificationMode, Notifications, TerminalNotificationSurface, unread_total,
    },
    platform::open_browser,
    theme::{ThemeManager, ThemePalette},
    wordmark,
};

pub use mutte_client::Connection;

#[cfg(test)]
use crate::conversation_layout::continues_sender_group;

const MAILBOX_FALLBACK_INTERVAL: Duration = Duration::from_secs(10);
const INFO_NOTICE_DURATION: Duration = Duration::from_secs(5);
const WARNING_NOTICE_DURATION: Duration = Duration::from_secs(8);
const MINIMUM_WIDTH: u16 = 52;
const MINIMUM_HEIGHT: u16 = 16;
const SIDEBAR_MINIMUM_WIDTH: u16 = 88;
const QUICK_REACTIONS: [&str; 6] = ["👍", "❤️", "😂", "😮", "😢", "👎"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ComposerMode {
    Message,
    Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UiMode {
    Conversations,
    Messages,
    Composer(ComposerMode),
    Palette,
    Verification,
    Devices,
    Attachments,
    AttachmentDetails,
    FilePreview,
    Reactions,
}

impl UiMode {
    fn is_composer(self) -> bool {
        matches!(self, Self::Composer(_))
    }

    fn cycle(self, backwards: bool) -> Self {
        let modes = [
            Self::Conversations,
            Self::Messages,
            Self::Composer(ComposerMode::Message),
            Self::Composer(ComposerMode::Command),
        ];
        let index = modes.iter().position(|mode| *mode == self).unwrap_or(0);
        modes[(index + if backwards { 3 } else { 1 }) % modes.len()]
    }
}

// Scope by encrypted conversation ID, never by handle: one handle can have
// multiple independent histories. Main-chat and thread drafts stay separate.
type ConversationScope = (Option<Uuid>, Option<Uuid>);

#[derive(Default)]
struct MessageDraft {
    text: String,
    reply_to: Option<Uuid>,
}

struct AttachmentDialog {
    picker: AttachmentPicker,
    scope: ConversationScope,
    reply_to: Option<Uuid>,
    recipient: String,
    return_mode: UiMode,
}

struct PendingAttachment {
    file: ChosenFile,
    conversation_id: Uuid,
    thread_root: Option<Uuid>,
    reply_to: Option<Uuid>,
    recipient: String,
}

struct AttachmentDetails {
    message: MessageSnapshot,
    return_mode: UiMode,
    error: Option<String>,
    scroll: u16,
}

struct AttachmentTransfer {
    filename: String,
    bytes: u64,
    context: String,
    downloading: bool,
}

struct ReactionDialog {
    conversation_id: Uuid,
    message_id: Uuid,
    target_preview: String,
    selected: usize,
    return_mode: UiMode,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoticeSeverity {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoticeScope {
    Composer,
    Overlay,
}

#[derive(Clone, Debug)]
struct UiNotice {
    severity: NoticeSeverity,
    scope: NoticeScope,
    message: String,
    expires_at: Option<Instant>,
}

impl UiNotice {
    fn new(
        severity: NoticeSeverity,
        scope: NoticeScope,
        message: impl Into<String>,
        now: Instant,
    ) -> Self {
        let lifetime = match severity {
            NoticeSeverity::Info | NoticeSeverity::Success => Some(INFO_NOTICE_DURATION),
            NoticeSeverity::Warning => Some(WARNING_NOTICE_DURATION),
            NoticeSeverity::Error => None,
        };
        Self {
            severity,
            scope,
            message: message.into(),
            expires_at: lifetime.and_then(|duration| now.checked_add(duration)),
        }
    }

    fn from_client(message: String, scope: NoticeScope, now: Instant) -> Self {
        let normalized = message.to_ascii_lowercase();
        let severity = if normalized.contains("error") || normalized.contains("failed") {
            NoticeSeverity::Error
        } else if normalized.contains("waiting")
            || normalized.contains("unavailable")
            || normalized.contains("queued")
            || normalized.contains("changed")
            || normalized.contains("expired")
            || normalized.contains("cancelled")
            || normalized.contains("link an account")
        {
            NoticeSeverity::Warning
        } else if normalized.contains("sent")
            || normalized.contains("ready")
            || normalized.contains("verified")
            || normalized.contains("loaded")
            || normalized.contains("synchronized")
            || normalized.contains("downloaded")
            || normalized.contains("received")
            || normalized.contains("revoked")
        {
            NoticeSeverity::Success
        } else {
            NoticeSeverity::Info
        };
        Self::new(severity, scope, message, now)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionState {
    Ready,
    Authenticating,
    Unavailable,
}

impl ConnectionState {
    fn label(self) -> &'static str {
        match self {
            Self::Ready => "mailbox ready",
            Self::Authenticating => "authentication required",
            Self::Unavailable => "mailbox unavailable",
        }
    }

    fn severity(self) -> NoticeSeverity {
        match self {
            Self::Ready => NoticeSeverity::Success,
            Self::Authenticating | Self::Unavailable => NoticeSeverity::Warning,
        }
    }
}

#[derive(Clone, Debug)]
struct UiState {
    mode: UiMode,
    return_mode: UiMode,
    connection: ConnectionState,
    notice: Option<UiNotice>,
    last_client_notice: String,
    capture_next_client_notice: bool,
}

impl UiState {
    fn new(initial_client_notice: String) -> Self {
        Self {
            mode: UiMode::Composer(ComposerMode::Message),
            return_mode: UiMode::Composer(ComposerMode::Message),
            connection: ConnectionState::Ready,
            notice: None,
            last_client_notice: initial_client_notice,
            capture_next_client_notice: false,
        }
    }

    fn set_notice(
        &mut self,
        severity: NoticeSeverity,
        scope: NoticeScope,
        message: impl Into<String>,
    ) {
        self.set_notice_at(severity, scope, message, Instant::now());
    }

    fn set_notice_at(
        &mut self,
        severity: NoticeSeverity,
        scope: NoticeScope,
        message: impl Into<String>,
        now: Instant,
    ) {
        self.notice = Some(UiNotice::new(severity, scope, message, now));
    }

    fn capture_client_notice(&mut self, message: String, scope: NoticeScope) {
        let explicitly_requested = std::mem::take(&mut self.capture_next_client_notice);
        if message == "mailbox ready"
            || (!explicitly_requested && message == self.last_client_notice)
        {
            return;
        }
        self.last_client_notice.clone_from(&message);
        self.notice = Some(UiNotice::from_client(message, scope, Instant::now()));
    }

    fn prepare_client_action(&mut self) {
        self.capture_next_client_notice = true;
    }

    fn cancel_client_action(&mut self) {
        self.capture_next_client_notice = false;
    }

    fn expire_notices(&mut self, now: Instant) {
        if self
            .notice
            .as_ref()
            .and_then(|notice| notice.expires_at)
            .is_some_and(|expires_at| now >= expires_at)
        {
            self.notice = None;
        }
    }

    fn notice_for(&self, scope: NoticeScope) -> Option<&UiNotice> {
        self.notice.as_ref().filter(|notice| notice.scope == scope)
    }

    fn clear_notice_scope(&mut self, scope: NoticeScope) {
        if self.notice_for(scope).is_some() {
            self.notice = None;
        }
    }

    fn open_palette(&mut self) {
        if self.mode == UiMode::Palette {
            return;
        }
        self.return_mode = self.mode;
        self.mode = UiMode::Palette;
    }

    fn close_palette(&mut self) {
        if self.mode == UiMode::Palette {
            self.mode = self.return_mode;
        }
    }

    fn focus_composer(&mut self) {
        self.mode = UiMode::Composer(ComposerMode::Message);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PaletteAction {
    PersonalHome,
    Search,
    Poll,
    Keepsakes,
    Quiet,
    Settings,
    Sending,
    NewChat,
    SendAttachment,
    Verify,
    Devices,
    SyncDevice,
    Reply,
    React,
    Thread,
    ReadReceipts,
    Quit,
}

#[derive(Clone, Copy)]
struct PaletteEntry {
    action: PaletteAction,
    shortcut: char,
    label: &'static str,
    detail: &'static str,
}

const PALETTE_ENTRIES: [PaletteEntry; 17] = [
    PaletteEntry {
        action: PaletteAction::NewChat,
        shortcut: 'n',
        label: "New encrypted chat",
        detail: "Start a private conversation",
    },
    PaletteEntry {
        action: PaletteAction::SendAttachment,
        shortcut: 'a',
        label: "Send an attachment",
        detail: "Encrypt a file before upload",
    },
    PaletteEntry {
        action: PaletteAction::Verify,
        shortcut: 'v',
        label: "Verify this conversation",
        detail: "Compare the shared safety code",
    },
    PaletteEntry {
        action: PaletteAction::Devices,
        shortcut: 'd',
        label: "Account devices",
        detail: "Review linked terminals",
    },
    PaletteEntry {
        action: PaletteAction::SyncDevice,
        shortcut: 's',
        label: "Sync a new device",
        detail: "Add a trusted device to local chats",
    },
    PaletteEntry {
        action: PaletteAction::Reply,
        shortcut: 'r',
        label: "Reply to a message",
        detail: "Quote the selected message",
    },
    PaletteEntry {
        action: PaletteAction::React,
        shortcut: 'e',
        label: "React to a message",
        detail: "Toggle an encrypted emoji reaction",
    },
    PaletteEntry {
        action: PaletteAction::Thread,
        shortcut: 't',
        label: "Open a thread",
        detail: "Thread from the selected message",
    },
    PaletteEntry {
        action: PaletteAction::ReadReceipts,
        shortcut: 'p',
        label: "Read receipt privacy",
        detail: "Choose whether reads are shared",
    },
    PaletteEntry {
        action: PaletteAction::PersonalHome,
        shortcut: 'h',
        label: "Chats & people",
        detail: "Chats, Quiet, keepsakes and settings · F5",
    },
    PaletteEntry {
        action: PaletteAction::Search,
        shortcut: 'f',
        label: "Search this device",
        detail: "People, messages, files and private notes · F6",
    },
    PaletteEntry {
        action: PaletteAction::Poll,
        shortcut: 'l',
        label: "Create a poll",
        detail: "Named votes in this conversation or thread",
    },
    PaletteEntry {
        action: PaletteAction::Keepsakes,
        shortcut: 'b',
        label: "Keepsakes",
        detail: "Select moments, save privately and export",
    },
    PaletteEntry {
        action: PaletteAction::Quiet,
        shortcut: 'm',
        label: "Conversation preferences",
        detail: "Quiet, private note, notifications and following",
    },
    PaletteEntry {
        action: PaletteAction::Settings,
        shortcut: 'g',
        label: "Settings",
        detail: "Account, privacy, storage and sharing",
    },
    PaletteEntry {
        action: PaletteAction::Sending,
        shortcut: 'u',
        label: "Sending & Undo",
        detail: "Off / 5 / 10 seconds; recover held drafts",
    },
    PaletteEntry {
        action: PaletteAction::Quit,
        shortcut: 'q',
        label: "Quit Mutte",
        detail: "Close this terminal session",
    },
];

pub struct App {
    personal: PersonalState,
    personal_ui: PersonalUi,
    client: MutteClient,
    theme: ThemeManager,
    input: String,
    command_input: String,
    reply_to: Option<Uuid>,
    draft_scope: ConversationScope,
    drafts: HashMap<ConversationScope, MessageDraft>,
    selected_messages: HashMap<ConversationScope, Uuid>,
    transcript_viewports: RefCell<HashMap<ConversationScope, TranscriptViewport>>,
    palette_selection: usize,
    ui: UiState,
    should_quit: bool,
    demo: bool,
    notifications: Notifications,
    window_focused: bool,
    monochrome: bool,
    last_visible: Option<ConversationScope>,
    attachment_dialog: Option<AttachmentDialog>,
    pending_attachment: Option<PendingAttachment>,
    attachment_directory: Option<PathBuf>,
    attachment_details: Option<AttachmentDetails>,
    pending_download: Option<Uuid>,
    file_preview: Option<PreviewDialog>,
    reaction_dialog: Option<ReactionDialog>,
}

impl Deref for App {
    type Target = MutteClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl DerefMut for App {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

impl App {
    pub fn new(profile: Profile, demo: bool) -> Self {
        let client = MutteClient::new(profile, demo);
        let ui = UiState::new(client.notice.clone());
        let draft_scope = (client.conversations[client.selected].conversation_id, None);
        let notifications = Notifications::new(&client.conversations);
        Self {
            personal: PersonalState::default(),
            personal_ui: PersonalUi::default(),
            client,
            theme: ThemeManager::discover(),
            input: String::new(),
            command_input: String::new(),
            reply_to: None,
            draft_scope,
            drafts: HashMap::new(),
            selected_messages: HashMap::new(),
            transcript_viewports: RefCell::new(HashMap::new()),
            palette_selection: 0,
            ui,
            should_quit: false,
            demo,
            notifications,
            window_focused: true,
            monochrome: std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            last_visible: None,
            attachment_dialog: None,
            pending_attachment: None,
            attachment_directory: None,
            attachment_details: None,
            pending_download: None,
            file_preview: None,
            reaction_dialog: None,
        }
    }

    pub fn connected(profile: Profile, vault: Vault) -> Result<Self> {
        let client = MutteClient::connected(profile, vault)?;
        let personal = client.load_personal_state()?;
        let ui = UiState::new(client.notice.clone());
        let draft_scope = (client.conversations[client.selected].conversation_id, None);
        let notifications = Notifications::new(&client.conversations);
        Ok(Self {
            personal,
            personal_ui: PersonalUi::default(),
            client,
            theme: ThemeManager::discover(),
            input: String::new(),
            command_input: String::new(),
            reply_to: None,
            draft_scope,
            drafts: HashMap::new(),
            selected_messages: HashMap::new(),
            transcript_viewports: RefCell::new(HashMap::new()),
            palette_selection: 0,
            ui,
            should_quit: false,
            demo: false,
            notifications,
            window_focused: true,
            monochrome: std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            last_visible: None,
            attachment_dialog: None,
            pending_attachment: None,
            attachment_directory: None,
            attachment_details: None,
            pending_download: None,
            file_preview: None,
            reaction_dialog: None,
        })
    }

    pub fn with_notifications(mut self, mode: Option<NotificationMode>) -> Self {
        self.notifications.mode = mode.unwrap_or(match self.personal.terminal_alerts.as_deref() {
            Some("off") => NotificationMode::Off,
            Some("bell") => NotificationMode::Bell,
            _ => NotificationMode::Auto,
        });
        self
    }

    fn handle_client_events(&mut self) {
        for event in self.take_events() {
            match event {
                ClientEvent::AuthenticationRequired { url } => {
                    self.ui.connection = ConnectionState::Authenticating;
                    if let Err(error) = open_browser(&url) {
                        self.ui.set_notice(
                            NoticeSeverity::Error,
                            NoticeScope::Composer,
                            format!("browser failed ({error}); open: {url}"),
                        );
                    }
                }
                ClientEvent::QuitRequested => self.should_quit = true,
                ClientEvent::HelpRequested => self.ui.open_palette(),
                ClientEvent::ConnectionChanged { connected } => {
                    self.ui.connection = if connected {
                        ConnectionState::Ready
                    } else {
                        ConnectionState::Unavailable
                    };
                }
                ClientEvent::MailboxReady => self.ui.connection = ConnectionState::Ready,
                ClientEvent::MessageReceived {
                    conversation_id,
                    message_id,
                } => {
                    if let Some(message) = self
                        .client
                        .conversations
                        .iter()
                        .find(|chat| chat.conversation_id == Some(conversation_id))
                        .and_then(|chat| {
                            chat.messages
                                .iter()
                                .find(|message| message.id == message_id)
                        })
                    {
                        self.notifications
                            .received(conversation_id, message, Instant::now());
                    }
                }
                ClientEvent::Notice { message } => {
                    let scope = if self.verification_panel.is_some() || self.device_panel.is_some()
                    {
                        NoticeScope::Overlay
                    } else {
                        NoticeScope::Composer
                    };
                    self.ui.capture_client_notice(message, scope);
                }
                _ => {}
            }
        }
        if self.verification_panel.is_some() {
            self.ui.mode = UiMode::Verification;
        } else if self.device_panel.is_some() {
            self.ui.mode = UiMode::Devices;
        }
        self.sync_draft_scope();
        if let Some(details) = &mut self.attachment_details
            && let Some(message) = self
                .client
                .conversations
                .iter()
                .flat_map(|chat| &chat.messages)
                .find(|message| message.id == details.message.id)
        {
            details.message = message.clone();
            if details
                .message
                .attachment
                .as_ref()
                .is_some_and(|file| file.local_path.is_some())
            {
                details.error = None;
            }
        }
        self.notifications
            .clear_if_read(unread_total(&self.conversations));
        self.refresh_personal_poll();
    }

    fn open_attachment_picker(&mut self) {
        self.ui.close_palette();
        if self.scope().0.is_none() {
            self.ui.set_notice(
                NoticeSeverity::Info,
                NoticeScope::Composer,
                "Open an encrypted chat before attaching a file",
            );
            return;
        }
        let directory = self
            .attachment_directory
            .clone()
            .unwrap_or_else(AttachmentPicker::initial_directory);
        let chat = &self.conversations[self.selected];
        let recipient = format!(
            "{}{}",
            display_handle(&chat.handle),
            if chat.active_thread.is_some() {
                " · current thread"
            } else {
                " · main chat"
            }
        );
        self.attachment_dialog = Some(AttachmentDialog {
            picker: AttachmentPicker::new(directory),
            scope: self.scope(),
            reply_to: self.reply_to,
            recipient,
            return_mode: self.ui.mode,
        });
        self.ui.mode = UiMode::Attachments;
    }

    fn close_attachment_picker(&mut self) {
        if let Some(dialog) = self.attachment_dialog.take() {
            self.attachment_directory = Some(dialog.picker.directory);
            self.ui.mode = dialog.return_mode;
        }
        self.pending_attachment = None;
    }

    fn handle_attachment_key(&mut self, key: KeyEvent) {
        let Some(dialog) = &mut self.attachment_dialog else {
            return;
        };
        match dialog.picker.on_key(key) {
            PickerAction::None => {}
            PickerAction::Cancel => self.close_attachment_picker(),
            PickerAction::Preview(file) => {
                self.open_file_preview(file.path, file.filename, PreviewReturn::Attachments)
            }
            PickerAction::Send(file) => {
                let scope = self.scope();
                let dialog = self.attachment_dialog.as_mut().unwrap();
                if dialog.scope != scope {
                    dialog.picker.set_error("The conversation changed. Cancel and reopen Attach to choose the destination again.".into());
                    return;
                }
                self.pending_attachment = Some(PendingAttachment {
                    file,
                    conversation_id: dialog.scope.0.unwrap(),
                    thread_root: dialog.scope.1,
                    reply_to: dialog.reply_to,
                    recipient: dialog.recipient.clone(),
                });
            }
        }
    }

    async fn send_attachment_from_dialog(
        &mut self,
        terminal: &mut DefaultTerminal,
        connection: Option<&Connection<'_>>,
        pending: PendingAttachment,
    ) -> Result<()> {
        if self.demo {
            if let Some(dialog) = &mut self.attachment_dialog {
                dialog.picker.set_error(
                    "Demo mode does not upload files. Your file and draft are unchanged.".into(),
                );
            }
            return Ok(());
        }
        if let Err(error) = pending.file.validate_unchanged() {
            if let Some(dialog) = &mut self.attachment_dialog {
                dialog.picker.set_error(error.to_string());
            }
            return Ok(());
        }
        let transfer = AttachmentTransfer {
            filename: pending.file.filename.clone(),
            bytes: pending.file.bytes,
            context: format!("To {}", pending.recipient),
            downloading: false,
        };
        let result = self
            .run_attachment_command(
                terminal,
                connection,
                ClientCommand::SendAttachmentInScope {
                    conversation_id: pending.conversation_id,
                    path: pending.file.path.clone(),
                    reply_to: pending.reply_to,
                    thread_root: pending.thread_root,
                },
                &transfer,
            )
            .await?;
        match result {
            Some(Ok(())) => {
                self.close_attachment_picker();
                let notice = UiNotice::from_client(
                    self.client.notice.clone(),
                    NoticeScope::Composer,
                    Instant::now(),
                );
                self.ui.notice = Some(notice);
            }
            Some(Err(error))
                if self.client.attachment_send_pending(
                    pending.conversation_id,
                    &pending.file.path,
                    pending.reply_to,
                    pending.thread_root,
                ) =>
            {
                self.close_attachment_picker();
                self.ui.set_notice(NoticeSeverity::Warning, NoticeScope::Composer, format!("File queued for retry: {error}. Keep the source file available; do not resend it."));
            }
            Some(Err(error)) => {
                if let Some(dialog) = &mut self.attachment_dialog {
                    dialog.picker.set_error(format!("Could not send: {error}"));
                }
            }
            None => {}
        }
        Ok(())
    }

    async fn run_attachment_command(
        &mut self,
        terminal: &mut DefaultTerminal,
        connection: Option<&Connection<'_>>,
        command: ClientCommand,
        transfer: &AttachmentTransfer,
    ) -> Result<Option<Result<()>>> {
        let palette = self.theme.palette();
        let started = Instant::now();
        terminal
            .draw(|frame| draw_attachment_transfer(frame, transfer, started.elapsed(), palette))?;
        // Keep the progress modal and Ctrl+C responsive while the existing
        // resumable transfer future owns the encrypted client. No other client
        // mutation can race the upload or change its frozen destination.
        let result = {
            let mut operation = Box::pin(self.client.execute(connection, command));
            'transfer: loop {
                tokio::select! {
                    result = &mut operation => break Some(result),
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        terminal.draw(|frame| draw_attachment_transfer(frame, transfer, started.elapsed(), palette))?;
                        while event::poll(Duration::ZERO)? {
                            match event::read()? {
                                Event::Key(key) if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) => {
                                    self.should_quit = true;
                                    break 'transfer None;
                                }
                                Event::FocusLost => self.window_focused = false,
                                Event::FocusGained => self.window_focused = true,
                                _ => {}
                            }
                        }
                    }
                }
            }
        };
        self.handle_client_events();
        Ok(result)
    }

    fn open_attachment_details(&mut self) {
        let Some(message) = self
            .selected_message()
            .filter(|message| message.attachment.is_some())
            .cloned()
        else {
            self.ui.set_notice(
                NoticeSeverity::Info,
                NoticeScope::Composer,
                "Select a message with a file first",
            );
            return;
        };
        self.attachment_details = Some(AttachmentDetails {
            message,
            return_mode: self.ui.mode,
            error: None,
            scroll: 0,
        });
        self.ui.mode = UiMode::AttachmentDetails;
    }

    fn handle_attachment_details_key(&mut self, key: KeyEvent) {
        let mut preview = None;
        let Some(details) = &mut self.attachment_details else {
            return;
        };
        match key.code {
            KeyCode::Esc => {
                self.ui.mode = details.return_mode;
                self.attachment_details = None;
                self.pending_download = None;
            }
            KeyCode::Down => details.scroll = details.scroll.saturating_add(1),
            KeyCode::Up => details.scroll = details.scroll.saturating_sub(1),
            KeyCode::Home => details.scroll = 0,
            KeyCode::Enter | KeyCode::Char('d' | 'D') => {
                let attachment = details.message.attachment.as_ref().unwrap();
                if attachment.local_path.is_none() {
                    if self.demo {
                        details.error = Some("Demo mode does not download files.".into());
                    } else {
                        self.pending_download = Some(attachment.metadata.attachment_id);
                    }
                }
            }
            KeyCode::Char('p' | 'P') => {
                let attachment = details.message.attachment.as_ref().unwrap();
                if let Some(path) = attachment.local_path.clone() {
                    preview = Some((path, attachment.metadata.filename.clone()));
                } else {
                    details.error = Some("Download the file before previewing it.".into());
                }
            }
            _ => {}
        }
        if let Some((path, filename)) = preview {
            self.open_file_preview(path, filename, PreviewReturn::AttachmentDetails);
        }
    }

    fn open_file_preview(&mut self, path: PathBuf, filename: String, return_mode: PreviewReturn) {
        match PreviewDialog::new(&path, filename, return_mode) {
            Ok(preview) => {
                self.file_preview = Some(preview);
                self.ui.mode = UiMode::FilePreview;
            }
            Err(error) => {
                if let Some(dialog) = &mut self.attachment_dialog {
                    dialog.picker.set_error(format!("Cannot preview: {error}"));
                } else if let Some(details) = &mut self.attachment_details {
                    details.error = Some(format!("Cannot preview: {error}"));
                }
            }
        }
    }

    fn handle_file_preview_key(&mut self, key: KeyEvent) {
        let Some(preview) = &mut self.file_preview else {
            return;
        };
        match key.code {
            KeyCode::Esc => {
                self.ui.mode = match preview.return_mode {
                    PreviewReturn::Attachments => UiMode::Attachments,
                    PreviewReturn::AttachmentDetails => UiMode::AttachmentDetails,
                };
                self.file_preview = None;
            }
            KeyCode::Up => preview.scroll_up(),
            KeyCode::Down => preview.scroll_down(),
            KeyCode::Home => preview.home(),
            _ => {}
        }
    }

    fn open_reactions(&mut self) {
        let Some(conversation_id) = self.scope().0 else {
            return;
        };
        let Some(message) = self.selected_message().cloned() else {
            self.ui.set_notice(
                NoticeSeverity::Info,
                NoticeScope::Composer,
                "Select a message to react",
            );
            return;
        };
        let preview = if message.text.trim().is_empty() {
            message
                .attachment
                .as_ref()
                .map(|file| file.metadata.filename.clone())
                .unwrap_or_else(|| "Encrypted message".into())
        } else {
            message
                .text
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        self.reaction_dialog = Some(ReactionDialog {
            conversation_id,
            message_id: message.id,
            target_preview: truncate_cells(&preview, 64),
            selected: 0,
            return_mode: self.ui.mode,
            error: None,
        });
        self.ui.mode = UiMode::Reactions;
    }

    async fn handle_reaction_key(&mut self, key: KeyEvent, connection: Option<&Connection<'_>>) {
        let Some(dialog) = &mut self.reaction_dialog else {
            return;
        };
        match key.code {
            KeyCode::Esc => {
                self.ui.mode = dialog.return_mode;
                self.reaction_dialog = None;
            }
            KeyCode::Left | KeyCode::Up | KeyCode::BackTab => {
                dialog.selected =
                    (dialog.selected + QUICK_REACTIONS.len() - 1) % QUICK_REACTIONS.len();
            }
            KeyCode::Right | KeyCode::Down | KeyCode::Tab => {
                dialog.selected = (dialog.selected + 1) % QUICK_REACTIONS.len();
            }
            KeyCode::Char(number @ '1'..='6') => dialog.selected = number as usize - '1' as usize,
            KeyCode::Enter => {
                if self.demo {
                    dialog.error = Some("Demo mode does not send reactions.".into());
                    return;
                }
                let (conversation_id, message_id, emoji) = (
                    dialog.conversation_id,
                    dialog.message_id,
                    QUICK_REACTIONS[dialog.selected].to_owned(),
                );
                let before = reactions_for(&self.conversations[self.selected].messages, message_id)
                    .iter()
                    .any(|reaction| reaction.emoji == emoji && reaction.mine);
                self.ui.prepare_client_action();
                let result = self
                    .execute(
                        connection,
                        ClientCommand::ToggleReaction {
                            conversation_id,
                            message_id,
                            emoji: emoji.clone(),
                        },
                    )
                    .await;
                self.handle_client_events();
                let after = self
                    .conversations
                    .iter()
                    .find(|chat| chat.conversation_id == Some(conversation_id))
                    .is_some_and(|chat| {
                        reactions_for(&chat.messages, message_id)
                            .iter()
                            .any(|reaction| reaction.emoji == emoji && reaction.mine)
                    });
                if result.is_ok() || before != after {
                    let return_mode = self.reaction_dialog.as_ref().unwrap().return_mode;
                    self.ui.mode = return_mode;
                    self.reaction_dialog = None;
                    if let Err(error) = result {
                        self.ui.set_notice(
                            NoticeSeverity::Warning,
                            NoticeScope::Composer,
                            format!("Reaction queued for retry: {error}"),
                        );
                    }
                } else if let Some(dialog) = &mut self.reaction_dialog {
                    dialog.error = result
                        .err()
                        .map(|error| format!("Could not react: {error}"));
                }
            }
            _ => {}
        }
    }

    async fn download_attachment_from_dialog(
        &mut self,
        terminal: &mut DefaultTerminal,
        connection: Option<&Connection<'_>>,
        attachment_id: Uuid,
    ) -> Result<()> {
        let Some(details) = &self.attachment_details else {
            return Ok(());
        };
        let attachment = details.message.attachment.as_ref().unwrap();
        if attachment.metadata.attachment_id != attachment_id || attachment.local_path.is_some() {
            return Ok(());
        }
        let transfer = AttachmentTransfer {
            filename: attachment.metadata.filename.clone(),
            bytes: attachment.metadata.plaintext_size,
            context: "Saving to Mutte's private downloads folder".into(),
            downloading: true,
        };
        let result = self
            .run_attachment_command(
                terminal,
                connection,
                ClientCommand::RequestAttachment {
                    prefix: attachment_id.simple().to_string(),
                },
                &transfer,
            )
            .await?;
        if let Some(details) = &mut self.attachment_details {
            if let Some(message) = self
                .client
                .conversations
                .iter()
                .flat_map(|chat| &chat.messages)
                .find(|message| message.id == details.message.id)
            {
                details.message = message.clone();
            }
            details.error = match result {
                Some(Err(error)) => Some(format!(
                    "Download incomplete: {error}. Queued downloads retry when connected."
                )),
                _ => None,
            };
            details.scroll = 0;
        }
        Ok(())
    }

    fn visible_scope(&self) -> Option<ConversationScope> {
        let chat = &self.conversations[self.selected];
        (self.window_focused
            && self.personal_ui.panel.is_none()
            && (self.ui.mode.is_composer() || self.ui.mode == UiMode::Messages)
            && chat.scroll_back == 0
            && (self.ui.mode != UiMode::Messages
                || self.selected_message().map(|message| message.id)
                    == self
                        .visible_messages()
                        .next_back()
                        .map(|message| message.id)))
        .then(|| self.scope())
        .filter(|scope| scope.0.is_some())
    }

    async fn update_visibility(&mut self, connection: Option<&Connection<'_>>) {
        let visible = self.visible_scope();
        if visible == self.last_visible {
            return;
        }
        let result = if visible.is_some() {
            self.mark_current_read(connection).await
        } else if self.demo {
            Ok(())
        } else {
            self.execute(connection, ClientCommand::ClearVisibleConversation)
                .await
        };
        match result {
            Ok(()) => self.last_visible = visible,
            Err(error) => self.ui.set_notice(
                NoticeSeverity::Error,
                NoticeScope::Composer,
                format!("read state: {error}"),
            ),
        }
        self.handle_client_events();
    }

    fn scope(&self) -> ConversationScope {
        let chat = &self.conversations[self.selected];
        (chat.conversation_id, chat.active_thread)
    }

    fn sync_draft_scope(&mut self) {
        let scope = self.scope();
        if self.draft_scope == scope {
            return;
        }
        let old = MessageDraft {
            text: std::mem::take(&mut self.input),
            reply_to: self.reply_to.take(),
        };
        if !old.text.is_empty() || old.reply_to.is_some() {
            self.drafts.insert(self.draft_scope, old);
        }
        let draft = self.drafts.remove(&scope).unwrap_or_default();
        self.input = draft.text;
        self.reply_to = draft.reply_to;
        self.draft_scope = scope;
    }

    fn visible_messages(&self) -> impl DoubleEndedIterator<Item = &MessageSnapshot> {
        let chat = &self.conversations[self.selected];
        chat.messages
            .iter()
            .filter(|message| !is_reaction_for_known_message(&chat.messages, message))
            .filter(|message| !is_poll_event(&chat.messages, message))
            .filter(|message| match chat.active_thread {
                Some(root) => message.id == root || message.thread_root == Some(root),
                None => message.thread_root.is_none(),
            })
    }

    fn selected_message(&self) -> Option<&MessageSnapshot> {
        let id = self.selected_messages.get(&self.scope());
        self.visible_messages()
            .find(|message| Some(&message.id) == id)
            .or_else(|| self.visible_messages().next_back())
    }

    fn focus(&mut self, mode: UiMode) {
        self.ui.mode = mode;
        if mode == UiMode::Messages {
            // Message selection drives the viewport in this mode, not the
            // composer's manual scroll offset. Do not retain an invisible
            // scroll-back flag that prevents the newest message being read.
            let selected = self.selected;
            self.conversations[selected].scroll_back = 0;
            if let Some(id) = self.selected_message().map(|message| message.id) {
                self.selected_messages.insert(self.scope(), id);
            }
        }
    }

    fn move_message_selection(&mut self, delta: isize) {
        let ids = self
            .visible_messages()
            .map(|message| message.id)
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return;
        }
        let current = self.selected_message().map(|message| message.id);
        let index = ids
            .iter()
            .position(|id| Some(*id) == current)
            .unwrap_or(ids.len() - 1);
        let next = index.saturating_add_signed(delta).min(ids.len() - 1);
        self.selected_messages.insert(self.scope(), ids[next]);
    }

    fn reply_to_selected(&mut self) {
        let Some(id) = self.selected_message().map(|message| message.id) else {
            self.ui.set_notice(
                NoticeSeverity::Info,
                NoticeScope::Composer,
                "No message to reply to yet",
            );
            return;
        };
        self.reply_to = Some(id);
        self.ui.clear_notice_scope(NoticeScope::Composer);
        self.ui.focus_composer();
    }

    async fn jump_to_original(&mut self, connection: Option<&Connection<'_>>) {
        let target = self
            .selected_message()
            .and_then(|message| message.reply_to)
            .and_then(|id| {
                self.conversations[self.selected]
                    .messages
                    .iter()
                    .find(|message| message.id == id)
            })
            .map(|message| (message.id, message.thread_root));
        let Some((message_id, thread_root)) = target else {
            self.ui.set_notice(
                NoticeSeverity::Info,
                NoticeScope::Composer,
                "The original message is not on this device",
            );
            return;
        };
        let Some(conversation_id) = self.scope().0 else {
            return;
        };
        if self.scope().1 != thread_root {
            let command =
                thread_root.map_or(ClientCommand::CloseThread { conversation_id }, |root| {
                    ClientCommand::OpenThread {
                        conversation_id,
                        message_id: root,
                    }
                });
            if let Err(error) = self.execute(connection, command).await {
                self.ui.set_notice(
                    NoticeSeverity::Error,
                    NoticeScope::Composer,
                    format!("original: {error}"),
                );
                return;
            }
            self.sync_draft_scope();
        }
        self.selected_messages.insert(self.scope(), message_id);
        self.focus(UiMode::Messages);
        self.ui.clear_notice_scope(NoticeScope::Composer);
        self.handle_client_events();
    }

    async fn change_thread(&mut self, open: bool, connection: Option<&Connection<'_>>) {
        let Some(conversation_id) = self.scope().0 else {
            return;
        };
        let command = if open {
            let Some(message_id) = self.selected_message().map(|message| message.id) else {
                self.ui.set_notice(
                    NoticeSeverity::Info,
                    NoticeScope::Composer,
                    "No message to open a thread from yet",
                );
                return;
            };
            ClientCommand::OpenThread {
                conversation_id,
                message_id,
            }
        } else {
            ClientCommand::CloseThread { conversation_id }
        };
        match self.execute(connection, command).await {
            Ok(()) => {
                self.sync_draft_scope();
                self.ui.clear_notice_scope(NoticeScope::Composer);
                self.focus(UiMode::Messages);
            }
            Err(error) => self.ui.set_notice(
                NoticeSeverity::Error,
                NoticeScope::Composer,
                format!("thread: {error}"),
            ),
        }
        self.handle_client_events();
    }

    async fn send_draft(&mut self, connection: Option<&Connection<'_>>) {
        if self.input.trim().is_empty() {
            return;
        }
        if self.personal.undo_seconds > 0 || self.has_restored_hold() {
            let result = self.hold_draft();
            self.personal_result(result);
            return;
        }
        let (conversation_id, thread_root) = self.scope();
        let result = match conversation_id.context("open a chat first with Ctrl+N") {
            Ok(conversation_id) => {
                self.ui.prepare_client_action();
                self.client
                    .execute(
                        connection,
                        ClientCommand::SendMessage {
                            conversation_id,
                            text: self.input.clone(),
                            reply_to: self.reply_to.or(thread_root),
                            thread_root,
                        },
                    )
                    .await
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(()) => {
                self.input.clear();
                self.reply_to = None;
                let selected = self.selected;
                self.conversations[selected].scroll_back = 0;
                self.selected_messages.remove(&self.scope());
                self.ui.set_notice(
                    NoticeSeverity::Success,
                    NoticeScope::Composer,
                    "message sent",
                );
            }
            Err(error) => {
                self.ui.cancel_client_action();
                self.ui.set_notice(
                    NoticeSeverity::Error,
                    NoticeScope::Composer,
                    format!("error: {error}"),
                );
            }
        }
        self.handle_client_events();
    }

    async fn mark_current_read(&mut self, connection: Option<&Connection<'_>>) -> Result<()> {
        if self.demo {
            let selected = self.selected;
            let conversation = &mut self.conversations[selected];
            let active_thread = conversation.active_thread;
            for message in &mut conversation.messages {
                let visible = match active_thread {
                    Some(root) => message.id == root || message.thread_root == Some(root),
                    None => message.thread_root.is_none(),
                };
                if visible {
                    message.locally_read = true;
                }
            }
            conversation.unread = u16::try_from(
                conversation
                    .messages
                    .iter()
                    .filter(|message| !message.mine && !message.locally_read)
                    .count(),
            )
            .unwrap_or(u16::MAX);
            return Ok(());
        }
        let command = self
            .conversations
            .get(self.selected)
            .and_then(|conversation| {
                conversation
                    .conversation_id
                    .map(|conversation_id| (conversation_id, conversation.active_thread))
            })
            .map_or(
                ClientCommand::ClearVisibleConversation,
                |(conversation_id, thread_root)| ClientCommand::SetVisibleConversation {
                    conversation_id,
                    thread_root,
                },
            );
        self.execute(connection, command).await?;
        self.handle_client_events();
        Ok(())
    }

    fn observe_terminal_focus(&mut self, event: &Event) {
        match event {
            Event::FocusGained => self.window_focused = true,
            Event::FocusLost => {
                self.window_focused = false;
                let result = self.suspend_holds();
                self.personal_result(result);
            }
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                // Keyboard input is evidence of focus even if the terminal
                // omitted FocusGained. Observe this when reading events, not
                // when replaying queued keys after a later FocusLost.
                self.window_focused = true;
            }
            _ => {}
        }
    }

    pub async fn run(
        mut self,
        terminal: &mut DefaultTerminal,
        connection: Option<Connection<'_>>,
    ) -> Result<()> {
        let mut notification_surface = TerminalNotificationSurface::new()?;
        if let Some(connection) = connection {
            self.start(&connection).await?;
            self.handle_client_events();
        }
        self.update_visibility(connection.as_ref()).await;
        let mut event_notifications = connection
            .map(|connection| connection.api.events(connection.session))
            .transpose()?;
        let mut last_sync = Instant::now()
            .checked_sub(MAILBOX_FALLBACK_INTERVAL)
            .unwrap_or_else(Instant::now);
        let mut pending_events = VecDeque::new();
        while !self.should_quit {
            let now = Instant::now();
            self.ui.expire_notices(now);
            self.theme.refresh_if_due(now);
            notification_surface.update_badge(unread_total(&self.conversations))?;
            if self.notifications.take_alert(now) {
                tokio::spawn(notifications::alert(self.notifications.mode));
            }
            terminal.draw(|frame| self.draw(frame))?;
            if let Some(pending) = self.pending_attachment.take() {
                self.send_attachment_from_dialog(terminal, connection.as_ref(), pending)
                    .await?;
                continue;
            }
            if let Some(attachment_id) = self.pending_download.take() {
                self.download_attachment_from_dialog(terminal, connection.as_ref(), attachment_id)
                    .await?;
                continue;
            }
            let next_event = if let Some(event) = pending_events.pop_front() {
                Some(event)
            } else if event::poll(Duration::from_millis(200))? {
                let event = event::read()?;
                self.observe_terminal_focus(&event);
                Some(event)
            } else {
                None
            };
            if let Some(event) = next_event {
                match event {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        self.on_key(key, connection.as_ref()).await
                    }
                    Event::Mouse(mouse) => self.on_mouse(mouse, connection.as_ref()).await,
                    Event::FocusGained | Event::FocusLost => {
                        self.update_visibility(connection.as_ref()).await;
                    }
                    _ => {}
                }
            }
            if self.should_quit {
                break;
            }
            self.advance_holds(connection.as_ref()).await;
            let realtime_ready = event_notifications
                .as_mut()
                .is_some_and(|receiver| receiver.try_recv().is_ok());
            if let Some(connection) = connection
                && (realtime_ready || last_sync.elapsed() >= MAILBOX_FALLBACK_INTERVAL)
            {
                // Do not mark messages read using the focus state from before
                // a network fetch. Focus may change while it is in flight.
                let result = async {
                    self.execute(Some(&connection), ClientCommand::ClearVisibleConversation)
                        .await?;
                    self.last_visible = None;
                    self.synchronize(&connection).await
                }
                .await;
                while event::poll(Duration::ZERO)? {
                    let event = event::read()?;
                    self.observe_terminal_focus(&event);
                    match event {
                        Event::FocusGained | Event::FocusLost => {}
                        other => pending_events.push_back(other),
                    }
                }
                self.update_visibility(Some(&connection)).await;
                if let Err(error) = result {
                    self.ui.connection = ConnectionState::Unavailable;
                    self.ui.set_notice(
                        NoticeSeverity::Warning,
                        NoticeScope::Composer,
                        format!("mailbox unavailable: {error}"),
                    );
                }
                self.handle_client_events();
                last_sync = Instant::now();
            }
        }
        self.suspend_holds()?;
        Ok(())
    }

    async fn on_mouse(&mut self, mouse: MouseEvent, connection: Option<&Connection<'_>>) {
        let older = match mouse.kind {
            MouseEventKind::ScrollUp => true,
            MouseEventKind::ScrollDown => false,
            _ => return,
        };
        // Wheel navigation follows keyboard focus. It never activates an action,
        // changes the composer mode, or implies that the OS window gained focus.
        if self.personal_ui.panel.is_none() && self.ui.mode.is_composer() {
            let selected = self.selected;
            let current = self.conversations[selected].scroll_back;
            let next = self
                .transcript_viewports
                .borrow()
                .get(&self.scope())
                .map_or(current, |viewport| {
                    viewport.scroll_offset(current, older, 3)
                });
            self.conversations[selected].scroll_back = next;
            self.update_visibility(connection).await;
        } else {
            let key = if older { KeyCode::Up } else { KeyCode::Down };
            self.on_key(KeyEvent::new(key, KeyModifiers::NONE), connection)
                .await;
        }
    }

    async fn on_key(&mut self, key: KeyEvent, connection: Option<&Connection<'_>>) {
        self.handle_key(key, connection).await;
        self.update_visibility(connection).await;
    }

    async fn handle_key(&mut self, key: KeyEvent, connection: Option<&Connection<'_>>) {
        if self.handle_personal_key(key, connection).await {
            return;
        }
        self.ui.expire_notices(Instant::now());
        self.sync_draft_scope();
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        if self.ui.mode == UiMode::Attachments {
            self.handle_attachment_key(key);
            return;
        }
        if self.ui.mode == UiMode::AttachmentDetails {
            self.handle_attachment_details_key(key);
            return;
        }
        if self.ui.mode == UiMode::FilePreview {
            self.handle_file_preview_key(key);
            return;
        }
        if self.ui.mode == UiMode::Reactions {
            self.handle_reaction_key(key, connection).await;
            return;
        }
        if self.ui.mode == UiMode::Verification {
            match key.code {
                KeyCode::Esc => {
                    self.verification_panel = None;
                    self.ui.clear_notice_scope(NoticeScope::Overlay);
                    self.ui.focus_composer();
                }
                KeyCode::Char('v') => {
                    self.ui.prepare_client_action();
                    let result = self
                        .execute(connection, ClientCommand::ConfirmVerification)
                        .await;
                    if let Err(error) = result {
                        self.ui.cancel_client_action();
                        self.ui.set_notice(
                            NoticeSeverity::Error,
                            NoticeScope::Overlay,
                            format!("verification: {error}"),
                        );
                    }
                    self.handle_client_events();
                }
                _ => {}
            }
            return;
        }
        if self.ui.mode == UiMode::Devices {
            if key.code == KeyCode::Esc {
                self.device_panel = None;
                self.ui.clear_notice_scope(NoticeScope::Overlay);
                self.ui.focus_composer();
            }
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('o') {
            self.open_attachment_picker();
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('k') {
            if self.ui.mode == UiMode::Palette {
                self.ui.close_palette();
            } else {
                self.ui.open_palette();
            }
            self.palette_selection = 0;
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('n') {
            self.prepare_command("/dm ");
            return;
        }
        if self.ui.mode == UiMode::Palette {
            match key.code {
                KeyCode::Esc => self.ui.close_palette(),
                KeyCode::Up | KeyCode::Char('k') => {
                    self.palette_selection = self.palette_selection.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.palette_selection =
                        (self.palette_selection + 1).min(PALETTE_ENTRIES.len() - 1);
                }
                KeyCode::Home => self.palette_selection = 0,
                KeyCode::End => self.palette_selection = PALETTE_ENTRIES.len() - 1,
                KeyCode::Enter => {
                    let action = PALETTE_ENTRIES[self.palette_selection].action;
                    self.activate_palette_action(action, connection).await;
                }
                KeyCode::Char(shortcut) => {
                    if let Some(entry) = PALETTE_ENTRIES
                        .iter()
                        .find(|entry| entry.shortcut == shortcut.to_ascii_lowercase())
                    {
                        self.activate_palette_action(entry.action, connection).await;
                    }
                }
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Tab => self.focus(
                self.ui
                    .mode
                    .cycle(key.modifiers.contains(KeyModifiers::SHIFT)),
            ),
            KeyCode::BackTab => self.focus(self.ui.mode.cycle(true)),
            KeyCode::F(1) => self.focus(UiMode::Conversations),
            KeyCode::F(2) => self.focus(UiMode::Messages),
            KeyCode::F(3) => self.ui.focus_composer(),
            KeyCode::F(4) => self.focus(UiMode::Composer(ComposerMode::Command)),
            KeyCode::Left if self.ui.mode == UiMode::Messages => self.focus(UiMode::Conversations),
            KeyCode::Right | KeyCode::Enter if self.ui.mode == UiMode::Conversations => {
                self.focus(UiMode::Messages)
            }
            KeyCode::Esc if self.ui.mode == UiMode::Composer(ComposerMode::Command) => {
                self.command_input.clear();
                self.ui.focus_composer();
            }
            KeyCode::Esc
                if self.ui.mode == UiMode::Composer(ComposerMode::Message)
                    && self.reply_to.is_some() =>
            {
                self.reply_to = None;
            }
            KeyCode::Esc if self.ui.mode == UiMode::Messages && self.scope().1.is_some() => {
                self.change_thread(false, connection).await;
            }
            KeyCode::Esc if self.ui.notice_for(NoticeScope::Composer).is_some() => {
                self.ui.clear_notice_scope(NoticeScope::Composer);
            }
            KeyCode::Esc if self.ui.mode == UiMode::Conversations => {
                self.ui.focus_composer();
            }
            KeyCode::Esc if self.conversations[self.selected].active_thread.is_some() => {
                self.change_thread(false, connection).await;
            }
            KeyCode::Esc if self.ui.mode == UiMode::Messages => self.ui.focus_composer(),
            KeyCode::Up | KeyCode::Down | KeyCode::Home | KeyCode::End
                if self.ui.mode == UiMode::Conversations =>
            {
                self.selected = match key.code {
                    KeyCode::Up => self.selected.saturating_sub(1),
                    KeyCode::Down => {
                        (self.selected + 1).min(self.conversations.len().saturating_sub(1))
                    }
                    KeyCode::Home => 0,
                    _ => self.conversations.len().saturating_sub(1),
                };
                self.sync_draft_scope();
            }
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::PageUp
            | KeyCode::PageDown
                if self.ui.mode == UiMode::Messages =>
            {
                let delta = match key.code {
                    KeyCode::Up => -1,
                    KeyCode::Down => 1,
                    KeyCode::PageUp => -5,
                    KeyCode::PageDown => 5,
                    KeyCode::Home => isize::MIN,
                    _ => isize::MAX,
                };
                self.move_message_selection(delta);
            }
            KeyCode::Char('r' | 'R')
                if self.ui.mode == UiMode::Messages
                    && !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.reply_to_selected()
            }
            KeyCode::Char('t' | 'T')
                if self.ui.mode == UiMode::Messages
                    && !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.change_thread(true, connection).await
            }
            KeyCode::Char('o' | 'O')
                if self.ui.mode == UiMode::Messages
                    && !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.jump_to_original(connection).await
            }
            KeyCode::Char('a' | 'A')
                if self.ui.mode == UiMode::Messages
                    && !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.open_attachment_details()
            }
            KeyCode::Char('e' | 'E')
                if self.ui.mode == UiMode::Messages
                    && !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.open_reactions()
            }
            KeyCode::Enter | KeyCode::Right if self.ui.mode == UiMode::Messages => {
                self.ui.focus_composer()
            }
            KeyCode::Up if self.ui.mode == UiMode::Composer(ComposerMode::Message) => {
                self.focus(UiMode::Messages)
            }
            KeyCode::PageUp if self.ui.mode.is_composer() => {
                let selected = self.selected;
                self.conversations[selected].scroll_back =
                    self.conversations[selected].scroll_back.saturating_add(8);
            }
            KeyCode::PageDown if self.ui.mode.is_composer() => {
                let selected = self.selected;
                self.conversations[selected].scroll_back =
                    self.conversations[selected].scroll_back.saturating_sub(8);
            }
            KeyCode::Backspace if self.ui.mode.is_composer() => {
                self.active_input_mut().pop();
            }
            KeyCode::Char('u')
                if self.ui.mode.is_composer() && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.active_input_mut().clear()
            }
            KeyCode::Enter if self.ui.mode == UiMode::Composer(ComposerMode::Message) => {
                self.send_draft(connection).await
            }
            KeyCode::Enter if self.ui.mode == UiMode::Composer(ComposerMode::Command) => {
                self.submit_text(self.command_input.clone(), connection)
                    .await
            }
            KeyCode::Char(character)
                if self.ui.mode.is_composer() && !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                if character == '/'
                    && self.ui.mode == UiMode::Composer(ComposerMode::Message)
                    && self.input.is_empty()
                    && self.reply_to.is_none()
                {
                    self.prepare_command("/");
                } else {
                    self.active_input_mut().push(character);
                }
            }
            _ => {}
        }
    }

    fn prepare_command(&mut self, command: &str) {
        self.ui.close_palette();
        if self.command_input.trim().is_empty() || self.command_input == command {
            self.command_input = command.into();
        } else {
            self.ui.set_notice(
                NoticeSeverity::Warning,
                NoticeScope::Composer,
                "command draft kept · Ctrl+U clears it; message draft is safe",
            );
        }
        self.ui.mode = UiMode::Composer(ComposerMode::Command);
    }

    fn active_input_mut(&mut self) -> &mut String {
        if self.ui.mode == UiMode::Composer(ComposerMode::Command) {
            &mut self.command_input
        } else {
            &mut self.input
        }
    }

    async fn submit_text(&mut self, input: String, connection: Option<&Connection<'_>>) {
        self.run_text(input, connection, true).await;
    }

    async fn run_text(
        &mut self,
        input: String,
        connection: Option<&Connection<'_>>,
        clear_composer: bool,
    ) {
        if input.trim().is_empty() {
            return;
        }
        if !input.starts_with('/') {
            self.ui.set_notice(
                NoticeSeverity::Warning,
                NoticeScope::Composer,
                "Commands start with / · F3 returns to your message",
            );
            return;
        }
        if self.run_personal_command(&input, connection).await {
            return;
        }
        if let Some(handle) = input.trim().strip_prefix("/dm ")
            && let Err(error) = self.direct_conversation_index(handle)
            && error.is::<DirectConversationChoiceRequired>()
        {
            if clear_composer {
                self.command_input.clear();
            }
            self.ui.mode = UiMode::Conversations;
            self.ui.set_notice(
                NoticeSeverity::Warning,
                NoticeScope::Composer,
                "Separate histories share this handle. Choose with ↑↓, then Enter. Trust is unchanged.",
            );
            return;
        }
        let submitted_command = input.starts_with('/');
        self.ui.prepare_client_action();
        match self
            .execute(connection, ClientCommand::ExecuteText(input))
            .await
        {
            Ok(()) if clear_composer => {
                self.command_input.clear();
                self.ui.focus_composer();
                self.ui.set_notice(
                    NoticeSeverity::Success,
                    NoticeScope::Composer,
                    if submitted_command {
                        "action completed"
                    } else {
                        "message sent"
                    },
                );
            }
            Ok(()) => {}
            Err(error) => {
                self.ui.cancel_client_action();
                self.ui.set_notice(
                    NoticeSeverity::Error,
                    NoticeScope::Composer,
                    format!("error: {error}"),
                );
            }
        }
        self.handle_client_events();
    }

    async fn activate_palette_action(
        &mut self,
        action: PaletteAction,
        connection: Option<&Connection<'_>>,
    ) {
        self.ui.close_palette();
        match action {
            PaletteAction::PersonalHome => self.open_personal("home"),
            PaletteAction::Search => self.open_personal("search"),
            PaletteAction::Poll => self.open_personal("poll"),
            PaletteAction::Keepsakes => self.open_personal("keepsakes"),
            PaletteAction::Quiet => self.open_personal("preferences"),
            PaletteAction::Settings => self.open_personal("settings"),
            PaletteAction::Sending => self.open_personal("sending"),
            PaletteAction::NewChat => self.prepare_command("/dm "),
            PaletteAction::SendAttachment => self.open_attachment_picker(),
            PaletteAction::SyncDevice => self.prepare_command("/sync-device "),
            PaletteAction::Reply => self.reply_to_selected(),
            PaletteAction::React => self.open_reactions(),
            PaletteAction::Thread => self.change_thread(true, connection).await,
            PaletteAction::ReadReceipts => self.prepare_command("/read-receipts "),
            PaletteAction::Verify => self.run_text("/verify".into(), connection, false).await,
            PaletteAction::Devices => self.run_text("/devices".into(), connection, false).await,
            PaletteAction::Quit => self.should_quit = true,
        }
    }

    fn draw(&self, frame: &mut Frame) {
        let palette = self.theme.palette();
        frame.render_widget(
            Block::new().style(Style::default().bg(palette.bg)),
            frame.area(),
        );
        if frame.area().width < MINIMUM_WIDTH || frame.area().height < MINIMUM_HEIGHT {
            self.draw_resize_prompt(frame);
            return;
        }
        let vertical = Layout::vertical([
            Constraint::Length(self.header_height(frame.area())),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(frame.area());
        self.draw_top(frame, vertical[0]);
        if frame.area().width >= SIDEBAR_MINIMUM_WIDTH {
            let body = Layout::horizontal([Constraint::Length(31), Constraint::Min(50)])
                .split(vertical[1]);
            self.draw_sidebar(frame, body[0]);
            self.draw_conversation(frame, body[1]);
        } else {
            self.draw_conversation(frame, vertical[1]);
        }
        self.draw_footer(frame, vertical[2]);
        if frame.area().width < SIDEBAR_MINIMUM_WIDTH && self.ui.mode == UiMode::Conversations {
            self.draw_compact_conversation_switcher(frame);
        }
        if self.ui.mode == UiMode::Palette {
            self.draw_palette(frame);
        }
        if self.verification_panel.is_some() {
            self.draw_verification_panel(frame);
        }
        if self.device_panel.is_some() {
            self.draw_device_panel(frame);
        }
        if let Some(dialog) = &self.attachment_dialog {
            dialog.picker.draw(frame, &dialog.recipient, palette);
        }
        if let Some(details) = &self.attachment_details {
            draw_attachment_details(frame, details, palette);
        }
        if let Some(preview) = &self.file_preview {
            preview.draw(frame, palette);
        }
        if let Some(dialog) = &self.reaction_dialog {
            draw_reaction_dialog(
                frame,
                dialog,
                &self.conversations[self.selected].messages,
                palette,
            );
        }
        self.draw_personal(frame);
    }

    fn header_height(&self, area: Rect) -> u16 {
        if !self.monochrome && area.width >= SIDEBAR_MINIMUM_WIDTH && area.height >= 24 {
            wordmark::HEIGHT + 3
        } else {
            4
        }
    }

    fn draw_top(&self, frame: &mut Frame, area: Rect) {
        let palette = self.theme.palette();
        frame.render_widget(
            Block::new()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(palette.line_strong))
                .style(Style::default().bg(palette.bg)),
            area,
        );
        let content = Rect::new(
            area.x.saturating_add(2),
            area.y,
            area.width.saturating_sub(4),
            area.height.saturating_sub(1),
        );
        if content.width == 0 || content.height < 3 {
            return;
        }
        let show_wordmark = area.height >= wordmark::HEIGHT + 3;
        let rows = Layout::vertical([
            Constraint::Length(if show_wordmark { wordmark::HEIGHT } else { 1 }),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(content);
        let identity_row = if show_wordmark {
            wordmark::draw(
                frame,
                Rect::new(content.x, content.y, wordmark::WIDTH, wordmark::HEIGHT),
                palette,
            );
            Rect::new(
                rows[0].x + wordmark::WIDTH + 3,
                rows[0].y + wordmark::HEIGHT / 2,
                rows[0].width.saturating_sub(wordmark::WIDTH + 3),
                1,
            )
        } else {
            rows[0]
        };
        let right_width = if area.width >= 96 { 34 } else { 18 };
        let first_row = Layout::horizontal([Constraint::Min(18), Constraint::Length(right_width)])
            .split(identity_row);
        let status_row = Layout::horizontal([Constraint::Min(34), Constraint::Length(right_width)])
            .split(rows[2]);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    if show_wordmark { "" } else { "MUTTE  " },
                    Style::default().fg(palette.accent).bold(),
                ),
                Span::styled(
                    if unread_total(&self.conversations) > 0 {
                        format!("{} unread", unread_total(&self.conversations))
                    } else {
                        "All read".into()
                    },
                    Style::default().fg(palette.focus).bold(),
                ),
            ])),
            first_row[0],
        );
        frame.render_widget(
            Paragraph::new(Line::styled(
                truncate_text(&self.profile.display_name, usize::from(first_row[1].width)),
                Style::default().fg(palette.secondary),
            ))
            .alignment(Alignment::Right),
            first_row[1],
        );
        if let Some((count, at)) = self.notifications.toast
            && at.elapsed() < Duration::from_secs(8)
        {
            frame.render_widget(
                Paragraph::new(format!(
                    "New message{} · {count} received · F1 chats",
                    if count == 1 { "" } else { "s" }
                ))
                .style(Style::default().fg(palette.focus)),
                rows[1],
            );
        }
        if let Some(hold) = self
            .personal
            .holds
            .iter()
            .rev()
            .find(|h| h.phase == HoldPhase::Holding)
        {
            frame.render_widget(
                Paragraph::new(format!(
                    "Sending in {}s · Ctrl+Z Undo · F5 → Sending",
                    (hold.deadline - chrono::Utc::now()).num_seconds().max(0) + 1
                ))
                .style(Style::default().fg(palette.focus)),
                rows[1],
            );
        } else if !self.personal.holds.is_empty() {
            frame.render_widget(
                Paragraph::new(format!(
                    "{} saved drafts / send reviews · F5 → Sending",
                    self.personal.holds.len()
                ))
                .style(Style::default().fg(palette.focus)),
                rows[1],
            );
        }
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    "●  ",
                    Style::default().fg(severity_color(self.ui.connection.severity(), palette)),
                ),
                Span::styled(
                    self.ui.connection.label(),
                    Style::default().fg(palette.muted),
                ),
            ])),
            status_row[0],
        );
        let mode = if self.demo { "DEMO" } else { "E2EE" };
        let identity = if area.width >= 96 {
            format!("{mode}  ·  @{}", self.profile.handle)
        } else {
            mode.into()
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![Span::styled(
                identity,
                Style::default().fg(palette.text).bold(),
            )]))
            .alignment(Alignment::Right),
            status_row[1],
        );
    }

    fn draw_sidebar(&self, frame: &mut Frame, area: Rect) {
        let palette = self.theme.palette();
        let content_width = usize::from(area.width.saturating_sub(2)).max(1);
        let rows = self.conversations.iter().enumerate().map(|(index, chat)| {
            let selected = index == self.selected;
            let row_style = if selected {
                Style::default().bg(palette.selected)
            } else {
                Style::default()
            };
            let marker = if selected { "▌" } else { " " };
            let unread = if chat.unread > 0 {
                chat.unread.to_string()
            } else {
                String::new()
            };
            let (verification, verification_color) =
                compact_verification_label(chat.verification, palette);
            let name_width = content_width.saturating_sub(unread.chars().count() + 4);
            let heading = format!("{marker}  {}", truncate_text(&chat.name, name_width));
            let heading_padding = " ".repeat(
                content_width.saturating_sub(heading.chars().count() + unread.chars().count()),
            );
            let presence = format!("   {}", self.conversation_context(chat));
            let mut preview = wrap_message_body(&last_message_preview(chat), content_width);
            let preview_truncated = preview.len() > 2;
            preview.truncate(2);
            preview.resize(2, String::new());
            if preview_truncated {
                let continuation = format!("{}…", preview[1].trim_end());
                preview[1] = truncate_text(&continuation, content_width);
            }
            ListItem::new(
                Text::from(vec![
                    Line::from(vec![
                        Span::styled(heading, Style::default().fg(palette.text).bold()),
                        Span::raw(heading_padding),
                        Span::styled(unread, Style::default().fg(palette.focus).bold()),
                    ]),
                    Line::styled(
                        pad_to_width(&presence, content_width),
                        Style::default().fg(if selected {
                            palette.accent
                        } else {
                            palette.muted
                        }),
                    ),
                    Line::styled(
                        pad_to_width(&preview[0], content_width),
                        Style::default().fg(palette.secondary),
                    ),
                    Line::styled(
                        pad_to_width(&preview[1], content_width),
                        Style::default().fg(palette.secondary),
                    ),
                    Line::styled(
                        pad_to_width(&format!("   {verification}"), content_width),
                        Style::default().fg(verification_color),
                    ),
                    Line::raw(" ".repeat(content_width)),
                ])
                .style(row_style),
            )
            .style(row_style)
        });
        let title = Line::from(vec![
            Span::styled(" Conversations ", Style::default().fg(palette.secondary)),
            Span::styled(
                format!("{} ", self.conversations.len()),
                Style::default().fg(palette.text),
            ),
        ]);
        let border_color = if self.ui.mode == UiMode::Conversations {
            palette.focus
        } else {
            palette.line
        };
        frame.render_stateful_widget(
            List::new(rows)
                .block(
                    Block::new()
                        .title(title)
                        .borders(Borders::RIGHT)
                        .border_style(Style::default().fg(border_color))
                        .padding(Padding::top(1)),
                )
                .style(Style::default().bg(palette.bg)),
            area,
            &mut ListState::default().with_selected(Some(self.selected)),
        );
    }

    fn conversation_context(&self, chat: &ConversationSnapshot) -> String {
        if let Some(id) = chat.conversation_id
            && self
                .conversations
                .iter()
                .filter(|other| {
                    other.conversation_id.is_some()
                        && other.handle.eq_ignore_ascii_case(&chat.handle)
                })
                .count()
                > 1
        {
            return format!("Conversation #{}", &id.simple().to_string()[..8]);
        }
        format!(
            "{} · {}",
            display_handle(&chat.handle),
            clean_presence(&chat.status)
        )
    }

    fn draw_conversation(&self, frame: &mut Frame, area: Rect) {
        let palette = self.theme.palette();
        let parts = Layout::vertical([
            Constraint::Length(4),
            Constraint::Min(5),
            Constraint::Length(6),
        ])
        .split(area);
        let chat = &self.conversations[self.selected];
        let (verification, verification_color) =
            header_verification_label(chat.verification, palette);
        frame.render_widget(
            Block::new()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(palette.line))
                .style(Style::default().bg(palette.bg)),
            parts[0],
        );
        let header_area = parts[0].inner(Margin {
            horizontal: 2,
            vertical: 0,
        });
        let right_width = if parts[0].width >= 72 { 25 } else { 20 };
        let header_columns =
            Layout::horizontal([Constraint::Min(20), Constraint::Length(right_width)])
                .split(header_area);
        let context: Cow<'_, str> = chat.active_thread.map_or_else(
            || Cow::Borrowed(clean_presence(&chat.status)),
            |_| Cow::Borrowed("Thread view"),
        );
        frame.render_widget(
            Paragraph::new(Text::from(vec![
                Line::styled(&chat.name, Style::default().fg(palette.text).bold()),
                Line::from(vec![
                    Span::styled("● ", Style::default().fg(palette.success).bold()),
                    Span::styled(
                        display_handle(&chat.handle),
                        Style::default().fg(palette.accent),
                    ),
                    Span::styled(
                        format!("  ·  {context}"),
                        Style::default().fg(palette.muted),
                    ),
                ]),
            ])),
            header_columns[0],
        );
        let navigation_hint = if chat.active_thread.is_some() {
            "Esc closes thread"
        } else if chat.scroll_back > 0
            || (self.ui.mode == UiMode::Messages
                && self.selected_message().map(|message| message.id)
                    != self
                        .visible_messages()
                        .next_back()
                        .map(|message| message.id))
        {
            if self.ui.mode == UiMode::Messages {
                "End: latest"
            } else {
                "F2 then End: latest"
            }
        } else if chat.verification == VerificationState::NotApplicable {
            "Local only"
        } else {
            "End-to-end encrypted"
        };
        let sending_blocked = matches!(
            chat.verification,
            VerificationState::Changed | VerificationState::Unavailable
        );
        let detail = if sending_blocked {
            Line::styled(
                "Sending blocked",
                Style::default().fg(verification_color).bold(),
            )
        } else {
            Line::styled(navigation_hint, Style::default().fg(palette.muted))
        };
        let shortcut = if chat.verification == VerificationState::NotApplicable {
            ""
        } else {
            "Ctrl+K then V"
        };
        frame.render_widget(
            Paragraph::new(Text::from(vec![
                Line::styled(verification, Style::default().fg(verification_color).bold())
                    .right_aligned(),
                detail.right_aligned(),
                Line::styled(shortcut, Style::default().fg(palette.muted)).right_aligned(),
            ])),
            header_columns[1],
        );
        let message_width = parts[1].width.saturating_sub(6).clamp(1, LANE_MAX_WIDTH);
        let show_message_references = self.ui.mode == UiMode::Composer(ComposerMode::Command)
            && matches!(
                self.command_input.split_whitespace().next(),
                Some("/reply" | "/thread")
            );
        let messages_by_id = chat
            .messages
            .iter()
            .map(|message| (message.id, message))
            .collect::<HashMap<_, _>>();
        let mut message_area = centered_width(parts[1], message_width).inner(Margin {
            horizontal: 0,
            vertical: 1,
        });
        let selected_id = (self.ui.mode == UiMode::Messages)
            .then(|| self.selected_message().map(|message| message.id))
            .flatten();
        let transcript = Transcript::new(
            chat,
            message_area.width,
            palette,
            LayoutOptions {
                references: show_message_references,
                explicit_ownership: self.monochrome,
            },
        );
        // Short histories rest above the composer, just like a messaging app.
        // This offset is independent of focus/selection and never changes IDs.
        if !chat.messages.is_empty() && transcript.height() < usize::from(message_area.height) {
            let extra = message_area.height - transcript.height() as u16;
            message_area.y += extra;
            message_area.height -= extra;
        }
        let top = self
            .transcript_viewports
            .borrow_mut()
            .entry(self.scope())
            .or_default()
            .position(
                &transcript,
                message_area.height,
                selected_id,
                chat.scroll_back,
            );
        transcript.render(frame, message_area, top, selected_id, palette);
        let pane_label = if let Some(author) = transcript.continued_author(top) {
            format!(" Messages · {author} (continued)")
        } else if self.ui.mode == UiMode::Messages {
            " Messages · End: latest ".into()
        } else {
            " Messages · F2 select ".into()
        };
        frame.render_widget(
            Paragraph::new(truncate_cells(&pane_label, usize::from(message_area.width))).style(
                Style::default().fg(if self.ui.mode == UiMode::Messages {
                    palette.focus
                } else {
                    palette.muted
                }),
            ),
            Rect::new(message_area.x, parts[1].y, message_area.width, 1),
        );
        let composer_area = centered_width(
            parts[2],
            parts[2].width.saturating_sub(6).clamp(1, LANE_MAX_WIDTH),
        );
        let composer_width = usize::from(composer_area.width.saturating_sub(8)).max(1);
        let command_mode = self.ui.mode == UiMode::Composer(ComposerMode::Command);
        let input = if command_mode {
            &self.command_input
        } else {
            &self.input
        };
        let input_characters = input.chars().count();
        let prompt = if input.is_empty() {
            if command_mode {
                Cow::Borrowed("/command…")
            } else if chat.active_thread.is_some() {
                Cow::Borrowed("Reply in this thread…")
            } else {
                Cow::Owned(format!(
                    "Message {}…",
                    composer_recipient(&chat.name, &chat.handle)
                ))
            }
        } else if input_characters <= composer_width {
            Cow::Borrowed(input.as_str())
        } else {
            Cow::Owned(format!(
                "…{}",
                input
                    .chars()
                    .skip(input_characters - composer_width.saturating_sub(1))
                    .collect::<String>()
            ))
        };
        let color = if input.is_empty() {
            palette.muted
        } else {
            palette.text
        };
        let composer_title = if command_mode {
            " COMMAND MODE · F3 message "
        } else if chat.active_thread.is_some() {
            " THREAD MODE · F4 command "
        } else {
            " MESSAGE MODE · F4 command "
        };
        let action_hint = if self.ui.mode == UiMode::Messages
            && self
                .selected_message()
                .is_some_and(|message| message.attachment.is_some())
        {
            " A file · E react · R reply · Enter write "
        } else if self.ui.mode == UiMode::Messages && chat.active_thread.is_some() {
            " E react · R reply · Esc back · Enter write "
        } else if self.ui.mode == UiMode::Messages {
            " E react · R reply · T thread · Enter write "
        } else if command_mode {
            " Enter run · Esc cancel · Ctrl+K actions "
        } else if composer_area.width >= 66 {
            " Enter send · Ctrl+O attach · Ctrl+K actions "
        } else {
            " Enter send · Ctrl+O attach "
        };
        let contextual_notice = self.ui.notice_for(NoticeScope::Composer);
        let composer_hint = contextual_notice.map_or(action_hint, |notice| notice.message.as_str());
        let composer_hint_color = contextual_notice
            .map(|notice| severity_color(notice.severity, palette))
            .unwrap_or(palette.muted);
        let composer_border = if self.ui.mode.is_composer() {
            palette.accent
        } else {
            palette.line
        };
        let mut composer_lines = vec![Line::from(vec![
            Span::styled("› ", Style::default().fg(palette.accent).bold()),
            Span::styled(prompt.as_ref(), Style::default().fg(color)),
        ])];
        if self.ui.mode == UiMode::Messages
            && let Some(message) = self.selected_message()
        {
            let details = format!(
                "{} · {} · {}",
                if message.mine { "You" } else { &message.author },
                message.timestamp.format("%b %-d %H:%M"),
                delivery_label(message.delivery)
            );
            composer_lines.extend(
                wrap_cells(&details, composer_width)
                    .into_iter()
                    .take(2)
                    .map(|line| Line::styled(line, Style::default().fg(palette.secondary))),
            );
        } else if !command_mode && let Some(reply_to) = self.reply_to {
            let preview = messages_by_id.get(&reply_to).map_or_else(
                || "Replying · original unavailable".into(),
                |target| {
                    format!(
                        "↪ {}: {}",
                        target.author,
                        target.text.split_whitespace().collect::<Vec<_>>().join(" ")
                    )
                },
            );
            composer_lines.push(Line::styled(
                truncate_cells(&preview, composer_width),
                Style::default().fg(palette.focus),
            ));
            composer_lines.push(Line::styled(
                "Esc cancels reply · draft kept",
                Style::default().fg(palette.muted),
            ));
        } else if command_mode && !self.input.is_empty() {
            composer_lines.push(Line::styled(
                "Message draft saved · F3 returns to it",
                Style::default().fg(palette.muted),
            ));
        }
        let composer = Paragraph::new(composer_lines)
            .block(
                Block::new()
                    .title(Line::styled(
                        composer_title,
                        Style::default().fg(palette.accent).bold(),
                    ))
                    .title_bottom(
                        Line::styled(composer_hint, Style::default().fg(composer_hint_color))
                            .right_aligned(),
                    )
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(composer_border))
                    .padding(Padding::new(1, 1, 1, 0)),
            )
            .style(Style::default().bg(palette.panel));
        frame.render_widget(composer, composer_area);
        let cursor_characters = if input.is_empty() {
            0
        } else {
            Line::raw(prompt.as_ref()).width()
        };
        if self.ui.mode.is_composer() && self.personal_ui.panel.is_none() {
            let cursor_x = composer_area
                .x
                .saturating_add(4)
                .saturating_add(u16::try_from(cursor_characters).unwrap_or(u16::MAX))
                .min(composer_area.right().saturating_sub(3));
            frame.set_cursor_position((cursor_x, composer_area.y + 2));
        }
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let palette = self.theme.palette();
        let block = Block::new()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(palette.line_strong))
            .style(Style::default().bg(palette.bg));
        let content = block.inner(area);
        frame.render_widget(block, area);
        let hints = match self.ui.mode {
            UiMode::Messages => vec![Span::styled(
                if self
                    .selected_message()
                    .is_some_and(|message| PollState::fold(message, &[]).is_some())
                {
                    " ↑↓ · P vote/results · R reply · T thread · F5 home"
                } else if self
                    .selected_message()
                    .is_some_and(|message| message.attachment.is_some())
                {
                    " ↑↓ · A file · E react · R reply · Enter write"
                } else if self.scope().1.is_some() {
                    " ↑↓ · E react · R reply · O original · Esc back"
                } else if self
                    .selected_message()
                    .is_some_and(|message| message.reply_to.is_some())
                {
                    " ↑↓ · E react · R reply · T thread · O original"
                } else {
                    " ↑↓ · E react · R reply · T thread · Enter write"
                },
                Style::default().fg(palette.focus),
            )],
            UiMode::Conversations => vec![
                Span::styled(
                    " ↑↓ ",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(" navigate  ·  ", Style::default().fg(palette.muted)),
                Span::styled(
                    " Enter ",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(" open  ·  ", Style::default().fg(palette.muted)),
                Span::styled(
                    " Tab ",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(" messages", Style::default().fg(palette.muted)),
            ],
            UiMode::Composer(_) => vec![Span::styled(
                if area.width < 88 {
                    " F5 home · F6 search · Ctrl+K actions · Tab focus"
                } else {
                    " F5 home · F6 search · Ctrl+K actions · F1 chats · F2 messages · F3 write · F4 command"
                },
                Style::default().fg(palette.muted),
            )],
            UiMode::Palette => vec![
                Span::styled(
                    " ↑↓ ",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(" move  ·  ", Style::default().fg(palette.muted)),
                Span::styled(
                    " Enter ",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(" select  ·  ", Style::default().fg(palette.muted)),
                Span::styled(
                    " Esc ",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(" close", Style::default().fg(palette.muted)),
            ],
            UiMode::Verification
            | UiMode::Devices
            | UiMode::Attachments
            | UiMode::AttachmentDetails
            | UiMode::FilePreview
            | UiMode::Reactions => vec![
                Span::styled(
                    " Esc ",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(" close", Style::default().fg(palette.muted)),
            ],
        };
        frame.render_widget(Paragraph::new(Line::from(hints)), content);
    }

    fn draw_palette(&self, frame: &mut Frame) {
        let palette = self.theme.palette();
        let area = centered(78, 18, frame.area());
        frame.render_widget(Clear, area);
        let mut body = vec![
            Line::styled(
                "Everything you can do, without memorizing slash commands.",
                Style::default().fg(palette.muted),
            ),
            Line::raw(""),
        ];
        for (index, entry) in PALETTE_ENTRIES.iter().enumerate() {
            let selected = index == self.palette_selection;
            let accent = match index % 3 {
                0 => palette.accent,
                1 => palette.focus,
                _ => palette.secondary,
            };
            let mut spans = vec![
                Span::styled(
                    if selected { " ▌ " } else { "   " },
                    Style::default().fg(accent),
                ),
                Span::styled(
                    format!(" {} ", entry.shortcut.to_ascii_uppercase()),
                    Style::default()
                        .fg(palette.contrasting_text(accent))
                        .bg(accent)
                        .bold(),
                ),
                Span::styled(
                    format!("  {:<28}", entry.label),
                    Style::default().fg(palette.text).bold(),
                ),
            ];
            if area.width >= 72 {
                spans.push(Span::styled(
                    truncate_text(entry.detail, 36),
                    Style::default().fg(palette.muted),
                ));
            }
            let mut line = Line::from(spans);
            if selected {
                line = line.style(Style::default().bg(palette.selected));
            }
            body.push(line);
        }
        frame.render_widget(
            Paragraph::new(Text::from(body))
                .scroll((
                    u16::try_from(self.palette_selection + 3)
                        .unwrap_or(u16::MAX)
                        .saturating_sub(area.height.saturating_sub(6)),
                    0,
                ))
                .block(
                    Block::new()
                        .title(Line::styled(
                            " Actions ",
                            Style::default().fg(palette.focus).bold(),
                        ))
                        .title_bottom(
                            Line::styled(
                                " ↑↓ move · Enter select · letter shortcut · Esc close ",
                                Style::default().fg(palette.muted),
                            )
                            .right_aligned(),
                        )
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(palette.focus))
                        .padding(Padding::uniform(2)),
                )
                .style(Style::default().bg(palette.panel)),
            area,
        );
    }

    fn draw_compact_conversation_switcher(&self, frame: &mut Frame) {
        let palette = self.theme.palette();
        let height = self
            .conversations
            .len()
            .saturating_mul(3)
            .saturating_add(5)
            .min(22) as u16;
        let area = centered(48, height, frame.area());
        frame.render_widget(Clear, area);
        let rows = self.conversations.iter().enumerate().map(|(index, chat)| {
            let selected = index == self.selected;
            let unread = if chat.unread > 0 {
                format!("  {} new", chat.unread)
            } else {
                String::new()
            };
            ListItem::new(Text::from(vec![
                Line::from(vec![
                    Span::styled(
                        if selected { "▌  " } else { "   " },
                        Style::default().fg(palette.focus),
                    ),
                    Span::styled(&chat.name, Style::default().fg(palette.text).bold()),
                    Span::styled(unread, Style::default().fg(palette.accent).bold()),
                ]),
                Line::styled(
                    format!("   {}", self.conversation_context(chat)),
                    Style::default().fg(palette.muted),
                ),
                Line::styled(
                    format!("   {}", truncate_text(&last_message_preview(chat), 40)),
                    Style::default().fg(palette.secondary),
                ),
            ]))
            .style(if selected {
                Style::default().bg(palette.selected)
            } else {
                Style::default()
            })
        });
        frame.render_stateful_widget(
            List::new(rows)
                .block(
                    Block::new()
                        .title(Line::styled(
                            " Switch conversation ",
                            Style::default().fg(palette.focus).bold(),
                        ))
                        .title_bottom(
                            Line::styled(
                                " ↑↓ move · Enter open · Esc close ",
                                Style::default().fg(palette.muted),
                            )
                            .right_aligned(),
                        )
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(palette.focus))
                        .padding(Padding::uniform(1)),
                )
                .style(Style::default().bg(palette.panel)),
            area,
            &mut ListState::default().with_selected(Some(self.selected)),
        );
    }

    fn draw_resize_prompt(&self, frame: &mut Frame) {
        let palette = self.theme.palette();
        let area = centered(48, 10, frame.area());
        frame.render_widget(Clear, area);
        let body = Text::from(vec![
            Line::styled("MUTTE", Style::default().fg(palette.focus).bold()).centered(),
            Line::raw(""),
            Line::styled(
                "A little more room, please",
                Style::default().fg(palette.text).bold(),
            )
            .centered(),
            Line::styled(
                format!(
                    "Resize to at least {MINIMUM_WIDTH}×{MINIMUM_HEIGHT} · now {}×{}",
                    frame.area().width,
                    frame.area().height
                ),
                Style::default().fg(palette.muted),
            )
            .centered(),
            Line::raw(""),
            Line::styled("Ctrl+C quits", Style::default().fg(palette.muted)).centered(),
        ]);
        frame.render_widget(
            Paragraph::new(body)
                .block(
                    Block::new()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(palette.line))
                        .padding(Padding::uniform(1)),
                )
                .style(Style::default().bg(palette.panel)),
            area,
        );
    }

    fn draw_verification_panel(&self, frame: &mut Frame) {
        let palette = self.theme.palette();
        let Some(panel) = &self.verification_panel else {
            return;
        };
        let area = centered(74, 21, frame.area());
        frame.render_widget(Clear, area);
        let (state, state_color) = verification_label(panel.state, palette);
        let mut lines = vec![
            Line::from(vec![
                Span::styled("SAFETY CODE", Style::default().fg(palette.focus).bold()),
                Span::styled(
                    format!("   @{}", panel.peer_handle),
                    Style::default().fg(palette.text).bold(),
                ),
            ]),
            Line::styled(state, Style::default().fg(state_color).bold()),
            Line::raw(""),
        ];
        for row in safety_code_rows(&panel.fingerprint) {
            lines.push(Line::styled(row, Style::default().fg(palette.text).bold()));
        }
        lines.extend([
            Line::raw(""),
            Line::styled(
                format!(
                    "Fingerprints {} authenticated MLS device signing keys.",
                    panel.member_count
                ),
                Style::default().fg(palette.muted),
            ),
            Line::styled(
                "Compare every group in person, by video, or through another trusted channel.",
                Style::default().fg(palette.muted),
            ),
            Line::styled(
                "This confirms matching endpoints; it does not prove a real-world identity.",
                Style::default().fg(palette.warning),
            ),
        ]);
        if let Some(notice) = self.ui.notice_for(NoticeScope::Overlay) {
            lines.push(Line::styled(
                &notice.message,
                Style::default().fg(severity_color(notice.severity, palette)),
            ));
        }
        lines.extend([
            Line::raw(""),
            Line::from(vec![
                Span::styled(
                    " V ",
                    Style::default()
                        .fg(palette.contrasting_text(palette.accent_fill))
                        .bg(palette.accent_fill)
                        .bold(),
                ),
                Span::styled(
                    " mark compared + verified   ",
                    Style::default().fg(palette.text),
                ),
                Span::styled(
                    " Esc ",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(" close", Style::default().fg(palette.muted)),
            ]),
        ]);
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .block(
                    Block::new()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(state_color))
                        .padding(Padding::uniform(2)),
                )
                .style(Style::default().bg(palette.panel)),
            area,
        );
    }

    fn draw_device_panel(&self, frame: &mut Frame) {
        let palette = self.theme.palette();
        let Some(panel) = &self.device_panel else {
            return;
        };
        let height = (12 + panel.devices.len() as u16 * 3).min(30);
        let area = centered(78, height, frame.area());
        frame.render_widget(Clear, area);
        let mut lines = vec![
            Line::styled("ACCOUNT DEVICES", Style::default().fg(palette.focus).bold()),
            Line::styled(
                "Sync adds an active device to local chats. Removal requires step-up approval.",
                Style::default().fg(palette.muted),
            ),
            Line::raw(""),
        ];
        for device in &panel.devices {
            let short_id = device.device_id.simple().to_string()[..8].to_ascii_uppercase();
            let (state, color) = if device.current {
                ("CURRENT", palette.accent)
            } else {
                match device.state {
                    AccountDeviceState::Active => ("ACTIVE", palette.secondary),
                    AccountDeviceState::Revoked => ("REVOKED", palette.muted),
                }
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {short_id} "),
                    Style::default()
                        .fg(palette.contrasting_text(color))
                        .bg(color)
                        .bold(),
                ),
                Span::styled(
                    format!("  {}", device.device_name),
                    Style::default().fg(palette.text).bold(),
                ),
                Span::styled(format!("  {state}"), Style::default().fg(color).bold()),
            ]));
            lines.push(Line::styled(
                format!(
                    "          linked {}",
                    device.created_at.format("%Y-%m-%d %H:%M UTC")
                ),
                Style::default().fg(palette.muted),
            ));
            lines.push(Line::raw(""));
        }
        lines.extend([Line::styled(
            &panel.status,
            Style::default().fg(palette.warning),
        )]);
        if let Some(notice) = self.ui.notice_for(NoticeScope::Overlay) {
            lines.push(Line::styled(
                &notice.message,
                Style::default().fg(severity_color(notice.severity, palette)),
            ));
        }
        lines.extend([
            Line::raw(""),
            Line::styled("Esc  close", Style::default().fg(palette.muted)),
        ]);
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .block(
                    Block::new()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(palette.focus))
                        .padding(Padding::uniform(2)),
                )
                .style(Style::default().bg(palette.panel)),
            area,
        );
    }
}

fn verification_label(state: VerificationState, palette: ThemePalette) -> (&'static str, Color) {
    match state {
        VerificationState::NotApplicable => ("◈ local", palette.muted),
        VerificationState::Unverified => ("◇ safety code unverified", palette.warning),
        VerificationState::Verified => ("✓ safety code verified", palette.success),
        VerificationState::Changed => ("⚠ DEVICE KEYS CHANGED", palette.danger),
        VerificationState::Unavailable => ("⚠ key status unavailable", palette.warning),
    }
}

fn compact_verification_label(
    state: VerificationState,
    palette: ThemePalette,
) -> (&'static str, Color) {
    match state {
        VerificationState::NotApplicable => ("◈ Local conversation", palette.muted),
        VerificationState::Unverified => ("◇ Safety check needed", palette.warning),
        VerificationState::Verified => ("✓ Identity verified", palette.success),
        VerificationState::Changed => ("⚠ Device keys changed", palette.danger),
        VerificationState::Unavailable => ("⚠ Safety status unavailable", palette.warning),
    }
}

fn header_verification_label(
    state: VerificationState,
    palette: ThemePalette,
) -> (&'static str, Color) {
    match state {
        VerificationState::NotApplicable => ("◈ Local", palette.muted),
        VerificationState::Unverified => ("◇ Verify identity", palette.warning),
        VerificationState::Verified => ("✓ Verified", palette.success),
        VerificationState::Changed => ("⚠ Keys changed", palette.danger),
        VerificationState::Unavailable => ("⚠ Check unavailable", palette.warning),
    }
}

fn draw_attachment_details(frame: &mut Frame, details: &AttachmentDetails, palette: ThemePalette) {
    let Some(attachment) = &details.message.attachment else {
        return;
    };
    let area = modal_area(frame.area(), 78, 24);
    frame.render_widget(Clear, area);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(" Attachment ")
        .border_style(Style::default().fg(palette.focus))
        .style(Style::default().bg(palette.panel))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(2),
        Constraint::Length(2),
    ])
    .split(inner);
    let mut lines = wrap_cells(&attachment.metadata.filename, inner.width as usize)
        .into_iter()
        .map(|line| Line::styled(line, Style::default().fg(palette.text).bold()))
        .collect::<Vec<_>>();
    lines.push(Line::styled(
        format_bytes(attachment.metadata.plaintext_size),
        Style::default().fg(palette.secondary),
    ));
    lines.push(Line::default());
    let status = if attachment.local_path.is_some() {
        if details.message.mine {
            "Local source file"
        } else {
            "Downloaded and verified"
        }
    } else if attachment.download_requested {
        "Download queued · retries when connected"
    } else {
        "Encrypted file · not downloaded"
    };
    lines.push(Line::styled(status, Style::default().fg(palette.accent)));
    let explanation = if let Some(path) = &attachment.local_path {
        format!(
            "{}\n\nFiles are never opened automatically.",
            path.display()
        )
    } else {
        "Download to Mutte's private folder. The file is decrypted locally and verified before it is made available. Files are never opened automatically.".into()
    };
    lines.extend(
        wrap_cells(&explanation, inner.width as usize)
            .into_iter()
            .map(|line| Line::styled(line, Style::default().fg(palette.muted))),
    );
    let max_scroll = lines
        .len()
        .saturating_sub(rows[0].height as usize)
        .min(u16::MAX as usize) as u16;
    frame.render_widget(
        Paragraph::new(lines).scroll((details.scroll.min(max_scroll), 0)),
        rows[0],
    );
    if let Some(error) = &details.error {
        frame.render_widget(
            Paragraph::new(error.as_str())
                .wrap(Wrap { trim: false })
                .style(Style::default().fg(palette.danger)),
            rows[1],
        );
    }
    let action = if attachment.local_path.is_some() {
        "P preview · Esc close"
    } else {
        "Enter / D download · Esc cancel"
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(action, Style::default().fg(palette.focus)),
            Line::styled(
                "↑↓ scroll details · your draft is kept",
                Style::default().fg(palette.muted),
            ),
        ]),
        rows[2],
    );
}

fn draw_reaction_dialog(
    frame: &mut Frame,
    dialog: &ReactionDialog,
    messages: &[MessageSnapshot],
    palette: ThemePalette,
) {
    let area = modal_area(frame.area(), 58, 13);
    frame.render_widget(Clear, area);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(" React to message ")
        .border_style(Style::default().fg(palette.focus))
        .style(Style::default().bg(palette.panel))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(2),
        Constraint::Length(2),
    ])
    .split(inner);
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("Message", Style::default().fg(palette.muted)),
            Line::styled(
                truncate_cells(&dialog.target_preview, rows[0].width as usize),
                Style::default().fg(palette.text),
            ),
        ]),
        rows[0],
    );
    let current = reactions_for(messages, dialog.message_id);
    let mut lines = Vec::new();
    for row in 0..2 {
        let mut spans = Vec::new();
        for (index, emoji) in QUICK_REACTIONS.iter().enumerate().skip(row * 3).take(3) {
            let emoji = *emoji;
            let mine = current
                .iter()
                .any(|reaction| reaction.emoji == emoji && reaction.mine);
            let selected = dialog.selected == index;
            spans.push(Span::styled(
                format!(" {} {emoji}{} ", index + 1, if mine { " ●" } else { "" }),
                Style::default()
                    .fg(if mine || selected {
                        palette.focus
                    } else {
                        palette.text
                    })
                    .bg(if selected {
                        palette.selected
                    } else {
                        palette.panel
                    })
                    .bold(),
            ));
            spans.push(Span::raw(" "));
        }
        lines.push(Line::from(spans));
    }
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), rows[1]);
    if let Some(error) = &dialog.error {
        frame.render_widget(
            Paragraph::new(error.as_str())
                .style(Style::default().fg(palette.danger))
                .wrap(Wrap { trim: false }),
            rows[2],
        );
    } else {
        frame.render_widget(
            Paragraph::new("● means you reacted · choose it again to remove")
                .style(Style::default().fg(palette.muted))
                .alignment(Alignment::Center),
            rows[2],
        );
    }
    frame.render_widget(
        Paragraph::new("← → choose · Enter toggle · Esc cancel")
            .style(Style::default().fg(palette.focus))
            .alignment(Alignment::Center),
        rows[3],
    );
}

fn draw_attachment_transfer(
    frame: &mut Frame,
    transfer: &AttachmentTransfer,
    elapsed: Duration,
    palette: ThemePalette,
) {
    frame.render_widget(
        Block::new().style(Style::default().bg(palette.bg)),
        frame.area(),
    );
    let area = modal_area(frame.area(), 70, 16);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(if transfer.downloading {
            " Downloading attachment "
        } else {
            " Sending attachment "
        })
        .border_style(Style::default().fg(palette.focus))
        .style(Style::default().bg(palette.panel))
        .padding(Padding::uniform(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        [(elapsed.as_millis() / 100 % 10) as usize];
    let mut lines = vec![
        Line::styled(
            truncate_cells(&transfer.context, inner.width as usize),
            Style::default().fg(palette.accent),
        ),
        Line::default(),
    ];
    lines.extend(
        wrap_cells(&transfer.filename, inner.width as usize)
            .into_iter()
            .take(3)
            .map(|line| Line::styled(line, Style::default().fg(palette.text).bold())),
    );
    lines.push(Line::styled(
        format_bytes(transfer.bytes),
        Style::default().fg(palette.secondary),
    ));
    lines.push(Line::default());
    lines.push(Line::styled(
        format!(
            "{spinner} {} · {}s",
            if transfer.downloading {
                "Downloading / verifying"
            } else {
                "Encrypting / uploading"
            },
            elapsed.as_secs()
        ),
        Style::default().fg(palette.focus),
    ));
    lines.push(Line::styled(
        "Your message draft is kept.",
        Style::default().fg(palette.muted),
    ));
    lines.push(Line::styled(
        "Ctrl+C quits; queued transfers resume next launch.",
        Style::default().fg(palette.muted),
    ));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn severity_color(severity: NoticeSeverity, palette: ThemePalette) -> Color {
    match severity {
        NoticeSeverity::Info => palette.secondary,
        NoticeSeverity::Success => palette.success,
        NoticeSeverity::Warning => palette.warning,
        NoticeSeverity::Error => palette.danger,
    }
}

fn display_handle(handle: &str) -> String {
    if handle.chars().any(char::is_whitespace) {
        handle.into()
    } else {
        format!("@{handle}")
    }
}

fn clean_presence(status: &str) -> &str {
    status.trim_start_matches(|character: char| {
        character.is_whitespace() || matches!(character, '●' | '◈' | '◇')
    })
}

fn last_message_preview(chat: &ConversationSnapshot) -> String {
    chat.messages
        .iter()
        .rev()
        .find(|message| message.thread_root.is_none() && !is_poll_event(&chat.messages, message))
        .map_or_else(
            || "No messages yet".into(),
            |message| {
                if let Some(poll) = PollState::fold(message, &chat.messages) {
                    return format!("Poll · {}", poll.question);
                }
                if is_reaction_message(message) {
                    let (removed, emoji) = message
                        .text
                        .strip_prefix("Reaction removed: ")
                        .map(|emoji| (true, emoji))
                        .or_else(|| {
                            message
                                .text
                                .strip_prefix("Reaction: ")
                                .map(|emoji| (false, emoji))
                        })
                        .unwrap();
                    let actor = if message.mine { "You" } else { &message.author };
                    return if removed {
                        format!("{actor} removed {emoji}")
                    } else {
                        format!("{actor} reacted {emoji}")
                    };
                }
                if message.mine {
                    format!("You: {}", message.text)
                } else {
                    message.text.clone()
                }
            },
        )
}

fn composer_recipient(name: &str, handle: &str) -> String {
    if handle.chars().any(char::is_whitespace) {
        name.into()
    } else {
        format!("@{handle}")
    }
}

fn truncate_text(text: &str, width: usize) -> String {
    let character_count = text.chars().count();
    if character_count <= width {
        return text.into();
    }
    if width <= 1 {
        return "…".chars().take(width).collect();
    }
    let mut value = text.chars().take(width - 1).collect::<String>();
    value.push('…');
    value
}

fn pad_to_width(text: &str, width: usize) -> String {
    let mut value = truncate_text(text, width);
    value.extend(std::iter::repeat_n(
        ' ',
        width.saturating_sub(value.chars().count()),
    ));
    value
}

fn wrap_message_body(text: &str, width: usize) -> Vec<String> {
    const INDENT: &str = "    ";
    let content_width = width.saturating_sub(INDENT.len()).max(1);
    wrap_cells(text, content_width)
        .into_iter()
        .map(|line| format!("{INDENT}{line}"))
        .collect()
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height),
            Constraint::Fill(1),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(width),
            Constraint::Fill(1),
        ])
        .split(vertical[1])[1]
}

fn centered_width(area: Rect, width: u16) -> Rect {
    let width = width.min(area.width);
    Rect::new(
        area.x.saturating_add(area.width.saturating_sub(width) / 2),
        area.y,
        width,
        area.height,
    )
}

fn safety_code_rows(fingerprint: &str) -> Vec<String> {
    let groups = fingerprint
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>();
    groups.chunks(4).map(|row| row.join("  ")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutte_store::DeliveryState;
    use ratatui::{Terminal, backend::TestBackend};

    fn profile() -> Profile {
        Profile {
            id: Uuid::new_v4(),
            handle: "nightowl".into(),
            display_name: "Night Owl".into(),
            bio: String::new(),
            status: "quiet".into(),
        }
    }

    fn render(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .filter_map(|x| buffer.cell((x, y)))
                    .map(|cell| cell.symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    async fn press(app: &mut App, keys: &[KeyCode]) {
        for key in keys {
            app.on_key(KeyEvent::new(*key, KeyModifiers::NONE), None)
                .await;
        }
    }

    fn grouped_conversation() -> App {
        let mut app = App::new(profile(), true);
        app.monochrome = false;
        let template = app.conversations[0].messages[0].clone();
        app.conversations[0].messages = [
            (false, "incoming one"),
            (false, "incoming two"),
            (false, "incoming three"),
            (true, "outgoing one"),
            (true, "outgoing two"),
            (true, "outgoing three"),
        ]
        .into_iter()
        .map(|(mine, text)| {
            let mut message = template.clone();
            message.id = Uuid::new_v4();
            message.mine = mine;
            message.author = if mine { "You" } else { "Alice" }.into();
            message.text = text.into();
            message.delivery = if mine {
                DeliveryState::Read
            } else {
                DeliveryState::Received
            };
            message.locally_read = true;
            message
        })
        .collect();
        app
    }

    fn wheel(kind: MouseEventKind) -> MouseEvent {
        MouseEvent {
            kind,
            column: 45,
            row: 15,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[tokio::test]
    async fn wheel_scrolls_history_without_moving_the_header_or_losing_drafts() {
        for width in [52, 100, 140] {
            let mut app = grouped_conversation();
            app.input = "keep my draft".into();
            app.command_input = "/dm unfinished".into();
            app.reply_to = Some(app.conversations[0].messages[0].id);
            let reply_to = app.reply_to;
            let scope = app.scope();
            app.update_visibility(None).await;
            let before = render(&app, width, 24);
            let header_height = app.header_height(Rect::new(0, 0, width, 24)) as usize;

            app.on_mouse(wheel(MouseEventKind::ScrollUp), None).await;
            let after = render(&app, width, 24);
            assert_ne!(before, after);
            assert_eq!(
                before.lines().take(header_height).collect::<Vec<_>>(),
                after.lines().take(header_height).collect::<Vec<_>>()
            );
            assert!(app.conversations[0].scroll_back > 0);
            assert_eq!(app.last_visible, None);
            assert_eq!(app.ui.mode, UiMode::Composer(ComposerMode::Message));
            assert_eq!(app.input, "keep my draft");
            assert_eq!(app.command_input, "/dm unfinished");
            assert_eq!(app.reply_to, reply_to);
            assert_eq!(app.scope(), scope);

            for _ in 0..40 {
                app.on_mouse(wheel(MouseEventKind::ScrollUp), None).await;
                render(&app, width, 24);
            }
            let at_top = app.conversations[0].scroll_back;
            app.on_mouse(wheel(MouseEventKind::ScrollUp), None).await;
            assert_eq!(app.conversations[0].scroll_back, at_top);
            app.on_mouse(wheel(MouseEventKind::ScrollDown), None).await;
            assert!(app.conversations[0].scroll_back < at_top);
            for _ in 0..40 {
                render(&app, width, 24);
                app.on_mouse(wheel(MouseEventKind::ScrollDown), None).await;
            }
            assert_eq!(app.conversations[0].scroll_back, 0);
            assert_eq!(app.last_visible, Some(scope));
        }
    }

    #[tokio::test]
    async fn wheel_navigates_the_focused_pane_without_activating_actions_or_claiming_focus() {
        let mut app = grouped_conversation();
        app.input = "draft stays here".into();
        app.focus(UiMode::Messages);
        let latest = app.selected_message().unwrap().id;
        app.on_mouse(wheel(MouseEventKind::ScrollUp), None).await;
        assert_ne!(app.selected_message().unwrap().id, latest);
        assert_eq!(app.ui.mode, UiMode::Messages);
        assert_eq!(app.input, "draft stays here");
        app.on_mouse(wheel(MouseEventKind::ScrollDown), None).await;
        assert_eq!(app.selected_message().unwrap().id, latest);

        app.ui.open_palette();
        app.on_mouse(wheel(MouseEventKind::ScrollDown), None).await;
        assert_eq!(app.ui.mode, UiMode::Palette);
        assert_eq!(app.palette_selection, 1);
        assert!(!app.should_quit);
        app.ui.close_palette();
        app.focus(UiMode::Conversations);
        app.on_mouse(wheel(MouseEventKind::ScrollDown), None).await;
        assert_eq!(app.selected, 1);
        assert_eq!(app.last_visible, None);
        app.on_mouse(wheel(MouseEventKind::ScrollUp), None).await;
        assert_eq!(app.selected, 0);
        assert_eq!(app.input, "draft stays here");

        app.ui.focus_composer();
        render(&app, 100, 24);
        app.observe_terminal_focus(&Event::FocusLost);
        let mouse = wheel(MouseEventKind::ScrollUp);
        app.observe_terminal_focus(&Event::Mouse(mouse));
        app.on_mouse(mouse, None).await;
        assert!(!app.window_focused);
        assert_eq!(app.last_visible, None);
        let offset = app.conversations[0].scroll_back;
        for kind in [
            MouseEventKind::Moved,
            MouseEventKind::ScrollLeft,
            MouseEventKind::ScrollRight,
        ] {
            app.on_mouse(wheel(kind), None).await;
        }
        assert_eq!(app.conversations[0].scroll_back, offset);
        assert_eq!(app.input, "draft stays here");
    }

    #[test]
    fn consecutive_sender_groups_have_one_label_and_no_message_dividers() {
        let app = grouped_conversation();
        let screen = render(&app, 80, 50);
        let message_pane = screen
            .lines()
            .skip(9)
            .take(33)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(message_pane.matches("Alice").count(), 1, "{screen}");
        assert!(!message_pane.contains("YOU"), "{screen}");
        assert!(!message_pane.contains("────"), "{screen}");
        assert_eq!(message_pane.matches("✓✓").count(), 3, "{screen}");
        let rows = screen.lines().collect::<Vec<_>>();
        let first = rows
            .iter()
            .position(|row| row.contains("incoming one"))
            .unwrap();
        let third = rows
            .iter()
            .position(|row| row.contains("incoming three"))
            .unwrap();
        assert!(
            rows[first..=third].iter().all(|row| !row.trim().is_empty()),
            "{screen}"
        );
    }

    #[tokio::test]
    async fn short_history_sits_above_composer_without_reflowing_when_selected() {
        let mut app = grouped_conversation();
        app.conversations[0].messages.truncate(2);
        let resting = render(&app, 80, 50);
        let first = resting
            .lines()
            .position(|row| row.contains("incoming one"))
            .unwrap();
        let last = resting
            .lines()
            .position(|row| row.contains("incoming two"))
            .unwrap();
        let composer = resting
            .lines()
            .position(|row| row.contains("MESSAGE MODE"))
            .unwrap();
        assert!(
            first > 30,
            "short history should rest near the composer\n{resting}"
        );
        assert!(last < composer && composer - last <= 4, "{resting}");
        press(&mut app, &[KeyCode::F(2)]).await;
        let selected = render(&app, 80, 50);
        assert_eq!(
            selected
                .lines()
                .position(|row| row.contains("incoming one")),
            Some(first)
        );
        assert_eq!(
            selected
                .lines()
                .position(|row| row.contains("incoming two")),
            Some(last)
        );
    }

    #[test]
    fn outgoing_groups_stay_on_the_opposite_side_at_every_layout_size() {
        let app = grouped_conversation();
        for width in [52, 70, 80, 100, 140, 200] {
            let screen = render(&app, width, 50);
            let incoming = screen
                .lines()
                .find(|row| row.contains("incoming two"))
                .unwrap();
            let outgoing = screen
                .lines()
                .find(|row| row.contains("outgoing two"))
                .unwrap();
            let incoming_column = incoming[..incoming.find("incoming two").unwrap()]
                .chars()
                .count();
            let outgoing_column = outgoing[..outgoing.find("outgoing two").unwrap()]
                .chars()
                .count();
            assert!(
                outgoing_column > incoming_column + 10,
                "{width} columns\n{screen}"
            );
        }
    }

    #[test]
    fn sender_groups_break_at_sender_direction_day_and_thread_boundaries() {
        let app = grouped_conversation();
        let previous = &app.conversations[0].messages[0];
        let mut next = previous.clone();
        next.id = Uuid::new_v4();
        assert!(continues_sender_group(previous, &next));
        next.author = "Bob".into();
        assert!(!continues_sender_group(previous, &next));
        next.author = previous.author.clone();
        next.mine = true;
        assert!(!continues_sender_group(previous, &next));
        next.mine = false;
        next.timestamp += chrono::Duration::days(1);
        assert!(!continues_sender_group(previous, &next));
        next.timestamp = previous.timestamp;
        next.thread_root = Some(previous.id);
        assert!(!continues_sender_group(previous, &next));
    }

    #[test]
    fn hidden_thread_replies_do_not_break_main_sender_groups() {
        let mut app = grouped_conversation();
        let mut reply = app.conversations[0].messages[3].clone();
        reply.id = Uuid::new_v4();
        reply.text = "hidden thread message".into();
        reply.thread_root = Some(app.conversations[0].messages[0].id);
        app.conversations[0].messages.insert(1, reply);
        let screen = render(&app, 80, 50);
        assert_eq!(screen.matches("Alice").count(), 1, "{screen}");
        assert!(!screen.contains("hidden thread message"), "{screen}");
        assert!(screen.contains("1 reply"), "{screen}");
    }

    #[tokio::test]
    async fn a_message_in_the_middle_of_a_group_remains_selectable_for_reply_and_thread() {
        let mut app = grouped_conversation();
        let target = app.conversations[0].messages[1].id;
        press(&mut app, &[KeyCode::F(2), KeyCode::Home, KeyCode::Down]).await;
        assert_eq!(app.selected_message().unwrap().id, target);
        let screen = render(&app, 80, 30);
        assert!(screen.contains("▶ incoming two"), "{screen}");
        assert!(screen.contains("incoming two"), "{screen}");
        press(&mut app, &[KeyCode::Char('r')]).await;
        assert_eq!(app.reply_to, Some(target));
        assert!(render(&app, 80, 30).contains("↪ Alice: incoming two"));
        press(&mut app, &[KeyCode::F(2), KeyCode::Char('t')]).await;
        assert_eq!(app.scope().1, Some(target));
        assert!(render(&app, 80, 30).contains("incoming two"));
    }

    #[tokio::test]
    async fn original_shortcut_selects_exact_message_and_preserves_main_and_thread_drafts() {
        let mut app = grouped_conversation();
        let root = app.conversations[0].messages[0].id;
        let reply_id = app.conversations[0].messages[3].id;
        app.conversations[0].messages[3].reply_to = Some(root);
        app.input = "main draft kept".into();
        app.focus(UiMode::Messages);
        app.selected_messages.insert(app.scope(), reply_id);
        press(&mut app, &[KeyCode::Char('o')]).await;
        assert_eq!(app.selected_message().unwrap().id, root);
        assert_eq!(app.input, "main draft kept");
        press(&mut app, &[KeyCode::Char('t')]).await;
        app.input = "thread draft kept".into();
        let mut thread_reply = app.conversations[0].messages[3].clone();
        thread_reply.id = Uuid::new_v4();
        thread_reply.thread_root = Some(root);
        thread_reply.reply_to = Some(reply_id);
        let thread_reply_id = thread_reply.id;
        app.conversations[0].messages.push(thread_reply);
        app.selected_messages.insert(app.scope(), thread_reply_id);
        press(&mut app, &[KeyCode::Char('o')]).await;
        assert_eq!(app.scope().1, None);
        assert_eq!(app.selected_message().unwrap().id, reply_id);
        assert_eq!(app.input, "main draft kept");
        app.selected_messages.insert(app.scope(), root);
        press(&mut app, &[KeyCode::Char('t')]).await;
        assert_eq!(app.input, "thread draft kept");
    }

    #[tokio::test]
    async fn missing_original_keeps_selection_and_draft_unchanged() {
        let mut app = grouped_conversation();
        let target = app.conversations[0].messages[5].id;
        app.conversations[0].messages[5].reply_to = Some(Uuid::new_v4());
        app.input = "unsent draft".into();
        app.focus(UiMode::Messages);
        press(&mut app, &[KeyCode::Char('o')]).await;
        assert_eq!(app.selected_message().unwrap().id, target);
        assert_eq!(app.input, "unsent draft");
        assert_eq!(app.scope().1, None);
        assert_eq!(
            app.ui.notice.as_ref().unwrap().message,
            "The original message is not on this device"
        );
    }

    fn attachment_message_fixture(message: &mut MessageSnapshot) {
        message.text.clear();
        message.mine = false;
        message.attachment = Some(mutte_store::VaultAttachment {
            metadata: mutte_protocol::AttachmentMetadata {
                version: 1,
                attachment_id: Uuid::from_u128(77),
                filename: "Quiet by design.pdf".into(),
                plaintext_size: 25_600,
                chunk_count: 1,
                file_key: "fixture-key-never-display".into(),
                plaintext_hash: "fixture-hash-never-display".into(),
            },
            local_path: None,
            download_requested: false,
        });
    }

    #[tokio::test]
    async fn selected_attachment_download_uses_exact_id_and_preserves_drafts() {
        let mut app = grouped_conversation();
        let message = app.conversations[0].messages.last_mut().unwrap();
        attachment_message_fixture(message);
        let message_id = message.id;
        app.input = "draft survives attachment details".into();
        press(&mut app, &[KeyCode::F(2), KeyCode::End, KeyCode::Char('a')]).await;
        assert_eq!(app.ui.mode, UiMode::AttachmentDetails);
        assert!(app.pending_download.is_none());
        assert!(app.visible_scope().is_none());
        for (width, height) in [(52, 16), (80, 24), (140, 40)] {
            let screen = render(&app, width, height);
            assert!(screen.contains("Quiet by design.pdf"), "{screen}");
            assert!(
                screen.contains("D download") && screen.contains("Esc cancel"),
                "{screen}"
            );
            assert!(!screen.contains("fixture-key") && !screen.contains("fixture-hash"));
        }
        // Queue the typed action only; this unit test never executes a network command.
        app.demo = false;
        app.handle_attachment_details_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        assert_eq!(app.pending_download, Some(Uuid::from_u128(77)));
        app.handle_attachment_details_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.ui.mode, UiMode::Messages);
        assert_eq!(app.selected_message().unwrap().id, message_id);
        assert_eq!(app.input, "draft survives attachment details");
        assert!(app.pending_download.is_none());

        app.conversations[0]
            .messages
            .last_mut()
            .unwrap()
            .attachment
            .as_mut()
            .unwrap()
            .local_path = Some(PathBuf::from("/synthetic/private/Quiet by design.pdf"));
        app.open_attachment_details();
        app.handle_attachment_details_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.pending_download.is_none());
        assert!(render(&app, 80, 24).contains("Downloaded and verified"));
    }

    #[tokio::test]
    async fn capture_attachment_modal_fixtures() {
        use ratatui::style::Modifier;
        let Some(output) = std::env::var_os("MUTTE_ATTACHMENT_CAPTURE_DIR") else {
            return;
        };
        let output = PathBuf::from(output);
        assert!(output.is_absolute());
        std::fs::create_dir_all(&output).unwrap();
        let fixture = crate::attachment_picker::tests::Fixture::new();
        let mut app = grouped_conversation();
        app.input = "This message draft stays here".into();
        app.attachment_directory = Some(fixture.0.clone());
        app.open_attachment_picker();
        let image_path = fixture.0.join("gradient.png");
        image::RgbaImage::from_fn(320, 200, |x, y| {
            image::Rgba([((x * 255) / 319) as u8, ((y * 255) / 199) as u8, 180, 255])
        })
        .save(&image_path)
        .unwrap();
        for scene in [
            "browse",
            "review",
            "error",
            "download",
            "preview-text",
            "preview-image",
            "reaction",
        ] {
            match scene {
                "review" => {
                    press(
                        &mut app,
                        &[
                            KeyCode::Char('p'),
                            KeyCode::Char('h'),
                            KeyCode::Char('o'),
                            KeyCode::Char('t'),
                            KeyCode::Char('o'),
                            KeyCode::Enter,
                        ],
                    )
                    .await;
                }
                "error" => app.attachment_dialog.as_mut().unwrap().picker.set_error(
                    "The file changed. Go back and select it again before sending".into(),
                ),
                "download" => {
                    app.close_attachment_picker();
                    attachment_message_fixture(app.conversations[0].messages.last_mut().unwrap());
                    app.focus(UiMode::Messages);
                    app.open_attachment_details();
                }
                "preview-text" => {
                    app.attachment_details = None;
                    app.open_file_preview(
                        fixture.0.join("notes $(literal).txt"),
                        "notes $(literal).txt".into(),
                        PreviewReturn::Attachments,
                    );
                }
                "preview-image" => {
                    app.file_preview = None;
                    app.open_file_preview(
                        image_path.clone(),
                        "gradient.png".into(),
                        PreviewReturn::Attachments,
                    );
                }
                "reaction" => {
                    app.file_preview = None;
                    app.ui.mode = UiMode::Messages;
                    let target = app.conversations[0].messages.last().unwrap().clone();
                    app.selected_messages.insert(app.scope(), target.id);
                    let mut event = target.clone();
                    event.id = Uuid::new_v4();
                    event.text = "Reaction: 👍".into();
                    event.reply_to = Some(target.id);
                    event.mine = true;
                    event.timestamp += chrono::Duration::seconds(1);
                    app.conversations[0].messages.push(event);
                    app.open_reactions();
                }
                _ => {}
            }
            let palette = app.theme.palette();
            let rgb = |color, fallback| match color {
                Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
                _ => match fallback {
                    Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
                    _ => "#0c0e14".into(),
                },
            };
            for (width, height) in [(52, 16), (100, 36), (140, 44)] {
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                terminal.draw(|frame| app.draw(frame)).unwrap();
                let mut cells = Vec::new();
                for y in 0..height {
                    for x in 0..width {
                        let cell = terminal.backend().buffer().cell((x, y)).unwrap();
                        cells.push(serde_json::json!([
                            x,
                            y,
                            cell.symbol(),
                            rgb(cell.fg, palette.text),
                            rgb(cell.bg, palette.bg),
                            cell.modifier.contains(Modifier::BOLD)
                        ]));
                    }
                }
                let capture = serde_json::json!({"width":width, "height":height, "cells":cells, "source":"Ratatui TestBackend · synthetic attachment fixtures; no live account"});
                std::fs::write(
                    output.join(format!("attachment-{width}-{scene}.json")),
                    serde_json::to_vec(&capture).unwrap(),
                )
                .unwrap();
            }
        }
    }

    /// Opt-in, deterministic captures of the actual Ratatui render buffer. No
    /// terminal window, credentials, vault, network, or OS notifications are used.
    #[test]
    fn capture_terminal_layout_fixtures() {
        use chrono::TimeZone;
        use ratatui::style::Modifier;
        let Some(output) = std::env::var_os("MUTTE_TUI_CAPTURE_DIR") else {
            return;
        };
        let output = std::path::PathBuf::from(output);
        assert!(
            output.is_absolute(),
            "capture output must be an explicit absolute directory"
        );
        std::fs::create_dir_all(&output).unwrap();
        let mut app = App::new(profile(), true);
        // Captures describe the regular palette regardless of the test runner's
        // own NO_COLOR environment. Monochrome ownership has a separate test.
        app.monochrome = false;
        let template = app.conversations[0].messages[0].clone();
        app.conversations[0].messages = [
            (true, 21, 20, "Mutte device test 01: terminal to iPhone."),
            (false, 21, 22, "Reply 01"),
            (
                true,
                21,
                27,
                "Mutte device test 02: after both apps restarted.",
            ),
            (
                true,
                21,
                29,
                "Mutte device test 03: queued while iPhone app was closed.",
            ),
            (false, 21, 57, "Inline reply"),
            (
                true,
                21,
                59,
                "Terminal inline reply 01: replying to your inline reply.",
            ),
            (
                true,
                23,
                8,
                "Unread main 01: check read receipts only when this chat is open.",
            ),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (mine, hour, minute, body))| {
            let mut message = template.clone();
            message.id = Uuid::from_u128(index as u128 + 1);
            message.author = if mine { "You" } else { "@mira" }.into();
            message.mine = mine;
            message.text = body.into();
            message.timestamp = chrono::Local
                .with_ymd_and_hms(2026, 9, 2, hour, minute, 0)
                .unwrap();
            message.delivery = if mine {
                DeliveryState::Read
            } else {
                DeliveryState::Received
            };
            message.locally_read = true;
            message.reply_to = match index {
                4 => Some(Uuid::from_u128(1)),
                5 => Some(Uuid::from_u128(5)),
                _ => None,
            };
            message.thread_root = None;
            message
        })
        .collect();
        for index in 0..10 {
            let mut reply = template.clone();
            reply.id = Uuid::from_u128(100 + index);
            reply.thread_root = Some(Uuid::from_u128(1));
            reply.reply_to = reply.thread_root;
            reply.locally_read = index < 8;
            reply.text = format!("Thread fixture {}", index + 1);
            app.conversations[0].messages.push(reply);
        }
        let scene = std::env::var("MUTTE_TUI_CAPTURE_SCENE").unwrap_or_else(|_| "replies".into());
        assert!(matches!(scene.as_str(), "replies" | "burst" | "long-group"));
        let full_shell = std::env::var("MUTTE_TUI_CAPTURE_SHELL").as_deref() == Ok("1");
        if scene == "burst" {
            app.conversations[0].messages = [
                (false, 28, "Hey"),
                (false, 28, "Needs to be grouped"),
                (false, 28, "Needs to be grouped"),
                (true, 28, "okay"),
                (true, 29, "let it be"),
                (true, 29, "test notifications"),
                (true, 29, "emmm"),
                (true, 30, "one more"),
            ]
            .into_iter()
            .enumerate()
            .map(|(index, (mine, minute, body))| {
                let mut message = template.clone();
                message.id = Uuid::from_u128(index as u128 + 1);
                message.mine = mine;
                message.author = if mine { "You" } else { "@mira" }.into();
                message.text = body.into();
                message.timestamp = chrono::Local
                    .with_ymd_and_hms(2026, 9, 3, 16, minute, 0)
                    .unwrap();
                message.delivery = if !mine {
                    DeliveryState::Received
                } else if index < 6 {
                    DeliveryState::Read
                } else {
                    DeliveryState::Delivered
                };
                message.locally_read = true;
                message.reply_to = None;
                message.thread_root = None;
                message
            })
            .collect();
        } else if scene == "long-group" {
            app.conversations[0].messages = (0..18)
                .map(|index| {
                    let mut message = template.clone();
                    message.id = Uuid::from_u128(index + 1);
                    message.mine = false;
                    message.author = "@mira".into();
                    message.text = format!(
                        "Wired {} {:02}",
                        if index % 3 == 1 { "inline" } else { "main" },
                        index + 1
                    );
                    message.timestamp = chrono::Local
                        .with_ymd_and_hms(2026, 9, 3, 10, index as u32, 0)
                        .unwrap();
                    message.delivery = DeliveryState::Received;
                    message.locally_read = true;
                    message.reply_to = (index % 3 == 1).then(|| Uuid::from_u128(index));
                    message.thread_root = None;
                    message
                })
                .collect();
        }
        let palette = app.theme.palette();
        let rgb = |color, fallback| match color {
            Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
            _ => match fallback {
                Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
                _ => "#0c0e14".into(),
            },
        };
        for width in [52, 80, 88, 100, 128, 140, 200] {
            for selected in [false, true] {
                app.transcript_viewports.borrow_mut().clear();
                app.ui.mode = if selected {
                    UiMode::Messages
                } else {
                    UiMode::Composer(ComposerMode::Message)
                };
                app.selected_messages
                    .insert(app.scope(), Uuid::from_u128(4));
                let height = 44;
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                terminal
                    .draw(|frame| {
                        if full_shell {
                            app.draw(frame);
                        } else {
                            app.draw_conversation(frame, frame.area());
                        }
                    })
                    .unwrap();
                let buffer = terminal.backend().buffer();
                let mut cells = Vec::new();
                for y in 0..height {
                    for x in 0..width {
                        let cell = buffer.cell((x, y)).unwrap();
                        cells.push(serde_json::json!([
                            x,
                            y,
                            cell.symbol(),
                            rgb(cell.fg, palette.text),
                            rgb(cell.bg, palette.bg),
                            cell.modifier.contains(Modifier::BOLD)
                        ]));
                    }
                }
                let capture = serde_json::json!({"width":width,"height":height,"cells":cells,"scene":scene,"full_shell":full_shell,"source":"Ratatui TestBackend · synthetic fixtures, not a live session"});
                let state = if selected { "selected" } else { "reading" };
                std::fs::write(
                    output.join(format!("terminal-{width}-{state}.json")),
                    serde_json::to_vec(&capture).unwrap(),
                )
                .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn outgoing_group_selection_stays_visible_through_unicode_wrapping_and_resize() {
        let mut app = grouped_conversation();
        let target = app.conversations[0].messages[4].id;
        app.conversations[0].messages[4].text = format!(
            "Grouped selected · 你好 👋\n{}",
            "wrapped words ".repeat(30)
        );
        press(&mut app, &[KeyCode::F(2), KeyCode::End, KeyCode::Up]).await;
        for width in [52, 80, 100, 140] {
            let screen = render(&app, width, 30);
            assert!(
                screen.contains("Grouped selected"),
                "{width} columns\n{screen}"
            );
            assert!(screen.contains("▶ Grouped selected"), "{screen}");
            assert_eq!(app.selected_message().unwrap().id, target);
        }
    }

    #[tokio::test]
    async fn newest_message_after_scrolling_clears_durable_main_unread_but_keeps_threads() {
        use mutte_store::{VaultConversation, VaultMessage};
        let directory = std::env::temp_dir().join(format!("mutte-read-scroll-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let vault_path = directory.join("vault.json");
        let key = [29; 32];
        let conversation_id = Uuid::new_v4();
        let root = Uuid::new_v4();
        let mut vault = Vault::open_at(&vault_path, &key).unwrap();
        for (id, thread_root) in [
            (root, None),
            (Uuid::new_v4(), None),
            (Uuid::new_v4(), Some(root)),
        ] {
            let unread = vault.conversations().first().map_or(0, |chat| chat.unread);
            vault
                .store_inbound(
                    VaultConversation {
                        id: conversation_id,
                        peer_handle: "alice".into(),
                        unread,
                    },
                    VaultMessage {
                        id,
                        conversation_id,
                        author: "Alice".into(),
                        text: "Unread fixture".into(),
                        mine: false,
                        sent_at: chrono::Utc::now(),
                        delivery: DeliveryState::Received,
                        attachment: None,
                        reply_to: thread_root,
                        thread_root,
                        locally_read: false,
                    },
                    true,
                )
                .unwrap();
        }
        let mut app = App::connected(profile(), vault).unwrap();
        app.selected = app
            .conversations
            .iter()
            .position(|chat| chat.conversation_id == Some(conversation_id))
            .unwrap();
        let selected = app.selected;
        app.conversations[selected].scroll_back = 8;
        app.selected_messages.insert(app.scope(), root);
        app.update_visibility(None).await;
        assert_eq!(unread_total(&app.conversations), 3);
        press(&mut app, &[KeyCode::F(2)]).await;
        assert_eq!(app.conversations[app.selected].scroll_back, 0);
        assert_eq!(unread_total(&app.conversations), 3);
        press(&mut app, &[KeyCode::End]).await;
        assert_eq!(unread_total(&app.conversations), 1);
        assert!(
            app.conversations[app.selected]
                .messages
                .iter()
                .filter(|message| message.thread_root.is_none())
                .all(|message| message.locally_read)
        );
        drop(app);
        let mut restored =
            App::connected(profile(), Vault::open_at(&vault_path, &key).unwrap()).unwrap();
        restored.selected = restored
            .conversations
            .iter()
            .position(|chat| chat.conversation_id == Some(conversation_id))
            .unwrap();
        assert_eq!(unread_total(&restored.conversations), 1);
        let selected = restored.selected;
        restored.conversations[selected].active_thread = Some(root);
        restored.update_visibility(None).await;
        assert_eq!(unread_total(&restored.conversations), 0);
        drop(restored);
        assert_eq!(
            Vault::open_at(&vault_path, &key).unwrap().conversations()[0].unread,
            0
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn background_and_chat_browser_do_not_mark_unread_messages_read() {
        let mut app = App::new(profile(), true);
        for message in &mut app.conversations[0].messages {
            message.mine = false;
            message.locally_read = false;
        }
        app.conversations[0].unread = app.conversations[0].messages.len() as u16;
        let original = app.conversations[0].unread;
        app.window_focused = false;
        app.update_visibility(None).await;
        assert_eq!(app.visible_scope(), None);
        assert_eq!(app.conversations[0].unread, original);
        app.window_focused = true;
        app.ui.mode = UiMode::Conversations;
        app.update_visibility(None).await;
        assert_eq!(app.conversations[0].unread, original);
        press(&mut app, &[KeyCode::F(3)]).await;
        assert!(app.visible_scope().is_some());
        assert_eq!(app.conversations[0].unread, 0);
    }

    #[tokio::test]
    async fn keyboard_input_recovers_a_missing_focus_gained_event() {
        let mut app = App::new(profile(), true);
        for message in &mut app.conversations[0].messages {
            message.mine = false;
            message.locally_read = false;
        }
        app.conversations[0].unread = app.conversations[0].messages.len() as u16;
        app.observe_terminal_focus(&Event::FocusLost);
        app.update_visibility(None).await;
        assert!(app.conversations[0].unread > 0);

        let key = KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE);
        app.observe_terminal_focus(&Event::Key(key));
        app.on_key(key, None).await;
        assert!(app.window_focused);
        assert!(app.last_visible.is_some());
        assert_eq!(app.conversations[0].unread, 0);
    }

    #[tokio::test]
    async fn replaying_a_queued_key_does_not_override_a_later_focus_loss() {
        let mut app = App::new(profile(), true);
        for message in &mut app.conversations[0].messages {
            message.mine = false;
            message.locally_read = false;
        }
        app.conversations[0].unread = app.conversations[0].messages.len() as u16;
        let unread = app.conversations[0].unread;
        let key = KeyEvent::new(KeyCode::F(3), KeyModifiers::NONE);
        // Events arriving during a network fetch are observed in order;
        // only the queued key action is replayed after synchronization.
        app.observe_terminal_focus(&Event::Key(key));
        app.observe_terminal_focus(&Event::FocusLost);
        app.on_key(key, None).await;
        assert!(!app.window_focused);
        assert!(app.last_visible.is_none());
        assert_eq!(app.conversations[0].unread, unread);
    }

    #[test]
    fn resize_and_key_release_do_not_imply_window_focus() {
        let mut app = App::new(profile(), true);
        app.observe_terminal_focus(&Event::FocusLost);
        app.observe_terminal_focus(&Event::Resize(100, 30));
        app.observe_terminal_focus(&Event::Key(KeyEvent::new_with_kind(
            KeyCode::Char('a'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        )));
        assert!(!app.window_focused);
    }

    #[tokio::test]
    async fn reading_main_chat_preserves_thread_unread_and_header_total() {
        let mut app = App::new(profile(), true);
        for chat in &mut app.conversations {
            chat.unread = 0;
            for message in &mut chat.messages {
                message.locally_read = true;
            }
        }
        let root = app.conversations[0].messages[0].id;
        let mut incoming = app.conversations[0].messages[0].clone();
        incoming.id = Uuid::new_v4();
        incoming.mine = false;
        incoming.locally_read = false;
        incoming.thread_root = Some(root);
        app.conversations[0].messages.push(incoming);
        app.conversations[0].unread = 1;
        app.update_visibility(None).await;
        assert_eq!(unread_total(&app.conversations), 1);
        for width in [70, 100, 140] {
            let screen = render(&app, width, 30);
            assert!(screen.contains("1 unread"), "{screen}");
        }
        app.conversations[0].active_thread = Some(root);
        app.update_visibility(None).await;
        assert_eq!(unread_total(&app.conversations), 0);
        assert!(render(&app, 100, 30).contains("All read"));
    }

    #[tokio::test]
    async fn scrolling_selecting_old_message_and_opening_overlay_clear_visible_scope() {
        let mut app = App::new(profile(), true);
        app.update_visibility(None).await;
        assert!(app.last_visible.is_some());
        app.conversations[0].scroll_back = 1;
        app.update_visibility(None).await;
        assert_eq!(app.last_visible, None);
        app.conversations[0].scroll_back = 0;
        press(&mut app, &[KeyCode::F(2), KeyCode::Home]).await;
        assert_eq!(app.last_visible, None);
        press(&mut app, &[KeyCode::End]).await;
        assert!(app.last_visible.is_some());
        app.ui.mode = UiMode::Palette;
        app.update_visibility(None).await;
        assert_eq!(app.last_visible, None);
    }

    #[tokio::test]
    async fn four_focus_areas_cycle_both_ways_without_changing_drafts() {
        let mut app = App::new(profile(), true);
        app.input = "a message draft".into();
        app.command_input = "/dm another_peer".into();
        let modes = [
            UiMode::Composer(ComposerMode::Command),
            UiMode::Conversations,
            UiMode::Messages,
            UiMode::Composer(ComposerMode::Message),
        ];
        for expected in modes {
            press(&mut app, &[KeyCode::Tab]).await;
            assert_eq!(app.ui.mode, expected);
        }
        for expected in [
            UiMode::Messages,
            UiMode::Conversations,
            UiMode::Composer(ComposerMode::Command),
            UiMode::Composer(ComposerMode::Message),
        ] {
            press(&mut app, &[KeyCode::BackTab]).await;
            assert_eq!(app.ui.mode, expected);
        }
        assert_eq!(app.input, "a message draft");
        assert_eq!(app.command_input, "/dm another_peer");
    }

    #[tokio::test]
    async fn selected_message_reply_shows_quote_and_sends_exact_target() {
        let mut app = App::new(profile(), true);
        let target = app.conversations[0].messages[0].clone();
        press(
            &mut app,
            &[KeyCode::F(2), KeyCode::Home, KeyCode::Char('r')],
        )
        .await;
        assert_eq!(app.reply_to, Some(target.id));
        assert_eq!(app.ui.mode, UiMode::Composer(ComposerMode::Message));
        let screen = render(&app, 140, 40);
        assert!(screen.contains("↪ Mira: The midnight build"), "{screen}");
        assert!(!screen.contains('#'));
        app.input = "Reply without typing an ID".into();
        press(&mut app, &[KeyCode::Enter]).await;
        let sent = app.conversations[0].messages.last().unwrap();
        assert_eq!(sent.text, "Reply without typing an ID");
        assert_eq!(sent.reply_to, Some(target.id));
        assert_eq!(sent.thread_root, None);
        assert!(app.input.is_empty());
        assert!(app.reply_to.is_none());
        assert!(app.command_input.is_empty());
    }

    #[tokio::test]
    async fn thread_actions_preserve_main_draft_and_send_scoped_replies() {
        let mut app = App::new(profile(), true);
        let root = app.conversations[0].messages[0].id;
        app.input = "main draft".into();
        press(
            &mut app,
            &[
                KeyCode::F(2),
                KeyCode::Home,
                KeyCode::Char('r'),
                KeyCode::F(2),
                KeyCode::Char('t'),
            ],
        )
        .await;
        assert_eq!(app.scope().1, Some(root));
        assert!(app.input.is_empty());
        assert!(app.reply_to.is_none());
        press(&mut app, &[KeyCode::Enter]).await;
        app.input = "thread message".into();
        press(&mut app, &[KeyCode::Enter]).await;
        let first_reply = app.conversations[0].messages.last().unwrap().clone();
        assert_eq!(first_reply.reply_to, Some(root));
        assert_eq!(first_reply.thread_root, Some(root));
        press(&mut app, &[KeyCode::F(2), KeyCode::End, KeyCode::Char('r')]).await;
        app.input = "reply to thread message".into();
        press(&mut app, &[KeyCode::Enter]).await;
        let second_reply = app.conversations[0].messages.last().unwrap();
        assert_eq!(second_reply.reply_to, Some(first_reply.id));
        assert_eq!(second_reply.thread_root, Some(root));
        app.input = "thread draft".into();
        app.ui.notice = None;
        press(&mut app, &[KeyCode::F(2), KeyCode::Esc]).await;
        assert_eq!(app.scope().1, None);
        assert_eq!(app.input, "main draft");
        assert_eq!(app.reply_to, Some(root));
        assert!(
            app.visible_messages()
                .all(|message| message.thread_root.is_none())
        );
        press(&mut app, &[KeyCode::Home, KeyCode::Char('t')]).await;
        assert_eq!(app.input, "thread draft");
        assert_eq!(app.scope().1, Some(root));
    }

    #[tokio::test]
    async fn chat_switches_keep_drafts_and_reply_targets_bound_to_conversation_ids() {
        let mut app = App::new(profile(), true);
        let mut duplicate = app.conversations[0].clone();
        duplicate.conversation_id = Some(Uuid::new_v4());
        app.conversations.insert(1, duplicate);
        press(
            &mut app,
            &[KeyCode::F(2), KeyCode::Home, KeyCode::Char('r')],
        )
        .await;
        let reply_to = app.reply_to;
        app.input = "original history draft".into();
        app.command_input = "/devices".into();
        press(&mut app, &[KeyCode::F(1), KeyCode::Down]).await;
        assert!(app.input.is_empty());
        assert!(app.reply_to.is_none());
        app.input = "recovered history draft".into();
        press(&mut app, &[KeyCode::Up]).await;
        assert_eq!(app.input, "original history draft");
        assert_eq!(app.reply_to, reply_to);
        assert_eq!(app.command_input, "/devices");
        press(&mut app, &[KeyCode::Down]).await;
        assert_eq!(app.input, "recovered history draft");
        assert!(app.reply_to.is_none());
    }

    #[tokio::test]
    async fn failed_reply_preserves_text_and_target_for_retry() {
        let demo = App::new(profile(), true);
        let mut app = App::new(profile(), false);
        app.conversations = demo.conversations.clone();
        app.sync_draft_scope();
        press(&mut app, &[KeyCode::F(2), KeyCode::Char('r')]).await;
        let target = app.reply_to;
        app.input = "retain this reply".into();
        press(&mut app, &[KeyCode::Enter]).await;
        assert_eq!(app.input, "retain this reply");
        assert_eq!(app.reply_to, target);
        assert_eq!(
            app.ui.notice.as_ref().unwrap().severity,
            NoticeSeverity::Error
        );
    }

    #[tokio::test]
    async fn escape_cancels_reply_without_erasing_message_and_other_panes_do_not_edit() {
        let mut app = App::new(profile(), true);
        app.input = "keep this".into();
        press(
            &mut app,
            &[
                KeyCode::F(2),
                KeyCode::Char('r'),
                KeyCode::Esc,
                KeyCode::Esc,
            ],
        )
        .await;
        assert!(app.reply_to.is_none());
        assert_eq!(app.input, "keep this");
        for pane in [KeyCode::F(1), KeyCode::F(2)] {
            press(&mut app, &[pane, KeyCode::Backspace, KeyCode::Char('x')]).await;
            assert_eq!(app.input, "keep this");
        }
    }

    #[tokio::test]
    async fn command_entry_and_execution_never_consume_a_message_draft() {
        let mut app = App::new(profile(), true);
        app.input = "unfinished thought".into();
        app.prepare_command("/verify");
        press(&mut app, &[KeyCode::Enter]).await;
        assert_eq!(app.input, "unfinished thought");
        assert!(app.command_input.is_empty());
        assert_eq!(app.ui.mode, UiMode::Composer(ComposerMode::Message));
        app.input = "/quit is literal message content".into();
        press(&mut app, &[KeyCode::Enter]).await;
        assert!(!app.should_quit);
        assert_eq!(
            app.conversations[0].messages.last().unwrap().text,
            "/quit is literal message content"
        );
    }

    #[tokio::test]
    async fn commands_cannot_silently_send_plain_text() {
        let mut app = App::new(profile(), true);
        let before = app.conversations[0].messages.len();
        app.command_input = "not a command".into();
        press(&mut app, &[KeyCode::F(4), KeyCode::Enter]).await;
        assert_eq!(app.conversations[0].messages.len(), before);
        assert_eq!(app.command_input, "not a command");
        assert!(
            app.ui
                .notice
                .as_ref()
                .unwrap()
                .message
                .contains("Commands start with /")
        );
    }

    #[tokio::test]
    async fn palette_reply_and_thread_use_the_selected_message_not_an_id_prompt() {
        let mut app = App::new(profile(), true);
        press(&mut app, &[KeyCode::F(2), KeyCode::Home]).await;
        let target = app.selected_message().unwrap().id;
        app.ui.open_palette();
        press(&mut app, &[KeyCode::Char('r')]).await;
        assert_eq!(app.reply_to, Some(target));
        assert!(app.command_input.is_empty());
        app.ui.open_palette();
        press(&mut app, &[KeyCode::Char('t')]).await;
        assert_eq!(app.scope().1, Some(target));
        assert!(app.command_input.is_empty());
    }

    #[tokio::test]
    async fn empty_history_actions_are_safe_and_explain_why() {
        let mut app = App::new(profile(), true);
        app.conversations[0].messages.clear();
        for action in [KeyCode::Char('r'), KeyCode::Char('t')] {
            press(
                &mut app,
                &[KeyCode::F(2), KeyCode::Up, KeyCode::Home, action],
            )
            .await;
            assert!(app.selected_message().is_none());
            assert!(app.reply_to.is_none());
            assert_eq!(app.scope().1, None);
            assert!(
                app.ui
                    .notice
                    .as_ref()
                    .unwrap()
                    .message
                    .starts_with("No message")
            );
        }
    }

    #[tokio::test]
    async fn selected_message_follows_viewport_and_stays_anchored_on_arrival() {
        let mut app = App::new(profile(), true);
        let template = app.conversations[0].messages[0].clone();
        app.conversations[0].messages = (0..60)
            .map(|index| {
                let mut message = template.clone();
                message.id = Uuid::new_v4();
                message.text = format!("Message {index:02} · 你好 👋\n{}", "word ".repeat(40));
                message
            })
            .collect();
        press(&mut app, &[KeyCode::F(2), KeyCode::Home]).await;
        for _ in 0..30 {
            press(&mut app, &[KeyCode::Down]).await;
        }
        let selected_id = app.selected_message().unwrap().id;
        for (width, height) in [(52, 24), (80, 24), (100, 32), (140, 40)] {
            let screen = render(&app, width, height);
            assert!(screen.contains("Message 30"), "{width}×{height}\n{screen}");
            assert!(screen.contains('▶'), "{screen}");
            assert!(screen.contains("R reply"), "{screen}");
        }
        let mut arrival = template;
        arrival.id = Uuid::new_v4();
        app.conversations[0].messages.push(arrival);
        app.handle_client_events();
        assert_eq!(app.selected_message().unwrap().id, selected_id);
        press(&mut app, &[KeyCode::End]).await;
        assert_eq!(
            app.selected_message().unwrap().id,
            app.conversations[0].messages.last().unwrap().id
        );
    }

    #[tokio::test]
    async fn selected_chat_remains_visible_in_long_lists_at_both_layout_sizes() {
        let mut app = App::new(profile(), true);
        let template = app.conversations[0].clone();
        app.conversations = (0..30)
            .map(|index| {
                let mut chat = template.clone();
                chat.conversation_id = Some(Uuid::new_v4());
                chat.handle = format!("peer_{index:02}");
                chat.name = format!("Peer {index:02}");
                chat
            })
            .collect();
        press(&mut app, &[KeyCode::F(1), KeyCode::End]).await;
        for (width, height) in [(80, 24), (140, 40)] {
            let screen = render(&app, width, height);
            assert!(screen.contains("▌  Peer 29"), "{screen}");
        }
    }

    #[tokio::test]
    async fn successful_submission_clears_the_composer() {
        let mut app = App::new(profile(), true);
        app.input = "hello from mutte".into();

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), None)
            .await;

        assert!(app.input.is_empty());
    }

    #[tokio::test]
    async fn empty_submission_is_a_quiet_noop() {
        let mut app = App::new(profile(), true);

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), None)
            .await;

        assert!(app.input.is_empty());
        assert!(app.ui.notice.is_none());
    }

    #[tokio::test]
    async fn failed_submission_keeps_the_composer_for_retry() {
        let mut app = App::new(profile(), false);
        app.input = "retry this message".into();

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), None)
            .await;

        assert_eq!(app.input, "retry this message");
        let notice = app.ui.notice.as_ref().expect("typed error notice");
        assert_eq!(notice.severity, NoticeSeverity::Error);
        assert_eq!(notice.scope, NoticeScope::Composer);
        assert!(notice.message.starts_with("error:"));
    }

    #[test]
    fn main_layout_explains_security_focus_and_primary_actions() {
        let app = App::new(profile(), true);

        let screen = render(&app, 120, 36);

        assert!(screen.contains("Conversations"));
        assert!(!screen.contains("TRUST LENS"));
        assert!(screen.contains("Verify identity"));
        assert!(screen.contains("End-to-end encrypted"));
        assert!(screen.contains("Ctrl+K then V"));
        assert!(screen.contains("Message @mira"));
        assert!(screen.contains("Ctrl+K actions"));
        assert!(!screen.contains('#'));
    }

    #[tokio::test]
    async fn ambiguous_direct_handle_opens_explicit_switcher_without_selecting() {
        let mut app = App::new(profile(), true);
        let original_index = app.selected;
        let mut recovered = app.conversations[original_index].clone();
        recovered.conversation_id = Some(Uuid::new_v4());
        recovered.handle = recovered.handle.to_ascii_uppercase();
        let mut message = recovered.messages.last().unwrap().clone();
        message.text = "A separate recovered history".into();
        recovered.messages = vec![message];
        recovered.verification = VerificationState::Changed;
        app.conversations.push(recovered);
        let ids = app
            .conversations
            .iter()
            .filter_map(|chat| chat.conversation_id)
            .collect::<Vec<_>>();
        app.prepare_command(&format!(
            "/dm @{}",
            app.conversations[original_index].handle
        ));

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), None)
            .await;

        assert_eq!(app.selected, original_index);
        assert_eq!(app.ui.mode, UiMode::Conversations);
        assert!(app.input.is_empty());
        assert_eq!(
            app.conversations
                .iter()
                .filter_map(|chat| chat.conversation_id)
                .collect::<Vec<_>>(),
            ids
        );
        assert_eq!(
            app.conversations.last().unwrap().verification,
            VerificationState::Changed
        );
        for (width, height) in [(80, 24), (140, 40)] {
            let screen = render(&app, width, height);
            // The narrow sidebar wraps the preview across lines.
            assert!(screen.contains("recovered"), "{screen}");
            for chat in [
                &app.conversations[original_index],
                app.conversations.last().unwrap(),
            ] {
                let id = chat.conversation_id.unwrap();
                assert!(
                    screen.contains(&format!("Conversation #{}", &id.simple().to_string()[..8]))
                );
            }
        }
    }

    #[test]
    fn selected_conversation_uses_a_full_row_tint() {
        let app = App::new(profile(), true);
        let selected = app.theme.palette().selected;
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| app.draw(frame)).unwrap();

        let buffer = terminal.backend().buffer();
        for y in (app.header_height(Rect::new(0, 0, 120, 36)) + 2)
            ..(app.header_height(Rect::new(0, 0, 120, 36)) + 8)
        {
            assert_eq!(buffer.cell((1, y)).expect("selected row cell").bg, selected);
        }
    }

    #[test]
    fn header_uses_a_wordmark_with_a_compact_text_fallback() {
        let mut app = App::new(profile(), true);
        let palette = app.theme.palette();
        for (width, height, monochrome) in [
            (52, 30, false),
            (87, 30, false),
            (88, 23, false),
            (140, 16, false),
            (88, 24, false),
            (140, 30, false),
            (140, 30, true),
            (127, 40, false),
            (128, 31, false),
            (128, 32, false),
            (200, 44, false),
            (200, 44, true),
        ] {
            app.monochrome = monochrome;
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| app.draw(frame)).unwrap();
            let screen = render(&app, width, height);
            let header_height = app.header_height(Rect::new(0, 0, width, height));
            let header = screen
                .lines()
                .take(header_height as usize)
                .collect::<Vec<_>>()
                .join("\n");
            let has_art = header
                .chars()
                .any(|c| ('\u{2801}'..='\u{28ff}').contains(&c));
            assert_eq!(
                has_art,
                !monochrome && width >= 88 && height >= 24,
                "{header}"
            );
            let art_rows = header
                .lines()
                .filter(|row| row.chars().any(|c| ('\u{2801}'..='\u{28ff}').contains(&c)))
                .count();
            let expected_rows = if has_art { 3 } else { 0 };
            assert_eq!(art_rows, expected_rows, "{header}");
            assert_eq!(header.contains("MUTTE"), !has_art, "{header}");
            assert!(header.contains("unread"), "{header}");
            assert!(header.contains("Night Owl"), "{header}");
            assert!(header.contains("mailbox ready"), "{header}");
            assert!(!header.contains("/ quiet"));
            if !has_art {
                let brand = terminal.backend().buffer().cell((2, 0)).unwrap();
                assert_eq!(brand.symbol(), "M");
                assert_eq!(brand.fg, palette.accent);
                assert_eq!(brand.bg, palette.bg);
            }
        }
    }

    #[test]
    fn wordmark_keeps_notifications_and_held_send_controls_readable() {
        let mut app = App::new(profile(), true);
        app.monochrome = false;
        app.notifications.toast = Some((2, Instant::now()));
        for (width, height) in [
            (52, 16),
            (87, 24),
            (88, 24),
            (100, 30),
            (128, 31),
            (128, 32),
            (140, 40),
        ] {
            let screen = render(&app, width, height);
            assert!(
                screen.contains("New messages · 2 received · F1 chats"),
                "{screen}"
            );
        }
        app.personal.holds.push(HeldText {
            id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            text: "synthetic held draft".into(),
            reply_to: None,
            thread_root: None,
            deadline: chrono::Utc::now() + chrono::Duration::seconds(5),
            phase: HoldPhase::Holding,
        });
        for (width, height) in [
            (52, 16),
            (87, 24),
            (88, 24),
            (100, 30),
            (128, 31),
            (128, 32),
            (140, 40),
        ] {
            let screen = render(&app, width, height);
            let header = screen
                .lines()
                .take(app.header_height(Rect::new(0, 0, width, height)) as usize)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(header.contains("Sending in"), "{header}");
            assert!(header.contains("Ctrl+Z Undo · F5 → Sending"), "{header}");
            assert!(header.contains("mailbox ready"), "{header}");
        }
    }

    #[test]
    fn conversation_list_collapses_without_a_permanent_trust_rail() {
        let app = App::new(profile(), true);

        for width in [52, 80, 87, 88, 100, 112, 140, 200] {
            let screen = render(&app, width, 32);
            assert_eq!(screen.contains("Conversations"), width >= 88, "{screen}");
            assert!(!screen.contains("TRUST LENS"));
            assert!(screen.contains("Message @mira"), "{screen}");
            let header = screen
                .lines()
                .skip(app.header_height(Rect::new(0, 0, width, 32)) as usize)
                .take(3)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(header.contains("Verify identity"), "{header}");
            assert!(header.contains("Ctrl+K then V"), "{header}");
        }
    }

    #[test]
    fn blocked_trust_states_stay_visible_when_resizing_and_navigating_history() {
        let mut app = App::new(profile(), true);
        let selected = app.selected;
        for (state, warning) in [
            (VerificationState::Changed, "Keys changed"),
            (VerificationState::Unavailable, "Check unavailable"),
        ] {
            app.conversations[selected].verification = state;
            for (thread, scroll_back) in [(None, 0), (None, 10), (Some(Uuid::new_v4()), 0)] {
                app.conversations[selected].active_thread = thread;
                app.conversations[selected].scroll_back = scroll_back;
                for (width, height) in [52, 70, 87, 88, 100, 120, 127, 128, 140, 200]
                    .into_iter()
                    .flat_map(|width| [16, 24, 31, 32, 44].map(|height| (width, height)))
                {
                    let screen = render(&app, width, height);
                    let header = screen
                        .lines()
                        .skip(app.header_height(Rect::new(0, 0, width, height)) as usize)
                        .take(3)
                        .collect::<Vec<_>>()
                        .join("\n");
                    assert!(header.contains(warning), "{width} columns\n{header}");
                    assert!(header.contains("Sending blocked"), "{header}");
                    assert!(header.contains("Ctrl+K then V"), "{header}");
                    assert!(!header.contains("End-to-end encrypted"), "{header}");
                }
            }
        }
    }

    #[test]
    fn local_conversation_header_does_not_claim_encryption_or_offer_verification() {
        let mut app = App::new(profile(), true);
        let selected = app.selected;
        app.conversations[selected].verification = VerificationState::NotApplicable;
        for width in [52, 88, 140] {
            let screen = render(&app, width, 24);
            let header = screen
                .lines()
                .skip(app.header_height(Rect::new(0, 0, width, 24)) as usize)
                .take(3)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(header.contains("Local only"), "{header}");
            assert!(!header.contains("End-to-end encrypted"), "{header}");
            assert!(!header.contains("Ctrl+K then V"), "{header}");
        }
    }

    #[test]
    fn default_message_lane_hides_transport_identifiers() {
        let app = App::new(profile(), true);

        let screen = render(&app, 140, 40);

        assert!(screen.contains("The midnight build passed"));
        assert!(!screen.contains("open /thread"));
        assert!(!screen.contains('#'));
    }

    #[test]
    fn reply_and_thread_commands_reveal_message_references() {
        for command in ["/reply ", "/thread "] {
            let mut app = App::new(profile(), true);
            let message_id = app.conversations[app.selected].messages.last().unwrap().id;
            let reference = format!("#{}", &message_id.simple().to_string()[..8]);
            app.prepare_command(command);

            for (width, height) in [(140, 40), (80, 24)] {
                assert!(render(&app, width, height).contains(&reference));
            }
        }
    }

    #[test]
    fn unrelated_commands_and_message_drafts_keep_references_hidden() {
        for input in ["/dm ", "/replying ", "/threading ", "try /reply later"] {
            let mut app = App::new(profile(), true);
            if input.starts_with('/') {
                app.prepare_command(input);
            } else {
                app.input = input.into();
            }

            assert!(!render(&app, 140, 40).contains('#'));
        }
    }

    #[tokio::test]
    async fn canceling_a_reply_or_thread_command_hides_references() {
        for command in ["/reply ", "/thread "] {
            let mut app = App::new(profile(), true);
            app.prepare_command(command);
            assert!(render(&app, 140, 40).contains('#'));

            app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), None)
                .await;

            assert!(app.input.is_empty());
            assert!(!render(&app, 140, 40).contains('#'));
        }
    }

    #[test]
    fn message_copy_keeps_a_readable_measure_inside_the_wide_lane() {
        let lines = wrap_message_body(
            "A deliberately long encrypted message should wrap at a readable width without exposing transport details or losing its sender-group alignment in the reading flow.",
            72,
        );

        assert!(lines.len() > 1);
        assert!(lines.iter().all(|line| line.chars().count() <= 72));
    }

    #[test]
    fn small_terminal_gets_a_clear_resize_state() {
        let app = App::new(profile(), true);

        let screen = render(&app, 48, 12);

        assert!(screen.contains("A little more room, please"));
        assert!(screen.contains("52×16"));
    }

    #[tokio::test]
    async fn tab_focus_makes_conversation_navigation_explicit() {
        let mut app = App::new(profile(), true);

        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE), None)
            .await;
        assert_eq!(app.ui.mode, UiMode::Composer(ComposerMode::Command));
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE), None)
            .await;
        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), None)
            .await;

        assert_eq!(app.ui.mode, UiMode::Conversations);
        assert_eq!(app.selected, 1);
        assert!(
            app.ui
                .notice
                .as_ref()
                .is_none_or(|notice| !notice.message.contains("vault"))
        );

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), None)
            .await;
        assert_eq!(app.ui.mode, UiMode::Messages);
    }

    #[tokio::test]
    async fn compact_layout_opens_a_visible_conversation_switcher() {
        let mut app = App::new(profile(), true);

        app.on_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE), None)
            .await;
        let screen = render(&app, 80, 24);

        assert!(screen.contains("Switch conversation"));
        assert!(screen.contains("Enter open"));
    }

    #[tokio::test]
    async fn command_palette_supports_arrow_and_enter_selection() {
        let mut app = App::new(profile(), true);
        app.attachment_directory = Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"));

        app.on_key(
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None,
        )
        .await;
        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), None)
            .await;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), None)
            .await;

        assert_ne!(app.ui.mode, UiMode::Palette);
        assert!(app.command_input.is_empty());
        assert_eq!(app.ui.mode, UiMode::Attachments);
        assert!(app.attachment_dialog.is_some());
    }

    #[tokio::test]
    async fn attachment_modal_preserves_drafts_and_freezes_thread_and_reply_targets() {
        let fixture = crate::attachment_picker::tests::Fixture::new();
        let mut app = grouped_conversation();
        let root = app.conversations[0].messages[0].id;
        app.conversations[0].active_thread = Some(root);
        app.sync_draft_scope();
        app.input = "unsent thread draft".into();
        app.command_input = "/dm other".into();
        app.reply_to = Some(root);
        app.attachment_directory = Some(fixture.0.clone());
        app.on_key(
            KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL),
            None,
        )
        .await;
        assert_eq!(app.ui.mode, UiMode::Attachments);
        assert_eq!(app.visible_scope(), None);
        for c in "photo".chars() {
            press(&mut app, &[KeyCode::Char(c)]).await;
        }
        press(&mut app, &[KeyCode::Enter]).await;
        assert!(app.pending_attachment.is_none());
        press(&mut app, &[KeyCode::Enter]).await;
        let pending = app.pending_attachment.as_ref().unwrap();
        assert_eq!(pending.conversation_id, app.scope().0.unwrap());
        assert_eq!(
            (pending.thread_root, pending.reply_to),
            (Some(root), Some(root))
        );
        assert_eq!(pending.file.filename, "photo 夏.jpg");
        assert_eq!(app.input, "unsent thread draft");
        assert_eq!(app.command_input, "/dm other");
        app.pending_attachment = None;
        press(&mut app, &[KeyCode::Esc, KeyCode::Esc]).await;
        assert!(app.attachment_dialog.is_none());
        assert_eq!(app.input, "unsent thread draft");
        assert_eq!(app.reply_to, Some(root));
    }

    #[tokio::test]
    async fn attachment_confirmation_rejects_a_changed_conversation() {
        let fixture = crate::attachment_picker::tests::Fixture::new();
        let mut app = grouped_conversation();
        app.attachment_directory = Some(fixture.0.clone());
        app.open_attachment_picker();
        for c in "photo".chars() {
            press(&mut app, &[KeyCode::Char(c)]).await;
        }
        press(&mut app, &[KeyCode::Enter]).await;
        app.selected = 1;
        press(&mut app, &[KeyCode::Enter]).await;
        assert!(app.pending_attachment.is_none());
        assert!(render(&app, 100, 40).contains("conversation changed"));
    }

    #[tokio::test]
    async fn immediate_palette_action_preserves_a_message_draft() {
        let mut app = App::new(profile(), true);
        app.input = "unfinished thought".into();

        app.on_key(
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None,
        )
        .await;
        app.on_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE), None)
            .await;

        assert_eq!(app.input, "unfinished thought");
        let notice = app.ui.notice.as_ref().expect("contextual notice");
        assert!(notice.message.contains("real encrypted chat"));
        assert_eq!(notice.scope, NoticeScope::Composer);
    }

    #[tokio::test]
    async fn prepared_palette_action_never_overwrites_a_message_draft() {
        let mut app = App::new(profile(), true);
        app.input = "unfinished thought".into();

        app.on_key(
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None,
        )
        .await;
        app.on_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE), None)
            .await;

        assert_eq!(app.input, "unfinished thought");
        assert_eq!(app.command_input, "/dm ");
        assert_eq!(app.ui.mode, UiMode::Composer(ComposerMode::Command));
    }

    #[tokio::test]
    async fn slash_input_enters_an_explicit_command_mode() {
        let mut app = App::new(profile(), true);

        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE), None)
            .await;

        assert_eq!(app.ui.mode, UiMode::Composer(ComposerMode::Command));
        assert!(render(&app, 120, 36).contains("COMMAND MODE"));

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), None)
            .await;

        assert_eq!(app.ui.mode, UiMode::Composer(ComposerMode::Message));
        assert!(app.input.is_empty());
    }

    #[tokio::test]
    async fn local_text_preview_returns_to_review_without_changing_the_draft() {
        let fixture = crate::attachment_picker::tests::Fixture::new();
        let mut app = grouped_conversation();
        app.input = "draft remains untouched".into();
        app.attachment_directory = Some(fixture.0.clone());
        app.open_attachment_picker();
        press(
            &mut app,
            &[
                KeyCode::Char('n'),
                KeyCode::Char('o'),
                KeyCode::Char('t'),
                KeyCode::Char('e'),
                KeyCode::Char('s'),
                KeyCode::Enter,
                KeyCode::Char('p'),
            ],
        )
        .await;
        assert_eq!(app.ui.mode, UiMode::FilePreview);
        let screen = render(&app, 80, 24);
        assert!(screen.contains("not a shell command"), "{screen}");
        assert!(screen.contains("no auto-open or upload"), "{screen}");
        press(&mut app, &[KeyCode::Esc]).await;
        assert_eq!(app.ui.mode, UiMode::Attachments);
        assert_eq!(app.input, "draft remains untouched");
        assert!(app.pending_attachment.is_none());
    }

    #[tokio::test]
    async fn reaction_picker_hides_fallback_events_and_marks_own_reaction() {
        let mut app = grouped_conversation();
        let target = app.conversations[0].messages.last().unwrap().clone();
        let mut event = target.clone();
        event.id = Uuid::new_v4();
        event.text = "Reaction: 👍".into();
        event.reply_to = Some(target.id);
        event.mine = true;
        event.timestamp += chrono::Duration::seconds(1);
        app.conversations[0].messages.push(event);
        app.focus(UiMode::Messages);
        app.selected_messages.insert(app.scope(), target.id);
        let transcript = render(&app, 80, 32);
        assert!(
            transcript.contains("👍") && transcript.contains(" 1"),
            "{transcript}"
        );
        assert!(!transcript.contains("Reaction:"), "{transcript}");
        app.open_reactions();
        let picker = render(&app, 80, 24);
        assert!(
            picker.contains("React to message") && picker.contains("● means you reacted"),
            "{picker}"
        );
        app.handle_reaction_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), None)
            .await;
        assert_eq!(app.ui.mode, UiMode::Reactions);
        assert!(render(&app, 80, 24).contains("Demo mode does not send reactions"));
        app.handle_reaction_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), None)
            .await;
        assert_eq!(app.ui.mode, UiMode::Messages);
        assert_eq!(app.selected_message().unwrap().id, target.id);
    }

    #[test]
    fn transient_notices_expire_but_errors_persist() {
        let mut ui = UiState::new("mailbox ready".into());
        let now = Instant::now();
        ui.set_notice_at(
            NoticeSeverity::Success,
            NoticeScope::Composer,
            "message sent",
            now,
        );

        ui.expire_notices(now + INFO_NOTICE_DURATION + Duration::from_millis(1));
        assert!(ui.notice.is_none());

        ui.set_notice_at(
            NoticeSeverity::Error,
            NoticeScope::Composer,
            "send failed",
            now,
        );
        ui.expire_notices(now + Duration::from_secs(60));
        assert_eq!(
            ui.notice.as_ref().map(|notice| notice.severity),
            Some(NoticeSeverity::Error)
        );
    }

    #[tokio::test]
    async fn escape_dismisses_a_persistent_composer_error() {
        let mut app = App::new(profile(), true);
        app.ui
            .set_notice(NoticeSeverity::Error, NoticeScope::Composer, "send failed");

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), None)
            .await;

        assert!(app.ui.notice.is_none());
        assert_eq!(app.ui.mode, UiMode::Composer(ComposerMode::Message));
    }

    #[test]
    fn a_failed_action_cannot_be_replaced_by_a_stale_client_notice() {
        let mut ui = UiState::new("previous status".into());
        ui.prepare_client_action();
        ui.cancel_client_action();
        ui.set_notice(
            NoticeSeverity::Error,
            NoticeScope::Composer,
            "current failure",
        );

        ui.capture_client_notice("previous status".into(), NoticeScope::Composer);

        let notice = ui.notice.as_ref().expect("current error remains visible");
        assert_eq!(notice.severity, NoticeSeverity::Error);
        assert_eq!(notice.message, "current failure");
    }

    #[tokio::test]
    async fn successful_action_replaces_a_stale_error() {
        let mut app = App::new(profile(), true);
        app.ui
            .set_notice(NoticeSeverity::Error, NoticeScope::Composer, "old failure");
        app.input = "hello from mutte".into();

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), None)
            .await;

        let notice = app.ui.notice.as_ref().expect("send success notice");
        assert_eq!(notice.severity, NoticeSeverity::Success);
        assert!(notice.message.contains("sent"));
        assert!(!notice.message.contains("old failure"));
    }

    #[test]
    fn durable_connection_state_stays_in_the_header() {
        let mut app = App::new(profile(), true);
        app.ui.connection = ConnectionState::Unavailable;
        app.ui.set_notice(
            NoticeSeverity::Error,
            NoticeScope::Composer,
            "send failed beside composer",
        );

        let screen = render(&app, 120, 36);

        assert!(
            screen
                .lines()
                .take(app.header_height(Rect::new(0, 0, 120, 36)) as usize)
                .any(|line| line.contains("mailbox unavailable"))
        );
        assert!(screen.contains("send failed beside composer"));
    }
}
