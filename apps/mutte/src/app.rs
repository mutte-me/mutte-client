use std::{
    borrow::Cow,
    collections::HashMap,
    ops::{Deref, DerefMut},
    time::{Duration, Instant},
};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use mutte_client::{
    ClientCommand, ClientEvent, ConversationSnapshot, MutteClient, VerificationState,
};
use mutte_protocol::{AccountDeviceState, Profile};
use mutte_store::{DeliveryState, Vault};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, Padding, Paragraph, Wrap},
};
use uuid::Uuid;

use crate::{
    platform::open_browser,
    theme::{ThemeManager, ThemePalette},
};

pub use mutte_client::Connection;

const MAILBOX_FALLBACK_INTERVAL: Duration = Duration::from_secs(10);
const INFO_NOTICE_DURATION: Duration = Duration::from_secs(5);
const WARNING_NOTICE_DURATION: Duration = Duration::from_secs(8);
const MINIMUM_WIDTH: u16 = 52;
const MINIMUM_HEIGHT: u16 = 16;
const TRUST_RAIL_MINIMUM_WIDTH: u16 = 112;
const SIDEBAR_MINIMUM_WIDTH: u16 = 88;
const MESSAGE_MAXIMUM_WIDTH: u16 = 104;
const MESSAGE_BODY_MAXIMUM_WIDTH: usize = 72;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ComposerMode {
    Message,
    Command,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UiMode {
    Conversations,
    Composer(ComposerMode),
    Palette,
    Verification,
    Devices,
}

impl UiMode {
    fn composer(input: &str) -> Self {
        if input.starts_with('/') {
            Self::Composer(ComposerMode::Command)
        } else {
            Self::Composer(ComposerMode::Message)
        }
    }

    fn is_composer(self) -> bool {
        matches!(self, Self::Composer(_))
    }
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

    fn focus_composer(&mut self, input: &str) {
        self.mode = UiMode::composer(input);
    }

    fn sync_composer_mode(&mut self, input: &str) {
        if self.mode.is_composer() {
            self.focus_composer(input);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PaletteAction {
    NewChat,
    SendAttachment,
    Verify,
    Devices,
    SyncDevice,
    Reply,
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

const PALETTE_ENTRIES: [PaletteEntry; 9] = [
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
        detail: "Use the message's short ID",
    },
    PaletteEntry {
        action: PaletteAction::Thread,
        shortcut: 't',
        label: "Open a thread",
        detail: "Focus a conversation branch",
    },
    PaletteEntry {
        action: PaletteAction::ReadReceipts,
        shortcut: 'e',
        label: "Read receipt privacy",
        detail: "Choose whether reads are shared",
    },
    PaletteEntry {
        action: PaletteAction::Quit,
        shortcut: 'q',
        label: "Quit Mutte",
        detail: "Close this terminal session",
    },
];

pub struct App {
    client: MutteClient,
    theme: ThemeManager,
    input: String,
    palette_selection: usize,
    ui: UiState,
    should_quit: bool,
    demo: bool,
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
        Self {
            client,
            theme: ThemeManager::discover(),
            input: String::new(),
            palette_selection: 0,
            ui,
            should_quit: false,
            demo,
        }
    }

    pub fn connected(profile: Profile, vault: Vault) -> Result<Self> {
        let client = MutteClient::connected(profile, vault)?;
        let ui = UiState::new(client.notice.clone());
        Ok(Self {
            client,
            theme: ThemeManager::discover(),
            input: String::new(),
            palette_selection: 0,
            ui,
            should_quit: false,
            demo: false,
        })
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
            conversation.unread = 0;
            return Ok(());
        }
        let Some(conversation) = self.conversations.get(self.selected) else {
            return Ok(());
        };
        let Some(conversation_id) = conversation.conversation_id else {
            return Ok(());
        };
        let thread_root = conversation.active_thread;
        self.execute(
            connection,
            ClientCommand::MarkRead {
                conversation_id,
                thread_root,
            },
        )
        .await?;
        self.handle_client_events();
        Ok(())
    }

    pub async fn run(
        mut self,
        terminal: &mut DefaultTerminal,
        connection: Option<Connection<'_>>,
    ) -> Result<()> {
        if let Some(connection) = connection {
            self.start(&connection).await?;
            self.handle_client_events();
        }
        let mut event_notifications = connection
            .map(|connection| connection.api.events(connection.session))
            .transpose()?;
        let mut last_sync = Instant::now()
            .checked_sub(MAILBOX_FALLBACK_INTERVAL)
            .unwrap_or_else(Instant::now);
        while !self.should_quit {
            let now = Instant::now();
            self.ui.expire_notices(now);
            self.theme.refresh_if_due(now);
            terminal.draw(|frame| self.draw(frame))?;
            let realtime_ready = event_notifications
                .as_mut()
                .is_some_and(|receiver| receiver.try_recv().is_ok());
            if let Some(connection) = connection
                && (realtime_ready || last_sync.elapsed() >= MAILBOX_FALLBACK_INTERVAL)
            {
                if let Err(error) = self.synchronize(&connection).await {
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
            if event::poll(Duration::from_millis(200))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.on_key(key, connection.as_ref()).await;
            }
        }
        Ok(())
    }

    async fn on_key(&mut self, key: KeyEvent, connection: Option<&Connection<'_>>) {
        self.ui.expire_notices(Instant::now());
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        if self.ui.mode == UiMode::Verification {
            match key.code {
                KeyCode::Esc => {
                    self.verification_panel = None;
                    self.ui.clear_notice_scope(NoticeScope::Overlay);
                    self.ui.focus_composer(&self.input);
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
                self.ui.focus_composer(&self.input);
            }
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
            KeyCode::Tab => {
                if self.ui.mode == UiMode::Conversations {
                    self.ui.focus_composer(&self.input);
                } else if self.ui.mode.is_composer() {
                    self.ui.mode = UiMode::Conversations;
                }
            }
            KeyCode::BackTab => self.ui.mode = UiMode::Conversations,
            KeyCode::Left if self.input.is_empty() => self.ui.mode = UiMode::Conversations,
            KeyCode::Right if self.ui.mode == UiMode::Conversations => {
                self.ui.focus_composer(&self.input);
            }
            KeyCode::Esc if !self.input.is_empty() => {
                self.input.clear();
                self.ui.focus_composer(&self.input);
            }
            KeyCode::Esc if self.ui.notice_for(NoticeScope::Composer).is_some() => {
                self.ui.clear_notice_scope(NoticeScope::Composer);
            }
            KeyCode::Esc if self.ui.mode == UiMode::Conversations => {
                self.ui.focus_composer(&self.input);
            }
            KeyCode::Esc if self.conversations[self.selected].active_thread.is_some() => {
                self.submit_text("/thread close".into(), connection).await;
            }
            KeyCode::Up if self.input.is_empty() => {
                self.selected = self.selected.saturating_sub(1);
                self.verification_panel = None;
                if let Err(error) = self.mark_current_read(connection).await {
                    self.ui.set_notice(
                        NoticeSeverity::Error,
                        NoticeScope::Composer,
                        format!("vault: {error}"),
                    );
                }
            }
            KeyCode::Down if self.input.is_empty() => {
                self.selected = (self.selected + 1).min(self.conversations.len().saturating_sub(1));
                self.verification_panel = None;
                if let Err(error) = self.mark_current_read(connection).await {
                    self.ui.set_notice(
                        NoticeSeverity::Error,
                        NoticeScope::Composer,
                        format!("vault: {error}"),
                    );
                }
            }
            KeyCode::PageUp => {
                let selected = self.selected;
                self.conversations[selected].scroll_back =
                    self.conversations[selected].scroll_back.saturating_add(8);
            }
            KeyCode::PageDown => {
                let selected = self.selected;
                self.conversations[selected].scroll_back =
                    self.conversations[selected].scroll_back.saturating_sub(8);
            }
            KeyCode::Home if self.input.is_empty() => {
                let selected = self.selected;
                self.conversations[selected].scroll_back = u16::MAX;
            }
            KeyCode::End if self.input.is_empty() => {
                let selected = self.selected;
                self.conversations[selected].scroll_back = 0;
            }
            KeyCode::Backspace => {
                self.input.pop();
                self.ui.sync_composer_mode(&self.input);
            }
            KeyCode::Enter => {
                if self.ui.mode == UiMode::Conversations {
                    self.ui.focus_composer(&self.input);
                } else {
                    self.submit_text(self.input.clone(), connection).await;
                }
            }
            KeyCode::Char(character)
                if self.ui.mode.is_composer() && !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.input.push(character);
                self.ui.sync_composer_mode(&self.input);
            }
            _ => {}
        }
    }

    fn prepare_command(&mut self, command: &str) {
        self.ui.close_palette();
        self.ui.focus_composer(&self.input);
        if self.input.trim().is_empty() || self.input.starts_with('/') {
            self.input = command.into();
            self.ui.sync_composer_mode(&self.input);
        } else {
            self.ui.set_notice(
                NoticeSeverity::Warning,
                NoticeScope::Composer,
                "draft kept · send it or press Esc before starting another action",
            );
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
        let submitted_command = input.starts_with('/');
        self.ui.prepare_client_action();
        match self
            .execute(connection, ClientCommand::ExecuteText(input))
            .await
        {
            Ok(()) if clear_composer => {
                self.input.clear();
                self.ui.focus_composer(&self.input);
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
            PaletteAction::NewChat => self.prepare_command("/dm "),
            PaletteAction::SendAttachment => self.prepare_command("/send "),
            PaletteAction::SyncDevice => self.prepare_command("/sync-device "),
            PaletteAction::Reply => self.prepare_command("/reply "),
            PaletteAction::Thread => self.prepare_command("/thread "),
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
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(frame.area());
        self.draw_top(frame, vertical[0]);
        if frame.area().width >= TRUST_RAIL_MINIMUM_WIDTH {
            let body = Layout::horizontal([
                Constraint::Percentage(20),
                Constraint::Percentage(60),
                Constraint::Percentage(20),
            ])
            .split(vertical[1]);
            self.draw_sidebar(frame, body[0]);
            self.draw_conversation(frame, body[1]);
            self.draw_trust_rail(frame, body[2]);
        } else if frame.area().width >= SIDEBAR_MINIMUM_WIDTH {
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
        let rows = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(content);
        let right_width = if area.width >= 96 { 34 } else { 18 };
        let first_row = Layout::horizontal([Constraint::Min(24), Constraint::Length(right_width)])
            .split(rows[0]);
        let status_row = Layout::horizontal([Constraint::Min(34), Constraint::Length(right_width)])
            .split(rows[2]);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " mutte ",
                    Style::default()
                        .fg(palette.contrasting_text(palette.mint))
                        .bg(palette.mint)
                        .bold(),
                ),
                Span::styled("  1:mutte", Style::default().fg(palette.secondary)),
            ])),
            first_row[0],
        );
        frame.render_widget(
            Paragraph::new(Line::styled(
                truncate_text(&self.profile.display_name, usize::from(right_width)),
                Style::default().fg(palette.secondary),
            ))
            .alignment(Alignment::Right),
            first_row[1],
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("●  MUTTE", Style::default().fg(palette.text).bold()),
                Span::styled("  / quiet    ", Style::default().fg(palette.muted)),
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
            let presence = format!(
                "   {}  ·  {}",
                display_handle(&chat.handle),
                clean_presence(&chat.status)
            );
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
                            palette.mint
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
        frame.render_widget(
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
        );
    }

    fn draw_trust_rail(&self, frame: &mut Frame, area: Rect) {
        let palette = self.theme.palette();
        let chat = &self.conversations[self.selected];
        let (identity, identity_color, action) = trust_lens_labels(chat.verification, palette);
        let block = Block::new()
            .title(Line::styled(
                " TRUST LENS ",
                Style::default().fg(palette.secondary),
            ))
            .borders(Borders::LEFT)
            .border_style(Style::default().fg(palette.line_strong))
            .padding(Padding::new(2, 1, 1, 1))
            .style(Style::default().bg(palette.bg));
        let content = block.inner(area);
        frame.render_widget(block, area);
        if content.width < 12 || content.height < 12 {
            return;
        }

        let sections = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(7),
        ])
        .split(content);
        frame.render_widget(
            Paragraph::new(Line::styled(
                "SECURE CHANNEL",
                Style::default().fg(palette.focus).bold(),
            ))
            .alignment(Alignment::Center),
            sections[0],
        );
        frame.render_widget(
            Paragraph::new(Text::from(vec![
                Line::styled(
                    "End-to-end encrypted",
                    Style::default().fg(palette.success).bold(),
                )
                .centered(),
                Line::raw(""),
                Line::styled(identity, Style::default().fg(identity_color)).centered(),
            ]))
            .wrap(Wrap { trim: true }),
            sections[1],
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    " V",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(format!(" {action}"), Style::default().fg(palette.text)),
            ]))
            .block(
                Block::new()
                    .title(Line::styled(
                        " Ctrl+K then ",
                        Style::default().fg(palette.muted),
                    ))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(identity_color)),
            ),
            sections[2],
        );
        frame.render_widget(
            Paragraph::new(Line::styled(
                "────────────────────────",
                Style::default().fg(palette.line),
            )),
            sections[3],
        );
        frame.render_widget(
            Paragraph::new(Text::from(vec![
                Line::styled("ACTIONS · CTRL+K THEN", Style::default().fg(palette.muted)),
                Line::raw(""),
                action_hint_line("R", "Reply", palette),
                Line::raw(""),
                action_hint_line("A", "Attach", palette),
                Line::raw(""),
                action_hint_line("T", "Thread", palette),
            ])),
            sections[4],
        );
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
        let inline_trust = frame.area().width < TRUST_RAIL_MINIMUM_WIDTH;
        let right_width = if !inline_trust {
            0
        } else if parts[0].width >= 72 {
            25
        } else {
            20
        };
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
                        Style::default().fg(palette.mint),
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
        } else if chat.scroll_back > 0 {
            "End returns to latest"
        } else {
            "End-to-end encrypted"
        };
        if inline_trust {
            frame.render_widget(
                Paragraph::new(Text::from(vec![
                    Line::styled(verification, Style::default().fg(verification_color).bold())
                        .right_aligned(),
                    Line::styled(navigation_hint, Style::default().fg(palette.muted))
                        .right_aligned(),
                ])),
                header_columns[1],
            );
        }
        let message_width = parts[1]
            .width
            .saturating_sub(6)
            .clamp(1, MESSAGE_MAXIMUM_WIDTH);
        let mut lines = Vec::new();
        let messages_by_id = chat
            .messages
            .iter()
            .map(|message| (message.id, message))
            .collect::<HashMap<_, _>>();
        let mut thread_stats = HashMap::<Uuid, (usize, usize)>::new();
        for message in &chat.messages {
            if let Some(root) = message.thread_root {
                let stats = thread_stats.entry(root).or_default();
                stats.0 += 1;
                stats.1 += usize::from(!message.locally_read);
            }
        }
        let mut previous_date = None;
        for message in &chat.messages {
            let visible = match chat.active_thread {
                Some(root) => message.id == root || message.thread_root == Some(root),
                None => message.thread_root.is_none(),
            };
            if !visible {
                continue;
            }
            let message_date = message.timestamp.date_naive();
            if previous_date != Some(message_date) {
                lines.push(
                    Line::styled(
                        format!("── {} ──", message.timestamp.format("%A · %B %-d")),
                        Style::default().fg(palette.line),
                    )
                    .centered(),
                );
                lines.push(Line::raw(""));
                previous_date = Some(message_date);
            }
            let accent = if message.mine {
                palette.warning
            } else {
                palette.mint
            };
            let (delivery, delivery_color) = match message.delivery {
                DeliveryState::Pending => ("  ·  sending", palette.warning),
                DeliveryState::Sent => ("  ·  sent", palette.muted),
                DeliveryState::Delivered => ("  ·  delivered", palette.secondary),
                DeliveryState::Read => ("  ·  read", palette.mint),
                DeliveryState::Cancelled => ("  ·  cancelled after key change", palette.danger),
                DeliveryState::Received => ("", palette.muted),
            };
            lines.push(Line::from(vec![
                Span::styled("▌  ", Style::default().fg(accent)),
                Span::styled(
                    if message.mine {
                        "YOU".into()
                    } else {
                        message.author.to_uppercase()
                    },
                    Style::default().fg(accent).bold(),
                ),
                Span::styled("  ", Style::default()),
                Span::styled(
                    message.timestamp.format("%H:%M").to_string(),
                    Style::default().fg(palette.muted),
                ),
                Span::styled(
                    if message.mine { delivery } else { "" },
                    Style::default().fg(delivery_color),
                ),
                Span::styled(
                    if message.locally_read {
                        ""
                    } else {
                        "  ● new"
                    },
                    Style::default().fg(palette.danger).bold(),
                ),
            ]));
            if let Some(reply_to) = message.reply_to {
                let preview = messages_by_id.get(&reply_to).map_or_else(
                    || "↪ original unavailable".into(),
                    |target| {
                        let mut text = target.text.chars().take(54).collect::<String>();
                        if target.text.chars().count() > 54 {
                            text.push('…');
                        }
                        format!("↪ {} · {text}", target.author)
                    },
                );
                lines.push(Line::styled(
                    format!("    {preview}"),
                    Style::default().fg(palette.muted).italic(),
                ));
            }
            lines.extend(
                wrap_message_body(&message.text, MESSAGE_BODY_MAXIMUM_WIDTH)
                    .into_iter()
                    .map(|line| Line::styled(line, Style::default().fg(palette.text))),
            );
            if let Some(attachment) = &message.attachment {
                let location = attachment.local_path.as_ref().map_or_else(
                    || "encrypted · not downloaded".into(),
                    |path| path.display().to_string(),
                );
                lines.push(Line::styled(
                    format!(
                        "    ↳ {}  ·  {}  ·  {location}",
                        attachment.metadata.filename,
                        format_bytes(attachment.metadata.plaintext_size)
                    ),
                    Style::default().fg(palette.secondary),
                ));
            }
            if message.thread_root.is_none()
                && let Some((replies, unread)) = thread_stats.get(&message.id).copied()
            {
                let unread_label = if unread == 0 {
                    String::new()
                } else {
                    format!(" · {unread} unread")
                };
                lines.push(Line::styled(
                    format!(
                        "    ↳ {} repl{}{}  ·  Ctrl+K then T",
                        replies,
                        if replies == 1 { "y" } else { "ies" },
                        unread_label
                    ),
                    Style::default().fg(palette.secondary),
                ));
            }
            lines.push(Line::styled(
                "─".repeat(usize::from(message_width)),
                Style::default().fg(palette.line),
            ));
            lines.push(Line::raw(""));
        }
        if lines.is_empty() {
            lines.extend([
                Line::raw(""),
                Line::styled("No messages yet", Style::default().fg(palette.text).bold())
                    .centered(),
                Line::styled(
                    "Start with something small. It will be encrypted before it leaves.",
                    Style::default().fg(palette.muted),
                )
                .centered(),
            ]);
        }
        let message_area = centered_width(parts[1], message_width).inner(Margin {
            horizontal: 0,
            vertical: 1,
        });
        let total_lines = wrapped_line_count(&lines, message_area.width);
        let messages = Paragraph::new(lines).wrap(Wrap { trim: false });
        let max_scroll = total_lines.saturating_sub(message_area.height as usize);
        let scroll_back = usize::from(chat.scroll_back).min(max_scroll);
        let scroll = u16::try_from(max_scroll.saturating_sub(scroll_back)).unwrap_or(u16::MAX);
        frame.render_widget(messages.scroll((scroll, 0)), message_area);
        let composer_area = centered_width(parts[2], parts[2].width.saturating_sub(6).max(1));
        let composer_width = usize::from(composer_area.width.saturating_sub(8)).max(1);
        let input_characters = self.input.chars().count();
        let prompt = if self.input.is_empty() {
            if chat.active_thread.is_some() {
                Cow::Borrowed("Reply in this thread…")
            } else {
                Cow::Owned(format!(
                    "Message {}…",
                    composer_recipient(&chat.name, &chat.handle)
                ))
            }
        } else if input_characters <= composer_width {
            Cow::Borrowed(self.input.as_str())
        } else {
            Cow::Owned(format!(
                "…{}",
                self.input
                    .chars()
                    .skip(input_characters - composer_width.saturating_sub(1))
                    .collect::<String>()
            ))
        };
        let color = if self.input.is_empty() {
            palette.muted
        } else {
            palette.text
        };
        let composer_title = if chat.active_thread.is_some() {
            " THREAD MODE "
        } else if self.input.starts_with('/') {
            " COMMAND MODE "
        } else {
            " MESSAGE MODE "
        };
        let action_hint = if self.input.starts_with('/') {
            " Enter run · Esc cancel · Ctrl+K actions "
        } else if composer_area.width >= 66 {
            " Enter send · Esc cancel · Ctrl+K actions "
        } else {
            " Enter send · Ctrl+K actions "
        };
        let contextual_notice = self.ui.notice_for(NoticeScope::Composer);
        let composer_hint = contextual_notice.map_or(action_hint, |notice| notice.message.as_str());
        let composer_hint_color = contextual_notice
            .map(|notice| severity_color(notice.severity, palette))
            .unwrap_or(palette.muted);
        let composer_border = if self.ui.mode.is_composer() {
            palette.mint
        } else {
            palette.line
        };
        let composer = Paragraph::new(Line::from(vec![
            Span::styled("› ", Style::default().fg(palette.mint).bold()),
            Span::styled(prompt.as_ref(), Style::default().fg(color)),
        ]))
        .block(
            Block::new()
                .title(Line::styled(
                    composer_title,
                    Style::default().fg(palette.mint).bold(),
                ))
                .title_bottom(
                    Line::styled(composer_hint, Style::default().fg(composer_hint_color))
                        .right_aligned(),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(composer_border))
                .padding(Padding::new(1, 1, 1, 1)),
        )
        .style(Style::default().bg(palette.panel));
        frame.render_widget(composer, composer_area);
        let cursor_characters = if self.input.is_empty() {
            0
        } else {
            prompt.chars().count()
        };
        if self.ui.mode.is_composer() {
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
                Span::styled(" message", Style::default().fg(palette.muted)),
            ],
            UiMode::Composer(_) => vec![
                Span::styled(
                    " Tab ",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(" conversations  ·  ", Style::default().fg(palette.muted)),
                Span::styled(
                    " PgUp/PgDn ",
                    Style::default().fg(palette.text).bg(palette.keycap).bold(),
                ),
                Span::styled(" history", Style::default().fg(palette.muted)),
            ],
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
            UiMode::Verification | UiMode::Devices => vec![
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
                0 => palette.mint,
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
        let height = (self.conversations.len() as u16 * 2 + 5).min(22);
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
                    Span::styled(unread, Style::default().fg(palette.mint).bold()),
                ]),
                Line::styled(
                    format!("   {}", display_handle(&chat.handle)),
                    Style::default().fg(palette.muted),
                ),
            ]))
            .style(if selected {
                Style::default().bg(palette.selected)
            } else {
                Style::default()
            })
        });
        frame.render_widget(
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
                        .fg(palette.contrasting_text(palette.mint))
                        .bg(palette.mint)
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
                ("CURRENT", palette.mint)
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
        VerificationState::Verified => ("✓ safety code verified", palette.mint),
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
        VerificationState::Verified => ("✓ Identity verified", palette.mint),
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
        VerificationState::Verified => ("✓ Verified", palette.mint),
        VerificationState::Changed => ("⚠ Keys changed", palette.danger),
        VerificationState::Unavailable => ("⚠ Check unavailable", palette.warning),
    }
}

fn trust_lens_labels(
    state: VerificationState,
    palette: ThemePalette,
) -> (&'static str, Color, &'static str) {
    match state {
        VerificationState::NotApplicable => ("Local conversation", palette.muted, "Local only"),
        VerificationState::Unverified => {
            ("Identity not verified", palette.warning, "Verify identity")
        }
        VerificationState::Verified => ("Identity verified", palette.success, "View identity"),
        VerificationState::Changed => ("Device keys changed", palette.danger, "Review identity"),
        VerificationState::Unavailable => (
            "Safety status unavailable",
            palette.warning,
            "Check identity",
        ),
    }
}

fn action_hint_line(
    key: &'static str,
    label: &'static str,
    palette: ThemePalette,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {key} "),
            Style::default().fg(palette.text).bg(palette.keycap).bold(),
        ),
        Span::styled(format!("  {label}"), Style::default().fg(palette.text)),
    ])
}

fn severity_color(severity: NoticeSeverity, palette: ThemePalette) -> Color {
    match severity {
        NoticeSeverity::Info => palette.secondary,
        NoticeSeverity::Success => palette.success,
        NoticeSeverity::Warning => palette.warning,
        NoticeSeverity::Error => palette.danger,
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
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
        .find(|message| message.thread_root.is_none())
        .map_or_else(
            || "No messages yet".into(),
            |message| {
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

fn wrapped_line_count(lines: &[Line<'_>], width: u16) -> usize {
    let width = usize::from(width).max(1);
    lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(width))
        .sum()
}

fn wrap_message_body(text: &str, width: usize) -> Vec<String> {
    const INDENT: &str = "    ";
    let content_width = width.saturating_sub(INDENT.len()).max(1);
    let mut lines = Vec::new();
    for paragraph in text.lines() {
        if paragraph.is_empty() {
            lines.push(INDENT.into());
            continue;
        }
        let mut current = String::new();
        for word in paragraph.split_whitespace() {
            let required =
                current.chars().count() + usize::from(!current.is_empty()) + word.chars().count();
            if required > content_width && !current.is_empty() {
                lines.push(format!("{INDENT}{current}"));
                current.clear();
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
        lines.push(format!("{INDENT}{current}"));
    }
    if lines.is_empty() {
        lines.push(INDENT.into());
    }
    lines
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
        assert!(screen.contains("TRUST LENS"));
        assert!(screen.contains("Verify identity"));
        assert!(screen.contains("End-to-end encrypted"));
        assert!(screen.contains("Message @mira"));
        assert!(screen.contains("Ctrl+K actions"));
        assert!(!screen.contains('#'));
    }

    #[test]
    fn selected_conversation_uses_a_full_row_tint() {
        let app = App::new(profile(), true);
        let selected = app.theme.palette().selected;
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| app.draw(frame)).unwrap();

        let buffer = terminal.backend().buffer();
        for y in 6..12 {
            assert_eq!(buffer.cell((1, y)).expect("selected row cell").bg, selected);
        }
    }

    #[test]
    fn trust_rail_collapses_before_the_conversation_list() {
        let app = App::new(profile(), true);

        let medium = render(&app, 100, 32);
        let compact = render(&app, 80, 24);

        assert!(medium.contains("Conversations"));
        assert!(!medium.contains("TRUST LENS"));
        assert!(!compact.contains("Conversations"));
        assert!(compact.contains("Message @mira"));
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
    fn message_copy_keeps_a_readable_measure_inside_the_wide_lane() {
        let lines = wrap_message_body(
            "A deliberately long encrypted message should wrap without forcing the surrounding message divider to become narrow or exposing transport details in the reading flow.",
            MESSAGE_BODY_MAXIMUM_WIDTH,
        );

        assert!(lines.len() > 1);
        assert!(
            lines
                .iter()
                .all(|line| line.chars().count() <= MESSAGE_BODY_MAXIMUM_WIDTH)
        );
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
        assert_eq!(app.ui.mode, UiMode::Composer(ComposerMode::Message));
    }

    #[tokio::test]
    async fn compact_layout_opens_a_visible_conversation_switcher() {
        let mut app = App::new(profile(), true);

        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE), None)
            .await;
        let screen = render(&app, 80, 24);

        assert!(screen.contains("Switch conversation"));
        assert!(screen.contains("Enter open"));
    }

    #[tokio::test]
    async fn command_palette_supports_arrow_and_enter_selection() {
        let mut app = App::new(profile(), true);

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
        assert_eq!(app.input, "/send ");
        assert_eq!(app.ui.mode, UiMode::Composer(ComposerMode::Command));
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
        let notice = app.ui.notice.as_ref().expect("draft preservation notice");
        assert!(notice.message.contains("draft kept"));
        assert_eq!(notice.severity, NoticeSeverity::Warning);
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
                .take(3)
                .any(|line| line.contains("mailbox unavailable"))
        );
        assert!(screen.contains("send failed beside composer"));
    }
}
