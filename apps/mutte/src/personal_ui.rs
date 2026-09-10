//! Terminal-native personal messaging screens. All network actions use the engine.
use super::*;
use anyhow::{bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use mutte_client::{
    personal::{Keepsake, KeepsakeItem},
    polls::PollWire,
};
use mutte_store::NotificationMode as ChatNotifications;
use std::{collections::BTreeSet, io::Write};
use unicode_segmentation::UnicodeSegmentation;

#[derive(Clone)]
enum Action {
    Page(&'static str),
    Command(String),
    Chat(Uuid, Option<Uuid>, Option<Uuid>),
    Form(Form),
    Hold(Uuid),
    DiscardHold(Uuid),
    Poll(Uuid),
    Vote(Uuid, usize),
    SaveVote(Uuid),
    ClosePoll(Uuid),
    Keep(Uuid),
    Select(Uuid),
    SaveKeep,
    DeleteKeep(Uuid),
    Nothing,
}
#[derive(Clone)]
enum Form {
    Search(Option<Uuid>),
    Poll,
    Note(Uuid),
    Keep(Option<Uuid>),
    Export(Uuid),
}
#[derive(Clone)]
struct Row {
    text: String,
    action: Action,
}
pub(super) struct Panel {
    title: String,
    help: String,
    rows: Vec<Row>,
    selected: usize,
    form: Option<Form>,
    fields: Vec<(String, String)>,
}
#[derive(Default)]
pub(super) struct PersonalUi {
    restored_holds: HashMap<ConversationScope, Uuid>,
    pub panel: Option<Panel>,
    quiet_undo: Option<(Uuid, bool, ChatNotifications)>,
    chosen: BTreeSet<Uuid>,
    keep_conversation: Option<Uuid>,
    selection_filter: u8,
    poll_choices: BTreeSet<usize>,
    poll_target: Option<Uuid>,
}
impl Panel {
    fn new(title: &str, help: &str) -> Self {
        Self {
            title: title.into(),
            help: help.into(),
            rows: vec![],
            selected: 0,
            form: None,
            fields: vec![],
        }
    }
    fn row(&mut self, text: impl Into<String>, action: Action) {
        self.rows.push(Row {
            text: text.into(),
            action,
        });
    }
    fn page(&mut self, title: &str, page: &'static str) {
        self.row(title, Action::Page(page));
    }
    fn reading(&mut self, text: &str) {
        for line in wrap_cells(text, 64) {
            self.row(line, Action::Nothing);
        }
    }
}
impl App {
    fn clear_personal_error(&mut self) {
        if self
            .ui
            .notice_for(NoticeScope::Composer)
            .is_some_and(|n| n.severity == NoticeSeverity::Error)
        {
            self.ui.clear_notice_scope(NoticeScope::Composer);
        }
    }
    pub(super) fn refresh_personal_poll(&mut self) {
        let active = self
            .personal_ui
            .panel
            .as_ref()
            .filter(|p| {
                p.rows
                    .iter()
                    .any(|r| matches!(r.action, Action::Vote(_, _) | Action::SaveVote(_)))
            })
            .map(|p| p.selected);
        if let (Some(selected), Some(id)) = (active, self.personal_ui.poll_target)
            && self.show_poll(id).is_ok()
            && let Some(p) = &mut self.personal_ui.panel
        {
            p.selected = selected.min(p.rows.len().saturating_sub(1));
        }
    }
    pub(super) fn has_restored_hold(&self) -> bool {
        self.personal_ui.restored_holds.contains_key(&self.scope())
    }
    fn commit_personal(&mut self, next: PersonalState) -> Result<()> {
        self.client.save_personal_state(&next)?;
        self.personal = next;
        Ok(())
    }
    pub(super) fn personal_result(&mut self, result: Result<()>) {
        if let Err(error) = result {
            self.ui.set_notice(
                NoticeSeverity::Error,
                NoticeScope::Composer,
                error.to_string(),
            );
            if let Some(panel) = &mut self.personal_ui.panel {
                panel.help = format!("{error} · Esc back");
            }
        }
    }
    pub(super) fn hold_draft(&mut self) -> Result<()> {
        let (id, thread_root) = self.scope();
        let conversation_id = id.context("Open a chat first with Ctrl+N")?;
        let mut next = self.personal.clone();
        if let Some(id) = self.personal_ui.restored_holds.get(&self.scope()) {
            next.holds.retain(|h| h.id != *id);
        }
        next.holds.push(HeldText {
            id: Uuid::new_v4(),
            conversation_id,
            text: self.input.clone(),
            reply_to: self.reply_to.or(thread_root),
            thread_root,
            deadline: Utc::now() + chrono::Duration::seconds(i64::from(next.undo_seconds)),
            phase: HoldPhase::Holding,
        });
        self.commit_personal(next)?;
        self.personal_ui.restored_holds.remove(&self.scope());
        self.input.clear();
        self.reply_to = None;
        self.ui.set_notice(
            NoticeSeverity::Success,
            NoticeScope::Composer,
            format!(
                "Sending in {}s · Ctrl+Z Undo · F5 → Sending",
                self.personal.undo_seconds
            ),
        );
        Ok(())
    }
    pub(super) fn suspend_holds(&mut self) -> Result<()> {
        if !self
            .personal
            .holds
            .iter()
            .any(|h| matches!(h.phase, HoldPhase::Holding | HoldPhase::Submitting))
        {
            return Ok(());
        }
        let mut next = self.personal.clone();
        next.recover();
        if let Err(error) = self.commit_personal(next.clone()) {
            // Never let a failed disk write leave a live timer. The durable old
            // Holding/Submitting marker recovers to Draft/Uncertain at startup.
            self.personal = next;
            return Err(error);
        }
        Ok(())
    }
    pub(super) async fn advance_holds(&mut self, connection: Option<&Connection<'_>>) {
        if !self.window_focused {
            let result = self.suspend_holds();
            self.personal_result(result);
            return;
        }
        let due: Vec<_> = self
            .personal
            .holds
            .iter()
            .filter(|h| h.phase == HoldPhase::Holding && h.deadline <= Utc::now())
            .map(|h| h.id)
            .collect();
        for id in due {
            let result = self.submit_hold(id, connection).await;
            self.personal_result(result);
        }
    }
    async fn submit_hold(&mut self, id: Uuid, connection: Option<&Connection<'_>>) -> Result<()> {
        let hold = self
            .personal
            .holds
            .iter()
            .find(|h| h.id == id && h.phase == HoldPhase::Holding)
            .cloned()
            .context("Held message is unavailable")?;
        let mut next = self.personal.clone();
        next.holds.iter_mut().find(|h| h.id == id).unwrap().phase = HoldPhase::Submitting;
        if let Err(error) = self.commit_personal(next) {
            self.suspend_holds()?;
            return Err(error);
        }
        let selected = self.selected;
        let old_threads: Vec<_> = self.conversations.iter().map(|c| c.active_thread).collect();
        let result = self
            .client
            .execute(
                connection,
                ClientCommand::SendMessage {
                    conversation_id: hold.conversation_id,
                    text: hold.text,
                    reply_to: hold.reply_to,
                    thread_root: hold.thread_root,
                },
            )
            .await;
        self.selected = selected;
        for (chat, scope) in self.conversations.iter_mut().zip(old_threads) {
            chat.active_thread = scope;
        }
        let mut next = self.personal.clone();
        if result.is_ok() {
            next.holds.retain(|h| h.id != id);
        } else {
            next.holds.iter_mut().find(|h| h.id == id).unwrap().phase = HoldPhase::Uncertain;
        }
        if let Err(error) = self.commit_personal(next) {
            self.personal
                .holds
                .iter_mut()
                .find(|h| h.id == id)
                .unwrap()
                .phase = HoldPhase::Uncertain;
            return Err(error.context("Send may have completed. Check history before resending"));
        }
        self.handle_client_events();
        result.map_err(|e| e.context("Send outcome needs review. Check history before resending"))
    }
    fn restore_hold(&mut self, id: Uuid) -> Result<()> {
        let hold = self
            .personal
            .holds
            .iter()
            .find(|h| h.id == id)
            .cloned()
            .context("Draft unavailable")?;
        let index = self
            .conversations
            .iter()
            .position(|c| c.conversation_id == Some(hold.conversation_id))
            .context("Original conversation unavailable")?;
        let scope = (Some(hold.conversation_id), hold.thread_root);
        ensure!(
            !(self.draft_scope == scope && !self.input.is_empty())
                && !self.drafts.get(&scope).is_some_and(|d| !d.text.is_empty()),
            "A draft already exists there; send or clear it before restoring this one"
        );
        let mut next = self.personal.clone();
        // Keep a durable draft until it is handed off, replaced by a new hold,
        // or explicitly discarded. Ctrl+Z never destroys the only saved copy.
        next.holds.iter_mut().find(|h| h.id == id).unwrap().phase = HoldPhase::Draft;
        self.commit_personal(next)?;
        self.selected = index;
        self.conversations[index].active_thread = hold.thread_root;
        self.personal_ui.restored_holds.insert(scope, id);
        self.sync_draft_scope();
        self.input = hold.text;
        self.reply_to = hold.reply_to;
        self.personal_ui.panel = None;
        self.ui.focus_composer();
        self.ui.set_notice(
            NoticeSeverity::Info,
            NoticeScope::Composer,
            "Draft restored. Nothing sent; its saved copy is replaced when you send.",
        );
        Ok(())
    }
    pub(super) fn open_personal(&mut self, page: &str) {
        let mut p = Panel::new(
            "Mutte",
            "↑↓ choose · Enter open · Esc close · F5 home · F6 search",
        );
        match page {
            "home" => {
                p.title = "Chats".into();
                p.page("Search this device", "search");
                p.row("New message", Action::Command("/dm ".into()));
                for chat in &self.conversations {
                    if let Some(id) = chat.conversation_id {
                        if self.conversation_preferences(id).is_ok_and(|p| p.quiet) {
                            continue;
                        }
                        p.row(
                            format!("{} · {} unread", chat.name, chat.unread),
                            Action::Chat(id, None, None),
                        );
                    }
                }
                p.page("Quiet · past moments, still here", "quiet");
                p.page("Keepsakes · chosen by you", "keepsakes");
                p.page(
                    &format!(
                        "Sending · {} held / saved drafts",
                        self.personal.holds.len()
                    ),
                    "sending",
                );
                p.page("People", "people");
                p.page("Settings", "settings");
            }
            "people" | "quiet" => {
                p.title = if page == "people" { "People" } else { "Quiet" }.into();
                for chat in &self.conversations {
                    let Some(id) = chat.conversation_id else {
                        continue;
                    };
                    if page == "quiet" && !self.conversation_preferences(id).is_ok_and(|p| p.quiet)
                    {
                        continue;
                    }
                    p.row(
                        format!(
                            "{} · history {}{}",
                            chat.name,
                            &id.to_string()[..8],
                            self.personal
                                .notes
                                .get(&id)
                                .map(|n| format!(" · Private note: {n}"))
                                .unwrap_or_default()
                        ),
                        Action::Chat(id, None, None),
                    );
                }
                if p.rows.is_empty() {
                    p.row("Nothing here yet", Action::Nothing);
                }
                if page == "people" {
                    p.row("New message · exact handle", Action::Command("/dm ".into()));
                }
            }
            "search" => {
                self.open_form(Form::Search(None));
                return;
            }
            "search-chat" => {
                self.open_form(Form::Search(self.scope().0));
                return;
            }
            "poll" => {
                self.open_form(Form::Poll);
                return;
            }
            "settings" => {
                p.title = "Settings".into();
                p.row(
                    format!("{} · @{}", self.profile.display_name, self.profile.handle),
                    Action::Nothing,
                );
                p.page("Sending · Off / 5 / 10 seconds", "sending");
                p.page("Conversation notifications & Quiet", "preferences");
                for mode in ["auto", "bell", "off"] {
                    p.row(
                        format!(
                            "Terminal alerts: {mode}{}",
                            if self.personal.terminal_alerts.as_deref().unwrap_or("auto") == mode {
                                " ✓"
                            } else {
                                ""
                            }
                        ),
                        Action::Command(format!("/alerts {mode}")),
                    );
                }
                p.row(
                    format!("Read receipts: {} · toggle", self.read_receipts_enabled()),
                    Action::Command(format!(
                        "/read-receipts {}",
                        if self.read_receipts_enabled() {
                            "off"
                        } else {
                            "on"
                        }
                    )),
                );
                p.row("Your devices", Action::Command("/devices".into()));
                p.row(
                    "Verify current conversation",
                    Action::Command("/verify".into()),
                );
                p.page("Storage & uploads", "storage");
                p.page("Share Mutte", "share");
                p.row(
                    "Appearance follows terminal theme · NO_COLOR supported",
                    Action::Nothing,
                );
                p.row(
                    "Privacy: private notes, drafts and keepsakes stay on this device",
                    Action::Nothing,
                );
                p.row(
                    "Free · ad-free · voluntary support · https://mutte.me",
                    Action::Nothing,
                );
                p.row(
                    "Close Mutte · use your OS lock to protect this terminal",
                    Action::Command("/quit".into()),
                );
                p.page("Sign out of this terminal…", "sign-out");
            }
            "preferences" => {
                p.title = "Conversation preferences".into();
                p.page("Search this conversation · Photos & files", "search-chat");
                let Some(id) = self.scope().0 else {
                    self.open_personal("home");
                    return;
                };
                let preferences = self.conversation_preferences(id).unwrap_or_default();
                p.row(
                    if preferences.quiet {
                        "Move back to Chats"
                    } else {
                        "Move to Quiet"
                    },
                    Action::Command(
                        if preferences.quiet {
                            "/quiet off"
                        } else {
                            "/quiet on"
                        }
                        .into(),
                    ),
                );
                if self.personal_ui.quiet_undo.is_some() {
                    p.row(
                        "Undo last Quiet move",
                        Action::Command("/quiet undo".into()),
                    );
                }
                p.row(
                    "Private note · optional, only on this device",
                    Action::Form(Form::Note(id)),
                );
                for (label, value) in [
                    ("All messages", "all"),
                    ("Following + mentions", "following"),
                    ("Off", "off"),
                ] {
                    p.row(
                        format!("Notifications: {label}"),
                        Action::Command(format!("/notifications {value}")),
                    );
                }
                p.row(
                    format!(
                        "Current policy: {:?} · Quiet: {}",
                        preferences.notification_mode, preferences.quiet
                    ),
                    Action::Nothing,
                );
                if let Some(root) = self.scope().1 {
                    p.row(
                        if preferences.followed_threads.contains(&root) {
                            "Unfollow this discussion"
                        } else {
                            "Follow this discussion"
                        },
                        Action::Command(format!(
                            "/follow {}",
                            if preferences.followed_threads.contains(&root) {
                                "off"
                            } else {
                                "on"
                            }
                        )),
                    );
                }
                p.row(
                    "Following never overrides Off. Quiet is a personal choice.",
                    Action::Nothing,
                );
            }
            "sending" => {
                p.title = "Sending".into();
                for seconds in [0, 5, 10] {
                    p.row(
                        format!(
                            "{}{}",
                            if seconds == 0 {
                                "Off".into()
                            } else {
                                format!("{seconds} seconds")
                            },
                            if self.personal.undo_seconds == seconds {
                                " ✓"
                            } else {
                                ""
                            }
                        ),
                        Action::Command(format!("/sending {seconds}")),
                    );
                }
                p.row(
                    "Holds stay local. Leaving the terminal makes them drafts.",
                    Action::Nothing,
                );
                for hold in &self.personal.holds {
                    p.row(
                        format!(
                            "{:?}: {} · {}",
                            hold.phase,
                            &hold.conversation_id.to_string()[..8],
                            truncate_text(&hold.text, 44)
                        ),
                        Action::Hold(hold.id),
                    );
                }
            }
            "keepsakes" => {
                p.title = "Keepsakes".into();
                p.page("Create a keepsake from this conversation", "select-new");
                for keep in &self.personal.keepsakes {
                    p.row(
                        format!("{} · {} moments", keep.title, keep.items.len()),
                        Action::Keep(keep.id),
                    );
                }
                p.row(
                    "Private snapshots. Other devices and account recovery do not restore them.",
                    Action::Nothing,
                );
            }
            "select-new" | "select" => {
                if page == "select-new" {
                    self.personal_ui.chosen.clear();
                    self.personal_ui.keep_conversation = self.scope().0;
                    self.personal_ui.selection_filter = 0;
                }
                p.title = format!(
                    "Choose moments · {} selected",
                    self.personal_ui.chosen.len()
                );
                p.help =
                    "Space select · Enter select/save · f filter All/Photos/Messages · Esc back"
                        .into();
                p.row("Continue → title & introduction", Action::SaveKeep);
                p.row(
                    format!(
                        "Filter: {}",
                        ["All", "Photos", "Messages"][self.personal_ui.selection_filter as usize]
                    ),
                    Action::Nothing,
                );
                if let Some(chat) = self
                    .conversations
                    .iter()
                    .find(|c| c.conversation_id == self.personal_ui.keep_conversation)
                {
                    for message in &chat.messages {
                        if is_reaction_for_known_message(&chat.messages, message)
                            || is_poll_event(&chat.messages, message)
                            || message.delivery == mutte_store::DeliveryState::Cancelled
                        {
                            continue;
                        }
                        let photo = message
                            .attachment
                            .as_ref()
                            .is_some_and(|a| photo_filename(&a.metadata.filename));
                        if self.personal_ui.selection_filter == 1 && !photo
                            || self.personal_ui.selection_filter == 2
                                && message.attachment.is_some()
                        {
                            continue;
                        }
                        let body = PollState::fold(message, &chat.messages)
                            .map(|s| s.question)
                            .unwrap_or_else(|| message.text.clone());
                        p.row(
                            format!(
                                "[{}] {} · {}",
                                if self.personal_ui.chosen.contains(&message.id) {
                                    "x"
                                } else {
                                    " "
                                },
                                message.author,
                                truncate_text(&body, 70)
                            ),
                            Action::Select(message.id),
                        );
                    }
                }
            }
            "storage" => {
                p.title = "Storage & uploads".into();
                for chat in &self.conversations {
                    for message in &chat.messages {
                        if let Some(file) = &message.attachment
                            && let Some(id) = chat.conversation_id
                        {
                            p.row(
                                format!(
                                    "{} · {} · {}",
                                    file.metadata.filename,
                                    format_bytes(file.metadata.plaintext_size),
                                    if file.local_path.is_some() {
                                        "Downloaded"
                                    } else if file.download_requested {
                                        "Download queued"
                                    } else {
                                        "Open message"
                                    }
                                ),
                                Action::Chat(id, message.thread_root, Some(message.id)),
                            );
                        }
                    }
                }
                if p.rows.is_empty() {
                    p.row(
                        "No attachments yet · Ctrl+O to share a file",
                        Action::Nothing,
                    );
                }
                p.row("Open a file's message, then A for download/preview. Ctrl+C cancels an active transfer.", Action::Nothing);
            }
            "share" => {
                p.title = "Share Mutte".into();
                p.row("https://mutte.me", Action::Nothing);
                p.row(
                    format!("Find me on Mutte: @{}", self.profile.handle),
                    Action::Nothing,
                );
                p.row("Share this app link and your handle. New contacts start a private chat with your exact handle.", Action::Nothing);
            }
            "sign-out" => {
                p.title = "Sign out of this terminal?".into();
                p.reading("Signing in again links a new device. Existing chats and private notes/keepsakes will not automatically reappear. Queued messages will not be sent. This removes the saved local sign-in; it does not delete your account or revoke this device on the relay.");
                p.page("Cancel", "settings");
                p.row("Sign out", Action::Command("/sign-out confirm".into()));
                p.selected = p.rows.len().saturating_sub(2);
            }
            _ => return,
        }
        self.personal_ui.panel = Some(p);
    }
    fn open_form(&mut self, form: Form) {
        let mut p = Panel::new("", "Tab/↑↓ fields · Enter continue/save · Esc cancel");
        match &form {
            Form::Search(scope) => {
                p.title = if scope.is_some() {
                    "Search this conversation"
                } else {
                    "Search this device"
                }
                .into();
                p.fields = vec![
                    ("Query".into(), String::new()),
                    (
                        "Filter: all / photos / files / messages / people".into(),
                        "all".into(),
                    ),
                ];
            }
            Form::Poll => {
                p.title = "New poll".into();
                p.fields = vec![
                    ("Question (120 characters)".into(), String::new()),
                    ("Answer 1".into(), String::new()),
                    ("Answer 2".into(), String::new()),
                    ("Answer 3 (optional)".into(), String::new()),
                    ("Answer 4 (optional)".into(), String::new()),
                    ("Answer 5 (optional)".into(), String::new()),
                    ("Multiple answers: yes / no".into(), "no".into()),
                ];
            }
            Form::Note(id) => {
                p.title = "Private note".into();
                p.fields = vec![(
                    "Only on this device · 280 characters · empty removes".into(),
                    self.personal.notes.get(id).cloned().unwrap_or_default(),
                )];
            }
            Form::Keep(id) => {
                p.title = "Keepsake details".into();
                let keep = id.and_then(|id| self.personal.keepsakes.iter().find(|k| k.id == id));
                p.fields = vec![
                    (
                        "Title".into(),
                        keep.map(|k| k.title.clone()).unwrap_or_default(),
                    ),
                    (
                        "Private introduction (optional)".into(),
                        keep.map(|k| k.introduction.clone()).unwrap_or_default(),
                    ),
                ];
            }
            Form::Export(_) => {
                p.title = "Export readable HTML".into();
                p.help = "Includes private introduction and photos. Anyone with the file can read it. Not an encrypted backup. Enter confirms export; Esc cancels.".into();
                p.fields = vec![("New file path (will not overwrite)".into(), String::new())];
            }
        }
        p.form = Some(form);
        self.personal_ui.panel = Some(p);
    }
    fn show_poll(&mut self, id: Uuid) -> Result<()> {
        let chat = &self.conversations[self.selected];
        let root = chat
            .messages
            .iter()
            .find(|m| m.id == id)
            .context("Poll unavailable")?;
        let state = PollState::fold(root, &chat.messages).context("Select a poll message first")?;
        let mine = root.mine;
        if self.personal_ui.poll_target != Some(id) {
            self.personal_ui.poll_choices = state
                .votes
                .get(mutte_client::polls::LOCAL_VOTER)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect();
            self.personal_ui.poll_target = Some(id);
        }
        let mut p = Panel::new(
            &state.question,
            "↑↓ choose · Space/Enter toggle · Submit saves · Esc closes",
        );
        for (index, option) in state.options.iter().enumerate() {
            let voters = state.voters(index);
            p.row(
                format!(
                    "[{}] {} · {} votes{}",
                    if self.personal_ui.poll_choices.contains(&index) {
                        "x"
                    } else {
                        " "
                    },
                    option,
                    voters.len(),
                    if voters.is_empty() {
                        String::new()
                    } else {
                        format!(" · {}", voters.join(", "))
                    }
                ),
                if state.closed {
                    Action::Nothing
                } else {
                    Action::Vote(id, index)
                },
            );
        }
        if state.closed {
            p.row("Closed · results are final", Action::Nothing);
        } else {
            p.row(
                "Submit vote · uncheck all to withdraw",
                Action::SaveVote(id),
            );
            if mine {
                p.row("Close poll…", Action::ClosePoll(id));
            }
        }
        p.row(
            if state.multiple {
                "Multiple answers · voters are named"
            } else {
                "One answer · voters are named"
            },
            Action::Nothing,
        );
        self.personal_ui.panel = Some(p);
        Ok(())
    }
    async fn send_poll_event(
        &mut self,
        id: Uuid,
        close: bool,
        connection: Option<&Connection<'_>>,
    ) -> Result<()> {
        let chat = &self.conversations[self.selected];
        let root = chat
            .messages
            .iter()
            .find(|m| m.id == id)
            .context("Poll unavailable")?;
        let state = PollState::fold(root, &chat.messages).context("Invalid poll")?;
        ensure!(!state.closed, "This poll is closed");
        ensure!(!close || root.mine, "Only the creator can close this poll");
        let choices: Vec<_> = self.personal_ui.poll_choices.iter().copied().collect();
        ensure!(state.multiple || choices.len() <= 1, "Select one answer");
        let command = ClientCommand::SendMessage {
            conversation_id: chat.conversation_id.context("Open a chat first")?,
            text: if close {
                PollWire::close()
            } else {
                PollWire::vote(choices)?
            },
            reply_to: Some(id),
            thread_root: root.thread_root,
        };
        self.client.execute(connection, command).await?;
        self.personal_ui.poll_target = None;
        self.show_poll(id)
    }
    fn show_keep(&mut self, id: Uuid) -> Result<()> {
        let keep = self
            .personal
            .keepsakes
            .iter()
            .find(|k| k.id == id)
            .context("Keepsake unavailable")?;
        let mut p = Panel::new(
            &keep.title,
            "↑↓ read · Enter action · Esc close · Private snapshot",
        );
        p.row(
            "Edit title & introduction",
            Action::Form(Form::Keep(Some(id))),
        );
        p.row("Export readable HTML…", Action::Form(Form::Export(id)));
        p.row("Delete keepsake…", Action::DeleteKeep(id));
        p.reading(&keep.introduction);
        for item in &keep.items {
            p.reading(&format!(
                "{} · {}\n{}{}",
                item.author,
                item.sent_at.format("%Y-%m-%d %H:%M"),
                item.text,
                if item.jpeg_base64.is_some() {
                    "\n[Saved photo · included in HTML export]".into()
                } else {
                    item.filename
                        .as_ref()
                        .map(|n| format!("\n{n} (file name only)"))
                        .unwrap_or_default()
                }
            ));
        }
        self.personal_ui.panel = Some(p);
        Ok(())
    }
    fn snapshot_items(&self) -> Result<Vec<KeepsakeItem>> {
        ensure!(
            (1..=40).contains(&self.personal_ui.chosen.len()),
            "Select 1–40 moments"
        );
        let chat = self
            .conversations
            .iter()
            .find(|c| c.conversation_id == self.personal_ui.keep_conversation)
            .context("Conversation unavailable")?;
        let mut total = 0usize;
        let mut items = Vec::new();
        for message in &chat.messages {
            if !self.personal_ui.chosen.contains(&message.id) {
                continue;
            }
            let mut item = KeepsakeItem {
                id: message.id,
                author: if message.mine {
                    "You".into()
                } else {
                    message.author.clone()
                },
                text: PollState::fold(message, &chat.messages)
                    .map(|s| s.summary())
                    .unwrap_or_else(|| message.text.clone()),
                sent_at: message.timestamp.with_timezone(&Utc),
                filename: message
                    .attachment
                    .as_ref()
                    .map(|f| f.metadata.filename.clone()),
                jpeg_base64: None,
            };
            if let Some(file) = &message.attachment
                && photo_filename(&file.metadata.filename)
            {
                let path = file
                    .local_path
                    .as_ref()
                    .context("Download selected photos before saving a keepsake")?;
                let mut reader = image::ImageReader::open(path)?.with_guessed_format()?;
                let mut limits = image::Limits::default();
                limits.max_alloc = Some(128 * 1024 * 1024);
                limits.max_image_width = Some(16384);
                limits.max_image_height = Some(16384);
                reader.limits(limits);
                let image = reader.decode()?.thumbnail(1600, 1600).to_rgb8();
                let mut jpeg = Vec::new();
                image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 85)
                    .encode_image(&image)?;
                total += jpeg.len();
                ensure!(
                    total <= 20 * 1024 * 1024,
                    "Selected photo snapshots exceed 20 MiB"
                );
                item.jpeg_base64 = Some(STANDARD.encode(jpeg));
                item.filename = None;
            }
            items.push(item);
        }
        ensure!(
            items.len() == self.personal_ui.chosen.len(),
            "A selected moment is no longer available"
        );
        Ok(items)
    }
    fn search_personal(&mut self, query: &str, filter: &str) -> Result<()> {
        self.search_personal_scoped(query, filter, None)
    }
    fn search_personal_scoped(
        &mut self,
        query: &str,
        filter: &str,
        scope: Option<Uuid>,
    ) -> Result<()> {
        ensure!(
            ["all", "photos", "messages", "files", "people"].contains(&filter),
            "Choose all, photos, files, messages or people"
        );
        let query = query.trim().to_lowercase();
        let mut p = Panel::new(
            "Search results · this device",
            "↑↓ choose · Enter opens exact message/thread · Esc close",
        );
        p.row("New search", Action::Form(Form::Search(scope)));
        for chat in &self.conversations {
            if scope.is_some() && chat.conversation_id != scope {
                continue;
            }
            let Some(id) = chat.conversation_id else {
                continue;
            };
            if (filter == "all" || filter == "people")
                && format!("{} {}", chat.name, chat.handle)
                    .to_lowercase()
                    .contains(&query)
            {
                p.row(
                    format!("Person: {} · history {}", chat.name, &id.to_string()[..8]),
                    Action::Chat(id, None, None),
                );
            }
            if filter == "all"
                && !query.is_empty()
                && let Some(note) = self
                    .personal
                    .notes
                    .get(&id)
                    .filter(|n| n.to_lowercase().contains(&query))
            {
                p.row(
                    format!("Private note · {}: {note}", chat.name),
                    Action::Chat(id, None, None),
                );
            }
            if filter == "people" {
                continue;
            }
            for message in &chat.messages {
                if is_reaction_for_known_message(&chat.messages, message)
                    || is_poll_event(&chat.messages, message)
                {
                    continue;
                }
                let photo = message
                    .attachment
                    .as_ref()
                    .is_some_and(|f| photo_filename(&f.metadata.filename));
                if filter == "photos" && !photo
                    || filter == "files" && (message.attachment.is_none() || photo)
                    || filter == "messages" && message.attachment.is_some()
                {
                    continue;
                }
                let body = PollState::fold(message, &chat.messages)
                    .map(|s| s.summary())
                    .unwrap_or_else(|| message.text.clone());
                let filename = message
                    .attachment
                    .as_ref()
                    .map(|f| f.metadata.filename.as_str())
                    .unwrap_or("");
                if format!(
                    "{body} {filename} {} {} {}",
                    message.author, chat.name, chat.handle
                )
                .to_lowercase()
                .contains(&query)
                {
                    p.row(
                        format!(
                            "{} · {}\n{}",
                            chat.name,
                            message.timestamp.format("%m/%d %H:%M"),
                            truncate_text(&body, 160)
                        ),
                        Action::Chat(id, message.thread_root, Some(message.id)),
                    );
                }
            }
        }
        if p.rows.len() == 1 {
            p.row("No matches on this device", Action::Nothing);
        }
        self.personal_ui.panel = Some(p);
        Ok(())
    }
    async fn submit_form(
        &mut self,
        form: Form,
        values: Vec<String>,
        connection: Option<&Connection<'_>>,
    ) -> Result<()> {
        match form {
            Form::Search(scope) => {
                self.search_personal_scoped(&values[0], values[1].trim(), scope)?
            }
            Form::Poll => {
                let multiple = match values[6].trim().to_lowercase().as_str() {
                    "yes" => true,
                    "no" => false,
                    _ => bail!("Multiple answers: enter yes or no"),
                };
                let text = PollWire::create(
                    &values[0],
                    values[1..6]
                        .iter()
                        .filter(|s| !s.trim().is_empty())
                        .cloned()
                        .collect(),
                    multiple,
                )?;
                let (id, thread_root) = self.scope();
                self.client
                    .execute(
                        connection,
                        ClientCommand::SendMessage {
                            conversation_id: id.context("Open a chat first")?,
                            text,
                            reply_to: self.reply_to.or(thread_root),
                            thread_root,
                        },
                    )
                    .await?;
                self.personal_ui.panel = None;
                self.ui.focus_composer();
            }
            Form::Note(id) => {
                ensure!(
                    values[0].graphemes(true).count() <= 280,
                    "Private notes are limited to 280 characters"
                );
                let mut next = self.personal.clone();
                if values[0].trim().is_empty() {
                    next.notes.remove(&id);
                } else {
                    next.notes.insert(id, values[0].trim().into());
                }
                self.commit_personal(next)?;
                self.open_personal("preferences");
            }
            Form::Keep(id) => {
                ensure!(
                    !values[0].trim().is_empty() && values[0].graphemes(true).count() <= 80,
                    "Give your keepsake a title up to 80 characters"
                );
                ensure!(
                    values[1].graphemes(true).count() <= 2000,
                    "Introduction is limited to 2000 characters"
                );
                let mut next = self.personal.clone();
                let id = if let Some(id) = id {
                    let keep = next
                        .keepsakes
                        .iter_mut()
                        .find(|k| k.id == id)
                        .context("Keepsake unavailable")?;
                    keep.title = values[0].trim().into();
                    keep.introduction = values[1].clone();
                    id
                } else {
                    let id = Uuid::new_v4();
                    next.keepsakes.push(Keepsake {
                        id,
                        title: values[0].trim().into(),
                        introduction: values[1].clone(),
                        items: self.snapshot_items()?,
                    });
                    id
                };
                self.commit_personal(next)?;
                self.show_keep(id)?;
            }
            Form::Export(id) => {
                let path = PathBuf::from(values[0].trim());
                ensure!(!values[0].trim().is_empty(), "Choose a new .html file path");
                ensure!(
                    path.extension()
                        .is_some_and(|s| s.eq_ignore_ascii_case("html")),
                    "Use a .html filename"
                );
                let keep = self
                    .personal
                    .keepsakes
                    .iter()
                    .find(|k| k.id == id)
                    .context("Keepsake unavailable")?;
                let html = keep.html();
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options
                    .open(&path)
                    .context("Cannot create export; choose a new file in an existing directory")?;
                if let Err(error) = file
                    .write_all(html.as_bytes())
                    .and_then(|_| file.sync_all())
                {
                    let _ = std::fs::remove_file(&path);
                    return Err(error.into());
                }
                self.show_keep(id)?;
                self.ui.set_notice(
                    NoticeSeverity::Success,
                    NoticeScope::Composer,
                    format!("Readable copy exported to {}", path.display()),
                );
            }
        }
        self.clear_personal_error();
        Ok(())
    }
    async fn activate_personal(
        &mut self,
        action: Action,
        connection: Option<&Connection<'_>>,
    ) -> Result<()> {
        match action {
            Action::Page(page) => self.open_personal(page),
            Action::Nothing => {}
            Action::Command(command) => {
                self.personal_ui.panel = None;
                if command.ends_with(' ') {
                    self.prepare_command(&command);
                } else {
                    self.run_text(command, connection, false).await;
                }
            }
            Action::Form(form) => self.open_form(form),
            Action::Chat(id, scope, message) => {
                let index = self
                    .conversations
                    .iter()
                    .position(|c| c.conversation_id == Some(id))
                    .context("Conversation unavailable")?;
                self.selected = index;
                self.conversations[index].active_thread = scope;
                self.conversations[index].scroll_back = 0;
                self.sync_draft_scope();
                self.personal_ui.panel = None;
                self.focus(UiMode::Messages);
                if let Some(message) = message {
                    self.selected_messages.insert(self.scope(), message);
                }
            }
            Action::Hold(id) => {
                let hold = self
                    .personal
                    .holds
                    .iter()
                    .find(|h| h.id == id)
                    .context("Draft unavailable")?;
                if hold.phase == HoldPhase::Holding {
                    self.restore_hold(id)?;
                } else {
                    let mut p = Panel::new(
                        "Saved draft",
                        "Nothing will be sent automatically · Esc back",
                    );
                    p.row(hold.text.clone(), Action::Nothing);
                    if hold.phase == HoldPhase::Uncertain {
                        p.row("Send may have completed. Check conversation history before restoring to avoid a duplicate.", Action::Nothing);
                    }
                    p.row(
                        "Restore to composer",
                        Action::Command(format!("/restore {id}")),
                    );
                    p.row("Discard saved copy…", Action::DiscardHold(id));
                    self.personal_ui.panel = Some(p);
                }
            }
            Action::DiscardHold(id) => {
                let mut p = Panel::new(
                    "Discard saved draft?",
                    "This deletes only the held copy; any message already sent remains.",
                );
                p.page("Cancel", "sending");
                p.row("Discard", Action::Command(format!("/discard-hold {id}")));
                self.personal_ui.panel = Some(p);
            }
            Action::Poll(id) => self.show_poll(id)?,
            Action::Vote(id, index) => {
                let chat = &self.conversations[self.selected];
                let root = chat
                    .messages
                    .iter()
                    .find(|m| m.id == id)
                    .context("Poll unavailable")?;
                let state = PollState::fold(root, &chat.messages).context("Poll unavailable")?;
                ensure!(!state.closed, "Poll is closed");
                if !self.personal_ui.poll_choices.remove(&index) {
                    if !state.multiple {
                        self.personal_ui.poll_choices.clear();
                    }
                    self.personal_ui.poll_choices.insert(index);
                }
                self.show_poll(id)?;
                if let Some(panel) = &mut self.personal_ui.panel {
                    panel.selected = index;
                }
            }
            Action::SaveVote(id) => self.send_poll_event(id, false, connection).await?,
            Action::ClosePoll(id) => {
                let mut p = Panel::new(
                    "Close this poll?",
                    "Closing freezes the result · Esc cancels",
                );
                p.row("Keep open", Action::Poll(id));
                p.row("Close poll", Action::Command(format!("/close-poll {id}")));
                self.personal_ui.panel = Some(p);
            }
            Action::Keep(id) => self.show_keep(id)?,
            Action::Select(id) => {
                let selected = self
                    .personal_ui
                    .panel
                    .as_ref()
                    .map(|p| p.selected)
                    .unwrap_or(0);
                if !self.personal_ui.chosen.remove(&id) {
                    ensure!(
                        self.personal_ui.chosen.len() < 40,
                        "Select at most 40 moments"
                    );
                    self.personal_ui.chosen.insert(id);
                }
                self.open_personal("select");
                if let Some(p) = &mut self.personal_ui.panel {
                    p.selected = selected.min(p.rows.len().saturating_sub(1));
                }
            }
            Action::SaveKeep => {
                ensure!(
                    !self.personal_ui.chosen.is_empty(),
                    "Select at least one moment"
                );
                self.open_form(Form::Keep(None));
            }
            Action::DeleteKeep(id) => {
                let mut p = Panel::new(
                    "Delete this keepsake?",
                    "Source messages and exported copies remain unchanged.",
                );
                p.row("Cancel", Action::Keep(id));
                p.row(
                    "Delete private snapshot",
                    Action::Command(format!("/delete-keep {id}")),
                );
                self.personal_ui.panel = Some(p);
            }
        }
        Ok(())
    }
    pub(super) async fn run_personal_command(
        &mut self,
        input: &str,
        connection: Option<&Connection<'_>>,
    ) -> bool {
        let (cmd, value) = input.split_once(' ').unwrap_or((input, ""));
        let value = value.trim();
        if ![
            "/home",
            "/people",
            "/quiet",
            "/search",
            "/settings",
            "/sending",
            "/alerts",
            "/read-receipts",
            "/sign-out",
            "/undo",
            "/restore",
            "/discard-hold",
            "/notifications",
            "/follow",
            "/note",
            "/poll",
            "/keepsakes",
            "/storage",
            "/share",
            "/close-poll",
            "/delete-keep",
        ]
        .contains(&cmd)
        {
            return false;
        }
        let result: Result<()> = async {
            match cmd {
                "/read-receipts" => {
                    if value.is_empty() {
                        self.open_personal("settings");
                    } else {
                        ensure!(
                            ["on", "off"].contains(&value),
                            "Use /read-receipts on or off"
                        );
                        self.client
                            .execute(connection, ClientCommand::SetReadReceipts(value == "on"))
                            .await?;
                        self.open_personal("settings");
                    }
                }
                "/sign-out" => {
                    if value != "confirm" {
                        self.open_personal("sign-out");
                    } else {
                        self.suspend_holds()?;
                        if !self.demo {
                            let connection = connection.context("Session unavailable")?;
                            let identity = mutte_store::terminal_local_identity_path(
                                connection.api.relay_url(),
                            )?;
                            crate::session_control::request(
                                &identity,
                                connection.device.id(),
                                connection.session.profile.id,
                            )?;
                        }
                        self.should_quit = true;
                    }
                }
                "/alerts" => {
                    let mode = match value {
                        "auto" => NotificationMode::Auto,
                        "bell" => NotificationMode::Bell,
                        "off" => NotificationMode::Off,
                        _ => bail!("Choose auto, bell or off"),
                    };
                    let mut next = self.personal.clone();
                    next.terminal_alerts = Some(value.into());
                    self.commit_personal(next)?;
                    self.notifications.mode = mode;
                    if mode == NotificationMode::Off {
                        self.notifications.clear_if_read(0);
                    }
                    self.open_personal("settings");
                }
                "/home" | "/people" | "/settings" | "/storage" | "/share" | "/keepsakes" => {
                    self.open_personal(cmd.trim_start_matches('/'))
                }
                "/poll" => self.open_personal("poll"),
                "/search" => {
                    if value.is_empty() {
                        self.open_personal("search");
                    } else {
                        self.search_personal(value, "all")?;
                    }
                }
                "/note" => self.open_form(Form::Note(self.scope().0.context("Open a chat first")?)),
                "/sending" => {
                    if !value.is_empty() {
                        let seconds = if value == "off" { 0 } else { value.parse()? };
                        let mut next = self.personal.clone();
                        next.undo_seconds = seconds;
                        self.commit_personal(next)?;
                    }
                    self.open_personal("sending");
                }
                "/undo" => {
                    let id = self
                        .personal
                        .holds
                        .iter()
                        .rev()
                        .find(|h| h.phase == HoldPhase::Holding)
                        .context("No message is waiting to send")?
                        .id;
                    self.restore_hold(id)?;
                }
                "/restore" => self.restore_hold(value.parse()?)?,
                "/discard-hold" => {
                    let id: Uuid = value.parse()?;
                    let mut next = self.personal.clone();
                    next.holds.retain(|h| h.id != id);
                    self.commit_personal(next)?;
                    self.open_personal("sending");
                }
                "/quiet" => {
                    if value.is_empty() {
                        self.open_personal("quiet");
                    } else if value == "undo" {
                        let (id, quiet, mode) = self
                            .personal_ui
                            .quiet_undo
                            .context("No Quiet move to undo")?;
                        self.client
                            .execute(
                                connection,
                                ClientCommand::RestoreConversationAttention {
                                    conversation_id: id,
                                    quiet,
                                    mode,
                                },
                            )
                            .await?;
                        self.personal_ui.quiet_undo = None;
                        self.open_personal("preferences");
                    } else {
                        ensure!(["on", "off"].contains(&value), "Use /quiet on, off or undo");
                        let id = self.scope().0.context("Open a chat first")?;
                        let prior = self.conversation_preferences(id)?;
                        self.client
                            .execute(
                                connection,
                                ClientCommand::SetConversationQuiet {
                                    conversation_id: id,
                                    quiet: value == "on",
                                },
                            )
                            .await?;
                        self.personal_ui.quiet_undo =
                            Some((id, prior.quiet, prior.notification_mode));
                        self.open_personal("preferences");
                    }
                }
                "/notifications" => {
                    let mode = match value {
                        "all" => ChatNotifications::AllMessages,
                        "following" => ChatNotifications::FollowingAndMentions,
                        "off" => ChatNotifications::Off,
                        _ => bail!("Use all, following or off"),
                    };
                    self.client
                        .execute(
                            connection,
                            ClientCommand::SetNotificationMode {
                                conversation_id: self.scope().0.context("Open a chat first")?,
                                mode,
                            },
                        )
                        .await?;
                    self.open_personal("preferences");
                }
                "/follow" => {
                    ensure!(["on", "off"].contains(&value), "Use /follow on or off");
                    let (id, root) = self.scope();
                    self.client
                        .execute(
                            connection,
                            ClientCommand::SetThreadFollowed {
                                conversation_id: id.context("Open a chat first")?,
                                thread_root: root.context("Open a discussion first")?,
                                followed: value == "on",
                            },
                        )
                        .await?;
                    self.open_personal("preferences");
                }
                "/close-poll" => {
                    self.send_poll_event(value.parse()?, true, connection)
                        .await?
                }
                "/delete-keep" => {
                    let id: Uuid = value.parse()?;
                    let mut next = self.personal.clone();
                    next.keepsakes.retain(|k| k.id != id);
                    self.commit_personal(next)?;
                    self.open_personal("keepsakes");
                }
                _ => unreachable!(),
            }
            Ok(())
        }
        .await;
        if result.is_ok() {
            self.command_input.clear();
            self.clear_personal_error();
        }
        self.personal_result(result);
        self.handle_client_events();
        true
    }
    pub(super) async fn handle_personal_key(
        &mut self,
        key: KeyEvent,
        connection: Option<&Connection<'_>>,
    ) -> bool {
        if self.personal_ui.panel.is_none()
            && !matches!(
                self.ui.mode,
                UiMode::Conversations | UiMode::Messages | UiMode::Composer(_) | UiMode::Palette
            )
        {
            return false;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return false;
        }
        if key.code == KeyCode::F(5) {
            self.open_personal("home");
            return true;
        }
        if key.code == KeyCode::F(6) {
            self.open_personal("search");
            return true;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('z') {
            self.run_personal_command("/undo", connection).await;
            return true;
        }
        if self.personal_ui.panel.is_none() {
            if self.ui.mode == UiMode::Messages && matches!(key.code, KeyCode::Char('p' | 'P')) {
                let result = match self.selected_message().map(|m| m.id) {
                    Some(id) => self.show_poll(id),
                    None => Err(anyhow::anyhow!("Select a poll first")),
                };
                self.personal_result(result);
                return true;
            }
            return false;
        }
        if key.code == KeyCode::Esc {
            self.personal_ui.panel = None;
            return true;
        }
        let p = self.personal_ui.panel.as_mut().unwrap();
        if let Some(form) = &p.form {
            let form = form.clone();
            match key.code {
                KeyCode::Tab | KeyCode::Down => p.selected = (p.selected + 1) % p.fields.len(),
                KeyCode::BackTab | KeyCode::Up => {
                    p.selected = (p.selected + p.fields.len() - 1) % p.fields.len()
                }
                KeyCode::Backspace => {
                    p.fields[p.selected].1.pop();
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    p.fields[p.selected].1.clear()
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if p.fields[p.selected].1.len() < 8192 {
                        p.fields[p.selected].1.push(c);
                    }
                }
                KeyCode::Enter => {
                    if p.selected + 1 < p.fields.len() {
                        p.selected += 1;
                    } else {
                        let values = p.fields.iter().map(|(_, v)| v.clone()).collect();
                        let result = self.submit_form(form, values, connection).await;
                        self.personal_result(result);
                    }
                }
                _ => {}
            }
        } else {
            match key.code {
                KeyCode::Up => p.selected = p.selected.saturating_sub(1),
                KeyCode::Down => p.selected = (p.selected + 1).min(p.rows.len().saturating_sub(1)),
                KeyCode::Home => p.selected = 0,
                KeyCode::End => p.selected = p.rows.len().saturating_sub(1),
                KeyCode::PageUp => p.selected = p.selected.saturating_sub(5),
                KeyCode::PageDown => {
                    p.selected = (p.selected + 5).min(p.rows.len().saturating_sub(1))
                }
                KeyCode::Char('f') if p.title.starts_with("Choose moments") => {
                    self.personal_ui.selection_filter = (self.personal_ui.selection_filter + 1) % 3;
                    self.open_personal("select");
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    let action = p.rows.get(p.selected).map(|r| r.action.clone());
                    if let Some(action) = action {
                        let result = self.activate_personal(action, connection).await;
                        self.personal_result(result);
                    }
                }
                _ => {}
            }
        }
        true
    }
    pub(super) fn draw_personal(&self, frame: &mut Frame) {
        let Some(p) = &self.personal_ui.panel else {
            return;
        };
        let palette = self.theme.palette();
        let area = centered(
            frame.area().width.saturating_sub(4).min(88),
            frame.area().height.saturating_sub(4),
            frame.area(),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Block::bordered()
                .title(format!(" {} ", p.title))
                .border_style(Style::default().fg(palette.accent))
                .style(Style::default().bg(palette.panel)),
            area,
        );
        let inner = area.inner(Margin {
            horizontal: 2,
            vertical: 1,
        });
        let total = if p.form.is_some() {
            p.fields.len()
        } else {
            p.rows.len()
        };
        let help = format!("{} / {} · {}", p.selected + 1, total, p.help);
        let help_height = u16::try_from(wrap_cells(&help, usize::from(inner.width).max(1)).len())
            .unwrap_or(u16::MAX)
            .min(inner.height.saturating_sub(3))
            .max(1);
        let parts =
            Layout::vertical([Constraint::Min(3), Constraint::Length(help_height)]).split(inner);
        let rows: Vec<ListItem> = if p.form.is_some() {
            p.fields
                .iter()
                .enumerate()
                .map(|(index, (label, value))| {
                    let shown = if index == p.selected {
                        format!("{}▏", value)
                    } else {
                        value.clone()
                    };
                    let width = usize::from(parts[0].width.saturating_sub(4)).max(1);
                    let mut lines: Vec<_> = wrap_cells(label, width)
                        .into_iter()
                        .map(|line| Line::styled(line, Style::default().fg(palette.muted)))
                        .collect();
                    lines.push(Line::raw(if index == p.selected {
                        // The editing caret and latest graphemes stay visible
                        // for long names, notes and export paths.
                        let width = usize::from(parts[0].width.saturating_sub(4)).max(1);
                        let safe = wrap_cells(&shown, width);
                        safe.last().cloned().unwrap_or_default()
                    } else {
                        truncate_text(&shown, usize::from(parts[0].width.saturating_sub(4)))
                    }));
                    lines.push(Line::raw(""));
                    ListItem::new(Text::from(lines))
                })
                .collect()
        } else {
            p.rows
                .iter()
                .map(|r| {
                    let lines = wrap_cells(
                        &r.text,
                        usize::from(parts[0].width.saturating_sub(4)).max(1),
                    );
                    ListItem::new(Text::from(
                        lines.into_iter().map(Line::raw).collect::<Vec<_>>(),
                    ))
                })
                .collect()
        };
        let mut state = ListState::default().with_selected(Some(p.selected));
        frame.render_stateful_widget(
            List::new(rows)
                .style(Style::default().fg(palette.text))
                .highlight_symbol("› ")
                .highlight_style(
                    Style::default()
                        .bg(palette.keycap)
                        .fg(palette.accent)
                        .bold(),
                ),
            parts[0],
            &mut state,
        );
        frame.render_widget(
            Paragraph::new(help)
                .style(Style::default().fg(palette.muted))
                .wrap(Wrap { trim: false }),
            parts[1],
        );
    }
}

fn photo_filename(name: &str) -> bool {
    PathBuf::from(name).extension().is_some_and(|extension| {
        matches!(
            extension.to_string_lossy().to_lowercase().as_str(),
            "jpg" | "jpeg" | "png" | "gif" | "webp"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutte_store::{DeliveryState, VaultConversation};
    use ratatui::{Terminal, backend::TestBackend};
    fn profile() -> Profile {
        Profile {
            id: Uuid::new_v4(),
            handle: "test_personal".into(),
            display_name: "Mira".into(),
            bio: String::new(),
            status: String::new(),
        }
    }
    fn app() -> App {
        App::new(profile(), true)
    }
    fn render(app: &App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| terminal.backend().buffer()[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    struct Fixture {
        path: PathBuf,
        profile: Profile,
        id: Uuid,
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("mutte-tui-personal-{}", Uuid::new_v4()))
                .join("vault.json");
            let mut vault = Vault::open_at(&path, &[9; 32]).unwrap();
            let id = Uuid::new_v4();
            vault
                .upsert_conversation(VaultConversation {
                    id,
                    peer_handle: "mira".into(),
                    unread: 0,
                })
                .unwrap();
            Self {
                path,
                profile: profile(),
                id,
            }
        }
        fn open(&self) -> App {
            let mut app = App::connected(
                self.profile.clone(),
                Vault::open_at(&self.path, &[9; 32]).unwrap(),
            )
            .unwrap();
            app.selected = app
                .conversations
                .iter()
                .position(|c| c.conversation_id == Some(self.id))
                .unwrap();
            app.sync_draft_scope();
            app
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
        }
    }
    #[tokio::test]
    async fn hold_is_durable_before_transport_and_undo_restores_thread_context() {
        let f = Fixture::new();
        let mut a = f.open();
        a.personal.undo_seconds = 5;
        let root = Uuid::new_v4();
        let selected = a.selected;
        a.conversations[selected].active_thread = Some(root);
        a.sync_draft_scope();
        a.input = "private held text".into();
        a.reply_to = Some(root);
        a.send_draft(None).await;
        assert!(a.input.is_empty());
        assert!(a.conversations[selected].messages.is_empty());
        let recovered = f.open();
        assert_eq!(recovered.personal.holds[0].phase, HoldPhase::Draft);
        assert_eq!(recovered.personal.holds[0].thread_root, Some(root));
        let id = a.personal.holds[0].id;
        a.restore_hold(id).unwrap();
        assert_eq!(a.input, "private held text");
        assert_eq!(a.reply_to, Some(root));
        assert_eq!(a.scope().1, Some(root));
        a.send_draft(None).await;
        assert_eq!(
            a.personal.holds.len(),
            1,
            "resending replaces the restored hold atomically"
        );
        assert_ne!(a.personal.holds[0].id, id);
    }
    #[tokio::test]
    async fn timer_handoff_occurs_once_and_restores_active_chat() {
        let mut a = app();
        a.personal.undo_seconds = 5;
        a.input = "held message".into();
        let source = a.selected;
        a.hold_draft().unwrap();
        a.personal.holds[0].deadline = Utc::now() - chrono::Duration::seconds(1);
        a.selected = (source + 1) % a.conversations.len();
        a.sync_draft_scope();
        let selected = a.selected;
        a.advance_holds(None).await;
        a.advance_holds(None).await;
        assert!(a.personal.holds.is_empty());
        assert_eq!(a.selected, selected);
        assert_eq!(
            a.conversations[source]
                .messages
                .iter()
                .filter(|m| m.text == "held message")
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn loss_of_focus_cancels_timer_and_failed_handoff_needs_review() {
        let f = Fixture::new();
        let mut a = f.open();
        a.personal.undo_seconds = 5;
        a.input = "hold".into();
        a.hold_draft().unwrap();
        a.observe_terminal_focus(&Event::FocusLost);
        a.advance_holds(None).await;
        assert_eq!(a.personal.holds[0].phase, HoldPhase::Draft);
        a.window_focused = true;
        a.personal.holds[0].phase = HoldPhase::Holding;
        a.personal.holds[0].deadline = Utc::now();
        a.advance_holds(None).await;
        assert_eq!(a.personal.holds[0].phase, HoldPhase::Uncertain);
        assert_eq!(f.open().personal.holds[0].phase, HoldPhase::Uncertain);
    }
    #[tokio::test]
    async fn failed_hold_persistence_keeps_composer_and_never_starts_timer() {
        let f = Fixture::new();
        let mut a = f.open();
        std::fs::create_dir(f.path.with_extension("personal.json")).unwrap();
        a.personal.undo_seconds = 5;
        a.input = "must not vanish".into();
        a.reply_to = Some(Uuid::new_v4());
        let reply = a.reply_to;
        a.send_draft(None).await;
        assert_eq!(a.input, "must not vanish");
        assert_eq!(a.reply_to, reply);
        assert!(a.personal.holds.is_empty());
    }
    #[tokio::test]
    async fn quiet_undo_restores_off_and_notes_remain_local_searchable() {
        let f = Fixture::new();
        let mut a = f.open();
        a.run_personal_command("/notifications off", None).await;
        a.run_personal_command("/quiet on", None).await;
        assert!(a.conversation_preferences(f.id).unwrap().quiet);
        a.submit_form(Form::Note(f.id), vec!["Weekend pause".into()], None)
            .await
            .unwrap();
        a.run_personal_command("/quiet undo", None).await;
        let p = a.conversation_preferences(f.id).unwrap();
        assert!(!p.quiet);
        assert_eq!(p.notification_mode, ChatNotifications::Off);
        let mut restored = f.open();
        assert_eq!(restored.personal.notes[&f.id], "Weekend pause");
        assert!(
            restored.conversations[restored.selected]
                .messages
                .is_empty()
        );
        restored.search_personal("weekend", "all").unwrap();
        assert!(render(&restored, 90, 30).contains("Private note"));
        restored.search_personal("weekend", "messages").unwrap();
        assert!(render(&restored, 90, 30).contains("No matches"));
    }
    #[tokio::test]
    async fn keyboard_vote_keeps_focus_and_peer_updates_refresh_open_results() {
        let mut a = app();
        a.submit_form(
            Form::Poll,
            vec![
                "When?".into(),
                "Friday".into(),
                "Saturday".into(),
                "".into(),
                "".into(),
                "".into(),
                "no".into(),
            ],
            None,
        )
        .await
        .unwrap();
        let id = a.conversations[a.selected].messages.last().unwrap().id;
        a.show_poll(id).unwrap();
        for code in [KeyCode::Down, KeyCode::Char(' ')] {
            a.on_key(KeyEvent::new(code, KeyModifiers::NONE), None)
                .await;
        }
        assert_eq!(a.personal_ui.panel.as_ref().unwrap().selected, 1);
        for code in [KeyCode::Down, KeyCode::Enter] {
            a.on_key(KeyEvent::new(code, KeyModifiers::NONE), None)
                .await;
        }
        assert!(render(&a, 80, 24).contains("1 votes · You"));
        let selected = a.selected;
        let mut event = a.conversations[selected].messages.last().unwrap().clone();
        event.id = Uuid::new_v4();
        event.mine = false;
        event.author = "@mira".into();
        event.text = PollWire::vote(vec![0]).unwrap();
        a.conversations[selected].messages.push(event);
        a.handle_client_events();
        assert!(render(&a, 80, 24).contains("@mira"));
    }

    #[tokio::test]
    async fn poll_form_voting_and_timeline_hide_control_events() {
        let mut a = app();
        a.submit_form(
            Form::Poll,
            vec![
                "When?".into(),
                "Friday".into(),
                "Saturday".into(),
                "".into(),
                "".into(),
                "".into(),
                "no".into(),
            ],
            None,
        )
        .await
        .unwrap();
        let id = a.conversations[a.selected].messages.last().unwrap().id;
        a.show_poll(id).unwrap();
        a.activate_personal(Action::Vote(id, 1), None)
            .await
            .unwrap();
        a.activate_personal(Action::SaveVote(id), None)
            .await
            .unwrap();
        assert!(render(&a, 90, 30).contains("You"));
        let state = PollState::fold(
            a.conversations[a.selected]
                .messages
                .iter()
                .find(|m| m.id == id)
                .unwrap(),
            &a.conversations[a.selected].messages,
        )
        .unwrap();
        assert_eq!(state.voters(1), vec!["You"]);
        a.personal_ui.panel = None;
        assert!(
            !a.visible_messages()
                .any(|m| PollWire::parse(&m.text).is_some_and(|p| p.kind == "vote"))
        );
        let screen = render(&a, 90, 30);
        assert!(screen.contains("Poll · When?"));
        assert!(!screen.contains("\"selections\""));
        a.personal_ui.poll_choices.clear();
        a.send_poll_event(id, false, None).await.unwrap();
        a.send_poll_event(id, true, None).await.unwrap();
        assert!(a.send_poll_event(id, false, None).await.is_err());
    }
    #[test]
    fn photo_and_file_search_browse_empty_query_and_keep_conversation_scope() {
        let mut a = app();
        let first = a.selected;
        let id = a.conversations[first].conversation_id.unwrap();
        let mut photo = a.conversations[first].messages[0].clone();
        photo.text = "Shared image".into();
        let source = std::env::temp_dir().join(format!("mutte-search-{}.png", Uuid::new_v4()));
        std::fs::write(&source, b"synthetic metadata only").unwrap();
        let metadata = mutte_store::attachment::prepare(&source).unwrap().metadata;
        photo.attachment = Some(mutte_store::VaultAttachment {
            metadata,
            local_path: None,
            download_requested: false,
        });
        a.conversations[first].messages.push(photo.clone());
        let mut file = photo.clone();
        file.id = Uuid::new_v4();
        file.text = "Shared document".into();
        file.attachment.as_mut().unwrap().metadata.filename = "plan.pdf".into();
        a.conversations[first].messages.push(file);
        let other = (first + 1) % a.conversations.len();
        photo.id = Uuid::new_v4();
        a.conversations[other].messages.push(photo);
        a.search_personal_scoped("", "photos", Some(id)).unwrap();
        assert_eq!(a.personal_ui.panel.as_ref().unwrap().rows.len(), 2);
        assert!(render(&a, 80, 24).contains("Shared image"));
        assert!(!render(&a, 80, 24).contains("Shared document"));
        a.search_personal_scoped("", "files", Some(id)).unwrap();
        assert_eq!(a.personal_ui.panel.as_ref().unwrap().rows.len(), 2);
        assert!(render(&a, 80, 24).contains("Shared document"));
        std::fs::remove_file(source).unwrap();
    }

    #[tokio::test]
    async fn search_opens_exact_thread_and_preserves_composer() {
        let mut a = app();
        let selected = a.selected;
        let root = a.conversations[selected].messages[0].id;
        let mut reply = a.conversations[selected].messages[0].clone();
        reply.id = Uuid::new_v4();
        reply.text = "unique discussion needle".into();
        reply.thread_root = Some(root);
        reply.reply_to = Some(root);
        let id = reply.id;
        a.conversations[selected].messages.push(reply);
        a.input = "main draft".into();
        a.search_personal("unique discussion", "all").unwrap();
        let action = a.personal_ui.panel.as_ref().unwrap().rows[1].action.clone();
        a.activate_personal(action, None).await.unwrap();
        assert_eq!(a.scope().1, Some(root));
        assert_eq!(a.selected_message().unwrap().id, id);
        assert_eq!(
            a.drafts.get(&(a.scope().0, None)).unwrap().text,
            "main draft"
        );
    }
    #[tokio::test]
    async fn keepsake_is_snapshot_export_is_explicit_and_never_overwrites() {
        let mut a = app();
        let index = a.selected;
        let id = a.conversations[index].messages[0].id;
        let original = a.conversations[index].messages[0].text.clone();
        a.open_personal("select-new");
        a.personal_ui.chosen.insert(id);
        a.submit_form(
            Form::Keep(None),
            vec!["Weekend".into(), "<private> & us".into()],
            None,
        )
        .await
        .unwrap();
        let keep_id = a.personal.keepsakes[0].id;
        a.conversations[index].messages[0].text = "edited later".into();
        assert_eq!(a.personal.keepsakes[0].items[0].text, original);
        let path = std::env::temp_dir().join(format!("mutte-keepsake-{}.html", Uuid::new_v4()));
        a.open_form(Form::Export(keep_id));
        assert!(!path.exists());
        a.submit_form(
            Form::Export(keep_id),
            vec![path.to_string_lossy().into()],
            None,
        )
        .await
        .unwrap();
        let html = std::fs::read_to_string(&path).unwrap();
        assert!(html.contains("&lt;private&gt; &amp; us"));
        assert!(html.contains(&original));
        assert!(
            a.submit_form(
                Form::Export(keep_id),
                vec![path.to_string_lossy().into()],
                None
            )
            .await
            .is_err()
        );
        a.run_personal_command(&format!("/delete-keep {keep_id}"), None)
            .await;
        assert!(a.personal.keepsakes.is_empty());
        assert!(path.exists());
        assert!(!a.conversations[index].messages.is_empty());
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn downloaded_photo_is_embedded_and_survives_source_removal_and_restart() {
        let f = Fixture::new();
        let mut a = f.open();
        let source = f.path.parent().unwrap().join("photo.png");
        image::RgbImage::from_pixel(2000, 1000, image::Rgb([95, 64, 140]))
            .save(&source)
            .unwrap();
        let prepared = mutte_store::attachment::prepare(&source).unwrap();
        let mut photo = app().conversations[0].messages[0].clone();
        photo.text = "Photo memory".into();
        photo.attachment = Some(mutte_store::VaultAttachment {
            metadata: prepared.metadata,
            local_path: None,
            download_requested: false,
        });
        let id = photo.id;
        let index = a.selected;
        a.conversations[index].messages.push(photo);
        a.open_personal("select-new");
        a.personal_ui.chosen.insert(id);
        assert!(
            a.snapshot_items().is_err(),
            "never silently omit undownloaded photos"
        );
        a.conversations[index].messages[0]
            .attachment
            .as_mut()
            .unwrap()
            .local_path = Some(source.clone());
        a.submit_form(
            Form::Keep(None),
            vec!["Photo memory".into(), String::new()],
            None,
        )
        .await
        .unwrap();
        std::fs::remove_file(source).unwrap();
        let restored = f.open();
        let item = &restored.personal.keepsakes[0].items[0];
        let jpeg = STANDARD.decode(item.jpeg_base64.as_ref().unwrap()).unwrap();
        let image = image::load_from_memory(&jpeg).unwrap();
        assert_eq!(image.width(), 1600);
        assert_eq!(image.height(), 800);
        assert!(
            restored.personal.keepsakes[0]
                .html()
                .contains("data:image/jpeg;base64,")
        );
    }
    #[tokio::test]
    async fn terminal_alert_settings_persist_and_cli_override_is_session_only() {
        let f = Fixture::new();
        let mut a = f.open();
        a.run_personal_command("/alerts off", None).await;
        assert_eq!(
            f.open().with_notifications(None).notifications.mode,
            NotificationMode::Off
        );
        assert_eq!(
            f.open()
                .with_notifications(Some(NotificationMode::Bell))
                .notifications
                .mode,
            NotificationMode::Bell
        );
        assert_eq!(f.open().personal.terminal_alerts.as_deref(), Some("off"));
    }
    #[tokio::test]
    async fn capture_personal_screens() {
        let Some(directory) = std::env::var_os("MUTTE_PERSONAL_CAPTURE_DIR") else {
            return;
        };
        let directory = PathBuf::from(directory);
        assert!(directory.is_absolute());
        std::fs::create_dir_all(&directory).unwrap();
        let mut a = app();
        a.submit_form(
            Form::Poll,
            vec![
                "When shall we meet?".into(),
                "Friday evening".into(),
                "Saturday morning".into(),
                "".into(),
                "".into(),
                "".into(),
                "no".into(),
            ],
            None,
        )
        .await
        .unwrap();
        let poll = a.conversations[a.selected].messages.last().unwrap().id;
        for page in [
            "home",
            "settings",
            "sending",
            "search",
            "poll",
            "poll-vote",
            "select-new",
            "keepsakes",
        ] {
            if page == "poll-vote" {
                a.show_poll(poll).unwrap();
            } else {
                a.open_personal(page);
            }
            for (width, height) in [(52, 16), (80, 24), (100, 36)] {
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                terminal.draw(|f| a.draw(f)).unwrap();
                let palette = a.theme.palette();
                let rgb = |c: Color, fallback: Color| match c {
                    Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
                    _ => match fallback {
                        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
                        _ => "#111219".into(),
                    },
                };
                let mut cells = Vec::new();
                for y in 0..height {
                    for x in 0..width {
                        let cell = &terminal.backend().buffer()[(x, y)];
                        cells.push(serde_json::json!([
                            x,
                            y,
                            cell.symbol(),
                            rgb(cell.fg, palette.text),
                            rgb(cell.bg, palette.bg),
                            cell.modifier.contains(ratatui::style::Modifier::BOLD)
                        ]));
                    }
                }
                std::fs::write(
                    directory.join(format!("personal-{width}-{page}.json")),
                    serde_json::to_vec(
                        &serde_json::json!({"width":width,"height":height,"cells":cells}),
                    )
                    .unwrap(),
                )
                .unwrap();
            }
        }
    }
    #[test]
    fn all_screens_render_at_minimum_compact_and_wide_sizes_without_reading_messages() {
        let mut a = app();
        for page in [
            "home",
            "people",
            "quiet",
            "settings",
            "sending",
            "preferences",
            "keepsakes",
            "select-new",
            "search",
            "poll",
            "storage",
            "share",
        ] {
            a.open_personal(page);
            assert!(a.visible_scope().is_none());
            for (w, h) in [(52, 16), (80, 24), (120, 40)] {
                assert!(!render(&a, w, h).is_empty());
            }
        }
    }
    #[tokio::test]
    async fn forms_preserve_composer_and_poll_in_thread_uses_same_scope() {
        let mut a = app();
        let selected = a.selected;
        let root = a.conversations[selected].messages[0].id;
        a.conversations[selected].active_thread = Some(root);
        a.sync_draft_scope();
        a.input = "my other draft".into();
        a.ui.mode = UiMode::Composer(ComposerMode::Command);
        a.submit_form(
            Form::Poll,
            vec![
                "Where?".into(),
                "A".into(),
                "B".into(),
                "".into(),
                "".into(),
                "".into(),
                "yes".into(),
            ],
            None,
        )
        .await
        .unwrap();
        assert_eq!(a.input, "my other draft");
        assert_eq!(a.ui.mode, UiMode::Composer(ComposerMode::Message));
        let created = a.conversations[selected].messages.last().unwrap();
        assert_eq!(created.thread_root, Some(root));
        assert_eq!(created.reply_to, Some(root));
        assert_ne!(created.delivery, DeliveryState::Cancelled);
    }
}
