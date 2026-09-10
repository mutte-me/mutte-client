use std::{
    collections::HashSet,
    io::{self, Write},
    process::Stdio,
    time::{Duration, Instant},
};

use clap::ValueEnum;
use crossterm::{
    event::{DisableFocusChange, EnableFocusChange},
    execute,
    terminal::SetTitle,
};
use mutte_client::{ConversationSnapshot, MessageSnapshot};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum NotificationMode {
    /// Generic desktop alert on macOS/Linux, falling back to the terminal bell.
    #[default]
    Auto,
    /// Terminal bell only (the terminal's preferences control sound/attention).
    Bell,
    /// Unread counts remain visible, but no alert or bell is emitted.
    Off,
}

pub struct Notifications {
    seen: HashSet<(Uuid, Uuid)>,
    pub mode: NotificationMode,
    pub toast: Option<(usize, Instant)>,
    pending: bool,
    last_alert: Option<Instant>,
}

impl Notifications {
    pub fn new(chats: &[ConversationSnapshot]) -> Self {
        Self {
            seen: chats
                .iter()
                .filter_map(|chat| chat.conversation_id.map(|id| (id, chat)))
                .flat_map(|(id, chat)| chat.messages.iter().map(move |message| (id, message.id)))
                .collect(),
            mode: NotificationMode::Auto,
            toast: None,
            pending: false,
            last_alert: None,
        }
    }

    pub fn received(&mut self, conversation_id: Uuid, message: &MessageSnapshot, now: Instant) {
        if !self.seen.insert((conversation_id, message.id)) || message.mine || message.locally_read
        {
            return;
        }
        if self.mode == NotificationMode::Off {
            return;
        }
        let previous = self
            .toast
            .filter(|(_, at)| now.duration_since(*at) < Duration::from_secs(8));
        self.toast = Some((
            previous.map_or(1, |(count, _)| count.saturating_add(1)),
            now,
        ));
        self.pending = true;
    }

    pub fn take_alert(&mut self, now: Instant) -> bool {
        if !self.pending
            || self
                .last_alert
                .is_some_and(|last| now.duration_since(last) < Duration::from_secs(3))
        {
            return false;
        }
        self.pending = false;
        self.last_alert = Some(now);
        true
    }

    pub fn clear_if_read(&mut self, unread: usize) {
        if unread == 0 {
            self.pending = false;
            self.toast = None;
        }
    }
}

pub fn unread_total(chats: &[ConversationSnapshot]) -> usize {
    chats.iter().fold(0usize, |total, chat| {
        total.saturating_add(usize::from(chat.unread))
    })
}

/// Owns terminal-only effects and always disables focus reporting on exit.
pub struct TerminalNotificationSurface {
    last_unread: Option<usize>,
}

impl TerminalNotificationSurface {
    pub fn new() -> io::Result<Self> {
        execute!(io::stdout(), EnableFocusChange)?;
        Ok(Self { last_unread: None })
    }

    pub fn update_badge(&mut self, unread: usize) -> io::Result<()> {
        if self.last_unread != Some(unread) {
            execute!(
                io::stdout(),
                SetTitle(if unread == 0 {
                    "Mutte".into()
                } else {
                    format!("Mutte ({unread} unread)")
                })
            )?;
            self.last_unread = Some(unread);
        }
        Ok(())
    }
}

impl Drop for TerminalNotificationSurface {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableFocusChange, SetTitle("Mutte"));
    }
}

pub async fn alert(mode: NotificationMode) {
    if mode == NotificationMode::Off {
        return;
    }
    if mode == NotificationMode::Auto {
        // Only fixed product copy crosses the OS boundary. Never interpolate
        // sender handles, decrypted message text, IDs, or shell input here.
        #[cfg(target_os = "macos")]
        let mut command = {
            let mut command = tokio::process::Command::new("/usr/bin/osascript");
            command.args([
                "-e",
                "display notification \"New message\" with title \"Mutte\"",
            ]);
            command
        };
        #[cfg(not(target_os = "macos"))]
        let mut command = {
            let mut command = tokio::process::Command::new("notify-send");
            command.args(["--app-name=Mutte", "--", "Mutte", "New message"]);
            command
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if let Ok(Ok(status)) = tokio::time::timeout(Duration::from_secs(2), command.status()).await
            && status.success()
        {
            return;
        }
    }
    let _ = io::stdout().write_all(b"\x07");
    let _ = io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutte_client::MutteClient;
    use mutte_protocol::Profile;

    fn fixture() -> (Uuid, MessageSnapshot) {
        let client = MutteClient::new(
            Profile {
                id: Uuid::new_v4(),
                handle: "demo".into(),
                display_name: "Demo".into(),
                bio: String::new(),
                status: String::new(),
            },
            true,
        );
        let mut message = client.conversations[0].messages[0].clone();
        message.locally_read = false;
        (client.conversations[0].conversation_id.unwrap(), message)
    }

    #[test]
    fn unseen_messages_coalesce_and_duplicates_do_not_alert_twice() {
        let (chat, mut message) = fixture();
        let mut state = Notifications::new(&[]);
        let now = Instant::now();
        state.received(chat, &message, now);
        state.received(chat, &message, now);
        assert_eq!(state.toast.unwrap().0, 1);
        assert!(state.take_alert(now));
        message.id = Uuid::new_v4();
        state.received(chat, &message, now);
        assert!(!state.take_alert(now));
        assert!(state.take_alert(now + Duration::from_secs(4)));
        state.clear_if_read(0);
        assert!(state.toast.is_none());
    }

    #[test]
    fn own_read_and_muted_messages_never_alert() {
        for (mine, read, mode) in [
            (true, false, NotificationMode::Auto),
            (false, true, NotificationMode::Auto),
            (false, false, NotificationMode::Off),
        ] {
            let (chat, mut message) = fixture();
            message.mine = mine;
            message.locally_read = read;
            let mut state = Notifications::new(&[]);
            state.mode = mode;
            state.received(chat, &message, Instant::now());
            assert!(state.toast.is_none());
            assert!(!state.take_alert(Instant::now()));
        }
    }
}
