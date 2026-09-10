use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Recipient-owned policy. It never changes delivery or group membership.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationMode {
    /// Preserve the behavior of existing conversations on upgrade. New-group
    /// defaults are a separate, explicit product setting.
    #[default]
    AllMessages,
    FollowingAndMentions,
    Off,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct ConversationPreferences {
    pub quiet: bool,
    pub notification_mode: NotificationMode,
    pub followed_threads: BTreeSet<Uuid>,
}

impl ConversationPreferences {
    pub fn allows_notification(&self, thread_root: Option<Uuid>, mentioned: bool) -> bool {
        if self.quiet {
            return false;
        }
        match self.notification_mode {
            NotificationMode::AllMessages => true,
            NotificationMode::FollowingAndMentions => {
                mentioned || thread_root.is_some_and(|root| self.followed_threads.contains(&root))
            }
            NotificationMode::Off => false,
        }
    }
}
