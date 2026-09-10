use std::{fs, path::PathBuf};

use mutte_store::{ConversationPreferences, NotificationMode, Vault, VaultConversation};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    conversation: Uuid,
    vault: Vault,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("mutte-attention-{}", Uuid::new_v4()));
        let mut vault = Vault::open_at(root.join("vault.json"), &[19; 32]).unwrap();
        let conversation = Uuid::new_v4();
        vault
            .upsert_conversation(VaultConversation {
                id: conversation,
                peer_handle: "private_friend".into(),
                unread: 7,
            })
            .unwrap();
        Self {
            root,
            conversation,
            vault,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn undo_quiet_restores_off_without_leaving_the_conversation_in_quiet() {
    let mut f = Fixture::new();
    f.vault
        .set_notification_mode(f.conversation, NotificationMode::Off)
        .unwrap();
    f.vault
        .set_conversation_quiet(f.conversation, true)
        .unwrap();
    f.vault
        .restore_conversation_attention(f.conversation, false, NotificationMode::Off)
        .unwrap();
    let restored = f.vault.conversation_preferences(f.conversation).unwrap();
    assert!(!restored.quiet);
    assert_eq!(restored.notification_mode, NotificationMode::Off);
}

#[test]
fn quiet_and_restore_preserve_history_unread_and_following_without_reenabling_alerts() {
    let mut f = Fixture::new();
    let thread = Uuid::new_v4();
    f.vault
        .set_thread_followed(f.conversation, thread, true)
        .unwrap();
    f.vault
        .set_conversation_quiet(f.conversation, true)
        .unwrap();
    let quiet = f.vault.conversation_preferences(f.conversation).unwrap();
    assert!(quiet.quiet);
    assert_eq!(quiet.notification_mode, NotificationMode::Off);
    assert!(quiet.followed_threads.contains(&thread));
    assert_eq!(f.vault.conversations()[0].unread, 7);
    f.vault
        .set_conversation_quiet(f.conversation, false)
        .unwrap();
    let restored = f.vault.conversation_preferences(f.conversation).unwrap();
    assert!(!restored.quiet);
    assert_eq!(restored.notification_mode, NotificationMode::Off);
    assert_eq!(f.vault.conversations().len(), 1);
}

#[test]
fn following_never_overrides_off_but_explicit_alert_mode_restores_chats() {
    let mut f = Fixture::new();
    f.vault
        .set_conversation_quiet(f.conversation, true)
        .unwrap();
    f.vault
        .set_thread_followed(f.conversation, Uuid::new_v4(), true)
        .unwrap();
    assert_eq!(
        f.vault
            .conversation_preferences(f.conversation)
            .unwrap()
            .notification_mode,
        NotificationMode::Off
    );
    f.vault
        .set_notification_mode(f.conversation, NotificationMode::FollowingAndMentions)
        .unwrap();
    let preferences = f.vault.conversation_preferences(f.conversation).unwrap();
    assert!(!preferences.quiet);
    assert_eq!(
        preferences.notification_mode,
        NotificationMode::FollowingAndMentions
    );
}

#[test]
fn preferences_are_encrypted_durable_and_scoped_to_known_conversations() {
    let mut f = Fixture::new();
    let thread = Uuid::new_v4();
    f.vault
        .set_notification_mode(f.conversation, NotificationMode::FollowingAndMentions)
        .unwrap();
    f.vault
        .set_thread_followed(f.conversation, thread, true)
        .unwrap();
    let expected = f.vault.conversation_preferences(f.conversation).unwrap();
    let reopened = Vault::open_at(f.root.join("vault.json"), &[19; 32]).unwrap();
    assert_eq!(
        reopened.conversation_preferences(f.conversation).unwrap(),
        expected
    );
    let bytes = fs::read_to_string(f.root.join("vault.json")).unwrap();
    assert!(!bytes.contains("private_friend"));
    assert!(!bytes.contains(&thread.to_string()));
    let before = bytes;
    let unknown = Uuid::new_v4();
    assert!(
        f.vault
            .set_notification_mode(unknown, NotificationMode::Off)
            .is_err()
    );
    assert!(f.vault.set_conversation_quiet(unknown, true).is_err());
    assert!(f.vault.set_thread_followed(unknown, thread, true).is_err());
    assert!(f.vault.conversation_preferences(unknown).is_err());
    assert_eq!(
        fs::read_to_string(f.root.join("vault.json")).unwrap(),
        before
    );
}

#[test]
fn failed_persistence_does_not_publish_a_preference_change() {
    let mut f = Fixture::new();
    let original = f.vault.conversation_preferences(f.conversation).unwrap();
    fs::remove_file(f.root.join("vault.json")).unwrap();
    fs::create_dir(f.root.join("vault.json")).unwrap();
    assert!(
        f.vault
            .set_conversation_quiet(f.conversation, true)
            .is_err()
    );
    assert_eq!(
        f.vault.conversation_preferences(f.conversation).unwrap(),
        original
    );
}

#[test]
fn notification_matrix_respects_following_mentions_and_off() {
    let followed = Uuid::new_v4();
    let other = Uuid::new_v4();
    let mut policy = ConversationPreferences::default();
    policy.followed_threads.insert(followed);
    for mode in [
        NotificationMode::AllMessages,
        NotificationMode::FollowingAndMentions,
        NotificationMode::Off,
    ] {
        policy.notification_mode = mode;
        for thread in [None, Some(followed), Some(other)] {
            for mentioned in [false, true] {
                let expected = match mode {
                    NotificationMode::AllMessages => true,
                    NotificationMode::FollowingAndMentions => mentioned || thread == Some(followed),
                    NotificationMode::Off => false,
                };
                assert_eq!(policy.allows_notification(thread, mentioned), expected);
            }
        }
    }
    policy.quiet = true;
    policy.notification_mode = NotificationMode::AllMessages;
    assert!(!policy.allows_notification(Some(followed), true));
}

#[test]
fn legacy_conversations_keep_their_existing_alert_behavior() {
    let f = Fixture::new();
    let preferences = f.vault.conversation_preferences(f.conversation).unwrap();
    assert!(!preferences.quiet);
    assert_eq!(preferences.notification_mode, NotificationMode::AllMessages);
    assert!(preferences.followed_threads.is_empty());
}
