//! iOS-compatible poll content. Authority comes only from authenticated messages.
use crate::MessageSnapshot;
use anyhow::{Result, ensure};
use mutte_store::DeliveryState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;
#[cfg(test)]
use uuid::Uuid;

/// Local-only marker outside the valid authenticated handle alphabet.
pub const LOCAL_VOTER: &str = "\0mutte-local-author";
pub const PREFIX: &str = "Mutte poll · v1\n";
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PollWire {
    version: u8,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub question: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selections: Option<Vec<usize>>,
}
impl PollWire {
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > 8192 {
            return None;
        }
        let value: Self = serde_json::from_str(text.strip_prefix(PREFIX)?).ok()?;
        if value.version != 1 {
            return None;
        }
        let valid = match value.kind.as_str() {
            "create" => {
                value
                    .question
                    .as_ref()
                    .zip(value.options.as_ref())
                    .is_some_and(|(q, o)| {
                        !q.trim().is_empty()
                            && q.graphemes(true).count() <= 120
                            && (2..=5).contains(&o.len())
                            && o.iter()
                                .all(|s| !s.trim().is_empty() && s.graphemes(true).count() <= 60)
                            && o.iter()
                                // Swift String equality is canonically equivalent.
                                // Match it so TUI polls also validate on iOS.
                                .map(|s| s.trim().to_lowercase().nfc().collect::<String>())
                                .collect::<BTreeSet<_>>()
                                .len()
                                == o.len()
                    })
                    && value.multiple.is_some()
                    && value.selections.is_none()
            }
            "vote" => {
                value.selections.as_ref().is_some_and(|s| {
                    s.len() <= 5
                        && s.iter().all(|i| *i < 5)
                        && s.iter().collect::<BTreeSet<_>>().len() == s.len()
                }) && value.question.is_none()
                    && value.options.is_none()
                    && value.multiple.is_none()
            }
            "close" => {
                value.question.is_none()
                    && value.options.is_none()
                    && value.multiple.is_none()
                    && value.selections.is_none()
            }
            _ => false,
        };
        valid.then_some(value)
    }
    fn encode(self) -> Result<String> {
        let text = format!("{PREFIX}{}", serde_json::to_string(&self)?);
        ensure!(
            Self::parse(&text).is_some(),
            "Use a question up to 120 characters and 2–5 distinct options up to 60 characters each"
        );
        Ok(text)
    }
    pub fn create(question: &str, options: Vec<String>, multiple: bool) -> Result<String> {
        Self {
            version: 1,
            kind: "create".into(),
            question: Some(question.trim().into()),
            options: Some(options.iter().map(|s| s.trim().into()).collect()),
            multiple: Some(multiple),
            selections: None,
        }
        .encode()
    }
    pub fn vote(mut selections: Vec<usize>) -> Result<String> {
        selections.sort_unstable();
        Self {
            version: 1,
            kind: "vote".into(),
            question: None,
            options: None,
            multiple: None,
            selections: Some(selections),
        }
        .encode()
    }
    pub fn close() -> String {
        format!("{PREFIX}{{\"version\":1,\"kind\":\"close\"}}")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollState {
    pub question: String,
    pub options: Vec<String>,
    pub multiple: bool,
    pub closed: bool,
    pub votes: BTreeMap<String, Vec<usize>>,
}
impl PollState {
    /// Call with a single conversation's authenticated history.
    pub fn fold(root: &MessageSnapshot, messages: &[MessageSnapshot]) -> Option<Self> {
        if root.attachment.is_some() || root.delivery == DeliveryState::Cancelled {
            return None;
        }
        let wire = PollWire::parse(&root.text)?;
        if wire.kind != "create" {
            return None;
        }
        let mut state = Self {
            question: wire.question?,
            options: wire.options?,
            multiple: wire.multiple?,
            closed: false,
            votes: BTreeMap::new(),
        };
        let mut events: Vec<_> = messages.iter().collect();
        events.sort_by_key(|m| (m.timestamp, m.id));
        for event in events {
            if state.closed
                || event.reply_to != Some(root.id)
                || event.thread_root != root.thread_root
                || event.attachment.is_some()
                || event.delivery == DeliveryState::Cancelled
            {
                continue;
            }
            let Some(wire) = PollWire::parse(&event.text) else {
                continue;
            };
            let voter = Self::voter(event);
            if wire.kind == "close" && voter == Self::voter(root) {
                state.closed = true;
            }
            if wire.kind == "vote" {
                let selections = wire.selections?;
                if selections.iter().any(|i| *i >= state.options.len())
                    || (!state.multiple && selections.len() > 1)
                {
                    continue;
                }
                if selections.is_empty() {
                    state.votes.remove(&voter);
                } else {
                    state.votes.insert(voter, selections);
                }
            }
        }
        Some(state)
    }
    pub fn voter(message: &MessageSnapshot) -> String {
        if message.mine {
            LOCAL_VOTER.into()
        } else {
            message.author.to_lowercase()
        }
    }
    pub fn voters(&self, option: usize) -> Vec<String> {
        self.votes
            .iter()
            .filter(|(_, choices)| choices.contains(&option))
            .map(|(who, _)| {
                if who == LOCAL_VOTER {
                    "You".into()
                } else {
                    who.clone()
                }
            })
            .collect()
    }
    pub fn summary(&self) -> String {
        let mut lines = vec![format!("Poll · {}", self.question)];
        for (i, option) in self.options.iter().enumerate() {
            lines.push(format!(
                "{}. {}  · {}{}",
                i + 1,
                option,
                self.voters(i).len(),
                if self.votes.get(LOCAL_VOTER).is_some_and(|v| v.contains(&i)) {
                    " ✓"
                } else {
                    ""
                }
            ));
        }
        lines.push(format!(
            "{} · {} · named votes",
            if self.closed { "Closed" } else { "Open" },
            if self.multiple {
                "Multiple answers"
            } else {
                "One answer"
            }
        ));
        lines.join("\n")
    }
}
pub fn is_poll_event(messages: &[MessageSnapshot], message: &MessageSnapshot) -> bool {
    PollWire::parse(&message.text).is_some_and(|wire| wire.kind != "create")
        && messages.iter().any(|root| {
            Some(root.id) == message.reply_to
                && root.thread_root == message.thread_root
                && PollState::fold(root, &[]).is_some()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Local, TimeZone};
    use mutte_store::DeliveryState;

    fn message(n: u128, author: &str, text: String, reply: Option<Uuid>) -> MessageSnapshot {
        MessageSnapshot {
            id: Uuid::from_u128(n),
            author: author.into(),
            text,
            mine: author == "me",
            timestamp: Local.timestamp_opt(n as i64, 0).unwrap(),
            delivery: DeliveryState::Delivered,
            attachment: None,
            reply_to: reply,
            thread_root: None,
            locally_read: false,
        }
    }

    #[test]
    fn peer_named_self_cannot_close_or_replace_local_votes() {
        let root = message(
            1,
            "me",
            PollWire::create("When?", vec!["Fri".into(), "Sat".into()], false).unwrap(),
            None,
        );
        let own_vote = message(2, "me", PollWire::vote(vec![0]).unwrap(), Some(root.id));
        let peer_vote = message(3, "@self", PollWire::vote(vec![1]).unwrap(), Some(root.id));
        let peer_close = message(4, "@self", PollWire::close(), Some(root.id));
        let state = PollState::fold(&root, &[own_vote, peer_vote, peer_close]).unwrap();
        assert!(!state.closed);
        assert_eq!(state.voters(0), vec!["You"]);
        assert_eq!(state.voters(1), vec!["@self"]);
    }

    #[test]
    fn ios_wire_validation_and_readable_fallback() {
        let text = "Mutte poll · v1\n{\"version\":1,\"kind\":\"create\",\"question\":\"When?\",\"options\":[\"Friday\",\"Saturday\"],\"multiple\":false}";
        assert!(PollWire::parse(text).is_some());
        assert!(PollWire::parse(&text.replace("v1", "v2")).is_none());
        assert!(
            PollWire::create("When?", vec![" Friday ".into(), "friday".into()], false).is_err()
        );
        assert!(
            PollWire::parse(
                "Mutte poll · v1\n{\"version\":1,\"kind\":\"vote\",\"selections\":[0,0]}"
            )
            .is_none()
        );
        assert!(
            PollWire::parse(
                "Mutte poll · v1\n{\"version\":1,\"kind\":\"close\",\"question\":\"x\"}"
            )
            .is_none()
        );
    }

    #[test]
    fn canonically_equivalent_options_match_swift_duplicate_validation() {
        for options in [
            vec!["Caf\u{e9}".to_owned(), "Cafe\u{301}".to_owned()],
            vec![" CAF\u{c9} ".to_owned(), "cafe\u{301}".to_owned()],
            vec!["\u{ac00}".to_owned(), "\u{1100}\u{1161}".to_owned()],
        ] {
            let incoming = format!(
                "{PREFIX}{}",
                serde_json::json!({
                    "version": 1,
                    "kind": "create",
                    "question": "Where?",
                    "options": options,
                    "multiple": false,
                })
            );
            assert!(PollWire::parse(&incoming).is_none());
            assert!(PollWire::create("Where?", options, false).is_err());
        }
        assert!(PollWire::create("Where?", vec!["Caf\u{e9}".into(), "Cafe".into()], false).is_ok());
    }

    #[test]
    fn authenticated_votes_withdrawal_scope_and_creator_close() {
        let root = message(
            1,
            "me",
            PollWire::create("When?", vec!["Friday".into(), "Saturday".into()], false).unwrap(),
            None,
        );
        let vote =
            |n, who, indexes| message(n, who, PollWire::vote(indexes).unwrap(), Some(root.id));
        let mut wrong_scope = vote(4, "other", vec![0]);
        wrong_scope.thread_root = Some(Uuid::new_v4());
        let mut cancelled = vote(5, "other", vec![0]);
        cancelled.delivery = DeliveryState::Cancelled;
        let messages = vec![
            root.clone(),
            vote(2, "other", vec![0]),
            message(3, "other", PollWire::close(), Some(root.id)),
            wrong_scope,
            cancelled,
            vote(6, "other", vec![]),
            vote(7, "other", vec![1]),
            vote(8, "invalid", vec![4]),
            message(9, "me", PollWire::close(), Some(root.id)),
            vote(10, "other", vec![0]),
        ];
        let state = PollState::fold(&root, &messages).unwrap();
        assert!(state.closed);
        assert_eq!(state.voters(0), Vec::<String>::new());
        assert_eq!(state.voters(1), vec!["other"]);
        let mut reversed = messages.clone();
        reversed.reverse();
        assert_eq!(state, PollState::fold(&root, &reversed).unwrap());
        assert!(is_poll_event(&messages, &messages[1]));
        assert!(!is_poll_event(&messages, &messages[3]));
    }
}
