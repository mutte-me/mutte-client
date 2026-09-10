//! Device-local personal state. Never part of relay or history-sync payloads.
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum HoldPhase {
    #[default]
    Holding,
    Draft,
    Submitting,
    Uncertain,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeldText {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub text: String,
    pub reply_to: Option<Uuid>,
    pub thread_root: Option<Uuid>,
    pub deadline: DateTime<Utc>,
    pub phase: HoldPhase,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeepsakeItem {
    pub id: Uuid,
    pub author: String,
    pub text: String,
    pub sent_at: DateTime<Utc>,
    pub filename: Option<String>,
    pub jpeg_base64: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Keepsake {
    pub id: Uuid,
    pub title: String,
    pub introduction: String,
    pub items: Vec<KeepsakeItem>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PersonalState {
    pub version: u8,
    pub undo_seconds: u8,
    #[serde(default)]
    pub terminal_alerts: Option<String>,
    pub holds: Vec<HeldText>,
    pub notes: BTreeMap<Uuid, String>,
    pub keepsakes: Vec<Keepsake>,
}
impl Default for PersonalState {
    fn default() -> Self {
        Self {
            version: 1,
            undo_seconds: 0,
            terminal_alerts: None,
            holds: vec![],
            notes: BTreeMap::new(),
            keepsakes: vec![],
        }
    }
}
impl PersonalState {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported personal state version");
        ensure!(
            [0, 5, 10].contains(&self.undo_seconds),
            "Sending: choose Off, 5 or 10 seconds"
        );
        ensure!(
            self.terminal_alerts
                .as_deref()
                .is_none_or(|mode| ["auto", "bell", "off"].contains(&mode)),
            "Unknown terminal alert mode"
        );
        Ok(())
    }
    /// Startup and lost-focus recovery never start a send timer.
    pub fn recover(&mut self) {
        for hold in &mut self.holds {
            hold.phase = match hold.phase {
                HoldPhase::Holding => HoldPhase::Draft,
                HoldPhase::Submitting => HoldPhase::Uncertain,
                ref phase => phase.clone(),
            };
        }
    }
}

pub fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
impl Keepsake {
    pub fn html(&self) -> String {
        let mut html = format!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'\"><title>{}</title><style>body{{max-width:680px;margin:48px auto;padding:24px;background:#faf7f2;color:#292532;font:18px/1.7 system-ui}}figure{{margin:32px 0;border-top:1px solid #ddd;padding-top:24px}}img{{max-width:100%}}blockquote{{margin:0;white-space:pre-wrap}}figcaption{{font-size:14px;color:#655e71}}p{{white-space:pre-wrap}}</style><h1>{}</h1><p>{}</p>",
            escape_html(&self.title),
            escape_html(&self.title),
            escape_html(&self.introduction)
        );
        for item in &self.items {
            html.push_str("<figure>");
            if let Some(image) = &item.jpeg_base64 {
                html.push_str(&format!(
                    "<img alt=\"Saved photo\" src=\"data:image/jpeg;base64,{}\">",
                    escape_html(image)
                ));
            }
            html.push_str(&format!(
                "<blockquote>{}</blockquote><figcaption>{} · {}{}</figcaption></figure>",
                escape_html(&item.text),
                escape_html(&item.author),
                item.sent_at.format("%Y-%m-%d %H:%M UTC"),
                item.filename
                    .as_ref()
                    .map(|name| format!(" · {} (file name only)", escape_html(name)))
                    .unwrap_or_default()
            ));
        }
        html.push_str("</html>");
        html
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_never_resends_and_preserves_exact_scope() {
        let root = Uuid::new_v4();
        let hold = HeldText {
            id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            text: "draft".into(),
            reply_to: Some(root),
            thread_root: Some(root),
            deadline: Utc::now(),
            phase: HoldPhase::Holding,
        };
        let mut state = PersonalState {
            holds: vec![
                hold.clone(),
                HeldText {
                    phase: HoldPhase::Submitting,
                    ..hold
                },
            ],
            ..Default::default()
        };
        state.recover();
        assert_eq!(state.holds[0].phase, HoldPhase::Draft);
        assert_eq!(state.holds[1].phase, HoldPhase::Uncertain);
        assert_eq!(state.holds[0].reply_to, Some(root));
        assert_eq!(state.holds[0].thread_root, Some(root));
        state.recover();
        assert_eq!(state.holds[1].phase, HoldPhase::Uncertain);
    }
    #[test]
    fn html_is_self_contained_and_escapes_private_text() {
        let keep = Keepsake {
            id: Uuid::new_v4(),
            title: "<script>bad()</script>".into(),
            introduction: "Mira & me".into(),
            items: vec![],
        };
        let html = keep.html();
        assert!(!html.contains("<script>"));
        assert!(html.contains("Mira &amp; me"));
        assert!(html.contains("default-src 'none'"));
    }
}
