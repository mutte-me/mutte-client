//! Explicit live-test helper. Stop the ordinary terminal before opening its vault.
//! Never creates accounts/identities or prints credentials. Writes are restricted
//! to the saved terminal test account and a fresh E2E personal34 conversation.
use anyhow::{Context, Result, ensure};
use mutte_client::{Client, ClientCommand, Connection, MutteClient, Session};
use mutte_core::Device;
use mutte_store::{Vault, VaultKey, terminal_local_identity_path};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    io::{self, BufRead, Write},
    time::Duration,
};
use url::Url;
use uuid::Uuid;

const PREFIX: &str = "Mutte poll · v1\n";
fn emit(value: Value) {
    println!("{value}");
    let _ = io::stdout().flush();
}
#[tokio::main]
async fn main() -> Result<()> {
    ensure!(
        std::env::var("MUTTE_PERSONAL_LIVE_TEST").as_deref() == Ok("1"),
        "explicit test opt-in required"
    );
    let server = Url::parse("https://api.mutte.me")?;
    let path = terminal_local_identity_path(&server)?;
    ensure!(path.exists(), "existing terminal identity required");
    let key = VaultKey::load_or_create()?;
    let device = Device::load_or_create_at(&path, &*key.device_storage_key()?)?;
    let vault = Vault::load_active_terminal(&server, device.id(), &*key.message_storage_key()?)?
        .context("existing active vault required")?;
    let saved = vault
        .load_session(&server)
        .context("saved session required")?;
    ensure!(
        saved.profile.handle == "terminal_20260902" && saved.device_id == device.id(),
        "wrong test identity"
    );
    let api = Client::new(server)?;
    let session = Session {
        access_token: saved.access_token,
        device_id: saved.device_id,
        profile: saved.profile,
    };
    api.validate(&session).await?;
    let connection = Connection {
        api: &api,
        session: &session,
        device: &device,
        open_browser: false,
    };
    let mut engine = MutteClient::connected(session.profile.clone(), vault)?;
    engine.start(&connection).await?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    emit(json!({"ready":true,"account":"terminal_20260902"}));
    let mut voted = HashSet::new();
    let mut observed = HashSet::new();
    loop {
        if engine.synchronize(&connection).await.is_err() {
            emit(json!({"sync_error":true}));
        }
        let scopes: Vec<_> = engine
            .conversations
            .iter()
            .filter(|c| {
                c.handle == "melesh"
                    && c.messages
                        .iter()
                        .any(|m| m.text.starts_with("E2E personal34 bridge "))
            })
            .filter_map(|c| c.conversation_id)
            .collect();
        for id in &scopes {
            engine
                .execute(
                    Some(&connection),
                    ClientCommand::MarkRead {
                        conversation_id: *id,
                        thread_root: None,
                    },
                )
                .await?;
        }
        let fresh: Vec<_> = engine
            .conversations
            .iter()
            .filter(|c| c.conversation_id.is_some_and(|id| scopes.contains(&id)))
            .flat_map(|c| {
                c.messages
                    .iter()
                    .filter(|m| m.text.starts_with(PREFIX) || m.text.starts_with("E2E personal34"))
                    .map(move |m| (c.conversation_id.unwrap(), m.clone()))
            })
            .collect();
        for (conversation, m) in fresh {
            if observed.insert(m.id) {
                emit(
                    json!({"message":m.id,"conversation":conversation,"text":m.text,"mine":m.mine,"reply_to":m.reply_to,"thread_root":m.thread_root,"delivery":format!("{:?}",m.delivery)}),
                );
            }
            if !m.mine && m.text.starts_with(PREFIX) {
                let payload: Value = serde_json::from_str(&m.text[PREFIX.len()..])?;
                if payload["kind"] == "create"
                    && payload["question"]
                        .as_str()
                        .is_some_and(|q| q.starts_with("E2E personal34"))
                    && voted.insert(m.id)
                {
                    engine
                        .execute(
                            Some(&connection),
                            ClientCommand::SendMessage {
                                conversation_id: conversation,
                                text: format!(
                                    "{PREFIX}{}",
                                    json!({"version":1,"kind":"vote","selections":[0]})
                                ),
                                reply_to: Some(m.id),
                                thread_root: m.thread_root,
                            },
                        )
                        .await?;
                    emit(json!({"auto_voted":m.id}));
                }
            }
        }
        while let Ok(line) = rx.try_recv() {
            let value: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => {
                    emit(json!({"invalid_command":true}));
                    continue;
                }
            };
            if value["op"] == "quit" {
                return Ok(());
            }
            let action: Result<()> = async {
                let root_id = Uuid::parse_str(value["root"].as_str().context("root required")?)?;
                let (conversation, root) = engine
                    .conversations
                    .iter()
                    .filter(|c| c.conversation_id.is_some_and(|id| scopes.contains(&id)))
                    .find_map(|c| {
                        c.messages
                            .iter()
                            .find(|m| m.id == root_id && m.text.starts_with(PREFIX))
                            .map(|m| (c.conversation_id.unwrap(), m.clone()))
                    })
                    .context("test poll root required")?;
                let payload = match value["op"].as_str() {
                    Some("vote") => {
                        let choices = value["choices"].as_array().context("choices required")?;
                        ensure!(
                            choices.len() <= 5
                                && choices.iter().all(|v| v.as_u64().is_some_and(|i| i < 5)),
                            "invalid choices"
                        );
                        json!({"version":1,"kind":"vote","selections":choices})
                    }
                    Some("close") => json!({"version":1,"kind":"close"}),
                    _ => anyhow::bail!("unsupported operation"),
                };
                engine
                    .execute(
                        Some(&connection),
                        ClientCommand::SendMessage {
                            conversation_id: conversation,
                            text: format!("{PREFIX}{payload}"),
                            reply_to: Some(root_id),
                            thread_root: root.thread_root,
                        },
                    )
                    .await?;
                emit(json!({"command_sent":value["op"],"root":root_id}));
                Ok(())
            }
            .await;
            if action.is_err() {
                emit(json!({"command_rejected":true}));
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
