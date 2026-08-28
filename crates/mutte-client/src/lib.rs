//! Authenticated Mutte relay transport shared by every client frontend.
//!
//! Durable HTTPS resources remain the source of truth. [`Client::events`]
//! exposes a deliberately lossy wake-up stream that tells a frontend to fetch
//! the mailbox; callers must retain a polling fallback.

mod engine;

pub use engine::{
    ClientCommand, ClientPaths, Connection, ConversationSnapshot, DevicePanel, MessageSnapshot,
    MutteClient, VerificationPanel, VerificationState,
};

use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use mutte_protocol::{
    AccountDeviceEventAck, AccountDeviceEventBatch, AccountDeviceKeyPackageClaim,
    AttachmentChunkData, AttachmentChunkUpload, AttachmentRecipientGrant, AttachmentStart,
    AttachmentStatus, AuthorizationState, CiphertextEnvelope, ConversationMutationAuthorization,
    ConversationMutationRelease, ConversationMutationStart, DeviceAuthorization, DeviceList,
    DeviceRevocationAuthorization, DeviceRevocationStart, DeviceRevocationStatus, DeviceStart,
    DeviceStatus, KeyPackagePublish, KeyPackageRecord, MessageAck, MessageBatch, PROTOCOL_VERSION,
    Profile, RealtimeEvent,
};
use reqwest::{
    Client as HttpClient, StatusCode,
    header::{HeaderMap as HttpHeaderMap, HeaderValue as HttpHeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        Message as WebSocketMessage,
        client::IntoClientRequest,
        http::{HeaderValue, header::AUTHORIZATION},
    },
};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct Client {
    base: Url,
    client: HttpClient,
}

#[derive(Clone)]
pub struct Session {
    pub access_token: SecretString,
    pub device_id: Uuid,
    pub profile: Profile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    MailboxReady,
    QuitRequested,
    HelpRequested,
    StateChanged {
        conversation_id: Option<Uuid>,
    },
    MessageReceived {
        conversation_id: Uuid,
        message_id: Uuid,
    },
    DeliveryChanged {
        conversation_id: Uuid,
        message_id: Uuid,
    },
    AttachmentProgress {
        attachment_id: Uuid,
        completed_chunks: u32,
        total_chunks: u32,
    },
    AuthenticationRequired {
        url: String,
    },
    ConnectionChanged {
        connected: bool,
    },
    Notice {
        message: String,
    },
}

impl Client {
    pub fn new(base: Url) -> Result<Self> {
        let mut default_headers = HttpHeaderMap::new();
        default_headers.insert(
            "x-mutte-protocol",
            HttpHeaderValue::from_static(PROTOCOL_VERSION),
        );
        let client = HttpClient::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("mutte/", env!("CARGO_PKG_VERSION")))
            .default_headers(default_headers)
            .https_only(base.scheme() == "https")
            .build()?;
        Ok(Self { base, client })
    }

    pub async fn start_device(
        &self,
        device_id: Uuid,
        name: String,
        key_package: String,
    ) -> Result<DeviceAuthorization> {
        self.post("v1/devices")?
            .json(&DeviceStart {
                device_id,
                device_name: name,
                key_package,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("decode device authorization")
    }

    pub async fn wait_for_approval(&self, authorization: &DeviceAuthorization) -> Result<Session> {
        loop {
            if chrono::Utc::now() >= authorization.expires_at {
                bail!("device authorization expired");
            }
            let url = self
                .base
                .join(&format!("v1/devices/{}", authorization.device_id))?;
            let response = self
                .client
                .get(url)
                .header("x-mutte-device-secret", &authorization.device_secret)
                .send()
                .await?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
            let status: DeviceStatus = response.error_for_status()?.json().await?;
            match status.state {
                AuthorizationState::Pending => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                AuthorizationState::Expired => bail!("device authorization expired"),
                AuthorizationState::Approved => {
                    return Ok(Session {
                        access_token: SecretString::from(
                            status.access_token.context("relay omitted access token")?,
                        ),
                        device_id: authorization.device_id,
                        profile: status.profile.context("relay omitted profile")?,
                    });
                }
            }
        }
    }

    pub async fn validate(&self, session: &Session) -> Result<Profile> {
        Ok(self
            .client
            .get(self.base.join("v1/me")?)
            .bearer_auth(session.access_token.expose_secret())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    pub async fn publish_key_packages(
        &self,
        session: &Session,
        key_packages: Vec<String>,
    ) -> Result<()> {
        self.authorized_post(session, "v1/key-packages")?
            .json(&KeyPackagePublish { key_packages })
            .send()
            .await?
            .error_for_status()
            .context("publish fresh MLS key package")?;
        Ok(())
    }

    pub async fn account_devices(&self, session: &Session) -> Result<DeviceList> {
        Ok(self
            .client
            .get(self.base.join("v1/devices")?)
            .bearer_auth(session.access_token.expose_secret())
            .send()
            .await?
            .error_for_status()
            .context("list account devices")?
            .json()
            .await?)
    }

    pub async fn start_device_revocation(
        &self,
        session: &Session,
        target_device_id: Uuid,
    ) -> Result<DeviceRevocationAuthorization> {
        Ok(self
            .authorized_post(session, "v1/device-revocations")?
            .json(&DeviceRevocationStart { target_device_id })
            .send()
            .await?
            .error_for_status()
            .context("start device revocation")?
            .json()
            .await?)
    }

    pub async fn device_revocation_status(
        &self,
        session: &Session,
        request_id: Uuid,
    ) -> Result<DeviceRevocationStatus> {
        Ok(self
            .client
            .get(
                self.base
                    .join(&format!("v1/device-revocations/{request_id}"))?,
            )
            .bearer_auth(session.access_token.expose_secret())
            .send()
            .await?
            .error_for_status()
            .context("poll device revocation")?
            .json()
            .await?)
    }

    pub async fn claim_key_packages(
        &self,
        session: &Session,
        handle: &str,
    ) -> Result<Vec<KeyPackageRecord>> {
        Ok(self
            .authorized_post(session, &format!("v1/users/{handle}/key-packages/claim"))?
            .send()
            .await?
            .error_for_status()
            .context("claim peer MLS key packages")?
            .json()
            .await?)
    }

    pub async fn claim_account_device_key_packages(
        &self,
        session: &Session,
        target_device_id: Uuid,
        count: u16,
    ) -> Result<Vec<KeyPackageRecord>> {
        Ok(self
            .authorized_post(session, "v1/account-device-key-packages/claim")?
            .json(&AccountDeviceKeyPackageClaim {
                target_device_id,
                count,
            })
            .send()
            .await?
            .error_for_status()
            .context("claim same-account MLS key packages")?
            .json()
            .await?)
    }

    pub async fn account_device_events(
        &self,
        session: &Session,
    ) -> Result<AccountDeviceEventBatch> {
        Ok(self
            .client
            .get(self.base.join("v1/account-device-events")?)
            .bearer_auth(session.access_token.expose_secret())
            .send()
            .await?
            .error_for_status()
            .context("fetch account device events")?
            .json()
            .await?)
    }

    pub async fn acknowledge_account_device_event(
        &self,
        session: &Session,
        delivery_id: i64,
    ) -> Result<()> {
        self.authorized_post(session, "v1/account-device-events/ack")?
            .json(&AccountDeviceEventAck {
                delivery_ids: vec![delivery_id],
            })
            .send()
            .await?
            .error_for_status()
            .context("acknowledge account device event")?;
        Ok(())
    }

    pub async fn acquire_conversation_mutation(
        &self,
        session: &Session,
        conversation_id: Uuid,
    ) -> Result<ConversationMutationAuthorization> {
        Ok(self
            .authorized_post(session, "v1/conversation-mutations")?
            .json(&ConversationMutationStart { conversation_id })
            .send()
            .await?
            .error_for_status()
            .context("acquire exclusive conversation mutation")?
            .json()
            .await?)
    }

    pub async fn release_conversation_mutation(
        &self,
        session: &Session,
        conversation_id: Uuid,
        mutation_id: Uuid,
    ) -> Result<()> {
        self.authorized_post(session, "v1/conversation-mutations/release")?
            .json(&ConversationMutationRelease {
                conversation_id,
                mutation_id,
            })
            .send()
            .await?
            .error_for_status()
            .context("release exclusive conversation mutation")?;
        Ok(())
    }

    pub async fn send_message(
        &self,
        session: &Session,
        envelope: &CiphertextEnvelope,
    ) -> Result<()> {
        self.authorized_post(session, "v1/messages")?
            .json(envelope)
            .send()
            .await?
            .error_for_status()
            .context("queue encrypted message")?;
        Ok(())
    }

    pub async fn messages(&self, session: &Session) -> Result<MessageBatch> {
        Ok(self
            .client
            .get(self.base.join("v1/messages")?)
            .bearer_auth(session.access_token.expose_secret())
            .send()
            .await?
            .error_for_status()
            .context("fetch encrypted mailbox")?
            .json()
            .await?)
    }

    /// Connects a metadata-minimal realtime hint stream. The receiver is
    /// intentionally lossy/coalescing: every hint causes the caller to fetch
    /// the durable authenticated mailbox, and periodic polling remains the
    /// complete fallback when WebSocket connectivity is unavailable.
    pub fn events(&self, session: &Session) -> Result<mpsc::Receiver<ClientEvent>> {
        let mut url = self.base.join("v1/events")?;
        let scheme = match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            _ => bail!("Mutte server URL cannot be converted to WebSocket transport"),
        };
        url.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("set WebSocket URL scheme"))?;
        let token = session.access_token.expose_secret().to_owned();
        let (sender, receiver) = mpsc::channel(1);
        tokio::spawn(event_notification_loop(url, token, sender));
        Ok(receiver)
    }

    pub async fn acknowledge(&self, session: &Session, delivery_id: i64) -> Result<()> {
        self.authorized_post(session, "v1/messages/ack")?
            .json(&MessageAck {
                delivery_ids: vec![delivery_id],
            })
            .send()
            .await?
            .error_for_status()
            .context("acknowledge encrypted mailbox delivery")?;
        Ok(())
    }

    pub async fn start_attachment(
        &self,
        session: &Session,
        input: &AttachmentStart,
    ) -> Result<AttachmentStatus> {
        Ok(self
            .authorized_post(session, "v1/attachments")?
            .json(input)
            .send()
            .await?
            .error_for_status()
            .context("start encrypted attachment upload")?
            .json()
            .await?)
    }

    pub async fn upload_attachment_chunk(
        &self,
        session: &Session,
        attachment_id: Uuid,
        input: &AttachmentChunkUpload,
    ) -> Result<()> {
        self.authorized_post(session, &format!("v1/attachments/{attachment_id}/chunks"))?
            .json(input)
            .send()
            .await?
            .error_for_status()
            .context("upload encrypted attachment chunk")?;
        Ok(())
    }

    pub async fn complete_attachment(&self, session: &Session, attachment_id: Uuid) -> Result<()> {
        self.authorized_post(session, &format!("v1/attachments/{attachment_id}/complete"))?
            .send()
            .await?
            .error_for_status()
            .context("complete encrypted attachment upload")?;
        Ok(())
    }

    pub async fn delete_attachment(&self, session: &Session, attachment_id: Uuid) -> Result<()> {
        self.client
            .delete(self.base.join(&format!("v1/attachments/{attachment_id}"))?)
            .bearer_auth(session.access_token.expose_secret())
            .send()
            .await?
            .error_for_status()
            .context("delete cancelled encrypted attachment upload")?;
        Ok(())
    }

    pub async fn attachment_chunk(
        &self,
        session: &Session,
        attachment_id: Uuid,
        chunk_index: u32,
    ) -> Result<AttachmentChunkData> {
        Ok(self
            .client
            .get(self.base.join(&format!(
                "v1/attachments/{attachment_id}/chunks/{chunk_index}"
            ))?)
            .bearer_auth(session.access_token.expose_secret())
            .send()
            .await?
            .error_for_status()
            .context("download encrypted attachment chunk")?
            .json()
            .await?)
    }

    pub async fn grant_attachment_recipient(
        &self,
        session: &Session,
        attachment_id: Uuid,
        target_device_id: Uuid,
    ) -> Result<()> {
        self.authorized_post(
            session,
            &format!("v1/attachments/{attachment_id}/recipients"),
        )?
        .json(&AttachmentRecipientGrant { target_device_id })
        .send()
        .await?
        .error_for_status()
        .context("grant attachment to new account device")?;
        Ok(())
    }

    fn post(&self, path: &str) -> Result<reqwest::RequestBuilder> {
        Ok(self.client.post(self.base.join(path)?))
    }

    fn authorized_post(&self, session: &Session, path: &str) -> Result<reqwest::RequestBuilder> {
        Ok(self
            .post(path)?
            .bearer_auth(session.access_token.expose_secret()))
    }
}

async fn event_notification_loop(url: Url, token: String, sender: mpsc::Sender<ClientEvent>) {
    let mut retry_seconds = 1u64;
    loop {
        if sender.is_closed() {
            return;
        }
        let request = match websocket_request(&url, &token) {
            Ok(request) => request,
            Err(_) => return,
        };
        if let Ok((mut socket, _)) = connect_async(request).await {
            retry_seconds = 1;
            while let Some(message) = socket.next().await {
                match message {
                    Ok(WebSocketMessage::Text(text)) => {
                        if serde_json::from_str::<RealtimeEvent>(&text).is_ok() {
                            let _ = sender.try_send(ClientEvent::MailboxReady);
                        }
                    }
                    Ok(WebSocketMessage::Ping(payload)) => {
                        if socket.send(WebSocketMessage::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Ok(WebSocketMessage::Close(_)) | Err(_) => break,
                    Ok(_) => {}
                }
                if sender.is_closed() {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(retry_seconds)).await;
        retry_seconds = (retry_seconds * 2).min(30);
    }
}

fn websocket_request(
    url: &Url,
    token: &str,
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>> {
    let mut request = url.as_str().into_client_request()?;
    let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))?;
    authorization.set_sensitive(true);
    request.headers_mut().insert(AUTHORIZATION, authorization);
    request.headers_mut().insert(
        "x-mutte-protocol",
        HeaderValue::from_static(PROTOCOL_VERSION),
    );
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_request_keeps_bearer_out_of_url_and_marks_it_sensitive() {
        let request = websocket_request(
            &Url::parse("wss://relay.mutte.test/v1/events").unwrap(),
            "private-token",
        )
        .unwrap();
        assert_eq!(request.uri(), "wss://relay.mutte.test/v1/events");
        assert!(!request.uri().to_string().contains("private-token"));
        let authorization = request.headers().get(AUTHORIZATION).unwrap();
        assert_eq!(authorization, "Bearer private-token");
        assert!(authorization.is_sensitive());
    }
}
