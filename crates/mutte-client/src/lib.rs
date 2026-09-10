//! Authenticated Mutte relay transport shared by every client frontend.
//!
//! Durable HTTPS resources remain the source of truth. [`Client::events`]
//! exposes a deliberately lossy wake-up stream that tells a frontend to fetch
//! the mailbox; callers must retain a polling fallback.

mod engine;
pub mod personal;
pub mod polls;
mod transfer;
pub use transfer::{
    ActiveAttachmentTransfers, AttachmentCancellation, AttachmentCancelled, AttachmentDirection,
    TransferPhase, TransferProgress,
};

pub use engine::{
    ClientCommand, ClientPaths, Connection, ConversationSnapshot, DevicePanel,
    DirectConversationChoiceRequired, MessageReaction, MessageSnapshot, MutteClient,
    VerificationPanel, VerificationState, is_reaction_for_known_message, is_reaction_message,
    reactions_for,
};

use std::{error::Error as StdError, fmt, time::Duration};

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use mutte_protocol::{
    AccountDeviceEventAck, AccountDeviceEventBatch, AccountDeviceKeyPackageClaim, ApiError,
    AttachmentChunkData, AttachmentChunkUpload, AttachmentRecipientGrant, AttachmentStart,
    AttachmentStatus, AuthorizationState, CiphertextEnvelope, ConversationMutationAuthorization,
    ConversationMutationRelease, ConversationMutationStart, DeviceAuthorization, DeviceList,
    DeviceRevocationAuthorization, DeviceRevocationStart, DeviceRevocationStatus, DeviceStart,
    DeviceStatus, KeyPackagePublish, KeyPackageRecord, MessageAck, MessageBatch, PROTOCOL_VERSION,
    Profile, RealtimeEvent, error_code,
};
use reqwest::{
    Client as HttpClient, Response as HttpResponse, StatusCode,
    header::{HeaderMap as HttpHeaderMap, HeaderValue as HttpHeaderValue, RETRY_AFTER},
};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
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

/// Account details used by the relay's existing email authorization flow.
///
/// The relay treats the same request as sign-up when the email is new and as
/// sign-in when it is already bound to the supplied handle. Keeping this type
/// in the client transport avoids changing the frozen shared protocol surface.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailAuthorizationInput {
    pub handle: String,
    pub display_name: String,
    pub bio: String,
    pub email: String,
}

/// A frozen relay error safe to render without branching on human prose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayRejection {
    pub status: u16,
    pub code: String,
    pub message: String,
}

/// Result of requesting a device-bound email authorization link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmailStartOutcome {
    LinkSent,
    Rejected(RelayRejection),
    RateLimited {
        retry_after: Duration,
    },
    /// The request or response failed at a point where delivery may have happened.
    Ambiguous {
        reason: String,
    },
}

/// Result of consuming a device-bound email authorization token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmailFinishOutcome {
    Confirmed,
    Rejected(RelayRejection),
    RateLimited {
        retry_after: Duration,
    },
    /// The request or response failed at a point where approval may have committed.
    Ambiguous {
        reason: String,
    },
}

/// One protected observation of a pending device authorization.
pub enum DeviceApprovalOutcome {
    Pending,
    Approved(Session),
    /// The relay reports approval after its one-time session handoff was
    /// already consumed or returned without all required session fields.
    ApprovedSessionUnavailable,
    Expired,
    Rejected(RelayRejection),
    RateLimited {
        retry_after: Duration,
    },
    Ambiguous {
        reason: String,
    },
}

/// The relay's one-time approved-session handoff can no longer be recovered
/// for this device identity. Callers must retire it and start with a fresh ID.
#[derive(Debug)]
pub struct DeviceAuthorizationHandoffLost;

impl fmt::Display for DeviceAuthorizationHandoffLost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("device approval completed, but its one-time session handoff is unavailable")
    }
}

impl StdError for DeviceAuthorizationHandoffLost {}

#[derive(Serialize)]
struct EmailStartRequest<'a> {
    device_id: Uuid,
    handle: &'a str,
    display_name: &'a str,
    bio: &'a str,
    email: &'a str,
}

#[derive(Serialize)]
struct EmailFinishRequest<'a> {
    token: &'a str,
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

/// Returns whether a relay operation failed because the protected session is
/// no longer authorized. Callers can use this classification to leave an
/// authenticated shell without treating connectivity and server failures as
/// credential loss.
pub fn authentication_required(error: &anyhow::Error) -> bool {
    contains_http_status(error, authentication_required_status)
}

/// Returns whether a relay operation failed because transport or the relay's
/// server-side availability failed, rather than because an action was
/// semantically rejected. Native presentation layers use this to distinguish
/// an offline state from a conversation-scoped action error.
pub fn connectivity_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|error| error.status().is_none_or(|status| status.is_server_error()))
    })
}

/// Returns whether `POST /v1/devices` rejected an unbound local identity.
/// Terminal bootstrap uses this only around that request, whose frozen
/// contract reports incompatible device state as either 400 or 409.
pub fn request_conflicted(error: &anyhow::Error) -> bool {
    contains_http_status(error, |status| {
        status == StatusCode::BAD_REQUEST || status == StatusCode::CONFLICT
    })
}

/// Returns whether a completed device authorization lost its one-time session
/// handoff and therefore requires a fresh local device identity.
pub fn device_authorization_handoff_lost(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<DeviceAuthorizationHandoffLost>()
            .is_some()
    })
}

fn contains_http_status(error: &anyhow::Error, predicate: impl Fn(StatusCode) -> bool) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .and_then(reqwest::Error::status)
            .is_some_and(&predicate)
    })
}

fn authentication_required_status(status: StatusCode) -> bool {
    status == StatusCode::UNAUTHORIZED
}

const RETRY_AFTER_FALLBACK_SECONDS: u64 = 1;
const RETRY_JITTER_MAX_MILLIS: u64 = 750;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EmailResponseKind {
    Accepted,
    Rejected,
    RateLimited,
    Ambiguous,
}

fn classify_email_response(status: StatusCode, expected: StatusCode) -> EmailResponseKind {
    if status == expected {
        EmailResponseKind::Accepted
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        EmailResponseKind::RateLimited
    } else if status.is_client_error() {
        EmailResponseKind::Rejected
    } else {
        EmailResponseKind::Ambiguous
    }
}

fn retry_after_delay(headers: &HttpHeaderMap, jitter_millis: u64) -> Duration {
    let seconds = headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(RETRY_AFTER_FALLBACK_SECONDS);
    Duration::from_secs(seconds).saturating_add(Duration::from_millis(
        jitter_millis.min(RETRY_JITTER_MAX_MILLIS),
    ))
}

fn response_retry_delay(response: &HttpResponse) -> Duration {
    let jitter = (Uuid::new_v4().as_u128() % u128::from(RETRY_JITTER_MAX_MILLIS + 1)) as u64;
    retry_after_delay(response.headers(), jitter)
}

async fn relay_rejection(response: HttpResponse) -> RelayRejection {
    let status = response.status();
    let fallback_code = match status {
        StatusCode::BAD_REQUEST => error_code::BAD_REQUEST,
        StatusCode::CONFLICT => error_code::CONFLICT,
        StatusCode::UNAUTHORIZED => error_code::UNAUTHORIZED,
        StatusCode::TOO_MANY_REQUESTS => error_code::RATE_LIMITED,
        StatusCode::SERVICE_UNAVAILABLE => error_code::SERVICE_UNAVAILABLE,
        _ => error_code::INTERNAL_ERROR,
    };
    match response.json::<ApiError>().await {
        Ok(error) => RelayRejection {
            status: status.as_u16(),
            code: error.code,
            message: error.error,
        },
        Err(_) => RelayRejection {
            status: status.as_u16(),
            code: fallback_code.to_owned(),
            message: format!("relay returned HTTP {status}"),
        },
    }
}

async fn sleep_before_authorization_expiry(
    authorization: &DeviceAuthorization,
    delay: Duration,
) -> Result<()> {
    let remaining = (authorization.expires_at - chrono::Utc::now())
        .to_std()
        .unwrap_or_default();
    if remaining.is_zero() {
        bail!("device authorization expired");
    }
    tokio::time::sleep(delay.min(remaining)).await;
    if delay >= remaining {
        bail!("device authorization expired");
    }
    Ok(())
}

fn device_secret_header(secret: &str) -> Result<HttpHeaderValue> {
    let mut value = HttpHeaderValue::from_str(secret).context("encode protected device secret")?;
    value.set_sensitive(true);
    Ok(value)
}

fn device_approval_outcome(
    authorization: &DeviceAuthorization,
    status: DeviceStatus,
) -> DeviceApprovalOutcome {
    match status.state {
        AuthorizationState::Pending => DeviceApprovalOutcome::Pending,
        AuthorizationState::Expired => DeviceApprovalOutcome::Expired,
        AuthorizationState::Approved => match (status.access_token, status.profile) {
            (Some(access_token), Some(profile)) => DeviceApprovalOutcome::Approved(Session {
                access_token: SecretString::from(access_token),
                device_id: authorization.device_id,
                profile,
            }),
            // Approval consumes the handoff exactly once. A successful status
            // without both fields cannot become complete on another poll.
            _ => DeviceApprovalOutcome::ApprovedSessionUnavailable,
        },
    }
}

impl Client {
    pub fn relay_url(&self) -> &Url {
        &self.base
    }
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
            // Relay API routes are canonical and never redirect. Refusing all
            // redirects prevents custom device-secret headers and 307/308
            // request bodies from crossing an origin boundary.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { base, client })
    }

    pub async fn start_device(
        &self,
        device_id: Uuid,
        name: String,
        key_package: String,
    ) -> Result<DeviceAuthorization> {
        loop {
            let response = self
                .post("v1/devices")?
                .json(&DeviceStart {
                    device_id,
                    device_name: name.clone(),
                    key_package: key_package.clone(),
                })
                .send()
                .await?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                tokio::time::sleep(response_retry_delay(&response)).await;
                continue;
            }
            return response
                .error_for_status()?
                .json()
                .await
                .context("decode device authorization");
        }
    }

    /// Observe the protected device status once without consuming a pending
    /// authorization. Transport and server failures remain explicitly
    /// ambiguous so an authorization flow can keep its in-memory secret alive.
    pub async fn check_approval(
        &self,
        authorization: &DeviceAuthorization,
    ) -> Result<DeviceApprovalOutcome> {
        if chrono::Utc::now() >= authorization.expires_at {
            return Ok(DeviceApprovalOutcome::Expired);
        }
        let url = self
            .base
            .join(&format!("v1/devices/{}", authorization.device_id))?;
        let response = match self
            .client
            .get(url)
            .header(
                "x-mutte-device-secret",
                device_secret_header(&authorization.device_secret)?,
            )
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(DeviceApprovalOutcome::Ambiguous {
                    reason: error.to_string(),
                });
            }
        };
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Ok(DeviceApprovalOutcome::RateLimited {
                retry_after: response_retry_delay(&response),
            });
        }
        if !status.is_success() {
            let rejection = relay_rejection(response).await;
            if status.is_server_error() {
                return Ok(DeviceApprovalOutcome::Ambiguous {
                    reason: format!(
                        "relay returned HTTP {} ({})",
                        rejection.status, rejection.code
                    ),
                });
            }
            return Ok(DeviceApprovalOutcome::Rejected(rejection));
        }
        let status = match response.json::<DeviceStatus>().await {
            Ok(status) => status,
            Err(error) => {
                return Ok(DeviceApprovalOutcome::Ambiguous {
                    reason: format!("could not decode device authorization status: {error}"),
                });
            }
        };
        Ok(device_approval_outcome(authorization, status))
    }

    pub async fn wait_for_approval(&self, authorization: &DeviceAuthorization) -> Result<Session> {
        let mut transient_delay = Duration::from_secs(1);
        loop {
            match self.check_approval(authorization).await? {
                DeviceApprovalOutcome::Pending => {
                    transient_delay = Duration::from_secs(1);
                    sleep_before_authorization_expiry(authorization, Duration::from_secs(2))
                        .await?;
                }
                DeviceApprovalOutcome::Approved(session) => return Ok(session),
                DeviceApprovalOutcome::ApprovedSessionUnavailable => {
                    return Err(DeviceAuthorizationHandoffLost.into());
                }
                DeviceApprovalOutcome::Expired => bail!("device authorization expired"),
                DeviceApprovalOutcome::RateLimited { retry_after } => {
                    sleep_before_authorization_expiry(authorization, retry_after).await?;
                }
                DeviceApprovalOutcome::Ambiguous { .. } => {
                    sleep_before_authorization_expiry(authorization, transient_delay).await?;
                    transient_delay = (transient_delay * 2).min(Duration::from_secs(5));
                }
                DeviceApprovalOutcome::Rejected(rejection) => bail!(
                    "device authorization was rejected: {} ({}; HTTP {})",
                    rejection.message,
                    rejection.code,
                    rejection.status
                ),
            }
        }
    }

    /// Send a device-bound one-time authorization link through the relay's
    /// existing email fallback. A successful response deliberately does not
    /// reveal whether the account already exists.
    pub async fn start_email(
        &self,
        device_id: Uuid,
        input: &EmailAuthorizationInput,
    ) -> Result<EmailStartOutcome> {
        let response = match self
            .post("v1/email/start")?
            .json(&EmailStartRequest {
                device_id,
                handle: &input.handle,
                display_name: &input.display_name,
                bio: &input.bio,
                email: &input.email,
            })
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(EmailStartOutcome::Ambiguous {
                    reason: error.to_string(),
                });
            }
        };
        let status = response.status();
        Ok(
            match classify_email_response(status, StatusCode::ACCEPTED) {
                EmailResponseKind::Accepted => EmailStartOutcome::LinkSent,
                EmailResponseKind::RateLimited => EmailStartOutcome::RateLimited {
                    retry_after: response_retry_delay(&response),
                },
                EmailResponseKind::Rejected => {
                    EmailStartOutcome::Rejected(relay_rejection(response).await)
                }
                EmailResponseKind::Ambiguous => {
                    let rejection = relay_rejection(response).await;
                    EmailStartOutcome::Ambiguous {
                        reason: format!(
                            "relay returned HTTP {} ({})",
                            rejection.status, rejection.code
                        ),
                    }
                }
            },
        )
    }

    /// Consume a one-time email token without navigating to its verification
    /// page. Ambiguous responses are not collapsed into rejection because the
    /// relay may already have committed approval.
    pub async fn finish_email(&self, token: &SecretString) -> Result<EmailFinishOutcome> {
        let response = match self
            .post("v1/email/finish")?
            .json(&EmailFinishRequest {
                token: token.expose_secret(),
            })
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(EmailFinishOutcome::Ambiguous {
                    reason: error.to_string(),
                });
            }
        };
        let status = response.status();
        Ok(
            match classify_email_response(status, StatusCode::NO_CONTENT) {
                EmailResponseKind::Accepted => EmailFinishOutcome::Confirmed,
                EmailResponseKind::RateLimited => EmailFinishOutcome::RateLimited {
                    retry_after: response_retry_delay(&response),
                },
                EmailResponseKind::Rejected => {
                    EmailFinishOutcome::Rejected(relay_rejection(response).await)
                }
                EmailResponseKind::Ambiguous => {
                    let rejection = relay_rejection(response).await;
                    EmailFinishOutcome::Ambiguous {
                        reason: format!(
                            "relay returned HTTP {} ({})",
                            rejection.status, rejection.code
                        ),
                    }
                }
            },
        )
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
        let connection = tokio::select! {
            _ = sender.closed() => return,
            result = connect_async(request) => result,
        };
        realtime_connection_diagnostic(&connection);
        if let Ok((mut socket, _)) = connection {
            retry_seconds = 1;
            loop {
                let message = tokio::select! {
                    _ = sender.closed() => return,
                    message = socket.next() => message,
                };
                let Some(message) = message else { break };
                match message {
                    Ok(WebSocketMessage::Text(text)) => {
                        if serde_json::from_str::<RealtimeEvent>(&text).is_ok() {
                            let _ = sender.try_send(ClientEvent::MailboxReady);
                        }
                    }
                    Ok(WebSocketMessage::Ping(payload)) => {
                        let pong = tokio::select! {
                            _ = sender.closed() => return,
                            result = socket.send(WebSocketMessage::Pong(payload)) => result,
                        };
                        if pong.is_err() {
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
        tokio::select! {
            _ = sender.closed() => return,
            _ = tokio::time::sleep(Duration::from_secs(retry_seconds)) => {},
        }
        retry_seconds = (retry_seconds * 2).min(30);
    }
}

fn realtime_connection_diagnostic<S>(result: &Result<S, tokio_tungstenite::tungstenite::Error>) {
    #[cfg(debug_assertions)]
    if std::env::var_os("MUTTE_REALTIME_DIAGNOSTICS").is_some()
        || std::env::args().any(|arg| arg == "--mutte-realtime-diagnostics")
    {
        use tokio_tungstenite::tungstenite::Error;
        // Fixed categories only: never log the request, URL, token, response
        // headers/body, message content or the underlying error's Display.
        let (stage, status) = match result {
            Ok(_) => ("connected", 0),
            Err(Error::Http(response)) => ("http_rejected", response.status().as_u16()),
            Err(Error::Tls(_)) => ("tls_failed", 0),
            Err(Error::Io(_)) => ("io_failed", 0),
            Err(_) => ("connect_failed", 0),
        };
        eprintln!("[mutte-realtime] stage={stage} http_status={status}");
    }
    #[cfg(not(debug_assertions))]
    let _ = result;
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
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    fn authorization() -> DeviceAuthorization {
        DeviceAuthorization {
            device_id: Uuid::new_v4(),
            device_secret: "protected-device-secret".to_owned(),
            verification_url: "https://api.mutte.me/auth".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        }
    }

    #[test]
    fn email_authorization_requests_keep_the_frozen_wire_shape() {
        let device_id = Uuid::parse_str("2fbb20f1-5992-4b08-811e-39a66ecf68dc").unwrap();
        let start = serde_json::to_value(EmailStartRequest {
            device_id,
            handle: "nightowl",
            display_name: "Night Owl",
            bio: "building quietly",
            email: "night@example.com",
        })
        .unwrap();
        assert_eq!(
            start,
            serde_json::json!({
                "device_id": "2fbb20f1-5992-4b08-811e-39a66ecf68dc",
                "handle": "nightowl",
                "display_name": "Night Owl",
                "bio": "building quietly",
                "email": "night@example.com"
            })
        );

        let finish = serde_json::to_value(EmailFinishRequest {
            token: "private-email-token",
        })
        .unwrap();
        assert_eq!(finish, serde_json::json!({"token": "private-email-token"}));
    }

    #[test]
    fn email_statuses_separate_rejection_rate_limits_and_ambiguous_results() {
        assert_eq!(
            classify_email_response(StatusCode::ACCEPTED, StatusCode::ACCEPTED),
            EmailResponseKind::Accepted
        );
        assert_eq!(
            classify_email_response(StatusCode::NO_CONTENT, StatusCode::NO_CONTENT),
            EmailResponseKind::Accepted
        );
        assert_eq!(
            classify_email_response(StatusCode::BAD_REQUEST, StatusCode::NO_CONTENT),
            EmailResponseKind::Rejected
        );
        assert_eq!(
            classify_email_response(StatusCode::CONFLICT, StatusCode::NO_CONTENT),
            EmailResponseKind::Rejected
        );
        assert_eq!(
            classify_email_response(StatusCode::TOO_MANY_REQUESTS, StatusCode::NO_CONTENT),
            EmailResponseKind::RateLimited
        );
        assert_eq!(
            classify_email_response(StatusCode::INTERNAL_SERVER_ERROR, StatusCode::NO_CONTENT),
            EmailResponseKind::Ambiguous
        );
        assert_eq!(
            classify_email_response(StatusCode::OK, StatusCode::NO_CONTENT),
            EmailResponseKind::Ambiguous
        );
    }

    #[test]
    fn retry_after_delay_honors_seconds_and_bounds_only_the_jitter() {
        let mut headers = HttpHeaderMap::new();
        headers.insert(RETRY_AFTER, HttpHeaderValue::from_static("17"));
        assert_eq!(
            retry_after_delay(&headers, 250),
            Duration::from_millis(17_250)
        );
        assert_eq!(
            retry_after_delay(&headers, 9_000),
            Duration::from_millis(17_750)
        );

        headers.insert(RETRY_AFTER, HttpHeaderValue::from_static("invalid"));
        assert_eq!(
            retry_after_delay(&headers, 100),
            Duration::from_millis(1_100)
        );
    }

    #[test]
    fn device_secret_header_is_always_sensitive() {
        let header = device_secret_header("protected-device-secret").unwrap();
        assert_eq!(header, "protected-device-secret");
        assert!(header.is_sensitive());
    }

    #[test]
    fn approved_status_without_a_complete_session_requires_fresh_identity() {
        let authorization = authorization();
        let missing_token = device_approval_outcome(
            &authorization,
            DeviceStatus {
                state: AuthorizationState::Approved,
                access_token: None,
                profile: Some(Profile {
                    id: Uuid::new_v4(),
                    handle: "quiet_user".to_owned(),
                    display_name: "Quiet User".to_owned(),
                    bio: String::new(),
                    status: "quiet".to_owned(),
                }),
            },
        );
        assert!(matches!(
            missing_token,
            DeviceApprovalOutcome::ApprovedSessionUnavailable
        ));

        let error = anyhow::Error::from(DeviceAuthorizationHandoffLost);
        assert!(device_authorization_handoff_lost(&error));
    }

    #[tokio::test]
    async fn relay_client_does_not_follow_redirects_with_secret_request_bodies() {
        let redirect_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirect_target_address = redirect_target.local_addr().unwrap();
        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (mut stream, _) = relay.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{redirect_target_address}/capture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let client = Client::new(Url::parse(&format!("http://{relay_address}/")).unwrap()).unwrap();
        let outcome = client
            .finish_email(&SecretString::from("private-email-token"))
            .await
            .unwrap();
        assert!(matches!(outcome, EmailFinishOutcome::Ambiguous { .. }));
        relay_task.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), redirect_target.accept())
                .await
                .is_err(),
            "the secret-bearing request must not reach a redirect target"
        );
    }

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

    #[tokio::test]
    async fn dropping_mailbox_receiver_stops_an_idle_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "ws://{}/v1/events",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let (sender, receiver) = mpsc::channel(1);
        let task = tokio::spawn(event_notification_loop(url, "test-token".into(), sender));
        let (stream, _) = listener.accept().await.unwrap();
        let _socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        drop(receiver);
        tokio::time::timeout(Duration::from_millis(300), task)
            .await
            .expect("an idle connection must not outlive its receiver")
            .unwrap();
    }

    #[tokio::test]
    async fn dropping_mailbox_receiver_interrupts_a_pending_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "ws://{}/v1/events",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let (sender, receiver) = mpsc::channel(1);
        let task = tokio::spawn(event_notification_loop(url, "test-token".into(), sender));
        let (_stream, _) = listener.accept().await.unwrap();
        drop(receiver);
        tokio::time::timeout(Duration::from_millis(300), task)
            .await
            .expect("a stalled handshake must not delay suspension")
            .unwrap();
    }

    #[test]
    fn only_authentication_statuses_require_a_new_session() {
        assert!(authentication_required_status(StatusCode::UNAUTHORIZED));
        assert!(!authentication_required_status(StatusCode::CONFLICT));
        assert!(!authentication_required_status(StatusCode::FORBIDDEN));
        assert!(!authentication_required_status(
            StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(!authentication_required_status(
            StatusCode::INTERNAL_SERVER_ERROR
        ));
    }

    #[tokio::test]
    async fn unavailable_relay_is_classified_as_connectivity_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client = Client::new(Url::parse(&format!("http://{address}/")).unwrap()).unwrap();
        let error = client
            .validate(&Session {
                access_token: SecretString::from("private-token"),
                device_id: Uuid::new_v4(),
                profile: Profile {
                    id: Uuid::new_v4(),
                    handle: "quiet_user".to_owned(),
                    display_name: "Quiet User".to_owned(),
                    bio: String::new(),
                    status: "quiet".to_owned(),
                },
            })
            .await
            .unwrap_err();

        assert!(connectivity_failure(&error));
        assert!(!authentication_required(&error));
    }
}
