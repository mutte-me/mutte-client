use std::{fs, path::PathBuf};

use mutte_protocol::{
    ApiError, ChatApplicationPayload, CiphertextEnvelope, HistorySyncPayload, PushPayload,
    RealtimeEvent,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn assert_fixture_round_trip<T>(name: &str)
where
    T: DeserializeOwned + Serialize,
{
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures")
        .join(name);
    let expected: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let decoded: T = serde_json::from_value(expected.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), expected);
}

#[test]
fn frozen_language_neutral_wire_fixtures_match_rust_types() {
    assert_fixture_round_trip::<ApiError>("api-error-v1.json");
    assert_fixture_round_trip::<ChatApplicationPayload>("chat-message-v1.json");
    assert_fixture_round_trip::<ChatApplicationPayload>("chat-receipt-v1.json");
    assert_fixture_round_trip::<CiphertextEnvelope>("ciphertext-envelope-v1.json");
    assert_fixture_round_trip::<HistorySyncPayload>("history-ack-v1.json");
    assert_fixture_round_trip::<HistorySyncPayload>("history-chunk-v1.json");
    assert_fixture_round_trip::<HistorySyncPayload>("history-manifest-v1.json");
    assert_fixture_round_trip::<PushPayload>("push-mailbox-changed-v1.json");
    assert_fixture_round_trip::<RealtimeEvent>("realtime-mailbox-ready-v1.json");
}
