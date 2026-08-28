# Native-client contract freeze

The `mutte/0.8-alpha` relay contract is frozen as of 2026-08-27 so the Omarchy
and iOS clients can be built against a stable server boundary.

The normative HTTP contract is `contracts/openapi.yaml`; shared enums and
payload semantics are defined by `crates/mutte-protocol/src/lib.rs`. Stable
error behavior is registered in `contracts/error-semantics.json`, and
language-neutral examples live in `contracts/fixtures/`. CI pins all of these
files plus every applied relay migration in `contracts/frozen-contract.json`
and rejects an unreviewed edit.

Within this protocol version:

- existing paths, fields, status codes, enum values, authentication rules, and
  meanings cannot be removed or changed;
- additive optional fields and new endpoints require a compatibility review
  and an intentional refresh of the freeze manifest;
- any breaking change requires a new `X-Mutte-Protocol` value, an OpenAPI
  version bump, client migration notes, and a coexistence or rollout plan;
- `429 rate_limited` includes `Retry-After`; clients must wait at least that
  many seconds and add jitter;
- `409 quota_exceeded` is durable until the user removes data, recipients drain
  their mailbox, or an operator changes the configured quota;
- an approved device access token is handed off exactly once. Clients must
  persist it before making another authorization poll. If that response is
  lost, restart device authorization.

## Stable errors

Clients branch only on `ApiError.code`, never the human `error` text. The HTTP
status, retry classification, and `Retry-After` requirement for every known
code are frozen in `contracts/error-semantics.json`. Every error response has a
UUID `request_id` in both the JSON body and `X-Request-Id`; every relay response
has `X-Mutte-Protocol`.

Clients must decode `code` as a string. An unknown future code is displayed and
retried like `internal_error`; it must not make the envelope undecodable.
Automatic retries are allowed only where the registry permits them, and only
for operations whose idempotency contract makes replay safe.

## Encrypted and realtime payloads

The fixtures are canonical, language-neutral JSON examples for MLS application
plaintexts, history sync, opaque relay envelopes, WebSocket hints, push hints,
and errors. Their Rust round-trip test prevents Serde behavior from drifting
away from what Swift and future clients implement.

New variants, renamed fields, changed enum spellings, or new required fields in
these versioned payloads are breaking changes. Optional HTTP response fields
remain additive, but inner MLS and push payloads use their own numeric version
and must be migrated deliberately.

## Database migration baseline

Applied migrations are immutable. Never edit, rename, reorder, or remove an
existing file in `apps/mutte-relay/migrations`; PostgreSQL/SQLx checksums and
the freeze manifest both enforce this. Schema changes use a new, contiguous
`NNNN_description.sql` migration.

Migrations are expand-first: the previously deployed relay binary must still
start and serve its frozen contract after a new migration is applied. Dropping
or repurposing a column, constraint, enum value, or table requires a staged
compatibility plan and cannot occur while a rollback-compatible binary may run.
The relay image rollback therefore rolls code back, never migration history.

## Changing the freeze

An additive change requires compatibility review, updated tests/fixtures, and
an intentional digest refresh in `contracts/frozen-contract.json`. A breaking
change additionally requires a new protocol value, an OpenAPI version bump,
client migration notes, and a tested coexistence/rollout plan. CI failing on a
digest is evidence that review is needed, not a reason to update the digest
mechanically.

WebSocket and push messages remain hints. A reconnect always reads the
authenticated mailbox and account-device event feeds as the source of truth.
