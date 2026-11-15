# Optional trusted management proxy

This is a service integration contract, not SSO or independent validation of a
human identity. The trusted management backend authenticates its own users and
checks current membership/authorization before signing each request. Do not
expose its private key or delegated tokens to a browser, agent context or logs.
Normal local administrator login/bootstrap remains unchanged when unconfigured.
Inference keys (`mgp_`) remain independent and cannot manage providers/models.

## Configuration

- `MAGPIE_PROXY_PUBLIC_KEY_FILE`: bounded PEM P-256 public key; no private key.
- `MAGPIE_PROXY_ISSUER`: exact trusted issuer string.
- `MAGPIE_PROXY_AUDIENCE`: exact single installation-specific audience string.

All three are required together. Configuration is loaded once: restart all API
instances after key/issuer/audience changes and coordinate the trusted signer.
Use network policies to restrict the native management API to that backend.
A valid proxy configuration can satisfy management readiness without creating a
second human administrator. It does not enable inference or grant cluster/tool
execution rights. No automatic storage or provider selection is implied.

## Signed request

`Authorization: Bearer mgd_<ES256 JWT>` with exactly `alg=ES256,typ=JWT` headers.
Required claims: `iss`, exact string `aud`, canonical UUID `sub`, integer `iat`,
`nbf=iat`, integer `exp` (1..60 seconds after iat), canonical UUID `jti`,
`actor_kind=human|agent`, `scope`, `method`, `target`, `body_sha256`.
The target is the exact native path and raw query, without scheme/host. The
body hash covers exact transmitted bytes, including whitespace. Agent claims
also require a canonical UUID `agent_id`; human claims cannot contain that field.
Each backend derives these identities from its verified context, not client
headers. Tokens bind actor/method/target/body/audience; they are not generic PATs.

GET requires `magpie:admin:read`. POST/PUT/DELETE require
`magpie:admin:write` and a human originating actor. Delegation cannot manage local
administrator accounts/sessions. Read requests may be replayed within their short
lifetime; they cannot issue keys or change state. Replayed write requests return409.

Before any write effect, the request identity is consumed in an independent PG
transaction. Handler rollback does not restore it. A retry after a lost response
MUST reconcile the old request, not sign a new mutation blindly. Native API-key
issuance retains its separate Idempotency-Key semantics; raw keys are still
shown once and cannot be recovered by lookup or replay.

`GET /admin/proxy-requests/{jti}` with a fresh read delegation returns only the
same issuer/subject's consumed identity and linked audit evidence. An absent
record or absence of an audit is not proof of failure; it may be in-flight or
use a different DB/identity. Audit evidence is not proof of external delivery or
provider billing. Normal audit records carry a nullable `proxy_request_id`.
No plaintext token/body/credential is persisted in the delegation table.

Apply Alembic0029 with the migration owner before new code. Runtime needs the
reviewed table/sequence rights, not a migration-owner password. Backup/restore
must preserve consumed identities and audit together. Older restored backups or
independently running DBs can weaken replay evidence; this is not HA/fencing.
Operator maintenance prunes consumed identities only after two days and only
when no audit entry references them. Audit retention remains explicitly managed.

## Verification boundaries

Offline tests cover signature/issuer/audience/lifetime/body/path/scope/actor,
write replay despite rollback, audit identity and unchanged local mode. Native
PostgreSQL migration/concurrency/restore and real integrated issuer acceptance
must be recorded separately; no real provider invocation follows from these tests.
