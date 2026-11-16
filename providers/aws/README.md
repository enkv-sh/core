# AWS component

This module implements the state component's S3 Store and KMS Trust contracts. It
does not provide a public apply operation, domain initialization,
provider provisioning, general Store cleanup, or live construction qualification.
`Store.DeleteIfToken` provides guarded deletion of the exact obsolete handoff
selected by Core, using its observed strong ETag. It does not discover cleanup
targets or prove permanent physical erasure.

`NewStore(StoreConfig)` accepts an explicit credential provider, public
credential-route identity, domain, prefix, standard regional AWS endpoint
region, general-purpose bucket, and expected 12-digit bucket owner.
The bucket subset excludes dots and reserved aliases. Immutable keys must use
the exact domain and canonical member/recipient/root path; HEAD has one exact
coordinate. `NewTrust(TrustConfig)` accepts an exact regional UUID KMS key ARN
and canonical P-256 SPKI. `ParseVerifier` needs no credential or remote request.

`NewCandidateReader(CandidateReadConfig)` has GET access only to bounded HEAD,
Store-configuration and root objects. Its results are untrusted candidate bytes.
`CandidateLocation` returns the constructor location; it does not establish a
Store identity or caller admission. An optional expected bucket owner applies
from the first read. After Core authenticates the helper, it requires a guarded
reread of the same HEAD body and token before private recovery access.

`NewPublicSigningAnchor(PublicSigningAnchorConfig)` fixes one independently
supplied exact KMS key ARN and signing role. It exposes only
`QualifySigningBinding`; it has no Sign method. Qualification checks the selected
binding against that fixed resource, canonical SPKI and exact public-key reply.
Recovery qualification also checks enabled state and provider-generated origin.
A selected record cannot introduce another lookup resource. These primitives do
not by themselves authenticate a complete selection or reconstruct configuration.

The Store and Trust constructors validate inputs before credential retrieval. Every operation
retrieves credentials once before transmission and gives the SDK a fixed
snapshot. Cancellation before retrieval makes no credential call; cancellation
after retrieval prevents the provider request. The file loader opens the exact
path once with native nonblocking and
close-on-exec flags, admits one stable regular file of at most 64 KiB, and parses
only the selected static access-key, secret-key and optional session-token
fields. It does not invoke default credential discovery, helper processes,
roles, metadata, web identity or SSO. All returned facts use bounded Core reason
codes; raw SDK diagnostics are not returned.

`LoadSharedCredentialsFile(ctx, path, profile, expires)` supplies this explicit
credential provider. Session credentials require an independent future expiry.
Replacing a file takes effect through a new loader call before a new operation.
Other credential providers can use the same interface later.

Store, Trust and the owned HTTP boundary use production OpenTelemetry
instrumentation. Application startup resolves telemetry settings and passes an
invocation-owned context to Product calls, as shown in the
[local application example](../../tests/examples/telemetry/README.md).
The shared [metric contract](../../telemetry/definition.go) owns names, units,
attributes and completeness rules. File loading makes no credential HTTP requests.
HTTP body bytes exclude headers, TLS and TCP; consumption does not prove server
acceptance. See [test telemetry and reports](../../tests/README.md)
for local collection. With telemetry disabled, operations keep the same results.

The owned HTTP client copies only admitted fields from the supplied
`*http.Transport`: dial function, TLS settings, and timeouts. It disables
proxying, compression, connection reuse, HTTP/2, redirects and replay, limits
response headers to 16 KiB, and enforces one RoundTrip per SDK operation. TLS
dial overrides, insecure verification and explicit server-name overrides are
refused. The owned TLS configuration clones trust roots and preserves TLS 1.2
or 1.3 version bounds, ECDHE AEAD cipher restrictions, supported curve groups,
session-ticket disabling and record-sizing policy. TLS 1.2 cipher restrictions
support ECDHE with RSA or ECDSA authentication and AES-128-GCM, AES-256-GCM or
ChaCha20-Poly1305. Curve restrictions support P-256, P-384, P-521, X25519,
X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 and MLKEM1024. A zero
minimum uses TLS 1.2; a zero maximum uses the runtime maximum. Cipher and curve
slices are copied.
ALPN supports only HTTP/1.1. Client certificates, callbacks, session caches,
custom randomness or clocks, ECH and server-only settings are refused before
credential retrieval or network use. TLS key logging is refused. A positive
client timeout of at most two minutes is required.
The operator must supply the transport and credential route as part of
independent admission. These interfaces do not restrict actual IAM reach or
prove that operator-supplied trust roots, dial functions or credentials are
correct for a deployment.

S3 uses exact GET, create-only PUT, or one conditional HEAD PUT. Each PUT fixes
the complete body, length, expected owner and SHA-256 checksum. Core owns full
readback after all write outcomes. For PUT, only exact 412 `PreconditionFailed` maps to
precondition refusal; 409 conflict is separate, and other write errors retain
unknown status. A 403 read cannot establish absence. Only exact 404 `NoSuchKey`
maps to missing. A HEAD acknowledgment is not proof of current state.

Write and conditional-delete failures preserve their reason separately from
possible effects. A received `400 InvalidRequest` retains unknown status with a
construction reason; it does not acquire transport-only recovery permission.
Exact conditional rejection keeps its condition result. Unqualified or malformed
reply shapes retain unknown status with a malformed reason. The specific
`500 InternalError` reply retains unknown status and its qualified transport
recovery classification: [S3 can return it after applying the write](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorBestPractices.html).
Exact `503 SlowDown` also keeps unknown status with a transport reason because
[S3 documents it as temporary and retryable](https://docs.aws.amazon.com/AmazonS3/latest/userguide/optimizing-performance-design-patterns.html).
Only Core's existing readback, exact-request and cumulative retry limits apply.
A received
error alone does not prove that the request had no effect.

Credential refusal before SDK dispatch returns access refusal with positive
`NotSent`. This proves zero provider transmission for that call. A consumed
operation callback remains consumed; this fact alone grants no repeat.

Successful GET bodies use the selected object's byte limit. Non-2xx error
envelopes use a separate fixed 16 KiB limit before SDK decoding: a valid S3
error can be larger than a small selected object. Complete bounded errors
retain the mappings above. Oversized, encoded or incomplete error envelopes
return unavailable evidence. Actual excess success bytes establish an invalid
object; a declared length alone does not establish this when the transfer is
incomplete. Incomplete successful replies also return unavailable evidence.

KMS signs only a Core closed-purpose digest using `ECDSA_SHA_256` and `DIGEST`.
The adapter checks returned key identity, algorithm, signature length and
local P-256 verification. Signing itself performs no key lookup. The independent admission
record must establish the key's `ECC_NIST_P256` / `SIGN_VERIFY` provisioning.

Public inspection and receipt queries use the existing candidate and selected
public readers through the provider composition. Grant their principal bucket
object-read access. These routes construct no Store writer, signer, KMS metadata
lookup or private-key operation. Independent domain, Store and public trust
inputs remain required. The [operator reference](../../compositions/full/README.md#public-inspection-and-retained-receipts)
describes their source inputs, complete results and evidence limits.

## Local validation

Run from this directory:

```sh
GOWORK=off GOTOOLCHAIN=local go test -race -count=1 ./...
GOWORK=off GOTOOLCHAIN=local go vet ./...
GOWORK=off GOTOOLCHAIN=local go mod verify
```

Tests use the actual pinned SDK serializer and error decoder with controlled
RoundTrippers. A local TLS server also counts complete physical PUTs while
dropping an accepted write reply or returning a redirect. Both produce one
physical attempt and unknown status. Tests cover exact request coordinates and
conditions, bounded complete observations, malformed/truncated replies, exact
provider error codes, unavailable credentials, invalid constructions, foreign
domain keys and KMS key/algorithm/proof errors. No live AWS request is made.
Local TLS GET tests also count one physical request for small-object 403, 404
and 500 errors, oversized or truncated error envelopes, and oversized or
truncated object replies. Public `NewTrust` tests refuse wrong-region key ARNs,
malformed and non-P256 verifiers, and unsafe TLS before credential access.

The adapter rejects truncated, overlong or encoded 200 PUT replies,
foreign-domain paths and an uninitialized Store. The pinned PutObject success
decoder does not read its response body, so the transport completes and bounds
the reply before SDK decoding. PUT acknowledges only a complete empty 200;
conditional DELETE acknowledges only a complete empty 204. The same boundary
bounds SDK error-body allocation. DELETE maps exact 412 `PreconditionFailed`
and a received 404 to precondition refusal; this DELETE rule is distinct from
GET's exact `NoSuchKey` absence check and PUT's reply rules. A strong ETag is an
`If-Match` predicate for
the observed current representation. Equal bytes can yield the same ETag after
delete and recreate, so it is not a unique physical generation or an erasure
proof. Core selects only an obsolete logical handoff for cleanup; a released
inbox cannot become live work again.

The full module graph and checksums are in `go.mod` and `go.sum`. Direct pins are
AWS SDK core v1.39.0, S3 v1.88.0, KMS v1.45.2 and Smithy v1.23.0. These tests
establish local adapter behavior. Live IAM, key custody, region/bucket
configuration and provider availability need separate qualification. The
[test instructions](../../tests/README.md) cover complete offline checks and
explicit live execution with resource configuration and cleanup budgets.

## Contract sources

- [S3 PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)
- [S3 GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html)
- [S3 DeleteObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html)
- [S3 conditional deletes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-deletes.html)
- [S3 Object ETag](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Object.html#AmazonS3-Type-Object-ETag)
- [General-purpose bucket naming](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html)
- [KMS Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
- [Pinned S3 serializer](https://github.com/aws/aws-sdk-go-v2/blob/service/s3/v1.88.0/service/s3/serializers.go)
- [Pinned S3 response decoder](https://github.com/aws/aws-sdk-go-v2/blob/service/s3/v1.88.0/service/s3/deserializers.go)
- [Pinned KMS API](https://github.com/aws/aws-sdk-go-v2/blob/service/kms/v1.45.2/service/kms/api_op_Sign.go)
- [Go HTTP transport replay conditions](https://go.dev/src/net/http/transport.go)
