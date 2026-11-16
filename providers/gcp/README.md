# GCP provider boundary

This module implements the state component's GCS Store and Cloud KMS Trust contracts. It
uses `google.golang.org/api v0.222.0` with generated `storage/v1` and `cloudkms/v1`
clients. `go.mod` and `go.sum` record the full resolved dependency closure.

This is a library component. It supplies no public apply operation,
key discovery, general Store cleanup, retry
loop, resumable upload, or live-provider qualification. `Store.DeleteIfToken`
provides guarded deletion of the exact obsolete handoff selected by Core, using
its observed generation. It does not discover cleanup targets or prove permanent
physical erasure.

`Store.ListPage` performs one bounded listing under the admitted bucket/domain
prefix with an opaque continuation cursor. It checks the complete response and
returns at most the Store page limit. Core owns page traversal and cleanup target
selection; this API does not grant an unbounded bucket scan.

Public inspection and receipt queries use the existing candidate and selected
public readers through the provider composition. Grant their principal bucket
object-read access. These routes construct no Store writer, signer, KMS metadata
lookup or private-key operation. Independent domain, Store and public trust
inputs remain required. The [operator reference](../../compositions/full/README.md#public-inspection-and-retained-receipts)
describes their source inputs, complete results and evidence limits.

## Construction

`NewClient` accepts explicit `CredentialSource` and concrete `*http.Transport`
capabilities. It owns a fresh transport with fixed bounds, HTTP/1.1, normal server
certificate verification, no proxy, no connection reuse, no compression, and no
redirects. It does not inherit custom dial functions, custom TLS verification,
registered protocol handlers, or future protocol settings. The credential source
is resolved before each operation; the request uses that captured bearer value.
The credential source may independently refresh its cache in the background.
Cancellation before retrieval makes no credential call; cancellation after
retrieval prevents the provider request. Credential-source behavior and actual
credential reach still require independent admission. These interfaces are not an IAM boundary.

`LoadDefaultCredentials(ctx)` selects Application Default Credentials using the
provider library's standard discovery. Selected ADC caches may refresh tokens
in the background. Token capture checks expiry and cancellation, and the selected
universe must match the fixed service endpoints.

`LoadServiceAccountFile(ctx, path)` supplies a `CredentialSource` from a standard
service-account JSON key. It opens the exact path once with native nonblocking
and close-on-exec flags and admits one stable regular file of at most 64 KiB.
The RSA private key must have a modulus of at least 2048 bits. The loader accepts
only the standard Google token route and refreshes synchronously before an
operation. It uses no ambient credential fallback. An optional `quota_project_id`
is validated and captured from that same file; later file or environment changes
cannot replace the captured service quota header.

Store, Trust, the loaded credential source and owned HTTP boundaries use
production OpenTelemetry instrumentation. Application startup resolves
telemetry settings and passes an invocation-owned context to Product calls and
credential loading, as shown in the
[local application example](../../tests/examples/telemetry/README.md).
The shared [metric contract](../../telemetry/definition.go) owns names, units,
attributes and completeness rules; authentication traffic has its own operation
label. HTTP body bytes exclude headers, TLS and TCP; consumption does not prove
server acceptance. See [test telemetry and reports](../../tests/README.md)
for local collection. With telemetry disabled, operations keep the same results.

Construction refuses case-insensitive `true` in
`GOOGLE_API_USE_CLIENT_CERTIFICATE` or `EXPERIMENTAL_GOOGLE_API_USE_S2A`. The pinned
SDK can probe default client certificates before honoring an explicit HTTP client,
and rejects `WithHTTPClient` together with `WithClientCertSource`. The adapter
therefore refuses ambient discovery instead of changing the process environment.
The exact endpoint and explicit HTTP client also exclude the pinned S2A metadata
path; the refusal keeps that capability outside this construction. The admitted
process must not mutate these environment settings concurrently with construction.
The fixed universe, endpoint, client, and logger override other SDK ambient routes.

`NewStore` requires a nonzero domain, fixed prefix, fixed bucket, fixed region,
nonsecret credential-route identity, and the exact regional endpoint
`https://storage.REGION.rep.googleapis.com/storage/v1/`. The generated service uses
the corresponding `/download/storage/v1/` base for media GET. Its single multipart
insert resolves the fixed `/upload/storage/v1/` path. The descriptor binds the
construction and HEAD coordinate. Immutable object keys must match the admitted
domain, typed page/root coordinate, index, and lowercase nonzero object identity.

`NewCandidateReader` has GET access only to bounded HEAD, Store-configuration
and root objects at the fixed regional media endpoint. `CandidateLocation`
returns its constructor location. Candidate bytes and location metadata establish
neither a complete selection nor caller admission.

`NewPublicSigningAnchor` fixes one independently supplied exact
`cryptoKeyVersions/N` resource and signing role before it sees a selected binding.
It exposes only `QualifySigningBinding`, with no Sign method. The public-key reply
must have the exact resource, P-256 algorithm, permitted protection level and
matching canonical DER/SPKI. CRC32C is checked against the original PEM bytes.
Recovery qualification also checks the generated-origin metadata described below.
A selected record cannot introduce another lookup resource. These primitives do
not by themselves reconstruct configuration.

`NewTrust` requires the exact locational endpoint
`https://REGION-cloudkms.googleapis.com/`, exact key-version name in that
region, `ASYMMETRIC_SIGN`, `EC_SIGN_P256_SHA256`, and a canonical pinned P-256 SPKI.
Its public construction identity binds region, endpoint, algorithm, purpose and
role. The exact key and credential route remain separate pinned inputs.
Provisioning and key algorithm evidence must be independently admitted; construction does not fetch a
public key. `ParseVerifier` allows offline use of the pinned verifier. Recovery
signer qualification also requires a present RFC3339Nano generation time, empty
import time and import job, false re-import eligibility, and absent external
protection options on the exact enabled `SOFTWARE` or `HSM` version. Normal
signing does not use this generated-origin metadata rule.

Core compares authority and recovery encryption parents from validated literal
resource parts. Different location, key ring, or CryptoKey parts prove separate
parents. With the same parent tuple, distinct project IDs or distinct canonical
positive-int64 project numbers prove separation. An ID/number pair is ambiguous
and refuses in either order. The comparison does not normalize selectors, resolve
aliases, or call Cloud KMS. Provider-hosted imported encryption versions remain
eligible under the encryption KEK profile.
Cloud KMS uses its documented [locational service endpoints](https://docs.cloud.google.com/kms/docs/reference/service-apis-overview#service_endpoints).
The GCS regional hostname pattern does not establish KMS availability in a region.

The SDK's ambient wire logging is not used. Provider outcomes expose only bounded
status and reason codes, never SDK errors, response bodies, or credentials. Caller
context headers cannot add a billing route, encryption header, condition, or range
to the fixed request construction.

## Operations

- Read uses one complete bounded `Objects.Get(...).Download()` response and its
  canonical positive `X-Goog-Generation`. It cannot combine partial responses or
  substitute metageneration. It distinguishes missing objects from denied access.
  Reading more actual bytes than the requested limit proves an invalid object,
  including during immutable readback at the planned reference length. The
  bounded reader stopping at `limit+1` is not a failed transfer. Observed body
  errors, or an early body end before the advertised length without excess bytes,
  remain unavailable. The adapter never drains the rest of an oversized body.
  Missing-object evidence requires a complete physical `404` and a consistent
  qualified response: JSON code `404` with one `notFound` reason, XML with one
  `NoSuchKey` or `NoSuchBucket` code, or the exact body `No such object: BUCKET/KEY`
  with the requested bucket and logical key, without a newline or other extra bytes.
  Duplicate, conflicting or malformed proof fields and arbitrary empty `404`
  responses do not establish absence. Qualified
  bucket absence also establishes that the requested object is absent at that
  observation; it requires no separate bucket request and proves no deletion by
  this invocation.
- Create uses one JSON multipart insert with `ifGenerationMatch=0`, complete
  bytes, metadata CRC32C, and exact physical Content-Length. HEAD creation is
  refused. CompareAndSwap accepts only HEAD and its original positive generation.
- A write acknowledgment needs the returned exact bucket/name, canonical positive
  generation, encoded size, CRC32C and a complete HTTP 200. Core must still
  perform exact readback. Media GET uses `/download/storage/v1/`; conditional
  DELETE uses `/storage/v1/` and acknowledges only a complete empty HTTP 204.
  A generation predicate names a GCS object version; cleanup does not promise
  permanent physical erasure.
  A complete physical HTTP `412` with the single reason `conditionNotMet` is a
  conditional rejection. Other 412 reasons are refusals. The pinned write decoder
  can replace the physical status with a nonzero JSON `error.code`; the adapter
  retains the physical status and requires matching code evidence before a
  definitive rejection. Conflicting or malformed codes remain unknown, including
  HTTP `503` carrying JSON code `412`, `403`, or `404`. The pinned media decoder
  preserves physical status; missing-object responses require the separate read
  qualification above. Timeouts,
  lost or truncated replies, redirects, and retryable statuses remain unknown.
  The adapter never obtains a replacement generation or retries.
  Credential refusal before SDK dispatch returns access refusal with positive
  `NotSent`. It proves zero provider transmission for that call, while any
  consumed operation callback remains consumed. It is not a transport-retry
  witness.
- Sign accepts only a closed Core `SignRequest`. It sends the purpose-separated
  SHA-256 digest and CRC32C. It requires the exact returned key version, verified
  digest checksum flag, a present canonical matching signature checksum, bounded
  DER signature, and local P-256 verification before returning the signature.

## Local validation

Run from this directory:

```sh
GOWORK=off GOTOOLCHAIN=local go test -race -count=1 ./...
GOWORK=off GOTOOLCHAIN=local go vet ./...
GOWORK=off GOTOOLCHAIN=local go mod verify
```

The tests execute real generated SDK request serialization through controlled
HTTP transports. They inspect multipart metadata and media, exact paths and
conditions, bounded body/token pairing, error mapping, lost replies, malformed
acknowledgments, credentials-before-send behavior, and KMS proof validation. Local
TLS-server tests count physical sends after a lost reply, redirect, and retryable
response. Test-only routing and certificate bypasses never enter production
constructors or dependency closures.

The generated int64 decoder accepts a noncanonical generation such as `"010"`.
Raw bounded response checks prevent that normalization from producing a valid
acknowledgment. Fresh transport construction excludes registered alternate
handlers and unselected exported protocol settings.

No live provider, credential, IAM, key-custody, residency, throughput, SDK security,
or deployment qualification is claimed. Live-use admission must verify regional
availability, private uncached object access, complete-response generation headers,
transport behavior, credential reach, and provider lifecycle settings. The
[test instructions](../../tests/README.md)
cover complete offline checks and explicit live execution with resource
configuration and cleanup budgets.

## Contract sources

- [GCS regional endpoints](https://docs.cloud.google.com/storage/docs/regional-endpoints)
- [Objects insert](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/insert)
- [Objects get](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get)
- [Objects delete](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/delete)
- [GCS request endpoints](https://docs.cloud.google.com/storage/docs/request-endpoints)
- [Service-account OAuth token response](https://developers.google.com/identity/protocols/oauth2/service-account#httprest)
- [Google access-token lifetimes](https://docs.cloud.google.com/docs/authentication/token-types#service-account-access-tokens)
- [Cloud KMS asymmetricSign](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign)
- [Pinned generated Storage source](https://raw.githubusercontent.com/googleapis/google-api-go-client/v0.222.0/storage/v1/storage-gen.go)
- [Pinned generated KMS source](https://raw.githubusercontent.com/googleapis/google-api-go-client/v0.222.0/cloudkms/v1/cloudkms-gen.go)
- [Pinned multipart behavior](https://raw.githubusercontent.com/googleapis/google-api-go-client/v0.222.0/internal/gensupport/media.go)
- [Pinned send behavior](https://raw.githubusercontent.com/googleapis/google-api-go-client/v0.222.0/internal/gensupport/send.go)
- [Pinned HTTP constructor](https://raw.githubusercontent.com/googleapis/google-api-go-client/v0.222.0/transport/http/dial.go)
