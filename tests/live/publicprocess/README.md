# Public configuration process tests

The [stock CLI plugin acceptance guide](stock-plugin-acceptance.md) describes the
separate opt-in path that uses an unchanged packaged CLI, ordinary installed
plugins and disposable Store buckets. It has its own stock evidence variant and
does not use the overlays or native captures described below.

This directory contains the test executable that calls the installed public
reconstruction and key-replacement constructors. The live runner also builds
the public `enkv` CLI. It starts separate init, set, apply, comparison, abandonment,
key-replacement and reconstruction processes, then joins each original invocation. The helper cannot
create private init, apply or consumer admission.

`--reconstruct-output <absolute-path>` writes a complete current configuration
through the public reconstruction normalizer and the shared pair writer. The
output must start as an isolated exact copy of the source pair. The helper uses
the source's separately retained public basis, leaves the source unchanged, and
writes exact current recipient rows and retained secret pins to the output.
This permits a fresh-process Compare and unchanged Apply after standalone access
changes. It cannot be combined with retained-input materialization or successor
replacement. `--materialize-retained` keeps its narrower rule: the existing
registry and memberships must already match the authenticated current state.

The runner applies a source-bound Go overlay when it builds these executables.
The overlay observes actual credential-source selection, provider requests and
private plaintext equality. It can inject a specified HEAD contention or lost
reply. It does not supply a successful provider response or waive admission.
See the [test runner instructions](../../README.md) for execution records,
supervisor setup and retained evidence.

Worker telemetry covers its own bucket admission, prefix scans and independent
HEAD reads. It does not include metrics emitted inside a CLI child. The separate
joined native captures establish the child request, credential-source and
private-equality facts. The runner does not synthesize child SDK metrics. Worker-side cleanup and direct
GET helpers use their isolated fixture roles for setup and independent checks;
they do not supply the public child credential-source proof.

## Public prepare after complete local-file loss

The [prepare workflow](../../workflows/public-configuration-prepare-live.json)
selects one supplied-secret case on AWS and GCP in both Recovery modes. Use the
private `workflow-prepare-bounded.json` prepared from the checked-in examples
with actual resource selectors and isolated SDK homes. The resource owner
provisions those resources and permissions before any live execution.

Each cell requires the distinct `authority`, `apply`, `reader`, `consumer` and
`cleanup` contexts in the [permission table](#roles-and-permissions). AWS uses
existing AssumeRole profiles. GCP uses the existing impersonated ADC contexts
and the resource quota project. The source credential and each selected login
must remain usable at execution time. A local plan checks the packet and case
selection without proving credentials or applied permissions.

The writer initializes the domain and applies one supplied secret. It retains
cleanup ownership and independent expected facts in the parent, deletes the
setup pair directory, and starts the public CLI's `prepare` command. This child
gets independent provider, bucket, region, prefix and current Normal signing
resource selectors, plus new local path/name choices and standard credentials.
It gets no saved pair, genesis descriptor, public basis, DomainID pin or parent
oracle. The parent checks exact selected identity, recipient membership,
retained material and complete recovered meaning after the child joins.

Fresh CLI children then check public plan, private supplied equality, unchanged
apply, administrative listing and existing-pair prepare. The separate `consumer`
executable checks recovered bytes through ordinary Authority reconstruction;
it is not a Recipient sink. Reader has no KMS grant. All recovery observations
exclude Recovery private use and remote mutations. The enclosing runner joins
the writer, starts its final portable Reader and cleans only the recorded run
prefix. A failed child or uncertain cleanup remains a retained failure.

The prepared cells need no effect plugin, Cloudflare or GitHub credentials, output
target, new key or new IAM context beyond the existing public fixture. The result
qualifies this supplied complete-loss flow only; generated state, replacement
history, failure interleavings, maxima and release installations have separate
checks.

## Local operator authentication

The [operator workflow](../../workflows/public-configuration-operator-live.json)
selects one public configuration case for each of these four credential sources:

| Source | Example | Provider setup |
|---|---|---|
| GCP interactive user ADC | [user ADC](../../environments/public-operator-gcp-user-adc.example.json) | `gcloud auth application-default login` in the selected isolated home |
| GCP service-account credentials | [service-account ADC](../../environments/public-operator-gcp-service-account-adc.example.json) | An existing service-account JSON file selected through standard ADC |
| AWS noninteractive credentials | [shared credentials](../../environments/public-operator-aws-shared-credentials.example.json) | An existing IAM-user access-key profile in the selected home's `.aws/credentials` |
| AWS interactive SSO | [SSO](../../environments/public-operator-aws-sso.example.json) | An IAM Identity Center profile and completed `aws sso login` in the selected home |

Each source has a Recovery-disabled and a Recovery-enabled cell. One participant,
`operator`, fills the five logical test roles. It needs the combined Authority,
Apply, Reader, reconstruction and cleanup permissions for the selected resources.
The case initializes an empty domain, prepares and applies one secret, reconstructs
it, captures the selected output credential, checks a portable pair through Reader,
and removes its owned run prefix. Reader runs in a fresh process with a capture
policy that refuses KMS calls. These results establish source discovery and public
flow behavior. They do not establish GET-only IAM, Recovery permission refusal or
separation between cloud principals. Use the original restricted cases for those
claims.

For user ADC, use the same absolute home for the isolated `HOME` and
`CLOUDSDK_CONFIG=HOME/.config/gcloud` setup, and set its ADC quota project with
`gcloud auth application-default set-quota-project PROJECT`. Ordinary
`gcloud auth login` alone does not establish ADC. The environment's `quota_project`
must match that existing ADC context.

For service-account ADC, set `sdk_context.credentials_file` to the absolute path
of an existing JSON key file and `sdk_context.quota_project` to the resource's
`quota_project`. The child sets `GOOGLE_APPLICATION_CREDENTIALS` and
`GOOGLE_CLOUD_QUOTA_PROJECT`; production uses normal ADC discovery. It does not
use the injected fixture-file loader. The service account needs quota-use
permission on that project. Do not create a new key for this preparation.

For AWS shared credentials, the selected profile must contain existing IAM-user
credentials with no session token, role assumption or SSO configuration. The SDK
must report the shared-file source; an environment or role source is refused.
These credentials do not expire, so their output snapshot must retain zero expiry.
The other three modes must report a future provider expiry. The isolated home can
link to the existing credentials file; do not copy or print credential values.

AWS SSO requires IAM Identity Center activation, account access, an SSO profile
and an interactive login. Console activation and login are operator actions. A
missing setup leaves this cell unqualified; another credential source cannot
satisfy it. No virtual machine is required by these four cases.

Copy the selected example, replace the resource selectors and local context paths,
and inspect one cell before a separately authorized run:

```sh
tests/scripts/test plan --workflow tests/workflows/public-configuration-operator-live.json --step public-operator-gcp-user-adc-enabled
```

The examples do not contain usable credentials. Prepare exact private
environments from the owner-provisioned resource selectors. A plan checks
test selection; it does not perform cloud authentication. Keep SDK caches, JSON
keys and generated environment files local and private.

## Resources and login contexts

Use pre-existing buckets, immutable key selectors and permissions. The setup
source contains selectors, not pasted public keys or credentials. Signing keys
must satisfy the installed P-256 profile; encryption keys must satisfy the
installed RSA-3072 profile. Keep the fixture's resources in one provider and
region, with one AWS account or GCP project. Enabled Recovery uses separate
normal and Recovery signing and encryption keys. The successor case also needs
a distinct pre-existing normal signing key in that same account/project and
region.

Creating a protected abandonment plan requires its output directory and all
ancestor directories to be owned by root or the current user, without group or
other write permission. Keep source and successor output pairs under the
operator's control. Their capture checks file identity and metadata, plus `.enkv`
directory identity, owner and permissions, and rejects symlink substitution.
Hostile local users and mixed-trust paths remain outside the supported boundary.

Start from the [AWS environment example](../../environments/public-aws.example.json)
or [GCP environment example](../../environments/public-gcp.example.json). Set
`public_configuration` to `true`. Supply exact resource selectors, role bindings
and `access.sdk_context` values. Each selected role must have a valid binding
before credentials are opened. Unused roles do not load credentials. These test
settings are not an ENKV connection or credential profile.

For the standard-discovery suite, each AWS participant uses `mode: "aws-sso"`, an absolute isolated `home`, and a
named SSO `profile`. Its login must already be established in that home's
`.aws/config` and SSO cache. The child selects that profile and uses an absent
shared-credentials path; inherited AWS credentials and endpoint overrides are
removed. EC2 metadata discovery is disabled.

For the standard-discovery suite, each GCP participant uses `mode: "gcp-user-adc"` and an absolute isolated `home`,
without a profile. Its local user ADC login must already exist below
`.config/gcloud`. Service-account and impersonated credentials do not satisfy
this source check. Inherited Google credential and endpoint overrides are
removed. Set the expected quota project in the environment and in the existing
ADC context. The user needs `serviceusage.services.use` on that quota project;
see [Google's quota-project rules](https://docs.cloud.google.com/docs/quotas/set-quota-project).

The [functional workflow](../../workflows/public-configuration-functional-live.json)
selects the ten restricted functional public configuration cases. It excludes
the standard-discovery and single-operator credential-discovery cases. Start from the
[AWS AssumeRole example](../../environments/public-aws-assume-role.example.json)
or [GCP impersonated ADC example](../../environments/public-gcp-impersonated.example.json).
It uses the same resources, finite limits, role permissions, assertions and
cleanup rules. It cannot establish SSO or direct-user ADC support.

For AWS functional cases, use `mode: "aws-assume-role"`, an absolute isolated
`home`, and a named role `profile`. The standard SDK reads that home's
`.aws/config` and `.aws/credentials`. Configure `role_arn` and `source_profile`
using an existing permitted credential source. Do not create another long-lived
access key. STS issues temporary role credentials. The capture must identify the
actual `AssumeRoleProvider` before a resource request can proceed. SSO, SSO OIDC
and STS endpoint overrides in the selected configuration are refused.

For GCP functional cases, use `mode: "gcp-impersonated-adc"` with an absolute
isolated `home` and no profile. Establish ADC through your user account with
`gcloud auth application-default login --impersonate-service-account SERVICE_ACCOUNT_EMAIL`
in that home's `.config/gcloud` context. The user needs permission to mint
short-lived tokens for that service account, the IAM Service Account Credentials
API must be enabled, and the quota project must match the environment. No
service-account private key is needed. The observer checks impersonated ADC,
its user credential source and the official impersonation URL before token
acquisition. Resource permissions come from the selected service account. The owner must supply the restricted accounts, per-account impersonation
grants and isolated login contexts required by the selected cases. These can
reuse existing KMS keys and need no new service-account private keys. Direct
user ADC and service-account JSON operator cases remain separate selections.
Before execution, check each local ADC target and quota project against the
owner-provisioned expected test role. The native observer
checks source kind and endpoint; it does not bind the target account to the
expected test role.

Both functional modes remove inherited credential and endpoint overrides. AWS
metadata discovery stays disabled. GCP metadata discovery is confined to a
local unusable endpoint, and a metadata credential is refused before any
property or token access. A denied request cannot select your original
user account or another role as a fallback. Missing roles and an attempt to use
these modes for standard discovery fail during selection, before login access
or executable preparation.

Login, key provisioning, IAM changes and cloud execution are separate operator
actions. Selecting or documenting a scenario does not authorize these actions.
The test does not perform an interactive login or change permissions.

## Roles and permissions

The labels below identify test credential contexts. They confer no ENKV Product
role by themselves. Scope each permission to the nominated keys and owned test
prefix where the service permits it. Bucket-level listing has the scope described
below. A denied context must authenticate successfully and reach the required
service denial; missing credentials, expired tokens and transport errors cannot
substitute for that result.

| Context | Required capability and restriction |
| --- | --- |
| `authority` | Read and create/replace fixture Store objects; resolve required key public material and metadata; normal signing and Authority KEK decryption. Enabled init also needs Recovery signing and Recovery KEK decryption. AWS initialization also needs bucket-level `s3:ListBucket` on the dedicated test bucket so an exact missing HEAD GET returns `NoSuchKey`. The five denied-init contexts need the same absence visibility before their selected KMS refusal. For `empty-initialization`, deny decryption with the exact ordinary Recipient key named by `reader_kek_id`, while permitting its public lookup. The helper requires one actual authenticated permission denial with a bounded synthetic ciphertext before the public init processes run. |
| `apply` | Store read/write, exact conditional GC deletion, required public key lookup, normal signing and Authority KEK decryption. AWS also needs bucket-level `s3:ListBucket` for exact missing-object observations; deletion requires `If-Match`. Deny Recovery signing and Recovery KEK decryption. Public Recovery wrapping must remain available. |
| `proposer` | Store reads and public-key/metadata reads for the normal signer and nominated Recipient key. Recipient preparation has no Store write, signing or KMS decryption permission. |
| `reader` | Read exact selected Store objects and list for bounded capacity/GC queries. Ordinary inspection and receipt children still make GET calls only. No Store mutation, key lookup, signing or KMS decryption. The trusted pair supplies public verification facts. |
| `consumer` | Store reads, normal signing-key public lookup and Authority KEK decryption for ordinary reconstruction. It does not deliver to a Recipient sink. |
| `recipient-consumer` | Store reads, normal signing-key public lookup and decryption with the exact enrolled Recipient KEK for the separate private byte oracle. Authority and Recovery private capabilities are not needed. |
| `recovery` | Store reads, normal signing-key public lookup and Recovery KEK decryption for the separate private test oracle. Its decryption is not an apply dependency. |
| `successor` | Store read/write, required public lookup, surviving Recovery signing, successor normal signing and Authority KEK decryption for the preceding reconstruction/materialization. The lost normal signing private capability is not required. |
| `excluded-consumer` | Store reads and normal signing-key public lookup. Keep the same Recipient KEK permission as `recipient-consumer`; membership exclusion must prove the exact Recipient wrap and membership are absent from current selected material, with no decryption attempt. Authority and Recovery private capabilities are not needed. |
| `cleanup` | Read the bucket metadata required by the existing fixture admission checks, list the owned prefix, read exact owned objects and conditionally delete them. AWS bucket-level `s3:ListBucket` also permits the exact post-delete missing-object GET. No private key access. |
| `denied-public` | Init context with one required nominated key public lookup denied; other capabilities needed to reach that boundary remain available. |
| `denied-normal-signing` | Init context with normal signing denied; required public lookup and other applicable capabilities remain available. |
| `denied-authority-private` | Init context with Authority KEK decryption denied; required public lookup and other applicable capabilities remain available. |
| `denied-recovery-signing` | Enabled init context with Recovery signing denied; required public lookup and other required capabilities remain available. |
| `denied-recovery-private` | Enabled init context with Recovery KEK decryption denied; required public lookup and other required capabilities remain available. |

For AWS, the relevant KMS actions are `kms:GetPublicKey`, `kms:DescribeKey`,
`kms:Sign` and `kms:Decrypt`, separated by the selected key. See the
[AWS KMS permission reference](https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html).
Store operations use `s3:GetObject`, `s3:PutObject`, `s3:ListBucket` and
`s3:DeleteObject` according to the context above; see the
[S3 operation permission reference](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html).

For GCP, separate key-version public/metadata access from
`cloudkms.cryptoKeyVersions.useToSign` and
`cloudkms.cryptoKeyVersions.useToDecrypt`; public key retrieval uses
`cloudkms.cryptoKeyVersions.viewPublicKey`. See the
[Cloud KMS permission reference](https://docs.cloud.google.com/kms/docs/reference/permissions-and-roles).
Store permissions are `storage.objects.get`, `storage.objects.list`,
`storage.objects.create` and `storage.objects.delete` as required by each
context. Object replacement requires both create and delete permission. See the
[Cloud Storage permission reference](https://docs.cloud.google.com/storage/docs/access-control/iam-permissions).

AWS public initialization, Reader, Apply and cleanup listing grants cover the
dedicated test bucket. A prefix-conditioned allow does not establish permission
for a missing-object GET, which carries no `s3:prefix` condition key. See
[AWS GetObject permissions](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html).
GCP also grants listing at bucket scope; object-name IAM conditions cannot
restrict that permission to a prefix. Reader receives only list permission in
addition to its prefix-scoped object reads, not bucket metadata or KMS access.
The runtime bounds LIST to the exact run/domain prefix and one query page.
These runtime restrictions do not narrow the credential's IAM reach.

These are capability requirements, not a complete IAM policy template. Account
policies, key policies, resource policies and service restrictions must permit
the intended operation while preserving each required denial.

## Selection and planning

From the repository root, use the existing launcher:

```sh
tests/scripts/test list
tests/scripts/test plan --workflow tests/workflows/public-configuration-live.json
tests/scripts/test plan --workflow tests/workflows/public-configuration-live.json --step public-aws-enabled --scenario public-configuration.fresh-secret-apply/fresh_secret_apply
```

The workflow has separate `public-aws-disabled`, `public-gcp-disabled`,
`public-aws-enabled` and `public-gcp-enabled` steps. The suite is
[`public-configuration.json`](../../suites/public-configuration.json). Review
the selected roles, resources, Recovery mode and
[finite limits](../limits/public-configuration.json) before any authorized run.
Planning is read-only. A selected case or a successful plan is not evidence that
the service operations passed.

The recipient lifecycle includes public and private planning, selected binary and
empty-value display, original-seal exclusion and repeat apply, and maintenance
successor readback and observation. It uses at most 63 joined child captures.
Its finite reservation account is 5,570 requests, 1,136 MiB plus 18 bytes of
body intake, and 240 objects; the configured limits are 6,144 requests,
1,280 MiB and 256 objects. These are reservations, not measured service use.
Recipient preparation requires the separate `proposer` context. Regenerate
local environments from applied setup output after that context is added.

An explicitly authorized run uses the same selection with `run` in place of
`plan`. No example here instructs the agent to execute a live run. The cost
allowance is a bound chosen by the operator, not a billing estimate. A native
child's `MaxBytes` charges request bodies and streamed response intake in the
installed provider service transport to one shared allowance. SDK credential
exchange uses its own transport within the enclosing finite context. The service
transport closes a response when its allowance is exhausted. An
unknown-length response must reach EOF within the allowance; it has no extra
probe byte outside that limit.

## Private verification and portable trust

After real public reconstruction succeeds, the ordinary plaintext observer
compares the verifier's actual bytes with the private expected digest before
those bytes are cleared. Its capture records only an equality result and count.
It exports no plaintext or digest. Public reconstruction output contains public
correlation and part count only.

The empty initialization case starts two independent setup sources against the
same empty provider coordinate. Both original conditional HEAD writes wait at a
local test barrier before either is sent. The service must select one ready
winner and return contention for the other. Both pairs and manifests remain in
the private evidence directory. Cleanup can read objects from either proposed
Domain only when an original captured create names that exact object key.

The apply competition uses the same barrier with two independent fresh
declarations. These real service races are distinct from the synthetic 412
transport test. A synthetic response does not prove a competing service state.

`--prepare-output-credential` calls the linked official AWS or GCP output
implementation in this isolated helper. The build captures its current
descriptor and checks its identity and declared SDK route. Public normalization,
target interpretation and action checks precede credential discovery. The helper
passes only the exact declared environment inputs, bounded to 65,536 bytes.
GCP also requires `--output-project-number` for its public preparation target.

The implementation's `Prepare` owns credential discovery and expiry checks.
The test observer records the actual selected SDK source and checks Google's
actual quota project against the selected context. AWS preparation can make one
bounded read-only STS identity request. Every nonnil prepared owner is closed,
including one returned with an error. The helper never calls `Send`. Its result
contains provider, preparation and closure booleans; credential bytes remain
inside the implementation. The parent positively joins the helper. Separate
local native-output checks cover the host's private environment channel.

The Recovery oracle runs in a separate verification process after the real
public selected-state authentication. Its private policy supplies the
source-validated Recovery public binding. It opens the exact selected Recovery
wrap through the existing custody owner and compares the actual new bytes. It
also checks Recovery protection after retained-input grant and exclusion. It
always returns an unavailable Product result after the private observation;
an equality event never means successful Product reconstruction through a
Recovery role. The denied check additionally requires an actual authenticated
provider permission error for the selected Recovery private call: AWS KMS
`AccessDeniedException` at HTTP 400 or 403, or GCP `PERMISSION_DENIED` at HTTP 403.
Authentication failures and other errors at the same status do not qualify.

The ordinary Recipient oracle uses the same authenticated public-selection
boundary in a separate process. Its policy supplies one exact ordinary binding
from trusted generated enrollment metadata and the selected Recipient's own
credential context. A positive check requires current entry membership, the
exact selected Recipient wrap and actual byte equality. An exclusion check
records `wrap_absent` only when both the Recipient wrap and membership are absent;
it makes no private decryption call. An invalid binding or mismatched wrap cannot
produce that fact. Recipient and Recovery oracle modes are exclusive. Both
return an unavailable Product result, expose no plaintext and grant no sink or
new Product consumption authority.

`--materialize-retained` is a test preparation option. Use it only after public
reconstruction and the independent expected-byte assertion succeed. It derives
incarnation/material pins from authenticated typed projection pages, checks the
source's public meaning, and uses the production generated emitter and native
edit transaction. It is limited to one or two supplied secret entries and
does not grant apply authority or edit generated JSON by hand.

The successor preparation options are `--successor-signing-selector` and
`--successor-scratch`, together with `--materialize-retained`. They use the
installed `ReplaceKeysConfiguration` operation with Authority as the target and
Recovery as the current authorizer, using the nominated signing selector and a
separate successor output. The representative source must be JSON. The new
immutable signing selector must identify a different key in the same fixture
provider, account/project and region. The input pair remains unchanged. The
helper returns the delivered output path; later public Reader and consumption
processes use that pair. Keep its actual signed succession selection and complete
enrollment; an ordinary apply HEAD cannot replace the prior proof. Successor
pair members stay in the private scratch directory, including after an unknown
result. No connection, basis or proposal carrier is created.

For public validation on a clean machine, transfer only the trusted editable
file and its exact referenced `.enkv/<digest>.json` dependency. Preserve their
relative paths and bytes. Use independently established GET-only credentials;
do not transfer an ENKV cache, original process state or extra trust file. With
the installed CLI and explicit absolute path/representation, invoke:

```sh
enkv plan --trusted /ABSOLUTE/TRUST/configuration.json --trusted-format json --json
```

The reader does not repair a missing or damaged generated dependency. Restore
the exact file from the trusted source. A local process-isolation test does not
establish that a second physical machine has been tested.

## Evidence and cleanup

`source-kind` identifies the actual SDK-selected source: AWS SSO, AWS assumed
role, GCP local user ADC or GCP impersonated user ADC. Each child must match its
selected actor mode; an assumed identity cannot prove a direct-login route. It does not record when or how an operator logged in. A standard-source
case also needs real successful operations against the official service. A
cached credential, source-kind event, local responder or synthetic token alone
does not establish service access or the required IAM denial.

Captures and source manifests remain local. Capture fields contain bounded
operation/status facts, sequence/count/equality facts, object-key hashes and a
normal-return footer. Do not add credentials, request or response bodies,
plaintext, expected hashes, selectors or raw provider errors. A missing footer,
unjoined request or failed capture is incomplete evidence. It cannot establish
successful cleanup or authorize an automatic init/apply restart.

Cleanup uses the separate `cleanup` context, the exact run prefix and retained
ownership records. It accepts only objects tied to original recorded create
attempts and a complete prefix observation, then deletes with exact observed
tokens. Unknown keys, incomplete child evidence and unresolved effects are
preserved. Keep the private run directory, captures, source pair, administrative
scratch and ownership inventory until cleanup is resolved.

Use the existing retained-run command only after reviewing its recorded state
and granting the required cleanup action and finite allowance:

```sh
tests/scripts/test cleanup <run-id> --limits tests/live/limits/public-configuration.json
```

The command can refuse an incomplete or already retained inventory; do not erase
or rewrite evidence to make it proceed. No step authorizes external uploads,
publishing, login, provisioning or IAM changes.

## Opt-in generated lifecycle

`tests/workflows/public-generated-live.json` selects two public CLI cases for
AWS and GCP, with Recovery enabled and disabled. One case rotates with manual
retirement; the other rotates with automatic retirement. Both select absence
before explicit retirement of the last generation. They check current state,
exact old targets, list, no-op, cleanup and a final independent Reader process.
The cases do not test an unknown live provider result or accept live residue.

Copy `tests/environments/cloudflare-public-environment.example.json` to the
private `cloudflare-public-environment.json` path named in the workflow. Set the
account, permission group and absolute path of the installed production plugin.
Keep `credentials_file` absent. Supply `CLOUDFLARE_API_TOKEN` in the environment
of an explicitly authorized run. This route uses the installed environment
credential producer; it has no file fallback. Internal and stock Cloudflare
fixtures also use `CLOUDFLARE_API_TOKEN` and reject file credentials.

The runner verifies the production plugin against its exact native source
build, then binds its digest, length and dependency manifest into the public
CLI build. The plugin child has an empty environment. Only a public CLI child
with a reserved producer allowance receives the bearer. Planning, list, no-op,
initialization and generated cleanup run without it in these cases.

Each case reserves at most six entered creates: two lineages, each with at most
three entered branches. A lineage stores five templates, but an entered path is
initial, then one qualified no-effect or residue branch, then its one successor.
The delete allowance is 22: at most 16 reserved by writer commands and six for
cleanup of known resources. Limits are in `tests/live/limits/public-generated.json`.
The SDK and Cloudflare request and byte allowances are reserved before child
entry.

Each manual child reserves 512 SDK requests and 64 MiB; each automatic
child reserves 1024 SDK requests and 64 MiB. MiB means 1048576 bytes.
The reservations include unused retry allowance.

| Owner | Manual count | Automatic count | Other requests per case | Other body MiB per case |
| --- | ---: | ---: | ---: | ---: |
| Initialization CLI | 1 | 1 | | |
| Lifecycle mutation CLI | 7 | 6 | | |
| Generated list CLI, including fresh worker | 6 | 6 | | |
| Unapplied plan and writer/fresh comparison plan CLI | 3 | 3 | | |
| Cloudflare create/delete allowances | | | 22 | 110 |
| Setup Check | | | 16 | 80 |
| Preflight scan, up to 256 pages | | | 512 | 256 |
| Independent HEAD, three owners with up to three read attempts each | | | 18 | 45 |
| Total | 17 | 16 | 568 | 491 |

The manual ceiling is 9272 requests and 1579 MiB; the automatic ceiling is
16952 requests and 1515 MiB. The shared limits file covers both cases:
26224 requests, 3094 MiB, twelve creates and 44 retires. Each worker also
retains its own finite budget.

Each lifecycle mutation child permits at most 256 physical Store writes and
32 MiB of write request bodies. Initialization permits sixteen writes and
8 MiB, with no generator effects. The runtime enforces these limits before
delegation, separately from HTTP request and body limits. A retry consumes
another write attempt. GCP multipart framing counts toward the write-byte
limit. Reader children permit only Store reads and no KMS, and reserve no
object writes. Native captures retain their 1 MiB bound.
The manual case reserves at most 1808 writes and 232 MiB; the automatic case
reserves 1552 writes and 200 MiB. The combined ceiling is 3360 writes and
432 MiB. Failed or unknown requests do not refund their allowance.

Cleanup retains 39430 requests and 96542 MiB per case, or 78860 requests and
193084 MiB for the shared step. Each case stays below the existing 4096-object
scanner cap. The scanner permits 256 pages of at most 128 keys. Each page
reserves two requests and 1 MiB. Two full bounded scans reserve 1024 requests
and 512 MiB. Each object permits three read owners: adoption, pre-delete and
post-delete. Each read owner permits three attempts, each reserving two
requests and 5 MiB. Conditional deletion adds two requests and 5 MiB. The total
is at most twenty requests and 50 MiB per object. Six possible Cloudflare
cleanup deletes add six requests and 30 MiB. The read reservation is fixed;
small observed object bodies do not reduce it. These are logical reservation
ceilings, not measured traffic or memory bounds. Time limits can stop an
incomplete run earlier.

The test overlay records accepted Attempt, account, action and exact delete
target before invoking the real producer custody. It updates the existing
private fixture ledger only from qualified safe facts returned by that custody.
CLI JSON never supplies cleanup ownership. A post-result ledger error fails the
harness separately and preserves the actual Product result. Retained public
evidence contains a bounded immutable projection of the settled ledger, hashes
of its original file and positive writer join, and the exact native capture joins.
It contains no bearer or generated token value.

Generator cleanup must settle before the run prefix can be deleted. A local
process-group join does not settle an unknown remote request. Pending creates,
unclosed delete attempts, missing joins or damaged evidence block teardown.
Keep the private run state in that case. These authored opt-in cases require a
separate authorized live run before they can establish live qualification.
