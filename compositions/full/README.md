# Full CLI reference

For first installation and daily tasks, start with the
[operator guide](../../docs/README.md). This reference describes the detailed
command, result and library boundaries.

The `enkv` executable supports local `prepare`, empty-domain `init`, local `set` and recipient
preparation, complete declaration `apply`, `publish` and `plan` for AWS or GCP. Planning
uses public reads by default; explicit private checks can compare supplied
secrets and display selected proposed values. The source-based `abandon` family
lists selected work, delivers a protected plan, applies an exact reviewed
disposition and reads its retained receipt. `keys replace` changes existing
Authority, enabled Recovery or ordinary Recipient bindings through a separate
portable successor pair. Each operation constructs only its required Store,
signing, material or public-reader routes. General composition constructors
remain available to admitted internal callers.

Library callers use the same configuration and file operations as the CLI.
The [configuration library reference](library.md) lists the supported entry
points, request declarations, result helpers and ownership rules. Support for
those operations does not select every export in their implementation packages.

`NewReconstruction` selects one internal AWS or GCP reconstruction composition.
Supply exactly one provider configuration matching `Family`. Its inputs are an
explicit Store location, independently supplied immutable signing resources,
credential routes or clients, and optional continuity pins. `Reconstruct` uses
a finite caller context and returns a complete owned projection. It does not
install a configuration pair. `PrepareConfiguration` owns absent-pair delivery
around that reconstruction boundary. GCP clients remain owned by the caller. Close the
returned projection and engine when reconstruction is complete.

Use the [native CLI packaging recipes](../../distribution/cli-packaging.md)
to assemble a CLI with explicit plugin and CLI verification roots. Use the
[source build instructions](https://github.com/enkv-sh/extensions/blob/main/distribution/README.md)
for the coordinated workspace or exact versioned dependencies. A plain source
build has no implicit signing authority. The
[installation guide](https://github.com/enkv-sh/extensions/blob/main/distribution/local-installation.md)
describes archive verification, PATH setup and application plugin selection.

## Configuration commands

Examples show both the default source and explicit source paths.
Configuration-reading commands default to `enkv.yaml` in the current directory,
with YAML syntax. `plan` uses the same default for its trusted source. Explicit
relative paths resolve from the directory captured for that invocation.
Explicit `.yaml`, `.yml` and `.json` suffixes select syntax, without regard to
case. Use `--source-format yaml|json` with `--source`, `--trusted-format` with
`--trusted`, and `--candidate-format` with `--candidate` to override the suffix.
An unknown or absent suffix needs an explicit format. An explicit empty path
or format refuses. An omitted candidate uses the trusted declaration;
`--candidate-format` alone refuses. ENKV does not search parent directories or
try another file or parser after failure. The former `--format` flag is refused.
`--json` selects result presentation.
Configuration contains one editable file and, after resolution, its generated
JSON satellite.
The local `domain.name` selects `.enkv/<name>.generated.json`; for example,
`prod` selects `.enkv/prod.generated.json`. The editable filename is independent.
Keep both files together with the same relative path. The
[configuration module](../configuration/README.md) describes capture and edit
limits. Restore missing generated data from a trusted copy, or use the explicit
[missing-companion preparation](#restore-a-missing-generated-companion) below.
Apply and plan require complete input. The local name does not change DomainID,
keys or Store settings.

## Prepare an existing domain

Use the existing form for a valid complete local pair:

```sh
enkv prepare --json
```

This checks plugin requirements declared by the captured pair, including
unapplied generator/output selections and explicit entries in `plugins`. It has
no implicit manifest-renderer dependency. It can acquire missing official
plugins and capture explicitly trusted application-local builds.
It preserves both source images and makes no Store, KMS, provider credential
discovery or effect call. Selected plugins can run passive canonical validation.
Recovery options on this branch refuse; use only the existing form. Invalid, unreadable,
unsafe or pending files refuse. A confirmed missing companion requires the
explicit recovery inputs described below.

After complete loss of local ENKV files, supply new local choices and independent
cloud resource identifiers:

```sh
enkv prepare --source /absolute/restored.json --source-format json --name restored \
  --provider aws --bucket example-state-bucket --region ap-southeast-2 \
  --prefix production/app --normal-signing-key "$signing_key_arn" --json

enkv prepare --source /absolute/restored.yaml --source-format yaml --name restored \
  --provider gcp --bucket example-state-bucket --region australia-southeast1 \
  --prefix production/app --normal-signing-key "$signing_key_version" --json
```

Name, provider, bucket, region, explicitly supplied prefix and at least one
signing resource are required together. Signing resources are immutable exact
AWS KMS key ARNs or GCP CryptoKeyVersion resources. `--recovery-signing-key`
can supply an independently selected Recovery signer instead of, or together
with, the normal signer. The selected proof must have an adequate anchor.
Recovery is not a cloud account or a replacement for normal Authority decryption.
Reconstruction verifies every current secret through the current normal
Authority encryption key. Disabled Recovery requires no Recovery key lookup.

Optional equality pins are `--expected-domain` with a nonzero 64-character
lowercase hexadecimal DomainID, AWS-only `--expected-owner`, and
`--expected-authority-encryption-key`. Without an independent domain pin,
reconstruction authenticates the domain at the selected location and key; it
does not establish continuity with a previously known domain. Coherent Store
rollback is outside this guarantee. AWS uses the standard SDK credential chain,
including configured SSO; GCP uses ADC. These inputs create no ENKV account,
keys, IAM grants or remote state.

For complete-loss reconstruction, both destination files and coordination state
must be absent. Ordered native locks remain held through verification and local
delivery. Installation uses no-replace operations, satellite first, then editable
source. A concurrent creator is preserved, including identical foreign bytes.
The two files are not one atomic rename. The recovered pair retains a portable
public witness; later public reads qualify it locally without KMS lookup and
authenticate fresh state under their ordinary rules.

Recovered generator and output settings appear as nested `canonical.settings`.
The generated companion retains the exact complete records for those fields.
Keep the companion with its editable file. Recovery leaves local plugin
selections unset. Select trusted compatible plugins before dependent effects;
reconstruction itself does not require those plugins or apply newer defaults.

Preparation authenticates official signatures, exact installed bytes, native
platform and host compatibility. With no pin or selection, it selects the latest
compatible official stable release. Repeated preparation retains a valid
selection without a release-service call. `--upgrade` requests newer compatible
official releases for unpinned requirements; it never changes an exact pin.
Missing or incompatible effect plugins can leave `minimum_administrative_ready`
true while `all_declared_ready` is false. Readiness does not certify credentials,
IAM permissions or future execution. Preparation runs no installation hooks or
plugin version probes and grants no effect authority.

The editable file's optional `plugins` map holds local plugin IDs with `{}` or
an exact `version`. An ID need not belong to an official provider or format.
Project selection does not authorize a path, download or executable hook.
Trusted local overrides are held outside the project at
`os.UserConfigDir()/enkv/plugins.json`, keyed by the canonical directory of the
editable file. The next ordinary command that needs a local plugin captures a
complete rebuild without another preparation or approval prompt. Valid official
installations are reused offline; ordinary commands never download missing
official plugins. Follow the [installation guide](https://github.com/enkv-sh/extensions/blob/main/distribution/local-installation.md)
for the exact settings schema, selection rules and retained-build requirements.

`PrepareConfiguration(ctx, PrepareRequest)` uses the same complete-pair,
complete-loss and missing-companion rules and needs a finite context. Its optional
typed `PrepareRecoveryRequest` distinguishes
omitted fields from explicit empty or zero values. The opaque `PrepareResult`
retains immutable facts. `RenderPrepareJSON`, `RenderPrepareHuman` and
`PrepareExitCode` use those facts without retaining native handles or error text.

The closed `enkv/prepare-result/v2` reports invocation correlation, branch,
recovery, local delivery, dependency assessment, the complete `missing_inputs`
vector, outcome and safe diagnostics.
Dependency rows retain the source-order declaration subjects that need the same
plugin requirement. A missing selection reports `selection-required`; a
selected plugin whose installation is absent reports `not-installed`. These
checks establish plugin readiness, not domain equality, credential permission
or future provider success.
It contains no mutation receipt or replay identity. Recovery completion records
the exact accepted DomainID and signed HEAD digest. It does not claim that HEAD
remains current. Recorded local delivery retains both paths and verified digests
even if later cleanup or dependency checks fail.

Exit `0` requires complete preparation and successful presentation. Exit `2`
reports a known refusal or failure, missing supplied input, missing or
incompatible artifacts, cleanup failure without a confirmed remaining source
marker, or presentation failure.
Exit `3` reports pending or unknown delivery, unavailable required evidence,
contention, or a confirmed remaining recovery source. Exit `3` takes priority
over presentation failure. The result writer cannot include its own later write
failure in output already sent.

Keep any delivered pair after a dependency failure; the next invocation uses the
existing form. If `local_delivery.recovery_source` is present, run `enkv recover`
with that exact source and the original format. It completes only the saved local
candidate. Pending or unknown delivery can lack a confirmed recovery source;
retain the transaction files and inspect them without repeating reconstruction
automatically. A successful `recover` is followed by the existing `prepare` form.

## Restore a missing generated companion

If the editable YAML or JSON file survives, keep it at its current path. Supply
the complete recovery group and the independently known signing resource. Use
the name and Store settings already declared in that file. For example, a
surviving file whose local name is `prod` can use:

```sh
enkv prepare --source /absolute/configuration.yaml --source-format yaml --name prod \
  --provider aws --bucket example-state-bucket --region ap-southeast-2 \
  --prefix production/app --normal-signing-key "$signing_key_arn" --json
```

Prepare confirms that the declared companion is absent before it reconstructs
authenticated last-applied state. It installs only that companion at the declared
path. It preserves the editable file's bytes and native identity, including
comments, ordering and pending public edits. A changed source, a conflicting
domain/key/recipient identity, or an existing, unsafe or uncertain companion
refuses. A concurrently created companion is preserved even if its bytes match.
Pending local transactions require `recover` with their exact saved source.

ENKV-managed `recipients.<ref>.id` fields identify surviving recipient
declarations. Keep these fields through local-reference and display-name edits.
Preparation checks them against the authenticated current registry and checks
the selected keys; names and key-resource strings alone cannot recover identity.
Recovery does not apply the pending declaration or generate a value.

The domain has no copy of unapplied secret bytes. For an existing committed
supplied secret, recovery restores its last-applied input from authenticated
state. A never-applied supplied secret remains missing if its input existed only
in the lost companion. For a validated candidate, `missing_inputs` lists every
missing supplied-secret input in exact name order, with
`reason: supplied-input-missing` and `next_action: set`. The result
always includes this array, including `[]` when no missing input was recorded.
Read it with the recovery and delivery facts; an empty array before candidate
validation does not establish complete input.

Successful companion delivery can have `outcome: incomplete`, exit `2` and
`all_declared_ready: false` while inputs remain missing. Keep the delivered
companion. Human output lists every missing name and its next action. Fill each
listed entry through targeted `set`; for example:

```sh
enkv set --source /absolute/configuration.yaml --source-format yaml \
  --name API_TOKEN --json < /protected/new-api-token
enkv prepare --source /absolute/configuration.yaml --source-format yaml --json
```

Set fills its selected entry and preserves the other missing entries and every
valid present record. Repeat ordinary preparation to see the complete remaining
list. With the companion present, prepare checks the existing pair and does not
reconstruct again; omit recovery-only options. Plan, apply, read and materialize
require every supplied input to be present and valid. Complete preparation also
requires all declared plugin dependencies to be ready. After uncertain local
delivery, follow the reported recovery source before further edits.

## Initialize and edit configuration

Start init with an empty entry set, exact existing key selectors and an explicit
Recovery choice. It obtains validated public keys through one standard provider
credential context and stores them with the independent public descriptor. It
delivers and reads back the pair and the separate init manifest before private
qualification and create-only HEAD selection. Init creates no cloud keys or IAM.

```sh
enkv init --source /absolute/configuration.json --source-format json --json
enkv set --source /absolute/configuration.json --source-format json --name API_TOKEN --json < /protected/new-value
enkv apply --source /absolute/configuration.json --source-format json --json
enkv plan --trusted /absolute/configuration.json --trusted-format json --json
```

`set` consumes standard input once and prepares confidential input by default.
Use `--confidential=false` for a supplied plain value. Use `--base64` when the
input stream is canonical padded Base64. Set retains those exact input bytes
and records `source.encoding: base64`; it does not replace them with decoded
bytes. Without the flag, input is raw. An empty name is explicit `--name ''`.
The local operation uses the trusted public pair and makes no Store or KMS call.
Its result identifies the delivered pair and sealed artifact; it does not prove
that the domain is ready or that apply will accept the proposal. Keep confirmed
delivery paths after a failure. If `local_delivery.recovery_source` is present,
use `recover` with that source and the original format. Recovery completes the
saved candidate without reading the value again. An unknown result grants no
automatic retry.

`apply` interprets the complete declaration. It accepts plain, prepared
sealed-secret and exact retained-current secret input, including grants and
exclusions. A prepared new recipient and its declared memberships are selected
together. Editing only `display_name` changes stored display metadata; the next
identical apply is a no-op. Recipient omission does not retire a current identity.
Key replacement requires `keys replace`.

Apply creates and rotates generated values through each entry's selected
installed generator. Each plugin owns its settings and service behavior.
Unchanged canonical intent at the same epoch causes no create request, including
after selection of another compatible build. Apply selects the complete output
destinations, routes, entry output encodings and explicit groups with
the values and recipient memberships. It does not publish unless `--publish`
is present. Retained work can block a conflicting change;
its presence does not authorize another provider request. Apply uses normal Authority
capabilities, preserves enabled Recovery protection and requires no private
Recovery signing or decryption. Both source files remain unchanged for every
apply result. Equal complete input still receives required private validation
before a no-op result.

## Publish selected values

Configure outputs in the shared configuration pair.
Each target holds one entry. `outputs.routing.default` supplies a destination
list. `outputs.routing.entries` can replace that list for an exact entry name.
An omitted override inherits the default; an explicit empty list suppresses
publication for that entry. Routing is independent of recipient membership.
For example, `default: [primary]` sends inherited entries to `primary`, while
`entries: {LOCAL_ONLY: []}` excludes `LOCAL_ONLY`. Destination names refer to
`outputs.destinations`. A shared destination does not create an implicit group.
Each entry's `output_encoding` selects `raw` or `base64` for every destination
and for local materialization. The default is `raw`. ENKV converts only when
that setting differs from `source.encoding`; matching settings preserve exact
input bytes. Output-only edits take effect after apply and do not replace the
stored value or generate a new one. The provider payload limit is checked for
the complete selected group before any send. A 49,152-byte value fits a 65,536-byte
Base64 payload; 49,153 bytes exceeds that payload limit.

For the application value `ABC`, the four combinations are:

| `source.encoding` | Supplied bytes | `output_encoding` | Delivered bytes |
|---|---|---|---|
| `raw` | `ABC` | `raw` | `ABC` |
| `raw` | `ABC` | `base64` | `QUJD` |
| `base64` | `QUJD` | `raw` | `ABC` |
| `base64` | `QUJD` | `base64` | `QUJD` |

The table applies to publication and local materialization. A pending local
encoding edit has no effect on either operation until apply selects it.

```sh
enkv apply --source /absolute/configuration.yaml --source-format yaml --publish --json
enkv publish --source /absolute/configuration.yaml --source-format yaml --name API_TOKEN --json
enkv plan --trusted /absolute/configuration.yaml --trusted-format yaml --publish --json
```

`apply --publish` first completes apply, then evaluates every applicable selected
write and required retained deletion under Authority. An unchanged apply still
evaluates unfinished publication. Both operations share the original command
deadline. Failed or incomplete apply does not start publication, even when its
canonical change was selected before later work failed. The combined response
keeps both stages and the original apply receipt. It does not roll back apply
when publication fails.

Standalone `publish` requires explicit names or retained deletion coordinates.
Repeat `--name`; an empty name is `--name ''`. Select every member of an explicit
group. The source pair supplies trusted domain and runtime construction, while
authenticated selected state supplies the values, routes and targets. Pending
source edits do not change what standalone publication sends.

`plan --publish` shows proposed actions, conditional secret or future generated
values, retained deletion coordinates and unresolved Attempt IDs. It uses the
same fixed observation as the declaration comparison. Public mode needs no KMS
access or output credentials. Private equality checks keep their existing
explicit access requirements and do not grant publication authority.

Use exact lowercase hexadecimal IDs from that result:

```sh
enkv publish --source /absolute/configuration.yaml --source-format yaml --delete-coordinate "$coordinate_id=$output_plugin" --json
enkv publish --source /absolute/configuration.yaml --source-format yaml --name API_TOKEN --republish-after-unknown "$attempt_id" --json
```

Each `--delete-coordinate` value is `coordinate-id=local-plugin-id`. The
explicit plugin choice is checked against the retained semantic target before a
new deletion Attempt; the coordinate alone does not choose an executor.

Repeat `--republish-after-unknown` for the complete current blocker set of each
selected coordinate. This permits new Attempts; it does not retry or close the
old ones. Old unknown effects and late-write warnings remain visible. Deletion
uses retained target and birth facts, including after source removal. A provider
acknowledgement reports that request's accepted result; it does not prove current
remote contents, permanent absence or exclusive ownership.

Select trusted installed output plugins through
[preparation or a trusted local override](https://github.com/enkv-sh/extensions/blob/main/distribution/local-installation.md).
Private local services use the same family interface as official AWS Secrets
Manager, GCP Secret Manager and GitHub Actions outputs. The host checks the
family contract, captured build facts and exact bytes. The plugin interprets
its service target, policy and credentials. Official AWS uses the standard SDK
credential chain; official GCP uses Application Default Credentials. The
GitHub plugin uses only `GITHUB_TOKEN`, supplied by the operator's credential
manager, with no `GH_TOKEN` or token-file fallback.
No-op publication captures no output credentials and starts no output child.

The operator must keep managed names exclusive to this workflow. enkv does not
reserve a namespace or prove that another writer is absent. For GCP, do not
delete and recreate a managed secret outside enkv or give its name to another
secret while enkv manages it or earlier operations can still affect it. Binding
removal, deletion acknowledgement and local evidence discard do not prove that
reuse is safe. ENKV cannot enforce exclusive use of these names.
GitHub upsert acknowledgement does
not adopt a pre-existing secret or establish its creator.

Grant the output principal permissions for its selected service, independently
of the AWS or GCP domain cell:

| Service | Required output permissions |
|---|---|
| AWS Secrets Manager | `secretsmanager:CreateSecret`, `secretsmanager:PutSecretValue`, `secretsmanager:DeleteSecret`. See [create](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html), [write](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_PutSecretValue.html) and [delete](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html). |
| GCP Secret Manager | `secretmanager.secrets.create`, `secretmanager.versions.add`, `secretmanager.secrets.get`, `secretmanager.secrets.delete`, with the `cloud-platform` OAuth scope. Deletion reads the current ETag first. See [IAM permissions](https://docs.cloud.google.com/secret-manager/docs/access-control). |
| GitHub repository or organization | Secrets read/write access at the selected repository or organization, including its public-key endpoint. |
| GitHub environment | Environments read/write access at the selected repository. |

GitHub token type and repository access must also satisfy the selected
[Actions Secrets endpoint](https://docs.github.com/en/rest/actions/secrets?apiVersion=2026-03-10).
Permission setup is external to these commands; publication creates no IAM roles
or cloud keys.

Library callers use `PublishConfiguration` with a captured pair and an exact
`core.PublicationRequest`, or `PublishConfigurationFile` with a source path.
`ApplyConfigurationAndPublish` and `ContinueConfigurationApplyAndPublish`
return `core.PublicApplyPublicationResult`; their `File` forms capture and close
the pair. Supply distinct nonzero apply and publication request IDs and one
finite context. `WriteApplyPublicationJSON` and `WriteApplyPublicationHuman`
write both validated stages without a second concatenated response buffer.
JSON library output has no final line feed; the CLI adds one.

For a passive publication projection, pass
`contract.ComparisonOptions{Publish: true}` to public comparison, or set
`Publish: true` in `contract.PlanningOptions` for private planning. The projection
does not authorize a later publication request.

## Generated values

Generated values use a trusted installed generator selected by the entry's
local `plugin` ID. The generator owns settings, defaults and canonical intent.
It can be an unpublished local implementation or a modified official plugin;
adding behavior within the family contract requires no ENKV rebuild. See the
[generator SDK](https://github.com/enkv-sh/extensions/blob/main/sdk/generator/README.md),
[independent managed-token example](https://github.com/enkv-sh/extensions/blob/main/sdk/examples/local-token-generator/README.md)
and [installation guide](https://github.com/enkv-sh/extensions/blob/main/distribution/local-installation.md).

A command captures immutable build bytes. An accepted Duty/Attempt resolves its
original exact build and credential route independently of new-work selection.
A new retirement Duty can use a currently selected compatible implementation
for the original resource's contract, target and data; that choice is then fixed.
Changing a build or credential recipe alone does not change semantic intent.
Changed canonical intent at the same epoch refuses; advance the epoch for a
new generation.

AWS or GCP credentials supply the domain's Store and Authority access. Effect
credentials belong to the selected generator. For example, the official
Cloudflare plugin reads `CLOUDFLARE_API_TOKEN`; export it through your credential
manager before an effect command. Other plugins declare their own environment
inputs or use their service SDK's normal credential discovery. Public source
contains no credential value. A later invocation can capture a rotated token
through the retained route without changing its admitted target.

Add a generated entry to the editable declaration. Use the actual account and
permission-group IDs in the Cloudflare plugin settings:

```yaml
entries:
  API_TOKEN:
    confidentiality: secret
    recipients: []
    source:
      kind: generated
      plugin: cloudflare-account-token
      epoch: 0
      retirement: manual
      settings:
        account: '<32-lowercase-hex-account-id>'
        name: application-token
        policies:
          - effect: allow
            permission_groups: ['<32-lowercase-hex-permission-group-id>']
            resources:
              - kind: account
                id: '<32-lowercase-hex-account-id>'
```

The Authority is included in access. Declare other recipients explicitly. A new
entry starts at epoch zero. Edit the epoch to request rotation, then run apply.
Review the proposed intent first:

```sh
enkv plan --trusted /absolute/configuration.yaml --trusted-format yaml --json
enkv apply --source /absolute/configuration.yaml --source-format yaml --json
enkv generated list --source /absolute/configuration.yaml --source-format yaml --json
```

Plan reports generated creation, rotation, source changes and retirement
consequences. Future generated content is unavailable. It needs no effect
credentials. Ordinary settings can start a passive plugin validation child;
canonical input with an unset local selection can be compared without that
plugin. `--show-secret` supports supplied secrets only.

For a managed-resource generator, selecting a successor under `manual` policy
leaves an exact retirement Duty for the old resource. With `auto`, apply selects
the successor before it attempts retirement. A retirement failure cannot restore the old value as current.
Changing a generated entry to supplied input, or removing the entry, also retains
the required old-resource work. An old Duty keeps its original target and
resource even when the editable declaration changes. A generator with lifecycle
mode `none` has no external resource to retire.

When replacement or removal no longer selects a generator for the old entry,
choose the plugin for the NEW retirement Duty explicitly:

```sh
enkv apply --source /absolute/configuration.yaml --source-format yaml \
  --retire-generator "API_TOKEN=$generator_plugin" --json
```

Repeat the flag for each affected entry. It does not replace the original
support of an already accepted Duty, and cannot be combined with `--operation`.

Use the exact IDs from a bounded generated list or mutation result:

```sh
enkv apply --source /absolute/configuration.yaml --source-format yaml --operation "$operation_id" --json
enkv generated retire --source /absolute/configuration.yaml --source-format yaml --duty "$duty_id" --json
enkv generated retire --source /absolute/configuration.yaml --source-format yaml --operation "$operation_id" --json
enkv generated accept-retirement-risk --source /absolute/configuration.yaml --source-format yaml --duty "$duty_id" --attempt "$attempt_id" --json
enkv generated cleanup --source /absolute/configuration.yaml --source-format yaml --json
enkv generated cleanup --source /absolute/configuration.yaml --source-format yaml --operation "$operation_id" --json
enkv generated cleanup --source /absolute/configuration.yaml --source-format yaml --inbox "$inbox_id" --json
```

Retirement accepts exactly one of `--duty` or `--operation`. Risk acceptance
requires both `--duty` and `--attempt`; the explicit command records the decision
without another prompt. It sends no provider request and retains the exact
possible-live resource as a Hazard. Cleanup first reflects eligible original
results in Product order, then selects exact owned residue. With `--inbox`,
cleanup checks only the named temporary result inbox. Get its ID from `inspect`
after a command leaves a pending or unknown release. The command reads the
exact Store object and releases the selected mapping after confirmed absence
or acknowledged conditional deletion. If the outcome remains unknown, inspect
the current state before another attempt. `--inbox` and `--operation` are
mutually exclusive. Cleanup and list have no terminal receipt or
complete-history contract.

After restart or loss of a response, use `generated list` to discover selected
current generations and exact operations, Attempts, Duties and Hazards. List
uses bucket GETs and public verification. It needs no signer, private key route,
generator credential or process. Listed actions still require fresh
admission. Continuation uses accepted intent and exact targets from selected
state; pending local declaration edits do not replace that work. Missing evidence
does not permit another first send. A retained receipt is observation only.

Inspect state, effect, warnings and remaining work separately. The official
Cloudflare plugin reports `deletion-acknowledged`; invalidation is not confirmed. A successful frontier can
coexist with older possible-live residue. After an interrupted standalone retirement, use `generated list`. If ENKV saved
the original Unknown, the list can offer risk acceptance for that exact Duty and
Attempt. Accepting releases the owner, retains the possible-live warning and
sends no further DELETE. If neither record reached the Store, the owner can end
the work through the administrative command. Ending administrative work
does not prove provider cleanup.

Library callers use `ApplyConfiguration` or `ApplyConfigurationFile`, the
`ContinueConfigurationApply` family, and the `ListConfigurationGenerated`,
`RetireConfigurationGenerated`, `AcceptConfigurationGeneratedRetirementRisk` and
`CleanupConfigurationGenerated` families. Pass a finite context and a fresh
request ID. Close each captured Pair after its synchronous operation returns.
Results own their returned safe facts; generated secrets do not enter them.

## Planning and credentials

`plan` uses a deliberately trusted complete pair and bucket object-read
permission. By default, it performs keyed GETs and public verification without
KMS, LIST or writes, even when private credentials are available. To review a
candidate, add `--candidate /absolute/candidate.yaml --candidate-format yaml`.
The trusted pair alone supplies trust, Store construction and credentials.
Both inputs receive complete public validation before Store credential
construction. Ordinary plugin settings use the selected trusted plugin's passive
normalization; authenticated canonical settings do not require unrelated effect
plugins. An omitted candidate selects the trusted pair's declaration.

Add `--check-secrets` to authenticate every proposed supplied secret and compare
it with the same fixed observation used for public differences. This requires
the exact current Authority decrypt route; it does not try Recovery or Recipient
keys. Results distinguish `equal`, `changed`, `new`, `unchecked` and `failed`.
Retained input must name the exact current incarnation and material. Secret
content equality remains separate from membership and source changes. Generated,
publication and output changes remain outside this private comparison scope.

```sh
enkv plan --trusted /absolute/configuration.json --trusted-format json --candidate /absolute/candidate.yaml --candidate-format yaml --check-secrets --json
enkv plan --trusted /absolute/configuration.json --trusted-format json --check-secrets --show-secret API_TOKEN --json
```

Repeat `--show-secret NAME` for each exact proposed supplied-secret name to
show. It requires `--check-secrets`; duplicate, missing, plain and generated
selections refuse. Use `--show-secret ''` for an explicit empty name. Sealed
proposals and exact retained-current supplied values can be shown. All required
public and private checks finish before the first display record. An invalid
unselected supplied input therefore prevents disclosure of selected values too.

Human display identifies each name, input form and byte length, followed by
quoted reversible bytes. Controls and non-ASCII bytes use `\xNN` escapes.
Structured display is NDJSON: each `secret-display` record contains exact name,
`input_form`, `byte_length` and padded `value_base64`. A final `plan-result`
record contains the ordinary safe result. Without display, `--json` returns one
safe JSON result. Secret bytes do not enter ordinary results or telemetry.

Display streams one value at a time. A short write, cancellation, finalization
failure or later private failure stops it without replay. Already delivered
bytes cannot be recalled. An interrupted stream reports incomplete delivery;
a missing complete terminal result proves no pass. Planning preserves both
source pairs and performs no signing, Store write or provider effect.

Exit 0 means complete match within the stated scope; 1 means a complete verified
difference; 3 means unavailable evidence or contention; 2 means refusal,
integrity or output failure. Incomplete checks take precedence over a known
difference. A public match does not prove secret equality. No plan result proves
apply admission or future currentness; a later apply checks fresh state.

A new machine needs the complete trusted pair and its own GET-only credential
context. It does not need the original cache or a separate trust file. The init
manifest is needed for exact same-init observation, not ordinary public comparison.
A same-init retry can observe an already selected exact init; it does not resume
unfinished pre-HEAD work. Keep all delivered paths after an uncertain init result.

Local production credentials use the AWS SDK standard chain, including SSO, or
GCP Application Default Credentials. There is no required ENKV credential file or
profile flag. Provider login/configuration remains external; a GCP user context
needs ADC setup, not only a general gcloud login. A credential source grants no
ENKV role. See the [AWS](../../providers/aws/README.md) and
[GCP](../../providers/gcp/README.md) construction limits.

Init, confidential set and apply use `ProductResult/v1` with their distinct
payloads. Confidential set uses `operation_kind: set-confidential` and carries
local delivery separately from domain state. A later cleanup failure preserves
confirmed delivery facts but returns a failing exit status. Plan returns
match, mismatch or unable-to-verify results. Always inspect the operation's
`state_result`, diagnostics and local delivery or observation fields.

## Prepare local configuration

Local commands use the source and format defaults above and require each
action's selection. They use the shared pair transaction and preserve
unchanged encrypted records. They return `LocalEditResult/v1`; `--json` selects
structured output. Duplicate flags, positional arguments and unknown flags
refuse before editing.

```sh
enkv rename --source /absolute/configuration.yaml --source-format yaml --name production --json
enkv recipients add --source /absolute/configuration.yaml --source-format yaml --recipient service --mode create --display-name 'Service' --encryption-key "$recipient_key" --json
enkv recipients add --source /absolute/configuration.yaml --source-format yaml --recipient service --mode current --json
enkv recipients rename --source /absolute/configuration.yaml --source-format yaml --recipient service --new-reference worker --json
enkv recover --source /absolute/configuration.yaml --source-format yaml --json
```

`rename` changes `domain.name`, the satellite path and the editable reference
together. It keeps the editable filename and domain identity. The name must
match `[a-z0-9][a-z0-9_-]{0,63}`. An occupied or aliased destination refuses.
Update external references to the old satellite path. To change only the
editable filename, move that file within its directory during an exclusive
manual-editing window.

Recipient selection uses `--recipient <configured-reference>` for a local alias
and `--recipient-id <ID>` for an exact nonzero 64-character lowercase hexadecimal
ID. The flags are mutually exclusive. An unknown alias refuses; it is not
interpreted as an ID, even when it has hexadecimal spelling. Alias selection
uses the ENKV-managed ID in the captured source pair. Display names, cloud keys
and credentials do not identify a recipient.

`recipients add` prepares public data locally. `--mode create` requires the
selected recipient identity to be absent from current state and derives a fresh
identity from the authenticated predecessor and a fresh nonce. For a new local
reference, supply both `--display-name` and `--encryption-key`; an explicit empty
display name is valid. For an existing declaration, omit both flags. `--mode
current` requires that declaration's exact current RecipientID and key selector;
it refreshes public data from that binding. Neither a display name nor a reused
key resource identifies a recipient. `--mode` is required. Create mode requires
an alias and rejects `--recipient-id`. Current mode can instead select an
existing local declaration with `--recipient-id`. Rename, retirement and
recipient-key replacement also accept that exact-ID alternative and continue
to require an explicit target. Stale absent preparation needs explicit
fresh creation. Preparation preserves existing sealed records and their original
binding context. A key change can make a sealed proposal unusable. Prepare the
current public binding and use confidential `set` again when required; planning
does not repair the original input.

An intended recipient can prepare as Proposer with local write permission,
authenticated bucket reads and exact public-key/metadata lookup. Preparation
does not sign, decrypt, write to the Store or grant membership. Authority apply
independently qualifies each new key with its own public-read permissions and
owns domain admission. `recipients rename` changes the local reference in both
files and entry memberships. It preserves RecipientID, public
bindings, display name and encrypted records. Edit `display_name` directly when
only display metadata must change.

Edit a generated entry's `epoch` directly in the declaration. An edit alone
does not run a generator. Run `apply` to create the value or rotate it to the
requested epoch. Unchanged canonical intent at the same epoch requests no new
generation; changed intent at the same epoch refuses. Apply retains any required
retirement work and follows the selected retirement policy. Publication requires
`publish` or `apply --publish`; see [Generated values](#generated-values) for
retirement and continuation commands.

When `local_delivery.recovery_source` is present, `recover` uses that exact
source and the original format to complete the saved candidate. It checks the
recorded old/new file states and refuses foreign edits. It does not read new
plaintext or derive a new candidate. Exit 0 means confirmed delivery and
complete cleanup; exit 2 means refusal, cleanup failure or output failure;
exit 3 means pending or uncertain delivery. Confirmed readback can coexist with
pending cleanup. Retain those facts and the saved transaction after a failure.

## Remove readers, re-key or retire a recipient

To remove a reader, edit the entry's recipient list and use `apply`. A valid
original sealed input can remain unchanged when the current and proposed entries
are supplied secrets, the desired recipients are a subset of the current set,
and private authentication proves the proposed bytes equal the current value.
An identical repeat apply performs those checks again and can return no-op.
A different pending value, unusable seal, absent entry, source conversion or
addition under the mismatched seal cannot use this rule. Prepare a fresh input
for those changes. Exact retained-current input remains supported.

Apply refreshes protection when access changes while preserving the value and
required retained access. It cannot revoke information already obtained.
Recipient-list omission removes access; it does not permanently retire an identity.

```sh
enkv rekey --source /absolute/configuration.yaml --source-format yaml --name API_TOKEN --out /absolute/rekeyed/configuration.yaml --json
enkv recipients retire --source /absolute/configuration.yaml --source-format yaml --recipient worker --out /absolute/retired/configuration.yaml --json
```

Both commands require a separate `--out` pair. Create its directory first. The
output keeps the source format and logical domain name, so use a different
application directory to avoid aliasing the source satellite. Source and output
must not alias through either member. An existing unrelated, malformed or pending
output refuses before private construction. There is no overwrite option.

Re-key preserves current plaintext and recipients while creating fresh data
and commitment keys, ciphertext and wraps. For a generated secret, it preserves
the provider resource and original generation evidence without calling the
generator. Each freshly admitted operation creates new protected material;
repeating an exact command with its delivered output only observes that operation.

Retirement permanently removes one exact current ordinary recipient and all its
current memberships, including plain entries, in one selection. Each affected
secret receives fresh protection. An unassigned recipient is a valid target;
Authority is not. Required retained-reader routes block retirement until their
existing work closes. The refusal reports `recipient_retirement_blockers` with
the complete count and at most 64 ordered material/owner rows. It does not
remove a row or prove remote cleanup. Re-enrollment requires `recipients add
--mode create` and a fresh identity, even with the same display name and key.

The commands change authenticated current state without applying pending
declarations. They preserve both source files. Their separate successor pair
preserves unrelated pending content, comments, epochs, outputs and sealed
records. Retirement removes the retired live row and memberships from that pair
while preserving historical enrollment evidence. Both
commands update only retained pins that exactly match material changed by their
own candidate. They do not reseal inputs or replace a pending value with current
content. Rekey can preserve valid pending different content.

Stale retained pins, pending absent-recipient creation and proposals that need
resealing can prevent a usable successor. Such cases refuse before mutation
custody. When retirement needs to prove guarded sealed-input reuse, a separate
read-only private check must complete and close before mutation construction.
A required retained-reader blocker still prevents retirement.

The command prepares its exact candidate, delivers and synchronizes the new
pair, then reopens and verifies its bytes and meaning before one conditional
HEAD change. A local delivery failure prevents that change. Successful delivery
can still precede contention or an unknown selection reply. Read successor
delivery, canonical mutation outcome and current source usability as separate
facts; delivery alone does not prove domain success.

Keep both output members after an uncertain result. Repeat the exact original
command, including its source, target and output paths, to observe the stored
operation with GET-only reads. This path constructs no signer or decryptor,
allocates no mutation identity and sends no write. It cannot rebase, overwrite
or repeat retirement/rekey. A retained receipt can prove the original result
after HEAD advances; currentness and source usability have separate checks.
Missing or evicted evidence grants no permission to repeat the mutation.

Adopt a confirmed usable successor explicitly for later commands. Its usability
covers the checked current source relations, not every condition of future
apply or private IAM access. A later apply still interprets the complete pending
declaration and performs fresh admission. Metadata in an ordinary source is
inert; only the explicitly named output anchors this observation workflow.

Library callers use `RekeyConfigurationEnvelope` or
`RetireConfigurationRecipient` with a captured source and a mandatory fresh
`configuration.MaintenanceOutput`. Their `File` variants take the separate
output path and select existing-output observation when applicable. Use a finite
context and keep a borrowed pair open until return. File commands return
`MaintenanceCommandResult`; its domain result, delivery and observation facts
remain separate. Human and JSON renderers preserve those same facts.

## Abandon selected work

These commands use the installed `--source` pair and its independent public
basis. They do not infer trust from stored HEAD alone. Relative paths are
resolved once when the command starts. Keep the files and their directories
under the operator's control. Source and dependency files are checked for
identity, metadata and exact bytes. The `.enkv` directory is checked for identity,
owner and permissions. Symlink files or `.enkv` directories refuse. A
configuration file or credential does not grant an ENKV role. There is no connection file, separate basis file or caller grant to
create for these commands.

```sh
enkv abandon list --source /absolute/configuration.json --source-format json --json
enkv abandon plan --source /absolute/configuration.json --source-format json --target "$group_id" --out /protected/abandon-plan.json --json
enkv abandon apply --source /absolute/configuration.json --source-format json --plan /protected/abandon-plan.json --json
enkv abandon list --source /absolute/configuration.json --source-format json --json
enkv abandon receipt --source /absolute/configuration.json --source-format json --operation "$operation_id" --json
```

Choose the exact `GroupID` from `list`. IDs use 64 lowercase hexadecimal
characters. The list separates current targets from retained completed
abandonments. Group, duty, owner, resource and abandonment operation IDs have
different meanings. An active child can require its parent as the legal target.

`list`, `plan` and `receipt` use one freshly authenticated selected image. They
need bucket object-read permissions only. They construct no signer and make no
KMS, LIST, effect-provider or Store-write request. Missing disposable work bodies
do not force effect-provider access; missing mandatory receipt or index evidence
prevents a successful read.

`plan` writes a new protected artifact and reports its digest, exact readback and
local delivery. Its output directory and all ancestor directories must be owned
by root or the current user, without group or other write permission. It shows
the complete ordered scope, preserved current state,
original evidence, warning changes, risks and before/after page and byte counts.
Review that complete result before `apply`. Planning makes no remote mutation.

`apply` needs current Authority signing and Store-write permissions. Recovery
cannot authorize it. It checks the source, complete disposition and exact
predecessor again, then attempts one HEAD CAS. A changed predecessor or altered
plan requires a new reviewed plan; the command does not rebase or replace the
target. Preserve an uncertain plan and result rather than treating an uncertain
reply as permission to send again.

A selected abandonment ends local work rights and releases the receipted
exclusive capacity. It preserves current values, access and required shared
support. It does not cancel an old process or remote request, prove deletion or
completion, or grant a new effect send.

After later ordinary progress, use `list` to find a retained abandonment's
operation ID, then use `receipt`. The fresh read reports its current observation
separately from the receipt's original `work-ended` state and historical warning
summary. The original receipt bytes remain unchanged. Lookup needs no original
caller identity. The independent windows retain at most 256 successes and 256
failures and evict the oldest entry in each window on append. Missing targets or
missing/evicted receipts prove neither historical success nor failure. Current
permanent warnings remain after receipt eviction.

## Replace existing keys

`keys replace` uses exact existing AWS key ARNs or GCP key-version resources.
The provider resolves and validates their public metadata. The command accepts
no operator-supplied PEM, public-key bytes or fingerprint. It creates no cloud
key, role or IAM policy. Ordinary `apply` does not replace keys.

Every form requires a separate `--out` and uses the source and format defaults
above. An explicit `--source-format yaml|json` selects the parser; it does not
fall back to the filename suffix on failure. `--json` selects structured
output. Bare `keys` or `abandon` prints help without opening files or cloud
clients; incomplete executable subcommands refuse.

| Target | Required selection | Optional selection |
|---|---|---|
| `--target authority` | `--authorizer authority\|recovery`; `--signing <key>`, `--encryption <key>`, or both | `--decrypt-with authority\|recovery` when encryption is nominated |
| `--target recovery` | The same authorizer and key selections; Recovery must be enabled | `--decrypt-with authority\|recovery` when encryption is nominated |
| `--target recipient` | `--recipient <configured-reference>` or `--recipient-id <ID>`; `--encryption <key>` | Explicit `--authorizer authority` |

For a role target, the named current authorizer signs the transition. When
replacing encryption, `--decrypt-with` fixes the surviving current material
route before private work. Its default is the named authorizer's route. It is
invalid for signing-only requests. Credentials, signing authority and material
access are separate: failure does not select another route. Disabled Recovery
cannot be a target, authorizer or material source.

Recipient replacement fixes both authorizer and material source to Authority.
It selects an existing local declaration by alias or exact ID and preserves
RecipientID and membership. `--signing`, `--decrypt-with` and Recovery
authorization are invalid for this target; both recipient flags are invalid
for role targets. Neither old nor successor Recipient private access is
required. Role signing-only replacement
also needs no private decryption.

For example, use surviving Recovery signing to replace the Authority signer:

```sh
enkv keys replace --source /absolute/configuration.json --source-format json --target authority --authorizer recovery --signing "$successor_signing_key" --out /absolute/successor/configuration.json --json
```

To replace both Authority keys while choosing a different surviving material
route, specify both selectors and that route explicitly:

```sh
enkv keys replace --source /absolute/configuration.json --source-format json --target authority --authorizer authority --signing "$successor_signing_key" --encryption "$successor_encryption_key" --decrypt-with recovery --out /absolute/next-authority/configuration.json --json
```

To replace an existing ordinary Recipient binding:

```sh
enkv keys replace --source /absolute/configuration.json --source-format json --target recipient --recipient "$recipient_reference" --encryption "$successor_encryption_key" --out /absolute/next-recipient/configuration.json --json
```

Each transition changes only its nominated role pair or Recipient binding and
preserves current values, material coverage, retained work and Recovery mode.
Authority signer replacement changes the normal signing bindings together.
It can use surviving Recovery while the old Normal signing route is unavailable.
A declared encryption change needs the fixed eligible material route and
successor qualification; it does not probe a lost private route as a fallback.

`--out` creates a new editable/generated pair in the source's resolved format.
Create a separate output directory before running the command. The successor
keeps the local name and uses its own satellite in that directory. An output in
the source directory with the same local name aliases the source satellite and
refuses before private work or selection.
It preserves DomainID, FileID, RecipientIDs, logical configuration, unrelated
editable bytes and external sealed proposals byte-for-byte. The input pair stays
unchanged. The command copies these proposals without decrypting, resealing or removing
them. A proposal bound to a replaced key may need a new `set` before later
`apply`; that does not remove preserved selected material.

The command publishes both members without replacement, synchronizes them and
the directory, reparses and reads back the exact bytes, then independently
qualifies the successor basis against the exact candidate before CAS. An
unrelated existing output, partial publication or failed sync/readback refuses
selection. There is no overwrite flag. Recheck source/dependency and predecessor
pins before the one CAS with its original condition. A delivered pair alone does
not prove that its candidate selected.

Only complete current Authority binding equality can return `no-op`, after
current-state/current-authority authentication and before new replacement IDs,
private probes or writes. It creates no output pair or receipt. Partial equality
preserves the equal binding identities. Recovery and Recipient replacement have
their own fresh identity/progression rules and do not return this no-op. Changed
Authority replacement has no stored mutation receipt; Recovery and Recipient
replacement retain their distinct typed receipts.

Keep both output members after an uncertain result. Repeat the exact command
with its original source, request and output paths to observe it. Protected
output metadata selects GET-only observation before private clients are
constructed; an unrelated output is an error. Repetition cannot CAS again,
rebase, allocate a new mutation identity or reconstruct private capabilities.

For Authority output, the read reports successor-source usability and exact
candidate currentness separately. Ordinary later progress can preserve source
usability after that exact candidate is no longer current. This proves no
historical CAS attribution, private IAM availability or future currentness.
For Recovery or Recipient output, the read returns the original retained typed
receipt bytes and stored state; current selection is separate. Missing receipts
do not prove an earlier operation absent. Queries grant no mutation replay.
Use a usable delivered pair as a later `--source` and a new output path for the
next replacement. Old operation metadata in a source is inert history.

On macOS, file and directory sync, publication without replacement, exact
readback and refusal before CAS remain required. Persistence of the final local
successor name across abrupt power loss is not qualified. Power loss after
remote selection can leave that name unavailable and require restoration of
trusted successor information before ordinary restart. Successful readback does
not prove power-loss durability; no stronger post-name flush is supplied.

## Command results and common limits

Ordinary JSON results use two-space indentation and multiline nonempty
collections. Explicit secret display keeps its NDJSON stream. Keep the safe
result after an output failure; presentation does not change operation facts.
Omit `--json` for command-specific human summaries. Maintenance and key
replacement report the operation outcome, successor delivery, current source
relation, warnings and required local recovery separately. Use JSON for the
complete safe machine record.

`--json` returns `ProductResult/v1` for one operation. Combined `apply --publish`,
including `--operation` continuation, returns `ApplyPublicationResult/v1` with
the complete `apply` result and a `publication` stage. An `evaluated` stage
contains its complete `ProductResult/v1` result. An `unstarted` stage contains a
reason and `result: null`. Human output preserves both stages and the same state,
identity, warnings and delivery facts. For each operation result, read
`operation_kind`, `state_result`, `operation_payload`, evidence, diagnostics and
local delivery.
A selected abandonment reports `work-ended`. A later receipt read reports a
fresh read state separately from its original stored state. Complete Authority
equality reports an authenticated `no-op` observation without mutation replay.
Existing-output observations use `keys-replace-observe` for Authority and
`keys-replace-receipt` for Recovery or Recipient.

`evidence_ceiling: canonical` describes authenticated selected evidence, not
remote completion or physical cleanup. Read operations return no mutation
replay identity. Changed replacement and abandonment results retain only their
exact operation's replay limits; a replay identity does not permit a second CAS,
a rebase or another effect send. An unavailable read cannot establish absence.

Commands have a five-minute deadline. Exit code `0` means the operation succeeded
or returned its admitted no-op; `3` reports unavailable evidence, contention or
an unresolved commit; `2` reports input, admission, integrity or output failure.
A local cleanup or delivery failure can return a failing exit status while
preserving a known remote selection. Read `commit_may_have_occurred` with its
outcome and reason. Diagnostic or telemetry delivery failure changes an otherwise
successful exit to `2`, preserving existing nonzero operation exits and the
result bytes on stdout. Invalid fields of a recognized command keep that operation's
structured refusal with `--json`.

Complete-loss and missing-companion preparation use independent recovery inputs.
Offline tests use controlled transports and
fresh processes; they do not qualify a live provider deployment. Live execution
requires separately authorized infrastructure and test inputs described in the
[test reference](../../tests/README.md).

## Public inspection and retained receipts

Capacity inspection uses a separate bounded reader:

```sh
enkv inspect --source /absolute/configuration.yaml --source-format yaml --capacity --json
enkv inspect --source /absolute/configuration.yaml --source-format yaml --capacity --cursor "$cursor" --json
```

`--capacity` is mutually exclusive with either recipient flag. `--cursor` requires
`--capacity`. The scoped cursor is opaque and grants no mutation permission.
The configuration API checks its complete scope before default credential
construction. Ordinary inspection keeps its GET-only reader. Capacity inspection
adds one bounded LIST page and public exact reads; it installs no KMS or effect
route. The page is not a Store snapshot.

`CapacityPayload/v1` reports actual counts and encoded byte margins, selected
continuation and first-exit bounds with their exact basis, pending GC obligations,
and every candidate classification in the observed page. A bound that is not
established is distinct from measured exhaustion. These fields do not report a
general free-capacity number or admit fresh operations.

Library callers use `InspectConfigurationCapacity` with a typed
`core.CapacityInspectionRequest` and a captured pair, or
`InspectConfigurationCapacityFile` with the request, source path and explicit
format. `NewCapacityReader` and `NewDefaultCapacityReader` install this separate
surface. `WriteCapacityInspectionJSON/Human` validates the owned result before
output and preserves cancellation, short-write and writer failures.

`PlanConfigurationGC` and its `File` variant take a `GCPlanRequest` with fresh
request and operation IDs, an optional cursor and an absolute artifact path.
They write the exact canonical plan bytes, bounded by
`contract.GCPlanMaxLength` (105,413 bytes), into an absent protected file. Complete
delivery requires file sync, directory sync and exact bounded readback. Existing
files and source/satellite aliases are refused. Failure can leave a protected
partial file for inspection. `GCPlanResult.Delivery` remains separate from the
public preview result; `WriteGCPlanJSON/Human` renders both. A plan file is a
preview and grants no selected delete permission.

The GC command forms are:

```sh
enkv gc plan --source /absolute/configuration.yaml --source-format yaml --out /protected/plan.bin --json
enkv gc apply --source /absolute/configuration.yaml --source-format yaml --plan /protected/plan.bin --json
enkv gc apply --source /absolute/configuration.yaml --source-format yaml --operation "$operation_id" --json
```

The plan and operation inputs are mutually exclusive. Fresh apply checks the
protected artifact and its source scope before credentials. Core then owns one
fresh target preflight and exact predecessor check before the lazy Store and
Normal Trust factory can run. An empty plan is an equal-HEAD no-op and constructs
no mutation resources. Continuation authenticates the named selected obligation;
missing ownership does not establish historical success. Neither apply form
lists again or rebases a stale plan.

`ApplyConfigurationGC` and `ApplyConfigurationGCFile` take a typed
`GCApplyRequest`. The captured Pair stays open through the joined Core operation.
Core closes its mutation resources and reader before the File variant closes the
Pair. Local cleanup failure remains separate from the owned operation result.
`WriteGCApplyJSON` retains Core's state, effect and evidence axes, complete
target/candidate/failure vectors, selected counters and invocation observations.
Its sibling commitment covers the token-free result facts; the original target
descriptor is a separate opaque plan commitment. Provider conditions remain in
the protected plan and are excluded from the public result. Nested Core and
write result enums are numeric; their complete IDs, evidence and uncertainty
flags are preserved. `WriteGCApplyHuman` reports the operation outcome, deletion
counts, selected target status, phase failures and required continuation. Both
forms use finite two-pass output accounts, separate from the binary sibling
preimage limit, and propagate output failure.

Use a complete trusted configuration pair. Specify the source format explicitly:

```sh
enkv inspect --source /absolute/configuration.yaml --source-format yaml --json
enkv inspect --source /absolute/configuration.yaml --source-format yaml --recipient service --json
enkv receipt --source /absolute/configuration.yaml --source-format yaml --json
enkv receipt --source /absolute/configuration.yaml --source-format yaml --operation "$operation_id" --json
```

`inspect --recipient service` resolves the local alias. Use
`inspect --recipient-id "$recipient_id"` to select an exact identity directly,
including one absent from the local recipient declarations. The authenticated
Store determines whether it is current. Omit both flags for the domain
overview. Each exact ID is 64 lowercase hexadecimal characters and must be
nonzero. Duplicate options, conflicting recipient flags, extra positional
arguments and unknown options refuse before credential construction. Omit
`--json` for human output. These commands read the input pair
without changing either file and work when the source directories are read-only.

The credentials need bucket object reads and the pair must supply independently
expected domain, Store and public verification facts. The commands construct
public GET routes only. They need no signer, KMS metadata/private operation,
original caller, plugin credentials or effect executor. AWS uses its default
credential chain; GCP uses ADC. A successful read fixes one authenticated
observation. Later HEAD changes do not update that result. Missing required data
refuses the whole view; no retry or old-selection fallback fills a gap.

Domain inspection includes current entry and recipient metadata, generated work,
compact work relations, selected output configuration, retained coordinates and
markers, and exact current blockers. It returns no value bytes or credentials.
Human output shows named operational rows and counts actual blocker relations
across coordinates. Physical pages, spans, digests and encoded backing remain
in JSON. An empty current entry set or zero current blockers does not establish
remote cleanup.
Current configured targets and resolved locators have separate fields. Only
qualified retained birth evidence and the stored generic target facts can supply
a resolved locator; this does not prove that the remote resource still exists.
Recipient inspection returns only metadata of entries currently granted to that
exact registered recipient. It excludes domain work, other memberships and
domain warnings. Bucket credentials themselves do not make metadata private.

Receipt listing returns all retained results, newest terminal selection first,
across the independent 256-success and 256-failure windows. This order is not
invocation time, remote effect time or a complete history. An authenticated empty
list succeeds. Exact detail includes the original complete typed receipt and one
owned copy of its 471 stored bytes, encoded as padded Base64 in JSON. Historical
state, warning bits and evidence remain unchanged. Current observation and
warnings are separate. An unavailable exact ID cannot distinguish an evicted
receipt from an operation that was never recorded. Mandatory receipt/order
damage refuses both forms. Unrelated disposable work damage need not prevent a
receipt read; complete domain inspection requires all selected work bodies.

Library callers use `InspectConfiguration`, `InspectConfigurationRecipient`,
`ListConfigurationReceipts` and `ReadConfigurationReceipt` with a finite context,
request nonce and captured `*configuration.Pair`. Their `File` variants capture
one explicit path and source format. `NewInspectionReader` and `NewReceiptReader`
accept explicit provider construction, exact source pins and an unchanged-source
check. Their `NewDefault` variants load standard credentials. Close installed
readers after use. Stored generic service and target facts are read without an
output interpreter. Source normalization uses only its declared installed
plugins, under the composition's compatibility rules.

`WriteInspectionJSON/Human`, `WriteRecipientInspectionJSON/Human`,
`WriteReceiptListJSON/Human` and `WriteReceiptDetailJSON/Human` borrow the owned
result immutably until return. They validate its complete closed shape and bounds
before the first byte, then stream to the supplied writer. Cancellation, short
writes and writer errors return incomplete delivery; the CLI cannot return a
successful exit for truncated output. Queries grant no mutation replay right.
Descriptor/root-health inspection is not supported.

## Atomic Recipient materialization

Use one complete trusted source pair and an explicit selection of current entry
names to write one application-dotenv file:

```sh
enkv materialize --source /absolute/configuration.yaml --source-format yaml \
  --name DATABASE_URL --name APPLICATION_MODE --recipient service \
  --out /absolute/application.env --json
```

Repeat `--name` for distinct entries. Supply at least one name and an existing
parent directory for `--out`. The destination can be absent or a regular file.
The command refuses stdout `-`, duplicate names, repeated singleton options,
extra arguments, symlinks, other file types, and aliases of the source files or
their reserved artifacts. It creates no parent directories. Omit `--json` for
human output. `--recipient service` selects the local alias;
`--recipient-id "$recipient_id"` selects an exact nonzero 64-character lowercase
hexadecimal ID. The flags cannot be combined. Omit both to select current
Authority, including for shared entries. The selected recipient still needs
membership in every requested entry.

The selection uses authenticated current Store values and Recipient bindings.
The selected entry's output encoding controls the delivered bytes. Pending
source edits and publication state do not supply the values or change that
selected setting. All selected plain and secret entries must permit the acting
Recipient. AWS uses its standard credential chain; GCP uses ADC. Credentials
need bucket object reads and, for selected secrets, decryption through that
Recipient's exact current KMS binding. Plain-only selection uses no private KMS
operation. No signer, Authority/Recovery fallback, Store write, generator or
output plugin is constructed.

Crypto authenticates and checks every selected value before it creates a
plaintext candidate. It writes one private 0600 file, verifies the complete
candidate, performs one same-directory replacement, and verifies the installed
file. A failure before replacement preserves the previous destination. A late
failure can leave the new file installed. The result reports replacement,
candidate and installed verification, native completion, disk disclosure and
candidate cleanup separately. A returned residue path identifies only this
invocation's private candidate. Removal does not prove physical erasure. There
is no rollback or automatic repeated delivery.

The file targets UTF-8 `motdotla/dotenv` 18.0.9 default `parse`, without expansion
or the fast parser. Names use ASCII `[A-Za-z_][A-Za-z0-9_]*`; `__proto__` is
refused. Values must have an exact supported representation. Invalid UTF-8,
NUL, raw CR, Unicode line separators and values with no supported quote form
refuse the whole file. Records use bytewise name order. The existing limits
are 512 entries, 65,536 content bytes per value and 8 MiB aggregate content.
Base64 delivery permits up to 87,384 bytes per value and 11,186,176 bytes for
the complete set. The dotenv file limit is 11,319,296 bytes; the raw-only bound
is 8,521,728 bytes. Unsupported raw bytes refuse; materialization does not
switch an entry to Base64 automatically. Docker Compose, Docker CLI env files, shell
sourcing, other parsers and later application use are outside this profile.

The CLI fixes a five-minute operation deadline. After complete selected bytes
are loaded, later HEAD changes or GC do not require Store reads. Before that
point, typed unread-child loss can restart acquisition only after a changed
authenticated HEAD, within the original request and deadline. The bound is
three image attempts and four selection observations; public admission adds
at most two HEAD reads on AWS or one on GCP.

Library callers use `MaterializeConfiguration(ctx, request, pair, outPath)` with
a finite context and `contract.MaterializationRequest`. The caller keeps the
borrowed pair open until return and then closes it. The `File` variant takes
one source path and format, owns capture and close, and returns
`(core.MaterializationResult, error)`. A separate source capture or close error
does not overwrite the operation result or its native facts. Close an installed
owner made by `NewMaterialization` or `NewDefaultMaterialization` after use.
The captured pair keeps at most 256 MiB of disk-backed source images open
through completion. Source checks use bounded 64 KiB windows and finish before
private value custody. The source images contain configuration data; they do
not receive recovered secret plaintext.

`WriteMaterializationJSON/Human` validate the complete closed result before the
first byte and stream safe public selection identities, the current public
binding, exact semantic destination and local facts. They return presentation
errors separately. Results contain no plaintext, plaintext digest, mutation
receipt or replay handle. Keep the operation result if result delivery fails;
do not repeat the operation to obtain its response. Success describes one
verified installed observation. It does not promise continued presence against
another writer. Native filesystem and provider qualification remain specific
to the execution platform and service.

## Public consumption manifest files

Write a complete consumption manifest through an explicitly selected trusted
renderer. The local plugin ID selects the implementation; `--settings` supplies
its bounded JSON settings, defaulting to `{}`:

```sh
enkv manifest --source /absolute/configuration.yaml --source-format yaml \
  --plugin generic-json --out /absolute/consumption.json --json

enkv manifest --source /absolute/configuration.yaml --source-format yaml \
  --plugin generic-json --recipient service \
  --name DATABASE_URL --name APPLICATION_MODE \
  --service ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1 --out /absolute/consumption.json --json

enkv manifest --source /absolute/configuration.yaml --source-format yaml \
  --plugin opentofu-tfvars-json --settings '{}' \
  --out /absolute/enkv.tfvars.json --json
```

The examples use official local IDs. An independently authored renderer uses
its own trusted local ID and settings through the same command. The selected
plugin owns its format and settings grammar. `--source-format` still selects the source
file syntax. The official OpenTofu artifact has one root variable, `enkv`, with
plain bytes and secret destination references; it does not fetch secret values.
Runtime rendering does not acquire missing support.

Use `--recipient service` for a local alias or `--recipient-id "$recipient_id"`
for an exact ID. The flags cannot be combined. Omit both to select current
Authority, including for shared entries. Omit `--name` to select all current
entries granted to the selected recipient. Repeat `--name` for distinct
exact names. `--name ''` selects the empty name; `--empty-selection` selects no
entries and cannot be combined with names. IDs have 64 lowercase hexadecimal
characters and must be nonzero. Optional `--service` matches one exact stored
semantic service identity. It is independent of the Store provider, local
plugin alias and executable build. Omit it to include all services.

Selection and authorization use one authenticated current Store image. Pending
source edits do not supply selected values, memberships or routes. Plain entries
remain included. Secrets with no effective output are excluded as `no-output`;
secrets with valid outputs but no matching service are excluded as
`no-matching-service`. One missing or unauthorized requested entry, invalid
stored target contract or unusable matching locator refuses the complete
issuance. Reading stored generic service/target facts requires no output plugin.

The same admitted renderer first validates settings, then receives the complete
authorized projection in a separate bounded invocation. The host checks selected
build, correlation, framing, bounds, deadline, positive child/transport closure
and exact delivered bytes. Format validity and correspondence to that projection
belong to the renderer author and its independent format/consumer tests. Safe
result metadata describe input selection and artifact length/digest; they do not
certify the artifact's semantic contents. The child receives no credential input,
secret plaintext or Store connection. Installed native code remains trusted code
with OS access; this invocation boundary is not a sandbox. Comparison starts no
manifest renderer.

The command uses GET-only Store credentials, with no KMS operation, output
credential, provider effect or Store write. It has a five-minute deadline and
keeps its original observation without a query restart.

`--out` requires an existing trusted local parent. The destination can be absent
or a regular file. Stdout `-`, symlinks, special files, source aliases and
configuration transaction paths refuse. The writer creates one private mode
0600 candidate in that parent, writes the complete issued bytes, synchronizes,
closes and verifies them, then replaces once and verifies the installed file.
It does not copy old permissions or create parent directories. A late failure
can leave the complete new file installed. Read replacement, verification,
cleanup and residue facts separately; do not repeat delivery to obtain its result.
A retained candidate can be removed at its exact reported path after every
owning process has stopped. Removal does not prove physical erasure. Native
visibility and synchronization limits depend on the execution platform.

Stdout contains a safe `ManifestFileResult/v2`, with the issuance
`ProductResult/v1`, artifact metadata and native delivery facts. It contains no
artifact bytes. The artifact file contains plain values and public secret
consumer locators; protect it under the caller's custody. `result_delivery` is
`not-observed` in the emitted record because a stream cannot certify its own
completion. Exit `0` requires complete native delivery, source cleanup and result
delivery. Failed or unknown source cleanup or result delivery returns `2`, even
when issuance is unavailable. With complete terminal delivery, unavailable
issuance or contention returns `3`; other failures return `2`.

Library callers use `IssueConfigurationManifest` or
`IssueConfigurationManifestFile` with `ManifestOptions` for in-memory issuance.
The options select `Plugin`, JSON `Settings`, target/entry modes and optional
`ServiceFilter`; composition captures that exact renderer and its canonical
settings before Reader admission. Both return
`(core.PublicManifestResult, error)`; source lifetime errors remain separate from
successful issuance and its transferred artifact. `WriteConfigurationManifest`
and `WriteConfigurationManifestFile` return `ManifestFileResult` and release
artifact bytes after native settlement. Pair variants borrow the caller's pair;
file variants own source capture and close. Keep a finite context and stable
request backing until capture. `WriteManifestFileJSON/Human` return presentation
errors separately. After a successful write, the caller can set
`ResultDelivery = ManifestResultComplete` and call `ManifestFileExitCode`.

## Callable public Reader

`NewReader(ctx, ReaderConfig)` selects exactly one AWS or GCP GET-only
composition. Supply independent expected domain/Store facts and the complete
typed public basis. `ReaderConfig.InterpretOutput` supplies the public
interpreter required for ordinary output settings; stored canonical targets
remain generic data. `PrepareManifestRenderer` must resolve the exact selected
renderer when issuing a manifest. Configuration comparison captures a trusted
source pair and uses native AWS credential-chain or GCP ADC credentials through
`CompareConfigurationFiles`. No separate read connection is required. Reader
creates no Authority or Recovery admission and needs no issuer Recipient.

Use a finite context and stable typed backing through input capture:

```go
comparison := engine.Compare(ctx, requestID, desired)
issued := engine.Manifest(ctx, manifestRequestID, contract.ManifestRequest{
    Renderer: rendererSelection,
    FormatContractID: formatContractID,
    ConfigContractID: configContractID,
    Settings: canonicalSettings,
    TargetMode: manifestsdk.ExactRecipient,
    EntryMode: manifestsdk.ExactNames,
    TargetRecipientID: target,
    EntryNames: []string{"plain-entry", "secret-entry"},
})
engine.Close()
```

`manifestsdk` refers to `enkv.sh/sdk/manifest-generator`. The renderer selection
must identify the exact admitted build, and format/configuration identities and
canonical settings must come from that build's settings validation. These public
fields alone grant no permission to run code. Configuration callers can use
`ManifestOptions` and the adapters above to own that preparation.

`desired` is `contract.PublicConfiguration`; each complete set has an explicit
presence state. An empty set or empty name is distinct from omission. A nonnil
empty `EntryNames` selection in `manifestsdk.ExactNames` mode is valid after
current target/state verification. For the current Authority and every granted
entry, use `manifestsdk.CurrentAuthority` and `manifestsdk.AllAuthorized` with no
explicit ID or names. A nil `ServiceFilter` selects all output services; a
nonnull string selects exactly that stored semantic service identity.
Plain entries stay included. Secret entries without effective outputs or matching
services appear in `ExcludedEntries` with their reason.
Duplicate, missing or unauthorized entries and unusable required secret locators
refuse the complete manifest. Only successful issuance returns `Artifact` and
`ManifestPayload`; keep artifact bytes under the caller's custody.

`RenderComparisonJSON` and `RenderComparisonHuman` preserve the same complete
diagnostic vector, scope, completeness, issuer context and fixed observation.
Human output quotes empty and control-character names. `ComparisonExitCode`
returns 0 for match, 1 for mismatch, 2 for invalid/refused/profile/integrity or
incomplete evidence construction, and 3 for unavailable evidence/contention.
`RenderManifestResultJSON` and `RenderManifestResultHuman` report safe issuer,
target and completion context without embedding or copying the artifact.
Renderers return one exact complete backing or a fixed safe rendering error.

The authorized projection contains selected plain values and every resolved
secret destination, with its exact included/excluded partition. The renderer
must encode that projection correctly; the host establishes the common
`authorized-input-and-exact-bytes` assurance. No acknowledgement, remote resource
existence, output IAM, signature or independent later-verification claim follows.
Consumers trust the renderer implementation, issuer and subsequent artifact
custody. The Reader engine
returns in-memory bytes; the configuration adapters also support native file
delivery. No manifest route uploads artifacts.
`CompareConfiguration` and `CompareConfigurationFiles` adapt captured trusted
and optional candidate pairs to the same Reader comparison contract.

## Callable private planning

`PlanConfiguration` and `PlanConfigurationFiles` return safe private relations
with `contract.PlanningOptions{Purpose: contract.PlanningEquality}`. The pair
form borrows captured trusted and optional candidate pairs until all private
work joins. The file form captures and closes its own pairs. Both require a
finite context and use only the trusted Authority route. They perform no
mutation and return no permit for later apply.

`DisplayConfiguration` and `DisplayConfigurationFiles` additionally take exact
selected names and an explicit `crypto.PlanningDisplayFactory`. The factory and
acquired sink must report the admitted identity. Crypto lends one bounded raw
value to `Accept` until it returns; the sink must release it before the next
record. The sink owns its mutable encoding and finalization. `Close` must unblock
and join entered transfers. Core receives safe counts and delivery facts only.
A completed private check remains complete if later output fails; overall state
and exit still report that failure.
