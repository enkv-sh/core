# Stock CLI plugin acceptance

This opt-in scenario checks installed plugins against real services through one
unchanged packaged CLI. The runner captures the CLI before it builds the plugins.
Every Product command starts a fresh CLI process. The scenario uses the existing
runner and its private failure and recovery owners.

The checked-in workflow and environments are examples. They do not authorize a
live run. Local checks do not establish credentials, deployed permissions or
provider acceptance.

Run the local construction and controlled assertion checks with:

```sh
tests/scripts/test run --workflow tests/workflows/stock-plugin-acceptance-local.json
```

This workflow builds the stock CLI and ordinary plugin artifacts, checks the
exact scenario inputs, and runs local provider response fixtures. It starts no
live worker and invokes no OpenTofu command. It requires the installed Go
toolchain, OpenSSL and populated local module cache used by the existing runner.

## Cloud cells and claims

| Cell | Store and KMS | Output services | Other checks |
|---|---|---|---|
| AWS, Recovery enabled | S3 and KMS; SSO-based AssumeRole profiles | Secrets Manager; GitHub repository, organization and environment secrets | Cloudflare A/B continuation; independent INI manifest; canonical reconstruction |
| GCP, Recovery enabled | Cloud Storage and Cloud KMS; user ADC with service-account impersonation | Secret Manager | Cloudflare A/B continuation; independent INI manifest; canonical reconstruction |

The AWS and GCP consumers read complete output values with separate credentials
and compare them privately. GitHub checks establish exact secret metadata and
accepted operations. They do not establish plaintext consumption by a GitHub
Actions job. The INI consumer checks the complete manifest against independently
derived expectations.

These cases supplement the local unknown-plugin tests. Changing a Cloudflare
credential recipe proves a compatible source update and exact retained routing;
it does not by itself prove an arbitrary new service implementation.

## Generator sequence

1. Build and select A. Apply epoch 0 with manual retirement.
2. Apply epoch 1 with A. Require `retirement-pending` and the exact accepted A
   Duty for the epoch 0 resource.
3. Select compatible B with different executable bytes and a different declared
   environment credential name. Apply unchanged epoch 1 in a fresh process.
   Require no-op and the unchanged A Duty and current generation.
4. Make the test-owned retained A executable unavailable. Its retirement must
   refuse without using B or changing selected state. Restore the exact A bytes.
5. Retire the original Duty with only A's credential route. Compare its executor,
   route, result contract and original resource identities.
6. Advance to epoch 2 with B. Require new B generation and a new B Duty for the
   A-created epoch 1 resource. Complete that Duty through B.
7. Remove the generated declaration and retire the final resource through the
   accepted Product path. Check that no known generated work remains.

The recipe uses one fixed finite Cloudflare expiry timestamp across the A/B
declarations. Expiry limits a possible unknown resource's lifetime; it does not
establish retirement or cleanup. A Core resource digest is never used as a
Cloudflare token ID. Current selected token bytes stay in a private materialized
file and are used only for the bounded independent Verify Token check.

The scenario also publishes its small supplied plain/secret fixture, renders the
installed independent manifest, and reconstructs the canonical configuration
after local application-file loss. Reconstruction must leave executable
selections unset. Explicit reselection must preserve current semantic state.
The loss step does not remove SDK credentials, SSO caches or retained support for
accepted work.

## Required resources and credentials

Use the provider's opt-in `plugin_acceptance_id` fixture configuration in the
infrastructure repository. Its `plugin_acceptance_environment` output is the
current runner environment, including a closed `plugin_acceptance` grant. It
reuses existing KMS keys and public actors and provisions a dedicated Store
bucket. The fixture ID and the runner's invocation ID are different identities.

Keep the same fixture ID and bucket across invocations. Each invocation gets a
fresh random RunID and an object prefix `enkv-test/<RunID>/<case>`. Never reuse an
old run prefix. The ordinary fixture requires a bucket with versioning disabled.
The dedicated AWS `stock-plugin-retirement-proof` fixture requires versioning
enabled. Both require retention and holds disabled. GCP also requires soft
deletion disabled. Before its first Product effect, the scenario
checks the actual bucket configuration and requires only its selected prefix to
be empty. It retains a grant bound to the original run, prefix, fixture, bucket
identity and limits. Objects in old or sibling prefixes do not block a new run.
No ready marker is required or consumed, and no test principal can delete the
bucket. Initial provisioning is separate from later test invocations.

For AWS, configure `plugin_acceptance_sso_role_arn` with the exact existing IAM
Identity Center role. Verify effective `sts:AssumeRole` access to the five roles.
Same-account role trust can grant access without a separate identity-based allow,
although other applicable policies can restrict it. Cross-account access requires
an identity-based allow. If needed, the exported permission-set policy provides
the exact addition; this fixture does not manage that permission set. Configure
the five isolated standard AWS profiles with
their SSO `source_profile` and the exported target role ARNs. This is an
`aws-assume-role` context whose source is SSO; it is not a static credential
context. Do not seed it with the older test IAM user's access keys. The scenario
does not log in or export session keys.

For GCP, use the five existing isolated impersonated user-ADC contexts and the
exact project and quota-project settings. The output consumer needs
`secretmanager.versions.access`; the AWS consumer needs
`secretsmanager:GetSecretValue`. The fixture adds these scoped read permissions.
Consumer identity must differ from the publisher. Consumer Store/KMS read rights
remain available; this case does not claim output-only IAM isolation.

Supply the authorized Cloudflare account and permission-group IDs in a private
copy of `cloudflare-stock-plugin.example.json`. No prebuilt generator artifact is
an input: the scenario builds A and B after CLI capture. Supply
`CLOUDFLARE_API_TOKEN` through the normal environment. The recipe supplies that
credential to the selected A or B environment name without persisting its value.

For the AWS cell, set the three exact GitHub scopes in `public_outputs`, including
the organization visibility and sorted repository IDs. Supply `GITHUB_TOKEN`
through the environment. The GCP cell needs no GitHub scope or token. The scenario
does not create a repository, environment or GitHub Actions consumer.

Prepare the private input packet from the checked-in example schemas and the
owner-provisioned resources. AWS needs the limited SSO source selectors and
three public GitHub scopes. GCP needs the five isolated impersonated contexts.
Both need the Cloudflare environment source. Input presence does not prove live
permissions.

## Review the inputs before execution

Save the environment JSON values and Cloudflare scope in private local files.
Use mode 0600 for files and 0700 for their directory. Keep credentials out of JSON.
Prepare `environment.json`, `cloudflare-stock-plugin.json` and a one-provider
`workflow-stock.json` with absolute owning suite, limits and telemetry paths.
Provide `test-auth.json` for the selected source contexts and establish the
limited SDK logins before the live trial. Use the current consumer schemas and
absolute paths.

From the implementation repository, plan one cell:

```sh
tests/scripts/test plan --workflow /ABSOLUTE/PRIVATE/workflow.json \
  --step stock-plugin-aws-enabled
```

Use `stock-plugin-gcp-enabled` for GCP. Planning resolves local selection and
inputs. It does not prove live resource or login readiness.

Before a live run, review the exact source, CLI/plugin construction, account or
project, bucket identity, exact run-prefix grant, GitHub scopes, Cloudflare policy, limits and
cleanup behavior. After separate live authorization, run the same selection by
replacing `plan` with `run`. Do not run the checked-in example against a real
account without completing this input review.

## Limits and result meaning

Each cell admits at most 64 CLI commands and 32 non-Store provider verification
calls. A CLI command has a 120-second bound within the 3600-second cell deadline.
Cleanup has a separate 900-second bound. The generator allowance reserves nine
possible creates for the three lineages, including admitted successor/residue
branches. Normal retirement and cleanup have separate reservations. The nominal
successful path creates three tokens, with at most two known tokens live at once.

`tests/live/limits/stock-plugin-acceptance.json` declares finite request, byte,
object and effect reservations. Stock CLI reservations do not measure or enforce
every physical SDK request. Independent verification and cleanup calls have their own
bounded owners. No observer overlay, proxy or invented capture is used to claim
physical request counts.

### Fixed lifecycle reservation

The fixed successful path has 35 CLI children. This includes the compatible
no-op and generated list after reconstruction and the independent post-exit
Reader. A failed command boundary stops later commands. Each create still
reserves all three permitted entered branches within that command. Manual
retirement prevents automatic delete sequences.

Let `r` be the number of saved successful manual retirements before the
command, from zero through three. Successful managed creates do not leave a
selected Create release. Each manual Delete can retain its ended Attempt,
exact inbox mapping, graph fragment, slice carrier and support carrier. These
five rows add at most five physical pages. The command owner passes its saved
retirement count, including after the fresh Reader loads the original evidence.

A generated candidate has at most `32 + 5*r` immutable objects. Ordinary and
publication candidates have at most `20 + 5*r`. Both retain the 4 MiB aggregate
encoded-image bound. The image includes current and retained generated support,
physical intent blobs, both receipt windows, their index, output configuration,
publication rows, one administrative index shard and the root. Initialization
also reserves the Store configuration object and the first HEAD key.

A retained manual Delete graph has at most two value-entry plans, one retirement
lineage with one Delete template, two edges and one result-use row. Its graph
body is at most 6,171 bytes. The Attempt, mapping, graph fragment, slice carrier
and role-7 support carrier use at most 9,453 framed bytes, plus five 75-byte page
headers: 9,828 bytes per release. The maximum rotation image uses 4,138,649 bytes
before these releases. Even three releases fit in 4,168,133 bytes. The ordinary
output image fits below 3,932,693 bytes with three releases.

The capacity check keeps generic Product charges. For the physical byte proof,
it replaces only each fully validated released Delete continuation group's
64 KiB charge with its exact emitted Attempt and mapping bytes. This does not
reduce new-operation continuation charges. The administrative envelope includes
15 additional old rows and pages, and still fits one 512 KiB index shard.

The base generated profiles have at most eight fragment rows and seven logical
slices. Each fixed declaration, intent, graph, registry, preparation image and
receipt index fits one fragment. Create observations include all 12 history
carrier rows from three entered attempts and their duty or hazard histories.
The additional selected-read bounds are `94 + 5*r` for create, `40 + 5*r` for
retirement, and `18 + 5*r` for ordinary AWS images or `17 + 5*r` for GCP.
The predecessor fragment bounds are `8 + r` for create, `6 + r` for retirement
and `3 + r` for ordinary commands.

These counts follow actual fixed reads. Blob-ID lookup excludes unrelated
fragments from each logical slice read. The generic observation-stage ceiling
is an admission limit, not a count of actual calls. No cache saving is deducted.

For `I` immutable objects and `R` additional selected reads, the complete
persistence and selection episode reserves:

```text
12*I + 12 + 9*(I + 1 + R) service calls
```

The shared helper receives `I + 1 + R`: root and child reads, normal HEAD, and
additional reads. Its fixed term also covers the separate HEAD observation
used after a possible transport write. An extra persistence without selection
costs `12*I`. This covers three immutable writes and their bounded readbacks,
three HEAD sends, and all permitted observation stages.

Bodies retain the shared 5 MiB allowance for writes, extra service work and
HEAD/extra-read episodes. Immutable readbacks and complete image scans instead
use their aggregate 4 MiB image bound, plus 64 KiB per object for a provider
error envelope and one byte for an oversized-response probe. Pure public list,
preview, manifest and post-exit plan calls reserve 3 MiB per service read. Their
Store objects are at most 2 MiB; public-key and error replies are at most 64 KiB.
These public paths invoke no private KMS operation or output Prepare/Send.

The table includes cold Opens, repeated selected predecessor reads, KMS
operations, result inbox persistence and plugin effects. Counts sum to 35.

| CLI command class | Prior releases | Count | AWS requests each | GCP requests each |
|---|---:|---:|---:|---:|
| First two generated creates | 0 | 2 | 13,380 | 13,377 |
| B2 generated create | 1 | 1 | 14,700 | 14,697 |
| First exact retirement | 0 | 1 | 3,995 | 3,992 |
| Second exact retirement | 1 | 1 | 4,550 | 4,547 |
| Final exact retirement | 2 | 1 | 5,105 | 5,102 |
| Ordinary apply, including generated removal | 2 | 3 | 1,326 | 1,236 |
| Initialization | 0 | 1 | 759 | 753 |
| Compatible no-op before retirement | 0 | 1 | 156 | 138 |
| Compatible no-op after reconstruction | 2 | 1 | 216 | 198 |
| Missing-support retirement refusal | 0 | 1 | 399 | 366 |
| Generated list | 0 | 4 | 42 | 40 |
| Generated list | 1 | 1 | 52 | 50 |
| Generated list | 2 | 2 | 62 | 60 |
| Generated list | 3 | 2 | 72 | 70 |
| Materialize generated value | 0 | 2 | 123 | 119 |
| Materialize generated value | 1 | 1 | 153 | 149 |
| Publication preview | 2 | 4 | 99 | 94 |
| Manifest | 2 | 1 | 124 | 120 |
| Reconstruction prepare | 2 | 1 | 285 | 279 |
| Post-exit plan | 3 | 1 | 78 | 74 |
| Local secret set | 2 | 1 | 0 | 0 |
| Publish | 2 | 1 | 22,005 | 8,770 |
| Output delete | 2 | 1 | 17,583 | 4,469 |

The complete cell also includes four independent selected Opens and support
observations, all with two prior releases. Their recorded Store owner charges
two request units per logical read. These releases add 480 request units and
1,258,291,200 body bytes across the four Opens. Prefix preflight, at most 32
verification debits, and four cloud output value/deletion checks are also
included. Repeated persistence costs another byte debit, even when an immutable
key already exists. A result record reserves 92,637 bytes. Its fields use
16 bytes for framing, 452 for the core, 4,096 for safe facts, 215 for payload
framing, 87,384 for the retained value and 474 for the transfer envelope.
Each create or rotation reserves 18 result-record writes. Each exact retirement
reserves six.

| Complete cell reservation | AWS | GCP |
|---|---:|---:|
| Requests | 103,828 | 76,981 |
| Body bytes | 311,761,309,163 | 237,771,717,235 |
| Store objects, including HEAD/configuration/inboxes | 2,557 | 1,837 |
| Object bytes | 1,015,084,584 | 708,376,104 |
| Generator create reservations | 9 | 9 |
| Generator retirement reservations | 9 | 9 |

The common limits file uses the AWS request and body maxima. A separately
reviewed GCP input can use its exact provider bound. Every invocation still
needs allocation from its cumulative remaining allowance. Changing a limits
file does not refill that allowance.

For cleanup of `N` objects, the fixed owner reserves `2*N + 816` requests on AWS
or `2*N + 770` on GCP. This includes one body GET and one conditional delete per
object, up to three scans of 256 LIST pages, and bucket checks. Body debit is
`N*(2 MiB + 64 KiB) + 768*512 KiB`, plus 48 AWS or two GCP bucket checks at
64 KiB each. The complete bounds are 5,930 requests and 5,935,792,128 body bytes
for AWS, or 4,444 requests and 4,375,642,112 body bytes for GCP. They fit the
existing 8,192-request, 16 GiB cleanup cap and the scanner's 4,096-object bound.

These are fixture-owned service and object reservations. Standard SDK
credential fetch and refresh HTTP remains outside this owner. The CLI and
plugins remain unchanged, and this accounting does not measure all network
traffic. Original failed-writer recovery keeps its original reservations.

A positive process join and a Product outcome are separate facts. Exit 3 is
expected for pending manual retirement; exit 2 is expected for the retained-A
refusal. All other outcomes must match their exact step expectations. Reaching a
deadline, losing a response or failing an assertion stops the sequence and
retains the original attempt. The runner does not repeat until it passes.

## Cleanup and failed runs

Generated retirement and output deletion use admitted public Product commands.
Unknown creates are never adopted or deleted because a listed name matches.
Cloudflare deletion acknowledgement does not prove global token invalidation.
AWS Secrets Manager deletion uses its recovery window: two scheduled deletions
are reported as scheduled, not as erased secrets. Exact provider metadata and
the original output coordinates must support that result.

After every child has joined and known provider work is complete, Store cleanup
uses the original exact run-prefix grant. Every bounded LIST page selects that
prefix followed by `/`, and every returned key must belong to it. Cleanup reads
the admitted objects, deletes them with their observed condition tokens, and
requires a final empty-prefix observation. It leaves the bucket and all other
prefixes intact. IAM bounds the bucket/test object namespace; the runner enforces
the exact per-run scope. AWS retains bucket LIST permission because missing-key
GET requests need it to return 404.

The dedicated AWS fixture also checks historical versions. The initial prefix
must contain zero data versions and zero delete markers. Cleanup opens the
final domain using its public handoff and checks every HEAD version back to
the signed initialization. After reconstruction, it verifies the original
Genesis HEAD with its own root and recipient pages under the signing anchor
and Store configuration from the final handoff. It reads each data version by ID. For a released
result it requires the original bytes, the signed release, the resource from
this run and one current delete marker. The worker removes qualified data
versions first, then their markers, then the final HEAD. Each removal
names the qualified version ID and requires S3 to acknowledge that same ID.
It saves `stock-version-proof.json` in the private run directory before
the first deletion.
The file records version IDs, ETags, lengths, hashes, signed HEADs and the three
original retirement acknowledgements. It can be inspected after interruption.
Other value bodies stay out of this file. The worker lists the complete
prefix again between stages and after the final deletion. An unexpected
version, an incomplete listing or a lost deletion reply leaves cleanup open.
The failed-writer recovery route cannot dispose of this fixture.

The retained `stock-prefix-cleanup.json` record binds the original RunID, fixture,
prefix and bucket identity to `Started`, `Completed` and `ObservedEmpty` facts.
The final assertion is `store-prefix-observed-empty`. It means the prefix was
empty at the final check. It does not prove that no delayed request can write
later. Such an object remains in the old prefix and can require later cleanup;
it does not become part of a new invocation's prefix. `UnknownEffects` counts
known unresolved admitted effects, not every possible delayed remote request.
Failed or uncertain object deletion stays unsuccessful with the original facts.

Keep failed invocation files, original support builds, pending Duty identities
and recovery inputs. Use the existing runner's exact recovery path where the
record admits it. A new invocation may use the same bucket with a fresh prefix;
its result does not repair or replace the old result. Do not delete private
evidence or reuse an old prefix to obtain a clean result.

Automatic prefix cleanup requires complete provider-work facts from the original
writer and Reader, with every child joined. A failed writer, unknown provider
effect or incomplete record prevents that cleanup. The runner retains the
original files and grant; it does not promise automatic recovery from every
failed writer or automatically replay an uncertain cleanup attempt.

### Exact failed-writer recovery

The existing cleanup command supports a separate recovery of a settled stock
writer that failed during execution before recording a completed generation,
output or stock assertion. It requires one original case, its immutable receipt,
joined original workers and commands, the original source pair, and compatible
retained CLI and plugin builds. Keep the original limited SDK contexts usable.
Public stock recovery does not accept an environment replacement.
Supply `CLOUDFLARE_API_TOKEN` through the original environment credential route.
Preparation and claim admission check its required syntax before consuming the
one-use claim. These local checks do not test API permissions or token validity.

Before dispatch, prepare a reviewed mode-0600
`stock-recovery-accounting.json` in the original private case directory. Its
directory must have mode 0700. The record contains selectors, hashes and byte
lengths, with no credential contents:

| Field | Required value |
|---|---|
| `schema` | `1` |
| `run_id` | The exact original run ID |
| `complete` | `true` after all known command, reservation and join history is accounted for |
| `original_run_sha256` | SHA-256 of the unchanged original `run.json`, including its final newline |
| `original_input_sha256` | SHA-256 of the original private `input.json` |
| `original_evidence_sha256` | SHA-256 of the original `stock-plugin-evidence.json` |
| `original_grant_sha256` | SHA-256 of the original `stock-plugin-grant.json` |
| `sources` | The original editable and generated files, sorted by absolute path |
| `diagnostics` | Every additional retained reader invocation, each with `scope` and `result` file identities |

Each file identity has `path`, `sha256` and `length`: an absolute canonical path,
the SHA-256 of its complete unchanged bytes, and its positive byte length. Include
all additional reader invocations. Keep `complete` false if any command,
reservation or join is missing. That record cannot admit recovery.

Supported historical reader scopes use exactly one complete request/body pair:
`maximum_logical_requests` with `maximum_body_bytes`, or
`planned_logical_request_reservation` with `planned_body_byte_reservation`.
Their no-token, zero-mutation, bounded-time, source/support and joined-result facts
remain required. `no_subprocess_derivation` is a bounded historical explanation;
its text grants no command or effect authority. A complete typed diagnostic must
bind the original operation, attempt, owner, Hazard, resource and retained
generator support. Observed names and counts cannot supply those relations.

The recovery owner derives the original remaining Product allowance from the
native reservation and every listed reader reservation. It retains uncertain
allocations and charges each reader's full retained timeout when a narrower
elapsed fact is unavailable. Original command slots and service-verification
counts remain cumulative. Preparation checks these facts locally before any
recovery claim or provider effect.

Supply a current ten-field limits file for the new cleanup invocation. Historical
monetary fields remain readable only in old records; a new limits file rejects
them. The fixture-cleanup allowance is at most 8192 requests, 16 GiB and 900
seconds. Its grant does not refill the original Product allowance. The original
remaining budget must still cover the two bounded CLI reservations, with two
unused command slots and at least 240 Product seconds, 256 requests, 32 MiB of
body bytes, 128 objects, 32 MiB of object bytes and three retirements.

After authorization for the exact limited test effects and cleanup, run:

```sh
tests/scripts/test cleanup ORIGINAL_RUN_ID \
  --limits /ABSOLUTE/PRIVATE/cleanup-limits.json
```

The command creates one durable `stock-recovery-claim.json`. It runs one fresh
normal Product `generated cleanup` through the retained CLI. Only a qualified
original-result reflection or an eligible exact owned target can establish
progress. A no-target, unknown, unsupported or incomplete result leaves the
dependent work blocked. The recovery permits no create, writer/apply replay,
provider scan, name-based deletion or risk acceptance.

When the Product result proves closure, a separate read-only `generated list`
must observe the same HEAD and snapshot with no current generation, Duty, Hazard
or pending release. Exact original-prefix cleanup can then use the separate
fixture allowance and record final emptiness. Product commands keep the original
remaining deadline; Product elapsed stops when those commands join, before the
Store phase.

The recovery keeps the original run, input, grant, stock index and source bytes.
New command diagnostics, the copied command index, `stock-recovery.json` and any
`stock-prefix-cleanup.json` are written under the new cleanup worker's output
directory. The result records reflection, retirement, residual exposure, Product
reservations and Store cleanup separately. It does not turn the original failed
lifecycle into a successful stock test. A consumed claim, failed save, unjoined
child or uncertain outcome remains retained and cannot be replayed automatically.

The acceptance workflow does not consume infrastructure. Keep
`plugin_acceptance_id` stable across runs; no OpenTofu apply or bucket recreation
is required between invocations. The workflow runs no OpenTofu command and gives
test actors no bucket-creation or bucket-deletion permission.
