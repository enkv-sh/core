# Tests

Run commands from the repository root with stock Go 1.27.3, Git, a shell and
`gofmt`, Make and standalone golangci-lint v2.14.0 on `PATH`. The launcher uses the installed Go
toolchain and pinned module versions. Current artifacts use Go 1.27.3. Module
language minimums remain Go 1.27.0. This compiler update does not requalify the
Darwin Go 1.27.0 memory proof.
Before using the launcher, populate the pinned module cache and install the
native supervisor with `tests/scripts/setup-supervisor`. Repeat setup after
mapped source inputs or the native toolchain change. Ordinary commands refuse a
missing supervisor or incompatible native target. Darwin requires cgo and a
native C toolchain; Linux uses `/proc` and requires glibc 2.34 or later for the
native plugin hosts. A cross-build does not establish native execution evidence.
Materialization consumer checks also require Node v24.19.0 and the installed
dotenv 18.0.9 [consumer fixture](fixtures/dotenv-consumer/README.md); archive
checks require OpenSSL 3.x. The fixture guide gives the exact install command.
The two repositories must use the
[declared sibling layout](https://github.com/enkv-sh/extensions/blob/main/distribution/README.md#source-development).
Supervisor setup uses `/var/tmp/enkv-test-resources-<uid>/machine.lock`.

For live tests, the resource owner must provision buckets, keys, test
principals and exact scoped permissions, then prepare private copies of the
checked-in environment and workflow examples. Establish limited SDK login
contexts before execution. The runner performs no provisioning or administrator
login. An export or successful login does not establish the selected live
capabilities or cleanup results.

The runner tests internal empty genesis, complete supplied plain and secret
lifecycle, recipient grants and exclusions, current Recipient and Authority key
replacement, current-values and accepted-work recovery, public integrity, capacity limits and
fresh-process delivery and configuration reconstruction after complete local loss.
Provider controls test exact credential routing and
access refusal. The local Authority operator tests use production admission and
fresh executable processes. Public initialization and supplied apply use production admission. Other
value-mutation fixtures admit exact operation authority, current public bases
and recipient bindings through the test overlay; their command families remain
separate from the public supplied slice. Private signing keys, secret input and
sinks stay in the out-of-Core test facades.

Many `package core` component tests live in `tests/shared` and `tests/hermetic`.
The runner's [assembly owner](shared/runner/assembly.go) overlays those source
groups into Core with the required private test admissions. Plain `go test`
inside `core/` does not include these external files. For example,
[`installed_apply_reservation_test.go`](shared/installed_apply_reservation_test.go)
is selected through the component step:

```sh
tests/scripts/test run --workflow tests/workflows/dev.json --step components --test TestInstalledApplyReservationPreservesSelectedReadFailureCategory --parallel 1
```

The returned compiled inventory and terminal rows establish which root and
subtests actually ran. A preview or source declaration alone is not execution
evidence.

The shared regression includes plain additions, removals, empty state, selected
re-add, mixed membership and disjoint replacement of 512 value entries at both raw-byte
limits. Ordinary first-flow scenarios add empty genesis, direct first-secret
selection from genesis, authority-only delivery, shared secret delivery to a
Recipient and authenticated KMS refusal for a denied Recipient. The latter three
preserve a plain value entry while adding the secret. Supplied-value scenarios cover randomized equal-value
no-op, exact retained material, updates, historical-source re-use, grants,
exclusions, competing candidates and controlled lost replies. Recipient consumption
uses the Recipient's credential route; exclusion denies current access while leaving
previously obtained historical values readable. The retained `reader`,
`denied-reader` and `reader-successor` credential and scenario labels refer to
Recipients, not the public Reader role. Hermetic execution runs each scenario in
its declared supported recovery modes, including fresh processes before and after
writer exit. The same shared scenarios provide
live execution for those modes. Controlled provider tests establish local
behavior; recorded live runs are required for actual IAM evidence.

Public preparation after complete local-file loss uses the opt-in
[`public-configuration-prepare-live.json`](workflows/public-configuration-prepare-live.json)
workflow. It has AWS and GCP cells with Recovery disabled and enabled. Each cell
selects `public-configuration.prepare-complete-loss/prepare_complete_loss` with
five distinct SDK contexts: Authority, Apply, Reader, consumer and cleanup.
Prepare private `environment-prepare-{disabled,enabled}.json` and
`workflow-prepare-bounded.json` files for each selected provider from the
checked-in examples, using the existing resources and isolated SDK contexts.
The checked-in environments contain placeholders and cannot establish access.

Inspect the selected provider's private packet before a separately authorized run:

```sh
tests/scripts/test plan --workflow /ABSOLUTE/PRIVATE/workflow-prepare-bounded.json
```

For the later authorized run, replace `plan` with `run`. Use `--step public-prepare-aws-disabled` (or the matching provider and Recovery
mode) to select one cell. The invocation selects race detection through `--race` when required. The packet keeps existing finite request/byte/time
limits. SDK login or refresh must already work in each selected isolated
context. Planning does not contact cloud services or establish IAM readiness.

The scenario initializes and applies one shared supplied secret, removes every
file in the setup pair directory, and calls public `prepare` in a new process
with only the independent location and current Normal signing resource. It
checks the complete recovered pair and private bytes, then starts fresh public
plan, private equality, unchanged apply, minimum-administration and existing-pair
prepare callers. It retains the exact original HEAD and unchanged source files.
Setup and cleanup have separate mutation authority; reconstruction permits only
Store reads, public key lookup and Authority decryption. Owned-prefix cleanup
runs after all original child processes join. Keep failed-run evidence and use
the existing cleanup protocol if ownership or cleanup remains unresolved.

This live selection covers the small supplied fixture. Controlled local tests
own the replacement, generated/occupied-work, refusal/restart and capacity cases.
Installed-distribution and other native-platform qualification have separate
execution requirements. See the [public process instructions](live/publicprocess/README.md#public-prepare-after-complete-local-file-loss)
for the child inputs and credential roles.

Public inspection and receipt checks cover domain metadata, Recipient-scoped
metadata, the complete retained receipt list and exact receipt detail. The live
scenario uses separate Authority, Apply, Reader and cleanup contexts. Its Reader
children use only object GETs and repeat the queries from a portable source pair
after the writer exits. The small fixture retains initialization and supplied
apply receipts and includes a granted secret and an ungranted plain entry.

Run the local selection without cloud access:

```sh
tests/scripts/test run --workflow tests/workflows/public-inspection-receipts-local.json
```

The local workflow checks catalog and workflow selection, live result consumers,
and production CLI behavior with controlled AWS/GCP responses in both Recovery
modes. The separate `public-inspection-receipts-live.json` workflow is opt-in;
prepare private inputs for existing cloud resources and isolated SDK contexts
before an authorized live run. Local checks do not
qualify cloud permissions or execute the live scenario.

The [local plugin installation workflow](workflows/plugin-installation-local.json)
uses packaged production CLIs, a controlled HTTPS catalog and public author
tools. Its `official` step checks exact preparation, reuse, pins and upgrades;
its `local` step checks ordinary rebuild capture and application isolation before
a controlled credential refusal. Its `versioned` step packages a detached private
CLI from exact local module archives with no workspace or replacements.
All three roots are included by the unfiltered
`runner` step in `canonical.json`. They run on the current native platform.
They do not establish successful live provider execution or retained provider
continuation by the production CLI.

```sh
tests/scripts/test run --workflow tests/workflows/plugin-installation-local.json
```

Stock packaged-CLI cloud acceptance uses the opt-in
[`stock-plugin-acceptance-live.json`](workflows/stock-plugin-acceptance-live.json)
workflow. Its two Recovery-enabled cells cover AWS and GCP Store/KMS, compatible
Cloudflare A/B continuation, all five output profiles across the two cells, an
independent installed manifest generator and canonical reconstruction. Each cell
uses a reusable dedicated Store bucket with a fresh prefix per invocation.
It uses SSO-based AssumeRole or impersonated user ADC, with ordinary Cloudflare/GitHub environment
credentials. Follow the [stock acceptance guide](live/publicprocess/stock-plugin-acceptance.md)
for exact claims, input preparation, limits and cleanup. The workflow does not
provision resources, log in, run OpenTofu or authorize its own live execution.

The [daily browser-login retirement workflow](workflows/daily-retirement-browser-login.json)
runs the versioned AWS retirement proof with the two daily IAM users. Each worker
checks the browser session and its assigned role using STS. Select the dedicated
suite with its [environment template](environments/daily-retirement-browser-login.example.json).
The ordinary AWS acceptance workflow continues to require its SSO source.

The [local materialization workflow](workflows/materialization-local.json) selects
request/result contracts, Recipient custody, exact dotenv bytes, native file
faults and capacity, public CLI/GC paths, and workflow/evidence consumers. Select
one named step for a focused check:

```sh
tests/scripts/test plan --workflow tests/workflows/materialization-local.json --step core-projection-identity
tests/scripts/test run --workflow tests/workflows/materialization-local.json --step core-projection-identity
```

The workflow uses the current native platform. It has no live provider effects
and does not qualify another operating system or a release installation.

Recipient file materialization uses the opt-in
[`public-configuration-materialization-live.json`](workflows/public-configuration-materialization-live.json)
workflow. Its two cells use AWS and GCP with Recovery enabled and the existing
isolated Authority, Apply, Reader, Recipient consumer and cleanup SDK contexts.
Prepare private inputs from the checked-in examples with existing resource
selectors before a separately authorized live run:

```sh
tests/scripts/test plan --workflow tests/workflows/public-configuration-materialization-live.json
tests/scripts/test run --workflow /ABSOLUTE/PRIVATE/materialization-live.json
```

The one case initializes and applies a small shared plain/secret set through the
public executable. It checks exact complete file bytes and mode 0600, unchanged
pending source edits, a GET-only plain projection and an actual denied secret
KMS call without an Authority or Recovery fallback. A fresh Reader repeats the
plain and denied-secret checks after writer exit. Application files use temporary
private directories outside retained run evidence and are removed after comparison.
Retained facts contain public identities and bounded structural observations;
they contain no materialized values or plaintext file hashes. This workflow does
not establish the pinned parser, maximum capacity, GC races or another native
platform. Local controlled tests separately cover both Recovery modes.

Public consumption manifests use the opt-in
[`public-configuration-manifest-live.json`](workflows/public-configuration-manifest-live.json)
workflow. Its four cells use AWS and GCP in both Recovery modes with isolated
Authority, Apply, Reader and cleanup contexts. Prepare a private provider
workflow using the existing resource selectors and the checked-in examples:

```sh
tests/scripts/test plan --workflow tests/workflows/public-configuration-manifest-live.json
tests/scripts/test plan --workflow /ABSOLUTE/PRIVATE/workflow-manifest-bounded.json
```

After separate live authorization, replace `plan` with `run` for the prepared
workflow. The checked-in environments are examples. Setup publishes two values
only to the matching cloud service so the AWS locator uses an acknowledged
creation ARN. It then applies three passive GitHub route declarations without
publishing to GitHub. Those fixture locations do not claim remote existence or
publication and need no GitHub token. Cleanup removes the output declaration through an ordinary apply and uses the
existing guarded deletion protocol for the two acknowledged cloud coordinates.

Reader children check the default Authority/all-authorized selection, an ordinary
Recipient, exact names, explicit empty selection, service filters and the complete
included/excluded partition. They verify exact native file bytes, mode 0600,
separate completion facts and unchanged source files. A fresh Reader repeats the
read checks after writer exit. Issuance requires observed Store GETs and forbids
KMS, output and generator effects. File contents stay in temporary private
directories outside retained evidence. Static planning does not verify current
credentials or cloud permissions. Local denial, maximum capacity and GC proofs
remain separate from this small live case.

Capacity/GC provider checks use the opt-in
[`capacity-gc-live.json`](workflows/capacity-gc-live.json) workflow for AWS and GCP
in both Recovery modes. Its checked-in environments are examples. Prepare
private run inputs with existing resource selectors, and review the
required IAM changes before a separately authorized live run. The small scenario
checks bounded inspection, protected preview, conditional deletion, complete
close, preserved values/receipts and fresh-process reads. It does not establish
joint-maximum capacity. Prepared limits and local selection are not live evidence.

Replacement scenarios qualify exact successor keys, preserve selected material
and unaffected access, and use current keys after restart. The fixture owner
delivers the qualified current public basis through durable local storage before
HEAD selection; a fresh Recipient receives it independently of the Store. Recovery
scenarios check exact retained receipts and repeated replacement without a
historical private-key inventory. The remaining deferred accepted-work
scenarios use their closed private producer and effect counter. Generated
reservation tests use the generated producer path. The native generator tests
launch a real admitted child and pass its raw return directly to Crypto. They
protect exact sources, retained values and a late-result seed before loss,
preserve occupied work through replacement, and adopt the original sealed
result in a fresh process through current keys. Only the original producer can
return its result. Fresh phases receive no producer or effect permission.

Configuration recovery joins setup and writer processes and removes their saved
local state before it starts a restricted recovery process. That process receives
only the Store location, independently chosen immutable signing resources,
explicit working credentials, new local route names and finite limits. Optional
Domain and key pins have separate cases. The process receives no saved descriptor,
caller mapping, expected values or parent oracle data.

Local cases call the production reconstruction constructors through ordinary
AWS and GCP test artifacts with controlled provider responses. These artifacts
have no private Core admission overlay. After the recovery process exits, its
parent checks the complete returned public and encrypted state and privately
compares the recovered application bytes. Separate counters cover reconstruction,
private comparison and fixture cleanup. Reconstruction must make no mutation,
signing, publication, generator or cleanup calls. Process records retain source
and artifact identities, joined phases and exact helper completion. Public
records and logs contain no recovered plaintext or private oracle paths.

```sh
tests/scripts/test list
tests/scripts/test plan --workflow tests/workflows/smoke.json --step state
tests/scripts/test run --workflow tests/workflows/smoke.json --step state
tests/scripts/test unit core/contract crypto/internal/custody
tests/scripts/test dev
tests/scripts/test check
```

The smoke workflow's `state` step selects one 32-member point fixture from the
state-smoke suite. It runs that fixture once, with the invocation's race setting and both
recovery modes, as the required smoke entry. The transient-before-send case
remains in the suite and ordinary coverage. Select `--step state` for this local
check; the complete smoke workflow also contains live AWS and GCP steps.

## Focused output contract and boundary checks

The internal output records and distinct versioned output plugin boundary have
retained unit workflows. They select ordinary package tests through
the same launcher and retain complete package/test inventories:

```sh
tests/scripts/test run --workflow tests/workflows/output-contract-unit.json --step contract
tests/scripts/test run --workflow tests/workflows/output-boundary-unit.json --step output-boundary
tests/scripts/test run --workflow tests/workflows/publication-crypto-unit.json --step crypto
```

The contract workflow covers the canonical selected output configuration,
projection, publication records and result codecs. The boundary workflow covers
`protocols/output`, `compositions/outputhost`, the output contract-test artifact,
and the AWS Secrets Manager, GCP Secret Manager, and GitHub repository,
organization and environment artifacts. It checks framing and identity refusals,
passive public normalization and action checks, credential validation before payload release,
complete payload delivery, response uncertainty and positive native child joins.
Controlled provider tests use local servers and fixtures. These workflows make
no live cloud calls and establish no live IAM or provider qualification.
The Crypto workflow selects the complete Crypto module, including private
publication payload preparation, bounds and one-use custody. Controlled dispatch
checks cover plain, secret, empty and metadata-only preparation, complete-result
identity refusals, fixed dispatch pins, cancellation and Close joins, cleanup
errors, and retained owned or reserved-slot deletion. Action capabilities and
payload bounds come from the selected plugin. Its passive action check validates
the complete target and policy before effects. These facade checks do not establish the
selected-engine/native-child integration or live permissions.

The public manifest workflow selects common request and projection checks,
plugin-owned exact JSON checks, trusted-source APIs, native file delivery, CLI
and safe telemetry checks. Runtime assurance covers authorized input and exact
delivered bytes; format correctness belongs to the renderer tests:

```sh
tests/scripts/test plan --workflow tests/workflows/manifest-local.json
tests/scripts/test run --workflow tests/workflows/manifest-local.json
```

It uses synthetic values and controlled services. Native file faults and process
cuts qualify only the recorded host tuple and filesystem. The real encoder
maximum checks transfer the same artifact backing into native delivery and use
one bounded readback window. Linux, live IAM and provider qualification require
their own execution evidence. A failed or unexecuted step establishes no claim.

When an output action or payload limit changes, update the owning plugin's
target derivation and action checks together with its independent expectations:
[`AWS`](https://github.com/enkv-sh/extensions/blob/main/plugins/outputs/aws-secrets-manager/profile/profile.go),
[`GCP`](https://github.com/enkv-sh/extensions/blob/main/plugins/outputs/gcp-secret-manager/profile/profile.go), or
[`GitHub`](https://github.com/enkv-sh/extensions/blob/main/plugins/outputs/github-actions/profile/profile.go).
The family protocol carries bounded capabilities and payload limits; the host
has no provider action catalog. Retained deletion uses authenticated canonical
target and ownership facts without the old value, executable or full old
destination settings.
The explicitly selected compatible output still validates the target and action
before private preparation.

Selected-state component tests use controlled private owners to check complete
action chains, selected-marker permission, cancellation, current-key changes,
canonical-owner occupation, blocker sets, removal and safe re-addition. They
also cover whole-plan capacity refusal before private preparation, retained
uncertain-create cleanup and cleanup-error propagation across later results.

Test assemblies install either one contract-test output child or an explicit
nonempty selection of the five official output implementations. The contract-test
child has a separate installation. Each installation binds the exact binary,
selected credential route and public contract identities, compiled command
source, pinned module graph, Go toolchain, native tuple and race mode. The builder compiles
only selected output commands. The private TEST child uses the invocation's
race setting; production implementations use the stock artifact build settings.
Controlled passive and invalid-credential checks use the named native
children and require positive joins. They do not qualify cloud permissions or
service behavior. A fixture uses a private copy of its admitted child.

Memory publication checks
exercise selected plain and secret values as separate one-entry requests,
acknowledged value and policy changes, retained deletion, no-op behavior, cold
observation and cancellation. Cold observation uses the existing fresh worker;
the zero-restored-send plan check runs in the parent. The local contract child
does not qualify production service permissions or live effects.

Shared publication fixtures cover separate plain and secret containers, a
complete two-destination group with an unknown first or last result, value and
consumer-policy changes, revocation, unqualified creation, wrong-instance
refusal, unauthorized later members, reservation retirement without send, child cancellation
and cleanup failure. Their expected vector starts from the complete fixed
requested target set, including no-op coordinates. Local conformance outcomes
do not establish a cloud effect.

Select these workflows for the affected behavior. Add other focused checks when
they cover a required interaction that the selection does not establish. Neither
a current nor a previous complete `check` is required for focused work. New
product modules and their tests require explicit admission in `moduleSources` in
[`tests/shared/runner/module_sources.go`](shared/runner/module_sources.go), which
also defines `moduleRoots`. Update that list and
[`dev.json`](workflows/dev.json), [`check.json`](workflows/check.json) and
[`canonical.json`](workflows/canonical.json) together when adding, removing or
renaming a module. The existing
[`TestSavedWorkflowSelections`](shared/runner/workflow_test.go) checks saved
workflow completeness, including one canonical unit selection per admitted
module. Discovery of a `go.mod` does not admit a module. A result must name its
exact source and assembly; a printed count alone is insufficient.

Public author modules have fixed source owners in the sibling documentation
repository. Select the SDKs by `sdk/generator`, `sdk/output` and
`sdk/manifest-generator`. The independent examples are
`sdk/examples/local-token-generator`, `sdk/examples/local-value-output` and
`sdk/examples/ini-reference-manifest`; their included service is
`sdk/examples/testservice`. Each is a separate Go module. The `sdk/` and
`plugins/` containers are not modules. Official renderers, including
`plugins/manifest-generators/generic-json`, use the same public contract.
Renderer selection is explicit; preparation has no implicit generic-JSON
installation dependency. Format-specific expected output and consumer checks
belong to each renderer's tests.

[`output-manifest-sdks-local.json`](workflows/output-manifest-sdks-local.json)
selects public contracts, module boundaries, source binding and detached kits.
The kit checks copy only registered public modules with their documented
relative layout, disable Go workspaces and module network fetching, inspect the
compiled binary's dependencies, and require refusal when a required copied
module is absent. The output kit also refuses an empty provider module cache.
Its third-party inputs must already be present at the declared versions. Public
conformance uses ordinary Go tests with the accepted race setting inside these copies; no private
runner, host, Core, Crypto or private output fixture is copied into a kit. The
project runner supervises these local commands and validates their test events.
Detached builds do not grant production catalog admission or qualify a live
provider or an independent installation.


## Daily and complete local checks

`tests/scripts/test dev` runs [dev.json](workflows/dev.json). It includes lint,
runner tests, all registered product modules, common offline checks, controlled AWS and GCP assemblies, daily ordinary
component tests, and the complete isolated hermetic scenario catalog. Ordinary
checks and isolated scenario workers use the accepted race setting. Both workflows retain
fresh children, post-exit reopens, and both applicable recovery modes. Their
activity structure and telemetry policy match; the profile determines which
ordinary tests are selected.

Declare exactly one `full_only` Boolean in the Go doc comment of each runnable
root test, fuzz target, or example:

```go
// full_only: false
func TestExample(t *testing.T) { /* daily behavior check */ }

// full_only: true
// Proves the maximum retained history; the small behavior check is TestExample.
func TestExampleMaximum(t *testing.T) { /* complete capacity proof */ }
```

`dev` selects declarations with `full_only: false`; `full` selects both values.
The marker applies to the whole root, including all subtests. Reassess it when
adding children or increasing fixture sizes.
A captured runnable declaration with missing, malformed or duplicate
classification fails preparation before tests start. There is no separate
profile membership list. Classification comes from
the host's active Go source files, including build constraints and test overlays.
It applies to unit, runner, launcher, component and controlled assembly tests,
including focused and repeated
execution. A test cannot re-enter dev through another package execution path.
Records retain the compiled inventory, classification, selection and omissions;
an omitted test is not a pass. A dev pass establishes only its selected scope.

The compiler uses the active test-file bytes captured with their declarations.
Production source files remain ordinary compiler inputs. Edits to existing test
files cannot change a prepared test's body without its classification. A new test
file added during compilation can introduce a compiled root whose declaration
was not captured. Its record has `classification_unavailable: true` and
`full_only: null`; it stays in the actual inventory and `not_selected`. It is not
assigned an ordinary or exclusive resource class. An exact known selection can
finish successfully. A whole-profile or package-only request executes known
roots, then reports incomplete coverage as a failure. An exact request for the
unavailable root fails. No test outcome or elapsed duration is invented for that
root.

When adding or changing a test, classify its purpose before running it:

- Keep ordinary behavior, error handling, recovery, ownership, process joins and
  useful small boundary checks in dev. Execution time alone is not a reason to
  remove distinct behavior coverage.
- Use `full_only: true` for costly maximum-memory or payload fixtures, many real
  history/retirement cycles, saturation of retained windows, and large capacity
  or performance proofs. Name the bound or history being proved in the comment.
- If one root mixes small behavior and costly maximum cases with independent
  fixtures, split its existing cases into separate roots. Preserve the large
  fixture and all its assertions in full. Keep coupled sequences intact and
  assess their small behavior coverage separately. Reuse existing small cases
  and fixtures; do not build a duplicate test system.
- Check that dev retains the relevant behavior or record the specific gap.
  Smaller cases do not prove the full bound. Check both profile selections and
  update scheduling estimates using the procedure below.
- If a helper root can skip only with proof from a parent test, keep that parent
  selected in each profile that selects the helper. An unexplained skip fails.

`full_only` controls selection. `exclusive` controls whether a selected component
may overlap other components. These are independent rules.
When active on the host, `TestOrdinaryOutputMemoryNativeArtifact` remains in
dev and remains exclusive. Costly output-memory proofs are full-only. Full
checks retain all active maximum tests and are suitable for a separate
long-running qualification job.

`tests/scripts/test check` runs [check.json](workflows/check.json) with the full
component inventory and scenario workers under the accepted race policy. Provider-neutral
inventory controls execute once in `assemblies-gcp`; controlled wiring
and fresh-process checks execute in each provider binary. The full offline
check runs a representative route for each distinct hermetic scenario family,
fixture capability set and recovery mode through the inventory wrapper, plus
both modes of the held-CAS concurrent writer case. Focused tests check physical
accounting, before-send inventory, unknown-effect settlement, fresh-process
inventory, delayed resurrection and exact owned cleanup. Every hermetic catalog
scenario and required mode still runs in the hermetic stage.

One invocation owns each compatible executable and helper. Selected executions
borrow the completed build. Build recipes capture compiler and native settings,
race mode, package and overlay inputs, and actual provider/plugin/output bindings.
Focus names, configured steps, profiles, result directories and resource names do
not cause another compatible build. A failed construction blocks its consumers;
independent recipes can still build. A failed test does not invalidate its binary.
Artifacts remain available until all borrowers join, then the invocation removes
them. There is no cache across invocations. Mutable fixtures, credentials,
budgets and results remain private to each execution.

Selection uses the inventory of the actual executable. The runner does not build
a generic inventory executable before the bound one. Completed runner-owned
artifacts are trusted during their invocation; borrowing does not repeat file
hashing, dependency discovery or checkout-equality checks. Source and configuration
edits do not invalidate captured selection or completed builds.

Provider, architecture and custody regressions run through explicit
`assembly-checks`, `lint` or selected test activities. A scenario run does not
execute those regressions as a prerequisite. Exact operational target, credential,
budget, protocol and cleanup checks remain at their operation boundaries.

Both commands require the installed toolchain and populated module cache and
perform no live cloud calls. There is no daily workflow wall-time cap.
The source-policy settings `unitGroupAllowance`, `runnerGroupAllowance` and
`componentGroupAllowance` default to `0`: no cumulative suite deadline. A positive
duration re-enables the limit for that suite's preparation
and execution. Prepared repetitions and partitions share the same remaining
allowance; it does not restart for a test or repetition. These are source
settings; changing them requires rebuilding the runner. Parent cancellation and
any earlier parent deadline still apply when the suite setting is zero.

Preparation commands have an independent 15-minute limit at dispatch. This
includes Go metadata, compilation and compiled inventory, source Git commands,
lint, formatting and native bootstrap compilation. Admission and tool-lease
waiting do not spend that command limit. Actual test execution uses its own
process limit. Initial supervisor setup gives its compiler and native finalizer
15 minutes each after machine admission. Expiry starts bounded stop and join
attempts; an uncertain result still retains the machine lock.
Each active top-level component test retains 90 minutes. A hermetic scenario
has one five-minute case deadline; its writer and fresh readers use the remaining
case time. Live and fuzz budgets are separate and remain finite.

Each active top-level runner test has a 15-minute limit. Its package process
retains bounded startup, idle and shutdown time, a finite package backstop and
settlement grace, subject to an earlier parent deadline or cancellation.
Complete runner checks place normal root/helper bundles into bounded workers,
balanced by recorded top-level durations. The selected step's assigned share
sets the worker count, and each worker receives one inner Go share. Compatible
selected roots within a worker share a package process. Required helpers stay
with their proving parents. Concrete native or memory isolation and incompatible
literal child selections retain separate processes. Coverage profile does not
require exclusive resources. Unknown tests use a one-second estimate and remain
selected.
Launcher checks follow after all groups join. The ordinary result records group
membership, estimated and actual duration, outcome, and each command's evidence.
Maintain these weights through the [scheduling estimate procedure](#maintain-scheduling-estimates).
An earlier parent
deadline or cancellation still applies. Other per-process deadlines remain in
force. Component evidence retains group and test durations, separate
capacity-phase timings, and the exact selected inventory.

The native supervisor owns the machine lock and, for live work or cleanup, the
live lock. Ready work prepares and runs before unrelated later groups prepare.
Compilation uses the shared machine lock. Ordinary execution also uses that
shared lock; explicitly exclusive work acquires the exclusive machine lock for
its own execution. `full_only` does not change this resource class.
Before each class transition, all active compiler and test consumers join and
the supervisor releases the current tool leases and machine lock. It then takes
the required live and machine locks. Completed builds remain available across
these phases.

The per-invocation memory guard is 8192 MiB for normal work and 24576 MiB for
exclusive work. An explicit lower `--memory-limit-mib` remains effective. One
native census observes the supervisor and all its descendants through final
settlement. Resource transitions do not create a new invocation allowance or
restart elapsed-time budgets. These limits are not an aggregate host-memory budget. Stable lock
files under `/var/tmp/enkv-test-resources-<uid>` coordinate cooperating checkouts.
The kernel releases locks on owner death; this does not prove process joins or
authorize live cleanup. Keep the lock-file inodes at release. Do not move or
unlink them as stale claims. Inventory and generator-journal transaction locks
remain separate.

The native supervisor owns the actual preparation and execution tool leases.
Checkout-specific tool-lock files share the stable resource directory, so a
changed `TMPDIR` cannot select a different lock for the same checkout. Separate
worktrees use distinct tool locks. The runner reports joined consumers through
a borrowed phase. Before a machine-class transition it has no active compiler
or test child and no tool lease. The current execution lease remains with the
native owner until that phase's consumers physically settle.

Each invocation keeps temporary build and test files in one private stage
outside the checkout. The supervisor prefers `TMPDIR` when its physical path
and every ancestor are owned by the current user or root and have no group or
other write permission. Otherwise it tries the home directory under the same
checks. An unsuitable home and temporary directory cause refusal. A failure
after choosing a parent does not cause a retry on another filesystem. After
positive joins, cleanup can restore owner permissions on directory descendants
to remove read-only fixture builds. It leaves file modes and external symlink
targets unchanged and removes only the current stage with its verified identity.

The native supervisor and its direct runner exchange phase requests, admissions
and one terminal result through two private inherited pipes. The runner marks both
descriptors close-on-exec before child commands. This channel replaces child
tickets and the registry. A terminal result still requires native physical
settlement. Unknown joins retain current scratch and live recovery facts.

Initial supervisor setup, including its compiler and native finalization, is
outside the invocation memory guard. Setup still takes the exclusive machine
lock before its first compiler and requires positive process joins. The
production build allowance is four. The lock-owning shell directly starts and
waits for the compiler and native finalizer. Before publication, the native
finalizer checks the exact compiler group is absent and validates its
direct parent and that parent's child set. If a compiler fails before a native
candidate can make those checks, finite stop/wait attempts cannot prove group
absence. If a compiler or finalizer has started and native settlement remains
unavailable, setup reports incomplete work and keeps its owner and lock alive.
Terminating that owner releases the OS lock without proving settlement.
A captured-binding or native-target failure after native verification remains a
failed, settled setup. Checkout edits after compilation do not block publication
of the completed candidate. Setup needs no `ps`.

`--parallel` accepts 1–4 and defaults to 4. Current workflows use
`execution.parallel`; `--lanes` and saved workflow `execution.lanes` are refused.
Historical recovery records retain their original spelling without granting
current capacity. A parent divides its allowance among active independent
jobs. A Go test command's package concurrency multiplied by its per-package
test concurrency cannot exceed its assigned share. Build commands use at most
that share. Declared `parallel_group` steps, independent ordinary/component
repetitions and hermetic scenario cases can overlap within the same allowance.
Other workflow steps and cases within a live step remain sequential. Product
participants inside a scenario keep their required concurrent behavior even
with `--parallel=1`.

A result establishes only its exact selected tests, source observations and
native platform. Missing prerequisites, incomplete joins and unknown required
cleanup remain incomplete; an exit code alone cannot establish a pass.

Runner fixtures that enforce fixed native memory bounds retain their own test
processes, so earlier roots cannot contribute retained heap. Normal roots use deterministic placement across and within packages, within
the selected step or repetition's assigned share. Each worker can run several
compatible roots in one process; all workers borrow the completed package build.
A specific isolation, crash/restart or measurement requirement can require a
separate process. Incompatible literal child filters run in sequence under
their root's assigned worker. Each active top-level test
has its own deadline, including its subtests and cleanup. Package startup and
shutdown remain bounded, with finite termination grace and any enabled cumulative
limit. Selected roots, subtest events, the parallel allowance and fixed native
memory bounds remain checked. A single focused root keeps its literal selection.

Current scratch and live recovery retain exact target ownership, required
credentials, finite budgets and positive process quiescence. Unsupported records
or missing ownership refuse before effects. A cleanup operation cannot restore
a test campaign or replay a Product operation.
Ordinary execution returns current results and terminal output. There is no
qualification mode or `--evidence` option. The engine has no
retention allowance, pins, keep/release commands or old-result cleanup service.

Public-configuration cases retain a closed evidence set at
`evidence/public-configuration/<case sequence>/`. The set contains the exact
joined native captures, original typed write and condition facts, object
ownership and conditional cleanup observations, and a hash-bound manifest.
Each capture remains a separate file, with at most 64 files of 1 MiB each.
The producer saves original token bytes before legacy inventory JSON encoding;
a missing source cannot be filled from a later cleanup token. Private credentials,
value bodies and build files are removed only after the required local evidence
is saved, checked and joined. Incomplete evidence keeps the private state for
review and does not prove a successful cleanup or permit a new attempt.

Runner self-tests consume returned current results. Their current scratch has an
explicit owner and is removed only after all consumers join. This applies to
fixtures in the real checkout and in temporary repositories. A failed assertion
does not prove that consumers stopped. Unknown joins preserve current scratch;
they cannot become successful cleanup. Live recovery fixtures keep their durable
packet separate from disposable build and test scratch.

Both workflows have eight explicit steps:

```text
lint → runner → unit → [assembly-common | assemblies-gcp | assemblies-aws] → components → scenarios
```

The bracketed assembly steps share `"parallel_group": "assemblies"`. The
parallel allowance admits one, two or three concurrent assembly jobs. The
parent divides the allowance among active jobs. With `--parallel 4`, three
selected jobs receive shares of two, one and one.
Each step retains its own ID, status, timing, log and evidence. The next step
starts only after all started assembly jobs have stopped. A contained local
failure retains its result while independent jobs and later steps continue.
Parent cancellation, invalid inputs/results, output faults or uncertain process
settlement stop dispatch and join started work before cleanup.

The `components` step selects ordinary Go tests. The `scenarios` step selects
isolated cases from suite files. Scenario runs do not execute component tests as
preparation, including direct `run --suite ...` commands.

The daily workflow makes component scope explicit:

```json
{"id": "components", "kind": "component-tests", "profile": "dev"}
```

Its `scenarios` step keeps the same suites, environment and recovery mode as the
complete check. The complete check uses component `"profile": "full"`. All
selected steps use the invocation's accepted race setting.

Workflow-level `execution` supplies the common parallel and memory policy;
see the execution guide above. Component groups and independent runner work
use that allowance. Required in-test participant concurrency remains intact.

Each selected output memory root, including the generated maximum, uses its
own group and a fresh supervised process. These memory groups run one at a
time, with no other component group active. Explicitly exclusive roots also
run alone after normal workers join. Normal root/helper bundles, including
full-only roots, are distributed between the assigned workers. Compatible roots
in each worker share a process. Separate processes are used for concrete
isolation needs and literal child selections that cannot share a Go `-run`
expression without selecting extra children; those child partitions keep their
worker and run in sequence. Top-level tests keep all their subtests; helpers stay
with their proving parents. The resolved parallel allowance limits active jobs,
not the number of selected groups. Before dispatch, the runner reserves enough
diagnostic space for that group's test and conversion commands.

Preparation uses the host's active compiled inventory. The profile selects
roots from that inventory by their `full_only` declarations. Platform-specific
Go files can exclude native proofs from the inventory; they do not produce
skipped results. Each selected memory root and its subtests retain their
exclusive process placement. Each group's actual test results must match its
assigned inventory; the combined results must match the complete profile
selection.

Ordinary weights come from measured race-test durations; maximum-case weights
can use provisional estimates until a completed run supplies their durations.
New and short tests use a one-second weight. Weights affect scheduling and
reported cost only. They cannot omit a test or remove a dedicated memory group.

Each group uses a separate supervised process and independent output capture.
A contained child failure permits independent active and queued groups to
finish. Stop conditions still cancel active work and stop dispatch. The runner
joins all started processes before it returns. Progress and result records show the
resolved parallel allowance, group test counts, estimated cost and actual duration.

```sh
tests/scripts/test run --workflow tests/workflows/dev.json --step components
tests/scripts/test run --workflow tests/workflows/dev.json --step scenarios
```

Selecting one step runs only that step. Within one workflow, scenarios reuse
a compatible assembly from an earlier component step. Without one, scenarios
prepare their own actual binary. Build compatibility uses the captured recipe,
including compiler, race and binding settings. No previous workflow result is
reused. A scenarios-only result describes its selected scenarios; select component
tests separately when their assertions are required.

### Maintain scheduling estimates

Apply this procedure when adding, renaming, moving, removing or changing runner
or component tests, and after their affected checks complete. Recorded durations
are observations; estimates are inputs to later group placement. An estimate is
not a time limit or a guarantee that groups will finish together.

| Scheduled tests | Estimate file and key | Measurement source |
|---|---|---|
| Runner groups | `tests/shared/runner/runner_estimates.go`; full package path, `\x00`, top-level test name | Returned ordinary `tests[]` rows for `runner-tests`; `outcome: "pass"` and non-null observed `elapsed_seconds` |
| Components | `tests/shared/runner/component_estimates.go`; top-level test name | Returned component `tests[]` rows; `outcome: "pass"`, `elapsed_observed: true` and observed `elapsed_seconds` |

Use the selected invocation's retained ordinary results or original structured
Go test events. Component rows distinguish observed elapsed time from an
unavailable duration. Historical qualification files remain valid for their
original measurements; new runs do not publish them.

Launcher checks, unit modules, assembly checks, scenarios, lint and fuzz targets
do not use these maps for placement. Their measured durations remain in their
own results. Copying an assembly or launcher duration into a component or runner
map does not improve its scheduling.

1. **Reconcile changed identities.** New roots use the one-second fallback until
   measured; an explicit provisional estimate is allowed when justified and
   identified as such. Remove a deleted root's key. For a rename or package move,
   remove the old key and use the new identity. Carry a prior measurement across
   only when the test work is unchanged. Preserve helper/proof colocation and
   exclusive memory groups; estimates do not define those rules.
2. **Use the affected check already required for the change.** Read its linked
   evidence after actual command completion. Normal refresh uses a passed,
   race-enabled local check with valid test events and joined processes. A full
   workflow is not required solely to collect estimates. Keep failed attempts
   and their recorded outcomes unchanged.
3. **Select complete parent measurements.** Use a passing top-level row with an
   observed, finite, nonnegative elapsed duration. A focused complete parent can
   supply its measurement. A focused child cannot: its parent row measures only
   that selected subtree. Likewise, do not replace a complete parent's estimate
   from a filtered variant, failed, skipped, cancelled or incomplete execution.
   Use the test's `elapsed_seconds`, not timestamp subtraction, group duration,
   command/build time, a phase timing or a sum of subtests. Converted timestamps
   and parallel waits can differ from the recorded test duration.
4. **Update only measured roots.** Round the most recent eligible measurement
   up to whole seconds, with a minimum of one. An omitted key represents the
   one-second fallback. Repeated executions are separate observations; use the
   last eligible complete-parent result, not the sum of repetitions. Preserve
   estimates for roots that the run did not fully execute. Absence from `dev`,
   a host's active source set or a focused selection is not evidence that a test
   was removed.
5. **Record provenance.** In the owning work report, record the source result
   path and hash, tested source, toolchain, native platform, race setting, parallel
   allowance, selection and changed estimates. Keep observations from different
   environments distinct. A prior estimate remains approximate until a new
   eligible observation replaces it; describe any known stale or provisional
   entries instead of claiming current measurements.
6. **Check the edit.** Verify changed keys against the owning current inventory
   or explicit source rename/removal. Check measured values against their
   eligible results and rounding rule, carried values against their prior
   measurements, and provisional values against their recorded justification.
   Run `gofmt` on changed Go estimate files
   and inspect the diff. No scheduling logic, selected coverage, race setting,
   timeout or memory-isolation rule should change with a weight refresh.
7. **Stop after maintenance.** A pure estimate update does not require another
   check. Record the tested source and the later estimate-only delta separately.
   At the next required run, compare estimated and actual group durations and
   refresh eligible measurements again. Persistent imbalance can be reported
   for later work; it does not authorize repeated runs, timeout increases or
   splitting test roots within this maintenance procedure.

## Native platform checks

Use the same workflow on native `darwin/arm64` or `linux/amd64`. Go selects the
host's active source files; `dev` and `full` select from their declarations.
No platform profile or platform test-name list controls selection. An exact focus must
exist in the active compiled inventory. A root excluded by Go build constraints
cannot satisfy a requested focus.

The native output-memory proofs and their native helpers live in
[`memory_measurement_darwin_arm64_test.go`](hermetic/memory_measurement_darwin_arm64_test.go)
and [`output_transition_memory_darwin_arm64_test.go`](hermetic/output_transition_memory_darwin_arm64_test.go).
Their file suffixes restrict them to Darwin arm64. The ordinary native
output-memory proofs require exactly `go1.27.3` on that tuple. Their runtime
eligibility checks also enforce the audited build settings. Portable proof
arithmetic, synthetic eligibility checks, observer and small behavior controls, and the
generated maximum remain in portable files. Tests keep their `full_only`
declarations and memory process placement on each active source set.

The launcher requires Go 1.27.0 or later and a populated local module cache.
The current generator and output host constructions require cgo and a native C
toolchain. Linux uses glibc 2.34 or later for
`posix_spawn_file_actions_addclosefrom_np`; Darwin uses
`POSIX_SPAWN_CLOEXEC_DEFAULT`. These child actions close every unassigned
inherited descriptor while preserving the parent's descriptor flags and
ownership. A descriptor inventory or a limit chosen from the parent's current
open files cannot establish this boundary.

Native Linux needs execution evidence on its exact native build environment.
Record the OS, architecture, toolchain and libc environment. A Darwin result or
Linux cross-build does not qualify native Linux behavior. A focused result
establishes only its selected scope on the recorded source and host.

The generated maximum component proofs use in-process generator fixtures and
report fixed native byte charges. The native host unit measures one child.
These checks do not measure heap and RSS for all concurrent native children;
that capacity qualification remains separate.

Native file checks bound acquisition and reads, require regular files where the
input contract requires them, and check exact input parsing and artifact digests.
Credential disposal clears the complete owned buffer. These checks assume
operator-controlled local files and directories. Protection against hostile local
users, mixed-trust paths, and telemetry-file access by other local users is
outside the current support boundary. Local file checks do not authorize an
enkv operation or prove a deployed permission profile. GCP service-account
parsing clears owned parse buffers; accepted PEM input is retained by the pinned
SDK for token refresh and is outside that buffer-disposal claim.

## Workflows

A workflow is an ordered list of test activities. Its optional `profile` is
`full` (the default) or `dev`; `dev` permits only hermetic scenario runs. A suite
is a list of individual
scenario IDs. Both JSON formats accept an optional `description` for the reader;
it does not change selection or execution. A workflow's `run` step combines its suites into one scenario run
per selected recovery mode, with one environment, one smoke check and one budget
per run. Each step can use different
suites, parameters, telemetry and limits. Each saved suite declares the complete
union of roles that its scenarios can use. Duplicate scenarios across the selected
suites are refused; use `repetitions` when repeated execution is intended.

[`canonical.json`](workflows/canonical.json) is the complete reference for
supported checks. Its steps select lint, runner tests, each registered product
unit module, assembly checks, hermetic components, all supported fuzz targets
and hermetic suites, the base GCP and AWS live suites, and the
generated Cloudflare, Authority operator, publication and public-configuration
live suites in both recovery modes
on each provider. Each live cell has a finite allowance. Each unit module includes its packages recursively. Formatting,
dependency, vet, custody and controlled-provider checks remain in lint and
assembly activities.

[`check.json`](workflows/check.json) selects all local checks except fuzz;
[`dev.json`](workflows/dev.json) derives ordinary test selection from `full_only`
and runs the same hermetic scenario catalog. Both workflows use the host's
active Go source files. [`fuzz.json`](workflows/fuzz.json) selects
only the three fuzz campaigns. [`live.json`](workflows/live.json) selects all
supported GCP and AWS live scenarios, including generated Cloudflare,
Authority operator, publication and public-configuration cells. `canonical.json`
can run every activity when all live inputs exist;
the focused workflows let each validation stage run separately.

### Public configuration workflow

[`public-configuration-live.json`](workflows/public-configuration-live.json)
selects the public init, supplied apply and portable Reader scenarios for both
providers and Recovery modes. These opt-in cases use isolated AWS SSO or GCP user
ADC contexts, pre-existing keys and exact role permissions. Follow the
[process and operator instructions](live/publicprocess/README.md) for resource
inputs, finite limits, captured evidence and cleanup. The suite includes the
real secret change, independent Recipient/Recovery byte checks, GET-only trust
transfer, read-only sources and controlled response faults. Local readiness
checks do not prove live permissions, login success or second-machine execution.

[`public-configuration-functional-live.json`](workflows/public-configuration-functional-live.json)
selects the ten functional public configuration cases with isolated AWS
AssumeRole or GCP impersonated user ADC contexts. Recovery-disabled cells omit
the two enabled-only denial cases. The workflow reuses pre-existing keys and
requires prepared IAM permissions; it performs no provisioning or login.
Its results do not establish the separate SSO/direct-user ADC discovery case.
The original public workflow retains that case and its exact login routes.
The [operator workflow](workflows/public-configuration-operator-live.json)
adds eight cells: four local credential sources, each with both Recovery modes.
It uses one principal for authentication and public flow checks. All three public
configuration workflows are registered in the canonical and opt-in live inventories.
Use the [functional environment examples](live/publicprocess/README.md#resources-and-login-contexts)
and the same finite limits and owned cleanup rules.

### Publication subjects and qualification

State backend, execution mode and output destination are separate choices.
A step named `aws-state-output-publication-positive-disabled` uses AWS State and checks
AWS Secrets Manager, all three GitHub scopes and the mixed destination case.
Its GCP counterpart uses GCP State and GCP Secret Manager with the same GitHub
scopes. The State label does not imply that all output effects use that service.

| Subject and location | Mode and State backend | External services used during execution | Assurance |
|---|---|---|---|
| GitHub adapter controls: [`GitHub output implementation`](https://github.com/enkv-sh/extensions/blob/main/plugins/outputs/github-actions/internal/github), selected by [`output-boundary-unit.json`](workflows/output-boundary-unit.json) | Local controlled transport; no live State | None | API request and response rules, ownership evidence, bounds, cancellation and no replay after an uncertain effect; no live permissions proof. |
| Native child controls: [`compositions/outputhost`](../compositions/outputhost), selected by the same boundary workflow | Local installed native children; no live State | None | Framing, passive family checks, credential gates and positive child joins; no real service effects. |
| Output records and Crypto: [`output-contract-unit.json`](workflows/output-contract-unit.json), [`publication-crypto-unit.json`](workflows/publication-crypto-unit.json) | Local package controls; no live State | None | Selected output records, result codecs and private payload custody. |
| Shared local publication: [`publication.json`](suites/publication.json), in `dev`, `check` and canonical `scenarios` | Hermetic memory State; conformance output child | None | Selected publication behavior, complete result vectors, refusal, reconstruction and joins; no production output service qualification. |
| All live publication: [`publication-live.json`](workflows/publication-live.json), also included in `live` and canonical | Live AWS or GCP State | State backend APIs, that backend's Secrets Manager service and GitHub | Existing cloud, GitHub and mixed destination cases in both recovery modes. |
| GitHub live publication: [`github-publication-live.json`](workflows/github-publication-live.json) | Live AWS or GCP State | State backend APIs and GitHub | GitHub repository, organization and environment cases only; no cloud output or mixed destination qualification. |
| Generated lifecycle and generated recovery: `*-generated-lifecycle-{disabled,enabled}` in `live` and canonical | Live AWS or GCP State | State backend APIs and Cloudflare | Generator lifecycle and recovery behavior; this is separate from GitHub output publication. |
| Authority operator: `admin-*` in [authority-operator-live](workflows/authority-operator-live.json), `live` and canonical | Live AWS or GCP State | State backend APIs only; controlled generated producer | Actual administrative CLI commands, exact signed selection and private Recipient preservation after writer exit. |

The publication suites have explicit ownership:

- [`publication-aws-positive.json`](suites/publication-aws-positive.json) and
  [`publication-gcp-positive.json`](suites/publication-gcp-positive.json) own
  their cloud output lifecycle cases.
- [`publication-github-positive.json`](suites/publication-github-positive.json)
  owns the three GitHub scope lifecycles.
- [`publication-mixed-destinations.json`](suites/publication-mixed-destinations.json)
  owns the State backend's cloud output combined with all three GitHub scopes.
- `publication-{aws,gcp,github}-later-member-refusal.json` own the corresponding
  first-member acknowledgement followed by later-member admission refusal.

`publication-live` selects the same explicit publication steps as the
aggregate workflows in both recovery modes. `github-publication-live`
uses those same State/backend/mode cells with only the GitHub cases per run.
These are alternate focused views; the aggregate workflows do not run them as additional steps.

Positive and mixed cases retain the `positive` fixture namespace. Later-member
refusal cases retain the distinct `ambiguity` namespace. That historical name
does not mean that these cases inject a lost provider reply. Their assertion is
later-member admission refusal after the first complete acknowledged chain and
owner retirement. A GitHub acknowledgement or secret metadata observation does
not prove plaintext consumption by an Actions job. Cloud lifecycle consumers
check actual values; the GitHub cases establish only the evidence available
through their selected API and support-record checks.

For a local boundary check, use the command in the focused output section above.
For a live selection review, use:

```sh
tests/scripts/test plan --workflow tests/workflows/publication-live.json
tests/scripts/test plan --workflow tests/workflows/github-publication-live.json --step gcp-state-output-publication-positive-disabled
```

Planning validates configured selection without opening credential files. Live
execution still requires valid State and output inputs, finite limits and
separate authorization. Replacing `plan` with `run` executes the selected live
cells. A focused pass qualifies only its selected cases. Other required live
cells and local checks need their own results.

Copy this reference and remove steps or suites for a smaller workflow. File
references are relative to the workflow file. Environment files resolve their
credential references relative to themselves. The base cloud steps use
`tests/environments/gcp.json` and `tests/environments/aws.json`, prepared privately
from the examples with replacement keys available. Generated cloud steps use those same
domain environments and a separate ignored `tests/environments/cloudflare.json`
for Cloudflare inputs. The base steps reference
`tests/live/limits/example.json`; the generated steps use
`tests/live/limits/cloudflare.json`; administrative and public configuration
steps use `tests/live/limits/public-configuration.json`. Review the finite allowance before a live
run. Each live cell gets its own allowance. These are explicit check
selections, not an enumeration of every value entry count or repetition value.

```sh
tests/scripts/test plan --workflow tests/workflows/canonical.json
tests/scripts/test plan --workflow tests/workflows/canonical.json --step gcp-recovery-enabled
tests/scripts/test run --workflow tests/workflows/canonical.json --step unit-core
tests/scripts/test run --workflow tests/workflows/live.json --step gcp-generated-lifecycle-disabled
```

`--step` selects one step by ID. Unselected cloud steps do not load their
environment or limits files. The installed supervisor handles `plan` before
bootstrap/runner compilation or resource admission. It reports requested
selection, profiles, race settings, configuration paths and finite limits without
opening credentials, building, starting tests or waiting for execution locks.
Compiled test existence, classification and helper closure remain unresolved
until `run`. Supervisor installation is a separate prerequisite; preview does
not build a missing installation. Contained local failures remain visible while
independent work continues after settlement, including when the workflow has a
later live step. Within a live step, a failed case permits later independent
selected and authorized cases only after known effects, complete cleanup, positive
joins and durable result records, within the remaining allowance. Unknown effects,
incomplete cleanup, failed required records or unjoined work stop affected dispatch.
There is no automatic failed-case or workflow retry.

Every `run` step must set `recovery_mode` and inherits the invocation's race
setting. Per-step `race` fields are rejected. Cloud steps accept `enabled`, `disabled`
or `both`. Hermetic steps accept the same values. A single mode selects only
that mode's declared writer phases and fresh children; `both` retains all
declared modes. Reconstruction cases use only their declared provider/mode
cells. For example:

```json
{
  "id": "gcp",
  "kind": "run",
  "suites": ["../suites/accepted-work-recovery.json"],
  "environment": "../environments/gcp.json",
  "recovery_mode": "both",
  "limits": "../live/limits/example.json"
}
```

For an ungrouped cloud step, `both` resolves into two sequential runs: `gcp-enabled` then
`gcp-disabled`. Their records retain `configured_step: "gcp"`, and `--step gcp`
selects both. Both modes are validated before either starts. Each run has its
own smoke check, allowance, object prefix, evidence and cleanup. A failure,
including a cleanup failure, stops the workflow before the next mode starts.
The generated IDs must not match another configured step ID. The saved live
workflows use explicit mode IDs instead.

The saved `live` and `canonical` workflows declare only two live pairs:
`gcp-recovery-disabled` with `aws-recovery-disabled` in `recovery-disabled`, and
`gcp-recovery-enabled` with `aws-recovery-enabled` in `recovery-enabled`.
All other live steps run sequentially, including generated-lifecycle, operator
and publication steps. The `publication-live` and `github-publication-live`
views have no parallel groups. Different step IDs or cloud names do not establish
isolation when steps also share Cloudflare or GitHub.

Each pair is contiguous inside its recovery-mode block. The disabled pair and
the other disabled steps finish before the enabled pair starts. When both pair
members are selected, the parent divides the shared parallel allowance between
them. With `--parallel 4`, each receives a share of two. Selecting one step
retains its standalone capacity. Each step keeps its own run ID, namespace, limits,
telemetry, results and cleanup. `--parallel 1` serializes group members; two or more
slots allow both pair members to run together. These are step groups, not groups of individual scenario cases.
A step's cases run in order. All started disabled steps must finish before any
enabled step starts. Failure stops queued work, cancels active peers and joins
them before group cleanup. Shared preparation files remain owned until those
joins complete.

A live group requires full profile, finite limits, one explicit recovery
mode and no repetitions. It cannot mix assembly and live steps or recovery modes.
Each step retains its own finite cloud allowance; a group does not combine these
allowances. Account quotas still apply to concurrent steps. Local scheduler
checks do not qualify actual cloud concurrency or permissions.

Cases that do not support the selected mode appear in `schedule.not_applicable`;
they are not counted as passed. The remaining cases run normally. If no selected
case applies to a mode, planning fails before execution, including when that mode
is one half of `both`.

Interrupted or failed campaigns have no restoration command. Use the standalone
cleanup command with the retained live run ID and a new finite cleanup allowance.
That allowance funds cleanup only; it does not reset the original Product budget:

```sh
tests/scripts/test cleanup RUN_ID --limits /ABSOLUTE/PRIVATE/limits.json
```

Cleanup reads supported historical run/case records, exact owned inventories and
required join/quiescence evidence. It does not reconstruct a campaign or replay
Product tests. Source edits and original test-binary equality do not grant or
remove cleanup permission. A changed target, unsupported record or operation,
missing ownership or absent quiescence refuses before effects. Supported explicit
cleanup grants remain limited to their recorded target and finite attempt budget;
a later cleanup pass does not erase an earlier failure or unknown effect.

After cleanup, select the remaining tests in a new invocation. Historical passes
and failures remain history. Product crash/recovery scenarios, including declared
same-domain recovery, retain their own selected behavior and limits. Use
`--step <configured-id>` to select one step; its result has only that selected scope.

| Step kind | Selection and settings |
|---|---|
| `unit` | Optional `packages`: logical module/package selectors such as `core/contract` or `providers/gcp`. A module selector selects its packages recursively; omitted selection tests all product modules. Optional saved `package` selects one exact admitted package; optional `tests` selects literal test paths within it. |
| `runner-tests` | Test the coordinator, records, catalog and launcher. Optional `tests` selects literal paths, each resolved to its unique artifact owner. |
| `lint` | Existing complete formatting and lint checks. |
| `assembly-checks` | Required `responsibility`: `common`, `gcp` or `aws`. Optional `parallel_group` joins contiguous assembly steps with distinct responsibilities. Common checks every registered module dependency/vet closure and the offline Cloudflare artifact. Each provider checks its bound assembly; GCP owns neutral inventory once; its representative scenario wrapper declares `full_only: true`. |
| `fuzz` | Optional `targets`: `format`, `contract`, `crypto`; omitted selection runs all three. Each campaign keeps its existing ten-minute generation limit. |
| `component-tests` | Required `profile`: `dev` or `full`. Optional `tests` selects literal root or child paths. Optional `parallel_group` joins contiguous, unrepeated steps with literal ordinary selections. The group divides the shared workflow parallel allowance among active steps; memory proof roots and their subtests remain exclusive and cannot join. Each focused record proves only its requested subtrees and cannot replace complete-profile results. Workflow `execution.parallel` supplies the parallel allowance. Run selected hermetic components without isolated scenarios. |
| `run` | Required `suites`, `environment` and `recovery_mode`; live requires `limits`. Optional `parallel_group` joins contiguous live steps with the same explicit recovery mode under the shared parallel allowance. Optional `smoke_policy` (`separate-point` by default), `repetitions` (1–100, default 1), `telemetry_config` (JSON file path), `log_level`, and `additional_providers` for a selected live generator suite. The only supported additional provider is `cloudflare`. Hermetic steps refuse this field. |

Saved `repetitions` applies to `unit`, `runner-tests`, `component-tests` and
`run` steps. Its range is 1–100; omission means 1. `plan` and `run` refuse
`--repetitions`. Select a repeated step by its configured step ID.
Repetitions keep the same invocation parallel and memory allowance;
required participant concurrency within a test remains intact.

Repeated executions use fresh processes and separate mutable fixtures.
Independent ordinary and component repetitions can overlap within the shared
parallel allowance and reuse an eligible immutable build only within that
workflow invocation. Exclusive memory proofs run alone. Builds use captured
configuration; later source edits do not invalidate them. An actual incompatible
build recipe needs its own construction. Accepted race settings remain fixed
for the invocation.
Each execution retains a separate scalar result. Ordinary/component groups and selected
scenario cases report requested N and completed K. K counts started terminal
executions with positive participant joins. A joined failed execution increases
K and still fails. Missing start or join evidence does not increase K. An
incomplete diagnostic group cannot pass. A contained local failure permits
later configured repetitions and independent steps; a stop condition cancels
peers and stops dispatch. Started work joins before the next workflow step.
Results retain selected order. There is no automatic retry.

Each completed scenario case saves its evidence and telemetry before its
eligible disposable files are removed. Shared builds remain available through
their last consumer. Unresolved cleanup or required storage failure stops
further executions. Recovery material and incomplete evidence remain retained.

The [diagnostics workflow](workflows/diagnostics.json) saves four small literal
selections: one unit child, one runner test, one supplied-candidate case and one
component test. Each requests three executions. Its scenario step precedes the
focused component step and selects the common local telemetry file. Focused
passes do not establish complete component, local or live qualification.

```sh
tests/scripts/test plan --workflow tests/workflows/diagnostics.json
tests/scripts/test run --workflow tests/workflows/diagnostics.json --step token-validation
```

Telemetry defaults to a WARN stderr console, with metrics and traces off and no
file exporter. Set `"telemetry_config": "../telemetry/local.json"` on a run
step to collect WARN and higher logs, metrics and traces with sample ratio 1
through the local file exporter. Saved instrumented workflow run steps use this
one file for both hermetic and live runs. Exporter routes are an independent
configuration choice. Use `../telemetry/noop.json` for the defaults.
Workflow `telemetry_config` paths are relative to the workflow file. Both `plan`
and `run` accept `--telemetry-config <file>` with `--workflow`. This selects one
complete configuration for every selected `run` step and replaces its workflow
reference. The replaced file is not loaded. Command-line paths are relative to
the invocation working directory. Unselected run steps do not load telemetry
configuration; these overrides do not change the workflow's step selection.

Use `--log-level <level>` to set the common log threshold. It takes precedence
over a run step's `log_level`, then `ENKV_LOG_LEVEL`, the selected configuration's
`logs.level`, and the default `warn`. Only the effective level is validated;
other configuration structure and values must still be valid. A level override
does not select metrics, traces or additional export routes.

Configuration also reads the documented `OTEL_SERVICE_NAME` and
`OTEL_RESOURCE_ATTRIBUTES` startup variables. It does not change the parent
process environment. Run preparation and process isolation remain part of the
existing runner. Selecting a smaller suite does not remove those checks.
Budgets apply once to each cloud mode, shared by all its suites. `both` permits
twice the configured allowance in total, with separate limits for each mode.

Plans and results show the effective log threshold, trace sample ratio,
selected destinations for each signal, and the source of configuration and
level overrides. They omit exporter names, endpoints, headers and private
paths. Historical or incomplete display metadata is marked unavailable.
Reports keep Product assertions, measurement completeness and delivery status
separate. Delivery units are log records, metric batches and trace spans;
do not add these counters together. Missing selected delivery claims remain
incomplete, with unavailable counters.

Three different conditions can make telemetry incomplete. A phase with required
operation measurements must retain a positive observation from its execution
owner. A cached-state assertion does not need an artificial operation metric;
real Consume, Open and receipt checks do. Delegated work keeps the exact joined
child's observations. Separately, diagnostic capture can drop a record when its
lock is busy or its bounded buffer is full. After severity filtering, each output
queue can also drop a record, or its writer can fail. Reports preserve these
counters and the known failure reason separately. All accepted file records
being written does not prove lossless capture. Capture-drop counters do not
identify the lost record's severity. Keep passed assertions, missing required
observations, capture loss and output loss distinct when reporting a run.

Each writer, fresh process and cleanup process owns its observability runtime
and invocation span. Product operations use that worker's context. Invocation
and worker IDs correlate processes; separate workers do not share one parent
trace tree. The coordinator, build tools and individual assertions do not gain
spans merely because a telemetry configuration is selected. Successful
operations can have spans and metrics without WARN logs.

Select an `otlp_file` exporter to write bounded worker OTLP JSONL files. Each
worker owns separate `0600` files in its private directory. Capture drops new
records when its lock is busy or bounded buffer is full; output queues can also
drop records after capture. A killed worker can leave a valid
prefix and an incomplete final status. Current consumers check worker output
after positive joins and before disposal. Hermetic finalization removes the
current owner after those consumers finish, including when telemetry is
incomplete. It does not copy telemetry into a public result tree. Live recovery retains only files required by its separate recovery
obligation. Keep worker files local.

Workflows return selected work, step times and
`passed`/`failed`/`not_run`/`not_selected` outcomes directly. Live workflow
records remain available to exact cleanup. After cleanup, remaining tests require
a new invocation.
Provider assembly selection uses the same saved workflow for `plan` and `run`:

```sh
tests/scripts/test plan --workflow tests/workflows/dev.json --step assemblies-aws --test TestAWSProtectedObjectConditionalCleanup
tests/scripts/test run --workflow tests/workflows/dev.json --step assemblies-aws --test TestAWSProtectedObjectConditionalCleanup
```

Preview shows the requested provider and literal path. During `run`, each provider
resolves controlled roots from its actual assembly binary, then executes the
requested root or child through that binary. Execution results retain build
observations, inventory, exact selection and omitted roots. Dynamic child
existence requires execution: the requested node and its observed ancestors
must pass.
Helpers and coordinator entrypoints cannot be selected independently. The common
step refuses `--test`, and every assembly step refuses `--package`. Provider
focus retains the accepted race setting, assembly vet and positive process joins. A focused
pass cannot establish complete offline or live preflight scope. Complete local
workflows require `common`, `gcp` and `aws` exactly once. Selecting one step runs
only that step through its usual capacity and focus path; it does not select its
group peers. A configured group requires at least two contiguous assembly steps
with distinct responsibilities. It cannot include another step kind, repeat
later, or use repetitions. Without a group, steps run sequentially. Each assembly
step keeps its build and custody checks in the current execution owner.

Within one workflow, successful lint can supply module-check results to later
common assembly. Reuse requires matching captured Go/native/module settings
and the accepted race setting. Common assembly still runs module-cache
verification and checks the environment. Missing facts keep the complete module
checks. Source edits do not invalidate completed module checks. Modules with unregistered local
replacements also keep their complete checks. Errors while validating a fact
fail the step. Standalone lint and assembly perform their explicit analysis and
custody checks. Ordinary build preparation does not invoke those regressions.

Exact ordinary selection uses the same saved workflow for `plan` and `run`:

```sh
tests/scripts/test plan --workflow tests/workflows/dev.json --step unit --package core/contract --test TestTokenValidation/valid
tests/scripts/test run --workflow tests/workflows/dev.json --step unit --package core/contract --test TestTokenValidation/valid
tests/scripts/test run --workflow tests/workflows/dev.json --step runner --test TestGoEnvironmentPreservesExplicitTelemetry
```

Public generator selectors retain `protocols/generator` and `plugins/cloudflare`;
the fixed source map resolves them to sibling `enkv-extensions/sdk/protocols/generator`
and `enkv-extensions/plugins/generators/cloudflare-account-token`.

A unit `--package` names one exact logical package selector already included
by that step. It does not expand a module name recursively. Package-only focus
runs every root admitted by that package’s profile. Unit test focus requires an exact package,
supplied by saved `package` or command-line `--package`. Runner
`--test` resolves exactly one owner among the three overlaid runner, records and
catalog packages and the separate launcher file-list artifact. Unknown and
ambiguous roots fail before test execution. A saved runner `tests` list can span
several owners; each owner executes only its selected paths in its own package
process. Results retain those separate owners and their omissions. Full-only
roots cannot be focused
through dev; select a full-profile workflow for those checks. A requested root
must exist in the host's active compiled inventory. `Example` and `Fuzz` roots
remain part of ordinary
inventory; selecting a fuzz root runs its seed corpus, without fuzzing.

Saved `tests` and `package` use the same requested-selection parser as the CLI.
An absent or empty `tests` list selects the owning profile. The retired singular
workflow `test` field is rejected. Reject duplicate paths and overlapping
ancestor/descendant requests. With no CLI focus, the saved selection applies.
`--test` narrows the selection to one saved path or one of its descendants; it
cannot select an ancestor, sibling or different root outside the saved set.
A CLI package must keep the saved exact package. A saved package-only unit step
can add a literal test within that package. These bounds apply equally to `plan`
and `run`; compiled membership is confirmed only during execution.

Several component tests can share one step:

```json
{
  "id": "small-components",
  "kind": "component-tests",
  "profile": "dev",
  "tests": [
    "TestSelectionDefiniteWriteResults",
    "TestFixtureAdmissionKeepsExplicitProductionComposition"
  ]
}
```

Provider assembly steps accept at most one path in `tests`; their common
responsibility does not accept a test focus.

Test paths are literal at every slash segment. `run` resolves the requested set
against actual compiled inventory and requires every requested node to start and
pass. Ancestor-only success, missing children, unrequested siblings, failed
ancestors and unexplained skipped nodes fail. Controlled helper roots cannot run
independently. Parent setup and suffix assertions still run.

Compatible ordinary roots assigned to one worker share a package process. When
Go's segment matching would select extra children, execution partitions those
literal requests into sequential processes under the root's worker. Large normal
component groups also use sequential native partitions when both bounded filter
encodings would be too large. Each process is checked against its own selection. Retained
ancestor rows can repeat only as required by those partitions; they are not
merged into an invented result. Selection does not compile unselected product
modules, run hidden regression suites or bypass the accepted race setting.

Ordinary focused results identify the observed source revision and toolchain,
repository-relative artifact inputs, admitted scope, exact executed selector and
omitted roots/packages in its ordinary result.
An unavailable source observation is explicit and does not block execution.
`selected_complete` records selected completion; `complete` remains false.
Focused or narrowed results establish only their selected scope.
The package-bound helper witnesses still apply to package-only execution.

Each `unit` and `runner-tests` step returns its discovered package/test inventory
and terminal test/subtest outcomes to the workflow owner. Current step results
also appear as compact JSON lines with `"type":"test_result"` on standard
output. Each line contains the step, activity, outcome and its existing result
record. Redirect output to retain these records with the command log. Result
output failure stops later work; it does not become a passing step.
The workflow finishes its source observation once. It prints an informational
edit note and sets `source_changed` in retained live workflow results. A changed
checkout does not change a selected test outcome.
The steps require complete
structured Go test events under the selected build flags. A missing package or test, unexplained skip, failed or
missing terminal, damaged stream, or output overflow fails the step. The four
runner coordinator entrypoints may skip only when their exact parent cases
prove the matching worker invocation. In each ordinary AWS/GCP module,
`TestConfigurationRecoveryLiveParentControl` may skip only when its exact
same-package invoking-parent test passed. Unknown helpers and missing, failed or
wrong-package parents are refused. Eight command packages are explicitly
admitted as testless: the output contract command, three GitHub output commands,
AWS and GCP output commands, and two Cloudflare commands. No test result is
invented for these packages.

Run output identifies preparation and test stages. Check records keep bounded
command facts for process outcome, start, join, wall duration, event parsing and
tool-directory cleanup. A prepared test binary and its event converter have
separate command facts. These facts describe execution; they do not replace
inventory, race-policy or terminal-result checks. `race_observation: not_observed`
means no race warning was found in the joined captures, not proof of race freedom.

Test rows retain supplied timestamps and elapsed values. Ordinary
`event_time_source: go_test_json` identifies Go's execution events. Prepared
binaries use `post_join_test2json`: those timestamps describe conversion after
the binary joined, not when an assertion executed. Missing elapsed observations
are shown as unknown. Test durations include their children and must not be
summed as process wall time or CPU time. Started rows and valid earlier results
remain available after a failure or damaged event tail; the incomplete or failed
execution still fails.

The two recovery children of
`TestSuppliedPlainMutationOpensSourcesOnlyDuringComparison` retain one fixed
`retained_secret_material` relation: `expected_count` and `actual_count` are
either zero or one. Actual one means the selected secret is present and its
slot, core, payload and access match the predecessor. The source-log prefix is
private. The relation grants no completion; a mismatch with a claimed passing
terminal refuses the evidence.

Hermetic terminals retain bounded assertion and command
failure details. Live diagnostics use closed safe facts and exclude raw errors.
Each failure stays with its activity, including in a mixed workflow. A later
save or cleanup failure cannot replace the first failure cause. Diagnostic loss
or incomplete evidence cannot turn a failed assertion into a pass. These facts
remain available with telemetry off.

Race detection is resolved once per invocation:

| Invocation | Default |
|---|---|
| Ordinary, small or full scope | Off |

Use `--race` to enable detection in any class. `--race=true`, `--race=false`
and `--no-race` are not supported. A selected step or exact test focus keeps
its owning workflow profile. Test build discovery, compiled inventory,
controlled child builders, repetitions and result checks use that setting.
Saved steps cannot choose their own race mode. Installed production plugins
follow the stock artifact contract: `CGO_ENABLED=0` and no race instrumentation.
Their actual build settings are checked against that contract. The runner's
tagged test artifacts and private TEST output child use the invocation's setting.

For example, `tests/scripts/test run --workflow tests/workflows/dev.json --step
runner --test TestGoEnvironmentPreservesExplicitTelemetry` defaults to off.
Adding `--race` enables detection explicitly.

Results record the accepted setting and the observed build setting. Known
false differs from unavailable observation; missing or mismatched observations
cannot establish a passing result. Exact live recovery validates the original
setting and compares it with the current setting. Recovery of a race-enabled
original needs `--race`, plus the operation, join and authority checks.

Direct `unit` and `runner-tests` commands use the same current workflow result
owner as saved steps, with their admitted full-profile scope.

The unit and runner steps use the assigned parallel allowance across and within
packages, including packages in the same module. Each normal binary command
uses one inner Go execution share. They retain one canonical inventory per
package and merge worker results in stable order after joins. Required helpers
stay with their proving parents. Package and literal test focuses use the same
placement rule. At allowance one, compatible normal roots share a process.
Preparation captures estimates; each execution prepares its partition set after
its parent assigns the share. Reservations and dispatch use that same set.
Retained component focus results carry actual root/request ownership, so later
estimates or capacity defaults cannot change their coverage claim.

The unit cumulative setting is zero by default. When enabled with a positive
duration, it covers preparation and execution, shared across
prepared repetitions. Each active top-level unit test has ten minutes; a selected
`full_only: true` root and its required helper closure have 30 minutes each.
Unrelated ordinary roots in the same package keep ten minutes. Runner roots have
15 minutes each, and component roots have 90 minutes each. An unselected full-only
root or an exclusive-work requirement alone does not grant the longer limit.
Explicit positive test timeouts may shorten the applicable limit but cannot
exceed it.

A top-level Go pause suspends that root's remaining time; continuation resumes
it. Output and subtest activity do not reset deadlines. Startup, intervals with
no active root, and shutdown remain bounded. Testless unit packages retain ten
minutes. The native Go package alarm is a finite backstop for the whole selection;
its value is not the per-test deadline. Each process retains finite settlement
grace. A timeout stops the package without restarting it, and the runner retains
completed, incomplete and unstarted test results through the existing converter.
Before test bodies start, the
runner checks each unit or runner selection's maximum of 8192 physical test
processes, including testless packages and launcher checks, and reserves their
command facts within the existing 32 MiB record limit. Runner reservations
include the final queue prefixes in command scopes. Preparation, execution,
conversion and positive-join facts remain complete. The process bound does not
impose an aggregate subtest-count limit.

After a contained discovery or package compile failure, the runner retains
the failed requested scope and continues successfully prepared independent
packages, including others in the same module. Unknown compiled inventory stays explicitly unavailable; acquired
inventory remains visible without invented test terminals. Failed shared builds
block their consumers without a retry. Contained child assertions, detected
data races, crashes and child-local timeouts preserve failure while independent
work continues after settlement. A terminated package is not restarted to run
its remaining partitions. Separately requested steps and repetitions remain
distinct executions. Unstarted work has `not_run` results; capture damage that
can hide a start produces `incomplete` results. Neither invents timestamps.
Parent cancellation, changed
accepted race settings, malformed results, output/record faults, guard
failure and unjoined children stop dispatch. Every started process must join.
The final command exits nonzero for any failed or incomplete selected work.
Results retain `preparation_failures`, `module_failures` and
`not_run_reason` separately from actual test inventory and results.
Preview runs no bodies or preparation and labels facts that compilation must
resolve. Fuzz campaigns and live workflows have separate stop and recovery rules. Unit and
ungrouped component steps run in workflow order. Explicit assembly, ordinary
focused component and live groups allow
member steps to overlap; all use the common parallel allowance.
Race-enabled Go commands, assemblies, components, and scenario workers use
one runner-owned `GORACE` value:
`log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000`.
Inherited race options are replaced at subprocess launch when race is on and
removed when race is off. Current results retain the
observed value; a missing or changed required value cannot support full coverage.
Scenario steps return current results, including cleanup results. Each step keeps its
cleanup owner. Current scratch disposal requires positive consumer joins and
completed result capture. Live work retains the files required for exact cleanup.
Cloud scenario cleanup settles before later affected work starts, including after
a case fails. Concurrent group members each retain their own cleanup owner.
Source observations are informational. Executions borrow completed builds with
compatible captured recipes without current-checkout or repeated artifact checks.
Passing a selected step establishes only that step's recorded coverage.

Keep operator-captured logs, results and work measurements under
`tests/work-evidences/<work-number>/`. This directory is gitignored and excluded
from maintained-source formatting, custody and lint scans. Archived source
copies are evidence, not active source. New local checks return structured
results and terminal output; they do not publish into `tests/hermetic/runs` or
`tests/hermetic/reports`. Existing directories there contain historical results
and remain unchanged. Live cleanup records have their separate durable owners.

[`check.json`](workflows/check.json) preserves the full local check as a separate
workflow, without cloud runs or fuzz campaigns. `check` also verifies that this workflow still includes lint, runner
tests, all product modules, assembly checks, full components and full scenario coverage. Components must precede scenarios. Use a
separate workflow for a narrower development selection. `runner-tests` is also
available directly as `tests/scripts/test runner-tests`.

`plan` resolves the same schedule as `run` without loading credentials or creating
fixtures. `check` runs `lint`, module tests and dependency checks,
controlled provider assemblies, full hermetic component tests, then the complete isolated hermetic scenario catalog. It needs
no cloud credentials. Use `make fmt-check` to check formatting.

`make lint` (also `tests/scripts/test lint`) checks formatting, then runs
`errcheck`, `govet`, `ineffassign`, `staticcheck` and `unused` separately with
ordinary unit tests enabled in every registered Go module, including
the generator and output protocols, hosts and named provider plugins. It requires
the pinned binary and root `.golangci.yml`, uses `GOWORK=off` and read-only module
resolution, and does not execute tests or cloud fixtures. The `lint` and `check`
commands disable module downloads before the launcher build; populate the Go
module cache before using them. Maintained Go source discovery excludes real
directories named `node_modules` in the checkout and registered sibling modules.
Symbolic links in maintained source, including links named `node_modules`, remain
errors. The pinned linter reads a private temporary copy
of the maintained Go source, module files and lint configuration. This copy
materializes the exact test admission and Crypto test overlays, and Core's
hermetic/shared callers with their catalog and records dependencies. Core uses
the same source-group mapping as its execution overlay. The copy's path, source
digest and command flags are printed. The runner checks copied module locations
and source bytes, then removes the copy after a joined success or failure. If a
tool does not join, the runner retains the copy and reports its path. No admission
source is written into the checkout. For standalone tool vet, the runner borrows
the exact verified catalog/records copies and temporarily adds its runner sources.
It verifies borrowed files again and removes only the files it created after
the joined vet command.

The existing `go vet` coverage also includes runner sources, standalone bootstrap
scripts and local examples, and hermetic, AWS and GCP component assemblies.
Runner, standalone and live-only sources receive vet without the other four
linters; shared/hermetic Core callers and catalog/records receive all five.
Module verification and production/assembly dependency guards remain active.
Production telemetry can directly import the standard library and the pinned
`otel`, `otel/attribute` and `otel/metric` APIs. Their pinned API dependencies
are permitted transitively; SDK and collection remain in startup/test code.
Core, Crypto, telemetry, the generator and output protocols, and their hosts
must resolve to this checkout in every assembly.
The hermetic modfile and the two live modfiles add test-only module requirements;
they do not add another module. Core production has no Crypto import. Its tests
can import only the checked public facades `crypto/testsupport/trust`,
`crypto/testsupport/custody` and `crypto/testsupport/installedarchive` for fixtures.
The exact `tests/crypto/admission.go` overlay supplies test admission in Crypto and is absent from the production graph. Production checks
start from every Crypto runtime package and reject reachable test facades.

### Populate the module cache

Prepare the cache before a download-disabled command. A workspace or CLI build
does not necessarily load the runner, test-overlay or independent lint module
graphs. The launcher also disables downloads before its own build when
`--test` or `--package` is present. An unfocused launcher build can fetch its
dependencies; that does not establish every later selection's cache closure.

The existing bootstrapper writes a temporary module file with the coordinated
local first-party replacements and unchanged external pins. From the repository
root, this example prepares the runner/hermetic and Crypto graphs:

```sh
repository_root=$PWD
dependency_cache=$(mktemp -d)

GOWORK=off GOTOOLCHAIN=local go run tests/scripts/bootstrap.go modfile \
  "$repository_root" "$repository_root/core" \
  "$repository_root/tests/hermetic/hermetic.mod" "" \
  "$dependency_cache/runner.mod"
(cd core && GOWORK=off GOTOOLCHAIN=local \
  GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GONOPROXY=none \
  go mod download -modfile="$dependency_cache/runner.mod" all)

GOWORK=off GOTOOLCHAIN=local go run tests/scripts/bootstrap.go modfile \
  "$repository_root" "$repository_root/crypto" \
  "$repository_root/crypto/go.mod" "" \
  "$dependency_cache/crypto.mod"
(cd crypto && GOWORK=off GOTOOLCHAIN=local \
  GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GONOPROXY=none \
  go mod download -modfile="$dependency_cache/crypto.mod" all)
```

Only the temporary module files and the Go cache are written. Keep the maintained
`go.mod`, `go.sum` and test modfiles unchanged. The empty overlay argument is
intentional for these two graphs. For another selected module or test assembly,
use its own directory, input module file and required overlay with the same
bootstrapper. Each lint module resolves its own graph; the two examples above
do not establish that all lint inputs are cached. A missing pinned dependency
remains a setup failure, not a reason to change its version or the test profile.

Custody checks cover all Core source, including contract, format and test overlays.
The source check resolves imported names. The compiled check uses the same Go
export data and overlay sources to reject private-key methods and KMS private
operations. Public parsing and verification remain permitted. The three fixture
facades keep private dependencies and expose only their checked public surface.
These checks cannot classify arbitrary bytes as secret; disclosure tests and
source review remain required.

Narrow inline lint exceptions retain refusal of deprecated HTTP dial hooks and
the existing response-close contract: close failure makes body measurements
incomplete without changing a validated reply. Store bodies already replaced by
the owned transport are in-memory closers. There are no repository baseline or path
exclusions; upstream linter defaults remain.

[Suites](suites/) group scenarios by behavior. The hermetic regression suite files
cover every hermetic catalog scenario exactly once. The separate
`authority-operator` suite owns the three live-only operator scenarios.
Each suite records the first-use ordered union of its required roles. The
[Go catalog](shared/catalog/catalog.go) defines each scenario, role and expected
step; [shared Go scenarios](shared/shared_scenarios_test.go) perform actions and
assertions. Maintained tests refuse missing, duplicate or incorrectly declared
suite coverage.

| Suite | Purpose |
|---|---|
| [`state-smoke`](suites/state-smoke.json) | Update one value, then check one controlled same-domain recovery and cold reopen. |
| [`state-integrity`](suites/state-integrity.json) | Updates, atomic selection, storage conflicts, damaged evidence, lost replies and capacity. |
| [`state-lifecycle`](suites/state-lifecycle.json) | Empty state, re-addition, mixed membership and maximum disjoint replacement. |
| [`state-secret-lifecycle`](suites/state-secret-lifecycle.json) | Empty genesis, secret delivery, sharing, exclusion and supplied-value lifecycle. |
| [`current-key-replacement`](suites/current-key-replacement.json) | Recipient, normal Authority and Recovery key replacement. |
| [`accepted-work-recovery`](suites/accepted-work-recovery.json) | Accepted sources, late results, retained Recipients, combined lifecycle recovery and repeated key loss. |
| [`state-observer`](suites/state-observer.json) | Observer reads, distinct identities and provider read refusal. |
| [`generated-lifecycle`](suites/generated-lifecycle.json) | Generated whole-set selection and exact manual or automatic retirement acknowledgement. These cases also support an opt-in Cloudflare live cell. |
| [`generated-synthetic`](suites/generated-synthetic.json) | Controlled retirement ambiguity, residue and Product cleanup conditions in hermetic memory. |
| [`configuration-recovery`](suites/configuration-recovery.json) | Complete local loss, independent anchors, prior replacements, permission refusal and zero remote effects through ordinary AWS/GCP reconstruction artifacts. |
| [`configuration-recovery-aws-owner`](suites/configuration-recovery-aws-owner.json) | Refuse an incorrect AWS Store owner during reconstruction. |
| [`configuration-recovery-generated`](suites/configuration-recovery-generated.json) | Recover selected generated values and work state without generator effects; live execution requires Cloudflare. |
| [`publication`](suites/publication.json) | Separate entry containers, value and policy changes, complete mixed results, ownership and admission refusal, lost original process, cancellation and cleanup joins. |
| [`authority-operator`](suites/authority-operator.json) | Native abandonment plan/apply/history/receipt, Recovery-authorized Authority signing replacement and disabled-Recovery refusal through AWS/GCP Store and Trust. |
| [`public-configuration-prepare`](suites/public-configuration-prepare.json) | Complete local-file loss through public prepare, exact recovered meaning, fresh reads, unchanged apply and owned cleanup. |
| [`public-configuration`](suites/public-configuration.json) | Public initialization, SSO/user ADC discovery, portable Reader, supplied apply and restricted-role permission checks. |
| [`public-configuration-functional`](suites/public-configuration-functional.json) | The restricted public flows through existing AssumeRole or impersonated ADC contexts. |
| [`public-configuration-operator`](suites/public-configuration-operator.json) | The public flow through one local operator, selected from four actual credential sources; no IAM separation claim. |

The [local operator workflow](workflows/public-configuration-operator-live.json)
selects GCP interactive user ADC, GCP service-account ADC from an existing JSON
file, AWS existing IAM-user shared credentials and AWS SSO. Each route has both
Recovery modes. One selected principal fills all logical roles. The case checks
public initialization, secret preparation/apply, reconstruction, portable Reader,
output credential capture and owned cleanup. It does not prove restricted IAM or
independent cloud principals. See the [setup instructions](live/publicprocess/README.md#local-operator-authentication).
SSO activation and login must be completed by the operator. This workflow creates
no credentials or cloud infrastructure. Live execution needs separate authorization.

Combine these suites in workflows. The [canonical reference](workflows/canonical.json)
lists every suite supported by each provider. The complete hermetic selection
contains every supported hermetic catalog case and one required smoke execution.
Recovery mode and provider applicability remain explicit in the resolved schedule. The
three fuzz campaigns are separate workflow activities.

```sh
tests/scripts/test run --workflow tests/workflows/canonical.json --step scenarios
tests/scripts/test run --workflow tests/workflows/check.json --step scenarios
```

`check` requires the complete hermetic catalog through its explicit suites and
one required smoke execution.
The schedule's `full_coverage` flag still denotes the shared provider regression;
the check workflow adds an exact complete-hermetic-catalog requirement. Observer witnesses
support memory and GCP. Accepted-work and generated-synthetic scenarios support
only hermetic memory execution. The three Authority operator scenarios run only
in the AWS/GCP live cells; their controlled executable, construction, capture
and cleanup tests run in local assemblies. The three generated-lifecycle scenarios also
support GCP and AWS with an explicit Cloudflare generator configuration.
Configuration-recovery cases use the same restricted process input boundary in
local and live runs. The three suites contain 47 names and select 51 representative
local provider/mode executions in a both-mode run; the complete-loss case covers both providers in
both modes. The generated suite runs in Cloudflare-enabled live cells. The
common suite runs in both base provider cells; the AWS owner suite runs only
in the AWS base cells. Workflows select these suites without inline scenario
lists. Local fixture results do not qualify live services or another native platform. Recovery
snapshots read exact recorded fixture objects without listing the Store. The
object-loss case uses a separate parent actor and finite reservation to delete
one recorded object; reconstruction still has no delete permission. Old-domain
and copied-location cases retain their exact additional targets for snapshots
and cleanup.
Compose only the supported suites for a live provider workflow. Copy
[`cloudflare.example.json`](environments/cloudflare.example.json) to the ignored
local `tests/environments/cloudflare.json` and set its fields. A generated
workflow step names that file in `additional_providers`; the GCP or AWS
environment stays unchanged:

```json
{
  "schema_version": 1,
  "provider": "cloudflare",
  "generator": {
    "account": "<32-lowercase-hex-Cloudflare-account-ID>",
    "permission_group": "<32-lowercase-hex-permission-group-ID>",
    "artifact": "<locally-built-production-Cloudflare-generator>"
  }
}
```

```json
"additional_providers": {"cloudflare": "../environments/cloudflare.json"}
```

Select [`generated-lifecycle`](suites/generated-lifecycle.json) and/or the applicable
[`configuration-recovery-generated`](suites/configuration-recovery-generated.json)
and set finite `generator_creates` and `generator_retires` in the limits file. The runner
checks the exact installed artifact against its source build before starting
the worker. It records each possible create in a private ledger before the
request, then records only a qualified returned token ID. Cleanup runs after
the writer and fresh process groups stop. It sends bounded deletes only for exact ledger IDs;
an unknown create, delete result or unconfirmed residue keeps cleanup
unresolved. A coordinator crash before process-group settlement also keeps
Cloudflare cleanup recovery unresolved. This private ledger supplies test cleanup targets and grants no
Product ownership or successful scenario result.
Read actual outcomes from the saved workflow and run records and their reports.
Static workflow declarations do not establish live results.
Known scenarios that do not apply to the selected recovery mode appear in
the plan and results as `not_applicable`. Recovery-disabled runs omit cases that
require recovery; hermetic `both` runs each case in its supported modes.

[`live.json`](workflows/live.json) contains every supported live scenario. Its
four generated Cloudflare cells select the three generated-lifecycle cases and
five generated configuration-recovery cases for GCP and AWS, each with enabled
and disabled recovery, and use
[`cloudflare.json`](live/limits/cloudflare.json) for a finite allowance per
cell. The Cloudflare configuration file holds the account, permission group
and artifact path. The selected Cloudflare implementation discovers the bearer
through `CLOUDFLARE_API_TOKEN`.
The live workflow has no fuzz step. `plan` checks its selection without opening
credentials; `run` executes provider calls and requires the operator's
authorization.

The [Authority operator workflow](workflows/authority-operator-live.json) selects
eight independent runs. Each provider has abandonment with Recovery disabled
and enabled, Recovery-authorized Authority signer replacement followed by
abandonment, and disabled-Recovery replacement refusal. It retains three cases
and uses the finite [Authority operator limits](live/limits/authority-operator.json).

| Step | Provider | Recovery | Case |
|---|---|---|---|
| `admin-gcp-abandon-disabled` | GCP | disabled | abandonment |
| `admin-gcp-replacement-refusal-disabled` | GCP | disabled | replacement refusal |
| `admin-aws-abandon-disabled` | AWS | disabled | abandonment |
| `admin-aws-replacement-refusal-disabled` | AWS | disabled | replacement refusal |
| `admin-gcp-abandon-enabled` | GCP | enabled | abandonment |
| `admin-gcp-replace-authority-enabled` | GCP | enabled | signing replacement then abandonment |
| `admin-aws-abandon-enabled` | AWS | enabled | abandonment |
| `admin-aws-replace-authority-enabled` | AWS | enabled | signing replacement then abandonment |

The named cases are:

- `operator.abandon-selected-work-through-cli/one_generated_group_stale_plan_apply_history_receipt`
- `operator.replace-authority-then-abandon-through-cli/recovery_signing_replacement_then_stale_plan_apply_history`
- `operator.disabled-recovery-refuses-authority-replacement-through-cli/disabled_recovery_preserves_selected_work`

The fixture initializes a real domain through the production CLI, then uses a
controlled local producer to select generated work through the installed state
and Crypto paths. It makes no Cloudflare request and needs no generator token.
The native sequence is `abandon list`, `plan`, a real ordinary transition, stale
`apply` refusal, a new `plan`, then one `apply`. After further ordinary progress,
a fresh `list` discovers the retained abandonment and `receipt` returns its
original bytes and stored result. Reads use GET only; stale apply cannot sign,
write or CAS. The plan's protected artifact and exact risk/scope are preserved.

The enabled replacement case first runs `keys replace --target authority
--authorizer recovery --signing <successor-key> --out <successor-source>`. Later
commands and the cold consumer use the delivered successor pair; the original
source remains unchanged. Constructor and sent-request evidence exclude old
Normal signing, private decryption and unused encryption capabilities. Disabled
Recovery refuses before replacement construction, provider effects or output.
Exact current values, access, shared support and complete receipt windows remain
checked. These cells check behavior on controlled selected generated work;
they do not qualify a live generator or the full key-replacement role matrix.

`authority` initializes and abandons work, `reader` has Store GET access only,
and `cleanup` owns the exact run prefix. A separate `recipient-consumer`
decrypts preserved current values after the writer exits and verifies the actual
successor basis locally. It needs its existing Recipient decrypt permission,
without successor public lookup, signing or Store-write permission. Enabled
signing replacement also uses `successor`, with Store writes, surviving Recovery
signing and successor signing, without the initial Normal signer. Disabled
refusal requires no successor context. Each run keeps its selected SDK contexts,
finite budgets, positive process joins and exact cleanup ownership.

Prepare separate private administrative environment and workflow files using
the existing resources and required SDK contexts. Preserve other run inputs.
Review and plan the exact selection before separately authorized live work.
Planning opens no credentials and establishes no provider qualification:

```sh
tests/scripts/test list
tests/scripts/test plan --workflow tests/workflows/authority-operator-live.json --step admin-aws-abandon-disabled
tests/scripts/test plan --workflow /ABSOLUTE/PRIVATE/workflow-admin-aws.json
tests/scripts/test plan --workflow /ABSOLUTE/PRIVATE/workflow-admin-gcp.json
```

Use `run` in place of `plan` only with authorization for the selected effects.
The public cleanup route retains the selected SDK contexts and exact run-prefix
ownership ledger. Interrupted cleanup reports unknown effects and incomplete
inventory separately; a later pass does not clear an earlier unknown outcome.

```sh
tests/scripts/test run --workflow tests/workflows/fuzz.json
tests/scripts/test plan --workflow tests/workflows/live.json
tests/scripts/test run --workflow tests/workflows/live.json
```
Workflow focus accepts repeated literal `--scenario` values with exactly one
`--step` of kind `run`. Each value names a complete case path or a group. Groups
expand only within the selected step's suites and saved `scenarios` subset.
The result keeps suite order. Unknown, excluded, duplicate and overlapping
selections are refused. Patterns and exclusions are not supported.

`--recovery-mode` can narrow a saved `both` step to `enabled` or `disabled`, or
keep its saved mode. It cannot replace one single mode with the other or widen
it to `both`. Scenario and recovery focus cannot combine with `--test`,
`--package`. Planning uses the same selection as execution and
does not read credentials. Selecting a scenario does not run component steps.

```sh
tests/scripts/test plan --workflow tests/workflows/smoke.json --step state --scenario state.single-value-update-preserves-other-values --recovery-mode enabled
tests/scripts/test run --workflow tests/workflows/smoke.json --step state --scenario state.single-value-update-preserves-other-values/members_32 --recovery-mode enabled
```

Direct `plan` and `run` commands accept repeated `--suite` arguments. They use
the same combined schedule as a workflow run step. Each suite selects complete
case paths, such as `state.single-value-update-preserves-other-values/members_32`.
The case name fixes the fixture. Suite files require complete paths; direct
commands do not accept `--scenario`. Group names in suites and numeric
`--members` and `--repetitions` overrides are refused. Direct commands use
one repetition. Set saved workflow `repetitions` to repeat selected cases.
Use `--telemetry-config <file>` to select one JSON configuration for the run.
Use `--log-level <level>` to override its console and log-exporter threshold.

Under the `separate-point` policy, a run has one required 32-member authority
smoke execution,
even when several suites are combined. If the selected cases include
`state.single-value-update-preserves-other-values/members_32`, its repetition 1
is the first schedule entry and supplies the smoke. The remaining repetition-1
cases keep their relative selected order; later repetitions keep the complete
selected order. If this case is absent, the schedule adds one auxiliary smoke
at repetition 0. Suite JSON lists stay unchanged.

A saved point-only workflow step can instead set
`"smoke_policy": "first-selected-point"` with finite repetitions. Its first
selected point supplies the smoke check as repetition 1 and counts toward N.
Every selected case executes N times. An auxiliary repetition-0 smoke is excluded
from selected-case N/K. Other point sizes require the explicit diagnostic policy;
ordinary suites continue to use the 32-member case.

```sh
tests/scripts/test run --workflow tests/workflows/smoke.json --step state --parallel=1
tests/scripts/test plan --workflow tests/workflows/canonical.json --step state-point-diagnostics
```

The smoke step selects one 32-member point. The canonical diagnostic step lists
all 64 named point sizes, from 1 to 64. It is outside the ordinary `dev` and
`check` workflows. Full case paths remain in result records. New private case
directories use a sequence number and a SHA-256 token of the full case path;
historical evidence keeps its original paths and recorded fixture counts.

Live selections that include current-key replacement, accepted-work recovery
or configuration recovery require replacement keys and participants. The owner
must provision those exact resources and permissions, then update private
environment inputs before the run. Suite selection does not create or remove
cloud resources. Accepted-work private phase children use the current authority
decrypter, normal signer and replacement Store routes.

[Environments](environments/) choose `hermetic` or `live`, shared resources, named
participants and `role_bindings`. Only participants needed by selected scenarios
are loaded. Roles can share a participant unless a scenario requires distinct
identities. First-flow cases for Recipients, Recovery and denied Recipients require
separate participant labels and credential routes. Recovery is selected only in enabled
mode. Authority is a role. Cloud credentials do not establish Product
authority or a RecipientID/key binding. Expected results belong to scenarios.
The environment schema rejects `operator_cleanup`; administrative fixtures use
their selected public SDK `cleanup` role.

The environment parser also accepts optional `output_targets` objects. Each
object contains both `positive` and `ambiguity` targets. Each target declares a
writer, a cleaner, `consumer_a` and `consumer_b`, with separate credential-file
references and cloud-specific secret coordinates. The writer and cleaner use an
AWS profile or a GCP service account and must not declare a consumer principal.
Each consumer declares its matching cloud principal. AWS targets include account,
region, name prefix and version stage. GCP targets include project, project
number, secret resource prefix and version selector. These routes remain separate
from state `participants` and `role_bindings`, generator credentials and all
other output actor routes.
Input validation checks the complete shape and distinct credential paths without
opening credentials or invoking a provider. It does not grant output send rights.
Use actual identity and route references from the owner-provisioned fixtures;
parser acceptance alone does not establish deployed permissions.

Optional `github_output_targets` accepts independently supplied `repository`,
`organization` and `environment` scopes. Each scope declares its exact owner,
applicable repository/environment, uppercase `secret_name_prefix`, and distinct
writer/cleaner `credentials_file` references. Organization also requires exactly
two sorted unique positive `selected_repository_ids`; repository and environment
inherit their scope policy. Prefixes are at most 66 characters, leaving 34 for a
fresh hexadecimal identifier and `_P` or `_S`. Names use the installed GitHub
profile's canonical spelling. These inputs require live mode and share the
credential-path separation rules above. Parsing validates references without
opening credential files. Actual routes and deployed permissions need separate
qualification. A live environment declares cloud output for its State provider
and can also declare the selected GitHub scopes. The AWS and GCP environment
inputs together describe all five named output profiles.

The GCP test overlay can load a service-account source with an explicit
request-counting transport and capture one bearer token with its actual expiry.
The captured email identifies that same source without reopening its file.
Capture uses the production parser, fixed OAuth route, synchronous token cache,
cancellation and request supervision. A fixture must compare the returned
expiry with the exact output action deadline before it supplies the bearer
bytes to a child. This test-only capture adds no public credential API or live
qualification.

Live output source files are limited to 64 KiB and must be regular files owned
by the current user, with no group or other permission bits and a canonical
absolute path without symlink components. Loaders use a private snapshot of one
stable source and retain its original file identity for actor-alias checks. The
loader borrows the snapshot path for reading and returns before the fixture
closes it. Normalized native credentials have a separate 65,500-byte limit and
use exclusive 0600 files in fixture-owned 0700 directories. The fixture
serializes route creation and cleanup, and joins every route user before
removal. Existing routes are never rewritten. Cleanup identity checks detect
observed replacements; they do not provide conditional deletion against
concurrent modification by another process with the same user identity. Output
cleanup diagnostics identify bounded private output-inventory rows and grant no
Store cleanup or retry authority.

AWS output fixture preparation captures the selected static INI writer and both
consumer sources once. It checks their original file identities and distinct
same-account IAM-user identities before it creates the immutable native route.
A session token without qualified expiry is refused. Consumer checks read the
complete value by qualified ARN with `AWSCURRENT`. Only documented HTTP 400
`AccessDeniedException` or `NotAuthorized` is a permission refusal; authentication,
missing-resource and malformed responses remain errors. Permission-removal proof
also needs earlier access by the same consumer and unchanged complete bytes from
the remaining consumer. A separate cleaner checks exact metadata and sends at
most one exact-ARN deletion with a seven-day recovery window. Scheduled deletion
is not erasure.

GCP output fixture preparation captures the selected writer and both consumers
from their original service-account sources. Actual identities must be distinct;
the immutable bearer snapshots must cover each operation deadline. Consumer
checks use the exact secret version, complete decoded bytes and CRC32C. A separate
cleaner reads the exact recorded secret and uses its current etag for one
conditional DELETE. Unknown responses remain unresolved. Both cloud helpers use
finite physical-request, byte and time budgets. Controlled checks use synthetic
files and transports; deployed permissions and service behavior require a
separately authorized live run.

GitHub output fixtures use explicit private bearer files for repository,
organization and environment scopes. Each fixture has one writer or one cleaner.
Writer preparation captures its source once and publishes one immutable native
credential route; later calls cannot reopen the source or create another route.
The fixture owner retains that route until every user has joined.

GitHub fixture cleanup requires the recorded exact slot, reserved prefix and
writer join. It accepts bounded UTF-8 object metadata with unique field names
and one exact nonnull name, then sends one DELETE. Only an empty, fully read and
closed HTTP 204 acknowledges deletion. Metadata for a possible-create slot does
not establish Product ownership. HTTP 404 can mask missing permission, so it
retains unresolved residue and never proves absence. Cleanup does not read
secret values, list resources or run Actions consumers. Requests use the fixed
`api.github.com` endpoint and API version `2026-03-10`, explicit bearer input,
finite cancellation and per-request budgets. Controlled transports establish
local behavior only.

The local `publication.json` suite uses the installed conformance output child
with separate plain and secret values. It checks value changes, complete policy
replacement, no-op and deletion, complete mixed result vectors, unqualified
creation, wrong ownership, later-member refusal, lost-process reconstruction,
cancellation and cleanup failure. Each recovery fixture has its own finite
lifetime. Fresh observers have no restored writer permission. Native-backed
call returns and owner retirement are checked separately from lossy telemetry.

The private output inventory API retains exact profile, planned slot and namespace
rows before effects. Each action saves a fresh attempt before entry; only a
qualified create acknowledgement retains birth and owned instance. Cloud rows
require distinct actual writer and consumer principals before their first action.
Unknown outcomes and birth evidence survive deletion. Cleanup requires the exact
writer-joined marker and one durable pending cleanup attempt. Its result can be
absent, acknowledged, scheduled (AWS only), or unknown; scheduled deletion does
not establish erasure. Concrete durable operations enforce a 128 KiB encoded
record bound, ten rows, two rows per profile and eight action receipts per row.
Caller code must qualify provider identities and namespaces, join every writer
and child, and isolate cleaner credentials. These records grant no Product
ownership, retry permission or replay authority.

The records package validates private output input and creates independent
writer and cleaner projections. The writer has its native artifact and allowed
actor references; the cleaner has only its own credentials. Validation checks
the selected scope, exact two-target coordinates, inventory indices, identities,
path syntax and reference separation without opening credential files.

The live coordinator reserves two exact names per selected profile under the
configured exclusive fixture namespace and records the actual Domain before
launch. Fresh consumers and proven Store-only retries receive no output
references. A positive original writer-group join is required before cleanup
or native credential-route removal. Input, inventory and join metadata remain
available for exact owned cleanup. Cleanup does not replay completed Product
publication work; remaining tests use a new invocation.

Live publication cases use the installed named output children and actual
selected-state admission. Each ordinary lifecycle has two containers with fixed
plain and secret values, complete action/result checks, value changes, no-op,
supported policy contraction and binding deletion. Cloud consumers check the
whole value before and after policy contraction. Later-member cases end the
operation after the first complete acknowledged chain and owner retirement;
the next real admission must refuse. A mixed cell uses its State provider's
cloud output plus all three GitHub scopes. Fresh processes compare exact
authenticated output support records and have no output credentials or restored
send permission. These live cases require separate authorization to execute.

The output cleanup helper validates the whole original group before constructing
lazy provider helpers. It excludes the retained actual cloud writer and consumers
from cleaner authority and saves one cleanup intent before each exact call.
Pending or unknown cleanup is never replayed. Original unknown actions remain
unresolved after cleanup acknowledgement or absence; GitHub metadata 404 stays
unresolved. A known AWS deletion schedule can complete the cleanup operation
while its nonzero residue remains in the result. Parent completion and reporting
require exact retained evidence for that exception. Store-only retry cannot
replace output receipts or remove their residue and unknown counts.

The observer suite uses `hermetic.json` locally. Live execution is supported on
GCP. The success cases use the `observer`
role. The refusal case uses `denied-observer`; it must authenticate successfully
and receive provider access refusal when it reads the selected state. These roles
have separate bindings in one environment. Bind them to different cloud accounts,
both distinct from the authority account. A missing credential or a transport
failure cannot satisfy the refusal case. Expected outcomes remain in the cases.

These checks are component witnesses. A successful read does not prove that its
cloud principal lacks write permission.

Live runs need owner-provisioned resources and permissions, explicit credential file references,
and all ten finite values in a [limits file](live/limits/example.json).
Use `run --suite <suite.json> --environment <environment.json> --recovery-mode <enabled|disabled> --limits <limits.json>`.
For standalone `plan` and `run`, omitting `--recovery-mode` retains the environment's
default mode; hermetic runs default to `both` and also accept either single
mode. Use a workflow to run both cloud modes.
Each environment runs independently, in the order selected by the caller. Local
hermetic, native Linux, GCP and AWS execution have no cross-environment prerequisite.
Run the same launcher from the repository on each host. Source and build
observations describe the invocation; they do not freeze the checkout. Source
edits do not stop execution or cleanup. The runner enforces request, byte,
object, time and cleanup limits.

Live environment resource settings declare their default `recovery_mode` as
`enabled` or `disabled`, the
normal signing key and public key, and separate Authority and Recipient KEK IDs and
public keys. Enabled mode also requires the recovery signing key, recovery KEK,
their public keys and a recovery participant. Selecting disabled mode from a full
environment removes recovery key fields and recovery role bindings from the
effective worker configuration. The supplied environment file stays unchanged.

The `state.transient-before-send-rerun` live case saves its plain desired input
and independent public domain basis in the private run directory before the
first command. A joined writer with exact typed transport failure evidence can
start one fresh same-domain invocation within the remaining scenario limits.
The fresh invocation opens current state, compares the complete goal, and
selects a new candidate only if the goal differs. A separate process then
cold-reopens the result. The public run record keeps the first failure, rerun,
cold check and cleanup as separate facts. Inventory entries for calls with no
response remain unknown until positive safe-settlement evidence exists; a
later successful call or worker join does not clear them. A failed or missing
handoff, rerun, cold check or cleanup leaves the case failed or incomplete.

Each worker records the selected mode. Hermetic workers follow only the
declared phases and children for that selection. Cleanup keeps all
public resource identities. Public SDK fixtures use the separately selected
cleanup context; injected fixtures use their admitted cleanup route.

Current-key replacement, accepted-work recovery and configuration recovery
require the complete baseline successor bundle for the selected mode. Enabled
recovery needs its independent signing/encryption keys and restricted routes;
a disabled-only environment cannot satisfy it. Both
[AWS](environments/aws.example.json) and [GCP](environments/gcp.example.json)
examples show enabled recovery with public placeholders and separate credential
references. Replace the example resource IDs and PEM markers with the exact
independently obtained resources and public keys before use.

| Successor | Key setting | Public-key setting |
|---|---|---|
| Normal signer | `normal_successor_key_id` | `normal_successor_public_key_pem` |
| Optional second normal signer | `normal_successor_2_key_id` | `normal_successor_2_public_key_pem` |
| Recipient KEK | `reader_successor_kek_id` | `reader_successor_kek_public_key_pem` |
| First authority KEK | `authority_successor_1_kek_id` | `authority_successor_1_kek_public_key_pem` |
| Second authority KEK | `authority_successor_2_kek_id` | `authority_successor_2_kek_public_key_pem` |
| Recovery signer | `recovery_successor_key_id` | `recovery_successor_public_key_pem` |
| First recovery KEK | `recovery_successor_1_kek_id` | `recovery_successor_1_kek_public_key_pem` |
| Second recovery KEK | `recovery_successor_2_kek_id` | `recovery_successor_2_kek_public_key_pem` |

The baseline bundle requires seven successor pairs and twelve restricted roles
in enabled mode, in addition to the initial settings and participants. Disabled
mode requires the four non-recovery pairs and seven non-recovery roles. The
optional second normal signer is additional to those counts. Select
`recovery_mode: "disabled"` in a workflow or `--recovery-mode disabled` in a
standalone command; the runner selects the required fields and routes. Suites
without replacement, accepted-work or configuration-recovery scenarios can omit
the entire successor bundle; supplying one successor field requires the complete
baseline bundle for that mode.

`reconstruction.normal-combined-repeated` and
`reconstruction.generated-repeated-later` also require the second normal signer
pair and a `normal-signer-2` participant. Use a distinct immutable AWS KMS key ARN
or GCP CryptoKeyVersion and its independently obtained public key. Its route
must allow public-key lookup and signing with that key, with no decrypt
permission. Keep it distinct from the initial and first successor signer
routes. Other cases do not require this second signer. The runner does not
provision the key or grant permissions.

`reconstruction.required-public-denied` requires a separate `denied-observer`
route that authenticates but receives provider refusal for the required public
key lookup. A missing credential, transport error or decrypt-only denial does
not prove this condition. The example environment supplies a placeholder;
provide its actual credentials and permissions before live execution.

| Restricted roles | Private capability |
|---|---|
| `normal-signer-0`, `normal-signer-1` | Sign only with the initial or successor normal key, respectively |
| Optional `normal-signer-2` | Sign only with the second successor normal key |
| `authority-decrypter-0`, `authority-decrypter-1`, `authority-decrypter-2` | Decrypt only with the initial, first successor or second successor authority KEK, respectively |
| `reader-successor` | Decrypt only with the successor Recipient KEK |
| `replacement-store` | Test object storage operations; no private key access |
| `recovery-signer-0`, `recovery-signer-1` | Sign only with the initial or successor recovery key, respectively |
| `recovery-decrypter-0`, `recovery-decrypter-1`, `recovery-decrypter-2` | Decrypt only with the initial, first successor or second successor recovery KEK, respectively |

Each restricted role needs its own participant label and owner-provisioned credential route. A signer has no decrypt permission, and a decrypter has no
sign permission or access to another private key. The separate routes let the
scenarios make an old role unavailable while a qualifying current role remains
usable. Two authority and recovery KEK successors support repeated replacement;
independent signing scenarios start with fresh domains.

The GCP live backend leaves one second between HEAD mutation attempts, including
fixture creation and cleanup. Waiting preserves the original condition and can
end on context cancellation.

Credential paths are absolute or relative to the environment file. Keep files
local and out of Git. There is no ambient credential or participant fallback.
Successful runs remove private inputs. Failed live runs retain cleanup inputs;
recover with `tests/scripts/test cleanup RUN_ID --limits /ABSOLUTE/PRIVATE/limits.json`.
Use `--environment <environment.json>` on cleanup only to replace credential
references for the same resources. Do not delete retained inputs before cleanup.

Public configuration cleanup uses the saved SDK contexts and the separately
selected cleanup actor. It requires joined original workers and the retained
public ownership ledger. Renew an expired login in its original SDK context;
`--environment` replacement is not supported for these public cases.

For a non-generated AWS or GCP run whose Product work passed but whose cleanup
stopped on a recorded local admission refusal before sending a DELETE, the same
cleanup command can grant one new action for the refused object. It requires
joined workers, complete retained ownership evidence and new finite limits. The
current cleanup build can read supported older records after source edits. Its
result preserves the old failure and records current execution observations; it
does not grant Product workflow continuation.

The grant is saved before cleanup dispatch and is consumed even if that
invocation fails. The worker checks the old run, case receipt, inventory, exact
target and permitted credential route before it opens credentials. It accepts
proved absence, or verifies the recorded body and token before one conditional
DELETE and a
final absence check. Other recorded objects use ordinary cleanup. A changed
object, missing evidence or an unknown effect is refused. The original failed
attempt remains in the evidence; this path does not enable automatic retries.
AWS ETags remain conditions, not incarnation identities.

For a non-generated AWS run that passed its Product work and stopped on an
eligible uncertain conditional cleanup DELETE, this command can grant one new
cleanup action for that object. It requires complete retained ownership records,
positive worker joins and new finite limits. The current cleanup build can read
supported older retained records after source edits. Its result records current
execution observations and does not qualify old Product work on the new source.
A private grant claim is saved before recovery work starts. The claim remains after a failure, so another invocation
cannot grant a second attempt.

Recovery reads the exact recorded object. It accepts qualified absence, or
checks its body size, digest and ETag before one new conditional DELETE and a
final absence check. Other proved owned objects use ordinary cleanup; the grant
does not permit another attempt for any other failed deletion. ETags are
conditions, not incarnation identities. Changed ownership, unknown writes or
incomplete evidence stop recovery. The original failed run and unknown DELETE
outcome remain in the evidence. Automatic AWS retries stay disabled, and this
cleanup-only result cannot enable Product workflow continuation.

Supported retained GCP exact-generation cleanup failures also use the standalone
cleanup command with a new finite allowance. Admission checks the original case,
owned generation, failed attempt, remaining attempt ordinal and positive joins.
A durable target-bound grant precedes cleanup dispatch. It permits only the
supported exact cleanup operation and never starts missing Product cases.

Historical private run directories have no bulk cleanup command. Keep unresolved
live input, inventory and generator cleanup state for the exact cleanup command.
A cleanup recovery invocation owns only its new private directory; it borrows
the original recovery files and must preserve their bytes. Current owned scratch
can be removed only after its consumers join and required evidence is saved.

Ordinary commands return current outcomes, timings and bounded hermetic failure
details. They create no qualification record or ordinary historical result tree.
Source observations use Git revision/status/diff and metadata for Git-listed
untracked files. They do not create raw Git trees or claim an exact
frozen source snapshot. Start/end changes or incomplete observations are
informational; they do not invalidate a completed build or result.

Live recovery retains the run and case facts, inputs, inventories and journals
needed for exact cleanup. Historical files and source-format readers remain
available for supported records. Cleanup checks ownership, permitted operations,
credentials, budgets and process settlement. It does not require the original
checkout or original executable bytes. Historical run directories are not
deleted or converted by ordinary execution.

Live workers retain private assertion evidence independently of optional telemetry.
`failure.json` records the first intercepted test assertion: its fixed code,
repository-relative source location, phase and last completed checkpoint.
`checkpoint.json` records completed phases. A checkpoint does not prove that a
provider accepted a request. Each file is bound to one worker invocation, has a
4 KiB limit and mode `0600`, and stays in the private `0700` worker directory.
Assertion arguments and error text are excluded from these records.

Public records contain only marker/checkpoint availability and
validation status, the completed checkpoint and any retained marker-write error.
Detailed assertion locations and invocation bindings remain private. A missing
marker after process loss does not identify the failed assertion. A marker on a
worker reported as passing prevents that success from being admitted. Older
records without this evidence display `not_recorded`. Execution, assertion
evidence and fixture cleanup have separate outcomes; marker evidence cannot
grant a retry or replace the existing typed recovery evidence.

Full coverage requires every applicable ordinary test to pass. Helper skips stay
visible and require their exact invoking parent and completed worker evidence.
An unexplained skipped test or subtest makes coverage incomplete. Evidence from another environment cannot supply missing checks.

Run the fixed generated-input campaigns with `tests/scripts/test fuzz`:

| Selector | Module | Package | Target |
|---|---|---|---|
| `format` | `core` | `./format` | `FuzzCanonicalRecords` |
| `contract` | `core` | `./contract` | `FuzzFirstFlowRecords` |
| `crypto` | `crypto` | `./internal/custody` | `FuzzCustodyOpen` |

For selected campaigns, use `tests/scripts/test fuzz <selector> [<selector> ...]`.
They run in the supplied order. With no selector,
the runner executes these three targets in order and stops on the first failure.
Each target has a ten-minute generated campaign, one-minute minimization limit,
workers bounded by its assigned parallel allowance, and a fifteen-minute process
limit. Each result identifies its source revision, module, package and exact
build arguments in its ordinary result.
Private cache and work files follow the current scratch disposal rules. The
campaign processes can take up to 45 minutes, plus setup. Source edits are
informational throughout the selected batch. Core targets use the hermetic
modfile; all targets use the exact Crypto admission overlay. Native macOS
arm64 and Linux x86_64 require separate execution records. Cross-compilation
cannot supply native process-loss evidence. Live GCP and AWS runs use the same
shared lifecycle scenarios. Claims about each environment need its own results;
execution order is unrestricted.
