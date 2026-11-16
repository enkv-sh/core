# Application telemetry and Honeycomb setup

The example and test workers use the same `compositions/observability` setup.
Without a selected configuration, metrics, spans, files, and network export are
off. WARN and higher console logs use stderr. The Product result uses stdout.

`generated list` emits `core.generated.list` with admission, state-loading and
authentication stages only.

Plugin installation emits `plugin.resolve`, `plugin.capture`, `plugin.acquire`,
`plugin.select` and `plugin.retained` under the application owner, with an
admission stage and a closed final outcome. These calls do not execute a plugin
or grant provider authority. Paths, catalog URLs, signature bytes, raw errors and
credentials are excluded. Returned installation rows retain safe failure facts
when telemetry is disabled; offline reuse emits no acquisition operation.

Receipt list and detail emit `core.receipt.list` and `core.receipt.detail` with
admission, state-loading and authentication stages. Public domain and Recipient
inspection use `core.inspect` and `core.inspect_recipient` with the same stages.
Capacity inspection, GC preview and public artifact validation use
`core.inspect_capacity`, `core.gc_plan` and `core.gc_validate_plan`. They have
only those public stages; artifact validation performs no LIST or mutation.

Materialization emits `core.materialize` with admission, state-loading,
authentication and private-custody stages. Its private file owner emits
`crypto.materialize` with private-custody, local-staging, local-replacement and
local-completion stages. These local stages describe file delivery. They grant
no canonical mutation or provider output meaning. Values, filenames, plaintext
lengths, plaintext hashes and raw file/provider errors are not telemetry fields.
Safe failure facts remain in the operation result when collection is disabled.

Bounded Store enumeration emits `store.list` under its AWS or GCP provider.
It records one page call, its closed read result, owned key/cursor byte counts
and the one physical HTTP attempt. Keys, provider cursors, response bodies,
credentials and raw errors never enter diagnostic fields or metric labels.
Invalid input refuses before credentials or HTTP. Default disabled collection
preserves the same page result and safe failure classification.

Independent live fixture reads emit worker-owned `setup.verify_cloudflare` and
`setup.github_metadata`. Each normal return records `success`,
`admission_refused` or `failure`, its closed reason and operation duration.
An expected missing GitHub secret completes the metadata observation successfully.
The operation context parents the HTTP read. Tokens, account IDs, target paths,
response bodies, returned token IDs, raw errors and private byte counts do not
enter these signals. Disabled collection preserves the same bounded read result;
a panic emits no normal return.

Generated retirement, retirement risk acceptance and cleanup emit
`core.generated.retire`, `core.generated.accept_retirement_risk` and
`core.generated.cleanup` with admission and commit-observation stages.

Core's private observation collector reports `core.observation_offer` through
the same operation calls, results and duration signals. Its results are
`success`, `contention`, `capacity_exceeded`, or `invalid`. Disabled collection
emits no offer signal. Offer telemetry contains no observation identities,
entry names, detail rows or payload-byte measurements. Local collector drop
counts remain available when telemetry is off.

From the repository root, this local check sends nothing to Honeycomb:

```sh
(cd core && GOWORK=off GOTOOLCHAIN=local go run -mod=readonly -modfile=../tests/hermetic/hermetic.mod ../tests/examples/telemetry/main.go)
```

The example generates an invocation ID and calls `core.Open` with a zero
admission. The expected Product outcome is `8` (`admission_refused`), with the
diagnostic reason `admission_invalid`. This tests application startup and
refusal telemetry; it does not test a successful Product operation.

Use [Honeycomb's OTLP endpoint guidance](https://docs.honeycomb.io/send-data/opentelemetry/)
to confirm the account region. The manual
[`honeycomb-smoke.example.json`](../../telemetry/honeycomb-smoke.example.json)
uses the US endpoint. Change it to `https://api.eu1.honeycomb.io` for an EU
environment. Honeycomb Classic also needs `dataset` on the `honeycomb`
destination. Put an ingest key in `HONEYCOMB_API_KEY`; do not put its value in
the JSON file or shell command history. The key must permit logs, metrics, and
traces in the selected environment. This file is never selected by ordinary
workflows.

After local verification, the following commands test application and test-worker startup separately.
The application command below builds the existing example with the test-only
module overlay. It runs in a fresh local directory so its file route has no
existing output file:

```sh
repo=$PWD
config="$repo/tests/telemetry/honeycomb-smoke.example.json"
printf 'Honeycomb ingest key: ' >&2
IFS= read -r -s HONEYCOMB_API_KEY
printf '\n' >&2
export HONEYCOMB_API_KEY
app_run=$(mktemp -d "${TMPDIR:-/tmp}/enkv-telemetry-app.XXXXXX")
(cd "$repo/core" && GOWORK=off GOTOOLCHAIN=local go build -mod=readonly -modfile=../tests/hermetic/hermetic.mod -o "$app_run/telemetry-example" ../tests/examples/telemetry/main.go)
(cd "$app_run" && ./telemetry-example --telemetry-config "$config")
```

The application prints its invocation ID and `operation outcome: 8` on stdout.
Its delivery counts appear on stderr. This short check should have
`incomplete=false`, nonzero `written`, and zero `failed` and `dropped` for
`logs.honeycomb`, `metrics.honeycomb`, and `traces.honeycomb`. The local
comparison files are `$app_run/telemetry/{logs,metrics,traces}.jsonl`.

The test-engine command selects one existing short hermetic case. Its suite
file is a temporary selection, not a new scenario or workflow:

```sh
suite=$(mktemp "${TMPDIR:-/tmp}/enkv-telemetry-suite.XXXXXX")
cat > "$suite" <<'JSON'
{"schema_version":2,"name":"telemetry-smoke","description":"One small existing atomic candidate case","required_roles":["authority","recovery"],"scenarios":["secret.competing-supplied-candidates-preserve-atomic-outcomes"]}
JSON
tests/scripts/test run --suite "$suite" --environment tests/environments/hermetic.json --recovery-mode both --telemetry-config "$config" --log-level warn
```

The case has a fixed small fixture and includes expected refusals that produce
WARN logs. The engine also runs its required point smoke. Use file, HTTP or
both destinations with the same WARN threshold and sample ratio 1 when
comparing routes. The manual configuration above uses DEBUG for the application
example; the test command makes its WARN override explicit.

The case must pass its Product assertions and cleanup. The ordinary engine
returns its terminal outcome and disposes current hermetic files after joined
consumers finish. It does not retain run or telemetry JSON for inspection.
The focused `TestTelemetryRoutesPreserveSmallScenario` check compares actual
current file and HTTP output before disposal. Current worker delivery keys
are `logs.console`, `logs.file`, `logs.http`, `metrics.file`, `metrics.http`,
`traces.file` and `traces.http`, according to the selected routes. Private worker and application
status keys can retain configured exporter names. Keep accepted, written,
dropped, failed and incomplete status separate from assertion outcomes. Require
nonzero delivery for expected signals, including the writer's refusal logs;
a successful fresh Recipient need not emit a warning. Logs count records, metrics
count batches, and traces count spans. Do not compare those totals as if they
were the same unit.

Each instrumented worker has its own invocation span and child operation
spans. Run and worker IDs correlate workers; they do not establish one
cross-process parent trace tree. In the selected Honeycomb environment, use
a narrow time range to find each worker root and use its invocation and worker
attributes to correlate its operations. Check operation, result, reason and
admitted identity fields.
Every emitted warning must carry its own matching trace and span IDs. A span
for a successful operation need not have a WARN log. Check call/result counters
and duration histograms in the same time window; invocation IDs are deliberately
not metric dimensions.

The application example keeps its local comparison files in `$app_run`.
Test-engine file exports belong to current workers. Local telemetry tests
compare decoded files, HTTP content and delivery facts before disposing the
joined current owner. Incomplete telemetry alone does not retain hermetic
scratch. A qualification record does not contain telemetry files. Live recovery
files follow their separate recovery lifetime. A local receiver does not qualify
Honeycomb delivery.

Allow up to five minutes after each bounded shutdown for all three hosted
signals to become queryable. If one is absent, check the selected endpoint,
environment, time filter, and local delivery/loss counts before another
measurement. An HTTP response or one visible trace alone does not pass this
check. Record the tested source and configuration identity, commands, time
windows, local paths, Honeycomb query links or filters, per-signal findings,
and the qualification result in the owning work report. Keep local files and
logs private.

`--log-level` overrides `ENKV_LOG_LEVEL`, then the selected `logs.level`, with
WARN as the default. Only the effective level is validated. `off` disables
all log destinations; separately configured metrics and traces remain active.
For a workflow, `--telemetry-config` replaces each selected run step's file
reference. The command-line path is relative to the invocation directory;
a step's reference is relative to its workflow file.
`OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES` can supply resource
metadata. These inputs do not activate a destination. The application owns
setup, the invocation capability, and bounded shutdown; Product code owns no
SDK or global provider. Startup converts accepted numeric resource forms into
one owned representation for every signal. Resource keys, string values and
scope names/versions must be valid UTF-8; admitted text is not normalized.
Configuration JSON members must match their declared tags exactly. Resource
attribute map keys retain their exact case-sensitive meaning.
The upstream SDK also reads
`OTEL_RESOURCE_ATTRIBUTES` and `OTEL_SERVICE_NAME` during provider construction,
including lazy log setup. Supplied values take precedence for matching keys;
additional environment attributes can enter exported resources after startup
validation. Exact resource snapshots across environment changes are not enforced.
Admitted empty port and empty query/fragment delimiters normalize to the same
HTTPS base before exporter construction and egress checks. The supplied HTTP
client owns TLS; unused ambient OTLP certificate and client-key files are not
opened by log-exporter construction. Metrics and traces refuse startup when
`OTEL_EXPORTER_OTLP_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE` or
`OTEL_EXPORTER_OTLP_CLIENT_KEY` is nonempty. The corresponding
`OTEL_EXPORTER_OTLP_METRICS_*` and `OTEL_EXPORTER_OTLP_TRACES_*` TLS file settings
also refuse their selected signal. This includes file exporters and a lone
client certificate or key setting. Admission checks the environment setting
without opening its file, and delayed constructors repeat the check. No-export
and logs-only configurations retain support for these unused settings; an
unselected signal's TLS file settings do not block another signal.
The owned remote transport uses verified HTTP/1 TLS and permits application
reads only after its first request write starts. Closing before that write
returns a closed error without reading buffered peer bytes. Each connection
closes after its response to prevent post-response idle reads. Dial and TLS
handshake each retain their two-second budget. Runtime close cancels and joins
its dial/handshake callbacks, closes acquired sockets and reports cleanup errors.
These rules exclude raw early/idle collector text from standard HTTP diagnostics;
they do not prove settlement of Go's internal DNS resolver work.

`Close` gives delivery one fresh setup-owned deadline. A canceled caller stops
waiting and receives an error; the runtime retains worker and file cleanup
ownership. A later `Close` can wait for that same cleanup. Delivery loss remains
separate from worker completion. Keep output files private while an owner can
still write them, and retain the process join before evidence import or removal.

After its workers join, `Close` also reports a safe incomplete-delivery error
when any configured route has failed, dropped, or incomplete output, or accepted
output that was not written. It preserves cleanup errors as separate causes.
A delivery error does not mean that a worker remains active. A prior incomplete
wait remains visible even when a later call joins cleanup.

Configured logging applies its resolved severity threshold before bounded
capture. Valid records below that threshold consume no capture capacity and do
not count as delivery loss, including when capture is busy, full or closed.
Selected records retain all loss accounting. `telemetry.NewRecorder()` remains
an all-level recorder for explicit capture; its status describes that capture,
including every admitted severity.

The recorder charges its fixed slots and all owned string copies against the
existing 192 KiB capture ceiling. It reserves 64 KiB inside that ceiling for
admission encoding and retains a prefix within the remaining space. Long details
can fill byte capacity before slot capacity; new records then count as dropped.
Admission checks the actual encoded 16 KiB record limit, including JSON escaping.
Rejected records contribute to capture and log-loss status. The four-record drain
keeps its backing within the separate 64 KiB drain allowance; the combined
capture, drain and admission encoding ceiling remains 256 KiB. Other ambient SDK settings cannot change the resolved
controls. File and HTTP metrics use cumulative counters and explicit duration
histograms; the test evidence reader uses delta collection. SDK log limits
retain every field admitted by the bounded record contract.

Output-host logs, metrics and traces use the default scope
`enkv.sh/compositions/outputhost`. Set `scopes.outputhost`
with `name` and optional `version` to override it. A scope override does not
enable a signal or exporter.

Manifest-host logs, metrics and traces use the default scope
`enkv.sh/compositions/manifesthost`. Set `scopes.manifesthost` to override it.
The closed operations are `manifesthost.check`, `manifesthost.render`,
`manifesthost.join` and `manifesthost.cancel`. Check records admission; the
remaining operations record native execution under the provider-call stage.
No path, metadata body or child error text enters these records.

## Maintain operation telemetry

When an operation changes, update its named owner and result vocabulary in
`telemetry/definition.go`, then put `telemetry.Start` or
`telemetry.StartWithDetails` at the owning call boundary. Pass
`telemetry.CallContext(ctx, call)` to child operations so their spans and log
calls keep the parent. Record a checkpoint only for a useful stage and finish
the call once, on every return path, with the actual Product result and its
specific reason. Finish only after a normal return. A panic must not emit a
return record or count an operation as completed with a zero-value result.
Preserve resource cleanup and panic propagation. Record input or output byte
counts only when the boundary owns those counts. A nil call is the disabled
path and needs no special case.

Keep the severity mapping complete when adding a result. A failed operation
uses ERROR; uncertainty and expected refusal use WARN. A normal observation,
including an optional missing read, uses INFO. A more specific reason must not
hide a failed operation or an uncertain commit. These log severities do not
change Product results or control flow.

The parent Crypto process boundary records an unknown or unusable generator
response with its closed disposition, reason and HTTP status. A successful
Crypto return means that the process response was decoded. The producer owner
still checks its admitted account, request and intent. An unknown response has
no protected result packet. The warning records that uncertainty without
changing the Crypto result or its metric label.

The native output host records passive profile checks separately from dispatch.
Passive checks have no credential or payload phase. Dispatch records handshake,
command transfer, the credential gate, result reading and child termination.
Keep these calls under the owning host call. Crypto separately records publication
preparation, arming, sending and retirement; telemetry cannot create or extend
the private send permission.

Core records selected publication planning as `core.publication.plan`,
execution as `core.publication.execute`, reservation preparation as
`core.publication.prepare_reservation` and result preparation as
`core.publication.prepare_close`. Candidate preparation reports the Core
preparation result; it does not prove that an effect acknowledgement was
selected. Execution derives its effect result from the complete ordered output
vector, so a successful current-state observation cannot hide an unknown effect
or a mixed terminal failure. Cleanup failure remains ERROR at operation scope
even when the output vector retains selected acknowledgements. Operation and
Attempt identities belong in bounded diagnostic fields and spans, never metric
dimensions. These calls use the shared invocation capability and keep private
custody, provider dispatch and Store operations under their Core parent. They
capture no values, targets, policy bodies, credentials or raw errors. A panic
emits no normal return record.

Public Reader comparison records `core.reader.compare`; complete in-memory
manifest issuance records `core.reader.manifest`; authenticated complete
recipient registry reads record `core.reader.recipients`. Calls record admission,
selected-state loading and local public authentication only when those stages
are reached. Returned reasons use the closed public failure vocabulary; source
fault precedence remains the Core result's precedence. Equality and a verified
mismatch both complete comparison successfully. Manifest success records the
complete artifact byte count without its bytes. No compared value, consumer
locator, policy body, credential, raw profile/provider error or secret enters
Reader telemetry. Each normal return records one result; a panic records no
normal return. Disabled collection preserves the same safe Product failure
records, and the shared application setup retains its WARN stderr default and
opt-in local exporters.

Complete manifest projection records three bounded counters:
`enkv.manifest.selected_entries`, `enkv.manifest.included_entries` and
`enkv.manifest.excluded_entries`, with unit `{entry}`. Only a successful
`core.reader.manifest` return emits them. The selected count equals included
plus excluded and is at most 512. Empty complete selections emit zero counts.
These counters contain no entry names, IDs, routes or policy bodies.

Native manifest delivery records application-owned `manifest.file.write`.
It admits only admission, local staging, local replacement and local completion
checkpoints. Source capture remains under `configuration.capture`; selected
observation and safe issuance failures remain under the Reader child. Native
completion, source cleanup and presentation remain separate returned facts.
No path, artifact byte, plaintext, credential, ID or raw filesystem error enters
the native telemetry call. Disabled telemetry preserves the same safe result
facts and the shared WARN default.

Private supplied-value planning records `core.planning` with admission,
selected-state loading, public authentication and private custody stages only
when reached. Its separate Crypto owner records `crypto.planning`; selected
display records `crypto.planning_display`. Both use the private custody stage.
These operations return safe closed failure classifications. They record no secret
values, names, raw lengths, commitments, keys or encoding buffers, and no
mutation or provider-effect stage.

Configuration capture and parsing use `configuration.capture` and
`configuration.parse` under the application owner. Local pair writes use
`configuration.write`; exact initialization manifest delivery uses
`configuration.initialization_manifest`. Capture and parse report admission;
writes report candidate persistence and commit observation when reached. These
operations report bounded byte counts and closed result facts. Source names,
paths, scalar text, key material and raw filesystem errors do not enter records.
A possible editable replacement remains unknown even if later cleanup succeeds.
Local name/reference edits, recipient preparation, epoch edits and explicit
recovery retain `configuration.write` as their application owner. Recipient
preparation keeps its public Reader and exact public key lookup beneath that
owner. It adds no private capability or provider effect. Confirmed delivery,
pending recovery and cleanup failure keep their separate result meanings.

Public preparation uses application-owned `configuration.prepare`; passive
declared dependency assessment uses `configuration.prepare_dependencies` beneath
it. These owners admit only the admission checkpoint. Existing source capture,
native staging/delivery, Core reconstruction and Crypto verify/discard retain
their own child operations. The existing-pair branch has no provider credential,
Store, KMS or executable-host construction. Artifact checks are passive and do
not launch a version probe. Operation facts are fixed before native cleanup and
remain available when telemetry is disabled. A successful local readback cannot
erase pending ownership, unavailable dependencies or cleanup failure. Result
presentation failure is separate and preserves exit `3` when already required.
Paths, declaration bytes, public witness bodies, keys, credentials and raw
provider or filesystem errors are not telemetry fields or metric dimensions.

Source-based abandonment records `core.inspect_selected_work` for list,
`core.prepare_end_selected_work` for plan, `core.select_end_selected_work` for
apply and `core.mutation_receipt` for receipt lookup. Each installed invocation
loads one fresh administrative image. Protected plan delivery records the
application-owned `administrative.plan.write`, with bounded byte counts and a
candidate-persistence checkpoint. File delivery and cleanup failures remain
separate from a known selected mutation result.

Capacity and GC preview keep the public `core.inspect_capacity` and
`core.gc_plan` owners. Their separately installed reader adds bounded Store LIST
to exact GET reach and installs no KMS route. Protected canonical GC plan
delivery records application-owned `gc.plan.write`, with bounded byte counts
and only a candidate-persistence checkpoint. It reports completion only after
the file worker and its cleanup return. A delivery failure is separate from the
public preview and does not select a delete permission. The plan byte limit and
the public result output bound are separate. Raw object names, provider tokens,
cursor contents, source paths and bytes do not enter telemetry.

`core.gc_apply` and `core.gc_continue` are Core-only parents. They emit Start
and a normal Return, with no checkpoints of their own. Bounded physical Store
children own their specific checkpoints. A panic propagates without a parent
Return or completed-result count; cleanup must still join the owned work.

Installed Authority, Recovery and Recipient replacement record
`core.replace_authority_keys`, `core.replace_recovery_keys` and
`core.replace_recipient_key`. Existing preparation and provider operations are
children. Existing exact output uses the installed GET-only inspection or
receipt operation. Telemetry does not prove that an earlier uncertain CAS
committed. Protected paths, source text, credential selectors,
key material and raw provider errors do not enter these records.

Envelope re-key and recipient retirement record `core.rekey_envelope` and
`core.retire_recipient`. Recipient exclusions use the enclosing apply or
retirement operation.
These Core parents report admission and the final safe result. Comparison,
private preparation and conditional selection retain their existing child
owners. A retained duty does not turn a successful access mutation into pending
retirement. Returned hazards retain their warnings independently. Entry names,
recipient references, values and raw errors are not metric dimensions.

The `compositions/full/cmd/enkv` executable uses this shared setup for each
Authority invocation. Each supported command accepts `--telemetry-config` and
`--log-level`. Without configuration, it exports no signals and writes WARN or
higher diagnostics to stderr; `--log-level=off` disables those diagnostics.
Structured Product output stays on stdout. Relative telemetry configuration
paths and local file exporter directories use the command's captured invocation
directory, as do its configuration and artifact paths. The command closes its telemetry
runtime before exit and reports incomplete delivery separately from the Product
result. Plan exits `0` (match) and `1` (verified difference) both record successful
invocation completion. Other commands record success only for exit `0`.
Result adapters supply the established terminal class: known refusal,
incomplete setup, unavailable evidence, cancellation and unresolved effects
remain distinct. Cancellation and expiry require an operation-owned reason,
diagnostic or returned typed error. A later context cancellation during result
delivery cannot replace an established result. Ordinary and generated cleanup
inability remains evidence unavailable even when result delivery succeeds.
Exit `2` alone does not imply an unknown effect. Captured
source paths and safe parser positions stay in the Product result; these native
paths never enter invocation diagnostics. A failed result delivery cannot cause another
operation execution.
Diagnostic or telemetry delivery failure changes either successful plan exit,
or another command's exit `0`, to `2`; refusal/unknown exits and result bytes on
stdout remain unchanged. A panic does not emit a normal invocation return.

Crypto records private reconstruction verification as
`crypto.reconstruction.verify_discard`. This operation reports the typed result
of one secret verification without plaintext or selected configuration in its
diagnostics. Its success does not establish a complete reconstruction result.

A returned child result and a completed child join prove different facts. A
nonzero child exit must not become a successful join or an inferred cancellation.
Record cancellation or expiry only from the established context and termination
facts. Preserve unknown output effects independently of process diagnostics.
Output artifacts return closed evidence; they do not own an exporter or emit raw
provider responses. Add tests for early child exit, cancellation, malformed
responses, disabled telemetry and secret exclusion when these boundaries change.

Build `DiagnosticDetails` from reviewed source facts. Keep value entry names, key
IDs, command and attempt IDs, logical paths, configuration field names, error
classes, and HTTP status in their typed fields. A source owner must remove
private path segments before `WithReviewedPath` and must establish that text
is safe before `WithReviewedErrorText`; never pass raw `error.Error()`, response
bodies, credentials, secret values, or key bytes. If text safety is unknown,
use a typed error class and leave the text unavailable. Keep metric attributes
bounded to stable provider, operation, and result values. Invocation and
worker IDs belong in logs and spans, not metric dimensions. Do not add
baggage.

The existing `member_name` JSON field, `member.name` trace attribute and
`member=` console label retain their current `EntryName` meaning: a value entry
name. Retention is scoped to this naming change; it establishes no general
permanence or consumer compatibility guarantee and implies no output-schema
migration.

When metrics are enabled, require a successful `Runtime.AwaitMetrics(ctx)`
before `MeterProvider()` or `ManualReader()`. The getters do not wait for worker
initialization. A nil runtime or disabled metrics returns nil from both getters
and succeeds immediately from `AwaitMetrics`. `SetupOptions.ManualMetrics` adds
a delta reader only when metrics are already enabled; it neither enables
metrics nor replaces the configured exporter readers. `ManualReader()` is nil
without that option. Use `FlushMetrics` before collecting queued measurements.

SDK callbacks can contain unreviewed input. The setup-owned process logger and
error handler count those callbacks and discard their content without
formatting it. `Start` installs both process-wide callbacks once when any log,
metric or trace exporter is enabled. `Close` does not restore earlier callbacks.
The shared callback count is process-wide; a runtime count is the change since
its setup and can include callbacks from other runtimes. Do not replace them
with a default stderr logger or assign a process callback to an arbitrary worker. Destination delivery status retains
the invocation's export failures independently.

Update the owning component tests for call/result counts, reason and severity,
typed fields, and parent/child trace IDs. Include the disabled path, refusal,
success, and relevant failure boundaries. Check that secret sentinels cannot
enter any console, file, or HTTP signal. The shared application and worker
setup lives in `compositions/observability`; select the same schema through
`--telemetry-config` or a workflow `telemetry_config`. Default startup has no
OTel route and keeps WARN stderr logs. Use `tests/telemetry/local.json` for
the common instrumented test-run policy: WARN and higher logs, metrics and
traces with sample ratio 1 through the local file exporter. Saved instrumented
workflow run steps use this one file for both hermetic and live runs. Explicit
configuration and log-level overrides remain available. File, HTTP and combined
exporter routes are independent configuration choices; keep collection settings
the same when comparing routes. Keep Honeycomb routing in the manual smoke file
above; do not add it to ordinary workflows.

Select the affected owner and telemetry checks through `tests/scripts/test`
from the repository root. Plan and run the same saved workflow with the same
exact test selection. The runner supplies the maintained test overlay, module
graph and race settings. Expand the selection only for a stated affected
requirement that the focused checks cannot establish. The `dev` and `check`
workflows are available broader selections, not automatic completion gates.
When an instrumentation or configuration rule changes, update this guide and
the affected tests in the same work.

Immutable Store persistence emits `core.store.persist_immutable` after exact
readback. `immutable_created` records an acknowledged create plus verification;
`immutable_reused` records a known create precondition plus equal bytes without
an earlier possible write. `immutable_verified` records equal bytes when the
write outcome did not establish either relation. Reuse establishes no creator
or creation time. Provider and Core immutable Create records use
`verification_pending` for a known precondition before readback. HEAD and CAS
keep their precondition warnings. Physical unknown-write history stays visible;
the semantic terminal reports its later resolution or remaining failure.

Preparation with only known plugin setup remaining records `setup_incomplete`
with `setup_required`. Dependency assessment, preparation and invocation keep
these facts at DEBUG; the prepare command emits one actionable warning. Overall
incomplete and exit 2 remain. Recovery, delivery, cleanup and diagnostic-delivery
failures keep their separate results and exit precedence.
