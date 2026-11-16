# Configuration library API

Import `enkv.sh/compositions/full` as `compositionfull`. The file-level
operations below are the supported library counterparts of the `enkv` commands.
They keep their current package paths and types. This is the current API; it
does not promise unchanged signatures across future releases.

Use a nonnil context with a finite deadline, explicit absolute paths and
`configuration.JSON` or `configuration.YAML`. A request ID is a fresh nonzero
`contract.ID`, a 32-byte value. An operation ID used for continuation or receipt
lookup instead names the exact existing operation. Neither ID grants authority.
The file-level functions capture and close their own source pairs and installed
resources. A returned result describes the invocation's checked facts, not a
live connection or permission for a later call.

## Operations and result consumption

In this table, names without a package prefix are in `compositionfull`.
`configuration` is `enkv.sh/compositions/configuration`, `core` is `enkv.sh/core`,
and `contract` is `enkv.sh/core/contract`.

| Command or operation | Callable operation | Returned result and consumption helpers |
|---|---|---|
| `init` | `InitializeConfiguration` | `InitializationResult`, error; `RenderInitializationJSON/Human`, `InitializationExitCode` |
| `set` | `SetConfiguration` | `*SetResult`, error; `RenderSetJSON/Human`, `SetExitCode` |
| `prepare` | `PrepareConfiguration` | `*PrepareResult`, error; `RenderPrepareJSON/Human`, `PrepareExitCode` |
| `rename` | `RenameConfigurationDomain` | `*LocalEditResult`, error; `RenderLocalEditJSON/Human`, `LocalEditExitCode` |
| `recipients add` | `PrepareConfigurationRecipient` | Same local-edit result and helpers |
| `recipients rename` | `RenameConfigurationRecipientReference` | Same local-edit result and helpers |
| `recover` | `RecoverConfigurationEdit` | Same local-edit result and helpers |
| `apply` | `ApplyConfigurationFile` | `core.PublicApplyResult`; `RenderApplyJSON/Human`, `MutationExitCode` |
| `apply --operation` | `ContinueConfigurationApplyFile` | Same apply result and helpers |
| `apply --publish` | `ApplyConfigurationAndPublishFile` | `core.PublicApplyPublicationResult`; `WriteApplyPublicationJSON/Human` |
| Continued apply with publication | `ContinueConfigurationApplyAndPublishFile` | Same combined result and helpers |
| `publish` | `PublishConfigurationFile` | `core.PublicPublicationResult`; `RenderPublicationJSON/Human`, `PublicationExitCode` |
| `generated list` | `ListConfigurationGeneratedFile` | `core.PublicGeneratedListResult`; `RenderGeneratedListJSON/Human`, `PublicQueryExitCode` on `PublicQueryResult` |
| `generated retire` | `RetireConfigurationGeneratedFile` | `core.PublicApplyResult`; `RenderGeneratedMutationJSON/Human`, `MutationExitCode` |
| Continued retirement | `ContinueConfigurationGeneratedRetirementFile` | Same generated mutation result and helpers |
| Accept retirement risk | `AcceptConfigurationGeneratedRetirementRiskFile` | Same generated mutation result and helpers |
| `generated cleanup` | `CleanupConfigurationGeneratedFile` | Same generated mutation result and helpers |
| Continued cleanup | `ContinueConfigurationGeneratedCleanupFile` | Same generated mutation result and helpers |
| Public `plan` | `CompareConfigurationFiles` | `ConfigurationComparisonResult`; `RenderComparisonJSON/Human`, `ComparisonExitCode` |
| Private `plan` | `PlanConfigurationFiles` | `ConfigurationPlanningResult`; `RenderPlanningJSON/Human`, `RenderPlanningCommandJSON`, `PlanningExitCode` |
| Selected private display | `DisplayConfigurationFiles` | Same planning result; `NewPlanningDisplayFile`, `WritePlanningResult` |
| `inspect` | `InspectConfigurationFile` | `core.PublicDomainInspectionResult`; `WriteInspectionJSON/Human`, `PublicQueryExitCode` on `PublicQueryResult` |
| Recipient inspection | `InspectConfigurationRecipientFile` | `core.PublicRecipientInspectionResult`; `WriteRecipientInspectionJSON/Human`, same query exit helper |
| Capacity inspection | `InspectConfigurationCapacityFile` | `core.PublicCapacityInspectionResult`; `WriteCapacityInspectionJSON/Human`, same query exit helper |
| Receipt list | `ListConfigurationReceiptsFile` | `core.PublicReceiptListResult`; `WriteReceiptListJSON/Human`, same query exit helper |
| Receipt detail | `ReadConfigurationReceiptFile` | `core.PublicReceiptDetailResult`; `WriteReceiptDetailJSON/Human`, same query exit helper |
| Manifest file | `WriteConfigurationManifestFile` | `ManifestFileResult`; `WriteManifestFileJSON/Human`, `RenderManifestFileJSON/Human`, `ManifestFileExitCode` |
| Materialization | `MaterializeConfigurationFile` | `core.MaterializationResult`, error; `WriteMaterializationJSON/Human`, `MaterializationExitCode` |
| Abandon list, plan, apply or receipt | `AbandonConfigurationFile` | `AbandonmentResult`; `WriteAdministrativeJSON/Human`, `AbandonmentExitCode` |
| GC plan | `PlanConfigurationGCFile` | `GCPlanResult`; `WriteGCPlanJSON/Human`, `GCPlanExitCode` |
| GC apply or continuation | `ApplyConfigurationGCFile` | `GCApplyResult`; `WriteGCApplyJSON/Human`, `GCApplyExitCode` |
| Key replacement | `ReplaceKeysConfiguration` | `ReplacementCommandResult`; `WriteReplacementJSON/Human`, `ReplacementCommandExitCode` |
| Envelope rekey | `RekeyConfigurationEnvelopeFile` | `MaintenanceCommandResult`; `RenderMaintenanceCommandJSON/Human` |
| Recipient retirement | `RetireConfigurationRecipientFile` | Same maintenance result and helpers |

`Render…` returns an owned byte slice and an error. `Write…` borrows the supplied
writer for that call and reports write failure. JSON library output uses
two-space indentation and multiline nonempty collections, with no automatic
final line feed. Keep the operation result even when rendering,
delivery or cleanup fails. A known selected change and a local delivery failure
can both be true. Never repeat the operation to repair presentation.

Human renderers give command-specific summaries. Maintenance and replacement
keep the operation outcome, successor delivery, current source relation and
required recovery separate; JSON retains the complete safe machine record.

`PrepareConfiguration` can restore a confirmed absent companion while preserving
the surviving source. Supply the complete independent `PrepareRecoveryRequest`;
its layout fields must match that source. The result's `missing_inputs` array
lists the complete validated set of missing supplied inputs. Recorded delivery
can remain incomplete with exit `2`. Use `SetConfiguration` for one listed name;
other missing inputs and valid present records remain intact. Repeated prepare
with the companion present uses existing-pair admission, and ordinary consumers
remain strict until all input is supplied. Read the array through the result
renderers together with recovery, delivery and dependency facts.

Pass the actual returned result to its helpers. `PrepareResult` and
`LocalEditResult` have no public constructors for successful outcomes.
`SetResult` exposes public facts but also retains private delivery witnesses.
Filling or copying exported fields cannot manufacture a valid successful result.
The rendering helpers check the retained facts. The corresponding `New…Refusal`
helpers used by the CLI construct bounded refusal results when dispatch fails
before an operation can run.

The exit helpers report operation outcomes; the caller must also handle its own
presentation error. Preserve an existing unavailable or unknown exit (`3`).
Otherwise a failed presentation gives failure (`2`). Public comparison's
verified-difference exit (`1`) is distinct from failure. Combined apply and
publication retain both results; combine their exit categories with `3` before
`2` before `0`. An unstarted publication stage cannot count as publication
success. Maintenance results additionally require successful local delivery:
`Delivery.Failed` or `Delivery.CleanupFailed` gives failure unless the mutation
already requires exit `3`.

## Recipient selectors

The existing reference-based and exact-ID operations in the table remain
available. The CLI uses the selector-aware counterparts below when it accepts
both `--recipient` and `--recipient-id`. `RecipientSelector{Reference: "app"}`
selects a local alias; `RecipientSelector{ID: id}` selects an exact identity.
Set at most one field. An alias resolves only through its ENKV-managed ID in
the same captured or locked configuration pair used by the operation. An
unknown alias refuses; it does not fall back to ID parsing or Authority.

| Operation | Selector-aware callable |
|---|---|
| Prepare recipient data | `PrepareConfigurationSelectedRecipient(ctx, path, format, selector, options)` |
| Rename a local recipient reference | `RenameConfigurationSelectedRecipient(ctx, path, format, selector, newReference)` |
| Inspect recipient metadata | `InspectConfigurationSelectedRecipientFile(ctx, nonce, path, format, selector)` |
| Materialize current values | `MaterializeConfigurationRecipientFile(ctx, request, path, format, outPath, selector)` |
| Retire an ordinary recipient | `RetireConfigurationSelectedRecipientFile(ctx, nonce, path, format, selector, outputPath)` |
| Replace a recipient key | `ReplaceSelectedRecipientKeysConfiguration(ctx, nonce, path, format, request, outputPath, selector)` |

These counterparts use the same result types and handling rules as their
operations above. Lifecycle operations need an existing local declaration when
selecting by ID. Recipient creation instead requires a reference and allocates
a new ID. Read operations can select an exact ID absent from local declarations;
authenticated Store state still determines current identity and membership.

A zero selector selects current Authority only for materialization, including
shared entries. For alias-based materialization, leave `request.RecipientID`
zero. A nonzero `request.RecipientID` must match `selector.ID`. The existing
`MaterializeConfigurationFile` and borrowed-pair `MaterializeConfiguration`
continue to use `request.RecipientID` directly, with zero selecting current
Authority. Recipient inspection and lifecycle calls require an explicit target.
Domain inspection remains the separate `InspectConfigurationFile` operation.
For `ReplaceSelectedRecipientKeysConfiguration`, use `ReplaceRecipient` as the
request target. Leave `request.RecipientReference` empty or make it agree with
the selected local reference.

Manifests use `ManifestOptions.TargetRecipientReference` for an alias or
`TargetRecipientID` for an exact ID, exclusively, with `TargetMode` set to
`manifest.ExactRecipient`. `manifest.CurrentAuthority` requires both target
fields empty and includes shared entries authorized for Authority. Alias
resolution completes in the captured source pair before renderer capture.
Aliases remain a composition-level input; Core and manifest protocols receive
resolved stable IDs. Neither selection form changes membership, credentials or
private key permissions.

## Request declarations

These are the current request declarations required by the operations above.
The linked source owns field types, numeric enum values and validation.

| Declaration | Supported fields and values |
|---|---|
| [PrepareRequest](configuration_prepare.go) | `Source`, `Upgrade`, `Format`, `Recovery` |
| [PrepareRecoveryRequest](configuration_prepare.go) | `Name`, `Bucket`, `Region`, `Provider`, `Prefix`, `NormalSigningKey`, `RecoverySigningKey`, `ExpectedDomain`, `ExpectedOwner`, `ExpectedAuthorityEncryptionKey`. `Provider` uses `contract.AWS` or `contract.GCP`. Pointer fields distinguish omission from explicit empty or zero values. |
| [SetOptions](configuration_set.go) | `Confidential`, `Base64` |
| [RecipientSelector](configuration_recipient_selection.go) | `Reference` or `ID`, exclusively; the zero value selects current Authority only for materialization. |
| [RecipientPreparationOptions](configuration_recipient_preparation.go) | `Mode`, `Declaration`; `RecipientPreparationCurrent` or `RecipientPreparationCreate` |
| [configuration.RecipientDeclaration](../configuration/recipient_preparation.go) | `DisplayName`, `EncryptionSelector` |
| [ApplyOptions](apply.go) | `RetirementPlugins`, a map from configured entry name to selected plugin ID |
| [PublicationOptions](publication.go) | `Request`, `DeletePlugins` |
| [core.PublicationRequest](../../core/installed_publication.go) | `Names`, `DeleteCoordinates`, `RepublishAfterUnknown`; coordinate IDs remain exact retained identities |
| [Generated requests](../../core/installed_generated_retirement.go) | `core.GeneratedRetirementRequest.DutyID`; `core.GeneratedRetirementContinuationRequest.OperationID`; `core.GeneratedRetirementRiskRequest.DutyID` and `AttemptID` |
| [Cleanup continuation](../../core/installed_generated_cleanup.go) | `core.GeneratedCleanupContinuationRequest.OperationID` |
| [contract.ComparisonOptions](../../core/contract/publication_preview.go) | `Publish` |
| [contract.PlanningOptions](../../core/contract/private_planning.go) | `Publish`, `Purpose`, `SelectedNames`, `SinkID`; the public private-comparison form uses `PlanningEquality`. Selected display uses its separate factory argument. |
| [core.CapacityInspectionRequest](../../core/installed_capacity_reader.go) | `RequestNonce`, `Cursor` |
| [ManifestOptions](configuration_manifest.go) | `Plugin`, `Settings`, `TargetMode`, `EntryMode`, `TargetRecipientID`, `TargetRecipientReference`, `EntryNames`, `ServiceFilter`. The target reference and ID are exclusive and valid only with `ExactRecipient`; `CurrentAuthority` requires both empty. Modes are `manifest.CurrentAuthority` or `ExactRecipient`, and `AllAuthorized` or `ExactNames`, from `enkv.sh/sdk/manifest-generator`. `ExactNames` requires a nonnil slice; empty selects none. `AllAuthorized` requires nil. An absent service filter differs from an explicitly empty filter. |
| [contract.MaterializationRequest](../../core/contract/materialization.go) | `RequestNonce`, `Names`, `RecipientID` |
| [AbandonmentRequest](configuration_abandonment.go) | `Operation`, `TargetGroupID`, `OperationID`, `PlanPath`, `ArtifactPath`; the operation uses `core.AdministrativeList`, `AdministrativePlan`, `AdministrativeApply` or `AdministrativeReceipt` |
| [GCPlanRequest](gc_plan.go) | `RequestNonce`, `OperationID`, `Cursor`, `ArtifactPath` |
| [GCApplyRequest](configuration_gc.go) | `RequestNonce`, `PlanPath`, `OperationID`; select a fresh plan path or an existing exact operation, not both |
| [configuration.ReplacementRequest](../configuration/replacement_metadata.go) | `Target`, `RecipientReference`, `SigningSelector`, `EncryptionSelector`, `Authorizer`, `MaterialSource`. Targets are `ReplaceAuthority`, `ReplaceRecovery`, `ReplaceRecipient`. The authorizer uses `contract.NormalSigningRole` or `RecoverySigningRole`; material source is `authority` or `recovery` under the selected operation's rules. |

`configuration.Format` and its `JSON` and `YAML` constants are declared in
[model.go](../configuration/model.go). `contract.ID`, its `IsZero` method,
`Family`, `AWS` and `GCP` keep their existing [contract owner](../../core/contract/contract.go).
The [operator guide](README.md) gives the valid combinations and evidence limits
for each operation; a request struct's zero value is not generally valid.

## Result declarations

The named result types in the operation table are supported as producer-returned
values accepted by the listed helpers. This does not select general Core,
Crypto, provider or composition constructors as a public construction API.
The following direct fields are available for the same result handling used by
the CLI. Use the renderers for the complete closed result, including nested
payloads, evidence and safe diagnostics.

| Result owner | Direct fields used by a caller |
|---|---|
| [InitializationResult](initialization.go) | Embedded `core.PublicInitializationResult`, `PreAdmission`, `EditablePath`, `GeneratedPath`, `ManifestPath`; keep delivered paths after a later remote failure |
| [SetResult](configuration_set_result.go) | `EditablePath`, `GeneratedPath`, `Confidential`, `StateResult`, `OperationID`, `RequestNonce`, `RequestIdentity`, `PreAdmission`, `Payload`; `SetStateResult` and its `SetSuccess`, `SetRefused`, `SetProfileBlocked`, `SetUnavailable`, `SetPositiveDefect` constants |
| [ConfigurationComparisonResult and ConfigurationPlanningResult](configuration_plugin_requirements.go) | Embedded `core.PublicComparisonResult` or `core.PlanningResult`, plus `InstallationRequirements`; its `Complete` and `Differences`, and difference `Name`, `Trusted`, `Candidate` with `Version` |
| [core.PublicApplyResult](../../core/installed_apply.go) | `Result`, `Diagnostics`, optional `Preparation`; use the full result with the apply/generated renderers. `Result.Outcome`, `Generated.StateResult` and `Generated.EffectSummary` contribute to mutation exit handling. |
| `core.ApplyPreparationFacts` | `AcknowledgedCreates uint64`, `VerifiedPreparations uint64`, `PossibleUnacknowledgedCreate bool`; invocation-local facts returned through `PublicApplyResult.Preparation` |
| [core.PublicApplyPublicationResult](../../core/installed_apply_publication.go) | `Apply`, `Publication`; the latter's `Stage`, `Reason`, `Result` keep an unstarted publication separate from an evaluated result |
| [core.PublicPublicationResult](../../core/installed_publication.go) | `ExecutableCleanupFailed` reports a positive failure to remove temporary executable files or their directory, separately from the actual publication result |
| [core.PublicQueryResult](../../core/public_query.go) | Embedded `PublicQueryResult` in the inspection, receipt, generated-list and capacity results is accepted by `PublicQueryExitCode` |
| [ManifestFileResult](manifest_file_result.go) | `Issuance`, `Delivery`, `SourceCleanup`, `ResultDelivery`; use `ManifestSourceComplete` and the `ManifestResultNotObserved`, `ManifestResultFailed`, `ManifestResultComplete` delivery constants when the caller owns final presentation |
| [ReplacementCommandResult](configuration_replacement_command.go) | `Authority`, `Recovery`, `Recipient`, `Observation`, `PreAdmission`, `Delivery`; exactly one mutation/observation form is populated. `ReplacementCommandDelivery` exposes `Path`, `Status`, `Failed`, `CleanupFailed`, `RecoverySource`. |
| [MaintenanceCommandResult](configuration_maintenance.go) | Embedded `core.PublicApplyResult`, `Observation`, `Delivery`, `SourceUsability`, `OutputPins` |
| [AbandonmentResult](configuration_abandonment.go) | `Operation`, `Delivery`; delivery exposes `PlanCreated`, `PlanSynced`, `PlanReadback`, `PlanFailed`, `CleanupFailed` |
| [GCPlanResult](gc_plan.go) | `Operation`, `Delivery`, with the same five plan-delivery field names |
| [GCApplyResult](configuration_gc.go) | `Operation`, `Delivery`, `PreAdmission`; delivery exposes `CleanupFailed` |

The shared [core.Result](../../core/state.go) fields used by result handling
are `Outcome`, `Reason`, `RequestedRevision`, `ObservedRevision`,
`ObservedSnapshotID`, `Evidence`, `CommitMayHaveOccurred` and `StoreReason`.
`core.Outcome` is `Unchanged`, `ObservedCurrent`, `Contention`,
`UnresolvedCommit`, `IntegrityFailure`, `EvidenceUnavailable`,
`RootLossUnsupported` or `AdmissionRefused`. `core.Evidence` is `NoEvidence` or
`AuthenticatedClosure`. A `contract.Diagnostic` keeps its closed `Subject`, `Path`,
`Outcome` and `Reason`; `DiagnosticUnable` is unavailable evidence, and
`ReasonMissingRequiredField` can explain a missing generated file. Treat those
typed fields as checked facts and keep raw errors out of machine result records.
Enum values belong to their source declarations; do not reproduce them as
numeric literals in a client.

`Preparation` is an owned optional record for this invocation. Each logical
immutable persistence episode contributes at most once to `AcknowledgedCreates`
when Create is positively acknowledged, and at most once to
`VerifiedPreparations` when exact-byte readback completes. The counters are
independent: verification can succeed without an acknowledgement, including
equal pre-existing bytes or a lost reply followed by exact readback. Physical
retries stay within one episode. A later episode for the same key counts again;
the counters count neither unique objects nor HTTP calls.

`PossibleUnacknowledgedCreate` records that an unknown Create might have entered
transport. Later acknowledgement or verification does not erase that history.
Positive `NotSent` excludes that request from it. HEAD writes and external
generator/output effects have separate facts. Nil `Preparation` means facts are
not supplied. Neither nil nor zero counters prove absence or zero physical writes.
A fresh invocation, including Continue, starts new counters. The record stays
on the Apply side of combined output and supplies no historical counts through
receipts, commit proof, recovery, retry or cleanup authority.

`ExecutableCleanupFailed` renders as optional
`executable_cleanup_failed: true` and the same human-readable failure. False or
omission does not prove cleanup success. This local fact preserves the actual
publication outcome; it cannot qualify a result that failed correlation, EOF,
process completion, private-resource closure or the original lifetime. It adds
no retry right and is not stored publication evidence or a compact receipt.

## Ownership and private display

`SetConfiguration` takes ownership of its `io.ReadCloser` on entry, including
preflight refusal. It closes it once. Do not read, close or retain aliases to that
input concurrently. Mutable request slices, maps and byte input must remain
stable while the call captures them. Returned render buffers belong to the
caller. Writers supplied to result writers remain caller-owned.

`DisplayConfigurationFiles` takes the existing
[`crypto.PlanningDisplayFactory`](../../crypto/planning_display.go):
`Identity() contract.ID` and
`Acquire(context.Context) (crypto.PlanningDisplaySink, error)`.
Acquisition must return when its context ends and transfer any returned sink,
even on error. A sink has `Identity() contract.ID`,
`Accept(context.Context, string, contract.PlanningSourceForm, []byte) error`,
and `Close() error`. `PlanningSourceForm` is `PlanningSealed` or
`PlanningRetained` from the [planning contract](../../core/contract/private_planning.go).

`Accept` borrows one authenticated value only until it returns. Retain no alias;
own and clear any mutable encoding. `Close` must unblock and join entered
transfers and reject later calls. The factory and sink stay outside Core.
Display completion grants no apply or replay permission.

On supported Unix platforms, `NewPlanningDisplayFile(*os.File, structured)`
supplies this contract. It leaves the supplied descriptor open. Its sink owns a
duplicate and temporarily owns nonblocking status for the shared open file
description. Make no other use of that description during display. The call
joins writes and restores status before final result output; use
`WritePlanningResult` for that final safe write. Preserve an incomplete display
result even when the private comparison itself completed.

The external-package [calling examples](library_example_test.go) show preparation
result handling and the existing display factory without private constructors.
