// Package telemetry defines the neutral ENKV metric contract and API-only
// instrumentation. Application startup owns the SDK, collection and shutdown.
package telemetry

// ScopeName is the default Core instrumentation scope. Other components have
// their own scope names, resolved by application startup.
const ScopeName = "enkv.sh/core"
const ContractVersion = 1

type Provider string

const (
	ProviderCore          Provider = "core"
	ProviderCrypto        Provider = "crypto"
	ProviderAWS           Provider = "aws"
	ProviderGCP           Provider = "gcp"
	ProviderGeneratorHost Provider = "generatorhost"
	ProviderOutputHost    Provider = "outputhost"
	ProviderManifestHost  Provider = "manifesthost"
	ProviderApplication   Provider = "application"
	ProviderWorker        Provider = "worker"
)

type Operation string

const (
	OpCoreInitialize                           Operation = "core.initialize"
	OpCoreApply                                Operation = "core.apply"
	OpCoreRekeyEnvelope                        Operation = "core.rekey_envelope"
	OpCoreRetireRecipient                      Operation = "core.retire_recipient"
	OpCoreReplaceAuthorityKeys                 Operation = "core.replace_authority_keys"
	OpCoreReplaceRecoveryKeys                  Operation = "core.replace_recovery_keys"
	OpCoreReplaceRecipientKey                  Operation = "core.replace_recipient_key"
	OpCoreReconstruct                          Operation = "core.reconstruct"
	OpCorePrepareRecipientReplacement          Operation = "core.prepare_recipient_replacement"
	OpCorePrepareSuccession                    Operation = "core.prepare_succession"
	OpCoreMutationReceipt                      Operation = "core.mutation_receipt"
	OpCoreInspectSelectedWork                  Operation = "core.inspect_selected_work"
	OpCorePrepareEndSelectedWork               Operation = "core.prepare_end_selected_work"
	OpCoreSelectEndSelectedWork                Operation = "core.select_end_selected_work"
	OpCoreGeneratedPreparePlan                 Operation = "core.generated.prepare_plan"
	OpCoreGeneratedPrepareProducer             Operation = "core.generated.prepare_producer"
	OpCoreGeneratedPrepareRecord               Operation = "core.generated.prepare_record"
	OpCoreGeneratedPrepareFinal                Operation = "core.generated.prepare_final"
	OpCoreGeneratedPrepareCreateResidue        Operation = "core.generated.prepare_create_residue"
	OpCoreGeneratedPrepareLifecycle            Operation = "core.generated.prepare_lifecycle"
	OpCoreGeneratedPrepareSuccessorReservation Operation = "core.generated.prepare_successor_reservation"
	OpCoreGeneratedClaimPreparation            Operation = "core.generated.claim_preparation"
	OpCoreGeneratedClaimDetachedProducer       Operation = "core.generated.claim_detached_producer"
	OpCoreGeneratedClaimOriginalSet            Operation = "core.generated.claim_original_set"
	OpCoreGeneratedReadResult                  Operation = "core.generated.read_result"
	OpCoreGeneratedList                        Operation = "core.generated.list"
	OpCoreReceiptList                          Operation = "core.receipt.list"
	OpCoreReceiptDetail                        Operation = "core.receipt.detail"
	OpCoreInspect                              Operation = "core.inspect"
	OpCoreInspectRecipient                     Operation = "core.inspect_recipient"
	OpCoreInspectCapacity                      Operation = "core.inspect_capacity"
	OpCoreGCPlan                               Operation = "core.gc_plan"
	OpCoreGCValidatePlan                       Operation = "core.gc_validate_plan"
	OpCoreGCApply                              Operation = "core.gc_apply"
	OpCoreGCContinue                           Operation = "core.gc_continue"
	OpCoreGeneratedRetire                      Operation = "core.generated.retire"
	OpCoreGeneratedAcceptRetirementRisk        Operation = "core.generated.accept_retirement_risk"
	OpCoreGeneratedCleanup                     Operation = "core.generated.cleanup"
	OpCorePublicationPlan                      Operation = "core.publication.plan"
	OpCorePublicationExecute                   Operation = "core.publication.execute"
	OpCorePublicationPrepareReservation        Operation = "core.publication.prepare_reservation"
	OpCorePublicationPrepareClose              Operation = "core.publication.prepare_close"
	OpCryptoExchange                           Operation = "crypto.exchange"
	OpCryptoQualifyInitKeys                    Operation = "crypto.qualify_init_keys"
	OpCryptoPlanning                           Operation = "crypto.planning"
	OpCryptoMaterialize                        Operation = "crypto.materialize"
	OpCryptoPlanningDisplay                    Operation = "crypto.planning_display"
	OpCryptoCompare                            Operation = "crypto.compare"
	OpCryptoPrepare                            Operation = "crypto.prepare"
	OpCryptoFreeze                             Operation = "crypto.freeze"
	OpCryptoClaim                              Operation = "crypto.claim"
	OpCryptoDiscard                            Operation = "crypto.discard"
	OpCryptoAccessReplace                      Operation = "crypto.access_replace"
	OpCryptoSealSource                         Operation = "crypto.seal_source"
	OpCryptoConsume                            Operation = "crypto.consume"
	OpCryptoReconstructionVerify               Operation = "crypto.reconstruction.verify_discard"
	OpCryptoGeneratedProducerEntry             Operation = "crypto.generated.producer_entry"
	OpCryptoGeneratedProcess                   Operation = "crypto.generated.process"
	OpCryptoGeneratedResultIntake              Operation = "crypto.generated.result_intake"
	OpCryptoGeneratedResultSeal                Operation = "crypto.generated.result_seal"
	OpCryptoGeneratedReturnSettle              Operation = "crypto.generated.return_settle"
	OpCryptoPublicationPrepare                 Operation = "crypto.publication.prepare"
	OpCryptoPublicationArm                     Operation = "crypto.publication.arm"
	OpCryptoPublicationSend                    Operation = "crypto.publication.send"
	OpCryptoPublicationRetire                  Operation = "crypto.publication.retire"
	OpKeyQualify                               Operation = "key.qualify"
	OpKeyDecrypt                               Operation = "key.decrypt"
	OpCoreOpen                                 Operation = "core.open"
	OpCoreObservationOffer                     Operation = "core.observation_offer"
	OpCoreCompare                              Operation = "core.compare"
	OpCorePlanning                             Operation = "core.planning"
	OpCoreMaterialize                          Operation = "core.materialize"
	OpCoreReaderCompare                        Operation = "core.reader.compare"
	OpCoreReaderManifest                       Operation = "core.reader.manifest"
	OpCoreReaderRecipients                     Operation = "core.reader.recipients"
	OpCorePrepare                              Operation = "core.prepare"
	OpCoreSelect                               Operation = "core.select"
	OpCoreStoreRead                            Operation = "core.store.read"
	OpCoreStorePersistImmutable                Operation = "core.store.persist_immutable"
	OpCoreStoreCreate                          Operation = "core.store.create"
	OpCoreStoreCreateHead                      Operation = "core.store.create_head"
	OpCoreStoreCompareAndSwap                  Operation = "core.store.compare_and_swap"
	OpCoreStoreDeleteIfToken                   Operation = "core.store.delete_if_token"
	OpCoreTrustSign                            Operation = "core.trust.sign"
	OpStoreRead                                Operation = "store.read"
	OpStoreList                                Operation = "store.list"
	OpStoreCreate                              Operation = "store.create"
	OpStoreCompareAndSwap                      Operation = "store.compare_and_swap"
	OpTrustSign                                Operation = "trust.sign"
	OpTrustQualify                             Operation = "trust.qualify"
	OpAuthentication                           Operation = "authentication"
	OpSetupRead                                Operation = "setup.read"
	OpSetupVerifyCloudflare                    Operation = "setup.verify_cloudflare"
	OpSetupGitHubMetadata                      Operation = "setup.github_metadata"
	OpSetupCreate                              Operation = "setup.create"
	OpSetupDelete                              Operation = "setup.delete"
	OpSetupPublicKey                           Operation = "setup.public_key"
	OpCleanup                                  Operation = "cleanup"
	OpGeneratorHostStart                       Operation = "generatorhost.start"
	OpGeneratorHostHandshake                   Operation = "generatorhost.handshake"
	OpGeneratorHostCommandSend                 Operation = "generatorhost.command_send"
	OpGeneratorHostStatusRead                  Operation = "generatorhost.status_read"
	OpGeneratorHostCancel                      Operation = "generatorhost.cancel"
	OpGeneratorHostJoin                        Operation = "generatorhost.join"
	OpOutputHostPublicCheck                    Operation = "outputhost.public_check"
	OpOutputHostDispatch                       Operation = "outputhost.dispatch"
	OpOutputHostHandshake                      Operation = "outputhost.handshake"
	OpOutputHostCommandSend                    Operation = "outputhost.command_send"
	OpOutputHostCredentialGate                 Operation = "outputhost.credential_gate"
	OpOutputHostResultRead                     Operation = "outputhost.result_read"
	OpOutputHostJoin                           Operation = "outputhost.join"
	OpOutputHostCancel                         Operation = "outputhost.cancel"
	OpManifestHostCheck                        Operation = "manifesthost.check"
	OpManifestHostRender                       Operation = "manifesthost.render"
	OpManifestHostJoin                         Operation = "manifesthost.join"
	OpManifestHostCancel                       Operation = "manifesthost.cancel"
	OpApplicationInvocation                    Operation = "application.invocation"
	OpConfigurationCapture                     Operation = "configuration.capture"
	OpConfigurationParse                       Operation = "configuration.parse"
	OpConfigurationWrite                       Operation = "configuration.write"
	OpConfigurationPrepare                     Operation = "configuration.prepare"
	OpConfigurationPrepareDependencies         Operation = "configuration.prepare_dependencies"
	OpPluginResolve                            Operation = "plugin.resolve"
	OpPluginCapture                            Operation = "plugin.capture"
	OpPluginAcquire                            Operation = "plugin.acquire"
	OpPluginSelect                             Operation = "plugin.select"
	OpPluginRetained                           Operation = "plugin.retained"
	OpAdministrativePlanWrite                  Operation = "administrative.plan.write"
	OpGCPlanWrite                              Operation = "gc.plan.write"
	OpInitializationManifest                   Operation = "configuration.initialization_manifest"
	OpWorkerInvocation                         Operation = "worker.invocation"
	OpManifestFileWrite                        Operation = "manifest.file.write"
)

type Result string

const (
	ResultSuccess             Result = "success"
	ResultFailure             Result = "failure"
	ResultUnknown             Result = "unknown"
	ResultUnchanged           Result = "unchanged"
	ResultObservedCurrent     Result = "observed_current"
	ResultContention          Result = "contention"
	ResultUnresolvedCommit    Result = "unresolved_commit"
	ResultIntegrityFailure    Result = "integrity_failure"
	ResultEvidenceUnavailable Result = "evidence_unavailable"
	ResultRootLossUnsupported Result = "root_loss_unsupported"
	ResultAdmissionRefused    Result = "admission_refused"
	ResultInvalid             Result = "invalid"
	ResultDenied              Result = "denied"
	ResultCancelled           Result = "cancelled"
	ResultExpired             Result = "expired"
	ResultAlreadyUsed         Result = "already_used"
	ResultCapacityExceeded    Result = "capacity_exceeded"
	ResultReadOK              Result = "read_ok"
	ResultReadMissing         Result = "read_missing"
	ResultReadUnavailable     Result = "read_unavailable"
	ResultReadInvalid         Result = "read_invalid"
	ResultWriteAcknowledged   Result = "write_acknowledged"
	ResultVerificationPending Result = "verification_pending"
	ResultImmutableCreated    Result = "immutable_created"
	ResultImmutableReused     Result = "immutable_reused"
	ResultImmutableVerified   Result = "immutable_verified"
	ResultSetupIncomplete     Result = "setup_incomplete"
	ResultWritePrecondition   Result = "write_precondition"
	ResultWriteConflict       Result = "write_conflict"
	ResultWriteUnknown        Result = "write_unknown"
	ResultWriteRefused        Result = "write_refused"
	ResultSignOK              Result = "sign_ok"
	ResultSignUnavailable     Result = "sign_unavailable"
	ResultSignInvalid         Result = "sign_invalid"
)

const (
	ManifestSelectedEntries      = "enkv.manifest.selected_entries"
	ManifestIncludedEntries      = "enkv.manifest.included_entries"
	ManifestExcludedEntries      = "enkv.manifest.excluded_entries"
	OperationCalls               = "enkv.operation.calls"
	OperationResults             = "enkv.operation.results"
	OperationDuration            = "enkv.operation.duration"
	OperationInputBytes          = "enkv.operation.input_bytes"
	OperationOutputBytes         = "enkv.operation.output_bytes"
	HTTPAttempts                 = "enkv.http.attempts"
	HTTPResults                  = "enkv.http.results"
	HTTPDuration                 = "enkv.http.duration"
	HTTPRequestBodyBytes         = "enkv.http.request_body_bytes"
	HTTPResponseBodyBytes        = "enkv.http.response_body_bytes"
	HTTPRequestBodyObservations  = "enkv.http.request_body_observations"
	HTTPResponseBodyObservations = "enkv.http.response_body_observations"
)

// Definition is retained with local evidence. Completeness applies in addition
// to collection success; absent, failed or killed collections are unavailable.
type Definition struct {
	Name         string `json:"name"`
	Unit         string `json:"unit"`
	Description  string `json:"description"`
	Completeness string `json:"completeness"`
}

var definitions = [...]Definition{
	{ManifestSelectedEntries, "{entry}", "Selected entries in a complete manifest projection.", "Successful Reader issuance only; equals included plus excluded."},
	{ManifestIncludedEntries, "{entry}", "Included entries in a complete manifest projection.", "Successful Reader issuance only; does not prove remote availability."},
	{ManifestExcludedEntries, "{entry}", "Excluded entries in a complete manifest projection.", "Successful Reader issuance only; no names or exclusion bodies are recorded."},
	{OperationCalls, "{call}", "Started operations at the named component or boundary.", "Compare with operation results for the same provider and operation; unmatched starts are incomplete."},
	{OperationResults, "{call}", "Returned bounded operation results.", "Only returned calls; absence does not establish success or failure."},
	{OperationDuration, "s", "Elapsed operation time through return.", "Only returned calls; nested component and boundary durations overlap and must not be added."},
	{OperationInputBytes, "B", "Logical body, value or signing digest bytes supplied to a returned operation.", "Returned calls only; bytes do not prove remote acceptance. Core and provider boundaries overlap."},
	{OperationOutputBytes, "B", "Logical body or signature bytes returned from an operation.", "Returned calls only; bytes do not establish content validity. Core and provider boundaries overlap."},
	{HTTPAttempts, "{attempt}", "Underlying owned HTTP RoundTrip calls started after local request admission.", "Compare with HTTP results for the same provider and operation; unmatched starts are incomplete."},
	{HTTPResults, "{attempt}", "Returned owned HTTP attempts, with bounded status class and local transport result.", "A returned attempt does not establish complete bodies; use body observations separately."},
	{HTTPDuration, "s", "Elapsed time from underlying RoundTrip start through owned response processing and request joining.", "Returned attempts only; excludes local request construction and authentication performed before this attempt."},
	{HTTPRequestBodyBytes, "B", "Actual request body bytes read at the owned HTTP boundary.", "Status complete is final; incomplete bytes are a partial observation. Excludes headers, TLS and TCP; does not prove server acceptance."},
	{HTTPResponseBodyBytes, "B", "Actual response body bytes read at the owned HTTP boundary.", "Status complete is final; incomplete bytes are a partial observation. Excludes headers, TLS and TCP; not total network traffic."},
	{HTTPRequestBodyObservations, "{observation}", "Request body observations separated by completeness.", "One per returned HTTP attempt; missing or incomplete observations leave total body bytes unknown."},
	{HTTPResponseBodyObservations, "{observation}", "Response body observations separated by completeness.", "One per returned HTTP attempt; an absent response is incomplete, not a zero-byte success."},
}

func Definitions() []Definition { return append([]Definition(nil), definitions[:]...) }

func ValidMetric(name, unit string) bool {
	for _, definition := range definitions {
		if definition.Name == name {
			return definition.Unit == unit
		}
	}
	return false
}

// AllowedAttribute validates the closed instrumentation dimensions. Application
// startup validates configurable resource metadata separately.
func AllowedAttribute(key, value string) bool {
	switch key {
	case "provider":
		return value == string(ProviderCore) || value == string(ProviderCrypto) || value == string(ProviderAWS) || value == string(ProviderGCP) || value == string(ProviderGeneratorHost) || value == string(ProviderOutputHost) || value == string(ProviderManifestHost) || value == string(ProviderApplication) || value == string(ProviderWorker)
	case "operation":
		switch Operation(value) {
		case OpCoreObservationOffer, OpCoreInitialize, OpCoreApply, OpCoreRekeyEnvelope, OpCoreRetireRecipient, OpCoreReplaceAuthorityKeys, OpCoreReplaceRecoveryKeys, OpCoreReplaceRecipientKey, OpCorePrepareRecipientReplacement, OpCorePrepareSuccession, OpCoreMutationReceipt,
			OpCoreInspectSelectedWork, OpCorePrepareEndSelectedWork, OpCoreSelectEndSelectedWork,
			OpCoreGeneratedPreparePlan, OpCoreGeneratedPrepareProducer, OpCoreGeneratedPrepareRecord, OpCoreGeneratedPrepareFinal,
			OpCoreGeneratedPrepareCreateResidue, OpCoreGeneratedPrepareLifecycle, OpCoreGeneratedPrepareSuccessorReservation,
			OpCoreGeneratedClaimPreparation, OpCoreGeneratedClaimDetachedProducer, OpCoreGeneratedClaimOriginalSet, OpCoreGeneratedReadResult,
			OpCoreGeneratedRetire, OpCoreGeneratedAcceptRetirementRisk, OpCoreGeneratedCleanup,
			OpCorePublicationPlan, OpCorePublicationExecute, OpCorePublicationPrepareReservation, OpCorePublicationPrepareClose,
			OpCryptoExchange, OpCryptoQualifyInitKeys, OpCryptoPlanning, OpCryptoMaterialize, OpCryptoPlanningDisplay, OpCryptoCompare, OpCryptoPrepare, OpCryptoFreeze, OpCryptoClaim, OpCryptoDiscard, OpCryptoAccessReplace, OpCryptoSealSource, OpCryptoConsume, OpCryptoReconstructionVerify,
			OpCryptoGeneratedProducerEntry, OpCryptoGeneratedProcess, OpCryptoGeneratedResultIntake, OpCryptoGeneratedResultSeal, OpCryptoGeneratedReturnSettle,
			OpCryptoPublicationPrepare, OpCryptoPublicationArm, OpCryptoPublicationSend, OpCryptoPublicationRetire,
			OpKeyQualify, OpKeyDecrypt:
			return true
		case OpCoreOpen, OpCoreReconstruct, OpCorePlanning, OpCoreMaterialize, OpCoreReaderCompare, OpCoreReaderManifest, OpCoreReaderRecipients, OpCoreGeneratedList, OpCoreReceiptList, OpCoreReceiptDetail, OpCoreInspect, OpCoreInspectRecipient, OpCoreInspectCapacity, OpCoreGCPlan, OpCoreGCValidatePlan, OpCoreGCApply, OpCoreGCContinue, OpCoreCompare, OpCorePrepare, OpCoreSelect, OpCoreStoreRead, OpCoreStorePersistImmutable, OpCoreStoreCreate, OpCoreStoreCreateHead, OpCoreStoreCompareAndSwap, OpCoreStoreDeleteIfToken, OpCoreTrustSign,
			OpStoreRead, OpStoreList, OpStoreCreate, OpStoreCompareAndSwap, OpTrustSign, OpTrustQualify, OpAuthentication, OpSetupRead, OpSetupCreate, OpSetupDelete, OpSetupPublicKey, OpCleanup,
			OpGeneratorHostStart, OpGeneratorHostHandshake, OpGeneratorHostCommandSend, OpGeneratorHostStatusRead, OpGeneratorHostCancel, OpGeneratorHostJoin,
			OpOutputHostPublicCheck, OpOutputHostDispatch, OpOutputHostHandshake, OpOutputHostCommandSend, OpOutputHostCredentialGate, OpOutputHostResultRead, OpOutputHostJoin, OpOutputHostCancel,
			OpManifestHostCheck, OpManifestHostRender, OpManifestHostJoin, OpManifestHostCancel,
			OpApplicationInvocation, OpWorkerInvocation, OpSetupVerifyCloudflare, OpSetupGitHubMetadata, OpConfigurationCapture, OpConfigurationParse, OpConfigurationWrite, OpConfigurationPrepare, OpConfigurationPrepareDependencies, OpAdministrativePlanWrite, OpGCPlanWrite, OpInitializationManifest, OpManifestFileWrite, OpPluginResolve, OpPluginCapture, OpPluginAcquire, OpPluginSelect, OpPluginRetained:
			return true
		}
	case "result":
		switch Result(value) {
		case ResultInvalid, ResultDenied, ResultCancelled, ResultExpired, ResultAlreadyUsed, ResultCapacityExceeded:
			return true
		case ResultSuccess, ResultFailure, ResultUnknown, ResultUnchanged, ResultObservedCurrent, ResultContention, ResultUnresolvedCommit, ResultIntegrityFailure, ResultEvidenceUnavailable, ResultRootLossUnsupported, ResultAdmissionRefused,
			ResultVerificationPending, ResultImmutableCreated, ResultImmutableReused, ResultImmutableVerified, ResultSetupIncomplete, ResultReadOK, ResultReadMissing, ResultReadUnavailable, ResultReadInvalid, ResultWriteAcknowledged, ResultWritePrecondition, ResultWriteConflict, ResultWriteUnknown, ResultWriteRefused, ResultSignOK, ResultSignUnavailable, ResultSignInvalid:
			return true
		}
	case "status":
		switch value {
		case "none", "1xx", "2xx", "3xx", "4xx", "5xx", "other", "complete", "incomplete":
			return true
		}
	}
	return false
}

// ValidOperationOwner closes the operation namespace at its emitting layer.
func ValidOperationOwner(provider Provider, operation Operation) bool {
	switch provider {
	case ProviderCore:
		switch operation {
		case OpCoreObservationOffer, OpCoreInitialize, OpCoreApply, OpCoreRekeyEnvelope, OpCoreRetireRecipient, OpCoreReplaceAuthorityKeys, OpCoreReplaceRecoveryKeys, OpCoreReplaceRecipientKey, OpCorePrepareRecipientReplacement, OpCorePrepareSuccession, OpCoreMutationReceipt,
			OpCoreInspectSelectedWork, OpCorePrepareEndSelectedWork, OpCoreSelectEndSelectedWork,
			OpCoreGeneratedPreparePlan, OpCoreGeneratedPrepareProducer, OpCoreGeneratedPrepareRecord, OpCoreGeneratedPrepareFinal,
			OpCoreGeneratedPrepareCreateResidue, OpCoreGeneratedPrepareLifecycle, OpCoreGeneratedPrepareSuccessorReservation,
			OpCoreGeneratedClaimPreparation, OpCoreGeneratedClaimDetachedProducer, OpCoreGeneratedClaimOriginalSet, OpCoreGeneratedReadResult,
			OpCoreGeneratedRetire, OpCoreGeneratedAcceptRetirementRisk, OpCoreGeneratedCleanup,
			OpCorePublicationPlan, OpCorePublicationExecute, OpCorePublicationPrepareReservation, OpCorePublicationPrepareClose,
			OpCoreOpen, OpCoreReconstruct, OpCorePlanning, OpCoreMaterialize, OpCoreReaderCompare, OpCoreReaderManifest, OpCoreReaderRecipients, OpCoreGeneratedList, OpCoreReceiptList, OpCoreReceiptDetail, OpCoreInspect, OpCoreInspectRecipient, OpCoreInspectCapacity, OpCoreGCPlan, OpCoreGCValidatePlan, OpCoreGCApply, OpCoreGCContinue, OpCoreCompare, OpCorePrepare, OpCoreSelect, OpCoreStoreRead, OpCoreStorePersistImmutable, OpCoreStoreCreate,
			OpCoreStoreCreateHead, OpCoreStoreCompareAndSwap, OpCoreStoreDeleteIfToken, OpCoreTrustSign:
			return true
		}
	case ProviderCrypto:
		switch operation {
		case OpCryptoExchange, OpCryptoQualifyInitKeys, OpCryptoPlanning, OpCryptoMaterialize, OpCryptoPlanningDisplay, OpCryptoCompare, OpCryptoPrepare, OpCryptoFreeze,
			OpCryptoClaim, OpCryptoDiscard, OpCryptoAccessReplace, OpCryptoSealSource, OpCryptoConsume, OpCryptoReconstructionVerify,
			OpCryptoGeneratedProducerEntry, OpCryptoGeneratedProcess, OpCryptoGeneratedResultIntake, OpCryptoGeneratedResultSeal, OpCryptoGeneratedReturnSettle,
			OpCryptoPublicationPrepare, OpCryptoPublicationArm, OpCryptoPublicationSend, OpCryptoPublicationRetire:
			return true
		}
	case ProviderAWS, ProviderGCP:
		switch operation {
		case OpKeyQualify, OpKeyDecrypt, OpStoreRead, OpStoreList, OpStoreCreate, OpStoreCompareAndSwap, OpTrustSign,
			OpTrustQualify, OpAuthentication, OpSetupRead, OpSetupCreate, OpSetupDelete, OpSetupPublicKey, OpCleanup:
			return true
		}
	case ProviderGeneratorHost:
		switch operation {
		case OpGeneratorHostStart, OpGeneratorHostHandshake, OpGeneratorHostCommandSend, OpGeneratorHostStatusRead, OpGeneratorHostCancel, OpGeneratorHostJoin:
			return true
		}
	case ProviderOutputHost:
		switch operation {
		case OpOutputHostPublicCheck, OpOutputHostDispatch, OpOutputHostHandshake, OpOutputHostCommandSend,
			OpOutputHostCredentialGate, OpOutputHostResultRead, OpOutputHostJoin, OpOutputHostCancel:
			return true
		}
	case ProviderManifestHost:
		return operation == OpManifestHostCheck || operation == OpManifestHostRender || operation == OpManifestHostJoin || operation == OpManifestHostCancel
	case ProviderApplication:
		return operation == OpApplicationInvocation || operation == OpConfigurationCapture || operation == OpConfigurationParse || operation == OpConfigurationWrite || operation == OpConfigurationPrepare || operation == OpConfigurationPrepareDependencies || operation == OpAdministrativePlanWrite || operation == OpGCPlanWrite || operation == OpInitializationManifest || operation == OpManifestFileWrite || operation == OpPluginResolve || operation == OpPluginCapture || operation == OpPluginAcquire || operation == OpPluginSelect || operation == OpPluginRetained
	case ProviderWorker:
		return operation == OpWorkerInvocation || operation == OpSetupVerifyCloudflare || operation == OpSetupGitHubMetadata
	}
	return false
}

func ValidAttributes(attributes map[string]string) bool {
	for key, value := range attributes {
		if !AllowedAttribute(key, value) {
			return false
		}
	}
	return true
}
