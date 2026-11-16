package contract

import (
	"bytes"
	"testing"
)

// These encoders construct public structural seeds, not cryptographic oracles.
// Independent expected bytes remain in the fixed-vector tests.
func addGeneratedFuzzSeeds(f *testing.F) {
	add := func(b []byte, err error) []byte {
		f.Helper()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
		return b
	}
	id := successionTestID
	probe, _ := successorKEKProbeVector()
	seed := seedAccessRow(f)
	value := accessStructuralRow(f, 0, 65, CryptoMaxName)
	add(EncodeAccessRecord(seed.BeforeAccessRecord))
	add(EncodeAccessRecord(value.BeforeAccessRecord))
	add(EncodeCryptoAccessPrepareRequest(CryptoAccessPrepareRequest{OperationRef: id(30), Context: probe.Context, Final: 1, Rows: []CompactRow{value, seed}}))
	// Retained readers can fill the registry while each current entry remains
	// bounded to 64 ordinary recipients, plus the independent recovery wrap.
	union := value
	union.BeforeAccessRecord.Wraps = nil
	for i := 1; i <= CryptoMaxRecipients; i++ {
		wrap := value.BeforeAccessRecord.Wraps[0]
		wrap.SubjectID = ID{30: byte(i >> 8), 31: byte(i)}
		wrap.BindingID = Hash(wrap.SubjectID[:])
		union.BeforeAccessRecord.Wraps = append(union.BeforeAccessRecord.Wraps, wrap)
	}
	union.BeforeAccessRecord.Wraps = append(union.BeforeAccessRecord.Wraps, value.BeforeAccessRecord.Wraps[64])
	var err error
	union.Coverage.BeforeAccessDigest, err = AccessRecordDigest(union.BeforeAccessRecord)
	if err != nil {
		f.Fatal(err)
	}
	add(EncodeAccessRecord(union.BeforeAccessRecord))
	add(EncodeCryptoAccessPrepareRequest(CryptoAccessPrepareRequest{OperationRef: id(30), Context: probe.Context, Final: 1, Rows: []CompactRow{union, seed}}))

	for _, raw := range []uint32{0, CryptoMaxRawValue} {
		core := value.ValueCore
		core.ContentLength, core.RetainedLength = raw, raw
		add(EncodeValueCore(core))
		payload := CanonicalPayload{Profile: 2, CryptoSupportID: core.CryptoSupportID, DataKeyID: core.DataKeyID, DataKeyEpoch: core.DataKeyEpoch,
			CommitmentKeyID: core.CommitmentKeyID, CommitmentKeyEpoch: core.CommitmentKeyEpoch, PackageCheck: value.BeforeAccessRecord.PackageCheck,
			ContentLength: raw, Ciphertext: make([]byte, int(raw)+16), InputEncoding: InputEncodingRaw, RetainedLength: raw}
		entry := ValueEntry{Name: core.Name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID, OriginSnapshot: core.OriginSnapshotID,
			OriginTransition: core.OriginTransitionID, ValueSource: Supplied, ConfidentialityClass: Secret, ValueBytes: add(EncodeCanonicalPayload(payload)), InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, ContentLength: raw, RetainedLength: raw}
		for _, wrap := range value.BeforeAccessRecord.Wraps[:64] {
			entry.Recipients = append(entry.Recipients, wrap.SubjectID)
		}
		add(EncodeValueEntry(entry))
		canonical := add(EncodeRetainedCanonicalRecord(RetainedCanonicalRecord{OriginalSlot: 511, Entry: entry}))
		add(AppendSupportRecord(nil, SupportRecord{Kind: 6, RecordID: entry.ValueState, Body: canonical}))
		source := SealedInputCore{SealedInputCoreFields: SealedInputCoreFields{Schema: SealedInputSchema, Profile: 2, CompatibilityID: core.CompatibilityID,
			CryptoSupportID: core.CryptoSupportID, DomainID: core.DomainID, FileIdentity: id(40), SourceID: id(41),
			DataKeyID: id(44), DataKeyEpoch: 1, ContentLength: raw, InputEncoding: InputEncodingRaw, RetainedLength: raw}, Name: core.Name}
		digest, err := SealedInputCoreDigest(source)
		if err != nil {
			f.Fatal(err)
		}
		transfer := TransferEnvelope{Core: TransferCore{Schema: 2, Profile: 2, CompatibilityID: core.CompatibilityID, CryptoSupportID: core.CryptoSupportID,
			DomainID: core.DomainID, OperationID: id(35), OperationMaterialID: id(36), UsePlanDigest: id(37), EnvelopeID: id(46),
			UseKind: 1, PacketKind: 5, PacketLength: 68, SourceID: source.SourceID, SealedInputCoreDigest: digest}, Ciphertext: make([]byte, 84)}
		add(EncodeSealedInputCore(source))
		add(EncodeTransferCore(transfer.Core))
		add(EncodeTransferEnvelope(transfer))
	}

	parent := generatedRecordParent()
	parentBody := add(EncodeGeneratedParentRecord(parent))
	add(AppendSupportRecord(nil, SupportRecord{Kind: 2, RecordID: parent.OperationID, Body: parentBody}))
	plan := GeneratedParentPlan(parent)
	plan.RequestIdentityDigest = ID{}
	add(EncodeGeneratedParentPlan(plan))
	phase := generatedRecordPhase()
	phaseBody := add(EncodeGeneratedPhaseRecord(phase))
	add(AppendSupportRecord(nil, SupportRecord{Kind: 5, RecordID: phase.OperationID, Body: phaseBody}))
	lineage := generatedRecordLineage()
	lineageBody := add(EncodeGeneratedLineageRecord(lineage))
	add(AppendSupportRecord(nil, SupportRecord{Kind: 8, RecordID: lineage.LineageID, Body: lineageBody}))
	attempt := generatedRecordAttempt()
	attemptBody := add(EncodeGeneratedAttemptRecord(attempt))
	add(AppendSupportRecord(nil, SupportRecord{Kind: 9, RecordID: attempt.AttemptID, Body: attemptBody}))
	duty := generatedRecordDuty()
	dutyBody := add(EncodeGeneratedDutyRecord(duty))
	add(AppendSupportRecord(nil, SupportRecord{Kind: 10, RecordID: duty.DutyID, Body: dutyBody}))
	hazard := generatedRecordHazard()
	hazardBody := add(EncodeGeneratedHazardRecord(hazard))
	add(AppendSupportRecord(nil, SupportRecord{Kind: 11, RecordID: hazard.HazardID, Body: hazardBody}))
	release := generatedRecordRelease()
	releaseBody := add(EncodePendingInboxReleaseRecord(release))
	add(AppendSupportRecord(nil, SupportRecord{Kind: 12, RecordID: release.InboxID, Body: releaseBody}))
	for index := uint16(0); index < 2; index++ {
		n := GeneratedFragmentMaxPayload
		if index == 1 {
			n = 1
		}
		fragment := GeneratedFragment{Schema: 1, BlobID: parent.OperationID, Index: index, Count: 2,
			TotalLength: GeneratedFragmentMaxPayload + 1, WholeDigest: generatedRecordID(19), Offset: uint32(index) * GeneratedFragmentMaxPayload, Payload: make([]byte, n)}
		body := add(EncodeGeneratedFragment(fragment))
		key, err := GeneratorFragmentID(fragment.BlobID, fragment.Index)
		if err != nil {
			f.Fatal(err)
		}
		add(AppendSupportRecord(nil, SupportRecord{Kind: 3, RecordID: key, Body: body}))
	}
	add(EncodeGeneratedEntryMetadata(generatedRecordEntryMetadata()))
	add(EncodeGeneratorAuthoritySubject(generatorAuthorityFixture()))
	add(EncodeGeneratorCapacityEvidence(generatorCapacityFixture()))
	add(EncodeGeneratorDeclaration(generatorDeclarationFixture(f)))
	referenceDeclaration := generatorDeclarationFixture(f)
	referenceDeclaration.Entries[1].Kind = GeneratorDeclarationGeneratedReference
	referenceDeclaration.Entries[1].Payload = generatorDeclarationReferencePayload(f)
	f.Add(referenceDeclaration.Entries[1].Payload)
	add(EncodeGeneratorDeclaration(referenceDeclaration))
	add(EncodeGeneratorSourceUse(generatorGraphSourceUseFixture()))
	for _, populated := range []bool{false, true} {
		bundle := generatorBundleFixture(f, populated)
		add(EncodeGeneratorPlanBundle(bundle))
		add(EncodeGeneratorRequestCore(bundle.Request))
		add(EncodeGeneratorGraphHeader(bundle.Header))
		add(EncodeGeneratorUsePlanCore(bundle.UsePlan))
		for _, entryPlan := range bundle.ValueEntryPlans {
			add(EncodeGeneratorValueEntryPlan(entryPlan))
		}
		for _, lineage := range bundle.Lineages {
			add(EncodeGeneratorLineageTemplate(lineage))
			for _, template := range lineage.Templates[:lineage.TemplateCount] {
				add(EncodeGeneratorAttemptTemplate(template))
			}
		}
		for _, edge := range bundle.Edges {
			add(EncodeGeneratorEdge(edge))
		}
		for _, use := range bundle.ResultUses {
			add(EncodeGeneratorResultUse(use))
		}
	}
	add(EncodeGeneratorSafeFacts(generatedSafeFactsFixture(4)))
	f.Add(generatedVectorMaximumBytes(f))
	for disposition := uint8(1); disposition <= 3; disposition++ {
		_, material, result := generatedResultFixture(f, disposition)
		add(EncodeOperationMaterialCore(material.Core))
		materialBody := add(EncodeOperationMaterialRecord(material))
		add(AppendSupportRecord(nil, SupportRecord{Kind: 1, RecordID: material.Core.OperationMaterialID, Body: materialBody}))
		factsBody := add(EncodeGeneratorSafeFacts(result.SafeFacts))
		coreBody := add(EncodeGeneratedResultCore(result.Core))
		if disposition != 3 {
			evidence := GeneratedCreateEvidence{
				Schema:            GeneratedCreateEvidenceSchema,
				OriginalResultID:  result.Core.ResultID,
				CredentialRouteID: generatedRecordID(21),
				ResultCore:        coreBody,
				SafeFacts:         factsBody,
				Intent:            generatedRecordDescriptor(20),
				CompletionClass:   1,
				LifecycleMode:     GeneratorLifecycleManaged,
			}
			evidenceBody := add(EncodeGeneratedCreateEvidence(evidence))
			add(AppendSupportRecord(nil, SupportRecord{Kind: 13, RecordID: evidence.OriginalResultID, Body: evidenceBody}))
		}
		add(EncodeTransferCore(result.Transfer.Core))
		add(EncodeTransferEnvelope(result.Transfer))
		body := add(EncodeGeneratedResultRecord(result))
		add(AppendSupportRecord(nil, SupportRecord{Kind: 4, RecordID: result.Core.ResultID, Body: body}))
	}
	for purpose := uint8(1); purpose <= 4; purpose++ {
		add(EncodeCryptoGeneratedCompareRequest(generatedCryptoCompareFixture(f, purpose)))
	}
	compare := generatedCryptoCompareFixture(f, 1)
	operation := generatedRecordID(27)
	add(EncodeCryptoGeneratedPlanPartRequest(CryptoGeneratedPlanPartRequest{OperationRef: operation, Context: compare.Context, BlobKind: 2, Count: 1, Total: 4, WholeDigest: Hash([]byte("abcd")), Payload: []byte("abcd")}))
	add(EncodeCryptoGeneratedFinishPlanRequest(CryptoGeneratedFinishPlanRequest{OperationRef: operation, Context: compare.Context, Declaration: compare.ParentPlan.Declaration, Graph: compare.PlanGraph, SourceUses: compare.AcceptedSources}))
	add(EncodeCryptoGeneratedDiscardRequest(CryptoGeneratedDiscardRequest{OperationRef: operation, Context: compare.Context}))
	producer, result := generatedCryptoProducerFixture(f)
	add(EncodeGeneratedProducerPreparation(producer.Preparation))
	commandIntent := generatorIntentFixture(f, generatedRecordID(6), producer.Preparation.ResourceContractID, producer.Preparation.LifecycleMode, []byte("{}"))
	commandPreparation := producer.Preparation
	commandPreparation.IntentDigest, err = GeneratorIntentDigest(commandIntent)
	if err != nil {
		f.Fatal(err)
	}
	add(EncodeGeneratedProducerCommand(GeneratedProducerCommand{GeneratedProducerPreparation: commandPreparation, DeadlineUnixMillis: 1000, Intent: commandIntent}))
	add(EncodeCryptoGeneratedProducerRequest(producer))
	body := add(EncodeGeneratedResultRecord(result))
	add(EncodeCryptoGeneratedAdoptRequest(CryptoGeneratedAdoptRequest{OperationRef: producer.OperationRef, Context: producer.Context, Result: body, ExpectedResult: GeneratorDescriptor{Digest: Hash(body), Length: uint64(len(body)), Count: 1}}))
	frozen := generatedCryptoFrozenFixture(f)
	add(EncodeCryptoGeneratedFreezeRequest(frozen))
	add(EncodeCryptoGeneratedClaimRequest(CryptoGeneratedClaimRequest(frozen)))
	context, input, output := generatedCryptoValueEntryFixture(f)
	for _, populated := range []bool{false, true} {
		request := CryptoGeneratedValueEntriesRequest{OperationRef: operation, Context: context, PhaseID: generatedRecordID(28), Final: 1}
		response := CryptoGeneratedValueEntriesResult{Final: 1}
		if populated {
			request.Rows = []CryptoGeneratedValueEntryPlan{input}
			response.Rows = []CryptoGeneratedValueEntryResult{output}
		}
		add(EncodeCryptoGeneratedValueEntriesRequest(request))
		add(EncodeCryptoGeneratedValueEntriesResult(response))
	}
	add(EncodeCryptoGeneratedCompareResult(CryptoGeneratedCompareResult{OperationRef: operation}))
	add(EncodeCryptoGeneratedPartResult(CryptoGeneratedPartResult{}))
	add(EncodeCryptoGeneratedFinishPlanResult(generatedCryptoFinishResultFixture(f)))
	add(EncodeCryptoGeneratedProducerResult(CryptoGeneratedProducerResult{ProducerLocatorID: operation}))
	add(EncodeCryptoGeneratedAdoptResult(CryptoGeneratedAdoptResult{Result: body}))
}

func generatedFuzzChecks() []func(*testing.T, []byte) {
	return []func(*testing.T, []byte){
		fuzzRecord("generated parent plan", InspectGeneratedParentPlan, EncodeGeneratedParentPlan),
		fuzzRecord("generated parent", DecodeGeneratedParentRecord, EncodeGeneratedParentRecord),
		fuzzRecord("generated phase", DecodeGeneratedPhaseRecord, EncodeGeneratedPhaseRecord),
		fuzzInspected("generated lineage", InspectGeneratedLineageRecord, GeneratedLineageRecordView.Own, DecodeGeneratedLineageRecord, EncodeGeneratedLineageRecord),
		fuzzRecord("generated attempt", DecodeGeneratedAttemptRecord, EncodeGeneratedAttemptRecord),
		fuzzRecord("generated duty", DecodeGeneratedDutyRecord, EncodeGeneratedDutyRecord),
		fuzzRecord("generated hazard", DecodeGeneratedHazardRecord, EncodeGeneratedHazardRecord),
		fuzzRecord("pending inbox release", InspectPendingInboxReleaseRecord, EncodePendingInboxReleaseRecord),
		fuzzRecord("generated member", DecodeGeneratedEntryMetadata, EncodeGeneratedEntryMetadata),
		fuzzInspected("generated fragment", InspectGeneratedFragment, GeneratedFragmentView.Own, DecodeGeneratedFragment, EncodeGeneratedFragment),
		fuzzInspected("generated create evidence", InspectGeneratedCreateEvidence, GeneratedCreateEvidenceView.Own, DecodeGeneratedCreateEvidence, EncodeGeneratedCreateEvidence),
		fuzzRecord("generator authority", DecodeGeneratorAuthoritySubject, EncodeGeneratorAuthoritySubject),
		fuzzRecord("generator capacity", InspectGeneratorCapacityEvidence, EncodeGeneratorCapacityEvidence),
		fuzzOwnedRecord("generator declaration", InspectGeneratorDeclaration, GeneratorDeclarationView.Own, EncodeGeneratorDeclaration),
		fuzzRecord("declared generation reference", InspectGeneratorDeclaredGenerationReference, EncodeGeneratorDeclaredGenerationReference),
		fuzzRecord("generator plan bundle", DecodeGeneratorPlanBundle, EncodeGeneratorPlanBundle),
		fuzzRecord("generator request", InspectGeneratorRequestCore, EncodeGeneratorRequestCore),
		fuzzRecord("generator graph header", InspectGeneratorGraphHeader, EncodeGeneratorGraphHeader),
		fuzzRecord("generator use plan", InspectGeneratorUsePlanCore, EncodeGeneratorUsePlanCore),
		fuzzOwnedRecord("generator member plan", InspectGeneratorValueEntryPlan, GeneratorValueEntryPlanView.Own, EncodeGeneratorValueEntryPlan),
		fuzzOwnedRecord("generator lineage template", InspectGeneratorLineageTemplate, GeneratorLineageTemplateView.Own, EncodeGeneratorLineageTemplate),
		fuzzRecord("generator attempt template", InspectGeneratorAttemptTemplate, EncodeGeneratorAttemptTemplate),
		fuzzRecord("generator edge", InspectGeneratorEdge, EncodeGeneratorEdge),
		fuzzRecord("generator result use", InspectGeneratorResultUse, EncodeGeneratorResultUse),
		fuzzRecord("generator source use", InspectGeneratorSourceUse, EncodeGeneratorSourceUse),
		fuzzRecord("generated result core", InspectGeneratedResultCore, EncodeGeneratedResultCore),
		fuzzInspected("generator safe facts", InspectGeneratorSafeFacts, GeneratorSafeFactsView.Own, DecodeGeneratorSafeFacts, EncodeGeneratorSafeFacts),
		fuzzInspected("generated result", InspectGeneratedResultRecord, GeneratedResultRecordView.Own, DecodeGeneratedResultRecord, EncodeGeneratedResultRecord),
		fuzzRecord("Crypto generated compare", InspectCryptoGeneratedCompareRequest, EncodeCryptoGeneratedCompareRequest),
		fuzzOwnedRecord("Crypto generated plan part", InspectCryptoGeneratedPlanPartRequest, CryptoGeneratedPlanPartRequestView.Own, EncodeCryptoGeneratedPlanPartRequest),
		fuzzRecord("Crypto generated finish plan", InspectCryptoGeneratedFinishPlanRequest, EncodeCryptoGeneratedFinishPlanRequest),
		fuzzRecord("generated producer preparation", InspectGeneratedProducerPreparation, EncodeGeneratedProducerPreparation),
		fuzzOwnedRecord("generated producer command", InspectGeneratedProducerCommand, func(v GeneratedProducerCommand) (GeneratedProducerCommand, error) {
			if _, err := generatedProducerCommandLength(v); err != nil {
				return GeneratedProducerCommand{}, err
			}
			v.Intent = bytes.Clone(v.Intent)
			v.OriginalFacts = bytes.Clone(v.OriginalFacts)
			return v, nil
		}, EncodeGeneratedProducerCommand),
		fuzzOwnedRecord("Crypto generated producer", InspectCryptoGeneratedProducerRequest, CryptoGeneratedProducerRequestView.Own, EncodeCryptoGeneratedProducerRequest),
		fuzzOwnedRecord("Crypto generated adopt", InspectCryptoGeneratedAdoptRequest, CryptoGeneratedAdoptRequestView.Own, EncodeCryptoGeneratedAdoptRequest),
		fuzzRecord("Crypto generated discard", InspectCryptoGeneratedDiscardRequest, EncodeCryptoGeneratedDiscardRequest),
		fuzzRecord("Crypto generated freeze", InspectCryptoGeneratedFreezeRequest, EncodeCryptoGeneratedFreezeRequest),
		fuzzRecord("Crypto generated claim", InspectCryptoGeneratedClaimRequest, EncodeCryptoGeneratedClaimRequest),
		fuzzOwnedRecord("Crypto generated members", InspectCryptoGeneratedValueEntriesRequest, CryptoGeneratedValueEntriesRequestView.Own, EncodeCryptoGeneratedValueEntriesRequest),
		fuzzRecord("Crypto generated compare result", InspectCryptoGeneratedCompareResult, EncodeCryptoGeneratedCompareResult),
		fuzzRecord("Crypto generated part result", InspectCryptoGeneratedPartResult, EncodeCryptoGeneratedPartResult),
		fuzzOwnedRecord("Crypto generated finish result", InspectCryptoGeneratedFinishPlanResult, CryptoGeneratedFinishPlanResultView.Own, EncodeCryptoGeneratedFinishPlanResult),
		fuzzRecord("Crypto generated producer result", InspectCryptoGeneratedProducerResult, EncodeCryptoGeneratedProducerResult),
		fuzzOwnedRecord("Crypto generated adopt result", InspectCryptoGeneratedAdoptResult, CryptoGeneratedAdoptResultView.Own, EncodeCryptoGeneratedAdoptResult),
		fuzzOwnedRecord("Crypto generated members result", InspectCryptoGeneratedValueEntriesResult, CryptoGeneratedValueEntriesResultView.Own, EncodeCryptoGeneratedValueEntriesResult),
	}
}
