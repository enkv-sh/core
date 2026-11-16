package core

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	protocol "enkv.sh/sdk/protocols/generator"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func generatedEffectPlanFixture(t testing.TB, sources ...contract.GeneratorDeclarationEntry) (contract.GeneratorPlanBundle, contract.GeneratorDeclaration, contract.GeneratedParentRecord) {
	return generatedEffectPlanForRequest(t, nil, sources...)
}

func generatedEffectPlanForRequest(t testing.TB, request *contract.GeneratorRequestCore, sources ...contract.GeneratorDeclarationEntry) (contract.GeneratorPlanBundle, contract.GeneratorDeclaration, contract.GeneratedParentRecord) {
	return generatedEffectPlanForAuthority(t, request, generatedVectorID(11), sources...)
}

func generatedEffectPlanForAuthority(t testing.TB, request *contract.GeneratorRequestCore, authority contract.ID, sources ...contract.GeneratorDeclarationEntry) (contract.GeneratorPlanBundle, contract.GeneratorDeclaration, contract.GeneratedParentRecord) {
	return generatedEffectPlanForGenerationNames(t, request, authority, []string{"generated"}, sources...)
}

func generatedEffectPlanForGenerationNames(t testing.TB, request *contract.GeneratorRequestCore, authority contract.ID, names []string, sources ...contract.GeneratorDeclarationEntry) (contract.GeneratorPlanBundle, contract.GeneratorDeclaration, contract.GeneratedParentRecord) {
	return generatedEffectPlanForGenerationIntent(t, request, authority, names, []byte(`{"name":"generated"}`), sources...)
}

type generatedFixtureProfile struct {
	LifecycleMode                                                                     contract.GeneratorLifecycleMode
	ResultReaderID                                                                    contract.ID
	ConfigContractID, ResourceContractID, ExecutorID, CredentialRouteID, DescriptorID contract.ID
	CreateResultContractID, DeleteResultContractID                                    contract.ID
	CompletionClass                                                                   uint8
	RetirementMode                                                                    uint8
	InputEncoding, OutputEncoding                                                     uint8
}

func generatedFixtureCanonicalIntent(t testing.TB, settings []byte, facts generatedFixtureProfile) []byte {
	t.Helper()
	if value, err := protocol.DecodeIntent(settings); err == nil {
		if contract.ID(value.ConfigContractID) != facts.ConfigContractID || contract.ID(value.ResourceContractID) != facts.ResourceContractID || contract.GeneratorLifecycleMode(value.LifecycleMode) != facts.LifecycleMode {
			t.Fatal("fixture intent meaning differs")
		}
		return bytes.Clone(settings)
	}
	// Arbitrary short fixture content denotes a JSON string. Already valid JSON
	// and complete canonical intents retain their exact bytes.
	if !json.Valid(settings) {
		encoded, err := json.Marshal(string(settings))
		if err != nil {
			t.Fatal("fixture JSON string", err)
		}
		settings = encoded
	}
	body := []byte{0, 1}
	body = append(body, facts.ConfigContractID[:]...)
	body = append(body, byte(facts.LifecycleMode))
	body = append(body, facts.ResourceContractID[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(settings)))
	body = append(body, settings...)
	if _, err := protocol.DecodeIntent(body); err != nil {
		t.Fatal("fixture canonical settings", err)
	}
	return body
}

func generatedCapacityReservationFixture() contract.GeneratorDescriptor {
	return contract.GeneratorDescriptor{Digest: generatedVectorID(94), Length: 4}
}

func defaultGeneratedFixtureProfile() generatedFixtureProfile {
	return generatedFixtureProfile{LifecycleMode: contract.GeneratorLifecycleManaged, ResultReaderID: contract.GeneratorResultReaderID(), ConfigContractID: generatedVectorID(41), ResourceContractID: generatedVectorID(42), ExecutorID: generatedVectorID(45),
		CredentialRouteID: generatedVectorID(46), DescriptorID: generatedVectorID(47),
		RetirementMode: contract.GeneratedRetirementManual}
}

func generatedEffectPlanForGenerationIntent(t testing.TB, request *contract.GeneratorRequestCore, authority contract.ID, names []string, intent []byte, sources ...contract.GeneratorDeclarationEntry) (contract.GeneratorPlanBundle, contract.GeneratorDeclaration, contract.GeneratedParentRecord) {
	return generatedEffectPlanForGenerationProfile(t, request, authority, names, intent, defaultGeneratedFixtureProfile(), sources...)
}

func generatedEffectPlanForGenerationProfile(t testing.TB, request *contract.GeneratorRequestCore, authority contract.ID, names []string, intent []byte, profile generatedFixtureProfile, sources ...contract.GeneratorDeclarationEntry) (contract.GeneratorPlanBundle, contract.GeneratorDeclaration, contract.GeneratedParentRecord) {
	return generatedEffectPlanForGenerationState(t, request, authority, names, intent, profile, 0, nil, nil, sources...)
}

func generatedEffectPlanForGenerationState(t testing.TB, request *contract.GeneratorRequestCore, authority contract.ID, names []string, intent []byte,
	profile generatedFixtureProfile, epoch uint64, incarnations map[string]contract.ID, retiring map[string]contract.ValueEntry,
	sources ...contract.GeneratorDeclarationEntry) (contract.GeneratorPlanBundle, contract.GeneratorDeclaration, contract.GeneratedParentRecord) {
	return generatedEffectPlanForGenerationMembershipState(t, request, authority, []contract.ID{authority}, names, intent, profile, epoch, incarnations, retiring, sources...)
}

func generatedEffectPlanForGenerationMembershipState(t testing.TB, request *contract.GeneratorRequestCore, authority contract.ID,
	generatedRecipients []contract.ID, names []string, intent []byte, profile generatedFixtureProfile, epoch uint64,
	incarnations map[string]contract.ID, retiring map[string]contract.ValueEntry,
	sources ...contract.GeneratorDeclarationEntry) (contract.GeneratorPlanBundle, contract.GeneratorDeclaration, contract.GeneratedParentRecord) {
	return generatedEffectPlanForGenerationMembershipStateWithIntents(t, request, authority, generatedRecipients, names,
		func(string) []byte { return intent }, profile, epoch, incarnations, retiring, sources...)
}

// The maximum-history fixture uses distinct bounded intents for each current
// generated value. Existing scenarios pass one immutable intent to all names.
func generatedEffectPlanForGenerationMembershipStateWithIntents(t testing.TB, request *contract.GeneratorRequestCore, authority contract.ID,
	generatedRecipients []contract.ID, names []string, intentForName func(string) []byte, profile generatedFixtureProfile, epoch uint64,
	incarnations map[string]contract.ID, retiring map[string]contract.ValueEntry,
	sources ...contract.GeneratorDeclarationEntry) (contract.GeneratorPlanBundle, contract.GeneratorDeclaration, contract.GeneratedParentRecord) {
	t.Helper()
	id := generatedVectorID
	fixed := func(v contract.ID, err error) contract.ID {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	descriptor := func(v contract.GeneratorDescriptor, err error) contract.GeneratorDescriptor {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	body := func(v []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	g, _, parent := generatedContentPlanFixture(t)
	schema := contract.GeneratorGraphHeaderSchema
	if profile.LifecycleMode != contract.GeneratorLifecycleNone && profile.LifecycleMode != contract.GeneratorLifecycleManaged {
		t.Fatal("fixture requires a typed lifecycle")
	}
	if profile.ResultReaderID.IsZero() {
		profile.ResultReaderID = contract.GeneratorResultReaderID()
	}
	inputEncoding := profile.InputEncoding
	if inputEncoding == 0 {
		inputEncoding = contract.InputEncodingRaw
	}
	if inputEncoding != contract.InputEncodingRaw && inputEncoding != contract.InputEncodingBase64 {
		t.Fatal("fixture requires a declared input representation")
	}
	outputEncoding := profile.OutputEncoding
	if outputEncoding == 0 {
		outputEncoding = contract.OutputEncodingRaw
	}
	if outputEncoding != contract.OutputEncodingRaw && outputEncoding != contract.OutputEncodingBase64 {
		t.Fatal("fixture requires a declared output representation")
	}
	g.Header.Schema = schema
	g.UsePlan.ValueDerivationID = contract.GeneratorValueDerivationID()
	sources = slices.Clone(sources)
	for _, source := range sources {
		if source.Schema != contract.GeneratorDeclarationEntrySchema {
			t.Fatal("fixture requires current declaration schema")
		}
	}
	g.ValueEntryPlans = nil
	if request != nil {
		g.Request = *request
		g.Header.DomainID, g.Header.OperationID, g.Header.RecoveryPolicyID = request.DomainID, request.OperationID, request.RecoveryPolicyID
		g.Header.MaterialID = fixed(contract.GeneratorMaterialID(request.DomainID, request.OperationID))
		g.UsePlan.DomainID, g.UsePlan.OperationID, g.UsePlan.MaterialID = request.DomainID, request.OperationID, g.Header.MaterialID
	}
	completion := profile.CompletionClass
	if completion == 0 && profile.LifecycleMode == contract.GeneratorLifecycleManaged {
		completion = contract.GeneratedCompletionAcknowledged
	}
	retirementMode := profile.RetirementMode
	if retirementMode == 0 && profile.LifecycleMode == contract.GeneratorLifecycleManaged {
		retirementMode = contract.GeneratedRetirementManual
	}
	createResultContract, deleteResultContract := profile.CreateResultContractID, profile.DeleteResultContractID
	if createResultContract.IsZero() {
		createResultContract = id(48)
	}
	if deleteResultContract.IsZero() {
		deleteResultContract = id(49)
	}
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: g.Header.DomainID, OperationID: g.Header.OperationID}
	membership := descriptor(contract.GeneratorIntendedMembershipDescriptor(generatedRecipients))
	for _, name := range names {
		intent := generatedFixtureCanonicalIntent(t, intentForName(name), profile)
		intentID := fixed(contract.GeneratorIntentDigest(intent))
		meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: profile.LifecycleMode, Epoch: epoch, RetirementMode: retirementMode, ConfigContractID: profile.ConfigContractID, ResourceContractID: profile.ResourceContractID, CompletionClass: completion, Intent: intent}
		payload := body(contract.EncodeGeneratorDeclaredGeneration(meta))
		declaration.Entries = append(declaration.Entries, contract.GeneratorDeclarationEntry{InputEncoding: inputEncoding, OutputEncoding: outputEncoding, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationGenerated, Name: name, Recipients: slices.Clone(generatedRecipients), Payload: payload})
		incarnation := append([]byte("fixture generated incarnation\x00"), g.Header.OperationID[:]...)
		incarnation = append(incarnation, name...)
		entryIncarnation := contract.Hash(incarnation)
		if fixedIncarnation, ok := incarnations[name]; ok {
			entryIncarnation = fixedIncarnation
		}
		x := contract.GeneratorLineageTemplate{Schema: schema, Purpose: 1, DomainID: g.Header.DomainID, OperationID: g.Header.OperationID,
			Name: name, EntryIncarnationID: entryIncarnation, Epoch: epoch, IntentDigest: intentID, TemplateCount: 5}
		if profile.LifecycleMode == contract.GeneratorLifecycleNone {
			x.TemplateCount = 1
		}
		x.LineageID = fixed(contract.GeneratorLineageID(x.DomainID, x.OperationID, x.Name, x.EntryIncarnationID, x.Epoch, x.IntentDigest))
		for i := range int(x.TemplateCount) {
			v := contract.GeneratorAttemptTemplate{Schema: schema, LifecycleMode: profile.LifecycleMode, ResultReaderID: profile.ResultReaderID, Branch: uint8(i), Action: 1, LineageID: x.LineageID, ConfigContractID: meta.ConfigContractID,
				ResourceContractID: meta.ResourceContractID, ExecutorID: profile.ExecutorID, CredentialRouteID: profile.CredentialRouteID, DescriptorID: profile.DescriptorID, ResultContractID: createResultContract,
				IntentDigest: intentID, TargetKind: 1, TargetSourceID: intentID, CompletionClass: completion, RequiredAuthoritySet: 1}
			v.AttemptID = fixed(contract.GeneratorAttemptID(x.LineageID, v.Branch))
			if i != 0 {
				branch := uint8(0)
				if i > 2 {
					branch = uint8(i - 2)
				}
				v.PredecessorAttemptID = fixed(contract.GeneratorAttemptID(x.LineageID, branch))
			}
			v.ResourceIncarnationID = fixed(contract.GeneratorResourceID(x.DomainID, x.OperationID, v.AttemptID))
			v.PlannedValueSlotID = fixed(contract.GeneratorValueSlotID(x.DomainID, x.OperationID, v.AttemptID))
			v.DutyID = fixed(contract.GeneratorDutyID(x.DomainID, x.OperationID, v.AttemptID, 1))
			v.HazardID = fixed(contract.GeneratorHazardID(x.DomainID, v.AttemptID))
			v.TransmissionID = fixed(contract.GeneratorTransmissionID(v.AttemptID, 1))
			v.ResultID = fixed(contract.GeneratorResultID(x.DomainID, x.OperationID, v.AttemptID, v.TransmissionID, 1))
			v.InboxID = fixed(contract.GeneratorInboxID(x.DomainID, x.OperationID, v.AttemptID, v.ResultID))
			if profile.LifecycleMode == contract.GeneratorLifecycleNone {
				v.TargetKind, v.TargetSourceID, v.HazardID = 0, contract.ID{}, contract.ID{}
			}
			v.RequestPlanDigest = fixed(contract.GeneratorRequestPlanDigest(v))
			if profile.LifecycleMode == contract.GeneratorLifecycleManaged && (i == 0 || i == 2) {
				v.NoEffectBudget = 1
			}
			if profile.LifecycleMode == contract.GeneratorLifecycleManaged && (i == 0 || i == 1) {
				v.ResidueBudget = 1
			}
			x.Templates[i] = v
		}
		g.Lineages = append(g.Lineages, x)
		for _, create := range x.Templates[:x.TemplateCount] {
			if profile.LifecycleMode == contract.GeneratorLifecycleNone {
				continue
			}
			cleanup := contract.GeneratorLineageTemplate{Schema: schema, Purpose: 3, DomainID: x.DomainID, OperationID: x.OperationID, Name: x.Name,
				EntryIncarnationID: x.EntryIncarnationID, Epoch: x.Epoch, IntentDigest: intentID, ResourceIncarnationID: create.ResourceIncarnationID, TemplateCount: 1}
			cleanup.LineageID = fixed(contract.GeneratorObligationLineageID(x.DomainID, x.OperationID, cleanup.ResourceIncarnationID, 3))
			v := create
			v.Action, v.Branch, v.NoEffectBudget, v.ResidueBudget, v.TargetKind = 2, 0, 0, 0, 3
			v.LineageID, v.TargetSourceID, v.PredecessorAttemptID, v.ResultContractID = cleanup.LineageID, create.ResultID, contract.ID{}, deleteResultContract
			v.AttemptID = fixed(contract.GeneratorAttemptID(v.LineageID, 0))
			v.PlannedValueSlotID = fixed(contract.GeneratorValueSlotID(x.DomainID, x.OperationID, v.AttemptID))
			v.HazardID = fixed(contract.GeneratorHazardID(x.DomainID, v.AttemptID))
			v.TransmissionID = fixed(contract.GeneratorTransmissionID(v.AttemptID, 2))
			v.ResultID = fixed(contract.GeneratorResultID(x.DomainID, x.OperationID, v.AttemptID, v.TransmissionID, 2))
			v.InboxID = fixed(contract.GeneratorInboxID(x.DomainID, x.OperationID, v.AttemptID, v.ResultID))
			v.RequestPlanDigest = fixed(contract.GeneratorRequestPlanDigest(v))
			cleanup.Templates[0] = v
			g.Lineages = append(g.Lineages, cleanup)
		}
		g.ValueEntryPlans = append(g.ValueEntryPlans, contract.GeneratorValueEntryPlan{InputEncoding: inputEncoding, OutputEncoding: outputEncoding, Schema: contract.GeneratorValueEntryPlanSchema, LifecycleMode: profile.LifecycleMode, Name: x.Name, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, EntryIncarnationID: x.EntryIncarnationID,
			Epoch: epoch, IntentDigest: intentID, PlannedValueSlotID: x.Templates[0].PlannedValueSlotID, IntendedMembership: membership, LineageID: x.LineageID, RetirementMode: retirementMode, ChangeMask: 1})
	}
	for _, old := range retiring {
		m := old.Generated
		lineage := contract.GeneratorLineageTemplate{Schema: schema, Purpose: 2, DomainID: g.Header.DomainID, OperationID: g.Header.OperationID,
			Name: old.Name, EntryIncarnationID: old.Incarnation, Epoch: m.Epoch, IntentDigest: m.IntentDigest,
			ResourceIncarnationID: m.ResourceIncarnationID, TemplateCount: 1}
		lineage.LineageID = fixed(contract.GeneratorObligationLineageID(lineage.DomainID, lineage.OperationID, lineage.ResourceIncarnationID, 2))
		x := contract.GeneratorAttemptTemplate{Schema: schema, LifecycleMode: profile.LifecycleMode, ResultReaderID: profile.ResultReaderID, Action: 2, LineageID: lineage.LineageID, ResourceIncarnationID: m.ResourceIncarnationID,
			ConfigContractID: m.ConfigContractID, ResourceContractID: m.ResourceContractID, ExecutorID: profile.ExecutorID, CredentialRouteID: profile.CredentialRouteID,
			DescriptorID: profile.DescriptorID, ResultContractID: deleteResultContract, IntentDigest: m.IntentDigest, ResourceDigest: m.ResourceDigest,
			TargetKind: 2, TargetSourceID: m.ResourceIncarnationID, CompletionClass: m.CompletionClass, RequiredAuthoritySet: 1}
		x.DutyID = fixed(contract.GeneratorDutyID(lineage.DomainID, m.OriginOperationID, m.OriginAttemptID, 2))
		x.AttemptID = fixed(contract.GeneratorAttemptID(lineage.LineageID, 0))
		x.PlannedValueSlotID = fixed(contract.GeneratorValueSlotID(lineage.DomainID, lineage.OperationID, x.AttemptID))
		x.HazardID = fixed(contract.GeneratorHazardID(lineage.DomainID, x.AttemptID))
		x.TransmissionID = fixed(contract.GeneratorTransmissionID(x.AttemptID, 2))
		x.ResultID = fixed(contract.GeneratorResultID(lineage.DomainID, lineage.OperationID, x.AttemptID, x.TransmissionID, 2))
		x.InboxID = fixed(contract.GeneratorInboxID(lineage.DomainID, lineage.OperationID, x.AttemptID, x.ResultID))
		x.RequestPlanDigest = fixed(contract.GeneratorRequestPlanDigest(x))
		lineage.Templates[0] = x
		g.Lineages = append(g.Lineages, lineage)
	}
	slices.SortFunc(g.Lineages, func(a, b contract.GeneratorLineageTemplate) int {
		if a.Name != b.Name {
			return bytes.Compare([]byte(a.Name), []byte(b.Name))
		}
		if a.Purpose != b.Purpose {
			return int(a.Purpose) - int(b.Purpose)
		}
		return bytes.Compare(a.ResourceIncarnationID[:], b.ResourceIncarnationID[:])
	})
	declaration.Entries = append(declaration.Entries, sources...)
	slices.SortFunc(declaration.Entries, func(a, b contract.GeneratorDeclarationEntry) int {
		return bytes.Compare([]byte(a.Name), []byte(b.Name))
	})
	g.Request.Declaration = descriptor(contract.GeneratorDeclarationDescriptor(declaration))
	decl, err := contract.InspectGeneratorDeclaration(body(contract.EncodeGeneratorDeclaration(declaration)))
	if err != nil {
		t.Fatal(err)
	}
	locations, err := decl.LogicalSlices()
	if err != nil {
		t.Fatal(err)
	}
	logical := make(map[contract.ID]contract.GeneratorLogicalSlice)
	for _, location := range locations {
		logical[location.ContentID] = location
	}
	for _, entry := range sources {
		if entry.Kind == contract.GeneratorDeclarationGeneratedReference || entry.Kind == contract.GeneratorDeclarationGenerated {
			var epoch uint64
			var retirementMode uint8
			var profileKind contract.GeneratorLifecycleMode
			var intent contract.GeneratorLogicalSlice
			if entry.Kind == contract.GeneratorDeclarationGeneratedReference {
				ref, err := contract.InspectGeneratorDeclaredGenerationReferenceForEntry(entry.Schema, entry.Payload)
				if err != nil {
					t.Fatal("current reference fixture generation", err)
				}
				epoch, retirementMode, intent, profileKind = ref.Epoch, ref.RetirementMode, ref.Intent, ref.LifecycleMode
			} else {
				generation, err := contract.InspectGeneratorDeclaredGenerationForEntry(entry.Schema, entry.Payload)
				if err != nil {
					t.Fatal("current embedded fixture generation", err)
				}
				intentID := fixed(contract.GeneratorIntentDigest(generation.Intent))
				epoch, retirementMode, intent, profileKind = generation.Epoch, generation.RetirementMode, logical[intentID], generation.LifecycleMode
			}
			if incarnations[entry.Name].IsZero() {
				t.Fatal("current generated fixture identity")
			}
			g.ValueEntryPlans = append(g.ValueEntryPlans, contract.GeneratorValueEntryPlan{InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, Schema: contract.GeneratorValueEntryPlanSchema, LifecycleMode: profileKind, Name: entry.Name,
				ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, EntryIncarnationID: incarnations[entry.Name],
				Epoch: epoch, IntentDigest: intent.ContentID, RetirementMode: retirementMode,
				SourceSlice:        descriptor(contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{intent})),
				IntendedMembership: descriptor(contract.GeneratorIntendedMembershipDescriptor(entry.Recipients))})
			continue
		}
		entryID := fixed(contract.GeneratorDeclarationEntryID(declaration.DomainID, declaration.OperationID, entry.Name))
		confidentialityClass := uint8(contract.Secret)
		if entry.Kind == contract.GeneratorDeclarationPlain {
			confidentialityClass = contract.Plain
		}
		g.ValueEntryPlans = append(g.ValueEntryPlans, contract.GeneratorValueEntryPlan{InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, Schema: contract.GeneratorValueEntryPlanSchema, Name: entry.Name, ValueSource: contract.Supplied, ConfidentialityClass: confidentialityClass,
			EntryIncarnationID: contract.Hash([]byte("fixture incarnation " + entry.Name)), ChangeMask: 1,
			SourceSlice:        descriptor(contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{logical[entryID]})),
			IntendedMembership: descriptor(contract.GeneratorIntendedMembershipDescriptor(entry.Recipients))})
		if entry.Kind != contract.GeneratorDeclarationSealed {
			continue
		}
		envelope, err := contract.DecodeSealedInputEnvelope(entry.Payload)
		if err != nil {
			t.Fatal(err)
		}
		use := contract.GeneratorSourceUse{Schema: 1, SourceID: envelope.Core.SourceID, SealedInputCoreDigest: fixed(contract.SealedInputCoreDigest(envelope.Core)),
			EnvelopeDigest: contract.Hash(entry.Payload), SourceSlice: descriptor(contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{logical[envelope.Core.SourceID]})), Purpose: 2}
		consumer, err := contract.GeneratorAcceptedSourceConsumer(declaration.OperationID, g.Header.MaterialID, use)
		if err != nil {
			t.Fatal(err)
		}
		use.Consumers = descriptor(contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, [][]byte{body(contract.EncodeGeneratorConsumer(consumer))}))
		g.SourceUses = append(g.SourceUses, use)
	}
	slices.SortFunc(g.ValueEntryPlans, func(a, b contract.GeneratorValueEntryPlan) int { return bytes.Compare([]byte(a.Name), []byte(b.Name)) })
	var occupied [contract.CryptoMaxValueEntries]bool
	retained := make(map[string]bool)
	for _, entry := range sources {
		if entry.Kind != contract.GeneratorDeclarationRetained {
			continue
		}
		r, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
		if err != nil || occupied[r.OriginalSlot] {
			t.Fatal("canonical fixture slot", err)
		}
		index := slices.IndexFunc(g.ValueEntryPlans, func(m contract.GeneratorValueEntryPlan) bool { return m.Name == entry.Name })
		g.ValueEntryPlans[index].Slot, g.ValueEntryPlans[index].EntryIncarnationID = r.OriginalSlot, r.Entry.Incarnation
		g.ValueEntryPlans[index].ChangeMask = 0
		if !slices.Equal(entry.Recipients, r.Entry.Recipients) {
			g.ValueEntryPlans[index].ChangeMask = contract.GeneratorValueChangeMembership
		}
		occupied[r.OriginalSlot], retained[entry.Name] = true, true
	}
	for i := range g.ValueEntryPlans {
		if retained[g.ValueEntryPlans[i].Name] {
			continue
		}
		free := slices.Index(occupied[:], false)
		if free < 0 {
			t.Fatal("fixture member capacity")
		}
		g.ValueEntryPlans[i].Slot, occupied[free] = uint16(free), true
	}
	slices.SortFunc(g.SourceUses, func(a, b contract.GeneratorSourceUse) int { return bytes.Compare(a.SourceID[:], b.SourceID[:]) })
	g.UsePlan.SourceUses = descriptor(contract.GeneratorSourceUsesDescriptor(g.SourceUses))
	g.Header.ValueEntryPlanCount, g.Header.LineageCount, g.Header.TemplateCount = uint16(len(g.ValueEntryPlans)), uint16(len(names)), 0
	for _, lineage := range g.Lineages {
		g.Header.TemplateCount += uint16(lineage.TemplateCount)
	}
	g.Header.RequestCoreDigest = fixed(contract.GeneratorRequestCoreDigest(g.Request))
	join := fixed(contract.GeneratorCompleteJoinID(g.Header.RequestCoreDigest))
	for _, lineage := range g.Lineages {
		for _, v := range lineage.Templates[:lineage.TemplateCount] {
			source := fixed(contract.GeneratorTemplateID(v))
			for guard := uint8(1); guard <= 4; guard++ {
				branch, destination := v.Branch, join
				if guard < 3 {
					if v.Action != 1 || v.LifecycleMode == contract.GeneratorLifecycleNone {
						continue
					}
					next, present, err := contract.GeneratorSuccessorBranch(v.Branch, guard)
					if err != nil {
						t.Fatal(err)
					}
					if !present {
						continue
					}
					branch, destination = next, fixed(contract.GeneratorTemplateID(lineage.Templates[next]))
				}
				n, r := uint8(0), uint8(0)
				if branch == 1 || branch == 3 || branch == 4 {
					n = 1
				}
				if branch >= 2 {
					r = 1
				}
				g.Edges = append(g.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: source, DestinationTemplateID: destination, Guard: guard, ResultSlotID: v.ResultID, RequiredAuthoritySet: 1, NoEffectUsed: n, ResidueUsed: r})
			}
			maximum := uint32(65536)
			if v.Action == 2 {
				maximum = 0
			}
			g.ResultUses = append(g.ResultUses, contract.GeneratorResultUse{Schema: 1, AttemptID: v.AttemptID, ResultID: v.ResultID, InboxID: v.InboxID, ExecutorID: v.ExecutorID,
				ResultContractID: v.ResultContractID, PlannedValueSlotID: v.PlannedValueSlotID, MaterialID: g.Header.MaterialID, Purpose: 1, MaxSecret: maximum, MaxFacts: 4096})
		}
	}
	slices.SortFunc(g.Edges, func(a, b contract.GeneratorEdge) int {
		if c := bytes.Compare(a.SourceTemplateID[:], b.SourceTemplateID[:]); c != 0 {
			return c
		}
		return int(a.Guard) - int(b.Guard)
	})
	slices.SortFunc(g.ResultUses, func(a, b contract.GeneratorResultUse) int { return bytes.Compare(a.AttemptID[:], b.AttemptID[:]) })
	g.UsePlan.PlanGraphID = fixed(contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges))
	g.UsePlan.ResultUses = descriptor(contract.GeneratorResultUsesDescriptor(g.ResultUses))
	if err := contract.ValidateGeneratorEffectGraph(g); err != nil {
		t.Fatal(err)
	}
	parent.ValueEntryPlanCount, parent.LineageCount, parent.TemplateCount = g.Header.ValueEntryPlanCount, g.Header.LineageCount, g.Header.TemplateCount
	parent.DomainID, parent.OperationID, parent.MaterialID = g.Header.DomainID, g.Header.OperationID, g.Header.MaterialID
	parent.RequestCoreDigest, parent.PlanGraphID, parent.UsePlanDigest = g.Header.RequestCoreDigest, g.UsePlan.PlanGraphID, fixed(contract.GeneratorUsePlanDigest(g.UsePlan))
	parent.Declaration, parent.Graph, parent.IntendedEntryPlans = g.Request.Declaration, descriptor(contract.GeneratorPlanBundleDescriptor(g)), descriptor(contract.GeneratorValueEntryPlansDescriptor(g.ValueEntryPlans))
	parent.SourceUses = g.UsePlan.SourceUses
	parent.Registry, parent.RecoveryPolicyID = g.Request.Registry, g.Request.RecoveryPolicyID
	parent.InitialPredecessorDigest, parent.ConditionDigest = g.Request.PredecessorHEADDigest, g.Request.ConditionDigest
	if err := contract.ValidateGeneratorDeclarationGraph(decl, g); err != nil {
		t.Fatal(err)
	}
	return g, declaration, parent
}

// full_only: false
func TestGeneratedEffectPlanPerNameIntentsKeepExactGraphBindings(t *testing.T) {
	intents := map[string][]byte{"first": []byte(`"first-intent"`), "second": []byte(`"second-intent"`)}
	g, declaration, _ := generatedEffectPlanForGenerationMembershipStateWithIntents(t, nil, generatedVectorID(11),
		[]contract.ID{generatedVectorID(11)}, []string{"first", "second"}, func(name string) []byte { return intents[name] },
		defaultGeneratedFixtureProfile(), 1, nil, nil)
	if err := contract.ValidateGeneratorEffectGraph(g); err != nil {
		t.Fatal("distinct-intent graph", err)
	}
	body, err := contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal("distinct-intent declaration encoding", err)
	}
	view, err := contract.InspectGeneratorDeclaration(body)
	if err != nil {
		t.Fatal("distinct-intent declaration inspection", err)
	}
	if err := contract.ValidateGeneratorDeclarationGraph(view, g); err != nil {
		t.Fatal("distinct-intent declaration and graph", err)
	}
	for _, plan := range g.ValueEntryPlans {
		want, err := contract.GeneratorIntentDigest(generatedFixtureCanonicalIntent(t, intents[plan.Name], defaultGeneratedFixtureProfile()))
		if err != nil || plan.IntentDigest != want {
			t.Fatal("value plan lost its own intent", plan.Name, err)
		}
		for _, lineage := range g.Lineages {
			if lineage.Purpose == contract.GeneratorLineageCreate && lineage.Name == plan.Name && lineage.IntentDigest != want {
				t.Fatal("create lineage substituted another intent", plan.Name)
			}
		}
	}
}

func generatedFixtureBundles(t testing.TB, s *StateSession) []contract.GeneratorPlanBundle {
	var bundles []contract.GeneratorPlanBundle
	if content, err := newGeneratedContentValidation(t.Context(), s); err == nil {
		for key := range content.facts.locations {
			if key.kind != contract.GeneratorContentGraph {
				continue
			}
			if bundle, err := content.graph(key.id); err == nil {
				bundles = append(bundles, bundle)
			}
		}
	}
	if len(bundles) == 0 && s.generatedWork != nil && s.generatedWork.selection != nil {
		bundles = slices.Clone(s.generatedWork.selection.bundles)
	}
	slices.SortFunc(bundles, func(a, b contract.GeneratorPlanBundle) int {
		return bytes.Compare(a.Header.OperationID[:], b.Header.OperationID[:])
	})
	return bundles
}

// These helpers are used only by the three valid selected-state constructors.
// Raw content fixtures and generic support refresh do not acquire a control shell.
func generatedFixtureSelectedShell(t testing.TB, s *StateSession) {
	t.Helper()
	base := generatedEmptyPredecessor(t)
	if s.root.Domain != base.root.Domain || s.root.Snapshot != base.root.Snapshot {
		t.Fatal("selected fixture shell domain or snapshot")
	}
	s.root.Transition = base.root.Transition
	s.root.CurrentAccess = base.root.CurrentAccess
	s.admission, s.head, s.token, s.body, s.cache = base.admission, base.head, base.token, base.body, base.cache
	s.recipients = base.recipients
}

// Both recovery-bearing selected fixture constructors require independent
// signing and KMS resources. Their normal route stays in the selected shell.
func generatedFixtureIndependentRecovery(t testing.TB, s *StateSession, binding contract.KMSBinding, label string) (contract.KMSBinding, contract.PublicSigningBinding) {
	t.Helper()
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(bytes.Repeat([]byte{253}, 384)), E: 65537}
	var err error
	binding.SPKI, err = x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal("independent recovery KMS public fixture", err)
	}
	binding.Fingerprint = contract.Hash(binding.SPKI)
	signing := s.root.CurrentAccess.Core.NormalSigning
	signer := testtrust.NewRecovery(t, signing.Provider, contract.Hash([]byte(label)))
	signing.Role, signing.BindingID = contract.RecoverySigningRole, contract.Hash([]byte(label))
	signing.SPKI, signing.KeySelector = signer.PublicKey(), signer.KeySelector()
	signing.Fingerprint = contract.Hash(signing.SPKI)
	signing.Binding.PublicKey = signing.Fingerprint
	if !contract.IndependentKMSBindings(*s.authority().CurrentBinding, binding) || signing.Fingerprint == s.root.CurrentAccess.Core.NormalSigning.Fingerprint {
		t.Fatal("recovery fixture shares a normal key resource")
	}
	return binding, signing
}

func generatedFixtureChildID(s *StateSession, kind contract.Kind, index uint16) contract.ID {
	return contract.Hash([]byte(fmt.Sprintf("valid generated fixture child/v1/%x/%x/%d/%d", s.root.Domain, s.root.Snapshot, kind, index)))
}

func generatedSealSelectedFixture(t testing.TB, s *StateSession) {
	t.Helper()
	var recipients []contract.Ref
	s.root.Recipients = [contract.MaxRecipientPages]*format.Ref{}
	s.root.ValueEntryPages = [contract.MaxValueEntryPages]*format.Ref{}
	s.root.RecipientCount, s.root.ValueEntryCount, s.root.SecretCount = 0, 0, 0
	s.root.MembershipCount, s.root.SecretOrdinaryWrapCount, s.root.RawBytes = 0, 0, 0
	for i, page := range s.recipients {
		if page == nil {
			continue
		}
		page.Domain, page.Object, page.Index = s.root.Domain, generatedFixtureChildID(s, contract.RecipientKind, uint16(i)), uint16(i)
		body, err := format.EncodeRecipientPage(*page)
		if err != nil {
			t.Fatal("selected fixture recipient page", i, err)
		}
		ref, err := format.Reference(contract.RecipientKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.Recipients[i] = &ref
		recipients = append(recipients, ref)
		for _, row := range page.Slots {
			if row != nil {
				s.root.RecipientCount++
				if row.RecipientID == s.admission.recipient {
					s.recipient = *page
				}
			}
		}
	}
	for i, page := range s.pages {
		if page == nil {
			continue
		}
		page.Domain, page.Object, page.Index = s.root.Domain, generatedFixtureChildID(s, contract.ValueEntryPageKind, uint16(i)), uint16(i)
		body, err := format.EncodeValueEntryPage(*page)
		if err != nil {
			t.Fatal("selected fixture value page", i, err)
		}
		ref, err := format.Reference(contract.ValueEntryPageKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.ValueEntryPages[i] = &ref
		for _, row := range page.Slots {
			if row == nil {
				continue
			}
			s.root.ValueEntryCount++
			s.root.MembershipCount += uint32(len(row.Recipients))
			if row.ConfidentialityClass == contract.Secret {
				payload, err := contract.InspectCanonicalPayload(row.ValueBytes)
				if err != nil {
					t.Fatal(err)
				}
				s.root.SecretCount++
				s.root.SecretOrdinaryWrapCount += uint32(len(row.Recipients))
				s.root.RawBytes += uint64(payload.ContentLength)
			} else {
				s.root.RawBytes += uint64(row.ContentLength)
			}
		}
	}
	var err error
	s.root.CurrentAccess.Core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: s.root.Domain, Refs: recipients})
	if err != nil {
		t.Fatal(err)
	}
	generatedCommitFixtureAccess(t, s)
	generatedRefreshSupport(t, s)
	body, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal("seal selected fixture Root", err)
	}
	s.head.Core.Root, err = format.Reference(contract.RootKind, s.root.Domain, s.root.Snapshot, 0, body)
	if err != nil {
		t.Fatal(err)
	}
}

// Only explicit valid selected fixture boundaries bind a verified Slice proof.
// Refresh can also describe deliberate damage and must not acquire this proof.
func generatedVerifySelectedFixtureSlices(t testing.TB, s *StateSession) {
	t.Helper()
	rootBody, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal("selected fixture Root", err)
	}
	image := s.selectedImage()
	if result := verifySelectedGeneratedSlices(t.Context(), image, s.selectedObjectReader()); result.Outcome != 0 {
		t.Fatal("selected fixture slices", result)
	}
	s.generatedSliceLocations, s.generatedSlicesRoot = image.generatedSliceLocations, contract.Hash(rootBody)
}

// Commit only the actual access rows. Negative fixtures can retain a semantic
// orphan while authenticating its exact child and scalar framing.
func generatedCommitFixtureAccess(t testing.TB, s *StateSession) {
	t.Helper()

	var access []contract.AccessRecord
	s.root.CurrentAccess.Core.AccessPageRefs = nil
	for i, page := range s.access {
		if page == nil {
			continue
		}
		if len(page.Records) == 0 {
			s.access[i] = nil
			continue
		}
		page.Domain, page.Object, page.Index = s.root.Domain, generatedFixtureChildID(s, contract.AccessKind, uint16(i)), uint16(i)
		slices.SortFunc(page.Records, func(a, b contract.AccessRecord) int {
			if contract.AccessRecordBefore(a, b) {
				return -1
			}
			if contract.AccessRecordBefore(b, a) {
				return 1
			}
			return 0
		})
		body, err := format.EncodeAccessPage(*page)
		if err != nil {
			t.Fatal("selected fixture access page", i, err)
		}
		ref, err := format.Reference(contract.AccessKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		s.root.CurrentAccess.Core.AccessPageRefs = append(s.root.CurrentAccess.Core.AccessPageRefs, ref)
		access = append(access, page.Records...)
	}
	s.root.AccessRecordCount = uint32(len(access))
	var err error
	s.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(s.root.Domain, access)
	if err != nil {
		t.Fatal(err)
	}
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal("selected fixture access commitment", err)
	}
	s.recountChildren()
}

func generatedFixtureMaterialAccess(t testing.TB, s *StateSession, kind contract.MaterialKind, id contract.ID) *contract.AccessRecord {
	t.Helper()
	if _, ok := s.materialAccess(kind, id); !ok {
		t.Fatal("selected fixture material access missing", kind)
	}
	location := s.accessLocations[materialIdentity{kind, id}]
	return &s.access[location.page].Records[location.row]
}

// Only the selected-state constructors call this. Content-only fixtures remain
// partial; refresh never replaces a missing or malformed nonempty declaration.
func generatedInitializeFixtureOutput(t testing.TB, s *StateSession) {
	t.Helper()
	if s.root.OutputConfiguration != (contract.OutputConfigurationDescriptor{}) || slices.ContainsFunc(s.supportRecords(), func(row contract.SupportRecord) bool {
		return row.Kind == contract.OutputConfigurationSliceSupportKind
	}) {
		t.Fatal("initial generated fixture already has output state")
	}
	image, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: s.root.Domain})
	if err != nil {
		t.Fatal("initial fixture output configuration", err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(s.root.Domain, image)
	if err != nil || len(parts) != 1 {
		t.Fatal("initial fixture output slice", err)
	}
	body, err := contract.EncodeOutputConfigurationSlice(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	id, err := contract.OutputConfigurationSliceID(s.root.Domain, descriptor.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	physical := generatedFixtureFreeSupportIndex(t, s)
	object := contract.Hash([]byte(fmt.Sprintf("fixture initial configuration/%x/%x", s.root.Domain, s.root.Snapshot)))
	s.support = append(s.support, format.RequiredSupportPageView{Domain: s.root.Domain, Object: object, Index: physical,
		Records: []contract.SupportRecordView{{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body}}})
	s.root.OutputConfiguration = descriptor
	s.admission.store.Prefix = "fixture"
}

// Direct unit fixtures stand in for a selected image after Open. Keep the exact
// encoded pages available for the mandatory uncached reads, separately from
// the mutable bodies used to prepare fixture changes.
type generatedFixtureSupportStore struct {
	t          testing.TB
	descriptor contract.Descriptor
	objects    map[string][]byte
	keys       []string
	limits     []uint32
}

func (s *generatedFixtureSupportStore) Descriptor() contract.Descriptor { return s.descriptor }
func (s *generatedFixtureSupportStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.keys = append(s.keys, key)
	s.limits = append(s.limits, limit)
	if ctx == nil || ctx.Err() != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	body, ok := s.objects[key]
	if !ok {
		return contract.ReadResult{Status: contract.ReadMissing}
	}
	if len(body) > int(limit) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonLimit}
	}
	return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(body)}
}
func (s *generatedFixtureSupportStore) Create(context.Context, string, []byte) contract.WriteResult {
	s.t.Fatal("selected unit fixture attempted Store.Create")
	return contract.WriteResult{}
}
func (s *generatedFixtureSupportStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	s.t.Fatal("selected unit fixture attempted Store.CreateHead")
	return contract.WriteResult{}
}
func (s *generatedFixtureSupportStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	s.t.Fatal("selected unit fixture attempted Store.CompareAndSwap")
	return contract.WriteResult{}
}

func generatedInstallFixtureSupportReader(t testing.TB, s *StateSession) {
	t.Helper()
	if len(s.support) != len(s.root.RequiredSupport) {
		t.Fatal("fixture support page/reference count mismatch")
	}
	store := &generatedFixtureSupportStore{t: t, descriptor: s.admission.store, objects: make(map[string][]byte)}
	facts := make([]selectedSupportPageFacts, len(s.support))
	fragments := make(map[format.FragmentLocation]selectedFragmentFact)
	for i, page := range s.support {
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
		}
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil {
			t.Fatal("encode selected fixture support", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil || ref != s.root.RequiredSupport[i] {
			t.Fatal("selected fixture support reference mismatch", err)
		}
		key, err := format.Key(s.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal("selected fixture support key", err)
		}
		store.objects[key] = body
		facts[i].ref = ref
		decoded, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal("inspect selected fixture support", err)
		}
		for j, row := range decoded.Records {
			fact, err := contract.InspectSupportRecordDigest(s.root.Domain, contract.SupportRecord(row))
			if err != nil {
				t.Fatal("selected fixture row fact", err)
			}
			facts[i].rows = append(facts[i].rows, fact)
			facts[i].ordinals = append(facts[i].ordinals, uint16(j))
			if row.Kind == contract.GeneratedFragmentSupportKind {
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil || j > 255 {
					t.Fatal("selected fixture fragment", err)
				}
				location := format.FragmentLocation{BlobID: fragment.BlobID, FragmentIndex: fragment.Index,
					SupportPageIndex: ref.Index, RowSlot: uint8(j)}
				if _, duplicate := fragments[location]; duplicate {
					t.Fatal("duplicate selected fixture fragment")
				}
				fragments[location] = selectedFragmentFact{ref: ref, row: fact, physical: uint16(j), logical: uint8(j),
					blob: fragment.BlobID, index: fragment.Index, count: fragment.Count, total: fragment.TotalLength,
					whole: fragment.WholeDigest, offset: fragment.Offset, payloadLength: uint32(len(fragment.Payload))}
			}
		}
	}
	s.supportFacts, s.fragmentFacts, s.store = facts, fragments, store
}

// Fixture mutations need complete row bodies. The complete reader keeps fragment
// facts instead; materialize only those authenticated payloads before editing.
func generatedMaterializeFixtureSupport(t testing.TB, s *StateSession) {
	t.Helper()
	if s.fragmentFacts == nil {
		return
	}
	byID, err := s.selectedFragmentLocationsByRecord()
	if err != nil {
		t.Fatal("fixture selected fragments", err)
	}
	for i, page := range s.support {
		if !slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
			return row.Body == nil && (row.Kind == contract.GeneratedFragmentSupportKind || row.Kind == contract.OutputConfigurationSliceSupportKind)
		}) {
			continue
		}
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
		}
		materialized, err := s.materializeGeneratedSupportPageAt(t.Context(), rows, page.Object, page.Index, nil, byID)
		if err != nil {
			t.Fatal("fixture selected support materialization", err)
		}
		s.support[i] = materialized.view
	}
	s.supportFacts, s.fragmentFacts = nil, nil
}

func generatedRefreshSupport(t testing.TB, s *StateSession, bundles ...contract.GeneratorPlanBundle) {
	t.Helper()
	generatedMaterializeFixtureSupport(t, s)
	s.generatedSliceLocations, s.generatedSlicesRoot = nil, contract.ID{}
	if s.root.OutputConfiguration.SliceCount != 0 && !slices.ContainsFunc(s.supportRecords(), func(row contract.SupportRecord) bool { return row.Kind == contract.OutputConfigurationSliceSupportKind }) {
		image, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: s.root.Domain})
		if err != nil {
			t.Fatal("empty fixture configuration", err)
		}
		descriptor, parts, err := contract.SplitOutputConfiguration(s.root.Domain, image)
		if err != nil || descriptor != s.root.OutputConfiguration || len(parts) != 1 {
			t.Fatal("fixture omitted a nonempty configuration", err)
		}
		body, err := contract.EncodeOutputConfigurationSlice(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.OutputConfigurationSliceID(s.root.Domain, descriptor.ConfigurationDigest, 0)
		if err != nil {
			t.Fatal(err)
		}
		physical := generatedFixtureFreeSupportIndex(t, s)
		object := contract.Hash([]byte(fmt.Sprintf("fixture empty configuration/%x/%x", s.root.Domain, s.root.Snapshot)))
		s.support = append(s.support, format.RequiredSupportPageView{Domain: s.root.Domain, Object: object, Index: physical, Records: []contract.SupportRecordView{{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body}}})
	}
	if len(bundles) == 0 {
		bundles = generatedFixtureBundles(t, s)
	}
	rows := s.supportRecords()
	locations := generatedFixtureSliceLocations(t, rows)
	for _, row := range rows {
		if row.Kind != contract.PublicationCoordinateSupportKind {
			continue
		}
		coordinate, err := contract.InspectPublicationCoordinate(row.Body)
		if err != nil {
			t.Fatal("inspect fixture coordinate", err)
		}
		if !slices.ContainsFunc(s.adminIndex.PublicationOrder, func(order format.PublicationCoordinateOrder) bool {
			return order.CoordinateID == coordinate.CoordinateID
		}) {
			s.adminIndex.PublicationOrder = append(slices.Clone(s.adminIndex.PublicationOrder), format.PublicationCoordinateOrder{CoordinateID: coordinate.CoordinateID, Incarnations: []contract.ID{coordinate.CurrentPublicationIncarnationID}})
		}
	}
	slices.SortFunc(s.adminIndex.PublicationOrder, func(a, b format.PublicationCoordinateOrder) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	mandatory, err := newAdministrativeMandatorySupport(s, locations)
	if err != nil {
		t.Fatal("classify refreshed generated support", err)
	}
	if _, err := mandatory.selectedPublication(s.root.Domain, rows, s.adminIndex.PublicationOrder); err != nil {
		t.Fatal("classify refreshed publication support", err)
	}
	// A fixture can add or enlarge a row after the prior page was full, or
	// turn a shared page into mixed mandatory and disposable support. Repack
	// that complete image before rebuilding its authenticated references.
	for _, page := range s.support {
		pageRows := make([]contract.SupportRecord, len(page.Records))
		var mandatoryPage, optionalPage bool
		for j, row := range page.Records {
			pageRows[j] = contract.SupportRecord(row)
			keep, err := mandatory.row(pageRows[j])
			if err != nil {
				t.Fatal("classify refreshed generated support row", err)
			}
			mandatoryPage, optionalPage = mandatoryPage || keep, optionalPage || !keep
		}
		if _, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{
			Domain: page.Domain, Object: page.Object, Index: page.Index, Records: pageRows,
		}); err != nil || mandatoryPage && optionalPage {
			generatedRepackSupportAtLocations(t, s, rows, bundles, locations)
			return
		}
	}
	s.root.RequiredSupport, s.root.RequiredSupportRecordCount = nil, 0
	pages := make([]format.RequiredSupportPage, 0, len(s.support))
	for i, page := range s.support {
		rows := make([]contract.SupportRecord, len(page.Records))
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
		}
		stored := format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows}
		pages = append(pages, stored)
		body, err := format.EncodeRequiredSupportPage(stored)
		if err != nil {
			t.Fatal("encode refreshed generated support page", i, err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal("reference refreshed generated support page", i, err)
		}
		s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
		s.root.RequiredSupportRecordCount += uint32(len(rows))
		s.support[i], err = format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal("inspect refreshed generated support page", i, err)
		}
	}
	// The fixture changes complete support rows before this refresh. Rebuild
	// their authenticated ownership index from that selected image.
	base := &StateSession{adminIndex: format.AdministrativeIndex{PublicationOrder: s.adminIndex.PublicationOrder}}
	index, err := base.buildAdministrativeIndex(context.Background(), s.root, pages, nil, nil, s, bundles...)
	if err != nil {
		t.Fatal("index refreshed generated support", err)
	}
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(shards) == 0 {
		t.Fatal("encode refreshed generated index", err)
	}
	s.adminIndex = index
	s.root.AdministrativeIndex = shards[0].Ref
	s.root.AdministrativeIndexShards = nil
	for _, shard := range shards[1:] {
		s.root.AdministrativeIndexShards = append(s.root.AdministrativeIndexShards, shard.Ref)
	}
	s.recountChildren()
	s.supportFacts, s.fragmentFacts, s.generatedWork = nil, nil, nil
	s.selectedReceiptRoot = format.Ref{}
	generatedInstallFixtureSupportReader(t, s)
}

// Some negative fixtures are rejected while their administrative ownership
// index is built. That is an earlier rejection of the same selected image.
// Check that boundary before a fixture helper that requires a valid index.
func generatedIndexRejectsAlteredSupport(t testing.TB, s *StateSession) bool {
	t.Helper()
	_, err := generatedAlteredSupportIndexResult(t, s)
	return err != nil
}

func generatedAlteredSupportIndexResult(t testing.TB, s *StateSession) (indexChecked bool, refusal error) {
	t.Helper()
	rows := s.supportRecords()
	bundles := generatedFixtureBundles(t, s)
	var locations []contract.GeneratorSliceLocation
	for _, row := range rows {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Logf("altered support refused at carrier inspection: %v", err)
			return false, err
		}
		if carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices {
			location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
			if err != nil {
				t.Logf("altered support refused at slice inspection: %v", err)
				return false, err
			}
			locations = append(locations, location)
		}
	}
	locations, err := generatedUniqueLocations(locations)
	if err != nil {
		t.Logf("altered support refused at slice uniqueness: %v", err)
		return false, err
	}
	groups, err := generatedReservationGroupsForState(s, rows, locations, bundles)
	if err != nil {
		t.Logf("altered support refused at group classification: %v", err)
		return false, err
	}
	packed, err := format.PackRequiredSupportRows(s.root.Domain, groups, 1)
	if err != nil {
		t.Logf("altered support refused at support packing: %v", err)
		return false, err
	}
	root := s.root
	root.RequiredSupport = nil
	root.RequiredSupportRecordCount = 0
	pages := make([]format.RequiredSupportPage, 0, len(packed))
	for i, records := range packed {
		page := format.RequiredSupportPage{Domain: root.Domain, Object: contract.Hash([]byte(fmt.Sprintf("fixture support page/%x/%x/%d", s.root.Domain, s.root.Snapshot, i))), Index: uint16(i), Records: records}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal("encode repacked altered generated support page", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal("reference altered generated support page", err)
		}
		root.RequiredSupport = append(root.RequiredSupport, ref)
		root.RequiredSupportRecordCount += uint32(len(records))
		pages = append(pages, page)
	}
	base := &StateSession{adminIndex: format.AdministrativeIndex{PublicationOrder: s.adminIndex.PublicationOrder}}
	_, err = base.buildAdministrativeIndex(context.Background(), root, pages, nil, nil, s, bundles...)
	if err != nil {
		t.Logf("altered support refused at administrative index: %v", err)
	}
	return true, err
}

func generatedRepackSupport(t testing.TB, s *StateSession, rows []contract.SupportRecord, bundles []contract.GeneratorPlanBundle) {
	t.Helper()
	generatedRepackSupportAtLocations(t, s, rows, bundles, generatedFixtureSliceLocations(t, rows))
}

func generatedFixtureSliceLocations(t testing.TB, rows []contract.SupportRecord) []contract.GeneratorSliceLocation {
	t.Helper()
	var locations []contract.GeneratorSliceLocation
	for _, row := range rows {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal("inspect carrier before support repack:", err)
		}
		if carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.VectorKind != contract.GeneratorVectorSlices {
			continue
		}
		location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
		if err != nil {
			t.Fatal("inspect slice before support repack:", err)
		}
		locations = append(locations, location)
	}
	locations, err := generatedUniqueLocations(locations)
	if err != nil {
		t.Fatal("unique slices before support repack:", err)
	}
	return locations
}

func generatedRepackSupportAtLocations(t testing.TB, s *StateSession, rows []contract.SupportRecord, bundles []contract.GeneratorPlanBundle, locations []contract.GeneratorSliceLocation) {
	t.Helper()
	groups, err := generatedReservationGroupsForState(s, rows, locations, bundles)
	if err != nil {
		t.Fatal("group support for repack:", err)
	}
	packed, err := format.PackRequiredSupportRows(s.root.Domain, groups, 1)
	if err != nil {
		t.Fatal("pack support rows:", err)
	}
	s.support = nil
	var pages []format.RequiredSupportPage
	for i, records := range packed {
		page := format.RequiredSupportPage{Domain: s.root.Domain, Object: contract.Hash([]byte(fmt.Sprintf("fixture support page/%x/%x/%d", s.root.Domain, s.root.Snapshot, i))), Index: uint16(i), Records: records}
		pages = append(pages, page)
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal("encode repacked support page", i, err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal("inspect repacked support page", i, err)
		}
		s.support = append(s.support, view)
	}
	s.root.Generated.Fragments, err = generatedFragmentDirectory(pages)
	if err != nil {
		t.Fatal("directory for repacked fragments:", err)
	}
	generatedRefreshSupport(t, s, bundles...)
}

func generatedPublicResultFixture(t testing.TB, a generatedAttempt, disposition uint8) []byte {
	raw := uint32(1)
	if disposition == 2 || disposition == 3 {
		raw = 0
	}
	return generatedPublicResultFixtureWithRaw(t, a, disposition, raw)
}

func generatedPublicResultFixtureWithRaw(t testing.TB, a generatedAttempt, disposition uint8, raw uint32) []byte {
	return generatedPublicResultFixtureWithRawToken(t, a, disposition, raw, generatedVectorID(97))
}

func generatedPublicResultFixtureWithRawToken(t testing.TB, a generatedAttempt, disposition uint8, raw uint32, resource contract.ID) []byte {
	t.Helper()
	x := a.expected.Template
	if x.Action != contract.GeneratorActionCreate {
		t.Fatal("retirement fixture requires original selected facts")
	}
	facts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: x.Action, LifecycleMode: x.LifecycleMode,
		ResourceContractID: x.ResourceContractID, Disposition: disposition, RequestDigest: a.expected.RequestDigest, IntentDigest: x.IntentDigest}
	if x.LifecycleMode == contract.GeneratorLifecycleManaged && disposition != contract.GeneratorDispositionConfirmedNoEffect {
		facts.Target, facts.ResourceData = []byte("fixture-target"), bytes.Clone(resource[:])
	}
	if disposition == contract.GeneratorDispositionOwnedUnusableCreate {
		facts.Reason, raw = contract.GeneratorReasonMissingValue, 0
	}
	if disposition == contract.GeneratorDispositionConfirmedNoEffect {
		raw = 0
	}
	return generatedPublicResultWithFacts(t, a, facts, raw)
}

func generatedRetirementResultFixture(t testing.TB, state *StateSession, a generatedAttempt, disposition uint8) []byte {
	t.Helper()
	return generatedPublicResultWithFacts(t, a, generatedRetirementFactsFixture(t, state, a, disposition), 0)
}

func generatedPublicResultWithFacts(t testing.TB, a generatedAttempt, facts contract.GeneratorSafeFacts, raw uint32) []byte {
	t.Helper()
	x := a.expected.Template
	core, err := contract.ExpectedGeneratedResultCore(a.expected, a.material, facts)
	if err != nil {
		t.Fatal(err)
	}
	data, commitment, err := contract.GeneratorResultKeyIDs(x.ResultID)
	if err != nil {
		t.Fatal(err)
	}
	coreDigest, err := contract.GeneratedResultCoreDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	m := a.material.Core
	result, err := contract.EncodeGeneratedResultRecord(contract.GeneratedResultRecord{Core: core, SafeFacts: facts,
		Payload: contract.CanonicalPayload{Profile: 2, CryptoSupportID: m.CryptoSupportID, DataKeyID: data, DataKeyEpoch: 1,
			CommitmentKeyID: commitment, CommitmentKeyEpoch: 1, ContentLength: raw, Ciphertext: bytes.Repeat([]byte{90}, int(raw)+16),
			PackageCheck: generatedVectorID(91), SemanticCommitment: generatedVectorID(92), InputEncoding: contract.InputEncodingRaw, RetainedLength: raw},
		Transfer: contract.TransferEnvelope{Core: contract.TransferCore{Schema: 2, Profile: 2, CompatibilityID: m.CompatibilityID,
			CryptoSupportID: m.CryptoSupportID, DomainID: m.DomainID, OperationID: m.OperationID, OperationMaterialID: m.OperationMaterialID,
			UsePlanDigest: m.UsePlanDigest, UseKind: 2, PacketKind: 6, PacketLength: 100, AttemptID: x.AttemptID, ResultID: x.ResultID,
			ResultCoreDigest: coreDigest, EnvelopeID: generatedVectorID(93)}, Ciphertext: bytes.Repeat([]byte{94}, 116)}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func generatedReservationState(t testing.TB, sources ...contract.GeneratorDeclarationEntry) *StateSession {
	return generatedReservationStateForNames(t, []string{"generated"}, sources...)
}

func generatedReservationStateForNames(t testing.TB, names []string, sources ...contract.GeneratorDeclarationEntry) *StateSession {
	t.Helper()
	id := generatedVectorID
	body := func(v []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	descriptor := func(v contract.GeneratorDescriptor, err error) contract.GeneratorDescriptor {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	fixed := func(v contract.ID, err error) contract.ID {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	g, declaration, parent := generatedEffectPlanForGenerationNames(t, nil, generatedVectorID(11), names, sources...)
	x := g.Lineages[0].Templates[0]
	u := g.ResultUses[slices.IndexFunc(g.ResultUses, func(v contract.GeneratorResultUse) bool { return v.AttemptID == x.AttemptID })]
	consumers := make([][]byte, 2)
	for i := range consumers {
		consumers[i] = body(contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: x.DutyID, MaterialID: parent.MaterialID,
			ContextDigest: fixed(contract.GeneratorResultUseDigest(u)), SubjectKind: 3, SubjectID: x.ResultID, Purpose: uint8(3 + i)}))
	}
	consumerDescriptor, rows := generatedVectorRows(t, 10, x.DutyID, contract.GeneratorVectorConsumers, consumers)
	empty := contract.EmptyGeneratorVector
	a := contract.GeneratedAttemptRecord{Schema: contract.GeneratedAttemptRecordSchema, LifecycleMode: x.LifecycleMode, DomainID: parent.DomainID, OperationID: parent.OperationID, LineageID: x.LineageID, AttemptID: x.AttemptID,
		TemplateDigest: fixed(contract.GeneratorTemplateID(x)), OwnerID: x.DutyID, ResourceID: x.ResourceIncarnationID, TransmissionID: x.TransmissionID, ResultID: x.ResultID,
		InboxID: x.InboxID, ConfigContractID: x.ConfigContractID, ResourceContractID: x.ResourceContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		DescriptorID: x.DescriptorID, ResultContractID: x.ResultContractID, RequestDigest: id(61), State: contract.GeneratedEffectTransmitted,
		Stage: contract.GeneratedStageRetainedResult, CompletionClass: x.CompletionClass, Facts: empty(contract.GeneratorVectorFacts), Progress: empty(contract.GeneratorVectorProgress),
		Support: empty(contract.GeneratorVectorSupport), History: empty(contract.GeneratorVectorHistory)}
	d := contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, LifecycleMode: x.LifecycleMode, DomainID: a.DomainID, DutyID: x.DutyID, OriginalOperationID: a.OperationID, OriginalAttemptID: a.AttemptID,
		OwnerID: x.DutyID, ResourceID: a.ResourceID, ConfigContractID: a.ConfigContractID, ResourceContractID: a.ResourceContractID, ExecutorID: a.ExecutorID, CredentialRouteID: a.CredentialRouteID,
		DescriptorID: a.DescriptorID, ResultContractID: a.ResultContractID, Kind: contract.GeneratedDutyCreate, CompletionClass: a.CompletionClass, Step: 1,
		Status: a.State, CapacityReservation: parent.Capacity, Target: empty(contract.GeneratorVectorTargets), Progress: empty(contract.GeneratorVectorProgress), History: empty(contract.GeneratorVectorHistory),
		Support: a.Support, Consumers: consumerDescriptor}
	aRow := contract.SupportRecord{Kind: 9, RecordID: a.AttemptID, Body: body(contract.EncodeGeneratedAttemptRecord(a))}
	dRow := contract.SupportRecord{Kind: 10, RecordID: d.DutyID, Body: body(contract.EncodeGeneratedDutyRecord(d))}
	phase := contract.GeneratedPhaseRecord{Schema: contract.GeneratedPhaseSchema, DomainID: a.DomainID, OperationID: a.OperationID, OwnerID: a.OperationID, PlanGraphID: parent.PlanGraphID, UsePlanDigest: parent.UsePlanDigest,
		PhaseID: fixed(contract.GeneratorInitialPhaseID(parent.RequestCoreDigest)), Phase: 1, FrontierAttemptID: a.AttemptID, Stage: a.Stage,
		AcceptedResults: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseResults), Attempts: descriptor(contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseAttempts, a.DomainID, []contract.SupportRecord{aRow})),
		Duties: descriptor(contract.GeneratorRecordSetDescriptor(contract.GeneratorPhaseDuties, a.DomainID, []contract.SupportRecord{dRow})), Hazards: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseHazards),
		PendingReleases: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseReleases), Proofs: empty(contract.GeneratorVectorProofs)}
	material := contract.OperationMaterialRecord{Core: contract.OperationMaterialCore{Schema: contract.CanonicalSchema, Profile: 2, DomainID: a.DomainID, OperationID: a.OperationID, OperationMaterialID: parent.MaterialID,
		UsePlanDigest: parent.UsePlanDigest, CompatibilityID: g.Request.CompatibilityID, CryptoSupportID: contract.CryptoSupportID(), SeedEpoch: 1}, SeedCheck: id(63)}
	var protected []contract.CryptoGeneratedSourceProtection
	for _, source := range g.SourceUses {
		consumer, err := contract.GeneratorAcceptedSourceConsumer(a.OperationID, parent.MaterialID, source)
		if err != nil {
			t.Fatal(err)
		}
		_, carriers := generatedVectorRows(t, 2, a.OperationID, contract.GeneratorVectorConsumers, [][]byte{body(contract.EncodeGeneratorConsumer(consumer))})
		rows = append(rows, carriers...)
		protected = append(protected, contract.CryptoGeneratedSourceProtection{SourceID: source.SourceID, OriginalSourceCoreDigest: source.SealedInputCoreDigest,
			OriginalEnvelopeDigest: source.EnvelopeDigest, Transfer: contract.TransferEnvelope{Core: contract.TransferCore{Schema: 2, Profile: 2,
				CompatibilityID: material.Core.CompatibilityID, CryptoSupportID: material.Core.CryptoSupportID, DomainID: a.DomainID,
				OperationID: a.OperationID, OperationMaterialID: parent.MaterialID, UsePlanDigest: parent.UsePlanDigest,
				EnvelopeID: contract.Hash(source.SourceID[:]), UseKind: 1, PacketKind: 5, PacketLength: 68,
				SourceID: source.SourceID, SealedInputCoreDigest: source.SealedInputCoreDigest}, Ciphertext: bytes.Repeat([]byte{71}, 84)}})
	}
	var configuration []generatedContentFixtureBlob
	if len(protected) != 0 {
		configuration = append(configuration, generatedContentFixtureBlob{parent.MaterialID, body(contract.EncodeGeneratedSourceProtections(material, protected))})
	}
	s := generatedPlanContentState(t, g, declaration, configuration...)
	generatedFixtureSelectedShell(t, s)
	generatedInitializeFixtureOutput(t, s)
	decl, err := contract.InspectGeneratorDeclaration(body(contract.EncodeGeneratorDeclaration(declaration)))
	if err != nil {
		t.Fatal(err)
	}
	lineages, err := generatedInitialLineageRows(g, decl)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, lineages...)
	rows = append(rows, aRow, dRow, contract.SupportRecord{Kind: 1, RecordID: parent.MaterialID, Body: body(contract.EncodeOperationMaterialRecord(material))},
		contract.SupportRecord{Kind: 2, RecordID: parent.OperationID, Body: body(contract.EncodeGeneratedParentRecord(parent))},
		contract.SupportRecord{Kind: 5, RecordID: parent.OperationID, Body: body(contract.EncodeGeneratedPhaseRecord(phase))})
	page := format.RequiredSupportPageView{Domain: a.DomainID, Object: id(64), Index: uint16(len(s.support))}
	for _, row := range rows {
		page.Records = append(page.Records, contract.SupportRecordView(row))
	}
	s.support = append(s.support, page)
	s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = parent.OperationID, phase.PhaseID, parent.PlanGraphID
	s.root.Generated.Attempts, s.root.Generated.Duties, s.root.Generated.Materials = 1, 1, 1
	s.root.Generated.Graphs = descriptor(contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, []contract.ID{parent.PlanGraphID}))
	owners := []contract.ID{parent.OperationID, x.DutyID}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.LiveOwners = descriptor(contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners))
	binding := *s.recipients[0].Slots[0].CurrentBinding
	s.admission.recipient = id(11)
	s.root.CurrentAccess.Core.AuthorityRecipientID, s.root.CurrentAccess.Core.CompatibilityID, s.root.CurrentAccess.Core.CryptoSupportID = id(11), material.Core.CompatibilityID, material.Core.CryptoSupportID
	s.recipients[0] = &format.RecipientPage{Domain: a.DomainID, Object: id(66)}
	s.recipients[0].Slots[0] = &contract.RecipientRecord{RecipientID: id(11), Status: contract.CurrentRecipient, CurrentBinding: &binding}
	s.access[0] = &format.AccessPage{Domain: a.DomainID, Object: id(67), Records: []contract.AccessRecord{{Schema: contract.CanonicalSchema, MaterialKind: 3, MaterialID: parent.MaterialID,
		MaterialContextDigest: fixed(contract.OperationMaterialContextDigest(material.Core)), PackageCheck: material.SeedCheck,
		Wraps: []contract.WrapRow{{SubjectKind: 1, SubjectID: id(11), BindingID: binding.BindingID, BindingSerial: 1,
			PublicBindingDigest: fixed(contract.PublicBindingDigest(binding)), RSACiphertext: bytes.Repeat([]byte{68}, 384)}}}}}
	s.root.AccessRecordCount = 1
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("access index")
	}
	return s
}

// full_only: false
func TestGeneratedReservationRetainsAbsentOriginalInbox(t *testing.T) {
	s := generatedReservationState(t)
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil || selected == nil {
		t.Fatal("valid reservation refused", err)
	}
	if len(selected.attempts) != 1 || len(selected.materials) != 1 {
		t.Fatal("reservation lost its exact Attempt or seed")
	}
	for _, attempt := range selected.attempts {
		inbox, err := contract.GeneratorInboxID(s.root.Domain, selected.parent.OperationID, attempt.record.AttemptID, attempt.record.ResultID)
		if err != nil || attempt.record.InboxID != inbox || len(attempt.result) != 0 {
			t.Fatal("missing original result lost its inbox root", err)
		}
	}
	for name, change := range map[string]func(*StateSession){
		"wrong active phase":         func(s *StateSession) { s.root.Generated.ActivePhase = generatedVectorID(90) },
		"missing material count":     func(s *StateSession) { s.root.Generated.Materials = 0 },
		"invented result count":      func(s *StateSession) { s.root.Generated.Results = 1 },
		"obsolete authority binding": func(s *StateSession) { s.access[0].Records[0].Wraps[0].BindingID = generatedVectorID(90) },
		"wrong seed context":         func(s *StateSession) { s.access[0].Records[0].MaterialContextDigest = generatedVectorID(90) },
	} {
		t.Run(name, func(t *testing.T) {
			s := generatedReservationState(t)
			change(s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("invalid reservation accepted")
			}
		})
	}
}

func generatedReplaceRecord(t testing.TB, s *StateSession, kind uint8, id contract.ID, body []byte) {
	t.Helper()
	for i := range s.support {
		for j, row := range s.support[i].Records {
			if row.Kind == kind && row.RecordID == id {
				s.support[i].Records[j].Body = body
				return
			}
		}
	}
	t.Fatal("record missing")
}

func generatedRefreshPhaseSets(t testing.TB, s *StateSession) {
	t.Helper()
	generatedRefreshPhaseSetsUnrefreshed(t, s)
	generatedRefreshSupport(t, s)
}

func generatedRefreshPhaseSetsUnrefreshed(t testing.TB, s *StateSession) {
	t.Helper()
	rows := s.supportRecords()
	var phase contract.GeneratedPhaseRecord
	for _, row := range rows {
		if row.Kind == 5 {
			var err error
			phase, err = contract.InspectGeneratedPhaseRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, field := range []struct {
		kind       contract.GeneratorRecordSetKind
		rowKind    uint8
		descriptor *contract.GeneratorDescriptor
	}{{contract.GeneratorPhaseAttempts, 9, &phase.Attempts}, {contract.GeneratorPhaseDuties, 10, &phase.Duties},
		{contract.GeneratorPhaseResults, 4, &phase.AcceptedResults}, {contract.GeneratorPhaseHazards, 11, &phase.Hazards},
		{contract.GeneratorPhaseReleases, 12, &phase.PendingReleases}} {
		var selected []contract.SupportRecord
		for _, row := range rows {
			if row.Kind == field.rowKind {
				selected = append(selected, row)
			}
		}
		var err error
		*field.descriptor, err = contract.GeneratorRecordSetDescriptor(field.kind, s.root.Domain, selected)
		if err != nil {
			t.Fatal(err)
		}
	}
	body, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 5, phase.OperationID, body)
}

// full_only: false
func TestGeneratedReservationChecksOwnersAfterDescriptorRebinding(t *testing.T) {
	for name, change := range map[string]func(*contract.GeneratedAttemptRecord){
		"owner":               func(v *contract.GeneratedAttemptRecord) { v.OwnerID = generatedVectorID(90) },
		"resource":            func(v *contract.GeneratedAttemptRecord) { v.ResourceID = generatedVectorID(90) },
		"lineage":             func(v *contract.GeneratedAttemptRecord) { v.LineageID = generatedVectorID(90) },
		"template":            func(v *contract.GeneratedAttemptRecord) { v.TemplateDigest = generatedVectorID(90) },
		"executor":            func(v *contract.GeneratedAttemptRecord) { v.ExecutorID = generatedVectorID(90) },
		"permission contract": func(v *contract.GeneratedAttemptRecord) { v.DescriptorID = generatedVectorID(90) },
		"result contract":     func(v *contract.GeneratedAttemptRecord) { v.ResultContractID = generatedVectorID(90) },
		"inbox":               func(v *contract.GeneratedAttemptRecord) { v.InboxID = generatedVectorID(90) },
		"predecessor":         func(v *contract.GeneratedAttemptRecord) { v.PredecessorAttemptID = generatedVectorID(90) },
		"unqualified retry":   func(v *contract.GeneratedAttemptRecord) { v.RetryUsed = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			s := generatedReservationState(t)
			for _, row := range s.supportRecords() {
				if row.Kind != 9 {
					continue
				}
				a, err := contract.InspectGeneratedAttemptRecord(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				change(&a)
				body, err := contract.EncodeGeneratedAttemptRecord(a)
				if err != nil {
					t.Fatal(err)
				}
				generatedReplaceRecord(t, s, 9, row.RecordID, body)
			}
			generatedRefreshPhaseSets(t, s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("self-consistent descriptor hid a changed owner relation")
			}
		})
	}
	for name, change := range map[string]func(*contract.GeneratorConsumer){
		"context":  func(v *contract.GeneratorConsumer) { v.ContextDigest = generatedVectorID(90) },
		"material": func(v *contract.GeneratorConsumer) { v.MaterialID = generatedVectorID(90) },
		"subject":  func(v *contract.GeneratorConsumer) { v.SubjectID = generatedVectorID(90) },
		"owner":    func(v *contract.GeneratorConsumer) { v.OwnerID = generatedVectorID(90) },
	} {
		t.Run("consumer "+name, func(t *testing.T) {
			s := generatedReservationState(t)
			rows := s.supportRecords()
			var duty contract.GeneratedDutyRecord
			for _, row := range rows {
				if row.Kind == 10 {
					var err error
					duty, err = contract.InspectGeneratedDutyRecord(row.Body)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			vectors, err := newGeneratedVectorSet(s.root.Domain, rows)
			if err != nil {
				t.Fatal(err)
			}
			consumers, err := vectors.resolve(10, duty.DutyID, contract.GeneratorVectorConsumers, duty.Consumers)
			if err != nil {
				t.Fatal(err)
			}
			for i, body := range consumers {
				consumer, err := contract.InspectGeneratorConsumer(body)
				if err != nil {
					t.Fatal(err)
				}
				change(&consumer)
				consumers[i], err = contract.EncodeGeneratorConsumer(consumer)
				if err != nil {
					t.Fatal(err)
				}
			}
			descriptor, carriers := generatedVectorRows(t, 10, duty.DutyID, contract.GeneratorVectorConsumers, consumers)
			next := 0
			for i := range s.support {
				for j, row := range s.support[i].Records {
					if row.Kind != contract.GeneratorVectorSupportKind {
						continue
					}
					v, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if v.OwnerKind == 10 && v.OwnerID == duty.DutyID && v.VectorKind == contract.GeneratorVectorConsumers {
						s.support[i].Records[j] = contract.SupportRecordView(carriers[next])
						next++
					}
				}
			}
			duty.Consumers = descriptor
			body, err := contract.EncodeGeneratedDutyRecord(duty)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 10, duty.DutyID, body)
			if name == "owner" {
				generatedRefreshPhaseSetsUnrefreshed(t, s)
				s.generatedWork = nil
			} else {
				generatedRefreshPhaseSets(t, s)
			}
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("self-consistent vector hid a changed consumer relation")
			}
		})
	}
}

func generatedFixtureFreeSupportIndex(t testing.TB, s *StateSession) uint16 {
	t.Helper()
	used := make(map[uint16]bool)
	for _, page := range s.support {
		used[page.Index] = true
	}
	for _, ref := range s.root.RequiredSupport {
		used[ref.Index] = true
	}
	for index := uint16(0); index < contract.MaxChildPages; index++ {
		if !used[index] {
			return index
		}
	}
	t.Fatal("fixture has no free physical support index")
	return 0
}
