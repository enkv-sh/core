package crypto

import (
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func generatedCurrentIntentPlanFixture(t *testing.T, embedded bool) generatedRuntimeFixture {
	t.Helper()
	f := generatedRuntimePlanFixture(t, false)
	id := consumerID
	check := func(step string, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(step, err)
		}
	}
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	check("graph decode", err)
	intent := generatedFixtureIntent(id("carried profile"), id("carried assumption"), contract.GeneratorLifecycleManaged, `{"intent":"exact current generated intent"}`)
	intentID, err := contract.GeneratorIntentDigest(intent)
	check("intent digest", err)
	logical := contract.GeneratorLogicalSlice{Schema: 1, ContentKind: contract.GeneratorContentIntent, ContentID: intentID,
		Length: uint32(len(intent)), Digest: contract.Hash(intent)}
	meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 7, RetirementMode: contract.GeneratedRetirementManual,
		ConfigContractID: id("carried profile"), ResourceContractID: id("carried assumption"), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: intent}
	kind := contract.GeneratorDeclarationGeneratedReference
	payload, err := contract.EncodeGeneratorDeclaredGenerationReference(contract.GeneratorDeclaredGenerationReference{Schema: contract.GeneratorDeclaredReferenceSchema, LifecycleMode: contract.GeneratorLifecycleManaged,
		Epoch: meta.Epoch, RetirementMode: meta.RetirementMode, ConfigContractID: meta.ConfigContractID, ResourceContractID: meta.ResourceContractID,
		CompletionClass: meta.CompletionClass, Intent: logical})
	check("reference payload", err)
	if embedded {
		kind = contract.GeneratorDeclarationGenerated
		payload, err = contract.EncodeGeneratorDeclaredGeneration(meta)
		check("embedded payload", err)
	}
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: g.Header.DomainID, OperationID: g.Header.OperationID,
		Entries: []contract.GeneratorDeclarationEntry{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: kind, Name: "carried", Recipients: []contract.ID{f.base.control.AuthorityRecipientID}, Payload: payload}}}
	f.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	check("declaration encoding", err)
	g.Request.Declaration, err = contract.GeneratorDeclarationDescriptor(declaration)
	check("declaration descriptor", err)
	source, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{logical})
	check("logical descriptor", err)
	membership, err := contract.GeneratorIntendedMembershipDescriptor(declaration.Entries[0].Recipients)
	check("membership descriptor", err)
	plan := contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, LifecycleMode: meta.LifecycleMode, Schema: contract.GeneratorValueEntryPlanSchema, Name: "carried", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
		EntryIncarnationID: id("carried incarnation"), Epoch: meta.Epoch, IntentDigest: intentID, SourceSlice: source,
		IntendedMembership: membership, RetirementMode: meta.RetirementMode}
	g.ValueEntryPlans, g.Header.ValueEntryPlanCount = []contract.GeneratorValueEntryPlan{plan}, 1
	g.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(g.Request)
	check("request digest", err)
	g.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, nil, nil)
	check("graph identity", err)
	f.graph, err = contract.EncodeGeneratorPlanBundle(g)
	check("graph encoding", err)
	f.compare.PlanGraph, err = contract.GeneratorPlanBundleDescriptor(g)
	check("graph descriptor", err)
	f.compare.IntendedEntryPlans, err = contract.GeneratorValueEntryPlansDescriptor(g.ValueEntryPlans)
	check("plan descriptor", err)
	f.compare.UsePlanDigest, err = contract.GeneratorUsePlanDigest(g.UsePlan)
	check("use-plan digest", err)
	p := &f.compare.ParentPlan
	p.ValueEntryPlanCount, p.RequestCoreDigest, p.PlanGraphID, p.UsePlanDigest = 1, g.Header.RequestCoreDigest, g.UsePlan.PlanGraphID, f.compare.UsePlanDigest
	p.Declaration, p.Graph, p.IntendedEntryPlans = g.Request.Declaration, f.compare.PlanGraph, f.compare.IntendedEntryPlans
	generation := id("carried generation")
	data, commitment, err := contract.GeneratorValueKeyIDs(generation)
	check("generated value key identities", err)
	value, err := contract.EncodeCanonicalPayload(contract.CanonicalPayload{Profile: 2, CryptoSupportID: contract.CryptoSupportID(),
		DataKeyID: data, CommitmentKeyID: commitment, DataKeyEpoch: 1, CommitmentKeyEpoch: 1, ContentLength: 3, Ciphertext: make([]byte, 19), InputEncoding: contract.InputEncodingRaw, RetainedLength: 3})
	check("canonical payload", err)
	entry := contract.ValueEntry{Name: plan.Name, Incarnation: plan.EntryIncarnationID, ValueState: generation,
		OriginSnapshot: id("carried snapshot"), OriginTransition: id("carried transition"), ValueSource: contract.Generated,
		ConfidentialityClass: contract.Secret, ValueBytes: value, Recipients: declaration.Entries[0].Recipients,
		Generated: contract.GeneratedEntryMetadata{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedEntryMetadataSchema, Epoch: meta.Epoch, ConfigContractID: meta.ConfigContractID, ResourceContractID: meta.ResourceContractID,
			IntentDigest: intentID, ResourceIncarnationID: id("carried resource"), OriginOperationID: id("carried operation"),
			OriginAttemptID: id("carried attempt"), GenerationID: generation, ResourceDigest: id("carried token"),
			CreateResultID: id("carried result"), CreateEvidence: contract.GeneratorDescriptor{Digest: id("carried evidence"), Length: 8, Count: 1},
			RequiredSupport: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), CompletionClass: meta.CompletionClass, RetirementMode: meta.RetirementMode}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len(value) - contract.CanonicalPayloadOverhead), RetainedLength: uint32(len(value) - contract.CanonicalPayloadOverhead)}
	digest, err := contract.PublicValueEntryDigest(g.Header.DomainID, 0, entry)
	check("selected entry digest", err)
	row := contract.PublicStateRow{Name: entry.Name, EntryDigest: digest}
	f.reservation.Session.BeforePublic.Rows = []contract.PublicStateRow{row}
	f.reservation.Session.Output = generatedEmptyOutputWitness(t, &f.reservation.Session.BeforePublic, []generatedCandidateEntry{{Entry: entry}}, nil)
	root, err := contract.DecodeRef(f.compare.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	check("selected root", err)
	f.reservation.Plan.CurrentIntents = []contract.GeneratedCurrentIntentSelection{{DomainID: f.compare.Context.DomainID,
		HEADDigest: f.compare.Context.PredecessorHEADDigest,
		AccessRoot: f.compare.Context.CurrentAccessRoot, Root: root, HEADRevision: g.Request.PredecessorRevisionID,
		HEADToken: contract.Token{Family: contract.GCP, Value: "1"}, Row: row, Incarnation: entry.Incarnation, Generated: entry.Generated, Intent: logical}}
	f.reservation.Plan.Declaration, f.reservation.Session.Graph = f.declaration, f.graph
	return f
}

// full_only: false
func TestGeneratedPlanPurposesRequireFreshExactCurrentIntents(t *testing.T) {
	for _, embedded := range []bool{false, true} {
		f := generatedCurrentIntentPlanFixture(t, embedded)
		form := "reference"
		if embedded {
			form = "embedded"
		}
		for _, purpose := range []contract.CryptoGeneratedPurpose{contract.CryptoGeneratedReservationPurpose,
			contract.CryptoGeneratedAdoptionPurpose, contract.CryptoGeneratedFinalPreparationPurpose, contract.CryptoGeneratedProducerPreparationPurpose} {
			q := f.compare
			q.Purpose = purpose
			if purpose != contract.CryptoGeneratedReservationPurpose {
				q.Parent = contract.GeneratedParentRecord(q.ParentPlan)
				q.Parent.RequestIdentityDigest = consumerID("accepted carried plan")
				q.ParentPlan = contract.GeneratedParentPlan{}
			}
			state := func() generatedPurposeState {
				switch purpose {
				case contract.CryptoGeneratedReservationPurpose:
					return generatedPurposeState{reservation: &generatedReservationState{}}
				case contract.CryptoGeneratedAdoptionPurpose:
					return generatedPurposeState{adoption: &generatedAdoptionState{}}
				case contract.CryptoGeneratedFinalPreparationPurpose:
					return generatedPurposeState{final: &generatedFinalPreparationState{}}
				default:
					return generatedPurposeState{producer: &generatedProducerPreparationState{}}
				}
			}
			r := newConsumerRuntime(t, f.base.route)
			a, err := r.prepareGeneratedPlan(q, f.reservation.Session, f.reservation.Plan, state(), nil, f.graph, f.base.deadline)
			if err != nil {
				t.Fatal("exact current intent refused", purpose, embedded, err)
			}
			if len(a.purpose.plan().intents) != 1 || a.purpose.plan().intents[0] == (contract.GeneratorDescriptor{}) {
				t.Fatal("carried logical descriptor omitted")
			}
			selected := f.reservation.Plan.CurrentIntents[0]
			selected.Generated.ConfigContractID = consumerID("matching fabricated provider profile")
			meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: selected.Generated.Epoch, RetirementMode: selected.Generated.RetirementMode,
				ConfigContractID: selected.Generated.ConfigContractID, ResourceContractID: selected.Generated.ResourceContractID, CompletionClass: selected.Generated.CompletionClass}
			if a.currentIntentMatches(selected, a.graph.ValueEntryPlans[0], meta, selected.Intent) {
				t.Fatal("matching caller metadata replaced independent authenticated entry metadata")
			}
			a.clear()
			cached := r.generatedPlan
			public, private := f.base.route.publicCalls, f.base.route.privateCalls
			for name, damage := range map[string]func(*contract.GeneratedCurrentIntentSelection){
				"domain":       func(v *contract.GeneratedCurrentIntentSelection) { v.DomainID = consumerID("wrong domain") },
				"head":         func(v *contract.GeneratedCurrentIntentSelection) { v.HEADDigest = consumerID("stale head") },
				"root":         func(v *contract.GeneratedCurrentIntentSelection) { v.Root.Digest = consumerID("stale root") },
				"condition":    func(v *contract.GeneratedCurrentIntentSelection) { v.HEADToken.Value = "2" },
				"access root":  func(v *contract.GeneratedCurrentIntentSelection) { v.AccessRoot = consumerID("old access root") },
				"name":         func(v *contract.GeneratedCurrentIntentSelection) { v.Row.Name = "absent" },
				"slot":         func(v *contract.GeneratedCurrentIntentSelection) { v.Row.Slot++ },
				"entry digest": func(v *contract.GeneratedCurrentIntentSelection) { v.Row.EntryDigest = consumerID("unselected entry") },
				"incarnation":  func(v *contract.GeneratedCurrentIntentSelection) { v.Incarnation = consumerID("readded incarnation") },
				"epoch":        func(v *contract.GeneratedCurrentIntentSelection) { v.Generated.Epoch-- },
				"intent": func(v *contract.GeneratedCurrentIntentSelection) {
					v.Generated.IntentDigest = consumerID("changed intent")
				},
				"config contract": func(v *contract.GeneratedCurrentIntentSelection) {
					v.Generated.ConfigContractID = consumerID("different profile")
				},
				"resource contract": func(v *contract.GeneratedCurrentIntentSelection) {
					v.Generated.ResourceContractID = consumerID("different assumption")
				},
				"lifecycle": func(v *contract.GeneratedCurrentIntentSelection) {
					v.Generated.LifecycleMode = contract.GeneratorLifecycleNone
				},
				"completion": func(v *contract.GeneratedCurrentIntentSelection) { v.Generated.CompletionClass = 2 },
				"retirement": func(v *contract.GeneratedCurrentIntentSelection) { v.Generated.RetirementMode = 2 },
				"length":     func(v *contract.GeneratedCurrentIntentSelection) { v.Intent.Length++ },
				"digest":     func(v *contract.GeneratedCurrentIntentSelection) { v.Intent.Digest = consumerID("different bytes") },
			} {
				t.Run(fmt.Sprintf("%s/purpose%d/%s", form, purpose, name), func(t *testing.T) {
					plan := f.reservation.Plan
					plan.CurrentIntents = slices.Clone(plan.CurrentIntents)
					damage(&plan.CurrentIntents[0])
					if bad, err := r.prepareGeneratedPlan(q, f.reservation.Session, plan, state(), nil, f.graph, f.base.deadline); err == nil || bad != nil {
						t.Fatal("different selected intent admitted", purpose, embedded)
					}
					if r.generatedPlan != cached || r.slot != nil || r.generated != nil || f.base.route.publicCalls != public || f.base.route.privateCalls != private {
						t.Fatal("refusal changed cache, authority or key use")
					}
				})
			}
			for _, facts := range [][]contract.GeneratedCurrentIntentSelection{nil, {f.reservation.Plan.CurrentIntents[0], f.reservation.Plan.CurrentIntents[0]}} {
				plan := f.reservation.Plan
				plan.CurrentIntents = facts
				if bad, err := r.prepareGeneratedPlan(q, f.reservation.Session, plan, state(), nil, f.graph, f.base.deadline); err == nil || bad != nil {
					t.Fatal("incomplete or surplus current intent facts admitted")
				}
			}
		}
	}
}
