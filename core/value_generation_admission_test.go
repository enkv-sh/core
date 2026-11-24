package core

import (
	"bytes"
	stdcontext "context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedPlanInputFixture(t testing.TB, s *StateSession, sources ...contract.GeneratorDeclarationEntry) generatedPlanInput {
	return generatedPlanInputForOperation(t, s, generatedVectorID(10), sources...)
}

func generatedPlanInputForOperation(t testing.TB, s *StateSession, operation contract.ID, sources ...contract.GeneratorDeclarationEntry) generatedPlanInput {
	return generatedPlanInputForProfile(t, s, operation, defaultGeneratedFixtureProfile(), sources...)
}

func generatedPlanInputForProfile(t testing.TB, s *StateSession, operation contract.ID, profile generatedFixtureProfile, sources ...contract.GeneratorDeclarationEntry) generatedPlanInput {
	return generatedPlanInputForGenerations(t, s, operation, []string{"generated"}, profile, sources...)
}

func generatedPlanInputForGenerations(t testing.TB, s *StateSession, operation contract.ID, names []string, profile generatedFixtureProfile, sources ...contract.GeneratorDeclarationEntry) generatedPlanInput {
	return generatedPlanInputForGenerationsIntent(t, s, operation, names, []byte(`{"name":"generated"}`), profile, sources...)
}

func generatedPlanInputForGenerationsIntent(t testing.TB, s *StateSession, operation contract.ID, names []string, intent []byte,
	profile generatedFixtureProfile, sources ...contract.GeneratorDeclarationEntry) generatedPlanInput {
	return generatedPlanInputForGenerationsMembershipIntent(t, s, operation, names, []contract.ID{s.admission.recipient}, intent,
		profile, sources...)
}

func generatedPlanInputForGenerationsMembershipIntent(t testing.TB, s *StateSession, operation contract.ID, names []string,
	generatedRecipients []contract.ID, intent []byte, profile generatedFixtureProfile,
	sources ...contract.GeneratorDeclarationEntry) generatedPlanInput {
	t.Helper()
	x := generatedReservationInputForMembershipStateIntent(t, s, operation, generatedRecipients, names, intent, profile, 0, nil, nil, sources...)
	context := contract.ApplyContext{OperationClass: contract.CryptoGeneratedClass, AdmissionID: generatedVectorID(81), SessionID: generatedVectorID(82),
		DomainID: s.admission.domain, CompatibilityID: contract.CompatibilityID(),
		Expiry: uint64(time.Now().Add(time.Minute).UnixNano()), PredecessorHEADDigest: contract.Hash(s.body), CurrentAccessRoot: s.root.CurrentAccess.AccessRoot}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(context.PredecessorRootRef[:], root)
	context.OriginalConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		t.Fatal(err)
	}
	return generatedPlanInput{graph: x.graph, declaration: x.declaration, registry: x.graph.Request.Registry,
		recoveryPolicy: x.graph.Request.RecoveryPolicyID, context: context, requestBindings: slices.Clone(x.requestBindings)}
}

// full_only: false
func TestGeneratedEpochRequiresExactSameIntentOrFreshGeneration(t *testing.T) {
	current := &contract.ValueEntry{ValueSource: contract.Generated, Generated: contract.GeneratedEntryMetadata{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedEntryMetadataSchema, Epoch: 4, IntentDigest: generatedVectorID(1),
		ConfigContractID: generatedVectorID(2), ResourceContractID: generatedVectorID(3), CompletionClass: 1, RetirementMode: 1}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	plan := contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Epoch: 4, IntentDigest: current.Generated.IntentDigest}
	meta := contract.GeneratorDeclaredGeneration{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratorDeclaredGenerationSchema, Epoch: 4, ConfigContractID: current.Generated.ConfigContractID, ResourceContractID: current.Generated.ResourceContractID, CompletionClass: 1, RetirementMode: 1}
	for _, tc := range []struct {
		name    string
		epoch   uint64
		changed bool
		fresh   bool
		want    bool
	}{{"unchanged", 4, false, false, true}, {"repeat effect", 4, false, true, false}, {"changed same epoch", 4, true, true, false},
		{"lower epoch", 3, false, true, false}, {"higher without generation", 5, false, false, false}, {"higher", 5, false, true, true},
		{"higher changed intent", 5, true, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			p := plan
			p.Epoch = tc.epoch
			if tc.changed {
				p.IntentDigest = generatedVectorID(99)
			}
			if tc.fresh {
				p.ChangeMask = 1
			}
			if generatedEpochValid(current, p, meta) != tc.want {
				t.Fatal("incorrect epoch admission")
			}
		})
	}
	for _, tc := range []struct {
		name          string
		input, output uint8
		epoch         uint64
		fresh, want   bool
	}{
		{"input class same epoch", contract.InputEncodingBase64, contract.OutputEncodingRaw, 4, false, false},
		{"input class fresh same epoch", contract.InputEncodingBase64, contract.OutputEncodingRaw, 4, true, false},
		{"input class new epoch", contract.InputEncodingBase64, contract.OutputEncodingRaw, 5, true, true},
		{"output only", contract.InputEncodingRaw, contract.OutputEncodingBase64, 4, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := plan
			p.InputEncoding, p.OutputEncoding, p.Epoch = tc.input, tc.output, tc.epoch
			if tc.fresh {
				p.ChangeMask = contract.GeneratorValueChangeContent
			}
			if generatedEpochValid(current, p, meta) != tc.want {
				t.Fatal("representation changed epoch admission")
			}
		})
	}

	for _, change := range []func(*contract.GeneratorDeclaredGeneration){
		func(v *contract.GeneratorDeclaredGeneration) { v.ConfigContractID = generatedVectorID(99) },
		func(v *contract.GeneratorDeclaredGeneration) { v.ResourceContractID = generatedVectorID(99) },
		func(v *contract.GeneratorDeclaredGeneration) { v.LifecycleMode = contract.GeneratorLifecycleNone },
		func(v *contract.GeneratorDeclaredGeneration) { v.CompletionClass = 2 },
		func(v *contract.GeneratorDeclaredGeneration) { v.RetirementMode = 2 },
	} {
		changed := meta
		change(&changed)
		if generatedEpochValid(current, plan, changed) {
			t.Fatal("same epoch changed the accepted contract")
		}
	}
	for _, predecessor := range []*contract.ValueEntry{nil, {ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret}} {
		for _, epoch := range []uint64{0, 7} {
			for _, content := range []bool{false, true} {
				t.Run(fmt.Sprintf("initial/source=%v/epoch=%d/content=%t", predecessor != nil, epoch, content), func(t *testing.T) {
					p := contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Epoch: epoch, IntentDigest: generatedVectorID(90)}
					if content {
						p.ChangeMask = contract.GeneratorValueChangeContent
					}
					if generatedEpochValid(predecessor, p, meta) != (content && epoch == 0) {
						t.Fatal("initial generation must require epoch zero and new content")
					}
				})
			}
		}
	}
	if generatedEpochValid(nil, plan, meta) {
		t.Fatal("new member omitted generation")
	}
	plan.ChangeMask = 1
	plan.Epoch = 0
	if !generatedEpochValid(nil, plan, meta) {
		t.Fatal("new generated member refused")
	}
}

// full_only: false
func TestGeneratedPlanAdmissionPinsPredecessorAndCapacity(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	before := *s
	input := generatedPlanInputFixture(t, s)
	plan, err := s.generatedPlanRequest(t.Context(), input)
	if err != nil {
		t.Fatal("valid fixed plan refused", err)
	}
	if _, err := contract.EncodeCryptoGeneratedCompareRequest(plan.request); err != nil {
		t.Fatal(err)
	}
	d, err := contract.GeneratorCapacityDescriptor(plan.capacity)
	if err != nil || plan.request.ParentPlan.Capacity != d || d.Length != contract.GeneratorCapacityEvidenceLength+8 ||
		plan.capacity.BeforeRootDigest != s.head.Core.Root.Digest || plan.capacity.PlanGraphID != input.graph.UsePlan.PlanGraphID {
		t.Fatal("reservation did not derive complete capacity evidence", err)
	}
	for name, damage := range map[string]func(*generatedPlanInput){
		"missing private admission": func(x *generatedPlanInput) { x.context.AdmissionID = contract.ID{} },
		"missing private session":   func(x *generatedPlanInput) { x.context.SessionID = contract.ID{} },
		"root":                      func(x *generatedPlanInput) { x.context.PredecessorRootRef[100] ^= 1 },
		"head":                      func(x *generatedPlanInput) { x.context.PredecessorHEADDigest = generatedVectorID(98) },
		"condition":                 func(x *generatedPlanInput) { x.context.OriginalConditionDigest = generatedVectorID(98) },
		"access root":               func(x *generatedPlanInput) { x.context.CurrentAccessRoot = generatedVectorID(98) },
		"compatibility":             func(x *generatedPlanInput) { x.context.CompatibilityID = generatedVectorID(98) },
		"registry":                  func(x *generatedPlanInput) { x.registry.Digest = generatedVectorID(98) },
		"recovery policy":           func(x *generatedPlanInput) { x.recoveryPolicy = generatedVectorID(98) },
		"expired":                   func(x *generatedPlanInput) { x.context.Expiry = 1 },
		"foreign descriptor": func(x *generatedPlanInput) {
			x.context.IntentDescriptor = contract.DescriptorVector{Digest: generatedVectorID(98), Length: 1, Count: 1}
		},
		"missing request": func(x *generatedPlanInput) { x.requestBindings[0].Digest = contract.ID{} },
		"changed declaration": func(x *generatedPlanInput) {
			x.declaration = append([]byte(nil), x.declaration...)
			x.declaration[len(x.declaration)-1] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			x := input
			x.requestBindings = slices.Clone(input.requestBindings)
			damage(&x)
			if _, err := s.generatedPlanRequest(t.Context(), x); err == nil {
				t.Fatal("changed admission accepted")
			}
		})
	}
	if !reflect.DeepEqual(*s, before) {
		t.Fatal("public admission changed the predecessor")
	}
}

// full_only: false
func TestGeneratedAdmissionCountsActualRetainedDeclaration(t *testing.T) {
	s, _, _ := generatedCanonicalState(t, false)

	s.head.Core.Revision = generatedVectorID(14)
	current := s.valueEntry(7)
	if current == nil || current.ValueSource != contract.Supplied || current.ConfidentialityClass != contract.Secret {
		t.Fatal("selected predecessor lacks retained source")
	}
	retained, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: 7, Entry: *current})
	if err != nil {
		t.Fatal(err)
	}
	declarationEntry := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
		Name: current.Name, Recipients: slices.Clone(current.Recipients), Payload: retained}
	base, _, _ := generatedEffectPlanFixture(t)
	request := base.Request
	request.OperationID = generatedVectorID(250)
	request.DomainID = s.admission.domain
	request.PredecessorRevisionID, request.PredecessorHEADDigest = s.head.Core.Revision, contract.Hash(s.body)
	request.ConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		t.Fatal(err)
	}
	graph, declaration, _ := generatedEffectPlanForRequest(t, &request, declarationEntry)
	selected, err := s.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal(err)
	}
	declarationBytes, err := contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	view, err := contract.InspectGeneratorDeclaration(declarationBytes)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := s.generatedAdmissionShape(t.Context(), graph, view, selected)
	if err != nil {
		t.Fatal("retained declaration did not reach capacity admission", err)
	}
	shape.DeclarationBytes = uint64(len(declarationBytes))
	if len(graph.SourceUses) != 0 || shape.Sources != 0 || shape.RetainedSources != 1 {
		t.Fatal("sealed and retained sources were conflated", len(graph.SourceUses), shape.Sources, shape.RetainedSources)
	}
	// The sealed selected fixture already records the exact registry count.
	// Capacity admission must carry it once, without counting the pages again.
	if shape.Recipients != uint64(len(s.registry())) || shape.Recipients != uint64(s.root.RecipientCount) {
		t.Fatal("capacity admission changed the selected recipient count", shape.Recipients)
	}
	groups, err := generatedCleanCapacity(shape)
	if err != nil || groups[contract.GeneratorCapacityOldValues].MaxCount < shape.OldGenerated+1 {
		t.Fatalf("retained source was not charged as selected old value: shape=%+v err=%v", shape, err)
	}
	rows, _, _, err := generatedAdministrativeRowEnvelope(shape)
	if err != nil || rows[contract.RetainedCanonicalSupportKind] < shape.OldGenerated+1 {
		t.Fatal("retained source was omitted from authenticated row envelope", err)
	}
	// Isolate this admission-shape projection from operation authorization.
	// The separate current-only declaration test checks both complete Delete
	// contracts and their positive/negative qualification boundaries. A Delete
	// declaration qualifies current bytes; it does not install another kind-6
	// row or remove the independently selected historical row.
	for _, operation := range []uint16{contract.OperationCleanOwnedFailureResidue, contract.OperationRetireGeneratedGeneration} {
		deleteGraph := graph
		deleteGraph.Request.OperationKind = operation
		deleteShape, err := s.generatedAdmissionShape(t.Context(), deleteGraph, view, selected)
		if err != nil {
			t.Fatal("current-only Delete declaration did not reach shape admission", operation, err)
		}
		deleteShape.DeclarationBytes = uint64(len(declarationBytes))
		if deleteShape.RetainedSources != 0 || len(deleteShape.RetainedRows) != 0 || deleteShape.Sources != 0 ||
			deleteShape.DeclarationBytes != shape.DeclarationBytes || deleteShape.Secrets != shape.Secrets ||
			deleteShape.Memberships != shape.Memberships || deleteShape.SecretMemberships != shape.SecretMemberships {
			t.Fatal("Delete declaration invented retained support or lost declaration/current material charge", operation)
		}
		groups, err := generatedCleanCapacity(deleteShape)
		if err != nil || groups[contract.GeneratorCapacityOldValues].MaxCount != deleteShape.OldGenerated {
			t.Fatal("Delete declaration charged an unpersisted canonical row", operation, err)
		}
		rows, _, _, err := generatedAdministrativeRowEnvelope(deleteShape)
		if err != nil || rows[contract.RetainedCanonicalSupportKind] != 0 {
			t.Fatal("Delete declaration reserved an unpersisted canonical row", operation, err)
		}
		if historical, present := selected.records[generatedRecordKey{kind: contract.RetainedCanonicalSupportKind, id: current.ValueState}]; !present || len(historical.Body) == 0 || bytes.Equal(historical.Body, retained) {
			t.Fatal("projection fixture lost its distinct selected historical reader row", operation)
		}
	}
}

// full_only: false
func TestGeneratedPlanBindsEveryCreateLineage(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	names := []string{"alpha", "beta", "gamma"}
	input := generatedPlanInputForGenerations(t, s, generatedVectorID(10), names, defaultGeneratedFixtureProfile())
	if len(input.requestBindings) != len(names) {
		t.Fatal("fixture omitted a create lineage")
	}
	for i := range input.requestBindings {
		input.requestBindings[i].Digest = generatedVectorID(byte(61 + i))
	}
	if _, err := s.generatedPlanRequest(t.Context(), input); err != nil {
		t.Fatal("complete distinct requests refused", err)
	}
	sameBody := input
	sameBody.requestBindings = slices.Clone(input.requestBindings)
	for i := range sameBody.requestBindings {
		sameBody.requestBindings[i].Digest = input.requestBindings[0].Digest
	}
	if _, err := s.generatedPlanRequest(t.Context(), sameBody); err != nil {
		t.Fatal("independent attempts with identical request bodies were refused", err)
	}
	for name, change := range map[string]func(*generatedPlanInput){
		"missing": func(x *generatedPlanInput) { x.requestBindings = x.requestBindings[:2] },
		"extra":   func(x *generatedPlanInput) { x.requestBindings = append(x.requestBindings, x.requestBindings[0]) },
		"reordered": func(x *generatedPlanInput) {
			x.requestBindings[0], x.requestBindings[1] = x.requestBindings[1], x.requestBindings[0]
		},
		"duplicate":    func(x *generatedPlanInput) { x.requestBindings[1] = x.requestBindings[0] },
		"substituted":  func(x *generatedPlanInput) { x.requestBindings[1].AttemptID = generatedVectorID(98) },
		"empty digest": func(x *generatedPlanInput) { x.requestBindings[1].Digest = contract.ID{} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := input
			changed.requestBindings = slices.Clone(input.requestBindings)
			change(&changed)
			if _, err := s.generatedPlanRequest(t.Context(), changed); err == nil {
				t.Fatal("incomplete or mismatched request set accepted")
			}
		})
	}
	reservationInput := generatedReservationInputForGenerations(t, s, generatedVectorID(10), names)
	reservationInput.requestBindings = slices.Clone(input.requestBindings)
	reservation, err := s.deriveGeneratedReservation(stdcontext.Background(), reservationInput)
	if err != nil {
		t.Fatal("distinct request reservation", err)
	}
	selection, err := reservation.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal("selected request set", err)
	}
	for _, binding := range input.requestBindings {
		attempt, present := selection.attempts[binding.AttemptID]
		if !present || attempt.record.RequestDigest != binding.Digest {
			t.Fatal("create lineage received another request digest")
		}
	}
	reservation.state.generatedWork = nil
	selection, err = reservation.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal("cold request binding reconstruction", err)
	}
	first := selection.attempts[selection.phase.FrontierAttemptID]
	record, err := reservation.state.generatedRecordRequest(stdcontext.Background(), first.record.AttemptID, generatedPublicResultFixture(t, first, 1),
		generatedContinuationContext(t, reservation.state, 101, 102))
	if err != nil {
		t.Fatal("first distinct request record", err)
	}
	recorded, err := reservation.state.deriveGeneratedRecord(stdcontext.Background(), record)
	if err != nil {
		t.Fatal("partial distinct request progress", err)
	}
	recorded.state.generatedWork = nil
	selection, err = recorded.state.selectedGeneratedWork(stdcontext.Background())
	if err != nil {
		t.Fatal("cold partial request progress", err)
	}
	for _, binding := range input.requestBindings {
		attempt, present := selection.attempts[binding.AttemptID]
		if !present || attempt.record.RequestDigest != binding.Digest {
			t.Fatal("partial progress lost an independent request binding")
		}
	}
}

// full_only: false
func TestGeneratedOperationKindMatchesGraphFamily(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	create := generatedPlanInputFixture(t, before).graph
	old, _, _ := generatedDetachedRetirementState(t, "absent", 0)
	before.support, before.root.Generated = old.support, old.root.Generated
	generatedRefreshSupport(t, before)
	before.recountChildren()
	retirement := generatedDeleteReservationInputFixture(t, before, generatedVectorID(98), 2).graph
	cleanup := retirement
	cleanup.Lineages = slices.Clone(retirement.Lineages)
	cleanup.Lineages[0].Purpose = contract.GeneratorLineageCleanup
	for _, kind := range []uint16{2, 12, 31, 38, 39} {
		for _, tc := range []struct {
			name string
			g    contract.GeneratorPlanBundle
			want bool
		}{{"create", create, kind == 2 || kind == 12}, {"cleanup", cleanup, kind == 31},
			{"retirement", retirement, kind == 38}} {
			t.Run(fmt.Sprintf("kind%d/%s", kind, tc.name), func(t *testing.T) {
				g := tc.g
				g.Request.OperationKind = kind
				if generatedOperationGraphValid(g) != tc.want {
					t.Fatal("operation kind admitted an incompatible effect family")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedAdmissionRefusesCleanupKindOnCreateGraph(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	base := generatedPlanInputFixture(t, s)
	for _, kind := range []uint16{31, 38, 39} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			input := base
			input.graph = cloneGeneratorPlanBundle(base.graph)
			oldJoin, err := contract.GeneratorCompleteJoinID(input.graph.Header.RequestCoreDigest)
			if err != nil {
				t.Fatal(err)
			}
			input.graph.Request.OperationKind = kind
			input.graph.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(input.graph.Request)
			if err != nil {
				t.Fatal(err)
			}
			newJoin, err := contract.GeneratorCompleteJoinID(input.graph.Header.RequestCoreDigest)
			if err != nil {
				t.Fatal(err)
			}
			for i := range input.graph.Edges {
				if input.graph.Edges[i].DestinationTemplateID == oldJoin {
					input.graph.Edges[i].DestinationTemplateID = newJoin
				}
			}
			input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header,
				input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
			if err != nil || contract.ValidateGeneratorEffectGraph(input.graph) != nil {
				t.Fatal("incompatible graph was malformed before admission", err)
			}
			if _, err := s.generatedPlanRequest(t.Context(), input); err == nil {
				t.Fatal("incompatible operation reached generated reservation")
			}
		})
	}
}

// full_only: false
func TestGeneratedPlanAdmissionIncludesOlderWork(t *testing.T) {
	for _, backlog := range []string{"retirement", "missing create result", "retained create result"} {
		t.Run(backlog, func(t *testing.T) {
			s := generatedEmptyPredecessor(t)
			input := generatedPlanInputFixture(t, s)
			clean, err := s.generatedPlanRequest(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			if backlog == "retirement" {
				old, _, _ := generatedDetachedRetirementState(t, "absent", 0)
				s.support, s.root.Generated = old.support, old.root.Generated
				generatedRefreshSupport(t, s)
			} else {
				reserved, err := s.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputFixture(t, s))
				if err != nil {
					t.Fatal(err)
				}
				var original generatedAttempt
				s, original = generatedUnselectedCleanupFromReservation(t, reserved.state)
				disposition := uint8(0)
				if backlog == "retained create result" {
					disposition = 2
				}
				s, _, _ = generatedCreateHazardFromCleanup(t, s, original, disposition)
			}
			s.recountChildren()
			if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
				t.Fatal("invalid predecessor with older work")
			}
			input = generatedPlanInputForOperation(t, s, generatedVectorID(98))
			plan, err := s.generatedPlanRequest(t.Context(), input)
			if err != nil {
				t.Fatal("small backlog refused", err)
			}
			want := map[int]uint64{contract.GeneratorCapacityOwners: 1}
			if backlog != "retirement" {
				want[contract.GeneratorCapacityCreates] = 1
				want[contract.GeneratorCapacityCreateResults] = 1
				want[contract.GeneratorCapacityMaterial] = 1
				want[contract.GeneratorCapacitySeedAccess] = 1
			}
			for group, extra := range want {
				if plan.capacity.Groups[group].MaxCount != clean.capacity.Groups[group].MaxCount+extra {
					t.Errorf("group %d omitted older work: clean=%+v occupied=%+v", group, clean.capacity.Groups[group], plan.capacity.Groups[group])
				}
			}
			if plan.capacity.Groups[contract.GeneratorCapacityIntents].MaxFramedBytes <= clean.capacity.Groups[contract.GeneratorCapacityIntents].MaxFramedBytes {
				t.Error("older intent bytes omitted")
			}
		})
	}
}

// full_only: false
func TestGeneratedPlanAdmissionReservesDetachedRetirement(t *testing.T) {
	old, duty, _ := generatedDetachedRetirementState(t, "absent", 0)
	before := generatedEmptyPredecessor(t)
	before.support, before.root.Generated = old.support, old.root.Generated
	generatedRefreshSupport(t, before)
	before.recountChildren()
	if _, relationErr := before.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("invalid detached retirement predecessor")
	}
	operation := generatedVectorID(98)
	reservation := generatedDeleteReservationInputFixture(t, before, operation, 2)
	input := generatedPlanInputForOperation(t, before, operation)
	input.graph, input.declaration = reservation.graph, reservation.declaration
	input.registry, input.recoveryPolicy = reservation.graph.Request.Registry, reservation.graph.Request.RecoveryPolicyID
	input.requestBindings = slices.Clone(reservation.requestBindings)
	plan, err := before.generatedPlanRequest(t.Context(), input)
	if err != nil || plan == nil || plan.phase == nil || plan.phase.TransitionKind != contract.GeneratorAuthorityRetireReserve {
		t.Fatal("public admission refused exact detached duty", err, duty.DutyID)
	}
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
func TestGeneratedPlanAdmissionRefusesBacklogBeyondReservedChildren(t *testing.T) {
	var constructed, greatestRequested int
	t.Cleanup(func() {
		t.Logf("backlog construction: requested=%d constructed=%d", greatestRequested, constructed)
		if constructed != greatestRequested {
			t.Fatal("backlog construction exceeded selected scope", constructed, greatestRequested)
		}
	})
	var locations []contract.GeneratorSliceLocation
	var blobs []generatedContentFixtureBlob
	var records []contract.SupportRecord
	var access []contract.AccessRecord
	var bundles []contract.GeneratorPlanBundle
	var graphs, owners []contract.ID
	seen := make(map[generatedContentKey]bool)
	buildPrefix := func(t *testing.T, count int) {
		t.Helper()
		for i := constructed + 1; i <= count; i++ {
			old := generatedEmptyPredecessor(t)
			operation := contract.Hash([]byte(fmt.Sprintf("pending generated operation %d", i)))
			reservation, err := old.deriveGeneratedReservation(stdcontext.Background(), generatedReservationInputForOperation(t, old, operation))
			if err != nil {
				t.Fatal(err)
			}
			old, original := generatedUnselectedCleanupFromReservation(t, reservation.state)
			old, _, hazard := generatedCreateHazardFromCleanup(t, old, original, 0)
			constructed++
			selected, err := old.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			for key, location := range selected.content.locations {
				if seen[key] {
					continue
				}
				seen[key] = true
				body, err := selected.readSelectedSlice(t.Context(), key.kind, key.id, location.Length)
				if err != nil {
					t.Fatal(err)
				}
				location.BlobID, location.Offset = contract.Hash(body), 0
				locations = append(locations, location)
				blobs = append(blobs, generatedContentFixtureBlob{location.BlobID, body})
			}
			for _, row := range old.supportRecords() {
				_, carrier, err := snapshotSliceRecord(row, old.root.Domain, old.root.Snapshot)
				if err != nil {
					t.Fatal(err)
				}
				if row.Kind != contract.GeneratedFragmentSupportKind && row.Kind != contract.OutputConfigurationSliceSupportKind && !carrier {
					records = append(records, row)
				}
			}
			access = append(access, old.accessRecords()...)
			bundles = append(bundles, selected.bundles...)
			graphs = append(graphs, selected.bundles[0].UsePlan.PlanGraphID)
			owners = append(owners, hazard.HazardID)
		}
	}
	for _, i := range []int{393, 394, 395} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			greatestRequested = max(greatestRequested, i)
			buildPrefix(t, i)
			s := generatedEmptyPredecessor(t)
			rows := append(slices.Clone(records), s.supportRecords()...)
			for _, blob := range blobs {
				fragments, err := generatedFragmentRows(blob.id, blob.body)
				if err != nil {
					t.Fatal(err)
				}
				rows = append(rows, fragments...)
			}
			locations, err := generatedUniqueLocations(slices.Clone(locations))
			if err != nil {
				t.Fatal(err)
			}
			var sliceBodies [][]byte
			for _, location := range locations {
				body, err := contract.EncodeGeneratorSliceLocation(location)
				if err != nil {
					t.Fatal(err)
				}
				sliceBodies = append(sliceBodies, body)
			}
			descriptor, carriers := generatedVectorRows(t, contract.GeneratorSnapshotOwner, s.root.Snapshot, contract.GeneratorVectorSlices, sliceBodies)
			s.root.Generated.Slices = descriptor
			rows = append(rows, carriers...)
			s.root.Generated.Attempts, s.root.Generated.Materials, s.root.Generated.Hazards = uint32(i), uint32(i), uint32(i)
			graphs := slices.Clone(graphs)
			owners := slices.Clone(owners)
			slices.SortFunc(graphs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			s.root.Generated.Graphs, err = contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, graphs)
			if err != nil {
				t.Fatal(err)
			}
			s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.packGeneratedAccess(slices.Clone(access), contract.Hash([]byte("backlog access pages")), &Candidate{}); err != nil {
				t.Fatal(err)
			}
			groups, err := generatedReservationGroups(rows, locations, bundles)
			if err != nil {
				t.Fatal(err)
			}
			packed, err := format.PackRequiredSupportRows(s.root.Domain, groups, 2)
			if err != nil {
				t.Fatal(err)
			}
			var pages []format.RequiredSupportPage
			s.support, s.root.RequiredSupport = nil, nil
			for index, rows := range packed {
				object, err := contract.GeneratorInitialPageID(contract.Hash([]byte("backlog support pages")), contract.RequiredSupportKind, uint16(index))
				if err != nil {
					t.Fatal(err)
				}
				page := format.RequiredSupportPage{Domain: s.root.Domain, Object: object, Index: uint16(index), Records: rows}
				body, err := format.EncodeRequiredSupportPage(page)
				if err != nil {
					t.Fatal(err)
				}
				view, err := format.InspectRequiredSupportPage(body)
				if err != nil {
					t.Fatal(err)
				}
				pages, s.support = append(pages, page), append(s.support, view)
			}
			s.root.Generated.Fragments, err = generatedFragmentDirectory(pages)
			if err != nil {
				t.Fatal(err)
			}
			generatedRefreshSupport(t, s)
			s.recountChildren()
			if !s.indexSelectedMaterials() {
				t.Fatal("invalid authenticated backlog shape")
			}
			if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
				t.Fatal("invalid authenticated backlog shape")
			}
			// The selected predecessor has one graph fragment for each old
			// operation. Two fragments fit a page. Its ten other physical
			// children stay fixed across these four cases.
			wantChildren := uint32(10 + (i+1)/2)
			if s.root.ChildCount != wantChildren {
				t.Fatal("wrong encoded predecessor child count", s.root.ChildCount, wantChildren)
			}
			input := generatedPlanInputFixture(t, s)
			plan, err := s.generatedPlanRequest(t.Context(), input)
			// Each pending hazard contributes one old create owner. The new
			// request reserves three entered attempts. A 64 KiB owner group
			// fits 31 times per support page. The independent graph fragments
			// use two rows per page in addition to four reserved graph pages.
			// Sealed result envelopes fit 22 per page. The other fourteen
			// groups reserve 18 pages, including five auxiliary pages.
			wantCreatePages := uint32((i + 3 + 30) / 31)
			wantResultPages := uint32((i + 3 + 21) / 22)
			wantGraphPages := 4 + uint32((i+1)/2)
			wantProjected := uint32(18) + wantCreatePages + wantResultPages + wantGraphPages
			if i >= 395 {
				if wantProjected+1 <= ordinaryChildPageLimit {
					t.Fatal("incorrect fixture crossing", wantProjected)
				}
				if err != contract.ErrRecordCapacity || plan != nil || s.prepared {
					t.Fatal("ordinary continuation above 252 children reached private preparation", err)
				}
				return
			}
			if err != nil {
				t.Fatal("ordinary continuation within 252 children refused", err)
			}
			reservedPages := uint32(0)
			for _, group := range plan.capacity.Groups {
				reservedPages += group.MaxPages
			}
			selected, err := s.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
			if err != nil {
				t.Fatal(err)
			}
			shape, err := s.generatedAdmissionShape(t.Context(), input.graph, declaration, selected)
			if err != nil {
				t.Fatal(err)
			}
			shape.DeclarationBytes = uint64(len(input.declaration))
			shape.RegistryBytes = uint64(len(input.registryImage))
			shards, err := s.generatedAdministrativeShardReserve(shape)
			if err != nil || reservedPages != wantProjected || shards != 1 || reservedPages+shards > ordinaryChildPageLimit || s.root.ChildCount >= ordinaryChildPageLimit || s.prepared {
				t.Fatal("did not reserve projected continuation and index before private work", reservedPages, shards, s.root.ChildCount, err)
			}
			if i == 394 {
				if reservedPages+shards != ordinaryChildPageLimit {
					t.Fatal("dense boundary", reservedPages, shards)
				}
				return
			}
			// Two sparse current pages require one more page than the new
			// one-entry image. This reaches the exact ordinary child limit.
			for index := range 2 {
				entry := contract.ValueEntry{Name: fmt.Sprintf("plain-%d", index),
					Incarnation:    contract.Hash([]byte(fmt.Sprintf("backlog plain incarnation %d", index))),
					ValueState:     contract.Hash([]byte(fmt.Sprintf("backlog plain state %d", index))),
					OriginSnapshot: s.root.Snapshot, OriginTransition: s.root.Transition, ValueSource: contract.Supplied,
					ConfidentialityClass: contract.Plain, Recipients: []contract.ID{s.admission.recipient}, ValueBytes: []byte("v"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("v"))), RetainedLength: uint32(len([]byte("v")))}
				page := &format.ValueEntryPage{Domain: s.root.Domain, Object: contract.Hash([]byte(fmt.Sprintf("backlog plain page %d", index))), Index: uint16(index)}
				page.Slots[0] = &entry
				body, err := format.EncodeValueEntryPage(*page)
				if err != nil {
					t.Fatal(err)
				}
				ref, err := format.Reference(format.ValueEntryPageKind, page.Domain, page.Object, page.Index, body)
				if err != nil {
					t.Fatal(err)
				}
				s.pages[index], s.root.ValueEntryPages[index] = page, &ref
				s.root.Names = append(s.root.Names, format.NameEntry{Name: entry.Name, Slot: uint16(index * format.PageSlots)})
			}
			s.root.ValueEntryCount, s.root.MembershipCount, s.root.RawBytes = 2, 2, 2
			s.recountChildren()
			if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
				t.Fatal("exact-limit ordinary page predecessor")
			}
			atLimit, err := s.generatedPlanRequest(t.Context(), generatedPlanInputFixture(t, s))
			if err != nil || atLimit == nil {
				t.Fatal("exact-limit continuation refused", err)
			}
			var exactPages uint32
			for _, group := range atLimit.capacity.Groups {
				exactPages += group.MaxPages
			}
			if exactPages != wantProjected+1 || exactPages+shards != ordinaryChildPageLimit || s.prepared {
				t.Fatal("configuration and sparse ordinary pages lost the exact 252-child boundary", exactPages, shards)
			}
		})
	}
}

// full_only: false
func TestGeneratedPlanAdmissionChargesWholeRetainedBlob(t *testing.T) {
	for _, offset := range []uint64{0, contract.GeneratedFragmentMaxPayload - 1} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			s := generatedEmptyPredecessor(t)
			old, _, _ := generatedDetachedRetirementState(t, "absent", 0)
			selected, err := old.selectedGeneratedWork(stdcontext.Background())
			if err != nil {
				t.Fatal(err)
			}
			var locations []contract.GeneratorSliceLocation
			var blobs []generatedContentFixtureBlob
			for key, location := range selected.content.locations {
				intent, err := selected.readSelectedSlice(t.Context(), key.kind, key.id, location.Length)
				if err != nil || key.kind != contract.GeneratorContentIntent {
					t.Fatal("unexpected retained content", err)
				}
				body := bytes.Repeat([]byte{' '}, contract.GeneratedFragmentMaxPayload+256)
				copy(body[offset:], intent)
				location.BlobID, location.Offset = contract.Hash(body), offset
				locations = append(locations, location)
				blobs = append(blobs, generatedContentFixtureBlob{location.BlobID, body})
			}
			if len(blobs) != 1 {
				t.Fatal("expected one retained intent")
			}
			content := generatedContentStateAtSnapshot(t, s.root.Snapshot, blobs, locations)
			s.support, s.root.Generated = content.support, old.root.Generated
			s.root.Generated.Fragments, s.root.Generated.Slices = content.root.Generated.Fragments, content.root.Generated.Slices
			for _, row := range old.supportRecords() {
				_, carrier, err := snapshotSliceRecord(row, old.root.Domain, old.root.Snapshot)
				if err != nil {
					t.Fatal(err)
				}
				if row.Kind != contract.GeneratedFragmentSupportKind && row.Kind != contract.OutputConfigurationSliceSupportKind && !carrier {
					s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
				}
			}
			generatedRepackSupportAtLocations(t, s, s.supportRecords(), selected.bundles, locations)
			s.recountChildren()
			if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
				t.Fatal("invalid shared-blob predecessor")
			}
			input := generatedPlanInputForOperation(t, s, generatedVectorID(98))
			plan, err := s.generatedPlanRequest(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			group := plan.capacity.Groups[contract.GeneratorCapacityIntents]
			// Two old fragments plus one new declaration fragment, at two
			// per page. Each fragment has 123 bytes of support-row framing.
			if group.MaxCount != 3 || group.MaxPages != 2 || group.MaxFramedBytes != uint64(len(blobs[0].body)+len(input.declaration)+3*123) {
				t.Fatal("charged the logical slice instead of its complete stored blob", group)
			}
		})
	}
}

// full_only: false
func TestGeneratedAdmissionCountsPlainBase64Content(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	// Independent padded encoding of 65,536 decoded 'd' bytes.
	source := contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
		Name: "plain", InputEncoding: contract.InputEncodingBase64, OutputEncoding: contract.OutputEncodingRaw,
		Recipients: []contract.ID{s.admission.recipient}, Payload: []byte(strings.Repeat("ZGRk", 21845) + "ZA==")}
	input := generatedPlanInputFixture(t, s, source)
	plan, err := s.generatedPlanRequest(t.Context(), input)
	if err != nil || plan == nil {
		t.Fatal("valid logical plain bound charged retained bytes", err)
	}
}

// full_only: false
func TestGeneratedNoContentPlanRejectsChangedPlainInputClass(t *testing.T) {
	for _, oldInput := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
		t.Run(fmt.Sprint(oldInput), func(t *testing.T) {
			s, _ := observationTestSession(t)
			current := observationPlainEntry("plain", generatedVectorID(201), []contract.ID{s.admission.recipient})
			current.InputEncoding, current.ValueBytes, current.ContentLength, current.RetainedLength = oldInput, []byte("QUJD"), 4, 4
			newInput := contract.InputEncodingBase64
			if oldInput == contract.InputEncodingBase64 {
				current.ContentLength, newInput = 3, contract.InputEncodingRaw
			}
			observationInstallEntries(s, []contract.ValueEntry{current})
			generatedSealSelectedFixture(t, s)
			source := contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
				Name: current.Name, InputEncoding: newInput, OutputEncoding: current.OutputEncoding, Recipients: current.Recipients, Payload: bytes.Clone(current.ValueBytes)}
			input := generatedPlanInputFixture(t, s, source)
			at := slices.IndexFunc(input.graph.ValueEntryPlans, func(p contract.GeneratorValueEntryPlan) bool { return p.Name == current.Name })
			if at < 0 {
				t.Fatal("plain sibling missing from graph")
			}
			input.graph.ValueEntryPlans[at].ChangeMask &^= contract.GeneratorValueChangeContent
			var err error
			input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
			if err != nil {
				t.Fatal("closed no-content graph could not be framed", err)
			}
			if plan, err := s.generatedPlanRequest(t.Context(), input); err == nil || plan != nil {
				t.Fatal("changed input class admitted as unchanged content")
			}
		})
	}
}
