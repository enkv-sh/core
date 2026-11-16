package crypto

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func generatedTwoSuppliedFinalFixture(t *testing.T) generatedRuntimeFixture {
	t.Helper()
	// This source fixture has no result/entry pair, so Final admission selects
	// the nonselecting path. The batch tests below set only its final-progress
	// fields after Compare; Core's mixed Final tests cover real selecting admission.
	f := generatedSealedPlanFixture(t, true)
	entry := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: "beta",
		Recipients: slices.Clone(f.base.q.Intent[1].Recipients), Payload: f.base.q.SealedInputs[1].EnvelopeBytes}
	generatedAddDeclarationSource(t, &f, entry, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 2, Name: entry.Name,
		ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, EntryIncarnationID: consumerID("beta incarnation"), ChangeMask: 1})
	f.reservation.Accepted[contract.Hash(entry.Payload)] = f.base.accepted[contract.Hash(entry.Payload)]
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation.Plan.LiveSourceUses = slices.Clone(graph.SourceUses)
	return generatedSealedFinalFromPlan(t, f)
}

func generatedSuppliedBatchRequest(t *testing.T, a *generatedAdmission, rows []contract.IdentityRow, index uint32, final uint8) []byte {
	t.Helper()
	phase := a.purpose.final.phaseID
	snapshot, err := contract.GeneratorPhaseSnapshotID(phase)
	if err != nil {
		t.Fatal(err)
	}
	transition, err := contract.GeneratorPhaseTransitionID(phase)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := contract.GeneratorPhaseRevisionID(phase)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := contract.EncodeIdentityPlan(contract.IdentityPlan{Operation: a.graph.Header.OperationID,
		Snapshot: snapshot, Transition: transition, Revision: revision, Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := contract.InspectGeneratorDeclaration(a.purpose.final.plan.declaration)
	if err != nil {
		t.Fatal(err)
	}
	var sources []contract.CryptoSealedInput
	for _, row := range rows {
		plan := slices.IndexFunc(a.graph.ValueEntryPlans, func(entryPlan contract.GeneratorValueEntryPlan) bool { return entryPlan.Name == row.Name })
		if plan < 0 {
			continue
		}
		entry, _, err := declaration.Entry(plan)
		if err != nil {
			t.Fatal(err)
		}
		if entry.Kind == contract.GeneratorDeclarationSealed {
			sources = append(sources, contract.CryptoSealedInput{Name: row.Name, EnvelopeBytes: entry.Payload})
		}
	}
	body, err := contract.EncodeCryptoGeneratedSuppliedRequest(contract.CryptoGeneratedSuppliedRequest{OperationRef: a.operation,
		Context: a.request.Context, PhaseID: phase, BatchIndex: index, Final: final, IdentityPlan: identity, SealedInputs: sources})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func generatedSuppliedFixtureRows(t *testing.T, a *generatedAdmission) []contract.IdentityRow {
	t.Helper()
	phase := a.purpose.final.phaseID
	snapshot, err := contract.GeneratorPhaseSnapshotID(phase)
	if err != nil {
		t.Fatal(err)
	}
	transition, err := contract.GeneratorPhaseTransitionID(phase)
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]contract.IdentityRow, 0, 2)
	for _, entryPlan := range a.graph.ValueEntryPlans {
		if entryPlan.ValueSource != contract.Supplied || entryPlan.ChangeMask&1 == 0 {
			continue
		}
		value, err := contract.GeneratorPhaseValueID(phase, entryPlan.Slot)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.IdentityRow{Name: entryPlan.Name, Slot: entryPlan.Slot, Incarnation: entryPlan.EntryIncarnationID,
			ValueState: value, OriginSnapshot: snapshot, OriginTransition: transition})
	}
	if len(rows) != 2 {
		t.Fatal("fixture needs two changed supplied rows", len(rows))
	}
	return rows
}

// full_only: false
func TestGeneratedSuppliedBatchesRequireExactGlobalOrderAndFinality(t *testing.T) {
	f := generatedTwoSuppliedFinalFixture(t)
	for _, tc := range []struct {
		name          string
		firstRow      int
		firstIndex    uint32
		firstFinal    uint8
		secondRow     int
		secondIndex   uint32
		secondFinal   uint8
		secondPresent bool
		valid         bool
	}{
		{name: "correct", firstRow: 0, firstFinal: 0, secondRow: 1, secondIndex: 1, secondFinal: 1, secondPresent: true, valid: true},
		{name: "wrong first index", firstRow: 0, firstIndex: 1},
		{name: "reordered first row", firstRow: 1},
		{name: "early final", firstRow: 0, firstFinal: 1},
		{name: "duplicate row", firstRow: 0, secondRow: 0, secondIndex: 1, secondFinal: 1, secondPresent: true},
		{name: "repeated index", firstRow: 0, secondRow: 1, secondIndex: 0, secondFinal: 1, secondPresent: true},
		{name: "missing final", firstRow: 0, secondRow: 1, secondIndex: 1, secondFinal: 0, secondPresent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.finalRuntime(t)
			generatedSourceCompare(t, r, f)
			a := r.generated
			a.purpose.final.nonselecting = false
			a.purpose.final.suppliedCount = 2
			a.purpose.final.suppliedFinal = false
			rows := generatedSuppliedFixtureRows(t, a)
			first := generatedSuppliedBatchRequest(t, a, rows[tc.firstRow:tc.firstRow+1], tc.firstIndex, tc.firstFinal)
			out := applyCall(r, context.Background(), contract.CryptoPrepare, first)
			if tc.name != "correct" && !tc.secondPresent {
				if out.ResultCode != contract.CryptoInvalidAdmission || len(out.KeyUseRows) != 0 || len(out.Body) != 0 {
					t.Fatal("invalid first batch reached custody", out.ResultCode)
				}
				return
			}
			if out.ResultCode != contract.CryptoSuccess || a.purpose.final.suppliedNext != 1 || a.purpose.final.suppliedFinal {
				t.Fatal("first nonfinal batch", out.ResultCode)
			}
			second := generatedSuppliedBatchRequest(t, a, rows[tc.secondRow:tc.secondRow+1], tc.secondIndex, tc.secondFinal)
			out = applyCall(r, context.Background(), contract.CryptoPrepare, second)
			if tc.valid {
				if out.ResultCode != contract.CryptoSuccess || a.purpose.final.suppliedNext != 2 || !a.purpose.final.suppliedFinal || len(a.purpose.final.supplied) != 2 {
					t.Fatal("complete supplied batches", out.ResultCode)
				}
				view, err := contract.InspectCryptoGeneratedSuppliedResult(out.Body)
				if err != nil || view.BatchIndex != 1 || view.Final != 1 {
					t.Fatal("second batch response", err)
				}
			} else if out.ResultCode != contract.CryptoInvalidAdmission || len(out.Body) != 0 || len(out.KeyUseRows) != 0 {
				t.Fatal("invalid second batch reached custody", out.ResultCode)
			}
		})
	}
}

// full_only: false
func TestGeneratedSuppliedBatchPreflightAndCancellationLeaveNoFinal(t *testing.T) {
	f := generatedTwoSuppliedFinalFixture(t)
	for _, tc := range []string{"oversized", "members before supplied final", "cancelled", "repeated final"} {
		t.Run(tc, func(t *testing.T) {
			r := f.finalRuntime(t)
			generatedSourceCompare(t, r, f)
			a := r.generated
			a.purpose.final.nonselecting = false
			a.purpose.final.suppliedCount = 2
			a.purpose.final.suppliedFinal = false
			rows := generatedSuppliedFixtureRows(t, a)
			if tc == "oversized" {
				many := make([]contract.IdentityRow, 65)
				for i := range many {
					many[i] = rows[0]
					many[i].Name = fmt.Sprintf("large-%03d", i)
					many[i].Slot = uint16(i + 3)
				}
				body := generatedSuppliedBatchRequest(t, a, many, 0, 1)
				out := applyCall(r, context.Background(), contract.CryptoPrepare, body)
				if out.ResultCode != contract.CryptoCapacityExceeded || len(out.Body) != 0 || len(out.KeyUseRows) != 0 {
					t.Fatal("oversized reply was not preflighted", out.ResultCode)
				}
				return
			}
			first := generatedSuppliedBatchRequest(t, a, rows[:1], 0, 0)
			if out := applyCall(r, context.Background(), contract.CryptoPrepare, first); out.ResultCode != contract.CryptoSuccess {
				t.Fatal("first supplied batch", out.ResultCode)
			}
			if tc == "members before supplied final" {
				body, err := contract.EncodeCryptoGeneratedValueEntriesRequest(contract.CryptoGeneratedValueEntriesRequest{OperationRef: a.operation,
					Context: a.request.Context, PhaseID: a.purpose.final.phaseID, Final: 1})
				if err != nil {
					t.Fatal(err)
				}
				if out := applyCall(r, context.Background(), contract.CryptoPrepare, body); out.ResultCode != contract.CryptoInvalidAdmission {
					t.Fatal("members before supplied final", out.ResultCode)
				}
				return
			}
			second := generatedSuppliedBatchRequest(t, a, rows[1:], 1, 1)
			if tc == "cancelled" {
				// Keep the session observer from clearing the partial state
				// until the cancellation assertions have inspected it.
				a.work.Add(1)
				defer a.work.Done()
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if out := applyCall(r, ctx, contract.CryptoPrepare, second); out.ResultCode != contract.CryptoCancelled ||
					!a.terminal || a.purpose.final.suppliedFinal || a.purpose.final.suppliedNext != 1 {
					t.Fatal("cancelled partial supplied final", out.ResultCode)
				}
				if out := applyCall(r, context.Background(), contract.CryptoPrepare, second); out.ResultCode != contract.CryptoAlreadyUsed {
					t.Fatal("cancelled batch retained preparation right", out.ResultCode)
				}
				return
			}
			if out := applyCall(r, context.Background(), contract.CryptoPrepare, second); out.ResultCode != contract.CryptoSuccess {
				t.Fatal("second supplied batch", out.ResultCode)
			}
			if out := applyCall(r, context.Background(), contract.CryptoPrepare, second); out.ResultCode != contract.CryptoInvalidAdmission || !a.terminal {
				t.Fatal("repeated supplied final", out.ResultCode)
			}
		})
	}
}

// full_only: false
func TestGeneratedRetainedContentRemovalUsesFreshProtection(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, mask := range []uint8{contract.GeneratorValueChangeContent, contract.GeneratorValueChangeContent | contract.GeneratorValueChangeMembership} {
			t.Run(fmt.Sprintf("recovery_%v/mask_%d", recovery, mask), func(t *testing.T) {
				a, _, _, route := generatedRetainedReplayFixture(t, contract.GeneratedHazardSupportKind, recovery, false)
				final := a.purpose.final
				a.operation = consumerID("retained exclusion operation reference")
				before := final.membership[0].Selection
				final.preparedImage.Clear()
				final.preparedImage = nil
				a.graph.ValueEntryPlans[0].ChangeMask = mask
				value, err := contract.GeneratorPhaseValueID(final.phaseID, before.Slot)
				if err != nil {
					t.Fatal(err)
				}
				snapshot, err := contract.GeneratorPhaseSnapshotID(final.phaseID)
				if err != nil {
					t.Fatal(err)
				}
				transition, err := contract.GeneratorPhaseTransitionID(final.phaseID)
				if err != nil {
					t.Fatal(err)
				}
				identity := contract.IdentityRow{Name: before.Entry.Name, Slot: before.Slot, Incarnation: before.Entry.Incarnation,
					ValueState: value, OriginSnapshot: snapshot, OriginTransition: transition}
				body := generatedSuppliedBatchRequest(t, a, []contract.IdentityRow{identity}, 0, 1)
				view, err := contract.InspectCryptoGeneratedSuppliedRequest(body)
				if err != nil {
					t.Fatal(err)
				}
				reply := &contract.CryptoResponse{}
				if code := a.prepareSupplied(t.Context(), route, view, reply); code != contract.CryptoSuccess {
					t.Fatal("retained-content exclusion preparation failed", code)
				}
				result, err := contract.InspectCryptoGeneratedSuppliedResult(reply.Body)
				if err != nil {
					t.Fatal(err)
				}
				rows, err := result.Own()
				if err != nil || len(rows) != 1 {
					t.Fatal("retained-content exclusion returned incomplete rows", err)
				}
				entry, err := contract.DecodeValueEntry(rows[0].EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				checkGeneratedFreshProtection(t, a, route, before, entry, rows[0].AccessRecord, []contract.ID{a.control.AuthorityRecipientID})
				if len(final.supplied) != 1 || final.supplied[0].canonical != before.Entry.ValueState || final.supplied[0].identity.ValueState == before.Entry.ValueState {
					t.Fatal("retained source identity was coupled to fresh output identity")
				}
			})
		}
	}
}
