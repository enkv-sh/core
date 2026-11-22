package core

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestAdministrativeReleaseEndsOnlyItsConsumedGraph(t *testing.T) {
	for _, order := range []string{"release-first", "duty-first"} {
		t.Run(order, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
			f.env.GeneratedProcess = process
			current := f.selected
			apply := func(label string, entries []ApplyEntryInput) {
				t.Helper()
				e := installedGeneratedTestEngine(t, ctx, f, current, entries, currentApplyRecipients(current.registry()), installedGeneratedRetirementCallbacks(t, f, process))
				result := e.Apply(ctx, testID(order+" "+label), entries)
				e.Close()
				if result.Result.Outcome != ObservedCurrent {
					t.Fatal("ordinary apply", label, result.Result)
				}
				current = f.open(t, ctx)
			}
			input := installedGeneratedRetirementEntries(process, current.admission.recipient, 0, "keep me")
			apply("create", input)
			input[0].Generated.Epoch, input[0].Generated.RetirementMode = 1, contract.GeneratedRetirementAuto
			apply("rotate", input)
			newValue := *current.valueEntry(entrySlot(t, current, "generated"))
			duty, err := contract.GeneratorDutyID(current.root.Domain, newValue.Generated.OriginOperationID, newValue.Generated.OriginAttemptID, contract.GeneratedDutyRetirement)
			if err != nil {
				t.Fatal(err)
			}
			apply("remove rotated value", input[1:])
			g := mustSelectedGeneratedWork(t, current)
			var release, graph contract.ID
			var mappingAttempt contract.GeneratedAttemptRecord
			for _, mapping := range g.releases {
				if mapping.attempt.OperationID == newValue.Generated.OriginOperationID {
					if !release.IsZero() || mapping.release.State != contract.GeneratedReleasePending {
						t.Fatal("unexpected release", mapping.release.State)
					}
					release, mappingAttempt = mapping.release.InboxID, mapping.attempt
				}
			}
			for _, bundle := range g.bundles {
				if bundle.Header.OperationID == newValue.Generated.OriginOperationID {
					graph = bundle.UsePlan.PlanGraphID
				}
			}
			if release.IsZero() || graph.IsZero() {
				t.Fatal("rotation did not retain its Delete inbox and graph", len(g.releases), len(g.bundles))
			}
			original, err := g.readSelectedSlice(ctx, contract.GeneratorContentGraph, graph, contract.GeneratorGraphMaxLength)
			if err != nil {
				t.Fatal(err)
			}
			seenDuty, err := contract.InspectGeneratedDutyRecord(g.records[generatedRecordKey{contract.GeneratedDutySupportKind, duty}].Body)
			if err != nil || seenDuty.Status != contract.GeneratedEffectNotStarted {
				t.Fatal("new retirement must be unstarted", err)
			}
			verify := func(live bool) {
				t.Helper()
				location, mandatory, owners, found := sharedIntentContentCarrier(t, current, contract.GeneratorContentGraph, graph)
				if live != found || live && (mandatory || !slices.Equal(owners, []contract.ID{release})) {
					t.Fatal("graph has incorrect logical owners", live, found, mandatory, owners)
				}
				work := mustSelectedGeneratedWork(t, current)
				var ids []contract.ID
				if live {
					ids = []contract.ID{graph}
					verifyReleaseGraphCharges(t, current, release, mappingAttempt, location)
					body, err := work.readSelectedSlice(ctx, contract.GeneratorContentGraph, location.ContentID, contract.GeneratorGraphMaxLength)
					if err != nil || !bytes.Equal(body, original) {
						t.Fatal("retained graph bytes changed", err)
					}
				}
				want, err := contract.GeneratorIndexDescriptor(contract.GeneratorGraphSet, ids)
				if err != nil || current.root.Generated.Graphs != want || len(work.bundles) != len(ids) {
					t.Fatal("complete graph set differs", err, len(work.bundles), len(ids))
				}
				creates, deletes := effects()
				if creates != 2 || len(deletes) != 1 {
					t.Fatal("administrative work changed generator call count", creates, len(deletes))
				}
			}
			verify(true)
			ends := []contract.ID{release, duty}
			if order == "duty-first" {
				slices.Reverse(ends)
			}
			live := true
			for step, id := range ends {
				administrative, result := openAdministrative(ctx, OpenContext{admission: &current.admission}, f.env.Store)
				if administrative == nil || result.Outcome != ObservedCurrent {
					t.Fatal("administrative open", result)
				}
				before := current.head.Core.Revision
				endSharedIntentWork(t, administrative, id, f.env.Trust)
				current = f.open(t, ctx)
				if id == release {
					live = false
				}
				verify(live)
				t.Logf("end=%x predecessor=%x successor=%x graph_retained=%t", id, before, current.head.Core.Revision, live)
				input[1].InputBytes = []byte([]string{"after first exit", "after second exit"}[step])
				apply(string(input[1].InputBytes), input[1:])
				verify(live)
			}
		})
	}
}

// A single acknowledged Delete release retains its mapping, that Attempt's
// own vectors, its exact support and the physical fragments of its one graph.
func verifyReleaseGraphCharges(t testing.TB, s *StateSession, release contract.ID, attempt contract.GeneratedAttemptRecord, graph contract.GeneratorSliceLocation) {
	t.Helper()
	var chargedPages uint16
	var chargedBytes uint64
	for _, page := range s.adminIndex.Pages {
		body, r := s.readObject(t.Context(), page.Ref)
		if r.Outcome != 0 {
			t.Fatal("read physical support page", r)
		}
		physical, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		charged := false
		for _, span := range page.Spans {
			for _, row := range physical.Records[int(span.First) : int(span.First)+int(span.Count)] {
				var expected bool
				switch row.Kind {
				case contract.PendingInboxReleaseSupportKind:
					expected = row.RecordID == release
				case contract.GeneratedAttemptSupportKind:
					expected = row.RecordID == attempt.AttemptID
				case contract.GeneratedFragmentSupportKind:
					f, err := contract.InspectGeneratedFragment(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					expected = f.BlobID == graph.BlobID
				case contract.GeneratorVectorSupportKind:
					v, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					switch v.OwnerKind {
					case contract.GeneratedAttemptSupportKind:
						expected = v.OwnerID == attempt.AttemptID
					case contract.GeneratedParentSupportKind:
						expected = v.OwnerID == attempt.OperationID && v.VectorKind == contract.GeneratorVectorSupport && v.Vector == attempt.Support
					case contract.GeneratorSnapshotOwner:
						if v.VectorKind == contract.GeneratorVectorSlices {
							location, err := contract.InspectGeneratorSliceLocation(v.Row)
							if err != nil {
								t.Fatal(err)
							}
							expected = location == graph
						}
					}
				}
				actual := slices.ContainsFunc(span.GroupIndexes, func(i uint16) bool { return s.adminIndex.Groups[i].GroupID == release })
				if expected != actual {
					t.Fatalf("release row kind %d id %x expected %v got %v", row.Kind, row.RecordID, expected, actual)
				}
				if expected {
					charged = true
					chargedBytes += uint64(contract.SupportRecordOverhead + len(row.Body))
				}
			}
		}
		if charged {
			chargedPages++
		}
	}
	i := slices.IndexFunc(s.adminIndex.Groups, func(g format.AdministrativeGroup) bool { return g.GroupID == release })
	if i < 0 || chargedPages == 0 || s.adminIndex.Groups[i].ChargedPages != chargedPages || s.adminIndex.Groups[i].ChargedBytes != chargedBytes {
		t.Fatal("release capacity differs from physical row sizes", chargedPages, chargedBytes)
	}
}
