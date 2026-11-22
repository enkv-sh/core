package core

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestAdministrativeRetirementExitKeepsOnlyConsumedVectors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		shared bool
		order  [2]int
	}{{"distinct-first", false, [2]int{0, 1}}, {"distinct-second", false, [2]int{1, 0}}, {"shared", true, [2]int{0, 1}}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			env, keys := genesisEnvironment(t, contract.GCP, false)
			env.Context = ctx
			defer keys.RetireGenerated()
			defer keys.RetireApply()
			current := newEnvironmentFixture(t, ctx, env, nil, false).session
			names := []string{"first", "second"}
			op := fixtureID(env.Domain, "two managed generations")
			in := generatedWriterPlanInput(t, current, op, names, func(name string) []byte { return []byte("generate " + name) }, 0, nil)
			current = selectGeneratedWriterBatch(t, env, current, in, "two managed generations", custody.StandardValue)
			current = generatedLifecycleReopen(t, ctx, current, env.Store)
			apply := func(entries []ApplyEntryInput, registry ...contract.GeneratorImplementation) {
				t.Helper()
				parent := admitSuppliedComparison(t, current, keys, entries, registry...)
				comparison, result := current.Compare(ctx, entries, parent)
				if comparison == nil {
					t.Fatal("ordinary comparison", result)
				}
				candidate, result := current.Prepare(ctx, comparison, admit(t, current, comparison), env.Trust)
				if candidate == nil {
					t.Fatal("ordinary preparation", result)
				}
				selected, result := current.selectCandidate(ctx, candidate)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("ordinary selection", result)
				}
				keys.RetireApply()
				current = generatedLifecycleReopen(t, ctx, selected, env.Store)
			}
			var duties [2]contract.ID
			var desc [2]contract.GeneratorDescriptor
			expected := map[contract.ID]map[contract.ID][]byte{}
			for i, name := range names {
				original := current.valueEntry(entrySlot(t, current, name)).Generated
				if original.OriginOperationID != op {
					t.Fatal("fixture did not share one original operation")
				}
				var err error
				duties[i], err = contract.GeneratorDutyID(env.Domain, op, original.OriginAttemptID, contract.GeneratedDutyRetirement)
				if err != nil {
					t.Fatal(err)
				}
				identity := env.Domain
				if i == 1 && !tc.shared {
					identity = fixtureID(env.Domain, "independent compatible retirement build")
				}
				implementation := staticGeneratedHandoffImplementation(t, identity, defaultGeneratedFixtureProfile())
				inputs := slices.DeleteFunc(current.currentEntryInputs(), func(v ApplyEntryInput) bool { return v.Name == name })
				apply(inputs, implementation)
				work := mustSelectedGeneratedWork(t, current)
				duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{contract.GeneratedDutySupportKind, duties[i]}].Body)
				if err != nil || duty.Support.Count == 0 || duty.OriginalOperationID != op {
					t.Fatal("ordinary removal did not retain its retirement support", err)
				}
				desc[i] = duty.Support
				expected[duties[i]] = make(map[contract.ID][]byte)
				for k, row := range work.records {
					if k.kind != contract.GeneratorVectorSupportKind {
						continue
					}
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if carrier.OwnerKind == contract.GeneratedParentSupportKind && carrier.OwnerID == op && carrier.VectorKind == contract.GeneratorVectorSupport && carrier.Vector == duty.Support {
						expected[duties[i]][row.RecordID] = bytes.Clone(row.Body)
					}
				}
				if len(expected[duties[i]]) != int(duty.Support.Count) {
					t.Fatal("accepted vector is incomplete")
				}
			}
			if (desc[0] == desc[1]) != tc.shared {
				t.Fatal("unexpected descriptor equality", tc.shared)
			}
			check := func() {
				t.Helper()
				seen := make(map[contract.ID]bool)
				for n, page := range current.support {
					// Cold Open returns only selected rows. Span.First still indexes the physical page.
					var spans []format.AdministrativeSpan
					for _, span := range current.adminIndex.Pages[n].Spans {
						for range span.Count {
							spans = append(spans, span)
						}
					}
					if len(spans) != len(page.Records) {
						t.Fatal("selected row count differs from span coverage")
					}
					for i, row := range page.Records {
						if row.Kind != contract.GeneratorVectorSupportKind {
							continue
						}
						carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						if carrier.OwnerKind != contract.GeneratedParentSupportKind || carrier.OwnerID != op || carrier.VectorKind != contract.GeneratorVectorSupport {
							continue
						}
						seen[row.RecordID] = true
						span := spans[i]
						if span.Mandatory {
							t.Fatal("wrong optional retirement disposition")
						}
						var want []contract.ID
						for id, rows := range expected {
							if body, present := rows[row.RecordID]; present {
								if !bytes.Equal(body, row.Body) {
									t.Fatal("retirement support changed")
								}
								want = append(want, id)
							}
						}
						if len(want) == 0 || len(want) != len(span.GroupIndexes) {
							t.Fatal("unrelated retirement owns a support vector", len(want), len(span.GroupIndexes))
						}
						for _, idx := range span.GroupIndexes {
							if !slices.Contains(want, current.adminIndex.Groups[idx].GroupID) {
								t.Fatal("wrong retirement group")
							}
						}
					}
				}
				for _, rows := range expected {
					for id := range rows {
						if !seen[id] {
							t.Fatal("live support vector disappeared")
						}
					}
				}
			}
			check()
			for step, index := range tc.order {
				before := current.head.Core.Revision
				administrative, r := openAdministrative(ctx, OpenContext{admission: &current.admission}, env.Store)
				if administrative == nil || r.Outcome != ObservedCurrent {
					t.Fatal("administrative open", r)
				}
				ended := endSharedIntentWork(t, administrative, duties[index], env.Trust)
				current = generatedLifecycleReopen(t, ctx, ended, env.Store)
				delete(expected, duties[index])
				check()
				t.Logf("end=%x predecessor=%x successor=%x live_duties=%d", duties[index], before, current.head.Core.Revision, len(expected))
				ordinary := ApplyEntryInput{Name: []string{"third", "fourth"}[step], Recipients: []contract.ID{current.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: []byte("after exit")}
				apply(append(current.currentEntryInputs(), ordinary))
				check()
			}
		})
	}
}
