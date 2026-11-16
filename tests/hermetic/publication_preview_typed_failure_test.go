package core

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationPreviewLateReadKeepsTypedFailure(t *testing.T) {
	ctx, cancel, env, selected, public, validator, sealed := previewTestSuppliedFixture(t)
	defer cancel()
	var key string
	for i, page := range selected.support {
		if slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
			return row.Kind == contract.PublicationCoordinateSupportKind
		}) {
			key = readerFixtureKey(t, selected.admission.store.Prefix, selected.root.RequiredSupport[i])
			break
		}
	}
	if key == "" {
		t.Fatal("selected coordinate page missing")
	}
	observation := contract.ComparisonObservation{DomainID: env.Domain, HeadRevisionID: selected.head.Core.Revision, SnapshotID: selected.root.Snapshot}
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	creates, cas, signs := store.creates, store.cas, trust.signs
	publicCalls, privateCalls := env.Custody.Calls()
	checkNoEffects := func(t *testing.T) {
		t.Helper()
		if p, k := env.Custody.Calls(); p != publicCalls || k != privateCalls || store.creates != creates || store.cas != cas || trust.signs != signs {
			t.Fatal("publication preview acquired private or mutation authority")
		}
	}
	var ordinaryReads, previewReads int
	t.Run("healthy", func(t *testing.T) {
		for _, publish := range []bool{false, true} {
			reader, _, source := readerEngineFixture(t, env, selected)
			reader.validator = validator
			gate := &comparisonReadGate{PublicSelectedReader: source, key: key}
			reader.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
				return gate, Result{}
			}
			got := reader.Compare(ctx, fixtureID(env.Domain, "typed preview healthy"), public, contract.ComparisonOptions{Publish: publish})
			reader.Close()
			want := Result{Outcome: ObservedCurrent, ObservedRevision: observation.HeadRevisionID, ObservedSnapshotID: observation.SnapshotID, Evidence: AuthenticatedClosure}
			if got.Result != want || got.StateResult != contract.ReaderSuccess || got.Verdict != contract.ComparisonMatch || got.Observation == nil || *got.Observation != observation || !got.DiagnosticsComplete || len(got.Diagnostics) != 0 || source.closes != 1 || reader.activeDone != nil {
				t.Fatalf("healthy comparison differs: result=%+v state=%s verdict=%s reads=%d", got.Result, got.StateResult, got.Verdict, gate.reads)
			}
			if publish {
				previewReads = gate.reads
				if !got.PublicationRequested || got.Publication == nil || !got.Publication.Complete || got.Publication.ReasonCode != 0 || len(got.Publication.Entries) != 1 {
					t.Fatal("healthy publication preview incomplete")
				}
			} else {
				ordinaryReads = gate.reads
			}
			checkNoEffects(t)
		}
		if ordinaryReads == 0 || previewReads <= ordinaryReads {
			t.Fatal("fault boundary is not a publication-specific reread", ordinaryReads, previewReads)
		}
	})
	if ordinaryReads == 0 || previewReads <= ordinaryReads {
		t.Fatal("healthy reread control did not complete")
	}
	for _, caller := range []string{"public", "public-mismatch", "private"} {
		for _, damage := range []string{"missing", "unavailable", "unavailable-cancelled"} {
			if caller == "private" && damage == "unavailable-cancelled" {
				continue
			}
			t.Run(caller+"/"+damage, func(t *testing.T) {
				readCtx, stop := context.WithCancel(ctx)
				defer stop()
				reads := 0
				store.readHook = func(readKey string, read contract.ReadResult) contract.ReadResult {
					if readKey != key {
						return read
					}
					reads++
					if reads != previewReads {
						return read
					}
					if damage == "missing" {
						return contract.ReadResult{Status: contract.ReadMissing}
					}
					if damage == "unavailable-cancelled" {
						stop()
					}
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				}
				defer func() { store.readHook = nil }()
				// These exact tuples follow the selected-object read classification:
				// missing is not a Store denial, and unavailable retains its Store cause.
				want := Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}
				wantDiagnostic := contract.ReasonSelectedObjectUnavailable
				wantState := contract.ReaderUnavailable
				wantPreviewReason := uint8(MissingSelectedObject)
				if damage != "missing" {
					want = Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess}
					wantDiagnostic, wantPreviewReason = contract.ReasonEvidenceUnavailable, uint8(ReadUnavailable)
				}
				if damage == "unavailable-cancelled" {
					want = Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}
					wantDiagnostic, wantState, wantPreviewReason = contract.ReasonCancelled, contract.ReaderRefused, uint8(AdmissionInvalid)
				}
				var result Result
				var state contract.ReaderStateResult
				var payload contract.ComparisonPayload
				if caller == "public" || caller == "public-mismatch" {
					reader, _, source := readerEngineFixture(t, env, selected)
					reader.validator = validator
					desired := ownPublicConfiguration(public)
					if caller == "public-mismatch" {
						desired.Recipients.Value[0].DisplayName.Value += " changed"
					}
					got := reader.Compare(readCtx, fixtureID(env.Domain, "typed preview "+damage), desired, contract.ComparisonOptions{Publish: true})
					reader.Close()
					result, state, payload = got.Result, got.StateResult, got.ComparisonPayload
					if source.closes != 1 || reader.activeDone != nil {
						t.Fatal("public preview retained read ownership")
					}
				} else {
					inputs := []contract.PlanningInput{{Name: "secret", Form: contract.PlanningSealed, SealedInput: sealed.InputBytes}}
					factories := 0
					planner, _, source := installedPlanningFixture(t, env, selected, public, inputs, func(context.Context, contract.PlanningAdmission) (PlanningCustody, error) {
						factories++
						return nil, contract.ErrRecord
					})
					planner.reader.validator = validator
					got := planner.Plan(readCtx, fixtureID(env.Domain, "typed private preview "+damage), public, inputs, contract.PlanningOptions{Purpose: contract.PlanningEquality, Publish: true})
					planner.Close()
					result, state, payload = got.Result, got.StateResult, got.ComparisonPayload
					if factories != 0 || got.PrivateComplete || !reflect.DeepEqual(got.PrivateEntries, []contract.PlanningRelation{{Name: "secret", Form: contract.PlanningSealed, Relation: contract.PlanningUnchecked}}) || got.CompletedRecords != 0 || source.closes != 1 || planner.activeDone != nil {
						t.Fatal("private preview crossed its public evidence barrier")
					}
				}
				wantDiagnostics := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: wantDiagnostic}}
				if caller == "public-mismatch" && damage != "unavailable-cancelled" {
					wantDiagnostics = append(wantDiagnostics, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: public.Recipients.Value[0].RecipientID}, Path: []contract.DiagnosticField{contract.FieldDisplayName}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers})
				}
				if result != want || state != wantState || payload.Verdict != contract.ComparisonUnable || payload.Observation == nil || *payload.Observation != observation || !payload.DiagnosticsComplete || !reflect.DeepEqual(payload.Diagnostics, wantDiagnostics) || !payload.PublicationRequested || payload.Publication == nil || payload.Publication.Complete || payload.Publication.ReasonCode != wantPreviewReason || len(payload.Publication.Entries) != 0 || reads != previewReads {
					t.Fatalf("late preview lost typed failure: result=%+v want=%+v state=%s verdict=%s reads=%d want_reads=%d", result, want, state, payload.Verdict, reads, previewReads)
				}
				checkNoEffects(t)
			})
		}
	}
}
