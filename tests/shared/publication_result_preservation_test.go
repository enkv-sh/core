package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPublicationIntegrityEpisodeAndIndependentUnknownsRemainSeparate(t *testing.T) {
	for _, integrityFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("integrity-first-%t", integrityFirst), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f, input, private := publicationEngineFixture(t)
			private.evidence = contract.PublicationUnproved
			callbacks := private.callbacks()
			plan, state := f.session.planPublication(ctx, input, callbacks)
			if plan == nil || len(plan.targets) != 1 || len(plan.targets[0].actions) != 1 {
				t.Fatal("one-action fixture", state)
			}
			integrity := Result{Outcome: IntegrityFailure, Reason: InvalidProof, RequestedRevision: contract.ID{201}, ObservedRevision: contract.ID{202}, ObservedSnapshotID: contract.ID{203}, Evidence: AuthenticatedClosure}
			uncertain := Result{Outcome: UnresolvedCommit, Reason: WriteUncertain, RequestedRevision: contract.ID{211}, CommitMayHaveOccurred: true, StoreReason: contract.ReasonTransport}
			failures := []Result{uncertain, integrity}
			if integrityFirst {
				failures[0], failures[1] = integrity, uncertain
			}
			low, high := contract.ID{0, 0, 0, 1}, contract.ID{255, 255, 255, 255}
			realTarget, realRow := plan.targets[0], plan.vector.Entries[0]
			if bytes.Compare(low[:], realRow.CoordinateID[:]) >= 0 || bytes.Compare(high[:], realRow.CoordinateID[:]) <= 0 {
				t.Fatal("fixture coordinate ordering")
			}
			failedTarget := publicationTargetPlan{actions: []uint8{contract.PublicationWriteValue}}
			failedRow := func(id contract.ID) contract.PublicationTargetOutcome {
				return contract.PublicationTargetOutcome{CoordinateID: id, Actions: []contract.PublicationOutcome{{Action: contract.PublicationWriteValue, ProjectionCommitment: contract.ID{8}, Disposition: contract.PublicationNotSent, CoreReason: uint16(AdmissionInvalid)}}}
			}
			plan.targets = []publicationTargetPlan{failedTarget, realTarget, failedTarget}
			plan.vector.Entries = []contract.PublicationTargetOutcome{failedRow(low), realRow, failedRow(high)}
			calls := 0
			got := plan.execute(ctx, callbacks, func(ctx context.Context) (*StateSession, contract.Trust, Result) {
				call := calls
				calls++
				if call == 0 {
					return nil, nil, failures[0]
				}
				if call == 3 {
					return nil, nil, failures[1]
				}
				selected, result := Open(ctx, f.admission, f.store)
				return selected, f.trust, result
			})
			if calls != 4 || got.state != integrity || got.summary != contract.PublicationSummaryUnknown || got.output.Entries[1].Actions[0].Disposition != contract.PublicationOutcomeUnknown {
				t.Error("independent episodes were combined or an unknown action was lost", calls, got.state, got.summary)
			}
			if got.output.Entries[0].Actions[0].CoreReason != uint16(failures[0].Reason) || got.output.Entries[2].Actions[0].CoreReason != uint16(failures[1].Reason) {
				t.Error("complete failure reasons were lost")
			}
		})
	}
}

// full_only: false
func TestPublicationAcknowledgementDoesNotEraseAnotherTargetFailure(t *testing.T) {
	for _, failure := range []Result{{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess}, {Outcome: Contention, Reason: StalePrecondition}, {Outcome: AdmissionRefused, Reason: InvalidIntent}} {
		for _, failureFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("outcome-%d/failure-first-%t", failure.Outcome, failureFirst), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				f, input, private := publicationEngineFixture(t)
				callbacks := private.callbacks()
				plan, state := f.session.planPublication(ctx, input, callbacks)
				if plan == nil || len(plan.targets) != 1 || len(plan.targets[0].actions) != 1 {
					t.Fatal("one-action fixture", state)
				}
				realTarget, realRow := plan.targets[0], plan.vector.Entries[0]
				coordinate := contract.ID{255, 255, 255, 255}
				if failureFirst {
					coordinate = contract.ID{0, 0, 0, 1}
				}
				if failureFirst != (bytes.Compare(coordinate[:], realRow.CoordinateID[:]) < 0) {
					t.Fatal("fixture coordinate ordering")
				}
				failedTarget := publicationTargetPlan{actions: []uint8{contract.PublicationWriteValue}}
				failedRow := contract.PublicationTargetOutcome{CoordinateID: coordinate, Actions: []contract.PublicationOutcome{{Action: contract.PublicationWriteValue, ProjectionCommitment: contract.ID{8}, Disposition: contract.PublicationNotSent, CoreReason: uint16(AdmissionInvalid)}}}
				plan.targets, plan.vector.Entries = []publicationTargetPlan{realTarget, failedTarget}, []contract.PublicationTargetOutcome{realRow, failedRow}
				failedCall, acknowledgedIndex := 2, 0
				if failureFirst {
					plan.targets, plan.vector.Entries = []publicationTargetPlan{failedTarget, realTarget}, []contract.PublicationTargetOutcome{failedRow, realRow}
					failedCall, acknowledgedIndex = 0, 1
				}
				calls := 0
				got := plan.execute(ctx, callbacks, func(ctx context.Context) (*StateSession, contract.Trust, Result) {
					call := calls
					calls++
					if call == failedCall {
						return nil, nil, failure
					}
					selected, result := Open(ctx, f.admission, f.store)
					return selected, f.trust, result
				})
				if got.state != failure || got.summary != contract.PublicationSummaryMixedTerminal || calls != 3 {
					t.Errorf("ACK replaced independent failure: %+v summary=%d calls=%d", got.state, got.summary, calls)
				}
				ack := got.output.Entries[acknowledgedIndex].Actions[0]
				refused := got.output.Entries[1-acknowledgedIndex].Actions[0]
				if ack.Disposition != contract.PublicationOutcomeAcknowledged || ack.Evidence.Class != contract.PublicationRequestAcknowledged || refused.Disposition != contract.PublicationNotSent || refused.CoreReason != uint16(failure.Reason) {
					t.Error("aggregate changed exact provider or refusal facts", ack, refused)
				}
				if len(private.owners) != 1 || private.owners[0].sent != 1 || private.owners[0].retired != 1 {
					t.Error("original output owner did not settle exactly once")
				}
			})
		}
	}
}

// full_only: false
func TestPublicationRetainsWarningsFromReservationAndCloseSelectionReadbacks(t *testing.T) {
	for _, phase := range []string{"reservation", "close"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f, input, private := publicationEngineFixture(t)
			callbacks := private.callbacks()
			plan, state := f.session.planPublication(ctx, input, callbacks)
			if plan == nil || len(plan.targets) != 1 || len(plan.targets[0].actions) != 1 || plan.vector.DomainWideWarning != 0 {
				t.Fatal("clean one-action fixture", state)
			}
			calls, injected, readbackObserved := 0, false, false
			var expectedRevision contract.ID
			got := plan.execute(ctx, callbacks, func(ctx context.Context) (*StateSession, contract.Trust, Result) {
				selected, result := Open(ctx, f.admission, f.store)
				if selected == nil {
					t.Fatal("authenticated current fixture", result)
				}
				calls++
				if phase == "reservation" && calls == 1 || phase == "close" && calls == 2 {
					oldHead := f.store.objects[f.store.desc.HeadKey]
					newer := *selected
					newer.head = plan.session.head
					newer.head.Core = selected.head.Core
					newer.support = make([]format.RequiredSupportPageView, len(selected.root.RequiredSupport))
					for i, ref := range selected.root.RequiredSupport {
						key, err := format.Key(f.store.desc.Prefix, ref)
						if err != nil {
							t.Fatal("warning fixture support key", err)
						}
						read := f.store.Read(ctx, key, ref.Length)
						if read.Status != contract.ReadOK {
							t.Fatal("warning fixture support unavailable", read.Status)
						}
						newer.support[i], err = format.InspectRequiredSupportPage(read.Body)
						if err != nil {
							t.Fatal("warning fixture support invalid", err)
						}
					}
					newer.root.WarningBits |= WarningPublicationOrderValue | WarningDiscardedExactEvidence
					newer.root.Snapshot = fixtureID(newer.root.Domain, "warning readback snapshot "+phase)
					newer.head.Core.PreviousRevision, newer.head.Core.PreviousDigest, newer.head.Core.PreviousToken = selected.head.Core.Revision, contract.Hash(selected.body), selected.token
					newer.head.Core.Form = format.SuccessorHead
					newer.head.Core.Revision = fixtureID(newer.root.Domain, "warning readback revision "+phase)
					expectedRevision = newer.head.Core.Revision
					f.session = &newer
					publicationStoreSelectedFixture(t, f)
					competingHead := f.store.objects[f.store.desc.HeadKey]
					f.store.objects[f.store.desc.HeadKey] = oldHead
					f.session = selected
					beforeCAS := f.store.cas
					f.store.casMode = "lost-before"
					f.store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
						if key == f.store.desc.HeadKey && f.store.cas > beforeCAS {
							f.store.objects[key] = competingHead
							f.store.readHook = nil
							readbackObserved = true
							return readFixtureStoredBody(competingHead, uint32(len(competingHead.Body)))
						}
						return read
					}
					injected = true
				}
				return selected, f.trust, result
			})
			wantSummary := uint8(contract.PublicationSummaryFailed)
			if phase == "close" {
				wantSummary = contract.PublicationSummaryUnknown
			}
			if !injected || !readbackObserved || got.state.Outcome != Contention || got.state.Evidence != AuthenticatedClosure || got.state.ObservedRevision != expectedRevision || got.summary != wantSummary {
				t.Fatal("authenticated competing selection readback not established", injected, readbackObserved, got.state, got.summary)
			}
			if !injected || got.output.DomainWideWarning != 1 {
				t.Error("authenticated selection warning disappeared", injected, got.state, got.output.DomainWideWarning)
			}
			wantSends := 0
			if phase == "close" {
				wantSends = 1
			}
			if len(private.owners) != 1 || private.owners[0].sent != wantSends || private.owners[0].retired != 1 {
				t.Error("selection warning changed original effect ownership", len(private.owners), wantSends)
			}
		})
	}
}
