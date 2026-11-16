package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type receiptReservationSnapshot struct {
	root                  []byte
	support               []format.RequiredSupportPageView
	facts                 []selectedSupportPageFacts
	fragments             map[format.FragmentLocation]selectedFragmentFact
	slices                []contract.GeneratorSliceLocation
	sliceRoot, outputRoot contract.ID
	index                 format.AdministrativeIndex
	publication           *selectedPublicationProof
}

func receiptReservationInputSnapshot(t testing.TB, s *StateSession) receiptReservationSnapshot {
	t.Helper()
	root, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal(err)
	}
	out := receiptReservationSnapshot{root: root, support: slices.Clone(s.support), facts: slices.Clone(s.supportFacts), fragments: maps.Clone(s.fragmentFacts), slices: slices.Clone(s.generatedSliceLocations), sliceRoot: s.generatedSlicesRoot, outputRoot: s.outputConfigurationRoot, index: clonePublicationWork(s.adminIndex)}
	for i := range out.support {
		out.support[i].Records = slices.Clone(out.support[i].Records)
		for j := range out.support[i].Records {
			out.support[i].Records[j].Body = bytes.Clone(out.support[i].Records[j].Body)
		}
	}
	for i := range out.facts {
		out.facts[i].rows = slices.Clone(out.facts[i].rows)
		out.facts[i].ordinals = slices.Clone(out.facts[i].ordinals)
		if out.facts[i].plannedReceipt != nil {
			own := *out.facts[i].plannedReceipt
			own.body = bytes.Clone(own.body)
			out.facts[i].plannedReceipt = &own
		}
	}
	if s.publicationProof != nil {
		own := *s.publicationProof
		own.rows = maps.Clone(own.rows)
		out.publication = &own
	}
	return out
}

func receiptReservationFixture(t testing.TB, kind uint16) (*StateSession, *StateSession, contract.CompactMutationReceiptPlan) {
	t.Helper()
	source := successionReceiptCapacityFixture(t)
	generatedInstallFixtureSupportReader(t, source)
	if result := source.validateSelectedOutputConfiguration(t.Context()); result.Outcome != 0 {
		t.Fatal("authenticate receipt reservation predecessor output", result)
	}
	if !source.selectedOutputComplete() || source.generatedSlicesRoot.IsZero() {
		t.Fatal("receipt reservation predecessor lacks complete output or Slice proof")
	}
	// Match a complete cold reader: payloads have been released, but exact
	// physical facts and the independently verified Slice locations remain.
	source.support = slices.Clone(source.support)
	for i := range source.support {
		source.support[i].Records = slices.Clone(source.support[i].Records)
		for j := range source.support[i].Records {
			if opaqueSupportKind(source.support[i].Records[j].Kind) {
				source.support[i].Records[j].Body = nil
			}
		}
	}
	before, err := source.receiptWindows(t.Context())
	if err != nil {
		t.Fatal("read receipt reservation predecessor windows", err)
	}
	row := contract.CompactMutationReceiptPlan(before.Successes[0])
	row.OperationKind = kind
	row.OperationID = contract.Hash([]byte(fmt.Sprintf("private receipt reservation operation/%d", kind)))
	row.RequestIdentityDigest = contract.ID{}
	row.RequestedRevisionID = contract.Hash([]byte("private receipt reservation revision"))
	row.ObservedRevisionID = row.RequestedRevisionID
	if kind == contract.OperationEndSelectedWork {
		row.StateResult = contract.ReceiptStateWorkEnded
		row.EffectSummary = contract.ReceiptEffectNotApplicable
		row.AdministrativeTargetKind = contract.AdministrativeGeneratedParent
		row.AdministrativeTargetID = contract.Hash([]byte("private receipt reservation ended target"))
		row.AdministrativeDisposition = contract.Hash([]byte("private receipt reservation disposition"))
		row.AdministrativeGroupID = contract.Hash([]byte("private receipt reservation group"))
		row.AdministrativeOriginalEvidence = contract.AdministrativeEvidenceMissing
		row.ChangedSubjects = contract.GeneratorDescriptor{Digest: contract.Hash([]byte("private receipt reservation changed group")), Length: 42, Count: 1}
	}
	delta := contract.MutationReceiptDeltaPlan{DomainID: source.root.Domain, OperationKind: kind, AddedCount: 1, Before: before, NewReceipt: row}
	plan := transitionPlan{operation: row.OperationID, snapshot: contract.Hash([]byte("private receipt reservation snapshot")), transition: contract.Hash([]byte("private receipt reservation transition")), revision: row.RequestedRevisionID}
	indexes, err := source.mutationReceiptPageIndexes(t.Context())
	if err != nil {
		t.Fatal("plan receipt reservation support indexes", err)
	}
	for _, index := range indexes {
		plan.supportPages[index] = contract.Hash([]byte(fmt.Sprintf("private receipt reservation support/%d", index)))
	}
	storage, err := source.encodeMutationReceiptSupport(t.Context(), plan, delta, contract.ID{})
	if err != nil {
		t.Fatal("encode receipt reservation planned support", err)
	}
	next := *source
	next.root.Snapshot, next.root.Transition = plan.snapshot, plan.transition
	storage.install(&next)
	if err := source.installAdministrativeIndex(t.Context(), &next, &Candidate{session: source}, &row); err != nil {
		t.Fatal("typed receipt fixture administrative plan", err)
	}
	return source, &next, row
}

// full_only: false
func TestPlannedReceiptReservationKeepsHoleSeparateFromAuthenticatedRows(t *testing.T) {
	// These are public receipt row kinds, not additional admitted operations.
	// Generated terminal and administrative writers normally seal their rows
	// before the ordinary index path; their physical reader stays strict too.
	for _, kind := range []uint16{contract.OperationApplyDeclaration, contract.OperationRotateRecipientKeyBinding, contract.OperationReplaceRecoveryKeysAndRoot, contract.OperationEndSelectedWork} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			source, next, row := receiptReservationFixture(t, kind)
			beforeSource, beforeNext := receiptReservationInputSnapshot(t, source), receiptReservationInputSnapshot(t, next)
			store := source.store.(*generatedFixtureSupportStore)
			reads := len(store.keys)
			cancelled, cancel := context.WithCancel(t.Context())
			cancel()
			unavailable, cancelErr := source.receiptReservationCopy(cancelled, next, row, nil)
			var readErr *selectedReadError
			if unavailable != nil || !errors.As(cancelErr, &readErr) || readErr.result != failure(EvidenceUnavailable, ReadUnavailable) {
				t.Fatal("cancelled reservation lost read-unavailable classification", cancelErr)
			}
			view, err := source.receiptReservationCopy(t.Context(), next, row, nil)
			if err != nil || view == next || view == source {
				t.Fatal("private typed reservation refused", err)
			}
			if len(store.keys) != reads || !reflect.DeepEqual(receiptReservationInputSnapshot(t, source), beforeSource) || !reflect.DeepEqual(receiptReservationInputSnapshot(t, next), beforeNext) {
				t.Fatal("reservation read unrelated detail or changed an input")
			}
			if !next.outputConfigurationRoot.IsZero() || next.publicationProof != nil {
				t.Fatal("outgoing plan acquired complete output proof")
			}
			tagged, holes := 0, 0
			for i, page := range view.supportFacts {
				if page.plannedReceipt == nil {
					continue
				}
				tagged++
				if page.plannedReceipt.owner != view {
					t.Fatal("plan carrier has another owner")
				}
				for j, record := range view.support[i].Records {
					if record.RecordID == row.OperationID {
						holes++
						if page.rows[j] != (contract.SupportRecordDigest{}) {
							t.Fatal("typed hole acquired an inspected receipt fact")
						}
					}
				}
				rows, err := view.administrativeSelectedRows(view.adminIndex.Pages[i])
				if err != nil || len(rows) != len(view.support[i].Records) {
					t.Fatal("capacity could not inspect its exact typed plan", err)
				}
				reads, consumes := 0, 0
				result, err := withAuthenticatedSupportRows(t.Context(), func(context.Context, format.Ref) ([]byte, Result) { reads++; return nil, Result{} }, source.root.Domain, page, func(uint16, uint16, contract.SupportRecordView) error { consumes++; return nil })
				if err != nil || result != failure(IntegrityFailure, InvalidRelation) || reads != 0 || consumes != 0 {
					t.Fatal("typed plan entered an authenticated physical reader", result, err, reads, consumes)
				}
				copied := *view
				if _, err := copied.administrativeSelectedRows(copied.adminIndex.Pages[i]); err == nil {
					t.Fatal("plan page was usable by another reservation owner")
				}
			}
			if tagged != 1 || holes != 1 {
				t.Fatal("reservation needs exactly one separate typed receipt hole", tagged, holes)
			}
			if _, err := view.receiptReservationCopy(t.Context(), next, row, nil); err == nil {
				t.Fatal("a reservation copy was accepted as an authenticated predecessor")
			}
			// Omitting every old page cannot launder a tagged source either. This
			// empty output is otherwise a valid input to the fact reconstruction
			// helper, so only the source-plan boundary can explain its refusal.
			if err := (&mutationReceiptStorage{}).bindSupportFacts(view, nil); err == nil {
				t.Fatal("omitting a tagged predecessor page erased its planning provenance")
			}

			for _, page := range next.supportFacts {
				if page.plannedReceipt != nil {
					t.Fatal("private reservation token escaped to outgoing plan")
				}
			}
		})
	}
}

// full_only: false
func TestPlannedReceiptReservationRefusesChangedPlanAndPredecessorFacts(t *testing.T) {
	for _, damage := range []string{"owner", "plan", "body", "fact", "mandatory", "short optional view", "source fragment", "source Slice proof"} {
		t.Run(damage, func(t *testing.T) {
			source, next, row := receiptReservationFixture(t, contract.OperationRotateRecipientKeyBinding)
			if damage == "source fragment" || damage == "source Slice proof" {
				changed := *source
				if damage == "source fragment" {
					changed.fragmentFacts = make(map[format.FragmentLocation]selectedFragmentFact, len(source.fragmentFacts))
					for key, fact := range source.fragmentFacts {
						changed.fragmentFacts[key] = fact
					}
					for key := range changed.fragmentFacts {
						delete(changed.fragmentFacts, key)
						break
					}
				} else {
					changed.generatedSlicesRoot = contract.Hash([]byte("changed source Slice proof"))
				}
				if _, err := changed.receiptReservationCopy(t.Context(), next, row, nil); err == nil {
					t.Fatal("changed predecessor facts entered reservation")
				}
				return
			}
			view, err := source.receiptReservationCopy(t.Context(), next, row, nil)
			if err != nil {
				t.Fatal(err)
			}
			position := -1
			for i, page := range view.supportFacts {
				if page.plannedReceipt != nil {
					position = i
					break
				}
			}
			if position < 0 {
				t.Fatal("plan page absent")
			}
			view.supportFacts = slices.Clone(view.supportFacts)
			page := &view.supportFacts[position]
			own := *page.plannedReceipt
			own.body = bytes.Clone(own.body)
			page.plannedReceipt = &own
			switch damage {
			case "owner":
				own.owner = next
			case "plan":
				own.plan.RequestedRevisionID = contract.Hash([]byte("changed planned revision"))
			case "body":
				own.body[0] ^= 1
			case "fact":
				page.rows = slices.Clone(page.rows)
				for i, record := range view.support[position].Records {
					if record.RecordID == row.OperationID {
						page.rows[i] = source.supportFacts[0].rows[0]
					}
				}
			case "short optional view":
				view.support = slices.Clone(view.support)
				view.support[position].Records = nil
			case "mandatory":
				view.adminIndex.Pages = slices.Clone(view.adminIndex.Pages)
				view.adminIndex.Pages[position].Spans = slices.Clone(view.adminIndex.Pages[position].Spans)
				for i := range view.adminIndex.Pages[position].Spans {
					view.adminIndex.Pages[position].Spans[i].Mandatory = false
				}
			}
			if _, err := view.administrativeSelectedRows(view.adminIndex.Pages[position]); err == nil {
				t.Fatal("changed typed plan entered administrative capacity reader")
			}
		})
	}
}
