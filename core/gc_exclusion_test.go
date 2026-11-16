package core

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGCActiveSlotBlocksOrdinaryAndGeneratedAdmission(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "pending"}[pending], func(t *testing.T) {
			s, _ := gcStateFixture(t, pending)
			ctx := installedAdministrativeTestContext(t)
			deadline, _ := ctx.Deadline()
			store := s.store.(*observationSelectionStore)
			beforeSends, beforeObjects := store.sends, len(store.objects)
			inputEntries := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{s.admission.recipient}, InputBytes: []byte("ordinary-after-gc")}}
			unchecked, result := s.compareEntryInputs(inputEntries)
			if unchecked == nil {
				t.Fatal("ordinary intent fixture", result)
			}
			support, err := s.generatedSupportTransition(ctx, unchecked, nil)
			if err != nil || support == nil {
				t.Fatal("ordinary retained-work handoff", err)
			}
			comparison, result := s.compare(ctx, inputEntries, &AdmittedParentComparison{session: s, deadline: deadline, support: support})
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("GC blocked read-only ordinary comparison", result)
			}
			_, err = planTransition(ctx, comparison)
			if (err == nil) != pending {
				t.Fatal("ordinary admission did not follow active GC slot", pending, err)
			}
			input := generatedPlanInputFixture(t, s)
			plan, err := s.generatedPlanRequest(ctx, input)
			if (err == nil && plan != nil) != pending {
				t.Fatal("generated admission did not follow active GC slot", pending, err)
			}
			if store.sends != beforeSends || len(store.objects) != beforeObjects {
				t.Fatal("admission guard reached immutable persistence or CAS")
			}
		})
	}
}

// full_only: false
func TestGCActiveSlotBlocksPublicationSelectionOwners(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "pending"}[pending], func(t *testing.T) {
			s, _ := gcStateFixture(t, pending)
			ctx := installedAdministrativeTestContext(t)
			deadline, _ := ctx.Deadline()
			if !publicationNormalAdmission(ctx, s, deadline) {
				t.Fatal("fixture lacks normal publication admission")
			}
			plan := &publicationPlan{session: s, input: publicationInput{deadline: deadline}}
			store := s.store.(*observationSelectionStore)
			before := store.sends
			candidate, permission, reserve := plan.preparePublicationReservation(ctx, s, publicationTargetPlan{}, contract.PublicationCreateEmpty, publicationPrivate{})
			closed, closeResult := plan.preparePublicationClose(ctx, s, &publicationPreparation{}, contract.PublicationResult{})
			if candidate != nil || permission != nil || closed != nil || store.sends != before {
				t.Fatal("publication guard produced a candidate or effect")
			}
			if !pending && (reserve != refused(AdmissionInvalid) || closeResult != refused(AdmissionInvalid)) {
				t.Fatal("active GC reached publication selection construction", reserve, closeResult)
			}
			if pending && (reserve != refused(InvalidRelation) || closeResult != refused(InvalidProof)) {
				t.Fatal("pending GC blocked publication before its own target/proof checks", reserve, closeResult)
			}
		})
	}
}
