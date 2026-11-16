package core

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestApplyReceiptFirstEndWorkChargesFutureApplicationPages(t *testing.T) {
	for _, count := range []int{21, 22} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, store, trust, keys := successorCapacityColdSelection(t, successorWrappedCapacityState(t, count))
			input := s.currentEntryInputs()
			input = append(input, ApplyEntryInput{Name: "zz-future-page-charge", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{s.admission.recipient}, InputBytes: []byte("public"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			c, result := s.compareEntryInputs(input)
			if c == nil || result.Outcome != ObservedCurrent {
				t.Fatal("public unchanged-secret comparison", result)
			}
			// The reservation owner consumes public comparison/support facts. No
			// private comparison or invented material is needed to test its page bound.
			var err error
			c.support, err = s.generatedSupportTransition(t.Context(), c, nil)
			if err != nil || c.support == nil || len(c.support.Handoffs) != 0 || len(c.support.CurrentGenerated) != count+1 {
				t.Fatal("exact selected support", err)
			}
			before, err := s.receiptWindows(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			c.applyReceipt = &installedApplyReceipt{before: before}
			plan, err := planTransition(t.Context(), c)
			if err != nil {
				t.Fatal("ordinary receipt plan", err)
			}
			c.applyReceipt.subjects, err = installedApplyChangedSubjects(c, plan)
			if err != nil {
				t.Fatal(err)
			}
			values := 0
			for _, occupied := range c.nonemptyPages() {
				if occupied {
					values++
				}
			}
			accesses, unchanged, err := normalAccessShape(c, plan)
			if unchanged {
				accesses = len(s.root.CurrentAccess.Core.AccessPageRefs)
			}
			if err != nil || !unchanged || values != 2 || accesses != 1 || s.root.ChildCount != 250 || s.root.Generated.GeneratedCurrent != uint32(count+1) {
				t.Fatal("independent future page shape", values, accesses, s.root.ChildCount, err)
			}
			empty := contract.EmptyMutationResultDescriptors()
			request := requestCommitment(s.successorCore(plan), contract.LifecycleSubject{IdentityPlan: identityCommitment(c, plan), Normal: contract.NormalSection{Intent: contract.DigestLength{Digest: c.desired, Length: c.desiredLength}}})
			delta, err := s.installedApplyReceiptPlan(c, plan, empty[0], request)
			if err != nil {
				t.Fatal(err)
			}
			storage, err := s.encodeLifecycleReceiptSupport(t.Context(), c, plan, delta, contract.ID{})
			if err != nil {
				t.Fatal(err)
			}
			projected := *s
			storage.install(&projected)
			projected.recountChildren()
			if projected.root.ChildCount != 252 {
				t.Fatal("complete ordinary receipt shape", projected.root.ChildCount)
			}
			for _, fragment := range s.root.Generated.Fragments {
				at := slices.IndexFunc(s.root.RequiredSupport, func(ref contract.Ref) bool { return ref.Index == fragment.SupportPageIndex })
				if at < 0 || !slices.Contains(projected.root.RequiredSupport, s.root.RequiredSupport[at]) {
					t.Fatal("receipt rewrote a paired current-intent fragment page")
				}
			}
			// All current intent bytes must move; each old exclusive fragment shares
			// a page with a mandatory peer, so no physical support page is released.
			// Two old receipt pages are replaced by two first-exit pages (net zero).
			total := uint64(count)*393216 + 12
			fragments := (total + 1048320 - 1) / 1048320
			pages := (fragments + 1) / 2
			children := uint64(252) + pages
			if count == 21 && (total != 8257548 || fragments != 8 || pages != 4 || children != 256) || count == 22 && (total != 8650764 || fragments != 9 || pages != 5 || children != 257) {
				t.Fatal("independent adjacent first-exit count", total, fragments, pages, children)
			}
			original := generatedSuccessorPredecessorSnapshot(t, s)
			public, private := keys.Calls()
			creates, cas, signs, qualifications := store.creates, store.cas, trust.Calls(), trust.QualificationCalls()
			err = s.reserveInstalledApplyReceipt(t.Context(), c, plan)
			if count == 21 && err != nil || count == 22 && (!errors.Is(err, contract.ErrRecordCapacity) || err == contract.ErrRecordCapacity) {
				t.Error("first-EndWork omitted future value/access pages", children, err)
			}
			afterPublic, afterPrivate := keys.Calls()
			if public != afterPublic || private != afterPrivate || creates != store.creates || cas != store.cas || signs != trust.Calls() || qualifications != trust.QualificationCalls() || !bytes.Equal(original, generatedSuccessorPredecessorSnapshot(t, s)) {
				t.Fatal("reservation used effects or changed predecessor")
			}
		})
	}
}
