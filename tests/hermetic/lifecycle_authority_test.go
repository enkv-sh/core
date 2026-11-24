package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type entropyWitness struct {
	source io.Reader
	calls  int
}

func (r *entropyWitness) Read(b []byte) (int, error) {
	r.calls++
	if r.source == nil {
		return 0, errors.New("entropy unavailable")
	}
	return r.source.Read(b)
}
func mixedIntent(s *StateSession) []ApplyEntryInput {
	values := s.currentEntryInputs()[1:]
	values[0].InputBytes = append(values[0].InputBytes, 42)
	return append(values, ApplyEntryInput{Name: "added", Recipients: []contract.ID{s.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("new"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
}

// full_only: false
func TestLifecycleIdentityEntropyRefusesBeforeEffects(t *testing.T) {
	for _, name := range []string{"unavailable", "short", "zero", "current-member", "current-recipient", "duplicate-plan"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 3, false, 1)
			c, result := f.session.Compare(context.Background(), mixedIntent(f.session), admitSuppliedComparison(t, f.session, nil, mixedIntent(f.session)))
			if c == nil {
				t.Fatal(result)
			}
			entropy := &entropyWitness{}
			switch name {
			case "short":
				entropy.source = bytes.NewReader([]byte{1})
			case "zero":
				entropy.source = bytes.NewReader(make([]byte, 32))
			case "current-member":
				id := f.session.valueEntry(1).Incarnation
				entropy.source = bytes.NewReader(id[:])
			case "current-recipient":
				id := f.session.admission.recipient
				entropy.source = bytes.NewReader(id[:])
			case "duplicate-plan":
				id := testID("new repeated entropy")
				entropy.source = bytes.NewReader(bytes.Repeat(id[:], 2))
			}
			f.session.admission.entropy = entropy
			if _, err := planTransition(t.Context(), c); err == nil {
				t.Fatal("invalid entropy produced an identity plan")
			}
			if entropy.calls == 0 || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 || f.session.prepared {
				t.Fatal("entropy refusal crossed effects")
			}
		})
	}
}

// full_only: false
func TestLifecycleIdentityAllocationCountsSuccessorPages(t *testing.T) {
	for _, name := range []string{"mixed", "remove-last", "add-empty", "retained-update"} {
		t.Run(name, func(t *testing.T) {
			count := 3
			if name == "add-empty" {
				count = 0
			}
			f := newFixture(t, count, false, 1)
			var input []ApplyEntryInput
			switch name {
			case "mixed":
				input = mixedIntent(f.session)
			case "add-empty":
				input = []ApplyEntryInput{{Name: "new", Recipients: []contract.ID{f.session.admission.recipient}, ValueSource: 1, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: 1}}
			case "retained-update":
				input = f.session.currentEntryInputs()
				input[0].InputBytes = []byte{99}
			}
			c, result := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
			if c == nil {
				t.Fatal(result)
			}
			data := []byte{}
			for i := 0; i < 100; i++ {
				id := testID(string(rune(i)) + " entropy count")
				data = append(data, id[:]...)
			}
			entropy := &entropyWitness{source: bytes.NewReader(data)}
			f.session.admission.entropy = entropy
			p, err := planTransition(t.Context(), c)
			if err != nil {
				t.Fatal("valid entropy refused")
			}
			pages := 0
			for _, id := range p.pages {
				if !id.IsZero() {
					pages++
				}
			}
			supportPages := 0
			for _, id := range p.supportPages {
				if !id.IsZero() {
					supportPages++
				}
			}
			wantSupportPages := 0
			if name == "add-empty" {
				wantSupportPages = 2
			}
			if supportPages != wantSupportPages {
				t.Fatal("ordinary support allocation count", supportPages, wantSupportPages)
			}
			if entropy.calls != 4+len(c.added)+len(c.changed)+pages+supportPages {
				t.Fatalf("identity calls=%d additions=%d changed=%d pages=%d support-pages=%d", entropy.calls, len(c.added), len(c.changed), pages, supportPages)
			}
			if name == "remove-last" && pages != 0 {
				t.Fatal("dropped pages received identities")
			}
		})
	}
}

// full_only: false
func TestUnchangedIntentNeverRequestsEntropy(t *testing.T) {
	for _, count := range []int{0, 1, 32} {
		f := newFixture(t, count, false, 0)
		entropy := &entropyWitness{}
		f.session.admission.entropy = entropy
		if c, result := f.session.Compare(context.Background(), f.session.currentEntryInputs(), admitSuppliedComparison(t, f.session, nil, f.session.currentEntryInputs())); c != nil || result.Outcome != Unchanged {
			t.Fatal(result)
		}
		if entropy.calls != 0 || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 || f.session.prepared {
			t.Fatal("unchanged intent requested a mutation")
		}
	}
}

// full_only: false
func TestLifecyclePrivateAuthorityRejectsEveryWrongFamily(t *testing.T) {
	for _, name := range []string{"missing-normal", "missing-grant", "missing-exclusion", "empty-grant", "empty-exclusion", "excess-grant", "excess-exclusion", "grant-name", "grant-slot", "grant-incarnation", "grant-recipient", "grant-member", "exclusion-name", "exclusion-slot", "exclusion-incarnation", "exclusion-recipient", "exclusion-member", "plain-path", "retirement-count", "retirement-digest", "retirement-length", "normal-intent", "normal-state", "normal-union", "normal-changed", "normal-operation", "grant-operation", "exclusion-operation", "normal-basis", "grant-basis", "exclusion-basis", "grant-binding", "exclusion-predecessor", "grant-token", "exclusion-identity-plan", "normal-successor"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 3, false, 1)
			c, result := f.session.Compare(context.Background(), mixedIntent(f.session), admitSuppliedComparison(t, f.session, nil, mixedIntent(f.session)))
			if c == nil {
				t.Fatal(result)
			}
			permit := admit(t, f.session, c)
			a := &permit.authority
			switch name {
			case "missing-normal":
				a.normal = nil
			case "missing-grant":
				a.grant = nil
			case "missing-exclusion":
				a.exclusion = nil
			case "empty-grant":
				a.grant.Rows = nil
			case "empty-exclusion":
				a.exclusion.Rows = nil
			case "excess-grant":
				a.grant.Rows = append(a.grant.Rows, a.grant.Rows[0])
			case "excess-exclusion":
				a.exclusion.Rows = append(a.exclusion.Rows, a.exclusion.Rows[0])
			case "grant-name":
				a.grant.Rows[0].Name = "wrong"
			case "grant-slot":
				a.grant.Rows[0].Slot++
			case "grant-incarnation":
				a.grant.Rows[0].Incarnation = testID("wrong")
			case "grant-recipient":
				a.grant.Rows[0].Recipients[0] = testID("wrong")
			case "grant-member":
				a.grant.Rows[0].EntryDigest = testID("wrong")
			case "exclusion-name":
				a.exclusion.Rows[0].Name = "wrong"
			case "exclusion-slot":
				a.exclusion.Rows[0].Slot++
			case "exclusion-incarnation":
				a.exclusion.Rows[0].Incarnation = testID("wrong")
			case "exclusion-recipient":
				a.exclusion.Rows[0].Recipients[0] = testID("wrong")
			case "exclusion-member":
				a.exclusion.Rows[0].EntryDigest = testID("wrong")
			case "plain-path":
				a.exclusion.Rows[0].Path = testID("wrong")
			case "retirement-count":
				a.exclusion.Retirements.Count = 1
			case "retirement-digest":
				a.exclusion.Retirements.Digest = testID("wrong")
			case "retirement-length":
				a.exclusion.Retirements.Length++
			case "normal-intent":
				a.normal.Section.Intent.Digest = testID("wrong")
			case "normal-state":
				a.normal.Section.PublicState.Digest = testID("wrong")
			case "normal-union":
				a.normal.Section.Union.Digest = testID("wrong")
			case "normal-changed":
				a.normal.Section.Changed++
			case "normal-operation":
				a.normal.Context.Operation = testID("wrong")
			case "grant-operation":
				a.grant.Context.Operation = testID("wrong")
			case "exclusion-operation":
				a.exclusion.Context.Operation = testID("wrong")
			case "normal-basis":
				a.normal.Context.BeforeAccessRoot = testID("wrong")
			case "grant-basis":
				a.grant.Context.BeforeAccessRoot = testID("wrong")
			case "exclusion-basis":
				a.exclusion.Context.BeforeAccessRoot = testID("wrong")
			case "grant-binding":
				a.grant.Context.KeyBinding = testID("wrong")
			case "exclusion-predecessor":
				a.exclusion.Context.PreviousRevision = testID("wrong")
			case "grant-token":
				a.grant.Context.PreviousToken.Value = "9876"
			case "exclusion-identity-plan":
				a.exclusion.Context.IdentityPlan.Digest = testID("wrong")
			case "normal-successor":
				a.normal.Context.Snapshot = testID("wrong")
			}
			reads := f.store.reads
			if candidate, result := f.session.Prepare(context.Background(), c, permit, f.trust); candidate != nil || result != (Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}) {
				t.Fatalf("wrong authority accepted: %+v", result)
			}
			if permit.used || f.session.prepared || f.store.reads != reads || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 {
				t.Fatal("wrong family crossed admission")
			}
		})
	}
}

// full_only: false
func TestSignedLifecycleChecksOnlyItsPublicClosure(t *testing.T) {
	for _, name := range []string{"recipient", "key-binding", "fingerprint", "binding-version", "public-state", "empty-grant", "empty-exclusion", "empty-retirement", "historical-union", "historical-identity-plan"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 3, false, 1)
			// A retained-value update has empty grant and exclusion vectors.
			candidate := prepare(t, f, changed(t, f.session, 0))
			if result := f.session.Select(context.Background(), candidate); result.Outcome != ObservedCurrent {
				t.Fatal(result)
			}
			var result Result
			f.session, result = Open(context.Background(), f.admission, f.store)
			if f.session == nil {
				t.Fatal(result)
			}
			f.store.reads, f.store.creates, f.store.cas, f.trust.signs = 0, 0, 0, 0
			head := f.session.head
			wantSuccess := false
			switch name {
			case "recipient":
				head.Subject.Recipient = testID("other")
			case "key-binding":
				head.Subject.KeyBinding = testID("other")
			case "fingerprint":
				head.Subject.Fingerprint = testID("other")
			case "binding-version":
				head.Subject.BindingVersion++
			case "public-state":
				head.Subject.Normal.PublicState.Digest = testID("other")
			case "empty-grant":
				head.Subject.Grant.Grants.Digest = testID("other")
			case "empty-exclusion":
				head.Subject.Exclusion.Exclusions.Digest = testID("other")
			case "empty-retirement":
				head.Subject.Exclusion.Retirements.Digest = testID("other")
			case "historical-union":
				head.Subject.Normal.Union.Digest = testID("historical assertion")
				wantSuccess = true
			case "historical-identity-plan":
				head.Subject.IdentityPlan.Digest = testID("historical assertion")
				head.Subject.Request = requestCommitment(head.Core, head.Subject)
				wantSuccess = true
			}
			storeHead(t, f, head, true)
			f.trust.signs = 0
			s, result := Open(context.Background(), f.admission, f.store)
			if wantSuccess {
				if s == nil || result.Outcome != ObservedCurrent {
					t.Fatalf("cold reader required historical rows: %+v", result)
				}
			} else if s != nil || result != (Result{Outcome: IntegrityFailure, Reason: InvalidProof}) {
				t.Fatalf("signed wrong selected meaning: %+v", result)
			}
			if f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 {
				t.Fatal("cold verification had effects")
			}
		})
	}
}
