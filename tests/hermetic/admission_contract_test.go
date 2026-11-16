package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

type misboundTrust struct {
	contract.Trust
	id     contract.ID
	family contract.Family
}

func (t misboundTrust) Identity() contract.ID   { return t.id }
func (t misboundTrust) Family() contract.Family { return t.family }

// full_only: false
func TestOpenAdmissionRefusesBeforeRead(t *testing.T) {
	for _, name := range []string{"expired", "wrong-store", "invalid-public-key"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1, false, 0)
			admission := *f.admission.admission
			want := Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}
			switch name {
			case "expired":
				admission.expires = time.Now().Add(-time.Second)
			case "wrong-store":
				admission.store.Identity = testID("other store")
			case "invalid-public-key":
				admission.publicKey = []byte{0xff}
			}
			reads := f.store.reads
			if s, r := Open(context.Background(), OpenContext{admission: &admission}, f.store); s != nil || r != want {
				t.Fatalf("open admission: session=%v result=%+v", s, r)
			}
			if f.store.reads != reads || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 {
				t.Fatal("invalid admission reached data or signing")
			}
		})
	}
}

// full_only: false
func TestPreparationRejectsAlteredAdmission(t *testing.T) {
	for _, name := range []string{"nil-comparison", "nil-permit", "expired", "wrong-store", "nil-trust", "wrong-trust", "wrong-trust-family", "predecessor-revision", "predecessor-digest", "predecessor-token", "comparison-owner", "permit-owner", "permit-comparison", "desired-commitment", "desired-length", "changed-slots", "authority-subject"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 2, false, 1)
			c := changed(t, f.session, 0)
			permit := admit(t, f.session, c)
			originalPermit := permit
			var trust contract.Trust = f.trust
			want := Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}
			switch name {
			case "nil-comparison":
				c = nil
			case "nil-permit":
				permit = nil
			case "expired":
				f.session.admission.expires = time.Now().Add(-time.Second)
			case "wrong-store":
				f.store.desc.Identity = testID("other store")
			case "nil-trust":
				trust = nil
				want.Reason = ConstructionMismatch
			case "wrong-trust":
				trust = misboundTrust{Trust: f.trust, id: testID("other trust"), family: f.trust.Family()}
				want.Reason = ConstructionMismatch
			case "wrong-trust-family":
				trust = misboundTrust{Trust: f.trust, id: f.trust.Identity(), family: contract.AWS}
				want.Reason = ConstructionMismatch
			case "predecessor-revision":
				permit.predecessorRevision = testID("other revision")
			case "predecessor-digest":
				permit.predecessorDigest = testID("other digest")
			case "predecessor-token":
				permit.predecessorToken.Value = "987654321"
			case "comparison-owner":
				c.session = &StateSession{}
			case "permit-owner":
				permit.session = &StateSession{}
			case "permit-comparison":
				permit.comparison = changed(t, f.session, 1)
			case "desired-commitment":
				c.desired = testID("other desired")
			case "desired-length":
				c.desiredLength++
			case "changed-slots":
				c.changed = []uint16{1}
			case "authority-subject":
				permit.authority.normal.Section.Union.Digest = testID("other diff")
			}
			reads := f.store.reads
			if candidate, r := f.session.Prepare(context.Background(), c, permit, trust); candidate != nil || r != want {
				t.Fatalf("altered admission: candidate=%v result=%+v", candidate, r)
			}
			if originalPermit.used || f.session.prepared || f.store.reads != reads || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 {
				t.Fatal("pre-admission refusal consumed preparation or reached an external call")
			}
		})
	}
}

// full_only: false
func TestPreparationRejectsInvalidIdentityPlan(t *testing.T) {
	for _, name := range []string{"zero-operation", "zero-transition", "zero-snapshot", "zero-revision", "duplicate-transition", "retained-revision", "retained-page", "retained-value", "retained-incarnation", "retained-origin", "missing-value", "extra-value", "zero-value", "duplicate-value", "missing-page", "untouched-page", "duplicate-page"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 32, false, 1)
			c := changed(t, f.session, 0, 16)
			permit := admit(t, f.session, c)
			p := &permit.plan
			switch name {
			case "zero-operation":
				p.operation = contract.ID{}
			case "zero-transition":
				p.transition = contract.ID{}
			case "zero-snapshot":
				p.snapshot = contract.ID{}
			case "zero-revision":
				p.revision = contract.ID{}
			case "duplicate-transition":
				p.transition = p.operation
			case "retained-revision":
				p.revision = f.session.head.Core.Revision
			case "retained-page":
				p.pages[0] = f.session.pages[1].Object
			case "retained-value":
				p.values[0] = f.session.valueEntry(1).ValueState
			case "retained-incarnation":
				p.transition = f.session.valueEntry(1).Incarnation
			case "retained-origin":
				p.snapshot = f.session.valueEntry(1).OriginSnapshot
			case "missing-value":
				delete(p.values, 0)
			case "extra-value":
				p.values[1] = testID("untouched value")
			case "zero-value":
				p.values[0] = contract.ID{}
			case "duplicate-value":
				p.values[16] = p.values[0]
			case "missing-page":
				p.pages[0] = contract.ID{}
			case "untouched-page":
				p.pages[2] = testID("untouched page")
			case "duplicate-page":
				p.pages[1] = p.pages[0]
			}
			reads := f.store.reads
			if candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust); candidate != nil || r != (Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}) {
				t.Fatalf("invalid identity plan: candidate=%v result=%+v", candidate, r)
			}
			if permit.used || f.session.prepared || f.store.reads != reads || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 {
				t.Fatal("invalid identity plan crossed preparation admission")
			}
		})
	}
}

// full_only: false
func TestPreparationAttemptConsumption(t *testing.T) {
	for _, name := range []string{"pre-admission-refusal", "failed-admitted-attempt", "successful-admitted-attempt"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			c := changed(t, f.session, 0)
			permit := admit(t, f.session, c)
			freshComparison := changed(t, f.session, 0)
			freshPermit := admit(t, f.session, freshComparison)
			switch name {
			case "pre-admission-refusal":
				if candidate, r := f.session.Prepare(context.Background(), c, permit, nil); candidate != nil || r.Reason != ConstructionMismatch || permit.used || f.session.prepared {
					t.Fatal("pre-admission refusal consumed the attempt")
				}
			case "failed-admitted-attempt":
				f.store.createMode = "lost-before"
				if candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust); candidate != nil || r != (Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}) || !permit.used || !f.session.prepared {
					t.Fatalf("failed preparation did not consume admission: %+v", r)
				}
			case "successful-admitted-attempt":
				if candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust); candidate == nil || !permit.used || !f.session.prepared {
					t.Fatalf("successful preparation did not consume admission: %+v", r)
				}
			}
			if name == "pre-admission-refusal" {
				if candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust); candidate == nil {
					t.Fatalf("valid attempt after pre-admission refusal: %+v", r)
				}
				return
			}
			reads, creates, signs := f.store.reads, f.store.creates, f.trust.signs
			for _, reused := range []struct {
				comparison *Comparison
				permit     *AdmittedParentTransition
			}{{c, permit}, {freshComparison, freshPermit}} {
				if candidate, r := f.session.Prepare(context.Background(), reused.comparison, reused.permit, f.trust); candidate != nil || r != (Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}) {
					t.Fatalf("second admitted attempt: %+v", r)
				}
			}
			if !permit.used || !f.session.prepared || freshPermit.used || f.store.reads != reads || f.store.creates != creates || f.trust.signs != signs || f.store.cas != 0 {
				t.Fatal("second preparation had effects")
			}
		})
	}
}

// full_only: false
func TestCandidateCannotCrossSessions(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	candidate := prepare(t, f, changed(t, f.session, 0))
	other, r := Open(context.Background(), f.admission, f.store)
	if other == nil {
		t.Fatal(r)
	}
	reads := f.store.reads
	if r := other.Select(context.Background(), candidate); r != (Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}) || candidate.used || f.store.cas != 0 || f.store.reads != reads {
		t.Fatalf("cross-session candidate crossed selection: %+v", r)
	}
	if r := f.session.Select(context.Background(), candidate); r.Outcome != ObservedCurrent {
		t.Fatal(r)
	}
}
