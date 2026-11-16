package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestAdmissionExpiresBeforeSignAndSelection(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	c := changed(t, f.session, 0)
	permit := admit(t, f.session, c)
	f.store.readHook = func(key string, r contract.ReadResult) contract.ReadResult {
		if key != f.store.desc.HeadKey {
			f.session.admission.expires = time.Now().Add(-time.Second)
		}
		return r
	}
	if candidate, r := f.session.Prepare(context.Background(), c, permit, f.trust); candidate != nil || r.Outcome != AdmissionRefused || f.trust.signs != 0 || f.store.cas != 0 {
		t.Fatal(r)
	}
	f = newFixture(t, 1, false, 1)
	candidate := prepare(t, f, changed(t, f.session, 0))
	f.session.admission.expires = time.Now().Add(-time.Second)
	if r := f.session.Select(context.Background(), candidate); r.Outcome != AdmissionRefused || f.store.cas != 0 {
		t.Fatal(r)
	}
}
