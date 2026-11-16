package core

import (
	"context"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"testing"
)

// full_only: false
func TestValidSignaturesCannotChangeExpectedBindings(t *testing.T) {
	for _, field := range []string{"domain", "coordinate", "store", "trust", "interpretation", "epoch", "key", "request", "desired", "purpose", "token", "diff", "root", "revision", "previous-revision", "previous-digest", "nonbody", "operation", "desired-length", "diff-count"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			h := f.session.head
			resign := true
			switch field {
			case "domain":
				h.Core.Domain = testID("foreign domain")
				h.Core.Root.Domain = h.Core.Domain
			case "coordinate":
				h.Core.Coordinate = testID("foreign coordinate")
			case "store":
				h.Core.Store = testID("foreign store")
			case "trust":
				h.Core.Trust = testID("foreign trust")
			case "interpretation":
				h.Core.Interpretation = testID("foreign interpretation")
			case "epoch":
				h.Core.Epoch++
			case "key":
				f.admission.admission.publicKey = testtrust.New(t, f.store.desc.Family, testID("other public signer")).PublicKey()
			case "request":
				h.Subject.Request = testID("wrong complete request")
			case "desired":
				h.Subject.Normal.PublicState.Digest = testID("wrong desired image")
				h.Subject.Request = requestCommitment(h.Core, h.Subject)
			case "purpose":
				h.K1 = h.AuthorizationSignature
			case "token":
				h.Core.PreviousToken.Value = "9223372036854775807"
				resign = false
			case "diff":
				h.Subject.Normal.Union.Digest = testID("other diff")
				resign = false
			case "root":
				h.Core.Root.Object = testID("foreign root")
			case "revision":
				h.Core.Revision = testID("other revision")
				resign = false
			case "previous-revision":
				h.Core.PreviousRevision = testID("other predecessor")
				resign = false
			case "previous-digest":
				h.Core.PreviousDigest = testID("other predecessor bytes")
				resign = false
			case "nonbody":
				h.Core.NonBody = testID("other nonbody request")
				resign = false
			case "operation":
				h.Subject.Operation = testID("other operation")
				resign = false
			case "desired-length":
				h.Subject.Normal.Intent.Digest = testID("other intent")
				resign = false
			case "diff-count":
				h.Subject.Normal.Union.Digest = testID("other union")
				resign = false
			}
			storeHead(t, f, h, resign)
			f.trust.signs = 0
			if s, r := Open(context.Background(), f.admission, f.store); s != nil || r.Outcome == ObservedCurrent {
				t.Fatalf("accepted %s: %+v", field, r)
			}
			if f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 {
				t.Fatal("invalid signed binding caused creation, signing or selection")
			}
		})
	}
}
