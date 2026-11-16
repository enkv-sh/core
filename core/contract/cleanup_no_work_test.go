package contract

import (
	"encoding/hex"
	"testing"
)

// Fixed schema11 observation hashes use independent big-endian framing and
// SHA-256. The recorded derivation limits are in tests/shared/testdata/README.md.
// full_only: false
func TestCleanupNoWorkIdentityBindsCompleteBacklogAndEmptyEligibleSelection(t *testing.T) {
	id := func(n byte) ID { return ID{n} }
	// Independent Python hashlib and big-endian field concatenation produced
	// the 110-byte basis, 350-byte request and 403-byte observation literals.
	// Three hundred retained rows are valid: eligible work, not backlog, is zero.
	basis, err := CleanupNoWorkBasis(id(1), DescriptorVector{Digest: id(10), Length: 4096, Count: 300})
	if err != nil || basis.Length != 110 || basis.Count != 0 || hex.EncodeToString(basis.Digest[:]) != "05e260f96bc9949e6c4cbf60b9d812e899b3eef2aa8f1d58c8cb635ab872b9f5" {
		t.Fatal("cleanup empty-eligible basis differs from independent preimage", err, basis)
	}
	request := CleanupNoWorkRequestCore{Domain: id(1), Store: id(2), Trust: id(3), Coordinate: id(4), NonBody: id(5), Interpretation: id(6), Epoch: 9,
		PreviousRevision: id(7), PreviousDigest: id(8), PreviousToken: Token{Family: AWS, Value: "\"tag\""}, WorkBasis: basis}
	digest, err := CleanupNoWorkRequestDigest(request)
	if err != nil || hex.EncodeToString(digest[:]) != "fbd8e50f0ed4e422c185d7de09b4af307a58fb46c47574b3ff30ddc3f16f57fb" {
		t.Fatal("cleanup no-work request differs from independent preimage", err, digest)
	}
	observation := CleanupNoWorkObservation{OperationID: id(12), DomainID: id(1), RequestCoreDigest: digest, HEADRevisionID: id(7), HEADDigest: id(8), TokenDigest: id(13),
		Snapshot: Ref{Kind: RootKind, Format: CanonicalSchema, Domain: id(1), Object: id(14), Digest: id(15), Length: 123}, WorkBasis: basis, Nonce: id(16)}
	identity, err := CleanupNoWorkObservationIdentity(observation)
	if err != nil || hex.EncodeToString(identity[:]) != "0a03aa72d6078d47e95b322779c568a1c4beef0f1155beeace8eca1ff462ae29" {
		t.Fatal("cleanup NoWorkObservationIdentity differs from independent preimage", err, identity)
	}
	for _, field := range []string{"operation", "domain", "request", "head revision", "head digest", "token", "snapshot identity", "snapshot digest", "basis", "nonce"} {
		t.Run(field, func(t *testing.T) {
			changed := observation
			switch field {
			case "operation":
				changed.OperationID = id(90)
			case "domain":
				changed.DomainID, changed.Snapshot.Domain = id(90), id(90)
			case "request":
				changed.RequestCoreDigest = id(90)
			case "head revision":
				changed.HEADRevisionID = id(90)
			case "head digest":
				changed.HEADDigest = id(90)
			case "token":
				changed.TokenDigest = id(90)
			case "snapshot identity":
				changed.Snapshot.Object = id(90)
			case "snapshot digest":
				changed.Snapshot.Digest = id(90)
			case "basis":
				changed.WorkBasis.Digest = id(90)
			case "nonce":
				changed.Nonce = id(90)
			}
			other, err := CleanupNoWorkObservationIdentity(changed)
			if err != nil || other == identity {
				t.Fatal("cleanup no-work identity omitted exact observation field", err)
			}
		})
	}
	for _, changed := range []CleanupNoWorkObservation{{}, func() CleanupNoWorkObservation { v := observation; v.WorkBasis.Count = 1; return v }(), func() CleanupNoWorkObservation { v := observation; v.Nonce = ID{}; return v }()} {
		if _, err := CleanupNoWorkObservationIdentity(changed); err == nil {
			t.Fatal("incomplete or nonempty eligible selection admitted as no work")
		}
	}
	other, err := CleanupNoWorkBasis(id(1), DescriptorVector{Digest: id(11), Length: 4096, Count: 300})
	if err != nil || other == basis {
		t.Fatal("empty eligible basis omitted complete retained work", err)
	}
}
