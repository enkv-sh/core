package contract

import (
	"encoding/hex"
	"testing"
)

// Fixed schema11 observation hashes use independent big-endian framing and
// SHA-256. The recorded derivation limits are in tests/shared/testdata/README.md.
// full_only: false
func TestSuppliedApplyNoWorkIdentityHasIndependentCanonicalPreimage(t *testing.T) {
	id := func(n byte) ID { return ID{n} }
	intent := DescriptorVector{Digest: id(10), Length: 882, Count: 1}
	basis, err := SuppliedApplyNoWorkBasis(id(1), intent, DescriptorVector{Digest: id(11), Length: 200, Count: 1}, nil)
	if err != nil || basis.Length != 201 || basis.Count != 1 || hex.EncodeToString(basis.Digest[:]) != "96e7df53d8fb3cdfb73531d5b06fdae94c82f0fd72b922a4cceb4f7e895396f0" {
		t.Fatal("no-work complete comparison preimage differs", err, basis)
	}
	request := SuppliedApplyNoWorkRequestCore{Domain: id(1), Store: id(2), Trust: id(3), Coordinate: id(4), NonBody: id(5), Interpretation: id(6), Epoch: 9,
		PreviousRevision: id(7), PreviousDigest: id(8), PreviousToken: Token{Family: AWS, Value: "\"tag\""}, Intent: intent}
	digest, err := SuppliedApplyNoWorkRequestDigest(request)
	if err != nil || hex.EncodeToString(digest[:]) != "186c34ae82f9781197b88e38c102b85b89811a2a1b3ef95fe0ce5480f7024a1a" {
		t.Fatal("no-plan request-core preimage differs", err, digest)
	}
	observation := SuppliedApplyNoWorkObservation{OperationID: id(12), DomainID: id(1), RequestCoreDigest: digest, HEADRevisionID: id(7), HEADDigest: id(8), TokenDigest: id(13),
		Snapshot: Ref{Kind: RootKind, Format: CanonicalSchema, Domain: id(1), Object: id(14), Digest: id(15), Length: 123}, Comparison: basis, Nonce: id(16)}
	identity, err := SuppliedApplyNoWorkObservationIdentity(observation)
	if err != nil || hex.EncodeToString(identity[:]) != "df7593500d6284a17bf06374848e50e9510c8cfc514478b73f266a5b73f0d39d" {
		t.Fatal("NoWorkObservationIdentity/v1 preimage differs", err, identity)
	}
	// These literals were calculated from independent big-endian field
	// concatenation: 201-byte basis, 357-byte request and 403-byte observation.
	for _, field := range []string{"operation", "domain", "request core", "head revision", "head digest", "token", "snapshot identity", "snapshot digest", "comparison", "nonce"} {
		t.Run(field, func(t *testing.T) {
			changed := observation
			switch field {
			case "operation":
				changed.OperationID = id(90)
			case "domain":
				changed.DomainID, changed.Snapshot.Domain = id(90), id(90)
			case "request core":
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
			case "comparison":
				changed.Comparison.Digest = id(90)
			case "nonce":
				changed.Nonce = id(90)
			}
			other, err := SuppliedApplyNoWorkObservationIdentity(changed)
			if err != nil || other == identity {
				t.Fatal("changed observation field lost its binding", err)
			}
		})
	}
	for _, changed := range []SuppliedApplyNoWorkObservation{{}, {OperationID: observation.OperationID, DomainID: observation.DomainID}, func() SuppliedApplyNoWorkObservation { v := observation; v.Nonce = ID{}; return v }()} {
		if _, err := SuppliedApplyNoWorkObservationIdentity(changed); err == nil {
			t.Fatal("incomplete no-work identity accepted")
		}
	}
	if _, err := SuppliedApplyNoWorkBasis(id(1), intent, DescriptorVector{Digest: id(11), Length: 200, Count: 1}, []CryptoComparisonRow{{Relation: CryptoChanged, BeforePresent: true, AfterPresent: true}}); err == nil {
		t.Fatal("changed secret relation became an empty-work basis")
	}
	for _, length := range []uint64{215, ^uint64(0)} {
		bad := intent
		bad.Length = length
		if _, err := SuppliedApplyNoWorkBasis(id(1), bad, DescriptorVector{Digest: id(11), Length: 200, Count: 1}, nil); err == nil {
			t.Fatal("no-work accepted value-only or oversized intent")
		}
		request.Intent = bad
		if _, err := SuppliedApplyNoWorkRequestDigest(request); err == nil {
			t.Fatal("no-work request accepted value-only or oversized intent")
		}
	}
}
