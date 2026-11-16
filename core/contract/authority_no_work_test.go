package contract

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// full_only: false
func TestAuthorityNoWorkIdentityBindsExactObservationWithoutMutationPlan(t *testing.T) {
	id := func(n byte) ID { return ID{n} }
	binding := DescriptorVector{Digest: id(10), Length: 123, Count: 2}
	request := AuthorityNoWorkRequestCore{Domain: id(1), Store: id(2), Trust: id(3), Coordinate: id(4), NonBody: id(5), Interpretation: id(6), Epoch: 9,
		PreviousRevision: id(7), PreviousDigest: id(8), PreviousToken: Token{Family: AWS, Value: `"tag"`}, ApprovalRole: 1, Roles: 3, MaterialSubjectKind: 1, Bindings: binding}
	descriptor := func(out []byte, d DescriptorVector) []byte {
		out = append(out, d.Digest[:]...)
		out = binary.BigEndian.AppendUint64(out, d.Length)
		return binary.BigEndian.AppendUint32(out, d.Count)
	}
	body := []byte("ENKV/AUTHORITY-NO-WORK-REQUEST/v1\x00")
	for _, value := range []ID{id(1), id(2), id(3), id(4), id(5), id(6)} {
		body = append(body, value[:]...)
	}
	body = binary.BigEndian.AppendUint64(body, 9)
	for _, value := range []ID{id(7), id(8)} {
		body = append(body, value[:]...)
	}
	body = append(body, 1)
	body = binary.BigEndian.AppendUint32(body, 5)
	body = append(body, []byte(`"tag"`)...)
	body = append(body, 1, 3, 1)
	body = descriptor(body, binding)
	expectedRequest := sha256.Sum256(body)
	digest, err := AuthorityNoWorkRequestDigest(request)
	if err != nil || digest != expectedRequest {
		t.Fatal("independent no-work request preimage", err, digest, expectedRequest)
	}
	observation := AuthorityNoWorkObservation{OperationID: id(11), DomainID: id(1), RequestCoreDigest: digest, HEADRevisionID: id(7), HEADDigest: id(8), TokenDigest: id(12),
		Snapshot: Ref{Kind: RootKind, Format: 11, Domain: id(1), Object: id(13), Digest: id(14), Length: 777}, Bindings: binding, Nonce: id(15)}
	body = []byte("ENKV/NO-WORK-OBSERVATION/v1\x00")
	body = binary.BigEndian.AppendUint16(body, 25)
	for _, value := range []ID{id(11), id(1), expectedRequest, id(7), id(8), id(12)} {
		body = append(body, value[:]...)
	}
	body = append(body, 3)
	body = binary.BigEndian.AppendUint16(body, 11)
	for _, value := range []ID{id(1), id(13), id(14)} {
		body = append(body, value[:]...)
	}
	body = binary.BigEndian.AppendUint32(body, 777)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = descriptor(body, binding)
	nonce := id(15)
	body = append(body, nonce[:]...)
	expected := sha256.Sum256(body)
	actual, err := AuthorityNoWorkObservationIdentity(observation)
	if err != nil || actual != expected {
		t.Fatal("independent no-work observation preimage", err, actual, expected)
	}
	for _, field := range []string{"operation", "domain", "request", "head revision", "head digest", "token", "snapshot identity", "snapshot digest", "bindings", "nonce"} {
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
			case "bindings":
				changed.Bindings.Digest = id(90)
			case "nonce":
				changed.Nonce = id(90)
			}
			got, err := AuthorityNoWorkObservationIdentity(changed)
			if err != nil || got == actual {
				t.Fatal("changed observation pin lost", err)
			}
		})
	}
	if _, err := AuthorityNoWorkObservationIdentity(AuthorityNoWorkObservation{}); err == nil {
		t.Fatal("incomplete observation admitted")
	}
	changed := request
	changed.MaterialSubjectKind = 0
	if _, err := AuthorityNoWorkRequestDigest(changed); err == nil {
		t.Fatal("missing fixed material source admitted")
	}
	apply, err := SuppliedApplyNoWorkObservationIdentity(SuppliedApplyNoWorkObservation{OperationID: observation.OperationID, DomainID: observation.DomainID, RequestCoreDigest: observation.RequestCoreDigest,
		HEADRevisionID: observation.HEADRevisionID, HEADDigest: observation.HEADDigest, TokenDigest: observation.TokenDigest, Snapshot: observation.Snapshot, Comparison: observation.Bindings, Nonce: observation.Nonce})
	if err != nil || apply == actual {
		t.Fatal("different closed operation reused Authority identity", err)
	}
}
