package contract

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	outputprotocol "enkv.sh/sdk/protocols/output"
)

func publicationContractVectorID(t *testing.T, text string) ID {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != 32 {
		t.Fatal("invalid independent contract digest literal", err)
	}
	return ID(b)
}

// full_only: false
func TestPublicationContractDigests(t *testing.T) {
	// Independent Python hashlib/struct literals: UTF8 blob32 identity,
	// wire4 semantic request, then wire/result/evidence schema roles 4/1/3.
	protocol := publicationContractVectorID(t, "c0432dd35c122a5bf0b44a58234ef9aef0a2cbeb48acd2169f4bc027f322dcf2")
	config := publicationContractVectorID(t, "73a7d313254227a07dcc88482fba1ca4080c8c3772a4df4d8245a588e8654812")
	artifact := publicationContractVectorID(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	for _, vector := range []struct{ preimage, digest string }{{"454e4b562f4f55545055542f434f4e4649472d434f4e54524143542f7631000000000e707269766174652d636f6e666967", "73a7d313254227a07dcc88482fba1ca4080c8c3772a4df4d8245a588e8654812"}, {"454e4b562f4f55545055542f524551554553542d434f4e54524143542f763200c0432dd35c122a5bf0b44a58234ef9aef0a2cbeb48acd2169f4bc027f322dcf273a7d313254227a07dcc88482fba1ca4080c8c3772a4df4d8245a588e86548120000000f707269766174652d736572766963650000000e707269766174652d74617267657403", "da8e6d7a8a2bf95cd54b53f668bd61bd52dd2b60795f5b8a0ae59be664581d6d"}, {"454e4b562f4f55545055542f524553504f4e53452d434f4e54524143542f763200da8e6d7a8a2bf95cd54b53f668bd61bd52dd2b60795f5b8a0ae59be664581d6d000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000600010003", "ff1312f94467a5b6b997f73abecbae799d4e18c6ab81d76d1aa9133da9f5dfe8"}} {
		body, err := hex.DecodeString(vector.preimage)
		if err != nil || ID(sha256.Sum256(body)) != publicationContractVectorID(t, vector.digest) {
			t.Fatal("independent literal", err)
		}
	}
	gotConfig, err := OutputConfigContractDigest("private-config")
	if err != nil || gotConfig != config {
		t.Fatal("configuration identity", err)
	}
	got, err := PublicationRequestContractDigest(protocol, config, "private-service", "private-target", PublicationWriteValue)
	if err != nil || got != publicationContractVectorID(t, "da8e6d7a8a2bf95cd54b53f668bd61bd52dd2b60795f5b8a0ae59be664581d6d") {
		t.Fatal("request contract", err)
	}
	response, err := PublicationResponseContractDigest(got, artifact)
	if err != nil || response != publicationContractVectorID(t, "ff1312f94467a5b6b997f73abecbae799d4e18c6ab81d76d1aa9133da9f5dfe8") {
		t.Fatal("response contract", err)
	}
	seen := make(map[ID]bool)
	for action := PublicationCreateEmpty; action <= PublicationDeleteReservedSlot; action++ {
		digest, err := PublicationRequestContractDigest(protocol, config, "private-service", "private-target", action)
		if err != nil || seen[digest] {
			t.Fatal("action identity", err)
		}
		seen[digest] = true
	}
	for _, change := range []struct {
		config          ID
		service, target string
	}{{publicationTestID(99), "private-service", "private-target"}, {config, "other", "private-target"}, {config, "private-service", "other"}} {
		other, err := PublicationRequestContractDigest(protocol, change.config, change.service, change.target, PublicationWriteValue)
		if err != nil || other == got {
			t.Fatal("semantic input omitted", err)
		}
		if digest, err := PublicationResponseContractDigest(other, artifact); err != nil || digest == response {
			t.Fatal("response request input omitted", err)
		}
	}
	artifact[0] ^= 1
	if digest, err := PublicationResponseContractDigest(got, artifact); err != nil || digest == response {
		t.Fatal("artifact input omitted", err)
	}
}

// full_only: false
func TestPublicationContractDigestRefusesInvalidInputs(t *testing.T) {
	protocol := publicationContractVectorID(t, "c0432dd35c122a5bf0b44a58234ef9aef0a2cbeb48acd2169f4bc027f322dcf2")
	config := publicationTestID(1)
	for _, bad := range []string{"", strings.Repeat("x", 257), string([]byte{255})} {
		if _, err := OutputConfigContractDigest(bad); err == nil {
			t.Fatal("invalid config identity")
		}
		if _, err := PublicationRequestContractDigest(protocol, config, bad, "target", 1); err == nil {
			t.Fatal("invalid service")
		}
		if _, err := PublicationRequestContractDigest(protocol, config, "service", bad, 1); err == nil {
			t.Fatal("invalid target")
		}
	}
	for _, action := range []uint8{0, 7, 255} {
		if _, err := PublicationRequestContractDigest(protocol, config, "service", "target", action); err == nil {
			t.Fatal("unknown action")
		}
	}
	for _, wrong := range []ID{{}, publicationTestID(1)} {
		if _, err := PublicationRequestContractDigest(wrong, config, "service", "target", 1); err == nil {
			t.Fatal("wrong protocol")
		}
	}
	if _, err := PublicationRequestContractDigest(protocol, ID{}, "service", "target", 1); err == nil {
		t.Fatal("zero config digest")
	}
	for _, ids := range [][2]ID{{{}, {}}, {{}, protocol}, {protocol, {}}} {
		if digest, err := PublicationResponseContractDigest(ids[0], ids[1]); err == nil || !digest.IsZero() {
			t.Fatal("zero request/artifact")
		}
	}
}

// full_only: false
func TestPublicationContractAdmitsUnregisteredSemanticContracts(t *testing.T) {
	protocol := publicationContractVectorID(t, "c0432dd35c122a5bf0b44a58234ef9aef0a2cbeb48acd2169f4bc027f322dcf2")
	for _, identity := range []string{"private-local/v1", "αβ", strings.Repeat("x", 256)} {
		config, err := OutputConfigContractDigest(identity)
		if err != nil {
			t.Fatal(err)
		}
		for action := PublicationCreateEmpty; action <= PublicationDeleteReservedSlot; action++ {
			if digest, err := PublicationRequestContractDigest(protocol, config, identity, identity, action); err != nil || digest.IsZero() {
				t.Fatal("bounded unknown semantic contract refused", err)
			}
		}
	}
}

// full_only: false
func TestPublicationResponseContractBindsAdmittedSchemas(t *testing.T) {
	request, artifact := publicationTestID(1), publicationTestID(2)
	result := outputprotocol.Result{DomainID: outputprotocol.ID(publicationTestID(3)), OperationID: outputprotocol.ID(publicationTestID(4)),
		AttemptID: outputprotocol.ID(publicationTestID(5)), CoordinateID: outputprotocol.ID(publicationTestID(6)),
		ProjectionCommitment: outputprotocol.ID(publicationTestID(7)), DispatchContextDigest: outputprotocol.ID(publicationTestID(8)),
		ResponseContractDigest: outputprotocol.ID(request), Entry: outputprotocol.EntryNotEntered, Class: outputprotocol.ClassQualifiedNoEffect}
	evidence := PublicationEvidence{ResponseContractDigest: request, Entry: PublicationNotEntered, Class: PublicationQualifiedNoEffect}
	var resultSchema, evidenceSchema uint16
	var resultCount, evidenceCount int
	for schema := range uint16(16) {
		result.Schema, evidence.Schema = schema, schema
		if result.Valid() {
			resultSchema, resultCount = schema, resultCount+1
		}
		if _, err := EncodePublicationEvidence(evidence); err == nil {
			evidenceSchema, evidenceCount = schema, evidenceCount+1
		}
	}
	if resultCount != 1 || evidenceCount != 1 {
		t.Fatal("response owners did not admit one exact schema", resultCount, evidenceCount)
	}
	// Independent response-contract framing uses the schemas the actual
	// structural owners admit, without the contract digest implementation.
	preimage := []byte("ENKV/OUTPUT/RESPONSE-CONTRACT/v2\x00")
	preimage = append(preimage, request[:]...)
	preimage = append(preimage, artifact[:]...)
	preimage = binary.BigEndian.AppendUint16(preimage, uint16(outputprotocol.Version))
	preimage = binary.BigEndian.AppendUint16(preimage, resultSchema)
	preimage = binary.BigEndian.AppendUint16(preimage, evidenceSchema)
	got, err := PublicationResponseContractDigest(request, artifact)
	if err != nil || got != ID(sha256.Sum256(preimage)) {
		t.Fatal("response identity omitted an admitted schema", err)
	}
}
