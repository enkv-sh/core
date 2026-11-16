package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestRetainedMemberEqualityPreservesGeneratedOrigin(t *testing.T) {
	id := generatedVectorID
	value, err := contract.EncodeCanonicalPayload(contract.CanonicalPayload{Profile: 2, CryptoSupportID: id(20), DataKeyID: id(21), DataKeyEpoch: 1,
		CommitmentKeyID: id(22), CommitmentKeyEpoch: 1, Ciphertext: bytes.Repeat([]byte{1}, 16), InputEncoding: contract.InputEncodingRaw, RetainedLength: 0})
	if err != nil {
		t.Fatal(err)
	}
	m := contract.ValueEntry{Name: "generated", Incarnation: id(2), ValueState: id(3), OriginSnapshot: id(4), OriginTransition: id(5), ValueSource: contract.Generated,
		ConfidentialityClass: contract.Secret, Recipients: []contract.ID{id(6)}, ValueBytes: value, Generated: contract.GeneratedEntryMetadata{Schema: contract.GeneratedEntryMetadataSchema, LifecycleMode: contract.GeneratorLifecycleManaged, ConfigContractID: id(7), ResourceContractID: id(8), IntentDigest: id(9),
			ResourceIncarnationID: id(10), OriginOperationID: id(11), OriginAttemptID: id(12), GenerationID: id(3), ResourceDigest: id(14), CreateResultID: id(15),
			CreateEvidence: contract.GeneratorDescriptor{Digest: id(16), Length: 8, Count: 1}, RequiredSupport: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport),
			CompletionClass: 1, RetirementMode: 1}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len(value) - contract.CanonicalPayloadOverhead), RetainedLength: uint32(len(value) - contract.CanonicalPayloadOverhead)}
	if _, err := contract.ValueEntryLength(m); err != nil {
		t.Fatal(err)
	}
	if !sameRetainedEntryValue(m, m) {
		t.Fatal("identical value refused")
	}
	for name, change := range map[string]func(*contract.GeneratedEntryMetadata){
		"config contract":   func(v *contract.GeneratedEntryMetadata) { v.ConfigContractID = id(99) },
		"resource contract": func(v *contract.GeneratedEntryMetadata) { v.ResourceContractID = id(99) },
		"intent":            func(v *contract.GeneratedEntryMetadata) { v.IntentDigest = id(99) },
		"resource":          func(v *contract.GeneratedEntryMetadata) { v.ResourceIncarnationID = id(99) },
		"operation":         func(v *contract.GeneratedEntryMetadata) { v.OriginOperationID = id(99) },
		"attempt":           func(v *contract.GeneratedEntryMetadata) { v.OriginAttemptID = id(99) },
		"lifecycle":         func(v *contract.GeneratedEntryMetadata) { v.LifecycleMode = contract.GeneratorLifecycleNone },
		"resource digest":   func(v *contract.GeneratedEntryMetadata) { v.ResourceDigest = id(99) },
		"evidence":          func(v *contract.GeneratedEntryMetadata) { v.CreateEvidence.Digest = id(99) },
		"support":           func(v *contract.GeneratedEntryMetadata) { v.RequiredSupport.Digest = id(99) },
		"class":             func(v *contract.GeneratedEntryMetadata) { v.CompletionClass++ },
		"epoch":             func(v *contract.GeneratedEntryMetadata) { v.Epoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			other := m
			change(&other.Generated)
			if sameRetainedEntryValue(m, other) {
				t.Fatal("different generated origin accepted")
			}
		})
	}
	other := m
	other.Recipients = []contract.ID{id(6), id(23)}
	other.Generated.RetirementMode = 2
	other.Generated.RetiringDutyPresent, other.Generated.RetiringDutyID = 1, id(24)
	if !sameRetainedEntryValue(m, other) {
		t.Fatal("separate access and retirement state changed immutable equality")
	}
}
