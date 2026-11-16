package custody

import (
	"bytes"
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestSyntheticGeneratedCompleteResponseHasExactPublicFacts(t *testing.T) {
	var resource, token contract.ID
	for i := range resource {
		resource[i] = byte(i)
	}
	copy(token[:], "000102030405060708090a0b0c0d0e0f")
	intent, request := contract.Hash([]byte("independent intent")), contract.Hash([]byte("independent request"))
	expected := contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: contract.GeneratorAttemptTemplate{ResourceIncarnationID: resource, LifecycleMode: contract.GeneratorLifecycleManaged, ResourceContractID: contract.ID{9}, IntentDigest: intent}, RequestDigest: request}
	got := syntheticGeneratedCompleteReturn(expected, SyntheticCloudflareValue)
	defer clear(got.Secret)
	body, err := contract.EncodeGeneratorSafeFacts(got.Facts)
	decoded, decodeErr := contract.DecodeGeneratorSafeFacts(body)
	if err != nil || decodeErr != nil || !bytes.Equal(got.Secret, []byte("Generated_secret_0123456789_ABCDEFGHIJKLMN")) || !bytes.Equal(decoded.ResourceData, token[:]) || !bytes.Equal(decoded.Target, []byte("synthetic-service/target")) || !bytes.Equal(decoded.ProviderFacts, []byte{31}) || decoded.Action != contract.GeneratorActionCreate || decoded.LifecycleMode != contract.GeneratorLifecycleManaged || decoded.ResourceContractID != (contract.ID{9}) || decoded.RequestDigest != request || decoded.IntentDigest != intent || decoded.Disposition != contract.GeneratorDispositionCompleteCreate || decoded.Reason != 0 {
		t.Fatal("synthetic public facts or private value changed", err, decodeErr)
	}
	for _, b := range got.Facts.ResourceData {
		if b < '0' || b > '9' && b < 'a' || b > 'f' {
			t.Fatal("synthetic resource is not lowercase ASCII hex")
		}
	}
	generic := syntheticGeneratedCompleteReturn(expected, StandardValue)
	defer clear(generic.Secret)
	if !bytes.Equal(generic.Facts.ResourceData, resource[:]) || !bytes.Equal(generic.Facts.ProviderFacts, []byte{3}) {
		t.Fatal("generic public resource facts changed")
	}
}
