package contract

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func profileLiteralID(t *testing.T, text string) ID {
	t.Helper()
	body, err := hex.DecodeString(text)
	if err != nil || len(body) != 32 {
		t.Fatal("invalid independent identity")
	}
	return ID(body)
}

func localFactsFixture(t *testing.T) GeneratorSafeFacts {
	t.Helper()
	return GeneratorSafeFacts{Schema: GeneratorSafeFactsSchema, Action: GeneratorActionCreate, LifecycleMode: GeneratorLifecycleNone, Disposition: GeneratorDispositionCompleteCreate,
		RequestDigest: profileLiteralID(t, "ffc883f26ef97ff2caaa3df3acf8ec0d2dc87492741ade34fe3e1e109f7158cb"),
		IntentDigest:  profileLiteralID(t, "ab515aa74c9c7704485fecc716c8686a955b8731a9194ad0e46c2d0691db1336")}
}

// full_only: false
func TestLocalGeneratorFactsIndependentBytesAndDomain(t *testing.T) {
	// Python struct/hashlib: u16(4), create(1), none(1), complete(1), reason(0),
	// the two listed IDs, zero resource ID, three empty blob32 fields and tag0.
	v := localFactsFixture(t)
	body, err := EncodeGeneratorSafeFacts(v)
	if err != nil || len(body) != 115 || Hash(body) != profileLiteralID(t, "f344d5897828292246514410a21391b3e3615949e18f7f9832807dfb92835e26") {
		t.Fatal("local facts differ from independent bytes", err)
	}
	digest, err := GeneratorSafeFactsDigest(v)
	if err != nil || digest != profileLiteralID(t, "9f3559dd044f890622dda1228c5d01ac5622b86699dc2fde1f90829fd968aa25") {
		t.Fatal("local facts domain differs", err)
	}
	decoded, err := DecodeGeneratorSafeFacts(body)
	if err != nil || decoded.LifecycleMode != GeneratorLifecycleNone || decoded.RequestDigest != v.RequestDigest || decoded.IntentDigest != v.IntentDigest {
		t.Fatal("local facts round trip", err)
	}
	for _, change := range []func(*GeneratorSafeFacts){
		func(v *GeneratorSafeFacts) { v.ResourceContractID = generatedRecordID(1) },
		func(v *GeneratorSafeFacts) { v.ResourceData = []byte{2} },
		func(v *GeneratorSafeFacts) { v.Target = []byte("foreign") },
		func(v *GeneratorSafeFacts) { v.LifecycleMode = 3 },
		func(v *GeneratorSafeFacts) { v.Disposition = GeneratorDispositionUnknown },
		func(v *GeneratorSafeFacts) { v.Reason = GeneratorReasonMalformed },
	} {
		bad := v
		change(&bad)
		if _, err := EncodeGeneratorSafeFacts(bad); err == nil {
			t.Fatal("foreign local facts accepted")
		}
	}
	for cut := range len(body) {
		if _, err := InspectGeneratorSafeFacts(body[:cut]); err == nil {
			t.Fatal("truncated local facts accepted", cut)
		}
	}
	if _, err := InspectGeneratorSafeFacts(append(bytes.Clone(body), 0)); err == nil {
		t.Fatal("facts suffix accepted")
	}
}

func localResultCoreFixture(t *testing.T) GeneratedResultCore {
	t.Helper()
	return GeneratedResultCore{Schema: GeneratedResultCoreSchema, Profile: 2, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2), MaterialID: generatedRecordID(12),
		UsePlanDigest: generatedRecordID(13), PlanGraphID: generatedRecordID(4), AttemptID: generatedRecordID(6), TransmissionID: generatedRecordID(7), ResultID: generatedRecordID(8), ExecutorID: generatedRecordID(11),
		DescriptorID:     profileLiteralID(t, "096d1b26d67392e9fadaa38d3ffc8c35a967547b93fa21e40ba435a9d3192d96"),
		ConfigContractID: profileLiteralID(t, "411d73deb317b8c2fde83ca36dc36970c4c0798308be6e6f09e0d3728125e85a"),
		ResultContractID: profileLiteralID(t, "34ab33cedd1401bc91f0bb89aca50adeae1c7fadadcba19685f8777b4b9ce754"),
		RequestDigest:    profileLiteralID(t, "ffc883f26ef97ff2caaa3df3acf8ec0d2dc87492741ade34fe3e1e109f7158cb"),
		SafeFactsDigest:  profileLiteralID(t, "9f3559dd044f890622dda1228c5d01ac5622b86699dc2fde1f90829fd968aa25")}
}

// full_only: false
func TestGeneratedResultCoreOwnSchemaIndependentVector(t *testing.T) {
	v := localResultCoreFixture(t)
	body, err := EncodeGeneratedResultCore(v)
	if err != nil || len(body) != 452 || Hash(body) != profileLiteralID(t, "3e5d1681ca629448ea80c00081534433bc920e9868f7d6c9615f91680f59d45f") {
		t.Fatal("result core differs from independent bytes", err)
	}
	got, err := InspectGeneratedResultCore(body)
	if err != nil || got != v {
		t.Fatal("new result core round trip", err)
	}
	for _, schema := range []uint16{2, 10} {
		v.Schema = schema
		if _, err := EncodeGeneratedResultCore(v); err == nil {
			t.Fatal("superseded result schema encoded", schema)
		}
		old := bytes.Clone(body)
		old[0], old[1] = byte(schema>>8), byte(schema)
		if _, err := InspectGeneratedResultCore(old); err == nil {
			t.Fatal("superseded result schema admitted", schema)
		}
	}
}
