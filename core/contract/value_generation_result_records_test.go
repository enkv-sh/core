package contract

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func generatedResultCoreFixture() GeneratedResultCore {
	return GeneratedResultCore{Schema: GeneratedResultCoreSchema, Profile: 2, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
		MaterialID: generatedRecordID(3), UsePlanDigest: generatedRecordID(4), PlanGraphID: generatedRecordID(5),
		AttemptID: generatedRecordID(6), TransmissionID: generatedRecordID(7), ResultID: generatedRecordID(8),
		ExecutorID: generatedRecordID(9), DescriptorID: generatedRecordID(10), ConfigContractID: generatedRecordID(11),
		ResultContractID: generatedRecordID(12), RequestDigest: generatedRecordID(13), SafeFactsDigest: generatedRecordID(14)}
}

// full_only: false
func TestGeneratedResultCoreIndependentBytes(t *testing.T) {
	// Two big-endian u16 values followed by fourteen repeated-byte IDs.
	wantHex := "00040002"
	for i := byte(1); i <= 14; i++ {
		wantHex += strings.Repeat(hex.EncodeToString([]byte{i}), 32)
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	core := generatedResultCoreFixture()
	got, err := EncodeGeneratedResultCore(core)
	if err != nil || len(got) != 452 || !bytes.Equal(got, want) {
		t.Fatalf("core encoding: %d %v", len(got), err)
	}
	parsed, err := InspectGeneratedResultCore(want)
	if err != nil || parsed != core {
		t.Fatalf("core inspection: %v", err)
	}
	for n := range want {
		if _, err := InspectGeneratedResultCore(want[:n]); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	for _, offset := range []int{0, 2, 4, 36, 68, 100, 132, 164, 196, 228, 260, 292, 324, 356, 388, 420} {
		damaged := bytes.Clone(want)
		if offset < 4 {
			damaged[offset+1] = 99
		} else {
			clear(damaged[offset : offset+32])
		}
		if _, err := InspectGeneratedResultCore(damaged); err == nil {
			t.Fatalf("accepted changed field %d", offset)
		}
	}
	if _, err := InspectGeneratedResultCore(append(want, 0)); err == nil {
		t.Fatal("accepted trailing bytes")
	}
}

func generatedSafeFactsFixture(disposition uint8) GeneratorSafeFacts {
	f := GeneratorSafeFacts{Schema: GeneratorSafeFactsSchema, Action: GeneratorActionCreate, LifecycleMode: GeneratorLifecycleManaged, Disposition: disposition,
		ResourceContractID: generatedRecordID(9), Target: []byte("account/target"), ResourceData: []byte{0, 255, 2}, ProviderFacts: []byte{},
		RequestDigest: generatedRecordID(3), IntentDigest: generatedRecordID(4)}
	switch disposition {
	case GeneratorDispositionOwnedUnusableCreate:
		f.Reason = GeneratorReasonMissingValue
	case GeneratorDispositionConfirmedNoEffect:
		f.Target, f.ResourceData = []byte{}, []byte{}
	case GeneratorDispositionRetirementAcknowledged:
		f.Action = GeneratorActionDelete
	case GeneratorDispositionUnknown:
		f.Reason = GeneratorReasonTransport
	case GeneratorDispositionScopedUnusability, GeneratorDispositionContinuedUsability, GeneratorDispositionConflictingBinding:
		f.Action = GeneratorActionDelete
		f.ScopeID, f.PrecedingResultID, f.PrecedingResultBodyDigest = generatedRecordID(21), generatedRecordID(22), generatedRecordID(23)
		f.ObservedResourceID, f.ObservedResourceDigest, f.ObservedScopeID = generatedRecordID(24), generatedRecordID(25), f.ScopeID
	}
	return f
}

// full_only: false
func TestGeneratorSafeFactsClosedPredicates(t *testing.T) {
	for disposition := uint8(1); disposition <= 8; disposition++ {
		f := generatedSafeFactsFixture(disposition)
		b, err := EncodeGeneratorSafeFacts(f)
		if err != nil {
			t.Fatal(disposition, err)
		}
		parsed, err := DecodeGeneratorSafeFacts(b)
		if err != nil || parsed.Disposition != disposition {
			t.Fatal(disposition, err)
		}
		for n := range b {
			if _, err := InspectGeneratorSafeFacts(b[:n]); err == nil {
				t.Fatalf("accepted truncation %d/%d", disposition, n)
			}
		}
		if _, err := InspectGeneratorSafeFacts(append(b, 0)); err == nil {
			t.Fatal("accepted trailing facts")
		}
	}
	for name, change := range map[string]func(*GeneratorSafeFacts){
		"schema":                 func(f *GeneratorSafeFacts) { f.Schema++ },
		"action":                 func(f *GeneratorSafeFacts) { f.Action = 0 },
		"lifecycle":              func(f *GeneratorSafeFacts) { f.LifecycleMode = 0 },
		"disposition":            func(f *GeneratorSafeFacts) { f.Disposition = 9 },
		"reason":                 func(f *GeneratorSafeFacts) { f.Reason = 255 },
		"missing request":        func(f *GeneratorSafeFacts) { f.RequestDigest = ID{} },
		"missing intent":         func(f *GeneratorSafeFacts) { f.IntentDigest = ID{} },
		"missing contract":       func(f *GeneratorSafeFacts) { f.ResourceContractID = ID{} },
		"missing target":         func(f *GeneratorSafeFacts) { f.Target = nil },
		"missing resource":       func(f *GeneratorSafeFacts) { f.ResourceData = nil },
		"unexpected observation": func(f *GeneratorSafeFacts) { f.ScopeID = generatedRecordID(21) },
		"aggregate":              func(f *GeneratorSafeFacts) { f.ProviderFacts = make([]byte, 3981) },
	} {
		t.Run(name, func(t *testing.T) {
			f := generatedSafeFactsFixture(GeneratorDispositionCompleteCreate)
			change(&f)
			if _, err := EncodeGeneratorSafeFacts(f); err == nil {
				t.Fatal("accepted invalid facts")
			}
		})
	}
	unknown := generatedSafeFactsFixture(GeneratorDispositionUnknown)
	unknown.ProviderFacts = []byte{0, 255, 1, 2}
	b, err := EncodeGeneratorSafeFacts(unknown)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectGeneratorSafeFacts(b)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	clear(b)
	if !bytes.Equal(owned.ProviderFacts, unknown.ProviderFacts) || !bytes.Equal(owned.Target, unknown.Target) || !bytes.Equal(owned.ResourceData, unknown.ResourceData) {
		t.Fatal("facts did not own input")
	}
	if _, err := view.Own(); err == nil {
		t.Fatal("modified borrowed facts accepted")
	}
}
