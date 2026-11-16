package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicConfigurationProjectionReadsReleasedGeneratedSupport(t *testing.T) {
	s, _, _ := generatedDetachedRetirementState(t, "absent", 0)
	selected, err := s.selectedGeneratedWork(t.Context())
	if err != nil || selected.content.fragmentFacts == nil {
		t.Fatal("authenticated generated fixture", err)
	}
	wantIntent := generatedFixtureCanonicalIntent(t, []byte("{}"), generatedFixtureProfile{
		LifecycleMode: contract.GeneratorLifecycleManaged, ConfigContractID: generatedVectorID(9), ResourceContractID: generatedVectorID(7),
	})
	intent, err := contract.GeneratorIntentDigest(wantIntent)
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.support {
		s.support[i].Records = nil
	}
	s.cache = nil
	got, err := selected.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, intent, contract.GeneratorIntentMaxLength)
	if err != nil || !bytes.Equal(got, wantIntent) {
		t.Fatal("released support did not reread authenticated intent", err)
	}
}

// full_only: false
func TestPublicConfigurationProjectionRejectsPresentShortSupport(t *testing.T) {
	s, _, _ := generatedDetachedRetirementState(t, "absent", 0)
	selected, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	wantIntent := generatedFixtureCanonicalIntent(t, []byte("{}"), generatedFixtureProfile{
		LifecycleMode: contract.GeneratorLifecycleManaged, ConfigContractID: generatedVectorID(9), ResourceContractID: generatedVectorID(7),
	})
	intent, err := contract.GeneratorIntentDigest(wantIntent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := selected.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, intent, contract.GeneratorIntentMaxLength)
	if err != nil || !bytes.Equal(got, wantIntent) {
		t.Fatal("authenticated intent baseline refused", err)
	}
	for i := range s.support {
		s.support[i].Records = make([]contract.SupportRecordView, 0)
	}
	got, err = selected.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, intent, contract.GeneratorIntentMaxLength)
	if err == nil || got != nil {
		t.Fatal("present short selected page was silently reread")
	}
}
