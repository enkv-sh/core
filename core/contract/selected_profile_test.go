package contract

import "testing"

// full_only: false
func TestFirstFlowClosedOperationKinds(t *testing.T) {
	for n := 0; n <= 255; n++ {
		if got, want := CryptoKind(n).Valid(), n >= 1 && n <= 7; got != want {
			t.Fatalf("kind %d admitted=%v", n, got)
		}
	}
	if !ValidatePublicEntryTags(Generated, Secret) || ValidatePublicEntryTags(Generated, Plain) {
		t.Fatal("generated member encoding relation")
	}
	if err := cryptoIntentFieldsValid(CryptoIntentRow{ValueSource: Generated, ConfidentialityClass: Secret, InputEncoding: InputEncodingRaw, RetainedLength: 0, OutputEncoding: OutputEncodingRaw}, 0); err == nil {
		t.Fatal("generated source accepted as a supplied declaration")
	}
	if err := accessRecordHeaderError(CanonicalSchema, 3, Hash([]byte("material")), 1); err != nil {
		t.Fatal("selected operation-seed access record refused", err)
	}
}
