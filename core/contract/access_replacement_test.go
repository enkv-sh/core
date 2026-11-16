package contract

import "testing"

// full_only: false
func TestAccessReplacementMessageKindAvailable(t *testing.T) {
	if !CryptoKind(6).Valid() {
		t.Fatal("access replacement message kind is unavailable")
	}
}
