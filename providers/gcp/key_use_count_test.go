package gcp

import (
	"fmt"
	"testing"

	enkvcrypto "enkv.sh/crypto"
)

// full_only: false
func TestKeyUseCountsClassifyOneEnteredCall(t *testing.T) {
	for _, status := range []enkvcrypto.KeyStatus{0, enkvcrypto.KeyOK, enkvcrypto.KeyDenied, enkvcrypto.KeyInvalid, enkvcrypto.KeyUnavailable, enkvcrypto.KeyUnknown, enkvcrypto.KeyCancelled, enkvcrypto.KeyAuthenticationFailed, 255} {
		for _, attempts := range []uint32{0, 1, 2} {
			t.Run(fmt.Sprintf("status-%d/attempts-%d", status, attempts), func(t *testing.T) {
				got := enkvcrypto.KeyUses{Completed: 2, Denied: 3, Failed: 5, Unknown: 7}
				want := got
				if attempts != 0 {
					switch status {
					case enkvcrypto.KeyOK:
						want.Completed++
					case enkvcrypto.KeyDenied:
						want.Denied++
					case enkvcrypto.KeyInvalid, enkvcrypto.KeyAuthenticationFailed:
						want.Failed++
					default:
						want.Unknown++
					}
				}
				got.Record(attempts, status)
				if got != want {
					t.Fatalf("uses=%+v want=%+v", got, want)
				}
			})
		}
	}
}
