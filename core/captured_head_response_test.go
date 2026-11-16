package core

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestCapturedHeadResponsePreservesNormalValidation(t *testing.T) {
	state, _, store := observationSelectedPredecessor(t)
	original := store.Read(t.Context(), state.admission.store.HeadKey, contract.MaxHeadLength)
	expected, status := state.readAuthenticatedHead(t.Context())
	if status.Outcome != 0 {
		t.Fatal("ordinary control read failed", status)
	}
	actual, status := state.authenticateHeadResponse(t.Context(), original)
	if status.Outcome != 0 || actual.head.Core != expected.head.Core || actual.token != expected.token || !bytes.Equal(actual.body, expected.body) {
		t.Fatal("captured response changed normal authentication", status)
	}
	actual.body[0] ^= 0xff
	if bytes.Equal(actual.body, original.Body) {
		t.Fatal("authenticated body borrowed response bytes")
	}
	for _, condition := range []string{"missing", "invalid", "unavailable", "token", "oversized", "same-token-different-body"} {
		t.Run(condition, func(t *testing.T) {
			read := original
			read.Body = bytes.Clone(original.Body)
			want := IntegrityFailure
			switch condition {
			case "missing":
				read.Status = contract.ReadMissing
				want = RootLossUnsupported
			case "invalid":
				read.Status = contract.ReadInvalid
			case "unavailable":
				read.Status = contract.ReadUnavailable
				read.Reason = contract.ReasonAccess
				want = EvidenceUnavailable
			case "token":
				read.Token = contract.Token{}
			case "oversized":
				read.Body = make([]byte, contract.MaxHeadLength+1)
			case "same-token-different-body":
				read.Body[0] ^= 0xff
			}
			if _, result := state.authenticateHeadResponse(t.Context(), read); result.Outcome != want || condition == "unavailable" && result.StoreReason != contract.ReasonAccess {
				t.Fatal("response validation changed", result)
			}
		})
	}
}
