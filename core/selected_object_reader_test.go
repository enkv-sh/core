package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestSelectedObjectReaderPreservesCachedAndUncachedContextOrder(t *testing.T) {
	domain := contract.Hash([]byte("selected object domain"))
	body := []byte("immutable selected body")
	ref := format.Ref{Domain: domain, Length: uint32(len(body)), Digest: contract.Hash(body)}
	s := &StateSession{admission: openAdmission{domain: domain}, cache: map[format.Ref][]byte{ref: body}}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		got, result := s.readObject(ctx, ref)
		if result.Outcome != 0 || !bytes.Equal(got, body) {
			t.Fatal("exact cache changed context order", result)
		}
		if len(got) > 0 && &got[0] != &body[0] {
			t.Fatal("cache ownership changed")
		}
		got, result = s.readObjectUncached(ctx, ref)
		if got != nil || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable {
			t.Fatal("uncached context refusal changed", result)
		}
		other := ref
		other.Domain = contract.Hash([]byte("other domain"))
		got, result = s.readObject(ctx, other)
		if got != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidReference {
			t.Fatal("ordinary domain refusal changed precedence", result)
		}
	}
}
