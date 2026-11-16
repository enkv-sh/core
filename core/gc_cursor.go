package core

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

const (
	gcCursorTag       = "ENKV/GC-CURSOR/v1\x00"
	GCCursorMaxLength = 5580
)

func gcCursorScopeValid(domain contract.ID, store contract.Descriptor) bool {
	return !domain.IsZero() && store.Valid() && contract.StorePrefixValid(store.Family, store.Prefix)
}

type gcCursorFields struct {
	provider      string
	family        contract.Family
	domain, store contract.ID
}

// DecodeGCCursor checks scope before a composition constructs provider access.
// Empty input selects the first page; the returned token grants no authority.
func DecodeGCCursor(cursor string, domain contract.ID, store contract.Descriptor) (string, error) {
	if !gcCursorScopeValid(domain, store) {
		return "", contract.ErrRecord
	}
	fields, err := decodeGCCursorFields(cursor)
	if err != nil || cursor != "" && (fields.domain != domain || fields.store != administrativeStoreDescriptorDigest(store) || fields.family != store.Family) {
		return "", contract.ErrRecord
	}
	return fields.provider, nil
}

func decodeGCCursorFields(cursor string) (gcCursorFields, error) {
	var fields gcCursorFields
	if len(cursor) > GCCursorMaxLength {
		return fields, contract.ErrRecord
	}
	if cursor == "" {
		return fields, nil
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	const fixed = len(gcCursorTag) + 2 + 1 + 32 + 32 + 4
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != cursor || len(body) < fixed || len(body) > fixed+contract.GCProviderCursorLimit ||
		!bytes.Equal(body[:len(gcCursorTag)], []byte(gcCursorTag)) {
		return fields, contract.ErrRecord
	}
	off := len(gcCursorTag)
	fields.family = contract.Family(body[off+2])
	copy(fields.domain[:], body[off+3:off+35])
	copy(fields.store[:], body[off+35:off+67])
	if binary.BigEndian.Uint16(body[off:]) != 1 || !fields.family.Valid() || fields.domain.IsZero() || fields.store.IsZero() {
		return gcCursorFields{}, contract.ErrRecord
	}
	n := uint64(binary.BigEndian.Uint32(body[off+67:]))
	if n == 0 || n > contract.GCProviderCursorLimit || n != uint64(len(body)-fixed) || !utf8.Valid(body[fixed:]) {
		return gcCursorFields{}, contract.ErrRecord
	}
	fields.provider = string(body[fixed:])
	return fields, nil
}

// EncodeGCCursor wraps only a nonempty bounded provider continuation.
func EncodeGCCursor(providerCursor string, domain contract.ID, store contract.Descriptor) (string, error) {
	if !gcCursorScopeValid(domain, store) || len(providerCursor) > contract.GCProviderCursorLimit || !utf8.ValidString(providerCursor) {
		return "", contract.ErrRecord
	}
	if providerCursor == "" {
		return "", nil
	}
	body := append([]byte(gcCursorTag), 0, 1, byte(store.Family))
	body = append(body, domain[:]...)
	digest := administrativeStoreDescriptorDigest(store)
	body = append(body, digest[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(providerCursor)))
	body = append(body, providerCursor...)
	return base64.RawURLEncoding.EncodeToString(body), nil
}
