package format

import (
	"crypto/sha256"
	"encoding/binary"

	"enkv.sh/core/contract"
)

// The selected shard bodies remain borrowed during decoding. A field can
// cross one shard boundary; only that small field is copied.
type administrativeShardReader struct {
	parts                     [][]byte
	part, offset, used, total int
	bad                       bool
	next                      func() ([]byte, error)
	err                       error
}

func (r *administrativeShardReader) advance() bool {
	if r.next == nil {
		r.part++
		r.offset = 0
		return r.part < len(r.parts)
	}
	// A source may reuse its response buffer on its next read. No old
	// payload may remain reachable from this reader across that call.
	r.parts = nil
	r.part, r.offset = 0, 0
	part, err := r.next()
	if err != nil || len(part) == 0 {
		r.err, r.bad = err, true
		return false
	}
	r.parts = [][]byte{part}
	return true
}

func (r *administrativeShardReader) remaining() int { return r.total - r.used }
func (r *administrativeShardReader) badFormat()     { r.bad = true }
func (r *administrativeShardReader) take(n int) []byte {
	if r.bad || n < 0 || n > r.remaining() {
		r.bad = true
		return nil
	}
	if n == 0 {
		return nil
	}
	if r.part == len(r.parts) || r.offset == len(r.parts[r.part]) && !r.advance() {
		r.bad = true
		return nil
	}
	if n <= len(r.parts[r.part])-r.offset {
		out := r.parts[r.part][r.offset : r.offset+n]
		r.offset += n
		r.used += n
		return out
	}
	out := make([]byte, n)
	for copied := 0; copied < n; {
		if r.offset == len(r.parts[r.part]) {
			if !r.advance() {
				r.bad = true
				return nil
			}
		}
		step := copy(out[copied:], r.parts[r.part][r.offset:])
		copied += step
		r.offset += step
	}
	r.used += n
	return out
}
func (r *administrativeShardReader) u8() byte {
	b := r.take(1)
	if len(b) != 1 {
		return 0
	}
	return b[0]
}
func (r *administrativeShardReader) u16() uint16 {
	b := r.take(2)
	if len(b) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *administrativeShardReader) u32() uint32 {
	b := r.take(4)
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *administrativeShardReader) u64() uint64 {
	b := r.take(8)
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *administrativeShardReader) id() ID {
	var id ID
	copy(id[:], r.take(32))
	return id
}
func (r *administrativeShardReader) ref() Ref {
	v, _, err := contract.ParseRef(r.take(contract.RefLength), Version)
	if err != nil {
		r.bad = true
	}
	return v
}
func (r *administrativeShardReader) end() bool { return !r.bad && r.used == r.total }

const administrativeShardHeaderLength = 7 + 1 + 32 + 32 + 2 + 2 + 4 + 32 + 4

// AdministrativeIndexShardPayloadLimit excludes the physical shard header.
const AdministrativeIndexShardPayloadLimit = contract.MaxRequiredSupportPageLength - administrativeShardHeaderLength

// AdministrativeIndexShardCount charges exact logical bytes against the
// physical authenticated shard payload. It has no body allocation.
func AdministrativeIndexShardCount(length uint64) (uint32, error) {
	if length == 0 || length > administrativeLogicalMaxLength {
		return 0, ErrFormat
	}
	count := (length + AdministrativeIndexShardPayloadLimit - 1) / AdministrativeIndexShardPayloadLimit
	if count > contract.MaxChildPages {
		return 0, ErrFormat
	}
	return uint32(count), nil
}

// AdministrativeIndexPage is one mandatory authenticated physical shard of a
// canonical logical administrative index. The Ref order is the byte order.
type AdministrativeIndexPage struct {
	Ref  Ref
	Body []byte
}

type administrativeShard struct {
	Domain, LogicalObject, Object, Digest ID
	Index, Count                          uint16
	TotalLength                           uint32
	Payload                               []byte
}

func administrativeShardObject(domain, logical ID, index uint16) ID {
	if index == 0 {
		return logical
	}
	b := make([]byte, 0, 40+64+2)
	b = append(b, "ENKV/admin-index-shard/v1\x00"...)
	b = append(b, domain[:]...)
	b = append(b, logical[:]...)
	b = binary.BigEndian.AppendUint16(b, index)
	return contract.Hash(b)
}

func encodeAdministrativeShard(v administrativeShard) ([]byte, error) {
	if v.Domain.IsZero() || v.LogicalObject.IsZero() || v.Digest.IsZero() ||
		v.Count == 0 || v.Count > contract.MaxChildPages || v.Index >= v.Count ||
		v.Object != administrativeShardObject(v.Domain, v.LogicalObject, v.Index) ||
		v.TotalLength == 0 || int(v.TotalLength) > administrativeLogicalMaxLength ||
		len(v.Payload) == 0 || len(v.Payload) > AdministrativeIndexShardPayloadLimit {
		return nil, ErrFormat
	}
	w := start(byte(contract.AdministrativeIndexKind))
	w.u8(0xff)
	w.id(v.Domain)
	w.id(v.LogicalObject)
	w.u16(v.Index)
	w.u16(v.Count)
	w.u32(v.TotalLength)
	w.id(v.Digest)
	w.blob(v.Payload)
	return w.result()
}

func decodeAdministrativeShard(body []byte) (administrativeShard, error) {
	r := begin(body, byte(contract.AdministrativeIndexKind), contract.MaxRequiredSupportPageLength)
	if r.u8() != 0xff {
		return administrativeShard{}, ErrFormat
	}
	v := administrativeShard{Domain: r.id(), LogicalObject: r.id(), Index: r.u16(), Count: r.u16(), TotalLength: r.u32(), Digest: r.id()}
	v.Object = administrativeShardObject(v.Domain, v.LogicalObject, v.Index)
	v.Payload = r.blob(AdministrativeIndexShardPayloadLimit)
	if !r.end() || v.Domain.IsZero() || v.LogicalObject.IsZero() || v.Digest.IsZero() ||
		v.Count == 0 || v.Count > contract.MaxChildPages || v.Index >= v.Count ||
		v.TotalLength == 0 || int(v.TotalLength) > administrativeLogicalMaxLength ||
		len(v.Payload) == 0 || len(v.Payload) > AdministrativeIndexShardPayloadLimit {
		return administrativeShard{}, ErrFormat
	}
	return v, nil
}

func EncodeAdministrativeIndexPages(v AdministrativeIndex) ([]AdministrativeIndexPage, error) {
	logical, err := EncodeAdministrativeIndex(v)
	if err != nil {
		return nil, err
	}
	shardCount, err := AdministrativeIndexShardCount(uint64(len(logical)))
	if err != nil {
		return nil, ErrFormat
	}
	count := int(shardCount)
	out := make([]AdministrativeIndexPage, count)
	digest := contract.Hash(logical)
	for i := range out {
		start := i * AdministrativeIndexShardPayloadLimit
		end := min(start+AdministrativeIndexShardPayloadLimit, len(logical))
		object := administrativeShardObject(v.Domain, v.Object, uint16(i))
		body, err := encodeAdministrativeShard(administrativeShard{Domain: v.Domain, LogicalObject: v.Object,
			Object: object, Index: uint16(i), Count: uint16(count), TotalLength: uint32(len(logical)),
			Digest: digest, Payload: logical[start:end]})
		if err != nil {
			return nil, err
		}
		ref, err := Reference(contract.AdministrativeIndexKind, v.Domain, object, uint16(i), body)
		if err != nil {
			return nil, err
		}
		out[i] = AdministrativeIndexPage{Ref: ref, Body: body}
	}
	return out, nil
}

func DecodeAdministrativeIndexPages(pages []AdministrativeIndexPage) (AdministrativeIndex, error) {
	if len(pages) == 0 || len(pages) > contract.MaxChildPages {
		return AdministrativeIndex{}, ErrFormat
	}
	first, err := decodeAdministrativeShard(pages[0].Body)
	if err != nil || int(first.Count) != len(pages) ||
		(int(first.TotalLength)+AdministrativeIndexShardPayloadLimit-1)/AdministrativeIndexShardPayloadLimit != len(pages) {
		return AdministrativeIndex{}, ErrFormat
	}
	parts := make([][]byte, 0, len(pages))
	h := sha256.New()
	length := 0
	for i, page := range pages {
		shard, err := decodeAdministrativeShard(page.Body)
		if err != nil || CheckReference(page.Ref, page.Body) != nil || shard.Index != uint16(i) ||
			shard.Count != first.Count || shard.Domain != first.Domain || shard.LogicalObject != first.LogicalObject ||
			shard.TotalLength != first.TotalLength || shard.Digest != first.Digest ||
			i < len(pages)-1 && len(shard.Payload) != AdministrativeIndexShardPayloadLimit ||
			length+len(shard.Payload) > int(first.TotalLength) {
			return AdministrativeIndex{}, ErrFormat
		}
		length += len(shard.Payload)
		_, _ = h.Write(shard.Payload)
		parts = append(parts, shard.Payload)
	}
	var digest ID
	copy(digest[:], h.Sum(nil))
	if length != int(first.TotalLength) || digest != first.Digest {
		return AdministrativeIndex{}, ErrFormat
	}
	r := &administrativeShardReader{parts: parts, total: length}
	if string(r.take(7)) != string(start(byte(contract.AdministrativeIndexKind)).b) {
		return AdministrativeIndex{}, ErrFormat
	}
	index, err := decodeAdministrativeIndex(r, length)
	if err != nil || index.Domain != first.Domain || index.Object != first.LogicalObject {
		return AdministrativeIndex{}, ErrFormat
	}
	return index, nil
}

// DecodeAdministrativeIndexSource reads authenticated shards in their exact
// Ref order. The next read may replace the previous response backing. Only a
// field which crosses a shard boundary is copied; no encoded index is joined.
// Tentative metadata is returned only after complete wire and semantic checks.
func DecodeAdministrativeIndexSource(refs []Ref, read func(Ref) ([]byte, error)) (AdministrativeIndex, error) {
	if len(refs) == 0 || len(refs) > contract.MaxChildPages || read == nil {
		return AdministrativeIndex{}, ErrFormat
	}
	var first administrativeShard
	h := sha256.New()
	length, next := 0, 0
	load := func() ([]byte, error) {
		if next == len(refs) {
			return nil, ErrFormat
		}
		body, err := read(refs[next])
		if err != nil {
			return nil, err
		}
		shard, err := decodeAdministrativeShard(body)
		if err != nil || CheckReference(refs[next], body) != nil || shard.Index != uint16(next) {
			return nil, ErrFormat
		}
		if next == 0 {
			first = shard
			first.Payload = nil
			if int(first.Count) != len(refs) ||
				(int(first.TotalLength)+AdministrativeIndexShardPayloadLimit-1)/AdministrativeIndexShardPayloadLimit != len(refs) {
				return nil, ErrFormat
			}
		}
		if shard.Count != first.Count || shard.Domain != first.Domain || shard.LogicalObject != first.LogicalObject ||
			shard.TotalLength != first.TotalLength || shard.Digest != first.Digest ||
			next < len(refs)-1 && len(shard.Payload) != AdministrativeIndexShardPayloadLimit ||
			length+len(shard.Payload) > int(first.TotalLength) {
			return nil, ErrFormat
		}
		length += len(shard.Payload)
		_, _ = h.Write(shard.Payload)
		next++
		return shard.Payload, nil
	}
	payload, err := load()
	if err != nil {
		return AdministrativeIndex{}, err
	}
	r := &administrativeShardReader{parts: [][]byte{payload}, total: int(first.TotalLength), next: load}
	if string(r.take(7)) != string(start(byte(contract.AdministrativeIndexKind)).b) {
		return AdministrativeIndex{}, ErrFormat
	}
	index, err := decodeAdministrativeIndex(r, r.total)
	if r.err != nil {
		return AdministrativeIndex{}, r.err
	}
	var digest ID
	copy(digest[:], h.Sum(nil))
	if err != nil || next != len(refs) || length != r.total || digest != first.Digest ||
		index.Domain != first.Domain || index.Object != first.LogicalObject {
		return AdministrativeIndex{}, ErrFormat
	}
	return index, nil
}
