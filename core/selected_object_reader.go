package core

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// selectedObjectSource grants the complete selected-image reader only GET
// reach. The ordinary session adapter retains its existing read episode and
// telemetry behavior without giving this reader Store write methods.
type selectedObjectSource interface {
	Read(context.Context, string, uint32) contract.ReadResult
}

type admittedObjectSource struct{ session *StateSession }

func (r admittedObjectSource) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	return r.session.storeRead(ctx, key, limit)
}

type selectedObjectReader struct {
	domain                         contract.ID
	descriptor                     contract.Descriptor
	source                         selectedObjectSource
	cache                          map[format.Ref][]byte
	accessFacts                    map[format.Ref]*format.AccessPage
	replacementRead                bool
	cachedAdministrativeIndexFacts *selectedAdministrativeIndexFacts
}

func (s *StateSession) selectedObjectReader() selectedObjectReader {
	if s == nil {
		return selectedObjectReader{}
	}
	return selectedObjectReader{domain: s.admission.domain, descriptor: s.admission.store,
		source: admittedObjectSource{session: s}, cache: s.cache, accessFacts: s.accessFacts, replacementRead: s.replacementRead, cachedAdministrativeIndexFacts: s.cachedAdministrativeIndexFacts}
}

// readBorrowed checks the exact selected reference. A caller must finish using
// a Store-owned body before its next Store operation. Any selected row retained
// after inspection needs its own backing. The boolean identifies owned bytes
// from an authenticated cache or canonical encoding; false borrows Store bytes.
func (r selectedObjectReader) readBorrowed(ctx context.Context, ref format.Ref) ([]byte, bool, Result) {
	if ref.Domain == r.domain {
		if body, ok := r.cache[ref]; ok {
			return body, true, Result{}
		}
		if page, ok := r.accessFacts[ref]; ok {
			if page == nil {
				return nil, false, failure(IntegrityFailure, InvalidReference)
			}
			if ref.Kind != format.AccessKind || !ref.ValidFor(format.Version) || page.Domain != ref.Domain || page.Object != ref.Object || page.Index != ref.Index {
				return nil, false, failure(IntegrityFailure, InvalidReference)
			}
			body, err := format.EncodeAccessPage(*page)
			if err != nil || uint64(len(body)) != uint64(ref.Length) || contract.Hash(body) != ref.Digest {
				return nil, false, failure(IntegrityFailure, InvalidReference)
			}
			return body, true, Result{}
		}
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, false, failure(EvidenceUnavailable, ReadUnavailable)
	}
	if r.source == nil || ref.Domain != r.domain {
		return nil, false, failure(IntegrityFailure, InvalidReference)
	}
	key, err := format.Key(r.descriptor.Prefix, ref)
	if err != nil {
		return nil, false, failure(IntegrityFailure, InvalidReference)
	}
	read := r.source.Read(ctx, key, ref.Length)
	if read.Status == contract.ReadMissing {
		return nil, false, failure(EvidenceUnavailable, MissingSelectedObject)
	}
	if read.Status == contract.ReadInvalid {
		return nil, false, failure(IntegrityFailure, InvalidFormat)
	}
	if read.Status != contract.ReadOK {
		return nil, false, unavailableStoreRead(read)
	}
	if uint64(len(read.Body)) != uint64(ref.Length) || contract.Hash(read.Body) != ref.Digest {
		return nil, false, failure(IntegrityFailure, InvalidReference)
	}
	return read.Body, false, Result{}
}

func (r selectedObjectReader) readOwned(ctx context.Context, ref format.Ref) ([]byte, Result) {
	body, owned, result := r.readBorrowed(ctx, ref)
	if result.Outcome != 0 || owned {
		return body, result
	}
	return bytes.Clone(body), Result{}
}

func (s *StateSession) readObjectBorrowedUncached(ctx context.Context, ref format.Ref) ([]byte, Result) {
	reader := s.selectedObjectReader()
	reader.cache, reader.accessFacts = nil, nil
	body, _, result := reader.readBorrowed(ctx, ref)
	return body, result
}

// Callers verify immutable readback and the complete Ref before caching. The
// private one-use owner needs exactly the wire bytes; ordinary sessions keep
// their existing independently cloned cache behavior.
func (s *StateSession) cacheVerifiedObject(ref format.Ref, body []byte) {
	if s.replacementRead {
		owned := make([]byte, len(body))
		copy(owned, body)
		s.cache[ref] = owned
		return
	}
	s.cache[ref] = bytes.Clone(body)
}
