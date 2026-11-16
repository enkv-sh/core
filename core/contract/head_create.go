package contract

// HeadCreateRequest freezes the exact admitted Store construction and complete
// body. It offers no object-key or token choice. Construction is not admission.
type HeadCreateRequest struct {
	descriptor Descriptor
	body       []byte
	digest     ID
}

func NewHeadCreateRequest(d Descriptor, body []byte) (HeadCreateRequest, error) {
	if !d.Valid() || len(body) == 0 {
		return HeadCreateRequest{}, ErrRecord
	}
	if len(body) > 64<<10 {
		return HeadCreateRequest{}, ErrRecordCapacity
	}
	return HeadCreateRequest{descriptor: d, body: ownedBytes(body), digest: Hash(body)}, nil
}
func (r HeadCreateRequest) Descriptor() Descriptor   { return r.descriptor }
func (r HeadCreateRequest) Body() []byte             { return ownedBytes(r.body) }
func (r HeadCreateRequest) Digest() ID               { return r.digest }
func (r HeadCreateRequest) Length() uint32           { return uint32(len(r.body)) }
func (r HeadCreateRequest) Condition() HeadCondition { return AbsentHeadCondition() }
func (r HeadCreateRequest) Valid() bool {
	return r.descriptor.Valid() && len(r.body) > 0 && len(r.body) <= 64<<10 && Hash(r.body) == r.digest
}
