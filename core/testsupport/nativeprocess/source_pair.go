package nativeprocess

// SourcePairFactsLimit matches the existing test-child stdout intake. This
// fixture helper refuses larger public facts; it is not a Product capacity.
const SourcePairFactsLimit = 64 << 10

// SourcePairFacts conveys copied public facts, never admitted authority or
// private material. The owning Core test qualifies its independent basis.
type SourcePairFacts struct {
	Schema                          string
	GeneratedReference              string
	Resolved                        bool
	DomainID, FileID                [32]byte
	Format                          uint8
	EditableDigest, GeneratedDigest [32]byte
	EditableLength, GeneratedLength uint64
	Basis                           SourcePairBasis
	GeneratedRecipients             []SourcePairRecipient
}
type SourcePairBasis struct {
	Descriptor, Control, Selection                []byte
	Enrollment                                    []SourcePairEnrollment
	SigningAnchor, StoreConfiguration, HEAD, Root []byte
	RecipientPages                                [][]byte
}
type SourcePairEnrollment struct {
	ID          [32]byte
	Status      uint8
	DisplayName string
}
type SourcePairRecipient struct {
	Reference  string
	ID         [32]byte
	Encryption SourcePairKey
	Creation   *SourcePairCreation
}
type SourcePairKey struct {
	Selector  string
	PublicKey []byte
	Binding   SourcePairBinding
}
type SourcePairBinding struct {
	ID, Incarnation [32]byte
	Serial          uint64
	Protection      uint8
}
type SourcePairCreation struct{ Snapshot, Nonce [32]byte }
