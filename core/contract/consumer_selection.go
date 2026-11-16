package contract

// ConsumerSelection carries public selected-state facts. Constructing or
// decoding these fields does not grant admission or authenticate selection.
// The private consumer parent retains the independent HEAD, caller and sink pins.
type ConsumerSelection struct {
	DomainID, SnapshotID, HEADDigest, AccessRoot, EntryDigest ID
	Root                                                      Ref
	HEADRevision                                              ID
	HEADToken                                                 Token
	Slot                                                      uint16
	Entry                                                     ValueEntry
	Core                                                      ValueCore
	Payload                                                   CanonicalPayload
	Access                                                    AccessRecord
	Binding                                                   BindingTableRow
}

// GeneratedCanonicalSelection binds an original entry to its observation and,
// for retained use, one exact live Duty or Hazard's consumer rows. Public facts
// alone do not establish selected state or private admission.
type GeneratedCanonicalSelection struct {
	Selection ConsumerSelection
	Record    RetainedCanonicalRecord
	Owner     SupportRecord
	Consumers [][]byte
}
