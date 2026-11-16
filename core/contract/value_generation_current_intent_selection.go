package contract

// GeneratedCurrentIntentSelection contains bounded selected facts supplied by
// the private Core parent. It carries no value payload, intent bytes or physical
// locator. Constructing these fields does not authenticate a selection.
type GeneratedCurrentIntentSelection struct {
	DomainID, HEADDigest, AccessRoot ID
	Root                             Ref
	HEADRevision                     ID
	HEADToken                        Token
	Row                              PublicStateRow
	Incarnation                      ID
	Generated                        GeneratedEntryMetadata
	Intent                           GeneratorLogicalSlice
}
