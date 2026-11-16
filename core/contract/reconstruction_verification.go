package contract

// ReconstructionVerificationPins describe one completely selected current
// state. These public fields are not proof of selection and grant no admission
// by themselves. Only the installed private reconstruction composition may
// pass them to its Crypto verifier after Core completes the selected closure.
// These pins contain selected state and key facts only.
type ReconstructionVerificationPins struct {
	DomainID, SnapshotID, HEADDigest, HEADRevision, AccessRoot, AuthorityRecipientID ID
	Root                                                                             Ref
	HEADToken                                                                        Token
	AuthorityBinding                                                                 BindingTableRow
}
