package contract

// These Product operation codes identify the operations consumed by the current contracts.
const (
	OperationInitializeDomain                 = 1
	OperationApplyDeclaration                 = 2
	OperationRemoveSecretValueEntryAccess     = 8
	OperationRotateRecipientKeyBinding        = 9
	OperationRetireRecipientIdentity          = 10
	OperationEnvelopeRekey                    = 11
	OperationRotateValueEntryValue            = 12
	OperationPublishCurrentProjection         = 21
	OperationReplaceAuthorityKeys             = 25
	OperationRebindStoreConstruction          = 26
	OperationCleanOwnedFailureResidue         = 31
	OperationConfigureCommercialAttachment    = 32
	OperationReplaceRecoveryKeysAndRoot       = 36
	OperationRetireGeneratedGeneration        = 38
	OperationAcceptGeneratedRetirementResidue = 39
	OperationEndSelectedWork                  = 43
)

// SetConfidentialOperation identifies confidential local input preparation.
const SetConfidentialOperation = "set-confidential"
