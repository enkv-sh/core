package contract

// InitializationStateResult is the public state outcome for the bounded empty
// domain initialization path. It does not supply execution or retry authority.
type InitializationStateResult string

const (
	InitializationSuccess        InitializationStateResult = "success"
	InitializationExactResume    InitializationStateResult = "exact-resume"
	InitializationRefused        InitializationStateResult = "refused"
	InitializationUnavailable    InitializationStateResult = "unavailable"
	InitializationContention     InitializationStateResult = "contention"
	InitializationCommitUnknown  InitializationStateResult = "commit-outcome-unknown"
	InitializationPositiveDefect InitializationStateResult = "positive-defect"
)

// InitPayload contains only fixed public identities. It is returned only after
// an authenticated ready observation. Local delivery paths belong to composition.
type InitPayload struct {
	InitID, DomainID, DescriptorArtifactID, ManifestArtifactID ID
	DescriptorDigest, StoreID, HeadRevisionID, SnapshotID      ID
}
