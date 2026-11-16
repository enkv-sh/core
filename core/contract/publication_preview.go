package contract

const (
	MaxPublicationPreviewEntries          = 2048
	MaxPublicationPreviewBlockers         = 2048
	MaxPublicationPreviewRowJSONBytes     = 32768
	MaxPublicationPreviewJSONBytes        = 67311616
	MaxPublicationPlanningResultJSONBytes = MaxComparisonResultJSONBytes + MaxPublicationPreviewJSONBytes
)

type ComparisonOptions struct{ Publish bool }

// PublicationPreview describes prospective actions at its parent's observation.
// It carries no admission, Attempt or provider authority.
type PublicationPreview struct {
	Complete          bool
	ReasonCode        uint8
	DomainWideWarning bool
	Entries           []PublicationPreviewEntry
}

type PublicationPreviewEntry struct {
	ServiceContractID, PhysicalTarget, Origin string
	CoordinateID, BindingID                   ID
	EntryName, DestinationID                  *string
	TargetContractID                          string
	ConsumerLocator                           *string
	Actions                                   []uint8
	Basis                                     string
	Conditional                               bool
	ReasonCode                                uint8
	BlockerIDs                                []ID
	RemoteValueMayRemain, LateWriteRisk       bool
}
