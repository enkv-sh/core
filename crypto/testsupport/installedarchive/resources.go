package installedarchive

import (
	"enkv.sh/core/contract"
)

type SigningResource struct {
	Selector, Region  string
	PublicKey         []byte
	TrustID, Material contract.ID
}

// RecoveryResources is retained by the independent resource owner before
// DomainID allocation. It is separate from every Store-produced archive.
type RecoveryResources struct {
	InitialNormal, InitialRecovery       SigningResource
	Normal, Recovery                     SigningResource
	NormalSuccessors, RecoverySuccessors []SigningResource
	AuthorityPublicKeys                  [][]byte
	Domain, PriorDomain                  contract.ID
	RecoveryEnabled                      bool
	Location                             contract.StoreLocation
}

type RecoverySetup struct {
	Domain             contract.ID
	Descriptor         contract.Descriptor
	Configuration      contract.StoreConfiguration
	PriorDescriptor    contract.Descriptor
	PriorConfiguration contract.StoreConfiguration
}

type RecoveryResourceInput struct {
	Recovery         bool
	Location         contract.StoreLocation
	Resources, Setup string
}

// RecoveryWriterInput is private setup coordination, outside child input.
type RecoveryWriterInput struct {
	Locations       RecoveryLocations
	Domain          contract.ID
	OracleDirectory string
}
