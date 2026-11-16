package core

import "enkv.sh/core/contract"

// PreAdmissionRequestIdentity describes a recognized request before its
// operation-specific identity is available. It grants no replay authority.
type PreAdmissionRequestIdentity struct {
	Stage, Code                 string
	SourceSchema, SourceProfile string
	Format                      string
	RequestNonce                contract.ID
}
