package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/providers/gcp"
)

const liveFamily = contract.GCP

var _ contract.Store = (*gcp.Store)(nil)
var _ contract.Trust = (*gcp.Trust)(nil)
