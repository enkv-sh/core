package core

import (
	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
)

const liveFamily = contract.AWS

var _ contract.Store = (*awsprovider.Store)(nil)
var _ contract.Trust = (*awsprovider.Trust)(nil)
