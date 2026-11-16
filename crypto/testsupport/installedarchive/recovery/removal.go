package recovery

import (
	"strings"

	"enkv.sh/core/contract"
)

// ExactRemoval is private parent mutation authority for one observed non-HEAD
// object. Its relay is never supplied to the reconstruction child.
type ExactRemoval struct {
	Key   string
	Token contract.Token
}

func (r *ExactRemoval) valid(family contract.Family, prefix string) bool {
	return r != nil && r.Token.Family == family && r.Token.Valid() && strings.HasPrefix(r.Key, prefix+"/") && r.Key != prefix+"/HEAD"
}
