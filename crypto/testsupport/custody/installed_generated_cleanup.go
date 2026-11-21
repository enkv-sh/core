package custody

import (
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// This path has no process configuration or credential route. Verification
// delegates actual original-result admission and authentication to Crypto.
func (f *Fixture) NewInstalledGeneratedVerification(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedVerificationInput, deadline time.Time) (*InstalledGeneratedOwner, error) {
	construction, err := f.installedGeneratedConstruction(control, input.Session, contract.GeneratedPlanInput{}, contract.ID{}, q.Purpose, false)
	if err != nil {
		return nil, err
	}
	return f.installedGeneratedOwner(construction, func(runtime *privatecrypto.Runtime) (*privatecrypto.GeneratedCustody, error) {
		return privatecrypto.NewGeneratedVerificationCustody(runtime, q, control, construction, input, deadline)
	})
}
