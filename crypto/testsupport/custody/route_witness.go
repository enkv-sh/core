package custody

import (
	"context"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// RouteWitness reports one bounded private-route experiment. Counts describe
// actual provider calls; zero counts cannot establish an authenticated denial.
type RouteWitness struct {
	Outcome                            contract.CryptoResultCode
	Completed, Denied, Failed, Unknown uint32
}

// PrivateRouteWitness consumes a fresh, unadmitted runtime. The test-only
// private assembly generates and clears its challenge and returned packet.
func PrivateRouteWitness(ctx context.Context, adapter contract.Crypto, routeID contract.ID, target, wrappedUnder contract.KMSBinding) RouteWitness {
	runtime, ok := adapter.(*privatecrypto.Runtime)
	if !ok || runtime == nil {
		return RouteWitness{Outcome: contract.CryptoInvalidAdmission}
	}
	code, uses := privatecrypto.TestPrivateRouteWitness(runtime, ctx, routeID, target, wrappedUnder)
	return RouteWitness{Outcome: code, Completed: uses.Completed, Denied: uses.Denied, Failed: uses.Failed, Unknown: uses.Unknown}
}

// PrivateWitness copies only the named installed route into a fresh runtime.
// It grants no ENKV source, transition or consumer admission.
func (f *Fixture) PrivateWitness(ctx context.Context, routeBindingID contract.ID, target, wrappedUnder contract.KMSBinding) RouteWitness {
	if f == nil {
		return RouteWitness{Outcome: contract.CryptoInvalidAdmission}
	}
	f.mu.Lock()
	route := f.routes[routeBindingID]
	f.mu.Unlock()
	runtime, err := privatecrypto.TestNewConsumerRuntime(f.runtime, route)
	if err != nil {
		return RouteWitness{Outcome: contract.CryptoInvalidAdmission}
	}
	defer runtime.Close()
	return PrivateRouteWitness(ctx, runtime, route, target, wrappedUnder)
}
