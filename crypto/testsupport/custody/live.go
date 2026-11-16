package custody

import (
	"testing"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// Route fixes public qualification and private use independently. A zero route
// means the corresponding operation is not installed for this binding.
type Route struct {
	BindingID, PublicRoute, PrivateRoute contract.ID
}

// NewLive wraps the installed production adapter with private test admission.
// Its inputs contain public bindings and route identities only.
func NewLive(t testing.TB, adapter contract.Crypto, authorityID, recoveryID contract.ID, bindings []contract.BindingTableRow, routes []Route) *Fixture {
	t.Helper()
	f, err := newLive(adapter, authorityID, recoveryID, bindings, routes)
	if err != nil {
		t.Fatal("invalid live custody fixture")
	}
	t.Cleanup(func() { f.runtime.Close() })
	return f
}

// Close joins every private owner at fixture teardown.
func (f *Fixture) Close() { f.runtime.Close() }

// CloseRoutes retires replaceable access routes. An already-entered producer
// owns its seed separately until its one original return or final Close.
func (f *Fixture) CloseRoutes() { f.runtime.Close() }

func newLive(adapter contract.Crypto, authorityID, recoveryID contract.ID, bindings []contract.BindingTableRow, routes []Route) (*Fixture, error) {
	runtime, ok := adapter.(*privatecrypto.Runtime)
	if !ok || runtime == nil || authorityID.IsZero() || authorityID == recoveryID || len(bindings) == 0 || len(bindings) > contract.CryptoMaxRecipients+1 || len(routes) != len(bindings) {
		return nil, privatecrypto.ErrAdmission
	}
	body, err := contract.EncodeBindingTable(bindings)
	if err != nil {
		return nil, privatecrypto.ErrAdmission
	}
	owned, err := contract.DecodeBindingTable(body)
	if err != nil {
		return nil, privatecrypto.ErrAdmission
	}
	f := &Fixture{family: owned[0].Binding.Provider, authority: authorityID, recovery: recoveryID, bindings: owned, runtime: runtime, routes: make(map[contract.ID]contract.ID, len(routes)), publicRoutes: make(map[contract.ID]contract.ID, len(routes)), accepted: make(map[contract.ID]contract.SealedInputCore), denied: make(map[contract.ID]bool)}
	authority, recovery := false, false
	known := make(map[contract.ID]bool, len(owned))
	subjects := make(map[contract.ID]bool, len(owned))
	ordinary := 0
	for _, row := range owned {
		if row.Binding.Provider != f.family || known[row.Binding.BindingID] || subjects[row.SubjectID] {
			return nil, privatecrypto.ErrAdmission
		}
		known[row.Binding.BindingID] = true
		subjects[row.SubjectID] = true
		switch row.SubjectKind {
		case contract.OrdinaryWrapSubject:
			ordinary++
			if row.SubjectID == authorityID {
				authority = true
			}
		case contract.RecoveryWrapSubject:
			if recovery || recoveryID.IsZero() || row.SubjectID != recoveryID {
				return nil, privatecrypto.ErrAdmission
			}
			recovery = true
		default:
			return nil, privatecrypto.ErrAdmission
		}
	}
	if !authority || recovery != !recoveryID.IsZero() || ordinary > contract.CryptoMaxRecipients {
		return nil, privatecrypto.ErrAdmission
	}
	var routeIDs []contract.ID
	for _, route := range routes {
		if !known[route.BindingID] {
			return nil, privatecrypto.ErrAdmission
		}
		delete(known, route.BindingID)
		f.publicRoutes[route.BindingID], f.routes[route.BindingID] = route.PublicRoute, route.PrivateRoute
		for _, id := range []contract.ID{route.PublicRoute, route.PrivateRoute} {
			if !id.IsZero() {
				routeIDs = append(routeIDs, id)
			}
		}
	}
	if err := privatecrypto.TestRuntimeRoutes(runtime, f.family, routeIDs); err != nil {
		return nil, err
	}
	if err := privatecrypto.TestObserveKeyCalls(runtime, func(private bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if private {
			f.privateCalls++
		} else {
			f.publicCalls++
		}
	}); err != nil {
		return nil, err
	}
	return f, nil
}
