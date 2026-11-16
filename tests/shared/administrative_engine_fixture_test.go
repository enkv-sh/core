package core

import (
	"context"
	"crypto/rand"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// This helper tests the existing private engine with an independently retained
// typed public basis. It has no connection decoder or native product entrypoint.
func openAdministrativeEngineFixture(ctx context.Context, before *StateSession, store contract.Store, trust contract.Trust, mode LocalAuthorityOperation) (*AuthoritySession, Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	open := func() (*AuthoritySession, Result) {
		if ctx == nil || ctx.Err() != nil || before == nil || !mode.valid() {
			return nil, refused(AdmissionInvalid)
		}
		admitted, result := admitPublicNormal(telemetry.CallContext(ctx, call), before.admission.domain, before.admission.store, before.admission.publicBasis(), store, before.admission.composition, nil)
		if result.Outcome != ObservedCurrent {
			return nil, result
		}
		if mode == LocalAuthorityEnd && (trust == nil || trust.Identity() != admitted.admission.trust || trust.Family() != admitted.admission.store.Family) {
			return nil, refused(AdmissionInvalid)
		}
		if mode == LocalAuthorityPreview || mode == LocalAuthorityEnd {
			if _, err := rand.Read(admitted.admission.endWorkInvocation[:]); err != nil || admitted.admission.endWorkInvocation.IsZero() {
				return nil, refused(AdmissionInvalid)
			}
		}
		state, result := openAdministrative(telemetry.CallContext(ctx, call), admitted, store)
		if state == nil {
			return nil, result
		}
		return &AuthoritySession{state: state, trust: trust, mode: mode}, result
	}
	view, result := open()
	finishCore(call, result)
	return view, result
}
