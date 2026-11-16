package core

import (
	"context"
	"crypto/rand"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// administrativeReadStore retains only keyed public reads. There is no write
// client behind the internal Store methods required by StateSession.
type administrativeReadStore struct{ source PublicSelectedReader }

func (s administrativeReadStore) Descriptor() contract.Descriptor { return s.source.Descriptor() }
func (s administrativeReadStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	return s.source.Read(ctx, key, limit)
}
func (s administrativeReadStore) Create(context.Context, string, []byte) contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
}
func (s administrativeReadStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
}
func (s administrativeReadStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
}
func (s administrativeReadStore) StoreConfiguration() contract.StoreConfiguration {
	return s.source.StoreConfiguration()
}

// OpenAdministrativeReader accepts complete independent public trust and a
// GET-only source. It installs no signer, Crypto, LIST or effect capability.
func OpenAdministrativeReader(ctx context.Context, domain contract.ID, descriptor contract.Descriptor, basis PublicBasis, source PublicSelectedReader, composition contract.ID, operation LocalAuthorityOperation) (session *AuthoritySession, result Result) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreOpen)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	defer func() { finishCore(call, result) }()
	ctx = telemetry.CallContext(ctx, call)
	if source == nil || operation != LocalAuthorityInspect && operation != LocalAuthorityPreview && operation != LocalAuthorityRecheck {
		return nil, refused(AdmissionInvalid)
	}
	store := administrativeReadStore{source: source}
	admitted, result := admitPublicNormal(ctx, domain, descriptor, basis, store, composition, nil)
	if result.Outcome != ObservedCurrent {
		return nil, result
	}
	if operation == LocalAuthorityPreview {
		if _, err := rand.Read(admitted.admission.endWorkInvocation[:]); err != nil || admitted.admission.endWorkInvocation.IsZero() {
			return nil, refused(AdmissionInvalid)
		}
	}
	state, result := openAdministrative(ctx, admitted, store)
	if state == nil {
		return nil, result
	}
	return &AuthoritySession{state: state, mode: operation, closeReader: source.Close}, result
}
