package crypto

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// Core owns the original source body. A final preparation can authenticate
// each admitted live source once, after Compare and before entry batches.
// This check grants no effect permission and returns no plaintext or key.
func (r *Runtime) verifyGeneratedSource(ctx context.Context, id, sourceID contract.ID, body []byte) contract.CryptoResultCode {
	if r == nil || ctx == nil {
		return contract.CryptoInvalidAdmission
	}
	callerDone := ctx.Done()
	r.mu.Lock()
	a := r.generated
	if r.closed || a == nil || a.id != id || a.terminal {
		r.mu.Unlock()
		return contract.CryptoInvalidAdmission
	}
	refuse := func(code contract.CryptoResultCode) contract.CryptoResultCode {
		a.terminal = true
		a.cancel()
		r.mu.Unlock()
		return code
	}
	if code := sessionCancellationObserved(callerDone, a.session); code != contract.CryptoSuccess {
		return refuse(code)
	}
	final := a.purpose.final
	if final == nil || !slices.ContainsFunc(final.plan.liveSources, func(use contract.GeneratorSourceUse) bool { return use.SourceID == sourceID }) {
		return refuse(contract.CryptoInvalidAdmission)
	}
	index := slices.IndexFunc(final.plan.sources, func(source generatedSource) bool { return source.core.SourceID == sourceID })
	if index < 0 {
		return refuse(contract.CryptoInvalidAdmission)
	}
	if a.busy || a.stage != contract.CryptoPrepare || final.entryBatch != 0 || final.plan.sources[index].verified {
		return refuse(contract.CryptoAlreadyUsed)
	}
	a.busy = true
	a.work.Add(1)
	r.mu.Unlock()
	defer a.work.Done()
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	code := a.reopenSource(final.plan.sources[index], body)
	r.mu.Lock()
	defer r.mu.Unlock()
	if cancelled := sessionCancellationObserved(callerDone, a.session); cancelled != contract.CryptoSuccess {
		code = cancelled
	}
	a.busy = false
	if code != contract.CryptoSuccess {
		a.terminal = true
		a.cancel()
		return code
	}
	final.plan.sources[index].verified = true
	return contract.CryptoSuccess
}

func (a *generatedAdmission) reopenSource(source generatedSource, body []byte) contract.CryptoResultCode {
	plain, code := a.openTransferredSource(source, body)
	if plain != nil {
		clear(plain[:cap(plain)])
	}
	return code
}

func (a *generatedAdmission) compareContinuationSources(ctx context.Context, route KeyAccess, out *contract.CryptoResponse) contract.CryptoResultCode {
	plan := a.purpose.plan()
	if plan == nil {
		return contract.CryptoSuccess
	}
	for at := range plan.sources {
		source := &plan.sources[at]
		index := slices.IndexFunc(a.graph.ValueEntryPlans, func(row contract.GeneratorValueEntryPlan) bool { return row.Name == source.core.Name })
		if index < 0 {
			return contract.CryptoInvalidAdmission
		}
		if a.graph.ValueEntryPlans[index].ChangeMask&contract.GeneratorValueChangeContent != 0 || !slices.ContainsFunc(plan.liveSources, func(use contract.GeneratorSourceUse) bool { return use.SourceID == source.core.SourceID }) {
			continue
		}
		body := source.buffer
		if plan.declaration != nil {
			end := uint64(source.offset) + uint64(source.length)
			if end > uint64(len(plan.declaration)) {
				return contract.CryptoInvalidAdmission
			}
			body = plan.declaration[source.offset:uint32(end)]
		}
		plain, code := a.openTransferredSource(*source, body)
		if code == contract.CryptoSuccess {
			code = a.compareSuppliedCurrent(ctx, route, source.core.Name, plain, out)
		}
		clear(plain[:cap(plain)])
		if a.purpose.producer != nil {
			clear(source.buffer[:cap(source.buffer)])
			source.buffer = nil
		}
		if code != contract.CryptoSuccess {
			return code
		}
	}
	return contract.CryptoSuccess
}

func (a *generatedAdmission) openTransferredSource(source generatedSource, body []byte) ([]byte, contract.CryptoResultCode) {
	if len(body) != int(source.length) || contract.Hash(body) != source.envelope {
		return nil, contract.CryptoSourceAuthenticationFailed
	}
	view, err := contract.InspectSealedInputEnvelope(body)
	if err != nil {
		return nil, contract.CryptoSourceAuthenticationFailed
	}
	core, err := view.Core.Own()
	if err != nil || core != source.core {
		return nil, contract.CryptoSourceAuthenticationFailed
	}
	plan := a.purpose.plan()
	if plan == nil {
		return nil, contract.CryptoInvalidAdmission
	}
	protections, err := contract.InspectGeneratedSourceProtections(a.material, plan.protections)
	if err != nil {
		return nil, contract.CryptoInvalidAdmission
	}
	for i := 0; i < protections.Count(); i++ {
		row, err := protections.Row(i)
		if err != nil {
			return nil, contract.CryptoInvalidAdmission
		}
		if row.SourceID != source.core.SourceID {
			continue
		}
		digest, err := contract.SealedInputCoreDigest(source.core)
		if err != nil || digest != row.OriginalSourceCoreDigest || source.envelope != row.OriginalEnvelopeDigest {
			return nil, contract.CryptoInvalidAdmission
		}
		keys, err := custody.OpenTransfer(row.Transfer.Core, contract.TransferEnvelope(row.Transfer), a.seed)
		if err != nil {
			return nil, contract.CryptoStoredAuthenticationFailed
		}
		defer clear(keys[:cap(keys)])
		// The old authority wrap stays part of the original envelope, but its
		// private route is not used. The selected transfer supplies source D.
		envelope := contract.SealedInputEnvelope{Core: core, Nonce: view.Nonce, Ciphertext: view.Ciphertext, AuthorityWrap: contract.WrapRow(view.AuthorityWrap)}
		plain, err := custody.OpenSealedInput(source.core, envelope, keys)
		if err != nil {
			return nil, contract.CryptoSourceAuthenticationFailed
		}
		return plain, contract.CryptoSuccess
	}
	return nil, contract.CryptoInvalidAdmission
}
