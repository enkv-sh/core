package crypto

import (
	"context"
	"io"
	"slices"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

type inputSealAdmission struct {
	*session
	core          contract.SealedInputCore
	authority     contract.BindingTableRow
	input         io.ReadCloser
	closeOnce     sync.Once
	closeErr      error
	configuration *ConfigurationInputOptions
}

// admitInputSeal is private parent entry. Public state and the exact target must
// be authenticated independently before the parent supplies this input owner.
// Failure transfers no ownership and performs no stream read or provider call.
func (r *Runtime) admitInputSeal(id contract.ID, core contract.SealedInputCore, authority contract.ID, bindings []contract.BindingTableRow, input io.ReadCloser, deadline time.Time) error {
	return r.admitInputSealSource(id, core, authority, bindings, input, deadline, nil)
}

func (r *Runtime) admitInputSealSource(id contract.ID, core contract.SealedInputCore, authority contract.ID, bindings []contract.BindingTableRow, input io.ReadCloser, deadline time.Time, configuration *ConfigurationInputOptions) error {
	if r == nil || id.IsZero() || input == nil || !validDeadline(deadline) || core.CryptoSupportID != contract.CryptoSupportID() || core.CompatibilityID != contract.CompatibilityID() || len(bindings) < 1 || len(bindings) > contract.CryptoMaxValueEntryRecipients {
		return ErrAdmission
	}
	if _, err := contract.SealedInputCoreLength(core); err != nil {
		return ErrAdmission
	}
	refs := make([]contract.RecipientBindingReference, len(bindings))
	var selected contract.BindingTableRow
	for i, row := range bindings {
		if row.SubjectKind != contract.OrdinaryWrapSubject || row.Binding.Provider != r.family {
			return ErrAdmission
		}
		digest, err := contract.PublicBindingDigest(row.Binding)
		if err != nil {
			return ErrAdmission
		}
		refs[i] = contract.RecipientBindingReference{RecipientID: row.SubjectID, PublicBindingDigest: digest}
		if row.SubjectID == authority {
			selected = row
			selected.Binding.SPKI = slices.Clone(row.Binding.SPKI)
		}
	}
	digest, err := contract.IntendedRecipientBindingSetDigest(core.DomainID, authority, refs)
	if err != nil || digest != core.IntendedRecipientBindingSetDigest || selected.SubjectID.IsZero() {
		return ErrAdmission
	}
	a := &inputSealAdmission{core: core, authority: selected, input: input, configuration: configuration}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.slot != nil {
		return ErrAdmission
	}
	a.session = r.installSession(id, deadline, nil, func() {
		a.input = nil
		a.authority = contract.BindingTableRow{}
		a.core = contract.SealedInputCore{}
		a.configuration = nil
	})
	if a.session == nil {
		return ErrAdmission
	}
	r.inputSeal = a
	// Register Close before the observer can start waiting for session work.
	// External Close retains custody without holding the runtime mutex.
	a.work.Add(1)
	context.AfterFunc(a.ctx, func() {
		defer a.work.Done()
		a.closeInput()
	})
	return nil
}

func (a *inputSealAdmission) closeInput() {
	a.closeOnce.Do(func() { a.closeErr = a.input.Close() })
}

func (r *Runtime) sealInputEnvelope(ctx context.Context, id contract.ID) ([]byte, contract.CryptoResultCode) {
	if r == nil || ctx == nil {
		return nil, contract.CryptoInvalidAdmission
	}
	r.mu.Lock()
	a := r.inputSeal
	if r.closed || a == nil || a.id != id {
		r.mu.Unlock()
		return nil, contract.CryptoInvalidAdmission
	}
	if a.terminal {
		r.mu.Unlock()
		return nil, contract.CryptoAlreadyUsed
	}
	if a.ctx.Err() != nil || !time.Now().Before(a.deadline) {
		r.mu.Unlock()
		return nil, contract.CryptoExpired
	}
	if a.used {
		r.mu.Unlock()
		return nil, contract.CryptoAlreadyUsed
	}
	a.used = true
	a.work.Add(1)
	r.mu.Unlock()
	defer a.work.Done()
	defer r.finishSession(a.session)
	stop := context.AfterFunc(ctx, a.cancel)
	defer stop()
	privateCtx := telemetry.PrivateContext(a.ctx, ctx)
	if code := sessionCancellation(ctx, a.session); code != contract.CryptoSuccess {
		return nil, code
	}
	var plain []byte
	var code contract.CryptoResultCode
	if a.configuration == nil {
		limit := contract.CryptoMaxRawValue
		if a.core.InputEncoding == contract.InputEncodingBase64 {
			limit = contract.CryptoMaxRetainedValue
		}
		plain, code = readInputBytes(privateCtx, a.input, limit)
	} else {
		plain, code = readConfigurationInputValue(privateCtx, a.input, *a.configuration)
	}
	if plain != nil {
		defer clear(plain[:cap(plain)])
	}
	a.closeInput()
	if cancelled := sessionCancellation(ctx, a.session); cancelled != contract.CryptoSuccess {
		return nil, cancelled
	}
	if code != contract.CryptoSuccess {
		return nil, code
	}
	if a.closeErr != nil {
		return nil, contract.CryptoCustodyUnavailable
	}
	if a.configuration != nil {
		content, err := contract.InputContentLength(a.core.InputEncoding, plain)
		if err != nil {
			return nil, contract.CryptoInvalidInput
		}
		a.core.ContentLength = content
		a.core.RetainedLength = uint32(len(plain))
	}
	if len(plain) != int(a.core.RetainedLength) {
		return nil, contract.CryptoInvalidInput
	}
	envelope, err := custody.SealInput(a.core, a.authority, plain)
	if err != nil {
		return nil, contract.CryptoCustodyUnavailable
	}
	body, err := contract.EncodeSealedInputEnvelope(envelope)
	if err != nil {
		return nil, contract.CryptoInvalidInput
	}
	if code := sessionCancellation(ctx, a.session); code != contract.CryptoSuccess {
		clear(body)
		return nil, code
	}
	return body, contract.CryptoSuccess
}

func readInputBytes(ctx context.Context, input io.Reader, limit int) ([]byte, contract.CryptoResultCode) {
	buffer := make([]byte, limit+1)
	n, empty := 0, 0
	for {
		if ctx.Err() != nil {
			clear(buffer)
			return nil, contract.CryptoCancelled
		}
		count, err := input.Read(buffer[n:])
		if count < 0 || count > len(buffer)-n {
			clear(buffer)
			return nil, contract.CryptoInvalidInput
		}
		n += count
		if n > limit {
			clear(buffer)
			return nil, contract.CryptoCapacityExceeded
		}
		if err == io.EOF {
			return buffer[:n], contract.CryptoSuccess
		}
		if err != nil {
			clear(buffer)
			return nil, contract.CryptoCustodyUnavailable
		}
		if count == 0 {
			empty++
			if empty >= 100 {
				clear(buffer)
				return nil, contract.CryptoCustodyUnavailable
			}
		} else {
			empty = 0
		}
	}
}

func (r *Runtime) retireInputSeal() {
	if r == nil {
		return
	}
	r.mu.Lock()
	a := r.inputSeal
	r.mu.Unlock()
	if a != nil {
		r.retireSession(a.session)
	}
}
