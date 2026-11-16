package crypto

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// ConfigurationInputTarget fixes public source context before private input is
// accepted. Bindings contain ordinary recipients only, including Authority.
// The caller independently validates the complete source and candidate budget.
type ConfigurationInputTarget struct {
	DomainID, FileIdentity, FilePredecessorDigest contract.ID
	Name                                          string
	AuthorityRecipientID                          contract.ID
	Bindings                                      []contract.BindingTableRow
}

// MaximumRawLength is the remaining admitted whole-set budget, capped at the
// per-value bound. Zero permits only an empty value.
type ConfigurationInputOptions struct {
	Base64           bool
	MaximumRawLength uint32
}

type ConfigurationInputError struct{ Code contract.CryptoResultCode }

func (e *ConfigurationInputError) Error() string { return "configuration input preparation refused" }
func (e *ConfigurationInputError) Unwrap() error {
	if e == nil {
		return ErrAdmission
	}
	switch e.Code {
	case contract.CryptoCancelled:
		return context.Canceled
	case contract.CryptoExpired:
		return context.DeadlineExceeded
	default:
		return ErrAdmission
	}
}

// SealConfigurationInput validates the prepared public target without provider
// calls and reads input only in Crypto custody. A finite deadline is required.
// Successful admission transfers input ownership; refusal before admission
// neither reads nor closes it. The owning caller closes an untransferred input.
// On return, every admitted Read and Close has joined and only ciphertext leaves.
func SealConfigurationInput(ctx context.Context, target ConfigurationInputTarget, input io.ReadCloser, options ConfigurationInputOptions) ([]byte, error) {
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoSealSource)
	if ctx != nil {
		ctx = telemetry.CallContext(ctx, call)
	}
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	body, err := sealConfigurationInput(ctx, target, input, options)
	code := contract.CryptoSuccess
	var inputError *ConfigurationInputError
	if errors.As(err, &inputError) {
		code = inputError.Code
	} else if err != nil {
		code = contract.CryptoCustodyUnavailable
	}
	finishCryptoCall(call, code)
	return body, err
}

func sealConfigurationInput(ctx context.Context, target ConfigurationInputTarget, input io.ReadCloser, options ConfigurationInputOptions) ([]byte, error) {
	refuse := func(code contract.CryptoResultCode) ([]byte, error) { return nil, &ConfigurationInputError{Code: code} }
	if ctx == nil || ctx.Err() != nil || input == nil || target.DomainID.IsZero() || target.FileIdentity.IsZero() || target.FilePredecessorDigest.IsZero() || target.AuthorityRecipientID.IsZero() || options.MaximumRawLength > contract.CryptoMaxRawValue || len(target.Bindings) < 1 || len(target.Bindings) > contract.CryptoMaxValueEntryRecipients {
		return refuse(contract.CryptoInvalidAdmission)
	}
	deadline, ok := ctx.Deadline()
	if !ok || !validDeadline(deadline) {
		return refuse(contract.CryptoInvalidAdmission)
	}
	family := target.Bindings[0].Binding.Provider
	rows := make([]contract.BindingTableRow, len(target.Bindings))
	refs := make([]contract.RecipientBindingReference, len(rows))
	for i, row := range target.Bindings {
		if row.SubjectKind != contract.OrdinaryWrapSubject || row.Binding.Provider != family {
			return refuse(contract.CryptoInvalidAdmission)
		}
		digest, err := contract.PublicBindingDigest(row.Binding)
		if err != nil {
			return refuse(contract.CryptoInvalidAdmission)
		}
		rows[i] = row
		rows[i].Binding.SPKI = slices.Clone(row.Binding.SPKI)
		refs[i] = contract.RecipientBindingReference{RecipientID: row.SubjectID, PublicBindingDigest: digest}
	}
	bindingSet, err := contract.IntendedRecipientBindingSetDigest(target.DomainID, target.AuthorityRecipientID, refs)
	if err != nil {
		return refuse(contract.CryptoInvalidAdmission)
	}
	core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: contract.SealedInputSchema, Profile: contract.MaterialCryptoProfile, CompatibilityID: contract.CompatibilityID(), DomainID: target.DomainID, FileIdentity: target.FileIdentity, FilePredecessorDigest: target.FilePredecessorDigest, CryptoSupportID: contract.CryptoSupportID(), DataKeyEpoch: 1, IntendedRecipientBindingSetDigest: bindingSet, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: target.Name}
	core.InputEncoding = contract.InputEncodingRaw
	if options.Base64 {
		core.InputEncoding = contract.InputEncodingBase64
	}
	for _, id := range []*contract.ID{&core.SourceID, &core.DataKeyID} {
		if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
			return refuse(contract.CryptoCustodyUnavailable)
		}
	}
	if _, err := contract.SealedInputCoreLength(core); err != nil {
		return refuse(contract.CryptoInvalidAdmission)
	}
	runtime, err := New(family, nil)
	if err != nil {
		return refuse(contract.CryptoCustodyUnavailable)
	}
	defer runtime.Close()
	var sessionID contract.ID
	if _, err := rand.Read(sessionID[:]); err != nil || sessionID.IsZero() {
		return refuse(contract.CryptoCustodyUnavailable)
	}
	if err := runtime.admitInputSealSource(sessionID, core, target.AuthorityRecipientID, rows, input, deadline, &options); err != nil {
		return refuse(contract.CryptoInvalidAdmission)
	}
	body, code := runtime.sealInputEnvelope(ctx, sessionID)
	if code != contract.CryptoSuccess {
		return refuse(code)
	}
	return body, nil
}

func readConfigurationInputValue(ctx context.Context, input io.Reader, options ConfigurationInputOptions) ([]byte, contract.CryptoResultCode) {
	limit := int(options.MaximumRawLength)
	if !options.Base64 {
		return readInputBytes(ctx, input, limit)
	}
	encoded, code := readInputBytes(ctx, input, base64.StdEncoding.EncodedLen(limit))
	if code != contract.CryptoSuccess {
		clear(encoded[:cap(encoded)])
		return nil, code
	}
	content, err := contract.InputContentLength(contract.InputEncodingBase64, encoded)
	if err != nil || content > options.MaximumRawLength {
		clear(encoded[:cap(encoded)])
		if content > options.MaximumRawLength || errors.Is(err, contract.ErrRecordCapacity) {
			return nil, contract.CryptoCapacityExceeded
		}
		return nil, contract.CryptoInvalidInput
	}
	if ctx.Err() != nil {
		clear(encoded[:cap(encoded)])
		return nil, contract.CryptoCancelled
	}
	return encoded, contract.CryptoSuccess
}

var _ error = (*ConfigurationInputError)(nil)
