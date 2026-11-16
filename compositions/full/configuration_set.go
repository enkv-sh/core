package compositionfull

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/telemetry"
)

type SetOptions struct{ Confidential, Base64 bool }

type SetError struct {
	reason string
	cause  error
}

func (e *SetError) Error() string               { return "configuration set: " + e.reason }
func (e *SetError) Unwrap() error               { return e.cause }
func setError(reason string, cause error) error { return &SetError{reason: reason, cause: cause} }

type setInputOwner struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (o *setInputOwner) Close() error {
	o.once.Do(func() { o.err = o.ReadCloser.Close() })
	return o.err
}

// SetConfiguration takes ownership of input on entry, including preflight
// refusal. Confidential bytes are read only by Crypto after complete source and
// maximum replacement checks. The operation constructs no provider capability.
func SetConfiguration(ctx context.Context, path string, format configuration.Format, name string, input io.ReadCloser, options SetOptions) (*SetResult, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	if ctx != nil {
		ctx = telemetry.CallContext(ctx, call)
	}
	result, err := newSetResult(options.Confidential, format)
	if err != nil {
		if input != nil {
			err = errors.Join(err, input.Close())
		}
	} else {
		_, err = setConfiguration(ctx, path, format, name, input, options, result)
	}
	if result.StateResult != SetSuccess {
		finishSetFailure(ctx, result, err)
	}
	err = closeConfigurationDelivery(err)
	call.Finish(result.TelemetryResult(err))
	return result, err
}

func setConfiguration(ctx context.Context, path string, format configuration.Format, name string, input io.ReadCloser, options SetOptions, outcome *SetResult) (result *SetResult, resultErr error) {
	if input == nil {
		return nil, setError("input", nil)
	}
	owner := &setInputOwner{ReadCloser: input}
	defer func() {
		if err := owner.Close(); err != nil {
			resultErr = errors.Join(resultErr, setError("input-close", err))
		}
	}()
	if ctx == nil || len(name) > contract.CryptoMaxName || !utf8.ValidString(name) {
		return nil, setError("target", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, setError("target", err)
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) {
		return nil, setError("deadline", nil)
	}
	session, err := configuration.BeginEdit(ctx, path, format)
	if err != nil {
		return nil, setError("source", err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			resultErr = errors.Join(resultErr, setError("local-cleanup", err))
		}
	}()
	prepared, err := prepareConfigurationSet(ctx, session.Pair(), name, options)
	if err != nil {
		return nil, err
	}
	var envelope, plain []byte
	if options.Confidential {
		envelope, err = enkvcrypto.SealConfigurationInput(ctx, prepared.target, owner, enkvcrypto.ConfigurationInputOptions{Base64: options.Base64, MaximumRawLength: prepared.maximumRaw})
	} else {
		plain, err = readSetPlain(ctx, owner, options.Base64, prepared.maximumRaw)
		if closeErr := owner.Close(); closeErr != nil {
			err = errors.Join(err, setError("input-close", closeErr))
		}
	}
	if err != nil {
		return nil, setError("input", err)
	}
	if options.Confidential {
		view, inspectErr := contract.InspectSealedInputEnvelope(envelope)
		target := prepared.target
		if inspectErr != nil || view.Core.DomainID != target.DomainID || view.Core.FileIdentity != target.FileIdentity || view.Core.FilePredecessorDigest != target.FilePredecessorDigest || !bytes.Equal(view.Core.Name, []byte(target.Name)) || view.Core.IntendedRecipientBindingSetDigest != prepared.recipientImage || view.Core.CompatibilityID != contract.CompatibilityID() || view.Core.CryptoSupportID != contract.CryptoSupportID() {
			return nil, setError("candidate-target", inspectErr)
		}
		identity := ArtifactRequestIdentity{InputFileID: target.FileIdentity, PredecessorDigest: target.FilePredecessorDigest, Target: SetArtifactTarget{target.DomainID, strings.Clone(target.Name)}, RecipientImageDigest: prepared.recipientImage, SealedArtifactDigest: contract.Hash(envelope), RequestNonce: outcome.RequestNonce}
		outcome.fixedRequest = identity
		outcome.RequestIdentity = &identity
		outcome.PreAdmission = nil
	}
	var generated func(io.Writer) error
	if prepared.edit.ChangesGenerated() {
		generated = func(w io.Writer) error { return prepared.edit.EmitGenerated(ctx, w, envelope) }
	}
	candidate, model, err := session.StageForPreparation(ctx, generated, func(w io.Writer, ref string) error { return prepared.edit.EmitEditable(ctx, w, ref, plain) })
	if err != nil {
		return nil, setError("candidate", err)
	}
	valid := false
	for _, entry := range model.Entries {
		if entry.Name == name {
			valid = entry.Generated == nil && entry.Secret == options.Confidential
			if options.Confidential {
				valid = valid && bytes.Equal(entry.Sealed, envelope) && entry.Retained == nil
			} else {
				valid = valid && bytes.Equal(entry.Plain, plain)
			}
			break
		}
	}
	valid = valid && slices.Equal(model.MissingInputs, prepared.missingInputs)
	*model = configuration.Model{}
	if !valid {
		return nil, setError("candidate-target", nil)
	}
	delivery, err := session.Commit(ctx, candidate)
	if delivery == nil {
		return nil, setError("delivery", err)
	}
	editable, dependency := delivery.Paths()
	outcome.EditablePath, outcome.GeneratedPath = editable, dependency
	outcome.delivery = delivery
	if options.Confidential {
		editableDigest, generatedDigest, readbackErr := delivery.Digests()
		if readbackErr != nil {
			return nil, setError("delivery", readbackErr)
		}
		q := outcome.RequestIdentity
		payload := SealedArtifactPayload{InputFileID: q.InputFileID, PredecessorDigest: q.PredecessorDigest, Target: q.Target, SealedArtifactDigest: q.SealedArtifactDigest, Readback: SetPairReadback{contract.ID(editableDigest), contract.ID(generatedDigest)}}
		outcome.fixedPayload = payload
		outcome.Payload = &payload
	}
	outcome.StateResult = SetSuccess
	if err != nil {
		return outcome, setError("delivery", err)
	}
	return outcome, nil
}

type configurationSetPreparation struct {
	edit           *configuration.SuppliedEdit
	missingInputs  []string
	target         enkvcrypto.ConfigurationInputTarget
	maximumRaw     uint32
	recipientImage contract.ID
}

func prepareConfigurationSet(ctx context.Context, pair *configuration.Pair, name string, options SetOptions) (configurationSetPreparation, error) {
	confidential := options.Confidential
	encoding := contract.InputEncodingRaw
	if options.Base64 {
		encoding = contract.InputEncodingBase64
	}
	m, err := configuration.ParseForSet(ctx, pair, name)
	if err != nil {
		return configurationSetPreparation{}, setError("source", err)
	}
	if !m.Resolved || m.DomainID.IsZero() || m.FileID.IsZero() {
		return configurationSetPreparation{}, setError("prepared-source", nil)
	}
	checked := validateInstalledConfiguration(ctx, m.Public)
	if !checked.Valid || !checked.DiagnosticsComplete {
		return configurationSetPreparation{}, setError("public-configuration", nil)
	}
	basis, descriptor, err := configurationPublicBasis(m)
	if err != nil {
		return configurationSetPreparation{}, setError("public-basis", err)
	}
	control, err := basis.ControlCore(m.DomainID, descriptor)
	if err != nil {
		return configurationSetPreparation{}, setError("public-basis", err)
	}
	authority := setSourceBinding(m.Provider, m.Authority.Encryption, m.Authority.EncryptionSelector)
	if m.Authority.ID != control.AuthorityRecipientID || m.Authority.SigningSelector != control.NormalSigning.KeySelector || !bytes.Equal(m.Authority.Signing.PublicKey, control.NormalSigning.SPKI) || !setBindingEqual(authority, control.AuthorityKMSBinding) || m.RecoveryEnabled != (control.Recovery != nil) {
		return configurationSetPreparation{}, setError("prepared-keys", nil)
	}
	if control.Recovery != nil {
		recovery := setSourceBinding(m.Provider, m.Recovery.Encryption, m.Recovery.EncryptionSelector)
		if m.Recovery.SigningSelector != control.Recovery.Signing.KeySelector || !bytes.Equal(m.Recovery.Signing.PublicKey, control.Recovery.Signing.SPKI) || !setBindingEqual(recovery, control.Recovery.KMS) {
			return configurationSetPreparation{}, setError("prepared-keys", nil)
		}
	}
	edit, err := configuration.PrepareSuppliedEdit(pair, m, name, confidential, encoding)
	if err != nil {
		return configurationSetPreparation{}, setError("candidate-bounds", err)
	}
	knownRaw, members := uint64(0), 0
	var selectedRecipients []string
	present := false
	for _, entry := range m.Entries {
		members += 1 + len(entry.Recipients)
		if entry.Name == name {
			present = true
			selectedRecipients = entry.Recipients
			continue
		}
		if !entry.Secret {
			knownRaw += uint64(entry.ContentLength)
		} else if len(entry.Sealed) > 0 {
			view, err := contract.InspectSealedInputEnvelope(entry.Sealed)
			if err != nil {
				return configurationSetPreparation{}, setError("source", err)
			}
			knownRaw += uint64(view.Core.ContentLength)
		}
	}
	if !present {
		members++
	}
	if knownRaw > 8<<20 || members > 4096 {
		return configurationSetPreparation{}, setError("candidate-bounds", configuration.ErrEditBounds)
	}
	maximum := uint32(min(uint64(contract.CryptoMaxRawValue), (8<<20)-knownRaw))
	if _, err := edit.MaximumPairBytes(maximum); err != nil {
		return configurationSetPreparation{}, setError("candidate-bounds", err)
	}
	target := enkvcrypto.ConfigurationInputTarget{DomainID: m.DomainID, FileIdentity: m.FileID, FilePredecessorDigest: contract.ID(pair.Editable.Digest()), Name: name, AuthorityRecipientID: m.Authority.ID}
	if confidential {
		target.Bindings = append(target.Bindings, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: m.Authority.ID, Binding: authority})
		for _, ref := range selectedRecipients {
			found := false
			for _, recipient := range m.Recipients {
				if recipient.Reference == ref {
					found = true
					target.Bindings = append(target.Bindings, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: recipient.ID, Binding: setSourceBinding(m.Provider, recipient.Encryption, recipient.Selector)})
					break
				}
			}
			if !found {
				return configurationSetPreparation{}, setError("prepared-recipient", nil)
			}
		}
		sort.Slice(target.Bindings, func(i, j int) bool {
			return bytes.Compare(target.Bindings[i].SubjectID[:], target.Bindings[j].SubjectID[:]) < 0
		})
	}
	var recipientImage contract.ID
	if confidential {
		refs := make([]contract.RecipientBindingReference, len(target.Bindings))
		for i, row := range target.Bindings {
			digest, err := contract.PublicBindingDigest(row.Binding)
			if err != nil {
				return configurationSetPreparation{}, setError("prepared-recipient", err)
			}
			refs[i] = contract.RecipientBindingReference{RecipientID: row.SubjectID, PublicBindingDigest: digest}
		}
		recipientImage, err = contract.IntendedRecipientBindingSetDigest(target.DomainID, target.AuthorityRecipientID, refs)
		if err != nil {
			return configurationSetPreparation{}, setError("prepared-recipient", err)
		}
	}
	// Only target key facts and spans transfer into the sealing phase.
	missing := m.MissingInputs
	if at, present := slices.BinarySearch(missing, name); present {
		copy(missing[at:], missing[at+1:])
		missing[len(missing)-1] = ""
		missing = missing[:len(missing)-1]
	}
	*m = configuration.Model{}
	return configurationSetPreparation{edit: edit, missingInputs: missing, target: target, maximumRaw: maximum, recipientImage: recipientImage}, nil
}

func setSourceBinding(provider contract.Family, key configuration.Key, selector string) contract.KMSBinding {
	return contract.KMSBinding{BindingID: key.Binding.ID, BindingIncarnationID: key.Binding.Incarnation, BindingSerial: key.Binding.Serial, Provider: provider, WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: key.Binding.Protection, KeySelector: selector, SPKI: key.PublicKey, Fingerprint: contract.Hash(key.PublicKey)}
}

func setBindingEqual(a, b contract.KMSBinding) bool {
	return a.BindingID == b.BindingID && a.BindingIncarnationID == b.BindingIncarnationID && a.BindingSerial == b.BindingSerial && a.Provider == b.Provider && a.WrapProfile == b.WrapProfile && a.ProtectionClass == b.ProtectionClass && a.KeySelector == b.KeySelector && a.Fingerprint == b.Fingerprint && bytes.Equal(a.SPKI, b.SPKI)
}

func readSetPlain(ctx context.Context, input io.ReadCloser, encoded bool, maximum uint32) (plain []byte, resultErr error) {
	limit := int(maximum)
	if encoded {
		limit = base64.StdEncoding.EncodedLen(limit)
	}
	buffer := make([]byte, limit+1)
	observerDone := make(chan struct{})
	var closeErr error
	stop := context.AfterFunc(ctx, func() { closeErr = input.Close(); close(observerDone) })
	defer func() {
		if !stop() {
			<-observerDone
			if closeErr != nil {
				plain = nil
				resultErr = errors.Join(resultErr, setError("input-close", closeErr))
			}
		}
	}()
	n, empty := 0, 0
	for {
		if ctx.Err() != nil {
			return nil, setError("cancelled", ctx.Err())
		}
		count, err := input.Read(buffer[n:])
		if count < 0 || count > len(buffer)-n {
			return nil, setError("input", nil)
		}
		n += count
		if n > limit {
			return nil, setError("input-limit", configuration.ErrEditBounds)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, setError("input-read", err)
		}
		if count == 0 {
			empty++
			if empty >= 100 {
				return nil, setError("input-read", io.ErrNoProgress)
			}
		} else {
			empty = 0
		}
	}
	if !encoded {
		return buffer[:n], nil
	}
	content, err := contract.InputContentLength(contract.InputEncodingBase64, buffer[:n])
	if err != nil || content > maximum {
		return nil, setError("base64", err)
	}
	return buffer[:n], nil
}

func finishSetFailure(ctx context.Context, r *SetResult, err error) {
	r.StateResult = SetRefused
	var unknown *configuration.UnknownEdit
	var inputError *enkvcrypto.ConfigurationInputError
	var refusal *SetError
	switch {
	case errors.As(err, &unknown):
		r.StateResult = SetUnavailable
		r.localFailure = unknown
		if unknown != nil && unknown.Observation != nil {
			paths := unknown.Observation.Paths()
			if len(paths) >= 2 {
				r.EditablePath, r.GeneratedPath = paths[0], paths[1]
				r.failurePaths = [2]string{paths[0], paths[1]}
			}
		}
	case errors.As(err, &refusal) && refusal.reason == "unavailable":
		r.StateResult = SetUnavailable
	case errors.Is(err, configuration.ErrNativeEdit):
		r.StateResult = SetProfileBlocked
	case ctx != nil && ctx.Err() != nil:
		r.StateResult = SetUnavailable
	case errors.As(err, &inputError):
		switch inputError.Code {
		case contract.CryptoCustodyUnavailable, contract.CryptoCancelled, contract.CryptoExpired:
			r.StateResult = SetUnavailable
		}
	}
	if r.RequestIdentity == nil {
		stage := "dispatch"
		var refusal *SetError
		if errors.As(err, &refusal) && validSetFailureStage(refusal.reason) {
			stage = refusal.reason
		}
		r.PreAdmission = &SetPreAdmissionIdentity{Stage: stage, Code: string(r.StateResult)}
	}
}

func newSetResult(confidential bool, format configuration.Format) (*SetResult, error) {
	result := &SetResult{Confidential: confidential, StateResult: SetRefused, PreAdmission: &SetPreAdmissionIdentity{Stage: "dispatch", Code: "refused"}, sourceFormat: format}
	for _, id := range []*contract.ID{&result.OperationID, &result.RequestNonce} {
		if _, failure := rand.Read(id[:]); failure != nil || id.IsZero() {
			return result, setError("unavailable", failure)
		}
	}
	return result, nil
}

// NewSetRefusal supplies safe correlation for a recognized CLI request that
// fails dispatch validation. It grants no artifact, replay, or source fact.
func NewSetRefusal(confidential bool) (*SetResult, error) { return newSetResult(confidential, 0) }
