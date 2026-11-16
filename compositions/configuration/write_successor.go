package configuration

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// SuccessorOutput borrows the source pair until Close. Named output is checked
// before a caller can construct replacement capabilities. Installed output is
// retained on every failure; Close removes only private captured/staged images.
type SuccessorOutput struct {
	pairOutputDelivery
	path         string
	request      ReplacementRequest
	identity     SourcePairIdentity
	recipient    contract.ID
	recipientRow uint16
}
type SuccessorReadback struct {
	Pair  *Pair
	Model *Model
}

func PrepareSuccessorOutput(ctx context.Context, source *Pair, path string, request ReplacementRequest) (result *SuccessorOutput, resultErr error) {
	if source == nil {
		return nil, ErrEdit
	}
	capture, err := CaptureSuccessorOutput(ctx, path, source.Format)
	if err != nil {
		return nil, err
	}
	result, err = PrepareSuccessorOutputFromCapture(ctx, source, capture, request)
	if err != nil {
		return nil, errors.Join(err, capture.Close())
	}
	return result, nil
}

// PrepareSuccessorOutputFromCapture transfers the output capture only on
// success. Source remains borrowed. Failure keeps the parsed target available
// through SuccessorOutputRefusal even when source admission cannot complete.
func PrepareSuccessorOutputFromCapture(ctx context.Context, source *Pair, capture *SuccessorOutputCapture, request ReplacementRequest) (result *SuccessorOutput, resultErr error) {
	defer func() {
		if resultErr != nil && capture != nil {
			if target, known := capture.Target(); known {
				resultErr = &SuccessorOutputRefusal{Target: target, cause: resultErr}
			}
		}
	}()
	if ctx == nil || capture == nil || capture.closed || source == nil || source.Format != capture.format {
		return nil, ErrEdit
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	model, err := Parse(ctx, source)
	if err != nil {
		return nil, err
	}
	if !model.Resolved || !request.valid(model.Provider, model.RecoveryEnabled) {
		return nil, ErrEdit
	}
	model.Basis.clear()
	identity, err := pairIdentity(source)
	if err != nil {
		return nil, err
	}
	path := capture.path
	if path == source.Editable.path || path == source.Generated.path {
		return nil, ErrEdit
	}
	outputGenerated := filepath.Join(filepath.Dir(path), generatedPath(model.DomainName))
	if outputGenerated == source.Editable.path || outputGenerated == source.Generated.path || source.sourceDirectory != nil && os.SameFile(capture.directory, source.sourceDirectory) {
		return nil, ErrEdit
	}
	if capture.pair != nil {
		for _, outputImage := range []*Image{capture.pair.Editable, capture.pair.Generated} {
			for _, sourceImage := range []*Image{source.Editable, source.Generated} {
				if os.SameFile(outputImage.sourceInfo, sourceImage.sourceInfo) {
					return nil, ErrEdit
				}
			}
		}
	}
	s := &SuccessorOutput{
		pairOutputDelivery: pairOutputDelivery{capture: capture, source: source, model: model, io: nativeEditIO()},
		path:               path, request: request, identity: identity,
	}
	if request.Target == ReplaceRecipient {
		for _, r := range model.Recipients {
			if r.Reference == request.RecipientReference {
				s.recipient = r.ID
				break
			}
		}
		if s.recipient.IsZero() {
			return nil, ErrEdit
		}
		found := false
		for i, row := range model.GeneratedRecipients {
			if row.Reference == request.RecipientReference {
				s.recipientRow = uint16(i)
				found = true
				break
			}
		}
		if !found {
			return nil, ErrEdit
		}
	}
	if err := capture.CheckUnchanged(ctx); err != nil {
		return nil, err
	}
	if capture.pair != nil {
		if err := s.checkOutput(ctx, capture.pair, capture.model); err != nil {
			return nil, err
		}
		if err := source.CheckUnchanged(ctx); err != nil {
			return nil, err
		}
		s.existing, s.existingModel = capture.pair, capture.model
	}
	if capture.pair == nil {
		editor, err := beginPairOutput(ctx, source, path, source.Format, model.DomainName)
		if err != nil {
			return nil, err
		}
		if err := editor.locks.pinAlias(capture.aliasParent, filepath.Dir(capture.path)); err != nil {
			return nil, errors.Join(err, editor.Close())
		}
		if err := capture.checkDirectory(); err != nil {
			return nil, errors.Join(err, editor.Close())
		}
		s.editor = editor
	}
	return s, nil
}

func (s *SuccessorOutput) Existing() *Model {
	if s == nil || s.closed {
		return nil
	}
	return s.existingModel
}

func (s *SuccessorOutput) checkOutput(ctx context.Context, pair *Pair, m *Model) error {
	if m == nil || !m.Resolved || m.DomainName != s.model.DomainName || m.FileID != s.model.FileID || m.DomainID != s.model.DomainID || m.Store != s.model.Store || m.Provider != s.model.Provider || !m.Replacement.matches(s.identity, s.request, s.recipient) {
		return ErrEdit
	}
	h, err := m.Replacement.Candidate()
	if err != nil || h.Core.Domain != m.DomainID {
		return ErrEdit
	}
	store, err := contract.StoreConfigurationID(contract.StoreConfiguration{Provider: m.Provider, ConstructionProfile: contract.StoreConstructionProfile, DomainID: m.DomainID, Region: m.Store.Region, Bucket: m.Store.Bucket, PrefixBeforeHEAD: m.Store.PrefixBeforeHEAD, ExpectedOwner: m.Store.ExpectedOwner})
	if err != nil || h.Core.Store != store {
		return ErrEdit
	}
	switch s.request.Target {
	case ReplaceAuthority:
		if s.request.SigningSelector != "" && m.Authority.Signing.Selector != s.request.SigningSelector || s.request.EncryptionSelector != "" && m.Authority.Encryption.Selector != s.request.EncryptionSelector {
			return ErrEdit
		}
	case ReplaceRecovery:
		if !m.RecoveryEnabled || s.request.SigningSelector != "" && m.Recovery.Signing.Selector != s.request.SigningSelector || s.request.EncryptionSelector != "" && m.Recovery.Encryption.Selector != s.request.EncryptionSelector {
			return ErrEdit
		}
	case ReplaceRecipient:
		if h.Subject.Recipient != s.model.Authority.ID {
			return ErrEdit
		}
		found := false
		for _, r := range m.Recipients {
			if r.Reference == s.request.RecipientReference {
				found = r.ID == s.recipient && r.Encryption.Selector == s.request.EncryptionSelector
				break
			}
		}
		if !found {
			return ErrEdit
		}
	default:
		return ErrEdit
	}
	return s.checkProjection(ctx, pair, m)
}
func (s *SuccessorOutput) checkProjection(ctx context.Context, pair *Pair, model *Model) error {
	if pair == nil || pair.Generated == nil || pair.Editable == nil {
		return ErrEdit
	}
	editable, generated, err := s.projectionEdits(model)
	if err != nil {
		return err
	}
	digest := sha256.New()
	if err := CopyEdits(ctx, digest, s.source.Generated, generated); err != nil {
		return err
	}
	if !equalDigest(pair.Generated.digest, digest.Sum(nil)) {
		return ErrEdit
	}
	reference := generatedPath(model.DomainName)
	digest.Reset()
	if err := successorEditable(ctx, digest, s.source, s.model, editable, reference); err != nil {
		return err
	}
	if !equalDigest(pair.Editable.digest, digest.Sum(nil)) {
		return ErrEdit
	}
	return nil
}

// CheckUnchanged preserves the exact captured source and delivered output.
// A name which appears after absent-output admission is a conflict, not an
// instruction to change the invocation into observation or retry publication.
func (s *SuccessorOutput) CheckUnchanged(ctx context.Context) error {
	if s == nil {
		return ErrEdit
	}
	return s.checkUnchanged(ctx)
}

func (s *SuccessorOutput) Publish(ctx context.Context, material SuccessorMaterial) (*SuccessorReadback, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	readback, err := s.publish(editCallContext(ctx, call), material, call)
	finishEditCall(call, err)
	return readback, err
}

func (s *SuccessorOutput) publish(ctx context.Context, material SuccessorMaterial, call *telemetry.Call) (*SuccessorReadback, error) {
	if s == nil {
		return nil, ErrEdit
	}
	return s.pairOutputDelivery.publish(ctx, func(ctx context.Context) ([]Edit, []Edit, error) {
		return s.successorEdits(material)
	}, s.checkOutput, call)
}

func (s *SuccessorOutput) Close() error {
	if s == nil {
		return nil
	}
	return s.close()
}

// Delivered reports complete sync and exact reopened pair readback in this
// invocation. False establishes no absence or failure of an earlier attempt.
func (s *SuccessorOutput) Delivered() bool { return s != nil && s.delivered }

// LocalDelivery returns native pair readback independently of qualified
// successor delivery. Closing the output retains these immutable local facts.
func (s *SuccessorOutput) LocalDelivery() *PairDelivery {
	if s == nil {
		return nil
	}
	return s.localDelivery
}

// RecoverySource identifies a saved local transaction established by this
// invocation. Closing the output does not discard this recovery identity.
func (s *SuccessorOutput) RecoverySource() (string, bool) {
	if s == nil || s.recovery.source == "" || s.recovery.digest == "" {
		return "", false
	}
	return s.recovery.source, true
}

// OutputIdentity returns exact owned capture/readback facts, not a later
// currentness or delivery claim. Keep this output open and check its pins.
func (s *SuccessorOutput) OutputIdentity() (SourcePairIdentity, error) {
	if s == nil {
		return SourcePairIdentity{}, ErrEdit
	}
	return s.outputIdentity()
}
