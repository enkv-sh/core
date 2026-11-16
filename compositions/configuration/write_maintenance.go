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

// MaintenanceOutput borrows the source pair until Close. Named output is checked
// before a caller can construct maintenance capabilities. Installed output is
// retained on every failure; Close removes only private captured/staged images.
type MaintenanceOutput struct {
	pairOutputDelivery
	path     string
	request  MaintenanceRequest
	identity SourcePairIdentity
}

func PrepareMaintenanceOutput(ctx context.Context, source *Pair, path string, request MaintenanceRequest) (result *MaintenanceOutput, resultErr error) {
	if source == nil {
		return nil, ErrEdit
	}
	capture, err := CaptureMaintenanceOutput(ctx, path, source.Format)
	if err != nil {
		return nil, err
	}
	result, err = PrepareMaintenanceOutputFromCapture(ctx, source, capture, request)
	if err != nil {
		return nil, errors.Join(err, capture.Close())
	}
	return result, nil
}

// PrepareMaintenanceOutputFromCapture transfers the output capture only on
// success. Source remains borrowed. Failure keeps the parsed target available
// through MaintenanceOutputRefusal even when source admission cannot complete.
func PrepareMaintenanceOutputFromCapture(ctx context.Context, source *Pair, capture *MaintenanceOutputCapture, request MaintenanceRequest) (result *MaintenanceOutput, resultErr error) {
	defer func() {
		if resultErr != nil && capture != nil {
			if request, known := capture.Request(); known {
				resultErr = &MaintenanceOutputRefusal{Request: request, cause: resultErr}
			}
		}
	}()
	if ctx == nil || capture == nil || capture.closed || source == nil || source.Format != capture.format {
		return nil, ErrEdit
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	if !request.valid() {
		return nil, ErrEdit
	}
	selected := &Model{}
	if request.OperationKind == contract.OperationRetireRecipientIdentity {
		selected.maintenance = true
		selected.selectedReference = &request.RecipientReference
	}
	model, err := parseEditModel(ctx, source, selected)
	if err != nil {
		return nil, err
	}
	if !model.Resolved || !request.valid() {
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
	s := &MaintenanceOutput{
		pairOutputDelivery: pairOutputDelivery{capture: capture, source: source, model: model, io: nativeEditIO()},
		path:               path, request: request, identity: identity,
	}
	if request.OperationKind == contract.OperationRetireRecipientIdentity {
		found := false
		for _, row := range model.Recipients {
			if row.Reference != request.RecipientReference {
				continue
			}
			binding := contract.KMSBinding{BindingID: row.Encryption.Binding.ID, BindingIncarnationID: row.Encryption.Binding.Incarnation, BindingSerial: row.Encryption.Binding.Serial, Provider: model.Provider, WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: row.Encryption.Binding.Protection, KeySelector: row.Encryption.Selector, SPKI: row.Encryption.PublicKey, Fingerprint: contract.Hash(row.Encryption.PublicKey)}
			digest, err := contract.PublicBindingDigest(binding)
			if err != nil || row.ID != request.RecipientID || digest != request.BindingDigest {
				return nil, ErrEdit
			}
			found = true
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

func (s *MaintenanceOutput) Existing() *Model {
	if s == nil || s.closed {
		return nil
	}
	return s.existingModel
}

func (s *MaintenanceOutput) checkOutput(ctx context.Context, pair *Pair, m *Model) error {
	if m == nil || !m.Resolved || m.DomainName != s.model.DomainName || m.FileID != s.model.FileID || m.DomainID != s.model.DomainID || m.Store != s.model.Store || m.Provider != s.model.Provider || m.Maintenance == nil || m.Maintenance.Source != s.identity || m.Maintenance.Request != s.request || m.Maintenance.FileID != m.FileID || m.Maintenance.OutputPath != s.path {
		return ErrEdit
	}
	h, err := m.Maintenance.Candidate()
	if err != nil || h.Core.Domain != m.DomainID || h.Subject.Recipient != s.model.Authority.ID {
		return ErrEdit
	}
	store, err := contract.StoreConfigurationID(contract.StoreConfiguration{Provider: m.Provider, ConstructionProfile: contract.StoreConstructionProfile, DomainID: m.DomainID, Region: m.Store.Region, Bucket: m.Store.Bucket, PrefixBeforeHEAD: m.Store.PrefixBeforeHEAD, ExpectedOwner: m.Store.ExpectedOwner})
	if err != nil || h.Core.Store != store {
		return ErrEdit
	}
	return s.checkProjection(ctx, pair, m)
}
func (s *MaintenanceOutput) checkProjection(ctx context.Context, pair *Pair, model *Model) error {
	if pair == nil || pair.Generated == nil || pair.Editable == nil {
		return ErrEdit
	}
	editable, generated, err := s.projectionEdits(ctx, model.Maintenance)
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
func (s *MaintenanceOutput) CheckUnchanged(ctx context.Context) error {
	if s == nil {
		return ErrEdit
	}
	return s.checkUnchanged(ctx)
}

func (s *MaintenanceOutput) Publish(ctx context.Context, material MaintenanceMaterial) (*SuccessorReadback, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	readback, err := s.publish(editCallContext(ctx, call), material, call)
	finishEditCall(call, err)
	return readback, err
}

func (s *MaintenanceOutput) publish(ctx context.Context, material MaintenanceMaterial, call *telemetry.Call) (*SuccessorReadback, error) {
	if s == nil {
		return nil, ErrEdit
	}
	return s.pairOutputDelivery.publish(ctx, func(ctx context.Context) ([]Edit, []Edit, error) {
		return s.maintenanceEdits(ctx, material)
	}, s.checkOutput, call)
}

func (s *MaintenanceOutput) Close() error {
	if s == nil {
		return nil
	}
	return s.close()
}

// Delivered reports complete sync and exact reopened pair readback in this
// invocation. False establishes no absence or failure of an earlier attempt.
func (s *MaintenanceOutput) Delivered() bool { return s != nil && s.delivered }

// LocalDelivery returns native pair readback independently of qualified
// successor delivery. Closing the output retains these immutable local facts.
func (s *MaintenanceOutput) LocalDelivery() *PairDelivery {
	if s == nil {
		return nil
	}
	return s.localDelivery
}

// RecoverySource identifies a saved local transaction established by this
// invocation. Closing the output does not discard this recovery identity.
func (s *MaintenanceOutput) RecoverySource() (string, bool) {
	if s == nil || s.recovery.source == "" || s.recovery.digest == "" {
		return "", false
	}
	return s.recovery.source, true
}

// OutputIdentity returns exact owned capture/readback facts, not a later
// currentness or delivery claim. Keep this output open and check its pins.
func (s *MaintenanceOutput) OutputIdentity() (SourcePairIdentity, error) {
	if s == nil {
		return SourcePairIdentity{}, ErrEdit
	}
	return s.outputIdentity()
}

// Path returns the canonical output location fixed during capture.
func (s *MaintenanceOutput) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Request returns the exact target fixed before private construction.
func (s *MaintenanceOutput) Request() MaintenanceRequest {
	if s == nil || s.closed {
		return MaintenanceRequest{}
	}
	return s.request
}

// SourceIdentity returns the complete captured pair identity fixed at admission.
func (s *MaintenanceOutput) SourceIdentity() SourcePairIdentity {
	if s == nil || s.closed {
		return SourcePairIdentity{}
	}
	return s.identity
}
