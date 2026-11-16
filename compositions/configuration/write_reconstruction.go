package configuration

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"enkv.sh/telemetry"
)

// ReconstructionOutput holds destination namespaces and any surviving source
// capture until Close.
// Stage consumes its model; its returned model is borrowed until Commit or Close.
type ReconstructionOutput struct {
	editor      *EditSession
	staged      *Model
	pair        *Pair
	model       *Model
	delivery    *PairDelivery
	observation *EditObservation
	closed      bool
}

// BeginReconstruction admits only an absent pair before remote reconstruction.
// The explicit local name selects the stable satellite, not domain authority.
func BeginReconstruction(ctx context.Context, path string, format Format, name string) (*ReconstructionOutput, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	output, err := beginReconstruction(editCallContext(ctx, call), path, format, name)
	finishEditCall(call, err)
	return output, err
}

func beginReconstruction(ctx context.Context, path string, format Format, name string) (*ReconstructionOutput, error) {
	if ctx == nil || ctx.Err() != nil || !localPathValid(path) || format != JSON && format != YAML || !domainNameValid(name) {
		return nil, ErrEdit
	}
	originalParent := strings.Clone(filepath.Dir(path))
	path, err := canonicalDestination(path)
	if err != nil {
		return nil, err
	}
	if err := checkEditableParent(filepath.Dir(path)); err != nil {
		return nil, err
	}
	reference := generatedPath(name)
	paths := []string{path, filepath.Join(filepath.Dir(path), reference)}
	if err := refusePending(paths); err != nil {
		return nil, err
	}
	for index, destination := range paths {
		if err := checkEditDestinationAbsent(destination, index == 1); err != nil {
			return nil, err
		}
	}
	temporary, valid := temporaryDirectory()
	if !valid {
		return nil, ErrEditBounds
	}
	if err := preflightEditDisk([]string{filepath.Dir(path), temporary}, nativeEditIO()); err != nil {
		return nil, err
	}
	if err := ensureEditDirectory(filepath.Dir(paths[1]), syncEditDirectory); err != nil {
		return nil, err
	}
	locks, err := openPathLocks(paths, false, true)
	if err != nil {
		return nil, err
	}
	session := &EditSession{path: path, temporaryDirectory: temporary, format: format, reference: reference, sourceName: strings.Clone(name), locks: locks, io: nativeEditIO()}
	if err := locks.pinAlias(originalParent, filepath.Dir(path)); err != nil {
		return nil, errors.Join(err, session.Close())
	}
	if err := session.prepareDirectories(); err != nil {
		return nil, errors.Join(err, session.Close())
	}
	if err := session.CheckUnchanged(ctx); err != nil {
		return nil, errors.Join(err, session.Close())
	}
	return &ReconstructionOutput{editor: session}, nil
}

// Stage consumes the complete normalized model, stages both images and returns
// the parsed staged model. The caller must authenticate and validate that model
// before Commit; parsing alone grants no authority.
func (o *ReconstructionOutput) Stage(ctx context.Context, model *Model) (*Model, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	staged, err := o.stage(editCallContext(ctx, call), model)
	finishEditCall(call, err)
	return staged, err
}

func (o *ReconstructionOutput) stage(ctx context.Context, model *Model) (*Model, error) {
	defer func() { releaseReconstructionModel(model) }()
	if o == nil || o.closed || o.editor == nil || model == nil || !model.Resolved || model.DomainName != o.editor.sourceName || model.Generated != o.editor.reference || len(model.Basis.Descriptor) != 0 || len(model.Basis.Control) != 0 || len(model.Basis.Selection) != 0 || len(model.Basis.Enrollment) != 0 || len(model.Basis.SigningAnchor) == 0 {
		return nil, ErrEdit
	}
	if err := o.CheckUnchanged(ctx); err != nil {
		return nil, err
	}
	emitEditable := func(w io.Writer, _ string) error { return EmitEditable(w, model, o.editor.format) }
	if o.editor.predecessor != nil {
		emitEditable = func(w io.Writer, _ string) error {
			_, err := o.editor.predecessor.Editable.CopyTo(w)
			return err
		}
	}
	_, staged, err := o.editor.stageConsumed(ctx,
		func(w io.Writer) error { return EmitGenerated(w, model) },
		emitEditable, model, true)
	if err != nil {
		return nil, err
	}
	o.staged = staged
	return staged, nil
}

func releaseReconstructionModel(model *Model) {
	if model == nil {
		return
	}
	model.Basis.clear()
	*model = Model{}
}

// Commit releases the borrowed staged model and installs only its fixed bytes.
// Confirmed native delivery survives a later cleanup or capture failure.
func (o *ReconstructionOutput) Commit(ctx context.Context) (*PairDelivery, error) {
	if o == nil || o.closed || o.editor == nil || o.staged == nil {
		return nil, ErrEdit
	}
	releaseReconstructionModel(o.staged)
	o.staged = nil
	delivery, err := o.editor.Commit(ctx, o.editor.candidate)
	o.delivery = delivery
	var unknown *UnknownEdit
	if errors.As(err, &unknown) {
		o.observation = unknown.Observation
	}
	if err != nil {
		return delivery, err
	}
	err = o.editor.candidate.close()
	o.editor.candidate = nil
	if err != nil {
		return incompleteDelivery(o.editor.transaction, delivery, err)
	}
	return delivery, err
}

// Capture borrows the delivered pair and its parsed model until Close. It uses
// the existing exclusive lock owner and accepts only complete clean delivery.
func (o *ReconstructionOutput) Capture(ctx context.Context) (pair *Pair, model *Model, resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	defer func() { finishEditCall(call, resultErr) }()
	if o == nil || o.closed || o.editor == nil || o.pair != nil || o.delivery == nil || o.delivery.cleanupFailed || o.editor.candidate != nil {
		return nil, nil, ErrEdit
	}
	pair, model, err := o.editor.captureDeliveryMode(editCallContext(ctx, call), o.delivery, true)
	if err != nil {
		return nil, nil, err
	}
	o.pair, o.model = pair, model
	return pair, model, nil
}

// CheckUnchanged checks captured source images and admitted destination absence,
// or the captured delivered pair.
func (o *ReconstructionOutput) CheckUnchanged(ctx context.Context) error {
	if o == nil || o.closed || o.editor == nil {
		return ErrEdit
	}
	if o.pair != nil {
		return o.pair.CheckUnchanged(ctx)
	}
	if o.editor.attempted {
		return ErrEdit
	}
	if err := o.editor.CheckUnchanged(ctx); err != nil {
		return err
	}
	if o.editor.predecessor != nil {
		return checkEditDestinationAbsent(filepath.Join(filepath.Dir(o.editor.path), o.editor.reference), true)
	}
	return nil
}

// Close releases semantic owners and captured images before the native locks.
// An interrupted transaction retains its exact saved candidate on disk.
func (o *ReconstructionOutput) Close() error {
	if o == nil || o.closed {
		return nil
	}
	o.closed = true
	releaseReconstructionModel(o.staged)
	releaseReconstructionModel(o.model)
	err := o.pair.Close()
	err = errors.Join(err, o.observation.Close())
	if o.editor != nil {
		err = errors.Join(err, o.editor.Close())
	}
	o.staged, o.model, o.pair, o.editor, o.observation = nil, nil, nil, nil, nil
	return err
}
