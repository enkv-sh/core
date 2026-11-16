package configuration

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"enkv.sh/telemetry"
)

// BeginCompanionReconstruction captures a surviving declaration and holds its
// source and absent companion namespaces through reconstruction. The returned
// source model belongs to the caller and borrows the output's captured images.
// Neither the declaration nor its destination supplies domain authentication.
func BeginCompanionReconstruction(ctx context.Context, path string, format Format) (*ReconstructionOutput, *Model, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	output, model, err := beginCompanionReconstruction(editCallContext(ctx, call), path, format)
	finishEditCall(call, err)
	return output, model, err
}

func beginCompanionReconstruction(ctx context.Context, path string, format Format) (output *ReconstructionOutput, model *Model, resultErr error) {
	if ctx == nil || !localPathValid(path) || format != JSON && format != YAML {
		return nil, nil, ErrEdit
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, errors.Join(ErrEdit, err)
	}
	originalParent := strings.Clone(filepath.Dir(path))
	path, err := canonicalDestination(path)
	if err != nil {
		return nil, nil, err
	}
	if err := checkEditableParent(filepath.Dir(path)); err != nil {
		return nil, nil, err
	}
	if err := refusePending([]string{path}); err != nil {
		return nil, nil, err
	}
	temporary, valid := temporaryDirectory()
	if !valid {
		return nil, nil, ErrEditBounds
	}
	discovery, err := captureInDirectory(ctx, path, MaxPairBytes, temporary)
	if err != nil {
		return nil, nil, err
	}
	names, parseErr := parseEditableMode(ctx, discovery, format, true, nil)
	if err := errors.Join(parseErr, discovery.Close()); err != nil {
		return nil, nil, err
	}
	if names.Generated == "" {
		return nil, nil, sourceError("generated", "restore-exact-generated-file")
	}
	reference, name := names.Generated, names.DomainName
	names = nil
	generated := filepath.Join(filepath.Dir(path), reference)
	paths := []string{path, generated}
	if err := refusePending(paths); err != nil {
		return nil, nil, err
	}
	if err := checkEditDestinationAbsent(generated, true); err != nil {
		return nil, nil, err
	}
	if err := preflightEditDisk([]string{filepath.Dir(path), temporary}, nativeEditIO()); err != nil {
		return nil, nil, err
	}
	if err := ensureEditDirectory(filepath.Dir(generated), syncEditDirectory); err != nil {
		return nil, nil, err
	}
	locks, err := openPathLocks(paths, false, true)
	if err != nil {
		return nil, nil, err
	}
	session := &EditSession{path: path, temporaryDirectory: temporary, format: format, reference: reference, sourceName: name, locks: locks, io: nativeEditIO()}
	var ownedModel *Model
	complete := false
	defer func() {
		if !complete {
			releaseReconstructionModel(ownedModel)
			model = nil
			resultErr = errors.Join(resultErr, session.Close())
		}
	}()
	if err := locks.pinAlias(originalParent, filepath.Dir(path)); err != nil {
		return nil, nil, err
	}
	if err := refusePending(paths); err != nil {
		return nil, nil, err
	}
	if err := checkEditDestinationAbsent(generated, true); err != nil {
		return nil, nil, err
	}
	if err := session.prepareDirectories(); err != nil {
		return nil, nil, err
	}
	pair := &Pair{Format: format, ownedLocks: locks, sourceDirectory: locks.directories[filepath.Dir(path)], aliasParent: originalParent, aliasDirectory: locks.aliases[originalParent]}
	session.predecessor = pair
	pair.Editable, err = captureInDirectory(ctx, path, MaxPairBytes, temporary)
	if err != nil {
		return nil, nil, err
	}
	if err := sealPair(pair); err != nil {
		return nil, nil, err
	}
	model, err = parseEditableMode(ctx, pair.Editable, format, false, nil)
	ownedModel = model
	if err != nil {
		return nil, nil, err
	}
	if model.Generated != reference || model.DomainName != name {
		return nil, nil, errors.Join(ErrEdit, ErrSourceChanged)
	}
	model.parsedPair = pair
	if err := pair.Editable.removeName(); err != nil {
		return nil, nil, err
	}
	output = &ReconstructionOutput{editor: session}
	if err := output.CheckUnchanged(ctx); err != nil {
		return nil, nil, err
	}
	complete = true
	return output, model, nil
}
