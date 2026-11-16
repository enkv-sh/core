package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// The caller supplies an isolated exact copy as the output predecessor. The
// installed reconstruction and separately retained basis supply all new facts.
func emitReconstructedPair(ctx context.Context, source *configuration.Pair, model *configuration.Model, projection *core.ReconstructionProjection, output string) (err error) {
	if source == nil || model == nil || source.Editable == nil || source.Generated == nil || !filepath.IsAbs(output) || filepath.Clean(output) != output || filepath.Dir(output) == filepath.Dir(source.Editable.OriginalPath()) {
		return errRetainedPreparation
	}
	basis, _, _, err := publicSourceBasis(model)
	if err != nil {
		return err
	}
	var fileID contract.ID
	if _, err := rand.Read(fileID[:]); err != nil || fileID.IsZero() {
		return errors.Join(errRetainedPreparation, err)
	}
	current, err := compositionfull.ReconstructionConfiguration(ctx, projection, basis, compositionfull.ReconstructionConfigurationOptions{Name: model.DomainName, FileID: fileID})
	if err != nil {
		return err
	}
	session, err := configuration.BeginEdit(ctx, output, source.Format)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, session.Close()) }()
	if !capturedPublicPair(source).matches(session.Pair()) {
		return errRetainedPreparation
	}
	for _, before := range []*configuration.Image{source.Editable, source.Generated} {
		info, err := os.Stat(before.OriginalPath())
		if err != nil {
			return err
		}
		for _, target := range []*configuration.Image{session.Pair().Editable, session.Pair().Generated} {
			other, err := os.Stat(target.OriginalPath())
			first, firstOK := info.Sys().(*syscall.Stat_t)
			var second *syscall.Stat_t
			if other != nil {
				second, _ = other.Sys().(*syscall.Stat_t)
			}
			if err != nil || !firstOK || second == nil || first.Ino == second.Ino {
				return errors.Join(errRetainedPreparation, err)
			}
		}
	}
	candidate, _, err := session.Stage(ctx, func(out io.Writer) error {
		return configuration.EmitGenerated(out, current)
	}, func(out io.Writer, reference string) error {
		if reference != current.Generated {
			return errRetainedPreparation
		}
		return configuration.EmitEditable(out, current, source.Format)
	})
	if err != nil {
		return err
	}
	if _, err = session.Commit(ctx, candidate); err != nil {
		return closeEditObservation(err)
	}
	return source.CheckUnchanged(ctx)
}
