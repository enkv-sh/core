package configuration

import (
	"context"
	"errors"
	"io"

	"enkv.sh/telemetry"
)

type pairOutputCapture interface {
	checkDirectory() error
	Close() error
}

// pairOutputDelivery owns local delivery for replacement and maintenance output.
// The operation supplies its edits and qualifies both staged and reopened pairs.
type pairOutputDelivery struct {
	capture           pairOutputCapture
	source            *Pair
	model             *Model
	existing          *Pair
	existingModel     *Model
	readback          *SuccessorReadback
	observation       *EditObservation
	editor            *EditSession
	io                editIO
	attempted, closed bool
	delivered         bool
	localDelivery     *PairDelivery
	recovery          pendingIdentity
}

func (s *pairOutputDelivery) checkDirectory() error {
	if s == nil || s.capture == nil {
		return ErrEdit
	}
	return s.capture.checkDirectory()
}

func (s *pairOutputDelivery) checkUnchanged(ctx context.Context) error {
	if s == nil || s.closed || ctx == nil {
		return ErrEdit
	}
	if err := s.checkDirectory(); err != nil {
		return err
	}
	if s.editor != nil {
		if s.readback == nil {
			return s.editor.CheckUnchanged(ctx)
		}
		if err := s.source.checkWithLocks(ctx, s.editor.locks); err != nil {
			return err
		}
		return s.readback.Pair.checkWithLocks(ctx, s.editor.locks)
	}
	if s.existing == nil {
		return ErrEdit
	}
	if err := s.source.CheckUnchanged(ctx); err != nil {
		return err
	}
	if err := s.existing.CheckUnchanged(ctx); err != nil {
		return err
	}
	return s.checkDirectory()
}

func (s *pairOutputDelivery) publish(ctx context.Context, edits func(context.Context) ([]Edit, []Edit, error), checkOutput func(context.Context, *Pair, *Model) error, call *telemetry.Call) (readback *SuccessorReadback, resultErr error) {
	if s == nil || s.closed || s.attempted || s.existing != nil || ctx == nil {
		return nil, ErrEdit
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	s.attempted = true
	if s.editor == nil {
		return nil, ErrEdit
	}
	if err := s.checkUnchanged(ctx); err != nil {
		return nil, err
	}
	editable, generated, err := edits(ctx)
	if err != nil {
		return nil, err
	}
	editor := s.editor
	editor.io = s.io
	candidate, model, err := editor.stage(ctx, func(w io.Writer) error {
		return CopyEdits(ctx, w, s.source.Generated, generated)
	}, func(w io.Writer, reference string) error {
		return successorEditable(ctx, w, s.source, s.model, editable, reference)
	})
	if err != nil {
		return nil, err
	}
	if err := checkOutput(ctx, candidate.pair, model); err != nil {
		return nil, err
	}
	delivery, err := editor.commit(ctx, candidate, call)
	s.localDelivery = delivery
	if err != nil {
		var unknown *UnknownEdit
		if errors.As(err, &unknown) {
			s.recovery = unknown.recovery
			s.observation = unknown.Observation
			err = errors.Join(err, s.observation.Close())
		}
		return nil, err
	}
	cleanupErr := candidate.close()
	editor.candidate = nil
	if cleanupErr != nil {
		_, cleanupErr = incompleteDelivery(editor.transaction, delivery, cleanupErr)
		return nil, cleanupErr
	}
	pair, model, err := editor.captureDelivery(ctx, delivery)
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			resultErr = errors.Join(resultErr, pair.Close())
		}
	}()
	if err := checkOutput(ctx, pair, model); err != nil {
		return nil, err
	}
	if err := s.source.checkWithLocks(ctx, editor.locks); err != nil {
		return nil, err
	}
	if err := pair.CheckUnchanged(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrEdit, err)
	}
	readback = &SuccessorReadback{Pair: pair, Model: model}
	s.readback, s.delivered = readback, true
	complete = true
	return readback, nil
}

func (s *pairOutputDelivery) close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.capture != nil {
		err = s.capture.Close()
	}
	if s.readback != nil {
		err = errors.Join(err, s.readback.Pair.Close())
	}
	if s.observation != nil {
		err = errors.Join(err, s.observation.Close())
		s.observation = nil
	}
	if s.editor != nil {
		err = errors.Join(err, s.editor.Close())
		s.editor = nil
	}
	s.existing, s.existingModel, s.readback = nil, nil, nil
	return err
}

func (s *pairOutputDelivery) outputIdentity() (SourcePairIdentity, error) {
	if s == nil || s.closed {
		return SourcePairIdentity{}, ErrEdit
	}
	if s.existing != nil {
		return pairIdentity(s.existing)
	}
	if s.readback != nil {
		return pairIdentity(s.readback.Pair)
	}
	return SourcePairIdentity{}, ErrEdit
}
