package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"slices"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

var errRetainedPreparation = errors.New("retained source preparation refused")

// materializeRetained prepares test input only after the public reconstruction
// owner has committed its complete authenticated projection. It derives public
// pins from that projection and grants no apply or private-consumer admission.
func materializeRetained(ctx context.Context, absSource string, representation configuration.Format, original publicPairImage, model *configuration.Model, projection *core.ReconstructionProjection) (err error) {
	stage := preparationRetainedSource
	defer func() {
		if err != nil {
			err = publicPreparationFailure{stage: stage, cause: err}
		}
	}()
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(absSource) || filepath.Clean(absSource) != absSource || model == nil || !model.Resolved || projection == nil {
		return errRetainedPreparation
	}
	provenance, ok := projection.Provenance()
	if !ok || provenance.Domain != model.DomainID {
		return errRetainedPreparation
	}
	stage = preparationRetainedCapture
	session, err := configuration.BeginEdit(ctx, absSource, representation)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, session.Close()) }()
	locked, err := configuration.Parse(ctx, session.Pair())
	if err != nil || !original.matches(session.Pair()) {
		return errors.Join(errRetainedPreparation, err)
	}
	stage = preparationRetainedProjection
	pins, err := retainedProjectionPins(ctx, locked, projection)
	if err != nil {
		return err
	}
	current, ok := projection.Provenance()
	if !ok || current != provenance || int(locked.GeneratedSpan) >= len(locked.Spans) {
		return errRetainedPreparation
	}
	updated := *locked
	updated.Entries = slices.Clone(locked.Entries)
	for i := range updated.Entries {
		entry := &updated.Entries[i]
		if pin, selected := pins[entry.Name]; selected {
			entry.Sealed = nil
			entry.Retained = &pin
		}
	}
	span := locked.Spans[locked.GeneratedSpan]
	if span.Kind != configuration.SpanGeneratedReference {
		return errRetainedPreparation
	}
	stage = preparationRetainedStage
	candidate, staged, err := session.Stage(ctx, func(out io.Writer) error {
		return configuration.EmitGenerated(out, &updated)
	}, func(out io.Writer, reference string) error {
		encoded, err := json.Marshal(reference)
		if err != nil {
			return err
		}
		return configuration.CopyEdits(ctx, out, session.Pair().Editable, []configuration.Edit{{Offset: span.Offset, Length: span.Length, Replacement: encoded}})
	})
	if err != nil {
		return err
	}
	stage = preparationRetainedMeaning
	if !sameRetainedMeaning(&updated, staged) {
		return errRetainedPreparation
	}
	stage = preparationRetainedCommit
	_, err = session.Commit(ctx, candidate)
	return closeEditObservation(err)
}

func closeEditObservation(err error) error {
	var unknown *configuration.UnknownEdit
	if errors.As(err, &unknown) && unknown != nil && unknown.Observation != nil {
		return errors.Join(err, unknown.Observation.Close())
	}
	return err
}

func retainedProjectionPins(ctx context.Context, model *configuration.Model, projection *core.ReconstructionProjection) (map[string]configuration.Pin, error) {
	wanted := make(map[string]contract.PublicEntry, len(model.Entries))
	secretCount := 0
	for _, entry := range model.Public.Entries.Value {
		if entry.Source.State != contract.PublicPresent || entry.Source.Value != contract.Supplied || entry.Class.State != contract.PublicPresent || entry.Memberships.State != contract.PublicPresent {
			return nil, errRetainedPreparation
		}
		wanted[entry.Name] = entry
		if entry.Class.Value == contract.Secret {
			secretCount++
		}
	}
	if model.Public.Entries.State != contract.PublicPresent || len(wanted) != len(model.Entries) || secretCount < 1 || secretCount > 2 {
		return nil, errRetainedPreparation
	}
	pins := make(map[string]configuration.Pin, secretCount)
	seen := make(map[string]bool, len(wanted))
	for i, count := 0, projection.PartCount(); i < count; i++ {
		if ctx.Err() != nil {
			return nil, errors.Join(errRetainedPreparation, ctx.Err())
		}
		part, ok := projection.CopyPart(i)
		if !ok {
			return nil, errRetainedPreparation
		}
		if part.Kind != core.ReconstructionValuePagePart {
			clear(part.Body[:cap(part.Body)])
			continue
		}
		if err := retainValuePage(part, model.DomainID, wanted, seen, pins); err != nil {
			return nil, err
		}
	}
	if len(seen) != len(wanted) || len(pins) != secretCount {
		return nil, errRetainedPreparation
	}
	return pins, nil
}

func retainValuePage(part core.ReconstructionPart, domain contract.ID, wanted map[string]contract.PublicEntry, seen map[string]bool, pins map[string]configuration.Pin) error {
	defer clear(part.Body[:cap(part.Body)])
	page, err := format.DecodeValueEntryPage(part.Body)
	if err != nil || page.Domain != domain || page.Object != part.Ref.Object || page.Index != part.Ref.Index {
		return errRetainedPreparation
	}
	defer func() {
		for _, entry := range page.Slots {
			if entry != nil {
				clear(entry.ValueBytes[:cap(entry.ValueBytes)])
			}
		}
	}()
	for _, entry := range page.Slots {
		if entry == nil {
			continue
		}
		want, ok := wanted[entry.Name]
		if !ok || seen[entry.Name] || entry.ValueSource != want.Source.Value || entry.ConfidentialityClass != want.Class.Value {
			return errRetainedPreparation
		}
		members := slices.Clone(want.Memberships.Value)
		slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		if !slices.Equal(members, entry.Recipients) {
			return errRetainedPreparation
		}
		seen[entry.Name] = true
		if entry.ConfidentialityClass == contract.Secret {
			pins[entry.Name] = configuration.Pin{Incarnation: entry.Incarnation, Material: entry.ValueState}
		} else if want.PlainValue.State != contract.PublicPresent || !bytes.Equal(want.PlainValue.Value, entry.ValueBytes) {
			return errRetainedPreparation
		}
	}
	return nil
}

func sameRetainedMeaning(expected, actual *configuration.Model) bool {
	if actual == nil || !actual.Resolved || expected.FileID != actual.FileID || expected.DomainID != actual.DomainID ||
		!reflect.DeepEqual(expected.Public, actual.Public) || !reflect.DeepEqual(expected.Authority, actual.Authority) ||
		expected.RecoveryEnabled != actual.RecoveryEnabled || !reflect.DeepEqual(expected.Recovery, actual.Recovery) ||
		!reflect.DeepEqual(expected.Basis, actual.Basis) || !reflect.DeepEqual(expected.Observation, actual.Observation) ||
		len(expected.Recipients) != len(actual.Recipients) || len(expected.Entries) != len(actual.Entries) {
		return false
	}
	for i, want := range expected.Recipients {
		got := actual.Recipients[i]
		want.EditableSpan, want.GeneratedSpan, got.EditableSpan, got.GeneratedSpan = 0, 0, 0, 0
		if !reflect.DeepEqual(want, got) {
			return false
		}
	}
	for i, want := range expected.Entries {
		got := actual.Entries[i]
		want.EntrySpan, want.SecretSpan, got.EntrySpan, got.SecretSpan = 0, 0, 0, 0
		if !reflect.DeepEqual(want, got) {
			return false
		}
	}
	return true
}
