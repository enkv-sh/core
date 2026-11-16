package configuration

import (
	"context"
	"errors"
	"io"
	"sort"

	"enkv.sh/telemetry"
)

func BeginRename(ctx context.Context, path string, format Format, newName string) (*EditSession, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	if !domainNameValid(newName) {
		finishEditCall(call, ErrEdit)
		return nil, ErrEdit
	}
	session, err := beginEditForName(editCallContext(ctx, call), path, format, newName)
	finishEditCall(call, err)
	return session, err
}

func (s *EditSession) StageRename(ctx context.Context) (*EditCandidate, *Model, error) {
	if s == nil || s.targetName == "" || s.renameOld == "" || s.closed {
		return nil, nil, ErrEdit
	}
	model, err := Parse(ctx, s.predecessor)
	if err != nil {
		return nil, nil, err
	}
	nameSpan := model.Spans[model.DomainNameSpan]
	name, err := editableStringBytes(s.targetName, s.predecessor.Format, nameSpan, false)
	if err != nil {
		return nil, nil, err
	}
	edits := []Edit{{Offset: nameSpan.Offset, Length: nameSpan.Length, Replacement: name}}
	if s.predecessor.Generated != nil {
		span := model.Spans[model.GeneratedSpan]
		reference, err := editableStringBytes(s.reference, s.predecessor.Format, span, false)
		if err != nil {
			return nil, nil, err
		}
		edits = append(edits, Edit{Offset: span.Offset, Length: span.Length, Replacement: reference})
	}
	model = nil
	sort.Slice(edits, func(i, j int) bool { return edits[i].Offset < edits[j].Offset })
	candidate, prepared, err := s.Stage(ctx, nil, func(w io.Writer, _ string) error { return CopyEdits(ctx, w, s.predecessor.Editable, edits) })
	if err != nil {
		return nil, nil, err
	}
	if prepared.DomainName != s.targetName {
		return nil, nil, errors.Join(ErrEdit, candidate.close())
	}
	return candidate, prepared, nil
}
