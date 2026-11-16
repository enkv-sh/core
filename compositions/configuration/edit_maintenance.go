package configuration

import (
	"bytes"
	"context"
	"io"
	"sort"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type MaintenanceValuePage struct {
	Index uint16
	Body  []byte
}

type MaintenanceMaterial struct {
	RequestIdentity                   contract.ID
	SignedCandidate                   []byte
	PinDeltas                         []MaintenancePinDelta
	Retirement                        *contract.RecipientRetirementRow
	RekeyTarget                       *contract.SecretAccessTarget
	PredecessorHead, PredecessorRoot  []byte
	PredecessorPages                  []MaintenanceValuePage
	CandidateRoot                     []byte
	CandidatePages                    []MaintenanceValuePage
	BeforeGeneration, AfterGeneration contract.ID
}

// A removal retains only the exact live collection and its bounded item spans.
// Historical signed and sealed records are never searched for matching IDs.
type maintenanceRemoval struct {
	container   Span
	items       []Span
	selected    int
	array       bool
	ownerColumn uint64
}

func (s *MaintenanceOutput) maintenanceEdits(ctx context.Context, material MaintenanceMaterial) ([]Edit, []Edit, error) {
	h, err := format.DecodeHead(material.SignedCandidate)
	if err != nil {
		return nil, nil, ErrEdit
	}
	metadata := &MaintenanceMetadata{Request: s.request, Source: s.identity, FileID: s.model.FileID, OutputPath: s.path, RequestIdentity: material.RequestIdentity, RequestCoreDigest: h.Subject.Request, OperationID: h.Subject.Operation, SignedCandidate: material.SignedCandidate, PinDeltas: material.PinDeltas,
		PredecessorHead: material.PredecessorHead, PredecessorRoot: material.PredecessorRoot, PredecessorPages: material.PredecessorPages, CandidateRoot: material.CandidateRoot, CandidatePages: material.CandidatePages,
		BeforeGeneration: material.BeforeGeneration, AfterGeneration: material.AfterGeneration, Retirement: material.Retirement, RekeyTarget: material.RekeyTarget}
	if !metadata.materialCapacity() {
		return nil, nil, ErrEdit
	}
	metadata.PinDeltas = append([]MaintenancePinDelta(nil), material.PinDeltas...)
	sort.Slice(metadata.PinDeltas, func(i, j int) bool { return metadata.PinDeltas[i].Name < metadata.PinDeltas[j].Name })
	if _, err := metadata.Candidate(); err != nil {
		return nil, nil, err
	}
	metadata.SignedCandidate = bytes.Clone(material.SignedCandidate)
	metadata.PredecessorHead = bytes.Clone(material.PredecessorHead)
	metadata.PredecessorRoot = bytes.Clone(material.PredecessorRoot)
	metadata.PredecessorPages = make([]MaintenanceValuePage, len(material.PredecessorPages))
	for i, page := range material.PredecessorPages {
		metadata.PredecessorPages[i] = MaintenanceValuePage{Index: page.Index, Body: bytes.Clone(page.Body)}
	}
	metadata.CandidateRoot = bytes.Clone(material.CandidateRoot)
	metadata.CandidatePages = make([]MaintenanceValuePage, len(material.CandidatePages))
	for i, page := range material.CandidatePages {
		metadata.CandidatePages[i] = MaintenanceValuePage{Index: page.Index, Body: bytes.Clone(page.Body)}
	}
	if material.Retirement != nil {
		row := *material.Retirement
		metadata.Retirement = &row
	}
	if material.RekeyTarget != nil {
		target := *material.RekeyTarget
		metadata.RekeyTarget = &target
	}
	if h.Core.Domain != s.model.DomainID {
		return nil, nil, ErrEdit
	}
	return s.projectionEdits(ctx, metadata)
}

func (s *MaintenanceOutput) projectionEdits(ctx context.Context, metadata *MaintenanceMetadata) ([]Edit, []Edit, error) {
	if metadata == nil || metadata.Request != s.request || metadata.Source != s.identity || metadata.FileID != s.model.FileID || metadata.OutputPath != s.path {
		return nil, nil, ErrEdit
	}
	if _, err := metadata.Candidate(); err != nil {
		return nil, nil, err
	}
	m := s.model
	var editable, generated []Edit
	if s.request.OperationKind == contract.OperationRetireRecipientIdentity {
		for _, rows := range []struct {
			generated  bool
			container  uint32
			recipients []Recipient
		}{{false, m.RecipientsSpan, m.Recipients}, {true, m.GeneratedRecipientsSpan, m.GeneratedRecipients}} {
			container, err := modelSpan(m, rows.container)
			if err != nil {
				return nil, nil, err
			}
			items := make([]Span, 0, len(rows.recipients))
			selected := -1
			for _, row := range rows.recipients {
				index := row.EditableSpan
				if rows.generated {
					index = row.GeneratedSpan
				}
				span, err := modelSpan(m, index)
				if err != nil || span.SourceLength <= 0 {
					return nil, nil, ErrEdit
				}
				items = append(items, Span{Offset: span.SourceOffset, Length: span.Offset + span.Length - span.SourceOffset})
			}
			sort.Slice(items, func(i, j int) bool { return items[i].Offset < items[j].Offset })
			for _, row := range rows.recipients {
				if row.Reference != s.request.RecipientReference {
					continue
				}
				index := row.EditableSpan
				if rows.generated {
					index = row.GeneratedSpan
				}
				span, err := modelSpan(m, index)
				if err != nil {
					return nil, nil, err
				}
				for i, item := range items {
					if item.Offset == span.SourceOffset {
						selected = i
						break
					}
				}
			}
			if selected < 0 {
				return nil, nil, ErrEdit
			}
			image, encoding := s.source.Editable, s.source.Format
			if rows.generated {
				image, encoding = s.source.Generated, JSON
			}
			edits, err := maintenanceCollectionEdits(ctx, image, encoding, maintenanceRemoval{container: container, items: items, selected: selected})
			if err != nil {
				return nil, nil, err
			}
			if rows.generated {
				generated = append(generated, edits...)
			} else {
				editable = append(editable, edits...)
			}
		}
		for _, removal := range m.maintenanceRemovals {
			edits, err := maintenanceCollectionEdits(ctx, s.source.Editable, s.source.Format, removal)
			if err != nil {
				return nil, nil, err
			}
			editable = append(editable, edits...)
		}
	}
	for _, delta := range metadata.PinDeltas {
		for _, entry := range m.Entries {
			if entry.Name != delta.Name || entry.Retained == nil {
				continue
			}
			before := contract.RetainedSecretInput{Incarnation: entry.Retained.Incarnation, Material: entry.Retained.Material}
			if !entry.Secret || entry.Generated != nil || len(entry.Sealed) != 0 || before != delta.Before {
				return nil, nil, ErrEdit
			}
			span, err := modelSpan(m, entry.SecretSpan)
			if err != nil {
				return nil, nil, err
			}
			var body bytes.Buffer
			w := &generatedWriter{out: &body, multiline: true, baseDepth: 2}
			w.write(`{"retained":`)
			w.maintenancePin(delta.After)
			w.write(`}`)
			if w.err != nil {
				return nil, nil, w.err
			}
			generated = append(generated, Edit{Offset: span.Offset, Length: span.Length, Replacement: body.Bytes()})
		}
	}
	body, err := maintenanceMetadataBytes(metadata)
	if err != nil {
		return nil, nil, err
	}
	edit, err := maintenanceMetadataEdit(s.source.Generated, m, body)
	if err != nil {
		return nil, nil, err
	}
	generated = append(generated, edit)
	sort.Slice(editable, func(i, j int) bool { return editable[i].Offset < editable[j].Offset })
	sort.Slice(generated, func(i, j int) bool { return generated[i].Offset < generated[j].Offset })
	return editable, generated, nil
}

func maintenanceCollectionEdits(ctx context.Context, image *Image, encoding Format, removal maintenanceRemoval) ([]Edit, error) {
	if ctx == nil || image == nil || removal.selected < 0 || removal.selected >= len(removal.items) || removal.container.Length <= 0 {
		return nil, ErrEdit
	}
	container := removal.container
	if container.Offset < 0 || container.Length > image.Size()-container.Offset {
		return nil, ErrEdit
	}
	for i, item := range removal.items {
		if item.Offset < container.Offset || item.Length <= 0 || item.Length > container.Offset+container.Length-item.Offset || i > 0 && item.Offset < removal.items[i-1].Offset+removal.items[i-1].Length {
			return nil, ErrEdit
		}
	}
	var first [1]byte
	if _, err := image.ReadAt(first[:], container.Offset); err != nil {
		return nil, err
	}
	flow := first[0] == '{' || first[0] == '['
	item := removal.items[removal.selected]
	edit := Edit{Offset: item.Offset, Length: item.Length}
	if len(removal.items) == 1 && !flow {
		edit.Replacement = []byte("{}")
		if removal.array {
			edit.Replacement = []byte("[]")
			if removal.ownerColumn != 0 && item.Column == removal.ownerColumn {
				edit.Replacement = []byte("  []")
			}
		}
	}
	edits := []Edit{edit}
	if !flow {
		return edits, nil
	}
	if len(removal.items) > 1 {
		start := item.Offset + item.Length
		var end int64
		if removal.selected < len(removal.items)-1 {
			end = removal.items[removal.selected+1].Offset
		} else {
			start = removal.items[removal.selected-1].Offset + removal.items[removal.selected-1].Length
			end = item.Offset
		}
		comma, found, err := maintenanceComma(ctx, image, encoding, start, end)
		if err != nil || !found {
			return nil, ErrEdit
		}
		edits = append(edits, Edit{Offset: comma, Length: 1})
	} else {
		// YAML flow collections permit a final comma, even on their sole item.
		comma, found, err := maintenanceComma(ctx, image, encoding, item.Offset+item.Length, container.Offset+container.Length)
		if err != nil {
			return nil, err
		}
		if found {
			edits = append(edits, Edit{Offset: comma, Length: 1})
		}
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].Offset < edits[j].Offset })
	return edits, nil
}

func maintenanceComma(ctx context.Context, image *Image, encoding Format, start, end int64) (int64, bool, error) {
	if start < 0 || end < start || end > image.Size() {
		return 0, false, ErrEdit
	}
	p := newParser(ctx, io.NewSectionReader(image, start, end-start), encoding)
	p.indentation = false
	p.skip()
	if p.err != nil {
		return 0, false, p.err
	}
	return start + p.off, p.peek() == ',', p.err
}

func maintenanceMetadataEdit(image *Image, m *Model, body []byte) (Edit, error) {
	if m.Maintenance != nil {
		span, err := modelSpan(m, m.MaintenanceSpan)
		if err != nil {
			return Edit{}, err
		}
		return Edit{Offset: span.Offset, Length: span.Length, Replacement: body}, nil
	}
	root, err := modelSpan(m, m.GeneratedRootSpan)
	if err != nil || root.Length < 2 {
		return Edit{}, ErrEdit
	}
	end := root.Offset + root.Length - 1
	insertion := end
	buffer := make([]byte, WindowBytes)
	for insertion > root.Offset {
		start := max(root.Offset, insertion-int64(len(buffer)))
		n, err := image.ReadAt(buffer[:insertion-start], start)
		if err != nil {
			return Edit{}, err
		}
		for n > 0 && (buffer[n-1] == ' ' || buffer[n-1] == '\n' || buffer[n-1] == '\r' || buffer[n-1] == '\t') {
			n--
		}
		insertion = start + int64(n)
		if n > 0 {
			break
		}
	}
	replacement := append([]byte(",\n  \"maintenance\": "), body...)
	replacement = append(replacement, '\n')
	return Edit{Offset: insertion, Length: end - insertion, Replacement: replacement}, nil
}
