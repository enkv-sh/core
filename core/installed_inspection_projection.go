package core

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type InspectionEntry struct {
	Slot                        uint16
	Name                        string
	IncarnationID, ValueStateID contract.ID
	ValueSource                 uint8
	Confidential                bool
	RawLength                   uint32
	RecipientIDs                []contract.ID
	GenerationID                contract.ID
	Epoch                       uint64
	RetirementMode              uint8
}

type RecipientInspectionEntry struct {
	Name                        string
	IncarnationID, ValueStateID contract.ID
	ValueSource                 uint8
	Confidential                bool
	RawLength                   uint32
	GenerationID                contract.ID
	Epoch                       uint64
}

type InspectionRecipient struct {
	RecipientID        contract.ID
	Status             uint8
	DisplayName        string
	BindingID          contract.ID
	BindingSerial      uint64
	BindingFingerprint contract.ID
}

type InspectionGeneratedWork struct {
	CurrentGenerations []GeneratedCurrentGeneration
	Effects            []GeneratedEffectFact
	Duties             []GeneratedDutyFact
	Hazards            []GeneratedHazardFact
	PendingReleases    []GeneratedPendingResultCleanup
	NextActions        []GeneratedNextAction
}

type InspectionGroupSelection struct {
	Selectable          bool
	RequiredParentIndex *uint16
}

type InspectionWork struct {
	Groups           []format.AdministrativeGroup
	GroupSelections  []InspectionGroupSelection
	Pages            []format.AdministrativePage
	PublicationOrder []format.PublicationCoordinateOrder
}

type InspectionWarnings struct {
	Domain               PublicDomainWarnings
	Generated            GeneratedResultWarnings
	Output               InspectionOutputWarnings
	PossibleStoreGarbage bool
}

// DomainInspection owns facts from one complete authenticated selection.
type DomainInspection struct {
	Observation       PublicObservation
	Entries           []InspectionEntry
	Recipients        []InspectionRecipient
	ActiveOperation   *GeneratedActiveOperation
	Generated         InspectionGeneratedWork
	Work              InspectionWork
	Output            InspectionOutput
	DomainWarningBits uint8
	Warnings          InspectionWarnings
}

// RecipientInspection contains only metadata granted to its current recipient.
type RecipientInspection struct {
	Observation PublicObservation
	RecipientID contract.ID
	Entries     []RecipientInspectionEntry
}

func inspectionEntry(entry *contract.ValueEntry, slot uint16) (InspectionEntry, error) {
	if entry == nil {
		return InspectionEntry{}, contract.ErrRecord
	}
	raw := entry.ContentLength
	if entry.ConfidentialityClass == contract.Secret {
		payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
		if err != nil {
			return InspectionEntry{}, err
		}
		raw = payload.ContentLength
	}
	out := InspectionEntry{Slot: slot, Name: strings.Clone(entry.Name), IncarnationID: entry.Incarnation,
		ValueStateID: entry.ValueState, ValueSource: entry.ValueSource, Confidential: entry.ConfidentialityClass == contract.Secret,
		RawLength: raw, RecipientIDs: slices.Clone(entry.Recipients)}
	if entry.ValueSource == contract.Generated {
		out.GenerationID, out.Epoch, out.RetirementMode = entry.Generated.GenerationID, entry.Generated.Epoch, entry.Generated.RetirementMode
	}
	return out, nil
}

func projectRecipientInspection(ctx context.Context, selected *publicSelection, recipient contract.ID) (RecipientInspection, error) {
	var out RecipientInspection
	if ctx == nil || selected == nil || !selected.complete || recipient.IsZero() {
		return out, contract.ErrRecord
	}
	current := selectedRecipientRecord(&selected.image.recipients, recipient)
	if current == nil || current.Status != contract.CurrentRecipient {
		return out, contract.ErrRecord
	}
	out.RecipientID = recipient
	count := 0
	for _, named := range selected.image.root.Names {
		entry := selected.image.valueEntry(named.Slot)
		if entry == nil || entry.Name != named.Name {
			return RecipientInspection{}, contract.ErrRecord
		}
		if slices.Contains(entry.Recipients, recipient) {
			count++
		}
	}
	out.Entries = make([]RecipientInspectionEntry, 0, count)
	for _, named := range selected.image.root.Names {
		if err := ctx.Err(); err != nil {
			return RecipientInspection{}, err
		}
		entry := selected.image.valueEntry(named.Slot)
		if entry == nil || entry.Name != named.Name {
			return RecipientInspection{}, contract.ErrRecord
		}
		if !slices.Contains(entry.Recipients, recipient) {
			continue
		}
		rawLength := entry.ContentLength
		if entry.ConfidentialityClass == contract.Secret {
			payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
			if err != nil {
				return RecipientInspection{}, err
			}
			rawLength = payload.ContentLength
		}
		row := RecipientInspectionEntry{Name: strings.Clone(entry.Name), IncarnationID: entry.Incarnation,
			ValueStateID: entry.ValueState, ValueSource: entry.ValueSource, Confidential: entry.ConfidentialityClass == contract.Secret, RawLength: rawLength}
		if entry.ValueSource == contract.Generated {
			row.GenerationID, row.Epoch = entry.Generated.GenerationID, entry.Generated.Epoch
		}
		out.Entries = append(out.Entries, row)
	}
	return out, nil
}

func projectInspectionMetadata(ctx context.Context, selected *publicSelection) ([]InspectionEntry, []InspectionRecipient, error) {
	if ctx == nil || selected == nil || !selected.complete {
		return nil, nil, contract.ErrRecord
	}
	entries := make([]InspectionEntry, 0, len(selected.image.root.Names))
	for _, named := range selected.image.root.Names {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		entry := selected.image.valueEntry(named.Slot)
		if entry == nil || entry.Name != named.Name {
			return nil, nil, contract.ErrRecord
		}
		row, err := inspectionEntry(entry, named.Slot)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, row)
	}
	rows := make([]InspectionRecipient, 0, selected.image.root.RecipientCount)
	for _, page := range selected.image.recipients {
		if page == nil {
			continue
		}
		for _, row := range page.Slots {
			if row == nil {
				continue
			}
			public := InspectionRecipient{RecipientID: row.RecipientID, Status: row.Status, DisplayName: strings.Clone(row.DisplayName)}
			if row.CurrentBinding != nil {
				public.BindingID, public.BindingSerial, public.BindingFingerprint = row.CurrentBinding.BindingID, row.CurrentBinding.BindingSerial, row.CurrentBinding.Fingerprint
			}
			rows = append(rows, public)
		}
	}
	slices.SortFunc(rows, func(a, b InspectionRecipient) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
	return entries, rows, nil
}

func projectInspectionWork(root format.Root, index format.AdministrativeIndex, coordinates map[contract.ID]contract.PublicationCoordinate) (InspectionWork, error) {
	if !index.Valid() || index.Domain != root.Domain {
		return InspectionWork{}, contract.ErrRecord
	}
	out := InspectionWork{Groups: make([]format.AdministrativeGroup, len(index.Groups)), GroupSelections: make([]InspectionGroupSelection, len(index.Groups)), Pages: make([]format.AdministrativePage, len(index.Pages)), PublicationOrder: make([]format.PublicationCoordinateOrder, len(index.PublicationOrder))}
	for i, group := range index.Groups {
		group = group.Own()
		out.Groups[i] = group
		out.GroupSelections[i] = InspectionGroupSelection{Selectable: administrativeTargetSelectable(root, index, group, coordinates)}
		parent := administrativeRequiredParentTarget(root, index, group)
		if !parent.IsZero() {
			for _, related := range group.RelatedGroupIndexes {
				if index.Groups[related].GroupID == parent {
					position := related
					out.GroupSelections[i].RequiredParentIndex = &position
					break
				}
			}
			if out.GroupSelections[i].RequiredParentIndex == nil {
				return InspectionWork{}, contract.ErrRecord
			}
		}
	}
	for i, page := range index.Pages {
		out.Pages[i] = page
		out.Pages[i].Rows = slices.Clone(page.Rows)
		out.Pages[i].Spans = slices.Clone(page.Spans)
		for j := range out.Pages[i].Spans {
			out.Pages[i].Spans[j].GroupIndexes = slices.Clone(page.Spans[j].GroupIndexes)
		}
	}
	for i, order := range index.PublicationOrder {
		out.PublicationOrder[i] = format.PublicationCoordinateOrder{CoordinateID: order.CoordinateID, Incarnations: slices.Clone(order.Incarnations)}
	}
	return out, nil
}

func validInspectionEntry(name string, incarnation, state contract.ID, source uint8, length uint32, generation contract.ID, epoch uint64) bool {
	return len(name) <= contract.CryptoMaxName && utf8.ValidString(name) && !incarnation.IsZero() && !state.IsZero() &&
		length <= contract.CryptoMaxRawValue && (source == contract.Supplied && generation.IsZero() && epoch == 0 || source == contract.Generated && !generation.IsZero())
}

// Validate checks bounded shape and relations, not selected-state provenance.
func (v RecipientInspection) Validate() error {
	if !validInspectionObservation(v.Observation) || v.RecipientID.IsZero() || len(v.Entries) > contract.CryptoMaxValueEntries {
		return contract.ErrRecord
	}
	var rawBytes uint64
	generated := 0
	for i, row := range v.Entries {
		if !validInspectionEntry(row.Name, row.IncarnationID, row.ValueStateID, row.ValueSource, row.RawLength, row.GenerationID, row.Epoch) || i > 0 && v.Entries[i-1].Name >= row.Name {
			return contract.ErrRecord
		}
		rawBytes += uint64(row.RawLength)
		if row.ValueSource == contract.Generated {
			generated++
		}
	}
	if rawBytes > contract.CryptoMaxRawSet || generated > contract.GeneratedCurrentEntryLimit {
		return contract.ErrRecordCapacity
	}
	return nil
}

func validInspectionObservation(v PublicObservation) bool {
	return !v.DomainID.IsZero() && !v.HeadRevisionID.IsZero() && !v.SnapshotID.IsZero() && !v.RootDigest.IsZero()
}
