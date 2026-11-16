package compositionfull

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func validPublicationPreview(payload contract.ComparisonPayload) bool {
	p := payload.Publication
	if !payload.PublicationRequested {
		return p == nil
	}
	if p == nil || p.ReasonCode > uint8(core.GeneratedIntentConflict) || len(p.Entries) > contract.MaxPublicationPreviewEntries || p.Complete && payload.Observation == nil {
		return false
	}
	blockers := make(map[contract.ID]bool)
	for i, row := range p.Entries {
		if !boundedReaderText(row.ServiceContractID, 256) || !boundedReaderText(row.PhysicalTarget, 1024) || !boundedReaderText(row.TargetContractID, 256) || row.ReasonCode > uint8(core.GeneratedIntentConflict) || len(row.Actions) > 3 {
			return false
		}
		for _, item := range []struct {
			text *string
			max  int
		}{{row.EntryName, 256}, {row.DestinationID, 256}, {row.ConsumerLocator, 1024}} {
			if item.text != nil && !boundedReaderText(*item.text, item.max) {
				return false
			}
		}
		switch row.Origin {
		case "observed", "both":
			if row.CoordinateID.IsZero() || row.BindingID.IsZero() || payload.Observation == nil {
				return false
			}
		case "proposed":
			if !row.CoordinateID.IsZero() || !row.BindingID.IsZero() || len(row.BlockerIDs) != 0 {
				return false
			}
		default:
			return false
		}
		switch row.Basis {
		case "acknowledged-equal", "unpublished", "value-changed", "binding-changed", "policy-changed", "retained-deletion", "secret-unchecked", "generated-unavailable", "blocked", "warning", "conflict", "capacity", "evidence-unavailable":
		default:
			return false
		}
		for _, action := range row.Actions {
			if action < contract.PublicationCreateEmpty || action > contract.PublicationDeleteReservedSlot {
				return false
			}
		}
		if i > 0 {
			before := p.Entries[i-1]
			if before.ServiceContractID > row.ServiceContractID || before.ServiceContractID == row.ServiceContractID && before.PhysicalTarget >= row.PhysicalTarget {
				return false
			}
		}
		for j, id := range row.BlockerIDs {
			if id.IsZero() || blockers[id] || j > 0 && bytes.Compare(row.BlockerIDs[j-1][:], id[:]) >= 0 {
				return false
			}
			blockers[id] = true
			if len(blockers) > contract.MaxPublicationPreviewBlockers {
				return false
			}
		}
	}
	return true
}

type publicationPreviewRowRecord struct {
	ServiceContractID string   `json:"service_contract_id"`
	PhysicalTarget    string   `json:"physical_target"`
	Origin            string   `json:"origin"`
	CoordinateID      *string  `json:"coordinate_id"`
	BindingID         *string  `json:"binding_id"`
	EntryName         *string  `json:"entry_name"`
	DestinationID     *string  `json:"destination_id"`
	TargetContractID  string   `json:"target_contract_id"`
	ConsumerLocator   *string  `json:"consumer_locator"`
	Actions           []string `json:"actions"`
	Basis             string   `json:"basis"`
	Conditional       bool     `json:"conditional"`
	ReasonCode        uint8    `json:"reason_code"`
}

func previewNullableID(id contract.ID) *string {
	if id.IsZero() {
		return nil
	}
	text := readerID(id)
	return &text
}

func renderPublicationPreview(w *readerResultWriter, preview *contract.PublicationPreview, human bool) {
	if preview == nil {
		return
	}
	start := w.at
	if human {
		writePublicationPreviewHuman(w, preview)
		return
	}
	w.literal(`,"publication":`)
	w.literal(`{"schema":"PublicationPreview/v2","complete":` + strconv.FormatBool(preview.Complete) + `,"reason_code":` + strconv.Itoa(int(preview.ReasonCode)) + `,"domain_wide_warning":` + strconv.FormatBool(preview.DomainWideWarning) + `,"entries":[`)
	for i, row := range preview.Entries {
		if i > 0 {
			w.literal(",")
		}
		actions := make([]string, len(row.Actions))
		for j, action := range row.Actions {
			actions[j] = publicationActionName(action)
		}
		record := publicationPreviewRowRecord{row.ServiceContractID, row.PhysicalTarget, row.Origin, previewNullableID(row.CoordinateID), previewNullableID(row.BindingID), row.EntryName, row.DestinationID, row.TargetContractID, row.ConsumerLocator, actions, row.Basis, row.Conditional, row.ReasonCode}
		body, err := json.Marshal(record)
		if err != nil || len(body)+128 > contract.MaxPublicationPreviewRowJSONBytes {
			w.failed = true
			return
		}
		w.literal(strings.TrimSuffix(string(body), "}"))
		w.literal(`,"blocker_ids":[`)
		for j, id := range row.BlockerIDs {
			if j > 0 {
				w.literal(",")
			}
			w.json(readerID(id), 66)
		}
		w.literal(`],"remote_value_may_remain":` + strconv.FormatBool(row.RemoteValueMayRemain) + `,"late_write_risk":` + strconv.FormatBool(row.LateWriteRisk) + "}")
	}
	w.literal("]}")
	if w.at-start > contract.MaxPublicationPreviewJSONBytes {
		w.failed = true
	}
}

func writePublicationPreviewHuman(w *readerResultWriter, preview *contract.PublicationPreview) {
	start := w.at
	status := "incomplete"
	if preview.Complete {
		status = "complete"
	}
	unit := "targets"
	if len(preview.Entries) == 1 {
		unit = "target"
	}
	w.literal("Publication preview: " + status + "; " + strconv.Itoa(len(preview.Entries)) + " " + unit + ".\n")
	w.literal("  Reason code: " + strconv.Itoa(int(preview.ReasonCode)) + "\n")
	if preview.DomainWideWarning {
		w.literal("  Domain warning: remote output uncertainty remains.\n")
	}
	for _, row := range preview.Entries {
		rowStart := w.at
		w.literal("Target ")
		w.comparisonHumanString(row.ServiceContractID)
		w.literal(" / ")
		w.comparisonHumanString(row.PhysicalTarget)
		w.literal("\n  Origin: " + row.Origin + "; basis: " + row.Basis + "; reason code: " + strconv.Itoa(int(row.ReasonCode)) + "\n")
		for _, fact := range []struct {
			label string
			value *string
		}{{"Entry", row.EntryName}, {"Destination", row.DestinationID}, {"Consumer locator", row.ConsumerLocator}} {
			w.literal("  " + fact.label + ": ")
			if fact.value == nil {
				w.literal("unavailable")
			} else {
				w.comparisonHumanString(*fact.value)
			}
			w.literal("\n")
		}
		w.literal("  Target contract: ")
		w.comparisonHumanString(row.TargetContractID)
		w.literal("\n")
		for _, fact := range []struct {
			label string
			id    contract.ID
		}{{"Coordinate", row.CoordinateID}, {"Binding", row.BindingID}} {
			text := "unavailable"
			if !fact.id.IsZero() {
				text = readerID(fact.id)
			}
			w.literal("  " + fact.label + ": " + text + "\n")
		}
		w.literal("  Actions: ")
		if len(row.Actions) == 0 {
			w.literal("none")
		}
		for at, action := range row.Actions {
			if at != 0 {
				w.literal(", ")
			}
			w.literal(publicationActionName(action))
		}
		if row.Conditional {
			w.literal(" (conditional)")
		}
		w.literal("\n")
		if row.RemoteValueMayRemain {
			w.literal("  Remote value may remain.\n")
		}
		if row.LateWriteRisk {
			w.literal("  A late write may still arrive.\n")
		}
		if len(row.BlockerIDs) != 0 {
			w.literal("  Blocker attempts:\n")
		}
		if w.at-rowStart > contract.MaxPublicationPreviewRowJSONBytes {
			w.failed = true
		}
		for _, id := range row.BlockerIDs {
			w.literal("  " + readerID(id) + "\n")
		}
	}
	if w.at-start > contract.MaxPublicationPreviewJSONBytes {
		w.failed = true
	}
}
