package compositionfull

import (
	"bytes"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type recipientRetirementBlockerRecord struct {
	Material  string `json:"material_id"`
	OwnerKind string `json:"owner_kind"`
	Owner     string `json:"owner_id"`
}

type recipientRetirementBlockersRecord struct {
	Total uint32                             `json:"total"`
	Rows  []recipientRetirementBlockerRecord `json:"rows"`
}

func retirementBlockerProjection(r core.PublicApplyResult, operation uint16) (*recipientRetirementBlockersRecord, error) {
	p := r.RetirementBlockers
	if p == nil {
		return nil, nil
	}
	if operation != contract.OperationRetireRecipientIdentity || r.Result.Outcome != core.AdmissionRefused || p.Total == 0 || len(p.Rows) != int(min(p.Total, uint32(core.RecipientRetirementBlockerLimit))) || r.Payload != nil || len(r.Receipt) != 0 || r.Result.CommitMayHaveOccurred {
		return nil, errApplyResult
	}
	v := &recipientRetirementBlockersRecord{Total: p.Total, Rows: make([]recipientRetirementBlockerRecord, len(p.Rows))}
	for at, row := range p.Rows {
		if row.MaterialID.IsZero() || row.OwnerID.IsZero() {
			return nil, errApplyResult
		}
		if at > 0 {
			before := p.Rows[at-1]
			order := bytes.Compare(before.MaterialID[:], row.MaterialID[:])
			if order > 0 || order == 0 && (before.OwnerKind > row.OwnerKind || before.OwnerKind == row.OwnerKind && bytes.Compare(before.OwnerID[:], row.OwnerID[:]) >= 0) {
				return nil, errApplyResult
			}
		}
		kind := ""
		switch row.OwnerKind {
		case contract.GeneratedParentSupportKind:
			kind = "parent"
		case contract.GeneratedDutySupportKind:
			kind = "duty"
		case contract.GeneratedHazardSupportKind:
			kind = "hazard"
		default:
			return nil, errApplyResult
		}
		v.Rows[at] = recipientRetirementBlockerRecord{Material: readerID(row.MaterialID), OwnerKind: kind, Owner: readerID(row.OwnerID)}
	}
	return v, nil
}

// NewRecipientRetirementRefusal reports invalid fields without reading a source.
func NewRecipientRetirementRefusal(format configuration.Format) (core.PublicApplyResult, error) {
	return NewApplyRefusal(format)
}

func RenderRecipientRetirementJSON(r core.PublicApplyResult) ([]byte, error) {
	v, err := transitionResultProjection(r, contract.OperationRetireRecipientIdentity)
	if err != nil {
		return nil, err
	}
	return renderTransitionResultJSON(v)
}

func RenderRecipientRetirementHuman(r core.PublicApplyResult) ([]byte, error) {
	v, err := transitionResultProjection(r, contract.OperationRetireRecipientIdentity)
	if err != nil {
		return nil, err
	}
	return renderTransitionHuman(r, v)
}
