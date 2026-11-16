package core

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type MaintenancePinDelta struct {
	Name          string
	Before, After contract.RetainedSecretInput
}

type MaintenanceValuePage struct {
	Index uint16
	Body  []byte
}

// MaintenanceSuccessor describes one prepared candidate, not a selection.
type MaintenanceSuccessor struct {
	OperationKind                                        uint16
	Recipient                                            contract.RecipientBindingReference
	Name                                                 string
	FileIdentity, DomainID, OperationID, RequestIdentity contract.ID
	SignedCandidate                                      []byte
	PredecessorHead, PredecessorRoot                     []byte
	PredecessorPages                                     []MaintenanceValuePage
	CandidateRoot                                        []byte
	CandidatePages                                       []MaintenanceValuePage
	BeforeGeneration, AfterGeneration                    contract.ID
	PinDeltas                                            []MaintenancePinDelta
	Retirement                                           *contract.RecipientRetirementRow
	RekeyTarget                                          *contract.SecretAccessTarget
}

type MaintenanceReadback struct {
	SourcePins, OutputPins AdministrativeSourcePins
	OutputPath             string
	Basis                  PublicBasis
	Configuration          contract.PublicConfiguration
	Inputs                 []contract.PlanningInput
	Recipients             []contract.ApplyRecipientInput
	Correlation            MaintenanceSuccessor
}

// MaintenanceInstallation binds captured source facts to a named output. Only
// the installed local owner supplies delivery and exact reopened readback.
type MaintenanceInstallation struct {
	SourcePins       AdministrativeSourcePins
	OutputPath       string
	InputDigest      contract.ID
	Configuration    contract.PublicConfiguration
	Inputs           []contract.PlanningInput
	Recipients       []contract.ApplyRecipientInput
	CredentialRoute  contract.ID
	AdmitFeasibility func(context.Context, contract.PlanningAdmission) (PlanningCustody, error)
	PublishSuccessor func(context.Context, MaintenanceSuccessor) (MaintenanceReadback, error)
	SourceUnchanged  func(context.Context) error
	materialBounds   maintenanceMaterialBounds
}

func maintenanceOutputPathValid(path string) bool {
	return len(path) <= 4096 && utf8.ValidString(path) && !strings.ContainsRune(path, 0) && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

func ownMaintenanceRecipients(rows []contract.ApplyRecipientInput) ([]contract.ApplyRecipientInput, error) {
	if len(rows) == 0 || len(rows) > contract.CryptoMaxRecipients {
		return nil, contract.ErrRecordCapacity
	}
	owned := slices.Clone(rows)
	for i, row := range rows {
		body, err := contract.EncodeRecipientRecord(row.Recipient)
		if err != nil {
			return nil, err
		}
		owned[i].Recipient, err = contract.DecodeRecipientRecord(body)
		if err != nil || owned[i].Recipient.Status != contract.CurrentRecipient {
			return nil, contract.ErrRecord
		}
		if row.Creation != nil {
			creation := *row.Creation
			owned[i].Creation = &creation
		}
	}
	slices.SortFunc(owned, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	for i := 1; i < len(owned); i++ {
		if owned[i-1].Recipient.RecipientID == owned[i].Recipient.RecipientID {
			return nil, contract.ErrRecord
		}
	}
	return owned, nil
}

func ownMaintenanceInstallation(i *MaintenanceInstallation) (*MaintenanceInstallation, error) {
	if i == nil || !i.SourcePins.Valid() || !i.SourcePins.HasGenerated || !maintenanceOutputPathValid(i.OutputPath) ||
		i.InputDigest.IsZero() || i.CredentialRoute.IsZero() || i.PublishSuccessor == nil || i.SourceUnchanged == nil || i.AdmitFeasibility == nil {
		return nil, contract.ErrRecord
	}
	owned := *i
	digest, err := PlanningInputDigest(i.Configuration, i.Inputs)
	if err != nil || digest != i.InputDigest {
		return nil, contract.ErrRecord
	}
	owned.Configuration = ownPublicConfiguration(i.Configuration)
	owned.Inputs, err = ownPlanningInputs(i.Inputs)
	if err != nil {
		return nil, err
	}
	owned.Recipients, err = ownMaintenanceRecipients(i.Recipients)
	if err != nil {
		return nil, err
	}
	owned.OutputPath = strings.Clone(i.OutputPath)
	return &owned, nil
}

func ownMaintenanceSuccessor(v MaintenanceSuccessor) MaintenanceSuccessor {
	v.Name = strings.Clone(v.Name)
	v.SignedCandidate = bytes.Clone(v.SignedCandidate)
	v.PredecessorHead = bytes.Clone(v.PredecessorHead)
	v.PredecessorRoot = bytes.Clone(v.PredecessorRoot)
	v.PredecessorPages = slices.Clone(v.PredecessorPages)
	for i := range v.PredecessorPages {
		v.PredecessorPages[i].Body = bytes.Clone(v.PredecessorPages[i].Body)
	}
	v.CandidateRoot = bytes.Clone(v.CandidateRoot)
	v.CandidatePages = slices.Clone(v.CandidatePages)
	for i := range v.CandidatePages {
		v.CandidatePages[i].Body = bytes.Clone(v.CandidatePages[i].Body)
	}
	v.PinDeltas = slices.Clone(v.PinDeltas)
	for i := range v.PinDeltas {
		v.PinDeltas[i].Name = strings.Clone(v.PinDeltas[i].Name)
	}
	if v.Retirement != nil {
		row := *v.Retirement
		v.Retirement = &row
	}
	if v.RekeyTarget != nil {
		target := *v.RekeyTarget
		target.Name = strings.Clone(target.Name)
		v.RekeyTarget = &target
	}
	return v
}

func maintenanceSuccessorEqual(a, b MaintenanceSuccessor) bool {
	return a.OperationKind == b.OperationKind && a.Recipient == b.Recipient && a.Name == b.Name && a.FileIdentity == b.FileIdentity &&
		a.DomainID == b.DomainID && a.OperationID == b.OperationID && a.RequestIdentity == b.RequestIdentity && bytes.Equal(a.SignedCandidate, b.SignedCandidate) &&
		bytes.Equal(a.PredecessorHead, b.PredecessorHead) && bytes.Equal(a.PredecessorRoot, b.PredecessorRoot) && slices.EqualFunc(a.PredecessorPages, b.PredecessorPages, func(a, b MaintenanceValuePage) bool { return a.Index == b.Index && bytes.Equal(a.Body, b.Body) }) &&
		bytes.Equal(a.CandidateRoot, b.CandidateRoot) && slices.EqualFunc(a.CandidatePages, b.CandidatePages, func(a, b MaintenanceValuePage) bool { return a.Index == b.Index && bytes.Equal(a.Body, b.Body) }) &&
		a.BeforeGeneration == b.BeforeGeneration && a.AfterGeneration == b.AfterGeneration && slices.Equal(a.PinDeltas, b.PinDeltas) && optionalMaintenanceRetirementEqual(a.Retirement, b.Retirement) && optionalMaintenanceTargetEqual(a.RekeyTarget, b.RekeyTarget)
}

func maintenanceCorrelationValid(c MaintenanceSuccessor, domain, store, file contract.ID) bool {
	if c.DomainID != domain || c.FileIdentity != file || c.OperationID.IsZero() || c.RequestIdentity.IsZero() || len(c.SignedCandidate) > contract.MaxHeadLength || len(c.PinDeltas) > contract.CryptoMaxValueEntries {
		return false
	}
	h, err := format.DecodeHead(c.SignedCandidate)
	if err != nil || h.Core.Form != format.SuccessorHead || h.AuthKind != format.LifecycleAuth || h.Core.Domain != domain || h.Core.Store != store || h.Subject.Operation != c.OperationID || h.Subject.OperationKind != c.OperationKind {
		return false
	}
	switch c.OperationKind {
	case contract.OperationRetireRecipientIdentity:
		if c.Retirement == nil || c.RekeyTarget != nil || c.Retirement.RecipientID != c.Recipient.RecipientID || c.Recipient.PublicBindingDigest.IsZero() || c.Name != "" {
			return false
		}
		descriptor, err := contract.RetirementDescriptor(domain, []contract.RecipientRetirementRow{*c.Retirement})
		if err != nil || descriptor != h.Subject.Exclusion.Retirements {
			return false
		}
	case contract.OperationEnvelopeRekey:
		target := c.RekeyTarget
		if target == nil || c.Retirement != nil || c.Recipient != (contract.RecipientBindingReference{}) || target.Name != c.Name || target.Slot >= contract.CryptoMaxValueEntries || target.Incarnation.IsZero() || target.Material.IsZero() || target.BeforePublicEntryDigest.IsZero() || len(c.Name) > contract.CryptoMaxName || !utf8.ValidString(c.Name) {
			return false
		}
	default:
		return false
	}
	for i, delta := range c.PinDeltas {
		if len(delta.Name) > contract.CryptoMaxName || !utf8.ValidString(delta.Name) || i > 0 && c.PinDeltas[i-1].Name >= delta.Name || delta.Before.Incarnation.IsZero() || delta.Before.Material.IsZero() || delta.After.Incarnation != delta.Before.Incarnation || delta.After.Material.IsZero() || delta.Before.Material == delta.After.Material {
			return false
		}
	}
	_, _, valid := maintenanceMaterial(c, h)
	return valid
}

func optionalMaintenanceRetirementEqual(a, b *contract.RecipientRetirementRow) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func optionalMaintenanceTargetEqual(a, b *contract.SecretAccessTarget) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
