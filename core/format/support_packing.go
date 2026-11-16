package format

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

type SupportStorageGroup uint8

const (
	OldValueSupport SupportStorageGroup = iota + 1
	CandidateValueSupport
	ResultSupport
	MaterialSupport
	CreateContinuationSupport
	DeleteContinuationSupport
	OwnerSupport
	ReceiptSupport
	GraphIndexSupport
	AuxiliaryIndexSupport
	GCPlanSupport
	IntentFragmentSupport
	GraphFragmentSupport
	AuxiliaryFragmentSupport
	OutputConfigurationSupport
)

// RequiredSupportGroup is derived from selected ownership by Core. The page
// packer checks framing and capacity; the group is not an ownership assertion.
type RequiredSupportGroup struct {
	Class     SupportStorageGroup
	Owner     ID
	Mandatory bool
	Records   []contract.SupportRecord
}

// RequiredSupportGroupLimit includes all row framing for one owner group.
// Reservation accounting and actual packing use this same format boundary.
func RequiredSupportGroupLimit(class SupportStorageGroup) int {
	switch class {
	case OldValueSupport, CandidateValueSupport, ResultSupport:
		return 72 << 10
	case MaterialSupport, ReceiptSupport:
		return 4 << 10
	case CreateContinuationSupport, DeleteContinuationSupport:
		return 64 << 10
	case OwnerSupport:
		return 16 << 10
	case GraphIndexSupport, AuxiliaryIndexSupport, OutputConfigurationSupport, GCPlanSupport:
		return MaxRequiredSupportPage - contract.RequiredSupportPageHeaderLength
	case IntentFragmentSupport, GraphFragmentSupport, AuxiliaryFragmentSupport:
		return MaxRequiredSupportPage
	}
	return 0
}

func supportGroupKindValid(class SupportStorageGroup, row contract.SupportRecord) bool {
	if row.Kind == contract.GeneratorVectorSupportKind {
		v, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return false
		}
		switch class {
		case CreateContinuationSupport, DeleteContinuationSupport:
			return v.VectorKind != contract.GeneratorVectorTargets && v.VectorKind != contract.GeneratorVectorSlices
		case OwnerSupport:
			return v.VectorKind == contract.GeneratorVectorTargets
		case GraphIndexSupport:
			return v.VectorKind == contract.GeneratorVectorSlices
		case AuxiliaryIndexSupport:
			return v.VectorKind == contract.GeneratorVectorSupport || v.VectorKind == contract.GeneratorVectorConsumers
		default:
			return false
		}
	}
	kind := row.Kind
	switch class {
	case OldValueSupport:
		return kind == contract.RetainedCanonicalSupportKind || kind == contract.GeneratedCreateEvidenceSupportKind
	case CandidateValueSupport:
		return kind == contract.RetainedCanonicalSupportKind
	case ResultSupport:
		return kind == contract.GeneratedResultSupportKind
	case MaterialSupport:
		return kind == contract.OperationMaterialSupportKind || kind == contract.GeneratedParentSupportKind
	case CreateContinuationSupport, DeleteContinuationSupport:
		return kind == contract.GeneratedPhaseSupportKind || kind == contract.GeneratedFinalPreparationSupportKind || kind == contract.GeneratedLineageSupportKind || kind == contract.GeneratedAttemptSupportKind || kind == contract.PendingInboxReleaseSupportKind || kind == contract.GeneratedCreateEvidenceSupportKind || class == DeleteContinuationSupport && kind == contract.GeneratedResultSupportKind
	case OwnerSupport:
		return kind == contract.GeneratedDutySupportKind || kind == contract.GeneratedHazardSupportKind || kind == contract.GeneratedCreateEvidenceSupportKind || kind == contract.PublicationCoordinateSupportKind || kind == contract.PublicationMarkerSupportKind
	case ReceiptSupport:
		return kind == contract.MutationReceiptSupportKind
	case GCPlanSupport:
		return kind == contract.GCPlanSupportKind
	case OutputConfigurationSupport:
		return kind == contract.OutputConfigurationSliceSupportKind
	case IntentFragmentSupport, GraphFragmentSupport, AuxiliaryFragmentSupport:
		return kind == contract.GeneratedFragmentSupportKind
	}
	return false
}

func supportRecordCompare(a, b contract.SupportRecord) int {
	if a.Kind < b.Kind {
		return -1
	}
	if a.Kind > b.Kind {
		return 1
	}
	return bytes.Compare(a.RecordID[:], b.RecordID[:])
}

// PackRequiredSupportRows returns canonical page rows without assigning
// physical page identities. It borrows bodies; the caller must keep them fixed
// until encoding. Every nonfragment owner group fits on one page.
func PackRequiredSupportRows(domain ID, groups []RequiredSupportGroup, otherChildren uint32) ([][]contract.SupportRecord, error) {
	return packRequiredSupportRows(domain, groups, otherChildren, nil)
}

func PackRequiredSupportReceiptPlan(domain ID, groups []RequiredSupportGroup, otherChildren uint32, v contract.CompactMutationReceiptPlan) ([][]contract.SupportRecord, error) {
	plan, err := newReceiptSupportPlan(v)
	if err != nil || domain != v.DomainID {
		return nil, ErrFormat
	}
	return packRequiredSupportRows(domain, groups, otherChildren, plan)
}

func PackRequiredSupportParentPlan(domain ID, groups []RequiredSupportGroup, otherChildren uint32, v contract.GeneratedParentPlan) ([][]contract.SupportRecord, error) {
	plan, err := newGeneratedParentSupportPlan(v)
	if err != nil || domain != v.DomainID {
		return nil, ErrFormat
	}
	return packRequiredSupportRows(domain, groups, otherChildren, plan)
}

func packRequiredSupportRows(domain ID, groups []RequiredSupportGroup, otherChildren uint32, plan *supportRecordPlan) ([][]contract.SupportRecord, error) {
	if domain.IsZero() || otherChildren > contract.MaxChildPages {
		return nil, ErrFormat
	}
	maxRecords := (contract.MaxChildPages - int(otherChildren)) * ((MaxRequiredSupportPage - contract.RequiredSupportPageHeaderLength) / contract.SupportRecordMinLength)
	if len(groups) > maxRecords {
		return nil, ErrFormat
	}
	totalRecords := 0
	for _, group := range groups {
		if len(group.Records) > maxRecords-totalRecords {
			return nil, ErrFormat
		}
		totalRecords += len(group.Records)
	}
	ordered := slices.Clone(groups)
	slices.SortFunc(ordered, func(a, b RequiredSupportGroup) int {
		if a.Class < b.Class {
			return -1
		}
		if a.Class > b.Class {
			return 1
		}
		if a.Mandatory != b.Mandatory {
			if a.Mandatory {
				return -1
			}
			return 1
		}
		return bytes.Compare(a.Owner[:], b.Owner[:])
	})
	seen := make(map[supportRecordKey]bool, totalRecords)
	planned := 0
	var pages [][]contract.SupportRecord
	var page []contract.SupportRecord
	pageLength := contract.RequiredSupportPageHeaderLength
	flush := func() bool {
		if len(page) == 0 {
			return true
		}
		if len(pages) >= contract.MaxChildPages-int(otherChildren) {
			return false
		}
		pages = append(pages, page)
		page, pageLength = nil, contract.RequiredSupportPageHeaderLength
		return true
	}
	for i, group := range ordered {
		limit := RequiredSupportGroupLimit(group.Class)
		if limit == 0 || group.Owner.IsZero() || len(group.Records) == 0 ||
			i > 0 && ordered[i-1].Mandatory == group.Mandatory && ordered[i-1].Class == group.Class && ordered[i-1].Owner == group.Owner {
			return nil, ErrFormat
		}
		if i > 0 && (ordered[i-1].Mandatory != group.Mandatory || ordered[i-1].Class != group.Class) && !flush() {
			return nil, ErrFormat
		}
		rows := slices.Clone(group.Records)
		slices.SortFunc(rows, supportRecordCompare)
		fragments := group.Class >= IntentFragmentSupport && group.Class <= OutputConfigurationSupport
		groupLength := 0
		for _, row := range rows {
			actual, err := plan.domain(row)
			key := supportRecordKey{row.Kind, row.RecordID}
			if err != nil || !actual.IsZero() && actual != domain || seen[key] || !supportGroupKindValid(group.Class, row) {
				return nil, ErrFormat
			}
			seen[key] = true
			if plan.matches(row) {
				planned++
			}
			length := contract.SupportRecordOverhead + len(row.Body)
			if fragments {
				if group.Class == OutputConfigurationSupport {
					part, err := contract.InspectOutputConfigurationSlice(row.Body)
					if err != nil || part.ConfigurationDigest != group.Owner {
						return nil, ErrFormat
					}
				} else {
					fragment, err := contract.InspectGeneratedFragment(row.Body)
					if err != nil || fragment.BlobID != group.Owner {
						return nil, ErrFormat
					}
				}
				if len(page) == 2 || pageLength+length > MaxRequiredSupportPage {
					if !flush() {
						return nil, ErrFormat
					}
				}
				page, pageLength = append(page, row), pageLength+length
			} else {
				if length > limit-groupLength {
					return nil, ErrFormat
				}
				groupLength += length
			}
		}
		if !fragments {
			if pageLength+groupLength > MaxRequiredSupportPage && !flush() {
				return nil, ErrFormat
			}
			page, pageLength = append(page, rows...), pageLength+groupLength
		}
	}
	if plan != nil && planned != 1 || !flush() {
		return nil, ErrFormat
	}
	return pages, nil
}
