package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type CapacityCount struct {
	Name                string
	Used, Limit, Margin uint64
}

type CapacityObjectMargin struct {
	Namespace                   contract.StoreObjectNamespace
	Kind                        contract.Kind
	Index                       uint16
	ObjectID                    contract.ID
	EncodedBytes, Limit, Margin uint64
}

type CapacityEncodedUsage struct {
	HEADBytes, RootBytes, ChildBytes, ConfigurationBytes                                 uint64
	ValueEntryBytes, RecipientBytes, AccessBytes, SupportBytes, AdministrativeIndexBytes uint64
	Objects                                                                              []CapacityObjectMargin
}

type CapacitySelectedCounts struct {
	SecretValues, AccessRecords, SupportRecords                                                    uint64
	GeneratedAttempts, GeneratedDuties, GeneratedHazards, GeneratedMaterials, PendingInboxReleases uint64
	GeneratedGraphs, AdministrativeGroups, GCObligations                                           uint64
	OutputBindings, PublicationCoordinates, PublicationMarkers                                     uint64
}

type CapacityContinuationBound struct {
	Scope, Status                                              string
	BasisDigest                                                contract.ID
	Groups                                                     [contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup
	ChildPages, ChildEncodedBytes, RootBytes                   uint64
	AdministrativeIndexBytes, AdministrativeIndexShards        uint64
	ChildPageLimit, RootByteLimit, AdministrativePageByteLimit uint64
}

type CapacityContinuationBasis struct {
	RootDigest                                                             contract.ID
	Graphs                                                                 contract.GeneratorDescriptor
	GCPlans                                                                contract.GCDescriptor
	Remaining, FirstExit                                                   CapacityContinuationBound
	AdministrativeGroupCountQualification, AdministrativeExitQualification string
}

type GCCapacityObligation struct {
	OperationID                contract.ID
	Active                     bool
	PlanDigest, ProgressDigest contract.ID
	Targets                    contract.GCDescriptor
	RemainingCount             uint16
	ProgressOrdinal            uint32
	ConsumedAllowances         uint64
}

type GCCandidatePage struct {
	MarkDigest, EnumerationDigest contract.ID
	ProtectedObjectCount          uint64
	Candidates                    []contract.GCCandidate
	EligibleTargets               []contract.GCTarget
	Targets                       contract.GCDescriptor
	NextCursor                    string
	ObservationLimit              string
}

type CapacityInspection struct {
	Observation   PublicObservation
	Counts        []CapacityCount
	Selected      CapacitySelectedCounts
	Encoded       CapacityEncodedUsage
	Continuation  CapacityContinuationBasis
	GCObligations []GCCapacityObligation
	Garbage       GCCandidatePage
}

type gcSelectedObservation struct {
	marks       gcMarkSet
	capacity    selectedContinuationCapacity
	obligations []GCCapacityObligation
}

func captureGCSelectedObservation(ctx context.Context, image *selectedImage, generated *generatedSelection, store contract.Descriptor, includeCapacity bool) (gcSelectedObservation, error) {
	var out gcSelectedObservation
	marks, err := gcMarkSelected(image, generated, store)
	if err != nil {
		return out, err
	}
	out.marks = marks
	if includeCapacity {
		out.capacity, err = continuationCapacityFromSelected(ctx, image, generated, generated.readFragment)
		if err != nil {
			return gcSelectedObservation{}, err
		}
	}
	states, err := selectedGCState(image, true)
	if err != nil {
		return gcSelectedObservation{}, err
	}
	for id, state := range states {
		digest, err := contract.GCProgressDigest(state.progress)
		if err != nil {
			return gcSelectedObservation{}, err
		}
		row := GCCapacityObligation{OperationID: id, Active: image.root.ActiveGC == id, PlanDigest: state.progress.PlanDigest,
			ProgressDigest: digest, Targets: state.progress.TargetsDescriptor, RemainingCount: state.progress.RemainingCount,
			ProgressOrdinal: state.progress.Ordinal}
		for _, target := range state.progress.Targets {
			row.ConsumedAllowances += uint64(target.Consumed)
		}
		out.obligations = append(out.obligations, row)
	}
	slices.SortFunc(out.obligations, func(a, b GCCapacityObligation) int { return bytes.Compare(a.OperationID[:], b.OperationID[:]) })
	return out, nil
}

func publicCapacityBound(bound selectedCapacityBound) (CapacityContinuationBound, error) {
	out := CapacityContinuationBound{BasisDigest: bound.BasisDigest, Groups: bound.Groups, ChildPages: bound.ChildPages,
		ChildEncodedBytes: bound.ChildEncodedBytes, RootBytes: bound.RootBytes, AdministrativeIndexBytes: bound.AdministrativeIndexBytes,
		AdministrativeIndexShards: bound.AdministrativeIndexShards, ChildPageLimit: bound.ChildPageLimit,
		RootByteLimit: bound.RootByteLimit, AdministrativePageByteLimit: bound.AdministrativePageByteLimit}
	switch bound.Scope {
	case remainingSelectedContinuations:
		out.Scope = "remaining-selected-continuations"
	case firstAdministrativeExit:
		out.Scope = "sufficient-first-administrative-exit"
	default:
		return CapacityContinuationBound{}, contract.ErrRecord
	}
	switch bound.Status {
	case capacitySufficient:
		out.Status = "sufficient"
	case capacityNotEstablished:
		out.Status = "sufficient-bound-not-established"
	case capacityNotApplicable:
		out.Status = "not-applicable"
	default:
		return CapacityContinuationBound{}, contract.ErrRecord
	}
	if out.BasisDigest.IsZero() || out.ChildPageLimit == 0 || out.RootByteLimit == 0 || out.AdministrativePageByteLimit == 0 {
		return CapacityContinuationBound{}, contract.ErrRecord
	}
	return out, nil
}

func capacityCount(name string, used, limit uint64) (CapacityCount, error) {
	if used > limit {
		return CapacityCount{}, contract.ErrRecord
	}
	return CapacityCount{Name: name, Used: used, Limit: limit, Margin: limit - used}, nil
}

func capacityEncodedUsage(selected *publicSelection) (CapacityEncodedUsage, error) {
	var out CapacityEncodedUsage
	if selected == nil || !selected.complete {
		return out, contract.ErrRecord
	}
	root := selected.image.root
	add := func(namespace contract.StoreObjectNamespace, kind contract.Kind, index uint16, object contract.ID, length, limit uint64) error {
		if length == 0 || length > limit || object.IsZero() {
			return contract.ErrRecord
		}
		out.Objects = append(out.Objects, CapacityObjectMargin{Namespace: namespace, Kind: kind, Index: index, ObjectID: object, EncodedBytes: length, Limit: limit, Margin: limit - length})
		return nil
	}
	out.HEADBytes, out.RootBytes = uint64(len(selected.basis.anchor.headBody)), uint64(len(selected.basis.anchor.rootBody))
	if err := add(0, contract.HeadKind, 0, selected.basis.anchor.head.Core.Revision, out.HEADBytes, contract.MaxHeadLength); err != nil {
		return CapacityEncodedUsage{}, err
	}
	if err := add(contract.StorePageObject, contract.RootKind, 0, root.Snapshot, out.RootBytes, contract.MaxRootLength); err != nil {
		return CapacityEncodedUsage{}, err
	}
	configuration, err := contract.EncodeStoreConfiguration(selected.basis.anchor.configuration)
	if err != nil {
		return CapacityEncodedUsage{}, err
	}
	out.ConfigurationBytes = uint64(len(configuration))
	if err := add(contract.StoreConfigurationObject, 0, 0, selected.basis.reader.descriptor.Identity, out.ConfigurationBytes, contract.MaxStoreConfigurationLength); err != nil {
		return CapacityEncodedUsage{}, err
	}
	var childCount uint64
	addRef := func(ref format.Ref) error {
		if !ref.ValidFor(contract.CanonicalSchema) || ref.Domain != root.Domain {
			return contract.ErrRecord
		}
		length := uint64(ref.Length)
		if err := add(contract.StorePageObject, ref.Kind, ref.Index, ref.Object, length, uint64(contract.StoreObjectLimit(gcPageIdentity(ref)))); err != nil {
			return err
		}
		childCount++
		out.ChildBytes += length
		switch ref.Kind {
		case contract.ValueEntryPageKind:
			out.ValueEntryBytes += length
		case contract.RecipientKind:
			out.RecipientBytes += length
		case contract.AccessKind:
			out.AccessBytes += length
		case contract.RequiredSupportKind:
			out.SupportBytes += length
		case contract.AdministrativeIndexKind:
			out.AdministrativeIndexBytes += length
		default:
			return contract.ErrRecord
		}
		return nil
	}
	for _, refs := range [][]*format.Ref{root.ValueEntryPages[:], root.Recipients[:]} {
		for _, ref := range refs {
			if ref != nil {
				if err := addRef(*ref); err != nil {
					return CapacityEncodedUsage{}, err
				}
			}
		}
	}
	for _, refs := range [][]format.Ref{root.CurrentAccess.Core.AccessPageRefs, append([]format.Ref{root.AdministrativeIndex}, root.AdministrativeIndexShards...), root.RequiredSupport} {
		for _, ref := range refs {
			if err := addRef(ref); err != nil {
				return CapacityEncodedUsage{}, err
			}
		}
	}
	if childCount != uint64(root.ChildCount) || out.ChildBytes != root.ChildEncodedBytes {
		return CapacityEncodedUsage{}, contract.ErrRecord
	}
	return out, nil
}

func projectCapacityInspection(selected *publicSelection, facts gcSelectedObservation, page GCCandidatePage) (CapacityInspection, error) {
	var out CapacityInspection
	if selected == nil || !selected.complete || facts.capacity.RootDigest != selected.basis.anchor.head.Core.Root.Digest {
		return out, contract.ErrRecord
	}
	root := selected.image.root
	out.Observation = inspectionObservation(*selected)
	out.Garbage, out.GCObligations = page, facts.obligations
	out.Selected = CapacitySelectedCounts{SecretValues: uint64(root.SecretCount), AccessRecords: uint64(root.AccessRecordCount), SupportRecords: uint64(root.RequiredSupportRecordCount),
		GeneratedAttempts: uint64(root.Generated.Attempts), GeneratedDuties: uint64(root.Generated.Duties), GeneratedHazards: uint64(root.Generated.Hazards), GeneratedMaterials: uint64(root.Generated.Materials),
		PendingInboxReleases: uint64(root.Generated.PendingReleases), GeneratedGraphs: uint64(root.Generated.Graphs.Count), AdministrativeGroups: uint64(len(selected.image.adminIndex.Groups)), GCObligations: uint64(root.GCPlans.Count), OutputBindings: uint64(root.OutputConfiguration.BindingCount)}
	if selected.image.publicationProof != nil {
		for key := range selected.image.publicationProof.rows {
			switch key.kind {
			case contract.PublicationCoordinateSupportKind:
				out.Selected.PublicationCoordinates++
			case contract.PublicationMarkerSupportKind:
				out.Selected.PublicationMarkers++
			}
		}
	}
	measurements := []struct {
		name        string
		used, limit uint64
	}{
		{"current-value-entries", uint64(root.ValueEntryCount), contract.CryptoMaxValueEntries},
		{"current-generated-value-entries", uint64(root.Generated.GeneratedCurrent), contract.GeneratedCurrentEntryLimit},
		{"current-raw-value-bytes", root.RawBytes, contract.CryptoMaxRawSet},
		{"current-recipients", uint64(root.RecipientCount), contract.CryptoMaxRecipients},
		{"current-memberships", uint64(root.MembershipCount), contract.CryptoMaxMemberships},
		{"selected-child-pages", uint64(root.ChildCount), contract.MaxChildPages},
		{"retained-success-receipts", uint64(len(selected.windows.Successes)), contract.MutationReceiptWindowLimit},
		{"retained-failure-receipts", uint64(len(selected.windows.Failures)), contract.MutationReceiptWindowLimit},
		{"common-receipt-order", uint64(len(selected.windows.Order)), 2 * contract.MutationReceiptWindowLimit},
		{"administrative-groups-format", uint64(len(selected.image.adminIndex.Groups)), 65535},
	}
	for _, measurement := range measurements {
		row, err := capacityCount(measurement.name, measurement.used, measurement.limit)
		if err != nil {
			return CapacityInspection{}, err
		}
		out.Counts = append(out.Counts, row)
	}
	var err error
	out.Encoded, err = capacityEncodedUsage(selected)
	if err != nil {
		return CapacityInspection{}, err
	}
	remaining, err := publicCapacityBound(facts.capacity.Remaining)
	if err != nil {
		return CapacityInspection{}, err
	}
	exit, err := publicCapacityBound(facts.capacity.FirstExit)
	if err != nil {
		return CapacityInspection{}, err
	}
	out.Continuation = CapacityContinuationBasis{RootDigest: facts.capacity.RootDigest, Graphs: facts.capacity.Graphs, GCPlans: facts.capacity.GCPlans,
		Remaining: remaining, FirstExit: exit, AdministrativeGroupCountQualification: "format-limit-is-not-proved-usable-admission-capacity",
		AdministrativeExitQualification: "no-general-first-or-all-exit-capacity-guarantee"}
	return out, nil
}
