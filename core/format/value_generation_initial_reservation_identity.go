package format

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

// GeneratorInitialReservationPlan fixes containing objects before its request
// identity exists. Its root references the typed parent-page projection, not
// an actual stored parent. Inputs must remain unchanged through derivation.
// Private admission still owns graph, selected-state and authority checks.
type GeneratorInitialReservationPlan struct {
	Request         contract.GeneratorRequestCore
	Parent          contract.GeneratedParentPlan
	Material        contract.OperationMaterialRecord
	Snapshot        Root
	Head            HeadPlan
	Conditional     ConditionalRequestPlan
	SupportPages    []RequiredSupportPage
	RetainedSupport []Ref
	// OpaqueFragmentPages is used only by a complete selected-image verifier.
	// Its rows were inspected under exact selected Refs and administrative
	// physical spans before large fragment payloads were released.
	OpaqueFragmentPages []GeneratorInitialOpaqueFragmentPage
	AccessPages         []AccessPage
	Administrative      AdministrativeIndex
}

type GeneratorInitialOpaqueFragmentPage struct {
	Ref  Ref
	Rows []contract.SupportRecordDigest
}

type GeneratorInitialIdentity struct {
	RequestIdentityDigest, MaterialDigest ID
	Plan, InitialAccess                   contract.GeneratorDescriptor
}

type GeneratorInitialReservation struct {
	Identity            GeneratorInitialIdentity
	ParentPage          RequiredSupportPage
	Snapshot            Root
	Head                HeadCore
	Conditional         ConditionalPlan
	AdministrativePages []AdministrativeIndexPage
}

func generatorReservationDigest(label string, body []byte) ID {
	w := writer{b: []byte("ENKV/GENERATOR/v1/" + label + "\x00")}
	w.blob(body)
	return contract.Hash(w.b)
}

func generatorReservationDescriptor(label string, body []byte) contract.GeneratorDescriptor {
	w := writer{}
	w.u32(1)
	w.blob(body)
	return contract.GeneratorDescriptor{Digest: generatorReservationDigest(label, w.b), Length: uint64(len(w.b)), Count: 1}
}

type generatorInitialParts struct {
	request, plan, seed []byte
	parentPage          int
}

func (p GeneratorInitialReservationPlan) parts() (generatorInitialParts, error) {
	var out generatorInitialParts
	var err error
	if out.request, err = contract.EncodeGeneratorRequestCore(p.Request); err != nil {
		return out, err
	}
	request, err := contract.GeneratorRequestCoreDigest(p.Request)
	if err != nil || !p.requestMatches(request) {
		return out, ErrFormat
	}
	root, err := EncodeRoot(p.Snapshot)
	if err != nil {
		return out, err
	}
	head, err := EncodeHeadPlan(p.Head)
	if err != nil {
		return out, err
	}
	condition, err := EncodeConditionalRequestPlan(p.Conditional)
	if err != nil || !p.containersMatch(request, len(root), len(head)) {
		return out, ErrFormat
	}
	if out.parentPage, err = p.supportMatches(request); err != nil {
		return out, err
	}
	if err = p.administrativeMatches(); err != nil {
		return out, err
	}
	if out.seed, err = p.accessMatches(request); err != nil {
		return out, err
	}
	w := writer{}
	w.u16(1)
	w.blob(root)
	w.blob(head)
	w.blob(condition)
	out.plan = w.b
	return out, nil
}

func (p GeneratorInitialReservationPlan) administrativeMatches() error {
	if p.Administrative.Domain != p.Request.DomainID || p.Administrative.Object != p.Snapshot.AdministrativeIndex.Object ||
		len(p.Administrative.Pages) != len(p.Snapshot.RequiredSupport) {
		return ErrFormat
	}
	for i, page := range p.Administrative.Pages {
		if page.Ref != p.Snapshot.RequiredSupport[i] {
			return ErrFormat
		}
	}
	pages, err := EncodeAdministrativeIndexPages(p.Administrative)
	if err != nil || len(pages) != 1+len(p.Snapshot.AdministrativeIndexShards) || pages[0].Ref != p.Snapshot.AdministrativeIndex {
		return ErrFormat
	}
	for i, page := range pages[1:] {
		if page.Ref != p.Snapshot.AdministrativeIndexShards[i] {
			return ErrFormat
		}
	}
	return nil
}

func (p GeneratorInitialReservationPlan) requestMatches(request ID) bool {
	q, parent, m := p.Request, p.Parent, p.Material.Core
	if _, err := contract.GeneratedParentPlanLength(parent); err != nil {
		return false
	}
	if _, err := contract.OperationMaterialRecordLength(p.Material); err != nil {
		return false
	}
	material, err := contract.GeneratorMaterialID(q.DomainID, q.OperationID)
	return err == nil && parent.DomainID == q.DomainID && parent.OperationID == q.OperationID && parent.RequestCoreDigest == request &&
		parent.Declaration == q.Declaration && parent.Registry == q.Registry &&
		parent.RecoveryPolicyID == q.RecoveryPolicyID && parent.InitialPredecessorDigest == q.PredecessorHEADDigest && parent.ConditionDigest == q.ConditionDigest &&
		parent.MaterialID == material && m.OperationMaterialID == material && m.DomainID == q.DomainID && m.OperationID == q.OperationID &&
		m.UsePlanDigest == parent.UsePlanDigest && m.CompatibilityID == q.CompatibilityID && m.CryptoSupportID == p.Snapshot.CurrentAccess.Core.CryptoSupportID &&
		q.CompatibilityID == p.Snapshot.CurrentAccess.Core.CompatibilityID
}

func (p GeneratorInitialReservationPlan) containersMatch(request ID, rootLength, headLength int) bool {
	q, r, h, c := p.Request, p.Snapshot, HeadCore(p.Head), ConditionalPlan(p.Conditional)
	snapshot, err := contract.GeneratorInitialSnapshotID(request)
	if err != nil {
		return false
	}
	transition, err := contract.GeneratorInitialTransitionID(request)
	if err != nil {
		return false
	}
	revision, err := contract.GeneratorInitialRevisionID(request)
	if err != nil {
		return false
	}
	phase, err := contract.GeneratorInitialPhaseID(request)
	if err != nil {
		return false
	}
	control := r.CurrentAccess.Core
	if r.Domain != q.DomainID || r.Snapshot != snapshot || r.Transition != transition || r.Generated.ActiveOwner != q.OperationID ||
		r.Generated.ActivePhase != phase || r.Generated.ActiveGraph != p.Parent.PlanGraphID || h.Domain != q.DomainID || h.Revision != revision ||
		h.PreviousRevision != q.PredecessorRevisionID || h.PreviousDigest != q.PredecessorHEADDigest || h.Root.Object != snapshot || h.Root.Length != uint32(rootLength) ||
		h.Store != control.StoreID || h.Trust != control.NormalSigning.Binding.Trust || h.Coordinate != control.CoordinateID || h.NonBody != control.NonBodyID ||
		h.Interpretation != control.NormalSigning.Binding.Interpretation || h.Epoch != control.NormalSigning.Binding.Epoch ||
		c.Family != control.Provider || c.Store != h.Store || c.Coordinate != h.Coordinate || c.NonBody != h.NonBody || c.HeadCoreLength != uint32(headLength) {
		return false
	}
	token, ok := c.Condition.Token()
	digest, err := contract.CryptoConditionDigest(c.Condition)
	return ok && err == nil && token == h.PreviousToken && digest == q.ConditionDigest
}

func (p GeneratorInitialReservationPlan) initialPhaseValid(v contract.GeneratedPhaseRecord) bool {
	// Core checks the index against the complete graph, whose first create can
	// follow an earlier retirement container. This constructor binds that index.
	return v.DomainID == p.Request.DomainID && v.OperationID == p.Request.OperationID && v.OwnerID == p.Request.OperationID &&
		v.PlanGraphID == p.Parent.PlanGraphID && v.UsePlanDigest == p.Parent.UsePlanDigest && v.PhaseID == p.Snapshot.Generated.ActivePhase &&
		v.Phase == 1 && v.LineageIndex < contract.GeneratorMaxLineageTemplates && v.Branch == contract.GeneratorBranchInitial && v.Stage == contract.GeneratedStageRetainedResult && v.NoEffectUsed == 0 && v.ResidueUsed == 0 &&
		v.AcceptedResultID.IsZero() && v.ResultDigest.IsZero() && v.Proofs == contract.EmptyGeneratorVector(contract.GeneratorVectorProofs) &&
		v.AcceptedResults.Count == 0 && v.Hazards.Count == 0 && v.PendingReleases.Count == 0
}

func (p GeneratorInitialReservationPlan) supportMatches(request ID) (int, error) {
	if len(p.SupportPages)+len(p.RetainedSupport) != len(p.Snapshot.RequiredSupport) {
		return 0, ErrFormat
	}
	if len(p.OpaqueFragmentPages) != 0 && len(p.OpaqueFragmentPages) != len(p.SupportPages) {
		return 0, ErrFormat
	}
	parentPage, parents, materials, phases, count := 0, 0, 0, 0, uint32(0)
	seen := make(map[supportRecordKey]struct{})
	selectedRefs := make(map[uint16]Ref, len(p.Snapshot.RequiredSupport))
	for _, ref := range p.Snapshot.RequiredSupport {
		if _, duplicate := selectedRefs[ref.Index]; duplicate {
			return 0, ErrFormat
		}
		selectedRefs[ref.Index] = ref
	}
	usedIndices := make(map[uint16]bool)
	configurationIDs := make(map[ID]bool)
	configurationLengths := make(map[ID]uint32, p.Snapshot.OutputConfiguration.SliceCount)
	for i := uint16(0); i < p.Snapshot.OutputConfiguration.SliceCount; i++ {
		id, err := contract.OutputConfigurationSliceID(p.Request.DomainID, p.Snapshot.OutputConfiguration.ConfigurationDigest, i)
		if err != nil {
			return 0, ErrFormat
		}
		length := min(contract.MaxOutputConfigurationSliceBytes, int(p.Snapshot.OutputConfiguration.TotalLength)-int(i)*contract.MaxOutputConfigurationSliceBytes)
		configurationLengths[id] = uint32(contract.OutputConfigurationSliceBodyOverhead + length)
	}
	matchConfiguration := func(id ID, length uint32) bool {
		expected, present := configurationLengths[id]
		if !present || expected != length || configurationIDs[id] {
			return false
		}
		configurationIDs[id] = true
		return true
	}
	for _, ref := range p.RetainedSupport {
		if selectedRefs[ref.Index] != ref || usedIndices[ref.Index] {
			return 0, ErrFormat
		}
		usedIndices[ref.Index] = true
		position := slices.IndexFunc(p.Administrative.Pages, func(page AdministrativePage) bool { return page.Ref == ref })
		if position < 0 {
			return 0, ErrFormat
		}
		page := p.Administrative.Pages[position]
		if page.ReadRequired || len(page.Rows) == 0 {
			return 0, ErrFormat
		}
		for _, span := range page.Spans {
			if !span.Mandatory || len(span.GroupIndexes) != 0 {
				return 0, ErrFormat
			}
		}
		for _, row := range page.Rows {
			if row.Kind != contract.OutputConfigurationSliceSupportKind || !matchConfiguration(row.RecordID, row.BodyLength) {
				return 0, ErrFormat
			}
		}
		count += uint32(len(page.Rows))
	}
	for i, page := range p.SupportPages {
		if usedIndices[page.Index] {
			return 0, ErrFormat
		}
		usedIndices[page.Index] = true
		position := slices.IndexFunc(p.Snapshot.RequiredSupport, func(ref Ref) bool { return ref.Index == page.Index })
		if position < 0 {
			return 0, ErrFormat
		}
		if page.Domain != p.Request.DomainID || len(page.Records) > (MaxRequiredSupportPage-contract.RequiredSupportPageHeaderLength)/contract.SupportRecordMinLength {
			return 0, ErrFormat
		}
		if len(p.OpaqueFragmentPages) != 0 && len(p.OpaqueFragmentPages[i].Rows) != 0 {
			opaque := p.OpaqueFragmentPages[i]
			ref := p.Snapshot.RequiredSupport[position]
			if len(page.Records) != 0 || opaque.Ref != ref || ref.Kind != contract.RequiredSupportKind ||
				page.Domain != ref.Domain || page.Object != ref.Object || page.Index != ref.Index ||
				position >= len(p.Administrative.Pages) || p.Administrative.Pages[position].ReadRequired ||
				len(p.Administrative.Pages[position].Rows) != len(opaque.Rows) {
				return 0, ErrFormat
			}
			// The page keeps its authenticated physical row order. Distinct
			// fragment owners can share a page without RecordID order, while
			// the typed descriptor validator requires canonical key order.
			ordered := slices.Clone(opaque.Rows)
			slices.SortFunc(ordered, func(a, b contract.SupportRecordDigest) int {
				if a.Kind() < b.Kind() {
					return -1
				}
				if a.Kind() > b.Kind() {
					return 1
				}
				aID, bID := a.RecordID(), b.RecordID()
				return bytes.Compare(aID[:], bID[:])
			})
			if _, err := contract.RequiredSupportDescriptorFromDigests(page.Domain, ordered); err != nil {
				return 0, ErrFormat
			}
			for j, row := range opaque.Rows {
				indexed := p.Administrative.Pages[position].Rows[j]
				key := supportRecordKey{row.Kind(), row.RecordID()}
				if row.Kind() != contract.GeneratedFragmentSupportKind || indexed.Kind != row.Kind() ||
					indexed.RecordID != row.RecordID() || indexed.BodyLength != row.BodyLength() {
					return 0, ErrFormat
				}
				if _, duplicate := seen[key]; duplicate {
					return 0, ErrFormat
				}
				seen[key] = struct{}{}
			}
			count += uint32(len(opaque.Rows))
			continue
		}
		planned, newMaterial := false, false
		for _, row := range page.Records {
			key := supportRecordKey{row.Kind, row.RecordID}
			if _, duplicate := seen[key]; duplicate {
				return 0, ErrFormat
			}
			seen[key] = struct{}{}
			if row.Kind == contract.OutputConfigurationSliceSupportKind {
				part, err := contract.InspectOutputConfigurationSlice(row.Body)
				if err != nil || part.DomainID != p.Request.DomainID || part.ConfigurationDigest != p.Snapshot.OutputConfiguration.ConfigurationDigest ||
					part.SliceCount != p.Snapshot.OutputConfiguration.SliceCount || part.TotalLength != p.Snapshot.OutputConfiguration.TotalLength ||
					!matchConfiguration(row.RecordID, uint32(len(row.Body))) {
					return 0, ErrFormat
				}
			}
			switch {
			case row.Kind == contract.GeneratedParentSupportKind && row.RecordID == p.Parent.OperationID:
				planned, newMaterial = true, true
				parentPage, parents = i, parents+1
			case row.Kind == contract.OperationMaterialSupportKind && row.RecordID == p.Parent.MaterialID:
				material, err := contract.InspectOperationMaterialRecord(row.Body)
				if err != nil || material != p.Material {
					return 0, ErrFormat
				}
				materials++
				newMaterial = true
			case row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == p.Parent.OperationID:
				phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
				if err != nil || !p.initialPhaseValid(phase) {
					return 0, ErrFormat
				}
				phases++
				newMaterial = true
			case row.Kind == contract.MutationReceiptSupportKind && row.RecordID == p.Parent.OperationID:
				return 0, ErrFormat
			}
		}
		if newMaterial {
			id, err := contract.GeneratorInitialPageID(request, contract.RequiredSupportKind, page.Index)
			if err != nil || page.Object != id {
				return 0, ErrFormat
			}
		}
		var body []byte
		var err error
		if planned {
			body, err = EncodeRequiredSupportParentPlan(page, p.Parent)
		} else {
			body, err = EncodeRequiredSupportPage(page)
		}
		ref := Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: page.Domain, Object: page.Object, Index: page.Index, Digest: contract.Hash(body), Length: uint32(len(body))}
		if err != nil || p.Snapshot.RequiredSupport[position] != ref {
			return 0, ErrFormat
		}
		count += uint32(len(page.Records))
	}
	if len(configurationIDs) != int(p.Snapshot.OutputConfiguration.SliceCount) ||
		parents != 1 || materials != 1 || phases != 1 || count != p.Snapshot.RequiredSupportRecordCount {
		return 0, ErrFormat
	}
	return parentPage, nil
}

func (p GeneratorInitialReservationPlan) accessMatches(request ID) ([]byte, error) {
	if len(p.AccessPages) != len(p.Snapshot.CurrentAccess.Core.AccessPageRefs) {
		return nil, ErrFormat
	}
	var seed []byte
	var records []contract.AccessRecord
	context, err := contract.OperationMaterialContextDigest(p.Material.Core)
	if err != nil {
		return nil, err
	}
	for i, page := range p.AccessPages {
		body, err := EncodeAccessPage(page)
		if err != nil || page.Domain != p.Request.DomainID {
			return nil, ErrFormat
		}
		ref := Ref{Kind: AccessKind, Format: Version, Domain: page.Domain, Object: page.Object, Index: page.Index, Digest: contract.Hash(body), Length: uint32(len(body))}
		if p.Snapshot.CurrentAccess.Core.AccessPageRefs[i] != ref {
			return nil, ErrFormat
		}
		for _, row := range page.Records {
			if row.MaterialKind != contract.OperationSeedMaterialKind || row.MaterialID != p.Parent.MaterialID {
				continue
			}
			id, err := contract.GeneratorInitialPageID(request, AccessKind, page.Index)
			if err != nil || page.Object != id || seed != nil || row.MaterialContextDigest != context || row.PackageCheck != p.Material.SeedCheck || !p.seedSubjectsMatch(row) {
				return nil, ErrFormat
			}
			seed, err = contract.EncodeAccessRecord(row)
			if err != nil {
				return nil, err
			}
		}
		records = append(records, page.Records...)
	}
	slices.SortFunc(records, func(a, b contract.AccessRecord) int {
		if a.MaterialKind < b.MaterialKind {
			return -1
		}
		if a.MaterialKind > b.MaterialKind {
			return 1
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	d, err := contract.AccessRecordsDescriptor(p.Request.DomainID, records)
	if err != nil || seed == nil || d != p.Snapshot.CurrentAccess.Core.AccessRecordsDescriptor {
		return nil, ErrFormat
	}
	return seed, nil
}

func (p GeneratorInitialReservationPlan) seedSubjectsMatch(row contract.AccessRecord) bool {
	control := p.Snapshot.CurrentAccess.Core
	want := 1
	if control.Recovery != nil {
		want++
	}
	if len(row.Wraps) != want || row.Wraps[0].SubjectKind != contract.OrdinaryWrapSubject || row.Wraps[0].SubjectID != control.AuthorityRecipientID {
		return false
	}
	return want == 1 || row.Wraps[1].SubjectKind == contract.RecoveryWrapSubject && row.Wraps[1].SubjectID == control.Recovery.RoleID
}

func generatorInitialIdentity(p GeneratorInitialReservationPlan, parts generatorInitialParts) (GeneratorInitialIdentity, error) {
	material, err := contract.OperationImmutableBodyDigest(p.Material.Core, p.Material.SeedCheck)
	if err != nil {
		return GeneratorInitialIdentity{}, err
	}
	out := GeneratorInitialIdentity{MaterialDigest: material, Plan: generatorReservationDescriptor("initial-reservation", parts.plan),
		InitialAccess: generatorReservationDescriptor("initial-access", parts.seed)}
	w := writer{}
	w.blob(parts.request)
	w.id(p.Parent.PlanGraphID)
	w.id(p.Parent.UsePlanDigest)
	w.id(material)
	for _, d := range []contract.GeneratorDescriptor{out.InitialAccess, p.Parent.IntendedEntryPlans} {
		w.b, err = contract.AppendGeneratorDescriptor(w.b, d)
		if err != nil {
			return GeneratorInitialIdentity{}, err
		}
	}
	w.blob(parts.plan)
	out.RequestIdentityDigest = generatorReservationDigest("request", w.b)
	return out, nil
}

func DeriveGeneratorInitialIdentity(p GeneratorInitialReservationPlan) (GeneratorInitialIdentity, error) {
	parts, err := p.parts()
	if err != nil {
		return GeneratorInitialIdentity{}, err
	}
	return generatorInitialIdentity(p, parts)
}

// FillGeneratorInitialReservation does not produce proofs or select state. It
// changes only the named parent hole and the digest references that depend on it.
func FillGeneratorInitialReservation(p GeneratorInitialReservationPlan) (GeneratorInitialReservation, error) {
	parts, err := p.parts()
	if err != nil {
		return GeneratorInitialReservation{}, err
	}
	identity, err := generatorInitialIdentity(p, parts)
	if err != nil {
		return GeneratorInitialReservation{}, err
	}
	parent := contract.GeneratedParentRecord(p.Parent)
	parent.RequestIdentityDigest = identity.RequestIdentityDigest
	body, err := contract.EncodeGeneratedParentRecord(parent)
	if err != nil {
		return GeneratorInitialReservation{}, err
	}
	page := p.SupportPages[parts.parentPage]
	page.Records = slices.Clone(page.Records)
	for i, row := range page.Records {
		if row.Kind == contract.GeneratedParentSupportKind && row.RecordID == parent.OperationID {
			page.Records[i].Body = body
		}
	}
	pageBytes, err := EncodeRequiredSupportPage(page)
	if err != nil {
		return GeneratorInitialReservation{}, err
	}
	root := p.Snapshot
	root.RequiredSupport = slices.Clone(root.RequiredSupport)
	position := slices.IndexFunc(root.RequiredSupport, func(ref Ref) bool { return ref.Index == page.Index })
	if position < 0 {
		return GeneratorInitialReservation{}, ErrFormat
	}
	root.RequiredSupport[position].Digest = contract.Hash(pageBytes)
	administrative := p.Administrative
	administrative.Pages = slices.Clone(administrative.Pages)
	administrative.Pages[position].Ref = root.RequiredSupport[position]
	administrativePages, err := EncodeAdministrativeIndexPages(administrative)
	if err != nil || len(administrativePages) != 1+len(root.AdministrativeIndexShards) {
		return GeneratorInitialReservation{}, ErrFormat
	}
	root.AdministrativeIndex = administrativePages[0].Ref
	root.AdministrativeIndexShards = make([]Ref, 0, len(administrativePages)-1)
	for _, shard := range administrativePages[1:] {
		root.AdministrativeIndexShards = append(root.AdministrativeIndexShards, shard.Ref)
	}
	root.ChildEncodedBytes = p.Snapshot.ChildEncodedBytes - uint64(p.Snapshot.AdministrativeIndex.Length) + uint64(root.AdministrativeIndex.Length)
	for i, shard := range root.AdministrativeIndexShards {
		root.ChildEncodedBytes += uint64(shard.Length) - uint64(p.Snapshot.AdministrativeIndexShards[i].Length)
	}
	rootBytes, err := EncodeRoot(root)
	if err != nil {
		return GeneratorInitialReservation{}, err
	}
	head := HeadCore(p.Head)
	head.Root.Digest = contract.Hash(rootBytes)
	headBytes, err := EncodeHeadCore(head)
	if err != nil {
		return GeneratorInitialReservation{}, err
	}
	condition := ConditionalPlan(p.Conditional)
	condition.HeadCore = contract.Hash(headBytes)
	if _, err := EncodeConditionalPlan(condition); err != nil {
		return GeneratorInitialReservation{}, err
	}
	return GeneratorInitialReservation{Identity: identity, ParentPage: page, Snapshot: root, Head: head, Conditional: condition,
		AdministrativePages: administrativePages}, nil
}
