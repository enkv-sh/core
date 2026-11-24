package format

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func initialReservationFixture(t testing.TB) GeneratorInitialReservationPlan {
	t.Helper()
	r := rootFixture(t)
	outputRef := r.RequiredSupport[0]
	r.ValueEntryPages, r.Names = [contract.MaxValueEntryPages]*Ref{}, nil
	r.ValueEntryCount, r.RawBytes, r.MembershipCount = 0, 0, 0
	q := contract.GeneratorRequestCore{Schema: contract.GeneratorRequestCoreSchema, OperationKind: 2, DomainID: r.Domain, OperationID: fid(2),
		PredecessorRevisionID: fid(50), PredecessorHEADDigest: fid(51), CallerNonce: fid(52), CompatibilityID: r.CurrentAccess.Core.CompatibilityID,
		RecoveryPolicyID: fid(9), Declaration: generatedParentPlanFixture().Declaration, Registry: generatedParentPlanFixture().Registry}
	token := contract.Token{Family: contract.AWS, Value: `"etag"`}
	condition := conditionFixture(token)
	var err error
	q.ConditionDigest, err = contract.CryptoConditionDigest(condition)
	if err != nil {
		t.Fatal(err)
	}
	parent := generatedParentPlanFixture()
	parent.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(q)
	if err != nil {
		t.Fatal(err)
	}
	parent.MaterialID, err = contract.GeneratorMaterialID(q.DomainID, q.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	parent.InitialPredecessorDigest, parent.ConditionDigest = q.PredecessorHEADDigest, q.ConditionDigest
	material := contract.OperationMaterialRecord{Core: contract.OperationMaterialCore{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: q.CompatibilityID,
		CryptoSupportID: r.CurrentAccess.Core.CryptoSupportID, DomainID: q.DomainID, OperationID: q.OperationID, OperationMaterialID: parent.MaterialID,
		UsePlanDigest: parent.UsePlanDigest, SeedEpoch: 1}, SeedCheck: fid(55)}
	phaseID, err := contract.GeneratorInitialPhaseID(parent.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	d := contract.EmptyGeneratorIndexes()[0]
	phase := contract.GeneratedPhaseRecord{Schema: contract.GeneratedPhaseSchema, DomainID: q.DomainID, OperationID: q.OperationID, PlanGraphID: parent.PlanGraphID,
		UsePlanDigest: parent.UsePlanDigest, OwnerID: q.OperationID, PhaseID: phaseID, FrontierAttemptID: fid(56), Phase: 1, Stage: contract.GeneratedStageRetainedResult,
		AcceptedResults: d, Attempts: d, Duties: d, Hazards: d, PendingReleases: d, Proofs: contract.EmptyGeneratorVector(contract.GeneratorVectorProofs)}
	mb, err := contract.EncodeOperationMaterialRecord(material)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := contract.EncodeGeneratedParentPlan(parent)
	if err != nil {
		t.Fatal(err)
	}
	phb, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	pages := []RequiredSupportPage{{Domain: q.DomainID, Index: 1, Records: []contract.SupportRecord{{Kind: 1, RecordID: parent.MaterialID, Body: mb}, {Kind: 2, RecordID: parent.OperationID, Body: pb}}},
		{Domain: q.DomainID, Index: 2, Records: []contract.SupportRecord{{Kind: 5, RecordID: parent.OperationID, Body: phb}}}}
	for i := range pages {
		pages[i].Object, err = contract.GeneratorInitialPageID(parent.RequestCoreDigest, contract.RequiredSupportKind, pages[i].Index)
		if err != nil {
			t.Fatal(err)
		}
	}
	seedPage := accessFixture()
	seedPage.Index = 0
	seedPage.Object, err = contract.GeneratorInitialPageID(parent.RequestCoreDigest, AccessKind, seedPage.Index)
	if err != nil {
		t.Fatal(err)
	}
	seed := &seedPage.Records[0]
	seed.MaterialKind, seed.MaterialID, seed.PackageCheck = 3, parent.MaterialID, material.SeedCheck
	seed.MaterialContextDigest, err = contract.OperationMaterialContextDigest(material.Core)
	if err != nil {
		t.Fatal(err)
	}
	seed.Wraps[0].SubjectID = r.CurrentAccess.Core.AuthorityRecipientID
	r.Snapshot, err = contract.GeneratorInitialSnapshotID(parent.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	r.Transition, err = contract.GeneratorInitialTransitionID(parent.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	r.Generated.ActiveOwner, r.Generated.ActivePhase, r.Generated.ActiveGraph = q.OperationID, phaseID, parent.PlanGraphID
	r.Generated.Materials = 1
	h := HeadCore{Form: SuccessorHead, Domain: q.DomainID, PreviousRevision: q.PredecessorRevisionID, PreviousDigest: q.PredecessorHEADDigest, PreviousToken: token,
		Root: Ref{Kind: RootKind, Format: Version, Domain: q.DomainID, Object: r.Snapshot}, Store: r.CurrentAccess.Core.StoreID,
		Trust: r.CurrentAccess.Core.NormalSigning.Binding.Trust, Coordinate: r.CurrentAccess.Core.CoordinateID, NonBody: r.CurrentAccess.Core.NonBodyID,
		Interpretation: r.CurrentAccess.Core.NormalSigning.Binding.Interpretation, Epoch: r.CurrentAccess.Core.NormalSigning.Binding.Epoch}
	h.Revision, err = contract.GeneratorInitialRevisionID(parent.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	p := GeneratorInitialReservationPlan{Request: q, Parent: parent, Material: material, Snapshot: r, SupportPages: pages, RetainedSupport: []Ref{outputRef}, AccessPages: []AccessPage{seedPage},
		Head: HeadPlan(h), Conditional: ConditionalRequestPlan(ConditionalPlan{Family: token.Family, Store: h.Store, Coordinate: h.Coordinate, NonBody: h.NonBody, Condition: condition})}
	refreshInitialReservationFixture(t, &p)
	return p
}

func refreshInitialReservationFixture(t testing.TB, p *GeneratorInitialReservationPlan) {
	t.Helper()
	r := &p.Snapshot
	r.RequiredSupport, r.CurrentAccess.Core.AccessPageRefs = nil, nil
	r.RequiredSupportRecordCount = 0
	r.ChildCount, r.ChildEncodedBytes = 0, 0
	for _, table := range [][]*Ref{r.ValueEntryPages[:], r.Recipients[:]} {
		for _, ref := range table {
			if ref != nil {
				r.ChildCount++
				r.ChildEncodedBytes += uint64(ref.Length)
			}
		}
	}
	for _, page := range p.SupportPages {
		var body []byte
		var err error
		planned := false
		for _, row := range page.Records {
			if row.Kind == 2 && row.RecordID == p.Parent.OperationID {
				planned = true
			}
		}
		if planned {
			body, err = EncodeRequiredSupportParentPlan(page, p.Parent)
		} else {
			body, err = EncodeRequiredSupportPage(page)
		}
		if err != nil {
			t.Fatal(err)
		}
		r.RequiredSupport = append(r.RequiredSupport, Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: r.Domain, Object: page.Object, Index: page.Index, Digest: contract.Hash(body), Length: uint32(len(body))})
		r.RequiredSupportRecordCount += uint32(len(page.Records))
		r.ChildCount++
		r.ChildEncodedBytes += uint64(len(body))
	}
	for _, ref := range p.RetainedSupport {
		r.RequiredSupport = append(r.RequiredSupport, ref)
		r.RequiredSupportRecordCount++
		r.ChildCount++
		r.ChildEncodedBytes += uint64(ref.Length)
	}
	slices.SortFunc(r.RequiredSupport, func(a, b Ref) int { return int(a.Index) - int(b.Index) })
	indexID, err := contract.GeneratorInitialPageID(p.Parent.RequestCoreDigest, contract.AdministrativeIndexKind, 0)
	if err != nil {
		t.Fatal(err)
	}
	d := contract.GeneratorDescriptor{Digest: fid(6), Length: 4}
	index := AdministrativeIndex{Domain: r.Domain, Object: indexID, SliceSnapshot: r.Snapshot, Groups: []AdministrativeGroup{{
		GroupID: p.Parent.OperationID, OwnerID: p.Parent.OperationID, TargetID: p.Parent.OperationID, OwnerKind: AdministrativeGeneratedParent,
		SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing, Affected: d, Dependencies: d, Disposable: d,
	}}}
	for _, ref := range r.RequiredSupport {
		position := slices.IndexFunc(p.SupportPages, func(page RequiredSupportPage) bool { return page.Index == ref.Index })
		if position < 0 {
			image, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: r.Domain})
			if err != nil {
				t.Fatal(err)
			}
			_, slices, err := contract.SplitOutputConfiguration(r.Domain, image)
			if err != nil || len(slices) != 1 {
				t.Fatal(err)
			}
			body, err := contract.EncodeOutputConfigurationSlice(slices[0])
			if err != nil {
				t.Fatal(err)
			}
			id, err := contract.OutputConfigurationSliceID(r.Domain, r.OutputConfiguration.ConfigurationDigest, 0)
			if err != nil {
				t.Fatal(err)
			}
			index.Pages = append(index.Pages, AdministrativePage{Ref: ref, Rows: []AdministrativeRowSummary{{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, BodyLength: uint32(len(body))}}, Spans: []AdministrativeSpan{{First: 0, Count: 1, Mandatory: true}}})
			continue
		}
		rows := make([]AdministrativeRowSummary, len(p.SupportPages[position].Records))
		for j, row := range p.SupportPages[position].Records {
			rows[j] = AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))}
		}
		index.Pages = append(index.Pages, AdministrativePage{Ref: ref, Rows: rows, Spans: []AdministrativeSpan{{First: 0, Count: uint16(len(rows)), GroupIndexes: []uint16{0}}}})
	}
	indexPages, err := EncodeAdministrativeIndexPages(index)
	if err != nil || len(indexPages) != 1 {
		t.Fatal(err)
	}
	p.Administrative = index
	r.AdministrativeIndex = indexPages[0].Ref
	r.ChildCount++
	r.ChildEncodedBytes += uint64(len(indexPages[0].Body))
	a, err := EncodeAccessPage(p.AccessPages[0])
	if err != nil {
		t.Fatal(err)
	}
	ar, err := Reference(AccessKind, r.Domain, p.AccessPages[0].Object, p.AccessPages[0].Index, a)
	if err != nil {
		t.Fatal(err)
	}
	r.CurrentAccess.Core.AccessPageRefs = []Ref{ar}
	r.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(r.Domain, p.AccessPages[0].Records)
	if err != nil {
		t.Fatal(err)
	}
	r.CurrentAccess.AccessRoot, err = contract.AccessRoot(r.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	r.AccessRecordCount = uint32(len(p.AccessPages[0].Records))
	r.ChildCount++
	r.ChildEncodedBytes += uint64(len(a))
	raw, err := EncodeRoot(*r)
	if err != nil {
		t.Fatal(err)
	}
	p.Head.Root.Length = uint32(len(raw))
	hb, err := EncodeHeadPlan(p.Head)
	if err != nil {
		t.Fatal(err)
	}
	p.Conditional.HeadCoreLength = uint32(len(hb))
}

// full_only: false
func TestGeneratorInitialReservationRetainsSparseMixedOutputReference(t *testing.T) {
	p := initialReservationFixture(t)
	image, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: p.Request.DomainID})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, slices, err := contract.SplitOutputConfiguration(p.Request.DomainID, image)
	if err != nil || descriptor != p.Snapshot.OutputConfiguration || len(slices) != 1 {
		t.Fatal("canonical selected output", err)
	}
	body, err := contract.EncodeOutputConfigurationSlice(slices[0])
	if err != nil {
		t.Fatal(err)
	}
	id, err := contract.OutputConfigurationSliceID(p.Request.DomainID, descriptor.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	physical := RequiredSupportPage{Domain: p.Request.DomainID, Object: fid(230), Index: 5,
		Records: []contract.SupportRecord{p.SupportPages[0].Records[0], {Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body}}}
	physicalBytes, err := EncodeRequiredSupportPage(physical)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := Reference(contract.RequiredSupportKind, physical.Domain, physical.Object, physical.Index, physicalBytes)
	if err != nil {
		t.Fatal(err)
	}
	p.RetainedSupport = []Ref{ref}
	refreshInitialReservationFixture(t, &p)
	if len(p.Snapshot.RequiredSupport) != 3 || p.Snapshot.RequiredSupport[2] != ref || p.Snapshot.RequiredSupport[0].Index != 1 {
		t.Fatal("sparse output ref shifted or sorted incorrectly")
	}
	p.Administrative.Pages[2].Spans[0].First = 1 // Physical ordinal zero is no longer selected.
	indexPages, err := EncodeAdministrativeIndexPages(p.Administrative)
	if err != nil || len(indexPages) != 1 {
		t.Fatal(err)
	}
	p.Snapshot.AdministrativeIndex = indexPages[0].Ref
	got, err := DeriveGeneratorInitialIdentity(p)
	if err != nil {
		t.Fatal("sparse selected identity", err)
	}
	filled, err := FillGeneratorInitialReservation(p)
	if err != nil || filled.Identity != got || filled.ParentPage.Index != 1 || filled.Snapshot.RequiredSupport[2] != ref ||
		filled.AdministrativePages[0].Ref == (Ref{}) {
		t.Fatal("sparse parent or retained output changed", err)
	}
	missing := p
	missing.RetainedSupport = nil
	if _, err := DeriveGeneratorInitialIdentity(missing); err == nil {
		t.Fatal("retained output reference omitted")
	}
}

// full_only: false
func TestGeneratorInitialReservationConfigurationSlicePartitions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		retained int
		damage   string
	}{
		{"all new", 0, ""},
		{"all retained", 2, ""},
		{"mixed", 1, ""},
		{"missing new", 1, "missing"},
		{"missing all-new slice", 0, "missing"},
		{"duplicate retained and new", 1, "duplicate"},
		{"duplicate new", 0, "duplicate"},
		{"wrong new total", 1, "total"},
		{"wrong retained length", 1, "retained length"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := initialReservationFixture(t)
			p.RetainedSupport = nil
			// Format binds individual slice metadata. Core verifies the whole image.
			const total = contract.MaxOutputConfigurationSliceBytes + 14
			p.Snapshot.OutputConfiguration = contract.OutputConfigurationDescriptor{Schema: contract.OutputConfigurationSchema, ConfigurationDigest: fid(232), TotalLength: total, SliceCount: 2, RoutingLength: 5}
			var output []RequiredSupportPage
			for i := uint16(0); i < 2; i++ {
				if tc.damage == "missing" && i == 1 {
					continue
				}
				length := contract.MaxOutputConfigurationSliceBytes
				if i == 1 {
					length = 14
				}
				part := contract.OutputConfigurationSlice{Schema: contract.OutputConfigurationSchema, DomainID: p.Request.DomainID, ConfigurationDigest: p.Snapshot.OutputConfiguration.ConfigurationDigest,
					SliceIndex: i, SliceCount: 2, TotalLength: total, SliceBytes: make([]byte, length)}
				id, err := contract.OutputConfigurationSliceID(p.Request.DomainID, part.ConfigurationDigest, i)
				if err != nil {
					t.Fatal(err)
				}
				if i == 1 {
					switch tc.damage {
					case "duplicate":
						part.SliceIndex, part.SliceBytes = 0, make([]byte, contract.MaxOutputConfigurationSliceBytes)
						id, err = contract.OutputConfigurationSliceID(p.Request.DomainID, part.ConfigurationDigest, 0)
						if err != nil {
							t.Fatal(err)
						}
					case "total":
						part.TotalLength++
						part.SliceBytes = append(part.SliceBytes, 0)
					}
				}
				body, err := contract.EncodeOutputConfigurationSlice(part)
				if err != nil {
					t.Fatal(err)
				}
				output = append(output, RequiredSupportPage{Domain: p.Request.DomainID, Object: fid(byte(234 + i)), Index: 5 + i,
					Records: []contract.SupportRecord{{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body}}})
			}
			p.SupportPages = append(p.SupportPages, output...)
			refreshInitialReservationFixture(t, &p)
			for _, page := range output {
				position := slices.IndexFunc(p.Administrative.Pages, func(indexed AdministrativePage) bool { return indexed.Ref.Index == page.Index })
				p.Administrative.Pages[position].Spans = []AdministrativeSpan{{First: 0, Count: 1, Mandatory: true}}
				if tc.damage == "retained length" && page.Index == 5 {
					p.Administrative.Pages[position].Rows[0].BodyLength--
				}
			}
			indexPages, err := EncodeAdministrativeIndexPages(p.Administrative)
			if err != nil {
				t.Fatal(err)
			}
			p.Snapshot.ChildEncodedBytes -= uint64(p.Snapshot.AdministrativeIndex.Length)
			p.Snapshot.AdministrativeIndex = indexPages[0].Ref
			p.Snapshot.ChildEncodedBytes += uint64(indexPages[0].Ref.Length)
			root, err := EncodeRoot(p.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			p.Head.Root.Length = uint32(len(root))
			for _, page := range output[:min(tc.retained, len(output))] {
				position := slices.IndexFunc(p.Snapshot.RequiredSupport, func(ref Ref) bool { return ref.Index == page.Index })
				p.RetainedSupport = append(p.RetainedSupport, p.Snapshot.RequiredSupport[position])
				p.SupportPages = slices.DeleteFunc(p.SupportPages, func(changed RequiredSupportPage) bool { return changed.Index == page.Index })
			}
			got, err := DeriveGeneratorInitialIdentity(p)
			if tc.damage != "" {
				if err == nil {
					t.Fatal("invalid configuration slice selection accepted")
				}
				return
			}
			if err != nil {
				t.Fatal("complete configuration partition refused", err)
			}
			filled, err := FillGeneratorInitialReservation(p)
			if err != nil || filled.Identity != got {
				t.Fatal("configuration partition changed filled identity", err)
			}
		})
	}
}

// full_only: false
func TestGeneratorInitialReservationFillsOnlyNamedDependencies(t *testing.T) {
	p := initialReservationFixture(t)
	identity, err := DeriveGeneratorInitialIdentity(p)
	if err != nil || identity.RequestIdentityDigest.IsZero() || identity.InitialAccess.Count != 1 || identity.Plan.Count != 1 {
		t.Fatalf("initial identity: %v", err)
	}
	filled, err := FillGeneratorInitialReservation(p)
	if err != nil || filled.Identity != identity {
		t.Fatalf("fill: %v", err)
	}
	if filled.Snapshot.CurrentAccess.AccessRoot != p.Snapshot.CurrentAccess.AccessRoot || filled.Snapshot.ChildEncodedBytes != p.Snapshot.ChildEncodedBytes ||
		filled.Snapshot.Snapshot != p.Snapshot.Snapshot || filled.Head.Revision != p.Head.Revision {
		t.Fatal("fill changed independent state")
	}
	planned, err := EncodeRequiredSupportParentPlan(p.SupportPages[0], p.Parent)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := EncodeRequiredSupportPage(filled.ParentPage)
	if err != nil {
		t.Fatal(err)
	}
	// 75-byte page + 273-byte material row + 37-byte parent header + 66 bytes.
	want := bytes.Clone(planned)
	copy(want[451:483], identity.RequestIdentityDigest[:])
	if !bytes.Equal(want, actual) {
		t.Fatal("fill changed bytes outside request identity")
	}
	if !bytes.Equal(p.SupportPages[0].Records[1].Body[66:98], make([]byte, 32)) {
		t.Fatal("fill mutated borrowed plan")
	}
	if _, err := InspectRequiredSupportPage(actual); err != nil {
		t.Fatal(err)
	}
	rb, err := EncodeRoot(filled.Snapshot)
	if err != nil || contract.Hash(rb) != filled.Head.Root.Digest {
		t.Fatal("filled root reference", err)
	}
	hb, err := EncodeHeadCore(filled.Head)
	if err != nil || contract.Hash(hb) != filled.Conditional.HeadCore {
		t.Fatal("filled head reference", err)
	}
}

// full_only: false
func TestGeneratorInitialReservationOpaqueFragmentPhysicalOrder(t *testing.T) {
	p := initialReservationFixture(t)
	a := packedFragments(t, fid(70), 24)[0]
	b := packedFragments(t, fid(71), 24)[0]
	if bytes.Compare(a.RecordID[:], b.RecordID[:]) < 0 {
		a, b = b, a
	}
	page := RequiredSupportPage{Domain: p.Request.DomainID, Object: fid(72), Index: 3,
		Records: []contract.SupportRecord{a, b}}
	p.SupportPages = append(p.SupportPages, page)
	refreshInitialReservationFixture(t, &p)
	want, err := FillGeneratorInitialReservation(p)
	if err != nil {
		t.Fatalf("bodyful physical fragment order: %v", err)
	}
	p.OpaqueFragmentPages = make([]GeneratorInitialOpaqueFragmentPage, len(p.SupportPages))
	facts := make([]contract.SupportRecordDigest, len(page.Records))
	for i, row := range page.Records {
		facts[i], err = contract.InspectSupportRecordDigest(page.Domain, row)
		if err != nil {
			t.Fatal(err)
		}
	}
	p.OpaqueFragmentPages[2] = GeneratorInitialOpaqueFragmentPage{Ref: p.Snapshot.RequiredSupport[3], Rows: facts}
	p.SupportPages[2].Records = nil
	got, err := FillGeneratorInitialReservation(p)
	if err != nil || got.Identity != want.Identity || got.Head != want.Head || !reflect.DeepEqual(got.Snapshot, want.Snapshot) {
		t.Fatalf("opaque physical fragment order: %v", err)
	}
	if p.OpaqueFragmentPages[2].Rows[0].RecordID() != a.RecordID || p.OpaqueFragmentPages[2].Rows[1].RecordID() != b.RecordID {
		t.Fatal("opaque fact order changed")
	}
	for _, tc := range []struct {
		name string
		rows []contract.SupportRecordDigest
		ref  Ref
	}{
		{name: "swapped physical rows", rows: []contract.SupportRecordDigest{facts[1], facts[0]}, ref: p.Snapshot.RequiredSupport[3]},
		{name: "duplicate row", rows: []contract.SupportRecordDigest{facts[0], facts[0]}, ref: p.Snapshot.RequiredSupport[3]},
		{name: "wrong reference", rows: facts, ref: p.Snapshot.RequiredSupport[1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := p
			bad.OpaqueFragmentPages = append([]GeneratorInitialOpaqueFragmentPage(nil), p.OpaqueFragmentPages...)
			bad.OpaqueFragmentPages[2] = GeneratorInitialOpaqueFragmentPage{Ref: tc.ref, Rows: tc.rows}
			if _, err := FillGeneratorInitialReservation(bad); err == nil {
				t.Fatal("unbound opaque facts accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratorInitialReservationRejectsIndependentAssertions(t *testing.T) {
	for name, damage := range map[string]func(*GeneratorInitialReservationPlan){
		"parent identity": func(p *GeneratorInitialReservationPlan) { p.Parent.RequestIdentityDigest = fid(99) },
		"request binding": func(p *GeneratorInitialReservationPlan) { p.Request.DomainID = fid(99) },
		"graph":           func(p *GeneratorInitialReservationPlan) { p.Snapshot.Generated.ActiveGraph = fid(99) },
		"phase":           func(p *GeneratorInitialReservationPlan) { p.Snapshot.Generated.ActivePhase = fid(99) },
		"owner":           func(p *GeneratorInitialReservationPlan) { p.Snapshot.Generated.ActiveOwner = fid(99) },
		"snapshot":        func(p *GeneratorInitialReservationPlan) { p.Snapshot.Snapshot = fid(99) },
		"transition":      func(p *GeneratorInitialReservationPlan) { p.Snapshot.Transition = fid(99) },
		"revision":        func(p *GeneratorInitialReservationPlan) { p.Head.Revision = fid(99) },
		"predecessor":     func(p *GeneratorInitialReservationPlan) { p.Head.PreviousDigest = fid(99) },
		"head root hole":  func(p *GeneratorInitialReservationPlan) { p.Head.Root.Digest = fid(99) },
		"condition hole":  func(p *GeneratorInitialReservationPlan) { p.Conditional.HeadCore = fid(99) },
		"condition": func(p *GeneratorInitialReservationPlan) {
			p.Conditional.Condition = conditionFixture(contract.Token{Family: contract.AWS, Value: `"other"`})
		},
		"seed check":         func(p *GeneratorInitialReservationPlan) { p.Material.SeedCheck = fid(99) },
		"seed access":        func(p *GeneratorInitialReservationPlan) { p.AccessPages[0].Records[0].PackageCheck = fid(99) },
		"missing phase page": func(p *GeneratorInitialReservationPlan) { p.SupportPages = p.SupportPages[:1] },
		"missing seed page":  func(p *GeneratorInitialReservationPlan) { p.AccessPages = nil },
		"support reference":  func(p *GeneratorInitialReservationPlan) { p.Snapshot.RequiredSupport[0].Digest = fid(99) },
	} {
		t.Run(name, func(t *testing.T) {
			p := initialReservationFixture(t)
			damage(&p)
			if _, err := DeriveGeneratorInitialIdentity(p); err == nil {
				t.Fatal("changed assertion accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratorInitialReservationBindsExactSeedProtection(t *testing.T) {
	p := initialReservationFixture(t)
	before, err := DeriveGeneratorInitialIdentity(p)
	if err != nil {
		t.Fatal(err)
	}
	p.AccessPages[0].Records[0].Wraps[0].RSACiphertext[0] ^= 1
	refreshInitialReservationFixture(t, &p)
	after, err := DeriveGeneratorInitialIdentity(p)
	if err != nil || before.InitialAccess == after.InitialAccess || before.Plan == after.Plan || before.RequestIdentityDigest == after.RequestIdentityDigest {
		t.Fatal("seed protection omitted from request identity", err)
	}
}

// full_only: false
func TestGeneratorInitialReservationIdentityIncludesCreateDuty(t *testing.T) {
	p := initialReservationFixture(t)
	before, err := DeriveGeneratorInitialIdentity(p)
	if err != nil {
		t.Fatal(err)
	}
	phase, err := contract.DecodeGeneratedPhaseRecord(p.SupportPages[1].Records[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	// Complete owner/target resolution belongs to selected admission. The
	// identity projection must not force the initial create Duty to be absent.
	phase.Duties = contract.GeneratorDescriptor{Digest: fid(95), Count: 1, Length: 651}
	p.SupportPages[1].Records[0].Body, err = contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	refreshInitialReservationFixture(t, &p)
	after, err := DeriveGeneratorInitialIdentity(p)
	if err != nil || before.Plan == after.Plan || before.RequestIdentityDigest == after.RequestIdentityDigest {
		t.Fatal("initial create Duty excluded from identity", err)
	}
}

// full_only: false
func TestGeneratorInitialIdentityIndependentHashes(t *testing.T) {
	p := initialReservationFixture(t)
	got, err := DeriveGeneratorInitialIdentity(p)
	if err != nil {
		t.Fatal(err)
	}
	// Independently derived with Python big-endian writes and SHA-256 over
	// the fixed fixture component bytes. The empty output uses schema 5 and the
	// v5 configuration/slice commitment domains. The schema-11 plan contains the
	// administrative-index revision-5 reference. Its 247-byte group includes
	// the two-byte selected-evidence summary and two permission bytes.
	// The recorded derivation reproduces all six earlier and intermediate digests before
	// deriving canonical schema 11. The plan retains schema 2 and its 120-byte
	// zero canonical-selection anchor. Phase=716; initial support contains no
	// checkpoint image. RootPlan=2302,
	// HeadPlan=424, ConditionalPlan=158 bytes. The initial plan is
	// u16(1)||B(root)||B(head)||B(condition), 2898 bytes; its vector adds 8.
	// The request is D("request",B(requestCore)||graph||use||materialDigest||
	// initialAccessDescriptor||intendedEntryPlansDescriptor||B(initialPlan)).
	// The independent calculation also hashes the filled root and HEAD bytes.
	if got.Plan.Length != 2906 || got.Plan.Count != 1 || got.InitialAccess.Length != 599 || got.InitialAccess.Count != 1 {
		t.Fatal("initial projection lengths differ")
	}
	for name, check := range map[string]struct {
		got  ID
		want string
	}{
		"plan":     {got.Plan.Digest, "e5876a932c1746f093397e646ab48402ef3d36a85bca560930403ee3e04c50dd"},
		"access":   {got.InitialAccess.Digest, "0fe9fa5a873b11482cfa96f1ac8b941f1be43e49ead934d0604b9a7efc42299c"},
		"material": {got.MaterialDigest, "1d8c3bb0351aac1872508fb55828e7749ac7f4906078c48d912c1bc535ae6458"},
		"request":  {got.RequestIdentityDigest, "75b7ceaf3d0957c8687c9f618c479da27c28a5a2964f5849c5d6263b7ac742b9"},
	} {
		if check.got != successionLiteralID(t, check.want) {
			t.Errorf("independent %s digest differs", name)
		}
	}
	filled, err := FillGeneratorInitialReservation(p)
	if err != nil {
		t.Fatal(err)
	}
	if filled.Head.Root.Digest != successionLiteralID(t, "04b0d14ba84fb32d939ec8d783df43ca36ced000ddea254825c07a3ef300146d") ||
		filled.Conditional.HeadCore != successionLiteralID(t, "f2fbc78e340aba3c72bfc3ddbf42a8f8ed6f565576bcfbe93bf6e83fb2ecf1f1") {
		t.Fatal("filled dependent reference differs")
	}
}

// full_only: false
func TestGeneratorInitialReservationRejectsLaterPhaseState(t *testing.T) {
	for name, change := range map[string]func(*contract.GeneratedPhaseRecord){
		"phase number":         func(v *contract.GeneratedPhaseRecord) { v.Phase++ },
		"later branch":         func(v *contract.GeneratedPhaseRecord) { v.Branch, v.NoEffectUsed = 1, 1 },
		"wrong frontier owner": func(v *contract.GeneratedPhaseRecord) { v.OwnerID = fid(99) },
		"recorded result":      func(v *contract.GeneratedPhaseRecord) { v.AcceptedResultID, v.ResultDigest = fid(98), fid(99) },
		"nonempty proof": func(v *contract.GeneratedPhaseRecord) {
			v.Proofs = contract.GeneratorDescriptor{Digest: fid(99), Length: 4 + 4 + 43 + 1140 + 8, Count: 1}
		},
		"aggregate": func(v *contract.GeneratedPhaseRecord) {
			v.LineageIndex, v.FrontierAttemptID, v.Stage = contract.GeneratorMaxLineageTemplates, contract.ID{}, contract.GeneratedStageTerminal
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := initialReservationFixture(t)
			phase, err := contract.InspectGeneratedPhaseRecord(p.SupportPages[1].Records[0].Body)
			if err != nil {
				t.Fatal(err)
			}
			change(&phase)
			p.SupportPages[1].Records[0].Body, err = contract.EncodeGeneratedPhaseRecord(phase)
			if err != nil {
				t.Fatal("changed phase should remain structurally valid", err)
			}
			refreshInitialReservationFixture(t, &p)
			if _, err := DeriveGeneratorInitialIdentity(p); err == nil {
				t.Fatal("later state entered initial identity plan")
			}
		})
	}
}

// full_only: false
func TestGeneratorInitialReservationBindsNonzeroLineageIndex(t *testing.T) {
	p := initialReservationFixture(t)
	before, err := DeriveGeneratorInitialIdentity(p)
	if err != nil {
		t.Fatal(err)
	}
	phase, err := contract.InspectGeneratedPhaseRecord(p.SupportPages[1].Records[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	phase.LineageIndex = 1
	p.SupportPages[1].Records[0].Body, err = contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal(err)
	}
	refreshInitialReservationFixture(t, &p)
	after, err := DeriveGeneratorInitialIdentity(p)
	if err != nil || after.Plan == before.Plan || after.RequestIdentityDigest == before.RequestIdentityDigest {
		t.Fatal("initial format refused or omitted a nonzero graph-container index", err)
	}
}

// full_only: false
func TestGeneratorInitialReservationBindsEnabledRecoverySeedWrap(t *testing.T) {
	p := initialReservationFixture(t)
	signer := p.Snapshot.CurrentAccess.Core.NormalSigning
	signer.Role, signer.BindingID = contract.RecoverySigningRole, fid(91)
	signer.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000003"
	p.Snapshot.CurrentAccess.Core.Recovery = &contract.RecoveryBindings{RoleID: fid(90), Signing: signer, KMS: *recipientFixture(t).Slots[2].CurrentBinding}
	wrap := p.AccessPages[0].Records[0].Wraps[0]
	wrap.SubjectKind, wrap.SubjectID = 2, fid(90)
	wrap.RSACiphertext = bytes.Clone(wrap.RSACiphertext)
	p.AccessPages[0].Records[0].Wraps = append(p.AccessPages[0].Records[0].Wraps, wrap)
	refreshInitialReservationFixture(t, &p)
	before, err := DeriveGeneratorInitialIdentity(p)
	if err != nil {
		t.Fatal(err)
	}
	p.AccessPages[0].Records[0].Wraps[1].RSACiphertext[0] ^= 1
	refreshInitialReservationFixture(t, &p)
	after, err := DeriveGeneratorInitialIdentity(p)
	if err != nil || before.InitialAccess == after.InitialAccess || before.Plan == after.Plan || before.RequestIdentityDigest == after.RequestIdentityDigest {
		t.Fatal("recovery wrap omitted from identity", err)
	}
	p.AccessPages[0].Records[0].Wraps[1].SubjectID = fid(99)
	refreshInitialReservationFixture(t, &p)
	if _, err := DeriveGeneratorInitialIdentity(p); err == nil {
		t.Fatal("wrong recovery subject accepted")
	}
}
