package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func generatorGraphRequestFixture() GeneratorRequestCore {
	return GeneratorRequestCore{Schema: GeneratorRequestCoreSchema, OperationKind: 2, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
		PredecessorRevisionID: generatedRecordID(5),
		PredecessorHEADDigest: generatedRecordID(6), ConditionDigest: generatedRecordID(7), CallerNonce: generatedRecordID(8),
		Declaration: generatedRecordDescriptor(9), Registry: generatedRecordDescriptor(10),
		CompatibilityID: generatedRecordID(11), RecoveryPolicyID: generatedRecordID(12)}
}

// full_only: false
func TestGeneratorApplyRequestCommitsCompleteOutputImage(t *testing.T) {
	request := generatorGraphRequestFixture()
	request.Schema, request.OperationKind, request.RecoveryPolicyID = GeneratorApplyRequestCoreSchema, OperationApplyDeclaration, GeneratorRecoveryPolicyID()
	// Empty v5 image: schema, zero bindings/groups, five-byte routing body,
	// routing schema 3, zero default destinations and zero entry replacements.
	image := []byte{0, 5, 0, 0, 0, 0, 0, 0, 0, 5, 0, 3, 0, 0, 0}
	material := append([]byte("ENKV/OUTPUT/CONFIGURATION/v5\x00"), request.DomainID[:]...)
	material = binary.BigEndian.AppendUint32(material, 15)
	material = append(material, image...)
	request.OutputConfiguration = OutputConfigurationDescriptor{Schema: 5, ConfigurationDigest: ID(sha256.Sum256(material)), TotalLength: 15, SliceCount: 1, RoutingLength: 5}
	want := binary.BigEndian.AppendUint16(nil, 4)
	want = binary.BigEndian.AppendUint16(want, uint16(OperationApplyDeclaration))
	for _, id := range []ID{request.DomainID, request.OperationID, request.PredecessorRevisionID, request.PredecessorHEADDigest, request.ConditionDigest, request.CallerNonce} {
		want = append(want, id[:]...)
	}
	for _, descriptor := range []GeneratorDescriptor{request.Declaration, request.Registry} {
		want = append(want, descriptor.Digest[:]...)
		want = binary.BigEndian.AppendUint64(want, descriptor.Length)
		want = binary.BigEndian.AppendUint32(want, descriptor.Count)
	}
	want = append(want, request.CompatibilityID[:]...)
	want = append(want, request.RecoveryPolicyID[:]...)
	want = binary.BigEndian.AppendUint16(want, 5)
	want = append(want, request.OutputConfiguration.ConfigurationDigest[:]...)
	want = binary.BigEndian.AppendUint32(want, 15)
	want = binary.BigEndian.AppendUint16(want, 1)
	want = binary.BigEndian.AppendUint16(want, 0)
	want = binary.BigEndian.AppendUint32(want, 5)
	body, err := EncodeGeneratorRequestCore(request)
	if err != nil || len(body) != 394 || !bytes.Equal(body, want) {
		t.Fatal("apply request lost exact descriptor framing", err)
	}
	parsed, err := InspectGeneratorRequestCore(body)
	if err != nil || parsed != request {
		t.Fatal("apply request lost committed output fields", err)
	}
	material = binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/request-core\x00"), 394)
	material = append(material, want...)
	digest, err := GeneratorRequestCoreDigest(request)
	if err != nil || digest != ID(sha256.Sum256(material)) {
		t.Fatal("request digest used the wrong version length", err)
	}
	graph := GeneratorPlanBundle{Request: request}
	configuration, err := InspectGeneratedOutputConfiguration(graph, image)
	if err != nil || configuration.Schema != 5 || len(configuration.Bindings)+len(configuration.Groups)+len(configuration.Routes) != 0 {
		t.Fatal("real empty desired image refused", err)
	}
	for _, fault := range []string{"missing", "later-byte", "domain", "length", "binding-count", "routing-length"} {
		t.Run(fault, func(t *testing.T) {
			q, offered := request, bytes.Clone(image)
			switch fault {
			case "missing":
				offered = nil
			case "later-byte":
				offered[len(offered)-1] = 1
			case "domain":
				q.DomainID = generatedRecordID(203)
			case "length":
				q.OutputConfiguration.TotalLength++
			case "binding-count":
				q.OutputConfiguration.BindingCount++
			case "routing-length":
				q.OutputConfiguration.RoutingLength++
			}
			if _, err := InspectGeneratedOutputConfiguration(GeneratorPlanBundle{Request: q}, offered); err == nil {
				t.Fatal("damaged committed output accepted")
			}
		})
	}
	for _, schema := range []uint16{GeneratorRequestCoreSchema, GeneratorPublicRequestCoreSchema} {
		legacy := request
		legacy.Schema = schema
		if _, err := EncodeGeneratorRequestCore(legacy); err == nil {
			t.Fatal("old request silently dropped offered output fields")
		}
		legacy.OutputConfiguration = OutputConfigurationDescriptor{}
		if body, err := EncodeGeneratorRequestCore(legacy); err != nil || len(body) != 348 {
			t.Fatal("old request meaning or length changed", err)
		}
	}
	invalid := request
	invalid.OperationKind = OperationCleanOwnedFailureResidue
	if _, err := EncodeGeneratorRequestCore(invalid); err == nil {
		t.Fatal("non-apply operation acquired desired output meaning")
	}
	logical := GeneratorLogicalSlice{Schema: 1, ContentKind: 8, ContentID: request.OperationID, Length: 15, Digest: Hash(image)}
	if _, err := EncodeGeneratorLogicalSlice(logical); err != nil {
		t.Fatal("output content kind refused", err)
	}
	logical.ContentKind = 9
	if _, err := EncodeGeneratorLogicalSlice(logical); err == nil {
		t.Fatal("unknown generated content kind accepted")
	}
}

func generatorGraphResultUseFixture() GeneratorResultUse {
	return GeneratorResultUse{Schema: 1, AttemptID: generatedRecordID(1), ResultID: generatedRecordID(2), InboxID: generatedRecordID(3),
		ExecutorID: generatedRecordID(4), ResultContractID: generatedRecordID(5), PlannedValueSlotID: generatedRecordID(6),
		MaterialID: generatedRecordID(7), Purpose: 1, MaxSecret: 65536, MaxFacts: 4096}
}

func generatorGraphSourceUseFixture() GeneratorSourceUse {
	return GeneratorSourceUse{Schema: 1, SourceID: generatedRecordID(1), SealedInputCoreDigest: generatedRecordID(2),
		EnvelopeDigest: generatedRecordID(3), SourceSlice: generatedRecordDescriptor(4), Consumers: generatedRecordDescriptor(5), Purpose: 2}
}

// full_only: false
func TestGeneratorGraphIndependentRowHashes(t *testing.T) {
	// Independent Python struct concatenation plus SHA256. IDs are the fixture's
	// repeated byte, and each descriptor is ID||uint64be(4)||uint32be(0).
	// Request:00020002, IDs1/2/5..8, descriptors9/10, IDs11/12.
	// Result use:0001, IDs1..7, 01, uint32be(65536), uint32be(4096).
	// Source use:0001, IDs1..3, descriptors4/5, 02.
	for _, tc := range []struct {
		name, digest string
		length       int
		encode       func() ([]byte, error)
		inspect      func([]byte) error
	}{
		{"request", "a5cb67244a59fd965a11f929d1357622e94ce1137824ce4175acc3c119115dd9", 348,
			func() ([]byte, error) { return EncodeGeneratorRequestCore(generatorGraphRequestFixture()) }, func(b []byte) error { _, err := InspectGeneratorRequestCore(b); return err }},
		{"result use", "e0b0467b0dd6f494146f318ea4de4a0e31a34b63290fb5c9b957ec3fab7817ec", 235,
			func() ([]byte, error) { return EncodeGeneratorResultUse(generatorGraphResultUseFixture()) }, func(b []byte) error { _, err := InspectGeneratorResultUse(b); return err }},
		{"source use", "42498bd7841df31384d1288ce332869d9013cfb1e16ff283df2273ad92a32196", 187,
			func() ([]byte, error) { return EncodeGeneratorSourceUse(generatorGraphSourceUseFixture()) }, func(b []byte) error { _, err := InspectGeneratorSourceUse(b); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := tc.encode()
			if err != nil || len(wire) != tc.length {
				t.Fatal("fixed row", len(wire), err)
			}
			digest := sha256.Sum256(wire)
			if hex.EncodeToString(digest[:]) != tc.digest {
				t.Fatal("independent field order")
			}
			if err := tc.inspect(wire); err != nil {
				t.Fatal(err)
			}
			for i := range wire {
				if err := tc.inspect(wire[:i]); err == nil {
					t.Fatalf("truncation %d", i)
				}
			}
			if err := tc.inspect(append(bytes.Clone(wire), 0)); err == nil {
				t.Fatal("trailing byte")
			}
			bad := bytes.Clone(wire)
			bad[1] = 0
			if err := tc.inspect(bad); !errors.Is(err, ErrRecord) {
				t.Fatal("schema", err)
			}
		})
	}
	request, err := GeneratorRequestCoreDigest(generatorGraphRequestFixture())
	if err != nil || hex.EncodeToString(request[:]) != "d040333ce511d711be2fe0547e102bc7a14bca2ec6eadd8362a5a84290ea7281" {
		t.Fatal("independent request-core identity", err)
	}
}

// full_only: false
func TestGeneratorGraphEmptyTypedDescriptorHashes(t *testing.T) {
	// D(label,uint32be(0)); no zero digest stands for an empty typed vector.
	for _, tc := range []struct {
		name, want string
		describe   func() (GeneratorDescriptor, error)
	}{
		{"member plans", "9585ecf5690036a920c1366c9c81dd0b7875daf5ccdb667312cc5b852d8d6566", func() (GeneratorDescriptor, error) { return GeneratorValueEntryPlansDescriptor(nil) }},
		{"lineages", "f338f6c1551d83c1627ed2aa1735b6e2f4ff98e9ff8acbd260f8edb55f7b4508", func() (GeneratorDescriptor, error) { return GeneratorLineageTemplatesDescriptor(nil) }},
		{"edges", "5ee218c027a6d18f9b4ebdc7c29e4a0b6e73a13abd232ac05a5007ab86c69453", func() (GeneratorDescriptor, error) { return GeneratorTransitionRulesDescriptor(nil) }},
		{"result uses", "5e0db0dcd6a37efbb35755f21915b09d809937b8908eb989208ea4a38195ddc6", func() (GeneratorDescriptor, error) { return GeneratorResultUsesDescriptor(nil) }},
		{"source uses", "f61ee14eaadd5ebda3f390acc185ca0301f11a811fae92bd26f2bd03364130e6", func() (GeneratorDescriptor, error) { return GeneratorSourceUsesDescriptor(nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.describe()
			if err != nil || got.Count != 0 || got.Length != 4 || hex.EncodeToString(got.Digest[:]) != tc.want {
				t.Fatal("empty descriptor", got, err)
			}
		})
	}
}

func generatorGraphCreateFixture(t testing.TB, name string) GeneratorLineageTemplate {
	return generatorGraphCreateIntentFixture(t, name, generatedRecordID(4))
}

func generatorGraphCreateIntentFixture(t testing.TB, name string, intent ID) GeneratorLineageTemplate {
	t.Helper()
	must := func(id ID, err error) ID {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	v := GeneratorLineageTemplate{Schema: GeneratorLineageTemplateSchema, Purpose: 1, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
		Name: name, EntryIncarnationID: generatedRecordID(3), IntentDigest: intent, TemplateCount: 5}
	v.LineageID = must(GeneratorLineageID(v.DomainID, v.OperationID, v.Name, v.EntryIncarnationID, v.Epoch, v.IntentDigest))
	for i := range v.Templates {
		x := GeneratorAttemptTemplate{Schema: GeneratorAttemptTemplateSchema, LifecycleMode: GeneratorLifecycleManaged, ResultReaderID: GeneratorResultReaderID(), Branch: uint8(i), Action: 1, LineageID: v.LineageID, DescriptorID: generatedRecordID(5),
			ConfigContractID: generatedRecordID(6), ExecutorID: generatedRecordID(7), CredentialRouteID: generatedRecordID(8),
			ResourceContractID: generatedRecordID(9), ResultContractID: generatedRecordID(10), IntentDigest: v.IntentDigest,
			TargetKind: 1, TargetSourceID: v.IntentDigest, CompletionClass: 1, RequiredAuthoritySet: 1}
		x.AttemptID = must(GeneratorAttemptID(v.LineageID, x.Branch))
		if i != 0 {
			previous := uint8(0)
			if i > 2 {
				previous = uint8(i - 2)
			}
			x.PredecessorAttemptID = must(GeneratorAttemptID(v.LineageID, previous))
		}
		x.ResourceIncarnationID = must(GeneratorResourceID(v.DomainID, v.OperationID, x.AttemptID))
		x.PlannedValueSlotID = must(GeneratorValueSlotID(v.DomainID, v.OperationID, x.AttemptID))
		x.DutyID = must(GeneratorDutyID(v.DomainID, v.OperationID, x.AttemptID, 1))
		x.HazardID = must(GeneratorHazardID(v.DomainID, x.AttemptID))
		x.TransmissionID = must(GeneratorTransmissionID(x.AttemptID, 1))
		x.ResultID = must(GeneratorResultID(v.DomainID, v.OperationID, x.AttemptID, x.TransmissionID, 1))
		x.InboxID = must(GeneratorInboxID(v.DomainID, v.OperationID, x.AttemptID, x.ResultID))
		x.RequestPlanDigest = must(GeneratorRequestPlanDigest(x))
		if i == 0 || i == 2 {
			x.NoEffectBudget = 1
		}
		if i == 0 || i == 1 {
			x.ResidueBudget = 1
		}
		v.Templates[i] = x
	}
	return v
}

func generatorGraphEntryPlanFixture(lineage GeneratorLineageTemplate, slot uint16) GeneratorValueEntryPlan {
	return GeneratorValueEntryPlan{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorValueEntryPlanSchema, LifecycleMode: GeneratorLifecycleManaged, Slot: slot, Name: lineage.Name, ValueSource: Generated, ConfidentialityClass: Secret,
		EntryIncarnationID: lineage.EntryIncarnationID, Epoch: lineage.Epoch, IntentDigest: lineage.IntentDigest,
		PlannedValueSlotID: lineage.Templates[0].PlannedValueSlotID, IntendedMembership: GeneratorDescriptor{Digest: generatedRecordID(12), Length: 40, Count: 1},
		LineageID: lineage.LineageID, RetirementMode: 1, ChangeMask: 1}
}

func generatorGraphHeaderFixture(t testing.TB, entryCount, creates, templates uint16) GeneratorGraphHeader {
	t.Helper()
	request := generatorGraphRequestFixture()
	material, err := GeneratorMaterialID(request.DomainID, request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := GeneratorRequestCoreDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return GeneratorGraphHeader{Schema: GeneratorGraphHeaderSchema, DomainID: request.DomainID, OperationID: request.OperationID, MaterialID: material,
		RequestCoreDigest: digest, RecoveryPolicyID: request.RecoveryPolicyID, ValueEntryPlanCount: entryCount, LineageCount: creates, TemplateCount: templates}
}

func generatorGraphEdgesFixture(t testing.TB, header GeneratorGraphHeader, lineages []GeneratorLineageTemplate) []GeneratorEdge {
	t.Helper()
	join, err := GeneratorCompleteJoinID(header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	var edges []GeneratorEdge
	for _, lineage := range lineages {
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			source, err := GeneratorTemplateID(x)
			if err != nil {
				t.Fatal(err)
			}
			for guard := uint8(1); guard <= 4; guard++ {
				branch, destination := x.Branch, join
				if guard < 3 {
					if x.Action != 1 {
						continue
					}
					next, present, err := GeneratorSuccessorBranch(x.Branch, guard)
					if err != nil {
						t.Fatal(err)
					}
					if !present {
						continue
					}
					branch = next
					destination, err = GeneratorTemplateID(lineage.Templates[next])
					if err != nil {
						t.Fatal(err)
					}
				}
				noEffect, residue := uint8(0), uint8(0)
				if branch == 1 || branch == 3 || branch == 4 {
					noEffect = 1
				}
				if branch >= 2 {
					residue = 1
				}
				edges = append(edges, GeneratorEdge{Schema: 1, SourceTemplateID: source, DestinationTemplateID: destination, Guard: guard, ResultSlotID: x.ResultID,
					RequiredAuthoritySet: x.RequiredAuthoritySet, NoEffectUsed: noEffect, ResidueUsed: residue})
			}
		}
	}
	slices.SortFunc(edges, generatorEdgeCompare)
	return edges
}

func generatorGraphUsesFixture(header GeneratorGraphHeader, lineages []GeneratorLineageTemplate) []GeneratorResultUse {
	var uses []GeneratorResultUse
	for _, lineage := range lineages {
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			maxSecret := uint32(80)
			if x.Action == 2 {
				maxSecret = 0
			}
			uses = append(uses, GeneratorResultUse{Schema: 1, AttemptID: x.AttemptID, ResultID: x.ResultID, InboxID: x.InboxID, ExecutorID: x.ExecutorID,
				ResultContractID: x.ResultContractID, PlannedValueSlotID: x.PlannedValueSlotID, MaterialID: header.MaterialID, Purpose: 1, MaxSecret: maxSecret, MaxFacts: 4096})
		}
	}
	slices.SortFunc(uses, func(a, b GeneratorResultUse) int {
		if c := bytes.Compare(a.AttemptID[:], b.AttemptID[:]); c != 0 {
			return c
		}
		return bytes.Compare(a.ResultID[:], b.ResultID[:])
	})
	return uses
}

// full_only: false
func TestGeneratorGraphIndependentCompleteConstruction(t *testing.T) {
	lineage := generatorGraphCreateFixture(t, "g")
	entryPlan := generatorGraphEntryPlanFixture(lineage, 0)
	header := generatorGraphHeaderFixture(t, 1, 1, 5)
	lineages := []GeneratorLineageTemplate{lineage}
	entryPlans := []GeneratorValueEntryPlan{entryPlan}
	edges := generatorGraphEdgesFixture(t, header, lineages)
	// Independent Python struct/hashlib derivation, without production imports:
	// domain=01*32, operation=02*32, entry=03*32, intent=04*32, name="g",
	// epoch0, descriptor/config/executor/route/resource/contract=05..0a*32,
	// create resource digest zero, lifecycleManaged2, class/authority1, fixed
	// v3 result reader. Derive five exact Attempt identities by
	// the documented D(label,B(body)) rule. Encode schema3 container with
	// purpose1, zero resource, count5 and B(template) rows. ValueEntry slot0 uses
	// ValueSource2, ConfidentialityClass2, initial value slot, zero source
	// descriptor, membership descriptor(0c*32,40,1), retirement/change1/lifecycle2.
	// Templates are682 bytes. Edges are the four branch
	// edges plus two complete-join edges per template, sorted by source/guard.
	// Header uses the independent request-core digest above and counts1/1/5.
	for _, tc := range []struct {
		name, want string
		encode     func() ([]byte, error)
	}{
		{"member", "a8fb142f770396069eab549eab3875588818a712878cf9aa3ee92b1c4e9d5366", func() ([]byte, error) { return EncodeGeneratorValueEntryPlan(entryPlan) }},
		{"lineage", "5c1725f6a94bbb84b80ccf1735934a94c354993d25c00f0ce92e56fb8a2ca0d6", func() ([]byte, error) { return EncodeGeneratorLineageTemplate(lineage) }},
		{"header", "7e436abc96a6f64d6555a53c5bcaba0b32aa57af66db805f01bdd43ca2902a6c", func() ([]byte, error) { return EncodeGeneratorGraphHeader(header) }},
	} {
		wire, err := tc.encode()
		if err != nil {
			t.Fatal(tc.name, err)
		}
		digest := sha256.Sum256(wire)
		if hex.EncodeToString(digest[:]) != tc.want {
			t.Fatal(tc.name, "independent hash")
		}
	}
	graph, err := GeneratorGraphID(header, entryPlans, lineages, edges)
	if err != nil || hex.EncodeToString(graph[:]) != "08435603e559b84e3f06fc6b7fe916133db9495b503d8376696aa0a6d77ca2b1" {
		t.Fatal("complete graph identity", err)
	}
	if err := ValidateGeneratorGraphRequest(generatorGraphRequestFixture(), header); err != nil {
		t.Fatal(err)
	}
	uses := generatorGraphUsesFixture(header, lineages)
	if err := ValidateGeneratorResultUses(header, lineages, uses); err != nil {
		t.Fatal(err)
	}
	resultDesc, err := GeneratorResultUsesDescriptor(uses)
	if err != nil {
		t.Fatal(err)
	}
	sourceDesc, err := GeneratorSourceUsesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	use := GeneratorUsePlanCore{DomainID: header.DomainID, OperationID: header.OperationID, MaterialID: header.MaterialID, PlanGraphID: graph,
		ResultUses: resultDesc, SourceUses: sourceDesc, ValueDerivationID: GeneratorValueDerivationID()}
	useDigest, err := GeneratorUsePlanDigest(use)
	if err != nil || hex.EncodeToString(useDigest[:]) != "e3c035c4ab4bfcdf2ed9225ae7e260ba254e8c1f7e8d6f3de80d28e702fea4dc" {
		t.Fatal("independent use plan", err)
	}
	wire, err := EncodeGeneratorUsePlanCore(use)
	if err != nil || len(wire) != 248 {
		t.Fatal("use plan width", err)
	}
	if got, err := InspectGeneratorUsePlanCore(wire); err != nil || got != use {
		t.Fatal("use plan round trip", err)
	}
}

// full_only: false
func TestGeneratorGraphRefusesMissingEdgesAndChangedBranches(t *testing.T) {
	lineage := generatorGraphCreateFixture(t, "g")
	header := generatorGraphHeaderFixture(t, 1, 1, 5)
	entryPlans := []GeneratorValueEntryPlan{generatorGraphEntryPlanFixture(lineage, 0)}
	lineages := []GeneratorLineageTemplate{lineage}
	edges := generatorGraphEdgesFixture(t, header, lineages)
	for i := range edges {
		omitted := append(slices.Clone(edges[:i]), edges[i+1:]...)
		if _, err := GeneratorGraphID(header, entryPlans, lineages, omitted); err == nil {
			t.Fatal("missing branch or join edge", i)
		}
	}
	for _, mutate := range []func(*GeneratorEdge){
		func(v *GeneratorEdge) { v.DestinationTemplateID = generatedRecordID(99) }, func(v *GeneratorEdge) { v.ResultSlotID = generatedRecordID(99) },
		func(v *GeneratorEdge) { v.NoEffectUsed ^= 1 }, func(v *GeneratorEdge) { v.RequiredAuthoritySet = 3 },
	} {
		bad := slices.Clone(edges)
		mutate(&bad[0])
		slices.SortFunc(bad, generatorEdgeCompare)
		if _, err := GeneratorGraphID(header, entryPlans, lineages, bad); err == nil {
			t.Fatal("changed edge accepted")
		}
	}
	for _, mutate := range []func(*GeneratorLineageTemplate){
		func(v *GeneratorLineageTemplate) { v.Templates[4].NoEffectBudget = 1 }, func(v *GeneratorLineageTemplate) { v.Templates[2].ResultID = generatedRecordID(99) },
		func(v *GeneratorLineageTemplate) { v.Templates[1].DutyID = generatedRecordID(99) }, func(v *GeneratorLineageTemplate) { v.Templates[1].ResourceIncarnationID = generatedRecordID(99) },
		func(v *GeneratorLineageTemplate) { v.Templates[1].ExecutorID = generatedRecordID(99) }, func(v *GeneratorLineageTemplate) { v.Templates[1], v.Templates[2] = v.Templates[2], v.Templates[1] },
	} {
		bad := lineage
		mutate(&bad)
		if _, err := EncodeGeneratorLineageTemplate(bad); err == nil {
			t.Fatal("changed template accepted")
		}
	}
	badEntryPlans := slices.Clone(entryPlans)
	badEntryPlans[0].PlannedValueSlotID = lineage.Templates[1].PlannedValueSlotID
	if _, err := GeneratorGraphID(header, badEntryPlans, lineages, edges); err == nil {
		t.Fatal("member initial slot changed")
	}
	badHeader := header
	badHeader.RequestCoreDigest = generatedRecordID(99)
	if err := ValidateGeneratorGraphRequest(generatorGraphRequestFixture(), badHeader); !errors.Is(err, ErrRecord) {
		t.Fatal("request/graph mismatch", err)
	}
}

// full_only: false
func TestGeneratorGraphMemberVariantsAndNameBounds(t *testing.T) {
	v := generatorGraphEntryPlanFixture(generatorGraphCreateFixture(t, "g"), 0)
	v.ValueSource, v.ConfidentialityClass, v.Epoch, v.IntentDigest, v.PlannedValueSlotID, v.LineageID, v.RetirementMode = Supplied, Plain, 0, ID{}, ID{}, ID{}, 0
	v.LifecycleMode = 0
	v.SourceSlice = generatedRecordDescriptor(1)
	for _, name := range []string{"", strings.Repeat("n", 256)} {
		v.Name = name
		wire, err := EncodeGeneratorValueEntryPlan(v)
		if err != nil || len(wire) != 238+len(name) {
			t.Fatal("member name bound", err)
		}
		view, err := InspectGeneratorValueEntryPlan(wire)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := view.Own()
		if err != nil || owned != v {
			t.Fatal("member ownership", err)
		}
		if len(name) > 0 {
			wire[8] = 'x'
			if view.Name[0] != 'x' || owned.Name[0] != 'n' {
				t.Fatal("borrowed member name")
			}
		}
	}
	v.Name = strings.Repeat("n", 257)
	if _, err := EncodeGeneratorValueEntryPlan(v); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("oversized name", err)
	}
	v.Name = ""
	v.SourceSlice = GeneratorDescriptor{}
	if _, err := EncodeGeneratorValueEntryPlan(v); !errors.Is(err, ErrRecord) {
		t.Fatal("missing supplied source", err)
	}
	v = generatorGraphEntryPlanFixture(generatorGraphCreateFixture(t, "g"), 0)
	v.ChangeMask = 2
	v.LineageID, v.PlannedValueSlotID = ID{}, ID{}
	v.SourceSlice = generatedRecordDescriptor(1)
	if _, err := EncodeGeneratorValueEntryPlan(v); err != nil {
		t.Fatal("unchanged generated source", err)
	}
	v.ChangeMask = 8
	if _, err := EncodeGeneratorValueEntryPlan(v); !errors.Is(err, ErrRecord) {
		t.Fatal("unknown change mask", err)
	}
}

// full_only: false
func TestGeneratorGraphTypedVectorOrderingAndCounts(t *testing.T) {
	entryPlan := generatorGraphEntryPlanFixture(generatorGraphCreateFixture(t, "g"), 0)
	if _, err := GeneratorValueEntryPlansDescriptor([]GeneratorValueEntryPlan{entryPlan, entryPlan}); !errors.Is(err, ErrRecord) {
		t.Fatal("duplicate member", err)
	}
	lineage := generatorGraphCreateFixture(t, "g")
	if _, err := GeneratorLineageTemplatesDescriptor([]GeneratorLineageTemplate{lineage, lineage}); !errors.Is(err, ErrRecord) {
		t.Fatal("duplicate lineage", err)
	}
	use := generatorGraphResultUseFixture()
	if _, err := GeneratorResultUsesDescriptor([]GeneratorResultUse{use, use}); !errors.Is(err, ErrRecord) {
		t.Fatal("duplicate result use", err)
	}
	source := generatorGraphSourceUseFixture()
	if _, err := GeneratorSourceUsesDescriptor([]GeneratorSourceUse{source, source}); !errors.Is(err, ErrRecord) {
		t.Fatal("duplicate source use", err)
	}
	if _, err := GeneratorResultUsesDescriptor(make([]GeneratorResultUse, 1409)); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("result-use count", err)
	}
	if _, err := GeneratorSourceUsesDescriptor(make([]GeneratorSourceUse, 513)); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("source-use count", err)
	}
	if _, err := GeneratorLineageTemplatesDescriptor(make([]GeneratorLineageTemplate, 897)); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("lineage count", err)
	}
	rows := make([]GeneratorValueEntryPlan, 512)
	for i := range rows {
		rows[i] = GeneratorValueEntryPlan{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorValueEntryPlanSchema, Slot: uint16(i), Name: fmt.Sprintf("%03d", i), ValueSource: Supplied, ConfidentialityClass: Plain,
			EntryIncarnationID: generatedRecordID(1), SourceSlice: generatedRecordDescriptor(2), IntendedMembership: generatedRecordDescriptor(3)}
	}
	if _, err := GeneratorValueEntryPlansDescriptor(rows); err != nil {
		t.Fatal("512 members refused", err)
	}
	rows = append(rows, rows[0])
	if _, err := GeneratorValueEntryPlansDescriptor(rows); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("member-count boundary", err)
	}
}

func generatorGraphDeleteFixture(t *testing.T, create GeneratorLineageTemplate, branch uint8, purpose uint8, resource ID) GeneratorLineageTemplate {
	t.Helper()
	must := func(id ID, err error) ID {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	producer := create.Templates[branch]
	v := GeneratorLineageTemplate{Schema: GeneratorLineageTemplateSchema, Purpose: GeneratorLineagePurpose(purpose), DomainID: create.DomainID, OperationID: create.OperationID, Name: create.Name,
		EntryIncarnationID: create.EntryIncarnationID, Epoch: create.Epoch, IntentDigest: create.IntentDigest, ResourceIncarnationID: resource, TemplateCount: 1}
	v.LineageID = must(GeneratorObligationLineageID(v.DomainID, v.OperationID, resource, GeneratorLineagePurpose(purpose)))
	x := GeneratorAttemptTemplate{Schema: GeneratorAttemptTemplateSchema, LifecycleMode: GeneratorLifecycleManaged, ResultReaderID: GeneratorResultReaderID(), Action: 2, LineageID: v.LineageID, ResourceIncarnationID: resource,
		DutyID: producer.DutyID, DescriptorID: producer.DescriptorID, ConfigContractID: producer.ConfigContractID, ExecutorID: producer.ExecutorID,
		CredentialRouteID: producer.CredentialRouteID, ResourceContractID: producer.ResourceContractID, ResultContractID: generatedRecordID(21),
		IntentDigest: v.IntentDigest, ResourceDigest: producer.ResourceDigest, TargetKind: 3, TargetSourceID: producer.ResultID, CompletionClass: producer.CompletionClass,
		RequiredAuthoritySet: producer.RequiredAuthoritySet}
	if purpose == 2 {
		x.ResourceDigest = generatedRecordID(11)
		x.TargetKind = 2
		x.TargetSourceID = resource
	}
	x.AttemptID = must(GeneratorAttemptID(v.LineageID, 0))
	x.PlannedValueSlotID = must(GeneratorValueSlotID(v.DomainID, v.OperationID, x.AttemptID))
	x.HazardID = must(GeneratorHazardID(v.DomainID, x.AttemptID))
	x.TransmissionID = must(GeneratorTransmissionID(x.AttemptID, 2))
	x.ResultID = must(GeneratorResultID(v.DomainID, v.OperationID, x.AttemptID, x.TransmissionID, 2))
	x.InboxID = must(GeneratorInboxID(v.DomainID, v.OperationID, x.AttemptID, x.ResultID))
	x.RequestPlanDigest = must(GeneratorRequestPlanDigest(x))
	v.Templates[0] = x
	return v
}

// full_only: false
func TestGeneratorGraphDeletePreservesOriginalResourceAndDuty(t *testing.T) {
	create := generatorGraphCreateFixture(t, "g")
	cleanup := generatorGraphDeleteFixture(t, create, 0, 3, create.Templates[0].ResourceIncarnationID)
	header := generatorGraphHeaderFixture(t, 1, 1, 6)
	entryPlans := []GeneratorValueEntryPlan{generatorGraphEntryPlanFixture(create, 0)}
	lineages := []GeneratorLineageTemplate{create, cleanup}
	edges := generatorGraphEdgesFixture(t, header, lineages)
	if _, err := GeneratorGraphID(header, entryPlans, lineages, edges); err != nil {
		t.Fatal("original result-slot cleanup", err)
	}
	if cleanup.Templates[0].DutyID != create.Templates[0].DutyID || cleanup.Templates[0].ResourceIncarnationID != create.Templates[0].ResourceIncarnationID ||
		cleanup.Templates[0].AttemptID == create.Templates[0].AttemptID {
		t.Fatal("fresh delete and original target")
	}
	for _, tc := range []struct {
		name   string
		change func(*GeneratorAttemptTemplate)
	}{
		{"duty", func(v *GeneratorAttemptTemplate) { v.DutyID = generatedRecordID(90) }},
		{"target-source", func(v *GeneratorAttemptTemplate) { v.TargetSourceID = generatedRecordID(91) }},
		{"completion", func(v *GeneratorAttemptTemplate) { v.CompletionClass = 2 }},
		{"resource-contract", func(v *GeneratorAttemptTemplate) { v.ResourceContractID = generatedRecordID(92) }},
		{"descriptor", func(v *GeneratorAttemptTemplate) { v.DescriptorID = generatedRecordID(93) }},
		{"config-contract", func(v *GeneratorAttemptTemplate) { v.ConfigContractID = generatedRecordID(94) }},
		{"executor", func(v *GeneratorAttemptTemplate) { v.ExecutorID = generatedRecordID(95) }},
		{"credential-route", func(v *GeneratorAttemptTemplate) { v.CredentialRouteID = generatedRecordID(96) }},
		{"intent", func(v *GeneratorAttemptTemplate) { v.IntentDigest = generatedRecordID(97) }},
		{"resource-digest", func(v *GeneratorAttemptTemplate) { v.ResourceDigest = generatedRecordID(98) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := cleanup
			tc.change(&bad.Templates[0])
			bad.IntentDigest = bad.Templates[0].IntentDigest
			request, err := GeneratorRequestPlanDigest(bad.Templates[0])
			if err != nil {
				t.Fatal(err)
			}
			bad.Templates[0].RequestPlanDigest = request
			if _, err := EncodeGeneratorLineageTemplate(bad); err != nil {
				t.Fatal("mutation must reach graph validation", err)
			}
			badLineages := []GeneratorLineageTemplate{create, bad}
			badEdges := generatorGraphEdgesFixture(t, header, badLineages)
			if _, err := GeneratorGraphID(header, entryPlans, badLineages, badEdges); !errors.Is(err, ErrRecord) {
				t.Fatal("cross-target conflict accepted", err)
			}
		})
	}
	uses := generatorGraphUsesFixture(header, lineages)
	if err := ValidateGeneratorResultUses(header, lineages, uses); err != nil {
		t.Fatal(err)
	}
	for i := range uses {
		if uses[i].AttemptID == cleanup.Templates[0].AttemptID {
			uses[i].MaxSecret = 80
		}
	}
	if err := ValidateGeneratorResultUses(header, lineages, uses); !errors.Is(err, ErrRecord) {
		t.Fatal("delete secret use admitted", err)
	}
	cleanup.Templates[1] = cleanup.Templates[0]
	if _, err := EncodeGeneratorLineageTemplate(cleanup); !errors.Is(err, ErrRecord) {
		t.Fatal("inactive delete template bytes", err)
	}
}

// full_only: false
func TestGeneratorGraphAdmitsStandaloneCleanupOnlyForExternalSelectedResult(t *testing.T) {
	create := generatorGraphCreateFixture(t, "g")
	cleanup := generatorGraphDeleteFixture(t, create, 0, 3, create.Templates[0].ResourceIncarnationID)
	header := generatorGraphHeaderFixture(t, 0, 0, 1)
	lineages := []GeneratorLineageTemplate{cleanup}
	edges := generatorGraphEdgesFixture(t, header, lineages)
	if _, err := GeneratorGraphID(header, nil, lineages, edges); err != nil {
		t.Fatal("standalone selected-result cleanup", err)
	}
	bad := cleanup
	bad.Purpose = 2
	if _, err := GeneratorGraphID(header, nil, []GeneratorLineageTemplate{bad}, edges); !errors.Is(err, ErrRecord) {
		t.Fatal("retirement mislabeled as external-result cleanup", err)
	}
}

// full_only: false
func TestGeneratorGraphLineageFramingAndMaximumNames(t *testing.T) {
	for _, name := range []string{"", strings.Repeat("x", 256)} {
		lineage := generatorGraphCreateFixture(t, name)
		wire, err := EncodeGeneratorLineageTemplate(lineage)
		if err != nil || len(wire) != 208+len(name)+5*686 {
			t.Fatal("lineage width", len(wire), err)
		}
		view, err := InspectGeneratorLineageTemplate(wire)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := view.Own()
		if err != nil || owned != lineage {
			t.Fatal("lineage round trip", err)
		}
		for i := range wire {
			if _, err := InspectGeneratorLineageTemplate(wire[:i]); err == nil {
				t.Fatalf("lineage truncation %d", i)
			}
		}
		if len(name) > 0 {
			wire[103] = 'y'
			if view.Name[0] != 'y' || owned.Name[0] != 'x' {
				t.Fatal("lineage name ownership")
			}
		}
		retirement := generatorGraphDeleteFixture(t, lineage, 0, 2, generatedRecordID(90))
		body, err := EncodeGeneratorLineageTemplate(retirement)
		if err != nil || len(body) > 1150 {
			t.Fatal("delete container charge", len(body), err)
		}
	}
}

// full_only: false
func TestGeneratorGraphFullReplacementCountBoundary(t *testing.T) {
	header := generatorGraphHeaderFixture(t, 512, 128, 1408)
	entryPlans := make([]GeneratorValueEntryPlan, 512)
	lineages := make([]GeneratorLineageTemplate, 0, 896)
	for i := 0; i < 128; i++ {
		create := generatorGraphCreateFixture(t, fmt.Sprintf("%03d", i))
		entryPlans[i] = generatorGraphEntryPlanFixture(create, uint16(i))
		lineages = append(lineages, create)
		lineages = append(lineages, generatorGraphDeleteFixture(t, create, 0, 2, generatedRecordID(byte(i+1))))
		for branch := uint8(0); branch < 5; branch++ {
			lineages = append(lineages, generatorGraphDeleteFixture(t, create, branch, 3, create.Templates[branch].ResourceIncarnationID))
		}
	}
	for i := 128; i < 512; i++ {
		entryPlans[i] = GeneratorValueEntryPlan{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorValueEntryPlanSchema, Slot: uint16(i), Name: fmt.Sprintf("%03d", i), ValueSource: Supplied, ConfidentialityClass: Plain,
			EntryIncarnationID: generatedRecordID(1), SourceSlice: generatedRecordDescriptor(2), IntendedMembership: generatedRecordDescriptor(3)}
	}
	slices.SortFunc(lineages, generatorLineageCompare)
	edges := generatorGraphEdgesFixture(t, header, lineages)
	if len(lineages) != 896 || len(edges) != 3328 {
		t.Fatal("fixed maximum construction count", len(lineages), len(edges))
	}
	if _, err := GeneratorGraphID(header, entryPlans, lineages, edges); err != nil {
		t.Fatal("full replacement graph", err)
	}
	uses := generatorGraphUsesFixture(header, lineages)
	if len(uses) != 1408 {
		t.Fatal("result-use count")
	}
	if err := ValidateGeneratorResultUses(header, lineages, uses); err != nil {
		t.Fatal("full replacement uses", err)
	}
	bad := header
	bad.TemplateCount++
	if _, err := GeneratorGraphID(bad, entryPlans, lineages, edges); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("next template boundary", err)
	}
	bad = header
	bad.LineageCount++
	if _, err := GeneratorGraphID(bad, entryPlans, lineages, edges); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("next create-lineage boundary", err)
	}
}

// full_only: false
func TestGeneratorGraphUsePlanRejectsWrongRecipeOrUses(t *testing.T) {
	lineage := generatorGraphCreateFixture(t, "g")
	header := generatorGraphHeaderFixture(t, 1, 1, 5)
	lineages := []GeneratorLineageTemplate{lineage}
	uses := generatorGraphUsesFixture(header, lineages)
	for _, mutate := range []func(*GeneratorResultUse){
		func(v *GeneratorResultUse) { v.InboxID = generatedRecordID(99) }, func(v *GeneratorResultUse) { v.ExecutorID = generatedRecordID(99) },
		func(v *GeneratorResultUse) { v.MaterialID = generatedRecordID(99) }, func(v *GeneratorResultUse) { v.MaxSecret = 0 },
	} {
		bad := slices.Clone(uses)
		mutate(&bad[0])
		if err := ValidateGeneratorResultUses(header, lineages, bad); !errors.Is(err, ErrRecord) {
			t.Fatal("wrong result use", err)
		}
	}
	if err := ValidateGeneratorResultUses(header, lineages, uses[:4]); !errors.Is(err, ErrRecord) {
		t.Fatal("missing latent result use", err)
	}
	results, err := GeneratorResultUsesDescriptor(uses)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := GeneratorSourceUsesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	v := GeneratorUsePlanCore{DomainID: header.DomainID, OperationID: header.OperationID, MaterialID: header.MaterialID, PlanGraphID: generatedRecordID(20), ResultUses: results, SourceUses: sources, ValueDerivationID: GeneratorValueDerivationID()}
	for _, mutate := range []func(*GeneratorUsePlanCore){
		func(v *GeneratorUsePlanCore) { v.ValueDerivationID = generatedRecordID(21) }, func(v *GeneratorUsePlanCore) { v.MaterialID = generatedRecordID(22) },
		func(v *GeneratorUsePlanCore) { v.ResultUses.Length++ }, func(v *GeneratorUsePlanCore) { v.SourceUses.Digest = generatedRecordID(23) },
	} {
		bad := v
		mutate(&bad)
		if _, err := EncodeGeneratorUsePlanCore(bad); !errors.Is(err, ErrRecord) {
			t.Fatal("invalid use-plan contract", err)
		}
	}
}

// Keep the accepted public operation bytes independent of the implementation
// constants; holes must be refused by both the encoder and stored reader.
// full_only: false
func TestGeneratorRequestOperationSetIsClosed(t *testing.T) {
	accepted := map[uint16]bool{2: true, 12: true, 31: true, 38: true, 39: true}
	base, err := EncodeGeneratorRequestCore(generatorGraphRequestFixture())
	if err != nil {
		t.Fatal(err)
	}
	for operation := uint16(0); operation <= 40; operation++ {
		value := generatorGraphRequestFixture()
		value.OperationKind = operation
		_, encodeErr := EncodeGeneratorRequestCore(value)
		wire := bytes.Clone(base)
		binary.BigEndian.PutUint16(wire[2:4], operation)
		_, decodeErr := InspectGeneratorRequestCore(wire)
		if (encodeErr == nil) != accepted[operation] || (decodeErr == nil) != accepted[operation] {
			t.Fatalf("operation %d: encoder %v, reader %v, accepted %t", operation, encodeErr, decodeErr, accepted[operation])
		}
	}
}
