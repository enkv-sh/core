package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// Expectations name physical keys directly from the fixture's selected refs.
// No marker, allocation-ID inventory or generated grouping derives this set.
func gcExpectedSelectedKeys(s *StateSession) []string {
	base := fmt.Sprintf("%s/%x/", s.admission.store.Prefix, s.root.Domain)
	want := []string{s.admission.store.HeadKey, fmt.Sprintf("%sroot/0/%x", base, s.root.Snapshot), fmt.Sprintf("%sconfiguration/%x", base, s.head.Core.Store)}
	add := func(name string, ref format.Ref) {
		want = append(want, fmt.Sprintf("%s%s/%d/%x", base, name, ref.Index, ref.Object))
	}
	for _, ref := range s.root.ValueEntryPages {
		if ref != nil {
			add("member", *ref)
		}
	}
	for _, ref := range s.root.Recipients {
		if ref != nil {
			add("recipient", *ref)
		}
	}
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		add("access", ref)
	}
	add("admin-index", s.root.AdministrativeIndex)
	for _, ref := range s.root.AdministrativeIndexShards {
		add("admin-index", ref)
	}
	for _, ref := range s.root.RequiredSupport {
		add("support", ref)
	}
	return want
}

func gcActualMarkKeys(t testing.TB, s *StateSession, marks gcMarkSet) []string {
	t.Helper()
	keys := []string{s.admission.store.HeadKey}
	for object := range marks.objects {
		keys = append(keys, gcObjectTestKey(t, s.admission.store, s.root.Domain, object))
	}
	slices.Sort(keys)
	return keys
}

func gcCheckMarkKeys(t testing.TB, s *StateSession, marks gcMarkSet, want []string) {
	t.Helper()
	slices.Sort(want)
	want = slices.Compact(want)
	if got := gcActualMarkKeys(t, s, marks); !reflect.DeepEqual(got, want) {
		t.Fatalf("physical mark differs\ngot %v\nwant %v", got, want)
	}
}

// full_only: false
func TestGCMarkingProtectsCompleteSelectedPhysicalClosure(t *testing.T) {
	s, plan := gcStateFixture(t, true)
	g := mustSelectedGeneratedWork(t, s)
	marks, err := gcMarkSelected(g.image, g, s.admission.store)
	if err != nil {
		t.Fatal(err)
	}
	gcCheckMarkKeys(t, s, marks, gcExpectedSelectedKeys(s))
	if len(marks.pending) != 1 {
		t.Fatal("pending vector lost exact exclusion", len(marks.pending))
	}
	if _, pending := marks.pending[plan.Targets[0].Object]; !pending {
		t.Fatal("selected pending target became freshly admissible")
	}
	if _, live := marks.objects[plan.Targets[0].Object]; live {
		t.Fatal("pending target became a live-data pin")
	}
	image := *g.image
	image.support = slices.Clone(g.image.support)
	for i, page := range image.support {
		for _, row := range page.Records {
			if row.Kind == contract.GCPlanSupportKind {
				image.support[i].Records = nil
			}
		}
	}
	copyGenerated := *g
	copyGenerated.image = &image
	if _, err := gcMarkSelected(&image, &copyGenerated, s.admission.store); err == nil {
		t.Fatal("missing optional target payload admitted a complete view")
	}
}

// full_only: false
func TestGCMarkingRetainsAbsentResultBranchesAndReleases(t *testing.T) {
	t.Run("active graph", func(t *testing.T) {
		s := generatedReservationState(t)
		g := mustSelectedGeneratedWork(t, s)
		marks, err := gcMarkSelected(g.image, g, s.admission.store)
		if err != nil {
			t.Fatal(err)
		}
		want := gcExpectedSelectedKeys(s)
		future := 0
		for _, lineage := range g.bundles[0].Lineages {
			for _, template := range lineage.Templates[:lineage.TemplateCount] {
				want = append(want, fmt.Sprintf("%s/%x/result/%x", s.admission.store.Prefix, s.root.Domain, template.InboxID))
				future++
			}
		}
		if future != 10 {
			t.Fatal("fixture no longer covers five create and five cleanup branches", future)
		}
		gcCheckMarkKeys(t, s, marks, want)
	})
	for _, action := range []uint8{1, 2} {
		for branch := uint8(0); branch < 5; branch++ {
			t.Run(fmt.Sprintf("release/action%d/branch%d", action, branch), func(t *testing.T) {
				s, _, release := generatedInboxReleaseTemplateState(t, action, branch, contract.GeneratedReleasePending)
				g := mustSelectedGeneratedWork(t, s)
				marks, err := gcMarkSelected(g.image, g, s.admission.store)
				if err != nil {
					t.Fatal(err)
				}
				want := append(gcExpectedSelectedKeys(s), fmt.Sprintf("%s/%x/result/%x", s.admission.store.Prefix, s.root.Domain, release.InboxID))
				gcCheckMarkKeys(t, s, marks, want)
			})
		}
	}
	t.Run("multiple original delete replies", func(t *testing.T) {
		s, g, _ := generatedRepeatedRetirementHazardState(t, 2)
		marks, err := gcMarkSelected(g.image, g, s.admission.store)
		if err != nil {
			t.Fatal(err)
		}
		want := gcExpectedSelectedKeys(s)
		if len(g.attempts) < 2 {
			t.Fatal("fixture has no independent original replies")
		}
		for _, a := range g.attempts {
			want = append(want, fmt.Sprintf("%s/%x/result/%x", s.admission.store.Prefix, s.root.Domain, a.record.InboxID))
		}
		for _, r := range g.releases {
			want = append(want, fmt.Sprintf("%s/%x/result/%x", s.admission.store.Prefix, s.root.Domain, r.release.InboxID))
		}
		gcCheckMarkKeys(t, s, marks, want)
	})
}

// full_only: false
func TestGCMarkingKeepsWholeSharedPageAfterOneOwnerEnds(t *testing.T) {
	s, first, second, shared := gcTestSharedSpentState(t)
	s.admission.endWorkInvocation = gcTestID("mark-shared-ending")
	ids := endWorkIDs{operation: gcTestID("mark/end/op"), transition: gcTestID("mark/end/transition"), snapshot: gcTestID("mark/end/snapshot"), revision: gcTestID("mark/end/revision"), receipts: gcTestID("mark/end/receipts"), receiptIndex: gcTestID("mark/end/index")}
	candidate, _, err := s.deriveEndWorkCandidate(t.Context(), second.OperationID, ids)
	if err != nil {
		t.Fatal(err)
	}
	candidate, result := s.persistCandidate(t.Context(), candidate, testtrust.New(t, s.admission.store.Family, s.admission.trust))
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("persist exact ending", result)
	}
	s, result = s.selectCandidate(t.Context(), candidate)
	if s == nil || result.Outcome != ObservedCurrent {
		t.Fatal("select exact ending", result)
	}
	// Exact ending admits an administrative image without optional plan
	// payloads. Complete marking first authenticates those surviving bytes.
	s, result = Open(t.Context(), OpenContext{admission: &s.admission}, s.store)
	if s == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold complete read after exact ending", result)
	}
	g := mustSelectedGeneratedWork(t, s)
	marks, err := gcMarkSelected(g.image, g, s.admission.store)
	if err != nil {
		t.Fatal(err)
	}
	gcCheckMarkKeys(t, s, marks, gcExpectedSelectedKeys(s))
	if _, live := marks.objects[gcPageIdentity(shared)]; !live {
		t.Fatal("dead physical row caused shared page reclamation")
	}
	if _, pending := marks.pending[first.Targets[0].Object]; !pending {
		t.Fatal("surviving pending target lost exclusion")
	}
	if _, pending := marks.pending[second.Targets[0].Object]; pending {
		t.Fatal("ended owner retained local continuation rights")
	}
}

// full_only: false
func TestGCMarkingProtectsSparsePublicationPeers(t *testing.T) {
	s, _, _, shared, bodies := publicationWholePageOwnerFixture(t, true, true)
	key := fmt.Sprintf("%s/%x/support/%d/%x", s.admission.store.Prefix, s.root.Domain, shared.Index, shared.Object)
	physical, err := format.InspectRequiredSupportPage(bodies[key])
	if err != nil || len(physical.Records) != 7 {
		t.Fatal("fixture lost four dead physical rows around three selected peers", err)
	}
	// The exit fixture supplies an administrative view. Re-read its exact
	// stored pages through the complete public owners before asking for a
	// complete mark; the sparse selected spans remain unchanged.
	reader := selectedObjectReader{domain: s.root.Domain, descriptor: s.admission.store, source: s.store}
	image, result := readCompleteSelectedImage(t.Context(), reader, s.root, false)
	if result.Outcome != 0 {
		t.Fatal("complete sparse publication image", result)
	}
	position := slices.IndexFunc(image.adminIndex.Pages, func(page format.AdministrativePage) bool { return page.Ref == shared })
	if position < 0 || len(image.adminIndex.Pages[position].Spans) != 3 || len(image.support[position].Records) != 3 {
		t.Fatal("complete read replaced the sparse selected peer page")
	}
	for i, span := range image.adminIndex.Pages[position].Spans {
		if span.First != uint16(2*i+1) || span.Count != 1 {
			t.Fatal("complete read changed sparse physical ordinals", i, span)
		}
	}
	if _, err := selectedReceiptWindowsWithReader(t.Context(), &image, reader); err != nil {
		t.Fatal("complete sparse publication receipts", err)
	}
	materials, ok := indexSelectedMaterialFacts(image.root, &image.pages, &image.access, image.support)
	if !ok {
		t.Fatal("complete sparse publication materials")
	}
	readFragment := func(ctx context.Context, location format.FragmentLocation, consume func([]byte) error) (Result, error) {
		return withSelectedFragmentFromImage(ctx, &image, reader, location, consume)
	}
	validated, err := selectedGeneratedWorkFromImageWithReader(t.Context(), &image, materials, nil, readFragment)
	if err != nil {
		t.Fatal("complete sparse publication generated facts", err)
	}
	g := validated.facts
	if g.parent == nil || g.parent.OperationID != generatedVectorID(10) || g.phase == nil || g.phase.Phase != 1 || g.phase.LineageIndex != 0 ||
		g.phase.Branch != contract.GeneratorBranchInitial || g.phase.NoEffectUsed != 0 || g.phase.ResidueUsed != 0 ||
		g.phase.Stage != contract.GeneratedStageRetainedResult || !g.phase.SelectionPhaseID.IsZero() || g.preparation != nil || len(g.attempts) != 1 || len(g.releases) != 0 {
		t.Fatal("sparse fixture no longer retains the initial generated permissions")
	}
	// The initial generation has five adoptable create reply coordinates.
	// The marker also conservatively protects its five embedded cleanup
	// coordinates while the graph is active; this grants no cleanup admission.
	// Both sets were derived independently from fixed fixture inputs with
	// Python hashlib/struct, not marker traversal.
	// The intent-v3 commitment includes the complete typed intent.
	inboxes := [5][2]string{
		{"3f9eb9e881e97df30c7add727ac20a6b0d54b5e857df9241e418c1ef9c804168", "4c0541786b24b978c549e2e244693250139c948f9495f4772438e54f435b3479"},
		{"6c7d4a17ed81ea259fdbb7f61bb87959f20783bc1ecdbc52ecd6f7cf228677e4", "fc46a869b50d12d3478ead7cbfab2235b58b3d3d5abfe87bcdede5bb09fcad18"},
		{"a05db10e32bc074d926196ef77db6168042a70ad5cf8a206aa35a1fc79834385", "d6313afd8bb755f02934a8e2ac20b83e7bb7a838c1523c77d393a1c7963edce6"},
		{"af4ed3708c37a401471f5e60571c90a2b5fceae9a17e902420bd85d3d2ee61ce", "b66c05a373ce90d463c61904f03136fd64adc56c787f8fe19148b7ffeb0cae7c"},
		{"c5a3a7a7dd32c3f39d5748915333c3c6cfe3fbb2c92dfea92303423cf21a2f25", "658ff65436b1e441f3189c50f46fe0e017a8124bdd6a0fc397c44dbb19491928"},
	}
	want := gcExpectedSelectedKeys(s)
	for _, pair := range inboxes {
		for _, inbox := range pair {
			want = append(want, fmt.Sprintf("%s/%x/result/%s", s.admission.store.Prefix, s.root.Domain, inbox))
		}
	}
	marks, err := gcMarkSelected(g.image, g, s.admission.store)
	if err != nil {
		t.Fatal(err)
	}
	gcCheckMarkKeys(t, s, marks, want)
	// The physical page has unselected marker rows between the selected
	// coordinate, output configuration and retained canonical rows.
	fact, present := marks.objects[gcPageIdentity(shared)]
	if !present || fact.length != uint32(len(bodies[key])) || fact.digest != contract.Hash(bodies[key]) || fact.length != shared.Length {
		t.Fatal("sparse selected peers lost the complete physical page", fact)
	}
}

// full_only: false
func TestGCMarkingUsesAdvancedResidueFrontierAndOriginalReplies(t *testing.T) {
	s := generatedReservationState(t)
	s = generatedRetainedClosureResidue(t, s, 230)
	s.generatedWork = nil
	g := mustSelectedGeneratedWork(t, s)
	if g.phase == nil || g.phase.Branch != contract.GeneratorBranchResidue || len(g.bundles) != 1 {
		t.Fatal("fixture did not select the planned residue successor")
	}
	create := g.bundles[0].Lineages[0]
	if create.Purpose != contract.GeneratorLineageCreate || create.TemplateCount != 5 || g.phase.FrontierAttemptID != create.Templates[2].AttemptID {
		t.Fatal("fixture lost its explicit residue branch")
	}
	if _, entered := g.attempts[create.Templates[0].AttemptID]; !entered {
		t.Fatal("original entered attempt disappeared")
	}
	if _, entered := g.attempts[create.Templates[2].AttemptID]; entered {
		t.Fatal("planned residue successor was already entered")
	}
	marks, err := gcMarkSelected(g.image, g, s.admission.store)
	if err != nil {
		t.Fatal(err)
	}
	want := gcExpectedSelectedKeys(s)
	// Residue consumes its one residue allowance. The original entered reply
	// stays adoptable; branches 2 and 4 remain reachable. Siblings 1 and 3
	// cannot be entered. These explicit branch sets do not use graph traversal.
	for _, branch := range []int{0, 2, 4} {
		want = append(want, fmt.Sprintf("%s/%x/result/%x", s.admission.store.Prefix, s.root.Domain, create.Templates[branch].InboxID))
	}
	cleanup := 0
	for _, lineage := range g.bundles[0].Lineages {
		if lineage.Purpose != contract.GeneratorLineageCleanup {
			continue
		}
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			if template.TargetSourceID == create.Templates[0].ResultID || template.TargetSourceID == create.Templates[2].ResultID || template.TargetSourceID == create.Templates[4].ResultID {
				want = append(want, fmt.Sprintf("%s/%x/result/%x", s.admission.store.Prefix, s.root.Domain, template.InboxID))
				cleanup++
			}
		}
	}
	if cleanup != 3 {
		t.Fatal("fixture lost matching cleanup coordinates", cleanup)
	}
	gcCheckMarkKeys(t, s, marks, want)
	for _, branch := range []int{2, 4} {
		key := fmt.Sprintf("%s/%x/result/%x", s.admission.store.Prefix, s.root.Domain, create.Templates[branch].InboxID)
		if result := s.store.Read(t.Context(), key, uint32(contract.GeneratedResultRecordMaxLength)); result.Status != contract.ReadMissing {
			t.Fatal("future protected reply was already stored", branch, result.Status)
		}
	}
}

// full_only: false
func TestGCMarkCommitmentUsesIndependentPhysicalFacts(t *testing.T) {
	store := gcCursorTestStore()
	configuration := contract.StoreObjectIdentity{Namespace: contract.StoreConfigurationObject, ObjectID: contract.ID{2}}
	recipient := contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RecipientKind, ObjectID: contract.ID{6}}
	marks := gcMarkSet{objects: map[contract.StoreObjectIdentity]gcMarkFact{configuration: {object: configuration}, recipient: {object: recipient, length: 20, digest: contract.ID{7}}}}
	got, err := marks.digest(store, contract.ID{1}, contract.ID{9})
	// Python struct/hashlib: fixed Store digest, domain, B(HEAD key), HEAD
	// digest, count2 and sorted B(key)/BE length/digest physical facts.
	want, e := hex.DecodeString("f6cdd9b41876149e0868bb2c4459a05b05c72e9ae3cb1ec2abf5b1dc21d3d385")
	if err != nil || e != nil || !bytes.Equal(got[:], want) {
		t.Fatal("independent mark commitment differs", err, e, got)
	}
}

// full_only: false
func TestGCMarkingLocalCreateProtectsOnlyAdmittedInbox(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	profile := defaultGeneratedFixtureProfile()
	profile.LifecycleMode = contract.GeneratorLifecycleNone
	profile.ResourceContractID, profile.DeleteResultContractID = contract.ID{}, contract.ID{}
	profile.CompletionClass, profile.RetirementMode = 0, 0
	input := generatedReservationInputForProfile(t, base, generatedVectorID(10), []string{"local"}, profile)
	reservation, err := base.deriveGeneratedReservation(t.Context(), input)
	if err != nil {
		t.Fatal("local reservation", err)
	}
	s := reservation.state
	g := mustSelectedGeneratedWork(t, s)
	if len(g.bundles) != 1 || len(g.bundles[0].Lineages) != 1 || g.bundles[0].Lineages[0].TemplateCount != 1 {
		t.Fatal("local graph is not a single CREATE template")
	}
	inbox := g.bundles[0].Lineages[0].Templates[0].InboxID
	marks, err := gcMarkSelected(g.image, g, s.admission.store)
	if err != nil {
		t.Fatal("valid local reservation blocked GC marking", err)
	}
	want := append(gcExpectedSelectedKeys(s), fmt.Sprintf("%s/%x/result/%x", s.admission.store.Prefix, s.root.Domain, inbox))
	gcCheckMarkKeys(t, s, marks, want)
	if fact := marks.objects[contract.StoreObjectIdentity{Namespace: contract.StoreResultObject, ObjectID: inbox}]; fact.length != 0 || !fact.digest.IsZero() {
		t.Fatal("absent adoptable inbox acquired stored bytes", fact)
	}
}

// full_only: false
func TestGCMarkingMixedGraphProtectsFutureLocalCreateInbox(t *testing.T) {
	s := generatedReservationState(t)
	g := mustSelectedGeneratedWork(t, s)
	graph := g.bundles[0]
	profile := defaultGeneratedFixtureProfile()
	profile.LifecycleMode = contract.GeneratorLifecycleNone
	profile.ResourceContractID, profile.DeleteResultContractID = contract.ID{}, contract.ID{}
	profile.CompletionClass, profile.RetirementMode = 0, 0
	local, _, _ := generatedEffectPlanForGenerationProfile(t, &graph.Request, s.admission.recipient, []string{"future-local"}, []byte(`{}`), profile)
	if len(local.Lineages) != 1 || local.Lineages[0].TemplateCount != 1 {
		t.Fatal("future local fixture has managed branches")
	}
	if _, err := contract.EncodeGeneratorLineageTemplate(local.Lineages[0]); err != nil {
		t.Fatal("future local lineage is not admitted", err)
	}
	graph.Lineages = append(slices.Clone(graph.Lineages), local.Lineages[0])
	mixed := *g
	mixed.bundles = []contract.GeneratorPlanBundle{graph}
	marks := gcMarkSet{objects: make(map[contract.StoreObjectIdentity]gcMarkFact)}
	if err := gcMarkActiveGraph(&marks, &mixed); err != nil {
		t.Fatal("future lifecycle-none lineage blocked active marking", err)
	}
	var want []contract.ID
	// The managed initial frontier has five CREATE and five cleanup inboxes;
	// the future local lineage has exactly its initial CREATE inbox.
	for _, lineage := range g.bundles[0].Lineages {
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			want = append(want, template.InboxID)
		}
	}
	want = append(want, local.Lineages[0].Templates[0].InboxID)
	if len(want) != 11 || len(marks.objects) != len(want) {
		t.Fatal("wrong exact mixed inbox set", len(marks.objects), len(want))
	}
	for _, inbox := range want {
		if _, ok := marks.objects[contract.StoreObjectIdentity{Namespace: contract.StoreResultObject, ObjectID: inbox}]; !ok {
			t.Fatal("admitted inbox not protected", inbox)
		}
	}
}

// full_only: false
func TestGCProtectsActiveRetirementAmbiguityBeforeItExists(t *testing.T) {
	active, attempt, duty, _ := generatedEnteredRetirementState(t, false)
	coord, err := contract.GeneratorRetirementAmbiguityID(attempt.record.InboxID)
	if err != nil {
		t.Fatal(err)
	}
	identity := contract.StoreObjectIdentity{Namespace: contract.StoreResultObject, ObjectID: coord}
	key := gcObjectTestKey(t, active.admission.store, active.root.Domain, identity)
	if r := active.store.Read(t.Context(), key, contract.StoreObjectLimit(identity)); r.Status != contract.ReadMissing {
		t.Fatal("fixture contains retirement evidence", r.Status)
	}
	g := mustSelectedGeneratedWork(t, active)
	marks, err := gcMarkSelected(g.image, g, active.admission.store)
	fact, ok := marks.objects[identity]
	if err != nil || !ok || fact.length != 0 || !fact.digest.IsZero() {
		t.Fatal("missing protection for independent retirement evidence", ok, err)
	}
	if g.phase.FrontierAttemptID != attempt.record.AttemptID || attempt.record.OwnerID != duty.DutyID {
		t.Fatal("wrong active retirement fixture")
	}
}
