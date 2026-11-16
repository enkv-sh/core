package core

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type gcActualJointSeed struct {
	env     fixtureEnvironment
	current *StateSession
	windows contract.MutationReceiptWindows
	bodies  map[contract.ID][]byte
	marker  contract.ID
}

// The receipt prefix is produced once by 1024 real CAS operations. The two
// generated origins and joint configuration then use the existing signed-image
// fixture assembly; this does not claim a single ordinary writer produced the
// assembled multi-origin image.
func gcActualJointMaximumSeed(t *testing.T) gcActualJointSeed {
	t.Helper()
	env, run, f, keys, enrolled := successionMemoryRegistryFixture(t, true)
	env.Context = t.Context()
	run.suppliedSelection(f, []ApplyEntryInput{{Name: "actual-receipt-plain-seed", ValueSource: contract.Supplied,
		ConfidentialityClass: contract.Plain, Recipients: []contract.ID{enrolled[0]}, InputBytes: []byte{0}}})
	store := env.Store.(*memoryStore)
	// scenarioRun counts the real supplied selection through its wrapper;
	// the actual receipt producer requires the same selected state on its
	// original file-backed physical Store, not the counting wrapper.
	opened, result := Open(t.Context(), f.admission, store)
	if opened == nil || result.Outcome != ObservedCurrent || !bytes.Equal(opened.body, f.session.body) {
		t.Fatal("actual receipt prefix cold open on original physical Store", result)
	}
	beforeCAS := store.cas
	selected, windows, bodies := actualFullReceiptWindows(t, env, opened)
	if store.cas-beforeCAS != 1024 || selected.root.WarningBits != 0x19 {
		t.Fatal("joint prefix did not use the actual receipt producer", store.cas-beforeCAS)
	}
	// Restore scenarioRun's counting Store before the shared ordinary producer.
	// Its assertions must observe the real creates/CAS, rather than bypassing
	// the counter wrapper after the physical-only receipt prefix.
	rebound, observed := Open(t.Context(), OpenContext{admission: &selected.admission}, run.env.Store)
	if rebound == nil || observed.Outcome != ObservedCurrent || !bytes.Equal(rebound.body, selected.body) || rebound.token != selected.token {
		t.Fatal("actual receipt prefix did not reopen through its ordinary producer Store", observed)
	}
	f.session, f.admission = rebound, OpenContext{admission: &rebound.admission}
	// The ordinary supplied fixture path currently preserves receipt history.
	// Do not substitute a new signed seed or infer a new receipt from its HEAD.
	retainActual := func(t *testing.T, _ fixtureEnvironment, current *environmentFixture) {
		assertFullReceiptHistoryBytes(t, current.session, windows, bodies)
		if current.session.root.WarningBits != 0x19 {
			t.Fatal("joint supplied transition cleared actual permanent receipt-prefix warnings")
		}
	}
	env, f, _ = configuredSuccessionMemoryFixtureFrom(t, true, env, run, f, keys, enrolled, retainActual)
	assertFullReceiptHistoryBytes(t, f.session, windows, bodies)
	if f.session.root.WarningBits != 0x19 {
		t.Fatal("joint configured assembly cleared actual permanent receipt-prefix warnings")
	}
	rows, orders, marker := publicationJointConfiguredMarkers(t, f.session, true)
	if len(rows) != 1024+2048 || len(orders) != 1024 {
		t.Fatal("joint marker producer did not reach its configured maxima", len(rows), len(orders))
	}
	env, selected = publicationJointSelectedImage(t, env, f.session, f.session, rows, orders, 0, 0, "GC actual joint maximum")
	assertFullReceiptHistoryBytes(t, selected, windows, bodies)
	if selected.root.WarningBits != 0x19 {
		t.Fatal("joint marker assembly cleared actual permanent receipt-prefix warnings")
	}
	gcAssertJointMaximum(t, selected)
	return gcActualJointSeed{env: env, current: selected, windows: windows, bodies: bodies, marker: marker}
}

func gcAssertJointMaximum(t *testing.T, s *StateSession) {
	t.Helper()
	r := s.root
	if r.ValueEntryCount != 512 || r.SecretCount != 512 || r.Generated.GeneratedCurrent != 128 || r.RawBytes != 8<<20 ||
		r.RecipientCount != 256 || r.MembershipCount != 4096 || r.SecretOrdinaryWrapCount != 4096 ||
		r.Generated.SuccessWindow.Count != 256 || r.Generated.FailureWindow.Count != 256 {
		t.Fatal("GC source does not reach every joint value/recipient/receipt maximum", r.ValueEntryCount,
			r.Generated.GeneratedCurrent, r.RawBytes, r.RecipientCount, r.MembershipCount)
	}
	configuration := capacityOutputConfiguration(t, s, true)
	relation, err := selectedPublicationRelation(s.selectedImage())
	if err != nil || len(configuration.Bindings) != 64 || len(relation.coordinates) != 1024 || len(relation.markers) != 2048 {
		t.Fatal("GC source does not reach joint output/publication maxima", len(configuration.Bindings), len(relation.coordinates), len(relation.markers), err)
	}
	// Exact current encoded children are the union of physical Ref identities.
	// This sum uses no capacity calculation or generated group-width helper.
	refs := make(map[format.Ref]bool)
	add := func(ref format.Ref) {
		if ref.Object.IsZero() || refs[ref] {
			t.Fatal("joint child identity is absent or counted twice", ref.Kind, ref.Index)
		}
		refs[ref] = true
	}
	for _, ref := range r.ValueEntryPages {
		if ref != nil {
			add(*ref)
		}
	}
	for _, ref := range r.Recipients {
		if ref != nil {
			add(*ref)
		}
	}
	for _, ref := range r.CurrentAccess.Core.AccessPageRefs {
		add(ref)
	}
	for _, ref := range r.RequiredSupport {
		add(ref)
	}
	add(r.AdministrativeIndex)
	for _, ref := range r.AdministrativeIndexShards {
		add(ref)
	}
	var encoded uint64
	for ref := range refs {
		encoded += uint64(ref.Length)
	}
	if uint32(len(refs)) != r.ChildCount || encoded != r.ChildEncodedBytes {
		t.Fatal("joint physical child count/bytes differ from independently summed Ref union", len(refs), encoded, r.ChildCount, r.ChildEncodedBytes)
	}
	t.Logf("actual joint source entries=512 generated=128 raw=8388608 recipients=256 memberships=4096 outputs=64 coordinates=1024 markers=2048 receipts=256/256 children=%d child_bytes=%d", len(refs), encoded)
}

func gcJointStoredLength(value stored) uint64 {
	if value.bodyPath != "" {
		return value.bodyLength
	}
	return uint64(len(value.Body))
}

// Choose actual obsolete physical pages already present in the completed
// producer Store. Prefer large pages so useful reclamation accounts for the
// entire new GC immutable population rather than just counting deletions.
func gcJointObsoletePageKeys(t *testing.T, seed gcActualJointSeed) []string {
	t.Helper()
	s := seed.current
	g, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal("joint selected generated proof", err)
	}
	marks, err := gcMarkSelected(g.image, g, s.admission.store)
	if err != nil {
		t.Fatal("joint complete protected-object relation", err)
	}
	store := seed.env.Store.(*memoryStore)
	var keys []string
	for key := range store.objects {
		object, err := contract.ParseStoreObjectKey(store.desc.Prefix, s.root.Domain, key)
		if err != nil || object.Namespace != contract.StorePageObject {
			continue
		}
		_, protected := marks.objects[object]
		_, pending := marks.pending[object]
		if !protected && !pending {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(a, b string) int {
		if c := cmp.Compare(gcJointStoredLength(store.objects[b]), gcJointStoredLength(store.objects[a])); c != 0 {
			return c
		}
		return bytes.Compare([]byte(a), []byte(b))
	})
	if len(keys) < 256 {
		t.Fatal("actual joint producer left fewer than 256 obsolete physical pages", len(keys))
	}
	keys = slices.Clone(keys[:256])
	slices.Sort(keys)
	var size uint64
	for _, key := range keys {
		size += gcJointStoredLength(store.objects[key])
	}
	t.Logf("actual obsolete target page population count=256 encoded_bytes=%d source_objects=%d", size, len(store.objects))
	return keys
}

func gcJointBranchLabel(name string, order int) string {
	return fmt.Sprintf("GC actual joint %s order %d", name, order)
}
