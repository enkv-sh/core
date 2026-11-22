package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type gcMarkFact struct {
	object contract.StoreObjectIdentity
	length uint32
	digest contract.ID
}

// These owned facts are provisional until the complete public admission returns.
// Pending targets exclude new admission; they are not live-data pins.
type gcMarkSet struct {
	objects map[contract.StoreObjectIdentity]gcMarkFact
	pending map[contract.StoreObjectIdentity]struct{}
}

func (m *gcMarkSet) add(object contract.StoreObjectIdentity, length uint32, digest contract.ID) error {
	if m == nil || m.objects == nil || contract.StoreObjectLimit(object) == 0 || length > contract.StoreObjectLimit(object) || (length == 0) != digest.IsZero() {
		return contract.ErrRecord
	}
	if before, exists := m.objects[object]; exists {
		if before.length != 0 && length != 0 && (before.length != length || before.digest != digest) {
			return contract.ErrRecord
		}
		if before.length != 0 {
			return nil
		}
	}
	m.objects[object] = gcMarkFact{object, length, digest}
	return nil
}

func gcPageIdentity(ref format.Ref) contract.StoreObjectIdentity {
	return contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: ref.Kind, Index: ref.Index, ObjectID: ref.Object}
}

func (m *gcMarkSet) addRef(domain contract.ID, ref format.Ref) error {
	if ref.Domain != domain || !ref.ValidFor(contract.CanonicalSchema) {
		return contract.ErrRecord
	}
	return m.add(gcPageIdentity(ref), ref.Length, ref.Digest)
}

func (m *gcMarkSet) addInbox(id contract.ID, body []byte) error {
	var length uint32
	var digest contract.ID
	if len(body) != 0 {
		length, digest = uint32(len(body)), contract.Hash(body)
	}
	return m.add(contract.StoreObjectIdentity{Namespace: contract.StoreResultObject, ObjectID: id}, length, digest)
}

func gcMarkSelected(image *selectedImage, generated *generatedSelection, store contract.Descriptor) (gcMarkSet, error) {
	marks := gcMarkSet{objects: make(map[contract.StoreObjectIdentity]gcMarkFact), pending: make(map[contract.StoreObjectIdentity]struct{})}
	if image == nil || generated == nil || generated.image != image || !store.Valid() || image.root.Domain.IsZero() ||
		image.root.CurrentAccess.Core.StoreID != store.Identity {
		return gcMarkSet{}, contract.ErrRecord
	}
	root := image.root
	rootBytes, err := format.EncodeRoot(root)
	if err != nil {
		return gcMarkSet{}, err
	}
	if err := marks.add(contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RootKind, ObjectID: root.Snapshot}, uint32(len(rootBytes)), contract.Hash(rootBytes)); err != nil {
		return gcMarkSet{}, err
	}
	refs := make([]format.Ref, 0, root.ChildCount)
	for _, list := range [][]*format.Ref{root.ValueEntryPages[:], root.Recipients[:]} {
		for _, ref := range list {
			if ref != nil {
				refs = append(refs, *ref)
			}
		}
	}
	refs = append(refs, root.CurrentAccess.Core.AccessPageRefs...)
	refs = append(refs, root.GrantPages...)
	refs = append(refs, root.AdministrativeIndex)
	refs = append(refs, root.AdministrativeIndexShards...)
	refs = append(refs, root.RequiredSupport...)
	for _, ref := range refs {
		if err := marks.addRef(root.Domain, ref); err != nil {
			return gcMarkSet{}, err
		}
	}
	// HEAD.Store fixes this helper even when normal selected reads did not GET it.
	if err := marks.add(contract.StoreObjectIdentity{Namespace: contract.StoreConfigurationObject, ObjectID: store.Identity}, 0, contract.ID{}); err != nil {
		return gcMarkSet{}, err
	}
	for _, attempt := range generated.attempts {
		if err := marks.addInbox(attempt.record.InboxID, attempt.result); err != nil {
			return gcMarkSet{}, err
		}
	}
	for _, released := range generated.releases {
		if err := marks.addInbox(released.release.InboxID, nil); err != nil {
			return gcMarkSet{}, err
		}
	}
	if err := gcMarkActiveGraph(&marks, generated); err != nil {
		return gcMarkSet{}, err
	}
	gc, err := selectedGCState(image, true)
	if err != nil || selectedGCStore(gc, store) != nil {
		return gcMarkSet{}, contract.ErrRecord
	}
	for _, obligation := range gc {
		if obligation.plan == nil {
			return gcMarkSet{}, contract.ErrRecord
		}
		for _, target := range obligation.plan.Targets {
			if _, live := marks.objects[target.Object]; live {
				return gcMarkSet{}, contract.ErrRecord
			}
			marks.pending[target.Object] = struct{}{}
		}
	}
	return marks, nil
}

// Only the active graph can install future templates. Graphs retained for an
// original result or release do not regain their unentered branches.
func gcMarkActiveGraph(marks *gcMarkSet, generated *generatedSelection) error {
	if generated.parent == nil {
		return nil
	}
	if generated.phase == nil || len(generated.bundles) == 0 || generated.bundles[0].Header.OperationID != generated.parent.OperationID {
		return contract.ErrRecord
	}
	graph := generated.bundles[0]
	possibleResults := make(map[contract.ID]bool)
	for _, a := range generated.attempts {
		if a.record.OperationID == generated.parent.OperationID && a.expected.Template.Action == contract.GeneratorActionCreate {
			possibleResults[a.record.ResultID] = true
		}
	}
	for index, lineage := range graph.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate || generatedSelectionAnchored(generated) || generated.preparation != nil || index < int(generated.phase.LineageIndex) {
			continue
		}
		start := uint8(0)
		if index == int(generated.phase.LineageIndex) {
			if generated.phase.Stage == contract.GeneratedStageTerminal {
				continue
			}
			row, ok := generated.records[generatedRecordKey{contract.GeneratedLineageSupportKind, lineage.LineageID}]
			if !ok {
				return contract.ErrRecord
			}
			state, err := contract.InspectGeneratedLineageRecord(row.Body)
			if err != nil {
				return err
			}
			start = state.Branch
		}
		var seen [contract.GeneratorCreateLineageTemplates]bool
		pending := []uint8{start}
		for len(pending) != 0 {
			branch := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			if int(branch) >= int(lineage.TemplateCount) || int(branch) >= len(seen) {
				return contract.ErrRecord
			}
			if seen[branch] {
				continue
			}
			seen[branch] = true
			template := lineage.Templates[branch]
			possibleResults[template.ResultID] = true
			if err := marks.addInbox(template.InboxID, nil); err != nil {
				return err
			}
			if template.LifecycleMode == contract.GeneratorLifecycleNone {
				continue
			}
			for _, guard := range []uint8{contract.GeneratorGuardQualifiedNoEffect, contract.GeneratorGuardResidue} {
				next, present, err := template.SuccessorBranch(guard)
				if err != nil {
					return err
				}
				if present {
					pending = append(pending, next)
				}
			}
		}
	}
	for _, lineage := range graph.Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			continue
		}
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			if lineage.Purpose == contract.GeneratorLineageCleanup && !possibleResults[template.TargetSourceID] {
				continue
			}
			if err := marks.addInbox(template.InboxID, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func gcHashBlob(h hash.Hash, body []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(body)))
	h.Write(length[:])
	h.Write(body)
}

func (m gcMarkSet) digest(store contract.Descriptor, domain, headDigest contract.ID) (contract.ID, error) {
	if m.objects == nil || !gcCursorScopeValid(domain, store) || headDigest.IsZero() {
		return contract.ID{}, contract.ErrRecord
	}
	facts := make([]gcMarkFact, 0, len(m.objects))
	keys := make(map[contract.StoreObjectIdentity]string, len(m.objects))
	for _, fact := range m.objects {
		key, err := contract.StoreObjectKey(store.Prefix, domain, fact.object)
		if err != nil {
			return contract.ID{}, err
		}
		keys[fact.object] = key
		facts = append(facts, fact)
	}
	slices.SortFunc(facts, func(a, b gcMarkFact) int {
		return bytes.Compare([]byte(keys[a.object]), []byte(keys[b.object]))
	})
	h := sha256.New()
	h.Write([]byte("ENKV/GC-MARK/v1\x00"))
	descriptor := administrativeStoreDescriptorDigest(store)
	h.Write(descriptor[:])
	h.Write(domain[:])
	gcHashBlob(h, []byte(store.HeadKey))
	h.Write(headDigest[:])
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(facts)))
	h.Write(count[:])
	for _, fact := range facts {
		gcHashBlob(h, []byte(keys[fact.object]))
		binary.BigEndian.PutUint32(count[:], fact.length)
		h.Write(count[:])
		h.Write(fact.digest[:])
	}
	var digest contract.ID
	copy(digest[:], h.Sum(nil))
	return digest, nil
}
