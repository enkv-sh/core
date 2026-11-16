package core

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The test signer authenticates the altered physical page and its index. This
// lets EndWork reach semantic checks after reference authentication succeeds.
func retainedReaderSignedCanonical(t *testing.T, f retainedReaderFixture, variant string) (*memoryStore, format.Ref) {
	t.Helper()
	original := f.env.Store.(*memoryStore)
	store := &memoryStore{desc: original.desc, configuration: original.configuration, generation: original.generation, objects: make(map[string]stored)}
	for key, value := range original.objects {
		value.Body = bytes.Clone(value.Body)
		store.objects[key] = value
	}
	bad := *f.selected
	bad.root.RequiredSupport = slices.Clone(bad.root.RequiredSupport)
	bad.adminIndex.Pages = slices.Clone(bad.adminIndex.Pages)
	bad.adminIndex.Groups = slices.Clone(bad.adminIndex.Groups)
	position := slices.Index(bad.root.RequiredSupport, f.retainedRef)
	if position < 0 {
		t.Fatal("retained page absent")
	}
	view, err := format.InspectRequiredSupportPage(store.objects[mustKey(t, store.desc.Prefix, f.retainedRef)].Body)
	if err != nil {
		t.Fatal(err)
	}
	page := format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index}
	for _, row := range view.Records {
		page.Records = append(page.Records, contract.SupportRecord(row))
	}
	rowPosition := slices.IndexFunc(page.Records, func(row contract.SupportRecord) bool {
		canonical, err := contract.DecodeRetainedCanonicalRecord(row.Body)
		return row.Kind == contract.RetainedCanonicalSupportKind && err == nil && canonical.Entry.ValueState == f.value.ValueState &&
			(!slices.Contains([]string{"exact legacy source", "missing Authority", "conflicting retained payload", "unsupported generated source", "changed Crypto support"}, variant) || row.RecordID == f.value.ValueState)
	})
	if rowPosition < 0 {
		t.Fatal("retained row absent")
	}
	canonical, err := contract.DecodeRetainedCanonicalRecord(page.Records[rowPosition].Body)
	if err != nil {
		t.Fatal(err)
	}
	switch variant {
	case "exact legacy source", "missing Authority", "conflicting retained payload", "unsupported generated source", "changed Crypto support":
		if page.Records[rowPosition].RecordID != canonical.Entry.ValueState {
			t.Fatal("noncurrent damage requires a historical material-keyed source")
		}
		switch variant {
		case "missing Authority":
			canonical.Entry.Recipients = slices.DeleteFunc(canonical.Entry.Recipients, func(id contract.ID) bool {
				return id == bad.root.CurrentAccess.Core.AuthorityRecipientID
			})
		case "conflicting retained payload":
			payload, decodeErr := contract.DecodeCanonicalPayload(canonical.Entry.ValueBytes)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			payload.Ciphertext[0] ^= 1
			canonical.Entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
		}

		if variant == "unsupported generated source" || variant == "changed Crypto support" {
			if variant == "unsupported generated source" {
				for _, named := range bad.root.Names {
					entry := bad.valueEntry(named.Slot)
					if entry.ValueSource == contract.Generated {
						canonical.Entry.ValueSource, canonical.Entry.Generated = contract.Generated, entry.Generated
						canonical.Entry.Generated.GenerationID = canonical.Entry.ValueState
						canonical.Entry.ValueBytes = bytes.Clone(entry.ValueBytes)
						break
					}
				}
				if canonical.Entry.ValueSource != contract.Generated {
					t.Fatal("generated metadata control absent")
				}
			} else {
				payload, decodeErr := contract.DecodeCanonicalPayload(canonical.Entry.ValueBytes)
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				payload.CryptoSupportID = testID(t.Name() + " unsupported Crypto support")
				canonical.Entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
				if err != nil {
					t.Fatal(err)
				}
			}
			core, coreErr := contract.ValueCoreForEntry(bad.root.Domain, bad.root.CurrentAccess.Core.CompatibilityID, canonical.Entry)
			if coreErr != nil {
				t.Fatal("damaged canonical value core", coreErr)
			}
			payload, payloadErr := contract.InspectCanonicalPayload(canonical.Entry.ValueBytes)
			if payloadErr != nil {
				t.Fatal("damaged canonical payload", payloadErr)
			}
			context, contextErr := contract.ValueMaterialContextDigest(core)
			if contextErr != nil {
				t.Fatal(contextErr)
			}
			bad.root.CurrentAccess.Core.AccessPageRefs = slices.Clone(bad.root.CurrentAccess.Core.AccessPageRefs)
			changed := false
			for i, old := range bad.root.CurrentAccess.Core.AccessPageRefs {
				access := *bad.access[old.Index]
				access.Records = slices.Clone(access.Records)
				found := false
				for j := range access.Records {
					row := &access.Records[j]
					if row.MaterialKind == contract.ValueMaterialKind && row.MaterialID == canonical.Entry.ValueState {
						row.MaterialContextDigest, found, changed = context, true, true
						row.PackageCheck = payload.PackageCheck
					}
				}
				if !found {
					continue
				}
				body, encodeErr := format.EncodeAccessPage(access)
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				ref, refErr := format.Reference(contract.AccessKind, old.Domain, old.Object, old.Index, body)
				if refErr != nil {
					t.Fatal(refErr)
				}
				bad.root.CurrentAccess.Core.AccessPageRefs[i], bad.access[old.Index] = ref, &access
				store.put(mustKey(t, store.desc.Prefix, ref), body)
			}
			if !changed {
				t.Fatal("noncurrent access row absent")
			}
			var records []contract.AccessRecord
			for _, ref := range bad.root.CurrentAccess.Core.AccessPageRefs {
				records = append(records, bad.access[ref.Index].Records...)
			}
			slices.SortFunc(records, func(a, b contract.AccessRecord) int {
				return compareMaterial(a.MaterialKind, a.MaterialID, b.MaterialKind, b.MaterialID)
			})
			bad.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(bad.root.Domain, records)
			if err != nil {
				t.Fatal(err)
			}
			bad.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(bad.root.CurrentAccess.Core)
			if err != nil {
				t.Fatal(err)
			}
		}
		page.Records[rowPosition].Body, err = contract.EncodeRetainedCanonicalRecord(canonical)
		if err != nil {
			t.Fatal(err)
		}
		bad.adminIndex.Pages[position].Rows = slices.Clone(bad.adminIndex.Pages[position].Rows)
		bad.adminIndex.Pages[position].Rows[rowPosition], err = format.AdministrativeSummary(page.Records[rowPosition])
	case "changed value context":
		canonical.Entry.OriginTransition = fixtureID(f.env.Domain, "changed retained origin")
		page.Records[rowPosition].Body, err = contract.EncodeRetainedCanonicalRecord(canonical)
		if err != nil {
			t.Fatal(err)
		}
		page.Records[rowPosition].RecordID, err = contract.AdmissionEntryDigest(canonical)
		if err != nil {
			t.Fatal(err)
		}
		bad.adminIndex.Pages[position].Rows = slices.Clone(bad.adminIndex.Pages[position].Rows)
		bad.adminIndex.Pages[position].Rows[rowPosition], err = format.AdministrativeSummary(page.Records[rowPosition])
	case "wrong physical ordinal", "valid sparse ordinal":
		// An unselected physical row may remain after an earlier disposition.
		// It is not a reader obligation and must not replace the selected row.
		canonical.Entry.ValueState = fixtureID(f.env.Domain, "unselected retained value")
		var body []byte
		body, err = contract.EncodeRetainedCanonicalRecord(canonical)
		page.Records = append([]contract.SupportRecord{{Kind: contract.RetainedCanonicalSupportKind, RecordID: canonical.Entry.ValueState, Body: body}}, page.Records...)
		if variant == "valid sparse ordinal" {
			indexed := &bad.adminIndex.Pages[position]
			indexed.Spans = slices.Clone(indexed.Spans)
			for i := range indexed.Spans {
				indexed.Spans[i].First++
			}
		}
	default:
		t.Fatal("unknown canonical variant")
	}
	if err != nil {
		t.Fatal(err)
	}
	body, err := format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal("altered physical page is not structurally valid", err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	bad.root.RequiredSupport[position], bad.adminIndex.Pages[position].Ref = ref, ref
	store.put(mustKey(t, store.desc.Prefix, ref), body)
	views := make(map[format.Ref]format.RequiredSupportPageView)
	for _, indexed := range bad.adminIndex.Pages {
		if indexed.ReadRequired {
			views[indexed.Ref], err = f.selected.administrativeSelectedSupportPage(indexed)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := rechargeEndWorkGroups(&bad.adminIndex, views); err != nil {
		t.Fatal(err)
	}
	shards, err := format.EncodeAdministrativeIndexPages(bad.adminIndex)
	if err != nil {
		t.Fatal("altered index is not structurally valid", err)
	}
	bad.root.AdministrativeIndex, bad.root.AdministrativeIndexShards = shards[0].Ref, nil
	for i, shard := range shards {
		store.put(mustKey(t, store.desc.Prefix, shard.Ref), shard.Body)
		if i != 0 {
			bad.root.AdministrativeIndexShards = append(bad.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	return retainedReaderSignedState(t, f, &bad, store), ref
}

// full_only: false
func TestAdministrativeEndWorkChecksAuthenticatedCanonicalSemantics(t *testing.T) {
	for _, variant := range []string{"changed value context", "wrong physical ordinal", "valid sparse ordinal"} {
		t.Run(variant, func(t *testing.T) {
			f := newRetainedReaderFixture(t, false, 3)
			store, ref := retainedReaderSignedCanonical(t, f, variant)
			observed := &retainedReaderObservingStore{memoryStore: store}
			key := mustKey(t, store.desc.Prefix, ref)
			partial, result := openAdministrative(t.Context(), OpenContext{admission: &f.selected.admission}, observed)
			if partial == nil || result.Outcome != ObservedCurrent || len(observed.readsFor(key)) != 0 {
				t.Fatal("partial admission did not omit the authenticated optional page", result)
			}
			creates, cas := store.creates, store.cas
			candidate, result := prepareTestEndSelectedWork(t, partial, t.Context(), retainedReaderOwnerIDs(f)[0], f.env.Trust)
			reads := observed.readsFor(key)
			if len(reads) == 0 || reads[len(reads)-1].status != contract.ReadOK || reads[len(reads)-1].digest != ref.Digest {
				t.Fatal("EndWork did not read the repinned authenticated page")
			}
			if variant != "valid sparse ordinal" {
				if candidate != nil || result != refused(InvalidRelation) || store.creates != creates || store.cas != cas {
					t.Fatal("EndWork did not refuse the authenticated semantic mismatch before writes", result)
				}
				return
			}
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("EndWork refused valid sparse physical selection", result)
			}
			next, result := partial.selectCandidate(t.Context(), candidate)
			if next == nil || result.Outcome != ObservedCurrent {
				t.Fatal("select sparse successor", result)
			}
			next = retainedReaderColdOpen(t, next, observed)
			checkRetainedReaderAccess(t, next, f, true)
		})
	}
}
