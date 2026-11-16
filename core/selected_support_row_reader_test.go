package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPreservedBodyBackedSupportFactsKeepSparsePhysicalOrdinals(t *testing.T) {
	domain, object := generatedVectorID(1), generatedVectorID(9)
	var rows []contract.SupportRecord
	for i, payload := range [][]byte{[]byte("first physical row"), []byte("second physical row")} {
		blob := generatedVectorID(uint8(10 + i))
		body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema,
			BlobID: blob, Index: 0, Count: 1, TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body})
	}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: domain, Object: object, Index: 7, Records: rows})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, domain, object, 7, body)
	if err != nil {
		t.Fatal(err)
	}
	base := generatedEmptyPredecessor(t)
	// The complete configuration remains unchanged while an independent immutable
	// page selects only its second physical row in the successor.
	prior := *base
	prior.root.RequiredSupport = append(slices.Clone(base.root.RequiredSupport), ref)
	prior.support = append(slices.Clone(base.support), format.RequiredSupportPageView{Domain: domain, Object: object, Index: 7,
		Records: []contract.SupportRecordView{contract.SupportRecordView(rows[0]), contract.SupportRecordView(rows[1])}})
	prior.root.RequiredSupportRecordCount += 2
	prior.recountChildren()
	prior.adminIndex.Pages = append(slices.Clone(base.adminIndex.Pages), format.AdministrativePage{Ref: ref,
		Spans: []format.AdministrativeSpan{{First: 0, Count: 2}}})
	if err := base.bindPreservedOutputConfiguration(&prior); err != nil {
		t.Fatal("complete predecessor facts", err)
	}
	for _, borrowed := range []bool{false, true} {
		t.Run(fmt.Sprintf("borrowed=%t", borrowed), func(t *testing.T) {
			next := prior
			next.root.RequiredSupportRecordCount--
			next.recountChildren()
			next.support = slices.Clone(prior.support)
			next.support[1].Records = []contract.SupportRecordView{contract.SupportRecordView(rows[1])}
			if borrowed {
				next.support[1].Records[0].Body = nil
			}
			next.adminIndex.Pages = slices.Clone(prior.adminIndex.Pages)
			next.adminIndex.Pages[1].Spans = []format.AdministrativeSpan{{First: 1, Count: 1}}
			if err := prior.bindPreservedOutputConfiguration(&next); err != nil {
				t.Fatal("preserved sparse selection", err)
			}
			if got := next.supportFacts[1].ordinals; !slices.Equal(got, []uint16{1}) {
				t.Fatal("physical ordinal changed after removal of the earlier row", got)
			}
			for _, damage := range []string{"span", "page-object", "index-ref"} {
				bad := next
				bad.support = slices.Clone(next.support)
				bad.adminIndex.Pages = slices.Clone(next.adminIndex.Pages)
				switch damage {
				case "span":
					bad.adminIndex.Pages[1].Spans = []format.AdministrativeSpan{{First: 0, Count: 1}}
				case "page-object":
					bad.support[1].Object = generatedVectorID(8)
				case "index-ref":
					bad.adminIndex.Pages[1].Ref.Digest[0] ^= 1
				}
				if err := prior.bindPreservedOutputConfiguration(&bad); err == nil {
					t.Fatal("inconsistent retained physical selection accepted", damage)
				}
			}
			result, err := withAuthenticatedSupportRow(t.Context(), func(context.Context, format.Ref) ([]byte, Result) {
				return body, Result{}
			}, domain, next.supportFacts[1], 0, func(row contract.SupportRecordView) error {
				if row.RecordID != rows[1].RecordID || !bytes.Equal(row.Body, rows[1].Body) {
					t.Fatal("sparse successor borrowed a different physical row")
				}
				return nil
			})
			if err != nil || result.Outcome != 0 {
				t.Fatal("sparse successor failed authenticated read", result, err)
			}
		})
	}
	t.Run("ordered-spans", testPreservedSupportFactsOrderedSpans)
	t.Run("unloaded-optional", testPreservedSupportFactsUnloadedOptional)
	t.Run("unloaded-optional-exit", testPreservedSupportFactsUnloadedOptionalExit)

}

func testPreservedSupportFactsUnloadedOptionalExit(t *testing.T) {
	before, rows := publicationReservationFixture(t, false)
	state := *before
	state.root.Snapshot, state.root.Transition = publicationRelationID(90), publicationRelationID(91)
	reservation := Candidate{session: before}
	construction, constructionErr := before.preparePublicationConstruction(t.Context(), rows)
	if constructionErr == nil {
		constructionErr = before.materializePublicationReservationConstruction(t.Context(), &state, &reservation, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
	}
	if err := constructionErr; err != nil {
		t.Fatal("real two-marker reservation", err)
	}
	generatedInstallFixtureSupportReader(t, &state)
	reader := state.store.(*generatedFixtureSupportStore)
	var target, survivor, uncertainCreate contract.ID
	for _, row := range rows {
		if row.Kind != contract.PublicationMarkerSupportKind {
			continue
		}
		marker, err := contract.InspectPublicationMarker(row.Body)
		if err != nil {
			t.Fatal("fixture marker", err)
		}
		switch marker.Projection.Action {
		case contract.PublicationCreateEmpty, contract.PublicationCreateWithValue:
			if !survivor.IsZero() {
				t.Fatal("fixture has multiple upstream creates")
			}
			survivor = marker.AttemptID
		case contract.PublicationDeleteReservedSlot:
			if !target.IsZero() {
				t.Fatal("fixture has multiple reserved deletes")
			}
			target, uncertainCreate = marker.AttemptID, marker.Projection.UncertainCreateAttemptID
		default:
			t.Fatal("fixture has an unexpected marker action")
		}
	}
	if target.IsZero() || survivor.IsZero() || uncertainCreate != survivor {
		t.Fatal("fixture reserved delete does not name its upstream create")
	}
	var unloaded []format.Ref
	var unloadedKeys []string
	for i, page := range state.adminIndex.Pages {
		if page.ReadRequired || slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
			continue
		}
		key, err := format.Key(state.admission.store.Prefix, page.Ref)
		if err != nil {
			t.Fatal("optional marker fixture key", err)
		}
		if _, cached := state.cache[page.Ref]; cached {
			t.Fatal("optional marker fixture still has cached payload")
		}
		delete(reader.objects, key)
		unloadedKeys = append(unloadedKeys, key)
		state.support[i].Records = nil
		state.supportFacts[i] = selectedSupportPageFacts{ref: page.Ref}
		unloaded = append(unloaded, page.Ref)
	}
	if len(unloaded) == 0 {
		t.Fatal("fixture has no optional marker pages")
	}
	state.admission.endWorkInvocation = generatedVectorID(196)
	ids := endWorkIDs{operation: generatedVectorID(180), transition: generatedVectorID(181), snapshot: generatedVectorID(182),
		revision: generatedVectorID(183), receipts: generatedVectorID(184), receiptIndex: generatedVectorID(185)}
	candidate, next, err := state.deriveEndWorkCandidate(t.Context(), target, ids)
	if err != nil {
		t.Fatal("actual exit with unrelated unloaded marker", err)
	}
	for _, key := range reader.keys {
		if slices.Contains(unloadedKeys, key) {
			t.Fatal("actual exit read an absent optional marker body")
		}
	}
	if candidate.head.EndWork == nil || candidate.head.EndWork.TargetGroupID != target {
		t.Error("actual exit is missing the target receipt")
	}
	if slices.ContainsFunc(next.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == target }) {
		t.Error("actual exit retained the target")
	}
	if !slices.ContainsFunc(next.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == survivor }) {
		t.Error("actual exit is missing the survivor")
	}
	if candidate.firstSend != nil {
		t.Error("actual exit gained firstSend")
	}
	if next.publicationProof != nil {
		t.Error("actual exit gained publicationProof")
	}
	if next.root.OutputConfiguration != state.root.OutputConfiguration {
		t.Error("actual exit changed output configuration")
	}
	if t.Failed() {
		t.FailNow()
	}
	kept := 0
	for i, ref := range next.root.RequiredSupport {
		if !slices.Contains(unloaded, ref) {
			continue
		}
		kept++
		if len(next.support[i].Records) != 0 || next.supportFacts[i].ref != ref ||
			len(next.supportFacts[i].rows) != 0 || len(next.supportFacts[i].ordinals) != 0 {
			t.Fatal("actual exit invented payload facts for retained optional page")
		}
	}
	if kept == 0 {
		t.Fatal("actual exit did not retain an unrelated unloaded page")
	}
}

func testPreservedSupportFactsUnloadedOptional(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	var records []contract.SupportRecord
	for i := range 2 {
		payload := []byte{byte(i + 1)}
		blob := contract.Hash(payload)
		body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema,
			BlobID: blob, Index: 0, Count: 1, TotalLength: 1, WholeDigest: blob, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body})
	}
	slices.SortFunc(records, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	object := generatedVectorID(90)
	body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: base.root.Domain, Object: object, Index: 7, Records: records})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, base.root.Domain, object, 7, body)
	if err != nil {
		t.Fatal(err)
	}
	prior := *base
	prior.root.RequiredSupport = append(slices.Clone(base.root.RequiredSupport), ref)
	prior.root.RequiredSupportRecordCount += 2
	prior.support = append(slices.Clone(base.support), format.RequiredSupportPageView{Domain: base.root.Domain, Object: object, Index: 7})
	prior.supportFacts = append(slices.Clone(base.supportFacts), selectedSupportPageFacts{ref: ref})
	prior.fragmentFacts = make(map[format.FragmentLocation]selectedFragmentFact)
	descriptor := contract.GeneratorDescriptor{Digest: generatedVectorID(91), Length: 4}
	for i := range 2 {
		id := generatedVectorID(byte(92 + i))
		prior.adminIndex.Groups = append(prior.adminIndex.Groups, format.AdministrativeGroup{GroupID: id, OwnerID: id, TargetID: id,
			OwnerKind: format.AdministrativeGeneratedParent, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
			Affected: descriptor, Dependencies: descriptor, Disposable: descriptor})
	}
	optional := format.AdministrativePage{Ref: ref, Spans: []format.AdministrativeSpan{
		{First: 0, Count: 1, GroupIndexes: []uint16{0}}, {First: 1, Count: 1, GroupIndexes: []uint16{1}}}}
	for _, row := range records {
		optional.Rows = append(optional.Rows, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
	}
	prior.adminIndex.Pages = append(slices.Clone(base.adminIndex.Pages), optional)
	prior.recountChildren()
	if !prior.adminIndex.Valid() {
		t.Fatal("invalid optional predecessor index")
	}
	next := prior
	next.adminIndex, err = prior.administrativeWorkDisposition(generatedVectorID(92))
	if err != nil {
		t.Fatal("dispose first owner without optional bytes", err)
	}
	next.root.RequiredSupportRecordCount--
	next.recountChildren()
	if len(next.adminIndex.Groups) != 1 || next.adminIndex.Groups[0].GroupID != generatedVectorID(93) ||
		next.adminIndex.Pages[1].Ref != ref || !reflect.DeepEqual(next.adminIndex.Pages[1].Rows, optional.Rows[1:]) ||
		!reflect.DeepEqual(next.adminIndex.Pages[1].Spans, []format.AdministrativeSpan{{First: 1, Count: 1, GroupIndexes: []uint16{0}}}) {
		t.Fatal("unrelated optional owner or physical selection changed")
	}
	for _, route := range []string{"preserved", "planned", "end-work"} {
		t.Run(route, func(t *testing.T) {
			bind := func(old, target *StateSession) error {
				switch route {
				case "planned":
					return old.bindPlannedRetainedSupportFacts(target)
				case "end-work":
					if err := old.bindEndWorkSupportFacts(target, nil); err != nil {
						return err
					}
				}
				return old.bindPreservedOutputConfiguration(target)
			}
			accepted := next
			accepted.outputConfigurationRoot, accepted.publicationProof = contract.ID{}, nil
			if err := bind(&prior, &accepted); err != nil {
				t.Fatal("retained unreadable optional page", err)
			}
			if accepted.supportFacts[1].ref != ref || len(accepted.supportFacts[1].rows) != 0 || len(accepted.supportFacts[1].ordinals) != 0 ||
				len(accepted.support[1].Records) != 0 || accepted.publicationProof != nil ||
				!reflect.DeepEqual(accepted.supportFacts[0], base.supportFacts[0]) {
				t.Fatal("optional page gained payload facts or mandatory configuration facts changed")
			}
			if route == "planned" && !accepted.outputConfigurationRoot.IsZero() {
				t.Fatal("planned image gained complete configuration proof")
			}
			for _, damage := range []string{"mandatory", "read-required", "old-mandatory", "old-read-required", "span", "overlap", "summary-count", "summary-identity", "summary-size", "old-summary", "page-object", "page-domain", "page-index", "index-ref", "root-ref", "old-view", "old-fact", "old-ordinal"} {
				t.Run(damage, func(t *testing.T) {
					old, bad := prior, next
					old.support, bad.support = slices.Clone(prior.support), slices.Clone(next.support)
					old.supportFacts = slices.Clone(prior.supportFacts)
					old.adminIndex.Pages, bad.adminIndex.Pages = slices.Clone(prior.adminIndex.Pages), slices.Clone(next.adminIndex.Pages)
					old.adminIndex.Pages[1].Spans, bad.adminIndex.Pages[1].Spans = slices.Clone(optional.Spans), slices.Clone(next.adminIndex.Pages[1].Spans)
					old.adminIndex.Pages[1].Rows, bad.adminIndex.Pages[1].Rows = slices.Clone(optional.Rows), slices.Clone(next.adminIndex.Pages[1].Rows)
					bad.root.RequiredSupport = slices.Clone(next.root.RequiredSupport)
					switch damage {
					case "mandatory":
						bad.adminIndex.Pages[1].Spans[0].Mandatory = true
					case "read-required":
						bad.adminIndex.Pages[1].ReadRequired = true
					case "old-mandatory":
						old.adminIndex.Pages[1].Spans[0].Mandatory = true
					case "old-read-required":
						old.adminIndex.Pages[1].ReadRequired = true
					case "span":
						bad.adminIndex.Pages[1].Spans[0].First = 0
					case "overlap":
						bad.adminIndex.Pages[1].Spans = append(bad.adminIndex.Pages[1].Spans, bad.adminIndex.Pages[1].Spans[0])
					case "summary-count":
						bad.adminIndex.Pages[1].Rows = nil
					case "summary-identity":
						bad.adminIndex.Pages[1].Rows[0].RecordID[0] ^= 1
					case "summary-size":
						bad.adminIndex.Pages[1].Rows[0].BodyLength = 0
					case "old-summary":
						old.adminIndex.Pages[1].Rows[1].Kind = 0
					case "page-object":
						bad.support[1].Object[0] ^= 1
					case "page-domain":
						bad.support[1].Domain[0] ^= 1
					case "page-index":
						bad.support[1].Index++
					case "index-ref":
						bad.adminIndex.Pages[1].Ref.Digest[0] ^= 1
					case "root-ref":
						bad.root.RequiredSupport[1].Digest[0] ^= 1
					case "old-view":
						old.support[1].Records = []contract.SupportRecordView{contract.SupportRecordView(records[0])}
					case "old-fact":
						old.supportFacts[1].rows = []contract.SupportRecordDigest{{}}
					case "old-ordinal":
						old.supportFacts[1].ordinals = []uint16{1}
					}
					if err := bind(&old, &bad); err == nil {
						t.Fatal("invalid unloaded retained page accepted", damage)
					}
				})
			}
		})
	}
}

func testPreservedSupportFactsOrderedSpans(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	var records []contract.SupportRecord
	_, _, marker, _ := publicationRelationFixtureForDomain(t, base.root.Domain)
	for i := range 8 {
		row := marker
		row.AttemptID = generatedVectorID(uint8(20 + i))
		body, err := contract.EncodePublicationMarker(row)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind, RecordID: row.AttemptID, Body: body})
	}
	slices.SortFunc(records, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	object := generatedVectorID(90)
	encoded, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: base.root.Domain, Object: object, Index: 7, Records: records})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, base.root.Domain, object, 7, encoded)
	if err != nil {
		t.Fatal(err)
	}
	prior := *base
	prior.root.RequiredSupport = append(slices.Clone(base.root.RequiredSupport), ref)
	prior.support = append(slices.Clone(base.support), format.RequiredSupportPageView{Domain: base.root.Domain, Object: object, Index: 7})
	for _, record := range records {
		prior.support[1].Records = append(prior.support[1].Records, contract.SupportRecordView(record))
	}
	prior.root.RequiredSupportRecordCount += uint32(len(records))
	prior.recountChildren()
	prior.adminIndex.Pages = append(slices.Clone(base.adminIndex.Pages), format.AdministrativePage{Ref: ref,
		Spans: []format.AdministrativeSpan{{First: 0, Count: 2}, {First: 2, Count: 1}, {First: 3, Count: 2}, {First: 5, Count: 3}}})
	if err := base.bindPreservedOutputConfiguration(&prior); err != nil {
		t.Fatal("complete ordered predecessor", err)
	}
	selectRows := func(state StateSession, ordinals []uint16, spans []format.AdministrativeSpan, bodyless bool) StateSession {
		state.root.RequiredSupportRecordCount = base.root.RequiredSupportRecordCount + uint32(len(ordinals))
		state.support = slices.Clone(state.support)
		state.support[1].Records = nil
		for _, physical := range ordinals {
			row := contract.SupportRecordView(records[physical])
			if bodyless {
				row.Body = nil
			}
			state.support[1].Records = append(state.support[1].Records, row)
		}
		state.adminIndex.Pages = slices.Clone(state.adminIndex.Pages)
		state.adminIndex.Pages[1].Spans = spans
		state.recountChildren()
		return state
	}
	for _, priorBodyless := range []bool{false, true} {
		for _, nextBodyless := range []bool{false, true} {
			t.Run(fmt.Sprintf("prior-bodyless=%t/next-bodyless=%t", priorBodyless, nextBodyless), func(t *testing.T) {
				before := selectRows(prior, []uint16{0, 1, 3, 5, 6, 7}, []format.AdministrativeSpan{{First: 0, Count: 2}, {First: 3, Count: 1}, {First: 5, Count: 3}}, priorBodyless)
				if err := prior.bindPreservedOutputConfiguration(&before); err != nil {
					t.Fatal("sparse predecessor", err)
				}
				next := selectRows(before, []uint16{1, 5, 7}, []format.AdministrativeSpan{{First: 1, Count: 1}, {First: 5, Count: 1}, {First: 7, Count: 1}}, nextBodyless)
				if err := before.bindPreservedOutputConfiguration(&next); err != nil {
					t.Fatal("ordered sparse successor", err)
				}
				if got := next.supportFacts[1].ordinals; !slices.Equal(got, []uint16{1, 5, 7}) {
					t.Fatal("physical ordinals changed", got)
				}
				for logical, physical := range []uint16{1, 5, 7} {
					expected, err := contract.InspectSupportRecordDigest(base.root.Domain, records[physical])
					if err != nil || next.supportFacts[1].rows[logical] != expected {
						t.Fatal("wrong exact retained digest", logical, physical, err)
					}
				}
				if err := next.bindPreservedOutputConfiguration(&next); err != nil {
					t.Fatal("self binding lost predecessor facts", err)
				}
				planned := next
				planned.outputConfigurationRoot = contract.ID{}
				planned.publicationProof = nil
				if err := next.bindPlannedRetainedSupportFacts(&planned); err != nil || !reflect.DeepEqual(planned.supportFacts, next.supportFacts) ||
					!planned.outputConfigurationRoot.IsZero() || planned.publicationProof != nil {
					t.Fatal("planned retention changed authenticated facts or gained proof", err)
				}
				damages := []string{"span", "overlap", "count", "prior-range", "domain", "page-index", "ref", "record"}
				if !nextBodyless {
					damages = append(damages, "body")
				}
				if priorBodyless || nextBodyless {
					damages = append(damages, "fact", "fact-ordinal", "missing-fact")
				}
				for _, damage := range damages {
					t.Run(damage, func(t *testing.T) {
						old, bad := before, next
						bad.support = slices.Clone(next.support)
						bad.support[1].Records = slices.Clone(next.support[1].Records)
						bad.adminIndex.Pages = slices.Clone(next.adminIndex.Pages)
						old.adminIndex.Pages = slices.Clone(before.adminIndex.Pages)
						old.supportFacts = slices.Clone(before.supportFacts)
						old.supportFacts[1].rows = slices.Clone(before.supportFacts[1].rows)
						old.supportFacts[1].ordinals = slices.Clone(before.supportFacts[1].ordinals)
						switch damage {
						case "span":
							bad.adminIndex.Pages[1].Spans = []format.AdministrativeSpan{{First: 0, Count: 1}, {First: 5, Count: 1}, {First: 7, Count: 1}}
						case "overlap":
							bad.adminIndex.Pages[1].Spans = []format.AdministrativeSpan{{First: 1, Count: 2}, {First: 2, Count: 1}}
						case "count":
							bad.adminIndex.Pages[1].Spans = []format.AdministrativeSpan{{First: 1, Count: 0}, {First: 5, Count: 1}, {First: 7, Count: 1}}
						case "prior-range":
							old.adminIndex.Pages[1].Spans = append(slices.Clone(old.adminIndex.Pages[1].Spans), format.AdministrativeSpan{First: 9, Count: 1})
						case "domain":
							bad.support[1].Domain[0] ^= 1
						case "page-index":
							bad.support[1].Index++
						case "ref":
							bad.adminIndex.Pages[1].Ref.Digest[0] ^= 1
						case "record":
							bad.support[1].Records[0].RecordID[0] ^= 1
						case "body":
							bad.support[1].Records[0].Body = bytes.Clone(bad.support[1].Records[0].Body)
							bad.support[1].Records[0].Body[len(bad.support[1].Records[0].Body)-1] ^= 1
						case "fact", "fact-ordinal", "missing-fact":
							switch damage {
							case "fact":
								old.supportFacts[1].rows[1] = old.supportFacts[1].rows[0]
							case "fact-ordinal":
								old.supportFacts[1].ordinals[1] = 0
							default:
								old.supportFacts[1].rows = nil
							}
						}
						if err := old.bindPreservedOutputConfiguration(&bad); err == nil {
							t.Fatal("changed retained selection accepted", damage)
						}
					})
				}
			})
		}
	}
	t.Run("new-physical-page", func(t *testing.T) {
		next := prior
		next.root.RequiredSupport = slices.Clone(prior.root.RequiredSupport)
		newObject := generatedVectorID(91)
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: base.root.Domain, Object: newObject, Index: 7, Records: records})
		if err != nil {
			t.Fatal(err)
		}
		next.root.RequiredSupport[1], err = format.Reference(contract.RequiredSupportKind, base.root.Domain, newObject, 7, body)
		if err != nil {
			t.Fatal(err)
		}
		next.support = slices.Clone(prior.support)
		next.support[1].Object = next.root.RequiredSupport[1].Object
		next.adminIndex.Pages = slices.Clone(prior.adminIndex.Pages)
		next.adminIndex.Pages[1].Ref = next.root.RequiredSupport[1]
		if err := prior.bindPreservedOutputConfiguration(&next); err != nil {
			t.Fatal("new page could not bind its inspected bodies", err)
		}
		if got := next.supportFacts[1].ordinals; !slices.Equal(got, []uint16{0, 1, 2, 3, 4, 5, 6, 7}) {
			t.Fatal("new page borrowed sparse prior ordinals", got)
		}
		planned := next
		planned.outputConfigurationRoot = contract.ID{}
		if err := prior.bindPlannedRetainedSupportFacts(&planned); err != nil || len(planned.supportFacts[1].rows) != 0 || len(planned.supportFacts[1].ordinals) != 0 || !planned.outputConfigurationRoot.IsZero() {
			t.Fatal("new planned page acquired prior authority", err)
		}
		borrowed := next
		borrowed.support = slices.Clone(next.support)
		borrowed.support[1].Records = slices.Clone(next.support[1].Records)
		borrowed.support[1].Records[0].Body = nil
		if err := prior.bindPreservedOutputConfiguration(&borrowed); err == nil {
			t.Fatal("new page accepted bodyless row from old physical authority")
		}
	})
	t.Run("configuration-sparse", func(t *testing.T) {
		configuration := base.support[0].Records[0]
		physical := []contract.SupportRecord{records[0], contract.SupportRecord(configuration)}
		page := base.support[0]
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: physical})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		before := *base
		before.root.RequiredSupport = []format.Ref{ref}
		before.root.RequiredSupportRecordCount = 2
		before.support = []format.RequiredSupportPageView{{Domain: page.Domain, Object: page.Object, Index: page.Index,
			Records: []contract.SupportRecordView{contract.SupportRecordView(physical[0]), configuration}}}
		before.adminIndex.Pages = []format.AdministrativePage{{Ref: ref, Spans: []format.AdministrativeSpan{{First: 0, Count: 1}, {First: 1, Count: 1}}}}
		before.recountChildren()
		if err := base.bindPreservedOutputConfiguration(&before); err != nil {
			t.Fatal("mixed configuration predecessor", err)
		}
		for _, bodyless := range []bool{false, true} {
			row := configuration
			if bodyless {
				row.Body = nil
			}
			next := before
			next.root.RequiredSupportRecordCount = 1
			next.support = []format.RequiredSupportPageView{{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: []contract.SupportRecordView{row}}}
			next.adminIndex.Pages = []format.AdministrativePage{{Ref: ref, Spans: []format.AdministrativeSpan{{First: 1, Count: 1}}}}
			next.recountChildren()
			if err := before.bindPreservedOutputConfiguration(&next); err != nil || !slices.Equal(next.supportFacts[0].ordinals, []uint16{1}) {
				t.Fatal("configuration lost exact physical slice", bodyless, err)
			}
			bad := next
			bad.adminIndex.Pages = []format.AdministrativePage{{Ref: ref, Spans: []format.AdministrativeSpan{{First: 0, Count: 1}}}}
			if err := before.bindPreservedOutputConfiguration(&bad); err == nil {
				t.Fatal("configuration accepted a different physical slice", bodyless)
			}
		}
	})

}

// full_only: false
func TestAuthenticatedSupportRowUsesExactPhysicalOrdinalAndBorrowScope(t *testing.T) {
	domain, object := generatedVectorID(1), generatedVectorID(2)
	var rows []contract.SupportRecord
	for i, payload := range [][]byte{[]byte("first physical row"), []byte("second physical row")} {
		blob := generatedVectorID(uint8(10 + i))
		body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema,
			BlobID: blob, Index: 0, Count: 1, TotalLength: uint64(len(payload)), WholeDigest: contract.Hash(payload), Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(blob, 0)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body})
	}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: domain, Object: object, Index: 0, Records: rows})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, domain, object, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contract.InspectSupportRecordDigest(domain, rows[1])
	if err != nil {
		t.Fatal(err)
	}
	facts := selectedSupportPageFacts{ref: ref, rows: []contract.SupportRecordDigest{digest}, ordinals: []uint16{1}}
	reads, calls := 0, 0
	read := func(ctx context.Context, got format.Ref) ([]byte, Result) {
		reads++
		if got != ref {
			t.Fatal("read used a different selected Ref")
		}
		return body, Result{}
	}
	consume := func(row contract.SupportRecordView) error {
		calls++
		if row.Kind != rows[1].Kind || row.RecordID != rows[1].RecordID || !bytes.Equal(row.Body, rows[1].Body) {
			t.Fatal("logical slot zero did not select physical row one")
		}
		return nil
	}
	result, err := withAuthenticatedSupportRow(context.Background(), read, domain, facts, 0, consume)
	if err != nil || result.Outcome != 0 || reads != 1 || calls != 1 {
		t.Fatal("exact selected row refused", result, err, reads, calls)
	}

	wrong := facts
	wrong.ordinals = []uint16{0}
	result, err = withAuthenticatedSupportRow(context.Background(), read, domain, wrong, 0, consume)
	if err != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation || calls != 1 {
		t.Fatal("wrong physical ordinal reached consumer", result, err)
	}

	damaged := bytes.Clone(body)
	damaged[len(damaged)-1] ^= 1
	result, err = withAuthenticatedSupportRow(context.Background(), func(context.Context, format.Ref) ([]byte, Result) {
		return damaged, Result{}
	}, domain, facts, 0, consume)
	if err != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidReference || calls != 1 {
		t.Fatal("changed selected bytes reached consumer", result, err)
	}

	missing := failure(EvidenceUnavailable, MissingSelectedObject)
	result, err = withAuthenticatedSupportRow(context.Background(), func(context.Context, format.Ref) ([]byte, Result) {
		return nil, missing
	}, domain, facts, 0, consume)
	if err != nil || result != missing || calls != 1 {
		t.Fatal("typed read loss changed", result, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = withAuthenticatedSupportRow(ctx, read, domain, facts, 0, consume)
	if err != nil || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable || reads != 2 {
		t.Fatal("cancelled read reached source", result, err, reads)
	}

	consumerErr := errors.New("consumer refused")
	result, err = withAuthenticatedSupportRow(context.Background(), read, domain, facts, 0,
		func(contract.SupportRecordView) error { return consumerErr })
	if result.Outcome != 0 || !errors.Is(err, consumerErr) {
		t.Fatal("consumer error was hidden", result, err)
	}

	firstDigest, err := contract.InspectSupportRecordDigest(domain, rows[0])
	if err != nil {
		t.Fatal(err)
	}
	all := selectedSupportPageFacts{ref: ref, rows: []contract.SupportRecordDigest{firstDigest, digest}, ordinals: []uint16{0, 1}}
	pageReads := 0
	readPage := func(context.Context, format.Ref) ([]byte, Result) {
		pageReads++
		return body, Result{}
	}
	var visited []uint16
	result, err = withAuthenticatedSupportRows(context.Background(), readPage, domain, all,
		func(logical, physical uint16, row contract.SupportRecordView) error {
			if logical != physical || row.RecordID != rows[logical].RecordID {
				t.Fatal("selected row order changed")
			}
			visited = append(visited, physical)
			return nil
		})
	if err != nil || result.Outcome != 0 || pageReads != 1 || !slices.Equal(visited, []uint16{0, 1}) {
		t.Fatal("whole selected page was not lent once", result, err, pageReads, visited)
	}
	all.rows[1] = firstDigest
	visited = nil
	result, err = withAuthenticatedSupportRows(context.Background(), readPage, domain, all,
		func(logical, physical uint16, row contract.SupportRecordView) error {
			visited = append(visited, physical)
			return nil
		})
	if err != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidRelation || len(visited) != 0 {
		t.Fatal("callback ran before every selected row was checked", result, err, visited)
	}

	all.rows[1] = digest
	result, err = withAuthenticatedSupportRows(context.Background(), func(context.Context, format.Ref) ([]byte, Result) {
		return body, Result{Reason: ReadUnavailable}
	}, domain, all, func(uint16, uint16, contract.SupportRecordView) error {
		visited = append(visited, 9)
		return nil
	})
	if err != nil || result == (Result{}) || len(visited) != 0 {
		t.Fatal("malformed success result reached consumer", result, err, visited)
	}

	postReadCtx, cancelPostRead := context.WithCancel(context.Background())
	visited = nil
	result, err = withAuthenticatedSupportRows(postReadCtx, func(context.Context, format.Ref) ([]byte, Result) {
		cancelPostRead()
		return body, Result{}
	}, domain, all, func(uint16, uint16, contract.SupportRecordView) error {
		visited = append(visited, 9)
		return nil
	})
	if err != nil || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable || len(visited) != 0 {
		t.Fatal("cancelled read reached consumer", result, err, visited)
	}

	callbackCtx, cancelCallback := context.WithCancel(context.Background())
	visited = nil
	result, err = withAuthenticatedSupportRows(callbackCtx, readPage, domain, all,
		func(logical, physical uint16, row contract.SupportRecordView) error {
			visited = append(visited, logical)
			if logical == 0 {
				cancelCallback()
			}
			return nil
		})
	if err != nil || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable || !slices.Equal(visited, []uint16{0}) {
		t.Fatal("cancelled callback reached another row or returned success", result, err, visited)
	}

	lastCtx, cancelLast := context.WithCancel(context.Background())
	visited = nil
	result, err = withAuthenticatedSupportRows(lastCtx, readPage, domain, all,
		func(logical, physical uint16, row contract.SupportRecordView) error {
			visited = append(visited, logical)
			if logical == 1 {
				cancelLast()
			}
			return nil
		})
	if err != nil || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable || !slices.Equal(visited, []uint16{0, 1}) {
		t.Fatal("last callback cancellation returned success", result, err, visited)
	}
}

// full_only: false
func TestSelectedConfigurationThreeSlicesChargePhysicalReadsAndPreserveFacts(t *testing.T) {
	state := generatedEmptyPredecessor(t)
	state.admission.store.Prefix = "selected-configuration"
	// This fixture proves three selected slices and shared-page read lifetime.
	// The source policy is stored once in addition to the five target policies.
	policy := contract.OutputPolicy{ContractID: "policy", Data: bytes.Repeat([]byte{1}, 480000)}
	configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: state.root.Domain,
		Bindings: []contract.OutputBinding{{DestinationID: "destination", IncarnationID: generatedVectorID(100),
			Destination: contract.OutputDestination{ConfigContractID: "config", ServiceContractID: "service", CanonicalSettings: []byte(`{}`), Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot, Policy: policy}}},
		DefaultDestinations: []string{"destination"}}
	for i := range 5 {
		configuration.Bindings[0].Targets = append(configuration.Bindings[0].Targets, contract.OutputTarget{
			EntryIncarnationID: generatedVectorID(byte(101 + i)), ServiceContractID: "service", CanonicalTarget: fmt.Sprintf("slot-%d", i),
			ConsumerLocator: "locator", TargetContractID: "target", PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot,
			Policy: policy})
	}
	image, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(state.root.Domain, image)
	if err != nil || len(parts) != 3 {
		t.Fatalf("three-slice fixture: parts=%d err=%v", len(parts), err)
	}
	group := format.RequiredSupportGroup{Class: format.OutputConfigurationSupport, Owner: descriptor.ConfigurationDigest, Mandatory: true}
	for _, part := range parts {
		body, err := contract.EncodeOutputConfigurationSlice(part)
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.OutputConfigurationSliceID(state.root.Domain, descriptor.ConfigurationDigest, part.SliceIndex)
		if err != nil {
			t.Fatal(err)
		}
		group.Records = append(group.Records, contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
	}
	packed, err := format.PackRequiredSupportRows(state.root.Domain, []format.RequiredSupportGroup{group}, 2)
	if err != nil || len(packed) != 2 || len(packed[0]) != 2 || len(packed[1]) != 1 {
		t.Fatalf("three slices must use two pages: pages=%d err=%v", len(packed), err)
	}
	state.root.OutputConfiguration = descriptor
	state.root.RequiredSupport, state.support, state.supportFacts = nil, nil, nil
	state.root.RequiredSupportRecordCount = uint32(len(parts))
	state.adminIndex.Pages = nil
	bodies := make(map[string][]byte)
	bySlice := make(map[contract.ID]format.Ref)
	for i, rows := range packed {
		page := format.RequiredSupportPage{Domain: state.root.Domain, Object: generatedVectorID(byte(110 + i)), Index: uint16(i), Records: rows}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatalf("configuration page %d length %d rows %d: %v", i, len(body), len(rows), err)
		}
		key, err := format.Key(state.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		bodies[key] = body
		facts := selectedSupportPageFacts{ref: ref}
		view := format.RequiredSupportPageView{Domain: page.Domain, Object: page.Object, Index: page.Index}
		for ordinal, row := range rows {
			fact, err := contract.InspectSupportRecordDigest(state.root.Domain, row)
			if err != nil {
				t.Fatal(err)
			}
			facts.rows = append(facts.rows, fact)
			facts.ordinals = append(facts.ordinals, uint16(ordinal))
			view.Records = append(view.Records, contract.SupportRecordView{Kind: row.Kind, RecordID: row.RecordID})
			bySlice[row.RecordID] = ref
		}
		state.root.RequiredSupport = append(state.root.RequiredSupport, ref)
		state.support = append(state.support, view)
		state.supportFacts = append(state.supportFacts, facts)
		indexed := format.AdministrativePage{Ref: ref, Spans: []format.AdministrativeSpan{{First: 0, Count: uint16(len(rows)), Mandatory: true}}}
		for _, row := range rows {
			indexed.Rows = append(indexed.Rows, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
		}
		state.adminIndex.Pages = append(state.adminIndex.Pages, indexed)
	}
	valuePage := format.ValueEntryPage{Domain: state.root.Domain, Object: generatedVectorID(112)}
	var coordinateRows []contract.SupportRecordView
	for i, target := range configuration.Bindings[0].Targets {
		name := fmt.Sprintf("plain-%d", i)
		valuePage.Slots[i] = &contract.ValueEntry{Name: name, Incarnation: target.EntryIncarnationID,
			ValueState: generatedVectorID(byte(130 + i)), OriginSnapshot: state.root.Snapshot,
			OriginTransition: state.root.Transition, ValueSource: contract.Supplied,
			ConfidentialityClass: contract.Plain, Recipients: []contract.ID{state.admission.recipient}, ValueBytes: []byte("v"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("v"))), RetainedLength: uint32(len([]byte("v")))}
		state.root.Names = append(state.root.Names, format.NameEntry{Name: name, Slot: uint16(i)})
		id, err := contract.PublicationCoordinateID(state.root.Domain, target.ServiceContractID, target.CanonicalTarget)
		if err != nil {
			t.Fatal(err)
		}
		coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: state.root.Domain, CoordinateID: id,
			ServiceContractID: target.ServiceContractID, CanonicalTarget: target.CanonicalTarget, BindingState: contract.PublicationBindingActive,
			OwnerState: contract.PublicationOwnerNone, ActiveBindingIncarnationID: configuration.Bindings[0].IncarnationID,
			LastBindingIncarnationID: configuration.Bindings[0].IncarnationID, LastEntryIncarnationID: target.EntryIncarnationID,
			CurrentPublicationIncarnationID: generatedVectorID(byte(140 + i))}
		body, err := contract.EncodePublicationCoordinate(coordinate)
		if err != nil {
			t.Fatal(err)
		}
		coordinateRows = append(coordinateRows, contract.SupportRecordView{Kind: contract.PublicationCoordinateSupportKind, RecordID: id, Body: body})
	}
	valueBody, err := format.EncodeValueEntryPage(valuePage)
	if err != nil {
		t.Fatal(err)
	}
	valueRef, err := format.Reference(format.ValueEntryPageKind, valuePage.Domain, valuePage.Object, 0, valueBody)
	if err != nil {
		t.Fatal(err)
	}
	state.pages[0], state.root.ValueEntryPages[0] = &valuePage, &valueRef
	state.root.ValueEntryCount, state.root.MembershipCount, state.root.RawBytes = 5, 5, 5
	for i, page := range state.support {
		for j := range page.Records {
			state.support[i].Records[j] = contract.SupportRecordView(packed[i][j])
		}
	}
	state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain,
		Object: generatedVectorID(113), Index: 2, Records: coordinateRows})
	generatedRefreshSupport(t, state)
	state.supportFacts = make([]selectedSupportPageFacts, len(state.support))
	for i, page := range state.support {
		ref := state.root.RequiredSupport[i]
		rows := make([]contract.SupportRecord, len(page.Records))
		facts := selectedSupportPageFacts{ref: ref}
		for j, row := range page.Records {
			rows[j] = contract.SupportRecord(row)
			fact, err := contract.InspectSupportRecordDigest(state.root.Domain, rows[j])
			if err != nil {
				t.Fatal(err)
			}
			facts.rows, facts.ordinals = append(facts.rows, fact), append(facts.ordinals, uint16(j))
			if row.Kind == contract.OutputConfigurationSliceSupportKind {
				state.support[i].Records[j].Body = nil
			}
		}
		state.supportFacts[i] = facts
		body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(state.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		bodies[key] = body
	}
	shards, err := format.EncodeAdministrativeIndexPages(state.adminIndex)
	if err != nil || len(shards) != 1 {
		t.Fatal("configuration index", err)
	}
	state.root.AdministrativeIndex = shards[0].Ref
	state.recountChildren()
	var expectedBytes uint64
	var expectedKeys []string
	for i := range parts {
		id, err := contract.OutputConfigurationSliceID(state.root.Domain, descriptor.ConfigurationDigest, uint16(i))
		if err != nil {
			t.Fatal(err)
		}
		ref := bySlice[id]
		key, _ := format.Key(state.admission.store.Prefix, ref)
		expectedKeys = append(expectedKeys, key)
		expectedBytes += uint64(ref.Length)
	}
	for _, condition := range []string{"complete", "changed", "missing", "cancelled", "successor", "preserved"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			episode := &storeEpisode{deadline: time.Now().Add(time.Minute)}
			if !episode.beginStage(1) || !episode.readAllowed() {
				t.Fatal("initial observation stage")
			}
			ctx = context.WithValue(ctx, storeEpisodeKey{}, episode)
			if !extendObservedReadStage(ctx, uint64(descriptor.SliceCount)) {
				t.Fatal("configuration read allowance")
			}
			store := &readFailureStore{}
			borrowed := make([]byte, format.MaxRequiredSupportPage)
			store.onReadCtx = func(context.Context) (contract.ReadResult, bool) {
				call := len(store.keys)
				if condition == "missing" && call == 2 {
					return contract.ReadResult{Status: contract.ReadMissing}, true
				}
				body := bodies[store.keys[call-1]]
				copy(borrowed, body)
				if condition == "changed" && call == 2 {
					borrowed[len(body)-1] ^= 1
				}
				if condition == "cancelled" && call == 1 {
					cancel()
				}
				return contract.ReadResult{Status: contract.ReadOK, Body: borrowed[:len(body)]}, true
			}
			selected := *state
			selected.store, selected.cache, selected.outputConfigurationRoot = store, nil, contract.ID{}
			result := selected.validateSelectedOutputConfiguration(ctx)
			if condition != "complete" && condition != "successor" && condition != "preserved" {
				if result.Outcome == 0 || selected.selectedOutputComplete() {
					t.Fatal("failed read issued a configuration proof", result)
				}
				return
			}
			if result.Outcome != 0 || !selected.selectedOutputComplete() || !slices.Equal(store.keys, expectedKeys) || episode.stageReads != 4 || episode.readLimit != 10 || episode.stages != 1 {
				t.Fatal("canonical stream or exact stage accounting failed", result, store.keys, episode)
			}
			var readBytes uint64
			for _, length := range store.limits {
				readBytes += uint64(length)
			}
			if readBytes != expectedBytes || readBytes <= uint64(state.root.RequiredSupport[0].Length)+uint64(state.root.RequiredSupport[1].Length) {
				t.Fatal("shared physical page reread was not charged", readBytes, expectedBytes)
			}
			for _, page := range selected.support {
				for _, row := range page.Records {
					if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body != nil {
						t.Fatal("configuration slice escaped its read lifetime")
					}
				}
			}
			if len(selected.cache) != 0 {
				t.Fatal("configuration physical bytes remained cached")
			}
			if condition == "successor" {
				selectedConfigurationReceiptSuccessor(t, ctx, &selected, episode, store, expectedBytes)
			}
			if condition == "preserved" {
				if err := selected.bindPreservedPublication(ctx, &selected); err != nil {
					t.Fatal("complete publication before preservation", err)
				}
				original := selected
				borrowedProjection, err := selected.preservedState(ctx, contract.SuccessionChangeNormalSigner, false)
				if err != nil {
					t.Fatal("multi-page borrowed configuration preservation", err)
				}
				backed := selected
				backed.support = slices.Clone(selected.support)
				for i, ref := range selected.root.RequiredSupport {
					key, err := format.Key(selected.admission.store.Prefix, ref)
					if err != nil {
						t.Fatal(err)
					}
					view, err := format.InspectRequiredSupportPage(bodies[key])
					if err != nil {
						t.Fatal(err)
					}
					backed.support[i] = view
				}
				backedProjection, err := backed.preservedState(ctx, contract.SuccessionChangeNormalSigner, false)
				if err != nil || backedProjection != borrowedProjection || !reflect.DeepEqual(selected, original) {
					t.Fatal("exact multi-page preservation identity or predecessor changed", err)
				}
				var actual uint64
				for _, length := range store.limits {
					actual += uint64(length)
				}
				if actual != 3*expectedBytes || episode.stageReads != 10 || episode.readLimit != 10 || !slices.Equal(store.keys, append(append(slices.Clone(expectedKeys), expectedKeys...), expectedKeys...)) {
					t.Fatal("multi-page preservation physical reads differ", actual, episode, store.keys)
				}
				if len(selected.cache) != 0 {
					t.Fatal("preservation retained physical configuration backing")
				}
				for _, page := range selected.support {
					for _, row := range page.Records {
						if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body != nil {
							t.Fatal("preservation retained configuration Body")
						}
					}
				}
				// A new bounded projection stage fails after one exact row was
				// hashed. Earlier grammar/publication checks have already passed.
				if !episode.beginStage(int(descriptor.SliceCount)) {
					t.Fatal("preservation refusal stage")
				}
				start := len(store.keys)
				originalRead := store.onReadCtx
				injected := false
				store.onReadCtx = func(readContext context.Context) (contract.ReadResult, bool) {
					if len(store.keys) == start+2 {
						injected = true
						return contract.ReadResult{Status: contract.ReadMissing}, true
					}
					return originalRead(readContext)
				}
				failedProjection, err := selected.preservedState(ctx, contract.SuccessionChangeNormalSigner, false)
				if err == nil || failedProjection != (contract.DigestLength{}) || !injected ||
					len(store.keys)-start != 2 || !slices.Equal(store.keys[start:], expectedKeys[:2]) ||
					episode.stageReads != 2 || episode.readLimit != int(descriptor.SliceCount) || episode.stages != 2 {
					t.Fatal("later preserved-row failure was not observed exactly", failedProjection, err, injected, store.keys[start:], episode)
				}
				var refusedBytes uint64
				for _, length := range store.limits[start:] {
					refusedBytes += uint64(length)
				}
				if refusedBytes != 2*uint64(selected.root.RequiredSupport[0].Length) ||
					!reflect.DeepEqual(selected, original) || !selected.selectedOutputComplete() ||
					!selected.publicationProof.validFor(selected.selectedImage()) || len(selected.cache) != 0 {
					t.Fatal("later refusal changed exact read accounting or predecessor", refusedBytes)
				}
				for _, page := range selected.support {
					for _, row := range page.Records {
						if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body != nil {
							t.Fatal("later refused preservation retained configuration Body")
						}
					}
				}

			}
			next := selected
			next.root.Transition = generatedVectorID(120)
			if next.selectedOutputComplete() {
				t.Fatal("old grammar proof survived changed Root")
			}
			if err := selected.bindPreservedOutputConfiguration(&next); err != nil || !next.selectedOutputComplete() || !slices.Equal(next.root.RequiredSupport, selected.root.RequiredSupport) || next.root.OutputConfiguration != selected.root.OutputConfiguration {
				t.Fatal("exact configuration preservation failed", err)
			}
			for _, page := range next.support {
				for _, row := range page.Records {
					if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body != nil {
						t.Fatal("preservation retained slice bytes")
					}
				}
			}
		})
	}
}

func selectedConfigurationReceiptSuccessor(t testing.TB, ctx context.Context, selected *StateSession,
	episode *storeEpisode, store *readFailureStore, readBytes uint64) {
	t.Helper()
	original := *selected
	before, err := selected.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	row := contract.CompactMutationReceiptPlan{Schema: contract.MutationReceiptSchema, OperationKind: 36, DomainID: selected.root.Domain,
		OperationID:           generatedVectorID(150),
		PredecessorRevisionID: generatedVectorID(151), RequestedRevisionID: generatedVectorID(152), ObservedRevisionID: generatedVectorID(152),
		StateResult: 1, EvidenceCeiling: 1, CanonicalOutcome: 1,
		ChangedSubjects: contract.GeneratorDescriptor{Digest: generatedVectorID(153), Length: 4},
		CompleteResult:  contract.GeneratorDescriptor{Digest: generatedVectorID(154), Length: 8 + contract.MutationResultProjectionLength, Count: 1}}
	delta := contract.MutationReceiptDeltaPlan{DomainID: selected.root.Domain, OperationKind: row.OperationKind, AddedCount: 1, Before: before, NewReceipt: row}
	plan := transitionPlan{snapshot: generatedVectorID(155), transition: generatedVectorID(156), revision: row.RequestedRevisionID}
	indexes, err := selected.mutationReceiptPageIndexes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range indexes {
		plan.supportPages[index] = contract.Hash([]byte(fmt.Sprintf("configuration receipt page/%d", index)))
	}
	storage, err := selected.encodeMutationReceiptSupport(ctx, plan, delta, contract.ID{})
	if err != nil {
		t.Fatal(err)
	}
	next := *selected
	next.root.Snapshot, next.root.Transition = plan.snapshot, plan.transition
	storage.install(&next)
	if err := selected.installAdministrativeIndex(ctx, &next, &Candidate{session: selected}, &row); err != nil {
		t.Fatal("configuration receipt plan", err)
	}
	if next.publicationProof != nil || !next.outputConfigurationRoot.IsZero() {
		t.Fatal("provisional receipt acquired complete proof")
	}
	storage, err = selected.encodeMutationReceiptSupport(ctx, plan, delta, generatedVectorID(157))
	if err != nil {
		t.Fatal(err)
	}
	storage.install(&next)
	if err := selected.installAdministrativeIndex(ctx, &next, &Candidate{session: selected}); err != nil {
		t.Fatal("sealed configuration receipt", err)
	}
	if next.publicationProof == nil || !next.publicationProof.validFor(next.selectedImage()) || !next.selectedOutputComplete() ||
		!reflect.DeepEqual(*selected, original) || next.root.OutputConfiguration != selected.root.OutputConfiguration {
		t.Fatal("sealed successor changed configuration or its predecessor")
	}
	for _, ref := range selected.root.RequiredSupport {
		if !slices.Contains(next.root.RequiredSupport, ref) {
			t.Fatal("selected configuration or coordinate page changed")
		}
	}
	var actual uint64
	for _, length := range store.limits {
		actual += uint64(length)
	}
	if actual != 3*readBytes || episode.stageReads != 10 || episode.readLimit != 10 {
		t.Fatal("receipt phases exceeded exact configuration read accounting", actual, episode)
	}
	for _, page := range next.support {
		for _, row := range page.Records {
			if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body != nil {
				t.Fatal("receipt successor retained configuration body")
			}
		}
	}
}

// full_only: false
func TestSelectedMixedConfigurationPageReleasesPhysicalBacking(t *testing.T) {
	for _, condition := range []string{"selected", "unselected"} {
		t.Run(condition, func(t *testing.T) {
			state, _ := publicationEmptyConfigurationImage(t, true)
			state.admission.store.Prefix = "fixture"
			var configuration, coordinate, marker contract.SupportRecordView
			for _, page := range state.support {
				for _, row := range page.Records {
					switch row.Kind {
					case contract.OutputConfigurationSliceSupportKind:
						configuration = row
					case contract.PublicationCoordinateSupportKind:
						coordinate = row
					case contract.PublicationMarkerSupportKind:
						marker = row
					}
				}
			}
			if condition == "selected" {
				state.support = []format.RequiredSupportPageView{
					{Domain: state.root.Domain, Object: generatedVectorID(67), Index: 0, Records: []contract.SupportRecordView{configuration, coordinate}},
					{Domain: state.root.Domain, Object: generatedVectorID(68), Index: 1, Records: []contract.SupportRecordView{marker}},
				}
			}
			generatedRefreshSupport(t, state)
			state.recountChildren()
			if !state.indexSelectedMaterials() {
				t.Fatal("mixed selected image material index")
			}
			bodies := make(map[format.Ref][]byte)
			mixedPosition := -1
			for position, page := range state.support {
				rows := make([]contract.SupportRecord, len(page.Records))
				for i, row := range page.Records {
					rows[i] = contract.SupportRecord(row)
				}
				if slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
					return row.Kind == contract.PublicationCoordinateSupportKind
				}) {
					mixedPosition = position
					if condition == "unselected" {
						rows = append([]contract.SupportRecord{contract.SupportRecord(configuration)}, rows...)
						for i := range state.adminIndex.Pages[position].Spans {
							state.adminIndex.Pages[position].Spans[i].First++
						}
					}
				}
				body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: rows})
				if err != nil {
					t.Fatal(err)
				}
				ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
				if err != nil {
					t.Fatal(err)
				}
				bodies[ref] = body
				state.root.RequiredSupport[position], state.adminIndex.Pages[position].Ref = ref, ref
				// Physical backing changed; the selected logical rows did not.
				state.supportFacts[position].ref = ref
				if condition == "unselected" && position == mixedPosition {
					for i := range state.supportFacts[position].ordinals {
						state.supportFacts[position].ordinals[i]++
					}
				}
			}
			for _, page := range state.recipients {
				if page == nil {
					continue
				}
				body, err := format.EncodeRecipientPage(*page)
				if err != nil {
					t.Fatal(err)
				}
				bodies[*state.root.Recipients[page.Index]] = body
			}
			if mixedPosition < 0 {
				t.Fatal("mixed coordinate page absent")
			}
			shards, err := format.EncodeAdministrativeIndexPages(state.adminIndex)
			if err != nil {
				t.Fatal(err)
			}
			for _, shard := range shards {
				bodies[shard.Ref] = shard.Body
			}
			state.root.AdministrativeIndex = shards[0].Ref
			state.recountChildren()
			rootBody, err := format.EncodeRoot(state.root)
			if err != nil {
				t.Fatal(err)
			}
			state.head.Core.Root, err = format.Reference(format.RootKind, state.root.Domain, state.root.Snapshot, 0, rootBody)
			if err != nil {
				t.Fatal(err)
			}
			bodies[state.head.Core.Root] = rootBody
			authority := state.authority()
			state.head.AuthKind = format.LifecycleAuth
			state.head.Subject.AfterAccessRoot = state.root.CurrentAccess.AccessRoot
			state.head.Subject.Recipient, state.head.Subject.KeyBinding = authority.RecipientID, authority.CurrentBinding.BindingID
			state.head.Subject.Fingerprint, state.head.Subject.BindingVersion = authority.CurrentBinding.Fingerprint, authority.CurrentBinding.BindingSerial
			state.head.Subject.Normal.PublicState = state.publicState()
			state.head.Subject.Grant.Grants = grantCommitment(state.root.Domain, nil)
			state.head.Subject.Exclusion.Exclusions = exclusionCommitment(state.root.Domain, nil)
			state.head.Subject.Exclusion.Retirements = retirementCommitment(state.root.Domain)
			store := &readFailureStore{}
			byKey := make(map[string][]byte)
			for ref, body := range bodies {
				key, err := format.Key(state.admission.store.Prefix, ref)
				if err != nil {
					t.Fatal(err)
				}
				byKey[key] = body
			}
			store.onReadCtx = func(context.Context) (contract.ReadResult, bool) {
				return contract.ReadResult{Status: contract.ReadOK, Body: byKey[store.keys[len(store.keys)-1]]}, true
			}
			state.store, state.cache = store, bodies
			selected, result := state.readImageFromHead(t.Context(), authenticatedHead{head: state.head, body: state.body, token: state.token}, true, false)
			if result.Outcome != ObservedCurrent || selected == nil {
				t.Fatal("complete mixed configuration read refused", result)
			}
			mixedRef := state.root.RequiredSupport[mixedPosition]
			physical := bodies[mixedRef]
			start := uintptr(unsafe.Pointer(&physical[0]))
			end := start + uintptr(len(physical))
			for _, row := range selected.support[mixedPosition].Records {
				if row.Kind == contract.OutputConfigurationSliceSupportKind {
					if row.Body != nil {
						t.Fatal("configuration body retained")
					}
					continue
				}
				if !bytes.Equal(row.Body, coordinate.Body) {
					t.Fatal("surviving coordinate bytes changed")
				}
				address := uintptr(unsafe.Pointer(&row.Body[0]))
				if address >= start && address < end {
					t.Fatal("surviving small body retains the physical configuration allocation")
				}
			}
			if _, retained := selected.cache[mixedRef]; retained {
				t.Fatal("mixed opaque physical page remains cached")
			}
		})
	}
}

// full_only: false
func TestSelectedSupportPageRefusesMixedGeneratedFragments(t *testing.T) {
	domain, coordinate, _, _ := publicationRelationFixture(t)
	coordinateBody, err := contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	fragment := generatedMaterializerFragment(t, generatedVectorID(8), []byte("opaque generated fragment"))
	page := format.RequiredSupportPage{Domain: domain, Object: generatedVectorID(67), Index: 0, Records: []contract.SupportRecord{fragment}}
	body, err := format.EncodeRequiredSupportPage(page)
	if err != nil {
		t.Fatal(err)
	}
	row := contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinate.CoordinateID, Body: coordinateBody}
	page.Records = append(page.Records, row)
	if _, err := format.EncodeRequiredSupportPage(page); err == nil {
		t.Fatal("encoder admitted a mixed generated-fragment page")
	}
	// Frame the forbidden second row directly so encoder refusal cannot hide
	// an inspector or selected-directory acceptance.
	binary.BigEndian.PutUint16(body[contract.RequiredSupportPageHeaderLength-2:], 2)
	body = append(body, row.Kind)
	body = append(body, row.RecordID[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(row.Body)))
	body = append(body, row.Body...)
	if _, err := format.InspectRequiredSupportPage(body); err == nil {
		t.Fatal("inspector admitted a mixed generated-fragment page")
	}
	view := format.RequiredSupportPageView{Domain: domain, Object: page.Object, Index: page.Index,
		Records: []contract.SupportRecordView{contract.SupportRecordView(fragment), contract.SupportRecordView(row)}}
	directory := []format.FragmentLocation{{BlobID: generatedVectorID(8), FragmentIndex: 0, SupportPageIndex: page.Index, RowSlot: 0}}
	fragmentOnly := view
	fragmentOnly.Records = fragmentOnly.Records[:1]
	if err := format.ValidateFragmentDirectory(directory, []format.RequiredSupportPageView{fragmentOnly}); err != nil {
		t.Fatalf("fragment-only control refused: %v", err)
	}
	if err := format.ValidateFragmentDirectory(directory, []format.RequiredSupportPageView{view}); err == nil {
		t.Fatal("selected directory admitted a mixed generated-fragment page")
	}
}
