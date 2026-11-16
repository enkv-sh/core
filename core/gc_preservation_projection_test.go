package core

import (
	"slices"
	"strconv"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func gcProjectionCopy(s *StateSession) *StateSession {
	next := *s
	next.root.RequiredSupport = slices.Clone(s.root.RequiredSupport)
	next.adminIndex = clonePublicationWork(s.adminIndex)
	next.support = slices.Clone(s.support)
	return &next
}

// Repage only complete GC plan rows through actual page encoders. The
// projection test does not publish the resulting hypothetical successor.
func gcProjectionRepage(t testing.TB, source *StateSession, split bool) *StateSession {
	t.Helper()
	next := gcProjectionCopy(source)
	var records []contract.SupportRecord
	var pages []format.AdministrativePage
	views := make(map[format.Ref]format.RequiredSupportPageView)
	first, maximum := uint16(contract.MaxChildPages), uint16(0)
	for i, page := range source.adminIndex.Pages {
		maximum = max(maximum, page.Ref.Index)
		if len(page.Rows) != 0 && !slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool { return row.Kind != contract.GCPlanSupportKind }) {
			first = min(first, page.Ref.Index)
			for _, row := range source.support[i].Records {
				records = append(records, contract.SupportRecord(row))
			}
		} else {
			pages = append(pages, page)
			views[page.Ref] = source.support[i]
		}
	}
	if len(records) != 2 {
		t.Fatal("projection fixture needs exactly two retained plans")
	}
	groups := [][]contract.SupportRecord{records}
	if split {
		groups = [][]contract.SupportRecord{{records[0]}, {records[1]}}
	}
	for i, rows := range groups {
		index := first
		if i != 0 {
			index = maximum + 1
		}
		page := format.RequiredSupportPage{Domain: source.root.Domain, Object: gcTestID("projection-page/" + strconv.FormatBool(split) + "/" + strconv.Itoa(i)), Index: index, Records: rows}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, index, body)
		if err != nil {
			t.Fatal(err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		indexed := format.AdministrativePage{Ref: ref}
		for n, row := range rows {
			owner := slices.IndexFunc(next.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == row.RecordID })
			if owner < 0 {
				t.Fatal("repacked row has no mandatory owner")
			}
			indexed.Spans = append(indexed.Spans, format.AdministrativeSpan{First: uint16(n), Count: 1, GroupIndexes: []uint16{uint16(owner)}})
			indexed.Rows = append(indexed.Rows, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
		}
		pages = append(pages, indexed)
		views[ref] = view
	}
	slices.SortFunc(pages, func(a, b format.AdministrativePage) int { return int(a.Ref.Index) - int(b.Ref.Index) })
	next.adminIndex.Pages, next.root.RequiredSupport, next.support = pages, nil, nil
	for _, page := range pages {
		next.root.RequiredSupport = append(next.root.RequiredSupport, page.Ref)
		next.support = append(next.support, views[page.Ref])
	}
	next.recountChildren()
	return next
}

// full_only: false
func TestGCPreservationOmitsOnlyGCPhysicalPacking(t *testing.T) {
	s, _, _, _ := gcTestSharedSpentState(t)
	operation := gcTestID("unselected-preservation-operation")
	beforeIndex, err := format.EncodeAdministrativeIndex(s.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	want, err := s.gcPreservedCurrent(t.Context(), operation)
	if err != nil {
		t.Fatal(err)
	}
	split := gcProjectionRepage(t, s, true)
	for name, repacked := range map[string]*StateSession{"new-ref": gcProjectionRepage(t, s, false), "split": split, "merge": gcProjectionRepage(t, split, false)} {
		t.Run(name, func(t *testing.T) {
			got, err := repacked.gcPreservedCurrent(t.Context(), operation)
			if err != nil || got != want {
				t.Fatal("GC physical packing changed retained logical commitment", got, want, err)
			}
		})
	}
	afterIndex, err := format.EncodeAdministrativeIndex(s.adminIndex)
	if err != nil || !slices.Equal(beforeIndex, afterIndex) {
		t.Fatal("preservation projection mutated selected page backing", err)
	}
	for _, damage := range []string{"plan digest", "ordinal", "budget", "evidence", "affected", "dependencies", "disposable", "charged bytes", "charged pages", "relation", "ownership", "root owners", "non-GC reference", "mixed reference"} {
		t.Run(damage, func(t *testing.T) {
			next := gcProjectionCopy(s)
			position := slices.IndexFunc(next.adminIndex.Groups, func(group format.AdministrativeGroup) bool { return group.GroupID == next.root.ActiveGC })
			if position < 0 {
				t.Fatal("fixture has no active GC owner")
			}
			group := &next.adminIndex.Groups[position]
			switch damage {
			case "plan digest":
				group.GC.PlanDigest = gcTestID("different-plan")
			case "ordinal":
				group.GC.Ordinal++
			case "budget":
				group.GC.Targets[0].Consumed++
			case "evidence":
				group.GC.Targets[0].Disposition = contract.GCTargetAbsent
				group.GC.Targets[0].EvidenceDigest = gcTestID("absence-witness")
				group.GC.RemainingCount = 0
				group.SelectedEvidenceSummary = group.GC.EvidenceSummary()
			case "affected":
				group.Affected.Digest = gcTestID("different-affected")
			case "dependencies":
				group.Dependencies.Digest = gcTestID("different-dependencies")
			case "disposable":
				group.Disposable.Digest = gcTestID("different-disposable")
			case "charged bytes":
				group.ChargedBytes++
			case "charged pages":
				group.ChargedPages++
			case "relation":
				other := 0
				if position == 0 {
					other = 1
				}
				group.RelatedGroupIndexes = []uint16{uint16(other)}
			case "ownership":
				for i := range next.adminIndex.Pages {
					if len(next.adminIndex.Pages[i].Rows) == 2 && next.adminIndex.Pages[i].Rows[0].Kind == contract.GCPlanSupportKind {
						next.adminIndex.Pages[i].Spans[0].GroupIndexes = slices.Clone(next.adminIndex.Pages[i].Spans[1].GroupIndexes)
					}
				}
			case "root owners":
				next.root.GCPlans.Digest = gcTestID("different-owner-commitment")
			case "non-GC reference":
				next.adminIndex.Pages[0].Ref.Digest = gcTestID("different-non-gc-page")
				next.root.RequiredSupport[0] = next.adminIndex.Pages[0].Ref
			case "mixed reference":
				for i := range next.adminIndex.Pages {
					page := &next.adminIndex.Pages[i]
					if len(page.Rows) == 2 && page.Rows[0].Kind == contract.GCPlanSupportKind {
						page.Ref.Length += contract.SupportRecordMinLength
						page.Ref.Digest = gcTestID("different-mixed-page")
						page.Rows = append(page.Rows, format.AdministrativeRowSummary{Kind: contract.MutationReceiptSupportKind, RecordID: gcTestID("mixed-row"), BodyLength: contract.SupportRecordMinLength - contract.SupportRecordOverhead})
						page.Spans = append(page.Spans, format.AdministrativeSpan{First: 2, Count: 1, Mandatory: true})
						next.root.RequiredSupport[i] = page.Ref
					}
				}
			}
			if damage != "root owners" {
				if descriptor, err := format.GCPlansDescriptor(next.adminIndex); err == nil {
					next.root.GCPlans = descriptor
				}
			}
			got, err := next.gcPreservedCurrent(t.Context(), operation)
			if err == nil && got == want {
				t.Fatal("GC preservation omitted unrelated selected meaning", damage)
			}
		})
	}
}

// full_only: false
func TestGCPreservationCanonicalizesOnlyEquivalentOwnerPartitions(t *testing.T) {
	base, active := gcStateFixture(t, true)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, base))
	if err != nil {
		t.Fatal("reservation with retained GC obligation", err)
	}
	s := reservation.state
	position, spanPosition := -1, -1
	for i, page := range s.adminIndex.Pages {
		for j, span := range page.Spans {
			if span.Count > 1 {
				position, spanPosition = i, j
				break
			}
		}
		if position >= 0 {
			break
		}
	}
	if position < 0 {
		t.Fatal("fixture lacks a multirow non-GC owner span")
	}
	page := s.adminIndex.Pages[position]
	if !page.ReadRequired && slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool { return row.Kind == contract.GCPlanSupportKind }) {
		t.Fatal("partition fixture selected an exempt GC-only page")
	}
	split := gcProjectionCopy(s)
	span := page.Spans[spanPosition]
	first, rest := span, span
	first.Count = 1
	rest.First, rest.Count = span.First+1, span.Count-1
	spans := slices.Clone(page.Spans[:spanPosition])
	spans = append(spans, first, rest)
	split.adminIndex.Pages[position].Spans = append(spans, page.Spans[spanPosition+1:]...)
	if !split.adminIndex.Valid() {
		t.Fatal("nonmaximal current-format index is invalid")
	}
	before, err := format.EncodeAdministrativeIndex(split.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	for name, operation := range map[string]contract.ID{"before selection": gcTestID("partition-new-operation"), "selected operation": active.OperationID} {
		t.Run(name, func(t *testing.T) {
			want, err := s.gcPreservedCurrent(t.Context(), operation)
			if err != nil {
				t.Fatal(err)
			}
			got, err := split.gcPreservedCurrent(t.Context(), operation)
			if err != nil || got != want {
				t.Fatal("equivalent current-format span partition changed preservation", got, want, err)
			}
			for _, damage := range []string{"physical range", "mandatory", "owners", "read required", "page commitment", "summary kind", "summary record", "summary length", "summary material"} {
				t.Run(damage, func(t *testing.T) {
					bad := gcProjectionCopy(split)
					p := &bad.adminIndex.Pages[position]
					switch damage {
					case "physical range":
						p.Spans[len(p.Spans)-1].First++
					case "mandatory":
						p.Spans[spanPosition].Mandatory = !p.Spans[spanPosition].Mandatory
					case "owners":
						if len(p.Spans[spanPosition].GroupIndexes) == 0 {
							p.Spans[spanPosition].GroupIndexes = []uint16{0}
						} else {
							p.Spans[spanPosition].GroupIndexes = nil
						}
					case "read required":
						p.ReadRequired = !p.ReadRequired
					case "page commitment":
						p.Ref.Digest = gcTestID("changed-non-GC-ref")
						bad.root.RequiredSupport[position] = p.Ref
					default:
						if len(p.Rows) == 0 {
							for _, row := range bad.support[position].Records {
								p.Rows = append(p.Rows, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
							}
							p.ReadRequired = false
						}
						if len(p.Rows) == 0 {
							t.Fatal("summary fixture has no rows")
						}
						switch damage {
						case "summary kind":
							p.Rows[0].Kind = contract.GeneratedDutySupportKind
						case "summary record":
							p.Rows[0].RecordID = gcTestID("changed-summary-record")
						case "summary length":
							p.Rows[0].BodyLength++
						case "summary material":
							p.Rows[0].MaterialID = gcTestID("changed-summary-material")
						}
					}
					got, err := bad.gcPreservedCurrent(t.Context(), operation)
					if err == nil && got == want {
						t.Fatal("changed authenticated fact was normalized away", damage)
					}
				})
			}
		})
	}
	after, err := format.EncodeAdministrativeIndex(split.adminIndex)
	if err != nil || !slices.Equal(before, after) {
		t.Fatal("projection mutated selected index backing", err)
	}
}
