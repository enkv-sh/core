package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type operatorAdvanceSupportRow struct {
	fact               format.AdministrativeRowSummary
	body               []byte
	bodyDigest         contract.ID
	groups             []uint16
	mandatory, carrier bool
	page               uint16
}

// Optional bodies stay unread. The authenticated summaries already commit their
// complete identities, lengths and ownership. Exact selected facts also retain
// each body digest; equal ID and length alone do not prove an unchanged body.
func operatorAdvanceSupportRows(selected *StateSession) ([]operatorAdvanceSupportRow, error) {
	var rows []operatorAdvanceSupportRow
	for pagePosition, page := range selected.adminIndex.Pages {
		position, ok := selected.selectedSupportPosition(page.Ref)
		if !ok || position != pagePosition || len(selected.root.RequiredSupport) != len(selected.adminIndex.Pages) {
			return nil, contract.ErrRecord
		}
		facts := selected.supportFacts[position]
		if len(facts.rows) != len(facts.ordinals) {
			return nil, contract.ErrRecord
		}
		var loaded []contract.SupportRecordView
		if page.ReadRequired {
			view, err := selected.administrativeSelectedSupportPage(page)
			if err != nil {
				return nil, err
			}
			loaded = view.Records
		}
		position = 0
		for _, span := range page.Spans {
			for offset := uint32(0); offset < uint32(span.Count); offset++ {
				row := operatorAdvanceSupportRow{groups: slices.Clone(span.GroupIndexes), mandatory: span.Mandatory,
					carrier: page.ReadRequired, page: page.Ref.Index}
				if page.ReadRequired {
					if position >= len(loaded) {
						return nil, contract.ErrRecord
					}
					v := loaded[position]
					row.fact = format.AdministrativeRowSummary{Kind: v.Kind, RecordID: v.RecordID, BodyLength: uint32(len(v.Body))}
					row.body = bytes.Clone(v.Body)
				} else {
					if position >= len(page.Rows) {
						return nil, contract.ErrRecord
					}
					row.fact = page.Rows[position]
				}
				position++
				if row.carrier || len(row.groups) != 0 {
					ordinal := uint32(span.First) + offset
					if position > len(facts.rows) || ordinal > uint32(^uint16(0)) || facts.ordinals[position-1] != uint16(ordinal) {
						return nil, contract.ErrRecord
					}
					fact := facts.rows[position-1]
					if fact.Kind() != row.fact.Kind || fact.RecordID() != row.fact.RecordID || fact.BodyLength() != row.fact.BodyLength {
						return nil, contract.ErrRecord
					}
					row.bodyDigest = fact.BodyDigest()
					if row.bodyDigest.IsZero() || row.carrier && row.bodyDigest != contract.ID(sha256.Sum256(row.body)) {
						return nil, contract.ErrRecord
					}
					rows = append(rows, row)
				}
			}
		}
		if page.ReadRequired && position != len(loaded) || !page.ReadRequired && position != len(page.Rows) {
			return nil, contract.ErrRecord
		}
	}
	return rows, nil
}

// The normal handoff changes only the Snapshot owner in each Slice carrier.
// Expected bytes and IDs below use the contract framing, not its encoder or ID
// helper. The logical vector and Row remain the exact predecessor bytes.
func operatorAdvanceExpectedGroups(groups []format.AdministrativeGroup, before, after []operatorAdvanceSupportRow,
	domain, oldSnapshot, newSnapshot contract.ID) ([]format.AdministrativeGroup, error) {
	if domain.IsZero() || oldSnapshot.IsZero() || newSnapshot.IsZero() || oldSnapshot == newSnapshot {
		return nil, contract.ErrRecord
	}
	expected := make(map[generatedRecordKey]operatorAdvanceSupportRow, len(before))
	for _, row := range before {
		if row.carrier {
			c, err := contract.InspectGeneratorVectorCarrier(row.body)
			if err != nil || row.fact.Kind != contract.GeneratorVectorSupportKind || c.DomainID != domain ||
				c.OwnerKind != contract.GeneratorSnapshotOwner || c.OwnerID != oldSnapshot || c.VectorKind != contract.GeneratorVectorSlices ||
				row.fact.BodyLength != uint32(len(row.body)) || !row.fact.MaterialID.IsZero() {
				return nil, contract.ErrRecord
			}
			identity := append([]byte(nil), domain[:]...)
			identity = append(identity, c.OwnerKind)
			identity = append(identity, newSnapshot[:]...)
			identity = append(identity, byte(c.VectorKind))
			identity = append(identity, c.Vector.Digest[:]...)
			identity = binary.BigEndian.AppendUint64(identity, c.Vector.Length)
			identity = binary.BigEndian.AppendUint32(identity, c.Vector.Count)
			identity = binary.BigEndian.AppendUint32(identity, c.Ordinal)
			preimage := []byte("ENKV/GENERATOR/v1/support-vector-row\x00")
			preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(identity)))
			row.fact.RecordID = contract.ID(sha256.Sum256(append(preimage, identity...)))
			row.body = bytes.Clone(row.body)
			copy(row.body[35:67], newSnapshot[:])
			row.bodyDigest = contract.ID(sha256.Sum256(row.body))
		}
		key := generatedRecordKey{row.fact.Kind, row.fact.RecordID}
		if _, duplicate := expected[key]; duplicate {
			return nil, contract.ErrRecord
		}
		expected[key] = row
	}
	if len(after) != len(expected) {
		return nil, contract.ErrRecord
	}
	ordered := make([]operatorAdvanceSupportRow, 0, len(after))
	for _, actual := range after {
		key := generatedRecordKey{actual.fact.Kind, actual.fact.RecordID}
		want, present := expected[key]
		if !present || want.fact != actual.fact || want.bodyDigest != actual.bodyDigest || want.mandatory != actual.mandatory || want.carrier != actual.carrier ||
			!slices.Equal(want.groups, actual.groups) || !bytes.Equal(want.body, actual.body) {
			return nil, contract.ErrRecord
		}
		delete(expected, key)
		want.page = actual.page
		ordered = append(ordered, want)
	}
	out := slices.Clone(groups)
	for i := range out {
		var count uint32
		var charge uint64
		pages := map[uint16]bool{}
		for _, row := range ordered {
			for _, owner := range row.groups {
				if int(owner) >= len(out) {
					return nil, contract.ErrRecord
				}
				if int(owner) == i {
					count++
					charge += 37 + uint64(row.fact.BodyLength)
					pages[row.page] = true
				}
			}
		}
		if count != groups[i].Disposable.Count || groups[i].Disposable.Length != 4+41*uint64(count) ||
			charge != groups[i].ChargedBytes || len(pages) != int(groups[i].ChargedPages) {
			return nil, contract.ErrRecord
		}
		framed := binary.BigEndian.AppendUint32([]byte("ENKV/admin-descriptor/v1/selected-disposable\x00"), count)
		for _, row := range ordered {
			if !slices.Contains(row.groups, uint16(i)) {
				continue
			}
			framed = binary.BigEndian.AppendUint32(framed, 37)
			framed = append(framed, row.fact.Kind)
			framed = append(framed, row.fact.RecordID[:]...)
			framed = binary.BigEndian.AppendUint32(framed, row.fact.BodyLength)
		}
		out[i].Disposable = contract.GeneratorDescriptor{Digest: contract.ID(sha256.Sum256(framed)), Length: 4 + 41*uint64(count), Count: count}
	}
	return out, nil
}

// full_only: false
func TestPublicOperatorOrdinaryAdvancePreservesExactOwnedSupport(t *testing.T) {
	env, keys := genesisEnvironment(t, liveFamily, true)
	admission := fixtureAdmission(env)
	init, _ := fixtureInitAdmission(t, env, admission)
	initial, result := Initialize(t.Context(), init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto)
	if initial == nil || result.Outcome != ObservedCurrent {
		t.Fatal("ordinary preservation fixture initialization refused")
	}
	keys.RetireInit()
	current := publicOperatorSelectedWork(t, env, initial, fixtureID(env.Domain, "reader"))
	before, err := operatorAdvanceSupportRows(current)
	if err != nil {
		t.Fatal("ordinary preservation predecessor unavailable")
	}
	run := newScenarioRun(t, t.Context(), env)
	wanted := append(current.currentEntryInputs(), ApplyEntryInput{Name: "ordinary-preservation", Recipients: []contract.ID{current.admission.recipient},
		ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("ordinary-preservation"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	next, result := current.selectCandidate(t.Context(), run.suppliedCandidate(current, wanted))
	if next == nil || result.Outcome != ObservedCurrent {
		t.Fatal("ordinary preservation successor refused")
	}
	after, err := operatorAdvanceSupportRows(next)
	if err != nil {
		t.Fatal("ordinary preservation successor unavailable")
	}
	check := func(rows []operatorAdvanceSupportRow, groups []format.AdministrativeGroup) bool {
		want, err := operatorAdvanceExpectedGroups(current.adminIndex.Groups, before, rows, current.root.Domain,
			current.adminIndex.SliceSnapshot, next.root.Snapshot)
		return err == nil && reflect.DeepEqual(want, groups)
	}
	if !check(after, next.adminIndex.Groups) || reflect.DeepEqual(current.adminIndex.Groups, next.adminIndex.Groups) {
		t.Fatal("fixture did not prove valid changed Disposable with exact retained work")
	}
	carrier, owned := -1, -1
	for i, row := range after {
		if row.carrier && len(row.groups) != 0 {
			carrier = i
		}
		if !row.carrier && len(row.groups) != 0 {
			owned = i
		}
	}
	if carrier < 0 || owned < 0 || len(after[carrier].body) <= 120 || len(next.adminIndex.Groups) != 1 {
		t.Fatal("fixture lacks complete carrier and ordinary owned row damage controls")
	}
	duty, dutyFact, dutyPage, dutySlot := -1, contract.ID{}, -1, -1
	for page, view := range next.support {
		for slot, row := range view.Records {
			if row.Kind != contract.GeneratedDutySupportKind {
				continue
			}
			old, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				t.Fatal("ordinary preservation Duty damage input unavailable")
			}
			changed := old
			changed.Step = old.Step%8 + 1
			body, err := contract.EncodeGeneratedDutyRecord(changed)
			if err != nil || len(body) != len(row.Body) || changed.DutyID != row.RecordID || bytes.Equal(body, row.Body) {
				t.Fatal("ordinary preservation damage did not retain a legal same-ID same-length Duty")
			}
			fact, err := contract.InspectSupportRecordDigest(next.root.Domain, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: body})
			if err != nil {
				t.Fatal("ordinary preservation changed Duty is not structurally valid")
			}
			for i, selected := range after {
				if selected.fact.Kind == row.Kind && selected.fact.RecordID == row.RecordID && len(selected.groups) != 0 {
					if selected.fact.BodyLength != fact.BodyLength() || selected.bodyDigest == fact.BodyDigest() {
						t.Fatal("ordinary preservation same-ID body damage is vacuous")
					}
					duty, dutyFact, dutyPage, dutySlot = i, fact.BodyDigest(), page, slot
				}
			}
		}
	}
	if duty < 0 {
		t.Fatal("ordinary preservation fixture has no independently valid same-ID body mutation")
	}
	for _, damage := range []string{"identity", "owner", "target", "duty-kind", "evidence", "exposure", "affected", "dependencies", "disposable", "count", "length", "page-charge", "byte-charge", "ownership", "mandatory", "material", "row-id", "row-length", "owned-body-same-id-and-length", "carrier-body-digest", "carrier-domain", "carrier-vector", "carrier-row", "carrier-owner", "missing", "extra"} {
		t.Run(damage, func(t *testing.T) {
			rows, groups := slices.Clone(after), slices.Clone(next.adminIndex.Groups)
			switch damage {
			case "identity":
				groups[0].GroupID[0] ^= 1
			case "owner":
				groups[0].OwnerID[0] ^= 1
			case "target":
				groups[0].TargetID[0] ^= 1
			case "duty-kind":
				groups[0].DutyKind ^= 1
			case "evidence":
				groups[0].SelectedEvidenceSummary ^= 1
			case "exposure":
				groups[0].DestructiveEffect ^= 1
			case "affected":
				groups[0].Affected.Digest[0] ^= 1
			case "dependencies":
				groups[0].Dependencies.Digest[0] ^= 1
			case "disposable":
				groups[0].Disposable.Digest[0] ^= 1
			case "count":
				groups[0].Disposable.Count++
			case "length":
				groups[0].Disposable.Length++
			case "page-charge":
				groups[0].ChargedPages++
			case "byte-charge":
				groups[0].ChargedBytes++
			case "ownership":
				rows[owned].groups = nil
			case "mandatory":
				rows[owned].mandatory = !rows[owned].mandatory
			case "material":
				rows[owned].fact.MaterialID[0] ^= 1
			case "row-id":
				rows[owned].fact.RecordID[0] ^= 1
			case "row-length":
				rows[owned].fact.BodyLength++
			case "owned-body-same-id-and-length":
				rows[duty].bodyDigest = dutyFact
			case "carrier-body-digest":
				rows[carrier].bodyDigest[0] ^= 1
			case "carrier-domain", "carrier-vector", "carrier-row", "carrier-owner":
				offset := map[string]int{"carrier-domain": 2, "carrier-vector": 72, "carrier-row": 120, "carrier-owner": 35}[damage]
				rows[carrier].body = bytes.Clone(rows[carrier].body)
				rows[carrier].body[offset] ^= 1
			case "missing":
				rows = rows[:len(rows)-1]
			case "extra":
				rows = append(rows, rows[owned])
			}
			if check(rows, groups) {
				t.Fatal("ordinary advancement admitted unexplained retained-work damage")
			}
		})
	}
	for _, damage := range []string{"fact-ref", "fact-ordinal"} {
		t.Run(damage, func(t *testing.T) {
			changed := *next
			changed.supportFacts = slices.Clone(next.supportFacts)
			if damage == "fact-ref" {
				changed.supportFacts[dutyPage].ref.Object[0] ^= 1
			} else {
				changed.supportFacts[dutyPage].ordinals = slices.Clone(next.supportFacts[dutyPage].ordinals)
				changed.supportFacts[dutyPage].ordinals[dutySlot] ^= 1
			}
			if _, err := operatorAdvanceSupportRows(&changed); err == nil {
				t.Fatal("ordinary support fact lost its exact selected Ref or physical ordinal")
			}
		})
	}
}
