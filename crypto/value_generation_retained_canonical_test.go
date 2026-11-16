package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func generatedCanonicalFixture(t *testing.T, kind uint8) (generatedCanonicalSelection, *consumerTestRoute) {
	t.Helper()
	s, route := consumerFixture(t)
	owner := consumerID("canonical owner")
	context, err := contract.ValueMaterialContextDigest(s.Core)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: owner,
		MaterialID: s.Core.ValueStateID, ContextDigest: context, SubjectKind: 2, SubjectID: s.Core.ValueStateID, Purpose: 2})
	if err != nil {
		t.Fatal(err)
	}
	v := generatedCanonicalSelection{Selection: s, Record: contract.RetainedCanonicalRecord{OriginalSlot: s.Slot, Entry: s.Entry},
		Owner: contract.SupportRecord{Kind: kind, RecordID: owner}, Consumers: [][]byte{body}}
	consumers, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, v.Consumers)
	if err != nil {
		t.Fatal(err)
	}
	id := consumerID
	capacity := contract.GeneratorDescriptor{Digest: id("original capacity reservation"), Length: 8, Count: 1}
	if kind == 10 {
		v.Owner.Body, err = contract.EncodeGeneratedDutyRecord(contract.GeneratedDutyRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedDutyRecordSchema, DomainID: s.DomainID, DutyID: owner,
			OriginalOperationID: id("original operation"), OriginalAttemptID: id("original attempt"), OwnerID: owner, ResourceID: id("resource"),
			DescriptorID: id("profile"), ConfigContractID: id("assumption"), ExecutorID: id("executor"), CredentialRouteID: id("provider route"),
			ResourceContractID: id("permission contract"), ResultContractID: id("delete contract"), Kind: contract.GeneratedDutyRetirement,
			CompletionClass: 1, Step: 1, Status: contract.GeneratedEffectTransmitted, Target: contract.EmptyGeneratorVector(contract.GeneratorVectorTargets),
			CapacityReservation: capacity,
			Progress:            contract.EmptyGeneratorVector(contract.GeneratorVectorProgress), History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory),
			Support: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), Consumers: consumers})
	} else {
		v.Owner.Body, err = contract.EncodeGeneratedHazardRecord(contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: s.DomainID, HazardID: owner,
			OriginalOperationID: id("original operation"), OriginalAttemptID: id("original attempt"), OwnerID: id("operation"), ResourceID: id("resource"),
			DescriptorID: id("profile"), ConfigContractID: id("assumption"), ExecutorID: id("executor"), CredentialRouteID: id("provider route"),
			ResourceContractID: id("permission contract"), ResultContractID: id("delete contract"), Exposure: contract.GeneratedExposurePossibleLive,
			CompletionClass: 1, OriginalResults: contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults),
			CapacityReservation: capacity,
			Target:              contract.EmptyGeneratorVector(contract.GeneratorVectorTargets), History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory),
			Support: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), Consumers: consumers})
	}
	if err != nil {
		t.Fatal(err)
	}
	return v, route
}

// full_only: false
func TestGeneratedCanonicalConsumerUsesExactOriginalValue(t *testing.T) {
	for _, kind := range []uint8{10, 11} {
		v, route := generatedCanonicalFixture(t, kind)
		r := newConsumerRuntime(t, route)
		sink := &consumerTestSink{id: consumerID("canonical sink")}
		id := consumerID("canonical admission")
		if err := r.admitGeneratedConsumer(id, consumerID("canonical use"), sink.id, route.CredentialRoute(), v, sink, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		result := r.consumeSelected(context.Background(), id)
		if result.code != contract.CryptoSuccess || result.delivery != consumerDeliveryComplete || sink.accepted != consumerID("secret-value") || len(result.keyUses) != 1 {
			t.Fatal("canonical consumption", result.code, result.delivery)
		}
	}
}

// full_only: false
func TestGeneratedCanonicalConsumerCannotUseClosedRoutes(t *testing.T) {
	for _, kind := range []uint8{10, 11} {
		for _, admitted := range []bool{false, true} {
			t.Run(strconv.Itoa(int(kind))+"/admitted="+strconv.FormatBool(admitted), func(t *testing.T) {
				v, route := generatedCanonicalFixture(t, kind)
				r := newConsumerRuntime(t, route)
				sink := &consumerTestSink{id: consumerID("canonical sink")}
				id := consumerID("canonical admission")
				if admitted {
					if err := r.admitGeneratedConsumer(id, consumerID("canonical use"), sink.id, route.CredentialRoute(), v, sink, time.Now().Add(time.Minute)); err != nil {
						t.Fatal(err)
					}
				}
				r.Close()
				if got := r.consumeSelected(context.Background(), id); got.code == contract.CryptoSuccess || got.delivery != consumerDeliveryNone || len(got.keyUses) != 0 {
					t.Fatal("closed route delivered a retained canonical value", got)
				}
				closes := 0
				if admitted {
					closes = 1
				}
				if sink.accepts != 0 || sink.closes != closes || route.publicCalls != 0 || route.privateCalls != 0 {
					t.Fatal("closed consumer acquired a key or changed sink ownership")
				}
				next := &consumerTestSink{id: consumerID("new canonical sink")}
				if err := r.admitGeneratedConsumer(consumerID("new canonical admission"), consumerID("canonical use"), next.id,
					route.CredentialRoute(), v, next, time.Now().Add(time.Minute)); err == nil || next.accepts != 0 || next.closes != 0 || route.privateCalls != 0 {
					t.Fatal("closed route accepted new consumer ownership", err)
				}
			})
		}
	}
}

func generatedCanonicalConsumers(t *testing.T, v *generatedCanonicalSelection, rows [][]byte) {
	t.Helper()
	descriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, rows)
	if err != nil {
		t.Fatal(err)
	}
	v.Consumers = rows
	if v.Owner.Kind == 10 {
		owner, err := contract.InspectGeneratedDutyRecord(v.Owner.Body)
		if err != nil {
			t.Fatal(err)
		}
		owner.Consumers = descriptor
		v.Owner.Body, err = contract.EncodeGeneratedDutyRecord(owner)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		owner, err := contract.InspectGeneratedHazardRecord(v.Owner.Body)
		if err != nil {
			t.Fatal(err)
		}
		owner.Consumers = descriptor
		v.Owner.Body, err = contract.EncodeGeneratedHazardRecord(owner)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func generatedVectorSupport(t *testing.T, domain contract.ID, ownerKind uint8, owner contract.ID, kind contract.GeneratorVectorKind, rows [][]byte) []contract.SupportRecord {
	t.Helper()
	descriptor, err := contract.GeneratorVectorDescriptor(kind, rows)
	if err != nil {
		t.Fatal(err)
	}
	var result []contract.SupportRecord
	for i, row := range rows {
		carrier := contract.GeneratorVectorCarrier{Schema: 1, DomainID: domain, OwnerKind: ownerKind, OwnerID: owner,
			VectorKind: kind, Ordinal: uint32(i), Vector: descriptor, Row: row}
		id, err := contract.GeneratorVectorCarrierID(carrier)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeGeneratorVectorCarrier(carrier)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, contract.SupportRecord{Kind: contract.GeneratorVectorSupportKind, RecordID: id, Body: body})
	}
	return result
}

// full_only: false
func TestGeneratedCanonicalConsumerRejectsChangedOwnerOrOriginal(t *testing.T) {
	for _, kind := range []uint8{10, 11} {
		base, route := generatedCanonicalFixture(t, kind)
		for _, name := range []string{"owner id", "owner domain", "missing consumers", "consumer owner", "consumer material", "consumer context", "consumer subject", "original slot", "original member", "value core"} {
			t.Run(strconv.Itoa(int(kind))+"/"+name, func(t *testing.T) {
				v := base
				row, err := contract.InspectGeneratorConsumer(v.Consumers[0])
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "owner id":
					v.Owner.RecordID = consumerID("unrelated canonical owner")
				case "owner domain":
					if kind == 10 {
						owner, err := contract.InspectGeneratedDutyRecord(v.Owner.Body)
						if err != nil {
							t.Fatal(err)
						}
						owner.DomainID = consumerID("another domain")
						v.Owner.Body, err = contract.EncodeGeneratedDutyRecord(owner)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						owner, err := contract.InspectGeneratedHazardRecord(v.Owner.Body)
						if err != nil {
							t.Fatal(err)
						}
						owner.DomainID = consumerID("another domain")
						v.Owner.Body, err = contract.EncodeGeneratedHazardRecord(owner)
						if err != nil {
							t.Fatal(err)
						}
					}
				case "missing consumers":
					v.Consumers = nil
				case "consumer owner":
					row.OwnerID = consumerID("another consumer owner")
				case "consumer material":
					row.MaterialID = consumerID("another canonical material")
				case "consumer context":
					row.ContextDigest = consumerID("another canonical context")
				case "consumer subject":
					row.SubjectID = consumerID("another canonical subject")
				case "original slot":
					v.Record.OriginalSlot++
				case "original member":
					v.Record.Entry.ValueBytes = bytes.Clone(v.Record.Entry.ValueBytes)
					v.Record.Entry.ValueBytes[len(v.Record.Entry.ValueBytes)-1] ^= 1
				case "value core":
					v.Selection.Core.Name = "substitute"
				}
				if name == "consumer owner" || name == "consumer material" || name == "consumer context" || name == "consumer subject" {
					body, err := contract.EncodeGeneratorConsumer(row)
					if err != nil {
						t.Fatal(err)
					}
					generatedCanonicalConsumers(t, &v, [][]byte{body})
				}
				r := newConsumerRuntime(t, route)
				sink := &consumerTestSink{id: consumerID("refused canonical sink")}
				if err := r.admitGeneratedConsumer(consumerID("canonical admission"), consumerID("canonical purpose"), sink.id,
					route.CredentialRoute(), v, sink, time.Now().Add(time.Minute)); err == nil || r.slot != nil || route.privateCalls != 0 || sink.closes != 0 {
					t.Fatal("invalid canonical selection took private ownership", err)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedCanonicalOwnerChecksEveryOccurrence(t *testing.T) {
	for _, kind := range []uint8{10, 11} {
		base, _ := generatedCanonicalFixture(t, kind)
		for _, name := range []string{"alias", "copy", "changed body", "changed domain", "changed vector", "reordered vector", "missing row", "extra row", "malformed unrelated row", "wrong first context", "wrong last context", "wrong material"} {
			t.Run(strconv.Itoa(int(kind))+"/"+name, func(t *testing.T) {
				v := base
				good, err := contract.InspectGeneratorConsumer(base.Consumers[0])
				if err != nil {
					t.Fatal(err)
				}
				other := good
				other.SubjectID, other.MaterialID, other.ContextDigest = consumerID("other subject"), consumerID("other material"), consumerID("other context")
				body, err := contract.EncodeGeneratorConsumer(other)
				if err != nil {
					t.Fatal(err)
				}
				rows := [][]byte{base.Consumers[0], body}
				slices.SortFunc(rows, bytes.Compare)
				generatedCanonicalConsumers(t, &v, rows)
				if !generatedCanonicalOwnerMatches(v) {
					t.Fatal("complete original owner refused")
				}
				want := name == "alias" || name == "copy" || name == "changed body"
				switch name {
				case "alias":
				case "copy":
					v.Owner.Body = bytes.Clone(v.Owner.Body)
					v.Consumers = slices.Clone(v.Consumers)
					for i := range v.Consumers {
						v.Consumers[i] = bytes.Clone(v.Consumers[i])
					}
				case "changed body", "changed domain":
					if kind == 10 {
						owner, err := contract.InspectGeneratedDutyRecord(v.Owner.Body)
						if err != nil {
							t.Fatal(err)
						}
						owner.ResourceID = consumerID("changed resource")
						if name == "changed domain" {
							owner.DomainID = consumerID("changed domain")
						}
						v.Owner.Body, err = contract.EncodeGeneratedDutyRecord(owner)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						owner, err := contract.InspectGeneratedHazardRecord(v.Owner.Body)
						if err != nil {
							t.Fatal(err)
						}
						owner.ResourceID = consumerID("changed resource")
						if name == "changed domain" {
							owner.DomainID = consumerID("changed domain")
						}
						v.Owner.Body, err = contract.EncodeGeneratedHazardRecord(owner)
						if err != nil {
							t.Fatal(err)
						}
					}
				case "changed vector":
					v.Consumers = [][]byte{body}
				case "reordered vector":
					v.Consumers = [][]byte{rows[1], rows[0]}
				case "missing row":
					v.Consumers = rows[:1]
				case "extra row":
					v.Consumers = append(slices.Clone(rows), rows[1])
				case "malformed unrelated row":
					v.Consumers = append(slices.Clone(rows), []byte{0})
				default:
					bad := good
					for i := range bad.ContextDigest {
						bad.ContextDigest[i] = 1
						if name == "wrong last context" {
							bad.ContextDigest[i] = 254
						}
					}
					if name == "wrong material" {
						bad.ContextDigest = good.ContextDigest
						bad.MaterialID = consumerID("wrong material")
					}
					badBody, err := contract.EncodeGeneratorConsumer(bad)
					if err != nil {
						t.Fatal(err)
					}
					rows = [][]byte{base.Consumers[0], badBody}
					slices.SortFunc(rows, bytes.Compare)
					generatedCanonicalConsumers(t, &v, rows)
				}
				if got := generatedCanonicalOwnerMatches(v); got != want {
					t.Fatalf("owner occurrence: got=%t want=%t", got, want)
				}
				if !generatedCanonicalOwnerMatches(base) {
					t.Fatal("an independent exact input inherited changed facts")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedCanonicalWrapUnionDoesNotExpandOriginalReaders(t *testing.T) {
	v, route := generatedCanonicalFixture(t, 10)
	core, err := custody.ValueWrapCore(v.Selection.Core, v.Selection.Binding)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, route.key, v.Selection.Access.Wraps[0].RSACiphertext, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet[:cap(packet)])
	contextDigest, err := contract.RSAPacketContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := custody.PacketKeys(packet, 1, contextDigest)
	if err != nil {
		t.Fatal(err)
	}
	var excluded contract.BindingTableRow
	for i := 1; i < 127; i++ {
		binding := v.Selection.Binding
		binding.SubjectID, binding.Binding.BindingID = consumerID("union reader "+strconv.Itoa(i)), consumerID("union binding "+strconv.Itoa(i))
		wrapCore, err := custody.ValueWrapCore(v.Selection.Core, binding)
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
		if err != nil {
			t.Fatal(err)
		}
		v.Selection.Access.Wraps = append(v.Selection.Access.Wraps, wrap)
		if i < 64 {
			v.Selection.Entry.Recipients = append(v.Selection.Entry.Recipients, binding.SubjectID)
		} else {
			excluded = binding
		}
	}
	slices.SortFunc(v.Selection.Entry.Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	slices.SortFunc(v.Selection.Access.Wraps, func(a, b contract.WrapRow) int { return bytes.Compare(a.SubjectID[:], b.SubjectID[:]) })
	refreshConsumerSelection(t, &v.Selection)
	v.Record.Entry = v.Selection.Entry
	r := newConsumerRuntime(t, route)
	sink := &consumerTestSink{id: consumerID("original reader union sink")}
	id := consumerID("original reader union admission")
	if err := r.admitGeneratedConsumer(id, consumerID("union purpose"), sink.id, route.CredentialRoute(), v, sink, time.Now().Add(time.Minute)); err != nil {
		t.Fatal("original reader with complete union", err)
	}
	if result := r.consumeSelected(context.Background(), id); result.code != contract.CryptoSuccess || sink.accepted != consumerID("secret-value") {
		t.Fatal("original reader could not consume through union", result.code)
	}
	r.retireConsumer()
	missing := v
	reader := v.Selection.Entry.Recipients[0]
	if reader == v.Selection.Binding.SubjectID {
		reader = v.Selection.Entry.Recipients[1]
	}
	missing.Selection.Access.Wraps = slices.DeleteFunc(slices.Clone(v.Selection.Access.Wraps), func(row contract.WrapRow) bool { return row.SubjectID == reader })
	r = newConsumerRuntime(t, route)
	sink = &consumerTestSink{id: consumerID("incomplete union sink")}
	if err := r.admitGeneratedConsumer(consumerID("incomplete union admission"), consumerID("union purpose"), sink.id,
		route.CredentialRoute(), missing, sink, time.Now().Add(time.Minute)); err == nil || r.slot != nil || sink.closes != 0 {
		t.Fatal("missing original reader wrap admitted", err)
	}
	v.Selection.Binding = excluded
	excludedRoute := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: route.key, binding: excluded.Binding}}
	r = newConsumerRuntime(t, excludedRoute)
	sink = &consumerTestSink{id: consumerID("excluded union sink")}
	if err := r.admitGeneratedConsumer(consumerID("excluded admission"), consumerID("union purpose"), sink.id,
		excludedRoute.CredentialRoute(), v, sink, time.Now().Add(time.Minute)); err == nil || r.slot != nil || excludedRoute.privateCalls != 0 || sink.closes != 0 {
		t.Fatal("wrap-only reader received original member authority", err)
	}
}

// full_only: false
func TestGeneratedCanonicalCandidateReleasesOnlyAfterLastConsumer(t *testing.T) {
	f := generatedCanonicalPlanFixture(t, true)
	r := f.reservationRuntime(t)
	op := generatedCompare(t, r, f)
	generatedPlanParts(t, r, f, op)
	generatedFinishPlan(t, r, f, op)
	a := r.generated
	canonical := f.reservation.Plan.Canonical[0].Record
	canonicalBody, err := contract.EncodeRetainedCanonicalRecord(canonical)
	if err != nil {
		t.Fatal(err)
	}
	sourceID, err := contract.AdmissionEntryDigest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	sources := map[contract.ID]contract.SupportRecord{sourceID: {Kind: contract.RetainedCanonicalSupportKind, RecordID: sourceID, Body: canonicalBody}}
	withSources := func(candidate generatedCandidate) generatedCandidate {
		candidate.SupportRecords = slices.Clone(candidate.SupportRecords)
		added := make(map[contract.ID]bool)
		for _, record := range candidate.SupportRecords {
			if record.Kind != contract.GeneratorVectorSupportKind {
				continue
			}
			carrier, err := contract.InspectGeneratorVectorCarrier(record.Body)
			if err != nil || carrier.VectorKind != contract.GeneratorVectorConsumers {
				continue
			}
			consumer, err := contract.InspectGeneratorConsumer(carrier.Row)
			if err != nil {
				continue
			}
			if source, ok := sources[consumer.SubjectID]; ok && !added[consumer.SubjectID] {
				candidate.SupportRecords = append(candidate.SupportRecords, source)
				added[consumer.SubjectID] = true
			}
		}
		return candidate
	}
	var owners []contract.SupportRecord
	var selections []generatedCanonicalSelection
	var second contract.ConsumerSelection
	for _, kind := range []uint8{10, 11} {
		selected, _ := generatedCanonicalFixture(t, kind)
		second = selected.Selection
		selected.Selection, selected.Record = f.reservation.Plan.Canonical[0].Selection, f.reservation.Plan.Canonical[0].Record
		contextDigest, err := contract.ValueMaterialContextDigest(selected.Selection.Core)
		if err != nil {
			t.Fatal(err)
		}
		row, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: selected.Owner.RecordID,
			MaterialID: selected.Selection.Core.ValueStateID, ContextDigest: contextDigest, SubjectKind: 2, SubjectID: sourceID, Purpose: 2})
		if err != nil {
			t.Fatal(err)
		}
		generatedCanonicalConsumers(t, &selected, [][]byte{row})
		support := append([]contract.SupportRecord{selected.Owner}, generatedVectorSupport(t, selected.Selection.DomainID,
			kind, selected.Owner.RecordID, contract.GeneratorVectorConsumers, selected.Consumers)...)
		owners = append(owners, support...)
		selections = append(selections, selected)
		for _, name := range []string{"exact", "missing access", "changed access", "missing carrier", "changed carrier id", "changed consumer context", "owner identity", "owner domain", "carrier domain", "carrier descriptor", "out of range ordinal", "consumer owner", "valid unrelated carrier", "unrelated consumer", "malformed unrelated carrier", "empty owner malformed unrelated carrier", "released", "orphan access"} {
			t.Run(strconv.Itoa(int(kind))+"/"+name, func(t *testing.T) {
				c := generatedCandidate{Subject: contract.GeneratorAuthoritySubject{DomainID: selected.Selection.DomainID},
					AccessRecords: []contract.AccessRecord{selected.Selection.Access}, SupportRecords: slices.Clone(support)}
				want := name == "exact" || name == "released" || name == "valid unrelated carrier"
				switch name {
				case "missing access":
					c.AccessRecords = nil
				case "changed access":
					c.AccessRecords[0].Wraps = slices.Clone(c.AccessRecords[0].Wraps)
					c.AccessRecords[0].Wraps[0].RSACiphertext = bytes.Clone(c.AccessRecords[0].Wraps[0].RSACiphertext)
					c.AccessRecords[0].Wraps[0].RSACiphertext[0] ^= 1
				case "missing carrier":
					c.SupportRecords = c.SupportRecords[:1]
				case "changed carrier id":
					c.SupportRecords[1].RecordID = consumerID("another carrier")
				case "owner identity":
					c.SupportRecords[0].RecordID = consumerID("another owner identity")
				case "owner domain":
					c.Subject.DomainID = consumerID("another owner domain")
				case "carrier domain", "carrier descriptor":
					carrier, err := contract.InspectGeneratorVectorCarrier(c.SupportRecords[1].Body)
					if err != nil {
						t.Fatal(err)
					}
					if name == "carrier domain" {
						carrier.DomainID = consumerID("another carrier domain")
					} else {
						carrier.Vector.Digest = consumerID("another vector descriptor")
					}
					c.SupportRecords[1].Body, err = contract.EncodeGeneratorVectorCarrier(carrier)
					if err != nil {
						t.Fatal(err)
					}
					c.SupportRecords[1].RecordID, err = contract.GeneratorVectorCarrierID(carrier)
					if err != nil {
						t.Fatal(err)
					}
				case "valid unrelated carrier":
					carrier, err := contract.InspectGeneratorVectorCarrier(c.SupportRecords[1].Body)
					if err != nil {
						t.Fatal(err)
					}
					carrier.OwnerID, carrier.DomainID = consumerID("unrelated owner"), consumerID("unrelated carrier domain")
					body, err := contract.EncodeGeneratorVectorCarrier(carrier)
					if err != nil {
						t.Fatal(err)
					}
					c.SupportRecords = append(c.SupportRecords, contract.SupportRecord{Kind: contract.GeneratorVectorSupportKind,
						RecordID: consumerID("unrelated carrier identity"), Body: body})
				case "out of range ordinal":
					c.SupportRecords[1].Body = bytes.Clone(c.SupportRecords[1].Body)
					c.SupportRecords[1].Body[71] = 1
				case "malformed unrelated carrier", "empty owner malformed unrelated carrier":
					if name == "empty owner malformed unrelated carrier" {
						changed := selected
						generatedCanonicalConsumers(t, &changed, nil)
						c.SupportRecords, c.AccessRecords = []contract.SupportRecord{changed.Owner}, nil
					}
					c.SupportRecords = append(c.SupportRecords, contract.SupportRecord{Kind: contract.GeneratorVectorSupportKind,
						RecordID: consumerID("malformed unrelated carrier"), Body: []byte{0}})
				case "changed consumer context", "consumer owner", "unrelated consumer":
					changed := selected
					consumer, err := contract.InspectGeneratorConsumer(row)
					if err != nil {
						t.Fatal(err)
					}
					switch name {
					case "unrelated consumer":
						consumer.SubjectID = consumerID("unrelated retained subject")
						consumer.ContextDigest = consumerID("unrelated retained context")
					case "consumer owner":
						consumer.OwnerID = consumerID("another consumer owner")
					default:
						consumer.ContextDigest = consumerID("wrong retained context")
					}
					body, err := contract.EncodeGeneratorConsumer(consumer)
					if err != nil {
						t.Fatal(err)
					}
					rows := [][]byte{body}
					if name == "unrelated consumer" {
						rows = append(rows, row)
						slices.SortFunc(rows, bytes.Compare)
					}
					generatedCanonicalConsumers(t, &changed, rows)
					c.SupportRecords = append([]contract.SupportRecord{changed.Owner}, generatedVectorSupport(t, selected.Selection.DomainID,
						kind, selected.Owner.RecordID, contract.GeneratorVectorConsumers, changed.Consumers)...)
				case "released":
					c.SupportRecords, c.AccessRecords = nil, nil
				case "orphan access":
					c.SupportRecords = nil
				}
				if got := a.candidateCanonicalsMatch(withSources(c)); got != want {
					t.Fatal("exact canonical consumer closure", got, want)
				}
			})
		}
	}
	c := generatedCandidate{Subject: contract.GeneratorAuthoritySubject{DomainID: f.compare.Context.DomainID},
		AccessRecords: []contract.AccessRecord{f.reservation.Plan.Canonical[0].Selection.Access}, SupportRecords: owners}
	if !a.candidateCanonicalsMatch(withSources(c)) {
		t.Fatal("shared original canonical consumers refused")
	}
	c.SupportRecords = c.SupportRecords[2:]
	if !a.candidateCanonicalsMatch(withSources(c)) {
		t.Fatal("remaining canonical consumer lost protection")
	}
	c.AccessRecords = nil
	if a.candidateCanonicalsMatch(withSources(c)) {
		t.Fatal("canonical protection released before last owner")
	}
	c.SupportRecords = nil
	if !a.candidateCanonicalsMatch(withSources(c)) {
		t.Fatal("last canonical owner could not release protection")
	}
	for _, field := range []string{"context", "material"} {
		for _, position := range []string{"first", "last"} {
			for _, arrangement := range []string{"one owner", "two owners"} {
				t.Run(field+"/"+position+"/"+arrangement, func(t *testing.T) {
					selected := selections[0]
					good, err := contract.InspectGeneratorConsumer(selected.Consumers[0])
					if err != nil {
						t.Fatal(err)
					}
					bad := good
					var changed contract.ID
					for i := range changed {
						changed[i] = 1
						if position == "last" {
							changed[i] = 254
						}
					}
					if field == "context" {
						bad.ContextDigest = changed
					} else {
						bad.MaterialID = changed
					}
					candidate := generatedCandidate{Subject: contract.GeneratorAuthoritySubject{DomainID: selected.Selection.DomainID},
						AccessRecords: []contract.AccessRecord{selected.Selection.Access}}
					if arrangement == "one owner" {
						body, err := contract.EncodeGeneratorConsumer(bad)
						if err != nil {
							t.Fatal(err)
						}
						rows := [][]byte{selected.Consumers[0], body}
						slices.SortFunc(rows, bytes.Compare)
						if (bytes.Equal(rows[0], body)) != (position == "first") {
							t.Fatal("mixed consumer ordering did not put the changed row at the requested boundary")
						}
						generatedCanonicalConsumers(t, &selected, rows)
						candidate.SupportRecords = append([]contract.SupportRecord{selected.Owner}, generatedVectorSupport(t,
							selected.Selection.DomainID, selected.Owner.Kind, selected.Owner.RecordID, contract.GeneratorVectorConsumers, rows)...)
					} else {
						other := selections[1]
						bad.OwnerID = other.Owner.RecordID
						body, err := contract.EncodeGeneratorConsumer(bad)
						if err != nil {
							t.Fatal(err)
						}
						generatedCanonicalConsumers(t, &other, [][]byte{body})
						candidate.SupportRecords = slices.Clone(owners[:2])
						wrong := append([]contract.SupportRecord{other.Owner}, generatedVectorSupport(t, other.Selection.DomainID,
							other.Owner.Kind, other.Owner.RecordID, contract.GeneratorVectorConsumers, other.Consumers)...)
						if position == "first" {
							candidate.SupportRecords = append(wrong, candidate.SupportRecords...)
						} else {
							candidate.SupportRecords = append(candidate.SupportRecords, wrong...)
						}
					}
					if a.candidateCanonicalsMatch(withSources(candidate)) {
						t.Fatal("a valid consumer hid a changed same-subject consumer")
					}
				})
			}
		}
	}
	t.Run("two sources", func(t *testing.T) {
		body, err := contract.EncodeAccessRecord(second.Access)
		if err != nil {
			t.Fatal(err)
		}
		secondRecord := contract.RetainedCanonicalRecord{OriginalSlot: second.Slot, Entry: second.Entry}
		secondBody, err := contract.EncodeRetainedCanonicalRecord(secondRecord)
		if err != nil {
			t.Fatal(err)
		}
		secondID, err := contract.AdmissionEntryDigest(secondRecord)
		if err != nil {
			t.Fatal(err)
		}
		sources[secondID] = contract.SupportRecord{Kind: contract.RetainedCanonicalSupportKind, RecordID: secondID, Body: secondBody}
		plan := a.purpose.plan()
		original := plan.canonicals
		plan.canonicals = append(slices.Clone(original), generatedCanonicalSource{sourceID: secondID, body: contract.Hash(secondBody), originalSlot: second.Slot, entryDigest: second.EntryDigest,
			core: second.Core, access: contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))}})
		defer func() { plan.canonicals = original }()
		selected := selections[1]
		contextDigest, err := contract.ValueMaterialContextDigest(second.Core)
		if err != nil {
			t.Fatal(err)
		}
		row, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: selected.Owner.RecordID,
			MaterialID: second.Core.ValueStateID, ContextDigest: contextDigest, SubjectKind: 2, SubjectID: secondID, Purpose: 2})
		if err != nil {
			t.Fatal(err)
		}
		rows := [][]byte{selected.Consumers[0], row}
		slices.SortFunc(rows, bytes.Compare)
		generatedCanonicalConsumers(t, &selected, rows)
		support := append(slices.Clone(owners[:2]), selected.Owner)
		support = append(support, generatedVectorSupport(t, selected.Selection.DomainID, selected.Owner.Kind,
			selected.Owner.RecordID, contract.GeneratorVectorConsumers, rows)...)
		for _, name := range []string{"both protected", "missing first access", "missing second access", "missing ordinal", "duplicate ordinal", "exact duplicate row", "release second only", "orphan second access"} {
			t.Run(name, func(t *testing.T) {
				candidate := generatedCandidate{Subject: contract.GeneratorAuthoritySubject{DomainID: selected.Selection.DomainID},
					AccessRecords: []contract.AccessRecord{selected.Selection.Access, second.Access}, SupportRecords: slices.Clone(support)}
				want := name == "both protected" || name == "release second only"
				switch name {
				case "missing first access":
					candidate.AccessRecords = candidate.AccessRecords[1:]
				case "missing second access":
					candidate.AccessRecords = candidate.AccessRecords[:1]
				case "missing ordinal":
					candidate.SupportRecords = candidate.SupportRecords[:len(support)-1]
				case "duplicate ordinal":
					candidate.SupportRecords = append(candidate.SupportRecords, support[3])
				case "exact duplicate row":
					carrier, err := contract.InspectGeneratorVectorCarrier(support[4].Body)
					if err != nil {
						t.Fatal(err)
					}
					carrier.Row = rows[0]
					candidate.SupportRecords[4].Body, err = contract.EncodeGeneratorVectorCarrier(carrier)
					if err != nil {
						t.Fatal(err)
					}
					candidate.SupportRecords[4].RecordID, err = contract.GeneratorVectorCarrierID(carrier)
					if err != nil {
						t.Fatal(err)
					}
				case "release second only", "orphan second access":
					candidate.SupportRecords = candidate.SupportRecords[:2]
					if name == "release second only" {
						candidate.AccessRecords = candidate.AccessRecords[:1]
					}
				}
				if got := a.candidateCanonicalsMatch(withSources(candidate)); got != want {
					t.Fatalf("canonical closure: accepted=%t want=%t sources=%d owners=%d access=%d", got, want,
						len(plan.canonicals), len(candidate.SupportRecords), len(candidate.AccessRecords))
				}
			})
		}
	})
	t.Run("unexamined carriers", func(t *testing.T) {
		malformed := generatedCandidate{SupportRecords: []contract.SupportRecord{{Kind: contract.GeneratorVectorSupportKind,
			RecordID: consumerID("unexamined malformed carrier"), Body: []byte{0}}}}
		noPlan := generatedAdmission{}
		if !noPlan.candidateCanonicalsMatch(malformed) {
			t.Fatal("no-plan canonical check examined unrelated support")
		}
		noCanonicals := generatedAdmission{purpose: generatedPurposeState{reservation: &generatedReservationState{}}}
		malformed.SupportRecords = append(malformed.SupportRecords, contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, Body: []byte{0}})
		if !noCanonicals.candidateCanonicalsMatch(malformed) {
			t.Fatal("empty canonical plan examined unrelated owners")
		}
		malformed.SupportRecords = malformed.SupportRecords[:1]
		if !a.candidateCanonicalsMatch(malformed) {
			t.Fatal("no-owner canonical check examined unrelated carriers")
		}
	})

	t.Run("duplicate owner bodies", func(t *testing.T) {
		for _, kind := range []uint8{10, 11} {
			selected := selections[int(kind)-10]
			for _, name := range []string{"copy", "different valid body", "different descriptor", "different domain", "different kind"} {
				t.Run(strconv.Itoa(int(kind))+"/"+name, func(t *testing.T) {
					other := selected
					other.Owner.Body = bytes.Clone(selected.Owner.Body)
					if name == "different descriptor" {
						generatedCanonicalConsumers(t, &other, nil)
					}
					if name == "different valid body" || name == "different domain" {
						if kind == 10 {
							row, err := contract.InspectGeneratedDutyRecord(other.Owner.Body)
							if err != nil {
								t.Fatal(err)
							}
							row.ResourceID = consumerID("other owner resource")
							if name == "different domain" {
								row.DomainID = consumerID("other owner domain")
							}
							other.Owner.Body, err = contract.EncodeGeneratedDutyRecord(row)
							if err != nil {
								t.Fatal(err)
							}
						} else {
							row, err := contract.InspectGeneratedHazardRecord(other.Owner.Body)
							if err != nil {
								t.Fatal(err)
							}
							row.ResourceID = consumerID("other owner resource")
							if name == "different domain" {
								row.DomainID = consumerID("other owner domain")
							}
							other.Owner.Body, err = contract.EncodeGeneratedHazardRecord(row)
							if err != nil {
								t.Fatal(err)
							}
						}
					}
					if name == "different kind" {
						other.Owner.Kind = 21 - kind
					}
					candidate := generatedCandidate{Subject: contract.GeneratorAuthoritySubject{DomainID: selected.Selection.DomainID},
						AccessRecords: []contract.AccessRecord{selected.Selection.Access}, SupportRecords: []contract.SupportRecord{selected.Owner, other.Owner}}
					candidate.SupportRecords = append(candidate.SupportRecords, generatedVectorSupport(t, selected.Selection.DomainID,
						kind, selected.Owner.RecordID, contract.GeneratorVectorConsumers, selected.Consumers)...)
					want := name == "copy" || name == "different valid body"
					if got := a.candidateCanonicalsMatch(withSources(candidate)); got != want {
						t.Fatalf("duplicate owner: got=%t want=%t", got, want)
					}
				})
			}
		}
	})

	r.retireGenerated()
}

func generatedCanonicalPlanFixture(t *testing.T, recovery bool) generatedRuntimeFixture {
	return generatedCanonicalPlanFixtureFrom(t, generatedRuntimePlanFixture(t, recovery))
}

func generatedCanonicalPlanFixtureFrom(t *testing.T, f generatedRuntimeFixture) generatedRuntimeFixture {
	t.Helper()
	id := consumerID
	plain := []byte("canonical-source")
	core := contract.ValueCore{ValueSource: contract.Supplied, Schema: contract.CanonicalSchema, Profile: 2, DomainID: f.compare.Context.DomainID,
		CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), Name: "alpha",
		EntryIncarnationID: id("original alpha incarnation"), ValueStateID: id("original alpha state"),
		OriginSnapshotID: id("original alpha snapshot"), OriginTransitionID: id("original alpha transition"),
		DataKeyID: id("original alpha data key"), CommitmentKeyID: id("original alpha commitment key"), DataKeyEpoch: 1,
		CommitmentKeyEpoch: 1, ContentLength: uint32(len(plain)), InputEncoding: contract.InputEncodingRaw, RetainedLength: uint32(len(plain))}
	payload, keys, err := custody.SealValue(core, plain)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys)
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	s := contract.ConsumerSelection{DomainID: core.DomainID,
		HEADDigest: f.compare.Context.PredecessorHEADDigest, AccessRoot: f.compare.Context.CurrentAccessRoot,
		HEADRevision: graph.Request.PredecessorRevisionID, HEADToken: contract.Token{Family: contract.GCP, Value: "1"}, Slot: 3,
		Core: core, Payload: payload, Binding: f.reservation.Session.Bindings[applyBindingIndex(f.reservation.Session.Bindings, f.reservation.Session.Control.AuthorityRecipientID)]}
	s.Root, err = contract.DecodeRef(f.compare.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	s.SnapshotID = s.Root.Object
	s.Entry = contract.ValueEntry{Name: core.Name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID,
		OriginSnapshot: core.OriginSnapshotID, OriginTransition: core.OriginTransitionID, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	s.Access = contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: 1, MaterialID: core.ValueStateID, PackageCheck: payload.PackageCheck}
	for _, binding := range f.reservation.Session.Bindings {
		wrapCore, err := custody.ValueWrapCore(core, binding)
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
		if err != nil {
			t.Fatal(err)
		}
		s.Access.MaterialContextDigest = wrapCore.MaterialContextDigest
		s.Access.Wraps = append(s.Access.Wraps, wrap)
		if binding.SubjectKind == 1 {
			s.Entry.Recipients = append(s.Entry.Recipients, binding.SubjectID)
		}
	}
	refreshConsumerSelection(t, &s)
	record := contract.RetainedCanonicalRecord{OriginalSlot: s.Slot, Entry: s.Entry}
	body, err := contract.EncodeRetainedCanonicalRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	generatedAddDeclarationSource(t, &f, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
		Name: s.Entry.Name, Recipients: slices.Clone(s.Entry.Recipients), Payload: body}, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: s.Slot,
		Name: s.Entry.Name, EntryIncarnationID: s.Entry.Incarnation, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret})
	f.reservation.Session.BeforePublic.Rows = []contract.PublicStateRow{{Slot: s.Slot, Name: s.Entry.Name, EntryDigest: s.EntryDigest}}
	f.entries = []generatedCandidateEntry{{Slot: s.Slot, Entry: s.Entry}}
	f.reservation.Session.Output = generatedEmptyOutputWitness(t, &f.reservation.Session.BeforePublic, f.entries, nil)
	f.reservation.Plan.Canonical = []generatedCanonicalSelection{{Selection: s, Record: record}}
	return f
}

// full_only: false
func TestGeneratedCanonicalPlanAuthenticatesStreamedOriginal(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		f := generatedCanonicalPlanFixture(t, recovery)
		r := f.reservationRuntime(t)
		op := generatedCompare(t, r, f)
		generatedPlanParts(t, r, f, op)
		result := generatedFinishPlan(t, r, f, op)
		if len(result.SourceProtections) != 0 || f.base.route.privateCalls != 1 {
			t.Fatal("canonical source became an accepted sealed source", len(result.SourceProtections), f.base.route.privateCalls)
		}
	}
}

// full_only: false
func TestGeneratedCanonicalPlanPinsSelectedHEADRevision(t *testing.T) {
	f := generatedCanonicalPlanFixture(t, false)
	f.reservation.Plan.Canonical[0].Selection.HEADRevision = consumerID("another selected revision")
	r := newConsumerRuntime(t, f.base.route)
	if err := r.admitGeneratedReservation(f.compare, f.reservation, f.base.deadline); err == nil || r.slot != nil || f.base.route.privateCalls != 0 {
		t.Fatal("canonical source admitted under another HEAD revision", err)
	}
}

// full_only: false
func TestGeneratedCanonicalContinuationRequiresAnOwnedConsumer(t *testing.T) {
	f := generatedCanonicalPlanFixture(t, false)
	r := f.reservationRuntime(t)
	op := generatedCompare(t, r, f)
	generatedPlanParts(t, r, f, op)
	prepared := generatedFinishPlan(t, r, f, op)
	c := generatedPlanCandidate(t, f, prepared)
	r.retireGenerated()
	f.compare.Parent = contract.GeneratedParentRecord(f.compare.ParentPlan)
	f.compare.Parent.RequestIdentityDigest = c.Subject.RequestIdentityDigest
	f.compare.ParentPlan, f.compare.Purpose = contract.GeneratedParentPlan{}, 3
	var err error
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	f.final = generatedFinalAdmissionInput{
		Session: f.reservation.Session, Plan: f.reservation.Plan, Material: prepared.Material, SeedAccess: prepared.SeedAccess,
		Phase: contract.GeneratorPhaseIdentity{RequestIdentityDigest: f.compare.Parent.RequestIdentityDigest,
			ObservedHEADDigest: f.compare.Context.PredecessorHEADDigest, ConditionDigest: f.compare.Context.OriginalConditionDigest,
			TransitionKind: contract.GeneratorAuthorityFinal, BeforePhase: 1, AfterPhase: 2, Evidence: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)},
	}
	r = newConsumerRuntime(t, f.base.route)
	if err := r.admitGeneratedFinal(f.compare, f.final, f.base.deadline); err == nil || r.slot != nil {
		t.Fatal("current membership alone admitted canonical generated continuation", err)
	}
}

func generatedCanonicalCandidate(t *testing.T, f generatedRuntimeFixture, result contract.CryptoGeneratedFinishPlanResult) generatedCandidate {
	t.Helper()
	c := generatedPlanCandidate(t, f, result)
	c.AccessRecords = append([]contract.AccessRecord{f.reservation.Plan.Canonical[0].Selection.Access}, c.AccessRecords...)
	var err error
	c.CurrentAccess.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(c.PublicState.Domain, c.AccessRecords)
	if err != nil {
		t.Fatal("canonical access descriptor", err)
	}
	length := 75
	for _, row := range c.AccessRecords {
		body, err := contract.EncodeAccessRecord(row)
		if err != nil {
			t.Fatal(err)
		}
		length += len(body)
	}
	c.CurrentAccess.AccessPageRefs[0].Length = uint32(length)
	c.PublicState.AccessRoot, err = contract.AccessRoot(c.CurrentAccess)
	if err != nil {
		t.Fatal("canonical access root", err)
	}
	c.Subject.AfterAccessDigest = c.PublicState.AccessRoot
	c.ActiveOwner, c.ActivePhase, c.ActiveGraph = f.compare.ParentPlan.OperationID, c.Subject.PhaseID, f.compare.ParentPlan.PlanGraphID
	phase := contract.GeneratedPhaseRecord{Schema: contract.GeneratedPhaseSchema, DomainID: c.PublicState.Domain, OperationID: c.ActiveOwner, OwnerID: c.ActiveOwner,
		PlanGraphID: c.ActiveGraph, UsePlanDigest: f.compare.UsePlanDigest, PhaseID: c.ActivePhase, Phase: 1, LineageIndex: contract.GeneratorMaxLineageTemplates,
		Stage: contract.GeneratedStageTerminal, AcceptedResults: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseResults),
		Attempts: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseAttempts), Duties: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseDuties),
		Hazards: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseHazards), PendingReleases: contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseReleases),
		Proofs: contract.EmptyGeneratorVector(contract.GeneratorVectorProofs)}
	body, err := contract.EncodeGeneratedPhaseRecord(phase)
	if err != nil {
		t.Fatal("canonical active phase", err)
	}
	c.SupportRecords = append(c.SupportRecords, contract.SupportRecord{Kind: 5, RecordID: c.ActiveOwner, Body: body})
	generatedCanonicalizeCandidateSupport(t, &c)
	return c
}

// full_only: false
func TestGeneratedCanonicalCandidatePreservesLiveAccessAndActivePins(t *testing.T) {
	f := generatedCanonicalPlanFixture(t, true)
	for _, name := range []string{"exact", "missing access", "changed wrap", "partial active", "wrong phase", "wrong graph"} {
		t.Run(name, func(t *testing.T) {
			r := f.reservationRuntime(t)
			op := generatedCompare(t, r, f)
			generatedPlanParts(t, r, f, op)
			result := generatedFinishPlan(t, r, f, op)
			c := generatedCanonicalCandidate(t, f, result)
			switch name {
			case "missing access":
				c.AccessRecords = c.AccessRecords[1:]
			case "changed wrap":
				c.AccessRecords[0].Wraps = slices.Clone(c.AccessRecords[0].Wraps)
				c.AccessRecords[0].Wraps[0].RSACiphertext = bytes.Clone(c.AccessRecords[0].Wraps[0].RSACiphertext)
				c.AccessRecords[0].Wraps[0].RSACiphertext[0] ^= 1
			case "partial active":
				c.ActiveOwner = contract.ID{}
			case "wrong phase":
				c.ActivePhase = consumerID("wrong active phase")
			case "wrong graph":
				c.ActiveGraph = consumerID("wrong active graph")
			}
			if name == "missing access" || name == "changed wrap" {
				var err error
				c.CurrentAccess.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(c.PublicState.Domain, c.AccessRecords)
				if err != nil {
					t.Fatal(err)
				}
				length := 75
				for _, row := range c.AccessRecords {
					body, _ := contract.EncodeAccessRecord(row)
					length += len(body)
				}
				c.CurrentAccess.AccessPageRefs[0].Length = uint32(length)
				c.PublicState.AccessRoot, err = contract.AccessRoot(c.CurrentAccess)
				if err != nil {
					t.Fatal(err)
				}
				c.Subject.AfterAccessDigest = c.PublicState.AccessRoot
			}
			want := contract.CryptoInvalidAdmission
			if name == "exact" {
				want = contract.CryptoSuccess
			}
			if got := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, c); got != want {
				t.Fatal("canonical candidate", got, want)
			}
		})
	}
}

// full_only: false
func TestGeneratedCanonicalPlanChecksEveryOwnerInput(t *testing.T) {
	f := generatedCanonicalPlanFixture(t, true)
	first := f.reservation.Plan.Canonical[0]
	second := first
	second.Selection.Slot++
	second.Selection.Core.Name, second.Selection.Entry.Name = "beta", "beta"
	second.Selection.Core.EntryIncarnationID = consumerID("second entry")
	second.Selection.Core.ValueStateID = consumerID("second state")
	second.Selection.Core.DataKeyID, second.Selection.Core.CommitmentKeyID = consumerID("second data key"), consumerID("second commitment key")
	second.Selection.Entry.Incarnation, second.Selection.Entry.ValueState = second.Selection.Core.EntryIncarnationID, second.Selection.Core.ValueStateID
	var err error
	payload, keys, err := custody.SealValue(second.Selection.Core, []byte("canonical-source"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys)
	second.Selection.Payload = payload
	second.Selection.Access = contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind,
		MaterialID: second.Selection.Core.ValueStateID, PackageCheck: second.Selection.Payload.PackageCheck}
	for _, binding := range f.reservation.Session.Bindings {
		core, err := custody.ValueWrapCore(second.Selection.Core, binding)
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := custody.Wrap(core, binding.Binding, keys)
		if err != nil {
			t.Fatal(err)
		}
		second.Selection.Access.MaterialContextDigest = core.MaterialContextDigest
		second.Selection.Access.Wraps = append(second.Selection.Access.Wraps, wrap)
	}
	refreshConsumerSelection(t, &second.Selection)
	second.Record = contract.RetainedCanonicalRecord{OriginalSlot: second.Selection.Slot, Entry: second.Selection.Entry}
	body, err := contract.EncodeRetainedCanonicalRecord(second.Record)
	if err != nil {
		t.Fatal(err)
	}
	generatedAddDeclarationSource(t, &f, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
		Name: "beta", Recipients: slices.Clone(second.Selection.Entry.Recipients), Payload: body}, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema,
		Slot: second.Selection.Slot, Name: "beta", EntryIncarnationID: second.Selection.Entry.Incarnation, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret})
	f.reservation.Session.BeforePublic.Rows = append(f.reservation.Session.BeforePublic.Rows, contract.PublicStateRow{Slot: second.Selection.Slot, Name: "beta", EntryDigest: second.Selection.EntryDigest})
	f.entries = append(f.entries, generatedCandidateEntry{Slot: second.Selection.Slot, Entry: second.Selection.Entry})
	f.reservation.Session.Output = generatedEmptyOutputWitness(t, &f.reservation.Session.BeforePublic, f.entries, nil)
	for _, kind := range []uint8{10, 11} {
		owner, _ := generatedCanonicalFixture(t, kind)
		first.Owner, second.Owner = owner.Owner, owner.Owner
		var rows [][]byte
		for _, selected := range []generatedCanonicalSelection{first, second} {
			context, err := contract.ValueMaterialContextDigest(selected.Selection.Core)
			if err != nil {
				t.Fatal(err)
			}
			body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: owner.Owner.RecordID,
				MaterialID: selected.Selection.Core.ValueStateID, ContextDigest: context, SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue,
				SubjectID: selected.Selection.Core.ValueStateID, Purpose: contract.GeneratorConsumerUseRetainedCanonical})
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, body)
		}
		slices.SortFunc(rows, bytes.Compare)
		generatedCanonicalConsumers(t, &first, rows)
		second.Owner, second.Consumers = first.Owner, first.Consumers
		for _, name := range []string{"alias", "copy", "changed owner body", "changed descriptor", "changed vector", "mutated alias", "copied binding", "changed binding", "changed recovery wrap"} {
			t.Run(strconv.Itoa(int(kind))+"/"+name, func(t *testing.T) {
				x := second
				x.Owner.Body = bytes.Clone(second.Owner.Body)
				x.Consumers = slices.Clone(second.Consumers)
				for i := range x.Consumers {
					x.Consumers[i] = bytes.Clone(x.Consumers[i])
				}
				input := f.reservation
				input.Plan.Canonical = []generatedCanonicalSelection{first, x}
				want := name == "alias" || name == "copy" || name == "changed owner body" || name == "copied binding"
				switch name {
				case "alias":
					input.Plan.Canonical[1].Owner, input.Plan.Canonical[1].Consumers = first.Owner, first.Consumers
				case "changed owner body":
					if kind == 10 {
						row, err := contract.InspectGeneratedDutyRecord(x.Owner.Body)
						if err != nil {
							t.Fatal(err)
						}
						row.ResourceID = consumerID("new resource")
						x.Owner.Body, err = contract.EncodeGeneratedDutyRecord(row)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						row, err := contract.InspectGeneratedHazardRecord(x.Owner.Body)
						if err != nil {
							t.Fatal(err)
						}
						row.ResourceID = consumerID("new resource")
						x.Owner.Body, err = contract.EncodeGeneratedHazardRecord(row)
						if err != nil {
							t.Fatal(err)
						}
					}
					input.Plan.Canonical[1] = x
				case "changed descriptor":
					generatedCanonicalConsumers(t, &x, nil)
					input.Plan.Canonical[1] = x
				case "changed vector", "mutated alias":
					row, err := contract.InspectGeneratorConsumer(x.Consumers[0])
					if err != nil {
						t.Fatal(err)
					}
					row.ContextDigest = consumerID("changed vector context")
					x.Consumers[0], err = contract.EncodeGeneratorConsumer(row)
					if err != nil {
						t.Fatal(err)
					}
					if name == "mutated alias" {
						input.Plan.Canonical[0].Consumers = x.Consumers
					}
				case "copied binding":
					input.Plan.Canonical[1].Selection.Binding.Binding.SPKI = bytes.Clone(x.Selection.Binding.Binding.SPKI)
				case "changed binding":
					input.Plan.Canonical[1].Selection.Binding.Binding.KeySelector += "1"
				case "changed recovery wrap":
					input.Plan.Canonical[1].Selection.Access.Wraps = slices.Clone(x.Selection.Access.Wraps)
					input.Plan.Canonical[1].Selection.Access.Wraps[len(x.Selection.Access.Wraps)-1].BindingSerial++
				}
				r := newConsumerRuntime(t, f.base.route)
				if got := r.admitGeneratedReservation(f.compare, input, f.base.deadline) == nil; got != want {
					t.Fatalf("complete owner input: accepted=%t want=%t", got, want)
				}
				r.retireGenerated()
			})
		}
	}
}

func generatedCurrentDeleteCanonicalFixture(t *testing.T, recovery bool, kind uint8) generatedRuntimeFixture {
	t.Helper()
	f := generatedSelectDeleteProducer(t, generatedDeleteProducerFixture(t, recovery), kind)
	f.compare.ParentPlan = contract.GeneratedParentPlan(f.compare.Parent)
	f.compare.ParentPlan.RequestIdentityDigest = contract.ID{}
	f.compare.Parent, f.compare.Purpose = contract.GeneratedParentRecord{}, contract.CryptoGeneratedReservationPurpose
	var err error
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal("restored delete reservation", err)
	}
	return generatedCanonicalPlanFixtureFrom(t, f)
}

// full_only: false
func TestGeneratedDeleteCurrentCanonicalStreamsWithoutValueKeyUse(t *testing.T) {
	for _, kind := range []uint8{contract.GeneratedDutyRetirement, contract.GeneratedDutyUnselectedCleanup} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("kind=%d/recovery=%t", kind, recovery), func(t *testing.T) {
				f := generatedCurrentDeleteCanonicalFixture(t, recovery, kind)
				privateBefore := f.base.route.privateCalls
				r := f.reservationRuntime(t)
				defer r.retireGenerated()
				op := generatedCompare(t, r, f)
				generatedPlanParts(t, r, f, op)
				plan := r.generated.purpose.plan()
				if len(plan.canonicals) != 1 || len(plan.canonicals[0].buffer) != 0 || plan.canonicals[0].opened || f.base.route.privateCalls != privateBefore {
					t.Fatal("delete declaration opened or buffered a current value", f.base.route.privateCalls-privateBefore)
				}
				result := generatedFinishPlan(t, r, f, op)
				if len(result.SourceProtections) != 0 || f.base.route.privateCalls != privateBefore {
					t.Fatal("delete finish introduced a canonical source or key use", f.base.route.privateCalls-privateBefore)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedDeleteCurrentCanonicalAdmissionAcrossPlanPurposes(t *testing.T) {
	for _, kind := range []uint8{contract.GeneratedDutyRetirement, contract.GeneratedDutyUnselectedCleanup} {
		for _, recovery := range []bool{false, true} {
			for _, purpose := range []contract.CryptoGeneratedPurpose{contract.CryptoGeneratedReservationPurpose, contract.CryptoGeneratedProducerPreparationPurpose, contract.CryptoGeneratedAdoptionPurpose, contract.CryptoGeneratedFinalPreparationPurpose} {
				t.Run(fmt.Sprintf("kind=%d/recovery=%t/purpose=%d", kind, recovery, purpose), func(t *testing.T) {
					f := generatedCurrentDeleteCanonicalFixture(t, recovery, kind)
					q := f.compare
					q.Purpose = purpose
					if purpose != contract.CryptoGeneratedReservationPurpose {
						q.Parent = contract.GeneratedParentRecord(q.ParentPlan)
						q.Parent.RequestIdentityDigest = f.reservation.Phase.RequestIdentityDigest
						q.ParentPlan = contract.GeneratedParentPlan{}
					}
					var err error
					q.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(q)
					if err != nil {
						t.Fatal(err)
					}
					body, err := contract.EncodeCryptoGeneratedCompareRequest(q)
					if err != nil {
						t.Fatal(err)
					}
					var state generatedPurposeState
					switch purpose {
					case contract.CryptoGeneratedReservationPurpose:
						state.reservation = &generatedReservationState{}
					case contract.CryptoGeneratedProducerPreparationPurpose:
						state.producer = &generatedProducerPreparationState{}
					case contract.CryptoGeneratedAdoptionPurpose:
						state.adoption = &generatedAdoptionState{}
					case contract.CryptoGeneratedFinalPreparationPurpose:
						state.final = &generatedFinalPreparationState{}
					}
					r := newConsumerRuntime(t, f.base.route)
					privateBefore := f.base.route.privateCalls
					a, err := r.prepareGeneratedPlan(q, f.reservation.Session, f.reservation.Plan, state, nil, body, f.base.deadline)
					if err != nil {
						t.Fatal("exact current delete metadata refused", err)
					}
					defer a.clear()
					plan := a.purpose.plan()
					if len(plan.canonicals) != 1 || len(plan.canonicals[0].buffer) != 0 || plan.canonicals[0].opened || f.base.route.privateCalls != privateBefore {
						t.Fatal("current delete admission retained openable payload or used a key")
					}
					view, err := contract.InspectGeneratorDeclaration(f.declaration)
					if err != nil {
						t.Fatal(err)
					}
					entry, _, err := view.Entry(0)
					if err != nil {
						t.Fatal(err)
					}
					// Complete valid ciphertext and wraps still grant no value-key operation in a delete plan.
					source := &plan.canonicals[0]
					source.buffer = bytes.Clone(entry.Payload)
					selected := f.reservation.Plan.Canonical[0].Selection
					wrap, _, valid := checkConsumerSelection(selected, f.base.control.Provider)
					if !valid {
						t.Fatal("healthy current selection")
					}
					source.wrap = selected.Access.Wraps[wrap]
					source.wrap.RSACiphertext = bytes.Clone(source.wrap.RSACiphertext)
					out := contract.CryptoResponse{}
					keys, code := a.openCanonicalKeys(t.Context(), f.base.route, source, &out)
					if code != contract.CryptoInvalidAdmission || len(keys) != 0 || len(out.KeyUseRows) != 0 || f.base.route.privateCalls != privateBefore {
						clear(keys)
						t.Fatal("delete metadata supplied canonical key or use permission", code, f.base.route.privateCalls-privateBefore)
					}
				})
			}
		}
	}
}

// full_only: false
func TestGeneratedDeleteCurrentCanonicalRefusesWrongAdmissionFacts(t *testing.T) {
	for _, condition := range []string{"missing input", "wrong slot", "changed recipients", "changed declared recipients", "stale context", "stale binding", "owner without kind", "consumer without owner", "mislabeled create graph", "mismatched lineage purpose", "changed plan", "changed plan reservation", "sealed source use", "duplicate selection", "changed access identity", "historical owner with newer current value"} {
		t.Run(condition, func(t *testing.T) {
			f := generatedCurrentDeleteCanonicalFixture(t, true, contract.GeneratedDutyUnselectedCleanup)
			r := f.reservationRuntime(t)
			defer r.retireGenerated()
			a := *r.generated
			a.purpose = generatedPurposeState{producer: &generatedProducerPreparationState{}}
			view, err := contract.InspectGeneratorDeclaration(f.declaration)
			if err != nil {
				t.Fatal(err)
			}
			entry, _, err := view.Entry(0)
			if err != nil {
				t.Fatal(err)
			}
			input := slices.Clone(f.reservation.Plan.Canonical)
			switch condition {
			case "missing input":
				input = nil
			case "wrong slot":
				input[0].Record.OriginalSlot++
			case "changed recipients":
				if len(input[0].Record.Entry.Recipients) != 2 {
					t.Fatal("healthy canonical recipient cardinality")
				}
				input[0].Record.Entry.Recipients = slices.Clone(input[0].Record.Entry.Recipients[:1])
			case "changed declared recipients":
				if len(entry.RecipientIDs) != 64 {
					t.Fatal("healthy declared recipient cardinality")
				}
				entry.RecipientIDs = entry.RecipientIDs[:32]
			case "stale context":
				input[0].Selection.HEADDigest = consumerID("unrelated current delete HEAD")
			case "stale binding":
				input[0].Selection.Binding.Binding.BindingSerial++
			case "owner without kind":
				input[0].Owner.RecordID = consumerID("untyped current delete owner")
			case "consumer without owner":
				input[0].Consumers = [][]byte{{1}}
			case "mislabeled create graph":
				create := generatedCanonicalPlanFixture(t, false)
				a.graph, err = contract.DecodeGeneratorPlanBundle(create.graph)
				if err != nil {
					t.Fatal(err)
				}
				a.graph.Request.OperationKind = contract.OperationCleanOwnedFailureResidue
			case "mismatched lineage purpose":
				a.graph.Lineages = slices.Clone(a.graph.Lineages)
				a.graph.Lineages[0].Purpose = contract.GeneratorLineageRetirement
			case "changed plan", "changed plan reservation":
				if len(a.graph.ValueEntryPlans) != 1 || a.graph.ValueEntryPlans[0].ChangeMask != 0 {
					t.Fatal("healthy unchanged delete entry plan")
				}
				a.graph.ValueEntryPlans = slices.Clone(a.graph.ValueEntryPlans)
				a.graph.ValueEntryPlans[0].ChangeMask = contract.GeneratorValueChangeContent
				if condition == "changed plan reservation" {
					a.purpose = generatedPurposeState{reservation: &generatedReservationState{}}
				}
			case "duplicate selection":
				input = append(input, input[0])
			case "changed access identity":
				if input[0].Selection.Access.MaterialID != input[0].Record.Entry.ValueState {
					t.Fatal("healthy current access identity")
				}
				input[0].Selection.Access.MaterialID = consumerID("unrelated delete current material")
			case "historical owner with newer current value":
				owner, _ := generatedCanonicalFixture(t, contract.GeneratedDutySupportKind)
				input[0].Owner = owner.Owner
				context, err := contract.ValueMaterialContextDigest(input[0].Selection.Core)
				if err != nil {
					t.Fatal(err)
				}
				body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1,
					OwnerID: input[0].Owner.RecordID, MaterialID: input[0].Record.Entry.ValueState,
					ContextDigest: context, SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue,
					SubjectID: input[0].Record.Entry.ValueState, Purpose: contract.GeneratorConsumerUseRetainedCanonical})
				if err != nil {
					t.Fatal(err)
				}
				generatedCanonicalConsumers(t, &input[0], [][]byte{body})
				if !generatedCanonicalOwnerMatches(input[0]) {
					t.Fatal("healthy historical ownership tuple")
				}
				current := a
				current.purpose = generatedPurposeState{producer: &generatedProducerPreparationState{}}
				present, valid := current.admitCanonical(entry, 0, input)
				if !present || !valid || len(current.purpose.plan().canonicals) != 1 || len(current.purpose.plan().canonicals[0].buffer) != 0 {
					t.Fatal("exact current value with a valid retained owner was refused or buffered", present, valid)
				}
				current.purpose.clear()
				a.before.Rows = []contract.PublicStateRow{{Name: input[0].Record.Entry.Name,
					Slot: input[0].Record.OriginalSlot, EntryDigest: consumerID("newer selected current entry")}}
			case "sealed source use":
				a.graph.SourceUses = []contract.GeneratorSourceUse{{SourceID: consumerID("unexpected delete sealed input")}}
			}
			privateBefore := f.base.route.privateCalls
			present, valid := a.admitCanonical(entry, 0, input)
			if present || valid || len(a.purpose.plan().canonicals) != 0 || f.base.route.privateCalls != privateBefore {
				t.Fatal("incorrect current delete facts granted canonical admission", present, valid)
			}
		})
	}
}

// full_only: false
func TestGeneratedDeleteCurrentCanonicalFinalRemainsNonselecting(t *testing.T) {
	for _, kind := range []uint8{contract.GeneratedDutyRetirement, contract.GeneratedDutyUnselectedCleanup} {
		f := generatedSealedFinalFromPlan(t, generatedCurrentDeleteCanonicalFixture(t, true, kind))
		r := newConsumerRuntime(t, f.base.route)
		privateBefore := f.base.route.privateCalls
		if err := r.admitGeneratedFinal(f.compare, f.final, f.base.deadline); err != nil {
			t.Fatal("current delete nonselecting Final", err)
		}
		state := r.generated.purpose.final
		if !state.nonselecting || state.suppliedCount != 0 || len(state.entryPreparations) != 0 || len(state.plan.canonicals) != 1 || len(state.plan.canonicals[0].buffer) != 0 || f.base.route.privateCalls != privateBefore {
			t.Fatal("delete Final acquired value preparation or payload permission")
		}
		rows, valid := r.generated.preparedPublicStateRows(generatedCandidate{})
		if !valid || !slices.Equal(rows, f.final.Session.BeforePublic.Rows) {
			t.Fatal("delete Final changed the current value rows")
		}
		r.retireGenerated()
		invalid := f.final
		invalid.EntryAdmissions = []generatedEntryAdmission{{}}
		r = newConsumerRuntime(t, f.base.route)
		if err := r.admitGeneratedFinal(f.compare, invalid, f.base.deadline); err == nil || r.slot != nil || f.base.route.privateCalls != privateBefore {
			t.Fatal("delete Final admitted a selecting value entry or private route", err)
		}
	}
}

// full_only: false
func TestGeneratedDeletePlanAdmissionRefusesChangedOrMismatchedGraphs(t *testing.T) {
	for _, condition := range []string{"changed value plan", "operation lineage mismatch"} {
		t.Run(condition, func(t *testing.T) {
			f := generatedSelectDeleteProducer(t, generatedDeleteProducerFixture(t, false), contract.GeneratedDutyUnselectedCleanup)
			f.compare.ParentPlan = contract.GeneratedParentPlan(f.compare.Parent)
			f.compare.ParentPlan.RequestIdentityDigest = contract.ID{}
			f.compare.Parent, f.compare.Purpose = contract.GeneratedParentRecord{}, contract.CryptoGeneratedReservationPurpose
			graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
			if err != nil {
				t.Fatal(err)
			}
			mask := uint8(contract.GeneratorValueChangeContent)
			if condition == "operation lineage mismatch" {
				mask = 0
				graph.Request.OperationKind = contract.OperationRetireGeneratedGeneration
				oldJoin, err := contract.GeneratorCompleteJoinID(graph.Header.RequestCoreDigest)
				if err != nil {
					t.Fatal(err)
				}
				graph.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(graph.Request)
				if err != nil {
					t.Fatal(err)
				}
				join, err := contract.GeneratorCompleteJoinID(graph.Header.RequestCoreDigest)
				if err != nil {
					t.Fatal(err)
				}
				for i := range graph.Edges {
					if graph.Edges[i].DestinationTemplateID == oldJoin {
						graph.Edges[i].DestinationTemplateID = join
					}
				}
				graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(graph.Header, graph.ValueEntryPlans, graph.Lineages, graph.Edges)
				if err != nil {
					t.Fatal(err)
				}
			}
			f.graph, err = contract.EncodeGeneratorPlanBundle(graph)
			if err != nil {
				t.Fatal(err)
			}
			generatedAddDeclarationSource(t, &f, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema,
				Kind: contract.GeneratorDeclarationPlain, Name: "alpha", Recipients: slices.Clone(f.base.q.Intent[0].Recipients), Payload: []byte("current plain value")},
				contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 3, Name: "alpha", EntryIncarnationID: consumerID("plain alpha incarnation"),
					ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, ChangeMask: mask})
			body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
			if err != nil {
				t.Fatal(err)
			}
			r := newConsumerRuntime(t, f.base.route)
			privateBefore := f.base.route.privateCalls
			a, err := r.prepareGeneratedPlan(f.compare, f.reservation.Session, f.reservation.Plan,
				generatedPurposeState{reservation: &generatedReservationState{}}, nil, body, f.base.deadline)
			if a != nil {
				a.clear()
			}
			if err == nil || a != nil || r.slot != nil || f.base.route.privateCalls != privateBefore {
				t.Fatal("delete operation admitted a changed or mismatched graph without canonical entries", err)
			}
		})
	}
}
