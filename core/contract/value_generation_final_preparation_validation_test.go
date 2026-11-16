package contract

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

// full_only: true
func TestGeneratedFinalPreparationImageExceedsOneFrameWithBoundedRows(t *testing.T) {
	first, _, _ := finalPreparationValidationRows(t, "plain")
	first = finalPreparationValidationSizedGenerated(t, first, 0, "base", 1, 1)
	image := GeneratedFinalPreparationImage{Schema: 1, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
		MaterializationPhaseID: generatedRecordID(3), ControlBindingDigest: generatedRecordID(4), Generated: []CryptoGeneratedValueEntryResult{first}}
	var readers []ID
	for i := range 256 {
		readers = append(readers, Hash([]byte(fmt.Sprintf("large image reader %d", i))))
	}
	slices.SortFunc(readers, func(a, b ID) int { return bytes.Compare(a[:], b[:]) })
	var suppliedFrames [][]byte
	for i := range 266 {
		name := fmt.Sprintf("s%03d", i)
		entry := finalPreparationValidationSizedGenerated(t, first, uint16(i+1), name, 1, 1).Entry
		entry.ValueSource, entry.Generated = Supplied, GeneratedEntryMetadata{}
		entry.ValueState, entry.Incarnation = Hash([]byte(name+" material")), Hash([]byte(name+" incarnation"))
		entry.Recipients = []ID{readers[0]}
		entryBody, err := EncodeValueEntry(entry)
		if err != nil {
			t.Fatal(err)
		}
		core, err := ValueCoreForEntry(first.ValueCore.DomainID, first.ValueCore.CompatibilityID, entry)
		if err != nil {
			t.Fatal(err)
		}
		access := first.Access
		access.MaterialID = entry.ValueState
		access.MaterialContextDigest, err = ValueMaterialContextDigest(core)
		if err != nil {
			t.Fatal(err)
		}
		access.Wraps = nil
		for _, id := range readers {
			wrap := first.Access.Wraps[0]
			wrap.SubjectID = id
			access.Wraps = append(access.Wraps, wrap)
		}
		recovery := first.Access.Wraps[0]
		recovery.SubjectKind, recovery.SubjectID = RecoveryWrapSubject, Hash([]byte("large image recovery"))
		access.Wraps = append(access.Wraps, recovery)
		accessBody, err := EncodeAccessRecord(access)
		if err != nil {
			t.Fatal(err)
		}
		row := CryptoPreparedSecret{Name: name, Slot: uint16(i + 1), EntryBytes: entryBody, AccessRecord: accessBody}
		frame, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: 1, Rows: []CryptoPreparedSecret{row}})
		// Four-byte image blob length, ten-byte result header, fourteen-byte
		// row framing, two names, entry/payload and 257 fixed-width wraps.
		if err != nil || len(frame)+4 != 4+10+14+8+154+32+216+102+257*489 {
			t.Fatal("independent single-row frame size", len(frame), err)
		}
		image.Supplied = append(image.Supplied, row)
		suppliedFrames = append(suppliedFrames, frame)
	}
	generatedFrame, err := EncodeCryptoGeneratedValueEntriesResult(CryptoGeneratedValueEntriesResult{Final: 1, Rows: image.Generated})
	if err != nil {
		t.Fatal(err)
	}
	want := finalPreparationValidationWire([][]byte{generatedFrame}, suppliedFrames)
	body, err := EncodeGeneratedFinalPreparationImage(image)
	if err != nil || len(body) <= 32<<20 || len(body) != 138+4+len(generatedFrame)+266*126213 || !bytes.Equal(body, want) {
		t.Fatal("complete image did not preserve separately bounded frames", len(body), err)
	}
	decoded, err := DecodeGeneratedFinalPreparationImage(body)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Clear()
	if len(decoded.Generated) != 1 || len(decoded.Supplied) != 266 {
		t.Fatal("large image row census")
	}
	for i, row := range decoded.Supplied {
		if row.Name != image.Supplied[i].Name || row.Slot != image.Supplied[i].Slot ||
			!bytes.Equal(row.EntryBytes, image.Supplied[i].EntryBytes) || !bytes.Equal(row.AccessRecord, image.Supplied[i].AccessRecord) {
			t.Fatal("large image changed a row", i)
		}
	}
}

// The outer framing is independent of EncodeGeneratedFinalPreparationImage.
// Inner row encoders only provide independently valid existing row messages.
func finalPreparationValidationWire(generated, supplied [][]byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, 1)
	for _, n := range []byte{1, 2, 3, 4} {
		body = append(body, bytes.Repeat([]byte{n}, 32)...)
	}
	body = binary.BigEndian.AppendUint32(body, uint32(len(generated)))
	for _, row := range generated {
		body = binary.BigEndian.AppendUint32(body, uint32(len(row)))
		body = append(body, row...)
	}
	body = binary.BigEndian.AppendUint32(body, uint32(len(supplied)))
	for _, row := range supplied {
		body = binary.BigEndian.AppendUint32(body, uint32(len(row)))
		body = append(body, row...)
	}
	return body
}

func finalPreparationValidationRows(t *testing.T, suppliedName string) (CryptoGeneratedValueEntryResult, CryptoGeneratedValueEntryResult, CryptoPreparedSecret) {
	t.Helper()
	_, _, first := generatedCryptoValueEntryFixture(t)
	second := first
	second.Slot = 3
	second.ValueCore.Name, second.Entry.Name = "z", "z"
	var err error
	second.Access.MaterialContextDigest, err = ValueMaterialContextDigest(second.ValueCore)
	if err != nil {
		t.Fatal(err)
	}
	q := generatedSuppliedCryptoFixture(t)
	identity, err := DecodeIdentityPlan(q.IdentityPlan)
	if err != nil {
		t.Fatal(err)
	}
	row := identity.Rows[0]
	row.Name = suppliedName
	return first, second, generatedSuppliedPreparedFixture(t, q, row)
}

// full_only: false
func TestGeneratedFinalPreparationImageRefusesGlobalNameDuplicates(t *testing.T) {
	for _, condition := range []string{"distinct", "duplicate_generated", "generated_supplied_collision"} {
		t.Run(condition, func(t *testing.T) {
			name := "plain"
			if condition == "generated_supplied_collision" {
				name = "n"
			}
			first, second, supplied := finalPreparationValidationRows(t, name)
			if condition == "duplicate_generated" {
				second = first
				second.Slot = 3
			}
			var generated [][]byte
			for _, row := range []CryptoGeneratedValueEntryResult{first, second} {
				body, err := EncodeCryptoGeneratedValueEntriesResult(CryptoGeneratedValueEntriesResult{Final: 1, Rows: []CryptoGeneratedValueEntryResult{row}})
				if err != nil {
					t.Fatal("individual row must be valid", err)
				}
				generated = append(generated, body)
			}
			suppliedBody, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: 1, Rows: []CryptoPreparedSecret{supplied}})
			if err != nil {
				t.Fatal("individual supplied row must be valid", err)
			}
			image := GeneratedFinalPreparationImage{Schema: 1, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
				MaterializationPhaseID: generatedRecordID(3), ControlBindingDigest: generatedRecordID(4), Generated: []CryptoGeneratedValueEntryResult{first, second}, Supplied: []CryptoPreparedSecret{supplied}}
			encoded, encodeErr := EncodeGeneratedFinalPreparationImage(image)
			wire := finalPreparationValidationWire(generated, [][]byte{suppliedBody})
			before := bytes.Clone(wire)
			decoded, decodeErr := DecodeGeneratedFinalPreparationImage(wire)
			if condition == "distinct" {
				defer decoded.Clear()
				if encodeErr != nil || decodeErr != nil || !bytes.Equal(encoded, wire) || len(decoded.Generated) != 2 || len(decoded.Supplied) != 1 ||
					decoded.Generated[0].ValueCore.Name != "n" || decoded.Generated[1].ValueCore.Name != "z" || decoded.Supplied[0].Name != "plain" {
					t.Fatal("distinct complete image refused or changed", encodeErr, decodeErr)
				}
			} else {
				if encodeErr == nil {
					t.Error("image encoder admitted duplicate global name")
				}
				if decodeErr == nil || !reflect.DeepEqual(decoded, GeneratedFinalPreparationImage{}) {
					decoded.Clear()
					t.Error("image decoder admitted duplicate name or retained partial owned state", decodeErr)
				}
			}
			if !bytes.Equal(wire, before) {
				t.Fatal("decoder changed borrowed image")
			}
		})
	}
}

// full_only: false
func TestGeneratedFinalPreparationImageRequiresCanonicalSingleRowFrames(t *testing.T) {
	first, second, supplied := finalPreparationValidationRows(t, "plain")
	for _, condition := range []string{"generated_nonzero_batch", "generated_nonfinal", "generated_multirow", "supplied_nonzero_batch", "supplied_nonfinal"} {
		t.Run(condition, func(t *testing.T) {
			g := CryptoGeneratedValueEntriesResult{Final: 1, Rows: []CryptoGeneratedValueEntryResult{first}}
			s := CryptoGeneratedSuppliedResult{Final: 1, Rows: []CryptoPreparedSecret{supplied}}
			switch condition {
			case "generated_nonzero_batch":
				g.BatchIndex = 1
			case "generated_nonfinal":
				g.Final = 0
			case "generated_multirow":
				g.Rows = append(g.Rows, second)
			case "supplied_nonzero_batch":
				s.BatchIndex = 1
			case "supplied_nonfinal":
				s.Final = 0
			}
			gb, err := EncodeCryptoGeneratedValueEntriesResult(g)
			if err != nil {
				t.Fatal("valid inner generated control", err)
			}
			sb, err := EncodeCryptoGeneratedSuppliedResult(s)
			if err != nil {
				t.Fatal("valid inner supplied control", err)
			}
			wire := finalPreparationValidationWire([][]byte{gb}, [][]byte{sb})
			before := bytes.Clone(wire)
			partial, err := DecodeGeneratedFinalPreparationImage(wire)
			if err == nil || !reflect.DeepEqual(partial, GeneratedFinalPreparationImage{}) {
				partial.Clear()
				t.Fatal("noncanonical inner frame admitted or partial owned state retained", condition, err)
			}
			if !bytes.Equal(before, wire) {
				t.Fatal("refusal changed borrowed image")
			}
		})
	}
}

// full_only: false
func TestGeneratedFinalPreparationImageChecksDeclaredBoundsBeforeRows(t *testing.T) {
	first, _, _ := finalPreparationValidationRows(t, "plain")
	for _, count := range []int{GeneratedCurrentEntryLimit, GeneratedCurrentEntryLimit + 1} {
		t.Run(fmt.Sprintf("generated_count_%d", count), func(t *testing.T) {
			image := GeneratedFinalPreparationImage{Schema: 1, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
				MaterializationPhaseID: generatedRecordID(3), ControlBindingDigest: generatedRecordID(4), Generated: make([]CryptoGeneratedValueEntryResult, count)}
			var frames [][]byte
			for i := range image.Generated {
				row := first
				row.Slot = uint16(i)
				row.ValueCore.Name, row.Entry.Name = fmt.Sprintf("n%03d", i), fmt.Sprintf("n%03d", i)
				var err error
				row.Access.MaterialContextDigest, err = ValueMaterialContextDigest(row.ValueCore)
				if err != nil {
					t.Fatal(err)
				}
				frame, err := EncodeCryptoGeneratedValueEntriesResult(CryptoGeneratedValueEntriesResult{Final: 1, Rows: []CryptoGeneratedValueEntryResult{row}})
				if err != nil {
					t.Fatal("individual selecting row must be valid", err)
				}
				image.Generated[i] = row
				frames = append(frames, frame)
			}
			encoded, encodeErr := EncodeGeneratedFinalPreparationImage(image)
			wire := finalPreparationValidationWire(frames, nil)
			decoded, decodeErr := DecodeGeneratedFinalPreparationImage(wire)
			if count == GeneratedCurrentEntryLimit {
				defer decoded.Clear()
				if encodeErr != nil || decodeErr != nil || len(decoded.Generated) != count || !bytes.Equal(encoded, wire) {
					t.Fatal("128 valid selecting rows refused or changed", encodeErr, decodeErr)
				}
			} else if encodeErr == nil || decodeErr == nil || !reflect.DeepEqual(decoded, GeneratedFinalPreparationImage{}) {
				decoded.Clear()
				t.Fatal("more than 128 valid selecting rows admitted or partial state retained", encodeErr, decodeErr)
			}
		})
	}
	// Fixed outer header and bad count suffice: absence of row backing cannot
	// turn an invalid declared count into an allocation or a partial result.
	wire := finalPreparationValidationWire(nil, nil)
	binary.BigEndian.PutUint32(wire[130:134], GeneratedCurrentEntryLimit+1)
	partial, err := DecodeGeneratedFinalPreparationImage(wire)
	if err == nil || !reflect.DeepEqual(partial, GeneratedFinalPreparationImage{}) {
		partial.Clear()
		t.Fatal("excess Generated count retained partial image", err)
	}
	oversize := make([]byte, GeneratedFinalPreparationMaxLength+1)
	partial, err = DecodeGeneratedFinalPreparationImage(oversize)
	if err == nil || !reflect.DeepEqual(partial, GeneratedFinalPreparationImage{}) {
		partial.Clear()
		t.Fatal("declared image maximum exceeded", err)
	}
}

func finalPreparationValidationSizedGenerated(t *testing.T, base CryptoGeneratedValueEntryResult, slot uint16, name string, raw uint32, recipients int) CryptoGeneratedValueEntryResult {
	t.Helper()
	row := base
	row.Slot, row.ValueCore.Name, row.Entry.Name, row.ValueCore.ContentLength = slot, name, name, raw
	row.ValueCore.RetainedLength, row.Entry.ContentLength, row.Entry.RetainedLength = raw, raw, raw
	payload, err := DecodeCanonicalPayload(base.Entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload.ContentLength, payload.RetainedLength, payload.Ciphertext = raw, raw, make([]byte, int(raw)+16)
	row.Entry.ValueBytes, err = EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	row.Access.MaterialContextDigest, err = ValueMaterialContextDigest(row.ValueCore)
	if err != nil {
		t.Fatal(err)
	}
	row.Entry.Recipients = make([]ID, recipients)
	row.Access.Wraps = make([]WrapRow, recipients)
	for i := range row.Entry.Recipients {
		id := generatedRecordID(byte(i + 1))
		row.Entry.Recipients[i] = id
		row.Access.Wraps[i] = base.Access.Wraps[0]
		row.Access.Wraps[i].SubjectID = id
	}
	return row
}

// full_only: false
func TestGeneratedFinalPreparationImageChecksAggregateRawAndCurrentMemberships(t *testing.T) {
	first, _, _ := finalPreparationValidationRows(t, "plain")
	for _, resource := range []string{"raw", "memberships"} {
		for _, over := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_one_over_%t", resource, over), func(t *testing.T) {
				count := 128 // 128 * 65,536 = 8,388,608 bytes; supplied adds zero or one.
				if resource == "memberships" {
					count = 64 // 63 * 64 + 63 + 1 = 4,096; last Generated adds one.
				}
				image := GeneratedFinalPreparationImage{Schema: 1, DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
					MaterializationPhaseID: generatedRecordID(3), ControlBindingDigest: generatedRecordID(4)}
				var frames [][]byte
				var totalRaw, totalMemberships uint64
				for i := range count {
					raw, recipients := uint32(CryptoMaxRawValue), 1
					if resource == "memberships" {
						raw, recipients = 1, 64
						if i == count-1 && !over {
							recipients = 63
						}
					}
					row := finalPreparationValidationSizedGenerated(t, first, uint16(i), fmt.Sprintf("n%03d", i), raw, recipients)
					frame, err := EncodeCryptoGeneratedValueEntriesResult(CryptoGeneratedValueEntriesResult{Final: 1, Rows: []CryptoGeneratedValueEntryResult{row}})
					if err != nil {
						t.Fatal("individual row below all per-row maxima must be valid", err)
					}
					image.Generated = append(image.Generated, row)
					frames = append(frames, frame)
					totalRaw += uint64(raw)
					totalMemberships += uint64(recipients)
				}
				suppliedRaw := uint32(0)
				if resource == "raw" && over {
					suppliedRaw = 1
				}
				suppliedEntry := finalPreparationValidationSizedGenerated(t, first, uint16(count), "zz", suppliedRaw, 1).Entry
				suppliedEntry.ValueSource, suppliedEntry.Generated = Supplied, GeneratedEntryMetadata{}
				entryBody, err := EncodeValueEntry(suppliedEntry)
				if err != nil {
					t.Fatal(err)
				}
				core, err := ValueCoreForEntry(first.ValueCore.DomainID, first.ValueCore.CompatibilityID, suppliedEntry)
				if err != nil {
					t.Fatal(err)
				}
				access := first.Access
				access.Wraps = []WrapRow{first.Access.Wraps[0]}
				access.Wraps[0].SubjectID = suppliedEntry.Recipients[0]
				access.MaterialContextDigest, err = ValueMaterialContextDigest(core)
				if err != nil {
					t.Fatal(err)
				}
				accessBody, err := EncodeAccessRecord(access)
				if err != nil {
					t.Fatal(err)
				}
				supplied := CryptoPreparedSecret{Name: "zz", Slot: uint16(count), EntryBytes: entryBody, AccessRecord: accessBody}
				suppliedFrame, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: 1, Rows: []CryptoPreparedSecret{supplied}})
				if err != nil {
					t.Fatal("individual supplied row must be valid", err)
				}
				image.Supplied = []CryptoPreparedSecret{supplied}
				totalRaw += uint64(suppliedRaw)
				totalMemberships++
				excess := uint64(0)
				if over {
					excess = 1
				}
				if resource == "raw" && (totalRaw != CryptoMaxRawSet+excess || totalMemberships != 129) ||
					resource == "memberships" && (totalMemberships != CryptoMaxMemberships+excess || totalRaw != 64) {
					t.Fatal("fixture aggregate differs from independent expected sums", totalRaw, totalMemberships)
				}
				wire := finalPreparationValidationWire(frames, [][]byte{suppliedFrame})
				if len(wire) >= GeneratedFinalPreparationMaxLength {
					t.Fatal("fixture reached outer image length guard before aggregate guard", len(wire))
				}
				before := bytes.Clone(wire)
				encoded, encodeErr := EncodeGeneratedFinalPreparationImage(image)
				decoded, decodeErr := DecodeGeneratedFinalPreparationImage(wire)
				if !over {
					defer decoded.Clear()
					if encodeErr != nil || decodeErr != nil || len(decoded.Generated) != count || len(decoded.Supplied) != 1 || !bytes.Equal(encoded, wire) {
						t.Fatal("exact aggregate maximum refused or changed", encodeErr, decodeErr)
					}
				} else if encodeErr == nil || decodeErr == nil || !reflect.DeepEqual(decoded, GeneratedFinalPreparationImage{}) {
					decoded.Clear()
					t.Fatal("one-over aggregate admitted or retained partial owned image", encodeErr, decodeErr)
				}
				if !bytes.Equal(wire, before) {
					t.Fatal("aggregate refusal changed borrowed image")
				}
			})
		}
	}
}
