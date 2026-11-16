package contract

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func selectedHistoryFixture(t testing.TB, count int) (ID, ID, GeneratorDescriptor, []SupportRecord) {
	t.Helper()
	id := func(n uint32) ID {
		var out ID
		binary.BigEndian.PutUint32(out[:4], n)
		return out
	}
	domain, owner := id(1), id(2)
	rows := make([][]byte, count)
	for i := range rows {
		h := GeneratorHistory{Schema: 1, PredecessorAttemptID: id(uint32(i + 3)), OwnerID: owner,
			Outcome: GeneratedEffectClosedWithResidue}
		if i+1 < count {
			h.NextAttemptID, h.Edge = id(uint32(i+4)), 2
		}
		var err error
		rows[i], err = EncodeGeneratorHistory(h)
		if err != nil {
			t.Fatal(err)
		}
	}
	descriptor, err := GeneratorVectorDescriptor(GeneratorVectorHistory, rows)
	if err != nil {
		t.Fatal(err)
	}
	records := make([]SupportRecord, count)
	for i, row := range rows {
		carrier := GeneratorVectorCarrier{Schema: 1, DomainID: domain, OwnerKind: 10, OwnerID: owner,
			VectorKind: GeneratorVectorHistory, Ordinal: uint32(i), Vector: descriptor, Row: row}
		records[i] = selectedHistoryCarrier(t, carrier)
	}
	return domain, owner, descriptor, records
}

func selectedHistoryCarrier(t testing.TB, carrier GeneratorVectorCarrier) SupportRecord {
	t.Helper()
	body, err := EncodeGeneratorVectorCarrier(carrier)
	if err != nil {
		t.Fatal(err)
	}
	id, err := GeneratorVectorCarrierID(carrier)
	if err != nil {
		t.Fatal(err)
	}
	return SupportRecord{Kind: GeneratorVectorSupportKind, RecordID: id, Body: body}
}

// full_only: false
func TestSelectedGeneratorVectorIndexChecksCompleteValidHistory(t *testing.T) {
	for _, count := range []int{64, 128, 256} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			domain, owner, descriptor, records := selectedHistoryFixture(t, count)
			index, err := NewSelectedGeneratorVectorIndex(domain, records)
			if err != nil {
				t.Fatal(err)
			}
			for pass := 0; pass < 2; pass++ {
				visited := 0
				err = index.Inspect(10, owner, GeneratorVectorHistory, descriptor, func(ordinal uint32, body []byte) error {
					if int(ordinal) != visited || len(body) != GeneratorHistoryLength {
						t.Fatal("history visit changed order")
					}
					visited++
					return nil
				})
				if err != nil || visited != count {
					t.Fatalf("valid complete history: visited %d, error %v", visited, err)
				}
			}
			for name, damage := range map[string]func([]SupportRecord){
				"duplicate ordinal": func(rows []SupportRecord) { rows[1] = rows[0] },
				"missing ordinal":   func(rows []SupportRecord) { rows[1].Kind = 3 },
				"changed owner": func(rows []SupportRecord) {
					carrier, _ := InspectGeneratorVectorCarrier(rows[1].Body)
					carrier.OwnerID = domain
					rows[1] = selectedHistoryCarrier(t, carrier)
				},
				"changed row": func(rows []SupportRecord) {
					carrier, _ := InspectGeneratorVectorCarrier(rows[1].Body)
					h, _ := InspectGeneratorHistory(carrier.Row)
					h.Outcome = GeneratedEffectTransmitted
					carrier.Row, _ = EncodeGeneratorHistory(h)
					rows[1] = selectedHistoryCarrier(t, carrier)
				},
			} {
				t.Run(name, func(t *testing.T) {
					broken := append([]SupportRecord(nil), records...)
					damage(broken)
					index, err := NewSelectedGeneratorVectorIndex(domain, broken)
					if err == nil {
						visited := 0
						err = index.Inspect(10, owner, GeneratorVectorHistory, descriptor, func(uint32, []byte) error {
							visited++
							return nil
						})
						if visited != 0 {
							t.Fatal("invalid vector exposed a prefix")
						}
					}
					if err == nil {
						t.Fatal("damaged history accepted")
					}
				})
			}
		})
	}
}

func BenchmarkSelectedGeneratorVectorIndexHistory(b *testing.B) {
	for _, count := range []int{64, 128, 256} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			domain, owner, descriptor, records := selectedHistoryFixture(b, count)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				index, err := NewSelectedGeneratorVectorIndex(domain, records)
				if err != nil {
					b.Fatal(err)
				}
				for pass := 0; pass < 2; pass++ {
					if err := index.Inspect(10, owner, GeneratorVectorHistory, descriptor, nil); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedControlledRetirementAdmitsBoundedNonfinalProgress(t *testing.T) {
	// Independent big-endian row: schema, two IDs, descriptor, three octets.
	body := make([]byte, 113)
	binary.BigEndian.PutUint16(body, 1)
	for i := 2; i < 98; i++ {
		body[i] = 1
	}
	binary.BigEndian.PutUint64(body[98:106], 1024)
	binary.BigEndian.PutUint32(body[106:110], 1)
	body[110], body[111], body[112] = 2, 1, 2
	if _, err := InspectGeneratorProgress(body); err != nil {
		t.Fatal("exact two-step nonfinal result evidence refused", err)
	}
	final := append([]byte(nil), body...)
	final[111] = 3
	if _, err := InspectGeneratorProgress(final); err != nil {
		t.Fatal("ordered complete mask refused", err)
	}
	badOrder := append([]byte(nil), body...)
	badOrder[111] = 2
	if _, err := InspectGeneratorProgress(badOrder); err == nil {
		t.Fatal("second step alone admitted")
	}
	for _, steps := range []byte{0, 1, 3, 8} {
		bad := append([]byte(nil), body...)
		bad[110] = steps
		if _, err := InspectGeneratorProgress(bad); err == nil {
			t.Fatal("changed required steps admitted", steps)
		}
	}
}

// full_only: false
func TestGeneratedControlledRetirementDomainSeparatedDigests(t *testing.T) {
	// Independently derived with Node's SHA-256, using literal domain strings
	// and raw 32-byte repeated-octet IDs, not the production encoder.
	id := func(n byte) ID {
		var out ID
		for i := range out {
			out[i] = n
		}
		return out
	}
	scope := GeneratorControlledRetirementScope(id(1), id(2), id(3))
	if hex.EncodeToString(scope[:]) != "48795eb74229d292e631501a4222b2a3542228aad6648659867118b203471b4f" {
		t.Fatal("scope transcript changed")
	}
	probe := GeneratorControlledRetirementProbeDigest(id(4), id(5), id(6), scope, id(7), id(8))
	if hex.EncodeToString(probe[:]) != "834c6b25c2a8169edec6f08767621db551955c0333cdf5184e4281126a30394f" {
		t.Fatal("probe transcript changed")
	}
}

// full_only: false
func TestGeneratedControlledRetirementAdmitsExactScopedFacts(t *testing.T) {
	// Independent Python struct concatenation: schema4, retire2, managed2,
	// scoped-unusable6, reason0, three R1 IDs, target/resource blob1,
	// empty provider blob, observation-tag1 and six R1 observation IDs.
	body, err := hex.DecodeString("000402020600010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101000000010100000001010000000001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101")
	if err != nil || len(body) != 309 {
		t.Fatal("scoped literal", err)
	}
	if _, err := InspectGeneratorSafeFacts(body); err != nil {
		t.Fatal("exact scoped confirmation refused", err)
	}
	for _, offset := range []int{117, 149, 181, 213, 245, 277} {
		bad := append([]byte(nil), body...)
		clear(bad[offset : offset+32])
		if _, err := InspectGeneratorSafeFacts(bad); err == nil {
			t.Fatal("missing exact evidence ID admitted", offset)
		}
	}
	for _, bad := range [][]byte{body[:308], append(append([]byte(nil), body...), 0)} {
		if _, err := InspectGeneratorSafeFacts(bad); err == nil {
			t.Fatal("damaged exact evidence framing admitted")
		}
	}
}
