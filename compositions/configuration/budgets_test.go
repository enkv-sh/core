package configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: true
func TestSourceCumulativeOwnerBudgets(t *testing.T) {
	plainRow := `{"confidentiality":"plain","recipients":[],"source":{"kind":"supplied","value":"` + strings.Repeat("x", 65536) + `"}}`
	build := func(count int, row string, extra bool) string {
		var out strings.Builder
		out.WriteByte('{')
		for i := 0; i < count; i++ {
			if i > 0 {
				out.WriteByte(',')
			}
			fmt.Fprintf(&out, `"e%d":%s`, i, row)
		}
		if extra {
			out.WriteString(`,"s":{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}}`)
		}
		out.WriteByte('}')
		return out.String()
	}
	t.Run("canonical-current-intents", func(t *testing.T) {
		// The independent schema-1 prefix has 67 bytes. A blob32 containing
		// a 393145-byte JSON string makes each complete intent 393216 bytes.
		settings := []byte(`"` + strings.Repeat("x", 393143) + `"`)
		intent := sourceCanonicalIntent(t, true)[:67]
		intent = binary.BigEndian.AppendUint32(intent, uint32(len(settings)))
		intent = append(intent, settings...)
		if len(intent) != 393216 || 128*len(intent) != 50331648 {
			t.Fatal("independent complete current-intent account")
		}
		check := func(t *testing.T, m *Model) {
			t.Helper()
			if len(m.Entries) != 128 || len(m.Public.Entries.Value) != 128 {
				t.Fatal("complete current-intent set was truncated")
			}
			total := 0
			for i, entry := range m.Entries {
				public := m.Public.Entries.Value[i]
				if entry.Name != fmt.Sprintf("e%d", i) || entry.Generated == nil || entry.Generated.Plugin != "" || entry.Generated.Settings != nil || !bytes.Equal(entry.Generated.Intent, intent) || public.Name != entry.Name || public.Generated == nil || public.Generated.ContentIntent.State != contract.PublicPresent || !bytes.Equal(public.Generated.ContentIntent.Value, intent) {
					t.Fatal("canonical current intent or unset local selection changed", i)
				}
				total += len(entry.Generated.Intent)
			}
			if total != 50331648 {
				t.Fatal("complete current-intent bytes differ", total)
			}
		}
		t.Run("parse", func(t *testing.T) {
			row := `{"confidentiality":"secret","recipients":[],"source":{"kind":"generated","plugin":null,"epoch":0,"retirement":"manual","canonical":{"settings":` + string(settings) + `}}}`
			m := &Model{Resolved: true}
			p := newParser(t.Context(), strings.NewReader(build(128, row, false)), JSON)
			parseEntries(p, m)
			if err := p.done(); err != nil {
				t.Fatal("complete current-intent source refused", err)
			}
			rows := make(map[string][]byte, 128)
			for i := 0; i < 128; i++ {
				rows[fmt.Sprintf("e%d", i)] = intent
			}
			records := newParser(t.Context(), strings.NewReader(sourceCanonicalRecordsJSON(t, rows, nil)), JSON)
			parseCanonicalRecords(records, m)
			if err := records.done(); err != nil {
				t.Fatal(err)
			}
			if err := resolveCanonicalSettings(m); err != nil {
				t.Fatal(err)
			}
			if err := RefreshPublic(m); err != nil {
				t.Fatal("parsed current-intent projection refused", err)
			}
			check(t, m)
		})
		t.Run("projection", func(t *testing.T) {
			m := &Model{Resolved: true}
			for i := 0; i < 128; i++ {
				m.Entries = append(m.Entries, Entry{Name: fmt.Sprintf("e%d", i), Secret: true, Generated: &Generator{Retirement: "manual", Intent: intent}})
			}
			if err := RefreshPublic(m); err != nil {
				t.Fatal("complete current-intent projection refused", err)
			}
			check(t, m)
			m.Entries = append(m.Entries, Entry{Name: "excess", Secret: true, Generated: &Generator{Retirement: "manual", Intent: intent}})
			if err := RefreshPublic(m); err == nil {
				t.Fatal("first excess current-intent projection was accepted")
			}
		})
	})
	t.Run("plain-first-excess", func(t *testing.T) {
		m := &Model{}
		p := newParser(context.Background(), strings.NewReader(build(129, plainRow, false)), JSON)
		parseEntries(p, m)
		raw := 0
		for _, e := range m.Entries {
			raw += len(e.Plain)
		}
		if p.done() == nil || raw > 8<<20 {
			t.Fatalf("refusal=%v retained raw=%d", p.err, raw)
		}
	})
	t.Run("joint-plain-and-sealed", func(t *testing.T) {

		one := contract.ID{}
		two := contract.ID{}
		for i := range one {
			one[i] = 1
			two[i] = 2
		}
		core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: 4, Profile: contract.MaterialCryptoProfile, CompatibilityID: one, DomainID: two, FileIdentity: one, SourceID: one, CryptoSupportID: one, DataKeyID: one, DataKeyEpoch: 1, ContentLength: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 1}, Name: "s"}
		envelope, err := contract.EncodeSealedInputEnvelope(contract.SealedInputEnvelope{Core: core, Ciphertext: make([]byte, 17), AuthorityWrap: contract.WrapRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: one, BindingID: one, BindingSerial: 1, PublicBindingDigest: one, RSACiphertext: make([]byte, 384)}})
		if err != nil {
			t.Fatal(err)
		}
		if len(envelope) != 821 {
			t.Fatalf("source envelope length %d, independent 819+1+1", len(envelope))
		}
		generated := strings.Replace(sourceGeneratedJSON, `"secrets":{}`, `"secrets":{"s":{"sealed":"`+base64.StdEncoding.EncodeToString(envelope)+`"}}`, 1)
		for _, exact := range []bool{true, false} {
			t.Run(map[bool]string{true: "exact", false: "first-excess"}[exact], func(t *testing.T) {
				source := build(128, plainRow, true)
				wantPlain := 8 << 20
				if exact {
					// One sealed raw byte fills the last byte of the joint budget.
					source = strings.Replace(source, strings.Repeat("x", 65536), strings.Repeat("x", 65535), 1)
					wantPlain--
				}
				m := &Model{Provider: contract.AWS, Authority: Role{SigningSelector: sourceSigningSelector, EncryptionSelector: sourceEncryptionSelector}}
				p := newParser(context.Background(), strings.NewReader(source), JSON)
				parseEntries(p, m)
				if p.done() != nil {
					t.Fatal(p.err)
				}
				plain := 0
				for _, e := range m.Entries {
					plain += len(e.Plain)
				}
				if plain != wantPlain {
					t.Fatalf("plain charge %d, want %d", plain, wantPlain)
				}
				p = newParser(context.Background(), strings.NewReader(generated), JSON)
				parseGenerated(p, m)
				retained := 0
				for _, e := range m.Entries {
					retained += len(e.Sealed)
				}
				if exact {
					if p.done() != nil || retained != 816 {
						t.Fatalf("exact joint refusal=%v retained sealed=%d", p.err, retained)
					}
				} else if p.done() == nil || retained != 0 {
					t.Fatalf("first-excess joint refusal=%v retained sealed=%d", p.err, retained)
				}
			})
		}

	})
	t.Run("membership-first-excess", func(t *testing.T) {
		var refs strings.Builder
		for i := 0; i < 63; i++ {
			if i > 0 {
				refs.WriteByte(',')
			}
			fmt.Fprintf(&refs, `"r%d"`, i)
		}
		row := `{"confidentiality":"plain","recipients":[` + refs.String() + `],"source":{"kind":"supplied","value":""}}`
		source := strings.TrimSuffix(build(64, row, false), "}") + `,"last":{"confidentiality":"plain","recipients":[],"source":{"kind":"supplied","value":"must-not-be-retained"}}}`
		m := &Model{}
		p := newParser(context.Background(), strings.NewReader(source), JSON)
		parseEntries(p, m)
		if p.done() == nil || len(m.Entries) > 64 {
			t.Fatalf("refusal=%v retained entries=%d", p.err, len(m.Entries))
		}
	})
	t.Run("generated-first-excess-kind-late", func(t *testing.T) {
		row := `{"confidentiality":"secret","recipients":[],"source":{"settings":` + pluginSettings + `,"plugin":"private-generator","epoch":0,"retirement":"manual","kind":"generated"}}`
		m := &Model{}
		p := newParser(context.Background(), strings.NewReader(build(129, row, false)), JSON)
		parseEntries(p, m)
		count := 0
		for _, e := range m.Entries {
			if e.Generated != nil {
				count++
			}
		}
		if p.done() == nil || count > 128 {
			t.Fatalf("refusal=%v retained generated=%d", p.err, count)
		}
	})
	t.Run("canonical-output-declaration", func(t *testing.T) {
		// Independent stored framing is75 bytes: destination name blob7,
		// binding incarnation32, destination(config5+service5+settings6+
		// policy blob4+schema2+contract5+data blob4+capability1), two counts4.
		const framing = 75
		data := make([]byte, contract.MaxOutputPolicyBytes)
		for _, extra := range []int{0, 1} {
			m := &Model{Resolved: true}
			remaining := contract.MaxOutputDeclarationBytes - 6 + extra
			for i := 0; i < contract.MaxOutputBindings; i++ {
				n := min(len(data), remaining-framing)
				if n <= 0 {
					t.Fatal("maximum fixture did not reach all64 bindings")
				}
				name := fmt.Sprintf("d%02d", i)
				m.Outputs = append(m.Outputs, OutputBinding{DestinationID: name, Binding: contract.NormalOutputBinding{DestinationID: name, Destination: contract.OutputDestination{ConfigContractID: "c", ServiceContractID: "s", CanonicalSettings: []byte("{}"), Policy: contract.OutputPolicy{ContractID: "p", Data: data[:n]}}}})
				remaining -= framing + n
			}
			if remaining != 0 {
				t.Fatal("independent complete byte account", remaining)
			}
			err := RefreshPublic(m)
			if (err == nil) != (extra == 0) {
				t.Fatal("complete canonical output declaration bound", extra, err)
			}
		}
	})

}
