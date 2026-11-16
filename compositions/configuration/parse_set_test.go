package configuration

import (
	"bytes"
	"context"
	"encoding/base64"

	"enkv.sh/core/contract"
	"strings"
	"testing"
)

// full_only: false
func TestSetPreparationJoins(t *testing.T) {
	secret := `{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}}`
	for _, name := range []string{"token", ""} {
		t.Run("selected-"+name, func(t *testing.T) {
			entries := `{"` + name + `":` + secret + `}`
			editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":`+entries, 1)
			pair := writePair(t, editable, sourceGeneratedJSON, JSON)
			if _, err := Parse(context.Background(), pair); err == nil {
				t.Fatal("ordinary parse accepted missing prepared secret")
			}
			m, err := ParseForSet(context.Background(), pair, name)
			if err != nil || !m.Resolved || len(m.Entries) != 1 || m.SelectedSecretPresent {
				t.Fatalf("selected missing row refused or invented: %v", err)
			}
			if editable[m.SelectedConfidentialityOffset:m.SelectedConfidentialityOffset+m.SelectedConfidentialityLength] != `"secret"` {
				t.Fatal("selected confidentiality token span differs")
			}
			s := m.Spans[m.EntriesSpan]
			if s.Kind != SpanEntries || editable[s.Offset:s.Offset+s.Length] != entries {
				t.Fatal("editable entries map span differs")
			}
			s = m.Spans[m.SecretsSpan]
			if s.Kind != SpanSecrets || sourceGeneratedJSON[s.Offset:s.Offset+s.Length] != `{}` {
				t.Fatal("generated secrets map span differs")
			}
		})
	}
	t.Run("unrelated-present-invalid", func(t *testing.T) {
		editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"token":`+secret+`,"other":`+secret+`}`, 1)
		generated := strings.Replace(sourceGeneratedJSON, `"secrets":{}`, `"secrets":{"other":{"sealed":"AQ=="}}`, 1)
		pair := writePair(t, editable, generated, JSON)
		if _, err := ParseForSet(context.Background(), pair, "token"); err == nil {
			t.Fatal("preparation hid an invalid present sibling record")
		}
	})
	t.Run("present-malformed-selected", func(t *testing.T) {
		editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"token":`+secret+`}`, 1)
		generated := strings.Replace(sourceGeneratedJSON, `"secrets":{}`, `"secrets":{"token":{"sealed":"AQ=="}}`, 1)
		pair := writePair(t, editable, generated, JSON)
		if _, err := ParseForSet(context.Background(), pair, "token"); err == nil {
			t.Fatal("selected exception hid malformed present row")
		}
	})
	t.Run("stale-key", func(t *testing.T) {
		editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"token":`+secret+`}`, 1)
		generated := strings.Replace(sourceGeneratedJSON, sourceSigningSelector, sourceEncryptionSelector, 1)
		pair := writePair(t, editable, generated, JSON)
		if _, err := ParseForSet(context.Background(), pair, "token"); err == nil {
			t.Fatal("selected exception hid stale prepared key")
		}
	})
	for _, presentEntry := range []bool{false, true} {
		t.Run(map[bool]string{false: "inactive-absent", true: "inactive-plain"}[presentEntry], func(t *testing.T) {
			row := `{"retained":{"incarnation":"` + sourceID4 + `","material":"` + sourceID5 + `"}}`
			generated := strings.Replace(sourceGeneratedJSON, `"secrets":{}`, `"secrets":{"token":`+row+`}`, 1)
			editable := sourceSetupJSON
			if presentEntry {
				editable = strings.Replace(editable, `"entries":{}`, `"entries":{"token":{"confidentiality":"plain","recipients":[],"source":{"kind":"supplied","value":"old"}}}`, 1)
			}
			pair := writePair(t, editable, generated, JSON)
			m, err := ParseForSet(context.Background(), pair, "token")
			if err != nil || !m.SelectedSecretPresent {
				t.Fatalf("inactive row span unavailable: %v", err)
			}
			s := m.Spans[m.SelectedSecretSpan]
			if s.Kind != SpanSecret || generated[s.Offset:s.Offset+s.Length] != row {
				t.Fatal("selected inactive row span differs")
			}
		})
	}
}

// full_only: false
func TestSourceCaptureDiscardsPayloadOwners(t *testing.T) {
	editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"p":{"confidentiality":"plain","recipients":[],"source":{"kind":"supplied","value":"public"}},"g":{"confidentiality":"secret","recipients":[],"source":{"kind":"generated","plugin":"private-generator","epoch":0,"retirement":"manual","settings":`+pluginSettings+`}}}`, 1)
	pair := writePair(t, editable, sourceGeneratedJSON, JSON)
	demand, err := parseEditableMode(context.Background(), pair.Editable, JSON, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if demand.Public.Entries.State != contract.PublicMissing || len(demand.Entries) != 2 {
		t.Fatal("demand scan retained a public projection")
	}
	for _, e := range demand.Entries {
		if len(e.Plain) != 0 || len(e.Sealed) != 0 || e.Generated != nil && (len(e.Generated.Intent) != 0 || len(e.Generated.Settings) != 0) {
			t.Fatal("demand scan retained a proportional payload owner")
		}
	}
	// Capture releases its scan model before the caller normalizes.
	demand = nil
	normal, err := Parse(context.Background(), pair)
	if err != nil || len(normal.Entries[1].Plain) != 6 || !bytes.Equal(normal.Entries[0].Generated.Settings, []byte(pluginSettings)) {
		t.Fatalf("normalization lost complete payloads: %v", err)
	}
}

// full_only: false
func TestSourceSealedContext(t *testing.T) {
	one, two := contract.ID{}, contract.ID{}
	for i := range one {
		one[i], two[i] = 1, 2
	}
	for _, damage := range []string{"none", "domain", "file", "name"} {
		t.Run(damage, func(t *testing.T) {
			domain, file, name := two, one, "token"
			switch damage {
			case "domain":
				domain = one
			case "file":
				file = two
			case "name":
				name = "other"
			}
			core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: 4, Profile: contract.MaterialCryptoProfile, CompatibilityID: one, DomainID: domain, FileIdentity: file, SourceID: one, CryptoSupportID: one, DataKeyID: one, DataKeyEpoch: 1, ContentLength: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 1}, Name: name}
			// This opaque source-shaped envelope proves source joins only. It is not
			// cryptographic evidence and cannot authorize an effect.
			envelope, err := contract.EncodeSealedInputEnvelope(contract.SealedInputEnvelope{Core: core, Ciphertext: make([]byte, 17), AuthorityWrap: contract.WrapRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: one, BindingID: one, BindingSerial: 1, PublicBindingDigest: one, RSACiphertext: make([]byte, 384)}})
			if err != nil {
				t.Fatal(err)
			}
			if len(envelope) != 825 {
				t.Fatal("sealed source fixture differs from independent 819+5+1 length")
			}
			editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"token":{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}}}`, 1)
			generated := strings.Replace(sourceGeneratedJSON, `"secrets":{}`, `"secrets":{"token":{"sealed":"`+base64.StdEncoding.EncodeToString(envelope)+`"}}`, 1)
			pair := writePair(t, editable, generated, JSON)
			normal, err := Parse(context.Background(), pair)
			if damage != "none" {
				if err == nil {
					t.Fatal("parser accepted stale context")
				}
				if _, err = ParseForSet(context.Background(), pair, "token"); err == nil {
					t.Fatal("set exception hid stale selected row")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			e := normal.Entries[0]
			if len(e.Sealed) != 825 || e.Retained != nil {
				t.Fatal("normalization lost source-shaped sealed payload")
			}
		})
	}
}
