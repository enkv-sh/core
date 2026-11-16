package configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestOutputSourcePreservesDefaultAndEntryReplacementLists(t *testing.T) {
	for _, routing := range []string{
		`{"default":["a"],"entries":{"empty":[],"equal":["a"],"other":["b"]}}`,
		`{"entries":{"empty":[],"equal":["a"],"other":["b"]},"default":["a"]}`,
	} {
		p := newParser(t.Context(), strings.NewReader(`{"destinations":{"a":{"plugin":"private","settings":{}},"b":{"plugin":"private","settings":{}}},"routing":`+routing+`}`), JSON)
		m := &Model{Entries: []Entry{{Name: "inherited"}, {Name: "empty"}, {Name: "equal"}, {Name: "other"}}}
		parseOutputs(p, m)
		if err := p.done(); err != nil {
			t.Fatal("default and replacement lists refused", err)
		}
		if err := validateOutputReferences(m); err != nil {
			t.Fatal("valid replacement references refused", err)
		}
		got := make(map[string][]string)
		var defaults []string
		for _, route := range m.Routes {
			if route.Default {
				defaults = route.Destinations
			} else {
				got[route.EntryName] = route.Destinations
			}
		}
		if !reflect.DeepEqual(defaults, []string{"a"}) || len(got) != 3 || len(got["empty"]) != 0 || !reflect.DeepEqual(got["equal"], []string{"a"}) || !reflect.DeepEqual(got["other"], []string{"b"}) {
			t.Fatal("declared inheritance or replacement meaning changed", defaults, got)
		}
		if _, inherited := got["inherited"]; inherited {
			t.Fatal("inherited entry acquired an explicit replacement")
		}
	}
}

// full_only: false
func TestOutputSourceRefusesRecipientAndFallbackRouting(t *testing.T) {
	for _, routing := range []string{`{"default":{"fallback":["a"]}}`, `{"authority":{"entries":{"x":["a"]}}}`, `{"recipients":{"r":{"fallback":["a"]}}}`} {
		p := newParser(t.Context(), strings.NewReader(`{"destinations":{"a":{"plugin":"private","settings":{}}},"routing":`+routing+`}`), JSON)
		parseOutputs(p, &Model{})
		if err := p.done(); err == nil {
			t.Fatal("superseded routing syntax accepted", routing)
		}
	}
	for _, encodings := range []string{`{}`, `{"x":"raw"}`, `{"x":"base64"}`} {
		p := newParser(t.Context(), strings.NewReader(`{"destinations":{"a":{"plugin":"private","settings":{},"encodings":`+encodings+`}}}`), JSON)
		parseOutputs(p, &Model{})
		if err := p.done(); err == nil {
			t.Fatal("superseded destination encodings accepted", encodings)
		}
	}
}

// Two independently bounded carriers have a larger aggregate than their exact
// 32 MiB stored declaration. Both complete-source decoders must preserve it.
// full_only: true
func TestCanonicalOutputSourceChargesAggregateStoredDeclaration(t *testing.T) {
	for _, grouped := range []bool{false, true} {
		t.Run(strconv.FormatBool(grouped), func(t *testing.T) {
			for _, extra := range []int{0, 1} {
				t.Run(strconv.Itoa(extra), func(t *testing.T) {
					base := outputStoredBoundaryBinding(256)
					policyBytes := 508277
					if grouped {
						policyBytes-- // 66 policy occurrences pay the 66-byte group.
					}
					policy := contract.OutputPolicy{ContractID: "p", Data: bytes.Repeat([]byte{7}, policyBytes)}
					var destinations, entries, routes strings.Builder
					backing := map[string][]byte{}
					carrierBytes, encodedBytes := 0, 0
					for i, id := range []string{"d", "e"} {
						binding := base
						binding.DestinationID = id
						binding.Destination.Policy = policy
						binding.Targets = append([]contract.NormalOutputTarget(nil), base.Targets[i*32:(i+1)*32]...)
						for j := range binding.Targets {
							binding.Targets[j].Target.Policy = policy
							binding.Targets[j].Target.TargetData = nil
						}
						if i == 0 {
							binding.Targets[0].Target.TargetData = bytes.Repeat([]byte{11}, 2178+extra)
						}
						body, err := contract.EncodeNormalOutputBinding(binding)
						if err != nil || len(body) > 33554432 {
							t.Fatal("individual carrier does not fit the original codec", err)
						}
						carrierBytes += len(body)
						encodedBytes += base64.StdEncoding.EncodedLen(len(body))
						if i > 0 {
							destinations.WriteByte(',')
						}
						destinations.WriteString(strconv.Quote(id) + `:{"plugin":null,"canonical":{"settings":{}}}`)
						backing[id] = body
						for _, target := range binding.Targets {
							if entries.Len() > 0 {
								entries.WriteByte(',')
								routes.WriteByte(',')
							}
							entries.WriteString(strconv.Quote(target.Name) + `:{"confidentiality":"plain","recipients":[],"source":{"kind":"supplied","value":""}}`)
							routes.WriteString(strconv.Quote(target.Name) + `:[` + strconv.Quote(id) + `]`)
						}
					}
					// Two binding fixed60, 64 target fixed80, 66 policy
					// records508288, one target-data2178, global framing6.
					const stored = 6 + 2*60 + 64*80 + 66*508288 + 2178
					wantCarrier, wantEncoded := 33571270+extra, 44761696
					if grouped {
						wantCarrier -= 66
						wantEncoded -= 88
					}
					if stored != 33554432 || carrierBytes != wantCarrier || encodedBytes != wantEncoded {
						t.Fatal("independent aggregate field algebra changed", carrierBytes, encodedBytes)
					}
					groups := ""
					if grouped {
						groups = `,"groups":[[` + strconv.Quote(base.Targets[0].Name) + `,` + strconv.Quote(base.Targets[1].Name) + `]]`
					}
					output := `"outputs":{"destinations":{` + destinations.String() + `},"routing":{"entries":{` + routes.String() + `}}` + groups + `}`
					source := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{`+entries.String()+`}`, 1)
					source = strings.Replace(source, `"outputs":{"destinations":{},"routing":{}}`, output, 1)
					for _, format := range []Format{JSON, YAML} {
						t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[format], func(t *testing.T) {
							const generated = ".enkv/prod.generated.json"
							editable := strings.TrimSuffix(source, "}") + `,"generated":"` + generated + `"}`
							dir := t.TempDir()
							if err := os.Mkdir(filepath.Join(dir, ".enkv"), 0700); err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(filepath.Join(dir, generated), []byte(sourceGeneratedCanonical(t, nil, backing)), 0600); err != nil {
								t.Fatal(err)
							}
							path := filepath.Join(dir, "configuration")
							if err := os.WriteFile(path, []byte(editable), 0600); err != nil {
								t.Fatal(err)
							}
							pair, err := Capture(context.Background(), path, format)
							var model *Model
							if err == nil {
								defer func() {
									if err := pair.Close(); err != nil {
										t.Error(err)
									}
								}()
								model, err = Parse(context.Background(), pair)
							}
							if extra == 1 {
								field := "canonical_records.outputs.item"
								var diagnostic *Diagnostic
								if !errors.As(err, &diagnostic) || diagnostic.Reason != "output-declaration-limit" || diagnostic.Field != field {
									t.Fatal("aggregate first excess did not return its exact declaration refusal", err)
								}
								return
							}
							if err != nil {
								t.Fatal("bounded complete source charged carrier bytes as stored bytes", err)
							}
							if len(model.Outputs) != 2 || len(model.Entries) != 64 || len(model.Routes) != 64 || len(model.Outputs[0].Binding.Targets) != 32 || len(model.Outputs[1].Binding.Targets) != 32 || len(model.Public.Groups.Value) != map[bool]int{false: 0, true: 1}[grouped] {
								t.Fatal("complete source lost output rows or groups")
							}
						})
					}
				})
			}
		})
	}
}

// Stored declarations reach 32 MiB. Named carriers add their own framing;
// parser admission charges the interpreted declaration independently.
// full_only: true
func TestCanonicalOutputSourceChecksStoredDeclarationIndependently(t *testing.T) {
	binding := outputStoredBoundaryBinding(3)
	body, err := contract.EncodeNormalOutputBinding(binding)
	if err != nil || len(body) != 33555104 {
		t.Fatal("stored-bound parser fixture carrier", len(body), err)
	}
	for _, extra := range []int{0, 1} {
		t.Run(strconv.Itoa(extra), func(t *testing.T) {
			carrier := body
			if extra == 1 {
				before := append(binary.BigEndian.AppendUint32(nil, 2161), bytes.Repeat([]byte{11}, 2161)...)
				after := append(binary.BigEndian.AppendUint32(nil, 2162), bytes.Repeat([]byte{11}, 2162)...)
				if bytes.Count(body, before) != 1 {
					t.Fatal("target-data framing is not unique")
				}
				carrier = bytes.Replace(body, before, after, 1)
			}
			if len(carrier) != 33555104+extra || base64.StdEncoding.EncodedLen(len(carrier)) != 44740140 {
				t.Fatal("independent source-carrier length differs")
			}
			source := `{"destinations":{"d":{"plugin":null,"canonical":{"settings":{}}}},"routing":{}}`
			p := newParser(context.Background(), strings.NewReader(source), JSON)
			m := &Model{}
			parseOutputs(p, m)
			err := p.done()
			if err == nil {
				records := newParser(t.Context(), strings.NewReader(sourceCanonicalRecordsJSON(t, nil, map[string][]byte{"d": carrier})), JSON)
				parseCanonicalRecords(records, m)
				err = records.done()
			}
			if err == nil {
				err = resolveCanonicalSettings(m)
			}
			if (err == nil) != (extra == 0) {
				t.Fatal("parser confused stored and carrier accounts", err)
			}
			if extra == 0 && (len(m.Outputs) != 1 || len(m.Outputs[0].Binding.Targets) != 64 || !bytes.Equal(m.Outputs[0].Binding.Destination.Policy.Data, binding.Destination.Policy.Data)) {
				t.Fatal("exact-bound canonical source lost stored fields")
			}
		})
	}
}

func outputStoredBoundaryBinding(nameBytes int) contract.NormalOutputBinding {
	policy := contract.OutputPolicy{ContractID: "p", Data: bytes.Repeat([]byte{7}, 516098)}
	capabilities := contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot
	binding := contract.NormalOutputBinding{DestinationID: "d", Destination: contract.OutputDestination{ConfigContractID: "c", ServiceContractID: "s", CanonicalSettings: []byte(`{}`), Policy: policy, Capabilities: capabilities}}
	for i := 0; i < 64; i++ {
		suffix := strconv.Itoa(100 + i)[1:]
		name := strings.Repeat("n", nameBytes-2) + suffix
		target := contract.OutputTarget{ServiceContractID: "s", TargetContractID: "t", CanonicalTarget: "t" + suffix, PayloadEncoding: contract.OutputEncodingBase64, LocatorRequiresCreation: true, Policy: policy, Capabilities: capabilities}
		if i == 0 {
			target.TargetData = bytes.Repeat([]byte{11}, 2161)
		}
		binding.Targets = append(binding.Targets, contract.NormalOutputTarget{Name: name, Target: target})
	}
	return binding
}

func parseOutputSource(t *testing.T, source string) *Model {
	t.Helper()
	p := newParser(context.Background(), strings.NewReader(source), JSON)
	m := &Model{}
	parseOutputs(p, m)
	if err := p.done(); err != nil {
		t.Fatal(err)
	}
	return m
}

// full_only: false
func TestOutputSourceRoutingReferences(t *testing.T) {
	source := `{"destinations":{"a":{"plugin":"private-output-a","settings":{"opaque":1}},"b":{"settings":{"opaque":2},"plugin":"private-output-b"}},"routing":{"default":["a"],"entries":{"": ["b"]}},"groups":[["other",""]]}`
	for _, condition := range []string{"valid", "recipients-independent", "unknown-destination", "unknown-entry", "unknown-group"} {
		t.Run(condition, func(t *testing.T) {
			m := parseOutputSource(t, source)
			m.Entries = []Entry{{Name: "", Recipients: []string{"r"}}, {Name: "other"}}
			m.Recipients = []Recipient{{Reference: "r"}}
			switch condition {
			case "recipients-independent":
				m.Recipients = nil
			case "unknown-destination":
				m.Routes[0].Destinations = []string{"missing"}
			case "unknown-entry":
				m.Routes = append(m.Routes, Route{EntryName: "missing", Destinations: []string{"a"}})
			case "unknown-group":
				m.Public.Groups.Value[0][0] = "missing"
			}
			err := validateOutputReferences(m)
			if (err == nil) != (condition == "valid" || condition == "recipients-independent") {
				t.Fatalf("reference result: %v", err)
			}
		})
	}
}

// full_only: false
func TestOutputSourceRefusesInvalidStructure(t *testing.T) {
	for name, source := range map[string]string{
		"old route shape":   `{"destinations":{},"routing":{"default":{"fallback":[]}}}`,
		"duplicate route":   `{"destinations":{},"routing":{"default":["a","a"]}}`,
		"duplicate group":   `{"destinations":{},"routing":{},"groups":[["x"],["x"]]}`,
		"empty group":       `{"destinations":{},"routing":{},"groups":[[]]}`,
		"unsafe selection":  `{"destinations":{"a":{"plugin":"../private","settings":{}}},"routing":{}}`,
		"missing selection": `{"destinations":{"a":{"plugin":null,"settings":{}}},"routing":{}}`,
		"old profile arm":   `{"destinations":{"a":{"profile":{"name":"old","version":"3"},"spec":{}}},"routing":{}}`,
		"two settings arms": `{"destinations":{"a":{"plugin":"private","settings":{},"canonical":{"settings":{}}}},"routing":{}}`,
		"invalid encoding":  `{"destinations":{"a":{"plugin":"private","settings":{},"encodings":{"entry":"hex"}}},"routing":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(source), JSON)
			parseOutputs(p, &Model{})
			if p.done() == nil {
				t.Fatal("invalid output source accepted")
			}
		})
	}
}
