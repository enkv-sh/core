package configuration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

// These file tests establish exact local transforms with structurally valid
// candidates. Independent Core tests own authentication and selected semantics.
func maintenanceFileFixture(t *testing.T, encoding Format, kind uint16) (*Pair, MaintenanceRequest, MaintenanceMaterial) {
	t.Helper()
	pair, m, _, base := successorFileFixture(t, encoding)
	h, err := format.DecodeHead(base.SignedCandidate)
	if err != nil {
		t.Fatal(err)
	}
	h.Subject.OperationKind = kind
	request := MaintenanceRequest{OperationKind: kind}
	material := MaintenanceMaterial{RequestIdentity: successorID(37)}
	if kind == contract.OperationRetireRecipientIdentity {
		request.RecipientReference = "chosen"
		request.RecipientID = successorID(6)
		request.BindingDigest, err = contract.PublicBindingDigest(base.Control.AuthorityKMSBinding)
		if err != nil {
			t.Fatal(err)
		}
		row, err := contract.NewRecipientRetirementRow(1, contract.RecipientRecord{RecipientID: request.RecipientID, Status: contract.CurrentRecipient, DisplayName: "pending-name", CurrentBinding: &base.Control.AuthorityKMSBinding})
		if err != nil {
			t.Fatal(err)
		}
		material.Retirement = &row
		h.Subject.Exclusion.Retirements, err = contract.RetirementDescriptor(m.DomainID, []contract.RecipientRetirementRow{row})
		if err != nil {
			t.Fatal(err)
		}
		h.Subject.Normal.Changed = 0
		h.Subject.IdentityPlan.Length = 197
		// The 888-byte complete intent adds the 120-byte retirement record.
		h.Subject.Normal.Intent.Length = 1008
	} else {
		request.Name = "opaque"
		h.Subject.BeforeSecretCount, h.Subject.AfterSecretCount = 1, 1
		// Complete intent: 882 fixed + 6 name bytes; rekey target: 147 fixed + 6 name bytes.
		h.Subject.Normal.Intent.Length = 1041
		material.RekeyTarget = &contract.SecretAccessTarget{Slot: 0, Name: request.Name, Incarnation: successorID(50), Material: successorID(51), BeforePublicEntryDigest: successorID(53)}
	}
	if kind == contract.OperationEnvelopeRekey {
		maintenanceCandidateFixture(t, &h, &material, base.Control, 5)
	}
	material.SignedCandidate, err = format.EncodeHead(h)
	if err != nil {
		t.Fatal(err)
	}
	return pair, request, material
}

func maintenanceImageBytes(t *testing.T, image *Image) []byte {
	t.Helper()
	body, err := io.ReadAll(io.NewSectionReader(image, 0, image.Size()))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestMaintenanceRetirementPreservesIndependentPair(t *testing.T) {
	for _, encoding := range []Format{JSON, YAML} {
		t.Run(fmt.Sprint(encoding), func(t *testing.T) {
			original, request, material := maintenanceFileFixture(t, encoding, contract.OperationRetireRecipientIdentity)
			editable := string(maintenanceImageBytes(t, original.Editable))
			editable = sourceWithPlugins(editable, encoding, sourcePluginRequirements)
			generated := string(maintenanceImageBytes(t, original.Generated))
			entry := `{"pending":{"confidentiality":"plain","recipients":["chosen"],"source":{"kind":"supplied","value":"chosen remains ordinary text"}}}`
			outputs := `{"destinations":{"sink":{"plugin":"aws-secrets-manager","settings":{"account":"123456789012","region":"us-east-1"}}},"routing":{"entries":{"pending":["sink"]}}}`
			if encoding == JSON {
				editable = strings.Replace(editable, `"entries":{}`, `"entries":`+entry, 1)
				editable = strings.Replace(editable, `"outputs":{"destinations":{},"routing":{}}`, `"outputs":`+outputs, 1)
			} else {
				editable = strings.Replace(editable, "entries: {}", "entries: "+entry+" # membership comment", 1)
				editable = strings.Replace(editable, "outputs:\n  destinations: {}\n  routing: {}", "outputs: "+outputs+" # routing comment", 1)
			}
			historical := `{"kind":"successor","control":"AQ==","selection":"Ag==","enrollment":[{"id":"` + strings.Repeat("06", 32) + `","status":"current","display_name":"historical chosen"}]}`
			generated = strings.Replace(generated, `{"kind":"genesis","descriptor":"AQ=="}`, historical, 1)
			pair := captureEditableEmission(t, []byte(editable), []byte(generated), encoding, ".enkv/prod.generated.json")
			sourceEditable, sourceGenerated := maintenanceImageBytes(t, pair.Editable), maintenanceImageBytes(t, pair.Generated)
			path := filepath.Join(t.TempDir(), "successor")
			const padding = 1 << 20
			backing := strings.Repeat("x", padding) + path + strings.Repeat("x", padding)
			input := backing[padding : padding+len(path)]
			capture, err := CaptureMaintenanceOutput(t.Context(), input, encoding)
			if err != nil {
				t.Fatal(err)
			}
			if capture.aliasParent != filepath.Dir(path) {
				t.Error("captured output parent differs from selected parent")
			}
			if unsafe.StringData(capture.aliasParent) == unsafe.StringData(input) {
				t.Error("captured output parent retains oversized caller backing")
			}
			for parent := range capture.parent.aliases {
				if unsafe.StringData(parent) == unsafe.StringData(input) {
					t.Error("captured output alias pin retains oversized caller backing")
				}
			}
			output, err := PrepareMaintenanceOutputFromCapture(t.Context(), pair, capture, request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, output)
			readback, err := output.Publish(t.Context(), material)
			if err != nil {
				t.Fatal(err)
			}
			if !output.Delivered() || output.LocalDelivery() == nil || output.Path() != path {
				t.Fatal("exact native delivery facts missing")
			}
			after := readback.Model
			requirePreservedPlugins(t, maintenanceImageBytes(t, readback.Pair.Editable))
			if len(after.Recipients) != 0 || len(after.GeneratedRecipients) != 1 || after.GeneratedRecipients[0].Reference != "unreferenced" || len(after.Entries) != 1 || len(after.Entries[0].Recipients) != 0 || !reflect.DeepEqual(after.Routes, []Route{{EntryName: "pending", Destinations: []string{"sink"}}}) {
				t.Fatal("retirement left a live join or removed an unrelated row")
			}
			if string(after.Entries[0].Plain) != "chosen remains ordinary text" || !bytes.Contains(maintenanceImageBytes(t, readback.Pair.Generated), []byte(historical)) {
				t.Fatal("unrelated value or historical public basis changed")
			}
			beforeSecret := sourceGenerated[bytes.Index(sourceGenerated, []byte(`"secrets":`)):bytes.Index(sourceGenerated, []byte(`,"public_basis":`))]
			if !bytes.Contains(maintenanceImageBytes(t, readback.Pair.Generated), beforeSecret) {
				t.Fatal("original sealed context changed")
			}
			if encoding == YAML {
				for _, comment := range []string{"# retained comment", "# membership comment", "# routing comment"} {
					if !bytes.Contains(maintenanceImageBytes(t, readback.Pair.Editable), []byte(comment)) {
						t.Fatal("unrelated comment removed", comment)
					}
				}
			}
			if err := output.CheckUnchanged(t.Context()); err != nil {
				t.Fatal(err)
			}
			identity, err := output.OutputIdentity()
			if err != nil || identity.Editable.Digest.IsZero() || identity.Generated.Digest.IsZero() {
				t.Fatal("external output pins missing", err)
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			observed, err := PrepareMaintenanceOutput(t.Context(), pair, input, request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, observed)
			capture = observed.capture.(*MaintenanceOutputCapture)
			if capture.aliasParent != filepath.Dir(path) {
				t.Error("captured output parent differs from selected parent")
			}
			if unsafe.StringData(capture.aliasParent) == unsafe.StringData(input) {
				t.Error("captured output parent retains oversized caller backing")
			}
			for parent := range capture.parent.aliases {
				if unsafe.StringData(parent) == unsafe.StringData(input) {
					t.Error("captured output alias pin retains oversized caller backing")
				}
			}
			if observed.Existing() == nil || observed.editor != nil || observed.Delivered() {
				t.Fatal("existing output acquired mutation or delivery authority")
			}
			if _, err := observed.Publish(t.Context(), material); !errors.Is(err, ErrEdit) {
				t.Fatal("observation allowed publication", err)
			}
			if err := observed.Close(); err != nil {
				t.Fatal(err)
			}
			outputBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			requirePreservedPlugins(t, outputBytes)
			changed := bytes.Replace(outputBytes, []byte(sourcePluginRequirements), []byte(strings.Replace(sourcePluginRequirements, "1.2.3", "1.2.4", 1)), 1)
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if tampered, err := PrepareMaintenanceOutput(t.Context(), pair, input, request); err == nil {
				closeSourceOwner(t, tampered)
				t.Fatal("existing successor accepted changed source plugin version")
			}
			actualEditable, err := os.ReadFile(pair.Editable.OriginalPath())
			if err != nil || !bytes.Equal(actualEditable, sourceEditable) {
				t.Fatal("editable source changed", err)
			}
			actualGenerated, err := os.ReadFile(pair.Generated.OriginalPath())
			if err != nil || !bytes.Equal(actualGenerated, sourceGenerated) {
				t.Fatal("generated source changed", err)
			}
		})
	}
}

// full_only: false
func TestMaintenanceRekeyChangesOnlyExactRetainedPin(t *testing.T) {
	for _, condition := range []string{"retained", "stale-retained", "sealed-pending", "absent-pending", "duplicate-delta", "changed-incarnation", "unchanged-material"} {
		t.Run(condition, func(t *testing.T) {
			original, request, material := maintenanceFileFixture(t, JSON, contract.OperationEnvelopeRekey)
			editable := string(maintenanceImageBytes(t, original.Editable))
			generated := string(maintenanceImageBytes(t, original.Generated))
			before := contract.RetainedSecretInput{Incarnation: successorID(50), Material: successorID(51)}
			after := contract.RetainedSecretInput{Incarnation: before.Incarnation, Material: successorID(52)}
			material.PinDeltas = []MaintenancePinDelta{{Name: "opaque", Before: before, After: after}}
			if condition != "absent-pending" {
				editable = strings.Replace(editable, `"entries":{}`, `"entries":{"opaque":{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}}}`, 1)
			}
			if condition != "sealed-pending" {
				old := base64.StdEncoding.EncodeToString(sourceEditEnvelope(t, "opaque"))
				pin := `{"retained":{"incarnation":"` + strings.Repeat("32", 32) + `","material":"` + strings.Repeat("33", 32) + `"}}`
				generated = strings.Replace(generated, `{"sealed":"`+old+`"}`, pin, 1)
			}
			if condition == "stale-retained" {
				material.PinDeltas[0].Before.Material = successorID(99)
			}
			if condition == "changed-incarnation" {
				material.PinDeltas[0].After.Incarnation = successorID(99)
			}
			if condition == "unchanged-material" {
				material.PinDeltas[0].After.Material = before.Material
			}
			if condition == "duplicate-delta" {
				material.PinDeltas = append(material.PinDeltas, material.PinDeltas[0])
			}
			pair := captureEditableEmission(t, []byte(editable), []byte(generated), JSON, ".enkv/prod.generated.json")
			output, err := PrepareMaintenanceOutput(t.Context(), pair, filepath.Join(t.TempDir(), "successor"), request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, output)
			result, err := output.Publish(t.Context(), material)
			if condition == "stale-retained" || condition == "duplicate-delta" || condition == "changed-incarnation" || condition == "unchanged-material" {
				if result != nil || !errors.Is(err, ErrEdit) || output.Delivered() {
					t.Fatal("invalid pin delta became a delivery", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch condition {
			case "retained":
				pin := result.Model.Entries[0].Retained
				if pin == nil || pin.Incarnation != after.Incarnation || pin.Material != after.Material {
					t.Fatal("exact retained material was not refreshed")
				}
			case "sealed-pending":
				if result.Model.Entries[0].Retained != nil || !bytes.Equal(result.Model.Entries[0].Sealed, sourceEditEnvelope(t, "opaque")) {
					t.Fatal("sealed pending input was converted or changed")
				}
			case "absent-pending":
				if len(result.Model.Entries) != 0 || !bytes.Contains(maintenanceImageBytes(t, result.Pair.Generated), []byte(`"material":"`+strings.Repeat("33", 32)+`"`)) {
					t.Fatal("inactive retained row was repinned by name")
				}
			}
			if err := output.CheckUnchanged(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// full_only: false
func TestMaintenanceMetadataRejectsCorrelationTransplants(t *testing.T) {
	pair, request, material := maintenanceFileFixture(t, JSON, contract.OperationRetireRecipientIdentity)
	output, err := PrepareMaintenanceOutput(t.Context(), pair, filepath.Join(t.TempDir(), "successor"), request)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceOwner(t, output)
	readback, err := output.Publish(t.Context(), material)
	if err != nil {
		t.Fatal(err)
	}
	original := readback.Model.Maintenance
	body, err := maintenanceMetadataBytes(original)
	if err != nil {
		t.Fatal(err)
	}
	p := newParser(t.Context(), bytes.NewReader(body), JSON)
	parsed := parseMaintenanceMetadata(p)
	if err := p.done(); err != nil || !reflect.DeepEqual(parsed, original) {
		t.Fatal("closed metadata roundtrip changed correlation", err)
	}
	for _, condition := range []string{"kind", "request-core", "operation", "retirement", "file", "path", "source", "request-identity", "candidate", "unknown", "duplicate"} {
		t.Run(condition, func(t *testing.T) {
			damaged := bytes.Clone(body)
			switch condition {
			case "kind":
				damaged = bytes.Replace(damaged, []byte(`"operation_kind": 10`), []byte(`"operation_kind": 11`), 1)
			case "request-core":
				damaged = bytes.Replace(damaged, []byte(fmt.Sprintf(`"request_core_digest": "%x"`, original.RequestCoreDigest)), []byte(fmt.Sprintf(`"request_core_digest": "%x"`, successorID(90))), 1)
			case "operation":
				damaged = bytes.Replace(damaged, []byte(fmt.Sprintf(`"operation_id": "%x"`, original.OperationID)), []byte(fmt.Sprintf(`"operation_id": "%x"`, successorID(90))), 1)
			case "retirement":
				damaged = bytes.Replace(damaged, []byte(`"before_record_length": `), []byte(`"before_record_length": 9`), 1)
			case "file":
				damaged = bytes.Replace(damaged, []byte(fmt.Sprintf(`"file_id": "%x"`, original.FileID)), []byte(fmt.Sprintf(`"file_id": "%x"`, successorID(90))), 1)
			case "path":
				damaged = bytes.Replace(damaged, []byte(original.OutputPath), []byte(original.OutputPath+"-other"), 1)
			case "source":
				damaged = bytes.Replace(damaged, []byte(fmt.Sprintf(`"editable_digest": "%x"`, original.Source.Editable.Digest)), []byte(fmt.Sprintf(`"editable_digest": "%x"`, successorID(90))), 1)
			case "request-identity":
				damaged = bytes.Replace(damaged, []byte(fmt.Sprintf(`"request_identity": "%x"`, original.RequestIdentity)), []byte(fmt.Sprintf(`"request_identity": "%x"`, successorID(90))), 1)
			case "candidate":
				damaged = bytes.Replace(damaged, []byte(base64.StdEncoding.EncodeToString(original.SignedCandidate)), []byte("AQ=="), 1)
			case "unknown":
				damaged = append([]byte(`{"foreign":true,`), damaged[1:]...)
			case "duplicate":
				damaged = append([]byte(`{"kind":"maintenance-successor/v1",`), damaged[1:]...)
			}
			if bytes.Equal(damaged, body) {
				t.Fatal("damage did not select metadata field")
			}
			parser := newParser(t.Context(), bytes.NewReader(damaged), JSON)
			metadata := parseMaintenanceMetadata(parser)
			parseErr := parser.done()
			if condition == "file" || condition == "path" || condition == "source" || condition == "request-identity" {
				if parseErr != nil {
					t.Fatal("structural parser consumed source/output authority", parseErr)
				}
				clone := *readback.Model
				clone.Maintenance = metadata
				if err := output.checkOutput(t.Context(), readback.Pair, &clone); !errors.Is(err, ErrEdit) {
					t.Fatal("source/output transplant admitted", err)
				}
			} else if parseErr == nil {
				t.Fatal("invalid closed correlation parsed")
			}
		})
	}
}

// full_only: false
func TestMaintenanceCollectionDeletionPreservesOtherBytes(t *testing.T) {
	cases := []struct {
		name, source, want string
		encoding           Format
		array              bool
	}{
		{"object-only", `{"chosen":1}`, `{}`, JSON, false},
		{"object-first", `{"chosen":1, "keep":2}`, `{ "keep":2}`, JSON, false},
		{"object-middle", `{"left":1, "chosen":2, "right":3}`, `{"left":1,  "right":3}`, JSON, false},
		{"object-last", `{"keep":1, "chosen":2}`, `{"keep":1 }`, JSON, false},
		{"yaml-flow-trailing", `{chosen: 1,}`, `{}`, YAML, false},
		{"yaml-object-only", "chosen: 1 # keep comment\n", "{} # keep comment\n", YAML, false},
		{"array-only", `["chosen"]`, `[]`, JSON, true},
		{"array-first", `["chosen", "keep"]`, `[ "keep"]`, JSON, true},
		{"array-last", `["keep", "chosen"]`, `["keep" ]`, JSON, true},
		{"yaml-array-only", "- chosen # keep comment\n", "[] # keep comment\n", YAML, true},
		{"yaml-array-block", "- left\n- chosen # keep comment\n- right\n", "- left\n # keep comment\n- right\n", YAML, true},
		{"yaml-flow-comments", "[left, # comma , in comment\n chosen, right]", "[left, # comma , in comment\n  right]", YAML, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "image")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString(tc.source); err != nil {
				t.Fatal(err)
			}
			image := &Image{file: file, size: int64(len(tc.source))}
			defer closeSourceOwner(t, image)
			p := newParser(t.Context(), strings.NewReader(tc.source), tc.encoding)
			removal := maintenanceRemoval{container: p.mark(0, 0), selected: -1, array: tc.array}
			record := func(name string, item Span) {
				item.Length = p.end - item.Offset
				if name == "chosen" {
					removal.selected = len(removal.items)
				}
				removal.items = append(removal.items, item)
			}
			if tc.array {
				p.array(10, func(_ int) { item := p.arrayItem; name := p.text(256, false, false); record(name, item) })
			} else {
				p.object(10, func(name string) { item := p.member; p.integer(); record(name, item) })
			}
			removal.container.Length = p.end - removal.container.Offset
			if err := p.done(); err != nil {
				t.Fatal(err)
			}
			edits, err := maintenanceCollectionEdits(t.Context(), image, tc.encoding, removal)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := CopyEdits(t.Context(), &out, image, edits); err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want {
				t.Fatalf("preserved bytes differ: got %q want %q", out.String(), tc.want)
			}
		})
	}
}

// full_only: false
func TestMaintenanceOutputRefusesAliasesAndChangedCapture(t *testing.T) {
	for _, condition := range []string{"same-directory", "hardlink", "appeared", "wrong-target"} {
		t.Run(condition, func(t *testing.T) {
			pair, request, _ := maintenanceFileFixture(t, JSON, contract.OperationRetireRecipientIdentity)
			path := filepath.Join(t.TempDir(), "successor")
			if condition == "same-directory" {
				path = filepath.Join(filepath.Dir(pair.Editable.OriginalPath()), "other")
			}
			if condition == "hardlink" {
				if err := os.Link(pair.Editable.OriginalPath(), path); err != nil {
					t.Fatal(err)
				}
			}
			capture, err := CaptureMaintenanceOutput(t.Context(), path, JSON)
			if err != nil {
				if condition == "hardlink" {
					return
				}
				t.Fatal(err)
			}
			defer closeSourceOwner(t, capture)
			if condition == "appeared" {
				if err := os.WriteFile(path, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			changed := request
			if condition == "wrong-target" {
				changed.RecipientID = successorID(99)
			}
			result, err := PrepareMaintenanceOutputFromCapture(t.Context(), pair, capture, changed)
			if result != nil || err == nil {
				if result != nil {
					_ = result.Close()
				}
				t.Fatal("invalid source/output boundary admitted")
			}
		})
	}
	pair, request, material := maintenanceFileFixture(t, JSON, contract.OperationRetireRecipientIdentity)
	output, err := PrepareMaintenanceOutput(t.Context(), pair, filepath.Join(t.TempDir(), "successor"), request)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceOwner(t, output)
	failure := errors.New("controlled stage failure")
	output.io.syncFile = func(*os.File) error { return failure }
	if result, err := output.Publish(t.Context(), material); result != nil || !errors.Is(err, failure) || output.Delivered() {
		t.Fatal("failed stage became delivery or lost cause", err)
	}
	if _, err := output.Publish(t.Context(), material); !errors.Is(err, ErrEdit) {
		t.Fatal("failed publication was replayed", err)
	}
}

// full_only: false
func TestMaintenancePublicationTelemetryExcludesPrivateContext(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(fmt.Sprint(refused), func(t *testing.T) {
			pair, request, material := maintenanceFileFixture(t, JSON, contract.OperationRetireRecipientIdentity)
			path := filepath.Join(t.TempDir(), "private-path-sentinel")
			output, err := PrepareMaintenanceOutput(t.Context(), pair, path, request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, output)
			failure := errors.New("private-error-sentinel")
			if refused {
				output.io.syncFile = func(*os.File) error { return failure }
			}
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder))
			result, err := output.Publish(ctx, material)
			if refused {
				if result != nil || !errors.Is(err, failure) {
					t.Fatal("write refusal lost cause", err)
				}
			} else if err != nil || result == nil {
				t.Fatal("publication failed", err)
			}
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 64))
			starts, returns := 0, 0
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Operation != telemetry.OpConfigurationWrite {
					continue
				}
				switch record.Event {
				case telemetry.DiagnosticStart:
					starts++
				case telemetry.DiagnosticReturn:
					returns++
					want := telemetry.ResultSuccess
					if refused {
						want = telemetry.ResultWriteRefused
					}
					if record.Result != want {
						t.Fatal("wrong maintenance write outcome")
					}
				}
			}
			if starts != 1 || returns != 1 {
				t.Fatal("maintenance write lacks exactly one terminal", starts, returns)
			}
			encoded, err := json.Marshal(records)
			if err != nil || bytes.Contains(encoded, []byte("sentinel")) || bytes.Contains(encoded, []byte(sourceEncryptionSelector)) {
				t.Fatal("telemetry exposed private context", err)
			}
		})
	}
}

// full_only: false
func TestMaintenanceExistingOutputBindsBeforePinToPredecessor(t *testing.T) {
	for _, encoding := range []Format{JSON, YAML} {
		t.Run(fmt.Sprint(encoding), func(t *testing.T) {
			original, request, material := maintenanceFileFixture(t, encoding, contract.OperationEnvelopeRekey)
			editable := string(maintenanceImageBytes(t, original.Editable))
			generated := string(maintenanceImageBytes(t, original.Generated))
			before := contract.RetainedSecretInput{Incarnation: successorID(50), Material: successorID(51)}
			material.PinDeltas = []MaintenancePinDelta{{Name: "opaque", Before: before, After: contract.RetainedSecretInput{Incarnation: before.Incarnation, Material: successorID(52)}}}
			if encoding == JSON {
				editable = strings.Replace(editable, `"entries":{}`, `"entries":{"opaque":{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}}}`, 1)
			} else {
				editable = strings.Replace(editable, "entries: {}", "entries: {opaque: {confidentiality: secret, recipients: [], source: {kind: supplied}}}", 1)
			}
			sealed := base64.StdEncoding.EncodeToString(sourceEditEnvelope(t, "opaque"))
			pin := `{"retained":{"incarnation":"` + strings.Repeat("32", 32) + `","material":"` + strings.Repeat("33", 32) + `"}}`
			generated = strings.Replace(generated, `{"sealed":"`+sealed+`"}`, pin, 1)
			pair := captureEditableEmission(t, []byte(editable), []byte(generated), encoding, ".enkv/prod.generated.json")
			path := filepath.Join(t.TempDir(), "successor")
			output, err := PrepareMaintenanceOutput(t.Context(), pair, path, request)
			if err != nil {
				t.Fatal(err)
			}
			readback, err := output.Publish(t.Context(), material)
			if err != nil {
				if closeErr := output.Close(); closeErr != nil {
					t.Error(closeErr)
				}
				t.Fatal("valid before-to-after output setup", err)
			}
			outputGeneratedPath := readback.Pair.Generated.path
			body := maintenanceImageBytes(t, readback.Pair.Generated)
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			exact, err := PrepareMaintenanceOutput(t.Context(), pair, path, request)
			if err != nil || exact.Existing() == nil {
				t.Fatal("exact existing output refused", err)
			}
			if err := exact.Close(); err != nil {
				t.Fatal(err)
			}
			olderGenerated := strings.Replace(generated, strings.Repeat("33", 32), strings.Repeat("63", 32), 1)
			older := captureEditableEmission(t, []byte(editable), []byte(olderGenerated), encoding, ".enkv/prod.generated.json")
			identity, err := pairIdentity(older)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]json.RawMessage
			if err := json.Unmarshal(body, &document); err != nil {
				t.Fatal(err)
			}
			metadata := bytes.Clone(document["maintenance"])
			if len(metadata) == 0 {
				t.Fatal("delivered metadata omitted")
			}
			if identity.Editable.Digest != contract.ID(pair.Editable.Digest()) || identity.Editable.Length != uint64(pair.Editable.Size()) || identity.Generated.Length != uint64(pair.Generated.Size()) {
				t.Fatal("older source changed unrelated editable bytes")
			}
			for _, edit := range []struct {
				before, after string
				count         int
			}{
				{`"` + strings.Repeat("33", 32) + `"`, `"` + strings.Repeat("63", 32) + `"`, 2},
				{fmt.Sprintf(`"%x"`, material.RekeyTarget.BeforePublicEntryDigest), `"` + strings.Repeat("64", 32) + `"`, 1},
				{fmt.Sprintf(`"generated_digest": "%x"`, contract.ID(pair.Generated.Digest())), fmt.Sprintf(`"generated_digest": "%x"`, identity.Generated.Digest), 1},
			} {
				if bytes.Count(metadata, []byte(edit.before)) != edit.count {
					t.Fatal("saved exact field was not selected", edit.before)
				}
				metadata = bytes.ReplaceAll(metadata, []byte(edit.before), []byte(edit.after))
			}
			if bytes.Count(body, document["maintenance"]) != 1 {
				t.Fatal("delivered metadata span is not unique")
			}
			damaged := bytes.Replace(body, document["maintenance"], metadata, 1)
			if err := os.WriteFile(outputGeneratedPath, damaged, 0600); err != nil {
				t.Fatal(err)
			}
			forged, err := PrepareMaintenanceOutput(t.Context(), older, path, request)
			if forged != nil {
				if closeErr := forged.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if err == nil || forged != nil {
				t.Fatal("older source and matching Before aliases qualified an existing output", err)
			}
		})
	}
}

// full_only: false
func TestMaintenanceRetirementPreservesYAMLSequenceLayout(t *testing.T) {
	for _, layout := range []string{"compact-singleton", "ordinary-singleton", "tab-before-close", "tab-before-comma"} {
		t.Run(layout, func(t *testing.T) {
			original, request, material := maintenanceFileFixture(t, YAML, contract.OperationRetireRecipientIdentity)
			editable := string(maintenanceImageBytes(t, original.Editable))
			generated := maintenanceImageBytes(t, original.Generated)
			membership, wantMembership := "[chosen\t] # member comment", "[\t] # member comment"
			if layout == "tab-before-comma" {
				membership = "[chosen\t,] # member comment"
			}
			switch layout {
			case "compact-singleton":
				membership, wantMembership = "\n    - chosen # member comment", "\n      [] # member comment"
			case "ordinary-singleton":
				membership, wantMembership = "\n      - chosen # member comment", "\n      [] # member comment"
			}
			entry := "entries:\n  pending:\n    confidentiality: plain\n    recipients: " + membership + "\n    source: {kind: supplied, value: unchanged}\n"
			editable = strings.Replace(editable, "entries: {}\n", entry, 1)
			pair := captureEditableEmission(t, []byte(editable), generated, YAML, ".enkv/prod.generated.json")
			before, err := Parse(t.Context(), pair)
			if err != nil || len(before.Entries) != 1 || !reflect.DeepEqual(before.Entries[0].Recipients, []string{"chosen"}) {
				t.Fatal("maintenance layout fixture refused", err)
			}
			output, err := PrepareMaintenanceOutput(t.Context(), pair, filepath.Join(t.TempDir(), "successor"), request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, output)
			readback, err := output.Publish(t.Context(), material)
			if err != nil {
				t.Fatal("legal YAML sequence refused retirement", err)
			}
			body := maintenanceImageBytes(t, readback.Pair.Editable)
			if !bytes.Contains(body, []byte("    recipients: "+wantMembership+"\n")) {
				t.Errorf("empty sequence layout differs: got %q want membership %q", body, wantMembership)
			}
			after := readback.Model
			if len(after.Entries) != 1 || after.Entries[0].Name != "pending" || string(after.Entries[0].Plain) != "unchanged" || len(after.Entries[0].Recipients) != 0 || len(after.Recipients) != 0 || len(after.GeneratedRecipients) != 1 || after.GeneratedRecipients[0].Reference != "unreferenced" || !reflect.DeepEqual(after.Routes, []Route{{EntryName: "pending", Destinations: []string{"sink"}}}) || len(after.Outputs) != 0 {
				t.Fatal("retirement changed unrelated whole-pair meaning")
			}
			beforeSecrets := generated[bytes.Index(generated, []byte(`"secrets":`)):bytes.Index(generated, []byte(`,"public_basis":`))]
			if !bytes.Contains(maintenanceImageBytes(t, readback.Pair.Generated), beforeSecrets) || !bytes.Equal(maintenanceImageBytes(t, pair.Editable), []byte(editable)) || !bytes.Equal(maintenanceImageBytes(t, pair.Generated), generated) {
				t.Fatal("retirement changed sealed history or original pair")
			}
		})
	}
}
