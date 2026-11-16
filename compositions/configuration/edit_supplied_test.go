package configuration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func sourceEditEnvelope(t *testing.T, name string) []byte {
	t.Helper()
	var one, two contract.ID
	if _, err := hex.Decode(one[:], []byte(sourceID1)); err != nil {
		t.Fatal(err)
	}
	if _, err := hex.Decode(two[:], []byte(sourceID2)); err != nil {
		t.Fatal(err)
	}
	core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: contract.SealedInputSchema, Profile: contract.MaterialCryptoProfile, CompatibilityID: one, DomainID: two, FileIdentity: one, FilePredecessorDigest: one, SourceID: one, CryptoSupportID: one, DataKeyID: one, DataKeyEpoch: 1, ContentLength: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 1}, Name: name}
	body, err := contract.EncodeSealedInputEnvelope(contract.SealedInputEnvelope{Core: core, Ciphertext: make([]byte, 17), AuthorityWrap: contract.WrapRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: one, BindingID: one, BindingSerial: 1, PublicBindingDigest: one, RSACiphertext: make([]byte, 384)}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestSuppliedEditPresentation(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[format], func(t *testing.T) {
			editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"item":{"source":{"value":"old","kind":"supplied"},"recipients":[],"confidentiality":"plain"}}`, 1)
			if format == YAML {
				editable = strings.Replace(sourceSetupYAML, "entries: {}", "entries:\n  item:\n    # entry comment\n    source:\n      value: |- # header comment\n        # literal value data\n        old\n      # between fields\n      kind: supplied # source trailing\n    recipients: [] # memberships\n    confidentiality: plain # confidentiality", 1)
			}
			editable = sourceWithPlugins(editable, format, sourcePluginRequirements)
			pair := writePair(t, editable, sourceGeneratedJSON, format)
			m, err := ParseForSet(context.Background(), pair, "item")
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareSuppliedEdit(pair, m, "item", false, contract.InputEncodingRaw)
			if err != nil {
				t.Fatal(err)
			}
			*m = Model{}
			s, err := BeginEdit(context.Background(), pair.Editable.OriginalPath(), format)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			}()
			candidate, normalized, err := s.Stage(context.Background(), nil, func(w io.Writer, ref string) error {
				return edit.EmitEditable(context.Background(), w, ref, []byte("new\nsecond"))
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(normalized.Entries) != 1 || !bytes.Equal(normalized.Entries[0].Plain, []byte("new\nsecond")) {
				t.Fatal("normalized edited value differs")
			}
			changedBytes, err := io.ReadAll(io.NewSectionReader(candidate.pair.Editable, 0, candidate.pair.Editable.Size()))
			if err != nil {
				t.Fatal(err)
			}
			changed := string(changedBytes)
			requirePreservedPlugins(t, changedBytes)
			if format == JSON {
				original, err := io.ReadAll(io.NewSectionReader(pair.Editable, 0, pair.Editable.Size()))
				if err != nil {
					t.Fatal(err)
				}
				if changed != strings.Replace(string(original), `"old"`, `"new\nsecond"`, 1) {
					t.Fatal("unselected JSON bytes or surviving source order changed")
				}
			} else {
				for _, comment := range []string{"# entry comment", "# header comment", "# between fields", "# source trailing", "# memberships", "# confidentiality"} {
					if strings.Count(changed, comment) != 1 {
						t.Fatal("YAML comment lost or duplicated", comment)
					}
				}
				if strings.Contains(changed, "# literal value data") || strings.Index(changed, "value:") > strings.Index(changed, "kind: supplied") {
					t.Fatal("literal data became comment or surviving field order changed")
				}
			}
		})
	}
}

// full_only: false
func TestSuppliedEditSecretRowAndNewEntry(t *testing.T) {
	for _, format := range []Format{JSON, YAML} {
		for _, name := range []string{"token", ""} {
			t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[format]+"/"+name, func(t *testing.T) {
				editable := sourceSetupJSON
				if format == YAML {
					editable = sourceSetupYAML
				}
				editable = sourceWithPlugins(editable, format, sourcePluginRequirements)
				pair := writePair(t, editable, sourceGeneratedJSON, format)
				m, err := ParseForSet(context.Background(), pair, name)
				if err != nil {
					t.Fatal(err)
				}
				edit, err := PrepareSuppliedEdit(pair, m, name, true, contract.InputEncodingRaw)
				if err != nil {
					t.Fatal(err)
				}
				maximum, err := edit.MaximumPairBytes(65536)
				if err != nil {
					t.Fatal(err)
				}
				*m = Model{}
				envelope := sourceEditEnvelope(t, name)
				s, err := BeginEdit(context.Background(), pair.Editable.OriginalPath(), format)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := s.Close(); err != nil {
						t.Error(err)
					}
				}()
				candidate, normalized, err := s.Stage(context.Background(), func(w io.Writer) error { return edit.EmitGenerated(context.Background(), w, envelope) }, func(w io.Writer, ref string) error { return edit.EmitEditable(context.Background(), w, ref, nil) })
				if err != nil {
					t.Fatal(err)
				}
				if len(normalized.Entries) != 1 || normalized.Entries[0].Name != name || !bytes.Equal(normalized.Entries[0].Sealed, envelope) {
					t.Fatal("selected generated row or new declaration differs")
				}
				if candidate.pair.Editable.Size()+candidate.pair.Generated.Size() > maximum {
					t.Fatal("actual candidate exceeded preflight maximum")
				}
				requirePreservedPlugins(t, maintenanceImageBytes(t, candidate.pair.Editable))
			})
		}
	}
}

// full_only: false
func TestSuppliedEditYAMLBlockInsertion(t *testing.T) {
	editable := strings.Replace(sourceSetupYAML, "entries: {}", "entries:\n  old: {confidentiality: plain, recipients: [], source: {kind: supplied, value: unchanged}} # preserve old", 1)
	editable = sourceWithPlugins(editable, YAML, sourcePluginRequirements)
	pair := writePair(t, editable, sourceGeneratedJSON, YAML)
	m, err := ParseForSet(context.Background(), pair, "new")
	if err != nil {
		t.Fatal(err)
	}
	edit, err := PrepareSuppliedEdit(pair, m, "new", true, contract.InputEncodingRaw)
	if err != nil {
		t.Fatal(err)
	}
	*m = Model{}
	envelope := sourceEditEnvelope(t, "new")
	s, err := BeginEdit(context.Background(), pair.Editable.OriginalPath(), YAML)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	candidate, normalized, err := s.Stage(context.Background(), func(w io.Writer) error { return edit.EmitGenerated(context.Background(), w, envelope) }, func(w io.Writer, ref string) error { return edit.EmitEditable(context.Background(), w, ref, nil) })
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.NewSectionReader(candidate.pair.Editable, 0, candidate.pair.Editable.Size()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("\n  new:\n    confidentiality: secret\n")) {
		t.Fatal("YAML block key/value separator lacks required space")
	}
	if len(normalized.Entries) != 2 || bytes.Count(body, []byte("# preserve old")) != 1 {
		t.Fatal("block insertion changed unrelated entry/comment")
	}
	requirePreservedPlugins(t, body)
}

// full_only: false
func TestSuppliedEditReferenceAccounting(t *testing.T) {
	for _, tc := range []struct {
		name     string
		format   Format
		spelling string
	}{
		{"json", JSON, "quoted"},
		{"json-escaped", JSON, "escaped"},
		{"yaml-quoted", YAML, "quoted"},
		{"yaml-unquoted", YAML, "unquoted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			editable := strings.Replace(sourceSetupJSON, `"entries":{}`, `"entries":{"item":{"confidentiality":"secret","recipients":[],"source":{"kind":"supplied"}}}`, 1)
			if tc.format == YAML {
				editable = strings.Replace(sourceSetupYAML, "entries: {}", `entries: {item: {confidentiality: "secret", recipients: [], source: {kind: supplied}}}`, 1)
			}
			pair := writePair(t, editable, sourceGeneratedJSON, tc.format)
			reference := ".enkv/prod.generated.json"
			oldToken := `"` + reference + `"`
			if tc.format == YAML {
				oldToken = "'" + reference + "'"
			}
			newToken := oldToken
			switch tc.spelling {
			case "escaped":
				newToken = `"\u002e` + strings.TrimPrefix(reference, ".") + `"`
			case "unquoted":
				newToken = reference
			}
			if newToken != oldToken {
				body, err := io.ReadAll(io.NewSectionReader(pair.Editable, 0, pair.Editable.Size()))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Count(string(body), oldToken) != 1 {
					t.Fatal("reference fixture is not unique")
				}
				path := pair.Editable.OriginalPath()
				if err := pair.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(strings.Replace(string(body), oldToken, newToken, 1)), 0600); err != nil {
					t.Fatal(err)
				}
				pair, err = Capture(context.Background(), path, tc.format)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := pair.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			m, err := ParseForSet(context.Background(), pair, "item")
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareSuppliedEdit(pair, m, "item", true, contract.InputEncodingRaw)
			if err != nil {
				t.Fatal(err)
			}
			maximum, err := edit.MaximumPairBytes(1)
			if err != nil {
				t.Fatal(err)
			}
			*m = Model{}
			envelope := sourceEditEnvelope(t, "item")
			if len(envelope) != contract.SealedInputEnvelopeFixedLength+len("item")+1 {
				t.Fatal("envelope fixture has unexpected raw length")
			}
			// New object framing is ten bytes; it replaces the original two braces.
			wantGenerated := pair.Generated.Size() + int64(len(`"item": {`)+len("\n      \"sealed\": \"\"\n    }")+base64.StdEncoding.EncodedLen(len(envelope))+8)
			wantEditable := pair.Editable.Size()
			s, err := BeginEdit(context.Background(), pair.Editable.OriginalPath(), tc.format)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			}()
			candidate, _, err := s.Stage(context.Background(), func(w io.Writer) error {
				return edit.EmitGenerated(context.Background(), w, envelope)
			}, func(w io.Writer, ref string) error {
				return edit.EmitEditable(context.Background(), w, ref, nil)
			})
			if err != nil {
				t.Fatal(err)
			}
			if candidate.pair.Editable.Size() != wantEditable || candidate.pair.Generated.Size() != wantGenerated {
				t.Fatalf("candidate sizes differ from stable reference preservation and multiline sealed-row insertion: editable %d/%d, generated %d/%d", candidate.pair.Editable.Size(), wantEditable, candidate.pair.Generated.Size(), wantGenerated)
			}
			if maximum != wantEditable+wantGenerated {
				t.Fatalf("preflight pair bytes %d, exact candidate bytes %d (reference token delta %d)", maximum, wantEditable+wantGenerated, len(reference)+2-len(newToken))
			}
		})
	}
}

// full_only: false
func TestSuppliedEditPreservesBlockScalarBoundaries(t *testing.T) {
	const reference = ".enkv/prod.generated.json"
	const oldEntry = "  old:\n    confidentiality: plain\n    recipients: []\n    source:\n      kind: supplied\n      value: |+\n        X\n"
	const newEntry = "  new:\n    confidentiality: plain\n    recipients: []\n    source:\n      kind: supplied\n      value: new\n"
	for _, operation := range []string{"replace-before-entry", "replace-keep-blanks-before-entry", "replace-strip-before-entry", "replace-folded-before-entry", "insert-before-outputs", "insert-after-keep-eof", "insert-after-plain-eof"} {
		t.Run(operation, func(t *testing.T) {
			scalar, fixturePlain := "|+\n        X\n", "X\n"
			if operation == "replace-keep-blanks-before-entry" {
				scalar, fixturePlain = "|+\n        X\n\n\n", "X\n\n\n"
			}
			if operation == "replace-strip-before-entry" {
				scalar, fixturePlain = "|-\n        X\n", "X"
			}
			if operation == "replace-folded-before-entry" {
				scalar, fixturePlain = ">\n        X\n        Y\n", "X Y\n"
			}
			entry := strings.Replace(oldEntry, "|+\n        X\n", scalar, 1)
			editable := strings.Replace(sourceSetupYAML, "entries: {}\n", "entries:\n"+entry, 1)
			name, wantOld := "new", "X\n"
			want := strings.Replace(editable, "outputs:\n", newEntry+"outputs:\n", 1)
			if strings.HasPrefix(operation, "replace-") {
				name, wantOld = "old", "new"
				editable = strings.Replace(editable, "outputs:\n", "  keep: {confidentiality: plain, recipients: [], source: {kind: supplied, value: untouched}}\noutputs:\n", 1)
				want = strings.Replace(editable, scalar, "new\n", 1)
			} else if operation == "insert-after-keep-eof" {
				editable = strings.Replace(sourceSetupYAML, "entries: {}\n", "", 1) + "entries:\n" + oldEntry
				want = editable + newEntry
			} else if operation == "insert-after-plain-eof" {
				fixturePlain, wantOld = "X", "X"
				editable = strings.Replace(sourceSetupYAML, "entries: {}\n", "", 1) + "entries:\n  old: {confidentiality: plain, recipients: [], source: {kind: supplied, value: X}}"
				want = strings.Replace(editable, "entries:\n", "entries:\n"+newEntry, 1)
			}
			editable = "generated: '" + reference + "'\n" + editable
			want = "generated: '" + reference + "'\n" + want
			pair := captureEditableEmission(t, []byte(editable), []byte(sourceGeneratedJSON), YAML, reference)
			before, err := Parse(t.Context(), pair)
			if err != nil {
				t.Fatal("block source fixture refused", err)
			}
			foundOld := false
			for _, entry := range before.Entries {
				if entry.Name == "old" {
					foundOld = bytes.Equal(entry.Plain, []byte(fixturePlain))
				}
			}
			if !foundOld {
				t.Fatal("block source fixture meaning differs")
			}
			model, err := ParseForSet(t.Context(), pair, name)
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareSuppliedEdit(pair, model, name, false, contract.InputEncodingRaw)
			if err != nil {
				t.Fatal(err)
			}
			var body bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &body, reference, []byte("new")); err != nil {
				t.Fatal(err)
			}
			if body.String() != want {
				t.Errorf("block edit bytes differ: got %q want %q", body.String(), want)
			}
			after, err := Parse(t.Context(), captureEditableEmission(t, body.Bytes(), []byte(sourceGeneratedJSON), YAML, reference))
			if err != nil {
				t.Fatal("block edit candidate refused", err)
			}
			wantCount := 2
			if len(after.Entries) != wantCount {
				t.Fatal("block edit changed complete entry set", len(after.Entries))
			}
			for _, entry := range after.Entries {
				wantValue := "new"
				if entry.Name == "old" {
					wantValue = wantOld
				}
				if entry.Name == "keep" {
					wantValue = "untouched"
				}
				if entry.Secret || entry.Generated != nil || !bytes.Equal(entry.Plain, []byte(wantValue)) {
					t.Fatal("block edit changed an entry's meaning", entry.Name)
				}
			}
			if !bytes.Equal(maintenanceImageBytes(t, pair.Editable), []byte(editable)) || !bytes.Equal(maintenanceImageBytes(t, pair.Generated), []byte(sourceGeneratedJSON)) {
				t.Fatal("edit changed original pair")
			}
		})
	}
}

// full_only: false
func TestSuppliedEditReusesYAMLFlowTrailingComma(t *testing.T) {
	const old = `old: {confidentiality: plain, recipients: [], source: {kind: supplied, value: untouched}}`
	for _, tc := range []struct{ name, comma string }{{"no-final-comma", ""}, {"final-comma", ","}, {"final-comma-comment", ", # retained comma , comment\n"}} {
		t.Run(tc.name, func(t *testing.T) {
			comma := tc.comma
			editable := strings.Replace(sourceSetupYAML, "entries: {}", "entries: {"+old+comma+"}", 1)
			pair := writePair(t, editable, sourceGeneratedJSON, YAML)
			model, err := ParseForSet(t.Context(), pair, "new")
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareSuppliedEdit(pair, model, "new", false, contract.InputEncodingRaw)
			if err != nil {
				t.Fatal(err)
			}
			var body bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &body, model.Generated, []byte("new")); err != nil {
				t.Fatal(err)
			}
			const expanded = "entries: \n" + `  old:
    confidentiality: plain
    recipients: []
    source:
      kind: supplied
      value: untouched`
			const added = `
  new:
    confidentiality: plain
    recipients: []
    source:
      kind: supplied
      value: new`
			comment := ""
			if tc.name == "final-comma-comment" {
				comment = "\n  # retained comma , comment"
			}
			want := strings.Replace(string(maintenanceImageBytes(t, pair.Editable)), "entries: {"+old+comma+"}", expanded+comment+added, 1)
			if body.String() != want {
				t.Errorf("flow insertion separator differs: got %q want %q", body.String(), want)
			}
			after, err := Parse(t.Context(), captureEditableEmission(t, body.Bytes(), []byte(sourceGeneratedJSON), YAML, model.Generated))
			if err != nil || len(after.Entries) != 2 || after.Entries[0].Name != "new" || string(after.Entries[0].Plain) != "new" || after.Entries[1].Name != "old" || string(after.Entries[1].Plain) != "untouched" {
				t.Fatal("flow insertion changed complete entry meaning", err)
			}
		})
	}
}

// full_only: false
func TestSuppliedEditRemovesPlainContinuationContent(t *testing.T) {
	const reference = ".enkv/prod.generated.json"
	const oldSource = "source:\n      kind: supplied\n      value: first\n        'x'#tail\n      # actual comment\n"
	for _, confidential := range []bool{false, true} {
		t.Run(fmt.Sprintf("secret-%t", confidential), func(t *testing.T) {
			editable := strings.Replace(sourceSetupYAML, "entries: {}", "entries:\n  item:\n    confidentiality: plain\n    recipients: []\n    "+oldSource+"  keep: {confidentiality: plain, recipients: [], source: {kind: supplied, value: untouched}}", 1)
			pair := writePair(t, editable, sourceGeneratedJSON, YAML)
			before, err := Parse(t.Context(), pair)
			if err != nil || len(before.Entries) != 2 || string(before.Entries[0].Plain) != "first 'x'#tail" {
				t.Fatal("plain continuation fixture meaning differs", err)
			}
			model, err := ParseForSet(t.Context(), pair, "item")
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareSuppliedEdit(pair, model, "item", confidential, contract.InputEncodingRaw)
			if err != nil {
				t.Fatal(err)
			}
			var body, generated bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &body, reference, []byte("new")); err != nil {
				t.Fatal(err)
			}
			generated.WriteString(sourceGeneratedJSON)
			if confidential {
				generated.Reset()
				if err := edit.EmitGenerated(t.Context(), &generated, sourceEditEnvelope(t, "item")); err != nil {
					t.Fatal(err)
				}
			}
			want := strings.Replace(string(maintenanceImageBytes(t, pair.Editable)), "first\n        'x'#tail", "new", 1)
			if confidential {
				want = strings.Replace(string(maintenanceImageBytes(t, pair.Editable)), "confidentiality: plain", "confidentiality: secret", 1)
				want = strings.Replace(want, "kind: supplied\n      value: first\n        'x'#tail", "kind: supplied", 1)
			}
			if body.String() != want {
				t.Errorf("complete replacement bytes differ: got %q want %q", body.String(), want)
			}
			if bytes.Contains(body.Bytes(), []byte("#tail")) || bytes.Count(body.Bytes(), []byte("# actual comment")) != 1 {
				t.Error("old value content became a comment or actual comment was lost")
			}
			after, err := Parse(t.Context(), captureEditableEmission(t, body.Bytes(), generated.Bytes(), YAML, reference))
			if err != nil || len(after.Entries) != 2 {
				t.Fatal("replacement candidate refused", err)
			}
			for _, entry := range after.Entries {
				if entry.Name == "item" {
					if entry.Secret != confidential || !confidential && string(entry.Plain) != "new" || confidential && !bytes.Equal(entry.Sealed, sourceEditEnvelope(t, "item")) {
						t.Fatal("replacement changed selected meaning")
					}
				} else if entry.Name != "keep" || string(entry.Plain) != "untouched" {
					t.Fatal("replacement changed unrelated entry")
				}
			}
		})
	}
}

// full_only: false
func TestSuppliedSecretConversionPreservesBlockBoundary(t *testing.T) {
	const reference = ".enkv/prod.generated.json"
	const oldSource = "source:\n      kind: supplied\n      value: |-\n        old\n"
	editable := strings.Replace(sourceSetupYAML, "entries: {}", "entries:\n  item:\n    confidentiality: plain\n    recipients: []\n    "+oldSource+"  keep: {confidentiality: plain, recipients: [], source: {kind: supplied, value: untouched}}", 1)
	pair := writePair(t, editable, sourceGeneratedJSON, YAML)
	model, err := ParseForSet(t.Context(), pair, "item")
	if err != nil {
		t.Fatal(err)
	}
	edit, err := PrepareSuppliedEdit(pair, model, "item", true, contract.InputEncodingRaw)
	if err != nil {
		t.Fatal(err)
	}
	var body, satellite bytes.Buffer
	if err := edit.EmitEditable(t.Context(), &body, reference, nil); err != nil {
		t.Fatal(err)
	}
	envelope := sourceEditEnvelope(t, "item")
	if err := edit.EmitGenerated(t.Context(), &satellite, envelope); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(string(maintenanceImageBytes(t, pair.Editable)), "confidentiality: plain", "confidentiality: secret", 1)
	want = strings.Replace(want, oldSource, "source:\n      kind: supplied\n", 1)
	if body.String() != want {
		t.Errorf("block source replacement bytes differ: got %q want %q", body.String(), want)
	}
	after, err := Parse(t.Context(), captureEditableEmission(t, body.Bytes(), satellite.Bytes(), YAML, reference))
	if err != nil || len(after.Entries) != 2 || after.Entries[0].Name != "item" || !after.Entries[0].Secret || !bytes.Equal(after.Entries[0].Sealed, envelope) || after.Entries[1].Name != "keep" || string(after.Entries[1].Plain) != "untouched" {
		t.Fatal("block conversion changed whole-pair meaning", err)
	}
}

// full_only: false
func TestSuppliedInsertionPreservesKeepChompedValues(t *testing.T) {
	const reference = ".enkv/prod.generated.json"
	const newEntry = "  new:\n    confidentiality: plain\n    recipients: []\n    source:\n      kind: supplied\n      value: new\n"
	for _, tc := range []struct {
		name, scalar, wantOld, lineBreak string
		eof, prepend                     bool
	}{
		{"literal-before-section", "|+\n        X\n\n", "X\n\n", "\n", false, false},
		{"folded-crlf-before-section", ">+\n        X\n        Y\n\n\n", "X Y\n\n\n", "\r\n", false, false},
		{"literal-crlf-eof", "|+\n        X\n\n", "X\n\n", "\r\n", true, false},
		{"folded-eof", ">+\n        X\n        Y\n\n\n", "X Y\n\n\n", "\n", true, false},
		{"literal-no-final-break-eof", "|+\n        X", "X", "\n", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries := "entries:\n  keep: {confidentiality: plain, recipients: [], source: {kind: supplied, value: untouched}}\n  old:\n    confidentiality: plain\n    recipients: []\n    source:\n      kind: supplied\n      value: " + tc.scalar
			editable := strings.Replace(sourceSetupYAML, "entries: {}\n", entries+"# retained section comment\n", 1)
			if tc.eof {
				editable = strings.Replace(sourceSetupYAML, "entries: {}\n", "", 1) + entries
			}
			editable = strings.ReplaceAll("generated: '"+reference+"'\n"+editable, "\n", tc.lineBreak)
			// Inserted rows use the emitter's LF; all original bytes retain their spelling.
			want := ""
			if tc.eof {
				want = editable + newEntry
				if tc.prepend {
					want = strings.Replace(editable, "entries:\n", "entries:\n"+newEntry, 1)
				}
			} else {
				want = strings.Replace(editable, "# retained section comment"+tc.lineBreak, newEntry+"# retained section comment"+tc.lineBreak, 1)
			}
			pair := captureEditableEmission(t, []byte(editable), []byte(sourceGeneratedJSON), YAML, reference)
			requireEntries := func(model *Model, added bool) {
				t.Helper()
				expected := map[string]string{"keep": "untouched", "old": tc.wantOld}
				if added {
					expected["new"] = "new"
				}
				if len(model.Entries) != len(expected) {
					t.Fatal("complete entry set differs", len(model.Entries))
				}
				for _, entry := range model.Entries {
					value, ok := expected[entry.Name]
					if !ok || entry.Secret || entry.Generated != nil || !bytes.Equal(entry.Plain, []byte(value)) {
						t.Fatalf("entry %q bytes %q, want %q", entry.Name, entry.Plain, value)
					}
				}
			}
			before, err := Parse(t.Context(), pair)
			if err != nil {
				t.Fatal(err)
			}
			requireEntries(before, false)
			model, err := ParseForSet(t.Context(), pair, "new")
			if err != nil {
				t.Fatal(err)
			}
			edit, err := PrepareSuppliedEdit(pair, model, "new", false, contract.InputEncodingRaw)
			if err != nil {
				t.Fatal(err)
			}
			var body bytes.Buffer
			if err := edit.EmitEditable(t.Context(), &body, reference, []byte("new")); err != nil {
				t.Fatal(err)
			}
			if body.String() != want {
				t.Errorf("insertion bytes %q, want %q", body.String(), want)
			}
			after, err := Parse(t.Context(), captureEditableEmission(t, body.Bytes(), []byte(sourceGeneratedJSON), YAML, reference))
			if err != nil {
				t.Fatal(err)
			}
			requireEntries(after, true)
			if !bytes.Equal(maintenanceImageBytes(t, pair.Editable), []byte(editable)) {
				t.Fatal("insertion changed predecessor bytes")
			}
		})
	}
}

// full_only: false
func TestAfterEditLineDistinguishesPendingAndConsumedBreaks(t *testing.T) {
	for _, tc := range []struct {
		name, body   string
		offset, want int64
	}{
		{"pending-lf", "x\n\nnext: y\n", 2, 3},
		{"pending-crlf", "x\r\n\r\nnext: y\r\n", 3, 5},
		{"pending-cr", "x\r\rnext: y\r", 2, 3},
		{"consumed-before-field", "x\nnext: y\n", 2, 2},
		{"consumed-before-comment", "x\n# retained\nnext: y\n", 2, 2},
		{"consumed-eof", "x\n", 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "image")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString(tc.body); err != nil {
				t.Fatal(err)
			}
			image := &Image{file: file, size: int64(len(tc.body))}
			defer closeSourceOwner(t, image)
			got, err := afterEditLine(image, tc.offset)
			if err != nil || got != tc.want {
				t.Fatalf("after line offset %d, want %d, error %v", got, tc.want, err)
			}
		})
	}
}

// full_only: false
func TestSuppliedInsertionExpandsOnlyRequiredFlowSection(t *testing.T) {
	const original = "entries: {old: {confidentiality: plain, recipients: [], source: {kind: supplied, value: 'keep'}}}"
	const expected = "entries: \n" + `  old:
    confidentiality: plain
    recipients: []
    source:
      kind: supplied
      value: 'keep'
  new:
    confidentiality: plain
    recipients: []
    source:
      kind: supplied
      value: "new\n雪"`
	editable := strings.Replace(sourceSetupYAML, "entries: {}", original, 1)
	pair := writePair(t, editable, sourceGeneratedJSON, YAML)
	model, err := ParseForSet(t.Context(), pair, "new")
	if err != nil {
		t.Fatal(err)
	}
	edit, err := PrepareSuppliedEdit(pair, model, "new", false, contract.InputEncodingRaw)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("new\n雪")
	maximum, err := edit.MaximumPairBytes(uint32(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := edit.EmitEditable(t.Context(), &out, model.Generated, plain); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(editable, original, expected, 1) + "generated: '.enkv/prod.generated.json'\n"
	if out.String() != want {
		t.Fatalf("required section or unrelated bytes changed:\n%s", out.String())
	}
	if int64(out.Len())+pair.Generated.Size() > maximum {
		t.Fatal("formatted edit exceeds its pre-input account")
	}
	again, err := Parse(t.Context(), captureEditableEmission(t, out.Bytes(), []byte(sourceGeneratedJSON), YAML, model.Generated))
	if err != nil || len(again.Entries) != 2 || again.Entries[0].Name != "new" || !bytes.Equal(again.Entries[0].Plain, plain) || again.Entries[1].Name != "old" || string(again.Entries[1].Plain) != "keep" {
		t.Fatal("formatted insertion changed source meaning", err)
	}
}
