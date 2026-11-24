package configuration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type canonicalPairCounter struct{ n int64 }

func (w *canonicalPairCounter) Write(body []byte) (int, error) {
	w.n += int64(len(body))
	return len(body), nil
}

func canonicalPairFileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, file)
	if err := errors.Join(readErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

// full_only: true
func TestRecoveredSettingsCompleteFormattedPairBoundary(t *testing.T) {
	const pairLimit int64 = 268435456
	if MaxPairBytes != pairLimit {
		t.Fatal("complete pair contract changed")
	}
	for _, format := range []Format{JSON, YAML} {
		t.Run(map[Format]string{JSON: "json", YAML: "yaml"}[format], func(t *testing.T) {
			model, err := Parse(t.Context(), writePair(t, sourceSetupJSON, sourceGeneratedJSON, JSON))
			if err != nil {
				t.Fatal(err)
			}
			// A depth-10,000 array chain contains ordinary zero leaves and one final
			// string. The chain keeps readable expansion large while canonical settings
			// remain below their independent existing byte limit.
			leaves := 3400
			if format == YAML {
				leaves = 8400
			}
			body := func(padding int) []byte {
				return []byte(strings.Repeat("[", 9999) + "[" + strings.Repeat("0,", leaves) + `"` + strings.Repeat("x", padding) + `"]` + strings.Repeat("]", 9999))
			}
			install := func(name string, settings []byte) {
				intent := sourceCanonicalIntent(t, false)[:67]
				intent = binary.BigEndian.AppendUint32(intent, uint32(len(settings)))
				intent = append(intent, settings...)
				model.DomainName = name
				model.Generated = generatedPath(name)
				model.Entries = []Entry{{Name: "token", Secret: true, Generated: &Generator{Intent: intent, Epoch: 7}}}
			}
			initialSettings := body(0)
			install("p", initialSettings)
			// Measure only the fixed envelope and selected readable layout once. The
			// boundary remains the independent literal above. Each added settings byte
			// adds one view byte and the documented Base64 blob's length difference;
			// each added domain-name byte occurs exactly twice in the editable image.
			initial := &canonicalPairCounter{}
			if err := EmitGenerated(initial, model); err != nil {
				t.Fatal(err)
			}
			if err := EmitEditable(initial, model, format); err != nil {
				t.Fatal(err)
			}
			// Independent two-space layout algebra for the settings value at
			// root/entries/entry/source/canonical depth5. Every nonempty JSON
			// collection pays opener, closer, newline and closing indentation;
			// each child pays its own newline/indent and all but the first a comma.
			// YAML pays one newline per collection and indent/dash/space/newline
			// for every leaf. There are 10,000 collections, leaves zeroes and one
			// empty string. This checks formatting independently of envelope sizing.
			const depth, baseDepth int64 = 10000, 5
			zeros := int64(leaves)
			wantView := 2*depth*(depth-1) + depth*(3+2*baseDepth) + (depth-1)*(1+2*baseDepth) + (zeros+1)*(1+2*(baseDepth+depth)) + 2*zeros + 2
			if format == YAML {
				wantView = depth + (depth-1)*(2*baseDepth-1) + depth*(depth-1) + (zeros+1)*(2*(baseDepth+depth)-1) + 3*zeros + 4
			}
			viewCount := &canonicalPairCounter{}
			view := editableWriter{generatedWriter: generatedWriter{out: viewCount}, format: format, level: 5}
			view.settingsValueIterative(initialSettings, maxCanonicalGeneratorSettings)
			if view.err != nil || viewCount.n != wantView {
				t.Fatal("readable settings differ from independent layout account", viewCount.n, wantView, view.err)
			}
			delta := pairLimit - initial.n
			recordLength := 71 + len(initialSettings)
			chosenPadding, chosenName := -1, ""
			estimate := int(delta * 3 / 7)
			for names := 0; names < 8 && chosenPadding < 0; names++ {
				for padding := max(0, estimate-32); padding <= estimate+8; padding++ {
					growth := int64(padding + base64.StdEncoding.EncodedLen(recordLength+padding) - base64.StdEncoding.EncodedLen(recordLength) + 2*names)
					if format == YAML && padding > 0 {
						// A nonempty plain scalar replaces the two quotes around the empty string.
						growth -= 2
					}
					if growth == delta && (recordLength+padding)%3 != 0 {
						chosenPadding, chosenName = padding, strings.Repeat("p", names+1)
						break
					}
				}
			}
			if chosenPadding < 0 {
				t.Fatal("no exact pair-boundary fixture", delta)
			}
			exactSettings := body(chosenPadding)
			if len(exactSettings)+1 > maxCanonicalGeneratorSettings {
				t.Fatal("pair fixture exceeded canonical settings capacity")
			}
			install(chosenName, exactSettings)
			directory := t.TempDir()
			if err := os.Mkdir(filepath.Join(directory, ".enkv"), 0700); err != nil {
				t.Fatal(err)
			}
			generatedPath := filepath.Join(directory, model.Generated)
			editablePath := filepath.Join(directory, "configuration")
			counter := &canonicalPairCounter{}
			generated, err := os.OpenFile(generatedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			err = EmitGenerated(io.MultiWriter(counter, generated), model)
			err = errors.Join(err, generated.Close())
			if err != nil {
				t.Fatal(err)
			}
			editable, err := os.OpenFile(editablePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			err = EmitEditable(io.MultiWriter(counter, editable), model, format)
			err = errors.Join(err, editable.Close())
			if err != nil || counter.n != pairLimit {
				t.Fatal("largest complete formatted pair refused", counter.n, err)
			}
			captured, err := Capture(t.Context(), editablePath, format)
			if err != nil {
				t.Fatal(err)
			}
			parsed, parseErr := Parse(t.Context(), captured)
			closeErr := captured.Close()
			if parseErr != nil || closeErr != nil || parsed == nil || len(parsed.Entries) != 1 || !bytes.Equal(parsed.Entries[0].Generated.Intent, model.Entries[0].Generated.Intent) {
				t.Fatal("exact pair did not recover the complete canonical record", parseErr, closeErr)
			}
			// This next byte does not cross a Base64 quantum, so the complete formatted
			// candidate is exactly one byte over, rather than a smaller surrogate case.
			install(chosenName, body(chosenPadding+1))
			beforeEditable, beforeGenerated := canonicalPairFileDigest(t, editablePath), canonicalPairFileDigest(t, generatedPath)
			beforeEditableInfo, err := os.Stat(editablePath)
			if err != nil {
				t.Fatal(err)
			}
			beforeGeneratedInfo, err := os.Stat(generatedPath)
			if err != nil {
				t.Fatal(err)
			}
			edit, err := BeginEdit(t.Context(), editablePath, format)
			if err != nil {
				t.Fatal(err)
			}
			candidate, normalized, stageErr := edit.Stage(t.Context(), func(out io.Writer) error { return EmitGenerated(out, model) }, func(out io.Writer, reference string) error {
				if reference != model.Generated {
					t.Fatal("staging changed exact generated reference")
				}
				return EmitEditable(out, model, format)
			})
			closeErr = edit.Close()
			if !errors.Is(stageErr, ErrEditBounds) || candidate != nil || normalized != nil || closeErr != nil {
				t.Fatal("Product staging did not refuse the one-byte aggregate excess", stageErr, closeErr)
			}
			afterEditableInfo, err := os.Stat(editablePath)
			if err != nil {
				t.Fatal(err)
			}
			afterGeneratedInfo, err := os.Stat(generatedPath)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(beforeEditableInfo, afterEditableInfo) || !os.SameFile(beforeGeneratedInfo, afterGeneratedInfo) || canonicalPairFileDigest(t, editablePath) != beforeEditable || canonicalPairFileDigest(t, generatedPath) != beforeGenerated {
				t.Fatal("refused staging partially replaced a delivered pair")
			}

		})
	}
}
