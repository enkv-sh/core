package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeSourcePairFactsUseJoinedParserWithoutSDK(t *testing.T) {
	cli, helper := workflowExecutables(t)
	assertRecipients := func(t *testing.T, body []byte, facts observer.SourcePairFacts) {
		t.Helper()
		var original struct {
			Recipients map[string]struct {
				ID         string
				Encryption struct {
					Selector  string
					PublicKey []byte `json:"public_key"`
					Binding   struct {
						ID, Incarnation, Protection string
						Serial                      uint64
					}
				}
				Creation *struct{ Snapshot, Nonce string }
			}
		}
		if json.Unmarshal(body, &original) != nil || len(original.Recipients) != len(facts.GeneratedRecipients) {
			t.Fatal("parse-only child changed complete generated Recipient membership")
		}
		for _, fact := range facts.GeneratedRecipients {
			row, ok := original.Recipients[fact.Reference]
			protection := contract.SoftwareProtection
			if row.Encryption.Binding.Protection == "hardware" {
				protection = contract.HardwareProtection
			} else if row.Encryption.Binding.Protection != "software" {
				t.Fatal("original generated Recipient has an unknown protection class")
			}
			if !ok || hex.EncodeToString(fact.ID[:]) != row.ID || fact.Encryption.Selector != row.Encryption.Selector || !bytes.Equal(fact.Encryption.PublicKey, row.Encryption.PublicKey) || hex.EncodeToString(fact.Encryption.Binding.ID[:]) != row.Encryption.Binding.ID || hex.EncodeToString(fact.Encryption.Binding.Incarnation[:]) != row.Encryption.Binding.Incarnation || fact.Encryption.Binding.Serial != row.Encryption.Binding.Serial || fact.Encryption.Binding.Protection != protection || (fact.Creation == nil) != (row.Creation == nil) {
				t.Fatal("parse-only child changed exact generated Recipient fields")
			}
			if row.Creation != nil && (hex.EncodeToString(fact.Creation.Snapshot[:]) != row.Creation.Snapshot || hex.EncodeToString(fact.Creation.Nonce[:]) != row.Creation.Nonce) {
				t.Fatal("parse-only child changed generated Recipient creation facts")
			}
		}
	}
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			s := newWorkflowServer(t, family, true)
			path := filepath.Join(t.TempDir(), "configuration.json")
			if err := os.WriteFile(path, workflowSetup(t, s, true), 0600); err != nil {
				t.Fatal(err)
			}
			workflowResult(t, workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", path, "--source-format", "json", "--json"), "success")
			pair := workflowReadPair(t, path)
			restore := workflowReadOnlyPair(t, path, pair)
			defer restore()
			s.mu.Lock()
			requests, credentials := s.requests, s.authRequests
			s.mu.Unlock()
			before := s.snapshot("reader")
			inspected := workflowRun(t, s, helper, "reader", observer.Policy{NoKMS: true, MaxRequests: 1, MaxBytes: 1}, nil, "--inspect-source-pair", "--source", path, "--source-format", "json")
			var facts observer.SourcePairFacts
			decoder := json.NewDecoder(bytes.NewReader(inspected.out))
			decoder.DisallowUnknownFields()
			if inspected.code != 0 || len(inspected.out) > observer.SourcePairFactsLimit || len(inspected.diagnostic) != 0 || decoder.Decode(&facts) != nil || decoder.Decode(new(any)) != io.EOF || facts.Schema != "PublicSourcePairFacts/v1" || !facts.Resolved || facts.DomainID != pair.descriptor.DomainID || facts.FileID != pair.fileID || facts.Format != 1 || facts.EditableDigest != sha256.Sum256(pair.editable) || facts.GeneratedDigest != sha256.Sum256(pair.generated) || facts.EditableLength != uint64(len(pair.editable)) || facts.GeneratedLength != uint64(len(pair.generated)) || len(facts.GeneratedRecipients) != 1 || facts.GeneratedRecipients[0].Reference != "reader" || facts.GeneratedRecipients[0].Encryption.Selector != s.selector(5) {
				t.Fatal("parse-only child lost exact bounded public facts")
			}
			var generated struct {
				PublicBasis struct {
					Descriptor []byte
				} `json:"public_basis"`
			}
			if json.Unmarshal(pair.generated, &generated) != nil || !bytes.Equal(facts.Basis.Descriptor, generated.PublicBasis.Descriptor) || len(facts.Basis.Control) != 0 || len(facts.Basis.Selection) != 0 || len(facts.Basis.Enrollment) != 0 {
				t.Fatal("parse-only child altered the original public genesis basis")
			}
			assertFooter := func(capture observer.Capture, code int) {
				t.Helper()
				if len(capture.Events) != 1 || capture.Events[0].Kind != "footer" || capture.Events[0].Code != code {
					t.Fatal("parse-only child constructed or used an SDK, credential source, Store or private route")
				}
			}
			assertRecipients(t, pair.generated, facts)
			assertFooter(inspected.capture, 0)
			for _, damaged := range []struct {
				name string
				args []string
			}{
				{"missing-source", []string{"--inspect-source-pair", "--source-format", "json"}},
				{"relative-source", []string{"--inspect-source-pair", "--source", "relative.json", "--source-format", "json"}},
				{"unsupported-format", []string{"--inspect-source-pair", "--source", path, "--source-format", "yaml"}},
				{"mixed-private-mode", []string{"--inspect-source-pair", "--source", path, "--source-format", "json", "--materialize-retained"}},
				{"absent-source", []string{"--inspect-source-pair", "--source", filepath.Join(t.TempDir(), "absent.json"), "--source-format", "json"}},
			} {
				t.Run(damaged.name, func(t *testing.T) {
					refused := workflowRun(t, s, helper, "reader", observer.Policy{NoKMS: true, MaxRequests: 1, MaxBytes: 1}, nil, damaged.args...)
					if refused.code != 2 || len(refused.out) != 0 || len(refused.diagnostic) != 0 {
						t.Fatal("invalid parse-only request emitted facts or diagnostics")
					}
					assertFooter(refused.capture, 2)
				})
			}
			if !reflect.DeepEqual(before, s.snapshot("reader")) {
				t.Fatal("parse-only source observation changed selected state or provider events")
			}
			s.mu.Lock()
			unchanged := requests == s.requests && credentials == s.authRequests
			s.mu.Unlock()
			if !unchanged {
				t.Fatal("parse-only child reached an SDK endpoint or credential source")
			}
			if editable, err := os.ReadFile(path); err != nil || !bytes.Equal(editable, pair.editable) {
				t.Fatal("parse-only child changed source bytes")
			}
			if generated, err := os.ReadFile(filepath.Join(filepath.Dir(path), pair.reference)); err != nil || !bytes.Equal(generated, pair.generated) {
				t.Fatal("parse-only child changed generated bytes")
			}
			outputDirectory := administrativeReplacementDirectory(t)
			output := filepath.Join(outputDirectory, "successor.json")
			workflowResult(t, workflowRun(t, s, cli, "successor", observer.Policy{}, nil, "keys", "replace", "--source", path, "--source-format", "json", "--target", "authority", "--authorizer", "recovery", "--signing", s.selector(6), "--out", output, "--json"), "success")
			outputImage := workflowSuccessorImage(t, outputDirectory)
			s.mu.Lock()
			requests, credentials = s.requests, s.authRequests
			s.mu.Unlock()
			inspected = workflowRun(t, s, helper, "reader", observer.Policy{NoKMS: true, MaxRequests: 1, MaxBytes: 1}, nil, "--inspect-source-pair", "--source", output, "--source-format", "json")
			decoder = json.NewDecoder(bytes.NewReader(inspected.out))
			decoder.DisallowUnknownFields()
			facts = observer.SourcePairFacts{}
			if inspected.code != 0 || len(inspected.diagnostic) != 0 || decoder.Decode(&facts) != nil || decoder.Decode(new(any)) != io.EOF || facts.Schema != "PublicSourcePairFacts/v1" || !facts.Resolved || facts.DomainID != pair.descriptor.DomainID || facts.FileID != pair.fileID || len(facts.Basis.Descriptor) != 0 || len(facts.Basis.Control) == 0 || len(facts.Basis.Selection) == 0 {
				t.Fatal("parse-only child lost the delivered successor basis")
			}
			assertFooter(inspected.capture, 0)
			editable, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var document struct{ Generated string }
			if json.Unmarshal(editable, &document) != nil {
				t.Fatal("successor source is not JSON")
			}
			generatedBody, err := os.ReadFile(filepath.Join(outputDirectory, document.Generated))
			if err != nil {
				t.Fatal(err)
			}
			var successor struct {
				PublicBasis struct {
					Control, Selection []byte
					Enrollment         []struct {
						ID, Status  string
						DisplayName string `json:"display_name"`
					}
				} `json:"public_basis"`
			}
			if json.Unmarshal(generatedBody, &successor) != nil || facts.EditableDigest != sha256.Sum256(editable) || facts.GeneratedDigest != sha256.Sum256(generatedBody) || facts.EditableLength != uint64(len(editable)) || facts.GeneratedLength != uint64(len(generatedBody)) || !bytes.Equal(facts.Basis.Control, successor.PublicBasis.Control) || !bytes.Equal(facts.Basis.Selection, successor.PublicBasis.Selection) || len(facts.Basis.Enrollment) != len(successor.PublicBasis.Enrollment) {
				t.Fatal("successor source facts differ from the exact original public bytes")
			}
			assertRecipients(t, generatedBody, facts)
			for i, row := range facts.Basis.Enrollment {
				original := successor.PublicBasis.Enrollment[i]
				if hex.EncodeToString(row.ID[:]) != original.ID || row.Status != 1 || original.Status != "current" || row.DisplayName != original.DisplayName {
					t.Fatal("successor source facts changed complete enrollment order or values")
				}
			}
			// An isolated parse-only pair covers nonnil public creation facts without
			// claiming that this edited pair authenticates selected state.
			creationSnapshot := sha256.Sum256([]byte("source-pair-parser creation snapshot"))
			creationNonce := sha256.Sum256([]byte("source-pair-parser creation nonce"))
			var creationDocument map[string]any
			if err := json.Unmarshal(generatedBody, &creationDocument); err != nil {
				t.Fatal(err)
			}
			creationRecipients, ok := creationDocument["recipients"].(map[string]any)
			if !ok || len(creationRecipients) != 1 {
				t.Fatal("creation fixture requires one generated Recipient")
			}
			creationReader, ok := creationRecipients["reader"].(map[string]any)
			if !ok {
				t.Fatal("creation fixture requires reader")
			}
			creationReader["creation"] = map[string]string{"snapshot": hex.EncodeToString(creationSnapshot[:]), "nonce": hex.EncodeToString(creationNonce[:])}
			creationBody, err := json.MarshalIndent(creationDocument, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			creationDigest := sha256.Sum256(creationBody)
			creationReference := ".enkv/prod.generated.json"
			creationDirectory := t.TempDir()
			creationPath := filepath.Join(creationDirectory, "creation.json")
			if bytes.Count(editable, []byte(document.Generated)) != 1 {
				t.Fatal("creation fixture requires one generated dependency reference")
			}
			creationEditable := bytes.Replace(editable, []byte(document.Generated), []byte(creationReference), 1)
			if err := os.Mkdir(filepath.Join(creationDirectory, ".enkv"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(creationDirectory, creationReference), creationBody, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(creationPath, creationEditable, 0600); err != nil {
				t.Fatal(err)
			}
			creation := workflowRun(t, s, helper, "reader", observer.Policy{NoKMS: true, MaxRequests: 1, MaxBytes: 1}, nil, "--inspect-source-pair", "--source", creationPath, "--source-format", "json")
			decoder = json.NewDecoder(bytes.NewReader(creation.out))
			decoder.DisallowUnknownFields()
			var creationFacts observer.SourcePairFacts
			if creation.code != 0 || len(creation.diagnostic) != 0 || decoder.Decode(&creationFacts) != nil || decoder.Decode(new(any)) != io.EOF || len(creationFacts.GeneratedRecipients) != 1 || creationFacts.GeneratedRecipients[0].Creation == nil || creationFacts.GeneratedDigest != creationDigest || creationFacts.EditableDigest != sha256.Sum256(creationEditable) {
				t.Fatal("parse-only child lost the nonnil creation fixture")
			}
			assertRecipients(t, creationBody, creationFacts)
			assertFooter(creation.capture, 0)
			if !reflect.DeepEqual(outputImage, workflowSuccessorImage(t, outputDirectory)) {
				t.Fatal("successor facts parser changed delivered files or metadata")
			}
			s.mu.Lock()
			unchanged = requests == s.requests && credentials == s.authRequests
			s.mu.Unlock()
			if !unchanged {
				t.Fatal("successor facts parser reached an SDK or credential endpoint")
			}

		})
	}
}
