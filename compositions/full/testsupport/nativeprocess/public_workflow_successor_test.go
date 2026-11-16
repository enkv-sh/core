package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeSuccessorBasisTransfersToGETOnlyReader(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family+"/recovery-enabled", func(t *testing.T) {
			s := newWorkflowServer(t, family, true)
			protected := os.Getenv("ENKV_TEST_PROTECTED_FIXTURES")
			if protected == "" || !filepath.IsAbs(protected) || filepath.Clean(protected) != protected {
				t.Fatal("successor fixture requires the runner's managed protected directory")
			}
			administrative, err := os.MkdirTemp(protected, "successor-")
			if err != nil {
				t.Fatal("protected successor fixture directory unavailable")
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(administrative); err != nil {
					t.Error("protected successor fixture cleanup failed")
				}
			})
			path := filepath.Join(t.TempDir(), "configuration.json")
			if err := os.WriteFile(path, workflowSetup(t, s, true), 0600); err != nil {
				t.Fatal(err)
			}
			workflowResult(t, workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", path, "--source-format", "json", "--json"), "success")
			genesis := workflowReadPair(t, path)
			plaintext := []byte{'s', 'u', 'c', 'c', 'e', 's', 's', 'o', 'r', 0, 255, 1, 128}
			defer clear(plaintext)
			prepared := workflowPrepare(t, s, cli, path, "set", genesis, plaintext)
			workflowResult(t, workflowRun(t, s, cli, "apply", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json"), "success")
			workflowUnchanged(t, path, prepared)
			before, beforeObject := workflowHead(t, s)
			beforeRoot := workflowRoot(t, s, before)
			sum := sha256.Sum256(plaintext)
			restored := workflowRun(t, s, helper, "successor", observer.Policy{ExpectedSHA256: map[string]string{"binary": hex.EncodeToString(sum[:])}}, nil,
				"--source", path, "--source-format", "json", "--materialize-retained", "--successor-signing-selector", s.selector(6), "--successor-scratch", filepath.Join(administrative, "restore"))
			var result struct {
				PreparationStage uint8
				Successor        *struct {
					Domain, Operation, Revision string
					PairPrepared                bool
					OutputPath                  string
					Result                      struct{ Outcome, Reason uint8 }
				}
			}
			// The test helper returns Core's bounded numeric ObservedCurrent (2),
			// rather than a Product success result for this administrative route.
			decodeErr := json.Unmarshal(restored.out, &result)
			if restored.code != 0 || decodeErr != nil || result.Successor == nil || !result.Successor.PairPrepared || result.Successor.Result.Outcome != 2 || result.Successor.OutputPath != filepath.Join(administrative, "restore", "successor.json") {
				var outcome, reason uint8
				if result.Successor != nil {
					outcome, reason = result.Successor.Result.Outcome, result.Successor.Result.Reason
				}
				t.Fatalf("real signer restoration did not deliver a successor pair: exit=%d stage=%d successor_summary=%t outcome=%d reason=%d %s", restored.code, result.PreparationStage, result.Successor != nil, outcome, reason, restored.summary)
			}
			workflowPlaintext(t, restored, "plaintext")
			var successorPublic, successorSign, recoverySign, authorityDecrypt int
			for _, event := range restored.capture.Events {
				if event.Kind != "http-start" {
					continue
				}
				switch event.Operation {
				case "kms-public":
					if event.Sent && event.Role == "successor" {
						successorPublic++
					}
				case "kms-sign":
					switch event.Role {
					case "successor":
						if event.Sent {
							successorSign++
						}
					case "recovery-signing":
						if event.Sent {
							recoverySign++
						}
					default:
						t.Fatal("restoration attempted a signer other than Recovery or the exact successor")
					}
				case "kms-decrypt":
					if event.Role != "authority" {
						t.Fatal("retained materialization attempted another private decryption route")
					}
					if event.Sent {
						authorityDecrypt++
					}
				}
			}
			if successorPublic == 0 || successorSign == 0 || recoverySign == 0 || authorityDecrypt == 0 {
				t.Fatalf("native capture missed exact restoration capabilities: successor public=%d sign=%d Recovery sign=%d Authority decrypt=%d", successorPublic, successorSign, recoverySign, authorityDecrypt)
			}
			counts := s.snapshot("successor")
			if counts.calls["Sign/normal"] != 0 || counts.calls["Sign/successor"] == 0 || counts.calls["Sign/recovery-signing"] == 0 || counts.calls["Decrypt/authority"] == 0 || counts.calls["Decrypt/recovery-private"] != 0 || counts.headCreates != 0 || counts.headUpdates != 1 || counts.conditions != 0 {
				t.Fatal("signer restoration used another authority or selection boundary", counts)
			}
			after, afterObject := workflowHead(t, s)
			if after.AuthKind != stateformat.SuccessionAuth || after.Succession == nil || after.Core.PreviousRevision != before.Core.Revision || after.Core.PreviousDigest != contract.Hash(beforeObject.body) || after.Core.PreviousToken != (contract.Token{Family: genesis.descriptor.Provider, Value: beforeObject.etag}) || after.Core.Revision == before.Core.Revision || afterObject.etag == beforeObject.etag || after.Succession.Subject.ApprovalRole != contract.RecoverySigningRole || after.Succession.Subject.ChangeMask != contract.SuccessionChangeNormalSigner || len(after.Succession.Acceptances) == 0 || !bytes.Equal(after.Succession.Authorizer.SPKI, s.keys[s.selector(3)].der) {
				t.Fatal("restoration did not select the exact Recovery-authorized successor proof")
			}
			if result.Successor.Domain != hex.EncodeToString(genesis.descriptor.DomainID[:]) || result.Successor.Revision != hex.EncodeToString(after.Core.Revision[:]) || len(result.Successor.Operation) != 64 {
				t.Fatal("restoration correlation differs from actual selected successor")
			}
			editable, generated, reference, basis := workflowSuccessorPair(t, result.Successor.OutputPath)
			control, err := contract.DecodeControlCore(basis.Control)
			if err != nil || !bytes.Equal(basis.Selection, afterObject.body) || control.NormalSigning.KeySelector != s.selector(6) || !bytes.Equal(control.NormalSigning.SPKI, s.keys[s.selector(6)].der) || control.NormalSigning.Binding.Epoch != genesis.descriptor.NormalSigning.Binding.Epoch+1 {
				t.Fatal("portable successor lacks the actual complete signed selection and new signer", err)
			}
			expectedControl := beforeRoot.CurrentAccess.Core.CurrentControl
			expectedControl.NormalSigning = control.NormalSigning
			expectedControl.AccessGeneration++
			if !reflect.DeepEqual(control.CurrentControl, expectedControl) || !reflect.DeepEqual(workflowRoot(t, s, after).CurrentAccess.Core.CurrentControl, control.CurrentControl) || len(basis.Enrollment) != len(genesis.descriptor.Recipients) {
				t.Fatal("successor changed another public control or omitted enrolled recipients")
			}
			for i, row := range genesis.descriptor.Recipients {
				if basis.Enrollment[i].ID != hex.EncodeToString(row.RecipientID[:]) || basis.Enrollment[i].Status != "current" || basis.Enrollment[i].DisplayName != row.DisplayName {
					t.Fatal("successor enrollment does not preserve the complete independently enrolled set")
				}
			}
			portable := t.TempDir()
			portablePath := filepath.Join(portable, "configuration.json")
			if os.Mkdir(filepath.Join(portable, ".enkv"), 0700) != nil || os.WriteFile(portablePath, editable, 0400) != nil || os.WriteFile(filepath.Join(portable, reference), generated, 0400) != nil {
				t.Fatal("exact successor pair transfer failed")
			}
			image := workflowSuccessorImage(t, portable)
			if len(image) != 3 { // one directory and exactly two regular files
				t.Fatal("portable successor machine includes state outside the pair")
			}
			objects := s.objectCount()
			reader := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", portablePath, "--trusted-format", "json", "--json")
			comparison := workflowResult(t, reader, "success")
			workflowGETOnly(t, reader)
			if comparison.Payload.Schema != "ComparisonPayload/v1" || comparison.Payload.Verdict != "match" || !comparison.Payload.DiagnosticsComplete || comparison.Payload.EvidenceLimit != contract.ComparisonEvidenceLimit || len(comparison.Payload.Scope) != 12 || comparison.Observation.Revision != hex.EncodeToString(after.Core.Revision[:]) {
				t.Fatal("pair-only successor Reader did not report the actual complete public match")
			}
			scopes := map[string]bool{}
			for _, scope := range comparison.Payload.Scope {
				if scope.Status != "complete" || scopes[scope.Family] {
					t.Fatal("successor Reader left a public scope incomplete or repeated")
				}
				scopes[scope.Family] = true
			}
			for _, family := range []string{"entries", "plain_values", "secret_settings", "memberships", "recipients", "encryption", "generated", "outputs", "routing", "domain_store", "authority_recovery", "compatibility_profiles"} {
				if !scopes[family] {
					t.Fatal("successor Reader omitted a required public comparison scope")
				}
			}
			_, readHead := workflowHead(t, s)
			if s.objectCount() != objects || readHead.etag != afterObject.etag || !bytes.Equal(readHead.body, afterObject.body) || !reflect.DeepEqual(image, workflowSuccessorImage(t, portable)) {
				t.Fatal("fresh successor Reader changed selected state or the exact portable pair inventory")
			}
		})
	}
}

type workflowSuccessorBasis struct {
	Kind                           string
	Descriptor, Control, Selection []byte
	SigningAnchor                  []byte   `json:"anchor"`
	StoreConfiguration             []byte   `json:"store_configuration"`
	HEAD                           []byte   `json:"head"`
	Root                           []byte   `json:"root"`
	RecipientPages                 [][]byte `json:"recipient_pages"`
	Enrollment                     []struct {
		ID, Status  string
		DisplayName string `json:"display_name"`
	}
}

func workflowSuccessorPair(t *testing.T, path string) ([]byte, []byte, string, workflowSuccessorBasis) {
	t.Helper()
	editable, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		Generated string
		Domain    struct{ Name string }
	}
	if json.Unmarshal(editable, &source) != nil || !strings.HasPrefix(source.Generated, ".enkv/") || strings.Contains(source.Generated, "..") {
		t.Fatal("successor editable source lacks its exact generated reference")
	}
	generated, err := os.ReadFile(filepath.Join(filepath.Dir(path), source.Generated))
	if err != nil {
		t.Fatal(err)
	}
	var image struct {
		Basis workflowSuccessorBasis `json:"public_basis"`
	}
	if json.Unmarshal(generated, &image) != nil || source.Domain.Name != "prod" || source.Generated != ".enkv/prod.generated.json" || image.Basis.Kind != "successor" || len(image.Basis.Descriptor) != 0 || len(image.Basis.Control) == 0 || len(image.Basis.Selection) == 0 || len(image.Basis.Enrollment) == 0 {
		t.Fatal("successor generated image lacks complete portable proof")
	}
	return editable, generated, source.Generated, image.Basis
}

type workflowSuccessorFile struct {
	Mode fs.FileMode
	Body []byte
}

func workflowSuccessorImage(t *testing.T, directory string) map[string]workflowSuccessorFile {
	t.Helper()
	image := map[string]workflowSuccessorFile{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || path == directory {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			t.Fatal("portable pair includes a nonregular artifact")
		}
		var body []byte
		if info.Mode().IsRegular() {
			body, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		relative, err := filepath.Rel(directory, path)
		if err == nil {
			image[relative] = workflowSuccessorFile{Mode: info.Mode(), Body: body}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return image
}
