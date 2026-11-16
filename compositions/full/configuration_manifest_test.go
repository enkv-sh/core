package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

func configurationManifestRequest(source configurationReaderSource) ManifestOptions {
	return ManifestOptions{Plugin: "private-renderer", Settings: []byte(`{}`), TargetMode: manifest.ExactRecipient, TargetRecipientID: readerFixtureTarget(source.archive.Domain), EntryMode: manifest.ExactNames, EntryNames: []string{"secret", "encoded", "a/\n雪", ""}}
}

// full_only: false
func TestConfigurationManifestUsesSelectedStateAndRetainsBorrowedPair(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			t.Run(fmt.Sprintf("%s/%d", family, format), func(t *testing.T) {
				t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
				t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
				source := configurationReaderPair(t, family, format, func(editable, generated map[string]any) {
					entry := editable["entries"].(map[string]any)[""].(map[string]any)
					entry["recipients"] = []string{}
					entry["source"] = map[string]any{"kind": "supplied", "bytes": []byte("pending source value")}
					editable["domain"].(map[string]any)["authority"].(map[string]any)["display_name"] = "pending authority display"
					editable["outputs"].(map[string]any)["destinations"].(map[string]any)["aws"].(map[string]any)["plugin"] = "unselected-private-output"
				})
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
				calls := 0
				open := configurationReaderOpener(t, source, h, &calls)
				var reader *core.ReaderEngine
				request := configurationManifestRequest(source)
				if format == configuration.YAML {
					model, err := configuration.Parse(ctx, source.pair)
					if err != nil {
						t.Fatal(err)
					}
					for _, row := range model.Recipients {
						if row.ID == request.TargetRecipientID {
							request.TargetRecipientReference, request.TargetRecipientID = row.Reference, contract.ID{}
							break
						}
					}
					if request.TargetRecipientReference == "" {
						t.Fatal("target has no local alias")
					}
				}
				result, err := issueTestConfigurationManifest(ctx, contract.ID{1}, source.pair, request, func(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
					var err error
					reader, err = open(ctx, c)
					return reader, err
				})
				want := configurationManifestExpectedArtifact(t)
				if err != nil || result.StateResult != contract.ReaderSuccess || result.Payload == nil || !bytes.Equal(result.Artifact, []byte(want)) || len(result.Artifact) != cap(result.Artifact) || result.Payload.ArtifactDigest != contract.ID(sha256.Sum256([]byte(want))) || calls != 1 {
					t.Fatal("public manifest did not transfer exact selected artifact", err, result.StateResult, result.FailureReason, calls)
				}
				if source.pair.CheckUnchanged(ctx) != nil {
					t.Fatal("borrowed source was closed")
				}
				closed := reader.Manifest(ctx, contract.ID{2}, contract.ManifestRequest{})
				if closed.StateResult == contract.ReaderSuccess || !bytes.Equal(result.Artifact, []byte(want)) {
					t.Fatal("Reader lifetime escaped issuance or damaged transferred bytes")
				}
				source.assertUnchanged(t)
				h.assertNoEffects(t)
				clear(result.Artifact)
			})
		}
	}
}

// full_only: false
func TestConfigurationManifestCapturesRequestBeforeReaderConstruction(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
	calls := 0
	open := configurationReaderOpener(t, source, h, &calls)
	provider := "github-actions"
	request := configurationManifestRequest(source)
	request.ServiceFilter = &provider
	result, err := issueTestConfigurationManifest(ctx, contract.ID{1}, source.pair, request, func(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
		request.EntryNames[0] = "absent pending name"
		request.Plugin = "different-renderer"
		request.Settings[0] = byte(32)
		provider = "aws-secrets-manager"
		return open(ctx, c)
	})
	if err != nil || result.StateResult != contract.ReaderSuccess || result.Payload == nil || len(result.Payload.IncludedEntries) != 4 || result.RequestScope == nil || result.RequestScope.ServiceFilter == nil || *result.RequestScope.ServiceFilter != "github-actions" || result.RequestScope.Renderer.Name != "private-renderer" || string(result.RequestScope.Settings) != `{}` || calls != 1 {
		t.Fatal("caller mutation replaced captured request", err, result.StateResult, result.FailureReason)
	}
	var document manifestTestDocument
	if json.Unmarshal(result.Artifact, &document) != nil || document.ServiceFilter == nil || *document.ServiceFilter != "github-actions" || len(document.Entries) != 4 {
		t.Fatal("captured service did not reach artifact")
	}
	for i, name := range []string{"", "a/\n雪", "encoded", "secret"} {
		entry := document.Entries[i]
		if entry.Name != name || i >= 2 && len(entry.Destinations) != 3 {
			t.Fatal("captured exact selection or service scope changed")
		}
		for _, destination := range entry.Destinations {
			if destination.ServiceContractID != "github-actions" {
				t.Fatal("caller replaced service after capture")
			}
		}
	}
	clear(result.Artifact)
	source.assertUnchanged(t)
	h.assertNoEffects(t)
}

// full_only: false
func TestConfigurationManifestSourceAndStoreFailuresCreateNoCandidate(t *testing.T) {
	for _, condition := range []string{"lost-trust", "stale-source", "pending-transaction", "denied-read"} {
		t.Run(condition, func(t *testing.T) {
			source := configurationReaderPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
				if condition == "lost-trust" {
					generated["public_basis"].(map[string]any)["descriptor"] = []byte{1}
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}, unavailable: condition == "denied-read"}
			if condition == "stale-source" {
				if err := os.Chmod(source.path, 0644); err != nil {
					t.Fatal(err)
				}
				changed := append(bytes.Clone(source.editableBytes), '\n')
				if err := os.WriteFile(source.path, changed, 0644); err != nil {
					t.Fatal(err)
				}
				source.editableBytes = changed
			}
			if condition == "pending-transaction" {
				if err := os.Chmod(filepath.Dir(source.path), 0700); err != nil {
					t.Fatal(err)
				}
				pending := filepath.Join(filepath.Dir(source.path), ".enkv-pending")
				if err := os.Mkdir(pending, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(pending, filepath.Base(source.path)), []byte("pending transaction"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			path := filepath.Join(protectedConfigurationTestDirectory(t), "manifest.json")
			result := writeTestConfigurationManifest(ctx, contract.ID{1}, source.pair, configurationManifestRequest(source), path, configurationReaderOpener(t, source, h, &calls))
			wantCalls := 0
			wantCleanup := ManifestSourceUnknown
			if condition == "denied-read" {
				wantCalls = 1
				wantCleanup = ManifestSourceComplete
			}
			if result.Issuance.StateResult == contract.ReaderSuccess || result.Issuance.Artifact != nil || result.Issuance.Payload != nil || calls != wantCalls || result.Delivery.CandidateCleanup != ManifestCandidateNotCreated || result.Delivery.Failure != nil || result.SourceCleanup != wantCleanup {
				t.Fatal("failed public read reached native delivery or lost facts", condition, calls, result)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed issuance created native destination", err)
			}
			if _, err := RenderManifestFileJSON(result); err != nil {
				t.Fatal("failed public read cannot render", err)
			}
			source.assertUnchanged(t)
			h.assertNoEffects(t)
		})
	}
}

// full_only: false
func TestConfigurationManifestRefusesBeforeReaderConstruction(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, condition := range []string{"invalid-selector", "duplicate-name", "nil-pair", "no-deadline", "canceled", "zero-nonce"} {
		t.Run(condition, func(t *testing.T) {
			request, pair, operationCtx, nonce := configurationManifestRequest(source), source.pair, ctx, contract.ID{1}
			switch condition {
			case "invalid-selector":
				request.TargetMode = ""
			case "duplicate-name":
				request.EntryNames = []string{"secret", "secret"}
			case "nil-pair":
				pair = nil
			case "no-deadline":
				operationCtx = context.Background()
			case "canceled":
				var stop context.CancelFunc
				operationCtx, stop = context.WithCancel(ctx)
				stop()
			case "zero-nonce":
				nonce = contract.ID{}
			}
			calls := 0
			result, _ := issueTestConfigurationManifest(operationCtx, nonce, pair, request, func(context.Context, ReaderConfig) (*core.ReaderEngine, error) {
				calls++
				return nil, errors.New("construction sentinel")
			})
			if calls != 0 || result.StateResult != contract.ReaderRefused || result.Payload != nil || result.Artifact != nil || result.PreAdmission == nil || result.Context.OperationID.IsZero() {
				t.Fatal("invalid input reached Reader or lost safe correlation", condition, calls, result)
			}
			if _, err := RenderManifestResultJSON(result); err != nil {
				t.Fatal("early refusal cannot render", err)
			}
		})
	}
	source.assertUnchanged(t)
}

// full_only: false
func TestConfigurationManifestFileSeparatesSourceCloseFromIssuance(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
	calls, closes := 0, 0
	result, err := issueTestConfigurationManifestFile(ctx, contract.ID{1}, source.path, configuration.JSON, configurationManifestRequest(source), configurationReaderOpener(t, source, h, &calls), func(pair *configuration.Pair) error {
		closes++
		return errors.Join(pair.Close(), errors.New("source close sentinel"))
	})
	if !errors.Is(err, ErrManifestSourceClose) || calls != 1 || closes != 1 || result.StateResult != contract.ReaderSuccess || result.Payload == nil || len(result.Artifact) == 0 || result.Payload.ArtifactDigest != contract.ID(sha256.Sum256(result.Artifact)) {
		t.Fatal("source close replaced completed issuance", err, calls, closes, result.StateResult)
	}
	source.assertUnchanged(t)
	h.assertNoEffects(t)
	clear(result.Artifact)
}

// full_only: false
func TestConfigurationManifestNativeDeliveryReleasesArtifactAndKeepsSourceFacts(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
	calls, closes := 0, 0
	path := filepath.Join(protectedConfigurationTestDirectory(t), "manifest.json")
	result := writeTestConfigurationManifestFile(ctx, contract.ID{1}, source.path, configuration.JSON, configurationManifestRequest(source), path, configurationReaderOpener(t, source, h, &calls), func(pair *configuration.Pair) error {
		closes++
		return errors.Join(pair.Close(), errors.New("source close sentinel"))
	})
	want := configurationManifestExpectedArtifact(t)
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, []byte(want)) || result.Issuance.StateResult != contract.ReaderSuccess || result.Issuance.Artifact != nil || result.Delivery.NativeCompletion != ManifestNativeComplete || result.SourceCleanup != ManifestSourceFailed || calls != 1 || closes != 1 {
		t.Fatal("native settlement lost independent facts", err, result.Delivery, result.SourceCleanup, calls, closes)
	}
	if result.Delivery.Artifact == nil || result.Delivery.Artifact.Digest != contract.ID(sha256.Sum256([]byte(want))) || result.Delivery.Artifact.Length != uint64(len(want)) {
		t.Fatal("released artifact lost exact metadata")
	}
	source.assertUnchanged(t)
	h.assertNoEffects(t)
}

// full_only: false
func TestConfigurationManifestLateSourceFailurePreservesIssuanceAndPreventsStaging(t *testing.T) {
	for _, condition := range []string{"source-change-during-load", "canceled-after-issuance"} {
		t.Run(condition, func(t *testing.T) {
			source := configurationReaderPair(t, "aws", configuration.JSON, nil)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
			var handler http.Handler = h
			changed := append(bytes.Clone(source.editableBytes), '\n')
			mutationDone := make(chan error, 1)
			if condition == "source-change-during-load" {
				var once sync.Once
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					once.Do(func() {
						err := os.Chmod(source.path, 0644)
						if err == nil {
							err = os.WriteFile(source.path, changed, 0644)
						}
						mutationDone <- err
					})
					h.ServeHTTP(w, r)
				})
			}
			transport, stop := readerHTTPTransport(t, handler, []string{"s3.us-east-1.amazonaws.com"})
			defer stop()
			calls := 0
			issuance, sourceErr := issueTestConfigurationManifest(ctx, contract.ID{1}, source.pair, configurationManifestRequest(source), func(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
				calls++
				c.AWS.Candidate.Credentials = readerFixtureCredentials{}
				c.AWS.Candidate.Transport = transport
				c.PrepareManifestRenderer = func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
					return manifestTestRender, ""
				}
				return NewReader(ctx, c)
			})
			want := configurationManifestExpectedArtifact(t)
			if issuance.StateResult != contract.ReaderSuccess || issuance.Payload == nil || !bytes.Equal(issuance.Artifact, []byte(want)) || issuance.Payload.ArtifactDigest != contract.ID(sha256.Sum256([]byte(want))) || calls != 1 {
				t.Fatal("late source failure replaced completed issuance", issuance.StateResult, issuance.FailureReason, calls)
			}
			wantReason := ManifestIOFailure
			if condition == "source-change-during-load" {
				select {
				case err := <-mutationDone:
					if err != nil {
						t.Fatal("controlled source change failed", err)
					}
				case <-ctx.Done():
					t.Fatal("source change did not join", ctx.Err())
				}
				if !errors.Is(sourceErr, ErrManifestSource) {
					t.Fatal("completed issuance lost independent source failure", sourceErr)
				}
				source.editableBytes = changed
			} else {
				if sourceErr != nil {
					t.Fatal("source failed before controlled cancellation", sourceErr)
				}
				cancel()
				if source.pair.CheckUnchanged(ctx) == nil {
					t.Fatal("canceled source check succeeded")
				}
				sourceErr, wantReason = ErrManifestSource, ManifestCanceled
			}
			path := filepath.Join(protectedConfigurationTestDirectory(t), "manifest.json")
			old := []byte("complete old artifact")
			if err := os.WriteFile(path, old, 0600); err != nil {
				t.Fatal(err)
			}
			backing := issuance.Artifact
			result := deliverConfigurationManifest(ctx, issuance, sourceErr, source.pair, path)
			if result.Issuance.StateResult != contract.ReaderSuccess || result.Issuance.Artifact != nil || result.Issuance.Payload == nil || result.Issuance.Observation == nil || result.Issuance.TargetRecipientID != readerFixtureTarget(source.archive.Domain) || result.Delivery.Replacement != ManifestReplacementNotAttempted || result.Delivery.CandidateCleanup != ManifestCandidateNotCreated || result.Delivery.CandidateVerification != ManifestVerificationNotObserved || result.Delivery.InstalledVerification != ManifestVerificationNotObserved || result.Delivery.NativeCompletion != ManifestNativeIncomplete || result.Delivery.Failure == nil || result.Delivery.Failure.Stage != ManifestPreflightStage || result.Delivery.Failure.Reason != wantReason || result.SourceCleanup != ManifestSourceUnknown {
				t.Fatal("late source failure staged bytes or replaced independent facts", result)
			}
			if result.Delivery.Artifact == nil || result.Delivery.Artifact.Digest != issuance.Payload.ArtifactDigest || result.Delivery.Artifact.Length != uint64(len(want)) {
				t.Fatal("late failure lost artifact metadata")
			}
			for _, value := range backing {
				if value != 0 {
					t.Fatal("native owner retained artifact contents after settlement")
				}
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, old) {
				t.Fatal("late source failure changed destination", err)
			}
			files, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(files) != 1 || files[0].Name() != filepath.Base(path) {
				t.Fatal("late source failure left a staging file", err)
			}
			if _, err := RenderManifestFileJSON(result); err != nil {
				t.Fatal("late source failure cannot render", err)
			}
			var one [1]byte
			if n, err := source.pair.Editable.ReadAt(one[:], 0); n != 1 || err != nil {
				t.Fatal("late failure closed caller-owned source", err)
			}
			source.assertUnchanged(t)
			h.assertNoEffects(t)
		})
	}
}

// full_only: false
func TestConfigurationManifestOpaqueSourceErrorsKeepCleanupUnknown(t *testing.T) {
	for _, condition := range []string{"capture-error", "check-before-issuance", "check-before-rename", "native-io-only"} {
		t.Run(condition, func(t *testing.T) {
			source := configurationReaderPair(t, "aws", configuration.JSON, nil)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
			calls := 0
			open := configurationReaderOpener(t, source, h, &calls)
			path := filepath.Join(protectedConfigurationTestDirectory(t), "manifest.json")
			old := []byte("complete old artifact")
			if err := os.WriteFile(path, old, 0600); err != nil {
				t.Fatal(err)
			}
			changeSource := func() error {
				if err := os.Chmod(source.path, 0644); err != nil {
					return err
				}
				changed := append(bytes.Clone(source.editableBytes), '\n')
				if err := os.WriteFile(source.path, changed, 0644); err != nil {
					return err
				}
				source.editableBytes = changed
				return nil
			}
			var result ManifestFileResult
			wantCleanup := ManifestSourceUnknown
			switch condition {
			case "capture-error":
				missing := filepath.Join(filepath.Dir(source.path), "missing-source.json")
				result = WriteConfigurationManifestFile(ctx, contract.ID{1}, missing, configuration.JSON, configurationManifestRequest(source), path)
				if result.Issuance.StateResult == contract.ReaderSuccess || result.Issuance.PreAdmission == nil || result.Issuance.PreAdmission.Stage != "capture" {
					t.Fatal("actual capture failure did not reach safe refusal")
				}
			case "check-before-issuance":
				closes := 0
				result = writeTestConfigurationManifestFile(ctx, contract.ID{1}, source.path, configuration.JSON, configurationManifestRequest(source), path, func(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
					reader, err := open(ctx, c)
					if err != nil {
						return reader, err
					}
					if err := changeSource(); err != nil {
						reader.Close()
						t.Fatal("controlled source change failed", err)
					}
					return reader, nil
				}, func(pair *configuration.Pair) error {
					closes++
					return pair.Close()
				})
				if calls != 1 || closes != 1 || result.Issuance.StateResult == contract.ReaderSuccess || result.Delivery.CandidateCleanup != ManifestCandidateNotCreated {
					t.Fatal("source check did not refuse before issuance or close its pair", calls, closes, result)
				}
			case "check-before-rename", "native-io-only":
				issuance, err := issueTestConfigurationManifest(ctx, contract.ID{1}, source.pair, configurationManifestRequest(source), open)
				if err != nil || issuance.StateResult != contract.ReaderSuccess {
					t.Fatal("fixture did not complete real issuance", err, issuance.StateResult)
				}
				backing := issuance.Artifact
				checks, renames := 0, 0
				target, delivery := newManifestFileTarget(path, []string{source.path, source.generated}, func(ctx context.Context) error {
					checks++
					return source.pair.CheckUnchanged(ctx)
				})
				if target == nil {
					clear(backing)
					t.Fatal("fixture target refused", delivery)
				}
				rename := target.io.rename
				target.io.rename = func(from, to string) (ManifestReplacement, error) {
					renames++
					return rename(from, to)
				}
				write := target.io.write
				target.io.write = func(file *os.File, body []byte) (int, error) {
					if condition == "native-io-only" {
						return 0, errors.New("native write sentinel")
					}
					n, err := write(file, body)
					if err != nil {
						return n, err
					}
					return n, changeSource()
				}
				result = installConfigurationManifest(ctx, issuance, target, delivery)
				wantChecks, wantStage, wantVerification := 2, ManifestPreflightStage, ManifestVerified
				if condition == "native-io-only" {
					wantCleanup = ManifestSourceComplete
					wantChecks, wantStage, wantVerification = 1, ManifestCandidateWriteStage, ManifestVerificationNotObserved
				}
				if checks != wantChecks || renames != 0 || result.Issuance.StateResult != contract.ReaderSuccess || result.Issuance.Artifact != nil || result.Delivery.Replacement != ManifestNotReplaced || result.Delivery.CandidateVerification != wantVerification || result.Delivery.CandidateCleanup != ManifestCandidateRemoved || result.Delivery.Failure == nil || result.Delivery.Failure.Stage != wantStage || result.Delivery.Failure.Reason != ManifestIOFailure {
					t.Fatal("controlled failure lost issuance or native facts", checks, renames, result)
				}
				for _, value := range backing {
					if value != 0 {
						t.Fatal("native failure retained artifact contents")
					}
				}
			}
			if result.SourceCleanup != wantCleanup {
				t.Fatalf("opaque source failure has no cleanup certificate: got %q, want %q", result.SourceCleanup, wantCleanup)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, old) {
				t.Fatal("failure changed existing destination", err)
			}
			if _, err := RenderManifestFileJSON(result); err != nil {
				t.Fatal("source cleanup facts cannot render", err)
			}
			source.assertUnchanged(t)
			h.assertNoEffects(t)
		})
	}
}

// full_only: false
func TestConfigurationManifestBuildAndFormatReachAllReaderConstructorsAndDelivery(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, profile := range []string{"private-renderer-a", "private-renderer-b"} {
			t.Run(family+"/"+profile, func(t *testing.T) {
				t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
				t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
				source := configurationReaderPair(t, family, configuration.JSON, nil)
				h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
				calls := 0
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				request := configurationManifestRequest(source)
				request.Plugin = profile
				destination := filepath.Join(t.TempDir(), "manifest.json")
				got := writeTestConfigurationManifest(ctx, contract.ID{1}, source.pair, request, destination, configurationReaderOpener(t, source, h, &calls))
				if calls != 1 || got.Issuance.StateResult != contract.ReaderSuccess || got.Issuance.RequestScope == nil || got.Issuance.RequestScope.FormatContractID != profile || got.Issuance.Payload == nil || got.Issuance.Payload.FormatContractID != profile || got.Delivery.Artifact == nil || got.Delivery.Artifact.FormatContractID != profile || got.Delivery.NativeCompletion != ManifestNativeComplete {
					t.Fatal("selected profile lost through Reader or delivery", calls, got.Issuance.StateResult)
				}
				body, err := os.ReadFile(destination)
				if err != nil || uint64(len(body)) != got.Issuance.Payload.ArtifactLength || contract.Hash(body) != got.Issuance.Payload.ArtifactDigest {
					t.Fatal("delivery did not preserve verified issuance", err)
				}
				var document manifestTestDocument
				if json.Unmarshal(body, &document) != nil || document.Format != profile {
					t.Fatal("selected private format differs")
				}
				for _, render := range []func(ManifestFileResult) ([]byte, error){RenderManifestFileJSON, RenderManifestFileHuman} {
					if result, err := render(got); err != nil || len(result) == 0 {
						t.Fatal("profile-bound delivery result refused", err)
					}
				}
				source.assertUnchanged(t)
				h.assertNoEffects(t)
			})
		}
	}
}

// full_only: false
func TestConfigurationManifestInvalidPluginRefusesBeforeSourceCapture(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	calls := 0
	got := writeTestConfigurationManifestFile(ctx, contract.ID{1}, filepath.Join(t.TempDir(), "missing.json"), configuration.JSON, ManifestOptions{Plugin: "../unknown", Settings: []byte(`{}`), TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}, filepath.Join(t.TempDir(), "manifest.json"), func(context.Context, ReaderConfig) (*core.ReaderEngine, error) {
		calls++
		return nil, errors.New("construction sentinel")
	}, func(*configuration.Pair) error { t.Fatal("unknown profile captured source"); return nil })
	if calls != 0 || got.Issuance.StateResult != contract.ReaderRefused || got.Issuance.FailureReason != contract.ReasonInvalidInput || got.Issuance.RequestScope != nil || got.Issuance.Payload != nil || got.Issuance.Artifact != nil || got.SourceCleanup != ManifestSourceComplete {
		t.Fatal("unknown profile reached source or lost safe refusal")
	}
	if _, err := RenderManifestFileJSON(got); err != nil {
		t.Fatal("early profile refusal cannot render", err)
	}
}

func configurationManifestExpectedArtifact(t *testing.T) []byte {
	t.Helper()
	// Values and destinations are the selected archive fixture, independently of
	// editable pending bytes and the renderer's borrowed View.
	document := manifestTestDocument{Format: "private-renderer", Entries: []manifestTestEntry{{Name: "", PlainValue: []byte{}, Destinations: []manifestTestDestination{}}, {Name: "a/\n雪", PlainValue: []byte{0, 10, 65}, Destinations: []manifestTestDestination{}}}}
	for _, name := range []string{"encoded", "secret"} {
		row := manifestTestEntry{Name: name, Destinations: []manifestTestDestination{}}
		for _, facts := range readerFixtureProfiles(name) {
			row.Destinations = append(row.Destinations, manifestTestDestination{ServiceContractID: facts.provider, ConsumerLocator: facts.locator})
		}
		document.Entries = append(document.Entries, row)
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
