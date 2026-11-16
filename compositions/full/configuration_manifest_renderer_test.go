package compositionfull

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	compositionaws "enkv.sh/compositions/aws"
	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	gcpprovider "enkv.sh/providers/gcp"
	manifest "enkv.sh/sdk/manifest-generator"
	"errors"
)

// full_only: false
func TestConfigurationManifestSeparatesOpaqueBytesFromTransportFailure(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, condition := range []string{"malformed", "well-formed-wrong-format", "cancel-after-render", "deadline-changed-after-render"} {
			t.Run(family+"/"+condition, func(t *testing.T) {
				t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
				t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
				source := configurationReaderPair(t, family, configuration.JSON, nil)
				h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
				transport, stop := readerHTTPTransport(t, h, []string{"s3.us-east-1.amazonaws.com", "storage.australia-southeast1.rep.googleapis.com"})
				defer stop()
				parent, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				operationCtx := &manifestChangingDeadlineContext{Context: parent}
				calls := 0
				var supplied, expected []byte
				renderer := func(ctx context.Context, v manifest.View) manifest.Result {
					calls++
					r := manifestTestRender(ctx, v)
					if r.Failure != "" {
						t.Fatal("fixture renderer refused", r.Failure)
					}
					supplied = r.Artifact
					switch condition {
					case "malformed":
						r.Artifact[0] = '['
					case "well-formed-wrong-format":
						at := bytes.Index(r.Artifact, []byte(`"format":"`)) + len(`"format":"`)
						r.Artifact[at] = 'X'
					case "cancel-after-render":
						cancel()
					case "deadline-changed-after-render":
						operationCtx.changed = true
					}
					expected = bytes.Clone(r.Artifact)
					return r
				}
				open := func(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
					installed, err := readerConfigWithValidator(c)
					if err != nil {
						return nil, err
					}
					if installed.AWS != nil {
						installed.AWS.Candidate.Credentials = readerFixtureCredentials{}
						installed.AWS.Candidate.Transport = transport
						installed.AWS.PrepareManifestRenderer = func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
							return renderer, ""
						}
						return compositionaws.NewReader(*installed.AWS)
					}
					client, err := gcpprovider.NewLocalResponderClient(transport, readerFixtureCredentials{})
					if err != nil {
						return nil, err
					}
					installed.GCP.Candidate.Client = client
					installed.GCP.PrepareManifestRenderer = func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
						return renderer, ""
					}
					return compositiongcp.NewReader(ctx, *installed.GCP)
				}
				path := filepath.Join(t.TempDir(), "manifest.json")
				old := []byte("prior complete artifact")
				if err := os.WriteFile(path, old, 0600); err != nil {
					t.Fatal(err)
				}
				result := writeTestConfigurationManifest(operationCtx, contract.ID{1}, source.pair, configurationManifestRequest(source), path, open)
				if condition == "malformed" || condition == "well-formed-wrong-format" {
					if calls != 1 || result.Issuance.StateResult != contract.ReaderSuccess || result.Issuance.Payload == nil || result.Issuance.Payload.EvidenceLimit != "authorized-input-and-exact-bytes" || result.Delivery.NativeCompletion != ManifestNativeComplete {
						t.Fatal("opaque format bytes gained a semantic verifier", calls, result.Issuance.StateResult, result.Issuance.FailureReason)
					}
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, expected) {
						t.Fatal("opaque exact bytes were not delivered", err)
					}
					if bytes.Count(supplied, []byte{0}) != len(supplied) {
						t.Fatal("delivered artifact was not cleared")
					}
					source.assertUnchanged(t)
					h.assertNoEffects(t)
					return
				}
				want := contract.ReasonInvalidInput
				if condition == "cancel-after-render" {
					want = contract.ReasonCancelled
				}
				if condition == "deadline-changed-after-render" {
					want = contract.ReasonExpired
				}
				if calls != 1 || result.Issuance.StateResult == contract.ReaderSuccess || result.Issuance.FailureReason != want || result.Issuance.Payload != nil || result.Issuance.Artifact != nil || result.Issuance.RequestScope == nil || result.Issuance.Observation == nil || result.Issuance.TargetRecipientID.IsZero() {
					t.Fatal("renderer refusal lost safe scope or reached success", calls, result.Issuance.StateResult, result.Issuance.FailureReason)
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, old) {
					t.Fatal("renderer failure changed destination", err)
				}
				names, err := os.ReadDir(filepath.Dir(path))
				if err != nil || len(names) != 1 {
					t.Fatal("renderer failure staged a candidate", err)
				}
				if bytes.Count(supplied, []byte{0}) != len(supplied) {
					t.Fatal("renderer artifact was not cleared")
				}
				source.assertUnchanged(t)
				h.assertNoEffects(t)
			})
		}
	}
}

// full_only: false
func TestFullReaderFixesInstalledManifestRenderer(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
	calls := 0
	open := configurationReaderOpener(t, source, h, &calls)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	result, err := issueTestConfigurationManifest(ctx, contract.ID{1}, source.pair, configurationManifestRequest(source), func(ctx context.Context, c ReaderConfig) (*core.ReaderEngine, error) {
		c.AWS.PrepareManifestRenderer = func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
			t.Fatal("operation configuration replaced installed renderer")
			return nil, manifest.InvalidInput
		}
		return open(ctx, c)
	})
	if err != nil || result.StateResult != contract.ReaderSuccess || result.Payload == nil || calls != 1 {
		t.Fatal("fixed installed renderer failed", err, result.StateResult)
	}
	clear(result.Artifact)
	source.assertUnchanged(t)
	h.assertNoEffects(t)
}

// The final admission gate must recheck the original deadline after verification.
type manifestChangingDeadlineContext struct {
	context.Context
	changed bool
}

func (c *manifestChangingDeadlineContext) Deadline() (time.Time, bool) {
	d, ok := c.Context.Deadline()
	if c.changed {
		d = d.Add(time.Second)
	}
	return d, ok
}

// full_only: false
func TestConfigurationManifestSourceChangeDuringRendererPreparationStaysUnknown(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	calls := 0
	capture := func(context.Context, *configuration.Pair, plugininstallation.Requirement, ManifestOptions) (contract.ManifestRequest, func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure), error) {
		if err := os.Chmod(source.path, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source.path, append(bytes.Clone(source.editableBytes), byte('\n')), 0644); err != nil {
			t.Fatal(err)
		}
		return contract.ManifestRequest{}, nil, errors.New("renderer preparation failure")
	}
	path := filepath.Join(t.TempDir(), "manifest")
	result := writeConfigurationManifest(ctx, contract.ID{1}, source.pair, configurationManifestRequest(source), path, func(context.Context, ReaderConfig) (*core.ReaderEngine, error) { calls++; return nil, nil }, capture)
	if calls != 0 || result.SourceCleanup != ManifestSourceUnknown || result.Issuance.StateResult == contract.ReaderSuccess || result.Issuance.Payload != nil || result.Delivery.CandidateCleanup != ManifestCandidateNotCreated {
		t.Fatal("source change during preparation lost its independent uncertainty", calls, result.SourceCleanup)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed preparation created an artifact", err)
	}
	if _, err := RenderManifestFileJSON(result); err != nil {
		t.Fatal("safe preparation failure cannot render", err)
	}
}
