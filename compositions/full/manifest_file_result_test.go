package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

func manifestFileResultFixture() ManifestFileResult {
	return ManifestFileResult{Issuance: core.PublicManifestResult{Context: core.ReaderOperationContext{Operation: contract.ReaderManifestOperation}, StateResult: contract.ReaderUnavailable, FailureReason: contract.ReasonSelectedObjectUnavailable}, Delivery: initialManifestDelivery(), SourceCleanup: ManifestSourceComplete, ResultDelivery: ManifestResultNotObserved}
}

// full_only: false
func TestManifestHumanSeparatesIssuanceAndLocalDelivery(t *testing.T) {
	r := manifestFileResultFixture()
	body, err := RenderManifestFileHuman(r)
	if err != nil {
		t.Fatal(err)
	}
	var delivered bytes.Buffer
	if err := WriteManifestFileHuman(t.Context(), &delivered, r); err != nil || !bytes.Equal(body, delivered.Bytes()) {
		t.Fatal("native human writer diverged from its renderer", err)
	}
	for _, want := range []string{"Manifest: unavailable\n", "Reason: selected-object-unavailable\n", "Local replacement: not-attempted\n", "Source cleanup: complete\n", "Result-stream delivery is not observed by this result.\n"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatal("manifest human omitted a phase fact", want, string(body))
		}
	}
	if bytes.Contains(body, []byte("ProductResult/v1")) || bytes.Contains(body, []byte("ManifestFileResult/v2")) {
		t.Fatal("manifest human exposed an internal envelope")
	}
}

// full_only: false
func TestManifestFileResultIndependentLiteralAndTerminalPrecedence(t *testing.T) {
	r := manifestFileResultFixture()
	// This closed grammar literal is independent of the production renderer.
	want := `{"schema":"ManifestFileResult/v2","issuance":{"schema":"ProductResult/v1","operation_kind":"issue-consumption-manifest","state_result":"unavailable","effect_summary":"not-applicable","output_summary":"not-applicable","context":{"operation":"issue-consumption-manifest"},"failure_reason":"selected-object-unavailable"},"delivery":{"target_path":null,"artifact":null,"replacement":"not-attempted","candidate_verification":"not-observed","installed_verification":"not-observed","native_completion":"incomplete","candidate_cleanup":"not-created","residue_path":null,"failure":null},"source_cleanup":"complete","result_delivery":"not-observed"}`
	body, err := RenderManifestFileJSON(r)
	if err != nil || !bytes.Equal(body, readableExpectedJSON(t, want)) || len(body) != cap(body) {
		t.Fatal("closed native record differs", err, string(body))
	}
	for _, source := range []ManifestSourceCleanup{ManifestSourceNotObserved, ManifestSourceComplete, ManifestSourceFailed, ManifestSourceUnknown} {
		for _, presentation := range []ManifestResultDelivery{ManifestResultNotObserved, ManifestResultComplete, ManifestResultFailed, ManifestResultUnknown} {
			r.SourceCleanup, r.ResultDelivery = source, presentation
			want := 2
			if source == ManifestSourceComplete && presentation == ManifestResultComplete {
				want = 3
			}
			if got := ManifestFileExitCode(r); got != want {
				t.Fatal("terminal failure lost precedence", source, presentation, got)
			}
		}
	}
}

// full_only: false
func TestManifestFileResultRefusesInvalidAxesBeforeOutput(t *testing.T) {
	for _, change := range []func(*ManifestFileResult){
		func(r *ManifestFileResult) { r.SourceCleanup = "private-error" }, func(r *ManifestFileResult) { r.ResultDelivery = ManifestResultComplete },
		func(r *ManifestFileResult) { r.Delivery.TargetPath = "relative" }, func(r *ManifestFileResult) { r.Delivery.TargetPath = "/" + strings.Repeat("x", 4096) },
		func(r *ManifestFileResult) { r.Delivery.Replacement = "private-error" }, func(r *ManifestFileResult) { r.Delivery.CandidateVerification = "private-error" },
		func(r *ManifestFileResult) { r.Delivery.InstalledVerification = "private-error" }, func(r *ManifestFileResult) { r.Delivery.NativeCompletion = ManifestNativeComplete },
		func(r *ManifestFileResult) { r.Delivery.CandidateCleanup = ManifestCandidateCleanupUnknown }, func(r *ManifestFileResult) { r.Delivery.ResiduePath = "/tmp/foreign" },
		func(r *ManifestFileResult) {
			r.Delivery.Failure = &ManifestFileFailure{Stage: ManifestRenameStage, Reason: ManifestIOFailure}
		},
		func(r *ManifestFileResult) { r.Issuance.Artifact = []byte("artifact-private-sentinel") },
	} {
		r := manifestFileResultFixture()
		change(&r)
		var out bytes.Buffer
		if err := WriteManifestFileJSON(t.Context(), &out, r); err == nil || out.Len() != 0 {
			t.Fatal("invalid native facts emitted", err, out.String())
		}
	}
}

type manifestResultWriter struct {
	body   bytes.Buffer
	mode   string
	cancel context.CancelFunc
}

func (w *manifestResultWriter) Write(p []byte) (int, error) {
	if len(p) != 0 && p[len(p)-1] == '\n' {
		n, err := w.body.Write(p[:len(p)-1])
		if err != nil {
			return n, err
		}
		if !json.Valid(w.body.Bytes()) {
			last, err := w.body.Write(p[len(p)-1:])
			return n + last, err
		}
		switch w.mode {
		case "short":
			return n, nil
		case "error":
			return n, errors.New("private-writer-sentinel")
		case "cancel":
			w.cancel()
		}
		last, err := w.body.Write(p[len(p)-1:])
		return n + last, err
	}
	return w.body.Write(p)
}

// full_only: false
func TestManifestFileResultDeliverySettlesAfterFinalWrite(t *testing.T) {
	for _, mode := range []string{"complete", "short", "error", "cancel"} {
		ctx, cancel := context.WithCancel(t.Context())
		w := &manifestResultWriter{mode: mode, cancel: cancel}
		r := manifestFileResultFixture()
		err := WriteManifestFileJSON(ctx, w, r)
		cancel()
		if (err == nil) != (mode == "complete") {
			t.Fatal("delivery verdict differs", mode, err)
		}
		if mode == "short" && !errors.Is(err, io.ErrShortWrite) {
			t.Fatal("short output lost", err)
		}
		if !json.Valid(w.body.Bytes()) || !bytes.Contains(w.body.Bytes(), []byte(`"result_delivery": "not-observed"`)) {
			t.Fatal("stream certified its own output")
		}
		if r.ResultDelivery != ManifestResultNotObserved {
			t.Fatal("writer changed caller result")
		}
	}
}

func completeManifestFileResultFixture() ManifestFileResult {
	selection := manifest.Selection{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}
	observation := manifest.Observation{DomainID: manifest.ID{1}, HEADRevisionID: manifest.ID{2}, SnapshotID: manifest.ID{3}}
	p := &contract.ManifestPayload{Selection: selection, IncludedEntries: []manifest.EntryIdentity{}, ExcludedEntries: []manifest.ExcludedEntry{}, Observation: observation, TargetRecipientID: contract.ID{4}, Renderer: manifestTestScope(selection).Renderer, FormatContractID: manifestTestFormat, ConfigContractID: "private-settings/v1", Settings: []byte(`{}`), ArtifactLength: 12, ArtifactDigest: contract.ID{5}, EvidenceLimit: manifest.EvidenceLimit}
	r := NewManifestFileResult(core.PublicManifestResult{Context: core.ReaderOperationContext{Operation: contract.ReaderManifestOperation}, StateResult: contract.ReaderSuccess, RequestScope: &contract.ManifestRequestScope{Renderer: manifestTestScope(selection).Renderer, FormatContractID: manifestTestFormat, ConfigContractID: "private-settings/v1", Settings: []byte(`{}`), Selection: selection}, Observation: &observation, TargetRecipientID: p.TargetRecipientID, Payload: p})
	r.SourceCleanup = ManifestSourceComplete
	r.Delivery = ManifestDelivery{TargetPath: "/tmp/manifest.json", Artifact: &ManifestArtifact{RendererArtifactID: p.Renderer.ArtifactID, FormatContractID: p.FormatContractID, Length: p.ArtifactLength, Digest: p.ArtifactDigest}, Replacement: ManifestReplaced, CandidateVerification: ManifestVerified, InstalledVerification: ManifestVerified, NativeCompletion: ManifestNativeComplete, CandidateCleanup: ManifestCandidateRenamed}
	return r
}

// full_only: false
func TestManifestFileCompleteRequiresAllNativeAndTerminalFacts(t *testing.T) {
	r := completeManifestFileResultFixture()
	body, err := RenderManifestFileJSON(r)
	if err != nil || !bytes.Contains(body, []byte(`"native_completion": "complete"`)) {
		t.Fatal("valid complete result refused", err)
	}
	r.ResultDelivery = ManifestResultComplete
	if ManifestFileExitCode(r) != 0 {
		t.Fatal("settled success refused")
	}
	for _, change := range []func(*ManifestFileResult){
		func(r *ManifestFileResult) { r.Delivery.Artifact = nil }, func(r *ManifestFileResult) { r.Delivery.TargetPath = "" },
		func(r *ManifestFileResult) {
			r.Delivery.Artifact = &ManifestArtifact{RendererArtifactID: contract.ID{6}, FormatContractID: manifestTestFormat, Length: 13, Digest: contract.ID{5}}
		},
		func(r *ManifestFileResult) { r.Delivery.Replacement = ManifestNotReplaced }, func(r *ManifestFileResult) { r.Delivery.CandidateVerification = ManifestVerificationNotObserved },
		func(r *ManifestFileResult) { r.Delivery.InstalledVerification = ManifestVerificationFailed }, func(r *ManifestFileResult) { r.Delivery.CandidateCleanup = ManifestCandidateRemoved },
		func(r *ManifestFileResult) {
			r.Delivery.Failure = &ManifestFileFailure{Stage: ManifestCloseStage, Reason: ManifestIOFailure}
		},
	} {
		bad := completeManifestFileResultFixture()
		change(&bad)
		if out, err := RenderManifestFileJSON(bad); err == nil || len(out) != 0 {
			t.Fatal("impossible success emitted", err)
		}
		bad.ResultDelivery = ManifestResultComplete
		if ManifestFileExitCode(bad) != 2 {
			t.Fatal("impossible success exit")
		}
	}
	r = completeManifestFileResultFixture()
	r.Delivery.NativeCompletion = ManifestNativeIncomplete
	r.Delivery.Failure = &ManifestFileFailure{Stage: ManifestCloseStage, Reason: ManifestIOFailure}
	if _, err := RenderManifestFileJSON(r); err != nil {
		t.Fatal("late close failure lost known replacement", err)
	}
}
