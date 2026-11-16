package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	genericjson "enkv.sh/plugins/manifest-generators/generic-json"
	manifest "enkv.sh/sdk/manifest-generator"
)

// full_only: false
func TestManifestPreparationPrecedesSelectedLoadingAndExcludesComparison(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	e, candidate, source := readerEngineFixture(t, env, f.session)
	calls := 0
	e.prepareManifestRenderer = func(got context.Context, selection contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
		calls++
		if selection != hermeticManifestRenderer() || got != ctx || len(candidate.calls) != 0 || source.reads != 0 {
			t.Fatal("preparation ran after selected loading or with another context")
		}
		return nil, manifest.InvalidInput
	}
	request := hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized})
	invalid := request
	invalid.TargetMode = "unknown"
	got := e.Manifest(ctx, contract.ID{1}, invalid)
	if calls != 0 || got.Artifact != nil || got.FailureReason != contract.ReasonInvalidInput {
		t.Fatal("invalid request reached preparation", calls, got)
	}
	got = e.Manifest(context.Background(), contract.ID{2}, request)
	if calls != 0 || got.Artifact != nil {
		t.Fatal("unbounded context reached preparation")
	}
	got = e.Manifest(ctx, contract.ID{}, request)
	if calls != 0 || got.Artifact != nil || got.FailureReason != contract.ReasonInvalidInput {
		t.Fatal("zero request ID reached preparation")
	}
	cancelled, stopCancelled := context.WithCancel(ctx)
	stopCancelled()
	got = e.Manifest(cancelled, contract.ID{6}, request)
	if calls != 0 || got.FailureReason != contract.ReasonCancelled {
		t.Fatal("cancelled request reached preparation")
	}
	expired, stopExpired := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer stopExpired()
	got = e.Manifest(expired, contract.ID{7}, request)
	if calls != 0 || got.FailureReason != contract.ReasonExpired {
		t.Fatal("expired request reached preparation")
	}
	got = e.Manifest(ctx, contract.ID{3}, request)
	if calls != 1 || len(candidate.calls) != 0 || source.reads != 0 || got.Artifact != nil || got.Payload != nil || got.Observation != nil || got.RequestScope == nil {
		t.Fatal("preparation refusal loaded state", calls, len(candidate.calls), source.reads, got)
	}
	input := comparisonCurrentInput(t, env, f.session)
	comparison := e.Compare(ctx, contract.ID{4}, input)
	if calls != 1 || comparison.StateResult != contract.ReaderSuccess || len(candidate.calls) == 0 || source.reads == 0 {
		t.Fatal("comparison depended on manifest preparation", calls, comparison)
	}
	e.Close()
	got = e.Manifest(ctx, contract.ID{5}, request)
	if calls != 1 || got.Artifact != nil {
		t.Fatal("closed Reader prepared renderer")
	}
}

// full_only: false
func TestManifestPreparationHasClosedReturnsAndRechecksOriginalAdmission(t *testing.T) {
	for _, condition := range []string{"complete", "nil-renderer", "unknown-failure", "renderer-with-failure", "cancelled", "expired-after-preparation", "invalid-input", "invalid-utf8", "limit-exceeded", "cancelled-failure", "expired-failure", "invalid-result"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, _ := genesisEnvironment(t, contract.GCP, false)
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			e, candidate, source := readerEngineFixture(t, env, f.session)
			if condition == "expired-after-preparation" {
				ctx, cancel = context.WithTimeout(t.Context(), time.Second)
				defer cancel()
			}
			originalDeadline, _ := ctx.Deadline()
			calls := 0
			e.prepareManifestRenderer = func(got context.Context, selection contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
				calls++
				if selection != hermeticManifestRenderer() || got != ctx || len(candidate.calls) != 0 || source.reads != 0 {
					t.Fatal("preparation order changed")
				}
				switch condition {
				case "nil-renderer":
					return nil, ""
				case "unknown-failure":
					return nil, "raw private error"
				case "renderer-with-failure":
					return genericjson.Render, manifest.InvalidInput
				case "cancelled":
					cancel()
				case "expired-after-preparation":
					deadline, finite := got.Deadline()
					if !finite || deadline != originalDeadline || got.Err() != nil {
						t.Fatal("preparation did not receive live original deadline")
					}
					<-got.Done()
					if got.Err() != context.DeadlineExceeded || time.Now().Before(originalDeadline) {
						t.Fatal("original deadline did not expire")
					}
				case "invalid-input":
					return nil, manifest.InvalidInput
				case "invalid-utf8":
					return nil, manifest.InvalidUTF8
				case "limit-exceeded":
					return nil, manifest.LimitExceeded
				case "cancelled-failure":
					return nil, manifest.Cancelled
				case "expired-failure":
					return nil, manifest.Expired
				case "invalid-result":
					return nil, manifest.InvalidResult
				}
				return genericjson.Render, ""
			}
			got := e.Manifest(ctx, contract.ID{1}, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized}))
			if calls != 1 {
				t.Fatal("preparation was repeated", calls)
			}
			if condition == "complete" {
				if got.StateResult != contract.ReaderSuccess || got.Payload == nil || len(got.Artifact) == 0 || len(candidate.calls) == 0 || source.reads == 0 {
					t.Fatal("prepared renderer failed", got)
				}
				clear(got.Artifact)
				return
			}
			want := contract.ReasonInvalidInput
			switch condition {
			case "cancelled", "cancelled-failure":
				want = contract.ReasonCancelled
			case "expired-after-preparation", "expired-failure":
				want = contract.ReasonExpired
			case "invalid-utf8":
				want = contract.ReasonInvalidUTF8
			case "limit-exceeded":
				want = contract.ReasonLimitExceeded
			}
			if got.Artifact != nil || got.Payload != nil || got.FailureReason != want || len(candidate.calls) != 0 || source.reads != 0 {
				t.Fatal("invalid preparation loaded state", got, len(candidate.calls), source.reads)
			}
		})
	}
}

// full_only: false
func TestManifestPreparationReceivesExactSelectedBuild(t *testing.T) {
	for _, condition := range []string{"fixture", "private-name", "new-build", "missing-build"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, _ := genesisEnvironment(t, contract.GCP, false)
			fixture := newEnvironmentFixture(t, ctx, env, nil, false)
			engine, candidate, source := readerEngineFixture(t, env, fixture.session)
			request := hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized})
			switch condition {
			case "private-name":
				request.Renderer.Name = "private-format"
				request.FormatContractID = "private/ini/v1"
				request.ConfigContractID = "private/settings/v1"
			case "new-build":
				request.Renderer.ArtifactSHA256[0]++
			case "missing-build":
				request.Renderer.ArtifactID = contract.ID{}
			}
			calls := 0
			engine.prepareManifestRenderer = func(got context.Context, selected contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
				calls++
				if selected != request.Renderer || got != ctx || len(candidate.calls) != 0 || source.reads != 0 {
					t.Fatal("build or preparation order differs")
				}
				return nil, manifest.InvalidInput
			}
			got := engine.Manifest(ctx, contract.ID{1}, request)
			wantCalls := 1
			if condition == "missing-build" {
				wantCalls = 0
				if got.FailureReason != contract.ReasonMissingRequiredField || got.RequestScope != nil {
					t.Fatal("missing build admitted")
				}
			} else if got.RequestScope == nil || got.RequestScope.Renderer != request.Renderer || got.RequestScope.FormatContractID != request.FormatContractID || got.RequestScope.ConfigContractID != request.ConfigContractID || string(got.RequestScope.Settings) != `{}` {
				t.Fatal("scope lost exact selected build or canonical settings")
			}
			if calls != wantCalls || len(candidate.calls) != 0 || source.reads != 0 || got.Payload != nil || got.Artifact != nil {
				t.Fatal("preparation refusal loaded selected data")
			}
		})
	}
}
