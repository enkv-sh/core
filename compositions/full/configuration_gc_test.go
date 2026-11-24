package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestConfigurationGCOperationalFailureDoesNotInventCleanupFailure(t *testing.T) {
	for _, failedClose := range []bool{false, true} {
		t.Run(fmt.Sprint(failedClose), func(t *testing.T) {
			source := configurationReaderPair(t, "aws", configuration.JSON, nil)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			open, h := configurationCapacityOpener(t, source)
			path := filepath.Join(protectedConfigurationTestDirectory(t), "plan.bin")
			preview := planConfigurationGC(ctx, GCPlanRequest{RequestNonce: contract.ID{71}, OperationID: contract.ID{72}, ArtifactPath: path}, source.pair, open, nativeAbandonPlanIO())
			if preview.Operation.Payload == nil || !preview.Delivery.PlanReadback || len(preview.Operation.Payload.Plan.Targets) != 1 {
				t.Fatal("actual eligible GC preview missing", preview.Operation.PublicQueryResult)
			}
			factories, closes := 0, 0
			out := applyConfigurationGC(ctx, GCApplyRequest{RequestNonce: contract.ID{73}, PlanPath: path}, source.pair, open, func(context.Context, *configuration.Model, abandonmentSource) (core.GCMutationResources, error) {
				factories++
				return core.GCMutationResources{Close: func() error {
					closes++
					if failedClose {
						return errors.New("private cleanup failure")
					}
					return nil
				}}, errors.New("private construction failure")
			})
			if factories != 1 || closes != 1 || out.Operation.Result.Outcome != core.AdmissionRefused || out.Operation.StateResult != "refused" || out.Delivery.CleanupFailed != failedClose {
				t.Fatal("operational refusal acquired a false cleanup fact", factories, closes, out.Operation.Result, out.Delivery)
			}
			var body bytes.Buffer
			if err := WriteGCApplyJSON(ctx, &body, out); err != nil || bytes.Contains(body.Bytes(), []byte("private construction")) || bytes.Contains(body.Bytes(), []byte("private cleanup")) {
				t.Fatal("safe result lost refusal or exposed raw cause", err)
			}
			h.base.assertNoEffects(t)
			source.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestConfigurationGCEmptyPlanAndAbsentContinuationNeverConstructMutation(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
			t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
			source := configurationReaderPair(t, family, configuration.JSON, nil)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			open, h := configurationCapacityOpener(t, source)
			h.keys = h.keys[:2]
			path := filepath.Join(protectedConfigurationTestDirectory(t), "empty.bin")
			preview := planConfigurationGC(ctx, GCPlanRequest{RequestNonce: contract.ID{51}, OperationID: contract.ID{52}, ArtifactPath: path}, source.pair, open, nativeAbandonPlanIO())
			if preview.Operation.Payload == nil || !preview.Delivery.PlanReadback || len(preview.Operation.Payload.Plan.Targets) != 0 {
				t.Fatal("actual empty preview fixture", preview.Operation.PublicQueryResult)
			}
			factories := 0
			mutation := func(context.Context, *configuration.Model, abandonmentSource) (core.GCMutationResources, error) {
				factories++
				return core.GCMutationResources{}, errors.New("private-factory-sentinel")
			}
			var identities [2]contract.ID
			for i, nonce := range []contract.ID{{53}, {55}} {
				applied := applyConfigurationGC(ctx, GCApplyRequest{RequestNonce: nonce, PlanPath: path}, source.pair, open, mutation)
				if applied.Operation.Validate() != nil || applied.Operation.StateResult != "no-op" || applied.Delivery.CleanupFailed || factories != 0 || h.lists.Load() != 1 {
					t.Fatal("empty apply constructed signing, listed again, or lost no-op", applied.Operation.StateResult, factories, h.lists.Load())
				}
				p := applied.Operation.Payload
				if p == nil || p.PlanDigest != preview.Operation.Payload.PlanDigest || p.RequestIdentity != preview.Operation.Payload.RequestIdentity || applied.Operation.RequestID != nonce || applied.Operation.OperationID != preview.Operation.Payload.Plan.OperationID {
					t.Fatal("fresh observation changed the immutable plan commitments")
				}
				identities[i] = applied.Operation.RequestIdentity
				var body bytes.Buffer
				if err := WriteGCApplyJSON(ctx, &body, applied); err != nil {
					t.Fatal("empty observation rendering", err)
				}
				var record struct {
					Identity string `json:"request_identity"`
					Replay   string `json:"replay_identity"`
					Payload  struct {
						Identity string `json:"request_identity"`
						Plan     string `json:"plan_digest"`
					} `json:"payload"`
				}
				if json.Unmarshal(body.Bytes(), &record) != nil || record.Identity != readerID(identities[i]) || record.Replay != "none" || record.Payload.Identity != readerID(p.RequestIdentity) || record.Payload.Plan != readerID(p.PlanDigest) {
					t.Fatal("renderer lost observation identity or original plan commitments", body.String())
				}
			}
			if identities[0] == identities[1] || identities[0] == preview.Operation.Payload.RequestIdentity || identities[1] == preview.Operation.Payload.RequestIdentity {
				t.Fatal("fresh empty observations reused the immutable preview request identity")
			}
			continued := applyConfigurationGC(ctx, GCApplyRequest{RequestNonce: contract.ID{54}, OperationID: contract.ID{52}}, source.pair, open, mutation)
			if continued.Operation.Validate() != nil || continued.Operation.StateResult == "success" || continued.Operation.Payload != nil || factories != 0 || h.lists.Load() != 1 {
				t.Fatal("absent continuation fabricated historical success or mutation", continued.Operation.StateResult)
			}
			h.base.assertNoEffects(t)
			source.assertUnchanged(t)
		})
	}
}

// full_only: false
func TestConfigurationGCRejectsArtifactBeforeCredentialsAndSignsLazily(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	open, h := configurationCapacityOpener(t, source)
	dir := protectedConfigurationTestDirectory(t)
	preview := planConfigurationGC(ctx, GCPlanRequest{RequestNonce: contract.ID{61}, OperationID: contract.ID{62}, ArtifactPath: filepath.Join(dir, "original.bin")}, source.pair, open, nativeAbandonPlanIO())
	if preview.Operation.Payload == nil || !preview.Delivery.PlanReadback || len(preview.Operation.Payload.Plan.Targets) != 1 {
		t.Fatal("actual eligible preview fixture", preview.Operation.PublicQueryResult)
	}
	opened, factories, closed := 0, 0, 0
	countedOpen := func(ctx context.Context, c CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
		opened++
		return open(ctx, c)
	}
	failure := errors.New("private-construction-sentinel")
	mutation := func(context.Context, *configuration.Model, abandonmentSource) (core.GCMutationResources, error) {
		factories++
		return core.GCMutationResources{Close: func() error { closed++; return failure }}, failure
	}
	for _, damage := range []string{"truncated", "oversized", "wrong-domain"} {
		body := append([]byte{}, preview.Operation.Payload.EncodedPlan...)
		switch damage {
		case "truncated":
			body = body[:len(body)-1]
		case "oversized":
			body = make([]byte, contract.GCPlanMaxLength+1)
		case "wrong-domain":
			p := preview.Operation.Payload.Plan
			p.DomainID = contract.ID{99}
			var err error
			body, err = contract.EncodeGCPlan(p)
			if err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(dir, damage+".bin")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		r := applyConfigurationGC(ctx, GCApplyRequest{RequestNonce: contract.ID{63}, PlanPath: path}, source.pair, countedOpen, mutation)
		if r.Operation.Validate() != nil || r.Operation.StateResult != "refused" || opened != 0 || factories != 0 {
			t.Fatal("artifact reached credentials or signing", damage, r.Operation.StateResult, opened, factories)
		}
	}
	for _, damage := range []string{"head", "target"} {
		p := preview.Operation.Payload.Plan
		p.Targets = append([]contract.GCTarget{}, p.Targets...)
		if damage == "head" {
			p.HeadRevisionID = contract.ID{98}
		} else {
			p.Targets[0].Length++
			d, err := contract.GCTargetsDescriptor(p.Targets)
			if err != nil {
				t.Fatal(err)
			}
			p.TargetsDigest = d.Digest
		}
		body, err := contract.EncodeGCPlan(p)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, damage+".bin")
		if os.WriteFile(path, body, 0600) != nil {
			t.Fatal("stale artifact fixture")
		}
		r := applyConfigurationGC(ctx, GCApplyRequest{RequestNonce: contract.ID{64}, PlanPath: path}, source.pair, countedOpen, mutation)
		if r.Operation.Validate() != nil || r.Operation.StateResult == "success" || r.Operation.StateResult == "no-op" || factories != 0 || h.lists.Load() != 1 {
			t.Fatal("public preflight did not precede private reach", damage, r.Operation.StateResult, factories)
		}
	}
	r := applyConfigurationGC(ctx, GCApplyRequest{RequestNonce: contract.ID{65}, PlanPath: filepath.Join(dir, "original.bin")}, source.pair, countedOpen, mutation)
	if r.Operation.Validate() != nil || factories != 1 || closed != 1 || !r.Delivery.CleanupFailed || r.Operation.StateResult != "refused" || h.lists.Load() != 1 {
		t.Fatal("lazy factory cleanup or operation result lost", factories, closed, r.Operation.StateResult, r.Delivery)
	}
	h.base.assertNoEffects(t)
	source.assertUnchanged(t)
}

// full_only: false
func TestConfigurationGCRecognizedRefusalsRetainPreAdmissionIdentity(t *testing.T) {
	seen := make(map[contract.ID]bool)
	for _, seam := range []string{"bound-factory-control", "raw-artifact", "reader-construction", "absent-owner", "recognized-parser"} {
		t.Run(seam, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			format := configuration.JSON
			if seam == "reader-construction" {
				format = configuration.YAML
			}
			nonce := contract.Hash([]byte("GC pre-admission " + seam))
			stage, code, state := "declaration", string(contract.ReasonInvalidInput), "refused"
			var result GCApplyResult
			if seam == "recognized-parser" {
				nonce = contract.ID{}
				stage = "dispatch"
				var err error
				result, err = NewGCApplyRefusal(format)
				if err != nil {
					t.Fatal("recognized parser refusal fixture", err)
				}
			} else {
				source := configurationReaderPair(t, "aws", format, nil)
				defer source.assertUnchanged(t)
				opened, factories := 0, 0
				open := func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
					opened++
					return nil, errors.New("private-envelope-sentinel")
				}
				mutation := func(context.Context, *configuration.Model, abandonmentSource) (core.GCMutationResources, error) {
					factories++
					return core.GCMutationResources{Close: func() error { return nil }}, errors.New("private-envelope-sentinel")
				}
				request := GCApplyRequest{RequestNonce: nonce, OperationID: contract.ID{81}}
				var server *capacityHTTPFixture
				var preview GCPlanResult
				switch seam {
				case "raw-artifact":
					request.OperationID = contract.ID{}
					request.PlanPath = filepath.Join(protectedConfigurationTestDirectory(t), "private-envelope-sentinel.bin")
					if err := os.WriteFile(request.PlanPath, []byte("not a canonical GC plan"), 0600); err != nil {
						t.Fatal(err)
					}
				case "reader-construction":
					stage, code, state = "construction", string(contract.ReasonEvidenceUnavailable), "unavailable"
				case "absent-owner", "bound-factory-control":
					stage = "observation"
					installed, h := configurationCapacityOpener(t, source)
					server = h
					open = func(ctx context.Context, c CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
						opened++
						return installed(ctx, c)
					}
					if seam == "bound-factory-control" {
						path := filepath.Join(protectedConfigurationTestDirectory(t), "bound.bin")
						preview = planConfigurationGC(ctx, GCPlanRequest{RequestNonce: contract.ID{82}, OperationID: contract.ID{83}, ArtifactPath: path}, source.pair, installed, nativeAbandonPlanIO())
						if preview.Operation.Payload == nil || !preview.Delivery.PlanReadback || len(preview.Operation.Payload.Plan.Targets) != 1 {
							t.Fatal("authentic bound-plan control", preview.Operation.PublicQueryResult)
						}
						request.OperationID, request.PlanPath = contract.ID{}, path
					}
				}
				result = applyConfigurationGC(ctx, request, source.pair, open, mutation)
				if server != nil {
					server.base.assertNoEffects(t)
					wantLists := int32(0)
					if seam == "bound-factory-control" {
						wantLists = 1
					}
					if server.lists.Load() != wantLists || server.base.count(source.archive.Location.PrefixBeforeHEAD+"/HEAD") == 0 {
						t.Fatal("public-load seam did not read or acquired unexpected LIST")
					}
				}
				wantOpen := 1
				if seam == "raw-artifact" {
					wantOpen = 0
				}
				if opened != wantOpen || factories != 0 && seam != "bound-factory-control" {
					t.Fatal("recognized refusal reached forbidden construction", opened, factories)
				}
				if seam == "bound-factory-control" {
					p := preview.Operation.Payload
					if factories != 1 || result.Operation.OperationID != p.Plan.OperationID || result.Operation.RequestIdentity != p.RequestIdentity || result.Operation.Payload == nil || result.Operation.Payload.PlanDigest != p.PlanDigest {
						t.Fatal("bound factory refusal lost original plan identity/payload")
					}
					var body bytes.Buffer
					if err := WriteGCApplyJSON(ctx, &body, result); err != nil {
						t.Fatal("bound control rendering", err)
					}
					var record map[string]json.RawMessage
					var identity, operation, replay string
					if json.Unmarshal(body.Bytes(), &record) != nil || json.Unmarshal(record["request_identity"], &identity) != nil || json.Unmarshal(record["operation_id"], &operation) != nil || json.Unmarshal(record["replay_identity"], &replay) != nil || identity != readerID(p.RequestIdentity) || operation != readerID(p.Plan.OperationID) || replay != identity || bytes.Equal(record["payload"], []byte("null")) {
						t.Fatal("bound operation was overlaid by local refusal metadata")
					}
					return
				}
			}
			if result.Operation.StateResult != state {
				t.Errorf("recognized refusal changed its expected state: got %s want %s", result.Operation.StateResult, state)
			}
			if result.Operation.RequestID != nonce || !result.Operation.RequestIdentity.IsZero() || result.Operation.Payload != nil || result.Operation.Result.CommitMayHaveOccurred {
				t.Fatal("pre-admission seam acquired bound identity/payload/rights")
			}
			if result.Operation.OperationID.IsZero() {
				t.Error("recognized GC refusal has no fresh local OperationID")
			} else if seen[result.Operation.OperationID] {
				t.Error("independent recognized requests reused a local OperationID")
			} else {
				seen[result.Operation.OperationID] = true
			}
			for _, human := range []bool{false, true} {
				var body bytes.Buffer
				var err error
				if human {
					err = WriteGCApplyHuman(ctx, &body, result)
				} else {
					err = WriteGCApplyJSON(ctx, &body, result)
				}
				if err != nil {
					t.Errorf("recognized refusal did not render: %v", err)
					continue
				}
				data := body.Bytes()
				if human {
					if !bytes.Contains(data, []byte(core.GCApplyOperation+": "+state+"\n")) ||
						!bytes.Contains(data, []byte("Operation: "+readerID(result.Operation.OperationID)+".\n")) ||
						!bytes.Contains(data, []byte("Admission: "+stage+" / "+code+".\n")) ||
						bytes.Contains(data, []byte("private-envelope-sentinel")) {
						t.Error("human GC result lost the refusal identity or disclosed private input")
					}
					continue
				}
				var record map[string]json.RawMessage
				if json.Unmarshal(data, &record) != nil {
					t.Fatal("recognized refusal is not a complete record")
				}
				var operation, local, replay, payloadKind string
				if json.Unmarshal(record["operation_kind"], &operation) != nil || json.Unmarshal(record["operation_id"], &local) != nil || json.Unmarshal(record["replay_identity"], &replay) != nil || json.Unmarshal(record["operation_payload"], &payloadKind) != nil || operation != core.GCApplyOperation || local != readerID(result.Operation.OperationID) || replay != "none" || payloadKind != "none" || !bytes.Equal(record["payload"], []byte("null")) || bytes.Contains(data, []byte("private-envelope-sentinel")) {
					t.Error("recognized refusal envelope claims missing facts or loses its one local ID")
				}
				var identity map[string]json.RawMessage
				if json.Unmarshal(record["request_identity"], &identity) != nil {
					t.Error("recognized GC refusal lacks PreAdmissionRequestIdentity/v1 object")
					continue
				}
				var q preAdmissionIdentityRecord
				if json.Unmarshal(record["request_identity"], &q) != nil || q.Schema != "PreAdmissionRequestIdentity/v1" || q.OperationID != local || q.OperationKind != core.GCApplyOperation || q.SourceSchema != "enkv/configuration/v3" || q.SourceProfile != "direct-candidate" || q.Format != configurationSourceFormat(format) || q.Stage != stage || q.Code != code || q.RequestNonce != readerID(nonce) {
					t.Error("recognized GC refusal lost exact schema/profile/format/stage/code/nonce")
				}
				for _, field := range []string{"predecessor", "predecessor_digest", "predecessor_revision_id", "selection", "authority_subject", "retry_right"} {
					if _, exists := identity[field]; exists {
						t.Errorf("pre-admission identity grants unavailable %s", field)
					}
				}
			}
		})
	}
}
