package compositionfull

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	gcpprovider "enkv.sh/providers/gcp"
)

type capacityHTTPFixture struct {
	t        *testing.T
	base     *readerHTTPFixture
	keys     []string
	obsolete contract.GCTarget
	lists    atomic.Int32
}

func (h *capacityHTTPFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a := h.base.archive
	list := a.Family == contract.AWS && r.URL.Query().Get("list-type") == "2" || a.Family == contract.GCP && r.URL.Path == "/storage/v1/b/"+a.Location.Bucket+"/o"
	if !list {
		h.base.ServeHTTP(w, r)
		return
	}
	wantPrefix := a.Location.PrefixBeforeHEAD + "/" + hex.EncodeToString(a.Domain[:]) + "/"
	if r.Method != http.MethodGet || r.Header.Get("Authorization") == "" || r.URL.Query().Get("prefix") != wantPrefix {
		h.base.mu.Lock()
		h.base.forbidden++
		h.base.mu.Unlock()
		http.Error(w, "forbidden raw-provider-sentinel", http.StatusForbidden)
		return
	}
	h.lists.Add(1)
	if a.Family == contract.AWS {
		w.Header().Set("Content-Type", "application/xml")
		if _, err := fmt.Fprintf(w, "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>%s</Name><Prefix>%s</Prefix><KeyCount>%d</KeyCount><MaxKeys>256</MaxKeys><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated>", html.EscapeString(a.Location.Bucket), html.EscapeString(wantPrefix), len(h.keys)); err != nil {
			h.t.Error("capacity fixture list header write failed", err)
			return
		}
		for _, key := range h.keys {
			if _, err := fmt.Fprintf(w, "<Contents><Key>%s</Key></Contents>", html.EscapeString(key)); err != nil {
				h.t.Error("capacity fixture list entry write failed", err)
				return
			}
		}
		if _, err := fmt.Fprint(w, "</ListBucketResult>"); err != nil {
			h.t.Error("capacity fixture list footer write failed", err)
			return
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
		items := make([]map[string]string, len(h.keys))
		for i, key := range h.keys {
			items[i] = map[string]string{"name": key}
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"items": items}); err != nil {
			h.t.Error("capacity fixture list response write failed", err)
			return
		}
	}
}

func configurationCapacityOpener(t *testing.T, source configurationReaderSource) (func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error), *capacityHTTPFixture) {
	t.Helper()
	object, ok := source.archive.Object(source.archive.Location.PrefixBeforeHEAD + "/HEAD")
	if !ok {
		t.Fatal("fixture HEAD absent")
	}
	head, err := format.DecodeHead(object.Body)
	if err != nil {
		t.Fatal(err)
	}
	root, err := format.Key(source.archive.Location.PrefixBeforeHEAD, head.Core.Root)
	if err != nil {
		t.Fatal(err)
	}
	rootObject, ok := source.archive.Object(root)
	if !ok {
		t.Fatal("selected root absent")
	}
	oldRoot, err := format.DecodeRoot(rootObject.Body)
	if err != nil {
		t.Fatal(err)
	}
	oldRoot.Snapshot = contract.Hash([]byte("capacity obsolete root fixture"))
	oldBody, err := format.EncodeRoot(oldRoot)
	if err != nil {
		t.Fatal(err)
	}
	identity := contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RootKind, ObjectID: oldRoot.Snapshot}
	oldKey, err := contract.StoreObjectKey(source.archive.Location.PrefixBeforeHEAD, source.archive.Domain, identity)
	if err != nil {
		t.Fatal(err)
	}
	oldToken := contract.Token{Family: source.archive.Family, Value: `"private-condition-sentinel"`}
	if source.archive.Family == contract.GCP {
		oldToken.Value = "987654321"
	}
	oldObject := rootObject
	oldObject.Key, oldObject.Body, oldObject.Token = oldKey, oldBody, oldToken
	archive := source.archive
	archive.Objects = append(archive.Objects, oldObject)
	foreign := source.archive.Location.PrefixBeforeHEAD + "/" + hex.EncodeToString(source.archive.Domain[:]) + "/raw-foreign-key-sentinel"
	h := &capacityHTTPFixture{t: t, base: &readerHTTPFixture{archive: archive, reads: make(map[string]int)}, keys: []string{root, foreign, oldKey}, obsolete: contract.GCTarget{Object: identity, Length: uint32(len(oldBody)), Digest: contract.Hash(oldBody), Token: oldToken}}
	transport, stop := readerHTTPTransport(t, h, []string{"s3.us-east-1.amazonaws.com", "storage.australia-southeast1.rep.googleapis.com"})
	t.Cleanup(stop)
	return func(ctx context.Context, c CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
		if c.AWS != nil {
			c.AWS.Candidate.Credentials = readerFixtureCredentials{}
			c.AWS.Candidate.Transport = transport
		} else {
			client, err := gcpprovider.NewLocalResponderClient(transport, readerFixtureCredentials{})
			if err != nil {
				return nil, err
			}
			c.GCP.Candidate.Client = client
		}
		return NewCapacityReader(ctx, c)
	}, h
}

// full_only: false
func TestConfigurationCapacityAndGCPlanUseSeparateBoundedPublicReach(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, syntax := range []configuration.Format{configuration.JSON, configuration.YAML} {
			t.Run(fmt.Sprintf("%s/%d", family, syntax), func(t *testing.T) {
				t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
				t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
				source := configurationReaderPair(t, family, syntax, nil)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				open, h := configurationCapacityOpener(t, source)
				capacity := inspectConfigurationCapacity(ctx, core.CapacityInspectionRequest{RequestNonce: contract.ID{31}}, source.pair, open)
				if capacity.StateResult != core.PublicQuerySuccess || capacity.Validate() != nil || capacity.View == nil || len(capacity.View.Encoded.Objects) == 0 || len(capacity.View.Garbage.Candidates) != 3 || h.lists.Load() != 1 {
					t.Fatal("complete installed capacity observation", capacity.PublicQueryResult)
				}
				if capacity.View.Garbage.Candidates[0].Classification != contract.GCCandidateProtected || capacity.View.Garbage.Candidates[1].Classification != contract.GCCandidateUnverifiable || capacity.View.Garbage.Candidates[1].KeyDigest != (contract.ID{}) || capacity.View.Garbage.Candidates[1].Reason != contract.GCReasonUnknownKind || capacity.View.Garbage.Candidates[2].Classification != contract.GCCandidateEligible || len(capacity.View.Garbage.EligibleTargets) != 1 || capacity.View.Garbage.EligibleTargets[0] != h.obsolete {
					t.Fatal("candidate page lost complete classifications/eligible target")
				}
				path := filepath.Join(protectedConfigurationTestDirectory(t), "plan.bin")
				planned := planConfigurationGC(ctx, GCPlanRequest{RequestNonce: contract.ID{32}, OperationID: contract.ID{33}, ArtifactPath: path}, source.pair, open, nativeAbandonPlanIO())
				if planned.Operation.StateResult != core.PublicQuerySuccess || planned.Operation.Validate() != nil || !planned.Delivery.PlanReadback || planned.Delivery.PlanFailed || h.lists.Load() != 2 {
					t.Fatal("protected complete preview delivery", planned.Operation.PublicQueryResult, planned.Delivery)
				}
				body, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(body, planned.Operation.Payload.EncodedPlan) {
					t.Fatal("artifact is not the exact canonical plan", err)
				}
				c, pins, err := configurationPublicQueryInput(ctx, contract.ID{34}, source.pair)
				if err != nil {
					t.Fatal(err)
				}
				domain, store := capacityReaderScope(c)
				var publicBasis core.PublicBasis
				if c.AWS != nil {
					publicBasis = c.AWS.PublicBasis
				} else {
					publicBasis = c.GCP.PublicBasis
				}
				read, err := readGCPlan(ctx, path, domain, store, publicBasis, pins)
				if err != nil || !bytes.Equal(read, body) {
					t.Fatal("canonical plan scope/readback", err)
				}
				if _, err := readGCPlan(ctx, path, contract.ID{99}, store, publicBasis, pins); err == nil {
					t.Fatal("foreign domain plan admitted")
				}
				if err := source.pair.Close(); err != nil {
					t.Fatal(err)
				}
				for _, human := range []bool{false, true} {
					var output bytes.Buffer
					if human {
						err = capacity.WriteHuman(ctx, &output)
					} else {
						err = capacity.WriteJSON(ctx, &output)
					}
					capacityHeading := "CapacityPayload/v1"
					if human {
						capacityHeading = "Capacity inspection: success\n"
					}
					if err != nil || !bytes.Contains(output.Bytes(), []byte(capacityHeading)) || !bytes.Contains(output.Bytes(), []byte("one-page-no-snapshot")) {
						t.Fatal("owned capacity result after source close", err)
					}
					if !human {
						assertCapacityResultFields(t, output.Bytes(), capacity.PublicCapacityInspectionResult, h.obsolete)
					} else {
						for _, row := range capacity.View.Garbage.Candidates {
							// Digests retain all 32 bytes, including the undisclosed zero digest
							// of an unverifiable key; optional identity formatting is different.
							want := fmt.Sprintf("Key digest: %q", hex.EncodeToString(row.KeyDigest[:]))
							if !bytes.Contains(output.Bytes(), []byte(want)) {
								var shown []string
								remaining := output.Bytes()
								for len(shown) < 3 {
									at := bytes.Index(remaining, []byte("Key digest: "))
									if at < 0 {
										break
									}
									remaining = remaining[at:]
									end := bytes.IndexByte(remaining, '\n')
									if end < 0 || end > 96 {
										end = min(len(remaining), 96)
									}
									shown = append(shown, string(remaining[:end]))
									remaining = remaining[end:]
								}
								t.Fatalf("human capacity candidate digest missing: classification=%d reason=%d want=%q shown=%q", row.Classification, row.Reason, want, shown)
							}
						}
						if !bytes.Contains(output.Bytes(), []byte("Counts: "+strconv.Itoa(len(capacity.View.Counts))+" rows")) || !bytes.Contains(output.Bytes(), []byte("Candidates: 3 rows")) || !bytes.Contains(output.Bytes(), []byte("Eligible targets: 1 rows")) {
							t.Fatal("human capacity omitted query rows")
						}
					}
					output.Reset()
					if human {
						err = WriteGCPlanHuman(ctx, &output, planned)
					} else {
						err = WriteGCPlanJSON(ctx, &output, planned)
					}
					planHeading := "CleanupPayload/v1"
					if human {
						planHeading = "GC plan: success\n"
					}
					if err != nil || !bytes.Contains(output.Bytes(), []byte(planHeading)) || bytes.Contains(output.Bytes(), []byte("raw-foreign-key-sentinel")) || bytes.Contains(output.Bytes(), []byte("raw-provider-sentinel")) || bytes.Contains(output.Bytes(), []byte("private-condition-sentinel")) {
						t.Fatal("safe complete preview result after close", err)
					}
					if human {
						for _, want := range []string{"Plan file created: true", "Plan file synced: true", "Plan file read back: true", "Plan delivery failed: false", "The plan is a preview; no delete permission is selected.", "No remote objects were deleted.", "Candidates: 3 rows", "Eligible targets: 1 rows"} {
							if !bytes.Contains(output.Bytes(), []byte(want)) {
								t.Fatal("human GC plan omitted delivery or query fact", want)
							}
						}
					}
				}
				bad := capacity
				view := *capacity.View
				bad.View = &view
				bad.View.Garbage.MarkDigest[0] ^= 1
				var rejected bytes.Buffer
				if bad.WriteJSON(ctx, &rejected) == nil || rejected.Len() != 0 {
					t.Fatal("late candidate damage crossed result preflight")
				}
				if err := capacity.WriteJSON(ctx, &publicQueryDeliveryWriter{short: true}); err == nil {
					t.Fatal("capacity result swallowed short write")
				}
				if err := WriteGCPlanJSON(ctx, &publicQueryDeliveryWriter{short: true}, planned); err == nil {
					t.Fatal("preview result swallowed short write")
				}
				h.base.assertNoEffects(t)
				source.assertUnchanged(t)
			})
		}
	}
}

func assertCapacityResultFields(t *testing.T, body []byte, result core.PublicCapacityInspectionResult, target contract.GCTarget) {
	t.Helper()
	type group struct {
		Index  int    `json:"group"`
		Count  uint64 `json:"max_count"`
		Framed uint64 `json:"max_framed_bytes"`
		Pages  uint32 `json:"max_pages"`
	}
	type bound struct {
		Scope  string
		Status string
		Basis  string `json:"basis_digest"`
		Groups []group
	}
	var document struct {
		Payload struct {
			Continuation struct {
				Remaining bound
				FirstExit bound `json:"first_exit"`
			}
			Encoded struct {
				Objects []struct {
					Object        string `json:"object_id"`
					Used          uint64 `json:"encoded_bytes"`
					Limit, Margin uint64
				}
			}
			Garbage struct {
				Candidates []struct {
					Class string `json:"classification"`
					Index uint16 `json:"target_index"`
				}
				Targets  struct{ Count uint32 }
				Eligible []struct {
					Object string `json:"object_id"`
					Length uint32
					Digest string
				} `json:"eligible_targets"`
			}
		}
	}
	if json.Unmarshal(body, &document) != nil {
		t.Fatal("capacity output is not complete JSON")
	}
	p := document.Payload
	if p.Continuation.Remaining.Scope != "remaining-selected-continuations" || p.Continuation.FirstExit.Scope != "sufficient-first-administrative-exit" || p.Continuation.Remaining.Status != result.View.Continuation.Remaining.Status || p.Continuation.FirstExit.Status != result.View.Continuation.FirstExit.Status {
		t.Fatal("capacity bound scopes/status omitted")
	}
	for _, pair := range []struct {
		got  bound
		want core.CapacityContinuationBound
	}{{p.Continuation.Remaining, result.View.Continuation.Remaining}, {p.Continuation.FirstExit, result.View.Continuation.FirstExit}} {
		if pair.got.Basis != readerID(pair.want.BasisDigest) || len(pair.got.Groups) != contract.GeneratorCapacityGroupCount {
			t.Fatal("capacity bound basis/group vector omitted")
		}
		for i, g := range pair.got.Groups {
			w := pair.want.Groups[i]
			if g.Index != i || g.Count != w.MaxCount || g.Framed != w.MaxFramedBytes || g.Pages != w.MaxPages {
				t.Fatal("capacity group value changed", i)
			}
		}
	}
	if len(p.Encoded.Objects) != len(result.View.Encoded.Objects) {
		t.Fatal("per-object margins omitted")
	}
	for i, o := range p.Encoded.Objects {
		w := result.View.Encoded.Objects[i]
		if o.Object != readerID(w.ObjectID) || o.Used != w.EncodedBytes || o.Limit != w.Limit || o.Used > o.Limit || o.Margin != o.Limit-o.Used {
			t.Fatal("per-object encoded margin changed", i)
		}
	}
	if len(p.Garbage.Candidates) != 3 || p.Garbage.Candidates[0].Class != "protected" || p.Garbage.Candidates[1].Class != "unverifiable" || p.Garbage.Candidates[2].Class != "eligible" || p.Garbage.Candidates[2].Index != 0 || p.Garbage.Targets.Count != 1 || len(p.Garbage.Eligible) != 1 {
		t.Fatal("candidate/eligible vector omitted")
	}
	v := p.Garbage.Eligible[0]
	if v.Object != readerID(target.Object.ObjectID) || v.Length != target.Length || v.Digest != readerID(target.Digest) {
		t.Fatal("eligible physical identity/byte commitment changed")
	}
}

// full_only: false
func TestConfigurationCapacityRejectsCursorAndGCOutputBeforeCredentials(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	c, _, err := configurationPublicQueryInput(ctx, contract.ID{1}, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	domain, store := capacityReaderScope(c)
	wrong, err := core.EncodeGCCursor("page", contract.ID{99}, store)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := core.EncodeGCCursor("page", domain, store)
	if err != nil {
		t.Fatal(err)
	}
	opened := 0
	open := func(context.Context, CapacityReaderConfig) (*core.InstalledCapacityReader, error) {
		opened++
		return nil, nil
	}
	for _, cursor := range []string{"malformed", wrong, valid + "=", strings.Repeat("x", core.GCCursorMaxLength+1)} {
		got := inspectConfigurationCapacity(ctx, core.CapacityInspectionRequest{RequestNonce: contract.ID{2}, Cursor: cursor}, source.pair, open)
		if got.StateResult != core.PublicQueryRefused || got.View != nil || got.Validate() != nil {
			t.Fatal("cursor refusal lost closed result", got.PublicQueryResult)
		}
		plan := planConfigurationGC(ctx, GCPlanRequest{RequestNonce: contract.ID{3}, OperationID: contract.ID{4}, Cursor: cursor, ArtifactPath: "/unused-plan.bin"}, source.pair, open, nativeAbandonPlanIO())
		if plan.Operation.StateResult != core.PublicQueryRefused || plan.Operation.Payload != nil || plan.Operation.Validate() != nil {
			t.Fatal("preview admitted malformed/wrong-scope cursor")
		}
	}
	for _, path := range []string{source.path, source.generated, "relative.bin"} {
		got := planConfigurationGC(ctx, GCPlanRequest{RequestNonce: contract.ID{5}, OperationID: contract.ID{6}, ArtifactPath: path}, source.pair, open, nativeAbandonPlanIO())
		if got.Operation.StateResult != core.PublicQueryRefused || got.Operation.Payload != nil {
			t.Fatal("source/output alias admitted")
		}
	}
	if opened != 0 {
		t.Fatal("invalid local request reached credential construction", opened)
	}
	source.assertUnchanged(t)
}
