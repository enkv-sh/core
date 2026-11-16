package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type abandonProcessInput struct {
	Family, Source, Objects, Reply, Label string
	Args                                  []string
	Cut                                   string
}
type abandonProcessReply struct {
	Code, Reads, Forbidden, Creates, CAS, Signs int
	Output, Diagnostic                          []byte
}

func abandonCLIProcessChild(t *testing.T, path string) {
	body, err := os.ReadFile(path)
	var in abandonProcessInput
	if err != nil || json.Unmarshal(body, &in) != nil {
		t.Fatal("child input unavailable", err)
	}
	fixture := installedarchive.LoadAdministrative(t, in.Family)
	var objects []testtrust.AdministrativeReadObject
	body, err = os.ReadFile(in.Objects)
	if err != nil || json.Unmarshal(body, &objects) != nil {
		t.Fatal("child Store image unavailable", err)
	}
	var basis struct {
		Descriptor []byte `json:"descriptor"`
	}
	if json.Unmarshal(fixture.Basis, &basis) != nil {
		t.Fatal("child basis unavailable")
	}
	d, err := contract.DecodeGenesisDescriptorCore(basis.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	testtrust.AdministrativeNativeCredentials(t, filepath.Dir(in.Source), in.Family, in.Label)
	h, transport := testtrust.NewAdministrativeMutationHTTP(t, fixture.Before.Archive.Location, objects, d.NormalSigning)
	if in.Cut == "lost-cas-reply" {
		h.DropNextCASReply()
	} else if in.Cut != "" {
		headKey := fixture.Before.Archive.Location.PrefixBeforeHEAD + "/HEAD"
		var headBody []byte
		for _, o := range objects {
			if o.Key == headKey {
				headBody = o.Body
			}
		}
		head, err := format.DecodeHead(headBody)
		if err != nil {
			t.Fatal(err)
		}
		key, err := format.Key(fixture.Before.Archive.Location.PrefixBeforeHEAD, head.Core.Root)
		if err != nil {
			t.Fatal(err)
		}
		h.Fail(in.Cut, key)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	execute := func(ctx context.Context, nonce contract.ID, path string, format configuration.Format, q compositionfull.AbandonmentRequest) compositionfull.AbandonmentResult {
		return compositionfull.AbandonAdministrativeLocalFixture(ctx, nonce, path, format, q, transport)
	}
	var output, diagnostic bytes.Buffer
	code := runAbandonWithExecutor(ctx, in.Args, &output, &diagnostic, execute)
	reads, forbidden, _ := h.Counts()
	creates, cas, signs := h.MutationCounts()
	body, err = json.Marshal(h.Objects())
	if err != nil || os.WriteFile(in.Objects, body, 0600) != nil {
		t.Fatal("child Store image delivery failed", err)
	}
	reply := abandonProcessReply{code, reads, forbidden, creates, cas, signs, output.Bytes(), diagnostic.Bytes()}
	body, err = json.Marshal(reply)
	if err != nil || os.WriteFile(in.Reply, body, 0600) != nil {
		t.Fatal("child result delivery failed", err)
	}
}
func abandonCLIProcess(t *testing.T, in abandonProcessInput) abandonProcessReply {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input := in.Reply + ".input"
	body, err := json.Marshal(in)
	if err != nil || os.WriteFile(input, body, 0600) != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, binary, "-test.run=^TestAbandonmentCLIUsesFreshNativeProcesses$")
	child.Env = append(os.Environ(), "ENKV_ABANDON_CLI_CHILD="+input)
	capture := boundedCommandOutput{limit: 16 << 10}
	child.Stdout, child.Stderr = &capture, &capture
	if err := child.Run(); err != nil || ctx.Err() != nil || capture.overflow {
		log := in.Reply + ".private.log"
		if writeErr := os.WriteFile(log, capture.Bytes(), 0600); writeErr != nil {
			t.Fatal("native CLI child did not join and diagnostic delivery failed", err, writeErr)
		}
		t.Fatal("native CLI child did not join; private diagnostic", log, err, ctx.Err())
	}
	body, err = os.ReadFile(in.Reply)
	var reply abandonProcessReply
	if err != nil || json.Unmarshal(body, &reply) != nil {
		t.Fatal("native CLI reply unavailable", err)
	}
	return reply
}

// full_only: false
func TestAbandonmentCLIUsesFreshNativeProcesses(t *testing.T) {
	if path := os.Getenv("ENKV_ABANDON_CLI_CHILD"); path != "" {
		abandonCLIProcessChild(t, path)
		return
	}
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			fixture := installedarchive.LoadAdministrative(t, family)
			dir := decisionFixtureDirectory(t)
			source := compositionfull.WriteAdministrativeFixtureSource(t, fixture, dir)
			objects := make([]testtrust.AdministrativeReadObject, len(fixture.Before.Archive.Objects))
			for i, o := range fixture.Before.Archive.Objects {
				objects[i] = testtrust.AdministrativeReadObject{Key: o.Key, Token: o.Token, Body: bytes.Clone(o.Body)}
			}
			state := filepath.Join(dir, "store.json")
			body, err := json.Marshal(objects)
			if err != nil || os.WriteFile(state, body, 0600) != nil {
				t.Fatal(err)
			}
			step := 0
			invoke := func(label string, args ...string) abandonProcessReply {
				t.Helper()
				step++
				reply := filepath.Join(dir, "reply-"+string(rune('a'+step))+".json")
				args = append(args, "--source", source, "--json")
				out := abandonCLIProcess(t, abandonProcessInput{Family: family, Source: source, Objects: state, Reply: reply, Label: label, Args: args})
				if out.Code != 0 || out.Forbidden != 0 || out.Reads == 0 || len(out.Diagnostic) != 0 {
					t.Fatal("native abandonment step refused", args[0], out.Code, out.Forbidden, out.Reads)
				}
				return out
			}
			first := invoke("initial-reader", "list")
			var listed struct {
				Payload struct {
					Targets []struct {
						Group      string `json:"group_id"`
						Selectable bool   `json:"selectable"`
					} `json:"targets"`
				} `json:"payload"`
			}
			if json.Unmarshal(first.Output, &listed) != nil || len(listed.Payload.Targets) != 1 || listed.Payload.Targets[0].Group != idText(fixture.GroupID) || !listed.Payload.Targets[0].Selectable {
				t.Fatal("fresh list lost exact target")
			}
			plan := filepath.Join(dir, "abandon.json")
			planned := invoke("planning-reader", "plan", "--target", idText(fixture.GroupID), "--out", plan)
			if planned.Creates != 0 || planned.CAS != 0 || planned.Signs != 0 {
				t.Fatal("plan made native mutation calls")
			}
			applied := invoke("current-authority", "apply", "--plan", plan)
			if applied.CAS != 1 || applied.Signs != 1 || applied.Creates == 0 {
				t.Fatal("apply did not use one exact CAS and Normal signature")
			}
			applied.Output = nil // Discovery cannot borrow the apply reply's operation ID.
			after := invoke("different-get-reader", "list")
			if after.Creates != 0 || after.CAS != 0 || after.Signs != 0 {
				t.Fatal("different reader constructed private mutation reach")
			}
			var history struct {
				Payload struct {
					Targets []json.RawMessage `json:"targets"`
					Rows    []struct {
						Operation string `json:"operation_id"`
						Group     string `json:"group_id"`
						Raw       string `json:"receipt_hex"`
					} `json:"abandonments"`
				} `json:"payload"`
			}
			if json.Unmarshal(after.Output, &history) != nil || len(history.Payload.Targets) != 0 || len(history.Payload.Rows) != 1 || history.Payload.Rows[0].Group != idText(fixture.GroupID) {
				t.Fatal("retained history did not discover removed exact target")
			}
			row := history.Payload.Rows[0]
			receipt := invoke("receipt-get-reader", "receipt", "--operation", row.Operation)
			if receipt.Creates != 0 || receipt.CAS != 0 || receipt.Signs != 0 {
				t.Fatal("receipt lookup made private calls")
			}
			var result struct {
				State   string `json:"state_result"`
				Payload struct {
					Raw         string `json:"receipt_hex"`
					StoredState string `json:"stored_state_result"`
					Group       string `json:"group_id"`
				} `json:"payload"`
			}
			if json.Unmarshal(receipt.Output, &result) != nil || result.State != "success" || result.Payload.StoredState != "work-ended" || result.Payload.Raw != row.Raw || result.Payload.Group != row.Group {
				t.Fatal("receipt query changed the original stored result")
			}
			raw, err := hex.DecodeString(row.Raw)
			stored, inspectErr := contract.InspectCompactMutationReceipt(raw)
			if err != nil || inspectErr != nil || stored.OperationKind != contract.OperationEndSelectedWork || idText(stored.OperationID) != row.Operation || stored.AdministrativeGroupID != fixture.GroupID {
				t.Fatal("discovered receipt correlation is not exact")
			}
		})
	}
}

// full_only: false
func TestAbandonmentCLIRefusesMandatoryNativeDamageWithoutEffects(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, cut := range []string{"missing", "denied", "corrupt"} {
			for _, operation := range []string{"list", "plan", "receipt"} {
				t.Run(family+"/"+cut+"/"+operation, func(t *testing.T) {
					fixture := installedarchive.LoadAdministrative(t, family)
					dir := decisionFixtureDirectory(t)
					source := compositionfull.WriteAdministrativeFixtureSource(t, fixture, dir)
					objects := make([]testtrust.AdministrativeReadObject, len(fixture.Before.Archive.Objects))
					for i, o := range fixture.Before.Archive.Objects {
						objects[i] = testtrust.AdministrativeReadObject{Key: o.Key, Token: o.Token, Body: bytes.Clone(o.Body)}
					}
					state := filepath.Join(dir, "store.json")
					body, err := json.Marshal(objects)
					if err != nil || os.WriteFile(state, body, 0600) != nil {
						t.Fatal(err)
					}
					args := []string{operation, "--source", source, "--json"}
					if operation == "plan" {
						args = append(args, "--target", idText(fixture.GroupID), "--out", filepath.Join(dir, "plan.json"))
					}
					if operation == "receipt" {
						args = append(args, "--operation", idText(fixture.OperationID))
					}
					reply := abandonCLIProcess(t, abandonProcessInput{Family: family, Source: source, Objects: state, Reply: filepath.Join(dir, "reply.json"), Label: "damaged-reader", Args: args, Cut: cut})
					var result struct {
						Operation string `json:"operation_kind"`
						State     string `json:"state_result"`
						Identity  struct {
							Schema string `json:"schema"`
						} `json:"request_identity"`
						Payload json.RawMessage `json:"payload"`
						Result  struct {
							Reason      string `json:"reason"`
							StoreReason string `json:"store_reason"`
						} `json:"result"`
					}
					wantCode, wantState, wantReason, wantStore := 3, "unavailable", "missing_selected_object", ""
					if cut == "denied" {
						wantReason, wantStore = "read_unavailable", "access"
					}
					if cut == "corrupt" {
						wantCode, wantState, wantReason = 2, "positive-defect", "invalid_reference"
					}
					if json.Unmarshal(reply.Output, &result) != nil || reply.Code != wantCode || result.Operation != "abandon-"+operation || result.State != wantState || result.Result.Reason != wantReason || result.Result.StoreReason != wantStore || string(result.Payload) != "null" || result.Identity.Schema != "QueryRequestIdentity/v1" || reply.Reads == 0 || reply.Forbidden != 0 || reply.Creates != 0 || reply.CAS != 0 || reply.Signs != 0 {
						t.Fatal("native damage changed refusal identity/evidence or caused effects", reply.Code, reply.Reads, reply.Forbidden, reply.Creates, reply.CAS, reply.Signs)
					}
				})
			}
		}
	}
}

// full_only: false
func TestAbandonmentCLIRefusesChangedPlansAndStalePredecessors(t *testing.T) {
	fixture := installedarchive.LoadAdministrative(t, "aws")
	dir := decisionFixtureDirectory(t)
	source := compositionfull.WriteAdministrativeFixtureSource(t, fixture, dir)
	objects := make([]testtrust.AdministrativeReadObject, len(fixture.Before.Archive.Objects))
	for i, o := range fixture.Before.Archive.Objects {
		objects[i] = testtrust.AdministrativeReadObject{Key: o.Key, Token: o.Token, Body: bytes.Clone(o.Body)}
	}
	state := filepath.Join(dir, "store.json")
	body, err := json.Marshal(objects)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(state, body, 0600); err != nil {
		t.Fatal(err)
	}
	step := 0
	invoke := func(cut string, args ...string) abandonProcessReply {
		t.Helper()
		step++
		args = append(args, "--source", source, "--json")
		return abandonCLIProcess(t, abandonProcessInput{Family: "aws", Source: source, Objects: state, Reply: filepath.Join(dir, "reply-"+string(rune('a'+step))+".json"), Label: "independent-invocation", Args: args, Cut: cut})
	}
	plan := filepath.Join(dir, "plan.json")
	if r := invoke("", "plan", "--target", idText(fixture.GroupID), "--out", plan); r.Code != 0 || r.CAS+r.Creates+r.Signs+r.Forbidden != 0 {
		t.Fatal("plan failed", r.Code)
	}
	original, err := os.ReadFile(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"risk", "scope", "source"} {
		t.Run(damage, func(t *testing.T) {
			path := filepath.Join(dir, "damaged-"+damage+".json")
			var record map[string]json.RawMessage
			if err := json.Unmarshal(original, &record); err != nil {
				t.Fatal(err)
			}
			candidate := bytes.Clone(original)
			switch damage {
			case "risk":
				candidate = bytes.Replace(candidate, []byte("old processes can still send"), []byte("old processes cannot send"), 1)
			case "scope":
				var p map[string]json.RawMessage
				if err := json.Unmarshal(record["preview"], &p); err != nil {
					t.Fatal(err)
				}
				var ids []string
				if err := json.Unmarshal(p["ended_group_ids"], &ids); err != nil {
					t.Fatal(err)
				}
				ids = append(ids, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
				p["ended_group_ids"], err = json.Marshal(ids)
				if err != nil {
					t.Fatal(err)
				}
				var d map[string]json.RawMessage
				if err := json.Unmarshal(p["dependent_groups"], &d); err != nil {
					t.Fatal(err)
				}
				d["count"] = json.RawMessage("2")
				p["dependent_groups"], err = json.Marshal(d)
				if err != nil {
					t.Fatal(err)
				}
				record["preview"], err = json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				candidate, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
			case "source":
				var pins map[string]json.RawMessage
				if err := json.Unmarshal(record["source"], &pins); err != nil {
					t.Fatal(err)
				}
				pins["file_id"] = json.RawMessage(`"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"`)
				record["source"], err = json.Marshal(pins)
				if err != nil {
					t.Fatal(err)
				}
				candidate, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, candidate, 0600); err != nil {
				t.Fatal(err)
			}
			r := invoke("", "apply", "--plan", path)
			if r.Code == 0 || r.Creates+r.CAS+r.Signs+r.Forbidden != 0 {
				t.Fatal("changed complete plan caused effects", damage, r.Code, r.Creates, r.CAS, r.Signs, r.Forbidden)
			}
			if damage == "scope" && r.Reads == 0 {
				t.Fatal("changed scope did not reach fresh Core equality")
			}
			if damage != "scope" && r.Reads != 0 {
				t.Fatal("altered source or risk reached provider")
			}
		})
	}
	ended := invoke("", "apply", "--plan", plan)
	if ended.Code != 0 || ended.CAS != 1 || ended.Signs != 1 {
		t.Fatal("valid plan did not end work", ended.Code)
	}
	stale := invoke("", "apply", "--plan", plan)
	if stale.Code == 0 || stale.Reads == 0 || stale.Creates+stale.CAS+stale.Signs+stale.Forbidden != 0 {
		t.Fatal("stale predecessor was retried or rebased", stale.Code, stale.CAS)
	}
	absent := invoke("", "receipt", "--operation", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	var refused struct {
		State   string          `json:"state_result"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(absent.Output, &refused) != nil || absent.Code != 3 || refused.State != "unavailable" || string(refused.Payload) != "null" || absent.CAS+absent.Creates+absent.Signs+absent.Forbidden != 0 {
		t.Fatal("absent receipt fabricated outcome", absent.Code)
	}
}

// full_only: false
func TestAbandonmentCLIDiscoversExactOriginalReceiptAfterLostCASReply(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			fixture := installedarchive.LoadAdministrative(t, family)
			dir := decisionFixtureDirectory(t)
			source := compositionfull.WriteAdministrativeFixtureSource(t, fixture, dir)
			objects := make([]testtrust.AdministrativeReadObject, len(fixture.Before.Archive.Objects))
			for i, o := range fixture.Before.Archive.Objects {
				objects[i] = testtrust.AdministrativeReadObject{Key: o.Key, Token: o.Token, Body: bytes.Clone(o.Body)}
			}
			state := filepath.Join(dir, "store.json")
			body, err := json.Marshal(objects)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(state, body, 0600); err != nil {
				t.Fatal(err)
			}
			step := 0
			invoke := func(cut string, args ...string) abandonProcessReply {
				t.Helper()
				step++
				args = append(args, "--source", source, "--json")
				return abandonCLIProcess(t, abandonProcessInput{Family: family, Source: source, Objects: state, Reply: filepath.Join(dir, "reply-"+string(rune('a'+step))+".json"), Label: "post-loss-reader", Args: args, Cut: cut})
			}
			plan := filepath.Join(dir, "plan.json")
			if r := invoke("", "plan", "--target", idText(fixture.GroupID), "--out", plan); r.Code != 0 {
				t.Fatal("plan", r.Code)
			}
			lost := invoke("lost-cas-reply", "apply", "--plan", plan)
			if lost.CAS != 1 || lost.Signs != 1 || lost.Forbidden != 0 {
				t.Fatal("lost reply issued another mutation", lost.CAS, lost.Signs, lost.Forbidden)
			}
			// The mutation reply is discarded regardless of whether the SDK reports its loss.
			listed := invoke("", "list")
			var history struct {
				Payload struct {
					Rows []struct {
						Operation string `json:"operation_id"`
						Raw       string `json:"receipt_hex"`
					} `json:"abandonments"`
				} `json:"payload"`
			}
			if listed.Code != 0 || json.Unmarshal(listed.Output, &history) != nil || len(history.Payload.Rows) != 1 {
				t.Fatal("lost reply hid retained ending", listed.Code)
			}
			queried := invoke("", "receipt", "--operation", history.Payload.Rows[0].Operation)
			var receipt struct {
				State   string `json:"state_result"`
				Payload struct {
					Raw   string `json:"receipt_hex"`
					State string `json:"stored_state_result"`
				} `json:"payload"`
			}
			if queried.Code != 0 || queried.CAS+queried.Creates+queried.Signs+queried.Forbidden != 0 || json.Unmarshal(queried.Output, &receipt) != nil || receipt.State != "success" || receipt.Payload.State != "work-ended" || receipt.Payload.Raw != history.Payload.Rows[0].Raw {
				t.Fatal("lost reply discovery changed original receipt", queried.Code)
			}
		})
	}
}
