package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestPublicNativeGeneratedContinuityAndExactAbandonment(t *testing.T) {
	manifest := nativeManifestProductionBuild(t)
	// This fresh provider fixture receives exactly two creates per family.
	// State B's bytes are literal expectations, independent of the responder.
	for _, cell := range []struct{ family, currentSecret string }{
		{"aws", "Generated_secret_0123456789_ABCDEFGHIJKLMN_00000000000000000000000000000002"},
		{"gcp", "Generated_secret_0123456789_ABCDEFGHIJKLMN_00000000000000000000000000000002"},
	} {
		t.Run(cell.family, func(t *testing.T) {
			cloudflare := newNativeGeneratedServer(t)
			origin := cloudflare.server.URL + "/client/v4"
			binaries := buildNativeGeneratedExecutables(t, origin)
			_, reconstruct := workflowExecutables(t)
			s := newWorkflowServer(t, cell.family, true)
			s.childLimit, s.objectLimit = 32, 512
			// The maintained setup supplies the independent successor KEK and Reader.
			f := nativeSequenceSetupOnServer(t, binaries.cli, s, true)
			source := f.source
			localName := "prod"
			for epoch := uint64(0); epoch < 2; epoch++ {
				nativeGeneratedDeclaration(t, source, nativeGeneratedAccountA, "manual", epoch, true)
				state, code := "success", 0
				if epoch != 0 {
					state, code = "retirement-pending", 3
				}
				nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, source, nativeGeneratedBearerA, "apply", false), state, code)
			}
			baseline := nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, source, "", "generated list", false), "success", 0)
			if len(baseline.Current) != 1 || baseline.Current[0].Epoch != 1 || len(baseline.Duties) != 1 || len(baseline.Hazards) != 0 || baseline.Duties[0].Facts.DutyID == "" || baseline.Duties[0].Facts.ResourceID == "" || baseline.Duties[0].Target.TokenID == baseline.Current[0].TokenID {
				t.Fatal("continuity fixture lacks one current generation and its different exact old duty")
			}
			before, resources := cloudflare.snapshot()
			if resources != 2 {
				t.Fatal("continuity fixture must own both independently created resources", resources)
			}
			// Later commands use the existing successor permission fixture. The
			// installed source still selects the actual current Authority and keys.
			recoverySigner := ""
			var preparedEnvironment []string
			command := func(binary, phase string, policy observer.Policy, args ...string) workflowChild {
				t.Helper()
				t.Setenv("CLOUDFLARE_API_TOKEN", "")
				pair := workflowReadNamedPair(t, source, localName)
				restore := workflowReadOnlyPair(t, source, pair)
				defer restore()
				inputFlag := "--source"
				if len(args) > 0 && args[0] == "plan" {
					inputFlag = "--trusted"
				}
				args = append(args, inputFlag, source, "--source-format", "json")
				policy.RecoverySigner = recoverySigner
				environment := preparedEnvironment
				if environment == nil && len(args) > 0 && args[0] == "apply" {
					environment = nativeGeneratedEnvironment(t, binaries, source)
				}
				child := workflowRunEnvironment(t, s, binary, phase, policy, nil, environment, args...)
				child.generatedResources = nativeGeneratedSelectedResources(t, s)
				workflowUnchanged(t, source, pair)
				return child
			}
			unchangedWork := func() {
				t.Helper()
				view := nativeGeneratedOutcome(t, command(binaries.cli, "reader", observer.Policy{NoKMS: true}, "generated", "list", "--json"), "success", 0)
				if !reflect.DeepEqual(view.Current, baseline.Current) || !reflect.DeepEqual(view.Duties, baseline.Duties) || !reflect.DeepEqual(view.Hazards, baseline.Hazards) {
					t.Fatal("public continuity command changed generated identities, targets or work")
				}
				after, count := cloudflare.snapshot()
				if !slices.Equal(before, after) || count != resources {
					t.Fatal("public continuity command entered Cloudflare or claimed provider cleanup")
				}
			}
			authorityOutput := filepath.Join(administrativeReplacementDirectory(t), "authority.json")
			authority := command(binaries.cli, "successor", observer.Policy{SuccessorKEK: s.selector(7)}, "keys", "replace", "--target", "authority", "--authorizer", "authority", "--encryption", s.selector(7), "--decrypt-with", "authority", "--out", authorityOutput, "--json")
			if r := nativeReplacementDecode(t, authority, "keys-replace-authority", "TransitionPayload/v1"); r.Delivery.Status != "delivered" {
				t.Fatal("Authority replacement did not deliver a selected public source")
			}
			source = authorityOutput
			unchangedWork()
			recoveryOutput := filepath.Join(administrativeReplacementDirectory(t), "recovery.json")
			recovery := command(binaries.cli, "successor", observer.Policy{SuccessorKEK: s.selector(7)}, "keys", "replace", "--target", "recovery", "--authorizer", "authority", "--signing", s.selector(6), "--out", recoveryOutput, "--json")
			if r := nativeReplacementDecode(t, recovery, "keys-replace-recovery", "TransitionPayload/v1"); r.Delivery.Status != "delivered" || r.StoredReceipt == nil {
				t.Fatal("Recovery replacement did not deliver its selected receipt-bearing source")
			}
			source = recoveryOutput
			recoverySigner = s.selector(6)
			unchangedWork()
			var editable map[string]any
			nativeGeneratedReadJSON(t, source, &editable)
			editable["entries"].(map[string]any)["generated"].(map[string]any)["recipients"] = []string{"reader"}
			nativeGeneratedWriteJSON(t, source, editable)
			nativeGeneratedOutcome(t, command(binaries.cli, "successor", observer.Policy{SuccessorKEK: s.selector(7)}, "apply", "--json"), "success", 0)
			membershipHead, _ := workflowHead(t, s)
			membershipRoot := workflowRoot(t, s, membershipHead)
			if entry := nativeLifecycleEntries(t, s, membershipRoot)["generated"]; len(entry.Recipients) != 2 {
				t.Fatal("public membership change did not add the Reader to current generated material")
			}
			unchangedWork()
			pair := workflowReadPair(t, source)
			reconstructed := nativeMergePair(t, pair)
			sum := sha256.Sum256([]byte(cell.currentSecret))
			_, beforeReconstruction := workflowHead(t, s)
			objects := s.objectCount()
			opened := command(reconstruct, "authority", observer.Policy{ExpectedSHA256: map[string]string{"generated": hex.EncodeToString(sum[:])}, SuccessorKEK: s.selector(7)}, "--reconstruct-output", reconstructed)
			if opened.code != 0 {
				var output struct{ PreparationStage uint8 }
				decoded := json.Unmarshal(opened.out, &output) == nil
				facts := []string{}
				for _, event := range opened.capture.Events {
					if event.Kind == "plaintext" || event.Kind == "footer" || event.Kind == "http-return" && event.Operation == "kms-decrypt" {
						facts = append(facts, fmt.Sprintf("%s:%s:%s:sent=%t:status=%d:matched=%t:count=%d:code=%d", event.Kind, event.Operation, event.Role, event.Sent, event.Status, event.Matched, event.Count, event.Code))
					}
				}
				if len(facts) > 8 {
					facts = facts[len(facts)-8:]
				}
				t.Fatalf("public generated reconstruction failed: exit=%d output_bytes=%d diagnostic_bytes=%d output_decoded=%t preparation_stage=%d events=%v %s", opened.code, len(opened.out), len(opened.diagnostic), decoded, output.PreparationStage, facts, opened.summary)
			}
			workflowPlaintext(t, opened, "plaintext")
			_, afterReconstruction := workflowHead(t, s)
			if !reflect.DeepEqual(beforeReconstruction, afterReconstruction) || objects != s.objectCount() {
				t.Fatal("public generated reconstruction changed selected state")
			}
			source = reconstructed
			compared := command(binaries.cli, "reader", observer.Policy{NoKMS: true}, "plan", "--json")
			if workflowResult(t, compared, "success").Payload.Verdict != "match" {
				t.Fatal("reconstructed generated configuration differs from current selection")
			}
			unchangedWork()
			beforeReceipts := nativePrepareReadFacts(t, command(binaries.cli, "reader", observer.Policy{NoKMS: true}, "receipt", "--json"))
			beforeInspection := nativePrepareReadFacts(t, command(binaries.cli, "reader", observer.Policy{NoKMS: true}, "inspect", "--json"))
			beforeApply := nativeGeneratedOutcome(t, command(binaries.cli, "successor", observer.Policy{SuccessorKEK: s.selector(7)}, "apply", "--json"), "no-op", 0)
			var beforeLoss map[string]any
			nativeGeneratedReadJSON(t, source, &beforeLoss)
			for _, prior := range []string{f.source, authorityOutput, recoveryOutput, reconstructed} {
				if err := os.RemoveAll(filepath.Dir(prior)); err != nil {
					t.Fatal("generated complete-loss removal failed", err)
				}
				if _, err := os.Lstat(filepath.Dir(prior)); !os.IsNotExist(err) {
					t.Fatal("generated complete loss retained an ENKV source directory")
				}
			}
			localName = "generated-restored"
			source = filepath.Join(t.TempDir(), "recovered.json")
			build, err := filepath.EvalSymlinks(binaries.localBuild)
			if err != nil {
				t.Fatal("generated local build directory unavailable", err)
			}
			generator := artifact.LocalPlugin{Name: "cloudflare-account-token", Directory: build}
			recoveredPlugins := newNativePluginFixture(t, generator, manifest)
			recoveredPlugins.home = binaries.home
			preparedEnvironment = recoveredPlugins.Environment(t, source)
			t.Log("fixture local plugin settings updated for recovered application after complete local source loss")
			prepared := workflowRunEnvironment(t, s, binaries.cli, "authority", observer.Policy{ExpectedSHA256: map[string]string{"generated": hex.EncodeToString(sum[:])}, SuccessorKEK: s.selector(7), RecoverySigner: recoverySigner}, nil, preparedEnvironment, nativePrepareArgs(s, source, localName, "--normal-signing-key", s.selector(1))...)
			preparation := nativePrepareDecode(t, prepared, "reconstruction", false)
			if preparation.Recovery.Head != workflowDigest(beforeReconstruction.body) || preparation.Delivery.Outcome != "recorded" || len(preparation.Dependencies.Requirements) != 1 || len(preparation.Dependencies.Installations) != 0 {
				t.Fatal("generated complete loss lost selected recovery, delivery or dependency facts")
			}
			dependency := preparation.Dependencies.Requirements[0]
			configContract := sha256.Sum256([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/CONFIG/v1\x00https://api.cloudflare.com/client/v4"))
			if dependency.Role != "generator" || dependency.Plugin != nil || dependency.Contract != hex.EncodeToString(configContract[:]) || dependency.ProtocolVersion != 3 || dependency.Artifact != nil || dependency.Status != "missing" || dependency.Reason != "not-installed" {
				t.Fatal("generated preparation changed the exact unselected canonical requirement")
			}
			var recoveredEditable map[string]any
			nativeGeneratedReadJSON(t, source, &recoveredEditable)
			if !reflect.DeepEqual(recoveredEditable["entries"].(map[string]any)["generated"].(map[string]any)["source"], beforeLoss["entries"].(map[string]any)["generated"].(map[string]any)["source"]) {
				t.Fatal("complete-loss recovery changed exact canonical generator source")
			}
			workflowPlaintext(t, prepared, "plaintext")
			nativeReplacementReadDecrypt(t, prepared, "successor-private", "normal")
			compared = command(binaries.cli, "reader", observer.Policy{NoKMS: true}, "plan", "--json")
			if workflowResult(t, compared, "success").Payload.Verdict != "match" {
				t.Fatal("fresh complete-loss generated plan did not match")
			}
			workflowGETOnly(t, compared)
			unchangedWork()
			if !reflect.DeepEqual(beforeReceipts, nativePrepareReadFacts(t, command(binaries.cli, "reader", observer.Policy{NoKMS: true}, "receipt", "--json"))) || !reflect.DeepEqual(beforeInspection, nativePrepareReadFacts(t, command(binaries.cli, "reader", observer.Policy{NoKMS: true}, "inspect", "--json"))) {
				t.Fatal("complete loss changed retained receipt order/results, registry or warnings")
			}
			afterApply := nativeGeneratedOutcome(t, command(binaries.cli, "successor", observer.Policy{SuccessorKEK: s.selector(7)}, "apply", "--json"), "no-op", 0)
			if beforeApply.Canonical != afterApply.Canonical || beforeApply.EffectSummary != afterApply.EffectSummary || !reflect.DeepEqual(beforeApply.Effects, afterApply.Effects) || !reflect.DeepEqual(beforeApply.Duties, afterApply.Duties) || !reflect.DeepEqual(beforeApply.Hazards, afterApply.Hazards) {
				t.Fatal("complete loss changed later occupied-work apply admission")
			}
			unchangedWork()
			_, afterPrepare := workflowHead(t, s)
			if !reflect.DeepEqual(beforeReconstruction, afterPrepare) || objects != s.objectCount() {
				t.Fatal("generated complete loss or later idle apply changed selected state")
			}
			listed := command(binaries.cli, "reader", observer.Policy{NoKMS: true}, "abandon", "list", "--json")
			var inspection struct {
				Payload struct {
					Targets []struct {
						Group      string `json:"group_id"`
						Kind       string `json:"kind"`
						Target     string `json:"target_id"`
						Selectable bool   `json:"selectable"`
					} `json:"targets"`
				} `json:"payload"`
			}
			if listed.code != 0 || json.Unmarshal(listed.out, &inspection) != nil {
				t.Fatal("public exact abandonment discovery failed", listed.summary)
			}
			group := ""
			for _, target := range inspection.Payload.Targets {
				if target.Kind == "generated-duty" && target.Group == baseline.Duties[0].Facts.DutyID && target.Target == baseline.Duties[0].Facts.ResourceID && target.Selectable {
					if group != "" {
						t.Fatal("exact duty has more than one selectable administrative group")
					}
					group = target.Group
				}
			}
			if group == "" {
				t.Fatal("retained duty has no exact selectable public abandonment group")
			}
			plan := filepath.Join(administrativeReplacementDirectory(t), "abandon.json")
			planned := command(binaries.cli, "reader", observer.Policy{NoKMS: true}, "abandon", "plan", "--target", group, "--out", plan, "--json")
			if planned.code != 0 {
				t.Fatal("exact public abandonment plan failed", planned.summary)
			}
			ended := command(binaries.cli, "successor", observer.Policy{SuccessorKEK: s.selector(7)}, "abandon", "apply", "--plan", plan, "--json")
			var ending struct {
				State   string `json:"state_result"`
				Payload struct {
					Completion string `json:"original_completion"`
					Cleanup    string `json:"physical_cleanup"`
					Receipt    struct {
						Raw string `json:"receipt_hex"`
					} `json:"receipt"`
				} `json:"payload"`
			}
			if ended.code != 0 || json.Unmarshal(ended.out, &ending) != nil || ending.State != "work-ended" || ending.Payload.Completion != "not-established" || ending.Payload.Cleanup != "not-established" {
				t.Fatal("ending selected work claimed original completion or provider cleanup", ended.summary)
			}
			receiptBody, err := hex.DecodeString(ending.Payload.Receipt.Raw)
			if err != nil {
				t.Fatal("exact abandonment receipt encoding is invalid")
			}
			receipt, err := contract.InspectCompactMutationReceipt(receiptBody)
			if err != nil || receipt.OperationKind != contract.OperationEndSelectedWork || receipt.StateResult != contract.ReceiptStateWorkEnded || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected {
				t.Fatal("exact abandonment did not carry its selected work-ended receipt")
			}
			if hex.EncodeToString(receipt.AdministrativeGroupID[:]) != group || hex.EncodeToString(receipt.AdministrativeTargetID[:]) != baseline.Duties[0].Facts.ResourceID {
				t.Fatal("abandonment receipt did not name the independently discovered exact duty group and resource")
			}
			view := nativeGeneratedOutcome(t, command(binaries.cli, "reader", observer.Policy{NoKMS: true}, "generated", "list", "--json"), "success", 0)
			if !reflect.DeepEqual(view.Current, baseline.Current) || len(view.Duties) != 0 || len(view.Hazards) != 0 {
				t.Fatal("exact abandonment changed current generation or left the ended duty selectable")
			}
			after, count := cloudflare.snapshot()
			if !slices.Equal(before, after) || count != resources {
				t.Fatal("ending local generated work sent a provider request or removed a physical resource")
			}
			if bytes.Contains(ended.out, []byte(nativeGeneratedSecret)) || bytes.Contains(ended.diagnostic, []byte(nativeGeneratedSecret)) {
				t.Fatal("exact abandonment disclosed generated material")
			}
		})
	}
}
