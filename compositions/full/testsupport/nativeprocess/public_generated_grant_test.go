package nativeprocess

import (
	"bytes"
	"encoding/hex"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeGeneratedGrantAfterColdFinal(t *testing.T) {
	cloud := newNativeGeneratedServer(t)
	binaries := buildNativeGeneratedExecutables(t, cloud.server.URL+"/client/v4")
	for _, scenario := range []struct{ family, fault string }{{"gcp", "lose-head-reply-and-observation"}, {"aws", "exit-after-head-write"}, {"aws", "replace-recovery"}} {
		t.Run(scenario.family+"/"+scenario.fault, func(t *testing.T) {
			binaries := binaries
			binaries.home = nativeGeneratedPrivateDirectory(t)
			runGeneratedGrantHistory(t, cloud, binaries, scenario.family, scenario.fault)
		})
	}
}

func runGeneratedGrantHistory(t *testing.T, cloud *nativeGeneratedServer, binaries nativeGeneratedExecutables, family, fault string) {
	t.Helper()
	initial, resourcesBefore := cloud.snapshot()
	s := newWorkflowServer(t, family, true)
	s.childRequestLimit = 1024
	source := nativeGeneratedInitialize(t, s, binaries.cli, true)
	binary := map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "supplied"}}
	nativePublicationSource(t, source, func(editable map[string]any) { editable["entries"] = map[string]any{"binary": binary} })
	value := []byte("generated-grant-fixture")
	workflowPrepare(t, s, binaries.cli, source, "set", workflowReadPair(t, source), value)
	workflowResult(t, workflowRun(t, s, binaries.cli, "apply", observer.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json"), "success")
	// Preserve the current sealed input when adding the generated sibling.
	var current map[string]any
	nativeGeneratedReadJSON(t, source, &current)
	editableSecret := current["entries"].(map[string]any)["binary"].(map[string]any)

	nativeGeneratedDeclaration(t, source, nativeGeneratedAccountA, "manual", 0, true)
	nativePublicationSource(t, source, func(editable map[string]any) { editable["entries"].(map[string]any)["binary"] = editableSecret })
	nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, source, nativeGeneratedBearerA, "apply", false), "success", 0)
	first, effects := cloud.snapshot()
	if effects != resourcesBefore+1 || len(first) != len(initial)+1 {
		t.Fatal("expected one selected generated value")
	}
	nativePublicationSource(t, source, func(editable map[string]any) {
		entries := editable["entries"].(map[string]any)
		generated := entries["generated"].(map[string]any)
		entries["fresh"] = maps.Clone(generated)
		generated["recipients"] = []string{"reader"}
		entries["binary"].(map[string]any)["recipients"] = []string{"reader"}
	})
	workflowPrepare(t, s, binaries.cli, source, "set-change", workflowReadPair(t, source), value)
	var refusedGrants contract.ID
	s.mu.Lock()
	s.rejectHeadBody = func(body []byte) bool {
		h, err := format.DecodeHead(body)
		if err != nil || h.Generator == nil || h.Generator.Purpose != contract.GeneratorAuthorityFinal {
			return false
		}
		refusedGrants = contract.Hash(h.GrantWraps)
		return true
	}
	s.mu.Unlock()
	nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, source, nativeGeneratedBearerA, "apply", false), "contention", 3)
	checkpoint, _ := workflowHead(t, s)
	if checkpoint.Generator == nil || checkpoint.Generator.Purpose != contract.GeneratorAuthorityFinalPreparation || len(checkpoint.GrantWraps) != 0 {
		t.Fatal("expected a selected preparation checkpoint")
	}
	root := workflowRoot(t, s, checkpoint)
	var records []contract.SupportRecord
	var prep contract.GeneratedFinalPreparationRecord
	for _, ref := range root.RequiredSupport {
		key, err := format.Key(s.prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := format.InspectRequiredSupportPage(s.object(t, key).body)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Records {
			records = append(records, contract.SupportRecord(row))
			if row.Kind == contract.GeneratedFinalPreparationSupportKind {
				prep, err = contract.InspectGeneratedFinalPreparationRecord(row.Body)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	image, err := contract.ReadGeneratedFinalPreparationImage(root.Domain, root.Snapshot, records, prep)
	if err != nil || len(image.GrantSeals) != 2 {
		t.Fatal("checkpoint does not identify both protected grants", err)
	}
	defer image.Clear()
	var masked []contract.WrapRow
	if err := image.VisitGrantWraps(func(_ contract.GeneratedGrantSeal, _, _ contract.ID, w contract.WrapRow) error {
		masked = append(masked, w)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, n := cloud.snapshot()
	if n != resourcesBefore+2 || len(before) != len(first)+1 {
		t.Fatal("the generated sibling was not created once", n)
	}
	s.mu.Lock()
	s.rejectHeadBody = nil
	var staged [][]byte
	for _, object := range s.objects {
		staged = append(staged, object.body)
	}
	s.mu.Unlock()
	operation := checkpoint.Generator.OperationID
	selectors := []string{"--operation", hex.EncodeToString(operation[:])}
	if fault == "replace-recovery" {
		out := filepath.Join(administrativeReplacementDirectory(t), "successor.json")
		child := workflowRun(t, s, binaries.cli, "successor", observer.Policy{MaxStoreWrites: 64, MaxStoreWriteBytes: 8 << 20}, nil, "keys", "replace", "--source", source, "--source-format", "json", "--target", "recovery", "--authorizer", "authority", "--signing", s.selector(6), "--out", out, "--json")
		reply := nativeReplacementDecode(t, child, "keys-replace-recovery", "TransitionPayload/v1")
		if reply.StoredReceipt == nil || reply.Delivery.Status != "delivered" {
			t.Fatal("replacement did not deliver its successor")
		}
		source = out
		nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, source, "", "apply", false, selectors...), "success", 0)
	} else {
		args := append([]string{"apply", "--source", source, "--source-format", "json"}, selectors...)
		args = append(args, "--json")
		policy := observer.Policy{MaxStoreWrites: 256, MaxStoreWriteBytes: 32 << 20, Fault: fault, FaultOrdinal: 1}
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
		resources := nativeGeneratedSelectedResources(t, s)
		child := workflowRunEnvironment(t, s, binaries.cli, "apply", policy, nil, nativeGeneratedEnvironment(t, binaries, source), args...)
		maps.Copy(resources, nativeGeneratedSelectedResources(t, s))
		child.generatedResources = resources
		if fault == "lose-head-reply-and-observation" {
			nativeGeneratedOutcome(t, child, "commit-outcome-unknown", 3)
		}
	}
	after, n := cloud.snapshot()
	if len(after) != len(before) || n != resourcesBefore+2 {
		t.Fatal("cold Final repeated a provider operation")
	}
	selected, _ := workflowHead(t, s)
	if selected.Generator == nil || selected.Generator.Purpose != contract.GeneratorAuthorityFinal || len(selected.GrantWraps) != 2*format.GrantWrapLength || fault != "replace-recovery" && contract.Hash(selected.GrantWraps) != refusedGrants {
		t.Fatal("selected Final omitted its grant")
	}
	wantRevision, err := contract.GeneratorPhaseRevisionID(selected.Generator.PhaseID)
	if err != nil || selected.Core.Revision != wantRevision || selected.Generator.OperationID != operation ||
		fault != "replace-recovery" && selected.Core.PreviousRevision != checkpoint.Core.Revision {
		t.Fatal("Final did not select the exact continuation", err)
	}
	t.Logf("operation=%x checkpoint_revision=%x final_predecessor=%x final_revision=%x grants=2 additional_creates=1 continuation_creates=0", operation, checkpoint.Core.Revision, selected.Core.PreviousRevision, selected.Core.Revision)
	for i := 0; i < len(selected.GrantWraps); i += format.GrantWrapLength {
		granted, err := contract.DecodeWrapRow(selected.GrantWraps[i+4 : i+format.GrantWrapLength])
		if err != nil {
			t.Fatal(err)
		}
		for _, object := range staged {
			if bytes.Contains(object, granted.RSACiphertext) {
				t.Fatal("immutable preselection object contains the selected grant ciphertext")
			}
		}
		for _, w := range masked {
			if granted.SubjectID != w.SubjectID || granted.PublicBindingDigest != w.PublicBindingDigest || bytes.Equal(granted.RSACiphertext, w.RSACiphertext) {
				t.Fatal("checkpoint recipient ciphertext was not protected")
			}
		}
	}
	read := func() {
		for name, expected := range map[string]string{"binary": "generated-grant-fixture", "generated": nativeGeneratedSecret + "_" + first[len(initial)].Target} {
			dest := filepath.Join(t.TempDir(), "selected.env")
			read := workflowRun(t, s, binaries.cli, "materialize", observer.Policy{RecipientKEK: s.selector(5)}, nil, "materialize", "--source", source, "--source-format", "json", "--out", dest, "--recipient", "reader", "--name", name, "--json")
			nativeMaterializationResult(t, read, "success", true)
			b, err := os.ReadFile(dest)
			if err != nil || !bytes.Equal(b, []byte(name+"="+expected+"\n")) {
				t.Fatal("cold recipient read changed selected content", name, err)
			}
		}
	}
	read()
	nativePublicationSource(t, source, func(editable map[string]any) {
		editable["entries"].(map[string]any)["extra"] = map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": "next"}}
	})
	nativeGeneratedOutcome(t, nativeGeneratedRun(t, s, binaries, source, "", "apply", false), "success", 0)
	later, _ := workflowHead(t, s)
	if later.Core.Revision == selected.Core.Revision || len(later.GrantWraps) != 0 {
		t.Fatal("successor did not carry selected grant pages forward")
	}
	read()
}
