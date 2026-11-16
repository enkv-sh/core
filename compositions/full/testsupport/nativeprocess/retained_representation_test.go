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
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeRetainedRepresentationUsesSelectedDelivery(t *testing.T) {
	output := newNativePublicationServer(t)
	binaries := buildNativeOutputExecutables(t, output.server.URL)
	binaries.nativePluginFixture = newNativePluginFixture(t, append(binaries.builds, nativeManifestProductionBuild(t))...)
	s := newWorkflowServer(t, "aws", false)
	// Twelve initial children, one output-change plan and three recovery consumers.
	s.childLimit, s.childRequestLimit, s.objectLimit = 16, 2048, 512
	const account = "000000000009"
	type valueCase struct {
		name, input, output, retained, delivered string
		secret                                   bool
	}
	var cases []valueCase
	for _, secret := range []bool{false, true} {
		prefix := "P_"
		if secret {
			prefix = "S_"
		}
		// These fixed RFC 4648 vectors are independent of the production codec.
		for _, row := range []valueCase{
			{name: "RAW_RAW", input: "raw", output: "raw", retained: "ABC", delivered: "ABC"},
			{name: "RAW_BASE64", input: "raw", output: "base64", retained: "ABC", delivered: "QUJD"},
			{name: "BASE64_RAW", input: "base64", output: "raw", retained: "QUJD", delivered: "ABC"},
			{name: "BASE64_BASE64", input: "base64", output: "base64", retained: "QUJD", delivered: "QUJD"},
		} {
			row.name, row.secret = prefix+row.name, secret
			cases = append(cases, row)
		}
	}
	path := filepath.Join(t.TempDir(), "configuration.json")
	if err := os.WriteFile(path, workflowSetup(t, s, false), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(phase string, policy observer.Policy, input []byte, args ...string) workflowChild {
		t.Helper()
		return workflowRunEnvironment(t, s, binaries.cli, phase, policy, input, binaries.Environment(t, path), args...)
	}
	workflowResult(t, run("init", observer.Policy{}, nil, "init", "--source", path, "--source-format", "json", "--json"), "success")
	nativePublicationSource(t, path, func(source map[string]any) {
		entries := source["entries"].(map[string]any)
		for _, row := range cases {
			input := map[string]any{"kind": "supplied", "encoding": row.input}
			class := "secret"
			if !row.secret {
				class = "plain"
				input["value"] = row.retained
			}
			entries[row.name] = map[string]any{"confidentiality": class, "recipients": []string{"reader"}, "source": input, "output_encoding": row.output}
		}
	})
	for _, row := range cases {
		if row.secret {
			args := []string{"set", "--source", path, "--source-format", "json", "--name", row.name, "--confidential=true", "--json"}
			if row.input == "base64" {
				args = append(args, "--base64=true")
			}
			workflowResult(t, run("set", observer.Policy{NoKMS: true}, []byte(row.retained), args...), "success")
		}
	}
	nativePublicationSource(t, path, func(source map[string]any) {
		source["outputs"] = map[string]any{
			"destinations": map[string]any{"app": map[string]any{"plugin": "aws-secrets-manager", "settings": map[string]any{"account": account, "region": "us-east-1"}}},
			"routing":      map[string]any{"default": []string{"app"}, "entries": map[string]any{}},
		}
	})
	before := nativePublicationCounters(t, binaries)
	workflowResult(t, run("apply", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json"), "success")
	nativePublicationNoEffects(t, binaries, before)
	if output.effectCount() != 0 {
		t.Fatal("apply published a value")
	}
	pair := workflowReadPair(t, path)
	head, _ := workflowHead(t, s)
	root := workflowRoot(t, s, head)
	readEntries := func(root stateformat.Root) map[string]contract.ValueEntry {
		selected := make(map[string]contract.ValueEntry)
		for _, ref := range root.ValueEntryPages {
			if ref == nil {
				continue
			}
			key, err := stateformat.Key(s.prefix, *ref)
			if err != nil {
				t.Fatal(err)
			}
			page, err := stateformat.DecodeValueEntryPage(s.object(t, key).body)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range page.Slots {
				if entry != nil {
					selected[entry.Name] = *entry
				}
			}
		}
		return selected
	}
	selected := readEntries(root)
	if len(selected) != len(cases) {
		t.Fatal("selected readback changed the complete value set")
	}
	var names, keys []string
	values := make(map[string]string)
	expected := make(map[string][]byte)
	var targets []nativePublicationTarget
	for _, row := range cases {
		entry, present := selected[row.name]
		if !present || entry.ValueSource != contract.Supplied {
			t.Fatal("selected supplied entry is missing", row.name)
		}
		if row.secret {
			payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
			if err != nil || entry.ConfidentialityClass != contract.Secret || len(payload.Ciphertext) != len(row.retained)+16 {
				t.Fatal("selected secret lost the retained representation", row.name, err)
			}
		} else if entry.ConfidentialityClass != contract.Plain || !bytes.Equal(entry.ValueBytes, []byte(row.retained)) {
			t.Fatal("selected plain entry changed exact retained bytes", row.name)
		}
		physical := "arn:aws:secretsmanager:us-east-1:" + account + ":secret:" + row.name
		key := "aws:" + physical + "-AbCd12"
		targets = append(targets, nativePublicationTarget{"ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", physical, key, "aws", row.name})
		keys, names = append(keys, key), append(names, row.name)
		values[row.name], expected[key] = row.delivered, []byte(row.delivered)
	}
	output.expect(account, expected)
	var recipient string
	for _, row := range pair.descriptor.Recipients {
		if row.RecipientID != pair.descriptor.AuthorityRecipientID {
			recipient = hex.EncodeToString(row.RecipientID[:])
		}
	}
	if recipient == "" {
		t.Fatal("selected reader is missing")
	}
	observation := nativeMaterializationObservation(t, s, path, recipient, pair)
	// Pending source edits must not change the encoding of selected delivery.
	nativePublicationSource(t, path, func(source map[string]any) {
		entries := source["entries"].(map[string]any)
		for _, row := range cases {
			pending := "raw"
			if row.output == "raw" {
				pending = "base64"
			}
			entries[row.name].(map[string]any)["output_encoding"] = pending
		}
	})
	images := nativePublicationImages(t, path, filepath.Join(filepath.Dir(path), pair.reference))
	slices.Sort(names)
	var dotenv strings.Builder
	for _, name := range names {
		fmt.Fprintf(&dotenv, "%s=%s\n", name, values[name])
	}
	destination := filepath.Join(t.TempDir(), "application.env")
	materialized := nativeMaterializationRun(t, s, binaries.cli, path, "json", recipient, destination, names...)
	nativeMaterializationSelected(t, s, materialized, observation, destination, names...)
	nativeMaterializationFile(t, destination, dotenv.String(), values)
	nativePublicationNoEffects(t, binaries, before)
	nativePublicationUnchanged(t, images)
	args := []string{"publish", "--source", path, "--source-format", "json", "--json"}
	for _, name := range names {
		args = append(args, "--name", name)
	}
	published := run("apply", observer.Policy{}, nil, args...)
	nativePublicationDecode(t, published, nativePublicationExpectedActions(t, hex.EncodeToString(pair.descriptor.DomainID[:]), targets, "create"), "success")
	nativePublicationEffects(t, binaries, before, 16)
	if output.effectCount() != 16 {
		t.Fatal("selected publication effect count differs")
	}
	output.checkValues(t, keys, false)
	nativePublicationUnchanged(t, images)
	// Applying the pending output tags changes selected delivery but preserves
	// every immutable supplied value, including its exact ciphertext and keys.

	afterFirstPublication := nativePublicationCounters(t, binaries)
	// The public proposal must remain fully comparable after publication.
	// An output-only edit has exactly one entry and target tag change per value.
	proposal := run("reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", path, "--trusted-format", "json", "--json")
	var facts nativePlanningOutput
	var faults struct {
		Payload struct {
			Diagnostics []struct {
				Subject struct{ Kind, Name string }
				Path    []struct{ Field string }
				Reason  string
			}
		}
	}
	decoded := json.Unmarshal(proposal.out, &facts) == nil && json.Unmarshal(proposal.out, &faults) == nil
	if !decoded || proposal.code != 1 || facts.Schema != "ProductResult/v1" || facts.State != "success" || facts.Payload.Schema != "ComparisonPayload/v1" || facts.Payload.Verdict != "mismatch" || !facts.Payload.Complete || len(faults.Payload.Diagnostics) != 0 || len(facts.Payload.Changes) != 2*len(cases) {
		for _, diagnostic := range faults.Payload.Diagnostics {
			t.Logf("output proposal diagnostic: subject=%s name=%s path=%v reason=%s", diagnostic.Subject.Kind, diagnostic.Subject.Name, diagnostic.Path, diagnostic.Reason)
		}
		t.Fatalf("output-only public proposal: decoded=%t exit=%d verdict=%s complete=%t diagnostics=%d changes=%d", decoded, proposal.code, facts.Payload.Verdict, facts.Payload.Complete, len(faults.Payload.Diagnostics), len(facts.Payload.Changes))
	}
	wantedChanges := make(map[string][2]string, 2*len(cases))
	for _, row := range cases {
		old, next := `"1"`, `"2"`
		if row.output == "base64" {
			old, next = next, old
		}
		wantedChanges["entry/"+row.name+"/output_encoding"] = [2]string{old, next}
		wantedChanges["output_target/"+row.name+"/payload_encoding"] = [2]string{old, next}
	}
	for _, change := range facts.Payload.Changes {
		if len(change.Path) != 1 {
			t.Fatal("output-only proposal changed a nested field")
		}
		key := change.Subject.Kind + "/" + change.Subject.Name + "/" + change.Path[0].Field
		wanted, present := wantedChanges[key]
		if !present || change.Action != "changed" || change.Before.State != "present" || change.After.State != "present" || change.Before.Type != "uint" || change.After.Type != "uint" || string(change.Before.Value) != wanted[0] || string(change.After.Value) != wanted[1] || change.Subject.Kind == "entry" && change.Subject.Destination != "" || change.Subject.Kind == "output_target" && change.Subject.Destination != "app" {
			t.Fatal("output-only proposal changed an unrelated fact or exact tag value", key)
		}
		delete(wantedChanges, key)
	}
	if len(wantedChanges) != 0 {
		t.Fatal("output-only proposal omitted an entry or target tag change")
	}
	workflowGETOnly(t, proposal)
	nativePublicationNoEffects(t, binaries, afterFirstPublication)
	nativePublicationUnchanged(t, images)
	workflowResult(t, run("apply", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json"), "success")
	nativePublicationNoEffects(t, binaries, afterFirstPublication)
	if output.effectCount() != 16 {
		t.Fatal("output-only apply published a value")
	}
	updatedHead, _ := workflowHead(t, s)
	updatedRoot := workflowRoot(t, s, updatedHead)
	updated := readEntries(updatedRoot)
	if len(updated) != len(selected) {
		t.Fatal("output-only apply changed the selected value set")
	}
	for _, row := range cases {
		prior, after := selected[row.name], updated[row.name]
		wantOutput := uint8(contract.OutputEncodingRaw)
		wantValue := "ABC"
		if row.output == "raw" {
			wantOutput, wantValue = contract.OutputEncodingBase64, "QUJD"
		}
		if after.InputEncoding != prior.InputEncoding || after.ContentLength != prior.ContentLength || after.RetainedLength != prior.RetainedLength || after.Incarnation != prior.Incarnation || after.ValueState != prior.ValueState || after.OriginSnapshot != prior.OriginSnapshot || after.OriginTransition != prior.OriginTransition || !slices.Equal(after.Recipients, prior.Recipients) || !bytes.Equal(after.ValueBytes, prior.ValueBytes) || after.OutputEncoding != wantOutput {
			t.Fatal("output-only apply replaced immutable material", row.name)
		}
		if row.secret {
			oldCore, err := contract.ValueCoreForEntry(root.Domain, root.CurrentAccess.Core.CompatibilityID, prior)
			if err != nil {
				t.Fatal(err)
			}
			newCore, err := contract.ValueCoreForEntry(updatedRoot.Domain, updatedRoot.CurrentAccess.Core.CompatibilityID, after)
			if err != nil || newCore != oldCore {
				t.Fatal("output-only apply changed secret key or context", row.name, err)
			}
		}
		values[row.name] = wantValue
		for _, target := range targets {
			if target.entry == row.name {
				expected[target.key] = []byte(wantValue)
			}
		}
	}
	output.expect(account, expected)
	updatedPair := workflowReadPair(t, path)
	images = nativePublicationImages(t, path, filepath.Join(filepath.Dir(path), updatedPair.reference))
	observation = nativeMaterializationObservation(t, s, path, recipient, updatedPair)
	dotenv.Reset()
	for _, name := range names {
		fmt.Fprintf(&dotenv, "%s=%s\n", name, values[name])
	}
	materialized = nativeMaterializationRun(t, s, binaries.cli, path, "json", recipient, destination, names...)
	nativeMaterializationSelected(t, s, materialized, observation, destination, names...)
	nativeMaterializationFile(t, destination, dotenv.String(), values)
	nativePublicationNoEffects(t, binaries, afterFirstPublication)
	nativePublicationUnchanged(t, images)
	rewritten := nativePublicationExpectedActions(t, hex.EncodeToString(updatedPair.descriptor.DomainID[:]), targets, "noop")
	for coordinate := range rewritten {
		rewritten[coordinate] = []string{"write-value"}
	}
	published = run("apply", observer.Policy{}, nil, args...)
	nativePublicationDecode(t, published, rewritten, "success")
	nativePublicationEffects(t, binaries, afterFirstPublication, 8)
	if output.effectCount() != 24 {
		t.Fatal("output-only selected publication effect count differs")
	}
	output.checkValues(t, keys, false)
	nativePublicationUnchanged(t, images)
	// The public renderer receives logical content for both retained input
	// classes. Its generic JSON transport encodes ABC exactly once as QUJD.
	var plainNames, manifestOptions []string
	plain := make(map[string]string)
	for _, row := range cases {
		if !row.secret {
			plainNames = append(plainNames, row.name)
			manifestOptions = append(manifestOptions, "--name", row.name)
			plain[row.name] = "ABC"
		}
	}
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	manifestChild := nativeManifestRun(t, s, binaries.cli, binaries.nativePluginFixture, path, "json", manifestPath, observer.Policy{}, manifestOptions...)
	manifestHead, _ := workflowHead(t, s)
	manifestRoot := workflowRoot(t, s, manifestHead)
	fixture := nativeMaterializationFixture{head: manifestHead, root: manifestRoot, entries: readEntries(manifestRoot)}
	wantManifest := nativeManifestExpected(t, fixture, nil, account, "", "", hex.EncodeToString(updatedPair.descriptor.AuthorityRecipientID[:]), "current-authority", "exact-names", "", plainNames, nil, plain)
	nativeManifestInstalled(t, manifestChild, manifestPath, wantManifest)
	nativePublicationUnchanged(t, images)

	// Complete source loss must preserve all four input/output combinations.
	// Retained secret verification uses the original ABC/QUJD bytes; selected
	// delivery still uses the independently fixed values after output-only Apply.
	beforeRecovery := nativePublicationCounters(t, binaries)
	selectedHead, selectedObject := workflowHead(t, s)
	selectedRoot := workflowRoot(t, s, selectedHead)
	selectedBeforeLoss := readEntries(selectedRoot)
	objectsBeforeLoss := s.objectCount()
	if err := os.RemoveAll(filepath.Dir(path)); err != nil {
		t.Fatal("complete representation source loss failed", err)
	}
	if _, err := os.Lstat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("complete-loss barrier retained a source file")
	}
	recoveredPath := filepath.Join(t.TempDir(), "recovered.json")
	retainedDigests := make(map[string]string)
	for _, row := range cases {
		if row.secret {
			digest := sha256.Sum256([]byte(row.retained))
			retainedDigests[row.name] = hex.EncodeToString(digest[:])
		}
	}
	recoveredEnvironment := binaries.Environment(t, recoveredPath)
	recoveredChild := workflowRunEnvironment(t, s, binaries.cli, "authority", observer.Policy{ExpectedSHA256: retainedDigests}, nil, recoveredEnvironment,
		nativePrepareArgs(s, recoveredPath, "restored", "--normal-signing-key", s.selector(1))...)
	recovery := nativePrepareDecode(t, recoveredChild, "reconstruction", false)
	recoveredPair := workflowReadNamedPair(t, recoveredPath, "restored")
	if recovery.Recovery.Status != "complete" || recovery.Recovery.Head != workflowDigest(selectedObject.body) || recovery.Recovery.Domain != hex.EncodeToString(selectedRoot.Domain[:]) || recovery.Delivery.Outcome != "recorded" || recovery.Delivery.CleanupFailed || recovery.Delivery.Readback == nil || recovery.Delivery.Readback.EditableDigest != workflowDigest(recoveredPair.editable) || recovery.Delivery.Readback.GeneratedDigest != workflowDigest(recoveredPair.generated) || recoveredPair.fileID == updatedPair.fileID {
		t.Fatal("representation recovery lost selected provenance or fresh exact pair delivery")
	}
	nativePrepareReadOnly(t, recoveredChild)
	if !nativeMaximumPlaintext(recoveredChild.capture, retainedDigests) {
		t.Fatal("reconstruction did not verify every exact retained secret")
	}
	func() {
		captured, err := configuration.Capture(t.Context(), recoveredPath, configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := captured.Close(); err != nil {
				t.Error(err)
			}
		}()
		model, err := configuration.Parse(t.Context(), captured)
		if err != nil || !model.Resolved || model.DomainID != selectedRoot.Domain || len(model.Entries) != len(cases) || len(model.Outputs) != 1 {
			t.Fatal("reconstructed representation source is incomplete", err)
		}
		want := make(map[string]valueCase, len(cases))
		for _, row := range cases {
			want[row.name] = row
		}
		for _, entry := range model.Entries {
			row, present := want[entry.Name]
			original := selectedBeforeLoss[entry.Name]
			if !present || entry.Secret != row.secret || entry.InputEncoding != original.InputEncoding || entry.OutputEncoding != original.OutputEncoding || entry.Generated != nil {
				t.Fatal("recovery changed an exact input/output classification", entry.Name)
			}
			if row.secret {
				if entry.Retained == nil || entry.Retained.Incarnation != original.Incarnation || entry.Retained.Material != original.ValueState || len(entry.Sealed) != 0 || len(entry.Plain) != 0 {
					t.Fatal("recovery changed immutable retained secret identity", entry.Name)
				}
			} else if entry.Retained != nil || entry.PlainBase64 || entry.ContentLength != 3 || string(entry.Plain) != row.retained {
				t.Fatal("recovery changed exact retained plain bytes", entry.Name)
			}
			delete(want, entry.Name)
		}
		if len(want) != 0 {
			t.Fatal("recovery omitted a representation case")
		}
		if len(recovery.Dependencies.Requirements) != 1 {
			t.Fatal("reconstruction changed the declared output dependency count")
		}
		dependency := recovery.Dependencies.Requirements[0]
		if dependency.Role != "output" || dependency.Contract != model.Outputs[0].Binding.Destination.ConfigContractID || dependency.ProtocolVersion != 6 || dependency.Plugin != nil || dependency.Artifact != nil || dependency.Status != "missing" || dependency.Reason != "not-installed" {
			t.Fatal("reconstruction invented an output implementation selection")
		}
	}()
	recoveredImages := nativePublicationImages(t, recoveredPath, filepath.Join(filepath.Dir(recoveredPath), recoveredPair.reference))
	planned := workflowRunEnvironment(t, s, binaries.cli, "reader", observer.Policy{NoKMS: true}, nil, recoveredEnvironment, "plan", "--trusted", recoveredPath, "--trusted-format", "json", "--json")
	if workflowResult(t, planned, "success").Payload.Verdict != "match" {
		t.Fatal("reconstructed representation source does not match selected state")
	}
	workflowGETOnly(t, planned)
	recoveredObservation := nativeMaterializationObservation(t, s, recoveredPath, recipient, recoveredPair)
	recoveredDestination := filepath.Join(t.TempDir(), "recovered.env")
	delivered := nativeMaterializationRun(t, s, binaries.cli, recoveredPath, "json", recipient, recoveredDestination, names...)
	nativeMaterializationSelected(t, s, delivered, recoveredObservation, recoveredDestination, names...)
	nativeMaterializationFile(t, recoveredDestination, dotenv.String(), values)
	nativePublicationNoEffects(t, binaries, beforeRecovery)
	nativePublicationUnchanged(t, recoveredImages)
	afterRecoveryHead, afterRecoveryObject := workflowHead(t, s)
	if !bytes.Equal(selectedObject.body, afterRecoveryObject.body) || s.objectCount() != objectsBeforeLoss || !reflect.DeepEqual(selectedBeforeLoss, readEntries(workflowRoot(t, s, afterRecoveryHead))) || output.effectCount() != 24 || s.children != 16 {
		t.Fatal("reconstruction or fresh consumers changed selected material, effects or child inventory")
	}

}
