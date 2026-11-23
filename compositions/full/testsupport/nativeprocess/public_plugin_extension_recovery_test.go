package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/examples/ini-reference-manifest/consumer"
	"enkv.sh/sdk/examples/testservice"
)

type nativeExtensionManifestResult struct {
	Schema   string
	Issuance struct {
		Schema    string
		Operation string `json:"operation_kind"`
		State     string `json:"state_result"`
		Payload   struct {
			Schema   string
			Renderer struct {
				Artifact string `json:"artifact_id"`
			} `json:"renderer"`
			Included []struct {
				Name string
				ID   string `json:"entry_incarnation_id"`
			} `json:"included_entries"`
			Excluded []json.RawMessage `json:"excluded_entries"`
			Format   string            `json:"format_contract_id"`
			Evidence string            `json:"evidence_limit"`
			Length   uint64            `json:"artifact_length"`
			Digest   string            `json:"artifact_digest"`
		} `json:"payload"`
	} `json:"issuance"`
	Delivery struct {
		Artifact struct {
			Renderer string `json:"renderer_artifact_id"`
			Format   string `json:"format_contract_id"`
			Length   uint64 `json:"length"`
			Digest   string `json:"digest"`
		} `json:"artifact"`
		Replacement string          `json:"replacement"`
		Candidate   string          `json:"candidate_verification"`
		Installed   string          `json:"installed_verification"`
		Completion  string          `json:"native_completion"`
		Cleanup     string          `json:"candidate_cleanup"`
		Residue     *string         `json:"residue_path"`
		Failure     json.RawMessage `json:"failure"`
	} `json:"delivery"`
	Source string `json:"source_cleanup"`
}

func nativeExtensionManifestBytes(t *testing.T, child workflowChild, path string, renderer artifact.Digest) (nativeExtensionManifestResult, []byte) {
	t.Helper()
	var result nativeExtensionManifestResult
	if err := json.Unmarshal(child.out, &result); err != nil {
		t.Fatal("manifest public result is malformed")
	}
	p := result.Issuance.Payload
	d := result.Delivery
	body, err := os.ReadFile(path)
	info, statErr := os.Lstat(path)
	if child.code != 0 || result.Schema != "ManifestFileResult/v2" || result.Issuance.Schema != "ProductResult/v1" || result.Issuance.Operation != "issue-consumption-manifest" || result.Issuance.State != "success" || p.Schema != "ManifestPayload/v3" || p.Format != "example/ini-reference/v1" || p.Evidence != "authorized-input-and-exact-bytes" || p.Renderer.Artifact != renderer.String() || result.Source != "complete" || err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || p.Length != uint64(len(body)) || p.Digest != workflowDigest(body) || d.Artifact.Renderer != renderer.String() || d.Artifact.Format != p.Format || d.Artifact.Length != p.Length || d.Artifact.Digest != p.Digest || d.Replacement != "replaced" || d.Candidate != "verified" || d.Installed != "verified" || d.Completion != "complete" || d.Cleanup != "renamed" || d.Residue != nil || !bytes.Equal(d.Failure, []byte("null")) {
		t.Fatalf("manifest common delivery differs: exit=%d decoded=true success=%t bytes=%d", child.code, result.Issuance.State == "success", len(body))
	}
	return result, body
}

func nativeExtensionRecoveryAndFiltering(t *testing.T, cli string, builds []artifact.LocalPlugin, renderer artifact.Digest) {
	f := newNativeExtensionCase(t, cli, builds)
	subject := "consumer"
	f.declare(t, 0, "manual", &subject, true)
	credential := []string{"ENKV_EXAMPLE_TOKEN=" + nativeExtensionBearer}
	nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, credential, "apply", "--source", f.path, "--source-format", "json", "--json"), "success", 0)
	published := f.run(t, "apply", false, credential, "publish", "--source", f.path, "--source-format", "json", "--name", "TOKEN", "--json")
	var publication nativePublicationOutput
	if json.Unmarshal(published.out, &publication) != nil || published.code != 0 || len(publication.Payload.Entries) != 1 || len(publication.Payload.Entries[0].Actions) != 1 || publication.Payload.Entries[0].Actions[0].Disposition != "acknowledged" {
		nativeExtensionPublicationFailure(t, published, publication)
		t.Fatal("recovery fixture did not publish its exact owned value")
	}
	coordinate := publication.Payload.Entries[0].Coordinate
	pair := workflowReadPair(t, f.path)
	head, root, entries := f.selected(t)
	locator := f.server.URL + "/values/extension/VE9LRU4"
	expected := nativeExtensionExpectedINI(t, f.store, root, head, pair.descriptor.AuthorityRecipientID, f.server.URL, locator)
	homes := []string{f.plugins.home}
	manifestBuild := builds[slices.IndexFunc(builds, func(v artifact.LocalPlugin) bool { return v.Name == "workshop-ini" })]
	// This new home has only the renderer: no installed output interpreter.
	f.plugins = newNativePluginFixture(t, manifestBuild)
	homes = append(homes, f.plugins.home)
	matchedPath := filepath.Join(t.TempDir(), "matched.ini")
	matched := f.run(t, "reader", true, nil, "manifest", "--source", f.path, "--source-format", "json", "--out", matchedPath, "--plugin", "workshop-ini", "--settings", `{"section_prefix":"client"}`, "--service", "local-values-service/v1", "--json")
	workflowGETOnly(t, matched)
	matching := strings.Replace(expected, "has_service_filter=\"false\"\nservice_filter_base64=\"\"", "has_service_filter=\"true\"\nservice_filter_base64=\"bG9jYWwtdmFsdWVzLXNlcnZpY2UvdjE=\"", 1)
	nativeExtensionManifest(t, matched, matchedPath, matching, locator, renderer)
	unmatchedPath := filepath.Join(t.TempDir(), "unmatched.ini")
	unmatched := f.run(t, "reader", true, nil, "manifest", "--source", f.path, "--source-format", "json", "--out", unmatchedPath, "--plugin", "workshop-ini", "--settings", `{"section_prefix":"client"}`, "--service", "private/other-service/v1", "--json")
	workflowGETOnly(t, unmatched)
	unmatchedExpected, _, found := strings.Cut(expected, "[client.entry.1]\n")
	if !found {
		t.Fatal("independent INI fixture has no secret section")
	}
	unmatchedExpected = strings.Replace(unmatchedExpected, "has_service_filter=\"false\"\nservice_filter_base64=\"\"", "has_service_filter=\"true\"\nservice_filter_base64=\"cHJpdmF0ZS9vdGhlci1zZXJ2aWNlL3Yx\"", 1)
	unmatchedExpected = strings.Replace(unmatchedExpected, "included_count=\"2\"\nexcluded_count=\"0\"", "included_count=\"1\"\nexcluded_count=\"1\"", 1)
	unmatchedExpected += fmt.Sprintf("[client.excluded.0]\nname_base64=\"VE9LRU4=\"\nincarnation_id=\"%s\"\nreason=\"no-matching-service\"\n\n", nativeExtensionID(entries["TOKEN"].Incarnation))
	unmatchedResult, unmatchedBody := nativeExtensionManifestBytes(t, unmatched, unmatchedPath, renderer)
	partition := unmatchedResult.Issuance.Payload
	if len(partition.Included) != 1 || partition.Included[0].Name != "PLAIN" || partition.Included[0].ID != nativeExtensionID(entries["PLAIN"].Incarnation) || len(partition.Excluded) != 1 {
		t.Fatal("nonmatching service changed the exact authorized input partition")
	}
	var excluded struct {
		Name   string
		ID     string `json:"entry_incarnation_id"`
		Reason string
	}
	if json.Unmarshal(partition.Excluded[0], &excluded) != nil || excluded.Name != "TOKEN" || excluded.ID != nativeExtensionID(entries["TOKEN"].Incarnation) || excluded.Reason != "no-matching-service" {
		t.Fatal("nonmatching service changed the exact excluded entry fact")
	}
	document, consumerErr := consumer.Read(bytes.NewReader(unmatchedBody))
	if string(unmatchedBody) != unmatchedExpected || consumerErr != nil || len(document.Sections) != 3 {
		t.Fatal("nonmatching private service changed the exact complete INI partition")
	}
	references, consumerErr := document.References()
	if consumerErr != nil || len(references) != 0 || document.Sections["client.excluded.0"]["reason"] != "no-matching-service" {
		t.Fatal("independent consumer did not retain the complete nonmatching exclusion")
	}
	badDirectory := nativeExtensionCopyExample(t, "ini-reference-manifest")
	var badDescriptor artifact.Descriptor
	nativeGeneratedReadJSON(t, filepath.Join(badDirectory, "plugin.json"), &badDescriptor)
	badDescriptor.Name, badDescriptor.Version = "workshop-ini-defective", "0.2.0"
	nativeGeneratedWriteJSON(t, filepath.Join(badDirectory, "plugin.json"), badDescriptor)
	nativeExtensionRewrite(t, filepath.Join(badDirectory, "render.go"), "plainField(w, e)", `w.Text("ZGVmZWN0aXZl", manifest.MaxQuotedTextBytes, true)`)
	badRenderer, badMetadata := nativeExtensionBuildAuthor(t, badDirectory)
	badID, err := badMetadata.Identity()
	if err != nil {
		t.Fatal(err)
	}
	f.plugins.builds = append(f.plugins.builds, badRenderer)
	badPath := filepath.Join(t.TempDir(), "defective.ini")
	bad := f.run(t, "reader", true, nil, "manifest", "--source", f.path, "--source-format", "json", "--out", badPath, "--plugin", "workshop-ini-defective", "--settings", `{"section_prefix":"client"}`, "--json")
	workflowGETOnly(t, bad)
	badResult, badBody := nativeExtensionManifestBytes(t, bad, badPath, badID)
	if len(badResult.Issuance.Payload.Included) != 2 || len(badResult.Issuance.Payload.Excluded) != 0 {
		t.Fatal("defective renderer changed host input-selection facts")
	}
	badDocument, err := consumer.Read(bytes.NewReader(badBody))
	if err != nil {
		t.Fatal("deliberately wrong semantic body must retain valid INI grammar")
	}
	badValues, err := badDocument.PlainValues()
	badExpected := strings.Replace(expected, `value_base64="cHVibGljICNzZWxlY3RlZA=="`, `value_base64="ZGVmZWN0aXZl"`, 1)
	if err != nil || string(badBody) != badExpected || bytes.Equal(badBody, []byte(expected)) || !reflect.DeepEqual(badValues, map[string][]byte{"PLAIN": []byte("defective")}) {
		t.Fatal("independent complete-byte/consumer check did not detect the encoder defect")
	}
	aliasDirectory := nativeExtensionCopyExample(t, "local-value-output")
	var aliasDescriptor artifact.Descriptor
	nativeGeneratedReadJSON(t, filepath.Join(aliasDirectory, "plugin.json"), &aliasDescriptor)
	aliasDescriptor.Name, aliasDescriptor.Version = "private-local-values-alias", "0.2.0"
	nativeGeneratedWriteJSON(t, filepath.Join(aliasDirectory, "plugin.json"), aliasDescriptor)
	alias, aliasMetadata := nativeExtensionBuildAuthor(t, aliasDirectory)
	originalOutput := builds[slices.IndexFunc(builds, func(v artifact.LocalPlugin) bool { return v.Name == "private-local-values" })]
	originalMetadata, err := artifact.VerifyBuild(t.Context(), originalOutput.Directory)
	if err != nil || originalMetadata.Executable == aliasMetadata.Executable {
		t.Fatal("output alias must be a distinct actual build", err)
	}
	f.plugins = newNativePluginFixture(t, append(slices.Clone(builds), alias)...)
	homes = append(homes, f.plugins.home)
	destinations := f.source["outputs"].(map[string]any)["destinations"].(map[string]any)
	destinations["alias"] = map[string]any{"plugin": "private-local-values-alias", "settings": map[string]any{"endpoint": f.server.URL, "namespace": "extension"}}
	f.source["outputs"].(map[string]any)["routing"] = map[string]any{"default": []string{"alias", "vault"}}
	nativeGeneratedWriteJSON(t, f.path, f.source)
	beforeCollision, _, _ := f.selected(t)
	// Public comparison preserves the complete source-validation diagnostics.
	// Apply intentionally reduces this normalization failure to its common refusal.
	collisionPlan := f.run(t, "reader", true, nil, "plan", "--trusted", f.path, "--trusted-format", "json", "--json")
	for _, event := range collisionPlan.capture.Events {
		if event.Kind == "http-start" || event.Kind == "store-result" || event.Kind == "plaintext" || event.Kind == "recovery-plaintext" || event.Kind == "recipient-plaintext" || strings.HasPrefix(event.Kind, "generator-") {
			t.Fatal("source-only collision validation entered provider or private custody work")
		}
	}
	var collisionResult struct {
		Schema   string
		State    string                       `json:"state_result"`
		Identity struct{ Stage, Code string } `json:"request_identity"`
		Payload  struct {
			Schema      string
			Complete    bool `json:"diagnostics_complete"`
			Diagnostics []struct {
				Subject         map[string]string
				Path            []struct{ Field string }
				Outcome, Reason string
			}
		}
	}
	decodedCollision := json.Unmarshal(collisionPlan.out, &collisionResult) == nil
	t.Logf("collision comparison boundary: decoded=%t exit=%d parse=%t public_configuration=%t installation=%t invalid_input=%t duplicate_key=%t diagnostics=%d", decodedCollision, collisionPlan.code, collisionResult.Identity.Stage == "parse", collisionResult.Identity.Stage == "public-configuration", collisionResult.Identity.Stage == "installation", collisionResult.Identity.Code == "invalid-input", collisionResult.Identity.Code == "duplicate-key", len(collisionResult.Payload.Diagnostics))
	for i, row := range collisionResult.Payload.Diagnostics[:min(4, len(collisionResult.Payload.Diagnostics))] {
		fields := make([]string, 0, min(4, len(row.Path)))
		for _, part := range row.Path[:min(4, len(row.Path))] {
			field := "other"
			switch part.Field {
			case "presence", "canonical_target", "destination", "targets", "generated", "source", "provider", "encodings":
				field = part.Field
			}
			fields = append(fields, field)
		}
		t.Logf("collision returned diagnostic[%d]: configuration=%t target=%t binding=%t entry=%t vault=%t alias=%t plain=%t token=%t unable=%t duplicate=%t invalid_input=%t invalid_combination=%t unresolved=%t unavailable=%t unsupported=%t path=%v", i, row.Subject["kind"] == "configuration", row.Subject["kind"] == "output_target", row.Subject["kind"] == "output_binding", row.Subject["kind"] == "entry", row.Subject["destination_id"] == "vault", row.Subject["destination_id"] == "alias", row.Subject["name"] == "PLAIN", row.Subject["name"] == "TOKEN", row.Outcome == "unable to verify", row.Reason == "duplicate-key", row.Reason == "invalid-input", row.Reason == "invalid-field-combination", row.Reason == "unresolved-reference", row.Reason == "source-unavailable" || row.Reason == "required-public-fact-unavailable", row.Reason == "unsupported-profile" || row.Reason == "unsupported-schema", fields)
	}
	if !decodedCollision || collisionPlan.code != 2 || collisionResult.Schema != "ProductResult/v1" || collisionResult.State != "refused" || collisionResult.Payload.Schema != "ComparisonPayload/v1" || !collisionResult.Payload.Complete || len(collisionResult.Payload.Diagnostics) != 2 {
		t.Logf("collision comparison facts: decoded=%t exit=%d schema=%t refused=%t comparison=%t complete=%t diagnostics=%d", decodedCollision, collisionPlan.code, collisionResult.Schema == "ProductResult/v1", collisionResult.State == "refused", collisionResult.Payload.Schema == "ComparisonPayload/v1", collisionResult.Payload.Complete, len(collisionResult.Payload.Diagnostics))
		t.Fatal("collision-specific public comparison diagnostic set differs")
	}
	for i, name := range []string{"PLAIN", "TOKEN"} {
		row := collisionResult.Payload.Diagnostics[i]
		if !reflect.DeepEqual(row.Subject, map[string]string{"kind": "output_target", "destination_id": "vault", "name": name}) || len(row.Path) != 1 || row.Path[0].Field != "canonical_target" || row.Outcome != "unable to verify" || row.Reason != "duplicate-key" {
			t.Logf("collision diagnostic[%d]: target=%t vault=%t expected_name=%t path_fields=%d unable=%t duplicate=%t", i, row.Subject["kind"] == "output_target", row.Subject["destination_id"] == "vault", row.Subject["name"] == name, len(row.Path), row.Outcome == "unable to verify", row.Reason == "duplicate-key")
			t.Fatal("refusal was not the exact semantic physical-target collision")
		}
	}
	collision := f.run(t, "apply", false, nil, "apply", "--source", f.path, "--source-format", "json", "--json")
	nativeExtensionGeneratedOutcome(t, collision, "refused", 2)
	afterCollision, _, _ := f.selected(t)
	if !reflect.DeepEqual(beforeCollision, afterCollision) || f.service.Counts() != (testservice.Counts{Tokens: 1, Values: 1, TokenCreates: 1, ValueCreates: 1}) {
		t.Fatal("output aliases escaped equal semantic physical-target collision")
	}
	for _, home := range homes {
		// Keep the root owned by nativeGeneratedPrivateDirectory's cleanup.
		if err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		}); err != nil {
			t.Fatal("make old installation contents removable", err)
		}
		members, err := os.ReadDir(home)
		if err != nil {
			t.Fatal(err)
		}
		for _, member := range members {
			if err := os.RemoveAll(filepath.Join(home, member.Name())); err != nil {
				t.Fatal("remove test-owned old installation contents", err)
			}
		}
	}
	oldSource := f.path
	if err := os.RemoveAll(filepath.Dir(oldSource)); err != nil {
		t.Fatal("remove test-owned old source pair", err)
	}
	if _, err := os.Lstat(oldSource); !os.IsNotExist(err) {
		t.Fatal("complete-loss test retained its old editable source")
	}
	f.path = filepath.Join(t.TempDir(), "recovered.json")
	emptyHome := nativeGeneratedPrivateDirectory(t)
	emptyConfig := filepath.Join(emptyHome, ".config")
	if err := os.Mkdir(emptyConfig, 0700); err != nil {
		t.Fatal(err)
	}
	emptyEnvironment := []string{"HOME=" + emptyHome, "XDG_CONFIG_HOME=" + emptyConfig}
	wantSecret := []byte("\x00\xffextension/consumer/t1")
	secretHash := sha256.Sum256(wantSecret)
	_, recoveryObject := workflowHead(t, f.store)
	prepared := workflowRunEnvironment(t, f.store, cli, "authority", observer.Policy{ExpectedSHA256: map[string]string{"TOKEN": hex.EncodeToString(secretHash[:])}}, nil, emptyEnvironment, nativePrepareArgs(f.store, f.path, "private-restored", "--normal-signing-key", f.store.selector(1))...)
	f.children = append(f.children, prepared)
	preparation := nativePrepareDecode(t, prepared, "reconstruction", false)
	nativePrepareReadOnly(t, prepared)
	if !nativeMaximumPlaintext(prepared.capture, map[string]string{"TOKEN": hex.EncodeToString(secretHash[:])}) {
		t.Fatal("complete private recovery lost its exact generated plaintext verification")
	}
	if preparation.Recovery.Head != workflowDigest(recoveryObject.body) || len(preparation.Dependencies.Requirements) != 2 || len(preparation.Dependencies.Installations) != 0 {
		t.Fatal("complete private recovery changed selected HEAD or invented installation")
	}
	contracts := map[string]struct {
		contract string
		version  uint32
		subject  uint16
	}{
		"generator": {"0280ab3c4fbe2f8279f592344001095c9509d7ebd749f01be042e138b1033d2f", 5, 1},
		"output":    {"local-values-config/v1", 6, 0},
	}
	for _, row := range preparation.Dependencies.Requirements {
		want, exists := contracts[row.Role]
		if !exists || row.Contract != want.contract || row.ProtocolVersion != want.version || row.Plugin != nil || row.Artifact != nil || row.Status != "missing" || row.Reason != "selection-required" || len(row.Subjects) != 1 || row.Subjects[0] != want.subject {
			t.Logf("recovered dependency facts: expected_role=%t contract=%t protocol=%d selection_absent=%t artifact_absent=%t missing=%t selection_required=%t subjects=%v", exists, row.Contract == want.contract, row.ProtocolVersion, row.Plugin == nil, row.Artifact == nil, row.Status == "missing", row.Reason == "selection-required", row.Subjects)
			t.Fatal("complete private recovery lost its exact unselected dependency")
		}
		delete(contracts, row.Role)
	}
	if len(contracts) != 0 {
		t.Fatal("complete private recovery omitted an effect dependency")
	}
	captured, err := configuration.Capture(t.Context(), f.path, configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if captured != nil {
			if err := captured.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	model, err := configuration.Parse(t.Context(), captured)
	if err != nil || !model.Resolved || len(model.Plugins) != 0 || len(model.Entries) != 2 || len(model.Outputs) != 1 {
		if model != nil {
			t.Logf("recovered source facts: parsed=%t resolved=%t plugins=%d entries=%d outputs=%d", err == nil, model.Resolved, len(model.Plugins), len(model.Entries), len(model.Outputs))
		}
		t.Fatal("complete private recovery lost its exact source shape", err)
	}
	canonicalSettings := []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"extension","subject":"consumer"}`, f.server.URL))
	configID, err := hex.DecodeString("0280ab3c4fbe2f8279f592344001095c9509d7ebd749f01be042e138b1033d2f")
	if err != nil {
		t.Fatal(err)
	}
	resourceID := sha256.Sum256([]byte("example/local-token-resource/v1"))
	wantIntent := append([]byte{0, 1}, configID...)
	wantIntent = append(wantIntent, 2)
	wantIntent = append(wantIntent, resourceID[:]...)
	wantIntent = binary.BigEndian.AppendUint32(wantIntent, uint32(len(canonicalSettings)))
	wantIntent = append(wantIntent, canonicalSettings...)
	for _, entry := range model.Entries {
		switch entry.Name {
		case "TOKEN":
			if entry.Generated == nil || entry.Generated.Plugin != "" || entry.Generated.Settings != nil || entry.Generated.Epoch != 0 || entry.Generated.Retirement != "manual" || !bytes.Equal(entry.Generated.Intent, wantIntent) {
				if entry.Generated != nil {
					t.Logf("recovered generator facts: selection_absent=%t ordinary_settings_absent=%t epoch=%d manual=%t exact_intent=%t intent_bytes=%d expected_bytes=%d", entry.Generated.Plugin == "", entry.Generated.Settings == nil, entry.Generated.Epoch, entry.Generated.Retirement == "manual", bytes.Equal(entry.Generated.Intent, wantIntent), len(entry.Generated.Intent), len(wantIntent))
				}
				t.Fatal("recovery changed exact canonical generator bytes or added a plugin")
			}
		case "PLAIN":
			if entry.Secret || entry.Generated != nil || !bytes.Equal(entry.Plain, []byte("public #selected")) {
				t.Fatal("recovery changed the exact plain entry")
			}
		default:
			t.Fatal("recovery substituted an entry name")
		}
	}
	output := model.Outputs[0]
	if output.Plugin != "" || output.Settings != nil || output.DestinationID != "vault" || output.Binding.Destination.ConfigContractID != "local-values-config/v1" || output.Binding.Destination.ServiceContractID != "local-values-service/v1" || !bytes.Equal(output.Binding.Destination.CanonicalSettings, []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"extension"}`, f.server.URL))) || output.Binding.Destination.Capabilities != 22 || output.Binding.Destination.Policy.ContractID != "" || len(output.Binding.Destination.Policy.Data) != 0 || len(output.Binding.Targets) != 2 {
		t.Logf("recovered output facts: selection_absent=%t ordinary_settings_absent=%t vault=%t config=%t service=%t capabilities=%d policy_absent=%t targets=%d", output.Plugin == "", output.Settings == nil, output.DestinationID == "vault", output.Binding.Destination.ConfigContractID == "local-values-config/v1", output.Binding.Destination.ServiceContractID == "local-values-service/v1", output.Binding.Destination.Capabilities, output.Binding.Destination.Policy.ContractID == "" && len(output.Binding.Destination.Policy.Data) == 0, len(output.Binding.Targets))
		t.Fatal("recovery changed complete canonical output settings or invented selection")
	}
	if !reflect.DeepEqual(model.Routes, []configuration.Route{{Default: true, Destinations: []string{"vault"}}}) || len(model.Public.Groups.Value) != 0 {
		t.Fatal("recovery changed the complete routing, groups or default encoding")
	}
	for _, row := range output.Binding.Targets {
		key := base64.RawURLEncoding.EncodeToString([]byte(row.Name))
		physical := f.server.URL + "/values/extension/" + key
		want := contract.OutputTarget{ServiceContractID: "local-values-service/v1", TargetContractID: "local-values-target/v1", CanonicalTarget: physical, ConsumerLocator: physical, TargetData: []byte(fmt.Sprintf(`{"endpoint":%q,"namespace":"extension","key":%q}`, f.server.URL, key)), PayloadEncoding: 1, Capabilities: contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}}
		actual := row.Target
		policyAbsent := actual.Policy.ContractID == "" && len(actual.Policy.Data) == 0
		// An absent policy has no semantic distinction between nil and empty backing.
		if policyAbsent {
			actual.Policy = contract.OutputPolicy{}
		}
		if row.Name != "PLAIN" && row.Name != "TOKEN" || !policyAbsent || !reflect.DeepEqual(actual, want) {
			t.Logf("recovered target facts: expected_name=%t service=%t contract=%t physical=%t locator=%t exact_data=%t raw=%t capabilities=%d create_bounds=%t write_bounds=%t source_incarnation_absent=%t policy_absent=%t", row.Name == "PLAIN" || row.Name == "TOKEN", actual.ServiceContractID == want.ServiceContractID, actual.TargetContractID == want.TargetContractID, actual.CanonicalTarget == want.CanonicalTarget, actual.ConsumerLocator == want.ConsumerLocator, bytes.Equal(actual.TargetData, want.TargetData), actual.PayloadEncoding == 1, actual.Capabilities, actual.CreateValueBounds == want.CreateValueBounds, actual.WriteValueBounds == want.WriteValueBounds, actual.EntryIncarnationID.IsZero(), policyAbsent)
			t.Fatal("recovery changed an exact source-ready output target")
		}
	}
	if f.service.Counts() != (testservice.Counts{Tokens: 1, Values: 1, TokenCreates: 1, ValueCreates: 1}) {
		t.Fatal("recovery or passive manifest/collision checks changed a service resource")
	}
	if err := captured.Close(); err != nil {
		t.Fatal(err)
	}
	captured = nil
	f.plugins = newNativePluginFixture(t, builds...)
	nativeGeneratedReadJSON(t, f.path, &f.source)
	f.source["entries"] = map[string]any{}
	f.source["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
	generatedPath := filepath.Join(filepath.Dir(f.path), f.source["generated"].(string))
	var generated map[string]any
	nativeGeneratedReadJSON(t, generatedPath, &generated)
	delete(generated, "canonical_records")
	nativeGeneratedWriteJSON(t, generatedPath, generated)
	nativeGeneratedWriteJSON(t, f.path, f.source)
	removed := nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, nil, "apply", "--source", f.path, "--source-format", "json", "--retire-generator", "TOKEN=private-local-token", "--json"), "retirement-pending", 3)
	if len(removed.Duties) != 1 {
		t.Fatal("recovered private cleanup did not retain exact retirement")
	}
	f.retire(t, credential, removed.Duties[0].Facts.DutyID)
	deleted := f.run(t, "apply", false, credential, "publish", "--source", f.path, "--source-format", "json", "--delete-coordinate", coordinate+"=private-local-values", "--json")
	var deletion nativePublicationOutput
	if json.Unmarshal(deleted.out, &deletion) != nil || deleted.code != 0 || deletion.State != "success" || f.service.Counts() != (testservice.Counts{TokenCreates: 1, TokenRetires: 1, ValueCreates: 1, ValueDeletes: 1}) {
		nativeExtensionPublicationFailure(t, deleted, deletion)
		t.Fatal("recovered private cleanup did not dispose the exact known resources")
	}
	f.finish(t, 12, "consumer/t1")
}
