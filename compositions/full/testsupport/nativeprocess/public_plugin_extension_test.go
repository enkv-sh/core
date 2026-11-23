package nativeprocess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact"
	artifactbuild "enkv.sh/sdk/artifact/build"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/examples/ini-reference-manifest/consumer"
	"enkv.sh/sdk/examples/testservice"
)

// full_only: false
func TestPublicNativeUnknownPluginsGeneratePublishAndRenderWithUnchangedCLI(t *testing.T) {
	cli, _ := workflowBuildExecutables(t, false)
	before, err := artifact.ExecutableIdentity(t.Context(), cli)
	if err != nil {
		t.Fatal(err)
	}
	nativeExtensionCLIClosure(t, cli)
	root := nativeRepository(t)
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GCCGO", "CC", "CXX", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS", "GOTOOLDIR", "GOCACHEPROG", "GOFIPS140", "GODEBUG"} {
		t.Setenv(key, "")
	}
	var renderer artifact.Digest
	var builds []artifact.LocalPlugin
	var declared []string
	for _, example := range []struct{ directory, family, testDependency string }{
		{"local-token-generator", "generator", "sdk/examples/testservice"},
		{"local-value-output", "output", "sdk/examples/testservice"},
		{"ini-reference-manifest", "manifest-generator", ""},
	} {
		directory := nativeGeneratedSourcePath(root, "sdk/examples/"+example.directory)
		descriptor, _, err := artifact.ReadDescriptor(t.Context(), filepath.Join(directory, "plugin.json"))
		if err != nil || descriptor.Role != example.family {
			t.Fatal("independent example descriptor differs", example.directory, err)
		}
		owners := []string{directory, nativeGeneratedSourcePath(root, "sdk/artifact"), nativeGeneratedSourcePath(root, "sdk/"+example.family), nativeGeneratedSourcePath(root, "protocols/"+example.family)}
		if example.testDependency != "" {
			owners = append(owners, nativeGeneratedSourcePath(root, example.testDependency))
		}
		workspace := nativePluginWorkspace(t, owners)
		output := filepath.Join(nativeGeneratedPrivateDirectory(t), "build")
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
		marker, err := artifactbuild.Run(ctx, artifactbuild.Config{Directory: directory, Descriptor: "plugin.json", Command: ".", Output: output, Workspace: workspace})
		cancel()
		if err != nil {
			t.Fatal("independent example build failed", example.directory, err)
		}
		metadata, err := artifact.VerifyBuild(t.Context(), output)
		if err != nil || metadata.Role != example.family || metadata.Name != descriptor.Name {
			t.Fatal("independent example build differs", err)
		}
		identity, err := metadata.Identity()
		if err != nil || identity != marker.Artifact {
			t.Fatal("independent example artifact differs", err)
		}
		if example.family == "manifest-generator" {
			renderer = identity
		}
		var encodedRoute []byte
		if descriptor.Generator != nil {
			encodedRoute = descriptor.Generator.CredentialRoute
		}
		if descriptor.Output != nil {
			encodedRoute = descriptor.Output.CredentialRoute
		}
		if encodedRoute != nil {
			route, err := credentialroute.Decode(encodedRoute)
			if err != nil {
				t.Fatal(err)
			}
			declared = append(declared, route.Names...)
		}
		builds = append(builds, artifact.LocalPlugin{Name: descriptor.Name, Directory: output})
		t.Logf("independent example role=%s name=%s artifact=%s executable=%s", metadata.Role, metadata.Name, marker.Artifact, metadata.Executable.SHA256)
	}
	t.Run("generate-publish-render-retire", func(t *testing.T) {
		nativeExtensionLifecycle(t, cli, builds, declared, renderer)
	})
	t.Run("generator-build-continuity", func(t *testing.T) {
		nativeExtensionGeneratorContinuity(t, cli, builds)
	})
	t.Run("recovery-service-filter-and-collision", func(t *testing.T) {
		nativeExtensionRecoveryAndFiltering(t, cli, builds, renderer)
	})
	t.Run("lost-output-reply", func(t *testing.T) {
		nativeExtensionLostOutput(t, cli, builds)
	})
	t.Run("lost-generator-reply", func(t *testing.T) {
		nativeExtensionLostGenerator(t, cli, builds)
	})
	after, err := artifact.ExecutableIdentity(t.Context(), cli)
	if err != nil || before != after {
		t.Fatal("new plugin service or format behavior changed the captured CLI", err)
	}
	t.Logf("unchanged CLI executable=%s length=%d; controlled Store/KMS fixture only", before.SHA256, before.Length)
}

func nativeExtensionLifecycle(t *testing.T, cli string, builds []artifact.LocalPlugin, declared []string, renderer artifact.Digest) {
	plugins := newNativePluginFixture(t, builds...)
	const bearer = "local-extension-private-credential"
	service, err := testservice.New(testservice.Config{Token: bearer, Namespace: "extension"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service)
	t.Cleanup(func() {
		server.Close()
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	s := newWorkflowServer(t, "aws", false)
	s.childLimit, s.requestLimit, s.objectLimit = 8, 8*workflowChildRequestLimit, 512
	path := filepath.Join(t.TempDir(), "configuration.json")
	if err := os.WriteFile(path, workflowSetup(t, s, false), 0600); err != nil {
		t.Fatal(err)
	}
	var children []workflowChild
	run := func(phase string, readOnly bool, args ...string) workflowChild {
		t.Helper()
		environment := append(plugins.Environment(t, path), "ENKV_EXAMPLE_TOKEN="+bearer)
		child := workflowRunDeclaredEnvironment(t, s, cli, phase, observer.Policy{NoKMS: readOnly}, nil, environment, declared, args...)
		children = append(children, child)
		if bytes.Contains(child.out, []byte(bearer)) || bytes.Contains(child.diagnostic, []byte(bearer)) {
			t.Fatal("plugin credential reached public process output")
		}
		return child
	}
	initialized := run("init", false, "init", "--source", path, "--source-format", "json", "--json")
	workflowResult(t, initialized, "success")
	pair := workflowReadPair(t, path)
	var source map[string]any
	nativeGeneratedReadJSON(t, path, &source)
	source["entries"] = map[string]any{
		"PLAIN": map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": "public #selected"}},
		"TOKEN": map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "generated", "plugin": "private-local-token", "settings": map[string]any{"endpoint": server.URL + "/", "namespace": " Extension ", "subject": "consumer"}, "epoch": 0, "retirement": "auto"}},
	}
	source["outputs"] = map[string]any{"destinations": map[string]any{"vault": map[string]any{"plugin": "private-local-values", "settings": map[string]any{"endpoint": server.URL + "/", "namespace": "extension"}}}, "routing": map[string]any{"default": []string{"vault"}}}
	nativeGeneratedWriteJSON(t, path, source)
	applied := run("apply", false, "apply", "--source", path, "--source-format", "json", "--json")
	workflowResult(t, applied, "success")
	if counts := service.Counts(); counts != (testservice.Counts{Tokens: 1, TokenCreates: 1}) {
		t.Fatal("generated creation did not make exactly one owned local token", counts)
	}
	published := run("apply", false, "publish", "--source", path, "--source-format", "json", "--name", "TOKEN", "--json")
	var publication nativePublicationOutput
	publicationDecodeErr := json.Unmarshal(published.out, &publication)
	if published.code != 0 || publicationDecodeErr != nil || publication.Schema != "ProductResult/v1" || publication.Operation != "publish" || publication.Replay != "none" || publication.State != "success" || publication.Summary != "output-complete" || len(publication.Payload.Entries) != 1 || len(publication.Payload.Entries[0].Actions) != 1 {
		nativeExtensionPublicationFailure(t, published, publication)
		t.Logf("local service resource observations: %+v", service.Counts())
		t.Fatal("unknown output did not publish one selected secret", published.code, published.summary)
	}
	action := publication.Payload.Entries[0].Actions[0]
	if action.Action == nil || *action.Action != "create-with-value" || action.Disposition != "acknowledged" || action.Evidence == nil || action.Evidence.Resource != "v1" {
		t.Fatal("unknown output lost exact acknowledged creation")
	}
	if counts := service.Counts(); counts != (testservice.Counts{Tokens: 1, Values: 1, TokenCreates: 1, ValueCreates: 1}) {
		t.Fatal("publication did not make exactly one local value", counts)
	}
	// The service derives the binary value from namespace, subject and token ID.
	// This independent literal does not call either plugin's implementation.
	secret := append([]byte{0, 255}, []byte("extension/consumer/t1")...)
	defer clear(secret)
	locator := server.URL + "/values/extension/VE9LRU4"
	coordinateInput := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), pair.descriptor.DomainID[:]...)
	for _, field := range []string{"local-values-service/v1", locator} {
		coordinateInput = binary.BigEndian.AppendUint32(coordinateInput, uint32(len(field)))
		coordinateInput = append(coordinateInput, field...)
	}
	if publication.Payload.Entries[0].Coordinate != workflowDigest(coordinateInput) {
		t.Fatal("unknown output coordinate differs from its semantic service and physical target")
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, locator, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	value, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
	closeErr := response.Body.Close()
	matched := response.StatusCode == http.StatusOK && readErr == nil && closeErr == nil && bytes.Equal(value, secret)
	clear(value)
	if !matched {
		t.Fatal("independent service consumer did not receive the exact generated binary value")
	}
	head, _ := workflowHead(t, s)
	selected := workflowRoot(t, s, head)
	expected := nativeExtensionExpectedINI(t, s, selected, head, pair.descriptor.AuthorityRecipientID, server.URL, locator)
	images := nativePublicationImages(t, path, filepath.Join(filepath.Dir(path), pair.reference))
	destination := filepath.Join(t.TempDir(), "reference.ini")
	rendered := run("reader", true, "manifest", "--source", path, "--source-format", "json", "--out", destination, "--plugin", "workshop-ini", "--settings", `{"section_prefix":"client"}`, "--json")
	workflowGETOnly(t, rendered)
	nativeExtensionManifest(t, rendered, destination, expected, locator, renderer)
	nativePublicationUnchanged(t, images)
	source["entries"] = map[string]any{}
	source["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
	nativeGeneratedWriteJSON(t, path, source)
	removed := run("apply", false, "apply", "--source", path, "--source-format", "json", "--retire-generator", "TOKEN=private-local-token", "--log-level", "info", "--json")
	pending := nativeExtensionGeneratedOutcome(t, removed, "retirement-pending", 3)
	if pending.Canonical != "selected" || pending.EffectSummary != "effect-no-change" || len(pending.Effects) != 0 || len(pending.Duties) != 1 || len(pending.Hazards) != 0 {
		t.Fatal("removal did not select exactly one pending retirement without another effect")
	}
	duty := pending.Duties[0]
	if duty.Facts.Kind != "retirement" || duty.Facts.Status != "not-started" || duty.Facts.Step != 1 || duty.Facts.Completion != "deletion-acknowledged" || len(duty.Target.ResourceDigest) != 64 {
		t.Fatal("removal did not retain the exact unstarted acknowledged-retirement duty")
	}
	removedHead, _ := workflowHead(t, s)
	removedRoot := workflowRoot(t, s, removedHead)
	if len(removedRoot.Names) != 0 || removedRoot.ValueEntryCount != 0 || removedRoot.SecretCount != 0 || removedRoot.Generated.GeneratedCurrent != 0 || removedRoot.Generated.Duties != 1 || removedRoot.Generated.Retiring != 1 || removedRoot.Generated.Hazards != 0 || !removedRoot.Generated.ActiveOwner.IsZero() || removedRoot.OutputConfiguration.BindingCount != 0 {
		t.Fatal("removal did not select canonical absence with only its exact retirement remaining")
	}
	var selectedDuties []contract.GeneratedDutyRecord
	for _, ref := range removedRoot.RequiredSupport {
		key, err := stateformat.Key(s.prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.InspectRequiredSupportPage(s.object(t, key).body)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range page.Records {
			if record.Kind != contract.GeneratedDutySupportKind {
				continue
			}
			selectedDuty, err := contract.InspectGeneratedDutyRecord(record.Body)
			if err != nil || selectedDuty.DutyID != record.RecordID {
				t.Fatal("selected retirement duty is invalid", err)
			}
			selectedDuties = append(selectedDuties, selectedDuty)
		}
	}
	if len(selectedDuties) != 1 || hex.EncodeToString(selectedDuties[0].DutyID[:]) != duty.Facts.DutyID || selectedDuties[0].Kind != contract.GeneratedDutyRetirement || selectedDuties[0].Status != contract.GeneratedEffectNotStarted || selectedDuties[0].Step != 1 || selectedDuties[0].CompletionClass != contract.GeneratedCompletionAcknowledged || hex.EncodeToString(selectedDuties[0].ResourceID[:]) != duty.Facts.ResourceID {
		t.Fatal("public pending retirement differs from its exact selected duty")
	}
	removalBytes, err := hex.DecodeString(pending.Receipt)
	if err != nil {
		t.Fatal("removal receipt encoding differs")
	}
	removalReceipt, err := contract.InspectCompactMutationReceipt(removalBytes)
	if err != nil || removalReceipt.OperationKind != contract.OperationApplyDeclaration || removalReceipt.StateResult != contract.ReceiptStateRetirementPending || removalReceipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || removalReceipt.EffectSummary != contract.ReceiptEffectNoChange || removalReceipt.EvidenceCeiling != contract.ReceiptEvidenceCanonical || removalReceipt.SummaryCounts[contract.ReceiptDutyCount] != 1 || removalReceipt.SummaryCounts[contract.ReceiptEffectCount] != 0 || removalReceipt.SummaryCounts[contract.ReceiptHazardCount] != 0 || removalReceipt.PredecessorRevisionID != head.Core.Revision || removalReceipt.RequestedRevisionID != removedHead.Core.Revision || removalReceipt.ObservedRevisionID != removedHead.Core.Revision || hex.EncodeToString(removalReceipt.OperationID[:]) != pending.Operation {
		t.Fatal("removal receipt did not retain the exact selected absence and pending duty", err)
	}
	if counts := service.Counts(); counts != (testservice.Counts{Tokens: 1, Values: 1, TokenCreates: 1, ValueCreates: 1}) {
		t.Fatal("canonical removal changed a remote resource before explicit retirement", counts)
	}
	s.gcListPrefix = s.prefix + "/" + nativeExtensionID(selected.Domain) + "/result/"
	retirement := run("apply", false, "generated", "retire", "--source", path, "--source-format", "json", "--duty", duty.Facts.DutyID, "--log-level", "info", "--json")
	retired := nativeExtensionGeneratedOutcome(t, retirement, "success", 0)
	if retired.Canonical != "selected" || retired.EffectSummary != "effect-complete" || len(retired.Effects) != 1 || len(retired.Duties) != 0 || len(retired.Hazards) != 0 {
		t.Fatal("exact generated retirement did not complete without remaining owned work")
	}
	effect := retired.Effects[0]
	if effect.Facts.DutyID != "" || effect.Facts.Action != "delete" || effect.Facts.State != "succeeded" || effect.Facts.Completion != "deletion-acknowledged" || effect.Target.ResourceDigest != duty.Target.ResourceDigest || effect.Target.ResourceID != hex.EncodeToString(selectedDuties[0].ResourceID[:]) || effect.Target.OriginalOperationID != hex.EncodeToString(selectedDuties[0].OriginalOperationID[:]) || effect.Target.OriginalAttemptID != hex.EncodeToString(selectedDuties[0].OriginalAttemptID[:]) {
		t.Fatal("generated retirement did not acknowledge the exact removed resource")
	}
	retirementReceipt := workflowReceipt(t, retired.Receipt, contract.OperationRetireGeneratedGeneration)
	if retirementReceipt.EvidenceCeiling != contract.ReceiptEvidenceAcknowledged || retirementReceipt.AcknowledgedCount != 1 || retirementReceipt.ConfirmedCount != 0 || retirementReceipt.SummaryCounts[contract.ReceiptEffectCount] != 1 || retirementReceipt.SummaryCounts[contract.ReceiptDutyCount] != 0 || retirementReceipt.SummaryCounts[contract.ReceiptHazardCount] != 0 || retirementReceipt.WarningBits&contract.ReceiptWarningInvalidationNotConfirmed == 0 {
		t.Fatal("retirement receipt lost its exact acknowledgement ceiling or retained work")
	}
	retiredHead, _ := workflowHead(t, s)
	retiredRoot := workflowRoot(t, s, retiredHead)
	if len(retiredRoot.Names) != 0 || retiredRoot.Generated.GeneratedCurrent != 0 || retiredRoot.Generated.Duties != 0 || retiredRoot.Generated.Retiring != 0 || retiredRoot.Generated.Hazards != 0 || !retiredRoot.Generated.ActiveOwner.IsZero() {
		t.Fatal("generated retirement left current values or owned generated work")
	}
	if counts := service.Counts(); counts != (testservice.Counts{Values: 1, TokenCreates: 1, TokenRetires: 1, ValueCreates: 1}) {
		t.Fatal("explicit generated retirement changed the exact service resource set", counts)
	}
	deleted := run("apply", false, "publish", "--source", path, "--source-format", "json", "--delete-coordinate", publication.Payload.Entries[0].Coordinate+"=private-local-values", "--json")
	var deletion nativePublicationOutput
	deletionDecodeErr := json.Unmarshal(deleted.out, &deletion)
	if deleted.code != 0 || deletionDecodeErr != nil || deletion.State != "success" || deletion.Summary != "output-complete" || len(deletion.Payload.Entries) != 1 || deletion.Payload.Entries[0].Coordinate != publication.Payload.Entries[0].Coordinate || len(deletion.Payload.Entries[0].Actions) != 1 {
		nativeExtensionPublicationFailure(t, deleted, deletion)
		t.Logf("local service resource observations: %+v", service.Counts())
		t.Fatal("removed binding did not delete its exact owned coordinate", deleted.code, deleted.summary)
	}
	deletionAction := deletion.Payload.Entries[0].Actions[0]
	if deletionAction.Action == nil || *deletionAction.Action != "delete-owned" || deletionAction.Disposition != "acknowledged" {
		t.Fatal("owned output cleanup was not acknowledged")
	}
	if counts := service.Counts(); counts != (testservice.Counts{TokenCreates: 1, TokenRetires: 1, ValueCreates: 1, ValueDeletes: 1}) {
		t.Fatal("required plugin resource cleanup differs", counts)
	}
	for _, child := range children {
		for _, private := range [][]byte{secret, []byte(base64.StdEncoding.EncodeToString(secret))} {
			if bytes.Contains(child.out, private) || bytes.Contains(child.diagnostic, private) {
				t.Fatal("private generated value reached public result facts")
			}
		}
	}
	nativeMaterializationJoined(t, children, 7)
}

func nativeExtensionGeneratedOutcome(t *testing.T, child workflowChild, state string, code int) nativeGeneratedOutput {
	t.Helper()
	var result nativeGeneratedOutput
	err := json.Unmarshal(child.out, &result)
	if err != nil || result.Schema != "ProductResult/v1" || result.State != state || child.code != code {
		workflowCoreFailureTelemetry(t, child.diagnostic)
		var failure struct {
			Identity json.RawMessage `json:"request_identity"`
			Commit   bool            `json:"commit_may_have_occurred"`
			Reasons  []struct {
				Reason string `json:"reason"`
			} `json:"diagnostics"`
		}
		var identity struct{ Schema, Stage, Code string }
		decoded := json.Unmarshal(child.out, &failure) == nil
		preAdmission := decoded && json.Unmarshal(failure.Identity, &identity) == nil && identity.Schema == "PreAdmissionRequestIdentity/v1"
		stage := "other"
		switch identity.Stage {
		case "dispatch", "input", "context", "capture", "parse", "declaration", "construction", "resolution", "observation", "installation", "initialize", "apply", "compare", "rekey", "retire", "output", "local-cleanup":
			stage = identity.Stage
		}
		closedReason := func(value string) string {
			switch value {
			case "invalid-input", "unsupported-schema", "missing-required-field", "duplicate-key", "duplicate-member", "invalid-field-combination", "limit-exceeded", "unresolved-reference", "source-unavailable", "evidence-unavailable", "cancelled", "expired", "unsupported-apply-change", "trust-basis-invalid", "domain-basis-invalid", "store-basis-invalid", "required-public-fact-unavailable", "selected-relation-invalid", "selected-object-invalid", "selected-object-unavailable", "proof-invalid", "head-invalid", "read-contention", "diagnostics-incomplete":
				return value
			}
			return "other"
		}
		reasons := make([]string, 0, min(4, len(failure.Reasons)))
		for _, row := range failure.Reasons[:min(4, len(failure.Reasons))] {
			reasons = append(reasons, closedReason(row.Reason))
		}
		t.Logf("extension generated failure boundary: decoded=%t pre_admission=%t stage=%s code=%s commit_possible=%t diagnostics=%d reasons=%v effect_complete=%t diagnostic_delivery_incomplete=%t", decoded, preAdmission, stage, closedReason(identity.Code), failure.Commit, len(failure.Reasons), reasons, result.EffectSummary == "effect-complete", bytes.Contains(child.diagnostic, []byte("diagnostic delivery incomplete; retain the result on stdout\n")))
		t.Fatalf("extension generated result expected=%s/%d actual=%s/%d decoded=%t schema_valid=%t canonical_selected=%t receipt_present=%t effects=%d duties=%d hazards=%d", state, code, workflowSafeState(result.State), child.code, err == nil, result.Schema == "ProductResult/v1", result.Canonical == "selected", result.Receipt != "", len(result.Effects), len(result.Duties), len(result.Hazards))
	}
	return result
}

func nativeExtensionCLIClosure(t *testing.T, cli string) {
	t.Helper()
	root := nativeRepository(t)
	overlayPath := filepath.Join(filepath.Dir(cli), "overlay", "overlay.json")
	var overlay struct{ Replace map[string]string }
	nativeGeneratedReadJSON(t, overlayPath, &overlay)
	listed := nativeGeneratedGoCaptured(t, root, "compositions/full", cli+".mod", nativeGoArguments("list", "-mod=readonly", "-deps", "-json", "-tags=netgo", "-overlay="+overlayPath, "./cmd/enkv")...)
	decoder := json.NewDecoder(bytes.NewReader(listed))
	packages, files := 0, 0
	for {
		var p artifact.SourcePackage
		if err := decoder.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal("captured CLI compiler inputs unavailable", err)
		}
		packages++
		if strings.HasPrefix(p.ImportPath, "enkv.sh/plugins/") || strings.HasPrefix(p.ImportPath, "enkv.sh/sdk/examples/") {
			t.Fatal("captured CLI imports a concrete plugin or example", p.ImportPath)
		}
		if p.Standard {
			continue
		}
		for _, group := range [][]string{p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles, p.SFiles, p.SwigFiles, p.SwigCXXFiles, p.SysoFiles, p.EmbedFiles} {
			for _, name := range group {
				path := filepath.Join(p.Dir, name)
				if replacement, ok := overlay.Replace[path]; ok {
					path = replacement
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal("captured CLI source unavailable", path, err)
				}
				for _, identity := range []string{"private-local-token", "private-incompatible-token", "private-local-values", "private-local-values-alias", "workshop-ini", "workshop-ini-defective", "local-values-service/v1", "example/ini-reference/v1", "enkv.sh/sdk/examples/"} {
					if bytes.Contains(body, []byte(identity)) {
						t.Fatal("captured CLI source contains independent example admission or implementation", p.ImportPath, name)
					}
				}
				files++
			}
		}
	}
	if packages == 0 || files == 0 {
		t.Fatal("captured CLI compiler closure is empty")
	}
	t.Logf("captured CLI compiler closure excludes concrete plugins and independent examples: packages=%d module_files=%d overlay=%s", packages, files, overlayPath)
}

func nativeExtensionExpectedINI(t *testing.T, s *workflowServer, root stateformat.Root, head stateformat.Head, authority contract.ID, endpoint, locator string) string {
	t.Helper()
	// Read dynamic identities from the selected stored state, not the renderer.
	entries := make(map[string]contract.ValueEntry)
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
				entries[entry.Name] = *entry
			}
		}
	}
	if len(entries) != 2 || entries["PLAIN"].ConfidentialityClass != contract.Plain || entries["TOKEN"].ValueSource != contract.Generated {
		t.Fatal("selected entries differ from independent manifest fixture")
	}
	var parts []contract.OutputConfigurationSlice
	for _, ref := range root.RequiredSupport {
		key, err := stateformat.Key(s.prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.InspectRequiredSupportPage(s.object(t, key).body)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range page.Records {
			if record.Kind != contract.OutputConfigurationSliceSupportKind {
				continue
			}
			part, err := contract.InspectOutputConfigurationSlice(record.Body)
			if err != nil {
				t.Fatal(err)
			}
			if part.ConfigurationDigest == root.OutputConfiguration.ConfigurationDigest {
				parts = append(parts, part)
			}
		}
	}
	slices.SortFunc(parts, func(a, b contract.OutputConfigurationSlice) int { return int(a.SliceIndex) - int(b.SliceIndex) })
	image, err := contract.JoinOutputConfiguration(root.Domain, root.OutputConfiguration, parts)
	if err != nil {
		t.Fatal(err)
	}
	configuration, _, err := contract.InspectOutputConfiguration(root.Domain, image)
	if err != nil || len(configuration.Bindings) != 1 || configuration.Bindings[0].DestinationID != "vault" {
		t.Fatal("selected output binding differs", err)
	}
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	b64 := func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }
	plain, token := entries["PLAIN"], entries["TOKEN"]
	targetData := fmt.Sprintf(`{"endpoint":%q,"namespace":"extension","key":"VE9LRU4"}`, endpoint)
	// Fixed grammar and public field values derive from the example's declared
	// INI format. Only selected state IDs and the loopback port vary per run.
	return fmt.Sprintf(`[client.manifest]
format="example/ini-reference/v1"
projection_schema="ENKV/CONSUMPTION-PROJECTION/v1"
config_contract="example/ini-reference-settings/v1"
settings_base64="eyJzZWN0aW9uX3ByZWZpeCI6ImNsaWVudCJ9"
domain_id="%s"
head_revision_id="%s"
snapshot_id="%s"
target_recipient_id="%s"
target_mode="current-authority"
entry_mode="all-authorized"
has_service_filter="false"
service_filter_base64=""
evidence_limit="authorized-input-and-exact-bytes"
included_count="2"
excluded_count="0"

[client.entry.0]
name_base64="UExBSU4="
incarnation_id="%s"
kind="plain"
value_base64="cHVibGljICNzZWxlY3RlZA=="

[client.entry.1]
name_base64="VE9LRU4="
incarnation_id="%s"
kind="secret"
destination_count="1"

[client.entry.1.destination.0]
destination_id_base64="dmF1bHQ="
binding_incarnation_id="%s"
entry_incarnation_id="%s"
service_contract_base64="bG9jYWwtdmFsdWVzLXNlcnZpY2UvdjE="
target_contract_base64="bG9jYWwtdmFsdWVzLXRhcmdldC92MQ=="
canonical_target_base64="%s"
consumer_locator_base64="%s"
target_data_base64="%s"
payload_encoding="raw"
policy_present="false"
policy_contract_base64=""
policy_digest=""
policy_data_base64=""

`, id(root.Domain), id(head.Core.Revision), id(root.Snapshot), id(authority), id(plain.Incarnation), id(token.Incarnation), id(configuration.Bindings[0].IncarnationID), id(token.Incarnation), b64(locator), b64(locator), b64(targetData))
}

func nativeExtensionManifest(t *testing.T, child workflowChild, path, expected, locator string, renderer artifact.Digest) {
	t.Helper()
	result, body := nativeExtensionManifestBytes(t, child, path, renderer)
	if string(body) != expected {
		t.Fatal("unknown manifest differs from complete independent INI bytes")
	}
	p := result.Issuance.Payload
	document, err := consumer.Read(bytes.NewReader(body))
	if err != nil || document.Prefix != "client" || len(document.Sections) != 4 {
		t.Fatal("independent INI consumer rejected the complete artifact", err)
	}
	if len(p.Included) != 2 || len(p.Excluded) != 0 || p.Included[0].Name != "PLAIN" || p.Included[1].Name != "TOKEN" || p.Included[0].ID != document.Sections["client.entry.0"]["incarnation_id"] || p.Included[1].ID != document.Sections["client.entry.1"]["incarnation_id"] {
		t.Fatal("manifest input-selection facts differ from selected entries")
	}
	values, err := document.PlainValues()
	if err != nil || !reflect.DeepEqual(values, map[string][]byte{"PLAIN": []byte("public #selected")}) {
		t.Fatal("independent INI consumer plain values differ", err)
	}
	references, err := document.References()
	if err != nil || len(references) != 1 || references[0].EntryName != "TOKEN" || references[0].DestinationID != "vault" || references[0].ServiceContract != "local-values-service/v1" || references[0].Locator != locator {
		t.Fatal("independent INI consumer reference set differs", err)
	}
}

func nativeExtensionPublicationFailure(t *testing.T, child workflowChild, result nativePublicationOutput) {
	t.Helper()
	closed := func(value string, admitted []string) string {
		if slices.Contains(admitted, value) {
			return value
		}
		return "other"
	}
	var reason struct {
		Code uint16 `json:"reason_code"`
	}
	resultDecodeErr := json.Unmarshal(child.out, &result)
	decoded := json.Unmarshal(child.out, &reason) == nil && resultDecodeErr == nil
	state := closed(result.State, []string{"success", "no-op", "refused", "contention", "unavailable", "positive-defect", "root-loss-unsupported", "commit-outcome-unknown", "snapshot-size-refusal", "effect-unknown", "effect-terminal-failure"})
	summary := closed(result.Summary, []string{"output-complete", "output-no-change", "output-unknown", "output-mixed-terminal", "output-failed"})
	t.Logf("publication failure boundary: decoded=%t schema_valid=%t state=%s summary=%s reason=%d entries=%d", decoded, result.Schema == "ProductResult/v1", state, summary, reason.Code, len(result.Payload.Entries))
	for index, target := range result.Payload.Entries[:min(3, len(result.Payload.Entries))] {
		t.Logf("publication target[%d]: coordinate_present=%t actions=%d", index, len(target.Coordinate) == 64, len(target.Actions))
		for at, row := range target.Actions[:min(3, len(target.Actions))] {
			action := "absent"
			if row.Action != nil {
				action = closed(*row.Action, []string{"create-empty", "create-with-value", "write-value", "update-policy", "delete-owned", "delete-reserved-slot"})
			}
			disposition := closed(row.Disposition, []string{"no-op", "not-sent", "acknowledged", "rejected", "unknown"})
			class, entry, status := "absent", "absent", uint16(0)
			if row.Evidence != nil {
				class = closed(row.Evidence.Class, []string{"unproved", "acknowledged", "qualified-no-effect"})
				entry = closed(row.Evidence.Entry, []string{"not-entered", "may-have-entered"})
				status = row.Evidence.Status
			}
			t.Logf("publication action[%d/%d]: action=%s disposition=%s reason=%d evidence_entry=%s evidence_class=%s normalized_status=%d blockers=%d remote_possible=%t late_risk=%t", index, at, action, disposition, row.Reason, entry, class, status, len(row.Blockers), row.Remote, row.Late)
		}
	}
}
