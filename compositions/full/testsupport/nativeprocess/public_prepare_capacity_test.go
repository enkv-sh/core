package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/generator"
)

func nativeMaximumIntentDigest(body []byte) contract.ID {
	preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/intent-v3\x00"), uint32(len(body)))
	preimage = append(preimage, body...)
	return contract.ID(sha256.Sum256(preimage))
}

func nativeMaximumPair(t *testing.T, path string, expected map[string][]byte) {
	t.Helper()
	pair, err := configuration.Capture(t.Context(), path, configuration.JSON)
	if err != nil {
		t.Fatal("maximum public pair capture refused", err)
	}
	defer func() {
		if err := pair.Close(); err != nil {
			t.Error(err)
		}
	}()
	model, err := configuration.Parse(t.Context(), pair)
	if err != nil {
		t.Fatal("maximum public pair parsing refused", err)
	}
	if !model.Resolved || len(model.Plugins) != 0 || len(model.Entries) != len(expected) || pair.Editable.Size()+pair.Generated.Size() > configuration.MaxPairBytes {
		t.Fatal("maximum pair lost current entries or exceeded source bytes")
	}
	total := 0
	for _, entry := range model.Entries {
		want, ok := expected[entry.Name]
		if !ok || entry.Generated == nil || !bytes.Equal(entry.Generated.Intent, want) || entry.Generated.Epoch != 0 || entry.Generated.Retirement != "manual" || entry.Generated.Plugin != "" || entry.Generated.Settings != nil {
			t.Fatal("maximum public pair changed exact installed intent", entry.Name)
		}
		intent, err := protocol.DecodeIntent(entry.Generated.Intent)
		if err != nil || intent.ConfigContractID.IsZero() || intent.LifecycleMode != protocol.LifecycleManaged || intent.ResourceContractID.IsZero() {
			t.Fatal("maximum recovered canonical intent lost its generic semantic contracts", err)
		}
		total += len(entry.Generated.Intent)
	}
	if total != 128*installedarchive.MaximumCloudflareIntentBytes {
		t.Fatal("maximum pair intent aggregate differs", total)
	}
	t.Logf("maximum public pair editable_bytes=%d generated_bytes=%d canonical_intent_bytes=%d entries=%d", pair.Editable.Size(), pair.Generated.Size(), total, len(model.Entries))
}

func nativeMaximumPlaintext(capture observer.Capture, expected map[string]string) bool {
	wanted := make(map[string]bool, len(expected))
	for name := range expected {
		sum := sha256.Sum256([]byte(name))
		wanted[hex.EncodeToString(sum[:])] = true
	}
	seen := make(map[string]bool, len(wanted))
	for _, event := range capture.Events {
		if event.Kind == "recovery-plaintext" {
			return false
		}
		if event.Kind != "plaintext" {
			continue
		}
		if event.Count != 1 || !event.Matched || !wanted[event.EntrySHA256] || seen[event.EntrySHA256] {
			return false
		}
		seen[event.EntrySHA256] = true
	}
	return len(seen) == len(wanted)
}

// full_only: false
func TestMaximumNativePlaintextEvidenceRequiresExactEntrySet(t *testing.T) {
	digest := sha256.Sum256([]byte("same expected synthetic value"))
	expected := map[string]string{"first": hex.EncodeToString(digest[:]), "second": hex.EncodeToString(digest[:])}
	event := func(name string) observer.Event {
		sum := sha256.Sum256([]byte(name))
		return observer.Event{Kind: "plaintext", Count: 1, Matched: true, EntrySHA256: hex.EncodeToString(sum[:])}
	}
	first, second := event("first"), event("second")
	for _, name := range []string{"complete", "reverse", "missing", "duplicate", "unknown", "malformed", "missing-identity", "unmatched", "wrong-count", "recovery"} {
		t.Run(name, func(t *testing.T) {
			events := []observer.Event{first, second}
			switch name {
			case "reverse":
				events = []observer.Event{second, first}
			case "missing":
				events = events[:1]
			case "duplicate":
				events[1] = first
			case "unknown":
				events[1] = event("other")
			case "malformed":
				events[1].EntrySHA256 = "invalid"
			case "missing-identity":
				events[1].EntrySHA256 = ""
			case "unmatched":
				events[1].Matched = false
			case "wrong-count":
				events[1].Count = 2
			case "recovery":
				events = append(events, observer.Event{Kind: "recovery-plaintext", Count: 1, Matched: true})
			}
			if nativeMaximumPlaintext(observer.Capture{Events: events}, expected) != (name == "complete" || name == "reverse") {
				t.Fatal("maximum plaintext evidence did not require the exact distinct entry set")
			}
		})
	}
}

// full_only: true
// Proves 128 maximum valid current intents from synthetic producer history;
// the generic Core 48 MiB proof has a different, opaque intent grammar.
func TestPublicNativePrepareMaximumCurrentIntents(t *testing.T) {
	started := time.Now()
	phaseStart := started
	t.Logf("maximum phase=setup event=begin since_start_ms=%d", phaseStart.Sub(started).Milliseconds())
	// Fix expected inputs and private test custody before archive loading.
	signer := testtrust.New(t, contract.AWS, contract.Hash([]byte("fixture/trust")))
	knownCustody := custody.New(t, contract.AWS, contract.Hash([]byte("independent maximum custody")), false, []contract.ID{contract.Hash([]byte("independent maximum authority"))})
	knownAuthority := knownCustody.Bindings()[0].Binding.SPKI
	expected := make(map[string][]byte, 128)
	hashes := make(map[string]string, 128)
	secretHash := sha256.Sum256([]byte(installedarchive.MaximumCloudflareSecret))
	const nameLength = 89
	for i := 0; i < 128; i++ {
		name := fmt.Sprintf("maximum-%03d", i) + strings.Repeat("x", 78)
		if len(name) != nameLength {
			t.Fatal("maximum expected name length differs")
		}
		intent, _ := installedarchive.MaximumCloudflareIntent(t, name)
		if len(intent) != installedarchive.MaximumCloudflareIntentBytes {
			t.Fatal("maximum expected intent byte account differs")
		}
		expected[name] = intent
		hashes[name] = hex.EncodeToString(secretHash[:])
	}
	archive := installedarchive.ReadMaximumIntentFixture(t, filepath.Join(nativeRepository(t), "crypto", "testsupport", "installedarchive", "testdata", "maximum-intents-aws.json.gz"))
	if archive.SignerSelector != signer.KeySelector() || !bytes.Equal(archive.SignerPublicKey, signer.PublicKey()) || !bytes.Equal(archive.AuthorityBinding.SPKI, knownAuthority) || archive.Location.Bucket != "fixture-bucket" || archive.Location.Region != "us-east-1" || archive.Location.ExpectedOwner != "123456789012" {
		t.Fatal("maximum fixture changed independent signer, authority key or Store")
	}
	binaries := buildNativeGeneratedExecutables(t, installedarchive.MaximumCloudflareOrigin)
	manifest := nativeManifestProductionBuild(t)
	generator := artifact.LocalPlugin{Name: "cloudflare-account-token", Directory: binaries.localBuild}
	plugins := newNativePluginFixture(t, generator, manifest)
	s := newWorkflowServer(t, "aws", false)
	s.prefix = archive.Location.PrefixBeforeHEAD
	s.childLimit = 5
	s.childRequestLimit = 4096
	s.objectLimit = 256 * (2*64*3 + 4)
	s.requestBodyLimit = 2 << 20
	s.requestBytesLimit = 1 << 32
	s.childBytesLimit = 1 << 32
	s.childTimeout = 8 * time.Minute
	s.objects = make(map[string]workflowObject, len(archive.Objects))
	s.keys = map[string]workflowKey{signer.KeySelector(): {der: signer.PublicKey(), role: "normal"}}
	var selectedBytes uint64
	for _, object := range archive.Objects {
		token, n, err := contract.ParseToken(object.TokenWire)
		if err != nil || n != len(object.TokenWire) || token.Family != contract.AWS {
			t.Fatal("maximum fixture provider token refused")
		}
		s.objects[object.Key] = workflowObject{body: bytes.Clone(object.Body), etag: token.Value}
		selectedBytes += uint64(len(object.Body))
	}
	parts, err := archive.SelectedParts()
	if err != nil {
		t.Fatal("maximum selected parts refused")
	}
	for _, part := range parts {
		if part.Kind == "recipient page" {
			page, err := stateformat.DecodeRecipientPage(part.Body)
			if err != nil {
				t.Fatal("maximum recipient page refused")
			}
			for _, row := range page.Slots {
				if row != nil && row.CurrentBinding != nil {
					s.keys[row.CurrentBinding.KeySelector] = workflowKey{der: bytes.Clone(row.CurrentBinding.SPKI), role: "ordinary"}
				}
			}
		}
	}
	s.keys[archive.AuthorityBinding.KeySelector] = workflowKey{der: bytes.Clone(knownAuthority), role: "authority", decrypt: archive.DecryptAuthority}
	head, selected := workflowHead(t, s)
	root := workflowRoot(t, s, head)
	selectedEntries := nativeLifecycleEntries(t, s, root)
	g := root.Generated
	if g.GeneratedCurrent != 128 || root.SecretCount != 128 || root.ValueEntryCount != 128 || len(selectedEntries) != 128 || !g.ActiveOwner.IsZero() || g.Duties != 0 || g.Hazards != 0 || g.Retiring != 0 || g.Attempts != 0 || g.Results != 0 || g.Materials != 0 || g.Graphs.Count != 0 || g.PendingReleases != 0 || root.WarningBits != 0 || root.CurrentAccess.Core.Recovery != nil {
		t.Fatal("maximum fixture dimensions or idle state differ")
	}
	tokens := make(map[string]bool, 128)
	for name, want := range expected {
		entry := selectedEntries[name]
		token := fmt.Sprintf("%x", entry.Generated.ResourceIncarnationID[:16])
		intent, err := protocol.DecodeIntent(want)
		if err != nil {
			t.Fatal("maximum expected intent requires current generic framing", err)
		}
		resourceBody := append([]byte{}, intent.ResourceContractID[:]...)
		// The archive writer uses the synthetic producer's fixed target and
		// lowercase hexadecimal resource, independently of the intent provider.
		for _, field := range [][]byte{[]byte("synthetic-service/target"), []byte(token)} {
			resourceBody = binary.BigEndian.AppendUint32(resourceBody, uint32(len(field)))
			resourceBody = append(resourceBody, field...)
		}
		resourceInput := []byte("ENKV/GENERATOR/v1/resource-v1\x00")
		resourceInput = binary.BigEndian.AppendUint32(resourceInput, uint32(len(resourceBody)))
		resourceInput = append(resourceInput, resourceBody...)
		resourceDigest := contract.ID(sha256.Sum256(resourceInput))
		if entry.ValueSource != contract.Generated || entry.Generated.IntentDigest != nativeMaximumIntentDigest(want) || entry.Generated.Epoch != 0 || entry.Generated.ConfigContractID != contract.ID(intent.ConfigContractID) || entry.Generated.ResourceContractID != contract.ID(intent.ResourceContractID) || entry.Generated.LifecycleMode != contract.GeneratorLifecycleManaged || entry.Generated.ResourceDigest != resourceDigest || entry.Generated.RetirementMode != contract.GeneratedRetirementManual || entry.Generated.CompletionClass != contract.GeneratedCompletionAcknowledged || tokens[token] {
			t.Fatalf("maximum selected canonical generation differs: generated=%t intent=%t epoch=%t config_contract=%t resource_contract=%t managed=%t resource_digest=%t manual=%t acknowledged=%t unique_resource=%t", entry.ValueSource == contract.Generated, entry.Generated.IntentDigest == nativeMaximumIntentDigest(want), entry.Generated.Epoch == 0, entry.Generated.ConfigContractID == contract.ID(intent.ConfigContractID), entry.Generated.ResourceContractID == contract.ID(intent.ResourceContractID), entry.Generated.LifecycleMode == contract.GeneratorLifecycleManaged, entry.Generated.ResourceDigest == resourceDigest, entry.Generated.RetirementMode == contract.GeneratedRetirementManual, entry.Generated.CompletionClass == contract.GeneratedCompletionAcknowledged, !tokens[token])
		}
		tokens[token] = true
	}
	t.Logf("maximum fixture selected_objects=%d selected_body_bytes=%d canonical_intent_bytes=%d", len(archive.Objects), selectedBytes, 128*installedarchive.MaximumCloudflareIntentBytes)
	beforeObjects := s.objectCount()
	basePolicy := observer.Policy{NormalSigner: signer.KeySelector(), AuthorityKEK: archive.AuthorityBinding.KeySelector}
	privatePolicy := basePolicy
	privatePolicy.ExpectedSHA256 = hashes
	publicPolicy := basePolicy
	publicPolicy.NoKMS = true
	recovered := filepath.Join(t.TempDir(), "maximum.json")
	environment := plugins.Environment(t, recovered)
	returned := time.Now()
	t.Logf("maximum phase=setup event=returned elapsed_ms=%d since_start_ms=%d", returned.Sub(phaseStart).Milliseconds(), returned.Sub(started).Milliseconds())
	phaseStart = time.Now()
	t.Logf("maximum phase=reconstruction event=begin since_start_ms=%d", phaseStart.Sub(started).Milliseconds())
	prepared := workflowRunEnvironment(t, s, binaries.cli, "authority", privatePolicy, nil, environment, nativePrepareArgs(s, recovered, "maximum-restored", "--normal-signing-key", signer.KeySelector())...)
	returned = time.Now()
	t.Logf("maximum phase=reconstruction event=returned elapsed_ms=%d since_start_ms=%d", returned.Sub(phaseStart).Milliseconds(), returned.Sub(started).Milliseconds())
	output := nativePrepareDecode(t, prepared, "reconstruction", false)
	if output.Recovery.Head != workflowDigest(selected.body) || output.Recovery.Domain != hex.EncodeToString(root.Domain[:]) || output.Delivery.Outcome != "recorded" || len(output.Dependencies.Requirements) != 1 {
		t.Fatal("maximum preparation lost exact selected recovery or dependency")
	}
	if len(output.Dependencies.Installations) != 0 {
		t.Fatal("canonical recovery selected a local plugin without an explicit source choice")
	}
	var requirements struct {
		Dependencies struct {
			Requirements []struct {
				Role           string   `json:"role"`
				Plugin         *string  `json:"plugin"`
				Contract       string   `json:"contract"`
				Version        uint32   `json:"protocol_version"`
				Artifact       *string  `json:"artifact"`
				Subjects       []uint16 `json:"subjects"`
				Status, Reason string
			}
		}
	}
	if json.Unmarshal(prepared.out, &requirements) != nil || len(requirements.Dependencies.Requirements) != 1 {
		t.Fatal("maximum preparation lost its generic requirement set")
	}
	dependency := requirements.Dependencies.Requirements[0]
	first := selectedEntries[fmt.Sprintf("maximum-%03d", 0)+strings.Repeat("x", 78)].Generated
	if dependency.Role != "generator" || dependency.Plugin != nil || dependency.Contract != hex.EncodeToString(first.ConfigContractID[:]) || dependency.Version != uint32(protocol.Version) || dependency.Artifact != nil || dependency.Status != "missing" || dependency.Reason != "selection-required" || len(dependency.Subjects) != 128 {
		t.Fatal("maximum preparation changed exact unselected canonical requirement")
	}
	for i, subject := range dependency.Subjects {
		if subject != uint16(i) {
			t.Fatal("maximum preparation omitted or changed an original entry declaration")
		}
	}
	workflowNoRecovery(t, prepared)
	if !nativeMaximumPlaintext(prepared.capture, hashes) {
		t.Fatal("maximum reconstruction lost exact distinct secret verification")
	}
	nativePrepareReadOnly(t, prepared)
	phaseStart = time.Now()
	t.Logf("maximum phase=pair-check event=begin since_start_ms=%d", phaseStart.Sub(started).Milliseconds())
	nativeMaximumPair(t, recovered, expected)
	returned = time.Now()
	t.Logf("maximum phase=pair-check event=returned elapsed_ms=%d since_start_ms=%d", returned.Sub(phaseStart).Milliseconds(), returned.Sub(started).Milliseconds())
	pair := workflowReadNamedPair(t, recovered, "maximum-restored")
	restore := workflowReadOnlyPair(t, recovered, pair)
	defer restore()
	phaseStart = time.Now()
	t.Logf("maximum phase=public-plan event=begin since_start_ms=%d", phaseStart.Sub(started).Milliseconds())
	public := workflowRunEnvironment(t, s, binaries.cli, "reader", publicPolicy, nil, environment, "plan", "--trusted", recovered, "--trusted-format", "json", "--json")
	returned = time.Now()
	t.Logf("maximum phase=public-plan event=returned elapsed_ms=%d since_start_ms=%d", returned.Sub(phaseStart).Milliseconds(), returned.Sub(started).Milliseconds())
	if !nativeMaximumPlanning(t, public, selectedEntries, head, root, false) {
		t.Fatal("fresh maximum public planning evidence differs")
	}
	phaseStart = time.Now()
	t.Logf("maximum phase=secret-check-plan event=begin since_start_ms=%d", phaseStart.Sub(started).Milliseconds())
	private := workflowRunEnvironment(t, s, binaries.cli, "noop", publicPolicy, nil, environment, "plan", "--trusted", recovered, "--trusted-format", "json", "--check-secrets", "--json")
	returned = time.Now()
	t.Logf("maximum phase=secret-check-plan event=returned elapsed_ms=%d since_start_ms=%d", returned.Sub(phaseStart).Milliseconds(), returned.Sub(started).Milliseconds())
	if !nativeMaximumPlanning(t, private, selectedEntries, head, root, true) {
		t.Fatal("fresh maximum private planning evidence differs")
	}
	phaseStart = time.Now()
	t.Logf("maximum phase=no-op-apply event=begin since_start_ms=%d", phaseStart.Sub(started).Milliseconds())
	idle := workflowRunEnvironment(t, s, binaries.cli, "noop", basePolicy, nil, environment, "apply", "--source", recovered, "--source-format", "json", "--json")
	returned = time.Now()
	t.Logf("maximum phase=no-op-apply event=returned elapsed_ms=%d since_start_ms=%d", returned.Sub(phaseStart).Milliseconds(), returned.Sub(started).Milliseconds())
	idle.generatedResources = nativeGeneratedSelectedResources(t, s)
	nativeGeneratedOutcome(t, idle, "no-op", 0)
	nativePrepareReadOnly(t, idle)
	phaseStart = time.Now()
	t.Logf("maximum phase=existing-prepare event=begin since_start_ms=%d", phaseStart.Sub(started).Milliseconds())
	existing := workflowRunEnvironment(t, s, binaries.cli, "reader", publicPolicy, nil, environment, "prepare", "--source", recovered, "--source-format", "json", "--json")
	returned = time.Now()
	t.Logf("maximum phase=existing-prepare event=returned elapsed_ms=%d since_start_ms=%d", returned.Sub(phaseStart).Milliseconds(), returned.Sub(started).Milliseconds())
	repeated := nativePrepareDecode(t, existing, "existing", false)
	if !reflect.DeepEqual(output.Dependencies, repeated.Dependencies) {
		t.Fatal("existing maximum preparation changed exact dependency facts")
	}
	if len(existing.capture.Events) != 1 {
		t.Fatal("existing maximum preparation entered provider work")
	}
	workflowUnchanged(t, recovered, pair)
	_, after := workflowHead(t, s)
	if !reflect.DeepEqual(selected, after) || s.objectCount() != beforeObjects || s.children != 5 {
		t.Fatal("maximum fresh consumers changed selected state, resources or child inventory")
	}
}
