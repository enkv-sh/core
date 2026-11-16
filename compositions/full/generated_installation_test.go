package compositionfull

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
)

func generatedInstallationRow(t *testing.T, build, environment string) contract.GeneratorImplementation {
	t.Helper()
	route := credentialroute.Route{Schema: 1, ContractID: [32]byte(contract.Hash([]byte("private credential contract"))), Mode: credentialroute.ModeEnvironment, Names: []string{environment}}
	body, err := credentialroute.Encode(route)
	if err != nil {
		t.Fatal(err)
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil {
		t.Fatal(err)
	}
	return contract.GeneratorImplementation{Schema: contract.GeneratorImplementationSchema, Kind: contract.GeneratorComponentKind,
		DescriptorID: contract.Hash([]byte("descriptor " + build)), ProtocolID: contract.ID(protocol.ProtocolID()), ExecutorID: contract.Hash([]byte("executor " + build)),
		ArtifactContractID: contract.Hash([]byte("artifact contract " + build)), DependencyManifestID: contract.Hash([]byte("dependencies " + build)), ArtifactSHA256: contract.Hash([]byte("artifact " + build)),
		ConfigContractID: contract.Hash([]byte("private canonical settings")), CredentialRoute: body, CredentialRouteID: contract.ID(routeID), ArtifactLength: 123,
		Module: "private.local/author/token", Command: ".", Version: "1.0.0", GoVersion: "go1.27.3", NativeTuple: runtime.GOOS + "/" + runtime.GOARCH}
}

func generatedInstallationRequest(t *testing.T, row contract.GeneratorImplementation) *core.GeneratedImplementationIdentity {
	t.Helper()
	result, err := contract.GeneratedResultContractID(row, contract.GeneratorActionCreate, contract.GeneratedCompletionAcknowledged, 65536, 4096, contract.InputEncodingRaw)
	if err != nil {
		t.Fatal(err)
	}
	return &core.GeneratedImplementationIdentity{DescriptorID: row.DescriptorID, ExecutorID: row.ExecutorID, CredentialRouteID: row.CredentialRouteID, ResultContractID: result,
		Action: contract.GeneratorActionCreate, InputEncoding: contract.InputEncodingRaw, CompletionClass: contract.GeneratedCompletionAcknowledged, MaxSecret: 65536, MaxFacts: 4096}
}

func generatedImplementationRequest(row contract.GeneratorImplementation) core.GeneratedImplementationRequest {
	return core.GeneratedImplementationRequest{EntryName: "token", ConfigContractID: row.ConfigContractID, ResourceContractID: contract.Hash([]byte("private resource")), LifecycleMode: contract.GeneratorLifecycleManaged}
}

// full_only: false
func TestGeneratedImplementationResolverKeepsExactRetainedSupport(t *testing.T) {
	original := generatedInstallationRow(t, "original", "PRIVATE_TOKEN_A")
	current := generatedInstallationRow(t, "current", "PRIVATE_TOKEN_B")
	request := generatedImplementationRequest(original)
	for _, row := range []contract.GeneratorImplementation{original, current} {
		got, err := resolveConfigurationGeneratedImplementation(request, row)
		if err != nil || !reflect.DeepEqual(got, row) {
			t.Fatal("fresh explicit build refused", err)
		}
		got.CredentialRoute[0] ^= 1
		if bytes.Equal(got.CredentialRoute, row.CredentialRoute) {
			t.Fatal("resolved route borrows installation bytes")
		}
	}
	for _, use := range []struct {
		action, inputEncoding uint8
		maxSecret             uint32
	}{
		{contract.GeneratorActionCreate, contract.InputEncodingRaw, 65536},
		{contract.GeneratorActionCreate, contract.InputEncodingBase64, 65536},
		{contract.GeneratorActionDelete, contract.InputEncodingRaw, 0},
	} {
		request.Retained = generatedInstallationRequest(t, original)
		retained := request.Retained
		retained.Action, retained.InputEncoding, retained.MaxSecret = use.action, use.inputEncoding, use.maxSecret
		var err error
		retained.ResultContractID, err = contract.GeneratedResultContractID(original, retained.Action, retained.CompletionClass, retained.MaxSecret, retained.MaxFacts, retained.InputEncoding)
		if err != nil {
			t.Fatal("retained result contract fixture refused", err)
		}
		got, err := resolveConfigurationGeneratedImplementation(request, original)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("exact original build refused", use.action, use.inputEncoding, err)
		}
		if _, err := resolveConfigurationGeneratedImplementation(request, current); !errors.Is(err, ErrCell) {
			t.Fatal("current selection replaced accepted original support", use.action, use.inputEncoding, err)
		}
	}
	// A selected build may validate older semantics through the passive exchange.
	request.Retained = nil
	request.ConfigContractID = contract.Hash([]byte("older canonical settings"))
	if _, err := resolveConfigurationGeneratedImplementation(request, current); err != nil {
		t.Fatal("descriptor default became a semantic catalog", err)
	}
}

// full_only: false
func TestGeneratedImplementationResolverRefusesChangedRetainedFacts(t *testing.T) {
	for _, field := range []string{"descriptor", "route", "executor", "result contract", "action", "class", "secret bound", "facts bound", "input encoding", "missing input encoding", "invalid input encoding", "delete input encoding", "protocol", "lifecycle", "resource contract"} {
		t.Run(field, func(t *testing.T) {
			row := generatedInstallationRow(t, "original", "PRIVATE_TOKEN")
			request := generatedImplementationRequest(row)
			request.Retained = generatedInstallationRequest(t, row)
			other := contract.Hash([]byte("other identity"))
			switch field {
			case "descriptor":
				request.Retained.DescriptorID = other
			case "route":
				request.Retained.CredentialRouteID = other
			case "executor":
				request.Retained.ExecutorID = other
			case "result contract":
				request.Retained.ResultContractID = other
			case "action":
				request.Retained.Action = contract.GeneratorActionDelete
			case "class":
				request.Retained.CompletionClass = contract.GeneratedCompletionConfirmed
			case "input encoding":
				request.Retained.InputEncoding = contract.InputEncodingBase64
			case "missing input encoding":
				request.Retained.InputEncoding = 0
			case "invalid input encoding":
				request.Retained.InputEncoding = 3
			case "delete input encoding":
				request.Retained.Action = contract.GeneratorActionDelete
				request.Retained.MaxSecret = 0
				var err error
				request.Retained.ResultContractID, err = contract.GeneratedResultContractID(row, request.Retained.Action, request.Retained.CompletionClass, request.Retained.MaxSecret, request.Retained.MaxFacts, request.Retained.InputEncoding)
				if err != nil {
					t.Fatal("retained Delete Raw result contract fixture refused", err)
				}
				if _, err := resolveConfigurationGeneratedImplementation(request, row); err != nil {
					t.Fatal("retained Delete Raw fixture refused before encoding change", err)
				}
				request.Retained.InputEncoding = contract.InputEncodingBase64
			case "secret bound":
				request.Retained.MaxSecret--
			case "facts bound":
				request.Retained.MaxFacts--
			case "protocol":
				row.ProtocolID = other
			case "lifecycle":
				request.LifecycleMode = 3
			case "resource contract":
				request.ResourceContractID = contract.ID{}
			}
			if _, err := resolveConfigurationGeneratedImplementation(request, row); !errors.Is(err, ErrCell) {
				t.Fatal("changed retained facts resolved", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedImplementationResolverAcceptsArbitraryNoResourceValueBound(t *testing.T) {
	row := generatedInstallationRow(t, "local", "PRIVATE_RANDOM_SEED")
	result, err := contract.GeneratedResultContractID(row, contract.GeneratorActionCreate, 0, 17, 115, contract.InputEncodingRaw)
	if err != nil {
		t.Fatal(err)
	}
	request := core.GeneratedImplementationRequest{ConfigContractID: row.ConfigContractID, LifecycleMode: contract.GeneratorLifecycleNone,
		Retained: &core.GeneratedImplementationIdentity{DescriptorID: row.DescriptorID, ExecutorID: row.ExecutorID, CredentialRouteID: row.CredentialRouteID, ResultContractID: result,
			Action: contract.GeneratorActionCreate, InputEncoding: contract.InputEncodingRaw, MaxSecret: 17, MaxFacts: 115}}
	if _, err := resolveConfigurationGeneratedImplementation(request, row); err != nil {
		t.Fatal("generic no-resource result bound refused", err)
	}
}

func generatedRequestFixture(t *testing.T) ([]byte, contract.GeneratorTarget) {
	t.Helper()
	// Python struct independently encoded schema1, R11 config, managed(2),
	// R22 resource and blob32 of the literal JSON. IDs Rxx repeat byte xx 32 times.
	intent, err := hex.DecodeString("000111111111111111111111111111111111111111111111111111111111111111110222222222222222222222222222222222222222222222222222222222222222220000001c7b2270617468223a222f746f6b656e73222c2273697a65223a32347d")
	if err != nil {
		t.Fatal(err)
	}
	id := func(value byte) contract.ID { return contract.ID(bytes.Repeat([]byte{value}, 32)) }
	target := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, Name: "token", IncarnationID: id(0x33), Epoch: 7,
		ResourceID: id(0x44), ConfigContractID: id(0x11), ResourceContractID: id(0x22), ResourceDigest: id(0x55), OriginalOperationID: id(0x66), OriginalAttemptID: id(0x77), ResultContractID: id(0x88),
		LifecycleMode: contract.GeneratorLifecycleManaged, CompletionClass: contract.GeneratedCompletionAcknowledged}
	return intent, target
}

// full_only: false
func TestGeneratedRequestDigestUsesCanonicalIntentAndExactRetirementTarget(t *testing.T) {
	row := generatedInstallationRow(t, "current", "PRIVATE_TOKEN")
	intent, target := generatedRequestFixture(t)
	// Python hashlib: ASCII domain plus NUL, action u8, intent blob32 and target
	// blob32 (empty on create). Target is schema2, name blob32, R33, epoch u64(7),
	// R44/R11/R22/R55/R66/R77/R88, managed u8(2), acknowledged u8(1).
	for _, test := range []struct {
		action uint8
		target *contract.GeneratorTarget
		want   string
	}{
		{contract.GeneratorActionCreate, nil, "532b939b26a484c073e891a148070a234edc35157a3a3a18b575d0452574a489"},
		{contract.GeneratorActionDelete, &target, "976ddc9bb9392c0c5dc24fd18b7ce3cf2a74482b406cad43a484e78c461496c1"},
	} {
		got, err := configurationGeneratedRequestDigest(t.Context(), row, test.action, intent, test.target)
		if err != nil || hex.EncodeToString(got[:]) != test.want {
			t.Fatal("request differs from independent hash", err)
		}
	}
	for _, change := range []func(*contract.GeneratorTarget){
		func(v *contract.GeneratorTarget) { v.ResourceID[0] ^= 1 },
		func(v *contract.GeneratorTarget) { v.ResourceDigest[0] ^= 1 },
		func(v *contract.GeneratorTarget) { v.OriginalOperationID[0] ^= 1 },
		func(v *contract.GeneratorTarget) { v.OriginalAttemptID[0] ^= 1 },
		func(v *contract.GeneratorTarget) { v.Epoch++ },
	} {
		changed := target
		change(&changed)
		got, err := configurationGeneratedRequestDigest(t.Context(), row, contract.GeneratorActionDelete, intent, &changed)
		if err != nil || hex.EncodeToString(got[:]) == "976ddc9bb9392c0c5dc24fd18b7ce3cf2a74482b406cad43a484e78c461496c1" {
			t.Fatal("retirement lost exact source identity", err)
		}
	}
	for _, test := range []struct {
		name   string
		action uint8
		intent []byte
		target *contract.GeneratorTarget
	}{
		{"damaged intent", 1, intent[:len(intent)-1], nil}, {"create target", 1, intent, &target}, {"missing retirement target", 2, intent, nil}, {"unknown action", 3, intent, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := configurationGeneratedRequestDigest(t.Context(), row, test.action, test.intent, test.target); !errors.Is(err, ErrCell) || !got.IsZero() {
				t.Fatal("invalid request admitted", err)
			}
		})
	}
	for _, change := range []func(*contract.GeneratorTarget){
		func(v *contract.GeneratorTarget) { v.ConfigContractID[0] ^= 1 },
		func(v *contract.GeneratorTarget) { v.ResourceContractID[0] ^= 1 },
		func(v *contract.GeneratorTarget) { v.LifecycleMode = contract.GeneratorLifecycleNone },
	} {
		changed := target
		change(&changed)
		if got, err := configurationGeneratedRequestDigest(t.Context(), row, contract.GeneratorActionDelete, intent, &changed); !errors.Is(err, ErrCell) || !got.IsZero() {
			t.Fatal("retirement target changed original semantic contract", err)
		}
	}
}

// full_only: false
func TestGeneratedProducerCloseEndsOnlyItsOwnedFork(t *testing.T) {
	parent, err := enkvcrypto.New(contract.GCP, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(parent.Close)
	fork, err := parent.Fork()
	if err != nil {
		t.Fatal(err)
	}
	closed := configurationGeneratedProducerCustody(new(enkvcrypto.GeneratedCustody), fork)
	closed.Close()
	closed.Close()
	if child, err := fork.Fork(); err == nil {
		child.Close()
		t.Fatal("producer retained an open fork")
	}
	other, err := parent.Fork()
	if err != nil {
		t.Fatal("producer close ended shared runtime", err)
	}
	other.Close()
}

// full_only: false
func TestGeneratedArtifactRequiresCapturedInstallation(t *testing.T) {
	row := generatedInstallationRow(t, "original", "PRIVATE_TOKEN")
	request := generatedImplementationRequest(row)
	if _, installed, path, err := configurationGeneratedInstalled(t.Context(), nil, request); err == nil || installed != nil || path != "" {
		t.Fatal("missing captured installation admitted", err)
	}
	request.Retained = generatedInstallationRequest(t, row)
	if _, installed, path, err := configurationGeneratedInstalled(t.Context(), nil, request); err == nil || installed != nil || path != "" {
		t.Fatal("missing exact original support admitted", err)
	}
}

// full_only: false
func TestGeneratedInstallationConstructionDoesNotCaptureCredential(t *testing.T) {
	t.Setenv("PRIVATE_GENERATOR_TOKEN", "invalid-input-must-not-be-read-here")
	runtime, err := enkvcrypto.New(contract.GCP, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	plugins, err := configurationAttachGeneratedPlugins(t.Context(), nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := contract.Hash([]byte("fixed construction"))
	installation, closeInvocation, err := configurationGeneratedInstallation(t.Context(), Config{Family: contract.GCP}, runtime, id, id, plugins)
	if err != nil || installation == nil || closeInvocation == nil || installation.CheckRetirementCompatibility == nil {
		t.Fatal("pure installation captured a credential", err)
	}
	closeInvocation()
	if _, err := os.Stat(configDirectory); !os.IsNotExist(err) {
		t.Fatal("dormant generator construction created configuration storage", err)
	}
	other, err := runtime.Fork()
	if err != nil {
		t.Fatal("credential close ended shared runtime", err)
	}
	other.Close()
}

// full_only: false
func TestGeneratedFreshResolutionSharesOneCapturePerExplicitPlugin(t *testing.T) {
	captured := &configurationInstalledPlugins{session: new(plugininstallation.Session)}
	failure := errors.New("fixed capture failure")
	for _, failed := range []string{"none", "private-token-a", "private-token-b"} {
		t.Run(failed, func(t *testing.T) {
			calls := map[string]int{}
			captures := map[string]func() (*configurationInstalledPlugins, error){}
			for _, name := range []string{"private-token-a", "private-token-b"} {
				captures[name] = func() (*configurationInstalledPlugins, error) {
					calls[name]++
					if name == failed {
						return nil, failure
					}
					return captured, nil
				}
			}
			plugins := &configurationInstalledPlugins{generatorPlugins: map[string]string{"first": "private-token-a", "second": "private-token-a", "third": "private-token-b"}, currentGenerator: configurationLazyCurrentGenerator(captures)}
			if len(calls) != 0 {
				t.Fatal("capture ran eagerly")
			}
			for _, entry := range []string{"third", "first", "second", "first"} {
				request := generatedImplementationRequest(generatedInstallationRow(t, entry, "PRIVATE_TOKEN"))
				request.EntryName = entry
				_, installed, path, err := configurationGeneratedInstalled(t.Context(), plugins, request)
				name := plugins.generatorPlugins[entry]
				if installed != nil || path != "" || name == failed && err != failure || name != failed && !errors.Is(err, ErrCell) {
					t.Fatal("explicit capture lost its exact outcome", entry, err)
				}
			}
			if calls["private-token-a"] != 1 || calls["private-token-b"] != 1 {
				t.Fatal("capture repeated or crossed plugin IDs", calls)
			}
			if got, err := plugins.currentGenerator("unknown-generator"); got != nil || !errors.Is(err, ErrCell) || len(calls) != 2 {
				t.Fatal("unknown plugin reached a capture", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedRetainedResolutionDoesNotLoadCurrentSelection(t *testing.T) {
	saved := installedPluginKeys
	installedPluginKeys = ""
	t.Cleanup(func() { installedPluginKeys = saved })
	calls := 0
	plugins := &configurationInstalledPlugins{currentGenerator: func(string) (*configurationInstalledPlugins, error) {
		calls++
		return nil, errors.New("current selection must remain unused")
	}}
	row := generatedInstallationRow(t, "original", "PRIVATE_TOKEN")
	request := generatedImplementationRequest(row)
	request.Retained = generatedInstallationRequest(t, row)
	if _, installed, path, err := configurationGeneratedInstalled(t.Context(), plugins, request); err == nil || installed != nil || path != "" {
		t.Fatal("missing exact original support resolved", err)
	}
	if calls != 0 {
		t.Fatal("retained resolution loaded a current selection", calls)
	}
}

// full_only: false
func TestGeneratedPluginSelectionRequiresExplicitUnambiguousEntry(t *testing.T) {
	model := &configuration.Model{Entries: []configuration.Entry{{Name: "token", Generated: &configuration.Generator{Plugin: "private-token-a"}}}}
	for _, retirement := range []map[string]string{nil, {"token": "private-token-a"}, {"removed": "private-token-b"}, {"": "private-token-empty"}} {
		plugins, err := configurationAttachGeneratedPlugins(t.Context(), nil, model, nil, retirement)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := plugins.generatorPlugin("token"); err != nil || got != "private-token-a" {
			t.Fatal("source selection changed", got, err)
		}
		if _, exists := retirement[""]; exists {
			if got, err := plugins.generatorPlugin(""); err != nil || got != "private-token-empty" {
				t.Fatal("empty entry lost its explicit retirement selection", got, err)
			}
		}
		if _, exists := retirement["removed"]; exists {
			retirement["removed"] = "edited-after-capture"
			if got, err := plugins.generatorPlugin("removed"); err != nil || got != "private-token-b" {
				t.Fatal("retirement selection borrowed caller map", got, err)
			}
		}
		if _, err := plugins.generatorPlugin("unknown"); !errors.Is(err, ErrCell) {
			t.Fatal("missing selection obtained a fallback", err)
		}
	}
	empty := &configuration.Model{Entries: []configuration.Entry{{Name: "", Generated: &configuration.Generator{Plugin: "private-token-empty"}}}}
	plugins, err := configurationAttachGeneratedPlugins(t.Context(), nil, empty, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := plugins.generatorPlugin(""); err != nil || got != "private-token-empty" {
		t.Fatal("empty entry lost its explicit current selection", got, err)
	}

	if _, err := configurationAttachGeneratedPlugins(t.Context(), nil, model, nil, map[string]string{"token": "private-token-b"}); !errors.Is(err, ErrCell) {
		t.Fatal("conflicting retirement selection replaced source", err)
	}
}

// full_only: false
func TestGeneratedRetirementCompatibilityRefusesInvalidOriginalFactsBeforeInstallation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	intent, _ := generatedRequestFixture(t)
	id, err := contract.GeneratorIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	facts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionCreate, LifecycleMode: contract.GeneratorLifecycleManaged,
		Disposition: contract.GeneratorDispositionCompleteCreate, RequestDigest: contract.ID{1}, IntentDigest: id, ResourceContractID: contract.ID(bytes.Repeat([]byte{0x22}, 32)), Target: []byte("original-target"), ResourceData: []byte("original-resource")}
	for _, change := range []func(*contract.GeneratorSafeFacts){
		func(v *contract.GeneratorSafeFacts) { v.IntentDigest[0] ^= 1 },
		func(v *contract.GeneratorSafeFacts) { v.ResourceContractID[0] ^= 1 },
		func(v *contract.GeneratorSafeFacts) { v.Action = contract.GeneratorActionDelete },
		func(v *contract.GeneratorSafeFacts) { v.Disposition = contract.GeneratorDispositionUnknown },
	} {
		changed := facts
		change(&changed)
		callback := configurationGeneratedRetirementCompatibility(nil)
		request, reply, err := callback(ctx, generatedInstallationRow(t, "current", "PRIVATE_TOKEN"), intent, changed, contract.GeneratedCompletionAcknowledged)
		if !errors.Is(err, contract.ErrRecord) && !errors.Is(err, protocol.ErrProtocol) || request != nil || reply != nil {
			t.Fatal("invalid original facts reached installation or produced compatibility evidence", err)
		}
	}
}

// full_only: false
func TestGeneratedPluginSelectionsKeepExistingCapacities(t *testing.T) {
	for _, test := range []struct {
		name                               string
		current, supplied, retire, plugins int
		accepted                           bool
	}{
		{name: "all supplied entries", supplied: 512, accepted: true},
		{name: "too many entries", supplied: 513},
		{name: "all generated entries", current: 128, plugins: 1, accepted: true},
		{name: "too many generated entries", current: 129, plugins: 1},
		{name: "all retirement entries", retire: 128, plugins: 1, accepted: true},
		{name: "too many retirement entries", retire: 129, plugins: 1},
		{name: "all selected implementations", current: 64, plugins: 64, accepted: true},
		{name: "too many selected implementations", current: 65, plugins: 65},
	} {
		t.Run(test.name, func(t *testing.T) {
			model := &configuration.Model{Entries: make([]configuration.Entry, test.current+test.supplied)}
			for i := range model.Entries {
				model.Entries[i].Name = "entry" + strconv.Itoa(i)
				if i < test.current {
					model.Entries[i].Generated = &configuration.Generator{Plugin: "private-token-" + strconv.Itoa(i%test.plugins)}
				}
			}
			retirement := make(map[string]string, test.retire)
			for i := range test.retire {
				retirement["removed"+strconv.Itoa(i)] = "private-token-" + strconv.Itoa(i%test.plugins)
			}
			_, err := configurationAttachGeneratedPlugins(t.Context(), nil, model, nil, retirement)
			if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrCell) {
				t.Fatal("selection capacity outcome differs", err)
			}
		})
	}
}
