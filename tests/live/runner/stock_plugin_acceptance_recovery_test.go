package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type stockPrepareResult struct {
	Schema, Operation, Branch, Outcome string
	RequestID                          string `json:"request_id"`
	Recovery                           struct{ Status, Domain, Head string }
	Delivery                           struct {
		Outcome        string
		EditablePath   string `json:"editable_path"`
		GeneratedPath  string `json:"generated_path"`
		RecoverySource string `json:"recovery_source"`
		CleanupFailed  bool   `json:"cleanup_failed"`
		Readback       *struct {
			EditableDigest  string `json:"editable_digest"`
			GeneratedDigest string `json:"generated_digest"`
		}
	} `json:"local_delivery"`
	Dependencies struct {
		Assessment                 string
		MinimumAdministrativeReady bool `json:"minimum_administrative_ready"`
		AllDeclaredReady           bool `json:"all_declared_ready"`
		Requirements               []struct {
			Role, Contract, Status, Reason string
			Plugin, Artifact               *string
			Protocol                       uint32   `json:"protocol_version"`
			Subjects                       []uint16 `json:"subjects"`
		}
		Installations []json.RawMessage
	}
	Diagnostics []struct{ Reason, Subject string }
}

func stockRecoveredIntent(account, name, permission, expires string, generated contract.GeneratedEntryMetadata) []byte {
	// Single policy/member fixture: canonical settings order is specified by the
	// plugin's public settings contract. Do not call its normalizer to derive it.
	settings := []byte(fmt.Sprintf(`{"account":%q,"name":%q,"policies":[{"effect":"allow","permission_groups":[%q],"resources":[{"kind":"account","id":%q}]}],"expires_on":%q}`, account, name, permission, account, expires))
	intent := append([]byte{0, 1}, generated.ConfigContractID[:]...)
	intent = append(intent, 2)
	intent = append(intent, generated.ResourceContractID[:]...)
	intent = binary.BigEndian.AppendUint32(intent, uint32(len(settings)))
	return append(intent, settings...)
}

// Reject duplicate members before decoding; keep repository IDs and epochs exact.
func stockRecoveryDocument(body []byte, out *map[string]any) bool {
	if !jsontext.Value(body).IsValid() {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	return decoder.Decode(out) == nil && *out != nil
}

func stockCanonicalViewMatches(view map[string]any, expected []byte) bool {
	canonical, ok := view["canonical"].(map[string]any)
	settings, present := canonical["settings"]
	body, err := json.Marshal(settings)
	return ok && len(canonical) == 1 && present && err == nil && publicOutputDeclarationMatches(body, expected)
}

// Read the raw source arm before decoding the Core carrier. In particular,
// absent selections and ordinary settings must not normalize into this arm.
func stockRecoveredOutputsMatch(outputs, records map[string]any, expected contract.OutputConfiguration, entries map[contract.ID]string) bool {
	if len(outputs) != len(expected.Bindings) || len(records) != len(expected.Bindings) {
		return false
	}
	for _, binding := range expected.Bindings {
		output, ok := outputs[binding.DestinationID].(map[string]any)
		if !ok || len(output) != 2 {
			return false
		}
		plugin, present := output["plugin"]
		if !present || plugin != nil {
			return false
		}
		if !stockCanonicalViewMatches(output, binding.Destination.CanonicalSettings) {
			return false
		}
		encoded, ok := records[binding.DestinationID].(string)
		if !ok {
			return false
		}
		body, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || base64.StdEncoding.EncodeToString(body) != encoded {
			return false
		}
		actual, err := contract.InspectNormalOutputBinding(body)
		if err != nil || actual.DestinationID != binding.DestinationID || !reflect.DeepEqual(actual.Destination, binding.Destination) || len(actual.Targets) != len(binding.Targets) {
			return false
		}
		targets := make(map[string]contract.OutputTarget, len(binding.Targets))
		for _, target := range binding.Targets {
			name, ok := entries[target.EntryIncarnationID]
			if !ok {
				return false
			}
			if _, duplicate := targets[name]; duplicate {
				return false
			}
			target.EntryIncarnationID = contract.ID{}
			targets[name] = target
		}
		for _, row := range actual.Targets {
			target, exists := targets[row.Name]
			if !exists || !reflect.DeepEqual(row.Target, target) {
				return false
			}
			delete(targets, row.Name)
		}
	}
	return true
}

func stockRecoveredRoutingMatches(outputs map[string]any, input liveRunInput) bool {
	scopes := slices.Clone(publicOutputScopes(input))
	slices.Sort(scopes)
	destinationNames := make([]any, len(scopes))
	for i, name := range scopes {
		destinationNames[i] = name
	}
	groupNames := make([]any, len(publicOutputNames(input.Prefix)))
	for i, name := range publicOutputNames(input.Prefix) {
		groupNames[i] = name
	}
	wantRouting := map[string]any{"default": []any{}, "entries": map[string]any{
		publicOutputNames(input.Prefix)[0]: destinationNames,
		publicOutputNames(input.Prefix)[1]: destinationNames,
	}}
	wantGroups := []any{groupNames}
	return reflect.DeepEqual(outputs["routing"], wantRouting) && reflect.DeepEqual(outputs["groups"], wantGroups)
}

func stockRecoveredGeneratedSourceMatches(source map[string]any, record any, epoch uint64, wantIntent []byte) bool {
	if len(source) != 5 || source["kind"] != "generated" || source["retirement"] != "manual" || source["epoch"] != json.Number(strconv.FormatUint(epoch, 10)) {
		return false
	}
	plugin, present := source["plugin"]
	if !present || plugin != nil {
		return false
	}
	intent, err := contract.InspectGeneratorIntent(wantIntent)
	if err != nil || !stockCanonicalViewMatches(source, intent.Settings) {
		return false
	}
	encoded, ok := record.(string)
	if !ok {
		return false
	}
	body, err := base64.StdEncoding.Strict().DecodeString(encoded)
	return err == nil && base64.StdEncoding.EncodeToString(body) == encoded && bytes.Equal(body, wantIntent)
}

func (r *stockPluginRun) reconstruct(ctx context.Context, source, expires string) string {
	selected := r.selected(ctx, source)
	configurationBefore, _, _ := publicSelectedOutputs(r.t, ctx, selected)
	entries := map[contract.ID]string{}
	expectedEntries := map[string]contract.ValueEntry{}
	var generated contract.GeneratedEntryMetadata
	for _, named := range selected.root.Names {
		entry := selected.valueEntry(named.Slot)
		if entry == nil {
			r.t.Fatal("stock pre-loss current member unavailable")
		}
		entries[entry.Incarnation] = entry.Name
		expectedEntries[entry.Name] = *entry
		if entry.Name == "generated" {
			generated = entry.Generated
		}
	}
	if generated.Epoch != 2 || generated.GenerationID.IsZero() || len(entries) != 3 {
		r.t.Fatal("stock pre-loss canonical state differs")
	}
	headDigest := bodyDigest(selected.body)
	priorImage := publicSourceImage(r.t, source)
	var priorDocument, priorSatellite map[string]any
	if !stockRecoveryDocument(priorImage.Files[source], &priorDocument) {
		r.t.Fatal("stock prior source JSON unavailable")
	}
	priorGeneratedPath := filepath.Join(filepath.Dir(source), filepath.FromSlash(priorDocument["generated"].(string)))
	if !stockRecoveryDocument(priorImage.Files[priorGeneratedPath], &priorSatellite) {
		r.t.Fatal("stock prior satellite JSON unavailable")
	}
	oldDirectory := filepath.Dir(source)
	if filepath.Dir(oldDirectory) != r.inv.StateDir || filepath.Base(oldDirectory) != "stock-source" {
		r.t.Fatal("stock complete-loss source ownership refused")
	}
	if os.RemoveAll(oldDirectory) != nil {
		r.t.Fatal("stock old application pair could not be removed")
	}
	if _, err := os.Lstat(oldDirectory); !os.IsNotExist(err) {
		r.t.Fatal("stock old application pair remains")
	}
	for _, home := range r.homes {
		config := filepath.Join(stockConfigDirectory(home), "enkv")
		if err := os.Remove(filepath.Join(config, "plugins.json")); err != nil && !os.IsNotExist(err) {
			r.t.Fatal("stock old source selection removal failed")
		}
		// Installed immutable builds remain intact for accepted work. Only this
		// test home's application-selection records are part of local-file loss.
		if os.RemoveAll(filepath.Join(config, "installation", "applications")) != nil {
			r.t.Fatal("stock old application selection records remain")
		}
	}
	directory := filepath.Join(r.inv.StateDir, "stock-recovered")
	if os.Mkdir(directory, 0700) != nil {
		r.t.Fatal("stock recovered application owner unavailable")
	}
	source = filepath.Join(directory, "configuration.json")
	child := r.command(ctx, "prepare", "authority", "", nil, "prepare", "--source", source, "--source-format", "json", "--name", "restored", "--provider", r.input.Settings.Provider, "--bucket", r.input.Settings.Bucket, "--region", r.input.Settings.Region, "--prefix", r.input.Prefix, "--normal-signing-key", r.input.Settings.KeyID, "--json")
	defer clear(child.Body)
	var result stockPrepareResult
	if child.Code != 2 || json.Unmarshal(child.Body, &result) != nil || result.Schema != "enkv/prepare-result/v2" || result.Operation != "prepare" || result.Branch != "reconstruction" || result.Outcome != "incomplete" || !publicIdentityHex(result.RequestID) || result.Recovery.Status != "complete" || result.Recovery.Domain != hex.EncodeToString(selected.root.Domain[:]) || result.Recovery.Head != headDigest || result.Delivery.Outcome != "recorded" || result.Delivery.EditablePath != source || result.Delivery.CleanupFailed || result.Delivery.RecoverySource != "" || result.Delivery.Readback == nil || result.Dependencies.Assessment != "complete" || !result.Dependencies.MinimumAdministrativeReady || result.Dependencies.AllDeclaredReady || len(result.Dependencies.Installations) != 0 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Reason != "dependency-missing" || result.Diagnostics[0].Subject != "dependencies" {
		r.t.Fatal("stock recovery did not deliver exact canonical state with unselected dependencies")
	}
	type requirement struct {
		role     string
		protocol uint32
		subjects []uint16
	}
	generatedSubject := slices.IndexFunc(selected.root.Names, func(row format.NameEntry) bool { return row.Name == "generated" })
	if generatedSubject < 0 {
		r.t.Fatal("selected recovery fixture lost its generated entry declaration")
	}
	expectedRequirements := map[string]requirement{hex.EncodeToString(generated.ConfigContractID[:]): {"generator", 5, []uint16{uint16(generatedSubject)}}}
	for i, binding := range configurationBefore.Bindings {
		row := expectedRequirements[binding.Destination.ConfigContractID]
		row.role, row.protocol = "output", 6
		row.subjects = append(row.subjects, uint16(i))
		expectedRequirements[binding.Destination.ConfigContractID] = row
	}
	if len(result.Dependencies.Requirements) != len(expectedRequirements) {
		r.t.Fatal("stock recovered dependency set differs")
	}
	for _, requirement := range result.Dependencies.Requirements {
		want, ok := expectedRequirements[requirement.Contract]
		if !ok || requirement.Role != want.role || requirement.Protocol != want.protocol || requirement.Plugin != nil || requirement.Artifact != nil || requirement.Status != "missing" || requirement.Reason != "selection-required" || !slices.Equal(requirement.Subjects, want.subjects) {
			r.t.Fatal("stock recovery invented or changed a local plugin selection")
		}
		delete(expectedRequirements, requirement.Contract)
	}
	image := publicSourceImage(r.t, source)
	generatedPath := filepath.Join(directory, filepath.FromSlash(publicSourceDocument(r.t, source)["generated"].(string)))
	if result.Delivery.GeneratedPath != generatedPath || result.Delivery.Readback.EditableDigest != bodyDigest(image.Files[source]) || result.Delivery.Readback.GeneratedDigest != bodyDigest(image.Files[generatedPath]) {
		r.t.Fatal("stock recovered exact pair readback differs")
	}
	// JSON v2 rejects duplicate object members throughout the unmodified source.
	// No product source parser or plugin normalizer participates in this oracle.
	var document, satellite map[string]any
	if !stockRecoveryDocument(image.Files[source], &document) || !stockRecoveryDocument(image.Files[generatedPath], &satellite) ||
		len(document) != 6 || document["schema"] != "enkv/configuration/v3" || document["generated"] != ".enkv/restored.generated.json" ||
		satellite["schema"] != "enkv/generated/v2" || !publicIdentityHex(fmt.Sprint(satellite["file_id"])) || satellite["file_id"] == priorSatellite["file_id"] ||
		!reflect.DeepEqual(satellite["domain"], priorSatellite["domain"]) {
		r.t.Fatal("stock recovery changed the raw canonical source or domain identity")
	}
	priorDomain, domainOK := priorDocument["domain"].(map[string]any)
	if !domainOK {
		r.t.Fatal("stock prior domain declaration unavailable")
	}
	priorDomain["name"] = "restored"
	if !reflect.DeepEqual(document["domain"], priorDomain) {
		r.t.Fatal("stock recovered domain coordinates or control selectors differ")
	}
	records, _ := satellite["canonical_records"].(map[string]any)
	generators, _ := records["generators"].(map[string]any)
	outputRecords, recordsOK := records["outputs"].(map[string]any)
	if len(records) != 2 || len(generators) != 1 || !recordsOK {
		r.t.Fatal("stock recovery changed the canonical record set")
	}
	outputs, ok := document["outputs"].(map[string]any)
	destinations, destinationsOK := outputs["destinations"].(map[string]any)
	if !ok || len(outputs) != 3 || !destinationsOK || !stockRecoveredOutputsMatch(destinations, outputRecords, configurationBefore, entries) {
		r.t.Fatal("stock recovery changed the complete canonical output configuration")
	}
	if !stockRecoveredRoutingMatches(outputs, r.input) {
		r.t.Fatal("stock recovery changed routing or complete publication group")
	}
	// Recovered references may have new local names. Bind their exact public
	// identities and encryption keys to the authenticated current registry.
	recipients, recipientsOK := document["recipients"].(map[string]any)
	recoveredRecipients, recoveredOK := satellite["recipients"].(map[string]any)
	if !recipientsOK || !recoveredOK || len(recipients) != len(recoveredRecipients) || len(recipients) != 1 {
		r.t.Fatal("stock recovered recipient set differs")
	}
	references := map[string]contract.ID{}
	for reference, value := range recoveredRecipients {
		row, rowOK := value.(map[string]any)
		editable, editableOK := recipients[reference].(map[string]any)
		if !rowOK || !editableOK || len(editable) != 3 || editable["id"] != row["id"] {
			r.t.Fatal("stock recovered recipient declaration unavailable")
		}
		found := false
		for _, original := range selected.registry() {
			if row["id"] != hex.EncodeToString(original.RecipientID[:]) {
				continue
			}
			key, keyOK := row["encryption"].(map[string]any)
			priorRecipients, _ := priorSatellite["recipients"].(map[string]any)
			var priorKey any
			for _, priorValue := range priorRecipients {
				priorRow, _ := priorValue.(map[string]any)
				if priorRow["id"] == row["id"] {
					priorKey = priorRow["encryption"]
				}
			}
			if original.Status != contract.CurrentRecipient || original.CurrentBinding == nil || !keyOK || !reflect.DeepEqual(key, priorKey) || editable["display_name"] != original.DisplayName || editable["encryption_key"] != original.CurrentBinding.KeySelector {
				r.t.Fatal("stock recovered recipient identity or binding differs")
			}
			references[reference] = original.RecipientID
			found = true
		}
		if !found {
			r.t.Fatal("stock recovery invented a recipient")
		}
	}
	stock := r.input.PublicConfiguration.Stock
	wantIntent := stockRecoveredIntent(stock.CloudflareAccount, "enkv-test-"+r.input.RunID, stock.CloudflarePermissionGroup, expires, generated)
	recoveredEntries, entriesOK := document["entries"].(map[string]any)
	secrets, secretsOK := satellite["secrets"].(map[string]any)
	if !entriesOK || len(recoveredEntries) != len(expectedEntries) || !secretsOK || len(secrets) != 1 {
		r.t.Fatal("stock recovered complete entry set differs")
	}
	for name, expected := range expectedEntries {
		entry, entryOK := recoveredEntries[name].(map[string]any)
		fields := 3
		if name == publicOutputNames(r.input.Prefix)[1] {
			fields++
			if entry["output_encoding"] != "base64" {
				r.t.Fatal("stock recovery changed the supplied secret output encoding")
			}
		}
		if !entryOK || len(entry) != fields {
			r.t.Fatal("stock recovered entry arm differs")
		}
		input, inputOK := entry["source"].(map[string]any)
		members, membersOK := entry["recipients"].([]any)
		if !inputOK || !membersOK {
			r.t.Fatal("stock recovered entry membership unavailable")
		}
		if !stockRecoveredMembershipMatches(members, references, selected.root.CurrentAccess.Core.CurrentControl.AuthorityRecipientID, expected) {
			r.t.Fatal("stock recovered selected membership differs")
		}
		switch name {
		case "generated":
			if entry["confidentiality"] != "secret" || !stockRecoveredGeneratedSourceMatches(input, generators[name], 2, wantIntent) {
				r.t.Fatal("stock recovery changed raw canonical generator intent or selected a build")
			}
		case publicOutputNames(r.input.Prefix)[0]:
			if entry["confidentiality"] != "plain" || !reflect.DeepEqual(input, map[string]any{"kind": "supplied", "value": stockPlainValue}) {
				r.t.Fatal("stock recovery changed plain bytes")
			}
		case publicOutputNames(r.input.Prefix)[1]:
			want := map[string]any{"retained": map[string]any{"incarnation": hex.EncodeToString(expected.Incarnation[:]), "material": hex.EncodeToString(expected.ValueState[:])}}
			if entry["confidentiality"] != "secret" || !reflect.DeepEqual(input, map[string]any{"kind": "supplied"}) || !reflect.DeepEqual(secrets[name], want) {
				r.t.Fatal("stock recovery changed the exact supplied secret material pin")
			}
		default:
			r.t.Fatal("stock recovery added another selected entry")
		}
	}
	var witness struct {
		Kind   string `json:"kind"`
		Anchor []byte `json:"anchor"`
		HEAD   []byte `json:"head"`
		Root   []byte `json:"root"`
	}
	basis, err := json.Marshal(satellite["public_basis"])
	if err != nil || jsonv2.Unmarshal(basis, &witness) != nil || witness.Kind != "observation" || !bytes.Equal(witness.HEAD, selected.body) {
		r.t.Fatal("stock recovery lost its exact selected observation")
	}
	anchor, err := contract.DecodePublicSigningBinding(witness.Anchor)
	if err != nil || !reflect.DeepEqual(anchor, selected.root.CurrentAccess.Core.CurrentControl.NormalSigning) {
		r.t.Fatal("stock recovered signing anchor differs")
	}
	root, err := format.DecodeRoot(witness.Root)
	if err != nil || !reflect.DeepEqual(root, selected.root) {
		r.t.Fatal("stock recovered selected root differs")
	}
	document = publicSourceDocument(r.t, source)
	document["entries"].(map[string]any)["generated"].(map[string]any)["source"].(map[string]any)["plugin"] = "cloudflare-account-token"
	for destination, value := range document["outputs"].(map[string]any)["destinations"].(map[string]any) {
		plugin := destination
		if strings.HasPrefix(plugin, "github-") {
			plugin = "github-actions-" + strings.TrimPrefix(plugin, "github-")
		}
		value.(map[string]any)["plugin"] = plugin
	}
	publicWriteSource(r.t, source, document)
	r.selectPlugins(source, true)
	r.generated(ctx, "b-same-epoch-reused", "", source, "no-op", "apply")
	current := r.list(ctx, source)
	if len(current.Current) != 1 || current.Current[0].Generation != hex.EncodeToString(generated.GenerationID[:]) || len(current.Duties) != 0 {
		r.t.Fatal("stock explicit compatible reselection changed recovered current state")
	}
	r.assert("reconstruction-canonical")
	return source
}

func stockRecoveredMembershipMatches(members []any, references map[string]contract.ID, authority contract.ID, expected contract.ValueEntry) bool {
	memberIDs := []contract.ID{authority}
	for _, member := range members {
		reference, ok := member.(string)
		id, exists := references[reference]
		if !ok || !exists || slices.Contains(memberIDs, id) {
			return false
		}
		memberIDs = append(memberIDs, id)
	}
	slices.SortFunc(memberIDs, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	wantMembers := slices.Clone(expected.Recipients)
	slices.SortFunc(wantMembers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Equal(memberIDs, wantMembers)
}

// full_only: false
func TestStockRecoveredMembershipIncludesAuthorityForEveryEntry(t *testing.T) {
	authority, first, second, foreign := contract.ID{1}, contract.ID{2}, contract.ID{3}, contract.ID{4}
	references := map[string]contract.ID{"first": first, "second": second, "authority": authority}
	for _, kind := range []string{"plain", "supplied-secret", "generated-secret"} {
		t.Run(kind, func(t *testing.T) {
			for _, condition := range []string{"authority-only", "additional", "multiple-unordered", "duplicate-additional", "explicit-authority", "unknown-reference", "non-string-reference", "missing-selected-member", "extra-selected-member", "foreign-selected-authority", "duplicate-selected-member", "omitted-authority"} {
				t.Run(condition, func(t *testing.T) {
					expected := contract.ValueEntry{ConfidentialityClass: contract.Secret, ValueSource: contract.Supplied, Recipients: []contract.ID{first, authority}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
					if kind == "plain" {
						expected.ConfidentialityClass = contract.Plain
					} else if kind == "generated-secret" {
						expected.ValueSource = contract.Generated
					}
					members := []any{"first"}
					want := false
					switch condition {
					case "authority-only":
						members, expected.Recipients, want = []any{}, []contract.ID{authority}, true
					case "additional":
						want = true
					case "multiple-unordered":
						members, expected.Recipients, want = []any{"second", "first"}, []contract.ID{first, authority, second}, true
					case "duplicate-additional":
						members = []any{"first", "first"}
					case "explicit-authority":
						members = []any{"first", "authority"}
					case "unknown-reference":
						members = []any{"first", "missing"}
					case "non-string-reference":
						members = []any{"first", 1}
					case "missing-selected-member":
						members = []any{}
					case "extra-selected-member":
						expected.Recipients = append(expected.Recipients, foreign)
					case "foreign-selected-authority":
						expected.Recipients = []contract.ID{first, foreign}
					case "duplicate-selected-member":
						expected.Recipients = append(expected.Recipients, first)
					case "omitted-authority":
						expected.Recipients = []contract.ID{first}
					}
					before := slices.Clone(expected.Recipients)
					if stockRecoveredMembershipMatches(members, references, authority, expected) != want {
						t.Fatal("recovered additional recipients did not preserve exact selected membership with implicit Authority")
					}
					if !slices.Equal(expected.Recipients, before) {
						t.Fatal("recovered membership comparison changed selected membership")
					}
				})
			}
		})
	}
}

// full_only: false
func TestStockRecoveredRoutingRequiresExactSuppliedPair(t *testing.T) {
	// Fixed names are SHA256 of each complete prefix, independently calculated.
	for _, row := range []struct{ provider, stem, scopes string }{
		{"aws", "ENKV_3FEBD118C3457A5095BD07B543A312B085D5F6EE434320C5584C6ADB2017A68B", `["aws-secrets-manager","github-environment","github-organization","github-repository"]`},
		{"gcp", "ENKV_D5027964B06388E64B9757AB4E4AD2470E3FA92D8DFEA6CB8C7F2A2460FA2D55", `["gcp-secret-manager"]`},
	} {
		t.Run(row.provider, func(t *testing.T) {
			input := liveRunInput{Settings: liveSettings{Provider: row.provider}, Prefix: "enkv-test/stock-recovered-" + row.provider,
				Scenarios: []string{"public-configuration.plugin-contracts/plugin_contracts"}}
			plain, secret := row.stem+"_PLAIN", row.stem+"_SECRET"
			for _, condition := range []string{"exact", "inherited-default", "missing-empty-default", "recipient", "extra-generated", "missing-secret", "changed-secret-destination", "cross-prefix", "partial-group", "extra-group"} {
				t.Run(condition, func(t *testing.T) {
					wire := fmt.Sprintf(`{"routing":{"default":[],"entries":{%q:%s,%q:%s}},"groups":[[%q,%q]]}`, plain, row.scopes, secret, row.scopes, plain, secret)
					switch condition {
					case "inherited-default":
						wire = fmt.Sprintf(`{"routing":{"default":%s,"entries":{}},"groups":[[%q,%q]]}`, row.scopes, plain, secret)
					case "missing-empty-default":
						wire = strings.Replace(wire, `"default":[],`, ``, 1)
					case "recipient":
						wire = strings.Replace(wire, `"entries":`, `"recipients":{"consumer":{}},"entries":`, 1)
					case "extra-generated":
						wire = strings.Replace(wire, `"entries":{`, `"entries":{"generated":`+row.scopes+`,`, 1)
					case "missing-secret":
						wire = strings.Replace(wire, fmt.Sprintf(`,%q:%s`, secret, row.scopes), ``, 1)
					case "changed-secret-destination":
						wire = strings.Replace(wire, fmt.Sprintf(`%q:%s`, secret, row.scopes), fmt.Sprintf(`%q:["wrong-destination"]`, secret), 1)
					case "cross-prefix":
						wire = strings.ReplaceAll(wire, row.stem, "ENKV_"+strings.Repeat("0", 64))
					case "partial-group":
						wire = strings.Replace(wire, fmt.Sprintf(`"groups":[[%q,%q]]`, plain, secret), fmt.Sprintf(`"groups":[[%q]]`, plain), 1)
					case "extra-group":
						wire = strings.Replace(wire, fmt.Sprintf(`"groups":[[%q,%q]]`, plain, secret), fmt.Sprintf(`"groups":[[%q,%q],["generated"]]`, plain, secret), 1)
					}
					var outputs map[string]any
					if jsonv2.Unmarshal([]byte(wire), &outputs) != nil {
						t.Fatal("controlled recovered routing fixture is invalid")
					}
					if stockRecoveredRoutingMatches(outputs, input) != (condition == "exact") {
						t.Fatal("recovered routing must retain only the exact named supplied pair and complete publication group")
					}
				})
			}
		})
	}
}

// full_only: false
func TestStockRecoveredIntentHasIndependentCompleteCanonicalBytes(t *testing.T) {
	metadata := contract.GeneratedEntryMetadata{ConfigContractID: contract.ID{1}, ResourceContractID: contract.ID{2}}
	got := stockRecoveredIntent("account", "name", "permission", "2030-01-01T00:00:00Z", metadata)
	wantSettings := `{"account":"account","name":"name","policies":[{"effect":"allow","permission_groups":["permission"],"resources":[{"kind":"account","id":"account"}]}],"expires_on":"2030-01-01T00:00:00Z"}`
	if len(got) != 71+len(wantSettings) || !bytes.Equal(got[:2], []byte{0, 1}) || got[2] != 1 || got[34] != 2 || got[35] != 2 || binary.BigEndian.Uint32(got[67:71]) != uint32(len(wantSettings)) || string(got[71:]) != wantSettings {
		t.Fatal("independent generator canonical carrier bytes differ")
	}
	encoded := base64.StdEncoding.EncodeToString(got)
	for _, condition := range []string{"exact", "selection", "missing-selection", "settings", "missing-epoch", "null-epoch", "changed-intent", "changed-view", "missing-record", "extra-canonical-member", "duplicate-selection"} {
		t.Run(condition, func(t *testing.T) {
			record := encoded
			wire := `{"kind":"generated","plugin":null,"epoch":2,"retirement":"manual","canonical":{"settings":` + wantSettings + `}}`
			switch condition {
			case "selection":
				wire = strings.Replace(wire, `"plugin":null`, `"plugin":"unrequested"`, 1)
			case "missing-selection":
				wire = strings.Replace(wire, `"plugin":null,`, ``, 1)
			case "settings":
				wire = strings.Replace(wire, `"plugin":null`, `"plugin":null,"settings":{}`, 1)
			case "missing-epoch":
				wire = strings.Replace(wire, `"epoch":2,`, ``, 1)
			case "null-epoch":
				wire = strings.Replace(wire, `"epoch":2`, `"epoch":null`, 1)
			case "changed-intent":
				record = base64.StdEncoding.EncodeToString(append(bytes.Clone(got), 0))
			case "changed-view":
				wire = strings.Replace(wire, wantSettings, "{}", 1)
			case "missing-record":
				record = ""
			case "extra-canonical-member":
				wire = strings.Replace(wire, `"settings":`, `"extra":null,"settings":`, 1)
			case "duplicate-selection":
				wire = strings.Replace(wire, `"plugin":null`, `"plugin":"unrequested","plugin":null`, 1)
			}
			var source map[string]any
			accepted := stockRecoveryDocument([]byte(wire), &source) && stockRecoveredGeneratedSourceMatches(source, record, 2, got)
			if accepted != (condition == "exact") {
				t.Fatal("recovery accepted changed raw generator canonical arm")
			}
		})
	}
}

// full_only: false
func TestStockRecoveredOutputComparisonChecksEveryTarget(t *testing.T) {
	a, b := contract.ID{1}, contract.ID{2}
	destination := contract.OutputDestination{ConfigContractID: "private-config/v1", ServiceContractID: "private/v1", CanonicalSettings: []byte(`{"region":"one","repository":9007199254740993}`), Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot}
	first := contract.OutputTarget{ServiceContractID: "private/v1", TargetContractID: "private-target/v1", CanonicalTarget: "one", ConsumerLocator: "consumer-one", PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot}
	second := contract.OutputTarget{ServiceContractID: "private/v1", TargetContractID: "private-target/v1", CanonicalTarget: "two", ConsumerLocator: "consumer-two", PayloadEncoding: contract.OutputEncodingBase64, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot}
	base := contract.NormalOutputBinding{DestinationID: "private", Destination: destination, Targets: []contract.NormalOutputTarget{{Name: "first", Target: first}, {Name: "second", Target: second}}}
	first.EntryIncarnationID, second.EntryIncarnationID = a, b
	expected := contract.OutputConfiguration{Bindings: []contract.OutputBinding{{DestinationID: "private", Destination: destination, Targets: []contract.OutputTarget{first, second}}}}
	for _, condition := range []string{"exact", "later-target", "later-locator", "later-contract", "later-encoding", "settings-bytes", "missing-target", "extra-target", "missing-profile", "extra-profile", "selection", "missing-selection", "ordinary-settings", "extra-canonical-member", "invalid-base64", "missing-record", "extra-record", "changed-repository", "duplicate-selection"} {
		t.Run(condition, func(t *testing.T) {
			binding := base
			binding.Targets = slices.Clone(base.Targets)
			switch condition {
			case "later-target":
				binding.Targets[1].Target.CanonicalTarget = "wrong"
			case "later-locator":
				binding.Targets[1].Target.ConsumerLocator = "wrong"
			case "later-contract":
				binding.Targets[1].Target.TargetContractID = "wrong/v1"
			case "later-encoding":
				binding.Targets[1].Target.PayloadEncoding = contract.OutputEncodingRaw
			case "settings-bytes":
				binding.Destination.CanonicalSettings = []byte(`{ "region":"one"}`)
			case "missing-target":
				binding.Targets = binding.Targets[:1]
			case "extra-target":
				extra := binding.Targets[1]
				extra.Name = "third"
				extra.Target.CanonicalTarget = "three"
				extra.Target.PayloadEncoding = contract.OutputEncodingRaw
				binding.Targets = append(binding.Targets, extra)
			}
			body, err := contract.EncodeNormalOutputBinding(binding)
			if err != nil {
				t.Fatal("valid controlled canonical carrier fixture unavailable")
			}
			encoded := base64.StdEncoding.EncodeToString(body)
			records := map[string]any{"private": encoded}
			wire := `{"private":{"plugin":null,"canonical":{"settings":{"repository":9007199254740993,"region":"one"}}}}`
			switch condition {
			case "missing-profile":
				wire = `{}`
			case "extra-profile":
				wire = strings.TrimSuffix(wire, "}") + `,"another":{"plugin":null,"canonical":{"settings":{}}}}`
			case "selection":
				wire = strings.Replace(wire, `"plugin":null`, `"plugin":"unrequested"`, 1)
			case "missing-selection":
				wire = strings.Replace(wire, `"plugin":null,`, ``, 1)
			case "ordinary-settings":
				wire = strings.Replace(wire, `"plugin":null`, `"plugin":null,"settings":{}`, 1)
			case "extra-canonical-member":
				wire = strings.Replace(wire, `"settings":`, `"extra":null,"settings":`, 1)
			case "invalid-base64":
				records["private"] = encoded + "!"
			case "missing-record":
				delete(records, "private")
			case "extra-record":
				records["another"] = encoded
			case "changed-repository":
				wire = strings.Replace(wire, "9007199254740993", "9007199254740992", 1)
			case "duplicate-selection":
				wire = strings.Replace(wire, `"plugin":null`, `"plugin":"unrequested","plugin":null`, 1)
			}
			var outputs map[string]any
			accepted := stockRecoveryDocument([]byte(wire), &outputs) && stockRecoveredOutputsMatch(outputs, records, expected, map[contract.ID]string{a: "first", b: "second"})
			if accepted != (condition == "exact") {
				t.Fatal("recovery accepted incomplete or changed raw canonical output source")
			}
		})
	}
}
