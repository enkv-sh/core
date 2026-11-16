package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

const publicManifestFormatContract = "ENKV/CONSUMPTION-MANIFEST/v3"
const publicManifestConfigContract = "ENKV/CONSUMPTION-MANIFEST-CONFIG/v1"
const publicManifestPlain = "public output plain"

type publicManifestSelection struct {
	Target string `json:"target_mode"`
	Entry  string `json:"entry_mode"`
}

type publicManifestObservation struct {
	Domain   string `json:"domain_id"`
	Revision string `json:"head_revision_id"`
	Snapshot string `json:"snapshot_id"`
}

type publicManifestPolicy struct {
	Contract string `json:"contract_id"`
	Data     string `json:"data_base64"`
	Digest   string `json:"digest"`
}

type publicManifestDestination struct {
	Destination     string                `json:"destination_id"`
	Binding         string                `json:"binding_incarnation_id"`
	Incarnation     string                `json:"entry_incarnation_id"`
	Service         string                `json:"service_contract_id"`
	Locator         string                `json:"consumer_locator"`
	TargetContract  string                `json:"target_contract_id"`
	CanonicalTarget string                `json:"canonical_target"`
	TargetData      string                `json:"target_data_base64"`
	Encoding        string                `json:"payload_encoding"`
	Policy          *publicManifestPolicy `json:"consumer_policy"`
}

type publicManifestRenderer = records.PublicManifestRenderer

func publicManifestRendererValid(r publicManifestRenderer) bool {
	if r.Name != "generic-json" || r.Version == "" || r.Length == 0 || r.Length > 512<<20 {
		return false
	}
	for _, value := range []string{r.Protocol, r.Descriptor, r.Executor, r.ArtifactContract, r.Dependency, r.Artifact, r.SHA256} {
		if !publicIdentityHex(value) {
			return false
		}
	}
	return true
}

type publicManifestScope struct {
	Renderer       publicManifestRenderer  `json:"renderer"`
	FormatContract string                  `json:"format_contract_id"`
	ConfigContract string                  `json:"config_contract_id"`
	Settings       []byte                  `json:"settings"`
	Selection      publicManifestSelection `json:"selection"`
	Service        *string                 `json:"service_filter"`
}

func publicManifestScopeMatches(scope publicManifestScope, want publicManifestArtifact) bool {
	return publicManifestRendererValid(scope.Renderer) && scope.Renderer == want.Renderer && scope.FormatContract == publicManifestFormatContract && scope.ConfigContract == publicManifestConfigContract && bytes.Equal(scope.Settings, []byte("{}")) && scope.Selection == want.Selection && reflect.DeepEqual(scope.Service, want.Service)
}

// Expected public target bytes are derived from the plugin's documented field
// order and primitive encodings, without its target or policy implementation.
func publicManifestDestinationExpected(t testing.TB, input liveRunInput, domain, destination, binding, entry, name, locator string) publicManifestDestination {
	d := publicManifestDestination{Destination: destination, Binding: binding, Incarnation: entry, Encoding: "base64"}
	var data []byte
	switch destination {
	case "aws-secrets-manager":
		d.Service, d.TargetContract = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1"
		d.CanonicalTarget = "arn:aws:secretsmanager:" + input.Settings.Region + ":" + input.Settings.Account + ":secret:" + name
		data = []byte(fmt.Sprintf(`{"account":%q,"region":%q,"name":%q}`, input.Settings.Account, input.Settings.Region, name))
		d.Locator = locator
	case "gcp-secret-manager":
		d.Service, d.TargetContract = "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1"
		d.CanonicalTarget = "projects/" + input.Settings.ProjectNumber + "/secrets/" + name
		data = []byte(fmt.Sprintf(`{"project_number":%q,"name":%q}`, input.Settings.ProjectNumber, name))
		d.Locator = d.CanonicalTarget + "/versions/latest"
	case "github-repository", "github-organization", "github-environment":
		d.Service, d.TargetContract = "github-actions/service/v1", "github-actions/target/v1"
		g := input.PublicConfiguration.Outputs
		scope := 1
		switch destination {
		case "github-repository":
			d.CanonicalTarget = "repos/" + g.Repository.Owner + "/" + g.Repository.Repository + "/actions/secrets/" + name
		case "github-environment":
			scope = 3
			d.CanonicalTarget = "repos/" + g.Environment.Owner + "/" + g.Environment.Repository + "/environments/" + g.Environment.Environment + "/secrets/" + name
		case "github-organization":
			scope = 2
			d.CanonicalTarget = "orgs/" + g.Organization.Owner + "/actions/secrets/" + name
			// schema u16, explicit-set u8, count u16, then sorted u64 IDs.
			policy := binary.BigEndian.AppendUint16([]byte{0, 1, 3}, uint16(len(g.Organization.Repositories)))
			for _, member := range g.Organization.Repositories {
				policy = binary.BigEndian.AppendUint64(policy, member)
			}
			contractID := "github-actions/org-visibility/v1"
			domainBytes, err := hex.DecodeString(domain)
			if err != nil || len(domainBytes) != 32 {
				t.Fatal("manifest expected policy domain unavailable")
			}
			preimage := append([]byte("ENKV/OUTPUT/POLICY/v3\x00"), domainBytes...)
			preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(contractID)))
			preimage = append(preimage, contractID...)
			preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(policy)))
			digest := sha256.Sum256(append(preimage, policy...))
			d.Policy = &publicManifestPolicy{contractID, base64.StdEncoding.EncodeToString(policy), hex.EncodeToString(digest[:])}
		}
		d.Locator = d.CanonicalTarget
		data = []byte(fmt.Sprintf(`{"scope":%d,"coordinate":%q}`, scope, d.CanonicalTarget))
	default:
		t.Fatal("manifest expected destination unavailable")
	}
	d.TargetData = base64.StdEncoding.EncodeToString(data)
	return d
}

type publicManifestEntryFact struct {
	Name, Incarnation string
	Plain             bool
	Ordinary          bool
	Destinations      []publicManifestDestination
}

// Only independently selected public facts survive the writer. Secret values
// and their hashes never enter this observation record.
type publicManifestFacts struct {
	Renderer             publicManifestRenderer
	Observation          publicManifestObservation
	Authority, Recipient string
	Entries              []publicManifestEntryFact
	Verified             bool
}

type publicManifestRow struct {
	Name        string `json:"name"`
	Incarnation string `json:"entry_incarnation_id"`
	Reason      string `json:"reason,omitempty"`
}

func publicManifestDeclaration(input liveRunInput) map[string]any {
	cloud := "aws-secrets-manager"
	if input.Settings.Provider == "gcp" {
		cloud = "gcp-secret-manager"
	}
	scopes := []string{cloud, "github-repository", "github-organization", "github-environment"}
	return publicManifestDeclarationForScopes(input, scopes)
}

func publicManifestDeclarationForScopes(input liveRunInput, scopes []string) map[string]any {
	declaration := publicOutputDeclarationForScopes(input, scopes)
	names := publicOutputNames(input.Prefix)
	declaration["routing"] = map[string]any{"entries": map[string]any{names[0]: scopes, names[1]: scopes}}
	return declaration
}

func publicManifestPassiveStateMatches(configuration contract.OutputConfiguration, coordinates map[string]contract.PublicationCoordinate, markers map[contract.ID]contract.PublicationMarker, passive []records.PublicOutputPassiveCoordinate, cloud []publicOutputCoordinate, facts publicManifestFacts) bool {
	if len(configuration.Bindings) != 3 && len(configuration.Bindings) != 4 || len(coordinates) != 8 || len(passive) != 6 || len(cloud) != 2 || hex.EncodeToString(configuration.DomainID[:]) != facts.Observation.Domain {
		return false
	}
	expected := map[string]records.PublicOutputPassiveCoordinate{}
	all, cloudIDs := map[string]bool{}, map[contract.ID]bool{}
	for _, row := range cloud {
		key := row.ServiceContractID + "\x00" + row.PhysicalTarget
		c, found := coordinates[key]
		if !found || hex.EncodeToString(c.CoordinateID[:]) != row.CoordinateID || c.DomainID != configuration.DomainID {
			return false
		}
		all[key], cloudIDs[c.CoordinateID] = true, true
	}
	for _, row := range passive {
		key := row.ServiceContractID + "\x00" + row.PhysicalTarget
		if !row.Valid() || row.Before.DomainID != configuration.DomainID || !coordinates[key].Equal(row.Before) || all[key] {
			return false
		}
		kind := ""
		for _, entry := range facts.Entries {
			if entry.Incarnation == row.EntryIncarnationID {
				kind = "secret"
				if entry.Plain {
					kind = "plain"
				}
			}
		}
		if kind != row.EntryKind {
			return false
		}
		expected[key], all[key] = row, true
	}
	seen, cloudBindings := map[string]bool{}, 0
	for _, binding := range configuration.Bindings {
		if binding.DestinationID == "aws-secrets-manager" || binding.DestinationID == "gcp-secret-manager" {
			cloudBindings++
			if cloudBindings > 1 || len(binding.Targets) != 2 {
				return false
			}
			for _, target := range binding.Targets {
				if !all[target.ServiceContractID+"\x00"+target.CanonicalTarget] || target.ServiceContractID != cloud[0].ServiceContractID {
					return false
				}
			}
			continue
		}
		if binding.DestinationID != "github-repository" && binding.DestinationID != "github-organization" && binding.DestinationID != "github-environment" || seen[binding.DestinationID] || len(binding.Targets) != 2 {
			return false
		}
		seen[binding.DestinationID] = true
		for _, target := range binding.Targets {
			key := target.ServiceContractID + "\x00" + target.CanonicalTarget
			row, present := expected[key]
			if !present || row.TargetContractID != target.TargetContractID || row.BindingID != hex.EncodeToString(binding.IncarnationID[:]) || row.EntryIncarnationID != hex.EncodeToString(target.EntryIncarnationID[:]) {
				return false
			}
			delete(expected, key)
		}
	}
	for key := range coordinates {
		if !all[key] {
			return false
		}
	}
	for id, marker := range markers {
		if marker.AttemptID != id || marker.DomainID != configuration.DomainID || !cloudIDs[marker.CoordinateID] {
			return false
		}
	}
	return len(expected) == 0 && len(seen) == 3
}

func publicManifestPassiveSupport(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, facts publicManifestFacts, cloud []publicOutputCoordinate, before []records.PublicOutputPassiveCoordinate) []records.PublicOutputPassiveCoordinate {
	t.Helper()
	basis, descriptor := publicOperatorGenesis(t, source)
	store, err := openPublicReaderStore(ctx, input, descriptor.DomainID, inv.StateDir)
	if err != nil {
		t.Fatal("manifest cleanup GET-only support unavailable")
	}
	selected := publicOperatorOpen(t, ctx, descriptor.DomainID, basis, recordedStore{Store: store, budget: budget})
	configuration, coordinates, markers := publicSelectedOutputs(t, ctx, selected)
	initial := before == nil
	if initial && !publicManifestCoordinateInventoryMatches(configuration, coordinates, markers) || !initial && len(configuration.Bindings) != 3 {
		t.Fatal("manifest cleanup complete coordinate set differs")
	}
	for _, binding := range configuration.Bindings {
		if !strings.HasPrefix(binding.DestinationID, "github-") {
			continue
		}
		for _, target := range binding.Targets {
			entryID := hex.EncodeToString(target.EntryIncarnationID[:])
			var entry publicManifestEntryFact
			for _, original := range facts.Entries {
				if original.Incarnation == entryID {
					entry = original
				}
			}
			if entry.Name == "" || entry.Name == "UNROUTED" {
				t.Fatal("manifest cleanup passive entry differs")
			}
			bindingID := ""
			for _, original := range facts.Entries {
				for _, d := range original.Destinations {
					if d.Destination == binding.DestinationID {
						bindingID = d.Binding
					}
				}
			}
			d := publicManifestDestinationExpected(t, input, facts.Observation.Domain, binding.DestinationID, bindingID, entryID, entry.Name, "")
			data, dataErr := base64.StdEncoding.DecodeString(d.TargetData)
			caps := contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot
			policy := contract.OutputPolicy{}
			if d.Policy != nil {
				policy.ContractID = d.Policy.Contract
				policy.Data, err = base64.StdEncoding.DecodeString(d.Policy.Data)
				caps |= contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy
			}
			encoding := uint8(contract.OutputEncodingBase64)
			if entry.Plain {
				encoding = contract.OutputEncodingRaw
			}
			want := contract.OutputTarget{EntryIncarnationID: target.EntryIncarnationID, ServiceContractID: d.Service, TargetContractID: d.TargetContract, CanonicalTarget: d.CanonicalTarget, ConsumerLocator: d.Locator, TargetData: data, PayloadEncoding: encoding, Capabilities: caps, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 48000}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 48000}, Policy: policy}
			if dataErr != nil || err != nil || !reflect.DeepEqual(target, want) {
				t.Fatal("manifest cleanup passive target meaning changed")
			}
			if initial {
				kind := "secret"
				if entry.Plain {
					kind = "plain"
				}
				c := coordinates[target.ServiceContractID+"\x00"+target.CanonicalTarget]
				row := records.PublicOutputPassiveCoordinate{PublicOutputCoordinate: publicOutputCoordinate{ServiceContractID: d.Service, TargetContractID: d.TargetContract, PhysicalTarget: d.CanonicalTarget, CoordinateID: hex.EncodeToString(c.CoordinateID[:]), BindingID: bindingID}, EntryKind: kind, EntryIncarnationID: entryID, Before: c, After: c}
				if !row.Valid() {
					t.Fatal("manifest cleanup passive coordinate has publication effects")
				}
				before = append(before, row)
			}
		}
	}
	if initial {
		slices.SortFunc(before, func(a, b records.PublicOutputPassiveCoordinate) int {
			return strings.Compare(a.PhysicalTarget, b.PhysicalTarget)
		})
	}
	if !publicManifestPassiveStateMatches(configuration, coordinates, markers, before, cloud, facts) {
		t.Fatal("manifest cleanup changed passive authenticated support")
	}
	result := append([]records.PublicOutputPassiveCoordinate(nil), before...)
	for i := range result {
		result[i].After = coordinates[result[i].ServiceContractID+"\x00"+result[i].PhysicalTarget]
	}
	return result
}

func runPublicManifest(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, row catalog.PublicConfigurationCase, source string) (*publicManifestFacts, []publicOutputCoordinate) {
	t.Helper()
	// Only the domain's own cloud service is published. The three GitHub scopes
	// below are passive public declarations and acquire no GitHub credentials.
	outputs := runPublicOutput(t, ctx, inv, input, budget, row, source)
	document := publicSourceDocument(t, source)
	names := publicOutputNames(input.Prefix)
	entries := document["entries"].(map[string]any)
	entries[names[0]].(map[string]any)["recipients"] = []string{"consumer"}
	entries["UNROUTED"] = map[string]any{"confidentiality": "secret", "recipients": []string{}, "source": map[string]any{"kind": "supplied"}}
	publicWriteSource(t, source, document)
	value := []byte("manifest-only unrouted input")
	set := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true}, value, "set", "--source", source, "--source-format", "json", "--name", "UNROUTED", "--json")
	clear(value)
	publicAssertSet(t, set, source, "UNROUTED")
	clear(set.Body)
	document = publicSourceDocument(t, source)
	document["outputs"] = publicManifestDeclaration(input)
	publicWriteSource(t, source, document)
	image := publicSourceImage(t, source)
	applied := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json")
	if !publicApplyMatches(applied, publicProduct(t, applied, "apply-declaration"), "success") {
		clear(applied.Body)
		t.Fatal("manifest passive declarations and exact current membership did not apply")
	}
	clear(applied.Body)
	publicImageUnchanged(t, image)
	facts := publicManifestExpected(t, ctx, inv, input, budget, source)
	cloud, other := "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1"
	if input.Settings.Provider == "gcp" {
		cloud, other = other, cloud
	}
	for _, request := range []publicManifestRequest{
		{}, {Service: "github-actions/service/v1"}, {Service: cloud}, {YAML: true},
		{Service: other, Names: []string{names[1]}, Exact: true},
		{Exact: true, Names: []string{}}, {Recipient: true},
	} {
		publicManifestCommand(t, ctx, inv, input, budget, source, facts, request)
	}
	facts.Verified = true
	return &facts, outputs
}

func publicManifestExpected(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) publicManifestFacts {
	t.Helper()
	if input.PublicConfiguration == nil || input.PublicConfiguration.Artifact.ManifestRenderer == nil || !publicManifestRendererValid(*input.PublicConfiguration.Artifact.ManifestRenderer) {
		t.Fatal("manifest fixture measured renderer unavailable")
	}
	basis, descriptor := publicOperatorGenesis(t, source)
	store, err := openPublicReaderStore(ctx, input, descriptor.DomainID, inv.StateDir)
	if err != nil {
		t.Fatal("manifest independent GET-only Store unavailable")
	}
	selected := publicOperatorOpen(t, ctx, descriptor.DomainID, basis, recordedStore{Store: store, budget: budget})
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	facts := publicManifestFacts{Renderer: *input.PublicConfiguration.Artifact.ManifestRenderer, Observation: publicManifestObservation{id(selected.root.Domain), id(selected.head.Core.Revision), id(selected.root.Snapshot)}, Authority: id(descriptor.AuthorityRecipientID)}
	for _, recipient := range descriptor.Recipients {
		if recipient.RecipientID != descriptor.AuthorityRecipientID && recipient.Status == contract.CurrentRecipient {
			if facts.Recipient != "" {
				t.Fatal("manifest fixture ordinary Recipient is not unique")
			}
			facts.Recipient = id(recipient.RecipientID)
		}
	}
	names := publicOutputNames(input.Prefix)
	if facts.Recipient == "" || len(selected.root.Names) != 3 {
		t.Fatal("manifest fixture current names or Recipient differ")
	}
	for _, named := range selected.root.Names {
		entry := selected.valueEntry(named.Slot)
		if entry == nil || entry.Name != named.Name || entry.ValueSource != contract.Supplied || !slices.Contains(entry.Recipients, descriptor.AuthorityRecipientID) {
			t.Fatal("manifest fixture selected entry differs")
		}
		f := publicManifestEntryFact{Name: named.Name, Incarnation: id(entry.Incarnation)}
		for _, recipient := range entry.Recipients {
			f.Ordinary = f.Ordinary || id(recipient) == facts.Recipient
		}
		switch named.Name {
		case names[0]:
			plain := publicManifestPlain
			if entry.ConfidentialityClass != contract.Plain || !bytes.Equal(entry.ValueBytes, []byte(plain)) || !f.Ordinary || len(entry.Recipients) != 2 {
				t.Fatal("manifest fixture plain bytes or ordinary grant differ")
			}
			f.Plain = true
		case names[1], "UNROUTED":
			if entry.ConfidentialityClass != contract.Secret || f.Ordinary || len(entry.Recipients) != 1 {
				t.Fatal("manifest fixture Authority-only secret membership differs")
			}
		default:
			t.Fatal("manifest fixture selected another name")
		}
		facts.Entries = append(facts.Entries, f)
	}
	configuration, coordinates, markers := publicSelectedOutputs(t, ctx, selected)
	if !publicManifestCoordinateInventoryMatches(configuration, coordinates, markers) {
		t.Fatal("manifest fixture cloud births or passive destination set differ")
	}
	for i := range facts.Entries {
		if facts.Entries[i].Name != names[1] {
			continue
		}
		for _, binding := range configuration.Bindings {
			var target *contract.OutputTarget
			for j := range binding.Targets {
				if id(binding.Targets[j].EntryIncarnationID) == facts.Entries[i].Incarnation {
					target = &binding.Targets[j]
				}
			}
			if len(binding.Targets) != 2 || target == nil || target.PayloadEncoding != contract.OutputEncodingBase64 {
				t.Fatal("manifest fixture complete secret destination unavailable")
			}
			if binding.DestinationID == "aws-secrets-manager" || binding.DestinationID == "gcp-secret-manager" {
				coordinate := coordinates[target.ServiceContractID+"\x00"+target.CanonicalTarget]
				if !publicManifestCloudBirthMatches(coordinate, markers[coordinate.OwnedBirthAttemptID], binding.IncarnationID, *target) {
					t.Fatal("manifest passive configuration changed its acknowledged cloud binding or entry")
				}
			}
			locator := target.ConsumerLocator
			if binding.DestinationID == "aws-secrets-manager" {
				coordinate := coordinates[target.ServiceContractID+"\x00"+target.CanonicalTarget]
				birth := markers[coordinate.OwnedBirthAttemptID]
				prefix := "arn:aws:secretsmanager:" + input.Settings.Region + ":" + input.Settings.Account + ":secret:" + names[1] + "-"
				resource := birth.Evidence.SafeResourceID
				if !strings.HasPrefix(resource, prefix) || len(resource) != len(prefix)+6 || target.ConsumerLocator != "" || !target.LocatorRequiresCreation || birth.Evidence.ConsumerLocator != resource+"?stage=AWSCURRENT" {
					t.Fatal("manifest fixture actual acknowledged AWS birth differs")
				}
				locator = birth.Evidence.ConsumerLocator
			}
			d := publicManifestDestinationExpected(t, input, facts.Observation.Domain, binding.DestinationID, id(binding.IncarnationID), facts.Entries[i].Incarnation, names[1], locator)
			if target.ServiceContractID != d.Service || target.TargetContractID != d.TargetContract || target.CanonicalTarget != d.CanonicalTarget || base64.StdEncoding.EncodeToString(target.TargetData) != d.TargetData || target.PayloadEncoding != contract.OutputEncodingBase64 {
				t.Fatal("manifest fixture selected target differs from literal expected meaning")
			}
			if d.Policy == nil {
				if target.Policy.ContractID != "" || len(target.Policy.Data) != 0 {
					t.Fatal("manifest fixture unexpected target policy")
				}
			} else if target.Policy.ContractID != d.Policy.Contract || base64.StdEncoding.EncodeToString(target.Policy.Data) != d.Policy.Data {
				t.Fatal("manifest fixture selected policy differs")
			}
			facts.Entries[i].Destinations = append(facts.Entries[i].Destinations, d)
		}
		slices.SortFunc(facts.Entries[i].Destinations, func(a, b publicManifestDestination) int { return strings.Compare(a.Destination, b.Destination) })
	}
	return facts
}

func publicSelectedOutputs(t testing.TB, ctx context.Context, selected *StateSession) (contract.OutputConfiguration, map[string]contract.PublicationCoordinate, map[contract.ID]contract.PublicationMarker) {
	t.Helper()
	var parts []contract.OutputConfigurationSlice
	coordinates := map[string]contract.PublicationCoordinate{}
	markers := map[contract.ID]contract.PublicationMarker{}
	rows, err := observePreservedGeneratedSupport(ctx, selected)
	if err != nil {
		t.Fatal("public output selected support unavailable")
	}
	publication, err := publicationRowsRelation(selected.root.Domain, rows, selected.adminIndex.PublicationOrder)
	if err != nil || validatePublicationIndexRelation(selected.selectedImage(), publication) != nil {
		t.Fatal("public output complete publication relation unavailable")
	}
	for _, coordinate := range publication.coordinates {
		key := coordinate.ServiceContractID + "\x00" + coordinate.CanonicalTarget
		if _, duplicate := coordinates[key]; duplicate {
			t.Fatal("public output coordinate identity is not unique")
		}
		coordinates[key] = coordinate
	}
	for id, marker := range publication.markers {
		markers[id] = marker
	}
	for _, record := range rows {
		switch record.Kind {
		case contract.OutputConfigurationSliceSupportKind:
			part, err := contract.InspectOutputConfigurationSlice(record.Body)
			if err != nil {
				t.Fatal("public output configuration slice refused")
			}
			if part.ConfigurationDigest == selected.root.OutputConfiguration.ConfigurationDigest {
				parts = append(parts, part)
			}
		}
	}
	body, err := contract.JoinOutputConfiguration(selected.root.Domain, selected.root.OutputConfiguration, parts)
	if err != nil {
		t.Fatal("public current output configuration unavailable")
	}
	configuration, _, err := contract.InspectOutputConfiguration(selected.root.Domain, body)
	if err != nil {
		t.Fatal("public canonical output configuration refused")
	}
	return configuration, coordinates, markers
}

func publicManifestCoordinateInventoryMatches(configuration contract.OutputConfiguration, coordinates map[string]contract.PublicationCoordinate, markers map[contract.ID]contract.PublicationMarker) bool {
	if len(configuration.Bindings) != 4 || len(coordinates) != 8 {
		return false
	}
	passiveBindings := map[string]bool{"github-repository": true, "github-organization": true, "github-environment": true}
	seen := map[string]bool{}
	cloudCoordinates := map[contract.ID]bool{}
	cloudBindings, passiveCoordinates := 0, 0
	for _, binding := range configuration.Bindings {
		cloud := binding.DestinationID == "aws-secrets-manager" || binding.DestinationID == "gcp-secret-manager"
		service := "github-actions/service/v1"
		if cloud {
			cloudBindings++
			service = "ENKV/OUTPUT/" + strings.ToUpper(binding.DestinationID) + "/v1"
		} else if !passiveBindings[binding.DestinationID] {
			return false
		} else {
			delete(passiveBindings, binding.DestinationID)
		}
		if len(binding.Targets) != 2 {
			return false
		}
		for _, target := range binding.Targets {
			key := target.ServiceContractID + "\x00" + target.CanonicalTarget
			coordinate, present := coordinates[key]
			if seen[key] || !present || target.ServiceContractID != service || coordinate.DomainID != configuration.DomainID ||
				coordinate.BindingState != contract.PublicationBindingActive || coordinate.ActiveBindingIncarnationID != binding.IncarnationID ||
				coordinate.LastBindingIncarnationID != binding.IncarnationID || coordinate.LastEntryIncarnationID != target.EntryIncarnationID {
				return false
			}
			seen[key] = true
			if cloud {
				if coordinate.OwnerState != contract.PublicationOwnerQualified || !publicManifestCloudBirthMatches(coordinate, markers[coordinate.OwnedBirthAttemptID], binding.IncarnationID, target) {
					return false
				}
				cloudCoordinates[coordinate.CoordinateID] = true
				continue
			}
			want := contract.PublicationCoordinate{Schema: 5, DomainID: configuration.DomainID, CoordinateID: coordinate.CoordinateID,
				ServiceContractID: target.ServiceContractID, CanonicalTarget: target.CanonicalTarget, BindingState: contract.PublicationBindingActive,
				OwnerState: contract.PublicationOwnerNone, ActiveBindingIncarnationID: binding.IncarnationID, LastBindingIncarnationID: binding.IncarnationID,
				LastEntryIncarnationID: target.EntryIncarnationID, CurrentPublicationIncarnationID: coordinate.CurrentPublicationIncarnationID}
			if !coordinate.Equal(want) {
				return false
			}
			passiveCoordinates++
		}
	}
	for id, marker := range markers {
		if marker.AttemptID != id || marker.DomainID != configuration.DomainID || !cloudCoordinates[marker.CoordinateID] {
			return false
		}
	}
	return cloudBindings == 1 && len(cloudCoordinates) == 2 && passiveCoordinates == 6 && len(passiveBindings) == 0
}

func publicManifestCloudBirthMatches(coordinate contract.PublicationCoordinate, birth contract.PublicationMarker, binding contract.ID, target contract.OutputTarget) bool {
	return !coordinate.OwnedBirthAttemptID.IsZero() && coordinate.ServiceContractID == target.ServiceContractID && coordinate.CanonicalTarget == target.CanonicalTarget &&
		coordinate.ActiveBindingIncarnationID == binding && coordinate.LastEntryIncarnationID == target.EntryIncarnationID &&
		birth.AttemptID == coordinate.OwnedBirthAttemptID && birth.CoordinateID == coordinate.CoordinateID && birth.State == contract.PublicationAcknowledged &&
		birth.Projection.BindingIncarnationID == binding && birth.Projection.EntryIncarnationID == target.EntryIncarnationID &&
		birth.BirthServiceContractID == target.ServiceContractID && birth.BirthTargetContractID == target.TargetContractID &&
		birth.Evidence.Class == contract.PublicationRequestAcknowledged && birth.Evidence.SafeResourceID != "" &&
		(!target.LocatorRequiresCreation || birth.Evidence.ConsumerLocator != "")
}

// full_only: false
func TestPublicManifestCoordinatesSeparatePassiveTargetsFromCloudBirths(t *testing.T) {
	for _, cloud := range []string{"aws-secrets-manager", "gcp-secret-manager"} {
		for _, condition := range []string{"exact", "missing-coordinate", "extra-coordinate", "passive-admission", "passive-birth", "passive-ack", "passive-unresolved", "passive-risk", "passive-deletion", "passive-marker", "cloud-birth", "cloud-entry"} {
			t.Run(cloud+"/"+condition, func(t *testing.T) {
				configuration := contract.OutputConfiguration{DomainID: contract.ID{1}}
				facts := publicManifestFacts{Observation: publicManifestObservation{Domain: hex.EncodeToString(configuration.DomainID[:])}}
				for j, name := range []string{"plain", "secret"} {
					entry := contract.ID{byte(20 + j)}
					facts.Entries = append(facts.Entries, publicManifestEntryFact{Name: name, Incarnation: hex.EncodeToString(entry[:]), Plain: j == 0})
				}
				var passiveProof []records.PublicOutputPassiveCoordinate
				var cloudProof []publicOutputCoordinate
				coordinates := map[string]contract.PublicationCoordinate{}
				markers := map[contract.ID]contract.PublicationMarker{}
				cloudKey, passiveKey := "", ""
				for i, destination := range []string{cloud, "github-repository", "github-organization", "github-environment"} {
					binding := contract.OutputBinding{DestinationID: destination, IncarnationID: contract.ID{byte(10 + i)}}
					for j, name := range []string{"plain", "secret"} {
						target := contract.OutputTarget{ServiceContractID: "github-actions/service/v1", CanonicalTarget: destination + "/" + name, EntryIncarnationID: contract.ID{byte(20 + j)}}
						if i > 0 {
							target.TargetContractID = "github-actions/target/v1"
							switch destination {
							case "github-repository":
								target.CanonicalTarget = "repos/owner/repo/actions/secrets/" + name
							case "github-organization":
								target.CanonicalTarget = "orgs/owner/actions/secrets/" + name
							case "github-environment":
								target.CanonicalTarget = "repos/owner/repo/environments/env/secrets/" + name
							}
						}
						if i == 0 {
							target.ServiceContractID = "ENKV/OUTPUT/" + strings.ToUpper(cloud) + "/v1"
							target.TargetContractID = "cloud/target/v1"
						}
						key := target.ServiceContractID + "\x00" + target.CanonicalTarget
						// Formats commits the Domain followed by two u32-length-prefixed
						// strings. This fixture does not call the production ID constructor.
						preimage := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), configuration.DomainID[:]...)
						for _, value := range []string{target.ServiceContractID, target.CanonicalTarget} {
							preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(value)))
							preimage = append(preimage, value...)
						}
						coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: configuration.DomainID, CoordinateID: sha256.Sum256(preimage), ServiceContractID: target.ServiceContractID, CanonicalTarget: target.CanonicalTarget, BindingState: contract.PublicationBindingActive, ActiveBindingIncarnationID: binding.IncarnationID, LastBindingIncarnationID: binding.IncarnationID, LastEntryIncarnationID: target.EntryIncarnationID, CurrentPublicationIncarnationID: contract.ID{byte(40 + 2*i + j)}}
						if i == 0 {
							cloudProof = append(cloudProof, publicOutputCoordinate{ServiceContractID: target.ServiceContractID, TargetContractID: target.TargetContractID, PhysicalTarget: target.CanonicalTarget, CoordinateID: hex.EncodeToString(coordinate.CoordinateID[:]), BindingID: hex.EncodeToString(binding.IncarnationID[:])})
							cloudKey = key
							coordinate.OwnerState = contract.PublicationOwnerQualified
							coordinate.OwnedBirthAttemptID = contract.ID{byte(50 + j)}
							birth := contract.PublicationMarker{DomainID: configuration.DomainID, CoordinateID: coordinate.CoordinateID, AttemptID: coordinate.OwnedBirthAttemptID, State: contract.PublicationAcknowledged, BirthServiceContractID: target.ServiceContractID, BirthTargetContractID: target.TargetContractID}
							birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID = binding.IncarnationID, target.EntryIncarnationID
							birth.Evidence.Class, birth.Evidence.SafeResourceID = contract.PublicationRequestAcknowledged, "created-resource"
							markers[birth.AttemptID] = birth
						} else {
							passiveKey = key
							kind := "plain"
							if j == 1 {
								kind = "secret"
							}
							passiveProof = append(passiveProof, records.PublicOutputPassiveCoordinate{PublicOutputCoordinate: publicOutputCoordinate{ServiceContractID: target.ServiceContractID, TargetContractID: target.TargetContractID, PhysicalTarget: target.CanonicalTarget, CoordinateID: hex.EncodeToString(coordinate.CoordinateID[:]), BindingID: hex.EncodeToString(binding.IncarnationID[:])}, EntryKind: kind, EntryIncarnationID: hex.EncodeToString(target.EntryIncarnationID[:]), Before: coordinate, After: coordinate})
						}
						binding.Targets = append(binding.Targets, target)
						coordinates[key] = coordinate
					}
					configuration.Bindings = append(configuration.Bindings, binding)
				}
				passive := coordinates[passiveKey]
				switch condition {
				case "missing-coordinate":
					delete(coordinates, passiveKey)
				case "extra-coordinate":
					coordinates["foreign"] = passive
				case "passive-admission":
					passive.LastAdmissionOrdinal = 1
				case "passive-birth":
					passive.OwnedBirthAttemptID = contract.ID{99}
				case "passive-ack":
					passive.LastValueAckAttemptID, passive.LastValueDigest = contract.ID{99}, contract.ID{98}
					passive.LastValueAckIncarnationID, passive.LastValueAckOrdinal = contract.ID{97}, 1
				case "passive-unresolved":
					passive.LatestUnresolvedAttemptID = contract.ID{99}
				case "passive-risk":
					passive.PossibleRemoteObject, passive.LateEffectRisk = 1, 1
				case "passive-deletion":
					passive.DeletionDestinationID = "foreign"
				case "passive-marker":
					markers[contract.ID{99}] = contract.PublicationMarker{DomainID: configuration.DomainID, AttemptID: contract.ID{99}, CoordinateID: passive.CoordinateID}
				case "cloud-birth":
					delete(markers, coordinates[cloudKey].OwnedBirthAttemptID)
				case "cloud-entry":
					coordinate := coordinates[cloudKey]
					coordinate.LastEntryIncarnationID = contract.ID{99}
					coordinates[cloudKey] = coordinate
				}
				if condition != "missing-coordinate" {
					coordinates[passiveKey] = passive
				}
				if publicManifestCoordinateInventoryMatches(configuration, coordinates, markers) != (condition == "exact") {
					t.Fatal("manifest coordinate inventory confused passive targets with acknowledged cloud births")
				}
				if condition == "exact" {
					slices.SortFunc(passiveProof, func(a, b records.PublicOutputPassiveCoordinate) int {
						return strings.Compare(a.PhysicalTarget, b.PhysicalTarget)
					})
					configuration.Bindings = configuration.Bindings[1:]
					if !publicManifestPassiveStateMatches(configuration, coordinates, markers, passiveProof, cloudProof, facts) {
						t.Fatal("cleanup lost unchanged passive support")
					}
					markers[contract.ID{99}] = contract.PublicationMarker{DomainID: configuration.DomainID, AttemptID: contract.ID{99}, CoordinateID: passive.CoordinateID}
					if publicManifestPassiveStateMatches(configuration, coordinates, markers, passiveProof, cloudProof, facts) {
						t.Fatal("cleanup admitted a passive publication marker")
					}
					delete(markers, contract.ID{99})
					changed := coordinates[passiveKey]
					changed.CurrentPublicationIncarnationID = contract.ID{99}
					coordinates[passiveKey] = changed
					if publicManifestPassiveStateMatches(configuration, coordinates, markers, passiveProof, cloudProof, facts) {
						t.Fatal("cleanup admitted changed passive incarnation")
					}
					coordinates[passiveKey] = passive
					facts.Entries[0].Plain = false
					if publicManifestPassiveStateMatches(configuration, coordinates, markers, passiveProof, cloudProof, facts) {
						t.Fatal("cleanup detached passive class from original entry")
					}
				}
			})
		}
	}
}

type publicManifestRequest struct {
	Service   string
	Names     []string
	Exact     bool
	Recipient bool
	YAML      bool
}

type publicManifestContent struct {
	Kind         string                      `json:"kind"`
	Plain        *string                     `json:"value_base64,omitempty"`
	Destinations []publicManifestDestination `json:"destinations,omitempty"`
}

type publicManifestArtifactEntry struct {
	Name        string                `json:"name"`
	Incarnation string                `json:"entry_incarnation_id"`
	Content     publicManifestContent `json:"content"`
}

type publicManifestArtifact struct {
	Schema         string                        `json:"schema"`
	FormatContract string                        `json:"format_contract_id"`
	ConfigContract string                        `json:"config_contract_id"`
	Renderer       publicManifestRenderer        `json:"-"`
	Observation    publicManifestObservation     `json:"observation"`
	Target         string                        `json:"target_recipient_id"`
	Selection      publicManifestSelection       `json:"selection"`
	Service        *string                       `json:"service_filter"`
	Entries        []publicManifestArtifactEntry `json:"entries"`
	Excluded       []publicManifestRow           `json:"excluded_entries"`
	Evidence       string                        `json:"evidence_limit"`
}

// Field order and literal target/locator/policy meanings follow the official
// generic JSON plugin grammar. Inputs come from the independent authenticated state, never Reader
// projection, its request builder, its JSON encoder, or a previous manifest.
func publicManifestArtifactExpected(facts publicManifestFacts, request publicManifestRequest) (publicManifestArtifact, []byte) {
	artifact := publicManifestArtifact{Schema: publicManifestFormatContract, FormatContract: publicManifestFormatContract, ConfigContract: publicManifestConfigContract, Renderer: facts.Renderer, Observation: facts.Observation, Target: facts.Authority, Selection: publicManifestSelection{"current-authority", "all-authorized"}, Entries: []publicManifestArtifactEntry{}, Excluded: []publicManifestRow{}, Evidence: "authorized-input-and-exact-bytes"}
	if request.Recipient {
		artifact.Target, artifact.Selection.Target = facts.Recipient, "exact-recipient"
	}
	if request.Exact {
		artifact.Selection.Entry = "exact-names"
	}
	if request.Service != "" {
		service := request.Service
		artifact.Service = &service
	}
	for _, entry := range facts.Entries {
		if request.Recipient && !entry.Ordinary || request.Exact && !slices.Contains(request.Names, entry.Name) {
			continue
		}
		row := publicManifestArtifactEntry{Name: entry.Name, Incarnation: entry.Incarnation}
		if entry.Plain {
			encoded := base64.StdEncoding.EncodeToString([]byte(publicManifestPlain))
			row.Content = publicManifestContent{Kind: "plain", Plain: &encoded}
		} else {
			row.Content.Kind = "secret"
			for _, destination := range entry.Destinations {
				if request.Service == "" || destination.Service == request.Service {
					row.Content.Destinations = append(row.Content.Destinations, destination)
				}
			}
			if len(row.Content.Destinations) == 0 {
				reason := "no-output"
				if len(entry.Destinations) != 0 {
					reason = "no-matching-service"
				}
				artifact.Excluded = append(artifact.Excluded, publicManifestRow{entry.Name, entry.Incarnation, reason})
				continue
			}
		}
		artifact.Entries = append(artifact.Entries, row)
	}
	body, err := json.Marshal(artifact)
	if err != nil {
		return artifact, nil
	}
	return artifact, body
}

func publicManifestCommand(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, facts publicManifestFacts, request publicManifestRequest) {
	t.Helper()
	directory, err := os.MkdirTemp("", "enkv-live-manifest-")
	if err != nil {
		t.Fatal("private manifest target directory unavailable")
	}
	target := filepath.Join(directory, "manifest.json")
	defer func() {
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			t.Error("manifest exact file removal failed", err)
		}
		if err := os.Remove(directory); err != nil {
			t.Error("manifest file or candidate remains", err)
		}
	}()
	if err := os.WriteFile(target, []byte("old complete manifest"), 0600); err != nil {
		t.Fatal("manifest replacement fixture unavailable")
	}
	image := publicSourceImage(t, source)
	commandSource, format := source, "json"
	var portableImage *publicPairImage
	var yamlBody []byte
	if request.YAML {
		portable := publicPortablePair(t, source, t.TempDir())
		original, err := os.ReadFile(portable)
		if err != nil {
			t.Fatal("portable YAML manifest source unavailable")
		}
		yamlBody = append([]byte("# Portable manifest source\n"), original...)
		commandSource, format = filepath.Join(filepath.Dir(portable), "configuration.yaml"), "yaml"
		if os.WriteFile(commandSource, yamlBody, 0400) != nil {
			t.Fatal("portable YAML manifest source write failed")
		}
		copied := publicSourceImage(t, portable)
		portableImage = &copied
	}
	args := []string{"manifest", "--source", commandSource, "--source-format", format, "--out", target, "--plugin", "generic-json", "--settings", "{}", "--json"}
	if request.Service != "" {
		args = append(args, "--service", request.Service)
	}
	if request.Recipient {
		args = append(args, "--recipient-id", facts.Recipient)
	}
	if request.Exact && len(request.Names) == 0 {
		args = append(args, "--empty-selection")
	}
	for _, name := range request.Names {
		args = append(args, "--name", name)
	}
	child := publicCLI(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, nil, args...)
	defer clear(child.Body)
	artifact, want := publicManifestArtifactExpected(facts, request)
	captureOK := publicInspectionReadCapture(child.Capture)
	resultOK := publicManifestResultMatches(child, artifact, want, target)
	fileOK := publicMaterializationFileMatches(target, want)
	if len(want) == 0 || !captureOK || !resultOK || !fileOK {
		t.Logf("manifest code=%d length=%d capture=%t result=%t file=%t", child.Code, len(want), captureOK, resultOK, fileOK)
		t.Fatal("public manifest file, whole partition, native facts or GET-only capability differs")
	}
	publicImageUnchanged(t, image)
	if portableImage != nil {
		publicImageUnchanged(t, *portableImage)
		after, err := os.ReadFile(commandSource)
		if err != nil || !bytes.Equal(after, yamlBody) {
			t.Fatal("manifest changed its YAML public source")
		}
	}
}

func publicManifestResultMatches(child publicChildResult, want publicManifestArtifact, body []byte, target string) bool {
	var result struct {
		Schema   string `json:"schema"`
		Issuance struct {
			Schema    string `json:"schema"`
			Operation string `json:"operation_kind"`
			State     string `json:"state_result"`
			Effect    string `json:"effect_summary"`
			Output    string `json:"output_summary"`
			Context   struct {
				Operation      string `json:"operation"`
				Request        string `json:"request_id"`
				OperationID    string `json:"operation_id"`
				ExpectedDomain string `json:"expected_domain_id"`
			} `json:"context"`
			Observation *publicManifestObservation `json:"observation"`
			Target      string                     `json:"target_recipient_id"`
			Scope       publicManifestScope        `json:"request_scope"`
			Payload     *struct {
				Schema string `json:"schema"`
				publicManifestScope
				Length   uint64              `json:"artifact_length"`
				Digest   string              `json:"artifact_digest"`
				Evidence string              `json:"evidence_limit"`
				Included []publicManifestRow `json:"included_entries"`
				Excluded []publicManifestRow `json:"excluded_entries"`
			} `json:"payload"`
		} `json:"issuance"`
		Delivery struct {
			Target   *string `json:"target_path"`
			Artifact *struct {
				Renderer       string `json:"renderer_artifact_id"`
				FormatContract string `json:"format_contract_id"`
				Length         uint64 `json:"length"`
				Digest         string `json:"digest"`
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
		Result string `json:"result_delivery"`
	}
	decoder := json.NewDecoder(bytes.NewReader(child.Body))
	decoder.DisallowUnknownFields()
	if child.Code != 0 || child.DiagnosticBytes != 0 || decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Schema != "ManifestFileResult/v2" || result.Source != "complete" || result.Result != "not-observed" {
		return false
	}
	r := result.Issuance
	if r.Schema != "ProductResult/v1" || r.Operation != "issue-consumption-manifest" || r.State != "success" || r.Effect != "not-applicable" || r.Output != "not-applicable" || r.Observation == nil || *r.Observation != want.Observation || r.Target != want.Target || !publicManifestScopeMatches(r.Scope, want) || r.Payload == nil {
		return false
	}
	context := r.Context
	if context.Operation != r.Operation || !publicIdentityHex(context.Request) || !publicIdentityHex(context.OperationID) || context.ExpectedDomain != want.Observation.Domain {
		return false
	}
	digest := sha256.Sum256(body)
	hash := hex.EncodeToString(digest[:])
	p := r.Payload
	if p.Schema != "ManifestPayload/v3" || !publicManifestScopeMatches(p.publicManifestScope, want) || p.Length != uint64(len(body)) || p.Digest != hash || p.Evidence != want.Evidence || p.Included == nil || !reflect.DeepEqual(p.Excluded, want.Excluded) || len(p.Included) != len(want.Entries) {
		return false
	}
	for i, entry := range want.Entries {
		if p.Included[i] != (publicManifestRow{Name: entry.Name, Incarnation: entry.Incarnation}) {
			return false
		}
	}
	d := result.Delivery
	parent, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil {
		return false
	}
	canonicalTarget := filepath.Join(parent, filepath.Base(target))
	return d.Target != nil && *d.Target == canonicalTarget && d.Artifact != nil && d.Artifact.Renderer == want.Renderer.Artifact && d.Artifact.FormatContract == publicManifestFormatContract && d.Artifact.Length == uint64(len(body)) && d.Artifact.Digest == hash && d.Replacement == "replaced" && d.Candidate == "verified" && d.Installed == "verified" && d.Completion == "complete" && d.Cleanup == "renamed" && d.Residue == nil && bytes.Equal(d.Failure, []byte("null"))
}

func publicManifestFreshFactsValid(condition string, facts publicProcessFacts) bool {
	if condition != "manifest" {
		return facts.Manifest == nil
	}
	f := facts.Manifest
	if f == nil || !publicManifestRendererValid(f.Renderer) || !f.Verified || !facts.ExpectReady || facts.Domain != f.Observation.Domain || facts.Operator != nil || facts.Replacement != nil || facts.Inspection != nil || facts.Materialization != nil || facts.CapacityGC != nil || len(facts.Outputs) != 2 || len(f.Entries) != 3 {
		return false
	}
	for _, value := range []string{f.Observation.Domain, f.Observation.Revision, f.Observation.Snapshot, f.Authority, f.Recipient} {
		if !publicIdentityHex(value) {
			return false
		}
	}
	if f.Authority == f.Recipient {
		return false
	}
	plain, secret, unrouted := 0, 0, 0
	for i, entry := range f.Entries {
		if !publicIdentityHex(entry.Incarnation) || i != 0 && f.Entries[i-1].Name >= entry.Name {
			return false
		}
		switch {
		case entry.Plain:
			if !entry.Ordinary || len(entry.Destinations) != 0 {
				return false
			}
			plain++
		case len(entry.Destinations) == 4:
			if entry.Ordinary {
				return false
			}
			secret++
		case entry.Name == "UNROUTED" && len(entry.Destinations) == 0 && !entry.Ordinary:
			unrouted++
		default:
			return false
		}
	}
	return plain == 1 && secret == 1 && unrouted == 1
}

func publicManifestFresh(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, facts publicManifestFacts) {
	t.Helper()
	expected := publicManifestExpected(t, ctx, inv, input, budget, source)
	expected.Verified = true
	if !reflect.DeepEqual(expected, facts) {
		t.Fatal("fresh manifest selected public facts differ from the completed writer")
	}
	for _, request := range []publicManifestRequest{{}, {Service: "github-actions/service/v1"}, {Recipient: true}} {
		publicManifestCommand(t, ctx, inv, input, budget, source, facts, request)
	}
}

func publicManifestFixtureFacts(t testing.TB) publicManifestFacts {
	t.Helper()
	id := func(n byte) string { return strings.Repeat(fmt.Sprintf("%02x", n), 32) }
	input := liveRunInput{Settings: liveSettings{Region: "us-east-1", Account: "123456789012"}, PublicConfiguration: &publicConfigurationInput{Outputs: &records.PublicOutputScopes{
		Repository:   records.PublicOutputScope{Owner: "owner", Repository: "repo"},
		Organization: records.PublicOutputScope{Owner: "organization", Repositories: []uint64{101, 202}},
		Environment:  records.PublicOutputScope{Owner: "owner", Repository: "repo", Environment: "prod"},
	}}}
	renderer := publicManifestRenderer{Name: "generic-json", Version: "4.0.0", Protocol: id(20), Descriptor: id(21), Executor: id(22), ArtifactContract: id(23), Dependency: id(24), Artifact: id(25), SHA256: id(26), Length: 100}
	destinations := []publicManifestDestination{}
	for i, name := range []string{"aws-secrets-manager", "github-environment", "github-organization", "github-repository"} {
		destinations = append(destinations, publicManifestDestinationExpected(t, input, id(1), name, id(byte(9+i)), id(7), "SECRET", "arn:aws:secretsmanager:us-east-1:123456789012:secret:SECRET-AbCd12?stage=AWSCURRENT"))
	}
	return publicManifestFacts{Renderer: renderer, Observation: publicManifestObservation{id(1), id(2), id(3)}, Authority: id(4), Recipient: id(5), Verified: true, Entries: []publicManifestEntryFact{
		{Name: "PLAIN", Incarnation: id(6), Plain: true, Ordinary: true},
		{Name: "SECRET", Incarnation: id(7), Destinations: destinations},
		{Name: "UNROUTED", Incarnation: id(8)},
	}}
}

// full_only: false
func TestPublicManifestLiteralSelectionPartition(t *testing.T) {
	f := publicManifestFixtureFacts(t)
	plain := fmt.Sprintf(`{"name":"PLAIN","entry_incarnation_id":"%s","content":{"kind":"plain","value_base64":"cHVibGljIG91dHB1dCBwbGFpbg=="}}`, f.Entries[0].Incarnation)
	cloud := fmt.Sprintf(`{"destination_id":"aws-secrets-manager","binding_incarnation_id":"%s","entry_incarnation_id":"%s","service_contract_id":"ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1","consumer_locator":"arn:aws:secretsmanager:us-east-1:123456789012:secret:SECRET-AbCd12?stage=AWSCURRENT","target_contract_id":"ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1","canonical_target":"arn:aws:secretsmanager:us-east-1:123456789012:secret:SECRET","target_data_base64":"eyJhY2NvdW50IjoiMTIzNDU2Nzg5MDEyIiwicmVnaW9uIjoidXMtZWFzdC0xIiwibmFtZSI6IlNFQ1JFVCJ9","payload_encoding":"base64","consumer_policy":null}`, f.Entries[1].Destinations[0].Binding, f.Entries[1].Incarnation)
	github := fmt.Sprintf(`{"destination_id":"github-environment","binding_incarnation_id":"%s","entry_incarnation_id":"%s","service_contract_id":"github-actions/service/v1","consumer_locator":"repos/owner/repo/environments/prod/secrets/SECRET","target_contract_id":"github-actions/target/v1","canonical_target":"repos/owner/repo/environments/prod/secrets/SECRET","target_data_base64":"eyJzY29wZSI6MywiY29vcmRpbmF0ZSI6InJlcG9zL293bmVyL3JlcG8vZW52aXJvbm1lbnRzL3Byb2Qvc2VjcmV0cy9TRUNSRVQifQ==","payload_encoding":"base64","consumer_policy":null},{"destination_id":"github-organization","binding_incarnation_id":"%s","entry_incarnation_id":"%s","service_contract_id":"github-actions/service/v1","consumer_locator":"orgs/organization/actions/secrets/SECRET","target_contract_id":"github-actions/target/v1","canonical_target":"orgs/organization/actions/secrets/SECRET","target_data_base64":"eyJzY29wZSI6MiwiY29vcmRpbmF0ZSI6Im9yZ3Mvb3JnYW5pemF0aW9uL2FjdGlvbnMvc2VjcmV0cy9TRUNSRVQifQ==","payload_encoding":"base64","consumer_policy":{"contract_id":"github-actions/org-visibility/v1","data_base64":"AAEDAAIAAAAAAAAAZQAAAAAAAADK","digest":"e3f9e43f2e876cea5bd2e8025d643408c4b31b886cb7952120878909ca36cbd8"}},{"destination_id":"github-repository","binding_incarnation_id":"%s","entry_incarnation_id":"%s","service_contract_id":"github-actions/service/v1","consumer_locator":"repos/owner/repo/actions/secrets/SECRET","target_contract_id":"github-actions/target/v1","canonical_target":"repos/owner/repo/actions/secrets/SECRET","target_data_base64":"eyJzY29wZSI6MSwiY29vcmRpbmF0ZSI6InJlcG9zL293bmVyL3JlcG8vYWN0aW9ucy9zZWNyZXRzL1NFQ1JFVCJ9","payload_encoding":"base64","consumer_policy":null}`, f.Entries[1].Destinations[1].Binding, f.Entries[1].Incarnation, f.Entries[1].Destinations[2].Binding, f.Entries[1].Incarnation, f.Entries[1].Destinations[3].Binding, f.Entries[1].Incarnation)
	secret := func(destinations string) string {
		return fmt.Sprintf(`{"name":"SECRET","entry_incarnation_id":"%s","content":{"kind":"secret","destinations":[%s]}}`, f.Entries[1].Incarnation, destinations)
	}
	unrouted := fmt.Sprintf(`{"name":"UNROUTED","entry_incarnation_id":"%s","reason":"no-output"}`, f.Entries[2].Incarnation)
	filtered := fmt.Sprintf(`{"name":"SECRET","entry_incarnation_id":"%s","reason":"no-matching-service"}`, f.Entries[1].Incarnation)
	for _, row := range []struct {
		name                                                      string
		request                                                   publicManifestRequest
		target, targetMode, entryMode, service, entries, excluded string
	}{
		{"defaults", publicManifestRequest{}, f.Authority, "current-authority", "all-authorized", "null", plain + "," + secret(cloud+","+github), unrouted},
		{"github", publicManifestRequest{Service: "github-actions/service/v1"}, f.Authority, "current-authority", "all-authorized", `"github-actions/service/v1"`, plain + "," + secret(github), unrouted},
		{"cloud", publicManifestRequest{Service: "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1"}, f.Authority, "current-authority", "all-authorized", `"ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1"`, plain + "," + secret(cloud), unrouted},
		{"all-excluded", publicManifestRequest{Service: "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", Exact: true, Names: []string{"SECRET"}}, f.Authority, "current-authority", "exact-names", `"ENKV/OUTPUT/GCP-SECRET-MANAGER/v1"`, "", filtered},
		{"plain-under-other-cloud", publicManifestRequest{Service: "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1"}, f.Authority, "current-authority", "all-authorized", `"ENKV/OUTPUT/GCP-SECRET-MANAGER/v1"`, plain, filtered + "," + unrouted},
		{"empty", publicManifestRequest{Exact: true, Names: []string{}}, f.Authority, "current-authority", "exact-names", "null", "", ""},
		{"ordinary-recipient", publicManifestRequest{Recipient: true}, f.Recipient, "exact-recipient", "all-authorized", "null", plain, ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, got := publicManifestArtifactExpected(f, row.request)
			want := fmt.Sprintf(`{"schema":"ENKV/CONSUMPTION-MANIFEST/v3","format_contract_id":"ENKV/CONSUMPTION-MANIFEST/v3","config_contract_id":"ENKV/CONSUMPTION-MANIFEST-CONFIG/v1","observation":{"domain_id":"%s","head_revision_id":"%s","snapshot_id":"%s"},"target_recipient_id":"%s","selection":{"target_mode":"%s","entry_mode":"%s"},"service_filter":%s,"entries":[%s],"excluded_entries":[%s],"evidence_limit":"authorized-input-and-exact-bytes"}`, f.Observation.Domain, f.Observation.Revision, f.Observation.Snapshot, row.target, row.targetMode, row.entryMode, row.service, row.entries, row.excluded)
			if string(got) != want {
				t.Fatal("public manifest oracle differs from the independently written literal partition")
			}
		})
	}
}

// full_only: false
func TestPublicManifestResultRequiresCompleteNativeAndPartitionFacts(t *testing.T) {
	f := publicManifestFixtureFacts(t)
	artifact, body := publicManifestArtifactExpected(f, publicManifestRequest{})
	digest := sha256.Sum256(body)
	hash := hex.EncodeToString(digest[:])
	included := []publicManifestRow{{Name: "PLAIN", Incarnation: f.Entries[0].Incarnation}, {Name: "SECRET", Incarnation: f.Entries[1].Incarnation}}
	scope := publicManifestScope{f.Renderer, publicManifestFormatContract, publicManifestConfigContract, []byte("{}"), artifact.Selection, nil}
	payload := map[string]any{"schema": "ManifestPayload/v3", "renderer": scope.Renderer, "format_contract_id": scope.FormatContract, "config_contract_id": scope.ConfigContract, "settings": scope.Settings, "artifact_length": len(body), "artifact_digest": hash, "evidence_limit": artifact.Evidence, "selection": artifact.Selection, "service_filter": nil, "included_entries": included, "excluded_entries": artifact.Excluded}
	context := map[string]any{"operation": "issue-consumption-manifest", "request_id": f.Authority, "operation_id": f.Recipient, "expected_domain_id": f.Observation.Domain}
	issuance := map[string]any{"schema": "ProductResult/v1", "operation_kind": "issue-consumption-manifest", "state_result": "success", "effect_summary": "not-applicable", "output_summary": "not-applicable", "context": context, "observation": artifact.Observation, "target_recipient_id": artifact.Target, "request_scope": scope, "payload": payload}
	delivery := map[string]any{"target_path": "/manifest.json", "artifact": map[string]any{"renderer_artifact_id": f.Renderer.Artifact, "format_contract_id": publicManifestFormatContract, "length": len(body), "digest": hash}, "replacement": "replaced", "candidate_verification": "verified", "installed_verification": "verified", "native_completion": "complete", "candidate_cleanup": "renamed", "residue_path": nil, "failure": nil}
	wire, err := json.Marshal(map[string]any{"schema": "ManifestFileResult/v2", "issuance": issuance, "delivery": delivery, "source_cleanup": "complete", "result_delivery": "not-observed"})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"complete", func(map[string]any) {}, true},
		{"source-unknown", func(v map[string]any) { v["source_cleanup"] = "unknown" }, false},
		{"missing-installed-verification", func(v map[string]any) { v["delivery"].(map[string]any)["installed_verification"] = "not-observed" }, false},
		{"wrong-renderer-artifact", func(v map[string]any) {
			v["delivery"].(map[string]any)["artifact"].(map[string]any)["renderer_artifact_id"] = f.Authority
		}, false},
		{"changed-scope-build", func(v map[string]any) {
			v["issuance"].(map[string]any)["request_scope"].(map[string]any)["renderer"].(map[string]any)["descriptor_id"] = f.Authority
		}, false},
		{"changed-payload-build", func(v map[string]any) {
			v["issuance"].(map[string]any)["payload"].(map[string]any)["renderer"].(map[string]any)["executor_id"] = f.Authority
		}, false},
		{"changed-payload-settings", func(v map[string]any) {
			v["issuance"].(map[string]any)["payload"].(map[string]any)["settings"] = []byte("{ }")
		}, false},
		{"changed-format-contract", func(v map[string]any) {
			v["delivery"].(map[string]any)["artifact"].(map[string]any)["format_contract_id"] = "private/format/v1"
		}, false},
		{"wrong-artifact-digest", func(v map[string]any) {
			v["delivery"].(map[string]any)["artifact"].(map[string]any)["digest"] = f.Authority
		}, false},
		{"partial-partition", func(v map[string]any) {
			v["issuance"].(map[string]any)["payload"].(map[string]any)["included_entries"] = []any{}
		}, false},
		{"wrong-filter", func(v map[string]any) {
			v["issuance"].(map[string]any)["payload"].(map[string]any)["service_filter"] = "github-actions/service/v1"
		}, false},
		{"unknown-file-field", func(v map[string]any) { v["raw_artifact"] = []byte("application bytes") }, false},
		{"unknown-context-field", func(v map[string]any) {
			v["issuance"].(map[string]any)["context"].(map[string]any)["raw_artifact"] = []byte("application bytes")
		}, false},
		{"wrong-context-domain", func(v map[string]any) {
			v["issuance"].(map[string]any)["context"].(map[string]any)["expected_domain_id"] = f.Authority
		}, false},
		{"missing-omission", func(v map[string]any) {
			v["issuance"].(map[string]any)["payload"].(map[string]any)["excluded_entries"] = []any{}
		}, false},
		{"changed-observation", func(v map[string]any) {
			v["issuance"].(map[string]any)["observation"].(map[string]any)["snapshot_id"] = f.Authority
		}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			var value map[string]any
			if json.Unmarshal(wire, &value) != nil {
				t.Fatal("synthetic manifest result unavailable")
			}
			row.change(value)
			changed, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if publicManifestResultMatches(publicChildResult{Body: changed}, artifact, body, "/manifest.json") != row.valid {
				t.Fatal("manifest result accepted a partial or different terminal fact")
			}
		})
	}
	t.Run("canonical-parent", func(t *testing.T) {
		real, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(t.TempDir(), "parent-alias")
		if err := os.Symlink(real, alias); err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(wire, &value); err != nil {
			t.Fatal(err)
		}
		value["delivery"].(map[string]any)["target_path"] = filepath.Join(real, "manifest.json")
		changed, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if !publicManifestResultMatches(publicChildResult{Body: changed}, artifact, body, filepath.Join(alias, "manifest.json")) {
			t.Fatal("native canonical target was compared to an aliased input path")
		}
	})
}

// full_only: false
func TestPublicManifestFreshFactsKeepExactVariant(t *testing.T) {
	f := publicManifestFixtureFacts(t)
	base := publicProcessFacts{Domain: f.Observation.Domain, ExpectReady: true, Manifest: &f, Outputs: make([]publicOutputCoordinate, 2)}
	wire, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name      string
		change    func(*publicProcessFacts)
		condition string
		valid     bool
	}{
		{"complete", func(*publicProcessFacts) {}, "manifest", true},
		{"missing", func(p *publicProcessFacts) { p.Manifest = nil }, "manifest", false},
		{"unverified-writer", func(p *publicProcessFacts) { p.Manifest.Verified = false }, "manifest", false},
		{"foreign-condition", func(*publicProcessFacts) {}, "materialization", false},
		{"different-domain", func(p *publicProcessFacts) { p.Domain = f.Authority }, "manifest", false},
		{"materialization-variant", func(p *publicProcessFacts) { p.Materialization = &publicMaterializationFacts{} }, "manifest", false},
		{"partial-entries", func(p *publicProcessFacts) { p.Manifest.Entries = p.Manifest.Entries[:2] }, "manifest", false},
		{"missing-cloud-evidence", func(p *publicProcessFacts) { p.Outputs = nil }, "manifest", false},
		{"nil-other-variant", func(p *publicProcessFacts) { p.Manifest = nil }, "materialization", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			var p publicProcessFacts
			if json.Unmarshal(wire, &p) != nil {
				t.Fatal("synthetic fresh manifest facts unavailable")
			}
			row.change(&p)
			if publicManifestFreshFactsValid(row.condition, p) != row.valid {
				t.Fatal("fresh manifest facts admitted an incomplete or foreign variant")
			}
		})
	}
}

// full_only: false
func TestPublicManifestCloudPreparationScopesDoNotRequireGitHubEffects(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "parent-token-must-not-be-forwarded")
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			input := liveRunInput{Prefix: "enkv-test/manifest/fixture", Scenarios: []string{"public-configuration.manifest/atomic_public_file"}, Settings: liveSettings{Provider: provider, Region: "us-east-1", Account: "123456789012", ProjectNumber: "123456789"}, PublicConfiguration: &publicConfigurationInput{Outputs: &records.PublicOutputScopes{Repository: records.PublicOutputScope{Owner: "owner", Repository: "repository"}, Organization: records.PublicOutputScope{Owner: "organization", Visibility: "selected", Repositories: []uint64{101, 202}}, Environment: records.PublicOutputScope{Owner: "owner", Repository: "repository", Environment: "prod"}}}}
			cloud := "aws-secrets-manager"
			if provider == "gcp" {
				cloud = "gcp-secret-manager"
			}
			if !slices.Equal(publicOutputScopes(input), []string{cloud}) || len(publicExpectedOutputCoordinates(input)) != 2 || len(publicOutputDeclaration(input)["destinations"].(map[string]any)) != 1 {
				t.Fatal("manifest preparation acquired a GitHub effect scope")
			}
			passive := publicManifestDeclaration(input)
			if len(passive["destinations"].(map[string]any)) != 4 {
				t.Fatal("manifest lost its passive GitHub destinations")
			}
			names := publicOutputNames(input.Prefix)
			destinations := []string{cloud, "github-repository", "github-organization", "github-environment"}
			wantRouting := map[string]any{"entries": map[string]any{names[0]: destinations, names[1]: destinations}}
			if !reflect.DeepEqual(passive["routing"], wantRouting) {
				t.Fatal("manifest must route only its published names; unselected entries must stay unrouted")
			}
			passiveScopes := destinations[1:]
			cleanup := publicManifestDeclarationForScopes(input, passiveScopes)
			cleanupDestinations := cleanup["destinations"].(map[string]any)
			wantCleanupRouting := map[string]any{"entries": map[string]any{names[0]: passiveScopes, names[1]: passiveScopes}}
			if len(cleanupDestinations) != 3 || cleanupDestinations[cloud] != nil || !reflect.DeepEqual(cleanup["routing"], wantCleanupRouting) {
				t.Fatal("manifest cleanup removed passive declarations or retained a cloud binding")
			}
			for _, value := range publicOutputEnvironment([]string{"GITHUB_TOKEN=must-not-be-used", "GH_TOKEN=must-not-be-used"}, true, publicOutputScopes(input)) {
				if strings.HasPrefix(value, "GITHUB_TOKEN=") || strings.HasPrefix(value, "GH_TOKEN=") {
					t.Fatal("manifest inherited a GitHub bearer")
				}
			}
		})
	}
	t.Run("retained-cloud-birth", func(t *testing.T) {
		binding, entry, attempt, coordinateID := contract.ID{1}, contract.ID{2}, contract.ID{3}, contract.ID{4}
		target := contract.OutputTarget{ServiceContractID: "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", TargetContractID: "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1", CanonicalTarget: "planned", EntryIncarnationID: entry, LocatorRequiresCreation: true}
		coordinate := contract.PublicationCoordinate{CoordinateID: coordinateID, ServiceContractID: target.ServiceContractID, CanonicalTarget: target.CanonicalTarget, ActiveBindingIncarnationID: binding, LastEntryIncarnationID: entry, OwnedBirthAttemptID: attempt}
		birth := contract.PublicationMarker{CoordinateID: coordinateID, AttemptID: attempt, State: contract.PublicationAcknowledged}
		birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID = binding, entry
		birth.BirthServiceContractID, birth.BirthTargetContractID = target.ServiceContractID, target.TargetContractID
		birth.Evidence.Class, birth.Evidence.SafeResourceID, birth.Evidence.ConsumerLocator = contract.PublicationRequestAcknowledged, "actual-resource", "actual-resource?stage=AWSCURRENT"
		if !publicManifestCloudBirthMatches(coordinate, birth, binding, target) {
			t.Fatal("exact retained cloud birth refused")
		}
		for _, condition := range []string{"binding", "entry", "birth", "resource", "evidence", "consumer-locator", "service-contract", "target-contract"} {
			c, b := coordinate, birth
			switch condition {
			case "binding":
				c.ActiveBindingIncarnationID = contract.ID{9}
			case "entry":
				b.Projection.EntryIncarnationID = contract.ID{9}
			case "birth":
				b.AttemptID = contract.ID{9}
			case "resource":
				b.Evidence.SafeResourceID = ""
			case "evidence":
				b.Evidence.Class = 0
			case "consumer-locator":
				b.Evidence.ConsumerLocator = ""
			case "service-contract":
				b.BirthServiceContractID = "private/service/v1"
			case "target-contract":
				b.BirthTargetContractID = "private/target/v1"
			}
			if publicManifestCloudBirthMatches(c, b, binding, target) {
				t.Fatal("cloud birth accepted changed selected facts", condition)
			}
		}
	})
}

// full_only: false
func TestPublicSelectedOutputsReloadReleasedConfiguration(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	entries := fixtureStateImage(t, f).entryInputs()
	entry := f.session.valueEntry(0).Incarnation
	intent := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{{
		entryName: entries[0].Name,
		target: outputFixtureTarget("aws", "app-secret", "app-secret?stage=AWSCURRENT", contract.OutputEncodingRaw,
			contract.OutputCapabilityCreateWithValue|contract.OutputCapabilityWriteValue|contract.OutputCapabilityDeleteOwned, contract.OutputPolicy{}),
	}}}}}
	selectOutputConfiguration(t, f, entries, intent)
	var released int
	for _, page := range f.session.support {
		for _, row := range page.Records {
			if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body == nil {
				released++
			}
		}
	}
	if released == 0 {
		t.Fatal("fixture retained output bodies instead of selected facts")
	}
	before := observeSelectedState(t, f.session)
	configuration, coordinates, markers := publicSelectedOutputs(t, t.Context(), f.session)
	if len(configuration.Bindings) != 1 || len(coordinates) != 1 || len(markers) != 0 {
		t.Fatal("public output observation lost the exact configuration or invented publication evidence")
	}
	binding := configuration.Bindings[0]
	if binding.DestinationID != "app" || len(binding.Targets) != 1 {
		t.Fatal("public output observation changed the destination or target set")
	}
	coordinate := coordinates["aws\x00app-secret"]
	if coordinate.ServiceContractID != "aws" || coordinate.CanonicalTarget != "app-secret" ||
		coordinate.ActiveBindingIncarnationID != binding.IncarnationID || coordinate.LastEntryIncarnationID != entry || !coordinate.OwnedBirthAttemptID.IsZero() {
		t.Fatal("public output observation changed the unpublished coordinate")
	}
	target := binding.Targets[0]
	if target.EntryIncarnationID != entry || target.CanonicalTarget != "app-secret" ||
		target.ConsumerLocator != "app-secret?stage=AWSCURRENT" || !bytes.Equal(target.TargetData, []byte("target:app-secret")) {
		t.Fatal("public output observation changed selected target meaning")
	}
	configuration.Bindings[0].Targets[0].TargetData[0] ^= 1
	again, _, _ := publicSelectedOutputs(t, t.Context(), f.session)
	if !bytes.Equal(again.Bindings[0].Targets[0].TargetData, []byte("target:app-secret")) ||
		!reflect.DeepEqual(observeSelectedState(t, f.session), before) {
		t.Fatal("public output observation borrowed bytes or changed selected state")
	}
}
