package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/examples/ini-reference-manifest/consumer"
	"enkv.sh/telemetry"
)

const stockPlainValue = "stock plugin plain value"
const stockSecretValue = "stock plugin secret\x00\xff"

// full_only: false
func TestStockOutputDeclarationRoutesOnlySuppliedPair(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			for _, suffix := range []string{"first", "second"} {
				t.Run(suffix, func(t *testing.T) {
					input := liveRunInput{Settings: liveSettings{Provider: provider, Region: "ap-southeast-2", Account: "123456789012", ProjectNumber: "123456789"},
						Prefix: "enkv-test/stock-output-" + suffix, Scenarios: []string{records.StockPluginScenario},
						PublicConfiguration: &publicConfigurationInput{Outputs: &records.PublicOutputScopes{
							Repository:   records.PublicOutputScope{Owner: "fixture", Repository: "repository"},
							Organization: records.PublicOutputScope{Owner: "fixture", Visibility: "selected", Repositories: []uint64{11, 22}},
							Environment:  records.PublicOutputScope{Owner: "fixture", Repository: "repository", Environment: "environment"},
						}}}
					if provider == "gcp" && suffix == "first" {
						input.PublicConfiguration.Outputs = nil
					}
					before, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					// The fixture name contract is SHA256 of the complete prefix.
					sum := sha256.Sum256([]byte(input.Prefix))
					stem := "ENKV_" + strings.ToUpper(hex.EncodeToString(sum[:]))
					plain, secret := stem+"_PLAIN", stem+"_SECRET"
					scopes := []string{"aws-secrets-manager", "github-repository", "github-organization", "github-environment"}
					destinations := map[string]any{
						"aws-secrets-manager": map[string]any{"plugin": "aws-secrets-manager", "settings": map[string]any{"account": "123456789012", "region": "ap-southeast-2"}},
						"github-repository":   map[string]any{"plugin": "github-actions-repository", "settings": map[string]any{"owner": "fixture", "repository": "repository"}},
						"github-organization": map[string]any{"plugin": "github-actions-organization", "settings": map[string]any{"owner": "fixture", "visibility": "selected", "repositories": []uint64{11, 22}}},
						"github-environment":  map[string]any{"plugin": "github-actions-environment", "settings": map[string]any{"owner": "fixture", "repository": "repository", "environment": "environment"}},
					}
					if provider == "gcp" {
						scopes = []string{"gcp-secret-manager"}
						destinations = map[string]any{"gcp-secret-manager": map[string]any{"plugin": "gcp-secret-manager", "settings": map[string]any{"project_number": "123456789"}}}
					}
					want := map[string]any{"destinations": destinations, "routing": map[string]any{"entries": map[string]any{plain: scopes, secret: scopes}}, "groups": [][]string{{plain, secret}}}
					actualBody, err := json.Marshal(stockOutputDeclaration(input))
					if err != nil {
						t.Fatal(err)
					}
					wantBody, err := json.Marshal(want)
					var actualObject, wantObject any
					if err != nil || json.Unmarshal(actualBody, &actualObject) != nil || json.Unmarshal(wantBody, &wantObject) != nil {
						t.Fatal("stock output declaration could not be read")
					}
					if !reflect.DeepEqual(actualObject, wantObject) {
						t.Fatal("stock output declaration must route only the supplied pair; generated and unrelated entries must have no inherited route")
					}
					after, err := json.Marshal(input)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("stock output declaration changed caller input")
					}
				})
			}
		})
	}
}

func stockOutputDeclaration(input liveRunInput) map[string]any {
	copyInput := input
	copyPublic := *input.PublicConfiguration
	if copyPublic.Outputs == nil {
		copyPublic.Outputs = &records.PublicOutputScopes{}
	}
	copyInput.PublicConfiguration = &copyPublic
	scopes := publicOutputScopes(input)
	declaration := publicOutputDeclarationForScopes(copyInput, scopes)
	names := publicOutputNames(input.Prefix)
	declaration["routing"] = map[string]any{"entries": map[string]any{
		names[0]: slices.Clone(scopes), names[1]: slices.Clone(scopes),
	}}
	return declaration
}

func (r *stockPluginRun) outputPreview(ctx context.Context, source string) (publicOutputPreview, string, publicComparisonObservation) {
	image := publicSourceImage(r.t, source)
	child := r.command(ctx, "plan", "reader", "", nil, "plan", "--trusted", source, "--trusted-format", "json", "--publish", "--json")
	defer clear(child.Body)
	product := publicProduct(r.t, child, contract.ReaderCompareOperation)
	var out struct {
		Payload struct {
			Publication publicOutputPreview `json:"publication"`
		} `json:"payload"`
	}
	if child.Code != 0 && child.Code != 1 || product.State != "success" || !product.Payload.Complete || len(product.Payload.Scope) != 12 || json.Unmarshal(child.Body, &out) != nil || product.Observation == nil || !publicIdentityHex(product.Observation.Domain) || !publicIdentityHex(product.Observation.Revision) || !publicIdentityHex(product.Observation.Snapshot) {
		r.t.Fatal("stock complete output observation unavailable")
	}
	for _, scope := range product.Payload.Scope {
		if scope.Status != "complete" {
			r.t.Fatal("stock output observation omitted a scope")
		}
	}
	publicImageUnchanged(r.t, image)
	return out.Payload.Publication, product.Payload.Verdict, *product.Observation
}

func (r *stockPluginRun) plainApply(ctx context.Context, source string) {
	image := publicSourceImage(r.t, source)
	child := r.command(ctx, "plan", "apply", "", nil, "apply", "--source", source, "--source-format", "json", "--json")
	defer clear(child.Body)
	if !publicApplyMatches(child, publicProduct(r.t, child, "apply-declaration"), "success") {
		r.t.Fatal("stock output configuration apply differs")
	}
	publicImageUnchanged(r.t, image)
}

type stockPublicationSupport struct{ Protocol, Config, Artifact contract.ID }

type stockPublicationObservation struct {
	Domain, Operation contract.ID
	Markers           map[contract.ID]contract.PublicationMarker
}

// full_only: false
func TestStockPublicationBindsStartingObservationAfterStateWrites(t *testing.T) {
	const domain = "1111111111111111111111111111111111111111111111111111111111111111"
	const operation = "2222222222222222222222222222222222222222222222222222222222222222"
	const start = "3333333333333333333333333333333333333333333333333333333333333333"
	const current = "4444444444444444444444444444444444444444444444444444444444444444"
	const revision = "5555555555555555555555555555555555555555555555555555555555555555"
	for _, phase := range []string{"publication", "deletion"} {
		t.Run(phase, func(t *testing.T) {
			beforeSnapshot, afterSnapshot, operationID := start, current, operation
			if phase == "deletion" {
				beforeSnapshot, afterSnapshot, operationID = current, revision, strings.Repeat("6", 64)
			}
			body := `{"schema":"ProductResult/v1","operation_kind":"publish","domain_id":"` + domain + `","operation_id":"` + operationID + `","payload":{"schema":"OutputPayload/v3","domain_id":"` + domain + `","operation_id":"` + operationID + `","snapshot_id":"` + beforeSnapshot + `"}}`
			for _, condition := range []string{"fixed-start", "same-snapshot", "current-only", "wrong-before-snapshot", "stale-publication-observation", "wrong-before-domain", "wrong-current-domain", "missing-before", "zero-before-revision", "malformed-before-snapshot", "missing-domain", "null-domain", "zero-operation", "malformed-operation", "payload-domain", "payload-operation", "duplicate-domain", "malformed-json"} {
				t.Run(condition, func(t *testing.T) {
					before := publicComparisonObservation{Domain: domain, Revision: revision, Snapshot: beforeSnapshot}
					after := publicComparisonObservation{Domain: domain, Snapshot: afterSnapshot}
					candidate := body
					want := condition == "fixed-start" || condition == "same-snapshot"
					switch condition {
					case "same-snapshot":
						after.Snapshot = beforeSnapshot
					case "current-only":
						candidate = strings.Replace(candidate, `"snapshot_id":"`+beforeSnapshot, `"snapshot_id":"`+afterSnapshot, 1)
					case "wrong-before-snapshot":
						before.Snapshot = operationID
					case "stale-publication-observation":
						before.Snapshot = start
						if phase == "publication" {
							before.Snapshot = revision
						}
					case "wrong-before-domain":
						before.Domain = revision
					case "wrong-current-domain":
						after.Domain = revision
					case "missing-before":
						before = publicComparisonObservation{}
					case "zero-before-revision":
						before.Revision = strings.Repeat("0", 64)
					case "malformed-before-snapshot":
						before.Snapshot = "bad"
					case "missing-domain":
						candidate = strings.Replace(candidate, `"domain_id":"`+domain+`",`, "", 1)
					case "null-domain":
						candidate = strings.Replace(candidate, `"domain_id":"`+domain+`"`, `"domain_id":null`, 1)
					case "zero-operation":
						candidate = strings.ReplaceAll(candidate, operationID, strings.Repeat("0", 64))
					case "malformed-operation":
						candidate = strings.ReplaceAll(candidate, operationID, "bad")
					case "payload-domain":
						candidate = strings.Replace(candidate, `"payload":{"schema":"OutputPayload/v3","domain_id":"`+domain, `"payload":{"schema":"OutputPayload/v3","domain_id":"`+revision, 1)
					case "payload-operation":
						candidate = strings.Replace(candidate, `"operation_id":"`+operationID+`","snapshot_id"`, `"operation_id":"`+revision+`","snapshot_id"`, 1)
					case "duplicate-domain":
						candidate = strings.Replace(candidate, `"domain_id":"`+domain+`"`, `"domain_id":"`+domain+`","domain_id":"`+domain+`"`, 1)
					case "malformed-json":
						candidate = candidate[:len(candidate)-1]
					}
					domainID, observedOperation, valid := stockPublicationObservationIdentities([]byte(candidate), before, after)
					if valid != want {
						t.Fatal("stock publication must bind its fixed starting observation after publication state writes")
					}
					if valid && (hex.EncodeToString(domainID[:]) != domain || hex.EncodeToString(observedOperation[:]) != operationID) {
						t.Fatal("stock publication observation changed operation or domain")
					}
				})
			}
		})
	}
}

func stockPublicationObservationIdentities(body []byte, before, after publicComparisonObservation) (contract.ID, contract.ID, bool) {
	var envelope struct {
		Domain    string `json:"domain_id"`
		Operation string `json:"operation_id"`
		Payload   struct {
			Domain    string `json:"domain_id"`
			Operation string `json:"operation_id"`
			Snapshot  string `json:"snapshot_id"`
		} `json:"payload"`
	}
	if jsonv2.Unmarshal(body, &envelope) != nil || !publicIdentityHex(envelope.Domain) || !publicIdentityHex(envelope.Operation) || envelope.Payload.Domain != envelope.Domain || envelope.Payload.Operation != envelope.Operation {
		return contract.ID{}, contract.ID{}, false
	}
	if !publicIdentityHex(before.Domain) || !publicIdentityHex(before.Revision) || !publicIdentityHex(before.Snapshot) || after.Domain != before.Domain || envelope.Domain != before.Domain || envelope.Payload.Snapshot != before.Snapshot {
		return contract.ID{}, contract.ID{}, false
	}
	domain, _ := hex.DecodeString(envelope.Domain)
	operation, _ := hex.DecodeString(envelope.Operation)
	return contract.ID(domain), contract.ID(operation), true
}

func (r *stockPluginRun) outputObservation(ctx context.Context, source string, child publicChildResult, before publicComparisonObservation) stockPublicationObservation {
	selected := r.selected(ctx, source)
	after := publicComparisonObservation{Domain: hex.EncodeToString(selected.root.Domain[:]), Snapshot: hex.EncodeToString(selected.root.Snapshot[:])}
	domain, operation, valid := stockPublicationObservationIdentities(child.Body, before, after)
	if !valid {
		r.t.Fatal("stock publication result or selected observation differs")
	}
	_, _, markers := publicSelectedOutputs(r.t, ctx, selected)
	return stockPublicationObservation{Domain: domain, Operation: operation, Markers: markers}
}

func (r *stockPluginRun) outputContracts(expected []publicOutputCoordinate) map[string]stockPublicationSupport {
	support := make(map[string]stockPublicationSupport, len(expected))
	for _, coordinate := range expected {
		name := publicOutputDeletionPlugin(r.t, coordinate)
		found := false
		for _, build := range r.input.PublicConfiguration.Stock.Artifact.Outputs {
			if build.Metadata.Name != name {
				continue
			}
			facts, err := build.Metadata.OutputFacts()
			if err != nil || facts.Descriptor.Output == nil {
				r.t.Fatal("stock admitted output support unavailable")
			}
			wire, err := hex.DecodeString(facts.Descriptor.Wire.Identity)
			if err != nil || len(wire) != 32 {
				r.t.Fatal("stock admitted output protocol unavailable")
			}
			config, err := contract.OutputConfigContractDigest(facts.Descriptor.Output.ConfigContractID)
			if err != nil {
				r.t.Fatal("stock admitted output config contract unavailable")
			}
			support[coordinate.CoordinateID] = stockPublicationSupport{Protocol: contract.ID(wire), Config: config, Artifact: contract.ID(facts.ArtifactContractID)}
			found = true
		}
		if !found {
			r.t.Fatal("stock exact output build unavailable")
		}
	}
	return support
}

func stockOutputActionsMatch(rows []records.PublicOutputActionResult, expected []publicOutputCoordinate, support map[string]stockPublicationSupport, observation stockPublicationObservation, deletion bool) bool {
	if len(rows) != len(expected) || len(support) != len(expected) || observation.Domain.IsZero() || observation.Operation.IsZero() || observation.Markers == nil {
		return false
	}
	want := make([]string, len(expected))
	coordinates := make(map[string]publicOutputCoordinate, len(expected))
	for i, coordinate := range expected {
		if !publicIdentityHex(coordinate.CoordinateID) || !publicIdentityHex(coordinate.BindingID) {
			return false
		}
		if _, duplicate := coordinates[coordinate.CoordinateID]; duplicate {
			return false
		}
		want[i] = coordinate.CoordinateID
		coordinates[coordinate.CoordinateID] = coordinate
	}
	slices.Sort(want)
	seen := make(map[string]bool)
	names := [...]string{"", "create-empty", "create-with-value", "write-value", "update-policy", "delete-owned", "delete-reserved-slot"}
	for i, row := range rows {
		if row.Coordinate != want[i] {
			return false
		}
		coordinate := coordinates[row.Coordinate]
		build, present := support[row.Coordinate]
		if !present || build.Protocol.IsZero() || build.Config.IsZero() || build.Artifact.IsZero() {
			return false
		}
		var actions []uint8
		switch {
		case coordinate.ServiceContractID == "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1" && coordinate.TargetContractID == "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1",
			coordinate.ServiceContractID == "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1" && coordinate.TargetContractID == "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1":
			actions = []uint8{contract.PublicationCreateEmpty, contract.PublicationWriteValue}
		case coordinate.ServiceContractID == "github-actions/service/v1" && coordinate.TargetContractID == "github-actions/target/v1":
			actions = []uint8{contract.PublicationCreateWithValue}
		default:
			return false
		}
		if deletion {
			actions = []uint8{contract.PublicationDeleteOwned}
		}
		if len(row.Actions) != len(actions) {
			return false
		}
		for at, action := range row.Actions {
			kind := actions[at]
			if !action.ValidAcknowledgement() || *action.Action != names[kind] || seen[*action.Attempt] || action.Evidence.SafeRequestID == nil || action.Evidence.SafeResourceID == nil {
				return false
			}
			seen[*action.Attempt] = true
			request, err := contract.PublicationRequestContractDigest(build.Protocol, build.Config, coordinate.ServiceContractID, coordinate.TargetContractID, kind)
			if err != nil {
				return false
			}
			response, err := contract.PublicationResponseContractDigest(request, build.Artifact)
			if err != nil || action.Evidence.Response != hex.EncodeToString(response[:]) {
				return false
			}
			attempt, err := hex.DecodeString(*action.Attempt)
			if err != nil || len(attempt) != 32 {
				return false
			}
			marker, present := observation.Markers[contract.ID(attempt)]
			projection, projectionErr := hex.DecodeString(*action.Projection)
			coordinateID, coordinateErr := hex.DecodeString(coordinate.CoordinateID)
			bindingID, bindingErr := hex.DecodeString(coordinate.BindingID)
			if !present || projectionErr != nil || len(projection) != 32 || coordinateErr != nil || len(coordinateID) != 32 || bindingErr != nil || len(bindingID) != 32 {
				return false
			}
			evidence := contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: response, NormalizedStatus: action.Evidence.Status, SafeRequestID: *action.Evidence.SafeRequestID, SafeResourceID: *action.Evidence.SafeResourceID, ConsumerLocator: *action.Evidence.ConsumerLocator}
			if marker.DomainID != observation.Domain || marker.OperationID != observation.Operation || marker.AttemptID != contract.ID(attempt) || marker.CoordinateID != contract.ID(coordinateID) || marker.ProjectionCommitment != contract.ID(projection) || marker.State != contract.PublicationAcknowledged || marker.BlockerCount != 0 || !marker.BlockerDigest.IsZero() || marker.LateEffectRisk != 0 || marker.Evidence != evidence ||
				marker.Projection.DomainID != observation.Domain || marker.Projection.CoordinateID != contract.ID(coordinateID) || marker.Projection.BindingIncarnationID != contract.ID(bindingID) || marker.Projection.Action != kind || marker.Projection.RequestContractDigest != request || !stockOutputResponseMatches(coordinate, kind, action) {
				return false
			}
		}
	}
	return true
}

func stockOutputResponseMatches(coordinate publicOutputCoordinate, kind uint8, action records.PublicOutputAction) bool {
	evidence := action.Evidence
	resource, locator := *evidence.SafeResourceID, *evidence.ConsumerLocator
	switch coordinate.ServiceContractID {
	case "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1":
		if evidence.Status != http.StatusOK {
			return false
		}
		if kind == contract.PublicationWriteValue {
			return resource == *action.Attempt && locator == ""
		}
		suffix, matches := strings.CutPrefix(resource, coordinate.PhysicalTarget+"-")
		if !matches || len(suffix) != 6 {
			return false
		}
		for _, c := range suffix {
			if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
				return false
			}
		}
		if kind == contract.PublicationCreateEmpty {
			return locator == resource+"?stage=AWSCURRENT"
		}
		return kind == contract.PublicationDeleteOwned && locator == ""
	case "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1":
		if evidence.Status != http.StatusOK {
			return false
		}
		if kind == contract.PublicationWriteValue {
			version, matches := strings.CutPrefix(resource, coordinate.PhysicalTarget+"/versions/")
			if !matches {
				return false
			}
			number, err := strconv.ParseInt(version, 10, 64)
			return err == nil && number > 0 && strconv.FormatInt(number, 10) == version && locator == ""
		}
		if resource != coordinate.PhysicalTarget {
			return false
		}
		if kind == contract.PublicationCreateEmpty {
			return locator == coordinate.PhysicalTarget+"/versions/latest"
		}
		return kind == contract.PublicationDeleteOwned && locator == ""
	case "github-actions/service/v1":
		if resource != coordinate.PhysicalTarget {
			return false
		}
		if kind == contract.PublicationCreateWithValue {
			return evidence.Status == http.StatusCreated && locator == coordinate.PhysicalTarget
		}
		return kind == contract.PublicationDeleteOwned && evidence.Status == http.StatusNoContent && locator == ""
	}
	return false
}

// full_only: false
func TestStockPublishedPreviewKeepsActivePlainAndUncheckedSecret(t *testing.T) {
	for _, provider := range []string{"gcp", "aws"} {
		t.Run(provider, func(t *testing.T) {
			for _, condition := range []string{"exact", "schema", "incomplete", "missing-complete", "reason", "warning", "missing-warning", "missing-row", "extra-row", "reordered", "duplicate-coordinate", "missing-coordinate", "foreign-coordinate", "foreign-binding", "foreign-target", "foreign-service", "foreign-contract", "retired-origin", "remote-absence", "late-risk", "blocker", "missing-actions", "missing-blockers", "missing-conditional", "plain-basis", "plain-action", "plain-conditional", "secret-basis", "secret-action", "secret-policy-action", "secret-nonconditional", "unknown-entry-kind"} {
				t.Run(condition, func(t *testing.T) {
					positive, negative, reason := true, false, uint8(0)
					service, target, prefixes := "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1", []string{"projects/123/secrets/ENKV_FIXTURE"}
					if provider == "aws" {
						service, target, prefixes = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1", []string{"aws/account/region/ENKV_FIXTURE", "orgs/owner/actions/secrets/ENKV_FIXTURE", "repos/owner/repo/actions/secrets/ENKV_FIXTURE", "repos/owner/repo/environments/env/secrets/ENKV_FIXTURE"}
					}
					preview := publicOutputPreview{Schema: "PublicationPreview/v2", Complete: &positive, Reason: &reason, Warning: &negative}
					var expected []publicOutputCoordinate
					for scope, prefix := range prefixes {
						if scope > 0 {
							service, target = "github-actions/service/v1", "github-actions/target/v1"
						}
						for _, kind := range []string{"PLAIN", "SECRET"} {
							id, binding := strings.Repeat(strconv.Itoa(len(expected)+1), 64), strings.Repeat("b", 63)+strconv.Itoa(len(expected)+1)
							coordinate := publicOutputCoordinate{ServiceContractID: service, TargetContractID: target, PhysicalTarget: prefix + "_" + kind, CoordinateID: id, BindingID: binding}
							row := publicOutputPreviewRow{ServiceContractID: service, TargetContractID: target, PhysicalTarget: coordinate.PhysicalTarget, Coordinate: &id, Binding: &binding, Origin: "both", Basis: "acknowledged-equal", Actions: []string{}, Blockers: []string{}, Conditional: &negative, Reason: &reason, Remote: &positive, Late: &negative}
							if kind == "SECRET" {
								row.Basis, row.Actions, row.Conditional = "secret-unchecked", []string{"write-value"}, &positive
							}
							expected, preview.Entries = append(expected, coordinate), append(preview.Entries, row)
						}
					}
					plain, secret := &preview.Entries[len(preview.Entries)-2], &preview.Entries[len(preview.Entries)-1]
					switch condition {
					case "schema":
						preview.Schema = "PublicationPreview/v1"
					case "incomplete":
						preview.Complete = &negative
					case "missing-complete":
						preview.Complete = nil
					case "reason":
						other := uint8(1)
						preview.Reason = &other
					case "warning":
						preview.Warning = &positive
					case "missing-warning":
						preview.Warning = nil
					case "missing-row":
						preview.Entries = preview.Entries[:len(preview.Entries)-1]
					case "extra-row":
						preview.Entries = append(preview.Entries, *secret)
					case "reordered":
						preview.Entries[0], preview.Entries[1] = preview.Entries[1], preview.Entries[0]
					case "duplicate-coordinate":
						secret.Coordinate = preview.Entries[0].Coordinate
					case "missing-coordinate":
						secret.Coordinate = nil
					case "foreign-coordinate":
						other := strings.Repeat("e", 64)
						secret.Coordinate = &other
					case "foreign-binding":
						other := strings.Repeat("e", 64)
						secret.Binding = &other
					case "foreign-target":
						secret.PhysicalTarget += "_OTHER"
					case "foreign-service":
						secret.ServiceContractID = "other/service/v1"
					case "foreign-contract":
						secret.TargetContractID = "other/target/v1"
					case "retired-origin":
						secret.Origin = "observed"
					case "remote-absence":
						secret.Remote = &negative
					case "late-risk":
						secret.Late = &positive
					case "blocker":
						secret.Blockers = []string{strings.Repeat("c", 64)}
					case "missing-actions":
						secret.Actions = nil
					case "missing-blockers":
						secret.Blockers = nil
					case "missing-conditional":
						secret.Conditional = nil
					case "plain-basis":
						plain.Basis = "secret-unchecked"
					case "plain-action":
						plain.Actions = []string{"write-value"}
					case "plain-conditional":
						plain.Conditional = &positive
					case "secret-basis":
						secret.Basis = "acknowledged-equal"
					case "secret-action":
						secret.Actions = []string{}
					case "secret-policy-action":
						secret.Actions = []string{"write-value", "update-policy"}
					case "secret-nonconditional":
						secret.Conditional = &negative
					case "unknown-entry-kind":
						plain.PhysicalTarget += "_OTHER"
						expected[len(expected)-2].PhysicalTarget = plain.PhysicalTarget
					}
					if stockPublishedOutputPreviewMatches(preview, expected) != (condition == "exact") {
						t.Fatal("active published preview was confused with retired deletion evidence or lost an exact row")
					}
				})
			}
		})
	}
}

func stockPublishedOutputPreviewMatches(preview publicOutputPreview, expected []publicOutputCoordinate) bool {
	if !publicOutputPreviewMatches(preview, expected, false) {
		return false
	}
	for _, row := range preview.Entries {
		if row.Origin != "both" || !*row.Remote {
			return false
		}
		switch {
		case strings.HasSuffix(row.PhysicalTarget, "_PLAIN"):
			if row.Basis != "acknowledged-equal" || len(row.Actions) != 0 || *row.Conditional {
				return false
			}
		case strings.HasSuffix(row.PhysicalTarget, "_SECRET"):
			if row.Basis != "secret-unchecked" || !slices.Equal(row.Actions, []string{"write-value"}) || !*row.Conditional {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (r *stockPluginRun) publishOutputs(ctx context.Context, source string) {
	names := publicOutputNames(r.input.Prefix)
	set := r.command(ctx, "set-secret", "apply", "", []byte(stockSecretValue), "set", "--source", source, "--source-format", "json", "--name", names[1], "--json")
	publicAssertSetPair(r.t, set, source, names[1])
	clear(set.Body)
	document := publicSourceDocument(r.t, source)
	document["entries"].(map[string]any)[names[1]].(map[string]any)["output_encoding"] = "base64"
	document["entries"].(map[string]any)[names[0]] = map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": stockPlainValue}}
	document["outputs"] = stockOutputDeclaration(r.input)
	publicWriteSource(r.t, source, document)
	r.plainApply(ctx, source)
	expected := publicExpectedOutputCoordinates(r.input)
	preview, verdict, before := r.outputPreview(ctx, source)
	if verdict != "match" || !publicOutputPreviewMatches(preview, expected, false) {
		r.t.Fatal("stock output target vector differs before publication")
	}
	for i, row := range preview.Entries {
		if row.Coordinate == nil || row.Binding == nil || len(row.Actions) == 0 {
			r.t.Fatal("stock unpublished output identity unavailable")
		}
		expected[i].CoordinateID, expected[i].BindingID = *row.Coordinate, *row.Binding
		r.evidence.Outputs = append(r.evidence.Outputs, records.StockPluginOutput{Coordinate: expected[i]})
	}
	r.save()
	if r.input.Settings.Provider == "aws" {
		for _, row := range expected {
			if row.ServiceContractID == "github-actions/service/v1" {
				r.verify(ctx)
				if stockGitHubMetadata(ctx, nil, row.PhysicalTarget, false) != nil {
					r.t.Fatal("stock GitHub output preflight did not establish absence")
				}
			}
		}
	}
	image := publicSourceImage(r.t, source)
	child := r.command(ctx, "publish", "apply", "", nil, "publish", "--source", source, "--source-format", "json", "--name", names[0], "--name", names[1], "--json")
	actions := publicOutputPublication(r.t, child, expected, false, false, false)
	if !stockOutputActionsMatch(actions, expected, r.outputContracts(expected), r.outputObservation(ctx, source, child, before), false) {
		r.t.Fatal("stock complete publication action acknowledgements differ")
	}
	clear(child.Body)
	publicImageUnchanged(r.t, image)
	for i := range r.evidence.Outputs {
		r.evidence.Outputs[i].Published = true
	}
	r.save()
	r.assert("outputs-published")
	preview, verdict, _ = r.outputPreview(ctx, source)
	if verdict != "match" || !stockPublishedOutputPreviewMatches(preview, expected) {
		r.t.Fatal("stock publication acknowledgement vector differs")
	}
	cloudReads := 0
	for i, row := range r.evidence.Outputs {
		r.verify(ctx)
		if row.Coordinate.ServiceContractID == "github-actions/service/v1" {
			if stockGitHubMetadata(ctx, nil, row.Coordinate.PhysicalTarget, true) != nil {
				r.t.Fatal("stock GitHub exact secret metadata unavailable")
			}
			r.evidence.Outputs[i].MetadataVerified = true
		} else {
			read, err := readStockCloudOutput(ctx, r.input, r.budget, r.inv.StateDir, row.Coordinate.PhysicalTarget)
			if err != nil {
				r.t.Fatal("stock independent cloud output value unavailable")
			}
			want := []byte(stockPlainValue)
			if strings.HasSuffix(row.Coordinate.PhysicalTarget, "_SECRET") {
				want = []byte(base64.StdEncoding.EncodeToString([]byte(stockSecretValue)))
			}
			equal := bytes.Equal(read.Bytes, want)
			clear(read.Bytes)
			clear(want)
			if !equal || read.Instance == "" || len(read.Instance) > 512 {
				r.t.Fatal("stock independent cloud output value differs")
			}
			r.evidence.Outputs[i].ValueEqual = true
			r.evidence.Outputs[i].Instance = read.Instance
			cloudReads++
		}
		r.save()
	}
	if cloudReads != 2 {
		r.t.Fatal("stock cloud output readback omitted a value")
	}
	r.assert("cloud-output-values-equal")
	if r.input.Settings.Provider == "aws" {
		r.assert("github-metadata-checked")
	}
}

// Only exact already-declared targets enter this independent metadata query.
// It observes existence and name; it cannot read GitHub secret plaintext.
func stockGitHubMetadata(ctx context.Context, client *http.Client, target string, present bool) error {
	call := telemetry.Start(ctx, telemetry.ProviderWorker, telemetry.OpSetupGitHubMetadata)
	ctx = telemetry.CallContext(ctx, call)
	if len(target) > 1024 || strings.ContainsAny(target, "?%\\\x00\r\n") || !strings.Contains(target, "/secrets/ENKV_") {
		call.FinishReason(telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionInvalid)
		return errInventory
	}
	parts := strings.Split(target, "/")
	valid := len(parts) == 6 && parts[0] == "repos" && parts[3] == "actions" && parts[4] == "secrets" ||
		len(parts) == 5 && parts[0] == "orgs" && parts[2] == "actions" && parts[3] == "secrets" ||
		len(parts) == 7 && parts[0] == "repos" && parts[3] == "environments" && parts[5] == "secrets"
	if !valid {
		call.FinishReason(telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionInvalid)
		return errInventory
	}
	name := parts[len(parts)-1]
	if !strings.HasPrefix(name, "ENKV_") || !strings.HasSuffix(name, "_PLAIN") && !strings.HasSuffix(name, "_SECRET") {
		call.FinishReason(telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionInvalid)
		return errInventory
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		call.FinishReason(telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionInvalid)
		return errInventory
	}
	if client == nil {
		var closeClient func()
		client, closeClient = stockVerificationClient()
		defer closeClient()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/"+target, nil)
	if err != nil {
		call.FinishReason(telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionInvalid)
		return errInventory
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := client.Do(request)
	if err != nil {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonReadUnavailable)
		return errInventory
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, stockVerificationBytes+1))
	closeErr := response.Body.Close()
	defer clear(body)
	if readErr != nil || closeErr != nil {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonReadUnavailable)
		return errInventory
	}
	if len(body) > stockVerificationBytes {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonCapacityExceeded)
		return errInventory
	}
	if !present {
		if response.StatusCode != http.StatusNotFound {
			call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonReadUnavailable)
			return errInventory
		}
		call.Finish(telemetry.ResultSuccess)
		return nil
	}
	if response.StatusCode != http.StatusOK {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonReadUnavailable)
		return errInventory
	}
	var out struct {
		Name, CreatedAt, UpdatedAt string
		Visibility                 string `json:"visibility"`
	}
	if json.Unmarshal(body, &out) != nil || out.Name != name {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonInvalidFormat)
		return errInventory
	}
	call.Finish(telemetry.ResultSuccess)
	return nil
}

// full_only: false
func TestStockSourceBasisAuthenticatesGenesisAndObservation(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(strconv.Itoa(int(family)), func(t *testing.T) {
			env, _ := genesisEnvironment(t, family, true)
			f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
			anchor, err := contract.EncodePublicSigningBinding(f.session.root.CurrentAccess.Core.CurrentControl.NormalSigning)
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := contract.EncodeStoreConfiguration(env.Store.(*memoryStore).StoreConfiguration())
			if err != nil {
				t.Fatal(err)
			}
			root, err := format.EncodeRoot(f.session.root)
			if err != nil {
				t.Fatal(err)
			}
			observation := localBasisImage{Kind: "observation", SigningAnchor: anchor, StoreConfiguration: configuration, HEAD: f.session.body, Root: root}
			for _, page := range f.session.recipients {
				if page != nil {
					body, err := format.EncodeRecipientPage(*page)
					if err != nil {
						t.Fatal(err)
					}
					observation.RecipientPages = append(observation.RecipientPages, body)
				}
			}
			for _, image := range []localBasisImage{{Kind: "genesis", Descriptor: fixtureAdmission(env).admission.descriptor}, observation} {
				t.Run(image.Kind, func(t *testing.T) {
					fields := map[string]any{"kind": image.Kind, "descriptor": image.Descriptor}
					required := "descriptor"
					if image.Kind == "observation" {
						fields = map[string]any{"kind": image.Kind, "anchor": image.SigningAnchor, "store_configuration": image.StoreConfiguration, "head": image.HEAD, "root": image.Root, "recipient_pages": image.RecipientPages}
						required = "root"
					}
					body, err := json.Marshal(map[string]any{"public_basis": fields})
					if err != nil {
						t.Fatal(err)
					}
					basis, domain, err := stockSourcePublicBasis(body)
					if err != nil || domain != env.Domain {
						t.Fatal("stock source basis cannot reach current-state admission", err)
					}
					opened := publicOperatorOpen(t, t.Context(), domain, basis, env.Store)
					if opened.root.Snapshot != f.session.root.Snapshot || opened.root.CurrentAccess.Core.CurrentControl.AuthorityRecipientID != f.session.root.CurrentAccess.Core.CurrentControl.AuthorityRecipientID {
						t.Fatal("stock basis changed selected Snapshot or Authority")
					}
					if _, err := basis.ControlCore(testID("foreign stock domain"), env.Store.Descriptor()); err == nil {
						t.Fatal("stock basis admitted another domain")
					}
					if image.Kind == "observation" && (!bytes.Equal(basis.SigningAnchor, image.SigningAnchor) || !bytes.Equal(basis.StoreConfiguration, image.StoreConfiguration) || !bytes.Equal(basis.HEAD, image.HEAD) || !bytes.Equal(basis.Root, image.Root) || !reflect.DeepEqual(basis.RecipientPages, image.RecipientPages)) {
						t.Fatal("stock source lost part of the observation")
					}
					for _, damage := range []string{"schema", "mixed-empty", "missing", "null", "empty", "unknown", "wrong-kind"} {
						t.Run(damage, func(t *testing.T) {
							changed := make(map[string]any, len(fields))
							for key, value := range fields {
								changed[key] = value
							}
							switch damage {
							case "schema":
								changed["schema"] = 0
							case "mixed-empty":
								changed["control"] = []byte{}
							case "missing":
								delete(changed, required)
							case "null":
								changed[required] = nil
							case "empty":
								changed[required] = []byte{}
							case "unknown":
								changed["unknown"] = true
							case "wrong-kind":
								changed["kind"] = "successor"
							}
							body, err := json.Marshal(map[string]any{"public_basis": changed})
							if err != nil {
								t.Fatal(err)
							}
							if _, _, err := stockSourcePublicBasis(body); err == nil {
								t.Fatal("stock source accepted malformed basis", damage)
							}
						})
					}
				})
			}
		})
	}
}

func stockSourcePublicBasis(body []byte) (PublicBasis, contract.ID, error) {
	var source struct {
		Basis json.RawMessage `json:"public_basis"`
	}
	if err := jsonv2.Unmarshal(body, &source); err != nil {
		return PublicBasis{}, contract.ID{}, err
	}
	var image localBasisImage
	if err := jsonv2.Unmarshal(source.Basis, &image, jsonv2.RejectUnknownMembers(true)); err != nil {
		return PublicBasis{}, contract.ID{}, err
	}
	var fields map[string]json.RawMessage
	if err := jsonv2.Unmarshal(source.Basis, &fields); err != nil {
		return PublicBasis{}, contract.ID{}, err
	}
	want := []string{"kind", "descriptor"}
	if image.Kind == "observation" {
		want = []string{"kind", "anchor", "store_configuration", "head", "root", "recipient_pages"}
	}
	if len(fields) != len(want) {
		return PublicBasis{}, contract.ID{}, ErrLocalAuthorityAdmission
	}
	for _, field := range want {
		if _, present := fields[field]; !present {
			return PublicBasis{}, contract.ID{}, ErrLocalAuthorityAdmission
		}
	}
	basis, err := (PublicBasis{Descriptor: image.Descriptor, Control: image.Control, Selection: image.Selection,
		SigningAnchor: image.SigningAnchor, StoreConfiguration: image.StoreConfiguration,
		HEAD: image.HEAD, Root: image.Root, RecipientPages: image.RecipientPages}).OwnedCopy()
	if err != nil {
		return PublicBasis{}, contract.ID{}, err
	}
	switch image.Kind {
	case "genesis":
		descriptor, err := contract.DecodeGenesisDescriptorCore(basis.Descriptor)
		return basis, descriptor.DomainID, err
	case "observation":
		configuration, err := contract.DecodeStoreConfiguration(basis.StoreConfiguration)
		return basis, configuration.DomainID, err
	default:
		return PublicBasis{}, contract.ID{}, ErrLocalAuthorityAdmission
	}
}

func stockPublicBasis(t testing.TB, source string) (PublicBasis, contract.ID) {
	t.Helper()
	document := publicSourceDocument(t, source)
	reference, ok := document["generated"].(string)
	if !ok {
		t.Fatal("stock generated source unavailable")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), filepath.FromSlash(reference)))
	if err != nil || len(body) > 8<<20 {
		t.Fatal("stock generated public basis unavailable")
	}
	basis, domain, err := stockSourcePublicBasis(body)
	clear(body)
	if err != nil {
		t.Fatal("stock generated public basis refused")
	}
	return basis, domain
}

func (r *stockPluginRun) selected(ctx context.Context, source string) *StateSession {
	basis, domain := stockPublicBasis(r.t, source)
	defer basis.clear()
	store, err := openPublicReaderStore(ctx, r.input, domain, r.inv.StateDir)
	if err != nil {
		r.t.Fatal("stock independent current Store unavailable")
	}
	return publicOperatorOpen(r.t, ctx, domain, basis, recordedStore{Store: store, budget: r.budget})
}

func (r *stockPluginRun) manifestFacts(ctx context.Context, source string) publicManifestFacts {
	selected := r.selected(ctx, source)
	authority := selected.root.CurrentAccess.Core.CurrentControl.AuthorityRecipientID
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	facts := publicManifestFacts{Observation: publicManifestObservation{Domain: id(selected.root.Domain), Revision: id(selected.head.Core.Revision), Snapshot: id(selected.root.Snapshot)}, Authority: id(authority)}
	names := publicOutputNames(r.input.Prefix)
	configuration, coordinates, markers := publicSelectedOutputs(r.t, ctx, selected)
	if len(configuration.Bindings) != len(publicOutputScopes(r.input)) {
		r.t.Fatal("stock manifest complete destination set differs")
	}
	for _, name := range names {
		var entry *contract.ValueEntry
		for _, named := range selected.root.Names {
			if named.Name == name {
				entry = selected.valueEntry(named.Slot)
			}
		}
		if entry == nil || entry.ValueSource != contract.Supplied || len(entry.Recipients) != 1 || entry.Recipients[0] != authority {
			r.t.Fatal("stock manifest selected entry identity or membership differs")
		}
		fact := publicManifestEntryFact{Name: name, Incarnation: id(entry.Incarnation), Plain: name == names[0]}
		if fact.Plain {
			if entry.ConfidentialityClass != contract.Plain || !bytes.Equal(entry.ValueBytes, []byte(stockPlainValue)) {
				r.t.Fatal("stock manifest plain bytes differ")
			}
		} else {
			if entry.ConfidentialityClass != contract.Secret {
				r.t.Fatal("stock manifest selected secret differs")
			}
			for _, binding := range configuration.Bindings {
				var target *contract.OutputTarget
				for i := range binding.Targets {
					if binding.Targets[i].EntryIncarnationID == entry.Incarnation {
						target = &binding.Targets[i]
					}
				}
				if target == nil || len(binding.Targets) != 2 {
					r.t.Fatal("stock manifest complete secret target set differs")
				}
				locator := target.ConsumerLocator
				if binding.DestinationID == "aws-secrets-manager" {
					coordinate := coordinates[target.ServiceContractID+"\x00"+target.CanonicalTarget]
					birth := markers[coordinate.OwnedBirthAttemptID]
					if !publicManifestCloudBirthMatches(coordinate, birth, binding.IncarnationID, *target) {
						r.t.Fatal("stock manifest cloud birth identity differs")
					}
					locator = birth.Evidence.ConsumerLocator
				}
				d := publicManifestDestinationExpected(r.t, r.input, facts.Observation.Domain, binding.DestinationID, id(binding.IncarnationID), fact.Incarnation, name, locator)
				if target.ServiceContractID != d.Service || target.TargetContractID != d.TargetContract || target.CanonicalTarget != d.CanonicalTarget || base64.StdEncoding.EncodeToString(target.TargetData) != d.TargetData || target.PayloadEncoding != contract.OutputEncodingBase64 {
					r.t.Fatal("stock manifest target meaning differs")
				}
				if d.Policy == nil {
					if target.Policy.ContractID != "" || len(target.Policy.Data) != 0 {
						r.t.Fatal("stock manifest unexpected target policy")
					}
				} else if target.Policy.ContractID != d.Policy.Contract || base64.StdEncoding.EncodeToString(target.Policy.Data) != d.Policy.Data {
					r.t.Fatal("stock manifest complete policy differs")
				}
				fact.Destinations = append(fact.Destinations, d)
			}
			slices.SortFunc(fact.Destinations, func(a, b publicManifestDestination) int { return strings.Compare(a.Destination, b.Destination) })
		}
		facts.Entries = append(facts.Entries, fact)
	}
	return facts
}

// The complete expected INI grammar is written independently of the renderer.
// Only authenticated state identities, retained policy bytes and real locators
// vary. The plain fixture bytes and all field ordering are literal expectations.
func stockExpectedINI(facts publicManifestFacts) string {
	var out strings.Builder
	section := func(name string) { out.WriteString("[client." + name + "]\n") }
	field := func(name, value string) { out.WriteString(name + "=" + strconv.Quote(value) + "\n") }
	b64 := func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) }
	section("manifest")
	for _, row := range [][2]string{{"format", "example/ini-reference/v1"}, {"projection_schema", "ENKV/CONSUMPTION-PROJECTION/v1"}, {"config_contract", "example/ini-reference-settings/v1"}, {"settings_base64", "eyJzZWN0aW9uX3ByZWZpeCI6ImNsaWVudCJ9"}, {"domain_id", facts.Observation.Domain}, {"head_revision_id", facts.Observation.Revision}, {"snapshot_id", facts.Observation.Snapshot}, {"target_recipient_id", facts.Authority}, {"target_mode", "current-authority"}, {"entry_mode", "exact-names"}, {"has_service_filter", "false"}, {"service_filter_base64", ""}, {"evidence_limit", "authorized-input-and-exact-bytes"}, {"included_count", strconv.Itoa(len(facts.Entries))}, {"excluded_count", "0"}} {
		field(row[0], row[1])
	}
	out.WriteByte('\n')
	for i, entry := range facts.Entries {
		entrySection := "entry." + strconv.Itoa(i)
		section(entrySection)
		field("name_base64", b64(entry.Name))
		field("incarnation_id", entry.Incarnation)
		if entry.Plain {
			field("kind", "plain")
			field("value_base64", b64(stockPlainValue))
			out.WriteByte('\n')
			continue
		}
		field("kind", "secret")
		field("destination_count", strconv.Itoa(len(entry.Destinations)))
		out.WriteByte('\n')
		for j, d := range entry.Destinations {
			section(entrySection + ".destination." + strconv.Itoa(j))
			for _, row := range [][2]string{{"destination_id_base64", b64(d.Destination)}, {"binding_incarnation_id", d.Binding}, {"entry_incarnation_id", d.Incarnation}, {"service_contract_base64", b64(d.Service)}, {"target_contract_base64", b64(d.TargetContract)}, {"canonical_target_base64", b64(d.CanonicalTarget)}, {"consumer_locator_base64", b64(d.Locator)}, {"target_data_base64", d.TargetData}, {"payload_encoding", d.Encoding}} {
				field(row[0], row[1])
			}
			present, contractID, digest, data := "false", "", "", ""
			if d.Policy != nil {
				present, contractID, digest, data = "true", d.Policy.Contract, d.Policy.Digest, d.Policy.Data
			}
			field("policy_present", present)
			field("policy_contract_base64", b64(contractID))
			field("policy_digest", digest)
			field("policy_data_base64", data)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// The caller owns this concrete manifest descriptor and checks its close.
func stockReadManifestFile(file *os.File) ([]byte, os.FileMode, error) {
	body, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return body, 0, err
	}
	info, err := file.Stat()
	if err != nil {
		return body, 0, err
	}
	if len(body) > 1<<20 {
		return body, info.Mode(), errInventory
	}
	return body, info.Mode(), nil
}

func (r *stockPluginRun) manifest(ctx context.Context, source string) {
	facts := r.manifestFacts(ctx, source)
	directory, err := os.MkdirTemp("", "enkv-stock-manifest-")
	if err != nil {
		r.t.Fatal("stock independent manifest sink unavailable")
	}
	path := filepath.Join(directory, "references.ini")
	defer func() {
		if os.Remove(path) != nil {
			r.t.Error("stock manifest exact file removal failed")
		}
		if os.Remove(directory) != nil {
			r.t.Error("stock manifest directory removal failed")
		}
	}()
	names := publicOutputNames(r.input.Prefix)
	child := r.command(ctx, "manifest", "reader", "", nil, "manifest", "--source", source, "--source-format", "json", "--plugin", "workshop-ini", "--settings", `{"section_prefix":"client"}`, "--name", names[0], "--name", names[1], "--out", path, "--json")
	defer clear(child.Body)
	file, openErr := os.Open(path)
	if openErr != nil {
		r.t.Fatal("stock manifest installed file unavailable")
	}
	body, mode, readErr := stockReadManifestFile(file)
	closeErr := file.Close()
	defer clear(body)
	info, statErr := os.Lstat(path)
	if readErr != nil || closeErr != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !mode.IsRegular() || mode.Perm() != 0600 || len(body) > 1<<20 {
		r.t.Fatal("stock manifest installed file identity differs")
	}
	rendererID, idErr := r.input.PublicConfiguration.Stock.Artifact.Renderer.Metadata.Identity()
	if idErr != nil {
		r.t.Fatal("stock renderer identity unavailable")
	}
	result, decodeErr := stockManifestDecode(child, body, mode, rendererID.String())
	if decodeErr != nil {
		r.t.Fatal("stock common manifest issuance or exact native delivery differs")
	}
	if len(result.Issuance.Payload.Included) != len(facts.Entries) || len(result.Issuance.Payload.Excluded) != 0 {
		r.t.Fatal("stock manifest selected input partition differs")
	}
	for i, entry := range facts.Entries {
		if result.Issuance.Payload.Included[i].Name != entry.Name || result.Issuance.Payload.Included[i].ID != entry.Incarnation {
			r.t.Fatal("stock manifest later selected member differs")
		}
	}
	if !stockCompleteINI(body, facts) {
		r.t.Fatal("stock complete independent INI artifact differs")
	}
	r.assert("manifest-complete")
}

func stockCompleteINI(body []byte, facts publicManifestFacts) bool {
	if len(facts.Entries) != 2 || !facts.Entries[0].Plain || facts.Entries[1].Plain || string(body) != stockExpectedINI(facts) {
		return false
	}
	document, err := consumer.Read(bytes.NewReader(body))
	if err != nil {
		return false
	}
	values, err := document.PlainValues()
	if err != nil || !reflect.DeepEqual(values, map[string][]byte{facts.Entries[0].Name: []byte(stockPlainValue)}) {
		return false
	}
	references, err := document.References()
	if err != nil || len(references) != len(facts.Entries[1].Destinations) {
		return false
	}
	for i, destination := range facts.Entries[1].Destinations {
		if references[i].EntryName != facts.Entries[1].Name || references[i].DestinationID != destination.Destination ||
			references[i].ServiceContract != destination.Service || references[i].Locator != destination.Locator {
			return false
		}
	}
	return true
}

func (r *stockPluginRun) removeOutputs(ctx context.Context, source string) {
	document := publicSourceDocument(r.t, source)
	document["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
	publicWriteSource(r.t, source, document)
	r.plainApply(ctx, source)
	expected := make([]publicOutputCoordinate, len(r.evidence.Outputs))
	for i, row := range r.evidence.Outputs {
		expected[i] = row.Coordinate
	}
	preview, _, before := r.outputPreview(ctx, source)
	if !publicOutputPreviewMatches(preview, expected, false) {
		r.t.Fatal("stock output deletion eligibility differs")
	}
	args := []string{"publish", "--source", source, "--source-format", "json", "--json"}
	for _, coordinate := range expected {
		args = append(args, "--delete-coordinate", coordinate.CoordinateID+"="+publicOutputDeletionPlugin(r.t, coordinate))
	}
	child := r.command(ctx, "output-delete", "apply", "", nil, args...)
	actions := publicOutputPublication(r.t, child, expected, false, false, true)
	if !stockOutputActionsMatch(actions, expected, r.outputContracts(expected), r.outputObservation(ctx, source, child, before), true) {
		r.t.Fatal("stock complete deletion action acknowledgements differ")
	}
	clear(child.Body)
	preview, verdict, _ := r.outputPreview(ctx, source)
	if verdict != "match" || !publicOutputPreviewMatches(preview, expected, true) {
		r.t.Fatal("stock complete output deletion acknowledgement differs")
	}
	for i, row := range r.evidence.Outputs {
		r.verify(ctx)
		if row.Coordinate.ServiceContractID == "github-actions/service/v1" {
			if stockGitHubMetadata(ctx, nil, row.Coordinate.PhysicalTarget, false) != nil {
				r.t.Fatal("stock GitHub exact output remains")
			}
			r.evidence.Outputs[i].Deletion = "acknowledged"
		} else {
			observation, err := verifyStockCloudOutputDeleted(ctx, r.input, r.budget, r.inv.StateDir, row.Coordinate.PhysicalTarget)
			if err != nil || observation.Disposition != "absent" && observation.Disposition != "scheduled" || r.input.Settings.Provider == "aws" && observation.Instance != row.Instance {
				r.t.Fatal("stock cloud output deletion observation differs")
			}
			r.evidence.Outputs[i].Deletion = observation.Disposition
		}
		r.save()
	}
}

// full_only: false
func TestStockCompleteINIConsumerDetectsLaterDestinationDamage(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	facts := publicManifestFacts{Observation: publicManifestObservation{Domain: id, Revision: id, Snapshot: id}, Authority: id, Entries: []publicManifestEntryFact{{Name: "PLAIN", Incarnation: id, Plain: true}, {Name: "SECRET", Incarnation: id, Destinations: []publicManifestDestination{{Destination: "first", Binding: id, Incarnation: id, Service: "private/v1", TargetContract: "private-target/v1", CanonicalTarget: "one", Locator: "one", TargetData: "e30=", Encoding: "raw"}, {Destination: "second", Binding: id, Incarnation: id, Service: "private/v1", TargetContract: "private-target/v1", CanonicalTarget: "two", Locator: "two", TargetData: "e30=", Encoding: "raw"}}}}}
	want := stockExpectedINI(facts)
	for _, condition := range []string{"exact", "later-locator", "later-missing", "extra-section", "wrong-plain"} {
		t.Run(condition, func(t *testing.T) {
			body := want
			switch condition {
			case "later-locator":
				body = strings.Replace(body, `consumer_locator_base64="dHdv"`, `consumer_locator_base64="d3Jvbmc="`, 1)
			case "later-missing":
				at := strings.Index(body, "[client.entry.1.destination.1]")
				body = body[:at]
			case "extra-section":
				body += "[client.extra]\nvalue=\"extra\"\n"
			case "wrong-plain":
				body = strings.Replace(body, base64.StdEncoding.EncodeToString([]byte(stockPlainValue)), "d3Jvbmc=", 1)
			}
			if stockCompleteINI([]byte(body), facts) != (condition == "exact") {
				t.Fatal("complete independent INI consumer accepted changed or incomplete bytes")
			}
		})
	}
}

// full_only: false
func TestStockSetPairAcceptsPublicReadbackWithoutObserverCapture(t *testing.T) {
	// The ciphertext is a structural local-input fixture, not a cryptographic
	// proof. This check owns the Product/result readback and observer boundary.
	id := contract.ID{1}
	envelope := contract.SealedInputEnvelope{
		Core: contract.SealedInputCore{
			SealedInputCoreFields: contract.SealedInputCoreFields{
				Schema: contract.SealedInputSchema, Profile: contract.MaterialCryptoProfile,
				CompatibilityID: id, DomainID: id, FileIdentity: id, SourceID: id,
				CryptoSupportID: id, DataKeyID: id, DataKeyEpoch: 1,
				InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: "SECRET",
		},
		Ciphertext:    make([]byte, 16),
		AuthorityWrap: contract.WrapRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: id, BindingID: id, BindingSerial: 1, RSACiphertext: make([]byte, contract.RSACiphertextLength)},
	}
	sealed, err := contract.EncodeSealedInputEnvelope(envelope)
	if err != nil {
		t.Fatal("local sealed readback fixture unavailable")
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "configuration.json")
	generated := filepath.Join(directory, "generated.json")
	idText := hex.EncodeToString(id[:])
	publicWriteSource(t, source, map[string]any{"generated": "generated.json"})
	publicWriteSource(t, generated, map[string]any{"file_id": idText, "domain": map[string]any{"id": idText}, "secrets": map[string]any{"SECRET": map[string]any{"sealed": base64.StdEncoding.EncodeToString(sealed)}}})
	image := publicSourceImage(t, source)
	zero := strings.Repeat("0", 64)
	result := map[string]any{
		"schema": "ProductResult/v1", "operation_kind": "set-confidential", "state_result": "success",
		"effect_summary": "not-applicable", "output_summary": "not-applicable", "operation_payload": "SealedArtifactPayload/v1", "evidence_ceiling": "exact-local-pair-readback",
		"payload":        map[string]any{"schema": "SealedArtifactPayload/v1", "input_file_id": idText, "predecessor_digest": zero, "sealed_artifact_digest": bodyDigest(sealed), "target": map[string]any{"domain_id": idText, "name": "SECRET"}, "readback": map[string]any{"editable_digest": bodyDigest(image.Files[source]), "generated_digest": bodyDigest(image.Files[generated])}},
		"local_delivery": map[string]any{"outcome": "recorded", "editable_path": source, "generated_path": generated, "observation_paths": []string{}, "cleanup_failed": false},
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	child := publicChildResult{Code: 0, Body: body}
	publicAssertSetPair(t, child, source, "SECRET")
	guard := &publicGeneratedCleanupTB{TB: t}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if _, ok := recovered.(publicGeneratedCleanupStop); !ok {
					panic(recovered)
				}
			}
		}()
		publicAssertSet(guard, child, source, "SECRET")
	}()
	if !guard.stopped || guard.message != "local confidential set selected a credential source or remote capability" {
		t.Fatal("old public set wrapper stopped requiring its own observer evidence")
	}
	child.Capture = nativeprocess.Capture{Events: []nativeprocess.Event{{Kind: "footer"}}}
	publicAssertSet(t, child, source, "SECRET")
}

// full_only: false
func TestStockGitHubMetadataUsesExactDeclaredScopesAndAcknowledgementCeiling(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "local_synthetic_token")
	const name = "ENKV_1111111111111111111111111111111111111111111111111111111111111111_SECRET"
	for _, target := range []string{"repos/owner/repo/actions/secrets/" + name, "orgs/owner/actions/secrets/" + name, "repos/owner/repo/environments/test/secrets/" + name} {
		t.Run(strings.Split(target, "/")[0]+strconv.Itoa(len(target)), func(t *testing.T) {
			for _, condition := range []string{"present", "absent", "wrong-name", "wrong-status", "malformed", "oversized"} {
				t.Run(condition, func(t *testing.T) {
					calls := 0
					client := &http.Client{Transport: stockVerificationTransport(func(request *http.Request) (*http.Response, error) {
						calls++
						if request.Method != "GET" || request.URL.String() != "https://api.github.com/"+target || request.Header.Get("Authorization") != "Bearer local_synthetic_token" {
							t.Error("GitHub metadata escaped the selected target or bearer")
						}
						status, body := http.StatusOK, `{"name":"`+name+`"}`
						switch condition {
						case "absent":
							status, body = http.StatusNotFound, `{"message":"Not Found"}`
						case "wrong-name":
							body = `{"name":"different"}`
						case "wrong-status":
							status = http.StatusAccepted
						case "malformed":
							body = `{"name":`
						case "oversized":
							body = strings.Repeat("x", stockVerificationBytes+1)
						}
						return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
					})}
					err := stockGitHubMetadata(t.Context(), client, target, condition != "absent")
					if (err == nil) != (condition == "present" || condition == "absent") || calls != 1 {
						t.Fatal("GitHub metadata claimed more than the exact bounded existence observation")
					}
				})
			}
		})
	}
}

// full_only: false
func TestStockManifestReadConsumesOnlyFiniteArtifactBytes(t *testing.T) {
	for _, size := range []int64{1 << 20, 2 << 20} {
		t.Run(strconv.FormatInt(size, 10), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "references.ini")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal("controlled manifest descriptor unavailable")
			}
			defer func() {
				if file.Close() != nil {
					t.Error("controlled manifest descriptor close failed")
				}
			}()
			// A small sparse file avoids creating a large test payload. The same
			// open descriptor makes its consumed byte count directly observable.
			if file.Truncate(size) != nil {
				t.Fatal("controlled manifest size unavailable")
			}
			body, mode, readErr := stockReadManifestFile(file)
			defer clear(body)
			consumed, seekErr := file.Seek(0, io.SeekCurrent)
			if seekErr != nil || consumed > (1<<20)+1 {
				t.Fatal("manifest reader consumed bytes beyond its finite allowance", consumed)
			}
			if !mode.IsRegular() || mode.Perm() != 0600 {
				t.Fatal("manifest reader changed the observed file mode")
			}
			if size == 1<<20 {
				if readErr != nil || len(body) != int(size) || consumed != size {
					t.Fatal("complete bounded manifest was not read")
				}
			} else if readErr == nil {
				t.Fatal("oversized manifest was accepted")
			}
		})
	}
}
