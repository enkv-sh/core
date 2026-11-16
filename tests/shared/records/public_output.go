package records

import (
	"encoding/hex"
	"slices"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

func publicOutputID(value string) bool {
	return validHex(value, 32) && value != strings.Repeat("0", 64)
}

// PublicOutputEvidence retains the acknowledged deletion ceiling and the
// unchanged possibility flags. It establishes no remote absence.
type PublicOutputEvidence struct {
	Verdict                   string                          `json:"verdict"`
	Version                   uint16                          `json:"version"`
	EditableSHA256            string                          `json:"editable_sha256"`
	GeneratedSHA256           string                          `json:"generated_sha256"`
	Coordinates               []PublicOutputCoordinate        `json:"coordinates"`
	PassiveCoordinates        []PublicOutputPassiveCoordinate `json:"passive_coordinates,omitempty"`
	CleanupCaptureOrdinal     uint16                          `json:"cleanup_capture_ordinal"`
	ObservationCaptureOrdinal uint16                          `json:"observation_capture_ordinal"`
	Deletes                   []PublicOutputActionResult      `json:"deletes"`
	Preview                   PublicOutputPreview             `json:"preview"`
}

type PublicOutputPassiveCoordinate struct {
	PublicOutputCoordinate `json:"coordinate"`
	EntryKind              string `json:"entry_kind"`
	EntryIncarnationID     string `json:"entry_incarnation_id"`
	Before, After          contract.PublicationCoordinate
}

func (p PublicOutputPassiveCoordinate) Valid() bool {
	if !strings.HasPrefix(publicOutputCoordinateScope(p.PublicOutputCoordinate), "github-") || p.EntryKind != "plain" && p.EntryKind != "secret" {
		return false
	}
	ids := make([]contract.ID, 3)
	for i, text := range []string{p.CoordinateID, p.BindingID, p.EntryIncarnationID} {
		body, err := hex.DecodeString(text)
		if err != nil || !publicOutputID(text) {
			return false
		}
		copy(ids[i][:], body)
	}
	c := p.Before
	want := contract.PublicationCoordinate{Schema: 5, DomainID: c.DomainID, CoordinateID: ids[0], ServiceContractID: p.ServiceContractID, CanonicalTarget: p.PhysicalTarget,
		BindingState: contract.PublicationBindingActive, OwnerState: contract.PublicationOwnerNone, ActiveBindingIncarnationID: ids[1], LastBindingIncarnationID: ids[1],
		LastEntryIncarnationID: ids[2], CurrentPublicationIncarnationID: c.CurrentPublicationIncarnationID}
	return c.Equal(want) && p.After.Equal(c)
}

// The complete vector keeps both acknowledged cloud residue and the six
// unchanged passive declarations. No projected row is discarded as evidence.
func PublicManifestOutputPreviewMatches(preview PublicOutputPreview, cloud []PublicOutputCoordinate, passive []PublicOutputPassiveCoordinate, settled bool) bool {
	if len(cloud) != 2 || len(passive) != 6 || len(preview.Entries) != 8 {
		return false
	}
	cloudPreview := preview
	cloudPreview.Entries = preview.Entries[:2]
	if !PublicOutputPreviewMatches(cloudPreview, cloud, settled) {
		return false
	}
	counts := map[string][2]int{"github-repository": {}, "github-organization": {}, "github-environment": {}}
	bindings, entries := map[string]string{}, map[string]string{}
	seen := map[string]bool{cloud[0].CoordinateID: true, cloud[1].CoordinateID: true}
	for i, expected := range passive {
		scope := publicOutputCoordinateScope(expected.PublicOutputCoordinate)
		count, known := counts[scope]
		if !known || !expected.Valid() || seen[expected.CoordinateID] || i > 0 && passive[i-1].PhysicalTarget >= expected.PhysicalTarget ||
			cloud[1].ServiceContractID >= expected.ServiceContractID || expected.Before.DomainID != passive[0].Before.DomainID {
			return false
		}
		seen[expected.CoordinateID] = true
		kind, basis, conditional := 0, "unpublished", false
		if expected.EntryKind == "secret" {
			kind, basis, conditional = 1, "secret-unchecked", true
		}
		if bindings[scope] != "" && bindings[scope] != expected.BindingID || entries[expected.EntryKind] != "" && entries[expected.EntryKind] != expected.EntryIncarnationID {
			return false
		}
		bindings[scope], entries[expected.EntryKind] = expected.BindingID, expected.EntryIncarnationID
		count[kind]++
		counts[scope] = count
		row := preview.Entries[i+2]
		if row.ServiceContractID != expected.ServiceContractID || row.TargetContractID != expected.TargetContractID || row.PhysicalTarget != expected.PhysicalTarget ||
			row.Coordinate == nil || *row.Coordinate != expected.CoordinateID || row.Binding == nil || *row.Binding != expected.BindingID ||
			row.Origin != "both" || row.Basis != basis || row.Conditional == nil || *row.Conditional != conditional ||
			!slices.Equal(row.Actions, []string{"create-with-value"}) || row.Blockers == nil || len(row.Blockers) != 0 || row.Reason == nil || *row.Reason != 0 ||
			row.Remote == nil || *row.Remote || row.Late == nil || *row.Late {
			return false
		}
	}
	for _, count := range counts {
		if count != [2]int{1, 1} {
			return false
		}
	}
	if entries["plain"] == entries["secret"] {
		return false
	}
	uniqueBindings := map[string]bool{}
	for _, binding := range bindings {
		if uniqueBindings[binding] {
			return false
		}
		uniqueBindings[binding] = true
	}
	return true
}

type PublicOutputActionResult struct {
	Coordinate string               `json:"coordinate_id"`
	Actions    []PublicOutputAction `json:"actions"`
}

type PublicOutputAction struct {
	Action      *string                     `json:"action"`
	Projection  *string                     `json:"projection_commitment"`
	Attempt     *string                     `json:"attempt_id"`
	Disposition string                      `json:"disposition"`
	Reason      *uint16                     `json:"reason_code"`
	Remote      *bool                       `json:"remote_value_may_remain"`
	Late        *bool                       `json:"late_write_risk"`
	Blockers    []string                    `json:"blocker_ids"`
	Evidence    *PublicOutputActionEvidence `json:"evidence"`
}

type PublicOutputActionEvidence struct {
	Schema          string  `json:"schema"`
	Entry           string  `json:"entry"`
	Class           string  `json:"class"`
	Response        string  `json:"response_contract_digest"`
	Status          uint16  `json:"normalized_status"`
	SafeRequestID   *string `json:"safe_request_id"`
	SafeResourceID  *string `json:"safe_resource_id"`
	ConsumerLocator *string `json:"consumer_locator"`
}

// ValidAcknowledgement checks the common public action acknowledgement. Exact
// action order, response contract and provider evidence remain caller-owned.
func (a PublicOutputAction) ValidAcknowledgement() bool {
	if a.Action == nil || *a.Action == "" || a.Projection == nil || !publicOutputID(*a.Projection) || a.Attempt == nil || !publicOutputID(*a.Attempt) || a.Disposition != "acknowledged" || a.Reason == nil || *a.Reason != 0 || a.Remote == nil || !*a.Remote || a.Late == nil || *a.Late || a.Blockers == nil || len(a.Blockers) != 0 || a.Evidence == nil {
		return false
	}
	evidence := a.Evidence
	if evidence.Schema != "PublicationEvidence/v3" || evidence.Entry != "may-have-entered" || evidence.Class != "acknowledged" || !publicOutputID(evidence.Response) || evidence.Status < 200 || evidence.Status >= 300 || evidence.ConsumerLocator == nil {
		return false
	}
	for _, field := range []*string{evidence.SafeRequestID, evidence.SafeResourceID, evidence.ConsumerLocator} {
		if field != nil && (len(*field) > 1024 || !utf8.ValidString(*field)) {
			return false
		}
	}
	return true
}

func (v PublicOutputEvidence) Validate(captureCount int, scopes []string) error {
	if len(scopes) != 1 && len(scopes) != 4 || scopes[0] != "aws-secrets-manager" && scopes[0] != "gcp-secret-manager" ||
		len(scopes) == 4 && !slices.Equal(scopes[1:], []string{"github-repository", "github-organization", "github-environment"}) {
		return errRecord
	}
	previewValid := v.Version == 2 && v.PassiveCoordinates == nil && PublicOutputPreviewMatches(v.Preview, v.Coordinates, true)
	if v.Version == 3 && len(scopes) == 1 {
		previewValid = PublicManifestOutputPreviewMatches(v.Preview, v.Coordinates, v.PassiveCoordinates, true)
	}
	if v.Verdict != "match" || !publicOutputID(v.EditableSHA256) || !publicOutputID(v.GeneratedSHA256) || len(v.Coordinates) != 2*len(scopes) || len(v.Deletes) != len(v.Coordinates) || int(v.CleanupCaptureOrdinal) >= captureCount || int(v.ObservationCaptureOrdinal) >= captureCount || v.CleanupCaptureOrdinal >= v.ObservationCaptureOrdinal || !previewValid {
		return errRecord
	}
	coordinates := make([]string, len(v.Coordinates))
	counts := make(map[string]int, len(scopes))
	for _, scope := range scopes {
		counts[scope] = 0
	}
	for i, row := range v.Coordinates {
		scope := publicOutputCoordinateScope(row)
		if _, known := counts[scope]; !known || !publicOutputID(row.CoordinateID) || !publicOutputID(row.BindingID) ||
			i > 0 && (v.Coordinates[i-1].ServiceContractID > row.ServiceContractID || v.Coordinates[i-1].ServiceContractID == row.ServiceContractID && v.Coordinates[i-1].PhysicalTarget >= row.PhysicalTarget) {
			return errRecord
		}
		coordinates[i] = row.CoordinateID
		counts[scope]++
	}
	for _, count := range counts {
		if count != 2 {
			return errRecord
		}
	}
	slices.Sort(coordinates)
	seen := map[string]bool{}
	for i, row := range v.Deletes {
		if row.Coordinate != coordinates[i] || len(row.Actions) != 1 {
			return errRecord
		}
		a := row.Actions[0]
		if !a.ValidAcknowledgement() || *a.Action != "delete-owned" && *a.Action != "delete-reserved-slot" || seen[*a.Attempt] || *a.Evidence.ConsumerLocator != "" {
			return errRecord
		}
		seen[*a.Attempt] = true
	}
	return nil
}

// PublicOutputScopes contains runtime locations for the public live cases.
// Cloud locations and SDK discovery use the selected domain context.
type PublicOutputScopes struct {
	Repository   PublicOutputScope `json:"repository"`
	Organization PublicOutputScope `json:"organization"`
	Environment  PublicOutputScope `json:"environment"`
}

type PublicOutputScope struct {
	Owner        string   `json:"owner"`
	Repository   string   `json:"repository,omitempty"`
	Environment  string   `json:"environment,omitempty"`
	Visibility   string   `json:"visibility,omitempty"`
	Repositories []uint64 `json:"repositories,omitempty"`
}

// ValidForScopes requires GitHub runtime locations only when a selected
// destination uses them. A supplied value must remain complete and valid.
func (v *PublicOutputScopes) ValidForScopes(scopes []string) bool {
	if v != nil && (len(scopes) == 0 || !v.Valid()) {
		return false
	}
	for _, scope := range scopes {
		switch scope {
		case "aws-secrets-manager", "gcp-secret-manager":
		case "github-repository", "github-organization", "github-environment":
			if v == nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (v PublicOutputScopes) Valid() bool {
	name := func(value string, max int, extra string) bool {
		if len(value) == 0 || len(value) > max {
			return false
		}
		for _, c := range value {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && !strings.ContainsRune(extra, c) {
				return false
			}
		}
		return value[0] != '-' && value[len(value)-1] != '-'
	}
	for _, scope := range []PublicOutputScope{v.Repository, v.Organization, v.Environment} {
		if !name(scope.Owner, 39, "-") {
			return false
		}
	}
	for _, scope := range []PublicOutputScope{v.Repository, v.Environment} {
		if !name(scope.Repository, 100, "._-") || strings.HasSuffix(scope.Repository, ".git") || scope.Visibility != "" || scope.Repositories != nil {
			return false
		}
	}
	if v.Repository.Environment != "" || !name(v.Environment.Environment, 255, "._-") || v.Organization.Repository != "" || v.Organization.Environment != "" || v.Organization.Visibility != "selected" || len(v.Organization.Repositories) == 0 || len(v.Organization.Repositories) > 65535 {
		return false
	}
	for i, id := range v.Organization.Repositories {
		if id == 0 || i > 0 && v.Organization.Repositories[i-1] >= id {
			return false
		}
	}
	return true
}

type PublicOutputCoordinate struct {
	ServiceContractID, TargetContractID, PhysicalTarget, CoordinateID, BindingID string
}

// The official live fixture's GitHub scopes share semantic contracts. Their
// canonical physical targets retain the scope needed to check the whole set.
func publicOutputCoordinateScope(row PublicOutputCoordinate) string {
	switch {
	case row.ServiceContractID == "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1" && row.TargetContractID == "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1":
		return "aws-secrets-manager"
	case row.ServiceContractID == "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1" && row.TargetContractID == "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1":
		return "gcp-secret-manager"
	case row.ServiceContractID == "github-actions/service/v1" && row.TargetContractID == "github-actions/target/v1":
		parts := strings.Split(row.PhysicalTarget, "/")
		if slices.Contains(parts, "") {
			return ""
		}
		switch {
		case len(parts) == 5 && parts[0] == "orgs" && parts[2] == "actions" && parts[3] == "secrets":
			return "github-organization"
		case len(parts) == 6 && parts[0] == "repos" && parts[3] == "actions" && parts[4] == "secrets":
			return "github-repository"
		case len(parts) == 7 && parts[0] == "repos" && parts[3] == "environments" && parts[5] == "secrets":
			return "github-environment"
		}
	}
	return ""
}

type PublicOutputPreviewRow struct {
	ServiceContractID string   `json:"service_contract_id"`
	PhysicalTarget    string   `json:"physical_target"`
	TargetContractID  string   `json:"target_contract_id"`
	Coordinate        *string  `json:"coordinate_id"`
	Binding           *string  `json:"binding_id"`
	Origin            string   `json:"origin"`
	Basis             string   `json:"basis"`
	Actions           []string `json:"actions"`
	Blockers          []string `json:"blocker_ids"`
	Conditional       *bool    `json:"conditional"`
	Reason            *uint8   `json:"reason_code"`
	Remote            *bool    `json:"remote_value_may_remain"`
	Late              *bool    `json:"late_write_risk"`
}

type PublicOutputPreview struct {
	Schema   string                   `json:"schema"`
	Complete *bool                    `json:"complete"`
	Reason   *uint8                   `json:"reason_code"`
	Warning  *bool                    `json:"domain_wide_warning"`
	Entries  []PublicOutputPreviewRow `json:"entries"`
}

func PublicOutputPreviewMatches(preview PublicOutputPreview, expected []PublicOutputCoordinate, settled bool) bool {
	if preview.Schema != "PublicationPreview/v2" || preview.Complete == nil || !*preview.Complete || preview.Reason == nil || *preview.Reason != 0 || preview.Warning == nil || *preview.Warning || len(preview.Entries) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for i, row := range preview.Entries {
		want := expected[i]
		if row.ServiceContractID != want.ServiceContractID || row.PhysicalTarget != want.PhysicalTarget || row.TargetContractID != want.TargetContractID || row.Coordinate == nil || !publicOutputID(*row.Coordinate) || seen[*row.Coordinate] || row.Binding == nil || !publicOutputID(*row.Binding) || want.CoordinateID != "" && *row.Coordinate != want.CoordinateID || want.BindingID != "" && *row.Binding != want.BindingID || row.Origin != "observed" && row.Origin != "both" || row.Actions == nil || row.Blockers == nil || len(row.Blockers) != 0 || row.Reason == nil || *row.Reason != 0 || row.Remote == nil || row.Late == nil || *row.Late || row.Conditional == nil {
			return false
		}
		seen[*row.Coordinate] = true
		if settled && (row.Origin != "observed" || row.Basis != "warning" || !*row.Remote || len(row.Actions) != 0 || *row.Conditional) {
			return false
		}
	}
	return true
}
