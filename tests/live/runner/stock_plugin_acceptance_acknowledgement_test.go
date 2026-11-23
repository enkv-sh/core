package core

import (
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestStockOutputAcknowledgementsRequireCompleteCorrelatedActions(t *testing.T) {
	// Fixed digests derived with Python hashlib/struct, independently of the
	// formatter and predicate: REQUEST-CONTRACT/v2 + wire32 + config32 +
	// blob32(service) + blob32(target) + action8; RESPONSE-CONTRACT/v2 + request32
	// + artifact32 + big-endian schema roles 6/1/3. Wire is SHA-256 of "ENKV/OUTPUT-WIRE/v6\x00".
	// Config starts with byte 1 and artifact starts with byte 2. The remaining
	// bytes are zero. Marker facts use separate fixed IDs.
	digests := map[string]struct{ request, response string }{
		"aws/create-empty":         {"ef021cd0da3794bde1589cd7a42251fae1732c0a7cf8590445c522afcf7e7a21", "c1e0d7896e153aeb8c4535fc292b78fb05175dcb350d14380ba06cc303763fdc"},
		"aws/write-value":          {"34f01e2598fe3016f3b3d741548aed89699521c21edcbf2e4b4438dd8e69ed1c", "fa27902fbcab0cc8f7c00fa31e227b65de5e5d4eb493f25f8ae93b2ce39e375f"},
		"aws/delete-owned":         {"50530cb2708f567600edae8d47bdbe77e84480173ba41c4dd06904988db076df", "ff668bcc2098e44f91ca287a88a5706b4b72215e96b95222c881749cf8b1d509"},
		"gcp/create-empty":         {"3c3565169541d1e33983a416807e929a1a58a15d232adb6287036941790126c5", "d81bc6bc1a3595c40d61bc9bf712059a2b7d780b128b7e34fd55f047969bf9fc"},
		"gcp/write-value":          {"7a5a51fcd92a45a2b7f2dc080ae421da6ca284e785108fdcc2eee65eda4749c4", "2fe0610fb335d9b2e3d924038e32c594a29aa285bd716d5ed1ff9c93cea448d0"},
		"gcp/delete-owned":         {"b14963c3a3ac2cde3889e639eb1bfc0d18e231640e02c5e60c9859ffc127ec3e", "d0b28bdad50311005f2698f828b90efb46e0e7c4e5b71a5a1017e970729cdd0d"},
		"github/create-with-value": {"d9a7c4c76be1409ef145ac72a8df634bb041323de322ec2cbc99625e4f931065", "e2d475b75207bf5c65a88df903f52bc1bfb66d06eb588d5217e972ac42c69e93"},
		"github/delete-owned":      {"82e05a90812ff0841bb0e9bb5c3fe29c4d75c709b9302469353a8906629877a5", "4fe76633ba101b8afaf1f7ea15cee06f25486448214db229e91adfbacbe44590"},
	}
	id := func(text string) contract.ID {
		body, err := hex.DecodeString(text)
		if err != nil || len(body) != 32 {
			t.Fatal("fixed identity literal unavailable")
		}
		return contract.ID(body)
	}
	support := stockPublicationSupport{Protocol: id("c0432dd35c122a5bf0b44a58234ef9aef0a2cbeb48acd2169f4bc027f322dcf2"), Config: contract.ID{1}, Artifact: contract.ID{2}}
	for _, profile := range []string{"aws", "gcp", "github-repository", "github-organization", "github-environment"} {
		for _, deletion := range []bool{false, true} {
			conditions := []string{"exact"}
			switch {
			case profile == "aws" && !deletion:
				conditions = append(conditions, "missing-action", "missing-projection", "malformed-projection", "wrong-projection", "missing-attempt", "malformed-attempt", "wrong-attempt", "duplicate-attempt", "missing-evidence", "missing-request", "missing-resource", "missing-locator", "wrong-response", "wrong-artifact", "wrong-class", "wrong-entry", "wrong-status", "wrong-resource", "wrong-locator", "missing-action-row", "duplicate-action", "wrong-action-set", "missing-marker", "wrong-marker-operation", "wrong-marker-coordinate", "wrong-create-resource", "wrong-create-locator")
			case profile == "aws" && deletion:
				conditions = append(conditions, "missing-action-row", "duplicate-action", "wrong-action-set", "wrong-response")
			case profile == "gcp" || profile == "github-repository":
				conditions = append(conditions, "wrong-status", "wrong-resource", "wrong-locator", "wrong-action-set")
				if profile == "gcp" && !deletion {
					conditions = append(conditions, "wrong-create-resource", "wrong-create-locator", "unqualified-version")
				}
			}
			for _, condition := range conditions {
				t.Run(fmt.Sprintf("%s/delete=%t/%s", profile, deletion, condition), func(t *testing.T) {
					family := profile
					service, target := "github-actions/service/v1", "github-actions/target/v1"
					actions := []string{"create-with-value"}
					if profile == "aws" {
						service, target = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1"
						actions = []string{"create-empty", "write-value"}
					}
					if profile == "gcp" {
						service, target = "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1"
						actions = []string{"create-empty", "write-value"}
					}
					if strings.HasPrefix(profile, "github-") {
						family = "github"
					}
					if deletion {
						actions = []string{"delete-owned"}
					}
					var expected []publicOutputCoordinate
					contracts := map[string]stockPublicationSupport{}
					observation := stockPublicationObservation{Domain: contract.ID{7}, Operation: contract.ID{8}, Markers: map[contract.ID]contract.PublicationMarker{}}
					var encodedRows []string
					nextAttempt := 1
					for i, name := range []string{"ENKV_TEST_PLAIN", "ENKV_TEST_SECRET"} {
						physical := "repos/owner/repository/actions/secrets/" + name
						switch profile {
						case "aws":
							physical = "arn:aws:secretsmanager:us-east-1:123456789012:secret:" + name
						case "gcp":
							physical = "projects/123456789/secrets/" + name
						case "github-organization":
							physical = "orgs/owner/actions/secrets/" + name
						case "github-environment":
							physical = "repos/owner/repository/environments/prod/secrets/" + name
						}
						coordinate := strings.Repeat(string(rune('a'+i)), 64)
						binding := strings.Repeat("c", 64)
						expected = append(expected, publicOutputCoordinate{ServiceContractID: service, TargetContractID: target, PhysicalTarget: physical, CoordinateID: coordinate, BindingID: binding})
						contracts[coordinate] = support
						var encodedActions []string
						for _, action := range actions {
							attempt := fmt.Sprintf("%064x", nextAttempt)
							projection := fmt.Sprintf("%064x", 100+nextAttempt)
							nextAttempt++
							resource, locator, status := physical, "", 200
							if family == "github" {
								status = 204
							}
							switch action {
							case "create-empty":
								if family == "aws" {
									resource = physical + "-AbCd12"
									locator = resource + "?stage=AWSCURRENT"
								} else {
									locator = physical + "/versions/latest"
								}
							case "create-with-value":
								locator = physical
								status = 201
							case "write-value":
								if family == "aws" {
									resource = attempt
								} else {
									resource = physical + "/versions/7"
								}
							case "delete-owned":
								if family == "aws" {
									resource = physical + "-AbCd12"
								}
							}
							digest := digests[family+"/"+action]
							encodedActions = append(encodedActions, fmt.Sprintf(`{"action":%q,"projection_commitment":%q,"attempt_id":%q,"disposition":"acknowledged","reason_code":0,"remote_value_may_remain":true,"late_write_risk":false,"blocker_ids":[],"evidence":{"schema":"PublicationEvidence/v3","entry":"may-have-entered","class":"acknowledged","response_contract_digest":%q,"normalized_status":%d,"safe_request_id":"","safe_resource_id":%q,"consumer_locator":%q}}`, action, projection, attempt, digest.response, status, resource, locator))
							actionCode := map[string]uint8{"create-empty": 1, "create-with-value": 2, "write-value": 3, "delete-owned": 5}[action]
							observation.Markers[id(attempt)] = contract.PublicationMarker{DomainID: observation.Domain, OperationID: observation.Operation, AttemptID: id(attempt), CoordinateID: id(coordinate), ProjectionCommitment: id(projection), Projection: contract.PublicationProjection{DomainID: observation.Domain, CoordinateID: id(coordinate), BindingIncarnationID: id(binding), Action: actionCode, RequestContractDigest: id(digest.request)}, State: contract.PublicationAcknowledged, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: id(digest.response), NormalizedStatus: uint16(status), SafeResourceID: resource, ConsumerLocator: locator}}
						}
						encodedRows = append(encodedRows, fmt.Sprintf(`{"coordinate_id":%q,"actions":[%s]}`, coordinate, strings.Join(encodedActions, ",")))
					}
					// Damage the later public coordinate after fixed-wire decoding. Markers
					// remain independent; semantic damage also changes the marker to prove
					// that canonical correlation alone cannot waive the fixed-profile rule.
					var rows []records.PublicOutputActionResult
					if jsonv2.Unmarshal([]byte("["+strings.Join(encodedRows, ",")+"]"), &rows) != nil {
						t.Fatal("fixed publication wire unavailable")
					}
					action := &rows[1].Actions[len(rows[1].Actions)-1]
					if condition == "wrong-create-resource" || condition == "wrong-create-locator" {
						action = &rows[1].Actions[0]
					}
					originalAttempt := id(*action.Attempt)
					marker := observation.Markers[originalAttempt]
					switch condition {
					case "missing-action":
						action.Action = nil
					case "missing-projection":
						action.Projection = nil
					case "malformed-projection":
						malformed := "invalid"
						action.Projection = &malformed
					case "wrong-projection":
						wrong := strings.Repeat("f", 64)
						action.Projection = &wrong
					case "missing-attempt":
						action.Attempt = nil
					case "malformed-attempt":
						malformed := "invalid"
						action.Attempt = &malformed
					case "wrong-attempt":
						wrong := strings.Repeat("f", 64)
						action.Attempt = &wrong
					case "duplicate-attempt":
						action.Attempt = rows[0].Actions[0].Attempt
					case "missing-evidence":
						action.Evidence = nil
					case "missing-request":
						action.Evidence.SafeRequestID = nil
					case "missing-resource":
						action.Evidence.SafeResourceID = nil
					case "missing-locator":
						action.Evidence.ConsumerLocator = nil
					case "wrong-response":
						action.Evidence.Response = strings.Repeat("e", 64)
						marker.Evidence.ResponseContractDigest = id(action.Evidence.Response)
					case "wrong-artifact":
						changed := support
						changed.Artifact = contract.ID{9}
						contracts[rows[1].Coordinate] = changed
					case "wrong-class":
						action.Evidence.Class = "qualified-no-effect"
						marker.Evidence.Class = contract.PublicationQualifiedNoEffect
					case "wrong-entry":
						action.Evidence.Entry = "not-entered"
						marker.Evidence.Entry = contract.PublicationNotEntered
					case "wrong-status":
						action.Evidence.Status = 205
						marker.Evidence.NormalizedStatus = 205
					case "wrong-resource", "wrong-create-resource":
						wrong := "other/target"
						action.Evidence.SafeResourceID = &wrong
						marker.Evidence.SafeResourceID = wrong
					case "wrong-locator", "wrong-create-locator":
						wrong := "other/target"
						action.Evidence.ConsumerLocator = &wrong
						marker.Evidence.ConsumerLocator = wrong
					case "unqualified-version":
						wrong := expected[1].PhysicalTarget + "/versions/latest"
						action.Evidence.SafeResourceID = &wrong
						marker.Evidence.SafeResourceID = wrong
					case "missing-action-row":
						rows[1].Actions = rows[1].Actions[:len(rows[1].Actions)-1]
					case "duplicate-action":
						rows[1].Actions = append(slices.Clone(rows[1].Actions), *action)
					case "wrong-action-set":
						wrong := "delete-reserved-slot"
						code := uint8(6)
						if !deletion {
							wrong = "update-policy"
							code = 4
						}
						action.Action = &wrong
						marker.Projection.Action = code
					case "wrong-marker-operation":
						marker.OperationID = contract.ID{9}
					case "wrong-marker-coordinate":
						marker.CoordinateID = contract.ID{9}
					}
					observation.Markers[originalAttempt] = marker
					if condition == "missing-marker" {
						delete(observation.Markers, originalAttempt)
					}
					if got, want := stockOutputActionsMatch(rows, expected, contracts, observation, deletion), condition == "exact"; got != want {
						t.Fatalf("stock acknowledgement match = %t, want %t", got, want)
					}
				})
			}
		}
	}
}
