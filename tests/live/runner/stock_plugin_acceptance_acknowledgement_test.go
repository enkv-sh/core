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
	// + artifact32 + big-endian schema roles 4/1/3. Config is {1}, artifact is
	// {2}; all remaining bytes are zero. Marker facts use separate fixed IDs.
	digests := map[string]struct{ request, response string }{
		"aws/create-empty":         {"aec221c62014342fdcf6e4bb3bc02c8b1406cfebae38136b0bd470af4248bc15", "ad610066a4e47a8811faed186401ddd351d2e2f7782b48acd73c0f1178594e6d"},
		"aws/write-value":          {"511ef08c7c1848f4adbf8392bdcbb335b2b473cac3fa7d93d1ba2101a08e6580", "77abf5a35dd0e2d75c5e8d75221caeae02c12cc7bbe367649a9c7c1d8ca2fc47"},
		"aws/delete-owned":         {"2cb1706c83d83849e70f3572df0fa3d94c7eda8fb679882b6de8b6cf76aeddcb", "8281b348b854305c24291d66ccb0eb57aba2356a7e985c971339ad6317e635a7"},
		"gcp/create-empty":         {"5a2d48a2ea96d777846e9b40a8f178f601ef7e8bf9dbd43a7b84f9e1baf5feb8", "9709d9e7569de1b1080d7d290df3f62c98cce72af9ee65caff16572359e91434"},
		"gcp/write-value":          {"6b1470df65325c6897c818d93484a1da97ff7b2f2c19c6fe18c7f3701b820d30", "65f3dec326370ff80cff01136cfbddb8dd729f8586bde4cdc3d79f76c923e6eb"},
		"gcp/delete-owned":         {"222d6097e8882b1202488d0bb6f0326b31dc3278fa09b94aa258bc1f5fe2e021", "ec492c443d00cbeb8d8365f5f921f8048a19b00fb34e3b401ec26a1a8e84e1ff"},
		"github/create-with-value": {"f4b5e4b914ab0927a7242d9128bf10cfbb8d3d4bae8390365b88dd55d43719c0", "61b0cab5404179829e725419548e29ef7891490bba157721a1bb7f95482cd8ae"},
		"github/delete-owned":      {"46a6b9a1c9e11b1b4b97618e36685479e9adec9dc3544401c504d9b49acd221d", "cc251026bf2cff08ed4ab6bb7319b7026de85a4a0c0fd7d49caa82a128daabc2"},
	}
	id := func(text string) contract.ID {
		body, err := hex.DecodeString(text)
		if err != nil || len(body) != 32 {
			t.Fatal("fixed identity literal unavailable")
		}
		return contract.ID(body)
	}
	support := stockPublicationSupport{Protocol: id("d64d97b5c889c28bfefaa9ae3b1ae283589e0f7a7ec6074f39298e06aeec293c"), Config: contract.ID{1}, Artifact: contract.ID{2}}
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
					if stockOutputActionsMatch(rows, expected, contracts, observation, deletion) != (condition == "exact") {
						t.Fatal("stock publication accepted an incomplete correlated acknowledgement")
					}
				})
			}
		}
	}
}
