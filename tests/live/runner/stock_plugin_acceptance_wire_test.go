package core

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
)

// These fixed wire literals follow spec/057's bounded public results and the
// product owners GeneratedCurrentGeneration, GeneratedEffectFact,
// GeneratedDutyFact and contract.GeneratorTarget. Field spellings follow the
// public projection in compositions/full/generated_result{,_writer}.go.
// No consumer struct or formatter produces the fixture bytes. Each identity
// has a separate sentinel so swapped JSON tags cannot compare equal by accident.
const (
	stockWireEntry                = "0101010101010101010101010101010101010101010101010101010101010101"
	stockWireA0Generation         = "0202020202020202020202020202020202020202020202020202020202020202"
	stockWireA0Resource           = "0303030303030303030303030303030303030303030303030303030303030303"
	stockWireA0Digest             = "0404040404040404040404040404040404040404040404040404040404040404"
	stockWireA0Operation          = "0505050505050505050505050505050505050505050505050505050505050505"
	stockWireA0Attempt            = "0606060606060606060606060606060606060606060606060606060606060606"
	stockWireConfig               = "0707070707070707070707070707070707070707070707070707070707070707"
	stockWireResourceContract     = "0808080808080808080808080808080808080808080808080808080808080808"
	stockWireADescriptor          = "0909090909090909090909090909090909090909090909090909090909090909"
	stockWireAExecutor            = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
	stockWireARoute               = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
	stockWireCreateResultContract = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
	stockWireRetireResultContract = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
	stockWireDuty                 = "1b5ce8cc25e0e1d8b510fd4c43050597cac4e82bcf0978f95d1d49530e1e92ba"
	stockWireA1Generation         = "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"
	stockWireA1Resource           = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
	stockWireA1Digest             = "1010101010101010101010101010101010101010101010101010101010101010"
	stockWireA1Operation          = "1111111111111111111111111111111111111111111111111111111111111111"
	stockWireA1Attempt            = "1212121212121212121212121212121212121212121212121212121212121212"
	stockWireBDescriptor          = "1313131313131313131313131313131313131313131313131313131313131313"
	stockWireBExecutor            = "1414141414141414141414141414141414141414141414141414141414141414"
	stockWireBRoute               = "1515151515151515151515151515151515151515151515151515151515151515"

	stockWireA1Current = `{"name":"generated","entry_incarnation_id":"0101010101010101010101010101010101010101010101010101010101010101",
"generation_id":"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e","epoch":1,"origin_operation_id":"1111111111111111111111111111111111111111111111111111111111111111",
"origin_attempt_id":"1212121212121212121212121212121212121212121212121212121212121212","resource_incarnation_id":"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
"config_contract_id":"0707070707070707070707070707070707070707070707070707070707070707","resource_contract_id":"0808080808080808080808080808080808080808080808080808080808080808",
"resource_digest":"1010101010101010101010101010101010101010101010101010101010101010","lifecycle_mode":"managed",
"completion_class":"deletion-acknowledged","retirement_policy":"manual","retiring_duty_id":null}`

	stockWireA0Duty = `{"facts":{"duty_id":"1b5ce8cc25e0e1d8b510fd4c43050597cac4e82bcf0978f95d1d49530e1e92ba",
"original_operation_id":"0505050505050505050505050505050505050505050505050505050505050505","original_attempt_id":"0606060606060606060606060606060606060606060606060606060606060606","owner_id":"1616161616161616161616161616161616161616161616161616161616161616",
"resource_incarnation_id":"0303030303030303030303030303030303030303030303030303030303030303","descriptor_id":"0909090909090909090909090909090909090909090909090909090909090909",
"config_contract_id":"0707070707070707070707070707070707070707070707070707070707070707","resource_contract_id":"0808080808080808080808080808080808080808080808080808080808080808","executor_id":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
"credential_route_id":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b","result_contract_id":"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b","lifecycle_mode":"managed",
"kind":"retirement","status":"not-started","step":0,"completion_class":"deletion-acknowledged",
"generation_id":"0202020202020202020202020202020202020202020202020202020202020202","retirement_policy":"manual","evidence_ceiling":"canonical",
"warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":false}},
"target":{"name":"generated","entry_incarnation_id":"0101010101010101010101010101010101010101010101010101010101010101","epoch":0,
"resource_incarnation_id":"0303030303030303030303030303030303030303030303030303030303030303","config_contract_id":"0707070707070707070707070707070707070707070707070707070707070707","resource_contract_id":"0808080808080808080808080808080808080808080808080808080808080808",
"resource_digest":"0404040404040404040404040404040404040404040404040404040404040404","lifecycle_mode":"managed","original_operation_id":"0505050505050505050505050505050505050505050505050505050505050505",
"original_attempt_id":"0606060606060606060606060606060606060606060606060606060606060606","result_contract_id":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c","completion_class":"deletion-acknowledged"},"progress":[]}`

	stockWireA1Create = `{"facts":{"operation_id":"1111111111111111111111111111111111111111111111111111111111111111","lineage_id":"1717171717171717171717171717171717171717171717171717171717171717",
"attempt_id":"1212121212121212121212121212121212121212121212121212121212121212","predecessor_attempt_id":null,"action":"create","name":"generated",
"entry_incarnation_id":"0101010101010101010101010101010101010101010101010101010101010101","epoch":1,"planned_value_slot_id":"1818181818181818181818181818181818181818181818181818181818181818",
"planned_resource_incarnation_id":"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f","resource_digest":"1010101010101010101010101010101010101010101010101010101010101010","generation_id":"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
"duty_id":null,"hazard_id":null,"transmission_id":"1919191919191919191919191919191919191919191919191919191919191919","result_id":"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
"descriptor_id":"0909090909090909090909090909090909090909090909090909090909090909","config_contract_id":"0707070707070707070707070707070707070707070707070707070707070707","resource_contract_id":"0808080808080808080808080808080808080808080808080808080808080808",
"executor_id":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a","credential_route_id":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b","result_contract_id":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
"lifecycle_mode":"managed","state":"succeeded","stage":5,"retry_consumed":false,
"completion_class":"deletion-acknowledged","reason":0,"evidence_ceiling":"provider-facts","summary_class":5,
"warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":false}},
"target":{"name":"generated","entry_incarnation_id":"0101010101010101010101010101010101010101010101010101010101010101","epoch":1,
"resource_incarnation_id":"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f","config_contract_id":"0707070707070707070707070707070707070707070707070707070707070707","resource_contract_id":"0808080808080808080808080808080808080808080808080808080808080808",
"resource_digest":"1010101010101010101010101010101010101010101010101010101010101010","lifecycle_mode":"managed","original_operation_id":"1111111111111111111111111111111111111111111111111111111111111111",
"original_attempt_id":"1212121212121212121212121212121212121212121212121212121212121212","result_contract_id":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c","completion_class":"deletion-acknowledged"},"progress":[]}`

	stockWireMutationA1 = `{"schema":"ProductResult/v1","operation_kind":"apply-declaration",
"state_result":"retirement-pending","request_identity":"1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b","commit_may_have_occurred":false,
"effect_warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":false},
"effects_available":true,"effects":[` + stockWireA1Create + `],"summary_counts_available":true,
"summary_counts":{"effects":1,"outputs":0,"duties":1,"hazards":0,"changed_access":0,"succeeded":1,
"failed":0,"neutral":0,"pending":1,"unknown":0,"preserved_residue":0,"no_effect_predecessors":0},
"deletion_acknowledged_count":0,"invalidation_confirmed_count":0,"unknown_count":0,
"related_work_available":true,"duties":[` + stockWireA0Duty + `],"hazards":[]}`

	stockWireListA1 = `{"schema":"ProductResult/v1","operation_kind":"generated-list","state_result":"success",
"observed_revision_id":"1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c","snapshot_id":"1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d",
"effect_warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":false},
"current_generations":[` + stockWireA1Current + `],"active_operation":null,
"attempts":[` + stockWireA1Create + `],"duties":[` + stockWireA0Duty + `],"hazards":[],
"pending_releases":[],"next_actions":[{"command":"generated retire","operation_id":null,"duty_id":"1b5ce8cc25e0e1d8b510fd4c43050597cac4e82bcf0978f95d1d49530e1e92ba","attempt_id":null}]}`

	stockWireRetirementEffect = `{"facts":{"operation_id":"1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e","lineage_id":"73076158b05a2630ddaa3e4b1dc8c89392e30816d50115f46b0641a4cdb0c40e",
"attempt_id":"552d57e193a7fc4bf0ced066753e9f18ff8a2ee447981c35717cfe8ab556ec62","predecessor_attempt_id":null,"action":"delete","name":"generated",
"entry_incarnation_id":"0101010101010101010101010101010101010101010101010101010101010101","epoch":0,"planned_value_slot_id":"2121212121212121212121212121212121212121212121212121212121212121",
"planned_resource_incarnation_id":"0303030303030303030303030303030303030303030303030303030303030303","resource_digest":"0404040404040404040404040404040404040404040404040404040404040404","generation_id":null,
"duty_id":null,"hazard_id":null,"transmission_id":"2222222222222222222222222222222222222222222222222222222222222222","result_id":"2323232323232323232323232323232323232323232323232323232323232323",
"descriptor_id":"0909090909090909090909090909090909090909090909090909090909090909","config_contract_id":"0707070707070707070707070707070707070707070707070707070707070707","resource_contract_id":"0808080808080808080808080808080808080808080808080808080808080808",
"executor_id":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a","credential_route_id":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b","result_contract_id":"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b",
"lifecycle_mode":"managed","state":"succeeded","stage":5,"retry_consumed":false,
"completion_class":"deletion-acknowledged","reason":0,"evidence_ceiling":"deletion-acknowledged","summary_class":5,
"warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":true}},
"target":{"name":"generated","entry_incarnation_id":"0101010101010101010101010101010101010101010101010101010101010101","epoch":0,
"resource_incarnation_id":"0303030303030303030303030303030303030303030303030303030303030303","config_contract_id":"0707070707070707070707070707070707070707070707070707070707070707","resource_contract_id":"0808080808080808080808080808080808080808080808080808080808080808",
"resource_digest":"0404040404040404040404040404040404040404040404040404040404040404","lifecycle_mode":"managed","original_operation_id":"0505050505050505050505050505050505050505050505050505050505050505",
"original_attempt_id":"0606060606060606060606060606060606060606060606060606060606060606","result_contract_id":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c","completion_class":"deletion-acknowledged"},"progress":[]}`

	stockWireRetirementACK = `{"schema":"ProductResult/v1","operation_kind":"retire-generated-generation",
"domain_id":"2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c","operation_id":"1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e",
"state_result":"success","request_identity":"2424242424242424242424242424242424242424242424242424242424242424","commit_may_have_occurred":false,
"effect_warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":true},
"effects_available":true,"effects":[` + stockWireRetirementEffect + `],"summary_counts_available":true,
"summary_counts":{"effects":1,"outputs":0,"duties":0,"hazards":0,"changed_access":0,"succeeded":1,
"failed":0,"neutral":0,"pending":0,"unknown":0,"preserved_residue":0,"no_effect_predecessors":0},
"deletion_acknowledged_count":1,"invalidation_confirmed_count":0,"unknown_count":0,
"related_work_available":true,"duties":[],"hazards":[],
"current_domain_duty_ids":[],"current_domain_hazard_ids":[],"related_duty_ids":[],"related_hazard_ids":[]}`
)

// full_only: false
func TestStockGeneratedWireBindsSelectedCreateAndDuty(t *testing.T) {
	wantCurrent := stockGeneratedCurrent{
		Name: "generated", Incarnation: stockWireEntry, Generation: stockWireA1Generation, Epoch: 1,
		Resource: stockWireA1Resource, Digest: stockWireA1Digest,
		OriginOperation: stockWireA1Operation, OriginAttempt: stockWireA1Attempt,
		ConfigContract: stockWireConfig, ResourceContract: stockWireResourceContract,
		Lifecycle: "managed", Completion: "deletion-acknowledged", RetirementPolicy: "manual",
	}
	old := wantCurrent
	old.Generation, old.Epoch, old.Resource, old.Digest = stockWireA0Generation, 0, stockWireA0Resource, stockWireA0Digest
	old.OriginOperation, old.OriginAttempt = stockWireA0Operation, stockWireA0Attempt
	a0Body := strings.NewReplacer(stockWireA1Generation, stockWireA0Generation, stockWireA1Resource, stockWireA0Resource, stockWireA1Digest, stockWireA0Digest, stockWireA1Operation, stockWireA0Operation, stockWireA1Attempt, stockWireA0Attempt, `"epoch":1`, `"epoch":0`).Replace(stockWireA1Create)
	var a0Create stockGeneratedFact
	if json.Unmarshal([]byte(a0Body), &a0Create) != nil {
		t.Fatal("fixed original create was refused")
	}
	b2 := wantCurrent
	b2.Epoch = 2
	b2.Generation = "2626262626262626262626262626262626262626262626262626262626262626"
	b2.Resource = "2727272727272727272727272727272727272727272727272727272727272727"
	b2.Digest = "2828282828282828282828282828282828282828282828282828282828282828"
	b2.OriginOperation = "2929292929292929292929292929292929292929292929292929292929292929"
	b2.OriginAttempt = "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
	mutation, err := stockGeneratedDecode([]byte(stockWireMutationA1), 3, "retirement-pending")
	if err != nil {
		t.Fatal("fixed populated A1 mutation was refused", err)
	}
	list, err := stockGeneratedDecode([]byte(stockWireListA1), 0, "success")
	if err != nil {
		t.Fatal("fixed populated generated list was refused", err)
	}
	if len(list.Current) != 1 || list.Current[0] != wantCurrent || !stockCurrentValid(list.Current[0], 1) ||
		len(list.Duties) != 1 || len(list.Effects) != 1 || len(mutation.Duties) != 1 || len(mutation.Effects) != 1 {
		t.Fatal("public populated fields did not retain their exact independent identities")
	}
	if _, ok := stockCreateMatches(mutation, wantCurrent, stockWireADescriptor, stockWireAExecutor, stockWireARoute); !ok {
		t.Fatal("A1 creation does not match its selected A support")
	}
	if _, ok := stockCreateMatches(list, wantCurrent, stockWireADescriptor, stockWireAExecutor, stockWireARoute); !ok {
		t.Fatal("generated-list attempt does not retain the selected A1 create tuple")
	}
	if !stockDutyMatchesSupport(list.Duties[0], old, a0Create, stockWireADescriptor, stockWireAExecutor, stockWireARoute, stockWireRetireResultContract) ||
		!stockDutyMatchesSupport(mutation.Duties[0], old, a0Create, stockWireADescriptor, stockWireAExecutor, stockWireARoute, stockWireRetireResultContract) {
		t.Fatal("A0 retirement Duty does not match its original resource and A support")
	}
	t.Run("selected-retirement-contract", func(t *testing.T) {
		descriptor, err := artifact.DecodeDescriptor([]byte(`{"schema":1,"name":"independent-stock-generator","role":"generator","version":"0.1.0","wire":{"kind":"wire","identity":"ae01109b61a0b703dc32a6453ea2356e9a0fe1633081893e2dfd33d269823310","version":4},"generator":{"config_contract_id":"0707070707070707070707070707070707070707070707070707070707070707","credential_route":"AAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBGUVOS1ZfR0VORVJBVE9SX1RFU1RfVE9LRU4AAAAA"},"output":null,"manifest":null}`))
		if err != nil {
			t.Fatal("fixed selected descriptor refused", err)
		}
		facts, err := artifact.BindGeneratorFacts(artifact.GeneratorFacts{
			Schema: artifact.FamilySchema, Descriptor: descriptor,
			ExecutionFacts: artifact.ExecutionFacts{Module: "author.example/generator", Command: ".", GoVersion: "go1.27.3", NativeTuple: "darwin/arm64"},
		}, artifact.Digest{1}, 1, artifact.Digest{2})
		if err != nil || facts.DescriptorID.String() != "0cac132f05038156bea2614834af780798374c8093f41db9ec92618a116c1e4b" {
			t.Fatal("fixed metadata differs from independently encoded descriptor", err)
		}
		body, err := json.Marshal(facts)
		if err != nil {
			t.Fatal(err)
		}
		metadata := artifact.Metadata{Role: "generator", Family: &artifact.Family{Schema: artifact.FamilySchema, Facts: body}}
		route, err := credentialroute.Decode(descriptor.Generator.CredentialRoute)
		if err != nil {
			t.Fatal(err)
		}
		routeID, err := credentialroute.Identity(route)
		if err != nil {
			t.Fatal(err)
		}
		duty := list.Duties[0]
		duty.Facts.Descriptor, duty.Facts.Executor, duty.Facts.CredentialRoute = facts.DescriptorID.String(), facts.ExecutorID.String(), artifact.Digest(routeID).String()
		duty.Facts.ResultContract = "4eb23fd5c025745915bbc82936ba56cbec6a7ebe05a77fc897daaf1e1a931799"
		if !stockDutyMatches(duty, old, a0Create, metadata) {
			t.Fatal("selected Delete contract differs from independent action/bounds vector")
		}
		duty.Facts.ResultContract = stockWireCreateResultContract
		if stockDutyMatches(duty, old, a0Create, metadata) {
			t.Fatal("selected retirement accepted original create result contract")
		}
	})
	// A0 and A1 use A; B2 must use B. The expected support comes from the
	// scenario's selected build, separately from the wire fields being checked.
	for _, tc := range []struct {
		name                                string
		current                             stockGeneratedCurrent
		effect, descriptor, executor, route string
	}{
		{"a0", old, strings.NewReplacer(stockWireA1Generation, stockWireA0Generation, stockWireA1Resource, stockWireA0Resource, stockWireA1Digest, stockWireA0Digest, stockWireA1Operation, stockWireA0Operation, stockWireA1Attempt, stockWireA0Attempt, `"epoch":1`, `"epoch":0`).Replace(stockWireA1Create), stockWireADescriptor, stockWireAExecutor, stockWireARoute},
		{"a1", wantCurrent, stockWireA1Create, stockWireADescriptor, stockWireAExecutor, stockWireARoute},
		{"b2", b2, strings.NewReplacer(stockWireA1Generation, b2.Generation, stockWireA1Resource, b2.Resource, stockWireA1Digest, b2.Digest, stockWireA1Operation, b2.OriginOperation, stockWireA1Attempt, b2.OriginAttempt, stockWireADescriptor, stockWireBDescriptor, stockWireAExecutor, stockWireBExecutor, stockWireARoute, stockWireBRoute, `"epoch":1`, `"epoch":2`).Replace(stockWireA1Create), stockWireBDescriptor, stockWireBExecutor, stockWireBRoute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, damage := range []string{"exact", "descriptor", "executor", "route", "origin", "resource", "target-origin"} {
				t.Run(damage, func(t *testing.T) {
					effect := tc.effect
					switch damage {
					case "descriptor":
						effect = strings.Replace(effect, `"descriptor_id":"`+tc.descriptor+`"`, `"descriptor_id":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
					case "executor":
						effect = strings.Replace(effect, `"executor_id":"`+tc.executor+`"`, `"executor_id":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
					case "route":
						effect = strings.Replace(effect, `"credential_route_id":"`+tc.route+`"`, `"credential_route_id":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
					case "origin":
						effect = strings.Replace(effect, `"operation_id":"`+tc.current.OriginOperation+`"`, `"operation_id":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
					case "resource":
						effect = strings.Replace(effect, `"planned_resource_incarnation_id":"`+tc.current.Resource+`"`, `"planned_resource_incarnation_id":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
					case "target-origin":
						effect = strings.Replace(effect, `"original_attempt_id":"`+tc.current.OriginAttempt+`"`, `"original_attempt_id":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
					}
					body := strings.Replace(stockWireMutationA1, stockWireA1Create, effect, 1)
					result, err := stockGeneratedDecode([]byte(body), 3, "retirement-pending")
					if err != nil {
						t.Fatal("structurally valid create wire was refused", err)
					}
					_, ok := stockCreateMatches(result, tc.current, tc.descriptor, tc.executor, tc.route)
					if ok != (damage == "exact") {
						t.Fatal("create support or original resource mismatch was accepted")
					}
				})
			}
		})
	}
	for _, field := range []string{"descriptor_id", "executor_id", "credential_route_id", "original_operation_id", "original_attempt_id", "resource_incarnation_id"} {
		t.Run("duty-"+field, func(t *testing.T) {
			original := map[string]string{"descriptor_id": stockWireADescriptor, "executor_id": stockWireAExecutor, "credential_route_id": stockWireARoute, "original_operation_id": stockWireA0Operation, "original_attempt_id": stockWireA0Attempt, "resource_incarnation_id": stockWireA0Resource}[field]
			duty := strings.Replace(stockWireA0Duty, `"`+field+`":"`+original+`"`, `"`+field+`":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
			damaged := strings.Replace(stockWireListA1, stockWireA0Duty, duty, 1)
			result, err := stockGeneratedDecode([]byte(damaged), 0, "success")
			if err != nil {
				t.Fatal("structurally valid Duty wire was refused", err)
			}
			if stockDutyMatchesSupport(result.Duties[0], old, a0Create, stockWireADescriptor, stockWireAExecutor, stockWireARoute, stockWireRetireResultContract) {
				t.Fatal("Duty support or original resource mismatch was accepted")
			}
		})
	}
	for _, condition := range []string{"exact", "target-contract", "duty-contract", "swapped-contracts", "equal-contracts", "wrong-selected-contract", "original-create-contract"} {
		t.Run(condition, func(t *testing.T) {
			duty, original := list.Duties[0], a0Create
			retirement := stockWireRetireResultContract
			switch condition {
			case "target-contract":
				duty.Target.ResultContract = stockWireA1Generation
			case "duty-contract":
				duty.Facts.ResultContract = stockWireA1Generation
			case "swapped-contracts":
				duty.Target.ResultContract, duty.Facts.ResultContract = duty.Facts.ResultContract, duty.Target.ResultContract
			case "equal-contracts":
				duty.Facts.ResultContract = duty.Target.ResultContract
			case "wrong-selected-contract":
				retirement = stockWireCreateResultContract
			case "original-create-contract":
				original.Target.ResultContract, original.Facts.ResultContract = stockWireA1Generation, stockWireA1Generation
			}
			if stockDutyMatchesSupport(duty, old, original, stockWireADescriptor, stockWireAExecutor, stockWireARoute, retirement) != (condition == "exact") {
				t.Fatal("Duty did not bind distinct original create and selected retirement contracts")
			}
		})
	}
	zeroCurrent := strings.Replace(stockWireA1Current, `"epoch":1`, `"epoch":0`, 1)
	zeroCreate := strings.ReplaceAll(stockWireA1Create, `"epoch":1`, `"epoch":0`)
	for _, tc := range []struct {
		name, body, state string
		code              int
	}{
		{"current-zero", strings.Replace(stockWireListA1, stockWireA1Current, zeroCurrent, 1), "success", 0},
		{"duty-target-zero", stockWireListA1, "success", 0},
		{"effect-zero", strings.Replace(stockWireMutationA1, stockWireA1Create, zeroCreate, 1), "retirement-pending", 3},
		{"later-attempt-zero", strings.Replace(stockWireListA1, `"attempts":[`+stockWireA1Create+`]`, `"attempts":[`+stockWireA1Create+`,`+zeroCreate+`]`, 1), "success", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := stockGeneratedDecode([]byte(tc.body), tc.code, tc.state); err != nil {
				t.Fatal("explicit zero epoch was refused", err)
			}
			// Zero is a legitimate epoch. Its absence and null must not decode
			// to a known zero in any populated current, target or effect row.
			for _, replacement := range []string{"", `"epoch":null,`} {
				body := strings.Replace(tc.body, `"epoch":0,`, replacement, 1)
				if _, err := stockGeneratedDecode([]byte(body), tc.code, tc.state); err == nil {
					t.Fatal("missing or null epoch became a known zero")
				}
			}
		})
	}
	later := strings.Replace(stockWireA1Create, `"late_effect":false`, `"late_effect":true`, 1)
	damaged := strings.Replace(stockWireListA1, `"attempts":[`+stockWireA1Create+`]`, `"attempts":[`+stockWireA1Create+`,`+later+`]`, 1)
	if _, err := stockGeneratedDecode([]byte(damaged), 0, "success"); err == nil {
		t.Fatal("a later unsafe attempt was ignored")
	}
}

// full_only: false
func TestStockRetirementWireRequiresExactAcknowledgement(t *testing.T) {
	accepted, err := stockGeneratedDecode([]byte(stockWireListA1), 0, "success")
	if err != nil || len(accepted.Duties) != 1 {
		t.Fatal("fixed accepted Duty was refused", err)
	}
	for _, condition := range []string{"exact", "missing-global-warning", "null-global-warning", "false-global-warning", "missing-effect-warning", "false-effect-warning", "missing-ack", "null-ack", "zero-ack", "two-acks", "missing-confirmed", "null-confirmed", "confirmed", "missing-unknown", "null-unknown", "unknown", "wrong-duty", "current-duty", "current-hazard", "missing-duty", "missing-hazard", "missing-domain", "null-domain", "wrong-domain", "missing-operation", "null-operation", "wrong-operation", "wrong-effect-operation", "reused-original-operation", "wrong-lineage", "wrong-attempt", "original-attempt", "wrong-accepted-duty", "remaining-current-duty", "remaining-current-hazard", "remaining-related-duty", "remaining-related-hazard", "missing-current-duty-vector", "null-current-duty-vector", "missing-related-duty-vector", "null-related-duty-vector", "wrong-route", "wrong-resource", "wrong-target-origin", "wrong-delete-contract", "wrong-create-contract", "swapped-contracts", "equal-contracts", "confirmed-ceiling", "missing-effect-epoch", "null-effect-epoch", "missing-target-epoch", "null-target-epoch", "extra-effect"} {
		t.Run(condition, func(t *testing.T) {
			body := stockWireRetirementACK
			duty := accepted.Duties[0]
			switch condition {
			case "missing-global-warning":
				body = strings.Replace(body, `,"invalidation_not_confirmed":true`, "", 1)
			case "null-global-warning":
				body = strings.Replace(body, `"invalidation_not_confirmed":true`, `"invalidation_not_confirmed":null`, 1)
			case "false-global-warning":
				body = strings.Replace(body, `"invalidation_not_confirmed":true`, `"invalidation_not_confirmed":false`, 1)
			case "missing-effect-warning":
				body = strings.Replace(body, stockWireRetirementEffect, strings.Replace(stockWireRetirementEffect, `,"invalidation_not_confirmed":true`, "", 1), 1)
			case "false-effect-warning":
				body = strings.Replace(body, stockWireRetirementEffect, strings.Replace(stockWireRetirementEffect, `"invalidation_not_confirmed":true`, `"invalidation_not_confirmed":false`, 1), 1)
			case "missing-ack":
				body = strings.Replace(body, `"deletion_acknowledged_count":1,`, "", 1)
			case "null-ack":
				body = strings.Replace(body, `"deletion_acknowledged_count":1`, `"deletion_acknowledged_count":null`, 1)
			case "zero-ack":
				body = strings.Replace(body, `"deletion_acknowledged_count":1`, `"deletion_acknowledged_count":0`, 1)
			case "two-acks":
				body = strings.Replace(body, `"deletion_acknowledged_count":1`, `"deletion_acknowledged_count":2`, 1)
			case "missing-confirmed":
				body = strings.Replace(body, `"invalidation_confirmed_count":0,`, "", 1)
			case "null-confirmed":
				body = strings.Replace(body, `"invalidation_confirmed_count":0`, `"invalidation_confirmed_count":null`, 1)
			case "confirmed":
				body = strings.Replace(body, `"invalidation_confirmed_count":0`, `"invalidation_confirmed_count":1`, 1)
			case "missing-unknown":
				body = strings.Replace(body, `,"unknown_count":0`, "", 1)
			case "null-unknown":
				body = strings.Replace(body, `"unknown_count":0`, `"unknown_count":null`, 1)
			case "unknown":
				body = strings.Replace(body, `"unknown_count":0`, `"unknown_count":1`, 1)
			case "wrong-duty":
				body = strings.Replace(body, `"duty_id":null`, `"duty_id":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
			case "current-duty":
				body = strings.Replace(body, `"duty_id":null`, `"duty_id":"`+stockWireDuty+`"`, 1)
			case "current-hazard":
				body = strings.Replace(body, `"hazard_id":null`, `"hazard_id":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
			case "missing-duty":
				body = strings.Replace(body, `"duty_id":null,`, "", 1)
			case "missing-hazard":
				body = strings.Replace(body, `"hazard_id":null,`, "", 1)
			case "missing-domain":
				body = strings.Replace(body, `"domain_id":"2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c",`, "", 1)
			case "null-domain":
				body = strings.Replace(body, `"domain_id":"2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c"`, `"domain_id":null`, 1)
			case "wrong-domain":
				body = strings.Replace(body, `"domain_id":"2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c"`, `"domain_id":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
			case "missing-operation":
				body = strings.Replace(body, `"operation_id":"1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e",`, "", 1)
			case "null-operation":
				body = strings.Replace(body, `"operation_id":"1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e"`, `"operation_id":null`, 1)
			case "wrong-operation":
				body = strings.Replace(body, `"operation_id":"1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e"`, `"operation_id":"2525252525252525252525252525252525252525252525252525252525252525"`, 1)
			case "wrong-effect-operation":
				body = strings.Replace(body, stockWireRetirementEffect, strings.Replace(stockWireRetirementEffect, `"operation_id":"1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e"`, `"operation_id":"`+stockWireA0Operation+`"`, 1), 1)
			case "reused-original-operation":
				body = strings.NewReplacer("1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e", stockWireA0Operation, "73076158b05a2630ddaa3e4b1dc8c89392e30816d50115f46b0641a4cdb0c40e", "4ca07d998e222bd3f10f6693785736589878e0312e638525a7d0f0178cb04b0f", "552d57e193a7fc4bf0ced066753e9f18ff8a2ee447981c35717cfe8ab556ec62", "37b248651bf8fc8e4f9bbed0a86e32000e4c8ab87cc368121fb8e728919f301d").Replace(body)
			case "wrong-lineage":
				body = strings.Replace(body, "73076158b05a2630ddaa3e4b1dc8c89392e30816d50115f46b0641a4cdb0c40e", stockWireA0Generation, 1)
			case "wrong-attempt":
				body = strings.Replace(body, "552d57e193a7fc4bf0ced066753e9f18ff8a2ee447981c35717cfe8ab556ec62", stockWireA1Attempt, 1)
			case "original-attempt":
				body = strings.Replace(body, "552d57e193a7fc4bf0ced066753e9f18ff8a2ee447981c35717cfe8ab556ec62", stockWireA0Attempt, 1)
			case "wrong-accepted-duty":
				duty.Facts.Duty = stockWireA1Generation
			case "remaining-current-duty":
				body = strings.Replace(body, `"current_domain_duty_ids":[]`, `"current_domain_duty_ids":["`+stockWireDuty+`"]`, 1)
			case "remaining-current-hazard":
				body = strings.Replace(body, `"current_domain_hazard_ids":[]`, `"current_domain_hazard_ids":["`+stockWireDuty+`"]`, 1)
			case "remaining-related-duty":
				body = strings.Replace(body, `"related_duty_ids":[]`, `"related_duty_ids":["`+stockWireDuty+`"]`, 1)
			case "remaining-related-hazard":
				body = strings.Replace(body, `"related_hazard_ids":[]`, `"related_hazard_ids":["`+stockWireDuty+`"]`, 1)
			case "missing-current-duty-vector":
				body = strings.Replace(body, `"current_domain_duty_ids":[],`, "", 1)
			case "null-current-duty-vector":
				body = strings.Replace(body, `"current_domain_duty_ids":[]`, `"current_domain_duty_ids":null`, 1)
			case "missing-related-duty-vector":
				body = strings.Replace(body, `"related_duty_ids":[],`, "", 1)
			case "null-related-duty-vector":
				body = strings.Replace(body, `"related_duty_ids":[]`, `"related_duty_ids":null`, 1)
			case "wrong-route":
				body = strings.Replace(body, stockWireARoute, stockWireBRoute, 1)
			case "wrong-resource":
				body = strings.Replace(body, stockWireA0Resource, stockWireA1Resource, 1)
			case "wrong-target-origin":
				body = strings.Replace(body, stockWireA0Attempt, stockWireA1Attempt, 1)
			case "wrong-delete-contract":
				body = strings.Replace(body, stockWireRetireResultContract, stockWireA1Generation, 1)
			case "wrong-create-contract":
				body = strings.Replace(body, stockWireCreateResultContract, stockWireA1Generation, 1)
			case "swapped-contracts":
				body = strings.NewReplacer(stockWireCreateResultContract, stockWireRetireResultContract, stockWireRetireResultContract, stockWireCreateResultContract).Replace(body)
			case "equal-contracts":
				body = strings.Replace(body, stockWireRetireResultContract, stockWireCreateResultContract, 1)
			case "confirmed-ceiling":
				body = strings.Replace(body, `"evidence_ceiling":"deletion-acknowledged"`, `"evidence_ceiling":"invalidation-confirmed"`, 1)
			case "missing-effect-epoch":
				body = strings.Replace(body, `"epoch":0,`, "", 1)
			case "null-effect-epoch":
				body = strings.Replace(body, `"epoch":0`, `"epoch":null`, 1)
			case "missing-target-epoch":
				body = strings.Replace(body, `"target":{"name":"generated","entry_incarnation_id":"`+stockWireEntry+`","epoch":0,`, `"target":{"name":"generated","entry_incarnation_id":"`+stockWireEntry+`",`, 1)
			case "null-target-epoch":
				body = strings.Replace(body, `"target":{"name":"generated","entry_incarnation_id":"`+stockWireEntry+`","epoch":0,`, `"target":{"name":"generated","entry_incarnation_id":"`+stockWireEntry+`","epoch":null,`, 1)
			case "extra-effect":
				body = strings.Replace(body, `"effects":[`+stockWireRetirementEffect+`]`, `"effects":[`+stockWireRetirementEffect+`,`+stockWireRetirementEffect+`]`, 1)
			}
			result, err := stockGeneratedDecode([]byte(body), 0, "success")
			matches := err == nil && stockRetirementMatches(result, duty)
			if matches != (condition == "exact") {
				t.Fatal("retirement wire lost its exact Duty, warning or acknowledgement ceiling")
			}
		})
	}
}

const stockWireReleasedCreateAttempt = `{"facts":{"operation_id":"1111111111111111111111111111111111111111111111111111111111111111","lineage_id":"1717171717171717171717171717171717171717171717171717171717171717","attempt_id":"1212121212121212121212121212121212121212121212121212121212121212","predecessor_attempt_id":null,"action":"create","name":"generated","entry_incarnation_id":"0101010101010101010101010101010101010101010101010101010101010101","epoch":1,"planned_value_slot_id":"1818181818181818181818181818181818181818181818181818181818181818","planned_resource_incarnation_id":"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f","resource_digest":null,"generation_id":null,"duty_id":null,"hazard_id":null,"transmission_id":"1919191919191919191919191919191919191919191919191919191919191919","result_id":"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a","descriptor_id":"0909090909090909090909090909090909090909090909090909090909090909","config_contract_id":"0707070707070707070707070707070707070707070707070707070707070707","resource_contract_id":"0808080808080808080808080808080808080808080808080808080808080808","executor_id":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a","credential_route_id":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b","result_contract_id":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c","lifecycle_mode":"managed","state":"succeeded","stage":5,"retry_consumed":false,"completion_class":"deletion-acknowledged","reason":0,"evidence_ceiling":"canonical","summary_class":0,"warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":false}},"target":null,"progress":[]}`
const stockWireReleasedDeleteAttempt = `{"facts":{"operation_id":"1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e","lineage_id":"73076158b05a2630ddaa3e4b1dc8c89392e30816d50115f46b0641a4cdb0c40e","attempt_id":"552d57e193a7fc4bf0ced066753e9f18ff8a2ee447981c35717cfe8ab556ec62","predecessor_attempt_id":null,"action":"delete","name":"generated","entry_incarnation_id":"0101010101010101010101010101010101010101010101010101010101010101","epoch":0,"planned_value_slot_id":"2121212121212121212121212121212121212121212121212121212121212121","planned_resource_incarnation_id":"0303030303030303030303030303030303030303030303030303030303030303","resource_digest":"0404040404040404040404040404040404040404040404040404040404040404","generation_id":null,"duty_id":null,"hazard_id":null,"transmission_id":"2222222222222222222222222222222222222222222222222222222222222222","result_id":"2323232323232323232323232323232323232323232323232323232323232323","descriptor_id":"0909090909090909090909090909090909090909090909090909090909090909","config_contract_id":"0707070707070707070707070707070707070707070707070707070707070707","resource_contract_id":"0808080808080808080808080808080808080808080808080808080808080808","executor_id":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a","credential_route_id":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b","result_contract_id":"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b","lifecycle_mode":"managed","state":"succeeded","stage":5,"retry_consumed":false,"completion_class":"deletion-acknowledged","reason":0,"evidence_ceiling":"deletion-acknowledged","summary_class":0,"warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":true}},"target":null,"progress":[]}`

const stockWirePendingCreateRelease = `{"inbox_id":"f305eef01d17990dfa83249bb9e300006c05c771f7825909fcccb399af61b858","original_result_id":"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a","selected_handoff_digest":"2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d","handoff_revision_id":"2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e","state":"pending","object_length":1505}`
const stockWirePendingDeleteRelease = `{"inbox_id":"cbd54351fe58ad3b5283bfb0694e8427440e810d3c4d93441d694f92c7c78c05","original_result_id":"2323232323232323232323232323232323232323232323232323232323232323","selected_handoff_digest":"2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d","handoff_revision_id":"2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e","state":"pending","object_length":1505}`

// full_only: false
func TestStockGeneratedListRetainsKnownPendingCreateAndDeleteReleases(t *testing.T) {
	for _, action := range []string{"create", "delete", "both"} {
		t.Run(action, func(t *testing.T) {
			attempts, releases := stockWireReleasedCreateAttempt, stockWirePendingCreateRelease
			if action == "delete" {
				attempts, releases = stockWireReleasedDeleteAttempt, stockWirePendingDeleteRelease
			}
			if action == "both" {
				attempts += "," + stockWireReleasedDeleteAttempt
				releases = stockWirePendingDeleteRelease + "," + stockWirePendingCreateRelease
			}
			body := stockWirePendingList(attempts, releases)
			got, err := stockGeneratedDecode([]byte(body), 0, "success")
			if err != nil {
				t.Fatal("known successful terminal Attempt with pending inbox release was rejected", err)
			}
			create := stockGeneratedRelease{Inbox: "f305eef01d17990dfa83249bb9e300006c05c771f7825909fcccb399af61b858", Result: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a", HandoffDigest: "2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d", HandoffRevision: "2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e", State: "pending", ObjectLength: 1505}
			deleted := create
			deleted.Inbox = "cbd54351fe58ad3b5283bfb0694e8427440e810d3c4d93441d694f92c7c78c05"
			deleted.Result = "2323232323232323232323232323232323232323232323232323232323232323"
			want := []stockGeneratedRelease{create}
			if action == "delete" {
				want = []stockGeneratedRelease{deleted}
			}
			if action == "both" {
				want = []stockGeneratedRelease{deleted, create}
			}
			if !reflect.DeepEqual(got.PendingReleases, want) {
				t.Fatal("pending release fields were lost or changed")
			}
		})
	}
}

func stockWirePendingList(attempts, releases string) string {
	return strings.NewReplacer(`"state_result":"success",`, `"state_result":"success","domain_id":"2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c",`, `"attempts":[`+stockWireA1Create+`]`, `"attempts":[`+attempts+`]`, `"pending_releases":[]`, `"pending_releases":[`+releases+`]`).Replace(stockWireListA1)
}

// full_only: false
func TestStockGeneratedListRejectsUnboundPendingReleases(t *testing.T) {
	for _, action := range []string{"create", "delete"} {
		t.Run(action, func(t *testing.T) {
			originalAttempt, originalRelease := stockWireReleasedCreateAttempt, stockWirePendingCreateRelease
			if action == "delete" {
				originalAttempt, originalRelease = stockWireReleasedDeleteAttempt, stockWirePendingDeleteRelease
			}
			for _, condition := range []string{"maximum-length", "zero-length", "excess-length", "negative-length", "fractional-length", "missing-length", "null-length", "unknown", "unobserved", "missing-state", "null-state", "duplicate-release", "unmatched-extra-release", "duplicate-attempt", "missing-attempt", "wrong-domain", "missing-domain", "wrong-operation", "wrong-attempt", "missing-support", "missing-transmission", "missing-slot", "missing-generation", "current-generation", "missing-progress", "nonempty-progress", "wrong-resource-digest", "missing-target", "wrong-target", "failed", "unknown-effect", "nonterminal", "missing-stage", "retry-used", "missing-retry", "live-duty", "missing-duty", "live-hazard", "missing-hazard", "wrong-action", "wrong-evidence", "possible-live", "late-effect"} {
				t.Run(condition, func(t *testing.T) {
					attempt, release := originalAttempt, originalRelease
					switch condition {
					case "maximum-length":
						release = strings.Replace(release, `"object_length":1505`, `"object_length":`+strconv.Itoa(int(contract.GeneratedResultRecordMaxLength)), 1)
					case "zero-length":
						release = strings.Replace(release, `"object_length":1505`, `"object_length":0`, 1)
					case "excess-length":
						release = strings.Replace(release, `"object_length":1505`, `"object_length":`+strconv.Itoa(int(contract.GeneratedResultRecordMaxLength)+1), 1)
					case "negative-length":
						release = strings.Replace(release, `"object_length":1505`, `"object_length":-1`, 1)
					case "fractional-length":
						release = strings.Replace(release, `"object_length":1505`, `"object_length":1.5`, 1)
					case "missing-length":
						release = strings.Replace(release, `,"object_length":1505`, "", 1)
					case "null-length":
						release = strings.Replace(release, `"object_length":1505`, `"object_length":null`, 1)
					case "unknown", "unobserved":
						release = strings.Replace(release, `"state":"pending"`, `"state":"`+condition+`"`, 1)
					case "missing-state":
						release = strings.Replace(release, `"state":"pending",`, "", 1)
					case "null-state":
						release = strings.Replace(release, `"state":"pending"`, `"state":null`, 1)
					case "duplicate-release":
						release += "," + release
					case "unmatched-extra-release":
						if action == "create" {
							release = stockWirePendingDeleteRelease + "," + release
						} else {
							release += "," + stockWirePendingCreateRelease
						}
					case "duplicate-attempt":
						attempt += "," + attempt
					case "missing-attempt":
						attempt = ""
					case "wrong-operation":
						attempt = strings.Replace(attempt, `"operation_id":"`, `"operation_id":"f`, 1)
					case "wrong-attempt":
						attempt = strings.Replace(attempt, `"attempt_id":"`, `"attempt_id":"f`, 1)
					case "missing-support":
						attempt = strings.ReplaceAll(attempt, stockWireAExecutor, "")
					case "missing-transmission":
						attempt = strings.Replace(attempt, `"transmission_id":"`, `"transmission_id":"f`, 1)
					case "missing-slot":
						attempt = strings.Replace(attempt, `"planned_value_slot_id":"`, `"planned_value_slot_id":"f`, 1)
					case "missing-generation":
						attempt = strings.Replace(attempt, `"generation_id":null,`, "", 1)
					case "current-generation":
						attempt = strings.Replace(attempt, `"generation_id":null`, `"generation_id":"`+stockWireA1Generation+`"`, 1)
					case "missing-progress":
						attempt = strings.Replace(attempt, `,"progress":[]`, "", 1)
					case "nonempty-progress":
						attempt = strings.Replace(attempt, `"progress":[]`, `"progress":[{}]`, 1)
					case "wrong-resource-digest":
						if action == "create" {
							attempt = strings.Replace(attempt, `"resource_digest":null`, `"resource_digest":"`+stockWireA1Digest+`"`, 1)
						} else {
							attempt = strings.Replace(attempt, `"resource_digest":"`+stockWireA0Digest+`"`, `"resource_digest":null`, 1)
						}
					case "missing-target":
						var row map[string]json.RawMessage
						if err := json.Unmarshal([]byte(attempt), &row); err != nil {
							t.Fatal(err)
						}
						delete(row, "target")
						raw, err := json.Marshal(row)
						if err != nil {
							t.Fatal(err)
						}
						attempt = string(raw)
					case "wrong-target":
						attempt = strings.Replace(attempt, `"target":null`, `"target":{}`, 1)
					case "failed", "unknown-effect":
						state := "failed"
						if condition == "unknown-effect" {
							state = "unknown"
						}
						attempt = strings.Replace(attempt, `"state":"succeeded"`, `"state":"`+state+`"`, 1)
					case "nonterminal":
						attempt = strings.Replace(attempt, `"stage":5`, `"stage":4`, 1)
					case "missing-stage":
						attempt = strings.Replace(attempt, `"stage":5,`, "", 1)
					case "retry-used":
						attempt = strings.Replace(attempt, `"retry_consumed":false`, `"retry_consumed":true`, 1)
					case "missing-retry":
						attempt = strings.Replace(attempt, `"retry_consumed":false,`, "", 1)
					case "live-duty":
						attempt = strings.Replace(attempt, `"duty_id":null`, `"duty_id":"`+stockWireDuty+`"`, 1)
					case "missing-duty":
						attempt = strings.Replace(attempt, `"duty_id":null,`, "", 1)
					case "live-hazard":
						attempt = strings.Replace(attempt, `"hazard_id":null`, `"hazard_id":"`+stockWireDuty+`"`, 1)
					case "missing-hazard":
						attempt = strings.Replace(attempt, `"hazard_id":null,`, "", 1)
					case "wrong-action":
						attempt = strings.Replace(attempt, `"action":"`+action+`"`, `"action":"other"`, 1)
					case "wrong-evidence":
						attempt = strings.Replace(attempt, `"evidence_ceiling":"`, `"evidence_ceiling":"wrong-`, 1)
					case "possible-live":
						attempt = strings.Replace(attempt, `"possible_live_residue":false`, `"possible_live_residue":true`, 1)
					case "late-effect":
						attempt = strings.Replace(attempt, `"late_effect":false`, `"late_effect":true`, 1)
					}
					body := stockWirePendingList(attempt, release)
					if condition == "wrong-domain" {
						body = strings.Replace(body, strings.Repeat("2c", 32), stockWireDuty, 1)
					}
					if condition == "missing-domain" {
						body = strings.Replace(body, `"domain_id":"`+strings.Repeat("2c", 32)+`",`, "", 1)
					}
					_, err := stockGeneratedDecode([]byte(body), 0, "success")
					if (err == nil) != (condition == "maximum-length") {
						t.Fatal("pending release lost its exact successful terminal Attempt or admitted malformed ownership")
					}
				})
			}
			for _, field := range []string{"inbox_id", "original_result_id", "selected_handoff_digest", "handoff_revision_id"} {
				damages := []struct {
					name  string
					value json.RawMessage
				}{{"missing", nil}, {"null", json.RawMessage("null")}, {"malformed", json.RawMessage(`"invalid"`)}, {"zero", json.RawMessage(`"` + strings.Repeat("0", 64) + `"`)}}
				if field == "inbox_id" || field == "original_result_id" {
					damages = append(damages, struct {
						name  string
						value json.RawMessage
					}{"unmatched", json.RawMessage(`"` + stockWireDuty + `"`)})
				}
				for _, damage := range damages {
					t.Run(field+"/"+damage.name, func(t *testing.T) {
						var fields map[string]json.RawMessage
						if err := json.Unmarshal([]byte(originalRelease), &fields); err != nil {
							t.Fatal(err)
						}
						if damage.value == nil {
							delete(fields, field)
						} else {
							fields[field] = damage.value
						}
						release, err := json.Marshal(fields)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := stockGeneratedDecode([]byte(stockWirePendingList(originalAttempt, string(release))), 0, "success"); err == nil {
							t.Fatal("incomplete or unmatched pending release identity was accepted")
						}
					})
				}
			}
		})
	}
}
