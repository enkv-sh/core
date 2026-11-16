package main

import (
	"context"
	"enkv.sh/sdk/output"
	"strings"
	"testing"

	protocol "enkv.sh/sdk/protocols/output"
)

// full_only: false
func TestContractChildExactActionPayloadPolicyAndInstance(t *testing.T) {
	policy := protocol.Policy{ContractID: "test-policy", Data: []byte("1,9")}
	command := protocol.Command{Schema: 1, Action: protocol.ActionCreateWithValue, Target: protocol.Target{CanonicalTarget: "plain-target", ConsumerLocator: "plain-target", PayloadEncoding: protocol.EncodingRaw},
		DomainID: protocol.ID{10}, OperationID: protocol.ID{11}, AttemptID: protocol.ID{1}, CoordinateID: protocol.ID{12},
		ProjectionCommitment: protocol.ID{13}, DispatchContextDigest: protocol.ID{14}, ResponseContractDigest: protocol.ID{15}}
	result, err := executeForTest(context.Background(), command, policy, []byte("private data"), []byte("private credential"))
	want := protocol.Result{Schema: 1, DomainID: protocol.ID{10}, OperationID: protocol.ID{11}, AttemptID: protocol.ID{1},
		CoordinateID: protocol.ID{12}, ProjectionCommitment: protocol.ID{13}, DispatchContextDigest: protocol.ID{14},
		ResponseContractDigest: protocol.ID{15}, Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassAcknowledged,
		NormalizedStatus: 201, SafeResourceID: testInstance(command.Target.CanonicalTarget, command.AttemptID), ConsumerLocator: command.Target.ConsumerLocator}
	if err != nil || result != want {
		t.Fatal("qualified create evidence", result, err)
	}
	birth, instance := command.AttemptID, result.SafeResourceID
	for _, action := range []protocol.Action{protocol.ActionWriteValue, protocol.ActionUpdatePolicy, protocol.ActionDeleteOwned} {
		command.Action, command.AttemptID, command.OwnedBirthAttemptID, command.OwnedInstance = action, protocol.ID{byte(action)}, birth, instance
		payload := []byte(nil)
		actionPolicy := policy
		if action == protocol.ActionWriteValue {
			payload = []byte("updated plain data")
		}
		if action == protocol.ActionUpdatePolicy {
			actionPolicy.Data = []byte("1")
		}
		if action == protocol.ActionDeleteOwned {
			actionPolicy = protocol.Policy{}
		}
		result, err := executeForTest(context.Background(), command, actionPolicy, payload, []byte("private credential"))
		want.AttemptID, want.NormalizedStatus, want.SafeResourceID, want.ConsumerLocator = protocol.ID{byte(action)}, 204, instance, ""
		if err != nil || result != want {
			t.Fatal("owned action evidence", action, result, err)
		}
		command.OwnedInstance = strings.Replace(instance, "plain-target", "other-target", 1)
		if _, err := executeForTest(context.Background(), command, actionPolicy, payload, []byte("private credential")); err == nil {
			t.Fatal("wrong owned instance admitted", action)
		}
	}
	command.Action, command.OwnedInstance = protocol.ActionCreateWithValue, ""
	if _, err := executeForTest(context.Background(), command, policy, []byte("private data plus another entry"), []byte("private credential")); err == nil {
		t.Fatal("incomplete payload comparison")
	}
	policy.Data = []byte("1,7")
	if _, err := executeForTest(context.Background(), command, policy, []byte("private data"), []byte("private credential")); err == nil {
		t.Fatal("incomplete policy comparison")
	}
}

// full_only: false
func TestContractChildFixedFaultResults(t *testing.T) {
	policy := protocol.Policy{ContractID: "test-policy", Data: []byte("1,9")}
	for _, condition := range []string{"unknown", "unqualified"} {
		t.Run(condition, func(t *testing.T) {
			command := protocol.Command{Schema: 1, Action: protocol.ActionCreateWithValue, Target: protocol.Target{CanonicalTarget: "plain-target-" + condition + "-0", ConsumerLocator: "plain-target-" + condition + "-0", PayloadEncoding: protocol.EncodingRaw},
				DomainID: protocol.ID{10}, OperationID: protocol.ID{11}, AttemptID: protocol.ID{1}, CoordinateID: protocol.ID{12},
				ProjectionCommitment: protocol.ID{13}, DispatchContextDigest: protocol.ID{14}, ResponseContractDigest: protocol.ID{15}}
			payload := []byte("private data")
			got, err := executeForTest(t.Context(), command, policy, payload, []byte("private credential"))
			if err != nil {
				t.Fatal(err)
			}
			want := protocol.Result{Schema: 1, DomainID: protocol.ID{10}, OperationID: protocol.ID{11}, AttemptID: protocol.ID{1},
				CoordinateID: protocol.ID{12}, ProjectionCommitment: protocol.ID{13}, DispatchContextDigest: protocol.ID{14},
				ResponseContractDigest: protocol.ID{15}, Entry: protocol.EntryMayHaveEntered, Class: protocol.ClassUnproved}
			if condition == "unqualified" {
				want.Class, want.NormalizedStatus, want.ConsumerLocator = protocol.ClassAcknowledged, 201, command.Target.ConsumerLocator
			}
			if got != want {
				t.Fatalf("fault=%#v want=%#v", got, want)
			}
			if _, err := executeForTest(t.Context(), command, policy, append(payload, '!'), []byte("private credential")); err == nil {
				t.Fatal("fault bypassed complete payload check")
			}
		})
	}
}

func executeForTest(ctx context.Context, c protocol.Command, policy protocol.Policy, payload, credential []byte) (protocol.Result, error) {
	facts := output.Preparation{Action: c.Action, Target: c.Target, AttemptID: c.AttemptID, OwnedInstance: c.OwnedInstance, ConditionalToken: c.ConditionalToken, PayloadLengthMode: c.PayloadLengthMode, PayloadLength: c.PayloadLength}
	outcome, err := (testImplementation{}).Execute(ctx, facts, policy, payload, credential)
	result := c.NewResult()
	result.Entry, result.Class, result.NormalizedStatus, result.SafeRequestID, result.SafeResourceID = outcome.Entry, outcome.Class, outcome.NormalizedStatus, outcome.SafeRequestID, outcome.SafeResourceID
	if outcome.Class == protocol.ClassAcknowledged && (c.Action == protocol.ActionCreateEmpty || c.Action == protocol.ActionCreateWithValue) {
		result.ConsumerLocator = c.Target.ConsumerLocator
		if c.Target.LocatorRequiresCreation {
			result.ConsumerLocator = outcome.AssignedLocator
		}
	}
	return result, err
}
