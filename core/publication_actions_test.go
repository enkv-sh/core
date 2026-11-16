package core

import (
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationOpenCapabilitiesDetermineExactActionOrder(t *testing.T) {
	for _, tc := range []struct {
		name                                          string
		caps                                          contract.OutputActionCapabilities
		owned, valueEqual, policyEqual, force, policy bool
		want                                          []uint8
		refuse                                        bool
	}{
		{"first_value_cannot_precede_separate_policy", (contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityUpdatePolicy), false, false, false, false, true, nil, true},
		{"new_value_without_policy", contract.OutputCapabilityCreateWithValue, false, false, false, false, false, []uint8{2}, false},
		{"new_value_applies_policy", contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityCreateSetsPolicy, false, false, false, false, true, []uint8{2}, false},
		{"prefer_empty_when_value_create_cannot_apply_policy", (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy), false, false, false, false, true, []uint8{1, 4, 3}, false},
		{"prefer_empty_then_atomic_first_write", (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue) | contract.OutputCapabilityWriteSetsPolicy, false, false, false, false, true, []uint8{1, 3}, false},
		{"first_empty_create_applies_policy", (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue) | contract.OutputCapabilityCreateSetsPolicy, false, false, false, false, true, []uint8{1, 3}, false},
		{"first_policy_needs_empty_create_capability", (contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy) | contract.OutputCapabilityWriteSetsPolicy, false, false, false, false, true, nil, true},
		{"first_policy_needs_first_write_capability", (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityUpdatePolicy), false, false, false, false, true, nil, true},
		{"new_empty_then_policy_then_write", (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy), false, false, false, false, true, []uint8{1, 4, 3}, false},
		{"new_empty_then_write_applies_policy", (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue) | contract.OutputCapabilityWriteSetsPolicy, false, false, false, false, true, []uint8{1, 3}, false},
		{"owned_custom_plugin_without_creation", contract.OutputCapabilityWriteValue, true, false, true, false, false, []uint8{3}, false},
		{"owned_write_applies_policy", contract.OutputCapabilityWriteValue | contract.OutputCapabilityWriteSetsPolicy, true, false, false, false, true, []uint8{3}, false},
		{"policy_only_without_value_action", contract.OutputCapabilityUpdatePolicy, true, true, false, false, true, []uint8{4}, false},
		{"equal_no_actions", contract.OutputCapabilityDeleteOwned, true, true, true, false, false, nil, false},
		{"missing_policy_action", contract.OutputCapabilityWriteValue, true, true, false, false, true, nil, true},
		{"explicit_republish_requires_write", contract.OutputCapabilityUpdatePolicy, true, true, true, true, true, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := publicationActionOrder(tc.caps, tc.owned, tc.valueEqual, tc.policyEqual, tc.force, tc.policy)
			if (err != nil) != tc.refuse || !tc.refuse && !slices.Equal(got, tc.want) {
				t.Fatalf("actions=%v error=%v", got, err)
			}
		})
	}
}

// full_only: false
func TestPublicationCurrentRouteDoesNotChangeAcknowledgedActionChoice(t *testing.T) {
	p := publicationTargetPlan{
		target:   contract.OutputTarget{Capabilities: contract.OutputCapabilityWriteValue},
		retained: contract.PublicationCoordinate{DeletionCredentialRouteContractID: "original-route/v1"},
		facts: publicationActionFacts{ProtocolID: publicationRelationID(1), DescriptorID: publicationRelationID(2), ConfigContractDigest: publicationRelationID(3),
			ArtifactContractID: publicationRelationID(4), ExecutorID: publicationRelationID(5), CredentialRouteID: publicationRelationID(6), CredentialRouteContractID: "current-route/v2"},
	}
	actions, err := publicationActionOrder(p.target.Capabilities, true, true, true, false, false)
	if err != nil || len(actions) != 0 {
		t.Fatal("current build/route introduced a value write", actions, err)
	}
	facts := publicationActionCheckFacts{ProtocolID: p.facts.ProtocolID, DescriptorID: p.facts.DescriptorID, ConfigContractDigest: p.facts.ConfigContractDigest,
		ArtifactContractID: p.facts.ArtifactContractID, ExecutorID: p.facts.ExecutorID, CredentialRouteID: p.facts.CredentialRouteID, CredentialRouteContractID: p.facts.CredentialRouteContractID}
	if !publicationFactsMatch(p, contract.PublicationUpdatePolicy, facts) {
		t.Fatal("current route was compared with retained discovery facts")
	}
	facts.CredentialRouteContractID = p.retained.DeletionCredentialRouteContractID
	if publicationFactsMatch(p, contract.PublicationUpdatePolicy, facts) {
		t.Fatal("current command did not bind the selected current route")
	}
	facts.CredentialRouteContractID = p.facts.CredentialRouteContractID
	facts.CredentialRouteID = publicationRelationID(99)
	if publicationFactsMatch(p, contract.PublicationUpdatePolicy, facts) {
		t.Fatal("current command accepted different measured route bytes")
	}
}

// full_only: false
func TestPublicationScheduledValueBoundsUseEncodedBytes(t *testing.T) {
	target := contract.OutputTarget{PayloadEncoding: contract.OutputEncodingBase64,
		CreateValueBounds: contract.OutputPayloadBounds{Minimum: 4, Maximum: 4},
		WriteValueBounds:  contract.OutputPayloadBounds{Minimum: 8, Maximum: 8}}
	for _, tc := range []struct {
		name      string
		actions   []uint8
		raw, want uint32
		refuse    bool
	}{
		{"create_exact", []uint8{2}, 1, 4, false},
		{"write_exact", []uint8{3}, 4, 8, false},
		{"write_limit_differs_from_create", []uint8{3}, 1, 0, true},
		{"all_scheduled_values_checked", []uint8{2, 3}, 1, 0, true},
		{"policy_ignores_unscheduled_value", []uint8{4}, 65536, 0, false},
		{"noop_ignores_unscheduled_value", nil, 65536, 0, false},
		{"base64_family_limit", []uint8{3}, 49153, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := publicationScheduledPayloadLength(target, tc.actions, tc.raw)
			if (err != nil) != tc.refuse || !tc.refuse && got != tc.want {
				t.Fatalf("encoded length=%d error=%v", got, err)
			}
		})
	}
	target.PayloadEncoding = contract.OutputEncodingRaw
	target.CreateValueBounds = contract.OutputPayloadBounds{}
	if got, err := publicationScheduledPayloadLength(target, []uint8{2}, 0); err != nil || got != 0 {
		t.Fatal("empty-only value refused", got, err)
	}
	if _, err := publicationScheduledPayloadLength(target, []uint8{2}, 1); err == nil {
		t.Fatal("empty-only interval admitted a byte")
	}
}
