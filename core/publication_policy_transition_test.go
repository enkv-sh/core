package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func publicationPolicyFixture(t *testing.T) (contract.PublicationCoordinate, contract.PublicationMarker, selectedPublication, []contract.ID) {
	t.Helper()
	domain, coordinate, birth, _ := publicationRelationFixture(t)
	birth.State, birth.Evidence.Class, birth.Evidence.NormalizedStatus = contract.PublicationAcknowledged, contract.PublicationRequestAcknowledged, 201
	birth.Evidence.SafeResourceID, birth.Evidence.ConsumerLocator = "owned-instance", "locator"
	coordinate.OwnerState, coordinate.LatestUnresolvedAttemptID, coordinate.OwnedBirthAttemptID = contract.PublicationOwnerQualified, contract.ID{}, birth.AttemptID
	var err error
	coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(domain, coordinate.CoordinateID, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.LastAdmissionOrdinal = 3
	coordinate.LastValueAckAttemptID, coordinate.LastPolicyAckAttemptID = publicationRelationID(80), publicationRelationID(80)
	coordinate.LastValueAckIncarnationID, coordinate.LastPolicyAckIncarnationID = birth.PublicationIncarnationID, birth.PublicationIncarnationID
	coordinate.LastValueAckOrdinal, coordinate.LastPolicyAckOrdinal = 2, 2
	coordinate.LastValueDigest, coordinate.LastPolicyDigest = publicationRelationID(81), publicationRelationID(82)
	selected, err := publicationFixtureRowsRelation(domain, publicationRelationRows(t, coordinate, birth))
	if err != nil {
		t.Fatal(err)
	}
	return coordinate, birth, selected, []contract.ID{birth.PublicationIncarnationID}
}

// full_only: false
func TestPublicationPolicyHistoryUsesExactOwnerProofOrAbsence(t *testing.T) {
	coordinate, birth, selected, order := publicationPolicyFixture(t)
	previous, marker, err := publicationPreviousPolicy(coordinate, &birth, selected, order)
	if err != nil || previous != publicationRelationID(82) || marker != nil {
		t.Fatal("equal signed tuples lost their current owner", previous, marker, err)
	}
	for _, damage := range []struct {
		name   string
		change func(*contract.PublicationCoordinate)
	}{
		{"attempt", func(c *contract.PublicationCoordinate) { c.LastPolicyAckAttemptID = publicationRelationID(83) }},
		{"incarnation", func(c *contract.PublicationCoordinate) { c.LastPolicyAckIncarnationID = publicationRelationID(84) }},
		{"ordinal", func(c *contract.PublicationCoordinate) { c.LastPolicyAckOrdinal = 3 }},
	} {
		t.Run("absent-auxiliary/"+damage.name, func(t *testing.T) {
			c := coordinate
			damage.change(&c)
			got, proof, err := publicationPreviousPolicy(c, &birth, selected, order)
			if err != nil || !got.IsZero() || proof != nil {
				t.Fatal("unequal tuple invented previous policy", got, proof, err)
			}
		})
	}
	policy := birth
	policy.AttemptID, policy.AdmissionOrdinal = publicationRelationID(85), 3
	policy.Projection.Action, policy.Projection.OwnedBirthAttemptID = contract.PublicationUpdatePolicy, birth.AttemptID
	policy.Projection.PolicyDigest = coordinate.LastPolicyDigest
	policy.BirthServiceContractID, policy.BirthTargetContractID = "", ""
	policy.Evidence.ConsumerLocator = ""
	policy.ProjectionCommitment, err = contract.PublicationProjectionCommitment(policy.Projection)
	if err != nil {
		t.Fatal(err)
	}
	coordinate.LastPolicyAckAttemptID, coordinate.LastPolicyAckOrdinal = policy.AttemptID, policy.AdmissionOrdinal
	selected.markers[policy.AttemptID] = policy
	previous, marker, err = publicationPreviousPolicy(coordinate, &birth, selected, order)
	if err != nil || previous != coordinate.LastPolicyDigest || marker == nil || *marker != policy {
		t.Fatal("retained exact policy ACK lost owner proof", previous, marker, err)
	}
	for _, damage := range []struct {
		name   string
		change func(*contract.PublicationMarker)
	}{
		{"domain", func(m *contract.PublicationMarker) { m.DomainID = publicationRelationID(86) }},
		{"binding", func(m *contract.PublicationMarker) { m.Projection.BindingIncarnationID = publicationRelationID(86) }},
		{"entry", func(m *contract.PublicationMarker) { m.Projection.EntryIncarnationID = publicationRelationID(86) }},
		{"digest", func(m *contract.PublicationMarker) { m.Projection.PolicyDigest = publicationRelationID(86) }},
		{"incarnation", func(m *contract.PublicationMarker) { m.PublicationIncarnationID = publicationRelationID(86) }},
		{"ordinal", func(m *contract.PublicationMarker) { m.AdmissionOrdinal++ }},
	} {
		t.Run("contradictory-marker/"+damage.name, func(t *testing.T) {
			bad := policy
			damage.change(&bad)
			selected.markers[policy.AttemptID] = bad
			if _, _, err := publicationPreviousPolicy(coordinate, &birth, selected, order); err == nil {
				t.Fatal("contradictory selected marker accepted")
			}
			selected.markers[policy.AttemptID] = policy
		})
	}
	t.Run("other-birth", func(t *testing.T) {
		bad := policy
		bad.Projection.OwnedBirthAttemptID = publicationRelationID(86)
		selected.markers[policy.AttemptID] = bad
		got, _, err := publicationPreviousPolicy(coordinate, &birth, selected, order)
		if err != nil || !got.IsZero() {
			t.Fatal("another owner's policy used", got, err)
		}
		selected.markers[policy.AttemptID] = policy
	})
	t.Run("before-delete", func(t *testing.T) {
		c := coordinate
		c.LastDeleteAckAttemptID = publicationRelationID(87)
		c.LastDeleteAckIncarnationID = policy.PublicationIncarnationID
		c.LastDeleteAckOrdinal = policy.AdmissionOrdinal
		got, _, err := publicationPreviousPolicy(c, &birth, selected, order)
		if err != nil || !got.IsZero() {
			t.Fatal("policy before delete used", got, err)
		}
	})
}

// full_only: false
func TestPublicationPolicyChoiceAndFreshPinKeepSelectedFacts(t *testing.T) {
	coordinate, birth, selected, order := publicationPolicyFixture(t)
	target := contract.OutputTarget{EntryIncarnationID: coordinate.LastEntryIncarnationID, Capabilities: contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityWriteSetsPolicy, Policy: contract.OutputPolicy{ContractID: "private/policy/v1", Data: []byte{1}}}
	input := publicationPolicyActionInput{DomainID: coordinate.DomainID, DestinationID: "destination", ConfigContractID: "current-config", Target: target, Deadline: time.Now().Add(time.Minute)}
	calls := 0
	selector := func(_ context.Context, in publicationPolicyActionInput) (uint8, error) {
		calls++
		if !in.HasPreviousPolicyDigest || in.PreviousPolicyDigest != publicationRelationID(82) || in.ConfigContractID != "current-config" {
			t.Fatal("wrong qualified selector inputs", in)
		}
		return contract.PublicationWriteValue, nil
	}
	actions, pin, err := publicationSelectActions(t.Context(), input, coordinate, &birth, selected, order, true, true, false, false, selector)
	if err != nil || !slices.Equal(actions, []uint8{contract.PublicationWriteValue}) || pin == nil || calls != 1 || !pin.matches(coordinate, selected, order, 0) {
		t.Fatal("policy action selection or fresh pin", actions, pin, err, calls)
	}
	for _, damage := range []struct {
		name   string
		change func(*contract.PublicationCoordinate)
	}{
		{"value-digest", func(c *contract.PublicationCoordinate) { c.LastValueDigest = publicationRelationID(90) }},
		{"policy-digest", func(c *contract.PublicationCoordinate) { c.LastPolicyDigest = publicationRelationID(90) }},
		{"value-attempt", func(c *contract.PublicationCoordinate) { c.LastValueAckAttemptID = publicationRelationID(90) }},
		{"policy-attempt", func(c *contract.PublicationCoordinate) { c.LastPolicyAckAttemptID = publicationRelationID(90) }},
		{"value-incarnation", func(c *contract.PublicationCoordinate) { c.LastValueAckIncarnationID = publicationRelationID(90) }},
		{"policy-incarnation", func(c *contract.PublicationCoordinate) { c.LastPolicyAckIncarnationID = publicationRelationID(90) }},
		{"value-ordinal", func(c *contract.PublicationCoordinate) { c.LastValueAckOrdinal++ }},
		{"policy-ordinal", func(c *contract.PublicationCoordinate) { c.LastPolicyAckOrdinal++ }},
		{"birth", func(c *contract.PublicationCoordinate) { c.OwnedBirthAttemptID = publicationRelationID(90) }},
		{"instance", func(c *contract.PublicationCoordinate) { c.OwnedInstanceDigest = publicationRelationID(90) }},
		{"binding", func(c *contract.PublicationCoordinate) { c.LastBindingIncarnationID = publicationRelationID(90) }},
		{"entry", func(c *contract.PublicationCoordinate) { c.LastEntryIncarnationID = publicationRelationID(90) }},
		{"risk", func(c *contract.PublicationCoordinate) { c.LateEffectRisk = 1 }},
	} {
		t.Run(damage.name, func(t *testing.T) {
			c := coordinate
			damage.change(&c)
			if pin.matches(c, selected, order, 0) {
				t.Fatal("changed selection retained passive choice")
			}
		})
	}
	if pin.matches(coordinate, selected, order, 1) || pin.matches(coordinate, selected, append(slices.Clone(order), publicationRelationID(91)), 0) {
		t.Fatal("warning or changed ordering retained passive choice")
	}
	for _, action := range []uint8{0, contract.PublicationCreateWithValue, contract.PublicationDeleteOwned} {
		if _, _, err := publicationSelectActions(t.Context(), input, coordinate, &birth, selected, order, true, true, false, false, func(context.Context, publicationPolicyActionInput) (uint8, error) { return action, nil }); err == nil {
			t.Fatal("unsupported selected action accepted", action)
		}
	}
	for _, state := range []struct {
		name                                  string
		owned, valueEqual, policyEqual, force bool
	}{
		{"new", false, false, false, false}, {"value-change", true, false, false, false}, {"no-op", true, true, true, false}, {"forced-value", true, true, false, true},
	} {
		t.Run(state.name, func(t *testing.T) {
			_, _, _ = publicationSelectActions(t.Context(), input, coordinate, &birth, selected, order, state.owned, state.valueEqual, state.policyEqual, state.force, func(context.Context, publicationPolicyActionInput) (uint8, error) {
				t.Fatal("independent action entered policy selector")
				return 0, nil
			})
		})
	}
	if _, _, err := publicationSelectActions(t.Context(), input, coordinate, &birth, selected, order, true, true, false, false, nil); err == nil {
		t.Fatal("missing selector silently selected an action")
	}
}

// full_only: false
func TestPublicationPolicyChoiceKeepsHistoricalWireMarkerBytes(t *testing.T) {
	coordinate, birth, _, order := publicationPolicyFixture(t)
	// Independent v4 request-contract derivation: domain, protocol ID, config
	// digest, two big-endian blob32 identifiers and the existing create action.
	protocolID := sha256.Sum256([]byte("ENKV/OUTPUT-WIRE/v4\x00"))
	configBody := []byte("ENKV/OUTPUT/CONFIG-CONTRACT/v1\x00")
	configBody = binary.BigEndian.AppendUint32(configBody, 1)
	configBody = append(configBody, '2')
	configID := sha256.Sum256(configBody)
	request := append([]byte("ENKV/OUTPUT/REQUEST-CONTRACT/v2\x00"), protocolID[:]...)
	request = append(request, configID[:]...)
	for _, text := range []string{"provider", "profile"} {
		request = binary.BigEndian.AppendUint32(request, uint32(len(text)))
		request = append(request, text...)
	}
	request = append(request, byte(contract.PublicationCreateEmpty))
	birth.Projection.RequestContractDigest = sha256.Sum256(request)
	var err error
	birth.ProjectionCommitment, err = contract.PublicationProjectionCommitment(birth.Projection)
	if err != nil {
		t.Fatal(err)
	}
	before, err := contract.EncodePublicationMarker(birth)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := publicationFixtureRowsRelation(coordinate.DomainID, publicationRelationRows(t, coordinate, birth))
	if err != nil {
		t.Fatal("v4 historical marker refused", err)
	}
	input := publicationPolicyActionInput{DomainID: coordinate.DomainID, Target: contract.OutputTarget{EntryIncarnationID: coordinate.LastEntryIncarnationID,
		Capabilities: contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityWriteSetsPolicy, Policy: contract.OutputPolicy{ContractID: "current/policy", Data: []byte{1}}}, Deadline: time.Now().Add(time.Minute)}
	for _, config := range []string{"A", "B", "A"} {
		input.ConfigContractID = config
		actions, _, err := publicationSelectActions(t.Context(), input, coordinate, &birth, selected, order, true, true, false, false, func(_ context.Context, in publicationPolicyActionInput) (uint8, error) {
			if !in.HasPreviousPolicyDigest || in.PreviousPolicyDigest != coordinate.LastPolicyDigest {
				t.Fatal("current config erased original policy proof")
			}
			return contract.PublicationWriteValue, nil
		})
		if err != nil || !slices.Equal(actions, []uint8{contract.PublicationWriteValue}) {
			t.Fatal("current config added historical wire matching", actions, err)
		}
	}
	after, err := contract.EncodePublicationMarker(selected.markers[birth.AttemptID])
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("current selection rewrote historical marker bytes", err)
	}
}
