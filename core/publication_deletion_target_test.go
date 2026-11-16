package core

import (
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationDeletionTargetUsesOnlyOwnershipAction(t *testing.T) {
	for _, test := range []struct {
		name                    string
		owner                   uint8
		locatorRequiresCreation bool
		locator                 string
		capabilities            contract.OutputActionCapabilities
	}{
		{name: "qualified-owned", owner: contract.PublicationOwnerQualified, locator: "consumer/owned", capabilities: contract.OutputCapabilityDeleteOwned},
		{name: "qualified-owned-assigned-locator", owner: contract.PublicationOwnerQualified, locatorRequiresCreation: true, capabilities: contract.OutputCapabilityDeleteOwned},
		{name: "uncertain-create", owner: contract.PublicationOwnerUncertainCreate, locator: "consumer/owned", capabilities: contract.OutputCapabilityDeleteReservedSlot},
		{name: "no-owner", owner: contract.PublicationOwnerNone, locator: "consumer/owned"},
	} {
		t.Run(test.name, func(t *testing.T) {
			coordinate := contract.PublicationCoordinate{
				Schema: 5, DomainID: contract.ID{1}, CoordinateID: contract.ID{2},
				ServiceContractID: "private-service/v1", CanonicalTarget: "account/exact-slot",
				BindingState: contract.PublicationBindingRetired, OwnerState: test.owner,
				LastBindingIncarnationID: contract.ID{3}, LastEntryIncarnationID: contract.ID{4},
				DeletionDestinationID: "removed-destination", DeletionConfigContractID: "private-config/v2",
				DeletionCredentialRouteContractID: "private-route/v3", DeletionTargetContractID: "private-target/v4",
				DeletionConsumerLocator: "consumer/owned", DeletionTargetData: []byte("exact retained target data"),
				DeletionPayloadEncoding: contract.OutputEncodingBase64, LocatorRequiresCreation: test.locatorRequiresCreation,
				DeletionTargetRowDigest: contract.ID{5},
			}
			want := contract.OutputTarget{
				EntryIncarnationID: contract.ID{4}, ServiceContractID: "private-service/v1",
				TargetContractID: "private-target/v4", CanonicalTarget: "account/exact-slot",
				ConsumerLocator: test.locator, TargetData: []byte("exact retained target data"),
				PayloadEncoding: contract.OutputEncodingBase64, LocatorRequiresCreation: test.locatorRequiresCreation,
				Capabilities: test.capabilities,
			}
			if got := publicationDeletionTarget(coordinate); !reflect.DeepEqual(got, want) {
				t.Fatalf("retained deletion target = %#v, want %#v", got, want)
			}
		})
	}
}
