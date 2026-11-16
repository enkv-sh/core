package core

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

func resolveOutputRoute(configuration contract.OutputConfiguration, entry contract.ID) []string {
	for _, route := range configuration.Routes {
		if route.EntryIncarnationID == entry {
			return route.Destinations
		}
	}
	return configuration.DefaultDestinations
}

func manifestContextFailure(ctx context.Context) readerFailure {
	if ctx == nil {
		return readerRefusal(contract.ReasonInvalidInput)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return readerRefusal(contract.ReasonExpired)
	}
	if ctx.Err() != nil {
		return readerRefusal(contract.ReasonCancelled)
	}
	return readerFailure{}
}

func manifestInputFailure(reason contract.DiagnosticReason) readerFailure {
	return readerFailure{Result: refused(InvalidIntent), diagnostic: reason}
}

type manifestLocatorRequest struct {
	binding         contract.ID
	destination     string
	target          contract.OutputTarget
	entry, position int
}

// The enclosing Reader invocation supplies the authenticated fixed selection
// and retains its exact read source until projection and encoding finish.
// No returned projection can outlive borrowed image bytes: plain bytes are
// copied, and parser-owned target strings/policy slices transfer to this owner.
// owned is captured and validated by the enclosing caller. No second request
// copy occurs during the public operation.
func buildOwnedManifestSelection(ctx context.Context, selected publicSelection, owned contract.ManifestRequest) (*manifest.Projection, readerFailure) {
	if failure := manifestContextFailure(ctx); failure.Outcome != 0 {
		return nil, failure
	}
	if !selected.complete {
		return nil, readerRefusal(contract.ReasonInvalidInput)
	}
	target, failed := manifestTargetRecipient(selected, owned)
	if failed.Outcome != 0 {
		return nil, failed
	}
	names := owned.EntryNames
	if owned.EntryMode == manifest.AllAuthorized {
		names = make([]string, 0, len(selected.image.root.Names))
		for _, named := range selected.image.root.Names {
			entry := selected.image.valueEntry(named.Slot)
			if entry == nil {
				return nil, manifestInputFailure(contract.ReasonSelectedRelationInvalid)
			}
			if slices.Contains(entry.Recipients, target) {
				names = append(names, entry.Name)
			}
		}
		slices.Sort(names)
	}
	slots, result, reason := consumerMembershipSlots(&selected.image, names, target)
	if result.Outcome != 0 {
		return nil, readerFailure{Result: result, diagnostic: reason}
	}
	projection := &manifest.Projection{Schema: manifest.Schema, FormatContractID: owned.FormatContractID, ConfigContractID: owned.ConfigContractID, Settings: owned.Settings,
		Observation:       manifest.Observation{DomainID: manifest.ID(selected.image.root.Domain), HEADRevisionID: manifest.ID(selected.basis.anchor.head.Core.Revision), SnapshotID: manifest.ID(selected.image.root.Snapshot)},
		TargetRecipientID: manifest.ID(target), Selection: manifest.Selection{TargetMode: owned.TargetMode, EntryMode: owned.EntryMode}, ServiceFilter: owned.ServiceFilter,
		ResolvedEntries: make([]manifest.EntryIdentity, len(slots)), ExcludedEntries: []manifest.ExcludedEntry{},
		Entries: make([]manifest.Entry, len(slots))}
	secrets := make(map[contract.ID]int, len(slots))
	for index, slot := range slots {
		entry := selected.image.valueEntry(slot)
		row := &projection.Entries[index]
		row.Name, row.EntryIncarnationID = strings.Clone(entry.Name), manifest.ID(entry.Incarnation)
		switch entry.ConfidentialityClass {
		case contract.Plain:
			row.Kind = manifest.Plain
		case contract.Secret:
			row.Kind = manifest.Secret
		default:
			releaseManifestProjection(projection)
			return nil, manifestInputFailure(contract.ReasonInvalidInput)
		}
		projection.ResolvedEntries[index] = manifest.EntryIdentity{Name: row.Name, EntryIncarnationID: row.EntryIncarnationID}
		if row.Kind == manifest.Plain {
			row.PlainValue = make([]byte, int(entry.ContentLength))
			if entry.InputEncoding == contract.InputEncodingBase64 {
				n, err := base64.StdEncoding.Strict().Decode(row.PlainValue, entry.ValueBytes)
				if err != nil || n != len(row.PlainValue) {
					releaseManifestProjection(projection)
					return nil, manifestInputFailure(contract.ReasonInvalidInput)
				}
			} else {
				copy(row.PlainValue, entry.ValueBytes)
			}
		} else {
			secrets[entry.Incarnation] = index
		}
	}
	if len(secrets) != 0 {
		if failure := fillManifestDestinations(ctx, selected, projection, secrets); failure.Outcome != 0 {
			releaseManifestProjection(projection)
			return nil, failure
		}
	}
	if failure := manifestContextFailure(ctx); failure.Outcome != 0 {
		releaseManifestProjection(projection)
		return nil, failure
	}
	return projection, readerFailure{}
}

func manifestTargetRecipient(selected publicSelection, owned contract.ManifestRequest) (contract.ID, readerFailure) {
	target := owned.TargetRecipientID
	if owned.TargetMode == manifest.CurrentAuthority {
		target = selected.authorityID
	}
	_, result, reason := consumerMembershipSlots(&selected.image, nil, target)
	if result.Outcome != 0 {
		return contract.ID{}, readerFailure{Result: result, diagnostic: reason}
	}
	return target, readerFailure{}
}

func fillManifestDestinations(ctx context.Context, selected publicSelection, projection *manifest.Projection, secrets map[contract.ID]int) readerFailure {
	// The relation-only pass retains at most one exact-capacity route vector per
	// requested secret. No policy image is allocated during route selection.
	routes := make([][]string, len(projection.Entries))
	visit := contract.OutputConfigurationVisit{Route: func(entry contract.ID, destinations []string) error {
		if entry.IsZero() {
			for _, index := range secrets {
				routes[index] = destinations
			}
		} else if index, selected := secrets[entry]; selected {
			routes[index] = destinations
		}
		return nil
	}}
	if _, result := selectedOutputConfigurationWithReader(ctx, selected.image.root, selected.image.supportFacts, selected.basis.reader, false, &visit); result.Outcome != 0 {
		if failure := manifestContextFailure(ctx); failure.Outcome != 0 {
			return failure
		}
		return readerSelectionFailure(result)
	}
	total := 0
	for _, index := range secrets {
		total += len(routes[index])
		if total > contract.MaxOutputTargets {
			return manifestInputFailure(contract.ReasonLimitExceeded)
		}
	}
	requests := make([]manifestLocatorRequest, 0, total)
	visit = contract.OutputConfigurationVisit{TargetFields: func(binding contract.ID, destination string, target contract.OutputTarget) error {
		index, chosen := secrets[target.EntryIncarnationID]
		if !chosen {
			return nil
		}
		position := slices.Index(routes[index], destination)
		if position < 0 {
			return nil
		}
		if len(requests) == total {
			return contract.ErrRecord
		}
		// Finish the immutable stream before a later GET can replace its backing.
		requests = append(requests, manifestLocatorRequest{binding: binding, destination: destination, target: target, entry: index, position: position})
		return nil
	}}
	_, result := selectedOutputConfigurationWithReader(ctx, selected.image.root, selected.image.supportFacts, selected.basis.reader, false, &visit)
	if failure := manifestContextFailure(ctx); failure.Outcome != 0 {
		return failure
	}
	if result.Outcome != 0 {
		return readerSelectionFailure(result)
	}
	if len(requests) != total {
		return manifestInputFailure(contract.ReasonLocatorUnusable)
	}
	matching := 0
	for _, request := range requests {
		target := request.target
		if projection.ServiceFilter != nil && target.ServiceContractID != *projection.ServiceFilter {
			continue
		}
		requests[matching] = request
		matching++
	}
	clear(requests[matching:])
	requests = requests[:matching]
	excluded := 0
	for _, index := range secrets {
		count := 0
		for _, request := range requests {
			if request.entry == index {
				count++
			}
		}
		if count == 0 {
			excluded++
			continue
		}
		projection.Entries[index].Destinations = make([]manifest.Destination, count)
		position := 0
		for i := range requests {
			request := &requests[i]
			if request.entry != index {
				continue
			}
			target := request.target
			destination := routes[index][request.position]
			request.position = position
			policyDigest, err := contract.OutputPolicyDigest(selected.image.root.Domain, target.Policy)
			if err != nil {
				return manifestInputFailure(contract.ReasonInvalidInput)
			}
			projection.Entries[index].Destinations[position] = manifest.Destination{DestinationID: destination, BindingIncarnationID: manifest.ID(request.binding), EntryIncarnationID: manifest.ID(target.EntryIncarnationID), ServiceContractID: target.ServiceContractID, ConsumerLocator: target.ConsumerLocator, TargetContractID: target.TargetContractID, CanonicalTarget: target.CanonicalTarget, TargetData: target.TargetData, PolicyContractID: target.Policy.ContractID, PolicyData: target.Policy.Data, PolicyDigest: manifest.ID(policyDigest), PayloadEncoding: target.PayloadEncoding, PolicyPresent: target.Policy.ContractID != ""}
			position++
		}
	}
	projection.ExcludedEntries = make([]manifest.ExcludedEntry, excluded)
	at := 0
	for i := range projection.Entries {
		row := &projection.Entries[i]
		if row.Kind != manifest.Secret || len(row.Destinations) != 0 {
			continue
		}
		reason := manifest.NoOutput
		if len(routes[i]) != 0 {
			reason = manifest.NoMatchingService
		}
		projection.ExcludedEntries[at] = manifest.ExcludedEntry{Name: row.Name, EntryIncarnationID: row.EntryIncarnationID, Reason: reason}
		at++
	}
	locators, failed := manifestConsumerLocators(ctx, selected, requests)
	if failed.Outcome != 0 {
		return failed
	}
	for index, request := range requests {
		projection.Entries[request.entry].Destinations[request.position].ConsumerLocator = locators[index]
	}
	at = 0
	for i := range projection.Entries {
		row := &projection.Entries[i]
		if row.Kind == manifest.Secret && len(row.Destinations) == 0 {
			continue
		}
		slices.SortFunc(row.Destinations, func(a, b manifest.Destination) int { return strings.Compare(a.DestinationID, b.DestinationID) })
		projection.Entries[at] = *row
		at++
	}
	clear(projection.Entries[at:])
	projection.Entries = projection.Entries[:at]
	return readerFailure{}
}

func manifestConsumerLocators(ctx context.Context, selected publicSelection, requests []manifestLocatorRequest) ([]string, readerFailure) {
	if failure := manifestContextFailure(ctx); failure.Outcome != 0 {
		return nil, failure
	}
	if len(requests) > contract.MaxOutputTargets {
		return nil, manifestInputFailure(contract.ReasonLimitExceeded)
	}
	locators := make([]string, len(requests))
	assigned := make([]int, 0, len(requests))
	for index, request := range requests {
		target := request.target
		if target.LocatorRequiresCreation {
			if target.ConsumerLocator != "" {
				return nil, manifestInputFailure(contract.ReasonLocatorUnusable)
			}
			assigned = append(assigned, index)
			continue
		}
		if publicCoordinateReason(target.ConsumerLocator) != "" {
			return nil, manifestInputFailure(contract.ReasonLocatorUnusable)
		}
		locators[index] = strings.Clone(target.ConsumerLocator)
	}
	if len(assigned) == 0 {
		return locators, readerFailure{}
	}
	resolved, failed := manifestSelectedCreationLocators(ctx, selected, requests, assigned)
	if failed.Outcome != 0 {
		return nil, failed
	}
	for index, requestIndex := range assigned {
		locators[requestIndex] = strings.Clone(resolved[index])
	}
	return locators, readerFailure{}
}
