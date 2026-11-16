package core

import (
	"bytes"
	"context"
	"slices"
	"strings"

	"enkv.sh/core/contract"
)

// The private apply input names entries and destinations. The transition plan,
// rather than the caller, supplies new entry and binding incarnations.
type outputApplyTarget struct {
	entryName string
	target    contract.OutputTarget // EntryIncarnationID must be zero in the input.
}

type outputApplyBinding struct {
	destinationID string
	destination   contract.OutputDestination

	targets         []outputApplyTarget
	targetsComplete bool
}

type outputApplyRoute struct {
	defaultRoute bool
	entryName    string
	destinations []string
}

func (r outputApplyRoute) validEntrySelector() bool {
	return !r.defaultRoute || r.entryName == ""
}

type outputApplyInput struct {
	bindings []outputApplyBinding
	routes   []outputApplyRoute
	groups   [][]string
}

type outputApplyRouteKey struct {
	defaultRoute bool
	entry        string
}

type outputApplySelection struct {
	descriptor      contract.OutputConfigurationDescriptor
	records         []contract.SupportRecord
	departedTargets []outputTargetDifference
	transition      *contract.NormalOutputTransition
}

func (s *StateSession) compareOutput(ctx context.Context, c *Comparison, output *outputApplyInput) Result {
	if c == nil || c.session != s {
		return refused(AdmissionInvalid)
	}
	recipients := make([]contract.ID, 0, len(c.recipients))
	for _, recipient := range c.proposedRegistry() {
		if recipient.Status == contract.CurrentRecipient {
			recipients = append(recipients, recipient.RecipientID)
		}
	}
	if output == nil {
		current, result := s.currentOutputConfigurationForApply(ctx)
		if result.Outcome != 0 {
			return result
		}
		var err error
		output, err = s.outputSourceInput(current, c.desiredEntries)
		if err != nil {
			return refused(InvalidIntent)
		}
	}
	if output != nil {
		normalized, err := normalizeOutputApply(ctx, c.desiredEntries, recipients, s.admission.recipient, output, s.admission.outputInterpreter)
		if err != nil {
			return refused(InvalidIntent)
		}
		output = normalized
		if !checkOutputApplyInput(s.root.Domain, c.desiredEntries, output) {
			return refused(InvalidIntent)
		}
		changed, result := s.outputApplyChangesSelected(ctx, c, output)
		if result.Outcome != 0 {
			return result
		}
		c.outputIntent, c.outputChanged = output, changed
	}
	return Result{}
}

func (s *StateSession) normalOutputTransition(ctx context.Context, c *Comparison) (*contract.NormalOutputTransition, error) {
	if c == nil || c.session != s || c.outputIntent == nil {
		return nil, contract.ErrRecord
	}
	before, result := s.currentOutputConfigurationForApply(ctx)
	if result.Outcome != 0 {
		return nil, selectedReadFailure(result)
	}
	v := &contract.NormalOutputTransition{Before: before, BeforeDescriptor: s.root.OutputConfiguration,
		Intent: c.intent, Slots: c.slots}
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry == nil {
			return nil, contract.ErrRecord
		}
		digest, err := contract.PublicValueEntryDigest(s.root.Domain, named.Slot, *entry)
		if err != nil {
			return nil, err
		}
		v.EntriesBefore = append(v.EntriesBefore, contract.MembershipRow{Name: entry.Name, Slot: named.Slot,
			Incarnation: entry.Incarnation, EntryDigest: digest, Recipients: entry.Recipients})
	}
	for _, binding := range c.outputIntent.bindings {
		row := contract.NormalOutputBinding{DestinationID: binding.destinationID, Destination: binding.destination}
		for _, target := range binding.targets {
			row.Targets = append(row.Targets, contract.NormalOutputTarget{Name: target.entryName, Target: target.target})
		}
		v.Bindings = append(v.Bindings, row)
	}
	v.Groups = c.outputIntent.groups
	for _, route := range c.outputIntent.routes {
		v.Routes = append(v.Routes, contract.NormalOutputRoute{Default: route.defaultRoute, Name: route.entryName, Destinations: route.destinations})
	}
	selected, err := s.selectedNormalSupportRows()
	if err != nil {
		return nil, err
	}
	if err := v.Inspect(selected); err != nil {
		return nil, err
	}
	return v.Own()
}

// A declaration difference is not evidence that a container exists. The
// selected coordinate and birth/unknown markers decide whether an old owner
// remains, reuse is blocked, or deletion is required after a target departs.
type outputTargetDifference struct {
	coordinateID, bindingIncarnationID, entryIncarnationID, targetRowDigest contract.ID
	destinationID                                                           string
	target                                                                  contract.OutputTarget
}

// The mutation path owns typed rows only after the complete selected slice
// stream has passed the same authenticated validator used by ordinary Open.
// No decoded configuration is retained in the selected session.
func (s *StateSession) currentOutputConfigurationForApply(ctx context.Context) (contract.OutputConfiguration, Result) {
	if s == nil || !s.selectedOutputComplete() {
		return contract.OutputConfiguration{}, refused(AdmissionInvalid)
	}
	return selectedOutputConfigurationWithReader(ctx, s.root, s.supportFacts, s.selectedObjectReader(), true, nil)
}

func ownOutputApplyInput(input *outputApplyInput) *outputApplyInput {
	if input == nil {
		return nil
	}
	owned := &outputApplyInput{bindings: make([]outputApplyBinding, len(input.bindings)), routes: make([]outputApplyRoute, len(input.routes))}
	for i, binding := range input.bindings {
		owned.bindings[i].destinationID = strings.Clone(binding.destinationID)
		owned.bindings[i].targetsComplete = binding.targetsComplete
		owned.bindings[i].destination = ownOutputDestination(binding.destination)
		owned.bindings[i].targets = make([]outputApplyTarget, len(binding.targets))
		for j, row := range binding.targets {
			target := ownOutputTarget(row.target)
			owned.bindings[i].targets[j] = outputApplyTarget{entryName: strings.Clone(row.entryName), target: target}
		}
	}
	owned.groups = slices.Clone(input.groups)
	for i := range owned.groups {
		owned.groups[i] = slices.Clone(owned.groups[i])
		for j := range owned.groups[i] {
			owned.groups[i][j] = strings.Clone(owned.groups[i][j])
		}
	}
	for i, route := range input.routes {
		owned.routes[i] = outputApplyRoute{defaultRoute: route.defaultRoute, entryName: strings.Clone(route.entryName), destinations: slices.Clone(route.destinations)}
		for j := range owned.routes[i].destinations {
			owned.routes[i].destinations[j] = strings.Clone(owned.routes[i].destinations[j])
		}
	}
	return owned
}

// outputApplyPreviewID is only a fixed-width grammar witness for the closed
// configuration codec. It is never stored, signed, or treated as an incarnation.
func outputApplyPreviewID(kind byte, name string) contract.ID {
	material := make([]byte, 0, len("ENKV/output-apply-preview/v1\x00")+1+len(name))
	material = append(material, "ENKV/output-apply-preview/v1\x00"...)
	material = append(material, kind)
	material = append(material, name...)
	return contract.Hash(material)
}

// outputApplyConfiguration delegates every row, policy, route, physical-alias
// and aggregate bound to the canonical configuration codec. The maps are
// supplied either by a grammar-only preview or by the admitted plan.
func outputApplyConfiguration(domain contract.ID, input *outputApplyInput, entries, bindings map[string]contract.ID) (contract.OutputConfiguration, []byte, error) {
	configuration, err := outputApplyConfigurationRows(domain, input, entries, bindings)
	if err != nil {
		return contract.OutputConfiguration{}, nil, err
	}
	image, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		return contract.OutputConfiguration{}, nil, err
	}
	return configuration, image, nil
}

func outputApplyConfigurationRows(domain contract.ID, input *outputApplyInput, entries, bindings map[string]contract.ID) (contract.OutputConfiguration, error) {
	if input == nil || domain.IsZero() {
		return contract.OutputConfiguration{}, contract.ErrRecord
	}
	configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: domain}
	for _, binding := range input.bindings {
		bindingID, present := bindings[binding.destinationID]
		if !present || bindingID.IsZero() {
			return contract.OutputConfiguration{}, contract.ErrRecord
		}
		row := contract.OutputBinding{DestinationID: binding.destinationID, IncarnationID: bindingID, Destination: binding.destination}

		seen := make(map[string]bool, len(binding.targets))
		for _, named := range binding.targets {
			id, present := entries[named.entryName]
			if !present || seen[named.entryName] || !named.target.EntryIncarnationID.IsZero() {
				return contract.OutputConfiguration{}, contract.ErrRecord
			}
			seen[named.entryName] = true
			target := named.target
			target.EntryIncarnationID = id
			row.Targets = append(row.Targets, target)
		}
		slices.SortFunc(row.Targets, func(a, b contract.OutputTarget) int {
			return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
		})
		configuration.Bindings = append(configuration.Bindings, row)
	}
	for _, group := range input.groups {
		ids := make([]contract.ID, len(group))
		for i, name := range group {
			ids[i] = entries[name]
			if ids[i].IsZero() {
				return contract.OutputConfiguration{}, contract.ErrRecord
			}
		}
		slices.SortFunc(ids, comparePublicIDs)
		configuration.Groups = append(configuration.Groups, ids)
	}
	slices.SortFunc(configuration.Groups, func(a, b []contract.ID) int { return comparePublicIDs(a[0], b[0]) })
	defaultSeen := false
	for _, route := range input.routes {
		if !route.validEntrySelector() {
			return contract.OutputConfiguration{}, contract.ErrRecord
		}
		if route.defaultRoute {
			if defaultSeen {
				return contract.OutputConfiguration{}, contract.ErrRecord
			}
			defaultSeen = true
			configuration.DefaultDestinations = route.destinations
			continue
		}
		id, present := entries[route.entryName]
		if !present || id.IsZero() {
			return contract.OutputConfiguration{}, contract.ErrRecord
		}
		configuration.Routes = append(configuration.Routes, contract.OutputRoute{EntryIncarnationID: id, Destinations: route.destinations})
	}
	slices.SortFunc(configuration.Routes, func(a, b contract.OutputRoute) int {
		return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
	})
	return configuration, nil
}

// outputProjectionForPlan resolves caller names only through the admitted
// transition plan. The returned records are complete, owned kind-17 bodies;
// the full image and intermediate slice copies stay invocation-local.
func (s *StateSession) outputProjectionForPlan(ctx context.Context, c *Comparison, p transitionPlan, before contract.OutputConfiguration) (*outputApplySelection, error) {
	if s == nil || c == nil || c.session != s || c.outputIntent == nil || before.DomainID != s.root.Domain || before.Schema != contract.OutputConfigurationSchema {
		return nil, contract.ErrRecord
	}
	v, err := s.normalOutputTransition(ctx, c)
	if err != nil {
		return nil, err
	}
	after, descriptor, records, err := v.ConfigurationAfter(identityPlan(c, p))
	if err != nil {
		return nil, err
	}
	departed, err := outputApplyTargetDifferences(s.root.Domain, before, after)
	if err != nil {
		return nil, err
	}
	return &outputApplySelection{descriptor: descriptor, records: records, departedTargets: departed, transition: v}, nil
}

// A target keeps the same configured binding, entry and physical coordinate
// through policy, consumer locator, profile, shape and encoding changes.
// Those changes still change the canonical projection, but do not alone
// prove that an old physical container must be deleted.
func outputApplyTargetDifferences(domain contract.ID, before, after contract.OutputConfiguration) ([]outputTargetDifference, error) {
	if domain.IsZero() || before.DomainID != domain || after.DomainID != domain || before.Schema != contract.OutputConfigurationSchema || after.Schema != contract.OutputConfigurationSchema {
		return nil, contract.ErrRecord
	}
	type targetKey struct{ binding, entry, coordinate contract.ID }
	retained := make(map[targetKey]bool)
	afterCount := 0
	for _, binding := range after.Bindings {
		for _, target := range binding.Targets {
			afterCount++
			if afterCount > contract.MaxOutputTargets {
				return nil, contract.ErrRecordCapacity
			}
			coordinate, err := contract.PublicationCoordinateID(domain, target.ServiceContractID, target.CanonicalTarget)
			if err != nil {
				return nil, err
			}
			retained[targetKey{binding.IncarnationID, target.EntryIncarnationID, coordinate}] = true
		}
	}
	departed := make([]outputTargetDifference, 0)
	beforeCount := 0
	for _, binding := range before.Bindings {
		for _, target := range binding.Targets {
			beforeCount++
			if beforeCount > contract.MaxOutputTargets {
				return nil, contract.ErrRecordCapacity
			}
			coordinate, err := contract.PublicationCoordinateID(domain, target.ServiceContractID, target.CanonicalTarget)
			if err != nil {
				return nil, err
			}
			if retained[targetKey{binding.IncarnationID, target.EntryIncarnationID, coordinate}] {
				continue
			}
			rowDigest, err := contract.PublicationTargetRowDigest(domain, binding.DestinationID, binding.IncarnationID, target)
			if err != nil {
				return nil, err
			}
			owned := ownOutputTarget(target)
			departed = append(departed, outputTargetDifference{coordinateID: coordinate,
				bindingIncarnationID: binding.IncarnationID, entryIncarnationID: target.EntryIncarnationID,
				targetRowDigest: rowDigest, destinationID: strings.Clone(binding.DestinationID), target: owned})
		}
	}
	return departed, nil
}

// checkOutputApplyInput validates the complete private name-based intent
// before a Crypto comparison. Preview IDs are never used as selected IDs.
func checkOutputApplyInput(domain contract.ID, entries []ApplyEntryInput, input *outputApplyInput) bool {
	return outputApplyInputShape(domain, entries, input) == nil
}

func outputApplyInputShape(domain contract.ID, entries []ApplyEntryInput, input *outputApplyInput) error {
	if input == nil || domain.IsZero() {
		return contract.ErrRecord
	}
	entryIDs := make(map[string]contract.ID, len(entries))
	for _, entry := range entries {
		if _, duplicate := entryIDs[entry.Name]; duplicate {
			return contract.ErrRecord
		}
		entryIDs[entry.Name] = outputApplyPreviewID(1, entry.Name)
	}
	bindingIDs := make(map[string]contract.ID, len(input.bindings))
	for _, binding := range input.bindings {
		if _, duplicate := bindingIDs[binding.destinationID]; duplicate {
			return contract.ErrRecord
		}
		bindingIDs[binding.destinationID] = outputApplyPreviewID(2, binding.destinationID)
	}
	configuration, err := outputApplyConfigurationRows(domain, input, entryIDs, bindingIDs)
	if err != nil {
		return err
	}
	_, err = contract.OutputConfigurationLength(configuration)
	return err
}

// An entry replacement takes precedence even when its list is empty.
func outputApplyRouteFor(routes map[outputApplyRouteKey]*outputApplyRoute, entry string) *outputApplyRoute {
	if route := routes[outputApplyRouteKey{entry: entry}]; route != nil {
		return route
	}
	return routes[outputApplyRouteKey{defaultRoute: true}]
}

func (s *StateSession) outputApplyRoutingReady(c *Comparison, input *outputApplyInput) bool {
	if s == nil || c == nil || input == nil {
		return false
	}
	for _, recipient := range c.proposedRegistry() {
		if recipient.Status == contract.CurrentRecipient && recipient.CurrentBinding == nil {
			return false
		}
	}
	entries := make(map[string]bool, len(c.desiredEntries))
	for _, entry := range c.desiredEntries {
		entries[entry.Name] = true
	}
	bindings := make(map[string]map[string]bool, len(input.bindings))
	for _, binding := range input.bindings {
		if _, duplicate := bindings[binding.destinationID]; duplicate {
			return false
		}
		targets := make(map[string]bool, len(binding.targets))
		for _, target := range binding.targets {
			if !entries[target.entryName] || targets[target.entryName] {
				return false
			}
			targets[target.entryName] = true
		}
		bindings[binding.destinationID] = targets
	}
	routes := make(map[outputApplyRouteKey]*outputApplyRoute, len(input.routes))
	for i := range input.routes {
		route := &input.routes[i]
		if !route.validEntrySelector() || !route.defaultRoute && !entries[route.entryName] {
			return false
		}
		key := outputApplyRouteKey{route.defaultRoute, route.entryName}
		if routes[key] != nil {
			return false
		}
		routes[key] = route
	}
	for _, entry := range c.desiredEntries {
		selected := outputApplyRouteFor(routes, entry.Name)
		if selected == nil {
			continue
		}
		for _, destination := range selected.destinations {
			if !bindings[destination][entry.Name] {
				return false
			}
		}
	}
	return true
}

// outputApplyChangesSelected compares only authenticated current identities.
// The successor transformation retires departed coordinates while retaining
// their selected ownership and unresolved publication evidence.
func (s *StateSession) outputApplyChangesSelected(ctx context.Context, c *Comparison, input *outputApplyInput) (bool, Result) {
	if s == nil || c == nil || input == nil {
		return false, refused(InvalidIntent)
	}
	if !s.outputApplyRoutingReady(c, input) {
		return false, refused(InvalidIntent)
	}
	before, result := s.currentOutputConfigurationForApply(ctx)
	if result.Outcome != 0 {
		return false, result
	}
	currentBindings := make(map[string]contract.ID, len(before.Bindings))
	for _, binding := range before.Bindings {
		currentBindings[binding.DestinationID] = binding.IncarnationID
	}
	entryIDs := make(map[string]contract.ID, len(c.desiredEntries))
	fresh := c.freshIncarnationSlots()
	changedIdentity := false
	for i, entry := range c.desiredEntries {
		slot := c.slots[i]
		if slices.Contains(fresh, slot) {
			for _, binding := range input.bindings {
				if slices.ContainsFunc(binding.targets, func(row outputApplyTarget) bool { return row.entryName == entry.Name }) {
					changedIdentity = true
					break
				}
			}
			if slices.ContainsFunc(input.routes, func(route outputApplyRoute) bool {
				return !route.defaultRoute && route.entryName == entry.Name
			}) {
				changedIdentity = true
			}
			if slices.ContainsFunc(input.groups, func(group []string) bool {
				return slices.Contains(group, entry.Name)
			}) {
				changedIdentity = true
			}
			continue
		}
		old := s.valueEntry(slot)
		if old == nil || old.Name != entry.Name {
			return false, refused(InvalidIntent)
		}
		entryIDs[entry.Name] = old.Incarnation
	}
	for _, binding := range input.bindings {
		if _, present := currentBindings[binding.destinationID]; !present {
			changedIdentity = true
		}
	}
	if changedIdentity {
		return true, Result{}
	}
	_, image, err := outputApplyConfiguration(s.root.Domain, input, entryIDs, currentBindings)
	if err != nil {
		return false, refused(InvalidIntent)
	}
	descriptor, _, err := contract.SplitOutputConfiguration(s.root.Domain, image)
	if err != nil {
		return false, refused(InvalidIntent)
	}
	return descriptor != s.root.OutputConfiguration, Result{}
}

func expectedNormalOutputDescriptor(c *Comparison) contract.OutputConfigurationDescriptor {
	if c.outputChanged && c.outputAfter != nil {
		return c.outputAfter.descriptor
	}
	return c.session.root.OutputConfiguration
}

func (s *StateSession) generatedOutputTransition(ctx context.Context, desired ...[]ApplyEntryInput) (*contract.GeneratedOutputTransition, error) {
	var entries []ApplyEntryInput
	if len(desired) > 0 {
		entries = desired[0]
	}
	return s.generatedOutputTransitionWithRecipients(ctx, s.registry(), entries, nil)
}

func (s *StateSession) generatedRequestedOutputTransition(ctx context.Context, graph contract.GeneratorPlanBundle, registry []contract.RecipientRecord, desired []ApplyEntryInput, image []byte) (*contract.GeneratedOutputTransition, error) {
	var output *outputApplyInput
	if graph.Request.Schema == contract.GeneratorApplyRequestCoreSchema {
		configuration, err := contract.InspectGeneratedOutputConfiguration(graph, image)
		if err != nil {
			return nil, err
		}
		output, err = generatedOutputApplyInput(graph.ValueEntryPlans, configuration)
		if err != nil {
			return nil, err
		}
	} else if len(image) != 0 {
		return nil, contract.ErrRecord
	}
	return s.generatedOutputTransitionWithRecipients(ctx, registry, desired, output)
}

func generatedOutputApplyInput(plans []contract.GeneratorValueEntryPlan, configuration contract.OutputConfiguration) (*outputApplyInput, error) {
	names := make(map[contract.ID]string, len(plans))
	for _, plan := range plans {
		if _, present := names[plan.EntryIncarnationID]; present || plan.EntryIncarnationID.IsZero() {
			return nil, contract.ErrRecord
		}
		names[plan.EntryIncarnationID] = plan.Name
	}
	nameFor := func(id contract.ID) (string, error) {
		name, present := names[id]
		if !present {
			return "", contract.ErrRecord
		}
		return name, nil
	}
	input := &outputApplyInput{}
	for _, binding := range configuration.Bindings {
		row := outputApplyBinding{destinationID: binding.DestinationID, destination: binding.Destination, targetsComplete: true}

		for _, target := range binding.Targets {
			name, err := nameFor(target.EntryIncarnationID)
			if err != nil {
				return nil, err
			}
			target.EntryIncarnationID = contract.ID{}
			row.targets = append(row.targets, outputApplyTarget{entryName: name, target: target})
		}
		input.bindings = append(input.bindings, row)
	}
	input.routes = append(input.routes, outputApplyRoute{defaultRoute: true, destinations: configuration.DefaultDestinations})
	for _, route := range configuration.Routes {
		name, err := nameFor(route.EntryIncarnationID)
		if err != nil {
			return nil, err
		}
		input.routes = append(input.routes, outputApplyRoute{entryName: name, destinations: route.Destinations})
	}
	for _, group := range configuration.Groups {
		names := make([]string, len(group))
		for i, id := range group {
			name, err := nameFor(id)
			if err != nil {
				return nil, err
			}
			names[i] = name
		}
		input.groups = append(input.groups, names)
	}
	return input, nil
}

func (s *StateSession) generatedOutputTransitionWithRecipients(ctx context.Context, registry []contract.RecipientRecord, desired []ApplyEntryInput, output *outputApplyInput) (*contract.GeneratedOutputTransition, error) {
	configuration, result := s.currentOutputConfigurationForApply(ctx)
	if result.Outcome != 0 {
		return nil, selectedReadFailure(result)
	}
	selected, err := s.selectedNormalSupportRows()
	if err != nil {
		return nil, err
	}
	w := &contract.GeneratedOutputTransition{Before: configuration, BeforeDescriptor: s.root.OutputConfiguration}
	entries := make([]ApplyEntryInput, 0, len(s.root.Names))
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry == nil {
			return nil, contract.ErrRecord
		}
		entries = append(entries, ApplyEntryInput{Name: entry.Name, Recipients: entry.Recipients, InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding})
	}
	if desired != nil {
		entries = desired
	}
	recipients := make([]contract.ID, 0, len(registry))
	for _, recipient := range registry {
		if recipient.Status == contract.CurrentRecipient {
			recipients = append(recipients, recipient.RecipientID)
		}
	}
	if output == nil {
		output, err = s.outputSourceInput(configuration, entries)
		if err != nil {
			return nil, err
		}
	}
	normalized, err := normalizeOutputApply(ctx, entries, recipients, s.admission.recipient, output, s.admission.outputInterpreter)
	if err != nil {
		return nil, err
	}
	for _, binding := range normalized.bindings {
		row := contract.NormalOutputBinding{DestinationID: binding.destinationID, Destination: binding.destination}
		for _, target := range binding.targets {
			row.Targets = append(row.Targets, contract.NormalOutputTarget{Name: target.entryName, Target: target.target})
		}
		w.Bindings = append(w.Bindings, row)
	}
	for _, route := range normalized.routes {
		w.Routes = append(w.Routes, contract.NormalOutputRoute{Default: route.defaultRoute, Name: route.entryName, Destinations: route.destinations})
	}
	w.Groups = normalized.groups

	w.Rows.Facts = selected.Facts
	for _, row := range selected.Records {
		if row.Kind == contract.RetainedCanonicalSupportKind {
			w.Retained = append(w.Retained, row)
		}
		if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
			w.Rows.Records = append(w.Rows.Records, row)
		}
	}
	image, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		return nil, err
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(s.root.Domain, image)
	if err != nil || descriptor != w.BeforeDescriptor {
		return nil, contract.ErrRecord
	}
	for _, part := range parts {
		body, err := contract.EncodeOutputConfigurationSlice(part)
		if err != nil {
			return nil, err
		}
		id, err := contract.OutputConfigurationSliceID(s.root.Domain, descriptor.ConfigurationDigest, part.SliceIndex)
		if err != nil {
			return nil, err
		}
		w.Rows.Records = append(w.Rows.Records, contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
	}
	slices.SortFunc(w.Rows.Records, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry == nil {
			return nil, contract.ErrRecord
		}
		digest, err := contract.PublicValueEntryDigest(s.root.Domain, named.Slot, *entry)
		if err != nil {
			return nil, err
		}
		w.EntriesBefore = append(w.EntriesBefore, contract.MembershipRow{Name: named.Name, Slot: named.Slot, Incarnation: entry.Incarnation,
			EntryDigest: digest, Recipients: entry.Recipients})
		body, err := contract.EncodeValueEntry(*entry)
		if err != nil {
			return nil, err
		}
		w.EntryBodies = append(w.EntryBodies, body)
	}
	public, err := s.publicProjection()
	if err != nil {
		return nil, err
	}
	return w.Own(public)
}
func normalSupportPredecessorMatches(c *Comparison) bool {
	if c.support == nil {
		return c.outputChanged && c.outputAfter != nil
	}
	return c.support.DomainID == c.session.root.Domain && c.support.BeforeSnapshot == c.session.root.Snapshot && c.support.BeforeSliceSnapshot == c.session.adminIndex.SliceSnapshot && c.support.BeforeRootDigest == c.session.head.Core.Root.Digest
}
