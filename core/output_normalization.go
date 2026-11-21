package core

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"

	"enkv.sh/core/contract"
)

func ownOutputDestination(v contract.OutputDestination) contract.OutputDestination {
	v.ConfigContractID, v.ServiceContractID = strings.Clone(v.ConfigContractID), strings.Clone(v.ServiceContractID)
	v.CanonicalSettings = ownPublicSlice(v.CanonicalSettings)
	v.Policy = ownOutputPolicy(v.Policy)
	return v
}
func ownOutputPolicy(v contract.OutputPolicy) contract.OutputPolicy {
	if v.ContractID == "" && len(v.Data) == 0 {
		return contract.OutputPolicy{}
	}
	v.ContractID = strings.Clone(v.ContractID)
	v.Data = ownPublicSlice(v.Data)
	return v
}
func ownOutputTarget(v contract.OutputTarget) contract.OutputTarget {
	v.ServiceContractID, v.TargetContractID = strings.Clone(v.ServiceContractID), strings.Clone(v.TargetContractID)
	v.CanonicalTarget, v.ConsumerLocator = strings.Clone(v.CanonicalTarget), strings.Clone(v.ConsumerLocator)
	v.TargetData = ownPublicSlice(v.TargetData)
	v.Policy = ownOutputPolicy(v.Policy)
	return v
}
func outputPoliciesEqual(a, b contract.OutputPolicy) bool {
	return a.ContractID == b.ContractID && bytes.Equal(a.Data, b.Data)
}

type publicOutputInterpretationError struct {
	destinationID, entryName string
	cause                    error
}

func (e publicOutputInterpretationError) Error() string {
	return "public output interpretation refused"
}
func (e publicOutputInterpretationError) Unwrap() error { return e.cause }

type publicOutputCollisionError struct {
	subjects []contract.DiagnosticSubject
	cause    error
}

func (e publicOutputCollisionError) Error() string     { return "public output coordinates collide" }
func (e publicOutputCollisionError) Is(err error) bool { return err == contract.ErrRecord }
func (e publicOutputCollisionError) Unwrap() error     { return e.cause }

func outputApplyInputAxes(input *outputApplyInput) bool {
	if input == nil || len(input.bindings) > contract.MaxOutputBindings || len(input.routes) > contract.MaxPublicRoutingRules || len(input.groups) > contract.CryptoMaxValueEntries {
		return false
	}
	targets, members := 0, 0
	policyBytes := uint64(0)
	admitPolicyShape := func(policy contract.OutputPolicy) bool {
		length, bounded := publicOutputPolicyMinimumLength(policy)
		if !bounded || length > uint64(contract.MaxOutputDeclarationBytes)-policyBytes {
			return false
		}
		policyBytes += length
		return true
	}
	for _, binding := range input.bindings {
		targets += len(binding.targets)
		if len(binding.targets) > contract.MaxOutputTargetsPerBinding || targets > contract.MaxOutputTargets || len(binding.destination.CanonicalSettings) > contract.MaxOutputDestinationSettings {
			return false
		}
		if !admitPolicyShape(binding.destination.Policy) {
			return false
		}
	}
	for _, binding := range input.bindings {
		for _, target := range binding.targets {
			if !admitPolicyShape(target.target.Policy) {
				return false
			}
		}
	}
	for _, group := range input.groups {
		members += len(group)
		if members > contract.CryptoMaxValueEntries {
			return false
		}
	}
	return true
}

// One passive normalizer computes the target union from source declarations and
// effective routes. Offered target rows are only a consistency assertion.
func normalizeOutputApply(ctx context.Context, entries []ApplyEntryInput, recipients []contract.ID, authority contract.ID, input *outputApplyInput, interpret PublicOutputInterpreter) (*outputApplyInput, error) {
	if !outputApplyInputAxes(input) || len(entries) > contract.CryptoMaxValueEntries || len(recipients) > contract.CryptoMaxRecipients || !outputApplySourceBounded(input) {
		return nil, contract.ErrRecordCapacity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return normalizeOwnedOutputApply(ctx, entries, recipients, authority, ownOutputApplyInput(input), interpret, false)
}

// Public capture already owns these rows. The private path owns them once in
// normalizeOutputApply before entering the same checks and passive derivation.
func normalizeOwnedOutputApply(ctx context.Context, entries []ApplyEntryInput, recipients []contract.ID, authority contract.ID, input *outputApplyInput, interpret PublicOutputInterpreter, verifyOffered bool) (*outputApplyInput, error) {
	if !outputApplyInputAxes(input) || len(entries) > contract.CryptoMaxValueEntries || len(recipients) > contract.CryptoMaxRecipients {
		return nil, contract.ErrRecordCapacity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	knownRecipients := make(map[contract.ID]bool, len(recipients))
	for _, id := range recipients {
		if id.IsZero() || knownRecipients[id] {
			return nil, contract.ErrRecord
		}
		knownRecipients[id] = true
	}
	if !knownRecipients[authority] {
		return nil, contract.ErrRecord
	}
	knownEntries := make(map[string]ApplyEntryInput, len(entries))
	for _, entry := range entries {
		if (entry.InputEncoding != contract.InputEncodingRaw && entry.InputEncoding != contract.InputEncodingBase64) || (entry.OutputEncoding != contract.OutputEncodingRaw && entry.OutputEncoding != contract.OutputEncodingBase64) {
			return nil, contract.ErrRecord
		}
		if publicNameReason(entry.Name) != "" {
			return nil, contract.ErrRecord
		}
		if _, duplicate := knownEntries[entry.Name]; duplicate {
			return nil, contract.ErrRecord
		}
		seen := make(map[contract.ID]bool, len(entry.Recipients))
		for _, id := range entry.Recipients {
			if !knownRecipients[id] || seen[id] {
				return nil, contract.ErrRecord
			}
			seen[id] = true
		}
		knownEntries[entry.Name] = entry
	}
	if !outputApplySourceBounded(input) {
		return nil, contract.ErrRecordCapacity
	}
	owned := input
	slices.SortFunc(owned.bindings, func(a, b outputApplyBinding) int { return strings.Compare(a.destinationID, b.destinationID) })
	bindings := make(map[string]*outputApplyBinding, len(owned.bindings))
	for i := range owned.bindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		binding := &owned.bindings[i]
		if !publicIdentifier(binding.destinationID) || bindings[binding.destinationID] != nil {
			return nil, contract.ErrRecord
		}
		if _, err := contract.OutputDestinationLength(binding.destination); err != nil {
			return nil, err
		}
		bindings[binding.destinationID] = binding
	}
	routes := make(map[outputApplyRouteKey]*outputApplyRoute, len(owned.routes))
	for i := range owned.routes {
		route := &owned.routes[i]
		if !route.validEntrySelector() || len(route.destinations) > contract.MaxOutputRouteDestinations {
			return nil, contract.ErrRecord
		}
		if !route.defaultRoute {
			if _, present := knownEntries[route.entryName]; !present {
				return nil, contract.ErrRecord
			}
		}
		key := outputApplyRouteKey{route.defaultRoute, route.entryName}
		if routes[key] != nil {
			return nil, contract.ErrRecord
		}
		routes[key] = route
		slices.Sort(route.destinations)
		for j, name := range route.destinations {
			if bindings[name] == nil || j > 0 && route.destinations[j-1] == name {
				return nil, contract.ErrRecord
			}
		}
	}
	grouped := make(map[string]bool)
	for _, group := range owned.groups {
		if len(group) == 0 {
			return nil, contract.ErrRecord
		}
		slices.Sort(group)
		for _, name := range group {
			if _, present := knownEntries[name]; !present || grouped[name] {
				return nil, contract.ErrRecord
			}
			grouped[name] = true
		}
	}
	slices.SortFunc(owned.groups, func(a, b []string) int { return strings.Compare(a[0], b[0]) })
	needed := make(map[string]map[string]bool, len(bindings))
	for name := range bindings {
		needed[name] = make(map[string]bool)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if route := outputApplyRouteFor(routes, entry.Name); route != nil {
			for _, destination := range route.destinations {
				needed[destination][entry.Name] = true
			}
		}
	}
	declaration := uint64(6)
	for _, binding := range owned.bindings {
		length, err := contract.OutputDestinationLength(binding.destination)
		if err != nil {
			return nil, err
		}
		declaration += uint64(4 + len(binding.destinationID) + 32 + length + 2)

	}
	for _, group := range owned.groups {
		declaration += uint64(2 + 32*len(group))
	}
	if declaration > contract.MaxOutputDeclarationBytes {
		return nil, contract.ErrRecordCapacity
	}
	physical := make(map[struct{ service, target string }]bool)
	var collisions []contract.DiagnosticSubject
	refuse := func(cause error) (*outputApplyInput, error) {
		if len(collisions) != 0 {
			return nil, publicOutputCollisionError{subjects: collisions, cause: cause}
		}
		return nil, cause
	}
	derivedCount := 0
	for i := range owned.bindings {
		binding := &owned.bindings[i]
		offered := binding.targets
		if offered != nil {
			slices.SortFunc(offered, func(a, b outputApplyTarget) int { return strings.Compare(a.entryName, b.entryName) })
		}
		for j, row := range offered {
			if publicNameReason(row.entryName) != "" || j > 0 && offered[j-1].entryName == row.entryName {
				return refuse(contract.ErrRecord)
			}
			if _, present := knownEntries[row.entryName]; !present {
				return refuse(contract.ErrRecord)
			}
		}
		binding.targets = nil
		names := make([]string, 0, len(needed[binding.destinationID]))
		for name := range needed[binding.destinationID] {
			names = append(names, name)
		}
		slices.Sort(names)
		if len(names) > contract.MaxOutputTargetsPerBinding {
			return refuse(contract.ErrRecordCapacity)
		}
		derivedCount += len(names)
		if derivedCount > contract.MaxOutputTargets {
			return refuse(contract.ErrRecordCapacity)
		}

		if binding.targetsComplete && len(offered) != len(names) {
			return refuse(contract.ErrRecord)
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return refuse(err)
			}
			encoding := knownEntries[name].OutputEncoding

			offeredIndex, hasOffered := slices.BinarySearchFunc(offered, name, func(row outputApplyTarget, name string) int { return strings.Compare(row.entryName, name) })
			var target contract.OutputTarget
			if !verifyOffered && hasOffered && offered[offeredIndex].target.PayloadEncoding != encoding {
				hasOffered = false
				binding.targetsComplete = false
			}
			if hasOffered && !verifyOffered {
				target = offered[offeredIndex].target
			} else {
				if !hasOffered && binding.targetsComplete {
					return refuse(contract.ErrRecord)
				}
				if interpret == nil {
					return refuse(publicOutputInterpretationError{binding.destinationID, name, ErrPublicOutputUnavailable})
				}
				var err error
				target, err = interpret(ctx, binding.destinationID, binding.destination, name, encoding)
				if err != nil {
					return refuse(publicOutputInterpretationError{binding.destinationID, name, err})
				}
				if hasOffered && !offered[offeredIndex].target.Equal(target) {
					return refuse(publicOutputInterpretationError{binding.destinationID, name, contract.ErrRecord})
				}
			}
			if err := ctx.Err(); err != nil {
				return refuse(err)
			}
			if !target.EntryIncarnationID.IsZero() || target.ServiceContractID != binding.destination.ServiceContractID || target.PayloadEncoding != encoding || target.Capabilities & ^binding.destination.Capabilities != 0 || !outputPoliciesEqual(target.Policy, binding.destination.Policy) {
				return refuse(contract.ErrRecord)
			}
			if _, err := contract.PublicationPayloadLength(target.PayloadEncoding, 0); err != nil {
				return refuse(err)
			}
			counted := target
			counted.EntryIncarnationID = outputApplyPreviewID(1, name)
			length, err := contract.OutputTargetRowLength(counted)
			if err != nil {
				return refuse(err)
			}
			if uint64(length) > uint64(contract.MaxOutputDeclarationBytes)-declaration {
				return refuse(contract.ErrRecordCapacity)
			}
			declaration += uint64(length)
			coordinate := struct{ service, target string }{target.ServiceContractID, target.CanonicalTarget}
			if physical[coordinate] {
				collisions = append(collisions, contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: binding.destinationID, Name: name})
			}
			physical[coordinate] = true
			if hasOffered {
				binding.targets = append(binding.targets, offered[offeredIndex])
			} else {
				binding.targets = append(binding.targets, outputApplyTarget{entryName: strings.Clone(name), target: ownOutputTarget(target)})
			}

		}
		binding.targetsComplete = true
	}
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	if len(collisions) != 0 {
		return refuse(nil)
	}
	if err := outputApplyInputShape(authority, entries, owned); err != nil {
		return nil, err
	}
	if routes[outputApplyRouteKey{defaultRoute: true}] == nil {
		owned.routes = append(owned.routes, outputApplyRoute{defaultRoute: true})
	}
	slices.SortFunc(owned.routes, func(a, b outputApplyRoute) int {
		if a.defaultRoute != b.defaultRoute {
			if a.defaultRoute {
				return 1
			}
			return -1
		}
		return strings.Compare(a.entryName, b.entryName)
	})
	return owned, nil
}

func outputApplySourceBounded(input *outputApplyInput) bool {
	declaration, routing := uint64(6), uint64(5)
	for _, binding := range input.bindings {
		if !publicIdentifier(binding.destinationID) {
			return false
		}
		n, err := contract.OutputDestinationLength(binding.destination)
		if err != nil {
			return false
		}
		declaration += uint64(4 + len(binding.destinationID) + 32 + n + 2)

		if declaration > contract.MaxOutputDeclarationBytes {
			return false
		}
		for _, named := range binding.targets {
			if len(named.entryName) > contract.CryptoMaxName {
				return false
			}
			target := named.target
			target.EntryIncarnationID = outputApplyPreviewID(1, named.entryName)
			n, err := contract.OutputTargetRowLength(target)
			if err != nil {
				return false
			}
			declaration += uint64(n)
			if declaration > contract.MaxOutputDeclarationBytes {
				return false
			}
		}
	}
	for _, group := range input.groups {
		declaration += uint64(2 + 32*len(group))
		for _, name := range group {
			if len(name) > contract.CryptoMaxName {
				return false
			}
		}
	}
	for _, route := range input.routes {
		if len(route.entryName) > contract.CryptoMaxName {
			return false
		}
		if !route.defaultRoute {
			routing += 33
		}
		for _, name := range route.destinations {
			if len(name) > contract.CryptoMaxName {
				return false
			}
			routing += uint64(4 + len(name))
		}
	}
	return declaration <= contract.MaxOutputDeclarationBytes && routing <= contract.MaxOutputRoutingBytes && declaration+4+routing <= contract.MaxOutputConfigurationBytes
}

func publicOutputTarget(name string, target contract.OutputTarget) contract.PublicOutputTarget {
	return contract.PublicOutputTarget{
		EntryName:               strings.Clone(name),
		ServiceContractID:       observedPublicField(target.ServiceContractID),
		TargetContractID:        observedPublicField(target.TargetContractID),
		CanonicalTarget:         observedPublicField(target.CanonicalTarget),
		ConsumerLocator:         observedPublicField(target.ConsumerLocator),
		TargetData:              observedPublicField(target.TargetData),
		PayloadEncoding:         observedPublicField(target.PayloadEncoding),
		LocatorRequiresCreation: observedPublicField(target.LocatorRequiresCreation),
		Capabilities:            observedPublicField(target.Capabilities),
		CreateValueBounds:       observedPublicField(target.CreateValueBounds),
		WriteValueBounds:        observedPublicField(target.WriteValueBounds),
		ConsumerPolicy:          observedPublicField(target.Policy),
	}
}
func publicTargetValue(target contract.PublicOutputTarget) contract.OutputTarget {
	return contract.OutputTarget{
		ServiceContractID:       target.ServiceContractID.Value,
		TargetContractID:        target.TargetContractID.Value,
		CanonicalTarget:         target.CanonicalTarget.Value,
		ConsumerLocator:         target.ConsumerLocator.Value,
		TargetData:              target.TargetData.Value,
		PayloadEncoding:         target.PayloadEncoding.Value,
		LocatorRequiresCreation: target.LocatorRequiresCreation.Value,
		Capabilities:            target.Capabilities.Value,
		CreateValueBounds:       target.CreateValueBounds.Value,
		WriteValueBounds:        target.WriteValueBounds.Value,
		Policy:                  target.ConsumerPolicy.Value,
	}
}

func publicOutputApplyInput(configuration contract.PublicConfiguration) *outputApplyInput {
	input := &outputApplyInput{groups: configuration.Groups.Value}
	for _, binding := range configuration.OutputBindings.Value {
		row := outputApplyBinding{destinationID: binding.DestinationID, destination: binding.Destination.Value, targetsComplete: binding.Targets.State == contract.PublicPresent}
		if binding.Targets.State == contract.PublicPresent {
			row.targets = make([]outputApplyTarget, 0, len(binding.Targets.Value))
			for _, target := range binding.Targets.Value {
				row.targets = append(row.targets, outputApplyTarget{entryName: target.EntryName, target: publicTargetValue(target)})
			}
		}
		input.bindings = append(input.bindings, row)
	}
	for _, route := range configuration.Routing.Value {
		input.routes = append(input.routes, outputApplyRoute{defaultRoute: route.Key.EntrySelector == contract.PublicDefaultRoute, entryName: route.Key.EntryName, destinations: route.Destinations.Value})
	}
	return input
}

// Default-route meaning depends only on the checked route collection. An
// unrelated unavailable Store, key or plain value cannot turn it into absence.
func normalizePublicDefaultRoute(c *publicConfigurationCheck, configuration *contract.PublicConfiguration) {
	if slices.ContainsFunc(configuration.Routing.Value, func(route contract.PublicRoutingRule) bool {
		return route.Key.EntrySelector == contract.PublicDefaultRoute
	}) {
		return
	}
	if len(configuration.Routing.Value) == contract.MaxPublicRoutingRules {
		c.add(contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule}, contract.FieldPresence, contract.ReasonLimitExceeded, configuration.Routing.SourceLocation)
		c.invalidRouting = true
		return
	}
	rows := make([]contract.PublicRoutingRule, len(configuration.Routing.Value)+1)
	copy(rows, configuration.Routing.Value)
	rows[len(rows)-1] = contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: observedPublicField([]string(nil))}
	slices.SortFunc(rows, func(a, b contract.PublicRoutingRule) int { return comparePublicRoutingKeys(a.Key, b.Key) })
	configuration.Routing.Value = rows
}

func (v *PublicConfigurationValidator) normalizePublicOutputs(c *publicConfigurationCheck, configuration *contract.PublicConfiguration, verifyOffered bool) bool {
	entries := make([]ApplyEntryInput, len(configuration.Entries.Value))
	for i, entry := range configuration.Entries.Value {
		entries[i] = ApplyEntryInput{Name: entry.Name, Recipients: entry.Memberships.Value, InputEncoding: entry.InputEncoding.Value, OutputEncoding: entry.OutputEncoding.Value}
	}
	recipients := make([]contract.ID, len(configuration.Recipients.Value))
	for i, recipient := range configuration.Recipients.Value {
		recipients[i] = recipient.RecipientID
	}
	input := publicOutputApplyInput(*configuration)
	normalized, err := normalizeOwnedOutputApply(c.ctx, entries, recipients, configuration.Authority.RecipientID.Value, input, v.interpret, verifyOffered)
	if err != nil {
		var collisions publicOutputCollisionError
		if errors.As(err, &collisions) {
			for _, subject := range collisions.subjects {
				c.add(subject, contract.FieldCanonicalTarget, contract.ReasonDuplicateKey, nil)
			}
			err = collisions.cause
			if err == nil {
				return true
			}
		}
		reason := publicErrorReason(err)
		if errors.Is(err, ErrPublicOutputUnavailable) {
			reason = contract.ReasonPublicFactUnavailable
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			reason = publicContextReason(err)
		}
		if contextErr := c.ctx.Err(); contextErr != nil {
			reason = publicContextReason(contextErr)
		}
		var interpretation publicOutputInterpretationError
		if errors.As(err, &interpretation) {
			attributed := false
			for _, field := range []contract.DiagnosticField{contract.FieldServiceContract, contract.FieldTargetContract, contract.FieldCanonicalTarget, contract.FieldConsumerLocator, contract.FieldTargetData, contract.FieldPayloadEncoding, contract.FieldLocatorRequiresCreation, contract.FieldCapabilities, contract.FieldCreateValueBounds, contract.FieldWriteValueBounds, contract.FieldConsumerPolicy} {
				if errors.Is(err, PublicOutputError{Field: field}) {
					c.add(contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: interpretation.destinationID, Name: interpretation.entryName}, field, reason, nil)
					attributed = true
				}
			}
			if !attributed {
				c.add(contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: interpretation.destinationID}, contract.FieldTargets, reason, nil)
			}
		} else {
			c.add(contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldPresence, reason, nil)
		}
		if reason == contract.ReasonLimitExceeded {
			return false
		}
		return true
	}
	configuration.Groups.State, configuration.Groups.Value = contract.PublicPresent, normalized.groups

	for i, binding := range normalized.bindings {
		row := &configuration.OutputBindings.Value[i]
		row.Destination.State, row.Destination.Value = contract.PublicPresent, binding.destination
		if row.Targets.State == contract.PublicPresent {
			for j, target := range binding.targets {
				current := &row.Targets.Value[j]
				t := target.target
				current.ServiceContractID.Value = t.ServiceContractID
				current.TargetContractID.Value = t.TargetContractID
				current.CanonicalTarget.Value = t.CanonicalTarget
				current.ConsumerLocator.Value = t.ConsumerLocator
				current.TargetData.Value = t.TargetData
				current.PayloadEncoding.Value = t.PayloadEncoding
				current.LocatorRequiresCreation.Value = t.LocatorRequiresCreation
				current.Capabilities.Value = t.Capabilities
				current.CreateValueBounds.Value = t.CreateValueBounds
				current.WriteValueBounds.Value = t.WriteValueBounds
				current.ConsumerPolicy.Value = t.Policy
			}
			continue
		}
		row.Targets.State = contract.PublicPresent
		row.Targets.Value = make([]contract.PublicOutputTarget, 0, len(binding.targets))
		for _, target := range binding.targets {
			t := target.target
			row.Targets.Value = append(row.Targets.Value, publicOutputTarget(target.entryName, t))
		}
	}
	return true
}

// outputSourceInput recovers desired source meaning from the authenticated
// configuration. Provider creation results never enter these declarations.
func (s *StateSession) outputSourceInput(configuration contract.OutputConfiguration, desired []ApplyEntryInput) (*outputApplyInput, error) {
	names := make(map[contract.ID]string, len(s.root.Names))
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		if entry == nil {
			return nil, contract.ErrRecord
		}
		names[entry.Incarnation] = entry.Name
	}
	intended := make(map[string]ApplyEntryInput, len(desired))
	for _, entry := range desired {
		intended[entry.Name] = entry
	}
	input := &outputApplyInput{}
	for _, binding := range configuration.Bindings {
		row := outputApplyBinding{destinationID: binding.DestinationID, destination: binding.Destination}

		for _, target := range binding.Targets {
			name, present := names[target.EntryIncarnationID]
			if !present {
				return nil, contract.ErrRecord
			}
			if _, present := intended[name]; present {
				target.EntryIncarnationID = contract.ID{}
				row.targets = append(row.targets, outputApplyTarget{entryName: name, target: target})
			}
		}
		input.bindings = append(input.bindings, row)
	}
	input.routes = append(input.routes, outputApplyRoute{defaultRoute: true, destinations: configuration.DefaultDestinations})
	for _, route := range configuration.Routes {
		name, present := names[route.EntryIncarnationID]
		if !present {
			return nil, contract.ErrRecord
		}
		if _, present := intended[name]; !present {
			continue
		}
		input.routes = append(input.routes, outputApplyRoute{entryName: name, destinations: route.Destinations})
	}
	for _, selected := range configuration.Groups {
		var group []string
		for _, incarnation := range selected {
			name, present := names[incarnation]
			if !present {
				return nil, contract.ErrRecord
			}
			if _, present := intended[name]; present {
				group = append(group, name)
			}
		}
		if len(group) != 0 {
			input.groups = append(input.groups, group)
		}
	}
	return input, nil
}

func generatedDeclarationOutputEntries(declaration contract.GeneratorDeclarationView) ([]ApplyEntryInput, error) {
	entries := make([]ApplyEntryInput, declaration.EntryCount())
	for i := range entries {
		entry, _, err := declaration.Entry(i)
		if err != nil {
			return nil, err
		}
		entries[i] = ApplyEntryInput{Name: string(entry.Name), InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding}
		for offset := 0; offset < len(entry.RecipientIDs); offset += len(contract.ID{}) {
			entries[i].Recipients = append(entries[i].Recipients, contract.ID(entry.RecipientIDs[offset:offset+len(contract.ID{})]))
		}
	}
	return entries, nil
}
