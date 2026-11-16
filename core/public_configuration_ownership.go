package core

import (
	"reflect"
	"slices"
	"strings"

	"enkv.sh/core/contract"
)

func publicConfigurationInputLimits(c *publicConfigurationCheck, v contract.PublicConfiguration) bool {
	ok := true
	limit := func(subject contract.DiagnosticSubject, field contract.DiagnosticField, n, maximum int) {
		if n > maximum {
			c.add(subject, field, contract.ReasonLimitExceeded, nil)
			ok = false
		}
	}
	configuration := contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}
	store := contract.DiagnosticSubject{Kind: contract.SubjectStore}
	checkPublicField(c, store, contract.FieldProvider, v.Store.Provider, publicFamilyReason)
	limit(store, contract.FieldRegion, len(v.Store.Region.Value), 64)
	limit(store, contract.FieldBucket, len(v.Store.Bucket.Value), 222)
	limit(store, contract.FieldPrefix, len(v.Store.Prefix.Value), contract.MaxStorePrefixLength)
	limit(store, contract.FieldExpectedOwner, len(v.Store.ExpectedOwner.Value), 12)
	limit(configuration, contract.FieldPresence, len(v.Entries.Value), contract.CryptoMaxValueEntries)
	limit(contract.DiagnosticSubject{Kind: contract.SubjectRecipient}, contract.FieldPresence, len(v.Recipients.Value), contract.CryptoMaxRecipients)
	limit(contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding}, contract.FieldPresence, len(v.OutputBindings.Value), contract.MaxOutputBindings)
	limit(contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule}, contract.FieldPresence, len(v.Routing.Value), contract.MaxPublicRoutingRules)
	limit(configuration, contract.FieldPresence, len(v.Groups.Value), contract.CryptoMaxValueEntries)
	if !ok {
		return false
	}
	targetCount, groupCount := 0, 0
	policyBytes := uint64(0)
	admitPolicy := func(p contract.OutputPolicy) bool {
		n, bounded := publicOutputPolicyMinimumLength(p)
		if !bounded || n > uint64(contract.MaxOutputDeclarationBytes)-policyBytes {
			c.add(configuration, contract.FieldPresence, contract.ReasonLimitExceeded, nil)
			return false
		}
		policyBytes += n
		return true
	}
	for _, binding := range v.OutputBindings.Value {
		if len(binding.Targets.Value) > contract.MaxOutputTargetsPerBinding || len(binding.Targets.Value) > contract.MaxOutputTargets-targetCount || len(binding.Destination.Value.CanonicalSettings) > contract.MaxOutputDestinationSettings {
			c.add(configuration, contract.FieldPresence, contract.ReasonLimitExceeded, nil)
			return false
		}
		targetCount += len(binding.Targets.Value)

		if !admitPolicy(binding.Destination.Value.Policy) {
			return false
		}
	}
	for _, binding := range v.OutputBindings.Value {
		for _, target := range binding.Targets.Value {
			if !admitPolicy(target.ConsumerPolicy.Value) {
				return false
			}
		}
	}
	for _, group := range v.Groups.Value {
		if len(group) > contract.CryptoMaxValueEntries-groupCount {
			c.add(configuration, contract.FieldPresence, contract.ReasonLimitExceeded, nil)
			return false
		}
		groupCount += len(group)
	}
	if !publicConfigurationBackingBounded(v) {
		c.add(configuration, contract.FieldPresence, contract.ReasonLimitExceeded, nil)
		return false
	}
	if err := c.ctx.Err(); err != nil {
		c.add(configuration, contract.FieldPresence, publicContextReason(err), nil)
		return false
	}
	keyLimits := func(subject contract.DiagnosticSubject, selector contract.PublicField[string], key contract.PublicField[[]byte], signing bool) {
		field, bytesField, maximum := contract.FieldEncryptionSelector, contract.FieldEncryptionPublicKey, contract.KMSPublicKeyLength
		if signing {
			field, bytesField, maximum = contract.FieldSigningSelector, contract.FieldSigningPublicKey, contract.MaxPublicKey
		}
		limit(subject, field, len(selector.Value), contract.MaxKeySelector)
		limit(subject, bytesField, len(key.Value), maximum)
	}
	for _, entry := range v.Entries.Value {
		if err := c.ctx.Err(); err != nil {
			c.add(configuration, contract.FieldPresence, publicContextReason(err), nil)
			return false
		}
		subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: entry.Name}
		if publicNameReason(entry.Name) != "" {
			subject = configuration
		}
		limit(configuration, contract.FieldPresence, len(entry.Name), contract.CryptoMaxName)
		limit(subject, contract.FieldPlainValue, len(entry.PlainValue.Value), contract.CryptoMaxRetainedValue)
		limit(subject, contract.FieldMemberships, len(entry.Memberships.Value), contract.CryptoMaxValueEntryRecipients)
		if entry.Generated != nil {
			limit(subject, contract.FieldContentIntent, len(entry.Generated.ContentIntent.Value), contract.GeneratorIntentMaxLength)
		}
	}
	for _, recipient := range v.Recipients.Value {
		subject := contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: recipient.RecipientID}
		limit(subject, contract.FieldDisplayName, len(recipient.DisplayName.Value), contract.CryptoMaxName)
		keyLimits(subject, recipient.Encryption.Selector, recipient.Encryption.PublicKey, false)
	}
	keyLimits(contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, v.Authority.Signing.Selector, v.Authority.Signing.PublicKey, true)
	if v.Recovery.Signing != nil {
		keyLimits(contract.DiagnosticSubject{Kind: contract.SubjectRecovery}, v.Recovery.Signing.Selector, v.Recovery.Signing.PublicKey, true)
	}
	if v.Recovery.Encryption != nil {
		keyLimits(contract.DiagnosticSubject{Kind: contract.SubjectRecovery}, v.Recovery.Encryption.Selector, v.Recovery.Encryption.PublicKey, false)
	}
	for _, binding := range v.OutputBindings.Value {
		if err := c.ctx.Err(); err != nil {
			c.add(configuration, contract.FieldPresence, publicContextReason(err), nil)
			return false
		}
		subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: binding.DestinationID}
		if !publicIdentifier(binding.DestinationID) {
			subject = configuration
		}
		limit(configuration, contract.FieldPresence, len(binding.DestinationID), contract.CryptoMaxName)
		d := binding.Destination.Value
		limit(subject, contract.FieldDestination, len(d.ConfigContractID), 256)
		limit(subject, contract.FieldDestination, len(d.ServiceContractID), 256)
		limit(subject, contract.FieldDestination, len(d.CanonicalSettings), contract.MaxOutputDestinationSettings)
		limit(subject, contract.FieldDestination, len(d.Policy.ContractID), 256)
		limit(subject, contract.FieldDestination, len(d.Policy.Data), contract.MaxOutputPolicyBytes)

		for _, target := range binding.Targets.Value {
			if err := c.ctx.Err(); err != nil {
				c.add(configuration, contract.FieldPresence, publicContextReason(err), nil)
				return false
			}
			subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: binding.DestinationID, Name: target.EntryName}
			if publicNameReason(target.EntryName) != "" || !publicIdentifier(binding.DestinationID) {
				subject = configuration
			}
			limit(configuration, contract.FieldPresence, len(target.EntryName), contract.CryptoMaxName)
			limit(subject, contract.FieldServiceContract, len(target.ServiceContractID.Value), 256)
			limit(subject, contract.FieldTargetContract, len(target.TargetContractID.Value), 256)
			limit(subject, contract.FieldCanonicalTarget, len(target.CanonicalTarget.Value), 1024)
			limit(subject, contract.FieldConsumerLocator, len(target.ConsumerLocator.Value), 1024)
			limit(subject, contract.FieldTargetData, len(target.TargetData.Value), contract.MaxOutputTargetDataBytes)
			limit(subject, contract.FieldConsumerPolicy, len(target.ConsumerPolicy.Value.ContractID), 256)
			limit(subject, contract.FieldConsumerPolicy, len(target.ConsumerPolicy.Value.Data), contract.MaxOutputPolicyBytes)
		}
	}
	for _, route := range v.Routing.Value {
		if err := c.ctx.Err(); err != nil {
			c.add(configuration, contract.FieldPresence, publicContextReason(err), nil)
			return false
		}
		subject := contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: route.Key}
		if publicNameReason(route.Key.EntryName) != "" || !publicRoutingKeyValid(route.Key) {
			subject = configuration
		}
		limit(configuration, contract.FieldPresence, len(route.Key.EntryName), contract.CryptoMaxName)
		limit(subject, contract.FieldDestinations, len(route.Destinations.Value), contract.MaxOutputRouteDestinations)
		if len(route.Destinations.Value) <= contract.MaxOutputRouteDestinations {
			for _, name := range route.Destinations.Value {
				limit(subject, contract.FieldDestinations, len(name), contract.CryptoMaxName)
			}
		}
	}
	for _, group := range v.Groups.Value {
		for _, name := range group {
			if reason := publicNameReason(name); reason != "" {
				c.add(configuration, contract.FieldGroups, reason, nil)
				ok = false
			}
		}
	}
	return ok
}

// Admission checks the independent byte/count axes before any collection or
// application-byte copy. Larger public sets cannot inherit mutation limits.
func publicConfigurationBounded(v contract.PublicConfiguration) bool {
	if len(v.Entries.Value) > contract.CryptoMaxValueEntries || len(v.Recipients.Value) > contract.CryptoMaxRecipients || len(v.OutputBindings.Value) > contract.MaxOutputBindings || len(v.Routing.Value) > contract.MaxPublicRoutingRules || len(v.Groups.Value) > contract.CryptoMaxValueEntries {
		return false
	}
	logical, retained, intents, memberships, generated, registry, declaration, routing, targets := uint64(0), uint64(0), uint64(0), uint64(0), 0, uint64(6), uint64(6), uint64(5), 0
	for _, entry := range v.Entries.Value {
		if len(entry.PlainValue.Value) > contract.CryptoMaxRetainedValue || len(entry.Memberships.Value) > contract.CryptoMaxValueEntryRecipients {
			return false
		}
		encoding := entry.InputEncoding.Value
		if entry.InputEncoding.State == contract.PublicMissing && encoding == 0 {
			encoding = contract.InputEncodingRaw
		}
		content, err := contract.InputContentLength(encoding, entry.PlainValue.Value)
		// Capacity is an admission constraint. A bounded malformed or unknown
		// representation belongs to its field owner, so independent facts remain
		// available even when this value has no application meaning.
		if err == contract.ErrRecordCapacity {
			return false
		}
		logical += uint64(content)
		retained += uint64(len(entry.PlainValue.Value))
		memberships += uint64(len(entry.Memberships.Value))
		if entry.Generated != nil {
			g := entry.Generated
			generated++
			if len(g.ContentIntent.Value) > contract.GeneratorIntentMaxLength {
				return false
			}
			intents += uint64(len(g.ContentIntent.Value))
		}
	}
	if logical > contract.CryptoMaxRawSet || retained > contract.CryptoMaxRetainedSet || memberships > contract.CryptoMaxMemberships || generated > contract.GeneratedCurrentEntryLimit || intents > contract.MaxPublicGeneratedIntents {
		return false
	}
	encryptionBounded := func(e contract.PublicEncryptionSettings) bool {
		return len(e.PublicKey.Value) <= contract.KMSPublicKeyLength && len(e.Selector.Value) <= contract.MaxKeySelector
	}
	signingBounded := func(s contract.PublicSigningSettings) bool {
		return len(s.PublicKey.Value) <= contract.MaxPublicKey && len(s.Selector.Value) <= contract.MaxKeySelector
	}
	for _, recipient := range v.Recipients.Value {
		if !encryptionBounded(recipient.Encryption) {
			return false
		}
		registry += uint64(41 + len(recipient.DisplayName.Value) + contract.KMSBindingMaxLength)
	}
	if registry > contract.MaxPublicRegistryBytes || !signingBounded(v.Authority.Signing) {
		return false
	}
	if v.Recovery.Signing != nil && !signingBounded(*v.Recovery.Signing) || v.Recovery.Encryption != nil && !encryptionBounded(*v.Recovery.Encryption) {
		return false
	}
	groupMembers := 0
	nestedNameExpansion := uint64(0)
	for _, binding := range v.OutputBindings.Value {
		if len(binding.Targets.Value) > contract.MaxOutputTargetsPerBinding || len(binding.Targets.Value) > contract.MaxOutputTargets-targets {
			return false
		}

		destination := binding.Destination.Value
		destinationPolicyLength, ok := publicOutputPolicyBoundedLength(destination.Policy)
		if !ok {
			return false
		}
		destinationLength := 17 + len(destination.ConfigContractID) + len(destination.ServiceContractID) + len(destination.CanonicalSettings) + destinationPolicyLength
		declaration += uint64(4 + len(binding.DestinationID) + 32 + destinationLength + 2)
		if declaration > contract.MaxOutputDeclarationBytes {
			return false
		}

		if declaration > contract.MaxOutputDeclarationBytes {
			return false
		}
		for _, target := range binding.Targets.Value {
			targets++
			policyLength, ok := publicOutputPolicyBoundedLength(target.ConsumerPolicy.Value)
			if !ok {
				return false
			}
			declaration += uint64(75 + len(target.ServiceContractID.Value) + len(target.TargetContractID.Value) + len(target.CanonicalTarget.Value) + len(target.ConsumerLocator.Value) + len(target.TargetData.Value) + policyLength)
			if declaration > contract.MaxOutputDeclarationBytes {
				return false
			}
		}
	}
	for _, group := range v.Groups.Value {
		if len(group) > contract.CryptoMaxValueEntries-groupMembers {
			return false
		}
		groupMembers += len(group)
		for _, name := range group {
			if publicNameReason(name) != "" {
				return false
			}
			nestedNameExpansion += uint64(max(0, len(name)-32))
		}
		declaration += 2 + 32*uint64(len(group))
	}
	if targets > contract.MaxOutputTargets || declaration > contract.MaxOutputDeclarationBytes {
		return false
	}
	for _, route := range v.Routing.Value {
		if len(route.Destinations.Value) > contract.MaxOutputRouteDestinations {
			return false
		}
		if route.Key.EntrySelector != contract.PublicDefaultRoute {
			routing += 33
		}
		for _, name := range route.Destinations.Value {
			routing += uint64(4 + len(name))
		}
	}
	if routing > contract.MaxOutputRoutingBytes || declaration+4+routing > contract.MaxOutputConfigurationBytes {
		return false
	}
	semantic := retained + intents + registry + declaration + 4 + routing + uint64(len(v.Entries.Value))*4096 + uint64(targets+len(v.Routing.Value))*232 + nestedNameExpansion + (64 << 10)
	return semantic <= contract.MaxPublicConfigurationBytes
}

// Count every opaque policy occurrence before cloning, including shared backing.
func publicOutputPolicyMinimumLength(policy contract.OutputPolicy) (uint64, bool) {
	if len(policy.ContractID) > 256 || len(policy.Data) > contract.MaxOutputPolicyBytes {
		return 0, false
	}
	if policy.ContractID == "" && len(policy.Data) == 0 {
		return 0, true
	}
	return uint64(10 + len(policy.ContractID) + len(policy.Data)), true
}
func publicOutputPolicyBoundedLength(policy contract.OutputPolicy) (int, bool) {
	n, ok := publicOutputPolicyMinimumLength(policy)
	return int(n), ok
}

func ownPublicField[T any](v contract.PublicField[T]) contract.PublicField[T] {
	if v.State == contract.PublicPresent {
		if value, ok := any(v.Value).(string); ok && len(value) <= 1024 {
			v.Value = any(strings.Clone(value)).(T)
		}
	}
	if v.SourceLocation != nil {
		source := *v.SourceLocation
		if len(source.SourceID) <= 64 {
			source.SourceID = strings.Clone(source.SourceID)
		}
		v.SourceLocation = &source
	}
	return v
}

func ownPublicBytes(v contract.PublicField[[]byte]) contract.PublicField[[]byte] {
	v = ownPublicField(v)
	v.Value = ownPublicSlice(v.Value)
	return v
}

func ownPublicIDs(v contract.PublicField[[]contract.ID]) contract.PublicField[[]contract.ID] {
	v = ownPublicField(v)
	v.Value = ownPublicSlice(v.Value)
	if v.State == contract.PublicPresent {
		slices.SortFunc(v.Value, comparePublicIDs)
	}
	return v
}

func ownPublicEncryption(v contract.PublicEncryptionSettings) contract.PublicEncryptionSettings {
	v.Provider = ownPublicField(v.Provider)
	v.Selector = ownPublicField(v.Selector)
	v.PublicKey = ownPublicBytes(v.PublicKey)
	v.Fingerprint = ownPublicField(v.Fingerprint)
	v.WrapProfile = ownPublicField(v.WrapProfile)
	v.ProtectionClass = ownPublicField(v.ProtectionClass)
	return v
}

func ownPublicSigning(v contract.PublicSigningSettings) contract.PublicSigningSettings {
	v.Provider = ownPublicField(v.Provider)
	v.Selector = ownPublicField(v.Selector)
	v.PublicKey = ownPublicBytes(v.PublicKey)
	v.Fingerprint = ownPublicField(v.Fingerprint)
	v.Role = ownPublicField(v.Role)
	v.Profile = ownPublicField(v.Profile)
	return v
}

func ownPublicConfiguration(v contract.PublicConfiguration) contract.PublicConfiguration {
	v.Groups = ownPublicField(v.Groups)
	if v.Groups.State == contract.PublicMissing && v.Groups.Value == nil {
		v.Groups.State = contract.PublicPresent
	}
	if v.Groups.State == contract.PublicPresent {
		v.Groups.Value = ownPublicSlice(v.Groups.Value)
		for i := range v.Groups.Value {
			v.Groups.Value[i] = ownPublicSlice(v.Groups.Value[i])
			for j := range v.Groups.Value[i] {
				v.Groups.Value[i][j] = strings.Clone(v.Groups.Value[i][j])
			}
			slices.Sort(v.Groups.Value[i])
		}
		slices.SortFunc(v.Groups.Value, func(a, b []string) int {
			if len(a) == 0 || len(b) == 0 {
				return len(a) - len(b)
			}
			return strings.Compare(a[0], b[0])
		})
	} else {
		if v.Groups.Value != nil {
			v.Groups.State = contract.PublicInvalid
		}
		v.Groups.Value = nil
	}
	v.Entries = ownPublicField(v.Entries)
	if v.Entries.State == contract.PublicPresent {
		v.Entries.Value = ownPublicSlice(v.Entries.Value)
		for i := range v.Entries.Value {
			e := &v.Entries.Value[i]
			if len(e.Name) <= contract.CryptoMaxName {
				e.Name = strings.Clone(e.Name)
			}
			e.Class = ownPublicField(e.Class)
			e.Source = ownPublicField(e.Source)
			e.InputEncoding = ownPublicField(e.InputEncoding)
			e.OutputEncoding = ownPublicField(e.OutputEncoding)
			if e.Class.State == contract.PublicPresent && e.Class.Value == contract.Plain {
				e.PlainValue = ownPublicBytes(e.PlainValue)
			} else {
				e.PlainValue = ownPublicField(e.PlainValue)
				if e.PlainValue.Value != nil && e.PlainValue.State != contract.PublicPresent {
					e.PlainValue.State = contract.PublicInvalid
				}
				e.PlainValue.Value = nil
			}
			e.Memberships = ownPublicIDs(e.Memberships)
			if e.Generated != nil {
				g := *e.Generated
				g.Epoch = ownPublicField(g.Epoch)
				g.ConfigContractID = ownPublicField(g.ConfigContractID)
				g.ResourceContractID = ownPublicField(g.ResourceContractID)
				g.LifecycleMode = ownPublicField(g.LifecycleMode)
				g.ContentIntent = ownPublicBytes(g.ContentIntent)
				g.Retirement = ownPublicField(g.Retirement)
				g.Completion = ownPublicField(g.Completion)
				e.Generated = &g
			}
		}
		slices.SortFunc(v.Entries.Value, func(a, b contract.PublicEntry) int { return strings.Compare(a.Name, b.Name) })
	}
	v.Recipients = ownPublicField(v.Recipients)
	if v.Recipients.State == contract.PublicPresent {
		v.Recipients.Value = ownPublicSlice(v.Recipients.Value)
		for i := range v.Recipients.Value {
			r := &v.Recipients.Value[i]
			r.DisplayName = ownPublicField(r.DisplayName)
			r.Encryption = ownPublicEncryption(r.Encryption)
		}
		slices.SortFunc(v.Recipients.Value, func(a, b contract.PublicRecipient) int { return comparePublicIDs(a.RecipientID, b.RecipientID) })
	}
	v.OutputBindings = ownPublicField(v.OutputBindings)
	if v.OutputBindings.State == contract.PublicPresent {
		v.OutputBindings.Value = ownPublicSlice(v.OutputBindings.Value)
		for i := range v.OutputBindings.Value {
			binding := &v.OutputBindings.Value[i]
			if len(binding.DestinationID) <= contract.CryptoMaxName {
				binding.DestinationID = strings.Clone(binding.DestinationID)
			}
			binding.Targets = ownPublicField(binding.Targets)
			binding.Destination = ownPublicField(binding.Destination)
			if binding.Destination.State == contract.PublicPresent {
				binding.Destination.Value = ownOutputDestination(binding.Destination.Value)
			} else {
				if !reflect.ValueOf(binding.Destination.Value).IsZero() {
					binding.Destination.State = contract.PublicInvalid
				}
				binding.Destination.Value = contract.OutputDestination{}
			}
			if binding.Targets.State != contract.PublicPresent {
				if binding.Targets.Value != nil {
					binding.Targets.State = contract.PublicInvalid
				}
				binding.Targets.Value = nil
				continue
			}
			binding.Targets.Value = ownPublicSlice(binding.Targets.Value)
			for j := range binding.Targets.Value {
				target := &binding.Targets.Value[j]
				if len(target.EntryName) <= contract.CryptoMaxName {
					target.EntryName = strings.Clone(target.EntryName)
				}
				target.ServiceContractID = ownPublicField(target.ServiceContractID)
				target.TargetContractID = ownPublicField(target.TargetContractID)
				target.CanonicalTarget = ownPublicField(target.CanonicalTarget)
				target.ConsumerLocator = ownPublicField(target.ConsumerLocator)
				target.TargetData = ownPublicBytes(target.TargetData)
				target.PayloadEncoding = ownPublicField(target.PayloadEncoding)
				target.LocatorRequiresCreation = ownPublicField(target.LocatorRequiresCreation)
				target.Capabilities = ownPublicField(target.Capabilities)
				target.CreateValueBounds = ownPublicField(target.CreateValueBounds)
				target.WriteValueBounds = ownPublicField(target.WriteValueBounds)
				target.ConsumerPolicy = ownPublicField(target.ConsumerPolicy)
				target.ConsumerPolicy.Value = ownOutputPolicy(target.ConsumerPolicy.Value)
			}
			slices.SortFunc(binding.Targets.Value, func(a, b contract.PublicOutputTarget) int { return strings.Compare(a.EntryName, b.EntryName) })
		}
		slices.SortFunc(v.OutputBindings.Value, func(a, b contract.PublicOutputBinding) int { return strings.Compare(a.DestinationID, b.DestinationID) })
	}
	v.Routing = ownPublicField(v.Routing)
	if v.Routing.State == contract.PublicPresent {
		v.Routing.Value = ownPublicSlice(v.Routing.Value)
		for i := range v.Routing.Value {
			r := &v.Routing.Value[i]
			if len(r.Key.EntryName) <= contract.CryptoMaxName {
				r.Key.EntryName = strings.Clone(r.Key.EntryName)
			}
			r.Destinations = ownPublicField(r.Destinations)
			if r.Destinations.State == contract.PublicPresent {
				r.Destinations.Value = ownPublicSlice(r.Destinations.Value)
				for k := range r.Destinations.Value {
					if len(r.Destinations.Value[k]) <= contract.CryptoMaxName {
						r.Destinations.Value[k] = strings.Clone(r.Destinations.Value[k])
					}
				}
				slices.Sort(r.Destinations.Value)
			}
		}
		slices.SortFunc(v.Routing.Value, func(a, b contract.PublicRoutingRule) int { return comparePublicRoutingKeys(a.Key, b.Key) })
	}
	s := &v.Store
	s.DomainID = ownPublicField(s.DomainID)
	s.Provider = ownPublicField(s.Provider)
	s.ConstructionProfile = ownPublicField(s.ConstructionProfile)
	s.Region = ownPublicField(s.Region)
	s.Bucket = ownPublicField(s.Bucket)
	s.Prefix = ownPublicField(s.Prefix)
	s.ExpectedOwner = ownPublicField(s.ExpectedOwner)
	v.Authority.RecipientID = ownPublicField(v.Authority.RecipientID)
	v.Authority.Signing = ownPublicSigning(v.Authority.Signing)
	v.Recovery.Enabled = ownPublicField(v.Recovery.Enabled)
	if v.Recovery.Signing != nil {
		s := ownPublicSigning(*v.Recovery.Signing)
		v.Recovery.Signing = &s
	}
	if v.Recovery.Encryption != nil {
		e := ownPublicEncryption(*v.Recovery.Encryption)
		v.Recovery.Encryption = &e
	}
	return v
}

func comparePublicRoutingKeys(a, b contract.PublicRoutingKey) int {
	if a.EntrySelector < b.EntrySelector {
		return -1
	}
	if a.EntrySelector > b.EntrySelector {
		return 1
	}
	return strings.Compare(a.EntryName, b.EntryName)
}

func ownPublicSlice[T any](source []T) []T {
	if source == nil {
		return nil
	}
	owned := make([]T, len(source))
	copy(owned, source)
	return owned
}
