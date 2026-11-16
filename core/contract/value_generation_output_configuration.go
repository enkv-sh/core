package contract

import (
	"bytes"
	"slices"
)

// GeneratedOutputTransition pins the actual selected predecessor of one
// private phase. All these facts are recoverable from its mandatory selected
// state; it carries no desired declaration or historical-root dependency.
type GeneratedOutputTransition struct {
	Before           OutputConfiguration
	BeforeDescriptor OutputConfigurationDescriptor
	EntriesBefore    []MembershipRow
	EntryBodies      [][]byte
	Rows             GeneratedSupportRows // Output bodies and complete predecessor row facts.
	Retained         []SupportRecord
	Bindings         []NormalOutputBinding
	Routes           []NormalOutputRoute
	Groups           [][]string
}

// InspectGeneratedOutputConfiguration checks the committed image and its exact
// planned entry identities. Current-entry recovery cannot interpret this image.
func InspectGeneratedOutputConfiguration(graph GeneratorPlanBundle, image []byte) (OutputConfiguration, error) {
	if graph.Request.Schema != GeneratorApplyRequestCoreSchema || graph.Request.OperationKind != OperationApplyDeclaration {
		return OutputConfiguration{}, ErrRecord
	}
	configuration, routing, err := InspectOutputConfiguration(graph.Request.DomainID, image)
	if err != nil {
		return OutputConfiguration{}, err
	}
	descriptor := outputConfigurationImageDescriptor(graph.Request.DomainID, image, uint16(len(configuration.Bindings)), routing)
	if descriptor != graph.Request.OutputConfiguration {
		return OutputConfiguration{}, ErrRecord
	}
	entries := make(map[ID]uint8, len(graph.ValueEntryPlans))
	for _, entry := range graph.ValueEntryPlans {
		if entry.EntryIncarnationID.IsZero() || entries[entry.EntryIncarnationID] != 0 || entry.OutputEncoding != OutputEncodingRaw && entry.OutputEncoding != OutputEncodingBase64 {
			return OutputConfiguration{}, ErrRecord
		}
		entries[entry.EntryIncarnationID] = entry.OutputEncoding
	}
	for _, binding := range configuration.Bindings {
		for _, target := range binding.Targets {
			if entries[target.EntryIncarnationID] != target.PayloadEncoding {
				return OutputConfiguration{}, ErrRecord
			}
		}
	}
	for _, group := range configuration.Groups {
		for _, entry := range group {
			if entries[entry] == 0 {
				return OutputConfiguration{}, ErrRecord
			}
		}
	}
	for _, route := range configuration.Routes {
		if !route.EntryIncarnationID.IsZero() && entries[route.EntryIncarnationID] == 0 {
			return OutputConfiguration{}, ErrRecord
		}
	}
	return configuration, nil
}

func (v *GeneratedOutputTransition) ConfigurationAfter(operation ID, plans []GeneratorValueEntryPlan) (OutputConfiguration, error) {
	normal, identity, err := v.rebindIntent(operation, plans)
	if err != nil {
		return OutputConfiguration{}, err
	}
	return normal.configurationAfter(identity)
}

func outputSupportKind(kind uint8) bool {
	return kind == PublicationCoordinateSupportKind || kind == PublicationMarkerSupportKind || kind == OutputConfigurationSliceSupportKind
}

func (v *GeneratedOutputTransition) Inspect(before PublicState) error {
	if v == nil || v.Before.DomainID != before.Domain || len(v.EntriesBefore) != len(before.Rows) || len(v.EntryBodies) != len(v.EntriesBefore) {
		return ErrRecord
	}
	if err := normalOutputOwnershipBounds(&NormalOutputTransition{Before: v.Before, EntriesBefore: v.EntriesBefore, Bindings: v.Bindings, Routes: v.Routes, Groups: v.Groups}); err != nil {
		return err
	}
	if _, err := GrantDescriptor(before.Domain, v.EntriesBefore); err != nil {
		return err
	}
	var raw uint64
	for i, entry := range v.EntriesBefore {
		row := before.Rows[i]
		if entry.Name != row.Name || entry.Slot != row.Slot || entry.EntryDigest != row.EntryDigest {
			return ErrRecord
		}
		body := v.EntryBodies[i]
		view, err := InspectValueEntry(body)
		if err != nil || string(view.Name) != entry.Name || view.Incarnation != entry.Incarnation || view.RecipientCount() != len(entry.Recipients) {
			return ErrRecord
		}
		for j, id := range entry.Recipients {
			actual, _ := view.RecipientID(j)
			if actual != id {
				return ErrRecord
			}
		}
		w := cryptoHashWriter(cryptoPurposePrefix + "public-member-v6\x00")
		w.id(before.Domain)
		w.u16(entry.Slot)
		w.raw(body)
		if w.result(1).Digest != entry.EntryDigest {
			return ErrRecord
		}
		raw += uint64(view.ContentLength)
		if raw > CryptoMaxRawSet {
			return ErrRecordCapacity
		}
	}
	d, err := RequiredSupportDescriptorFromDigests(before.Domain, v.Rows.Facts)
	if err != nil || d != before.RequiredSupport {
		return ErrRecord
	}
	if !v.RetainedCanonicalsValid() {
		return ErrRecord
	}
	parts, metadataErr := v.configurationParts(before)
	if metadataErr != nil {
		// Typed errors preceded selected-row comparison before this traversal.
		if _, _, err := writeOutputConfiguration(v.Before, false); err != nil {
			return err
		}
		return metadataErr
	}
	if err := matchOutputConfiguration(v.Before, v.BeforeDescriptor, parts); err != nil {
		return err
	}

	for _, binding := range v.Before.Bindings {
		for _, target := range binding.Targets {
			if !slices.ContainsFunc(v.EntriesBefore, func(row MembershipRow) bool { return row.Incarnation == target.EntryIncarnationID }) {
				return ErrRecord
			}
		}
	}
	return nil
}

func (v *GeneratedOutputTransition) RetainedCanonicalsValid() bool {
	if v == nil {
		return false
	}
	index := 0
	for _, fact := range v.Rows.Facts {
		if fact.Kind() != RetainedCanonicalSupportKind {
			continue
		}
		if index >= len(v.Retained) {
			return false
		}
		actual, err := InspectSupportRecordDigest(v.Before.DomainID, v.Retained[index])
		if err != nil || actual != fact {
			return false
		}
		index++
	}
	return index == len(v.Retained)
}

func (v *GeneratedOutputTransition) configurationParts(before PublicState) ([][]byte, error) {
	descriptor := v.BeforeDescriptor
	if _, err := EncodeOutputConfigurationDescriptor(descriptor); err != nil {
		return nil, ErrRecord
	}
	var selected []SupportRecordDigest
	for _, fact := range v.Rows.Facts {
		if outputSupportKind(fact.Kind()) {
			selected = append(selected, fact)
		}
	}
	if len(selected) != len(v.Rows.Records) {
		return nil, ErrRecord
	}
	for i, row := range v.Rows.Records {
		fact, err := InspectSupportRecordDigest(before.Domain, row)
		if err != nil || !outputSupportKind(row.Kind) || fact != selected[i] {
			return nil, ErrRecord
		}
	}
	parts := make([][]byte, descriptor.SliceCount)
	configurationRows := 0
	for _, row := range v.Rows.Records {
		if row.Kind != OutputConfigurationSliceSupportKind {
			continue
		}
		part, err := InspectOutputConfigurationSlice(row.Body)
		if err != nil || part.DomainID != before.Domain || part.ConfigurationDigest != descriptor.ConfigurationDigest ||
			part.SliceCount != descriptor.SliceCount || part.TotalLength != descriptor.TotalLength || parts[part.SliceIndex] != nil {
			return nil, ErrRecord
		}
		id, err := OutputConfigurationSliceID(before.Domain, descriptor.ConfigurationDigest, part.SliceIndex)
		if err != nil || id != row.RecordID {
			return nil, ErrRecord
		}
		parts[part.SliceIndex] = part.SliceBytes
		configurationRows++
	}
	if len(parts) != configurationRows {
		return nil, ErrRecord
	}
	return parts, nil
}

func (v *GeneratedOutputTransition) Own(before PublicState) (*GeneratedOutputTransition, error) {
	if err := v.Inspect(before); err != nil {
		return nil, err
	}
	out := *v
	out.Before = cloneOutputConfiguration(v.Before)
	normal := &NormalOutputTransition{Before: v.Before, Bindings: v.Bindings, Routes: v.Routes, Groups: v.Groups}
	owned, err := normal.Own()
	if err != nil {
		return nil, err
	}
	out.Bindings, out.Routes, out.Groups = owned.Bindings, owned.Routes, owned.Groups
	out.EntriesBefore = cloneOutputMembership(v.EntriesBefore)
	out.EntryBodies = slices.Clone(v.EntryBodies)
	for i := range out.EntryBodies {
		out.EntryBodies[i] = bytes.Clone(out.EntryBodies[i])
	}
	out.Retained = slices.Clone(v.Retained)
	for i := range out.Retained {
		out.Retained[i].Body = bytes.Clone(out.Retained[i].Body)
	}
	out.Rows.Records, out.Rows.Facts = slices.Clone(v.Rows.Records), slices.Clone(v.Rows.Facts)
	for i := range out.Rows.Records {
		out.Rows.Records[i].Body = bytes.Clone(out.Rows.Records[i].Body)
	}
	return &out, nil
}

// Rebind derives the final configuration from the signed complete entry plan.
// The physical coordinates and all their earlier ownership remain unchanged.
func (v *GeneratedOutputTransition) Rebind(operation ID, plans []GeneratorValueEntryPlan) (GeneratedSupportRows, OutputConfigurationDescriptor, error) {
	if v == nil || operation.IsZero() {
		return GeneratedSupportRows{}, OutputConfigurationDescriptor{}, ErrRecord
	}
	if len(v.Rows.Records) == 0 {
		return GeneratedSupportRows{}, OutputConfigurationDescriptor{}, ErrRecord
	}
	normal, identity, err := v.rebindIntent(operation, plans)
	if err != nil {
		return GeneratedSupportRows{}, OutputConfigurationDescriptor{}, err
	}
	_, descriptor, _, err := normal.ConfigurationAfter(identity)
	if err != nil {
		return GeneratedSupportRows{}, OutputConfigurationDescriptor{}, err
	}
	// SupportAfter requires one fact for each supplied record. Whole predecessor
	// facts above authenticated these output records; unrelated rows are retained
	// by the generated writer and its existing phase proof.
	before := GeneratedSupportRows{Records: v.Rows.Records}
	for _, fact := range v.Rows.Facts {
		if outputSupportKind(fact.Kind()) {
			before.Facts = append(before.Facts, fact)
		}
	}
	rows, err := normal.SupportAfter(identity, before)
	return rows, descriptor, err
}

func (v *GeneratedOutputTransition) rebindIntent(operation ID, plans []GeneratorValueEntryPlan) (*NormalOutputTransition, IdentityPlan, error) {
	if v == nil || operation.IsZero() {
		return nil, IdentityPlan{}, ErrRecord
	}
	normal := &NormalOutputTransition{Before: v.Before, BeforeDescriptor: v.BeforeDescriptor, EntriesBefore: v.EntriesBefore, Bindings: v.Bindings, Routes: v.Routes, Groups: v.Groups}
	identity := IdentityPlan{Operation: operation}
	intended := make(map[string]bool, len(plans))
	for _, row := range plans {
		if intended[row.Name] || row.EntryIncarnationID.IsZero() {
			return nil, IdentityPlan{}, ErrRecord
		}
		intended[row.Name] = true
		normal.Intent = append(normal.Intent, CryptoIntentRow{Name: row.Name, InputEncoding: row.InputEncoding, OutputEncoding: row.OutputEncoding})
		normal.Slots = append(normal.Slots, row.Slot)
		identity.Rows = append(identity.Rows, IdentityRow{Name: row.Name, Slot: row.Slot, Incarnation: row.EntryIncarnationID})
	}
	return normal, identity, nil
}

// ValidateSuccessorRouting checks the complete selecting declaration against
// the same deterministic rebind used by final selection. Delete graphs retain
// their selected configuration rather than selecting their empty entry plans.
func (v *GeneratedOutputTransition) ValidateSuccessorRouting(graph GeneratorPlanBundle, declaration GeneratorDeclarationView) error {
	if v == nil {
		return ErrRecord
	}
	switch graph.Request.OperationKind {
	case OperationApplyDeclaration, OperationRotateValueEntryValue:
	default:
		return nil
	}
	descriptor, err := declaration.Descriptor()
	if err != nil || descriptor != graph.Request.Declaration || declaration.DomainID != v.Before.DomainID || declaration.OperationID != graph.Header.OperationID || declaration.EntryCount() != len(graph.ValueEntryPlans) {
		return ErrRecord
	}
	normal, identity, err := v.rebindIntent(graph.Header.OperationID, graph.ValueEntryPlans)
	if err != nil {
		return err
	}
	configuration, err := normal.configurationAfter(identity)
	if err != nil {
		return err
	}
	if _, _, err := writeOutputConfiguration(configuration, false); err != nil {
		return err
	}
	if graph.Request.Schema == GeneratorApplyRequestCoreSchema {
		image, err := EncodeOutputConfiguration(configuration)
		if err != nil {
			return err
		}
		if _, err := InspectGeneratedOutputConfiguration(graph, image); err != nil {
			return err
		}
	}
	indices := make(map[ID]int, len(graph.ValueEntryPlans))
	var recipients [CryptoMaxValueEntryRecipients]ID
	for i, plan := range graph.ValueEntryPlans {
		entry, _, err := declaration.Entry(i)
		if err != nil || string(entry.Name) != plan.Name || indices[plan.EntryIncarnationID] != 0 {
			return ErrRecord
		}
		ids := recipients[:len(entry.RecipientIDs)/len(ID{})]
		for j := range ids {
			ids[j] = ID(entry.RecipientIDs[j*len(ID{}) : (j+1)*len(ID{})])
		}
		membership, err := GeneratorIntendedMembershipDescriptor(ids)
		if err != nil || membership != plan.IntendedMembership {
			return ErrRecord
		}
		indices[plan.EntryIncarnationID] = i + 1
	}
	destinations := make(map[string]uint64, len(configuration.Bindings))
	targets := make(map[ID]uint64, len(graph.ValueEntryPlans))
	for i, binding := range configuration.Bindings {
		bit := uint64(1) << uint(i)
		destinations[binding.DestinationID] = bit
		for _, target := range binding.Targets {
			targets[target.EntryIncarnationID] |= bit
		}
	}
	routes := make(map[ID]uint64, len(configuration.Routes))
	maskFor := func(names []string) uint64 {
		var mask uint64
		for _, destination := range names {
			mask |= destinations[destination]
		}
		return mask
	}
	defaults := maskFor(configuration.DefaultDestinations)
	for _, route := range configuration.Routes {
		if indices[route.EntryIncarnationID] == 0 {
			return ErrRecord
		}
		routes[route.EntryIncarnationID] = maskFor(route.Destinations)
	}
	for _, plan := range graph.ValueEntryPlans {
		mask, present := routes[plan.EntryIncarnationID]
		if !present {
			mask = defaults
		}
		if mask != targets[plan.EntryIncarnationID] {
			return ErrRecord
		}
	}
	return nil
}

func (v *GeneratedOutputTransition) CandidateMatches(operation ID, plans []GeneratorValueEntryPlan, selecting bool, candidate []SupportRecord) bool {
	var expected []SupportRecord
	if v == nil {
		return false
	}
	if selecting {
		rows, _, err := v.Rebind(operation, plans)
		if err != nil {
			return false
		}
		expected = rows.Records
	} else {
		expected = v.Rows.Records
	}
	var actual []SupportRecord
	for _, row := range candidate {
		if outputSupportKind(row.Kind) {
			actual = append(actual, row)
		}
	}
	return slices.EqualFunc(expected, actual, func(a, b SupportRecord) bool {
		return a.Kind == b.Kind && a.RecordID == b.RecordID && bytes.Equal(a.Body, b.Body)
	})
}
