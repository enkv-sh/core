package contract

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
)

// NormalOutputTransition is private parent meaning, not a wire request or an
// authority constructor. The parent authenticates Before and its entry table.
type NormalOutputTransition struct {
	Before           OutputConfiguration
	BeforeDescriptor OutputConfigurationDescriptor
	EntriesBefore    []MembershipRow
	Intent           []CryptoIntentRow
	Slots            []uint16
	Bindings         []NormalOutputBinding
	Routes           []NormalOutputRoute
	Groups           [][]string
}

type NormalOutputBinding struct {
	DestinationID string
	Destination   OutputDestination

	Targets []NormalOutputTarget
}

type NormalOutputTarget struct {
	Name   string
	Target OutputTarget
}

type NormalOutputRoute struct {
	Default      bool
	Name         string
	Destinations []string
}

func (r NormalOutputRoute) validEntrySelector() bool {
	return !r.Default || r.Name == ""
}

// Fresh IDs are bound to the already fresh admitted Operation. Length framing
// makes destination names unambiguous; the two purposes cannot share an ID.
func NormalOutputBindingID(domain, operation ID, destination string) (ID, error) {
	if domain.IsZero() || operation.IsZero() || !outputIdentifierValid(destination) {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/OUTPUT/APPLY-BINDING/v1\x00")
	w.id(domain)
	w.id(operation)
	w.blob([]byte(destination))
	return w.result(0).Digest, nil
}

func NormalOutputPublicationID(domain, operation, coordinate ID) (ID, error) {
	if domain.IsZero() || operation.IsZero() || coordinate.IsZero() {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/OUTPUT/APPLY-PUBLICATION/v1\x00")
	w.id(domain)
	w.id(operation)
	w.id(coordinate)
	return w.result(0).Digest, nil
}

func (v *NormalOutputTransition) Inspect(records GeneratedSupportRows) error {
	if v == nil || len(v.Intent) != len(v.Slots) || len(v.EntriesBefore) > CryptoMaxValueEntries || len(records.Records) != len(records.Facts) {
		return ErrRecord
	}
	if err := normalOutputOwnershipBounds(v); err != nil {
		return err
	}
	d, parts, err := encodedOutputConfiguration(v.Before)
	if err != nil {
		return err
	}
	if d != v.BeforeDescriptor {
		return ErrRecord
	}
	expected := make(map[ID]SupportRecordDigest, len(parts))
	for _, part := range parts {
		body, err := EncodeOutputConfigurationSlice(part)
		if err != nil {
			return err
		}
		id, err := OutputConfigurationSliceID(v.Before.DomainID, d.ConfigurationDigest, part.SliceIndex)
		if err != nil {
			return err
		}
		fact, err := InspectSupportRecordDigest(v.Before.DomainID, SupportRecord{Kind: OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
		if err != nil {
			return err
		}
		expected[id] = fact
	}
	for i, row := range records.Records {
		if row.Kind == OutputConfigurationSliceSupportKind {
			fact, ok := expected[row.RecordID]
			if !ok || fact != records.Facts[i] {
				return ErrRecord
			}
			delete(expected, row.RecordID)
		}
	}
	if len(expected) != 0 {
		return ErrRecord
	}
	if _, err := GrantDescriptor(v.Before.DomainID, v.EntriesBefore); err != nil {
		return err
	}
	var slots [CryptoMaxValueEntries]bool
	for i, slot := range v.Slots {
		if slot >= CryptoMaxValueEntries || slots[slot] {
			return ErrRecord
		}
		slots[slot] = true
		if before := slices.IndexFunc(v.EntriesBefore, func(row MembershipRow) bool { return row.Name == v.Intent[i].Name }); before >= 0 && v.EntriesBefore[before].Slot != slot {
			return ErrRecord
		}
	}
	if _, err := CryptoIntentDescriptor(v.Before.DomainID, v.Intent); err != nil {
		return err
	}
	return nil
}

func (v *NormalOutputTransition) Own() (*NormalOutputTransition, error) {
	if v == nil {
		return nil, ErrRecord
	}
	if _, _, err := writeOutputConfiguration(v.Before, false); err != nil {
		return nil, err
	}
	if err := normalOutputOwnershipBounds(v); err != nil {
		return nil, err
	}
	out := *v
	out.Before = cloneOutputConfiguration(v.Before)
	out.Groups = slices.Clone(v.Groups)
	for i := range out.Groups {
		out.Groups[i] = slices.Clone(out.Groups[i])
		for j := range out.Groups[i] {
			out.Groups[i][j] = strings.Clone(out.Groups[i][j])
		}
	}
	out.EntriesBefore = cloneOutputMembership(v.EntriesBefore)
	out.Intent = slices.Clone(v.Intent)
	for i := range out.Intent {
		out.Intent[i].Name = strings.Clone(out.Intent[i].Name)
		out.Intent[i].Recipients = slices.Clone(out.Intent[i].Recipients)
	}
	out.Slots = slices.Clone(v.Slots)
	out.Bindings = slices.Clone(v.Bindings)
	for i := range out.Bindings {
		out.Bindings[i].DestinationID = strings.Clone(out.Bindings[i].DestinationID)
		out.Bindings[i].Destination = cloneOutputDestination(v.Bindings[i].Destination)
		out.Bindings[i].Targets = slices.Clone(v.Bindings[i].Targets)
		for j := range out.Bindings[i].Targets {
			row := &out.Bindings[i].Targets[j]
			row.Name = strings.Clone(row.Name)
			row.Target = cloneOutputTarget(row.Target)
		}
	}
	out.Routes = slices.Clone(v.Routes)
	for i := range out.Routes {
		out.Routes[i].Name = strings.Clone(out.Routes[i].Name)
		out.Routes[i].Destinations = slices.Clone(v.Routes[i].Destinations)
		for j := range out.Routes[i].Destinations {
			out.Routes[i].Destinations[j] = strings.Clone(out.Routes[i].Destinations[j])
		}
	}
	return &out, nil
}

func (v *NormalOutputTransition) Equal(other *NormalOutputTransition) bool {
	if v == nil || other == nil || v.BeforeDescriptor != other.BeforeDescriptor || v.Before.DomainID != other.Before.DomainID || !slices.Equal(v.Slots, other.Slots) {
		return false
	}
	a, err := CryptoIntentDescriptor(v.Before.DomainID, v.Intent)
	b, otherErr := CryptoIntentDescriptor(other.Before.DomainID, other.Intent)
	if err != nil || otherErr != nil || a != b {
		return false
	}
	aBefore, err := GrantDescriptor(v.Before.DomainID, v.EntriesBefore)
	bBefore, otherErr := GrantDescriptor(other.Before.DomainID, other.EntriesBefore)
	if err != nil || otherErr != nil || aBefore != bBefore {
		return false
	}
	if !slices.EqualFunc(v.Bindings, other.Bindings, func(a, b NormalOutputBinding) bool {
		return a.DestinationID == b.DestinationID && reflect.DeepEqual(a.Destination, b.Destination) && slices.EqualFunc(a.Targets, b.Targets, func(a, b NormalOutputTarget) bool {
			return a.Name == b.Name && normalOutputTargetsEqual(a.Target, b.Target)
		})
	}) {
		return false
	}
	return reflect.DeepEqual(v.Groups, other.Groups) && slices.EqualFunc(v.Routes, other.Routes, func(a, b NormalOutputRoute) bool {
		return a.Default == b.Default && a.Name == b.Name && slices.Equal(a.Destinations, b.Destinations)
	})
}

func (v *NormalOutputTransition) configurationAfter(plan IdentityPlan) (OutputConfiguration, error) {
	if v == nil || plan.Operation.IsZero() || len(v.Slots) != len(v.Intent) {
		return OutputConfiguration{}, ErrRecord
	}
	entries := make(map[string]ID, len(v.Intent))
	for i, intent := range v.Intent {
		fresh := slices.IndexFunc(plan.Rows, func(row IdentityRow) bool { return row.Name == intent.Name })
		if fresh >= 0 {
			if plan.Rows[fresh].Slot != v.Slots[i] {
				return OutputConfiguration{}, ErrRecord
			}
			entries[intent.Name] = plan.Rows[fresh].Incarnation
		} else if before := slices.IndexFunc(v.EntriesBefore, func(row MembershipRow) bool { return row.Name == intent.Name && row.Slot == v.Slots[i] }); before >= 0 {
			entries[intent.Name] = v.EntriesBefore[before].Incarnation
		}
		if entries[intent.Name].IsZero() {
			return OutputConfiguration{}, ErrRecord
		}
	}
	after := OutputConfiguration{Schema: OutputConfigurationSchema, DomainID: v.Before.DomainID}
	for _, binding := range v.Bindings {
		id, err := NormalOutputBindingID(v.Before.DomainID, plan.Operation, binding.DestinationID)
		if err != nil {
			return OutputConfiguration{}, err
		}
		if before := slices.IndexFunc(v.Before.Bindings, func(row OutputBinding) bool { return row.DestinationID == binding.DestinationID }); before >= 0 {
			old := v.Before.Bindings[before]
			id = old.IncarnationID
		}
		row := OutputBinding{DestinationID: binding.DestinationID, IncarnationID: id, Destination: binding.Destination}
		for _, named := range binding.Targets {
			target := named.Target
			if !target.EntryIncarnationID.IsZero() || entries[named.Name].IsZero() {
				return OutputConfiguration{}, ErrRecord
			}
			target.EntryIncarnationID = entries[named.Name]
			row.Targets = append(row.Targets, target)
		}
		slices.SortFunc(row.Targets, func(a, b OutputTarget) int { return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:]) })
		after.Bindings = append(after.Bindings, row)
	}
	for _, group := range v.Groups {
		ids := make([]ID, len(group))
		for i, name := range group {
			ids[i] = entries[name]
			if ids[i].IsZero() {
				return OutputConfiguration{}, ErrRecord
			}
		}
		slices.SortFunc(ids, func(a, b ID) int { return bytes.Compare(a[:], b[:]) })
		after.Groups = append(after.Groups, ids)
	}
	slices.SortFunc(after.Groups, func(a, b []ID) int { return bytes.Compare(a[0][:], b[0][:]) })
	defaultSeen := false
	for _, route := range v.Routes {
		if !route.validEntrySelector() {
			return OutputConfiguration{}, ErrRecord
		}
		if route.Default {
			if defaultSeen {
				return OutputConfiguration{}, ErrRecord
			}
			defaultSeen = true
			after.DefaultDestinations = route.Destinations
			continue
		}
		row := OutputRoute{EntryIncarnationID: entries[route.Name], Destinations: route.Destinations}
		if row.EntryIncarnationID.IsZero() {
			return OutputConfiguration{}, ErrRecord
		}
		after.Routes = append(after.Routes, row)
	}
	slices.SortFunc(after.Routes, func(a, b OutputRoute) int {
		return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
	})
	return after, nil
}

func (v *NormalOutputTransition) ConfigurationAfter(plan IdentityPlan) (OutputConfiguration, OutputConfigurationDescriptor, []SupportRecord, error) {
	after, err := v.configurationAfter(plan)
	if err != nil {
		return OutputConfiguration{}, OutputConfigurationDescriptor{}, nil, err
	}
	d, parts, err := encodedOutputConfiguration(after)
	if err != nil {
		return OutputConfiguration{}, OutputConfigurationDescriptor{}, nil, err
	}
	rows := make([]SupportRecord, len(parts))
	for i, part := range parts {
		body, err := EncodeOutputConfigurationSlice(part)
		if err != nil {
			return OutputConfiguration{}, OutputConfigurationDescriptor{}, nil, err
		}
		id, err := OutputConfigurationSliceID(v.Before.DomainID, d.ConfigurationDigest, part.SliceIndex)
		if err != nil {
			return OutputConfiguration{}, OutputConfigurationDescriptor{}, nil, err
		}
		rows[i] = SupportRecord{Kind: OutputConfigurationSliceSupportKind, RecordID: id, Body: body}
	}
	slices.SortFunc(rows, func(a, b SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	return after, d, rows, nil
}

// OutputConfigurationChangedSubjects includes the routes and explicit groups
// that affect each binding's operation admission, as well as its target rows.
func OutputConfigurationChangedSubjects(before, after OutputConfiguration) ([]ChangedSubjectIdentity, error) {
	if before.DomainID != after.DomainID {
		return nil, ErrRecord
	}
	for _, configuration := range []OutputConfiguration{before, after} {
		if _, err := OutputConfigurationLength(configuration); err != nil {
			return nil, err
		}
	}
	routingChanged := outputEffectiveRouteChanges(before, after)
	var rows []ChangedSubjectIdentity
	appendBinding := func(binding OutputBinding, change uint8) error {
		id, err := ChangedSubjectIdentityID(before.DomainID, ChangedSubjectOutputBinding, binding.IncarnationID, ID{})
		if err != nil {
			return err
		}
		rows = append(rows, ChangedSubjectIdentity{Kind: ChangedSubjectOutputBinding, Change: change, Identity: id})
		return nil
	}
	for _, binding := range before.Bindings {
		index := slices.IndexFunc(after.Bindings, func(row OutputBinding) bool { return row.IncarnationID == binding.IncarnationID })
		if index < 0 {
			if err := appendBinding(binding, ChangedSubjectRemoved); err != nil {
				return nil, err
			}
			continue
		}
		current := after.Bindings[index]
		if !outputBindingDeclarationEqual(binding, current) || routingChanged[binding.DestinationID] || !outputBindingRelationsEqual(before, binding, after, current) {
			if err := appendBinding(current, ChangedSubjectUpdated); err != nil {
				return nil, err
			}
		}
	}
	for _, binding := range after.Bindings {
		if !slices.ContainsFunc(before.Bindings, func(row OutputBinding) bool { return row.IncarnationID == binding.IncarnationID }) {
			if err := appendBinding(binding, ChangedSubjectAdded); err != nil {
				return nil, err
			}
		}
	}
	return rows, nil
}

func outputEffectiveRouteChanges(before, after OutputConfiguration) map[string]bool {
	entries := map[ID]bool{{}: true}
	index := func(configuration OutputConfiguration) map[ID][]string {
		out := make(map[ID][]string, len(configuration.Routes))
		for _, route := range configuration.Routes {
			entries[route.EntryIncarnationID] = true
			out[route.EntryIncarnationID] = route.Destinations
		}
		for _, binding := range configuration.Bindings {
			for _, target := range binding.Targets {
				entries[target.EntryIncarnationID] = true
			}
		}
		return out
	}
	old, current := index(before), index(after)
	resolve := func(routes map[ID][]string, defaults []string, entry ID) []string {
		if destinations, present := routes[entry]; present {
			return destinations
		}
		return defaults
	}
	changed := make(map[string]bool)
	for entry := range entries {
		a, b := resolve(old, before.DefaultDestinations, entry), resolve(current, after.DefaultDestinations, entry)
		for _, destination := range a {
			if !slices.Contains(b, destination) {
				changed[destination] = true
			}
		}
		for _, destination := range b {
			if !slices.Contains(a, destination) {
				changed[destination] = true
			}
		}
	}
	return changed
}

func outputBindingDeclarationEqual(a, b OutputBinding) bool {
	x, y := a.Destination, b.Destination
	return a.DestinationID == b.DestinationID && a.IncarnationID == b.IncarnationID &&
		x.ConfigContractID == y.ConfigContractID && x.ServiceContractID == y.ServiceContractID && bytes.Equal(x.CanonicalSettings, y.CanonicalSettings) && x.Capabilities == y.Capabilities && outputPoliciesEqual(x.Policy, y.Policy) &&
		slices.EqualFunc(a.Targets, b.Targets, normalOutputTargetsEqual)
}

func normalOutputTargetsEqual(x, y OutputTarget) bool {
	return x.EntryIncarnationID == y.EntryIncarnationID && x.ServiceContractID == y.ServiceContractID && x.TargetContractID == y.TargetContractID &&
		x.CanonicalTarget == y.CanonicalTarget && x.ConsumerLocator == y.ConsumerLocator && bytes.Equal(x.TargetData, y.TargetData) &&
		x.PayloadEncoding == y.PayloadEncoding && x.LocatorRequiresCreation == y.LocatorRequiresCreation && x.Capabilities == y.Capabilities && x.CreateValueBounds == y.CreateValueBounds && x.WriteValueBounds == y.WriteValueBounds && outputPoliciesEqual(x.Policy, y.Policy)
}

func outputBindingRelationsEqual(before OutputConfiguration, old OutputBinding, after OutputConfiguration, current OutputBinding) bool {
	routes := func(configuration OutputConfiguration, binding OutputBinding) []OutputRoute {
		var rows []OutputRoute
		for _, route := range configuration.Routes {
			if slices.Contains(route.Destinations, binding.DestinationID) {
				rows = append(rows, OutputRoute{EntryIncarnationID: route.EntryIncarnationID})
			}
		}
		return rows
	}
	groups := func(configuration OutputConfiguration, binding OutputBinding) [][]ID {
		var rows [][]ID
		for _, group := range configuration.Groups {
			if slices.ContainsFunc(binding.Targets, func(target OutputTarget) bool { return slices.Contains(group, target.EntryIncarnationID) }) {
				rows = append(rows, group)
			}
		}
		return rows
	}
	return slices.Contains(before.DefaultDestinations, old.DestinationID) == slices.Contains(after.DefaultDestinations, current.DestinationID) && slices.EqualFunc(routes(before, old), routes(after, current), func(a, b OutputRoute) bool {
		return a.EntryIncarnationID == b.EntryIncarnationID
	}) && slices.EqualFunc(groups(before, old), groups(after, current), slices.Equal[[]ID, ID])
}

// OutputBindingIncarnationPreserved requires the same complete logical group.
// Equal IDs alone cannot turn a derived-ID collision into retained membership.
func OutputBindingIncarnationPreserved(before []OutputBinding, after OutputBinding) bool {
	return slices.ContainsFunc(before, func(old OutputBinding) bool {
		return old.DestinationID == after.DestinationID && old.IncarnationID == after.IncarnationID
	})
}

func (v *NormalOutputTransition) SupportAfter(plan IdentityPlan, before GeneratedSupportRows) (GeneratedSupportRows, error) {
	if len(before.Records) != len(before.Facts) {
		return GeneratedSupportRows{}, ErrRecord
	}
	after, _, configuration, err := v.ConfigurationAfter(plan)
	if err != nil {
		return GeneratedSupportRows{}, err
	}
	used := make(map[ID]bool)
	for _, row := range v.EntriesBefore {
		used[row.Incarnation] = true
	}
	for _, binding := range v.Before.Bindings {
		used[binding.IncarnationID] = true
	}
	for _, row := range before.Records {
		used[row.RecordID] = true
		if err := CollectPublicationRecordIdentities(row, used); err != nil {
			return GeneratedSupportRows{}, err
		}

	}
	for _, id := range []ID{plan.Operation, plan.Snapshot, plan.Transition, plan.Revision} {
		if !id.IsZero() {
			used[id] = true
		}
	}
	for _, row := range plan.Rows {
		used[row.Incarnation], used[row.ValueState] = true, true
	}
	for _, page := range plan.Pages {
		used[page.Object] = true
	}
	for _, binding := range after.Bindings {
		if OutputBindingIncarnationPreserved(v.Before.Bindings, binding) {
			continue
		}
		if used[binding.IncarnationID] {
			return GeneratedSupportRows{}, ErrRecord
		}
		used[binding.IncarnationID] = true
	}
	coordinates := make(map[ID]PublicationCoordinate)
	var rows []SupportRecord
	var facts []SupportRecordDigest
	for i, row := range before.Records {
		switch row.Kind {
		case OutputConfigurationSliceSupportKind:
			continue
		case PublicationCoordinateSupportKind:
			coordinate, err := InspectPublicationCoordinate(row.Body)
			if err != nil || coordinate.CoordinateID != row.RecordID || coordinate.DomainID != v.Before.DomainID {
				return GeneratedSupportRows{}, ErrRecord
			}
			coordinate.BindingState, coordinate.ActiveBindingIncarnationID = PublicationBindingRetired, ID{}
			coordinates[row.RecordID] = coordinate
		default:
			rows, facts = append(rows, row), append(facts, before.Facts[i])
		}
	}
	for _, binding := range after.Bindings {
		for _, target := range binding.Targets {
			id, err := PublicationCoordinateID(after.DomainID, target.ServiceContractID, target.CanonicalTarget)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
			coordinate, present := coordinates[id]
			if !present {
				incarnation, err := NormalOutputPublicationID(after.DomainID, plan.Operation, id)
				if err != nil {
					return GeneratedSupportRows{}, err
				}
				if used[incarnation] || used[id] {
					return GeneratedSupportRows{}, ErrRecord
				}
				used[incarnation], used[id] = true, true
				coordinate = PublicationCoordinate{Schema: 5, DomainID: after.DomainID, CoordinateID: id,
					ServiceContractID: target.ServiceContractID, CanonicalTarget: target.CanonicalTarget, CurrentPublicationIncarnationID: incarnation,
					LastBindingIncarnationID: binding.IncarnationID, LastEntryIncarnationID: target.EntryIncarnationID}
			}
			coordinate.BindingState, coordinate.ActiveBindingIncarnationID = PublicationBindingActive, binding.IncarnationID
			coordinates[id] = coordinate
		}
	}
	if len(coordinates) > MaxPublicationCoordinates {
		return GeneratedSupportRows{}, ErrRecordCapacity
	}
	for id, coordinate := range coordinates {
		body, err := EncodePublicationCoordinate(coordinate)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		configuration = append(configuration, SupportRecord{Kind: PublicationCoordinateSupportKind, RecordID: id, Body: body})
	}
	for _, row := range configuration {
		fact, err := InspectSupportRecordDigest(after.DomainID, row)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		rows, facts = append(rows, row), append(facts, fact)
	}
	order := make([]int, len(rows))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int {
		if rows[a].Kind != rows[b].Kind {
			return int(rows[a].Kind) - int(rows[b].Kind)
		}
		return bytes.Compare(rows[a].RecordID[:], rows[b].RecordID[:])
	})
	out := GeneratedSupportRows{Records: make([]SupportRecord, len(rows)), Facts: make([]SupportRecordDigest, len(rows))}
	for i, j := range order {
		out.Records[i], out.Facts[i] = rows[j], facts[j]
	}
	if _, err := RequiredSupportDescriptorFromDigests(after.DomainID, out.Facts); err != nil {
		return GeneratedSupportRows{}, err
	}
	return out, nil
}

func cloneOutputMembership(rows []MembershipRow) []MembershipRow {
	rows = slices.Clone(rows)
	for i := range rows {
		rows[i].Name = strings.Clone(rows[i].Name)
		rows[i].Recipients = slices.Clone(rows[i].Recipients)
	}
	return rows
}
