package contract

// Check every variable field that Own copies before any complete clone. These
// are structural limits; later admission still checks selector correspondence.
func normalOutputOwnershipBounds(v *NormalOutputTransition) error {
	if len(v.Bindings) > MaxOutputBindings || len(v.Routes) > MaxPublicRoutingRules || len(v.Groups) > CryptoMaxValueEntries ||
		len(v.EntriesBefore) > CryptoMaxValueEntries || len(v.Intent) > CryptoMaxValueEntries || len(v.Slots) > CryptoMaxValueEntries {
		return ErrRecordCapacity
	}
	memberships := 0
	for _, row := range v.EntriesBefore {
		memberships += len(row.Recipients)
		if len(row.Name) > CryptoMaxName || len(row.Recipients) > CryptoMaxValueEntryRecipients || memberships > CryptoMaxMemberships {
			return ErrRecordCapacity
		}
	}
	memberships = 0
	for _, row := range v.Intent {
		memberships += len(row.Recipients)
		if len(row.Name) > CryptoMaxName || len(row.Recipients) > CryptoMaxValueEntryRecipients || memberships > CryptoMaxMemberships {
			return ErrRecordCapacity
		}
	}
	// Desired names become fixed-width entry IDs in the canonical declaration.
	// Count its fields before cloning; semantic correspondence is checked later.
	declaration := newOutputWriter(false, 0)
	declaration.u16(OutputConfigurationSchema)
	declaration.u16(uint16(len(v.Bindings)))
	targets, groupNames := 0, 0
	for _, binding := range v.Bindings {
		if len(binding.DestinationID) > 256 || len(binding.Targets) > MaxOutputTargetsPerBinding {
			return ErrRecordCapacity
		}
		targets += len(binding.Targets)
		if targets > MaxOutputTargets {
			return ErrRecordCapacity
		}
		destination := binding.Destination
		if len(destination.ConfigContractID) > 256 || len(destination.ServiceContractID) > 256 || len(destination.CanonicalSettings) > MaxOutputDestinationSettings {
			return ErrRecordCapacity
		}
		declaration.text(binding.DestinationID)
		declaration.id(ID{}) // Binding incarnation has fixed width before assignment.
		if err := writeOutputDestinationFieldsTo(destination, &declaration); err != nil {
			return err
		}
		declaration.u16(uint16(len(binding.Targets)))
		for _, named := range binding.Targets {
			target := named.Target
			if len(named.Name) > CryptoMaxName || len(target.ServiceContractID) > 256 || len(target.CanonicalTarget) > 1024 || len(target.ConsumerLocator) > 1024 || len(target.TargetContractID) > 256 || len(target.TargetData) > 4096 {
				return ErrRecordCapacity
			}
			if err := writeOutputTargetFieldsTo(target, &declaration); err != nil {
				return err
			}
			if declaration.length > MaxOutputDeclarationBytes {
				return ErrRecordCapacity
			}
		}
		if declaration.length > MaxOutputDeclarationBytes {
			return ErrRecordCapacity
		}
	}
	declaration.u16(uint16(len(v.Groups)))
	for _, group := range v.Groups {
		groupNames += len(group)
		if groupNames > CryptoMaxValueEntries {
			return ErrRecordCapacity
		}
		declaration.u16(uint16(len(group)))
		for _, name := range group {
			if len(name) > CryptoMaxName {
				return ErrRecordCapacity
			}
			declaration.id(ID{})
		}
	}
	if declaration.length > MaxOutputDeclarationBytes {
		return ErrRecordCapacity
	}
	routing := 5
	for _, route := range v.Routes {
		if !route.validEntrySelector() || len(route.Name) > CryptoMaxName || len(route.Destinations) > MaxOutputRouteDestinations {
			return ErrRecord
		}
		if !route.Default {
			routing += 33
		}
		for _, name := range route.Destinations {
			if len(name) > 256 {
				return ErrRecordCapacity
			}
			routing += 4 + len(name)
		}
		if routing > MaxOutputRoutingBytes {
			return ErrRecordCapacity
		}
	}
	if declaration.length+4+routing > MaxOutputConfigurationBytes {
		return ErrRecordCapacity
	}
	return nil
}
