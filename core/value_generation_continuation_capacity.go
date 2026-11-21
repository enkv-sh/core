package core

import (
	"context"
	"math"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type capacityBoundScope uint8

const (
	remainingSelectedContinuations capacityBoundScope = iota + 1
	firstAdministrativeExit
)

type capacityBoundStatus uint8

const (
	capacitySufficient capacityBoundStatus = iota + 1
	capacityNotEstablished
	capacityNotApplicable
)

// Bounds describe the current selected rights. They do not reconstruct a
// historical reservation or admit a new operation.
type selectedCapacityBound struct {
	Scope                                                      capacityBoundScope
	Status                                                     capacityBoundStatus
	BasisDigest                                                contract.ID
	Groups                                                     [contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup
	ChildPages, ChildEncodedBytes, RootBytes                   uint64
	AdministrativeIndexBytes, AdministrativeIndexShards        uint64
	ChildPageLimit, RootByteLimit, AdministrativePageByteLimit uint64
}

type selectedContinuationCapacity struct {
	RootDigest           contract.ID
	Graphs               contract.GeneratorDescriptor
	GCPlans              contract.GCDescriptor
	Remaining, FirstExit selectedCapacityBound
}

func continuationCapacityFromSelected(ctx context.Context, image *selectedImage, generated *generatedSelection, read selectedFragmentRead) (selectedContinuationCapacity, error) {
	return calculateSelectedContinuationCapacity(ctx, image, generated, read)
}

type continuationGroupKey struct {
	class     format.SupportStorageGroup
	owner     contract.ID
	mandatory bool
}

type continuationGroupCharge struct {
	count, framed uint64
}

type continuationPopulation map[continuationGroupKey]continuationGroupCharge

type continuationPartition struct {
	class     format.SupportStorageGroup
	mandatory bool
}

type continuationPartitionCharge struct{ count, framed, width uint64 }

type continuationGrowth struct {
	parts                                 map[continuationPartition]continuationPartitionCharge
	accessCount, accessBytes, accessWidth uint64
	newGroups                             uint64
	templates                             uint64
}

func capacityCeiling(n, d uint64) uint64 {
	if n == 0 {
		return 0
	}
	return n/d + uint64(boolInt(n%d != 0))
}

func capacityAdd(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, contract.ErrRecordCapacity
	}
	return a + b, nil
}

func capacityMultiply(a, b uint64) (uint64, error) {
	if b != 0 && a > math.MaxUint64/b {
		return 0, contract.ErrRecordCapacity
	}
	return a * b, nil
}

func continuationTag(class format.SupportStorageGroup) (int, bool) {
	switch class {
	case format.OldValueSupport:
		return contract.GeneratorCapacityOldValues, true
	case format.CandidateValueSupport:
		return contract.GeneratorCapacityCandidateValues, true
	case format.ResultSupport:
		return contract.GeneratorCapacityCreateResults, true
	case format.MaterialSupport:
		return contract.GeneratorCapacityMaterial, true
	case format.CreateContinuationSupport:
		return contract.GeneratorCapacityCreates, true
	case format.DeleteContinuationSupport:
		return contract.GeneratorCapacityDeletes, true
	case format.OwnerSupport:
		return contract.GeneratorCapacityOwners, true
	case format.ReceiptSupport:
		return contract.GeneratorCapacityReceipts, true
	case format.IntentFragmentSupport:
		return contract.GeneratorCapacityIntents, true
	case format.GraphFragmentSupport, format.GraphIndexSupport:
		return contract.GeneratorCapacityGraph, true
	case format.AuxiliaryFragmentSupport, format.AuxiliaryIndexSupport, format.OutputConfigurationSupport, format.GCPlanSupport:
		return contract.GeneratorCapacityAuxiliary, true
	}
	return 0, false
}

// Each key is one stored owner group. A changed group replaces its old width;
// independent owners are added. Fragment groups count their physical rows.
func (p continuationPopulation) atLeast(key continuationGroupKey, count, framed uint64) {
	old := p[key]
	p[key] = continuationGroupCharge{count: max(old.count, count), framed: max(old.framed, framed)}
}

func (p continuationPopulation) atLeastWholeGroup(key continuationGroupKey, count, framed uint64) {
	other := key
	other.mandatory = !key.mandatory
	left, right := p[key], p[other]
	if left.framed == 0 && right.framed != 0 {
		key, other = other, key
		left, right = right, left
	}
	totalCount, totalBytes := left.count+right.count, left.framed+right.framed
	left.count += count - min(count, totalCount)
	left.framed += framed - min(framed, totalBytes)
	p[key] = left
}

func selectedContinuationGroups(ctx context.Context, image *selectedImage, generated *generatedSelection) (continuationPopulation, error) {
	fragments, err := image.selectedFragmentFactsByRecord()
	if err != nil {
		return nil, err
	}
	rows := image.supportRecords()
	groups, err := generatedReservationGroupsWithFacts(rows, selectedGeneratedLocations(generated), generated.bundles, fragments)
	if err != nil {
		return nil, err
	}
	var entries []contract.GeneratedEntryMetadata
	for _, name := range image.root.Names {
		entry := image.valueEntry(name.Slot)
		if entry == nil {
			return nil, contract.ErrRecord
		}
		if entry.ValueSource == contract.Generated {
			entries = append(entries, entry.Generated)
		}
	}
	mandatory := administrativeMandatorySupportForEntries(entries, selectedGeneratedLocations(generated))
	if _, err := mandatory.selectedPublication(image.root.Domain, rows, image.adminIndex.PublicationOrder); err != nil {
		return nil, err
	}
	groups, err = partitionAdministrativeSupportGroupsWithFacts(groups, mandatory, fragments)
	if err != nil {
		return nil, err
	}
	population := make(continuationPopulation, len(groups))
	seen := make(map[generatedRecordKey]bool, len(rows))
	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := continuationGroupKey{group.Class, group.Owner, group.Mandatory}
		if _, duplicate := population[key]; duplicate {
			return nil, contract.ErrRecord
		}
		var charge continuationGroupCharge
		for _, row := range group.Records {
			identity := generatedRecordKey{row.Kind, row.RecordID}
			if seen[identity] {
				return nil, contract.ErrRecord
			}
			seen[identity] = true
			length := uint64(len(row.Body))
			if row.Body == nil {
				fact, ok := fragments[row.RecordID]
				if !ok || fact.row.Kind() != row.Kind {
					return nil, contract.ErrRecord
				}
				length = uint64(fact.row.BodyLength())
			}
			charge.framed += contract.SupportRecordOverhead + length
			charge.count++
		}
		if _, ok := continuationTag(group.Class); !ok || charge.framed == 0 {
			return nil, contract.ErrRecord
		}
		population[key] = charge
	}
	return population, nil
}

func continuationGroupTotals(population continuationPopulation, growth continuationGrowth) ([contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup, uint64, error) {
	var groups [contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup
	parts := make(map[continuationPartition]continuationPartitionCharge)
	var rows uint64
	for key, charge := range population {
		if charge.count == 0 || charge.framed == 0 {
			return groups, 0, contract.ErrRecord
		}
		tag, ok := continuationTag(key.class)
		if !ok {
			return groups, 0, contract.ErrRecord
		}
		group := &groups[tag]
		var err error
		group.MaxCount, err = capacityAdd(group.MaxCount, charge.count)
		if err != nil {
			return groups, 0, err
		}
		group.MaxFramedBytes, err = capacityAdd(group.MaxFramedBytes, charge.framed)
		if err != nil {
			return groups, 0, err
		}
		rows, err = capacityAdd(rows, charge.count)
		if err != nil {
			return groups, 0, err
		}
		part := continuationPartition{key.class, key.mandatory}
		value := parts[part]
		value.count, err = capacityAdd(value.count, charge.count)
		if err != nil {
			return groups, 0, err
		}
		value.framed, err = capacityAdd(value.framed, charge.framed)
		if err != nil {
			return groups, 0, err
		}
		value.width = max(value.width, charge.framed)
		parts[part] = value
	}
	for key, extra := range growth.parts {
		if extra.framed == 0 {
			if extra.count != 0 {
				return groups, 0, contract.ErrRecord
			}
			continue
		}
		tag, ok := continuationTag(key.class)
		if !ok {
			return groups, 0, contract.ErrRecord
		}
		group := &groups[tag]
		var err error
		group.MaxCount, err = capacityAdd(group.MaxCount, extra.count)
		if err != nil {
			return groups, 0, err
		}
		group.MaxFramedBytes, err = capacityAdd(group.MaxFramedBytes, extra.framed)
		if err != nil {
			return groups, 0, err
		}
		rows, err = capacityAdd(rows, extra.count)
		if err != nil {
			return groups, 0, err
		}
		part := parts[key]
		part.count, err = capacityAdd(part.count, extra.count)
		if err != nil {
			return groups, 0, err
		}
		part.framed, err = capacityAdd(part.framed, extra.framed)
		if err != nil {
			return groups, 0, err
		}
		part.width = max(part.width, extra.width)
		parts[key] = part
	}
	const payload = uint64(contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength)
	for key, part := range parts {
		tag, _ := continuationTag(key.class)
		var pages uint64
		if key.class >= format.IntentFragmentSupport {
			pages = capacityCeiling(part.count, generatedFragmentsPerPage)
		} else {
			if part.width > payload {
				return groups, 0, contract.ErrRecord
			}
			pages = 1 + (part.framed-1)/(payload-part.width+1)
		}
		if pages > math.MaxUint32-uint64(groups[tag].MaxPages) {
			return groups, 0, contract.ErrRecordCapacity
		}
		groups[tag].MaxPages += uint32(pages)
	}
	return groups, rows, nil
}

// Paths contain at most the one no-effect and one residue successor. A path
// starts at the selected branch; it never joins the two alternative orders.
func continuationCreatePaths(lineage contract.GeneratorLineageTemplate, branch uint8, gate uint8) ([][]contract.GeneratorAttemptTemplate, error) {
	if lineage.Purpose != contract.GeneratorLineageCreate || branch >= lineage.TemplateCount {
		return nil, contract.ErrRecord
	}
	x := lineage.Templates[branch]
	paths := [][]contract.GeneratorAttemptTemplate{{x}}
	for _, nextGate := range []uint8{contract.GeneratorGuardQualifiedNoEffect, contract.GeneratorGuardResidue} {
		if gate != 0 && nextGate != gate {
			continue
		}
		next, present, err := x.SuccessorBranch(nextGate)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		if next >= lineage.TemplateCount {
			return nil, contract.ErrRecord
		}
		tails, err := continuationCreatePaths(lineage, next, 0)
		if err != nil {
			return nil, err
		}
		for _, tail := range tails {
			path := make([]contract.GeneratorAttemptTemplate, 1, len(tail)+1)
			path[0] = x
			path = append(path, tail...)
			if len(path) > contract.GeneratorMaxEnteredCreateAttempts {
				return nil, contract.ErrRecord
			}
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func (growth *continuationGrowth) merge(other continuationGrowth, alternative bool) error {
	if growth.parts == nil {
		growth.parts = make(map[continuationPartition]continuationPartitionCharge)
	}
	for key, value := range other.parts {
		old := growth.parts[key]
		if alternative {
			old.count, old.framed = max(old.count, value.count), max(old.framed, value.framed)
		} else {
			var err error
			old.count, err = capacityAdd(old.count, value.count)
			if err != nil {
				return err
			}
			old.framed, err = capacityAdd(old.framed, value.framed)
			if err != nil {
				return err
			}
		}
		old.width = max(old.width, value.width)
		growth.parts[key] = old
	}
	if alternative {
		growth.accessCount = max(growth.accessCount, other.accessCount)
		growth.accessBytes = max(growth.accessBytes, other.accessBytes)
		growth.newGroups = max(growth.newGroups, other.newGroups)
		growth.templates = max(growth.templates, other.templates)
	} else {
		var err error
		growth.accessCount, err = capacityAdd(growth.accessCount, other.accessCount)
		if err != nil {
			return err
		}
		growth.accessBytes, err = capacityAdd(growth.accessBytes, other.accessBytes)
		if err != nil {
			return err
		}
		growth.newGroups, err = capacityAdd(growth.newGroups, other.newGroups)
		if err != nil {
			return err
		}
		growth.templates, err = capacityAdd(growth.templates, other.templates)
		if err != nil {
			return err
		}
	}
	growth.accessWidth = max(growth.accessWidth, other.accessWidth)
	return nil
}

// A path contains only selected graph templates. These flags describe the
// actual transition prefix that can write each template, not a future request.
type continuationTemplateReach struct {
	template                               contract.GeneratorAttemptTemplate
	write, result, hazard, canonical, duty bool
}

func continuationTemplateCharge(population, projected continuationPopulation, reach continuationTemplateReach) {
	x := reach.template
	if reach.write {
		class := format.CreateContinuationSupport
		if x.Action == contract.GeneratorActionDelete {
			class = format.DeleteContinuationSupport
		}
		width := uint64(format.RequiredSupportGroupLimit(class))
		projected.atLeast(continuationGroupKey{class: class, owner: x.AttemptID}, width/contract.SupportRecordMinLength, width)
	}
	if x.Action == contract.GeneratorActionCreate && reach.result {
		projected.atLeast(continuationGroupKey{class: format.ResultSupport, owner: x.ResultID}, 1, uint64(contract.SupportRecordOverhead+contract.GeneratedResultRecordMaxLength))
	}
	if reach.canonical {
		projected.atLeast(continuationGroupKey{class: format.OldValueSupport, owner: x.ResultID, mandatory: true}, 1, generatedCurrentEvidenceCharge)
	}
	if reach.write || reach.duty || reach.hazard {
		// A fence and a failed Final replace this same Duty with its Hazard;
		// they do not retain two owner bodies. Both fixed bodies are654bytes.
		// Use an existing Duty group as the replacement stream when present.
		owner := x.DutyID
		if reach.hazard {
			key := continuationGroupKey{class: format.OwnerSupport, owner: owner}
			other := key
			other.mandatory = true
			if population[key].count+population[other].count == 0 {
				owner = x.HazardID
			}
		}
		if !owner.IsZero() {
			projected.atLeast(continuationGroupKey{class: format.OwnerSupport, owner: owner}, 2, generatedOwnerGroupCharge)
		}
	}

}

func continuationPathGrowth(image *selectedImage, population continuationPopulation, bundle contract.GeneratorPlanBundle, path []continuationTemplateReach) (continuationGrowth, error) {
	projected := make(continuationPopulation)
	materials := make(map[materialIdentity]bool)
	for _, page := range image.access {
		if page != nil {
			for _, row := range page.Records {
				materials[materialIdentity{row.MaterialKind, row.MaterialID}] = true
			}
		}
	}
	growth := continuationGrowth{parts: make(map[continuationPartition]continuationPartitionCharge)}
	access := make(map[materialIdentity]uint64)
	for _, reach := range path {
		x := reach.template
		continuationTemplateCharge(population, projected, reach)
		material := materialIdentity{contract.ValueMaterialKind, x.PlannedValueSlotID}
		if reach.canonical && !materials[material] {
			readers := uint64(0)
			for _, entry := range bundle.ValueEntryPlans {
				if entry.LineageID == x.LineageID {
					readers = uint64(entry.IntendedMembership.Count)
					break
				}
			}
			if readers == 0 || readers > contract.CryptoMaxValueEntryRecipients {
				return growth, contract.ErrRecord
			}
			readers += uint64(boolInt(image.root.CurrentAccess.Core.Recovery != nil))
			access[material] = contract.AccessRecordFixedLength + readers*contract.WrapRowWireLength
		}
	}
	for key, value := range projected {
		before := population[key]
		opposite := key
		opposite.mandatory = !key.mandatory
		other := population[opposite]
		before.count, before.framed = before.count+other.count, before.framed+other.framed
		if key.class == format.CreateContinuationSupport || key.class == format.DeleteContinuationSupport {
			growth.templates++
		}
		if key.class == format.OwnerSupport && before.framed == 0 {
			growth.newGroups++
		}
		if value.framed <= before.framed {
			continue
		}
		part := continuationPartition{key.class, key.mandatory}
		charge := growth.parts[part]
		charge.framed += value.framed - before.framed
		charge.count += value.count - min(value.count, before.count)
		charge.width = max(charge.width, value.framed)
		growth.parts[part] = charge
	}
	for _, width := range access {
		growth.accessCount++
		growth.accessBytes += width
		growth.accessWidth = max(growth.accessWidth, width)
	}
	return growth, nil
}

// Keep component maxima of sums at one shared phase cost. Inputs remain
// immutable; each destination belongs to the next cost row of this fold.
func (growth *continuationGrowth) mergeSum(left, right continuationGrowth) error {
	if growth.parts == nil {
		growth.parts = make(map[continuationPartition]continuationPartitionCharge)
	}
	add := func(key continuationPartition, a, b continuationPartitionCharge) error {
		count, err := capacityAdd(a.count, b.count)
		if err != nil {
			return err
		}
		framed, err := capacityAdd(a.framed, b.framed)
		if err != nil {
			return err
		}
		old := growth.parts[key]
		old.count, old.framed, old.width = max(old.count, count), max(old.framed, framed), max(old.width, max(a.width, b.width))
		growth.parts[key] = old
		return nil
	}
	for key, value := range left.parts {
		if err := add(key, value, right.parts[key]); err != nil {
			return err
		}
	}
	for key, value := range right.parts {
		if _, present := left.parts[key]; !present {
			if err := add(key, continuationPartitionCharge{}, value); err != nil {
				return err
			}
		}
	}
	for _, scalar := range []struct {
		target *uint64
		a, b   uint64
	}{
		{&growth.accessCount, left.accessCount, right.accessCount},
		{&growth.accessBytes, left.accessBytes, right.accessBytes},
		{&growth.newGroups, left.newGroups, right.newGroups},
		{&growth.templates, left.templates, right.templates},
	} {
		value, err := capacityAdd(scalar.a, scalar.b)
		if err != nil {
			return err
		}
		*scalar.target = max(*scalar.target, value)
	}
	growth.accessWidth = max(growth.accessWidth, max(left.accessWidth, right.accessWidth))
	return nil
}

type continuationPrefixOption struct {
	steps               uint64
	terminal, selecting bool
	ordinary, selected  continuationGrowth
}

// The already bounded <=3-template paths supply prefixes and terminal choices.
// A NoEffect edge is its Record; a residue edge is a result-free fence. The
// successor's Reserve is separate. Only the successful last frontier can be
// selected into canonical evidence and access.
func continuationLineageOptions(image *selectedImage, population continuationPopulation, bundle contract.GeneratorPlanBundle, lineage contract.GeneratorLineageTemplate, branch, gate uint8, entered bool) ([]continuationPrefixOption, error) {
	paths, err := continuationCreatePaths(lineage, branch, gate)
	if err != nil {
		return nil, err
	}
	var options []continuationPrefixOption
	appendOption := func(steps uint64, reaches []continuationTemplateReach, terminal, selecting bool) error {
		ordinary, err := continuationPathGrowth(image, population, bundle, reaches)
		if err != nil {
			return err
		}
		option := continuationPrefixOption{steps: steps, terminal: terminal, selecting: selecting, ordinary: ordinary}
		if selecting {
			selected := slices.Clone(reaches)
			selected[len(selected)-1].canonical = true
			option.selected, err = continuationPathGrowth(image, population, bundle, selected)
			if err != nil {
				return err
			}
		}
		options = append(options, option)
		return nil
	}
	for _, path := range paths {
		reaches := []continuationTemplateReach{{template: path[0]}}
		var steps uint64
		if !entered {
			steps++
			reaches[0].write = true
			if err := appendOption(steps, reaches, false, false); err != nil {
				return nil, err
			}
		}
		for i := range path {
			if i != 0 {
				prior := &reaches[i-1]
				prior.write = true
				if path[i].Branch == contract.GeneratorBranchNoEffect || path[i].Branch == contract.GeneratorBranchResidueThenNoEffect {
					prior.result = true
				} else {
					prior.hazard = true
				}
				steps++
				if err := appendOption(steps, reaches, false, false); err != nil {
					return nil, err
				}
				reaches = append(reaches, continuationTemplateReach{template: path[i], write: true})
				steps++
				if err := appendOption(steps, reaches, false, false); err != nil {
					return nil, err
				}
			}
			if i != len(path)-1 {
				continue
			}
			terminal := slices.Clone(reaches)
			terminal[i].write, terminal[i].result = true, true
			if err := appendOption(steps+1, terminal, true, true); err != nil {
				return nil, err
			}
			// OwnedUnusable Record is terminal but still stores its Duty.
			// A later failed Final may replace it by an equal-width Hazard.
			if err := appendOption(steps+1, terminal, true, false); err != nil {
				return nil, err
			}
			fenced := slices.Clone(reaches)
			fenced[i].write, fenced[i].hazard = true, true
			_, successor, err := path[i].SuccessorBranch(contract.GeneratorGuardResidue)
			if err != nil {
				return nil, err
			}
			if err := appendOption(steps+1, fenced, !successor, false); err != nil {
				return nil, err
			}
		}
	}
	return options, nil
}

// Parking consumes one transition after Reserve, retains its unknown Attempt
// and Duty, and advances the cursor. Its full64KiB delete-group envelope also
// bounds ACK's retained minimal Attempt+PendingInboxRelease in that SAME group;
// ACK takes an additional Record/Close transition. The release replaces one
// Duty administrative owner, so it does not increase owner count. Accumulating
// these retained per-cursor envelopes therefore covers both affordable paths.
func continuationAutomaticGrowth(image *selectedImage, population continuationPopulation, generated *generatedSelection, budget uint64, future bool) (continuationGrowth, error) {
	var maximum continuationGrowth
	bundle := generated.bundles[0]
	var elapsed uint64
	var retained []continuationTemplateReach
	for _, index := range contract.GeneratedAutomaticRetirementIndices(bundle) {
		if !future && index < generated.phase.LineageIndex {
			continue
		}
		x := bundle.Lineages[index].Templates[0]
		attempt, entered := generated.attempts[x.AttemptID]
		current := !future && index == generated.phase.LineageIndex
		if !current {
			entered = false
		}
		if current && entered && attempt.record.Stage == contract.GeneratedStageTerminal {
			elapsed++ // Its real ACK Close retains the selected minimal group.
			continue
		}
		reserve := uint64(1)
		if entered {
			reserve = 0
		}
		if elapsed+reserve > budget {
			break
		}
		prefix := append(slices.Clone(retained), continuationTemplateReach{template: x, write: true})
		// An already entered producer needs one remaining step to Record/Park.
		if !entered || elapsed+1 <= budget {
			delta, err := continuationPathGrowth(image, population, bundle, prefix)
			if err != nil {
				return maximum, err
			}
			if err := maximum.merge(delta, true); err != nil {
				return maximum, err
			}
		}
		if elapsed+reserve+1 > budget {
			break // Reserve fits; Park or Record does not.
		}
		retained = prefix
		elapsed += reserve + 1 // Park retains this group and advances the cursor.
	}
	return maximum, nil
}

func continuationFinalRetirementGrowth(image *selectedImage, population continuationPopulation, generated *generatedSelection) (continuationGrowth, error) {
	bundle := generated.bundles[0]
	var duties []continuationTemplateReach
	withDuties := make(continuationPopulation, len(population))
	for key, value := range population {
		withDuties[key] = value
	}
	for _, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageRetirement {
			continue
		}
		x := lineage.Templates[0]
		duties = append(duties, continuationTemplateReach{template: x, duty: true})
		withDuties.atLeastWholeGroup(continuationGroupKey{class: format.OwnerSupport, owner: x.DutyID}, 2, generatedOwnerGroupCharge)
	}
	growth, err := continuationPathGrowth(image, population, bundle, duties)
	if err != nil {
		return growth, err
	}
	// Selecting Final already reserves the complete automatic close suffix.
	// Its cumulative retained cursor prefix is therefore affordable.
	automatic, err := continuationAutomaticGrowth(image, withDuties, generated, uint64(3*len(contract.GeneratedAutomaticRetirementIndices(bundle))), true)
	if err != nil {
		return growth, err
	}
	if err := growth.merge(automatic, false); err != nil {
		return growth, err
	}
	return growth, nil
}

func continuationVectorGrowth(image *selectedImage, generated *generatedSelection, growth *continuationGrowth, preparation bool) error {
	if generated.parent == nil {
		return nil
	}
	bundle := generated.bundles[0]
	owners := map[contract.ID]bool{generated.parent.OperationID: true, generated.parent.MaterialID: true}
	for _, lineage := range bundle.Lineages {
		owners[lineage.LineageID] = true
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			for _, id := range []contract.ID{x.AttemptID, x.DutyID, x.HazardID, x.ResultID} {
				owners[id] = true
			}
		}
	}
	type vectorCharge struct{ count, framed uint64 }
	current := make(map[contract.GeneratorVectorKind]vectorCharge)
	for _, page := range image.support {
		for _, row := range page.Records {
			if row.Kind != contract.GeneratorVectorSupportKind {
				continue
			}
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return err
			}
			if !owners[carrier.OwnerID] || carrier.VectorKind != contract.GeneratorVectorConsumers && carrier.VectorKind != contract.GeneratorVectorSupport {
				continue
			}
			charge := current[carrier.VectorKind]
			charge.count++
			charge.framed += uint64(contract.SupportRecordOverhead + len(row.Body))
			current[carrier.VectorKind] = charge
		}
	}
	if growth.parts == nil {
		growth.parts = make(map[continuationPartition]continuationPartitionCharge)
	}
	for _, kind := range []contract.GeneratorVectorKind{contract.GeneratorVectorConsumers, contract.GeneratorVectorSupport} {
		before := current[kind]
		count := max(before.count, uint64(bundle.Header.ValueEntryPlanCount)+2*growth.templates)
		row := uint64(contract.GeneratorConsumerLength)
		if kind == contract.GeneratorVectorSupport {
			row = contract.GeneratorSupportBindingMaxLength
		}
		width := uint64(contract.SupportRecordOverhead+contract.GeneratorCarrierFixedLength) + row
		wanted := count * width
		key := continuationPartition{class: format.AuxiliaryIndexSupport}
		charge := growth.parts[key]
		charge.count += count - min(count, before.count)
		charge.framed += wanted - min(wanted, before.framed)
		charge.width = max(charge.width, width)
		growth.parts[key] = charge
	}
	if preparation {
		key := continuationPartition{class: format.GraphIndexSupport}
		charge := growth.parts[key]
		charge.count++
		charge.framed += generatedSliceCarrierCharge
		charge.width = max(charge.width, generatedSliceCarrierCharge)
		growth.parts[key] = charge
	}
	return nil
}

type continuationFinalShape struct {
	possible, materialized                                         bool
	values                                                         contract.GeneratorCapacityGroup
	registry                                                       contract.GeneratorCapacityGroup
	names, preparationBytes, accessCount, accessBytes, accessWidth uint64
	accessGrowthBytes, accessGrowthWidth                           uint64
}

// A completed failed lineage cannot be retried by this parent. Pending
// lineages retain the minimum permitted successful Reserve/Record path;
// alternative recovery orders are never added to that minimum.
func continuationMaySelectFinal(ctx context.Context, image *selectedImage, generated *generatedSelection) (bool, bool, error) {
	if generated.parent == nil {
		return false, false, nil
	}
	if generated.phase == nil || len(generated.bundles) == 0 {
		return false, false, contract.ErrRecord
	}
	if generatedSelectionAnchored(generated) {
		return false, false, nil
	}
	bundle := generated.bundles[0]
	if bundle.Request.OperationKind != contract.OperationApplyDeclaration && bundle.Request.OperationKind != contract.OperationRotateValueEntryValue {
		return false, false, nil
	}
	var pending uint64
	for index, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		if index >= int(generated.phase.LineageIndex) && generated.phase.Stage != contract.GeneratedStageTerminal {
			branch := uint8(contract.GeneratorBranchInitial)
			if row, present := generated.records[generatedRecordKey{contract.GeneratedLineageSupportKind, lineage.LineageID}]; present {
				state, err := contract.InspectGeneratedLineageRecord(row.Body)
				if err != nil {
					return false, false, err
				}
				branch = state.Branch
			}
			if branch >= lineage.TemplateCount {
				return false, false, contract.ErrRecord
			}
			attempt, entered := generated.attempts[lineage.Templates[branch].AttemptID]
			if entered && attempt.record.Stage == contract.GeneratedStageTerminal {
				// A terminal successful frontier needs no further Record.
				// A terminal failed frontier cannot become selecting evidence.
				if attempt.record.State != contract.GeneratedEffectSucceeded {
					return false, false, nil
				}
				continue
			}
			pending++ // Record also advances to the next original lineage.
			if !entered && index == int(generated.phase.LineageIndex) && branch != contract.GeneratorBranchInitial {
				pending++ // Only the current planned successor first Reserves.
			}
			continue
		}
		var frontier generatedAttempt
		entered := false
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			if attempt, present := generated.attempts[x.AttemptID]; present {
				frontier, entered = attempt, true
			}
		}
		if !entered {
			return false, false, contract.ErrRecord
		}
		if len(frontier.result) == 0 || frontier.record.State != contract.GeneratedEffectSucceeded {
			return false, false, nil
		}
		result, err := contract.InspectGeneratedResultRecord(frontier.result)
		if err != nil {
			return false, false, err
		}
		if result.Disposition() != contract.GeneratorDispositionCompleteCreate {
			return false, false, nil
		}
	}
	materialized := false
	if generated.preparation != nil {
		var err error
		materialized, err = selectedFinalPreparationReusable(ctx, image, generated)
		if err != nil {
			return false, false, err
		}
	}
	needed := pending + generatedFinalPhaseSteps(bundle, materialized)
	return uint64(generated.phase.Phase)+needed <= math.MaxUint32, materialized, nil
}

func selectedContinuationFinalShape(ctx context.Context, image *selectedImage, generated *generatedSelection, read selectedFragmentRead) (continuationFinalShape, error) {
	var shape continuationFinalShape
	possible, materialized, err := continuationMaySelectFinal(ctx, image, generated)
	if err != nil || !possible {
		return shape, err
	}
	shape.possible, shape.materialized = possible, materialized
	if len(generated.bundles) == 0 || generated.content == nil {
		return shape, contract.ErrRecord
	}
	bundle := generated.bundles[0]
	var body []byte
	_, err = generated.content.streamLogical(ctx, contract.GeneratorContentDeclaration, generated.parent.OperationID, contract.GeneratorDeclarationMaxLength, func(part []byte) error {
		body = append(body, part...)
		return nil
	}, read)
	defer clear(body)
	if err != nil {
		return shape, err
	}
	declaration, err := contract.InspectGeneratorDeclaration(body)
	if err != nil {
		return shape, err
	}
	if err := contract.ValidateGeneratorDeclarationGraph(declaration, bundle); err != nil {
		return shape, err
	}
	attemptSecretBounds := make(map[contract.ID]uint64, len(bundle.ResultUses))
	for _, use := range bundle.ResultUses {
		attemptSecretBounds[use.AttemptID] = max(attemptSecretBounds[use.AttemptID], uint64(use.MaxSecret))
	}
	lineageSecretBounds := make(map[contract.ID]uint64, len(bundle.Lineages))
	for _, lineage := range bundle.Lineages {
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			lineageSecretBounds[lineage.LineageID] = max(lineageSecretBounds[lineage.LineageID], attemptSecretBounds[template.AttemptID])
		}
	}
	entries := make(map[string]contract.GeneratorDeclarationEntryView, declaration.EntryCount())
	for i := 0; i < declaration.EntryCount(); i++ {
		entry, _, err := declaration.Entry(i)
		if err != nil {
			return shape, err
		}
		entries[string(entry.Name)] = entry
	}
	registryCount := uint64(image.root.RecipientCount)
	if generated.registry != nil {
		records, err := image.generatedEffectiveRecipients(generated)
		if err != nil {
			return shape, err
		}
		registryCount = max(registryCount, uint64(len(records)))
		shape.registry.MaxCount = uint64(len(records))
		shape.registry.MaxPages = uint32(capacityCeiling(shape.registry.MaxCount, format.RecipientSlots))
		for _, row := range records {
			length, err := contract.RecipientRecordLength(row)
			if err != nil {
				return shape, err
			}
			shape.registry.MaxFramedBytes += uint64(length)
		}
		shape.registry.MaxFramedBytes += uint64(shape.registry.MaxPages) * format.RecipientSlots
	}
	current := make(map[string]*contract.ValueEntry, len(image.root.Names))
	for _, named := range image.root.Names {
		current[named.Name] = image.valueEntry(named.Slot)
	}
	var pages [contract.MaxValueEntryPages]bool
	var raw, memberships, secrets, preparedReaders uint64
	recovery := uint64(boolInt(image.root.CurrentAccess.Core.Recovery != nil))
	for _, plan := range bundle.ValueEntryPlans {
		if err := ctx.Err(); err != nil {
			return shape, err
		}
		entry, ok := entries[plan.Name]
		if !ok || len(entry.RecipientIDs)%32 != 0 {
			return shape, contract.ErrRecord
		}
		ids := make([]contract.ID, len(entry.RecipientIDs)/32)
		for i := range ids {
			ids[i] = contract.ID(entry.RecipientIDs[32*i : 32*(i+1)])
		}
		memberships += uint64(len(ids))
		shape.names += uint64(6 + len(plan.Name))
		pages[plan.Slot/format.PageSlots] = true
		var length, retainedLength uint64
		switch entry.Kind {
		case contract.GeneratorDeclarationPlain:
			content, err := contract.InputContentLength(entry.InputEncoding, entry.Payload)
			if err != nil {
				return shape, err
			}
			length, retainedLength = uint64(content), uint64(len(entry.Payload))
		case contract.GeneratorDeclarationSealed:
			sealed, err := contract.InspectSealedInputEnvelope(entry.Payload)
			if err != nil {
				return shape, err
			}
			length, retainedLength = uint64(sealed.Core.ContentLength), uint64(sealed.Core.RetainedLength)
		case contract.GeneratorDeclarationRetained:
			retained, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
			if err != nil {
				return shape, err
			}
			payload, err := contract.InspectCanonicalPayload(retained.Entry.ValueBytes)
			if err != nil {
				return shape, err
			}
			length, retainedLength = uint64(payload.ContentLength), uint64(payload.RetainedLength)
		case contract.GeneratorDeclarationGenerated, contract.GeneratorDeclarationGeneratedReference:
			if plan.ChangeMask&contract.GeneratorValueChangeContent == 0 {
				prior := current[plan.Name]
				if prior == nil {
					return shape, contract.ErrRecord
				}
				payload, err := contract.InspectCanonicalPayload(prior.ValueBytes)
				if err != nil {
					return shape, err
				}
				length, retainedLength = uint64(payload.ContentLength), uint64(payload.RetainedLength)
			} else {
				length = lineageSecretBounds[plan.LineageID]
				retainedLength = length
				if plan.InputEncoding == contract.InputEncodingBase64 {
					retainedLength = 4 * ((length + 2) / 3)
				}
			}
		default:
			return shape, contract.ErrRecord
		}
		raw += length
		if length > contract.CryptoMaxRawValue || raw > contract.CryptoMaxRawSet || memberships > contract.CryptoMaxMemberships {
			return shape, contract.ErrRecord
		}
		width := uint64(contract.ValueEntryFixedLength+len(plan.Name)) + 32*uint64(len(ids)) + retainedLength
		if plan.ConfidentialityClass == contract.Secret {
			secrets++
			width += contract.CanonicalPayloadOverhead
			readers := uint64(len(ids))
			freshGenerated := plan.ValueSource == contract.Generated && plan.ChangeMask&contract.GeneratorValueChangeContent != 0
			if !freshGenerated {
				readers, err = generatedFinalImageReaderCount(current[plan.Name], ids, generated, registryCount)
				if err != nil {
					return shape, err
				}
				prior := current[plan.Name]
				if prior == nil || prior.Incarnation != plan.EntryIncarnationID || plan.ChangeMask&contract.GeneratorValueChangeContent != 0 {
					access := uint64(contract.AccessRecordFixedLength) + (readers+recovery)*contract.WrapRowWireLength
					shape.accessCount++
					shape.accessBytes += access
					shape.accessWidth = max(shape.accessWidth, access)
				} else {
					access, ok := generated.materialAccess(contract.ValueMaterialKind, prior.ValueState)
					if !ok {
						return shape, contract.ErrRecord
					}
					length, err := contract.AccessRecordLength(access)
					if err != nil {
						return shape, err
					}
					wanted := uint64(contract.AccessRecordFixedLength) + (readers+recovery)*contract.WrapRowWireLength
					shape.accessGrowthBytes += wanted - min(wanted, uint64(length))
					shape.accessGrowthWidth = max(shape.accessGrowthWidth, wanted)
				}
			} else {
				var maximumGrowth, maximumWidth uint64
				for _, lineage := range bundle.Lineages {
					if lineage.LineageID != plan.LineageID {
						continue
					}
					for _, x := range lineage.Templates[:lineage.TemplateCount] {
						access, ok := generated.materialAccess(contract.ValueMaterialKind, x.PlannedValueSlotID)
						if !ok {
							continue
						}
						length, err := contract.AccessRecordLength(access)
						if err != nil {
							return shape, err
						}
						wanted := uint64(contract.AccessRecordFixedLength) + (readers+recovery)*contract.WrapRowWireLength
						maximumGrowth = max(maximumGrowth, wanted-min(wanted, uint64(length)))
						maximumWidth = max(maximumWidth, wanted)
					}
				}
				shape.accessGrowthBytes += maximumGrowth
				shape.accessGrowthWidth = max(shape.accessGrowthWidth, maximumWidth)
			}
			preparedReaders += readers + recovery
		}
		if plan.ValueSource == contract.Generated {
			width += generatedEntryMetadataCharge
		}
		shape.values.MaxCount++
		shape.values.MaxFramedBytes += width
	}
	for _, present := range pages {
		if present {
			shape.values.MaxPages++
		}
	}
	var creates uint64
	for _, lineage := range bundle.Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			creates++
		}
	}
	if creates != 0 && !materialized {
		shape.preparationBytes = generatedFinalImageCapacity(shape.values.MaxFramedBytes, secrets*contract.AccessRecordFixedLength+preparedReaders*contract.WrapRowWireLength, 0, creates, shape.values.MaxCount)
	}
	return shape, nil
}

func continuationPageGroup(refs []format.Ref, count uint64) (contract.GeneratorCapacityGroup, error) {
	group := contract.GeneratorCapacityGroup{MaxCount: count}
	seen := make(map[format.Ref]bool, len(refs))
	for _, ref := range refs {
		if seen[ref] || ref.Length < contract.RequiredSupportPageHeaderLength {
			return group, contract.ErrRecord
		}
		seen[ref] = true
		group.MaxPages++
		group.MaxFramedBytes += uint64(ref.Length - contract.RequiredSupportPageHeaderLength)
	}
	return group, nil
}

func continuationCurrentGroups(image *selectedImage, groups *[contract.GeneratorCapacityGroupCount]contract.GeneratorCapacityGroup, final continuationFinalShape, growth continuationGrowth) error {
	var values, recipients []format.Ref
	for _, ref := range image.root.ValueEntryPages {
		if ref != nil {
			values = append(values, *ref)
		}
	}
	for _, ref := range image.root.Recipients {
		if ref != nil {
			recipients = append(recipients, *ref)
		}
	}
	for _, entry := range []struct {
		tag   int
		refs  []format.Ref
		count uint64
	}{
		{contract.GeneratorCapacityCurrentValueEntries, values, uint64(image.root.ValueEntryCount)},
		{contract.GeneratorCapacityCurrentRecipients, recipients, uint64(image.root.RecipientCount)},
		{contract.GeneratorCapacityCurrentAccess, image.root.CurrentAccess.Core.AccessPageRefs, uint64(image.root.AccessRecordCount)},
	} {
		group, err := continuationPageGroup(entry.refs, entry.count)
		if err != nil {
			return err
		}
		groups[entry.tag] = group
	}
	valueGroup := &groups[contract.GeneratorCapacityCurrentValueEntries]
	valueGroup.MaxCount = max(valueGroup.MaxCount, final.values.MaxCount)
	valueGroup.MaxFramedBytes = max(valueGroup.MaxFramedBytes, final.values.MaxFramedBytes)
	valueGroup.MaxPages = max(valueGroup.MaxPages, final.values.MaxPages)
	registryGroup := &groups[contract.GeneratorCapacityCurrentRecipients]
	registryGroup.MaxCount = max(registryGroup.MaxCount, final.registry.MaxCount)
	registryGroup.MaxFramedBytes = max(registryGroup.MaxFramedBytes, final.registry.MaxFramedBytes)
	registryGroup.MaxPages = max(registryGroup.MaxPages, final.registry.MaxPages)
	if final.accessGrowthBytes != 0 {
		group := &groups[contract.GeneratorCapacityCurrentAccess]
		group.MaxFramedBytes += final.accessGrowthBytes
		maximumWidth := final.accessGrowthWidth
		for _, page := range image.access {
			if page == nil {
				continue
			}
			for _, row := range page.Records {
				length, err := contract.AccessRecordLength(row)
				if err != nil {
					return err
				}
				maximumWidth = max(maximumWidth, uint64(length))
			}
		}
		payload := uint64(contract.MaxAccessPageLength - contract.AccessPageHeaderLength)
		if maximumWidth == 0 || maximumWidth > payload {
			return contract.ErrRecord
		}
		group.MaxPages = max(group.MaxPages, uint32(1+(group.MaxFramedBytes-1)/(payload-maximumWidth+1)))
	}
	count := growth.accessCount + final.accessCount
	bytes := growth.accessBytes + final.accessBytes
	width := max(growth.accessWidth, final.accessWidth)
	if count != 0 {
		payload := uint64(contract.MaxAccessPageLength - contract.AccessPageHeaderLength)
		if width == 0 || width > payload {
			return contract.ErrRecord
		}
		groups[contract.GeneratorCapacityCandidateAccess] = contract.GeneratorCapacityGroup{MaxCount: count, MaxFramedBytes: bytes, MaxPages: uint32(1 + (bytes-1)/(payload-width+1))}
	}
	return nil
}

func boundSelectedPhaseGroup(population continuationPopulation, generated *generatedSelection) error {
	if generated.parent == nil {
		return nil
	}
	if len(generated.bundles) == 0 {
		return contract.ErrRecord
	}
	for _, lineage := range generated.bundles[0].Lineages {
		for _, x := range lineage.Templates[:lineage.TemplateCount] {
			if _, entered := generated.attempts[x.AttemptID]; !entered {
				continue
			}
			class := format.CreateContinuationSupport
			if x.Action == contract.GeneratorActionDelete {
				class = format.DeleteContinuationSupport
			}
			width := uint64(format.RequiredSupportGroupLimit(class))
			population.atLeastWholeGroup(continuationGroupKey{class: class, owner: x.AttemptID}, width/contract.SupportRecordMinLength, width)
			return nil
		}
	}
	return contract.ErrRecord
}

func capacityBoundBasis(root contract.ID, scope capacityBoundScope) contract.ID {
	body := append([]byte("ENKV/CAPACITY/current/v1\x00"), byte(scope))
	body = append(body, root[:]...)
	return contract.Hash(body)
}

func setCapacityBoundTotals(bound *selectedCapacityBound) error {
	bound.AdministrativeIndexShards = capacityCeiling(bound.AdministrativeIndexBytes, uint64(format.AdministrativeIndexShardPayloadLimit))
	children := bound.AdministrativeIndexShards
	bytes := bound.AdministrativeIndexBytes
	indexFrames, err := capacityMultiply(bound.AdministrativeIndexShards, uint64(contract.MaxRequiredSupportPageLength-format.AdministrativeIndexShardPayloadLimit))
	if err != nil {
		return err
	}
	bytes, err = capacityAdd(bytes, indexFrames)
	if err != nil {
		return err
	}
	for _, group := range bound.Groups {
		children, err = capacityAdd(children, uint64(group.MaxPages))
		if err != nil {
			return err
		}
		frames, err := capacityMultiply(uint64(group.MaxPages), contract.RequiredSupportPageHeaderLength)
		if err != nil {
			return err
		}
		bytes, err = capacityAdd(bytes, group.MaxFramedBytes)
		if err != nil {
			return err
		}
		bytes, err = capacityAdd(bytes, frames)
		if err != nil {
			return err
		}
	}
	bound.ChildPages, bound.ChildEncodedBytes = children, bytes
	return nil
}

func reserveContinuationReceipts(image *selectedImage, population continuationPopulation, growth *continuationGrowth) error {
	index, err := selectedReceiptIndexID(image.root.Domain, image.root)
	if err != nil {
		return err
	}
	for key := range population {
		if key.class == format.ReceiptSupport || !index.IsZero() && key.class == format.AuxiliaryFragmentSupport && key.owner == index {
			delete(population, key)
		}
	}
	if growth.parts == nil {
		growth.parts = make(map[continuationPartition]continuationPartitionCharge)
	}
	count := uint64(2 * contract.MutationReceiptWindowLimit)
	width := uint64(contract.SupportRecordOverhead + contract.CompactMutationReceiptLength)
	growth.parts[continuationPartition{class: format.ReceiptSupport, mandatory: true}] = continuationPartitionCharge{count: count, framed: count * width, width: width}
	// The order is already in the one complete receipt index, not a second
	// allocation described by its root descriptor.
	width = contract.MutationReceiptIndexesMaxLength + generatedFragmentCharge
	key := continuationPartition{class: format.AuxiliaryFragmentSupport, mandatory: true}
	extra := growth.parts[key]
	extra.count++
	extra.framed += width
	extra.width = max(extra.width, width)
	growth.parts[key] = extra
	return nil
}

// Replacing one logical preparation does not duplicate its exclusive physical
// blob. A blob still referenced by any other selected slice remains intact;
// its complete physical charge stays once beside the new image.
func continuationPreparationPopulation(population continuationPopulation, generated *generatedSelection, bytes uint64) error {
	fragments := capacityCeiling(bytes, contract.GeneratedFragmentMaxPayload)
	framed := bytes + fragments*generatedFragmentCharge
	key := continuationGroupKey{class: format.AuxiliaryFragmentSupport, owner: generated.parent.OperationID}
	if generated.preparation != nil {
		logical := generatedContentKey{contract.GeneratorContentFinalPreparation, generated.preparation.Image.ContentID}
		before, present := generated.content.locations[logical]
		if !present {
			return contract.ErrRecord
		}
		shared := false
		for retained, location := range generated.content.locations {
			if retained != logical && location.BlobID == before.BlobID {
				shared = true
				break
			}
		}
		if !shared {
			key.owner = before.BlobID
			other := key
			other.mandatory = true
			if population[key].count+population[other].count == 0 {
				return contract.ErrRecord
			}
			population.atLeastWholeGroup(key, fragments, framed)
			return nil
		}
	}
	population.atLeast(key, fragments, framed)
	return nil
}

func calculateSelectedContinuationCapacity(ctx context.Context, image *selectedImage, generated *generatedSelection, read selectedFragmentRead) (selectedContinuationCapacity, error) {
	var out selectedContinuationCapacity
	if ctx == nil || image == nil || generated == nil || generated.image == nil || generated.content == nil || !image.receiptsValidated || image.root.Domain != generated.image.root.Domain || image.root.Snapshot != generated.image.root.Snapshot {
		return out, contract.ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	root, err := format.EncodeRoot(image.root)
	if err != nil {
		return out, err
	}
	out.RootDigest, out.Graphs, out.GCPlans = contract.Hash(root), image.root.Generated.Graphs, image.root.GCPlans
	gc, err := selectedGCState(image, true)
	if err != nil {
		return out, err
	}
	population, err := selectedContinuationGroups(ctx, image, generated)
	if err != nil {
		return out, err
	}
	if err := boundSelectedPhaseGroup(population, generated); err != nil {
		return out, err
	}
	final, err := selectedContinuationFinalShape(ctx, image, generated, read)
	if err != nil {
		return out, err
	}
	growth, err := selectedContinuationGrowthForFinal(ctx, image, generated, population, final.possible, final.materialized)
	if err != nil {
		return out, err
	}
	preparation := final.preparationBytes != 0
	if err := continuationVectorGrowth(image, generated, &growth, preparation && generated.preparation == nil); err != nil {
		return out, err
	}
	if preparation {
		if err := continuationPreparationPopulation(population, generated, final.preparationBytes); err != nil {
			return out, err
		}
	}
	publication, err := selectedPublicationCapacity(ctx, image)
	if err != nil {
		return out, err
	}
	for key, extra := range publication.growth {
		old := population[key]
		population[key] = continuationGroupCharge{count: old.count, framed: old.framed + extra}
	}
	if generated.parent != nil || len(image.adminIndex.Groups) != 0 {
		if err := reserveContinuationReceipts(image, population, &growth); err != nil {
			return out, err
		}
	}
	groups, rows, err := continuationGroupTotals(population, growth)
	if err != nil {
		return out, err
	}
	if err := continuationCurrentGroups(image, &groups, final, growth); err != nil {
		return out, err
	}
	if generated.parent != nil {
		// A required row can become current provenance while sibling work stays
		// disposable. One additional flush per class covers that partition.
		for _, tag := range []int{contract.GeneratorCapacityOldValues, contract.GeneratorCapacityOwners, contract.GeneratorCapacityGraph, contract.GeneratorCapacityAuxiliary} {
			if groups[tag].MaxFramedBytes != 0 {
				if groups[tag].MaxPages == math.MaxUint32 {
					return out, contract.ErrRecordCapacity
				}
				groups[tag].MaxPages++
			}
		}
	}
	var supportPages uint64
	for tag, group := range groups {
		if tag != contract.GeneratorCapacityCurrentValueEntries && tag != contract.GeneratorCapacityCurrentRecipients && tag != contract.GeneratorCapacityCurrentAccess && tag != contract.GeneratorCapacityCandidateAccess {
			supportPages += uint64(group.MaxPages)
		}
	}
	if generated.parent == nil {
		supportPages = max(supportPages, uint64(len(image.root.RequiredSupport)))
	}
	index, err := selectedContinuationIndexLength(image.adminIndex, rows, growth.newGroups, supportPages)
	if err != nil {
		return out, err
	}
	remaining := selectedCapacityBound{Scope: remainingSelectedContinuations, Status: capacitySufficient, BasisDigest: capacityBoundBasis(out.RootDigest, remainingSelectedContinuations), Groups: groups, AdministrativeIndexBytes: index, ChildPageLimit: ordinaryChildPageLimit, RootByteLimit: contract.MaxRootLength, AdministrativePageByteLimit: contract.MaxRequiredSupportPageLength}
	if err := setCapacityBoundTotals(&remaining); err != nil {
		return out, err
	}
	if err := retainContinuationPhysicalPages(image, generated, &remaining, publication); err != nil {
		return out, err
	}
	var currentNames uint64
	for _, name := range image.root.Names {
		currentNames += uint64(6 + len(name.Name))
	}
	remaining.RootBytes = uint64(len(root)) + uint64(contract.RefLength)*(remaining.ChildPages-min(remaining.ChildPages, uint64(image.root.ChildCount))) + final.names - min(final.names, currentNames)
	if generated.parent == nil && len(image.adminIndex.Groups) == 0 {
		remaining.Status = capacityNotApplicable
	}
	if remaining.ChildPages > remaining.ChildPageLimit || remaining.RootBytes > remaining.RootByteLimit {
		remaining.Status = capacityNotEstablished
	}
	out.Remaining = remaining
	out.FirstExit, err = selectedFirstExitCapacity(ctx, image, out.RootDigest, uint64(len(root)), publication)
	if err != nil {
		return out, err
	}
	if err := validateSelectedGCCapacity(gc, image, remaining); err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func retainContinuationPhysicalPages(image *selectedImage, generated *generatedSelection, bound *selectedCapacityBound, publication selectedPublicationCapacityBound) error {
	if generated.parent != nil {
		pages, bytes, err := retainedOutputCapacityOverhead(image)
		if err != nil {
			return err
		}
		if pages != 0 || bytes != 0 {
			oldIndex, oldShards := bound.AdministrativeIndexBytes, bound.AdministrativeIndexShards
			bound.AdministrativeIndexBytes += 108 * pages
			bound.AdministrativeIndexShards = capacityCeiling(bound.AdministrativeIndexBytes, uint64(format.AdministrativeIndexShardPayloadLimit))
			addedShards := bound.AdministrativeIndexShards - oldShards
			bound.ChildPages += pages + addedShards
			bound.ChildEncodedBytes += bytes + bound.AdministrativeIndexBytes - oldIndex + addedShards*uint64(contract.MaxRequiredSupportPageLength-format.AdministrativeIndexShardPayloadLimit)
		}
	}
	var nonSupportPages, nonSupportBytes uint64
	for _, tag := range []int{contract.GeneratorCapacityCurrentValueEntries, contract.GeneratorCapacityCurrentRecipients, contract.GeneratorCapacityCurrentAccess, contract.GeneratorCapacityCandidateAccess} {
		group := bound.Groups[tag]
		nonSupportPages += uint64(group.MaxPages)
		nonSupportBytes += group.MaxFramedBytes + uint64(group.MaxPages)*contract.RequiredSupportPageHeaderLength
	}
	indexBytes := bound.AdministrativeIndexBytes + bound.AdministrativeIndexShards*uint64(contract.MaxRequiredSupportPageLength-format.AdministrativeIndexShardPayloadLimit)
	if generated.parent == nil {
		var supportBytes uint64
		for _, ref := range image.root.RequiredSupport {
			supportBytes += uint64(ref.Length)
		}
		bound.ChildPages = max(bound.ChildPages, nonSupportPages+uint64(len(image.root.RequiredSupport))+bound.AdministrativeIndexShards)
		bound.ChildEncodedBytes = max(bound.ChildEncodedBytes, nonSupportBytes+supportBytes+indexBytes)
	}
	if publication.unresolved {
		futureIndex := max(bound.AdministrativeIndexBytes, publication.indexBytes)
		shards := capacityCeiling(futureIndex, uint64(format.AdministrativeIndexShardPayloadLimit))
		publicationSupportPages := int64(len(image.root.RequiredSupport)) + publication.pageDelta
		if publicationSupportPages < 0 {
			return contract.ErrRecord
		}
		bound.ChildPages = max(bound.ChildPages, nonSupportPages+uint64(publicationSupportPages)+shards)
		publicationIndexBytes := futureIndex + shards*uint64(contract.MaxRequiredSupportPageLength-format.AdministrativeIndexShardPayloadLimit)
		bound.ChildEncodedBytes = max(bound.ChildEncodedBytes, nonSupportBytes+publication.physicalBytes+publicationIndexBytes)
		bound.AdministrativeIndexBytes, bound.AdministrativeIndexShards = futureIndex, shards
	}
	return nil
}

func retainedOutputCapacityOverhead(image *selectedImage) (uint64, uint64, error) {
	facts, err := image.selectedFragmentFactsByRecord()
	if err != nil {
		return 0, 0, err
	}
	var rows, framed, physicalBytes, pages uint64
	for i, page := range image.support {
		if i >= len(image.root.RequiredSupport) {
			return 0, 0, contract.ErrRecord
		}
		outputOnly := len(page.Records) != 0
		var pageRows, pageFramed uint64
		for _, row := range page.Records {
			if row.Kind != contract.OutputConfigurationSliceSupportKind {
				outputOnly = false
				continue
			}
			length := uint64(len(row.Body))
			if row.Body == nil {
				fact, ok := facts[row.RecordID]
				if !ok || fact.row.Kind() != row.Kind {
					return 0, 0, contract.ErrRecord
				}
				length = uint64(fact.row.BodyLength())
			}
			pageRows++
			pageFramed += contract.SupportRecordOverhead + length
		}
		if outputOnly {
			pages++
			physicalBytes += uint64(image.root.RequiredSupport[i].Length)
			rows += pageRows
			framed += pageFramed
		}
	}
	packedPages := capacityCeiling(rows, generatedFragmentsPerPage)
	packedBytes := framed + packedPages*contract.RequiredSupportPageHeaderLength
	return pages - min(pages, packedPages), physicalBytes - min(physicalBytes, packedBytes), nil
}

func selectedContinuationGrowth(ctx context.Context, image *selectedImage, generated *generatedSelection, population continuationPopulation) (continuationGrowth, error) {
	possible, materialized, err := continuationMaySelectFinal(ctx, image, generated)
	if err != nil {
		return continuationGrowth{}, err
	}
	return selectedContinuationGrowthForFinal(ctx, image, generated, population, possible, materialized)
}

// The cost rows fold complete lineage prefixes against ONE shared allowance.
// Ordinary prefix maxima include nonselecting closure. The selecting channel
// carries one canonical frontier per lineage and is exposed only if the actual
// Final/preparation/automatic suffix also fits. No persisted state is planned.
func selectedContinuationGrowthForFinal(ctx context.Context, image *selectedImage, generated *generatedSelection, population continuationPopulation, possible, materialized bool) (continuationGrowth, error) {
	var maximum continuationGrowth
	if generated.parent == nil {
		return maximum, nil
	}
	if generated.phase == nil || len(generated.bundles) == 0 {
		return maximum, contract.ErrRecord
	}
	bundle := generated.bundles[0]
	if bundle.Header.OperationID != generated.parent.OperationID || bundle.UsePlan.PlanGraphID != generated.parent.PlanGraphID {
		return maximum, contract.ErrRecord
	}
	budget := uint64(math.MaxUint32 - generated.phase.Phase)
	if budget == 0 {
		return maximum, nil
	}
	if generatedSelectionAnchored(generated) {
		return continuationAutomaticGrowth(image, population, generated, budget, false)
	}
	// A current single-template delete parent owns its already entered Record
	// and closure. Unentered detached cleanup/retirement is a fresh admission.
	if len(bundle.Lineages) == 1 && bundle.Lineages[0].Purpose != contract.GeneratorLineageCreate {
		x := bundle.Lineages[0].Templates[0]
		if attempt, entered := generated.attempts[x.AttemptID]; entered && attempt.record.Stage != contract.GeneratedStageTerminal {
			return continuationPathGrowth(image, population, bundle, []continuationTemplateReach{{template: x, write: true, result: true}})
		}
		return maximum, nil
	}
	type costRow struct {
		ordinary, selected       continuationGrowth
		hasOrdinary, hasSelected bool
	}
	var completed []continuationTemplateReach
	var pending []contract.GeneratorLineageTemplate
	for index, lineage := range bundle.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		if index >= int(generated.phase.LineageIndex) && generated.phase.Stage != contract.GeneratedStageTerminal {
			pending = append(pending, lineage)
			continue
		}
		if possible {
			for _, x := range lineage.Templates[:lineage.TemplateCount] {
				if attempt, entered := generated.attempts[x.AttemptID]; entered && attempt.record.State == contract.GeneratedEffectSucceeded {
					completed = append(completed, continuationTemplateReach{template: x, canonical: true})
				}
			}
		}
	}
	seed, err := continuationPathGrowth(image, population, bundle, completed)
	if err != nil {
		return maximum, err
	}
	rows := map[uint64]costRow{0: {selected: seed, hasOrdinary: true, hasSelected: possible}}
	// Every lineage has at most three entered create templates: two gates,
	// two successor Reserves and a terminal Record (six from a planned start).
	// This caps cost-map work by the authenticated graph, never uint32 history.
	budget = min(budget, uint64(6*len(pending))+generatedFinalPhaseSteps(bundle, materialized))
	for _, lineage := range pending {
		if err := ctx.Err(); err != nil {
			return maximum, err
		}
		branch, gate := uint8(contract.GeneratorBranchInitial), uint8(0)
		if record, present := generated.records[generatedRecordKey{contract.GeneratedLineageSupportKind, lineage.LineageID}]; present {
			state, err := contract.InspectGeneratedLineageRecord(record.Body)
			if err != nil {
				return maximum, err
			}
			branch = state.Branch
		}
		if branch >= lineage.TemplateCount {
			return maximum, contract.ErrRecord
		}
		_, entered := generated.attempts[lineage.Templates[branch].AttemptID]
		// Later originals are installed by their predecessor Record; only the
		// current noninitial planned frontier spends a separate Reserve.
		if lineage.LineageID != generated.bundles[0].Lineages[generated.phase.LineageIndex].LineageID {
			entered = true
		}
		options, err := continuationLineageOptions(image, population, bundle, lineage, branch, gate, entered)
		if err != nil {
			return maximum, err
		}
		next := make(map[uint64]costRow)
		for before, row := range rows {
			for _, option := range options {
				cost := before + option.steps
				if cost > budget {
					continue
				}
				if row.hasOrdinary {
					if err := maximum.mergeSum(row.ordinary, option.ordinary); err != nil {
						return maximum, err
					}
				}
				if !option.terminal {
					continue
				}
				after := next[cost]
				if row.hasOrdinary {
					if err := after.ordinary.mergeSum(row.ordinary, option.ordinary); err != nil {
						return maximum, err
					}
					after.hasOrdinary = true
				}
				if row.hasSelected && option.selecting {
					if err := after.selected.mergeSum(row.selected, option.selected); err != nil {
						return maximum, err
					}
					after.hasSelected = true
				}
				next[cost] = after
			}
		}
		rows = next
	}
	if possible {
		retirement, err := continuationFinalRetirementGrowth(image, population, generated)
		if err != nil {
			return maximum, err
		}
		for cost, row := range rows {
			if row.hasSelected && cost+generatedFinalPhaseSteps(bundle, materialized) <= budget {
				if err := maximum.mergeSum(row.selected, retirement); err != nil {
					return maximum, err
				}
			}
		}
	}
	return maximum, nil
}
