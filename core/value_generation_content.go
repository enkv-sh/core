package core

import (
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedContentKey struct {
	kind uint8
	id   contract.ID
}

// A graph is immutable for its authenticated logical slice. Keeping the
// derived descriptors avoids repeating complete graph validation at every
// phase of one uninterrupted generated operation.
type validatedGeneratorGraph struct {
	logical            contract.GeneratorLogicalSlice
	bundle             contract.GeneratorPlanBundle
	descriptor         contract.GeneratorDescriptor
	usePlan            contract.ID
	intendedEntryPlans contract.GeneratorDescriptor
}

// Published content contains only immutable selected facts. A logical slice
// becomes a dependency only after its owning live record claims it.
type generatedContent struct {
	domain            contract.ID
	locations         map[generatedContentKey]contract.GeneratorSliceLocation
	fragments         map[contract.ID][]contract.GeneratedFragmentView
	fragmentLocations map[contract.ID][]format.FragmentLocation
	fragmentFacts     map[format.FragmentLocation]selectedFragmentFact
	graphs            map[contract.ID]validatedGeneratorGraph
}

type generatedContentValidation struct {
	facts        *generatedContent
	ctx          context.Context
	readFragment selectedFragmentRead
	claimed      map[generatedContentKey]bool
	reusable     map[contract.ID]validatedGeneratorGraph
}

func cloneGeneratorPlanBundle(v contract.GeneratorPlanBundle) contract.GeneratorPlanBundle {
	v.ValueEntryPlans = slices.Clone(v.ValueEntryPlans)
	v.Lineages = slices.Clone(v.Lineages)
	v.Edges = slices.Clone(v.Edges)
	v.ResultUses = slices.Clone(v.ResultUses)
	v.SourceUses = slices.Clone(v.SourceUses)
	return v
}

func newGeneratedContent(s *StateSession) (*generatedContent, error) {
	if s == nil || s.admission.domain != s.root.Domain {
		return nil, contract.ErrRecord
	}
	image := s.selectedImageView()
	return selectedGeneratedContent(&image)
}

// selectedGeneratedContent resolves only authenticated read-only image facts.
// The ordinary session keeps its separate admission and generated-work cache.
func selectedGeneratedContent(image *selectedImage) (*generatedContent, error) {
	if image == nil || image.root.Domain.IsZero() {
		return nil, contract.ErrRecord
	}
	locations := image.generatedSliceLocations
	if locations == nil {
		var err error
		if image.fragmentFacts != nil {
			locations, err = format.ResolveGeneratedSliceLocations(image.root.Domain, image.adminIndex.SliceSnapshot,
				image.root.Generated.Slices, image.support)
		} else {
			locations, err = format.ResolveGeneratedSlices(image.root.Domain, image.adminIndex.SliceSnapshot,
				image.root.Generated, image.support)
		}
		if err != nil {
			return nil, err
		}
	}
	c := &generatedContent{domain: image.root.Domain, locations: make(map[generatedContentKey]contract.GeneratorSliceLocation, len(locations)),
		fragments: make(map[contract.ID][]contract.GeneratedFragmentView), fragmentFacts: image.fragmentFacts,
		fragmentLocations: make(map[contract.ID][]format.FragmentLocation), graphs: make(map[contract.ID]validatedGeneratorGraph)}
	for _, row := range locations {
		key := generatedContentKey{row.ContentKind, row.ContentID}
		if _, duplicate := c.locations[key]; duplicate {
			return nil, contract.ErrRecord
		}
		c.locations[key] = row
	}
	var pages [contract.MaxChildPages]*format.RequiredSupportPageView
	for i := range image.support {
		page := &image.support[i]
		if page.Index >= contract.MaxChildPages || pages[page.Index] != nil || page.Domain != image.root.Domain {
			return nil, contract.ErrRecord
		}
		pages[page.Index] = page
	}
	for _, loc := range image.root.Generated.Fragments {
		if image.fragmentFacts != nil {
			fact, ok := image.fragmentFacts[loc]
			if !ok || fact.blob != loc.BlobID || fact.index != loc.FragmentIndex {
				return nil, contract.ErrRecord
			}
			c.fragmentLocations[fact.blob] = append(c.fragmentLocations[fact.blob], loc)
			continue
		}
		page := pages[loc.SupportPageIndex]
		if page == nil || int(loc.RowSlot) >= len(page.Records) {
			return nil, contract.ErrRecord
		}
		fragment, err := contract.InspectGeneratedFragment(page.Records[loc.RowSlot].Body)
		if err != nil {
			return nil, err
		}
		c.fragments[fragment.BlobID] = append(c.fragments[fragment.BlobID], fragment)
		c.fragmentLocations[fragment.BlobID] = append(c.fragmentLocations[fragment.BlobID], loc)
	}
	return c, nil
}

func selectedGeneratedContentValidationWithReader(ctx context.Context, image *selectedImage,
	reusable map[contract.ID]validatedGeneratorGraph, read selectedFragmentRead) (*generatedContentValidation, error) {
	facts, err := selectedGeneratedContent(image)
	if err != nil {
		return nil, err
	}
	if len(facts.fragmentFacts) != 0 && (ctx == nil || read == nil) {
		return nil, contract.ErrRecord
	}
	return &generatedContentValidation{facts: facts, ctx: ctx, readFragment: read,
		claimed: make(map[generatedContentKey]bool), reusable: reusable}, nil
}

func newGeneratedContentValidation(ctx context.Context, s *StateSession) (*generatedContentValidation, error) {
	if s == nil || s.admission.domain != s.root.Domain {
		return nil, contract.ErrRecord
	}
	image := s.selectedImageView()
	return selectedGeneratedContentValidationWithReader(ctx, &image, s.generatedGraphs, s.withSelectedFragmentForOpen)
}

func (b *generatedContentValidation) read(kind uint8, id contract.ID, limit uint32) ([]byte, error) {
	if b == nil || b.facts == nil {
		return nil, contract.ErrRecord
	}
	var body []byte
	var err error
	if b.facts.fragmentFacts != nil {
		body, err = b.facts.readSelectedSlice(b.ctx, kind, id, limit, b.readFragment)
	} else {
		body, err = b.facts.read(kind, id, limit)
	}
	if err == nil {
		b.claimed[generatedContentKey{kind, id}] = true
	}
	return body, err
}

func (b *generatedContentValidation) readLogical(kind uint8, id contract.ID, want contract.GeneratorDescriptor, limit uint32) ([]byte, error) {
	if b == nil || b.facts == nil {
		return nil, contract.ErrRecord
	}
	var body []byte
	var err error
	if b.facts.fragmentFacts != nil {
		body, err = b.facts.readSelectedLogicalSlice(b.ctx, kind, id, want, limit, b.readFragment)
	} else {
		body, err = b.facts.readLogical(kind, id, want, limit)
	}
	if err == nil {
		b.claimed[generatedContentKey{kind, id}] = true
	}
	return body, err
}

// read borrows a contiguous span when possible. A cross-fragment value copies
// only its requested slice, never the whole containing declaration or graph.
func (c *generatedContent) read(kind uint8, id contract.ID, limit uint32) ([]byte, error) {
	key := generatedContentKey{kind, id}
	location, ok := c.locations[key]
	if !ok || location.Length > limit {
		return nil, contract.ErrRecord
	}
	end := location.Offset + uint64(location.Length)
	fragments := c.fragments[location.BlobID]
	if len(fragments) == 0 {
		return nil, contract.ErrRecord
	}
	for _, fragment := range fragments {
		start, stop := uint64(fragment.Offset), uint64(fragment.Offset)+uint64(len(fragment.Payload))
		if start <= location.Offset && end <= stop {
			body := fragment.Payload[location.Offset-start : end-start : end-start]
			return body, nil
		}
	}
	data := make([]byte, 0, int(location.Length))
	for _, fragment := range fragments {
		start, stop := uint64(fragment.Offset), uint64(fragment.Offset)+uint64(len(fragment.Payload))
		if start < end && stop > location.Offset {
			data = append(data, fragment.Payload[max(start, location.Offset)-start:min(stop, end)-start]...)
		}
	}
	if uint32(len(data)) != location.Length {
		return nil, contract.ErrRecord
	}
	return data, nil
}

func (c *generatedContent) readLogical(kind uint8, id contract.ID, want contract.GeneratorDescriptor, limit uint32) ([]byte, error) {
	location, ok := c.locations[generatedContentKey{kind, id}]
	if !ok {
		return nil, contract.ErrRecord
	}
	d, err := contract.GeneratorLogicalSlicesDescriptor([]contract.GeneratorLogicalSlice{location.Logical()})
	if err != nil || d != want {
		return nil, contract.ErrRecord
	}
	return c.read(kind, id, limit)
}

func (c *generatedContent) graph(id contract.ID) (contract.GeneratorPlanBundle, error) {
	graph, ok := c.graphs[id]
	if !ok {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	return cloneGeneratorPlanBundle(graph.bundle), nil
}

func (b *generatedContentValidation) graph(id contract.ID) (contract.GeneratorPlanBundle, error) {
	graph, err := b.validatedGraph(id)
	if err != nil {
		return contract.GeneratorPlanBundle{}, err
	}
	b.claimed[generatedContentKey{contract.GeneratorContentGraph, id}] = true
	return cloneGeneratorPlanBundle(graph.bundle), nil
}

func (b *generatedContentValidation) validatedGraph(id contract.ID) (validatedGeneratorGraph, error) {
	if b == nil || b.facts == nil {
		return validatedGeneratorGraph{}, contract.ErrRecord
	}
	c := b.facts
	if graph, ok := c.graphs[id]; ok {
		return graph, nil
	}
	key := generatedContentKey{contract.GeneratorContentGraph, id}
	location, ok := c.locations[key]
	if !ok {
		return validatedGeneratorGraph{}, contract.ErrRecord
	}
	if graph, ok := b.reusable[id]; ok && graph.logical == location.Logical() &&
		graph.bundle.Header.DomainID == c.domain && graph.bundle.UsePlan.PlanGraphID == id {
		c.graphs[id] = graph
		return graph, nil
	}
	var body []byte
	var err error
	if c.fragmentFacts != nil {
		body, err = c.readSelectedSlice(b.ctx, contract.GeneratorContentGraph, id, contract.GeneratorGraphMaxLength-8, b.readFragment)
	} else {
		body, err = c.read(contract.GeneratorContentGraph, id, contract.GeneratorGraphMaxLength-8)
	}
	if err != nil {
		return validatedGeneratorGraph{}, err
	}
	bundle, err := contract.DecodeGeneratorPlanBundle(body)
	if err != nil || bundle.Header.DomainID != c.domain || bundle.UsePlan.PlanGraphID != id || contract.ValidateGeneratorEffectGraph(bundle) != nil {
		return validatedGeneratorGraph{}, contract.ErrRecord
	}
	descriptor, err := contract.GeneratorPlanBundleDescriptor(bundle)
	if err != nil {
		return validatedGeneratorGraph{}, err
	}
	usePlan, err := contract.GeneratorUsePlanDigest(bundle.UsePlan)
	if err != nil {
		return validatedGeneratorGraph{}, err
	}
	intended, err := contract.GeneratorValueEntryPlansDescriptor(bundle.ValueEntryPlans)
	if err != nil {
		return validatedGeneratorGraph{}, err
	}
	graph := validatedGeneratorGraph{logical: location.Logical(), bundle: bundle, descriptor: descriptor, usePlan: usePlan, intendedEntryPlans: intended}
	c.graphs[id] = graph
	return graph, nil
}

func (c *generatedContent) graphForOperation(operation contract.ID) (contract.GeneratorPlanBundle, error) {
	var found contract.GeneratorPlanBundle
	for key := range c.locations {
		if key.kind != contract.GeneratorContentGraph {
			continue
		}
		graph, err := c.graph(key.id)
		if err != nil {
			return contract.GeneratorPlanBundle{}, err
		}
		if graph.Header.OperationID == operation {
			if !found.Header.OperationID.IsZero() {
				return contract.GeneratorPlanBundle{}, contract.ErrRecord
			}
			found = graph
		}
	}
	if found.Header.OperationID.IsZero() {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	return found, nil
}

func (b *generatedContentValidation) graphForOperation(operation contract.ID) (contract.GeneratorPlanBundle, error) {
	if b == nil || b.facts == nil {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	var found contract.GeneratorPlanBundle
	for key := range b.facts.locations {
		if key.kind != contract.GeneratorContentGraph {
			continue
		}
		validated, err := b.validatedGraph(key.id)
		if err != nil {
			return contract.GeneratorPlanBundle{}, err
		}
		graph := validated.bundle
		if graph.Header.OperationID == operation {
			if !found.Header.OperationID.IsZero() {
				return contract.GeneratorPlanBundle{}, contract.ErrRecord
			}
			found = graph
		}
	}
	if found.Header.OperationID.IsZero() {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	return cloneGeneratorPlanBundle(found), nil
}

func (b *generatedContentValidation) parent(parent contract.GeneratedParentRecord, selected ...bool) (contract.GeneratorPlanBundle, error) {
	if b == nil || b.facts == nil {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	c := b.facts
	if _, err := contract.GeneratedParentRecordLength(parent); err != nil || parent.DomainID != c.domain {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	validated, err := b.validatedGraph(parent.PlanGraphID)
	if err != nil {
		return contract.GeneratorPlanBundle{}, err
	}
	b.claimed[generatedContentKey{contract.GeneratorContentGraph, parent.PlanGraphID}] = true
	bundle := validated.bundle
	q, h := bundle.Request, bundle.Header
	if (q.Schema == contract.GeneratorPublicRequestCoreSchema || q.Schema == contract.GeneratorApplyRequestCoreSchema) && q.RecoveryPolicyID != contract.GeneratorRecoveryPolicyID() {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	if validated.descriptor != parent.Graph {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	if validated.usePlan != parent.UsePlanDigest {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	if validated.intendedEntryPlans != parent.IntendedEntryPlans || parent.OperationID != q.OperationID || parent.RequestCoreDigest != h.RequestCoreDigest ||
		parent.MaterialID != h.MaterialID || parent.RecoveryPolicyID != q.RecoveryPolicyID ||
		parent.ValueEntryPlanCount != h.ValueEntryPlanCount || parent.LineageCount != h.LineageCount || parent.TemplateCount != h.TemplateCount ||
		parent.Declaration != q.Declaration || parent.Registry != q.Registry || parent.SourceUses != bundle.UsePlan.SourceUses ||
		parent.InitialPredecessorDigest != q.PredecessorHEADDigest || parent.ConditionDigest != q.ConditionDigest {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	body, err := b.read(contract.GeneratorContentDeclaration, q.OperationID, contract.GeneratorDeclarationMaxLength)
	if err != nil {
		return contract.GeneratorPlanBundle{}, err
	}
	declaration, err := contract.InspectGeneratorDeclaration(body)
	if err != nil {
		return contract.GeneratorPlanBundle{}, err
	}
	if contract.ValidateGeneratorDeclarationGraph(declaration, bundle) != nil {
		return contract.GeneratorPlanBundle{}, contract.ErrRecord
	}
	if q.Schema == contract.GeneratorPublicRequestCoreSchema || q.Schema == contract.GeneratorApplyRequestCoreSchema {
		body, err := b.read(contract.GeneratorContentRecipientRegistry, q.OperationID, contract.GeneratedRecipientRegistryMaxLength)
		if err != nil {
			return contract.GeneratorPlanBundle{}, err
		}
		image, err := contract.DecodeGeneratedRecipientRegistryImage(body)
		descriptor, de := contract.GeneratedRecipientRegistryDescriptor(body)
		if err != nil || de != nil || image.DomainID != q.DomainID || image.OperationID != q.OperationID || descriptor != q.Registry {
			return contract.GeneratorPlanBundle{}, contract.ErrRecord
		}
	}
	if q.Schema == contract.GeneratorApplyRequestCoreSchema {
		image, err := b.read(contract.GeneratorContentOutputConfiguration, q.OperationID, contract.MaxOutputConfigurationBytes)
		if err != nil {
			return contract.GeneratorPlanBundle{}, err
		}
		if _, err := contract.InspectGeneratedOutputConfiguration(bundle, image); err != nil {
			return contract.GeneratorPlanBundle{}, err
		}
	}
	logical, err := declaration.LogicalSlices()
	if err != nil {
		return contract.GeneratorPlanBundle{}, err
	}
	for _, row := range logical {
		if len(selected) == 1 && selected[0] && row.ContentKind == contract.GeneratorContentSource {
			continue
		}
		key := generatedContentKey{row.ContentKind, row.ContentID}
		location, ok := c.locations[key]
		if !ok || location.Logical() != row {
			return contract.GeneratorPlanBundle{}, contract.ErrRecord
		}
		b.claimed[key] = true
	}
	return cloneGeneratorPlanBundle(bundle), nil
}

// A receipt-index blob has its own exact typed owner and is checked by
// receiptWindows. Every other blob must contain at least one required slice.
func (b *generatedContentValidation) complete(receiptIndex contract.ID) bool {
	if b == nil || b.facts == nil {
		return false
	}
	c := b.facts
	used := make(map[contract.ID]bool)
	for key, location := range c.locations {
		if !b.claimed[key] {
			return false
		}
		used[location.BlobID] = true
	}
	if !receiptIndex.IsZero() {
		if len(c.fragmentLocations[receiptIndex]) == 0 {
			return false
		}
		used[receiptIndex] = true
	}
	for id := range c.fragmentLocations {
		if !used[id] {
			return false
		}
	}
	return true
}
