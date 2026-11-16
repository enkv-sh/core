package crypto

import (
	"reflect"
	"sync"

	"enkv.sh/core/contract"
)

// One invocation's runtime family shares immutable public input ownership.
// This owner retains only its latest plan, selected output, and access image;
// admitted sessions keep earlier images alive until their own retirement.
type generatedInputOwner struct {
	mu     sync.Mutex
	plan   *validatedGeneratedPlan
	output *contract.GeneratedOutputTransition
	before contract.DescriptorVector
	access *generatedAccessImage
}

func (r *Runtime) generatedInputOwner() (*generatedInputOwner, error) {
	if r == nil {
		return nil, ErrAdmission
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrAdmission
	}
	if r.generatedInputs == nil {
		r.generatedInputs = new(generatedInputOwner)
	}
	return r.generatedInputs, nil
}

func (o *generatedInputOwner) validatePlan(graphBody, declarationBody []byte, streams [2]generatedStream) (*validatedGeneratedPlan, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	cached := o.plan
	if cached != nil && cached.graphLength == len(graphBody) && cached.declarationLength == len(declarationBody) && cached.graphDigest == streams[1].digest && cached.declarationDigest == streams[0].digest {
		return cached, nil
	}
	graph, err := contract.DecodeGeneratorPlanBundle(graphBody)
	if err != nil || contract.ValidateGeneratorEffectGraph(graph) != nil {
		return nil, ErrAdmission
	}
	declaration, err := contract.InspectGeneratorDeclaration(declarationBody)
	if err != nil || contract.ValidateGeneratorDeclarationGraph(declaration, graph) != nil {
		return nil, ErrAdmission
	}
	descriptor, err := contract.GeneratorPlanBundleDescriptor(graph)
	if err != nil {
		return nil, ErrAdmission
	}
	usePlan, err := contract.GeneratorUsePlanDigest(graph.UsePlan)
	if err != nil {
		return nil, ErrAdmission
	}
	intended, err := contract.GeneratorValueEntryPlansDescriptor(graph.ValueEntryPlans)
	if err != nil {
		return nil, ErrAdmission
	}
	o.plan = &validatedGeneratedPlan{graphDigest: streams[1].digest, declarationDigest: streams[0].digest, graphLength: len(graphBody), declarationLength: len(declarationBody), graph: graph, descriptor: descriptor, usePlan: usePlan, intendedEntryPlans: intended}
	return o.plan, nil
}

func (o *generatedInputOwner) ownOutput(before contract.PublicState, input *contract.GeneratedOutputTransition) (*contract.GeneratedOutputTransition, error) {
	if input == nil {
		return nil, ErrAdmission
	}
	// Recheck actual caller bytes and all selected facts even when a previous
	// producer already owns an equal image. No caller digest asserts equality.
	if err := input.Inspect(before); err != nil {
		return nil, ErrAdmission
	}
	descriptor, err := contract.PublicStateDescriptor(before)
	if err != nil {
		return nil, ErrAdmission
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.output != nil && o.before == descriptor && reflect.DeepEqual(o.output, input) {
		return o.output, nil
	}
	owned, err := input.Own(before)
	if err != nil {
		return nil, ErrAdmission
	}
	o.output, o.before = owned, descriptor
	return owned, nil
}

// The access image is public encrypted data. All admitted siblings borrow one
// immutable canonical owner, while each keeps its own private seed and permit.
type generatedAccessImage struct {
	root    contract.ID
	records []contract.AccessRecord
	pins    map[generatedAccessIdentity]contract.ID
}

func (o *generatedInputOwner) ownAccess(domain, root contract.ID, core contract.CurrentAccessCore, rows []contract.AccessRecord) (*generatedAccessImage, error) {
	if o == nil || core.DomainID != domain {
		return nil, ErrAdmission
	}
	descriptor, err := contract.AccessRecordsDescriptor(domain, rows)
	if err != nil || descriptor != core.AccessRecordsDescriptor {
		return nil, ErrAdmission
	}
	actual, err := contract.AccessRoot(core)
	if err != nil || actual != root {
		return nil, ErrAdmission
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.access != nil && o.access.root == root && reflect.DeepEqual(o.access.records, rows) {
		return o.access, nil
	}
	image := &generatedAccessImage{root: root, records: make([]contract.AccessRecord, len(rows)), pins: make(map[generatedAccessIdentity]contract.ID, len(rows))}
	for i, row := range rows {
		body, err := contract.EncodeAccessRecord(row)
		if err != nil {
			return nil, ErrAdmission
		}
		owned, err := contract.DecodeAccessRecord(body)
		if err != nil {
			return nil, ErrAdmission
		}
		digest, err := contract.AccessRecordDigest(owned)
		if err != nil {
			return nil, ErrAdmission
		}
		image.records[i] = owned
		image.pins[generatedAccessIdentity{owned.MaterialKind, owned.MaterialID}] = digest
	}
	o.access = image
	return image, nil
}
