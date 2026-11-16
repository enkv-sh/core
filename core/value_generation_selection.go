package core

import (
	"context"
	"fmt"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type generatedRecordKey struct {
	kind contract.SupportRecordKind
	id   contract.ID
}

type generatedSelection struct {
	session            *StateSession
	image              *selectedImage
	selectedMaterials  selectedMaterialFacts
	readFragment       selectedFragmentRead
	content            *generatedContent
	vectors            generatedVectorSet
	records            map[generatedRecordKey]contract.SupportRecord
	materials          map[materialIdentity]bool
	parent             *contract.GeneratedParentRecord
	registry           *contract.GeneratedRecipientRegistryImage
	registryBody       []byte
	phase              *contract.GeneratedPhaseRecord
	preparation        *contract.GeneratedFinalPreparationRecord
	bundles            []contract.GeneratorPlanBundle
	attempts           map[contract.ID]generatedAttempt
	deleteHazards      map[contract.ID]contract.ID
	releases           map[contract.ID]generatedReleasedAttempt
	consumers          map[materialIdentity][]contract.GeneratorConsumer
	sources            map[contract.ID][]contract.GeneratorSourceUse
	protected          map[contract.ID][]byte
	canonical          map[contract.ID]generatedCanonical
	retainedOwners     map[contract.ID][]generatedRecordKey
	declaredCanonicals map[contract.ID]bool
}

// generatedSelectionBuilder owns every write used to validate a selected
// image. finish transfers its facts and closes all builder handles before
// those facts can enter the session cache.
type generatedSelectionBuilder struct {
	facts   *generatedSelection
	content *generatedContentValidation
	vectors *generatedVectorValidation
	claimed map[generatedRecordKey]bool
}

// A StateSession is immutable after authentication. The cached selection holds
// published facts for that exact encoded root while authenticated byte slices
// remain borrowed.
type validatedGeneratedSelection struct {
	session   *StateSession
	root      contract.ID
	selection *generatedSelection
}

func (s *StateSession) generatedSelectionRoot() (contract.ID, bool) {
	body, err := format.EncodeRoot(s.root)
	if err != nil {
		return contract.ID{}, false
	}
	return contract.Hash(body), true
}

type generatedAttempt struct {
	record   contract.GeneratedAttemptRecord
	expected contract.GeneratorResultExpectation
	material contract.OperationMaterialRecord
	result   []byte
}

func (a generatedAttempt) awaitingResult() bool {
	return len(a.result) == 0 && a.record.State == contract.GeneratedEffectTransmitted && a.record.Stage == contract.GeneratedStageRetainedResult
}

func (g *generatedSelection) record(kind contract.SupportRecordKind, id contract.ID) (contract.SupportRecord, bool) {
	row, ok := g.records[generatedRecordKey{kind, id}]
	return row, ok
}

func (g *generatedSelection) hasRecord(key generatedRecordKey) bool {
	if g == nil {
		return false
	}
	_, ok := g.records[key]
	return ok
}

func (b *generatedSelectionBuilder) claimRecord(kind contract.SupportRecordKind, id contract.ID) (contract.SupportRecord, bool) {
	if b == nil || b.facts == nil {
		return contract.SupportRecord{}, false
	}
	key := generatedRecordKey{kind, id}
	row, ok := b.facts.records[key]
	if ok {
		b.claimed[key] = true
	}
	return row, ok
}

func (b *generatedSelectionBuilder) recordClaimed(key generatedRecordKey) bool {
	return b != nil && b.facts != nil && b.claimed[key]
}

func (b *generatedSelectionBuilder) claimMaterial(key materialIdentity) bool {
	if b == nil || b.facts == nil {
		return false
	}
	b.facts.materials[key] = true
	return true
}

func (b *generatedSelectionBuilder) finish(receiptIndex contract.ID) (*generatedSelection, error) {
	if b == nil || b.facts == nil || b.content == nil || b.vectors == nil || b.content.facts != b.facts.content || b.vectors.facts != &b.facts.vectors {
		return nil, contract.ErrRecord
	}
	for key := range b.facts.records {
		if key.kind != contract.GeneratedFragmentSupportKind && key.kind != contract.GeneratorVectorSupportKind && !b.claimed[key] {
			return nil, fmt.Errorf("unclaimed generated support kind %d: %w", key.kind, contract.ErrRecord)
		}
	}
	if !b.vectors.complete() || !b.content.complete(receiptIndex) {
		return nil, contract.ErrRecord
	}
	facts := b.facts
	*b.content = generatedContentValidation{}
	*b.vectors = generatedVectorValidation{}
	*b = generatedSelectionBuilder{}
	return facts, nil
}

func (s *StateSession) selectedGeneratedWork(ctx context.Context) (*generatedSelection, error) {
	if s == nil || s.admission.domain.IsZero() || s.admission.domain != s.root.Domain {
		return nil, contract.ErrRecord
	}
	if cached := s.generatedWork; cached != nil && cached.session == s && cached.selection != nil {
		if root, ok := s.generatedSelectionRoot(); ok && cached.root == root {
			return cached.selection, nil
		}
	}
	image, err := s.completeSelectedImage(ctx)
	if err != nil {
		return nil, err
	}
	materials := selectedMaterialFacts{accessLocations: s.accessLocations, valueReaders: s.valueReaders}
	validated, err := selectedGeneratedWorkFromImageWithReader(ctx, image, materials, s.generatedGraphs, s.withSelectedFragmentForOpen)
	if err != nil {
		return nil, err
	}
	g := validated.facts
	g.session = s
	g.readFragment = nil
	return g, nil
}

type generatedImageValidation struct{ facts *generatedSelection }

func (v *generatedImageValidation) covers(records []contract.AccessRecord) bool {
	return v != nil && v.facts != nil && newGeneratedCoverageValidation(v.facts).consume(records)
}
func selectedGeneratedWorkFromImageWithReader(ctx context.Context, image *selectedImage, materials selectedMaterialFacts, reusableGraphs map[contract.ID]validatedGeneratorGraph, read selectedFragmentRead) (*generatedImageValidation, error) {
	if image == nil || image.root.Domain.IsZero() {
		return nil, contract.ErrRecord
	}
	if _, err := selectedGCState(image, true); err != nil {
		return nil, err
	}
	rows, err := selectedWorkSupportRecords(image)
	if err != nil {
		return nil, err
	}
	content, err := selectedGeneratedContentValidationWithReader(ctx, image, reusableGraphs, read)
	if err != nil {
		return nil, err
	}
	g := &generatedSelection{image: image, selectedMaterials: materials, readFragment: read, content: content.facts, records: make(map[generatedRecordKey]contract.SupportRecord, len(rows)),
		materials: make(map[materialIdentity]bool),
		attempts:  make(map[contract.ID]generatedAttempt), consumers: make(map[materialIdentity][]contract.GeneratorConsumer),
		deleteHazards: make(map[contract.ID]contract.ID),
		releases:      make(map[contract.ID]generatedReleasedAttempt),
		sources:       make(map[contract.ID][]contract.GeneratorSourceUse), protected: make(map[contract.ID][]byte),
		canonical: make(map[contract.ID]generatedCanonical), retainedOwners: make(map[contract.ID][]generatedRecordKey)}
	builder := &generatedSelectionBuilder{facts: g, content: content, claimed: make(map[generatedRecordKey]bool, len(rows))}
	configurationValidated, publicationValidated := false, false
	for _, row := range rows {
		key := generatedRecordKey{row.Kind, row.RecordID}
		if _, duplicate := g.records[key]; duplicate {
			return nil, contract.ErrRecord
		}
		g.records[key] = row
		if row.Kind == contract.GCPlanSupportKind {
			builder.claimed[key] = true
		}
		if row.Kind == contract.OutputConfigurationSliceSupportKind {
			if !configurationValidated {
				if !image.selectedOutputComplete() {
					return nil, contract.ErrRecord
				}
				configurationValidated = true
			}
			builder.claimed[key] = true
		}
		if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
			if !publicationValidated {
				if image.publicationProof == nil || !image.publicationProof.validFor(image) {
					return nil, contract.ErrRecord
				}
				publicationValidated = true
			}
			builder.claimed[key] = true
		}
	}
	// Configuration and publication rows have their own complete grammar and
	// relation proofs above. Authenticated fragments have their physical-row
	// proof. Their released bodies are not generated vector ownership input.
	vectorRows := make([]contract.SupportRecord, 0, len(rows))
	for _, row := range rows {
		if row.Kind == contract.GCPlanSupportKind || row.Kind == contract.OutputConfigurationSliceSupportKind ||
			publicationSupportKind(row.Kind) || image.fragmentFacts != nil && row.Kind == contract.GeneratedFragmentSupportKind {
			continue
		}
		vectorRows = append(vectorRows, row)
	}
	g.vectors, err = newGeneratedVectorSet(image.root.Domain, vectorRows)
	if err != nil {
		return nil, err
	}
	builder.vectors = newGeneratedVectorValidation(&g.vectors)
	var entries []contract.ValueEntry
	var generated uint32
	for _, entry := range image.root.Names {
		valueEntry := image.valueEntry(entry.Slot)
		if valueEntry == nil || valueEntry.Name != entry.Name {
			return nil, contract.ErrRecord
		}
		entries = append(entries, *valueEntry)
		if valueEntry.ConfidentialityClass == contract.Secret {
			builder.claimMaterial(materialIdentity{contract.ValueMaterialKind, valueEntry.ValueState})
		}
		if valueEntry.ValueSource == contract.Generated {
			generated++
			if err := builder.validateValueEntry(image.root.Domain, *valueEntry); err != nil {
				return nil, err
			}
		}
	}
	closure := image.root.Generated
	if closure.GeneratedCurrent != generated {
		return nil, contract.ErrRecord
	}
	if err := builder.resolveActive(rows); err != nil {
		return nil, fmt.Errorf("resolve generated owners: %w", err)
	}
	if err := builder.validateEnteredCreateBranches(); err != nil {
		return nil, err
	}
	if err := builder.validateActiveLineages(); err != nil {
		return nil, err
	}
	if err := builder.vectors.validateOwners(image.root.Domain, image.adminIndex.SliceSnapshot, closure, vectorRows, entries, g.bundles); err != nil {
		return nil, fmt.Errorf("validate generated vector owners: %w", err)
	}
	if err := builder.resolveRetirements(rows, entries); err != nil {
		return nil, err
	}
	if err := builder.resolveDetachedCreateHazards(rows); err != nil {
		return nil, err
	}
	if err := builder.validateResourceCoordinates(rows, entries); err != nil {
		return nil, fmt.Errorf("generated resource coordinates: %w", err)
	}
	if err := builder.validateActiveVectors(); err != nil {
		return nil, fmt.Errorf("validate generated vectors: %w", err)
	}
	if err := builder.validateCreateHistories(); err != nil {
		return nil, err
	}
	if g.phase != nil {
		if err := builder.validateActivePhase(rows); err != nil {
			return nil, fmt.Errorf("validate generated phase: %w", err)
		}
	}
	receiptIndex, err := selectedReceiptIndexID(image.root.Domain, image.root)
	if err != nil {
		return nil, contract.ErrRecord
	}
	selected, err := builder.finish(receiptIndex)
	if err != nil {
		return nil, err
	}
	return &generatedImageValidation{facts: selected}, nil
}

func (b *generatedSelectionBuilder) validateValueEntry(domain contract.ID, entry contract.ValueEntry) error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	row, ok := b.claimRecord(contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID)
	if !ok {
		return contract.ErrRecord
	}
	evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
	if err != nil {
		return err
	}
	intent, err := b.content.readLogical(contract.GeneratorContentIntent, entry.Generated.IntentDigest, evidence.Intent, contract.GeneratorIntentMaxLength)
	if err != nil {
		return err
	}
	return contract.ValidateGeneratedValueEntryEvidence(domain, entry, contract.GeneratedCreateEvidence(evidence), intent)
}

func (s *StateSession) validateGeneratedCoverage(ctx context.Context, records []contract.AccessRecord) (*generatedSelection, error) {
	g, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if !newGeneratedCoverageValidation(g).consume(records) {
		return nil, contract.ErrRecord
	}
	return g, nil
}

func (s *StateSession) generatedCoverageRecords() []contract.AccessRecord {
	if s == nil {
		return nil
	}
	records := make([]contract.AccessRecord, 0, s.root.AccessRecordCount)
	for _, page := range s.access {
		if page != nil {
			records = append(records, page.Records...)
		}
	}
	return records
}

type generatedCoverageValidation struct {
	facts    *generatedSelection
	consumed map[materialIdentity]bool
}

func newGeneratedCoverageValidation(g *generatedSelection) *generatedCoverageValidation {
	return &generatedCoverageValidation{facts: g, consumed: make(map[materialIdentity]bool)}
}

func (v *generatedCoverageValidation) consume(records []contract.AccessRecord) bool {
	if v == nil || v.facts == nil || len(v.facts.materials) != len(records) {
		return false
	}
	for _, row := range records {
		key := materialIdentity{row.MaterialKind, row.MaterialID}
		if !v.facts.materials[key] || v.consumed[key] {
			return false
		}
		v.consumed[key] = true
	}
	return len(v.consumed) == len(v.facts.materials)
}

func (g *generatedSelection) fragmentReader() (selectedFragmentRead, error) {
	if g == nil || g.content == nil {
		return nil, contract.ErrRecord
	}
	if g.content.fragmentFacts == nil {
		return nil, nil
	}
	if g.readFragment != nil {
		return g.readFragment, nil
	}
	if g.session == nil {
		return nil, contract.ErrRecord
	}
	return g.session.withSelectedFragmentForOpen, nil
}
func (g *generatedSelection) readSelectedSlice(ctx context.Context, kind uint8, id contract.ID, limit uint32) ([]byte, error) {
	read, err := g.fragmentReader()
	if err != nil {
		return nil, err
	}
	if read == nil {
		return g.content.read(kind, id, limit)
	}
	return g.content.readSelectedSlice(ctx, kind, id, limit, read)
}
func (g *generatedSelection) readSelectedLogicalSlice(ctx context.Context, kind uint8, id contract.ID, want contract.GeneratorDescriptor, limit uint32) ([]byte, error) {
	read, err := g.fragmentReader()
	if err != nil {
		return nil, err
	}
	if read == nil {
		return g.content.readLogical(kind, id, want, limit)
	}
	return g.content.readSelectedLogicalSlice(ctx, kind, id, want, limit, read)
}

func (g *generatedSelection) materialAccess(kind contract.MaterialKind, id contract.ID) (contract.AccessRecord, bool) {
	return selectedMaterialAccess(&g.image.access, g.selectedMaterials.accessLocations, kind, id)
}
func (g *generatedSelection) validateMaterialWraps(access contract.AccessRecord, readers []contract.ID) bool {
	return selectedMaterialWraps(g.image.root, &g.image.recipients, access, readers)
}
func (g *generatedSelection) validateValueAccess(core contract.ValueCore, payload contract.CanonicalPayload, access contract.AccessRecord, readers []contract.ID) bool {
	return selectedValueAccess(g.image.root, &g.image.recipients, core, payload, access, readers)
}

func (g *generatedSelection) streamLogical(ctx context.Context, kind uint8, id contract.ID, limit uint32, write func([]byte) error) (contract.GeneratorSliceLocation, error) {
	read, err := g.fragmentReader()
	if err != nil {
		return contract.GeneratorSliceLocation{}, err
	}
	return g.content.streamLogical(ctx, kind, id, limit, write, read)
}
