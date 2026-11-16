package core

import (
	"context"
	"math/bits"
	"sync"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

const operationBodyAllowance = 5 << 20

const maximumFreshRefusalReads = contract.MaxChildPages + 2 + contract.MaxOutputConfigurationSlices

type budgetReservation struct {
	Requests         uint64 `json:"requests"`
	BodyBytes        uint64 `json:"body_bytes"`
	Objects          uint64 `json:"objects"`
	ObjectBytes      uint64 `json:"object_bytes"`
	GeneratorCreates uint64 `json:"generator_creates"`
	GeneratorRetires uint64 `json:"generator_retires"`
}

type runBudget struct {
	mu                                 sync.Mutex
	limits                             liveLimits
	requests, bodyBytes                uint64
	transportReadFailures              uint64
	objects, objectBytes               uint64
	generatorCreates, generatorRetires uint64
	keys                               map[string]bool
	exhausted                          bool
}

func (b *runBudget) snapshot() budgetReservation {
	b.mu.Lock()
	defer b.mu.Unlock()
	return budgetReservation{Requests: b.requests, BodyBytes: b.bodyBytes, Objects: b.objects, ObjectBytes: b.objectBytes,
		GeneratorCreates: b.generatorCreates, GeneratorRetires: b.generatorRetires}
}

func (b *runBudget) transportFailures() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.transportReadFailures
}

func (b *runBudget) remaining() liveLimits {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limits
	remaining.Requests -= b.requests
	remaining.BodyBytes -= b.bodyBytes
	remaining.Objects -= b.objects
	remaining.ObjectBytes -= b.objectBytes
	remaining.GeneratorCreates -= b.generatorCreates
	remaining.GeneratorRetires -= b.generatorRetires
	return remaining
}

func (b *runBudget) absorbChild(child budgetReservation) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if child.Requests > b.limits.Requests-b.requests || child.BodyBytes > b.limits.BodyBytes-b.bodyBytes ||
		child.Objects > b.limits.Objects-b.objects || child.ObjectBytes > b.limits.ObjectBytes-b.objectBytes ||
		child.GeneratorCreates > b.limits.GeneratorCreates-b.generatorCreates || child.GeneratorRetires > b.limits.GeneratorRetires-b.generatorRetires {
		b.exhausted = true
		return false
	}
	b.requests += child.Requests
	b.bodyBytes += child.BodyBytes
	b.objects += child.Objects
	b.objectBytes += child.ObjectBytes
	b.generatorCreates += child.GeneratorCreates
	b.generatorRetires += child.GeneratorRetires
	return true
}

// full_only: false
func TestRunBudgetGeneratorReservationsAndFreshChildDebitAreFinite(t *testing.T) {
	b := &runBudget{limits: liveLimits{Requests: 4, BodyBytes: 4 * operationBodyAllowance, Objects: 2, ObjectBytes: 20,
		GeneratorCreates: 1, GeneratorRetires: 2}, keys: map[string]bool{}}
	if !b.reserveGenerator(true) || b.reserveGenerator(true) || !b.exhausted {
		t.Fatal("create cap did not stop a second physical send")
	}
	b.exhausted = false
	if !b.reserveGenerator(false) || !b.absorbChild(budgetReservation{Requests: 1, BodyBytes: operationBodyAllowance, Objects: 1, ObjectBytes: 10}) {
		t.Fatal("retire or fresh child debit refused within finite cap")
	}
	remaining := b.remaining()
	if remaining.Requests != 1 || remaining.GeneratorCreates != 0 || remaining.GeneratorRetires != 1 || remaining.Objects != 1 || remaining.ObjectBytes != 10 {
		t.Fatal("remaining budget did not include generated and fresh work")
	}
	if b.absorbChild(budgetReservation{Requests: 2}) || !b.exhausted {
		t.Fatal("fresh child exceeded parent's remaining request budget")
	}
}

// Every entered Cloudflare command reserves one physical request and its
// bounded response before the process can start. An unknown reply still costs
// the reservation and cannot be retried through this budget.
func (b *runBudget) reserveGenerator(create bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.requests >= b.limits.Requests || b.bodyBytes > b.limits.BodyBytes ||
		operationBodyAllowance > b.limits.BodyBytes-b.bodyBytes ||
		create && b.generatorCreates >= b.limits.GeneratorCreates ||
		!create && b.generatorRetires >= b.limits.GeneratorRetires {
		b.exhausted = true
		return false
	}
	b.requests++
	b.bodyBytes += operationBodyAllowance
	if create {
		b.generatorCreates++
	} else {
		b.generatorRetires++
	}
	return true
}

func (b *runBudget) admitFreshReads(reads, processes uint64) bool {
	// Each child has its own budget. Check the worst case before launch; the
	// coordinator debits the child's recorded actual use after it joins.
	b.mu.Lock()
	defer b.mu.Unlock()
	reservation, ok := freshReadReservation(reads, processes)
	if !ok || b.requests > b.limits.Requests || b.bodyBytes > b.limits.BodyBytes ||
		reservation.Requests > b.limits.Requests-b.requests || reservation.BodyBytes > b.limits.BodyBytes-b.bodyBytes {
		b.exhausted = true
		return false
	}
	return true
}

func freshReadReservation(reads, processes uint64) (budgetReservation, bool) {
	hi, total := bits.Mul64(reads, processes)
	if hi != 0 || total == 0 {
		return budgetReservation{}, false
	}
	hi, requests := bits.Mul64(total, 6)
	if hi != 0 {
		return budgetReservation{}, false
	}
	hi, bodyBytes := bits.Mul64(total, 3*operationBodyAllowance)
	if hi != 0 {
		return budgetReservation{}, false
	}
	return budgetReservation{Requests: requests, BodyBytes: bodyBytes}, true
}

// candidateStoreReservation charges one persistence/selection episode. Cold
// Open, KMS and result inboxes are separate. Repeated persistence of the same
// candidate requires another charge even when every immutable Create finds
// the existing exact object.
func candidateStoreReservation(objects, immutableBytes, selectedReads uint64) (budgetReservation, bool) {
	// 12*I + 3 + 9*(R+1): immutable sends/readbacks, three HEAD sends,
	// and three complete observation stages with bounded physical rereads.
	calls := uint64(12)
	for _, term := range []struct{ count, multiplier uint64 }{{objects, 12}, {selectedReads, 9}} {
		hi, product := bits.Mul64(term.count, term.multiplier)
		next, carry := bits.Add64(calls, product, 0)
		if hi != 0 || carry != 0 {
			return budgetReservation{}, false
		}
		calls = next
	}
	hi, requests := bits.Mul64(calls, 2)
	if hi != 0 {
		return budgetReservation{}, false
	}
	hi, bodyBytes := bits.Mul64(calls, operationBodyAllowance)
	if hi != 0 {
		return budgetReservation{}, false
	}
	hi, objectBytes := bits.Mul64(immutableBytes, 3)
	if hi != 0 {
		return budgetReservation{}, false
	}
	objectBytes, carry := bits.Add64(objectBytes, 3*contract.MaxHeadLength, 0)
	if carry != 0 {
		return budgetReservation{}, false
	}
	return budgetReservation{Requests: requests, BodyBytes: bodyBytes, Objects: objects, ObjectBytes: objectBytes}, true
}

// full_only: false
func TestCandidateStoreReservationChargesAllSelectionSends(t *testing.T) {
	for _, row := range []struct{ objects, bytes, reads, requests, bodyBytes, objectBytes uint64 }{
		{1, 1, 2, 84, 220200960, 196611},
		{2, 1000, 7, 198, 519045120, 199608},
		{0, 0, 0, 24, 62914560, 196608},
	} {
		got, ok := candidateStoreReservation(row.objects, row.bytes, row.reads)
		want := budgetReservation{Requests: row.requests, BodyBytes: row.bodyBytes, Objects: row.objects, ObjectBytes: row.objectBytes}
		if !ok || got != want {
			t.Fatal("complete candidate charge differs", row, got, ok)
		}
	}
	for _, row := range []struct{ objects, bytes, reads uint64 }{
		{^uint64(0), 1, 2}, {1, ^uint64(0), 2}, {1, 1, ^uint64(0)},
		{1, 1, (^uint64(0))/9 - 2},
		{0, 0, (^uint64(0)) / (9 * operationBodyAllowance)},
		{(^uint64(0)) / 12, 1, 0},
		{1, (^uint64(0)-3*contract.MaxHeadLength)/3 + 1, 2},
	} {
		if got, ok := candidateStoreReservation(row.objects, row.bytes, row.reads); ok || got != (budgetReservation{}) {
			t.Fatal("overflow admitted a partial candidate charge", row, got)
		}
	}
}

// Cold Open borrows configuration slices again after the unique child scan.
// Generated content also needs bounded fragment borrows for relations, proofs
// and receipt indexes. The saved index has row kinds but no vector bodies, so
// charging every selected vector as History is conservative and read-free.
func freshSelectedReadAllowance(expected stateImage) (uint64, bool) {
	root, index := expected.Root, expected.AdministrativeIndex
	if _, err := format.EncodeRoot(root); err != nil {
		return 0, false
	}
	if _, err := format.EncodeAdministrativeIndex(index); err != nil || index.Domain != root.Domain || index.Object != root.AdministrativeIndex.Object || len(index.Pages) != len(root.RequiredSupport) {
		return 0, false
	}
	var rows, parents, attempts, duties, hazards, vectors uint64
	for i, page := range index.Pages {
		if page.Ref != root.RequiredSupport[i] {
			return 0, false
		}
		// ReadRequired pages contain only slice vectors. Their index omits
		// summaries, but every selected row is still counted by its span.
		if page.ReadRequired {
			for _, span := range page.Spans {
				rows += uint64(span.Count)
				vectors += uint64(span.Count)
				if rows > uint64(root.RequiredSupportRecordCount) {
					return 0, false
				}
			}
		}
		for _, row := range page.Rows {
			rows++
			if rows > uint64(root.RequiredSupportRecordCount) || row.Kind < contract.OperationMaterialSupportKind || row.Kind > contract.OutputConfigurationSliceSupportKind {
				return 0, false
			}
			switch row.Kind {
			case contract.GeneratedParentSupportKind:
				parents++
			case contract.GeneratedAttemptSupportKind:
				attempts++
			case contract.GeneratedDutySupportKind:
				duties++
			case contract.GeneratedHazardSupportKind:
				hazards++
			case contract.GeneratorVectorSupportKind:
				vectors++
			}
		}
	}
	if rows != uint64(root.RequiredSupportRecordCount) {
		return 0, false
	}
	slices := uint64(root.Generated.Slices.Count)
	relations := uint64(root.ValueEntryCount)
	for _, term := range []struct{ count, multiplier uint64 }{
		{slices, 1}, {parents, 3 + contract.GeneratorMaxCreateLineages + contract.CryptoMaxValueEntries},
		{attempts, 2}, {duties, 2}, {hazards, 2}, {vectors, 4},
	} {
		hi, product := bits.Mul64(term.count, term.multiplier)
		sum, carry := bits.Add64(relations, product, 0)
		if hi != 0 || carry != 0 {
			return 0, false
		}
		relations = sum
	}
	logical, carry := bits.Add64(relations, slices, 0)
	if carry != 0 {
		return 0, false
	}
	logical, carry = bits.Add64(logical, 5, 0)
	if carry != 0 {
		return 0, false
	}
	hi, fragments := bits.Mul64(uint64(len(root.Generated.Fragments)), logical)
	if hi != 0 {
		return 0, false
	}
	reads, carry := bits.Add64(uint64(root.ChildCount)+2+uint64(root.OutputConfiguration.SliceCount), fragments, 0)
	return reads, carry == 0
}

func (b *runBudget) reserve(requests, bodyBytes uint64, key string, objectBytes uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	newObject := uint64(0)
	if key != "" && !b.keys[key] {
		newObject = 1
	}
	if requests > b.limits.Requests-b.requests || bodyBytes > b.limits.BodyBytes-b.bodyBytes || newObject > b.limits.Objects-b.objects || objectBytes > b.limits.ObjectBytes-b.objectBytes {
		b.exhausted = true
		return false
	}
	b.requests += requests
	b.bodyBytes += bodyBytes
	b.objects += newObject
	b.objectBytes += objectBytes
	if key != "" {
		b.keys[key] = true
	}
	return true
}

type recordedStore struct {
	contract.Store
	inventory *objectInventory
	budget    *runBudget
}

func (s recordedStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s recordedStore) admittedMemoryStore() *memoryStore {
	provider, ok := s.Store.(admittedMemoryStoreProvider)
	if !ok {
		return nil
	}
	return provider.admittedMemoryStore()
}

func (s recordedStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if !s.budget.reserve(2, operationBodyAllowance, "", 0) {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	result := s.Store.Read(ctx, key, limit)
	if s.inventory != nil && s.inventory.observeImmutableRead(key, result) != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonProof}
	}
	if result.Status == contract.ReadUnavailable && result.Reason == contract.ReasonTransport {
		s.budget.mu.Lock()
		s.budget.transportReadFailures++
		s.budget.mu.Unlock()
	}
	return result
}

func (s recordedStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	if !s.budget.reserve(2, operationBodyAllowance, key, uint64(len(body))) {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit}
	}
	return s.inventory.write(ctx, key, body, "create", func() contract.WriteResult { return s.Store.Create(ctx, key, body) })
}

func (s recordedStore) CreateHead(ctx context.Context, request contract.HeadCreateRequest) contract.WriteResult {
	if !request.Valid() || request.Descriptor() != s.Store.Descriptor() {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	key := request.Descriptor().HeadKey
	if !s.budget.reserve(2, operationBodyAllowance, key, uint64(request.Length())) {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit}
	}
	return s.inventory.write(ctx, key, request.Body(), "create_head", func() contract.WriteResult { return s.Store.CreateHead(ctx, request) })
}

func (s recordedStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	if !s.budget.reserve(2, operationBodyAllowance, key, uint64(len(body))) {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit}
	}
	return s.inventory.write(ctx, key, body, "compare_and_swap", func() contract.WriteResult { return s.Store.CompareAndSwap(ctx, key, token, body) }, token)
}

type budgetTrust struct {
	contract.Trust
	budget *runBudget
}

func (s budgetTrust) admittedFixtureTrust() *fixtureTrust {
	provider, ok := s.Trust.(admittedFixtureTrustProvider)
	if !ok {
		return nil
	}
	return provider.admittedFixtureTrust()
}

func (s budgetTrust) Sign(ctx context.Context, request contract.SignRequest) contract.SignResult {
	if !s.budget.reserve(2, operationBodyAllowance, "", 0) {
		return contract.SignResult{Reason: contract.ReasonLimit}
	}
	return s.Trust.Sign(ctx, request)
}

func (s budgetTrust) QualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	trust, ok := s.Trust.(contract.QualifyingTrust)
	if !ok {
		return contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
	}
	if !s.budget.reserve(6, 3*operationBodyAllowance, "", 0) {
		return contract.SigningQualificationResult{Reason: contract.ReasonLimit}
	}
	return trust.QualifySigningBinding(ctx, binding)
}

func (b *runBudget) reserveCustody(operation string, count int) bool {
	if count < 1 {
		return false
	}
	calls, maximum := count, 0
	switch operation {
	case "init":
		maximum = contract.CryptoMaxRecipients + 1
		calls = 3*count + 2
	case "compare":
		maximum = 2 * contract.CryptoMaxValueEntries
	case "prepare", "consume":
		maximum = contract.CryptoMaxValueEntries
	default:
		return false
	}
	if count > maximum {
		return false
	}
	return b.reserve(uint64(2*calls), uint64(calls)*operationBodyAllowance, "", 0)
}
