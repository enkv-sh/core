package core

import (
	"bytes"
	"context"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type observationStage uint8

const (
	observationComparison observationStage = iota + 1
	observationCandidate
	observationSelection
	observationExchange
)

// Zero IDs mean that the source did not establish the corresponding relation.
type observationSource struct {
	DomainID, AdmissionID, SessionID, InitID  contract.ID
	OperationID, ParentID, PhaseID, AttemptID contract.ID

	Stage observationStage
}

type observationSide uint8

const (
	observationBefore observationSide = iota + 1
	observationAfter
)

type observationRelation uint8

const (
	observationRelationUnavailable observationRelation = iota
	observationEqual
	observationChanged
)

type observationName struct {
	EntryIncarnationID contract.ID
	Name               string
	Side               observationSide
}

type observationEntry struct {
	BeforeIncarnationID, AfterIncarnationID     contract.ID
	ProposedName                                string
	BeforePresent, AfterPresent                 bool
	BeforeSource, AfterSource                   uint8
	BeforeConfidentiality, AfterConfidentiality uint8
	Relation                                    observationRelation
	Fields                                      observationFields
}

type observationMembership struct {
	EntryIncarnationID, RecipientID contract.ID
	EntryIndex                      uint16
	Change                          uint8
}

type observationFields uint16

const (
	observationFieldSource observationFields = 1 << iota
	observationFieldConfidentiality
	observationFieldMembership
	observationFieldEncodedMaterial
	observationFieldGeneration
)

const observationAllFields = observationFieldSource | observationFieldConfidentiality | observationFieldMembership | observationFieldEncodedMaterial | observationFieldGeneration

type observationSubject struct {
	Row                    contract.ChangedSubjectIdentity
	PrimaryID, SecondaryID contract.ID
	Fields                 observationFields
}

type observationGeneration struct {
	EntryIncarnationID, GenerationID, PlanID             contract.ID
	Side                                                 observationSide
	PlannedContent, PlannedMembership, PlannedRetirement bool
}

type observationSuccession struct {
	BeforeBindingID, AfterBindingID, BeforeBasisID, AfterBasisID contract.ID
	Purpose, Role                                                uint8
}

type observationAdministrative struct {
	TargetGroupID, TargetOwnerID, TargetID, DispositionID contract.ID
	TargetKind, DutyKind, BeforeWarnings, AfterWarnings   uint8
	EvidenceSummary                                       uint16
}

type observationCandidateIdentity struct {
	RevisionID, SnapshotID, PredecessorRevisionID, PredecessorDigest contract.ID
}

type changeObservation struct {
	Source             observationSource
	Entries            []observationEntry
	Memberships        []observationMembership
	Names              []observationName
	HasChangedSubjects bool
	Descriptor         contract.GeneratorDescriptor
	Subjects           []observationSubject
	Generations        []observationGeneration
	Succession         []observationSuccession
	Administrative     *observationAdministrative
	Candidate          observationCandidateIdentity
	Result             Result
}

type exchangeObservation struct {
	Source                       observationSource
	RequestID, CustodyInstanceID contract.ID
	Kind                         contract.CryptoKind
	ResultCode                   contract.CryptoResultCode
	Rows                         []contract.KeyUseRow
}

type observationFact struct {
	Change   *changeObservation
	Exchange *exchangeObservation
}

type observationRecord struct {
	fact observationFact
	next *observationRecord
}

type observationStatus struct {
	Accepted, DroppedContention, DroppedFull, Rejected uint64
	StoredBytes                                        uint64
}

type observationCollector struct {
	mu                                   sync.Mutex
	first, last                          *observationRecord
	count                                int
	storedBytes                          uint64
	accepted, contention, full, rejected atomic.Uint64
}

type operationObservation struct {
	source    observationSource
	collector *observationCollector
}

// Local protected operations need not have a Crypto admission or session ID.
// The owner lives in their private permit, never in the reusable state session.
func attachLocalObservation(slot **operationObservation, s *StateSession, enabled bool) bool {
	if slot == nil || *slot != nil || s == nil || !s.admission.valid(s.store) {
		return false
	}
	*slot = newOperationObservation(observationSource{DomainID: s.admission.domain}, enabled)
	return true
}

// The private enclosing admission calls this once, before sharing its permit.
// A disabled owner still occupies the slot and cannot be replaced later.
func attachOperationObservation(slot **operationObservation, s *StateSession, c contract.ApplyContext, enabled bool) bool {
	if slot == nil || *slot != nil || s == nil || !s.admission.valid(s.store) ||
		c.AdmissionID.IsZero() || c.SessionID.IsZero() ||
		(c.OperationClass != contract.CryptoOrdinaryLifecycle && c.OperationClass != contract.CryptoAccessReplacementClass && c.OperationClass != contract.CryptoGeneratedClass) ||
		c.DomainID != s.admission.domain || c.CompatibilityID != contract.CompatibilityID() || c.PredecessorHEADDigest != contract.Hash(s.body) ||
		c.Expiry > math.MaxInt64 || !validPrivateDeadline(time.Unix(0, int64(c.Expiry))) ||
		time.Unix(0, int64(c.Expiry)).After(s.admission.expires) {
		return false
	}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil || !bytes.Equal(root, c.PredecessorRootRef[:]) {
		return false
	}
	condition, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil || condition != c.OriginalConditionDigest || c.CurrentAccessRoot != s.root.CurrentAccess.AccessRoot {
		return false
	}
	*slot = newOperationObservation(observationSource{DomainID: c.DomainID,
		AdmissionID: c.AdmissionID, SessionID: c.SessionID}, enabled)
	return true
}

func attachInitObservation(a *initAdmission, store contract.Store, crypto contract.Crypto, enabled bool) bool {
	if a == nil || a.observation != nil || !a.valid(store, crypto) {
		return false
	}
	c := a.qualification.Context
	a.observation = newOperationObservation(observationSource{DomainID: c.DomainID,
		AdmissionID: c.AdmissionID, SessionID: c.SessionID, InitID: c.InitID}, enabled)
	return true
}

// A checked subadmission can carry its own correlation while retaining the
// enclosing collector. This is explicit private propagation, never a lookup.
func attachChildObservation(slot **operationObservation, parent *operationObservation, s *StateSession, c contract.ApplyContext) bool {
	if parent == nil || parent.source.DomainID != c.DomainID || !attachOperationObservation(slot, s, c, false) {
		return false
	}
	(*slot).collector = parent.collector
	return true
}

func newOperationObservation(source observationSource, enabled bool) *operationObservation {
	o := &operationObservation{source: source}
	if enabled {
		o.collector = &observationCollector{}
	}
	return o
}

func (o *operationObservation) enabled() bool { return o != nil && o.collector != nil }

func (o *operationObservation) sourceMatches(s observationSource) bool {
	if o == nil || o.source.DomainID.IsZero() {
		return false
	}
	for _, pair := range [][2]contract.ID{{s.DomainID, o.source.DomainID}, {s.AdmissionID, o.source.AdmissionID}, {s.SessionID, o.source.SessionID}, {s.InitID, o.source.InitID}} {
		if !pair[0].IsZero() && pair[0] != pair[1] {
			return false
		}
	}
	return true
}

func (o *operationObservation) sourceFor(s observationSource) observationSource {
	s.DomainID = o.source.DomainID
	s.AdmissionID, s.SessionID, s.InitID = o.source.AdmissionID, o.source.SessionID, o.source.InitID
	return s
}

const (
	observationMaxNames       = 2 * contract.CryptoMaxValueEntries
	observationMaxMemberships = 2 * contract.CryptoMaxMemberships
	observationMaxGenerations = contract.CryptoMaxValueEntries + 2*contract.GeneratedCurrentEntryLimit
	observationMaxSuccession  = 6
)

// Each allocation is charged a conservative allocator class plus header.
// Copies have exact slice capacities and own each nonempty string separately.
func observationAllocationBytes(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	class := uint64(32)
	for class < n+16 {
		class *= 2
	}
	return class
}

func observationChangeBytes(v changeObservation) uint64 {
	n := observationAllocationBytes(uint64(unsafe.Sizeof(observationRecord{}))) + observationAllocationBytes(uint64(unsafe.Sizeof(v)))
	n += observationAllocationBytes(uint64(len(v.Entries)) * uint64(unsafe.Sizeof(observationEntry{})))
	n += observationAllocationBytes(uint64(len(v.Memberships)) * uint64(unsafe.Sizeof(observationMembership{})))
	n += observationAllocationBytes(uint64(len(v.Names)) * uint64(unsafe.Sizeof(observationName{})))
	n += observationAllocationBytes(uint64(len(v.Subjects)) * uint64(unsafe.Sizeof(observationSubject{})))
	n += observationAllocationBytes(uint64(len(v.Generations)) * uint64(unsafe.Sizeof(observationGeneration{})))
	n += observationAllocationBytes(uint64(len(v.Succession)) * uint64(unsafe.Sizeof(observationSuccession{})))
	if v.Administrative != nil {
		n += observationAllocationBytes(uint64(unsafe.Sizeof(*v.Administrative)))
	}
	for _, e := range v.Entries {
		n += observationAllocationBytes(uint64(len(e.ProposedName)))
	}
	for _, name := range v.Names {
		n += observationAllocationBytes(uint64(len(name.Name)))
	}
	return n
}

func observationExchangeBytes(v exchangeObservation) uint64 {
	return observationAllocationBytes(uint64(unsafe.Sizeof(observationRecord{}))) + observationAllocationBytes(uint64(unsafe.Sizeof(v))) +
		observationAllocationBytes(uint64(len(v.Rows))*uint64(unsafe.Sizeof(contract.KeyUseRow{})))
}

// Independent source ceilings cover combinations of permitted detail without
// requiring a producer to split its complete projection.
func observationRetainedLimit() uint64 {
	change := observationAllocationBytes(uint64(unsafe.Sizeof(observationRecord{}))) + observationAllocationBytes(uint64(unsafe.Sizeof(changeObservation{}))) +
		observationAllocationBytes(observationMaxNames*uint64(unsafe.Sizeof(observationEntry{}))) +
		observationAllocationBytes(observationMaxMemberships*uint64(unsafe.Sizeof(observationMembership{}))) +
		observationAllocationBytes(observationMaxNames*uint64(unsafe.Sizeof(observationName{}))) +
		observationAllocationBytes(contract.MutationChangedSubjectLimit*uint64(unsafe.Sizeof(observationSubject{}))) +
		observationAllocationBytes(observationMaxGenerations*uint64(unsafe.Sizeof(observationGeneration{}))) +
		observationAllocationBytes(observationMaxSuccession*uint64(unsafe.Sizeof(observationSuccession{}))) +
		observationAllocationBytes(uint64(unsafe.Sizeof(observationAdministrative{}))) +
		2*observationMaxNames*observationAllocationBytes(contract.CryptoMaxName)
	exchange := observationAllocationBytes(uint64(unsafe.Sizeof(observationRecord{}))) + observationAllocationBytes(uint64(unsafe.Sizeof(exchangeObservation{}))) +
		observationAllocationBytes(contract.KeyUseRowsMaxCount*uint64(unsafe.Sizeof(contract.KeyUseRow{})))
	return max(change, exchange)
}

// Copies are made under the lock, so at most one pending read is collector-
// owned. Returned copies belong to the reader. A bounded local projection may
// coexist with retained data and one read until its owner offers it. Source
// strings and entry bytes are borrowed;
// no rejected offer stages a payload copy.
// Projection arrays use exact source-derived capacities. Names remain borrowed.
// Adding plan intent can overlap the old metadata vector with its replacement.
func observationProjectionLimit() uint64 {
	const subjects = 2 * (contract.CryptoMaxValueEntries + contract.CryptoMaxMemberships + contract.GeneratedCurrentEntryLimit)
	return observationAllocationBytes(uint64(unsafe.Sizeof(changeObservation{}))) +
		observationAllocationBytes(observationMaxNames*uint64(unsafe.Sizeof(observationEntry{}))) +
		observationAllocationBytes(observationMaxNames*uint64(unsafe.Sizeof(observationName{}))) +
		observationAllocationBytes(observationMaxMemberships*uint64(unsafe.Sizeof(observationMembership{}))) +
		observationAllocationBytes(subjects*uint64(unsafe.Sizeof(observationSubject{}))) +
		observationAllocationBytes(observationMaxGenerations*uint64(unsafe.Sizeof(observationGeneration{}))) +
		observationAllocationBytes(2*contract.GeneratedCurrentEntryLimit*uint64(unsafe.Sizeof(observationGeneration{})))
}

func observationMemoryBudget() uint64 {
	return 2*observationRetainedLimit() + observationProjectionLimit() + observationAllocationBytes(uint64(unsafe.Sizeof(observationCollector{}))) +
		observationAllocationBytes(uint64(unsafe.Sizeof(operationObservation{})))
}

func observationChangeValid(v changeObservation) bool {
	if v.Source.Stage < observationComparison || v.Source.Stage > observationSelection || len(v.Entries) > observationMaxNames ||
		len(v.Names) > observationMaxNames || len(v.Memberships) > observationMaxMemberships ||
		len(v.Subjects) > contract.MutationChangedSubjectLimit || len(v.Generations) > observationMaxGenerations || len(v.Succession) > observationMaxSuccession {
		return false
	}
	if v.HasChangedSubjects {
		if !v.Descriptor.Valid() || v.Descriptor.Count != uint32(len(v.Subjects)) || v.Descriptor.Length != 4+38*uint64(len(v.Subjects)) {
			return false
		}
	} else if len(v.Subjects) != 0 || v.Descriptor != (contract.GeneratorDescriptor{}) {
		return false
	}
	for _, e := range v.Entries {
		if e.BeforePresent && (e.BeforeIncarnationID.IsZero() || !observationEntryClassValid(e.BeforeSource, e.BeforeConfidentiality)) ||
			e.AfterPresent && !observationEntryClassValid(e.AfterSource, e.AfterConfidentiality) {
			return false
		}
		if len(e.ProposedName) > contract.CryptoMaxName || !utf8.ValidString(e.ProposedName) || e.Relation > observationChanged || e.Fields & ^observationAllFields != 0 ||
			!e.BeforePresent && !e.AfterPresent || !e.BeforePresent && !e.BeforeIncarnationID.IsZero() ||
			!e.AfterPresent && !e.AfterIncarnationID.IsZero() || e.ProposedName != "" && !e.AfterIncarnationID.IsZero() {
			return false
		}
	}
	for _, name := range v.Names {
		if name.EntryIncarnationID.IsZero() || name.Side < observationBefore || name.Side > observationAfter ||
			len(name.Name) > contract.CryptoMaxName || !utf8.ValidString(name.Name) {
			return false
		}
	}
	for _, m := range v.Memberships {
		if m.RecipientID.IsZero() || m.Change < contract.ChangedSubjectAdded || m.Change > contract.ChangedSubjectRemoved ||
			m.EntryIncarnationID.IsZero() && int(m.EntryIndex) >= len(v.Entries) {
			return false
		}
	}
	for _, s := range v.Subjects {
		if s.Row.Kind < contract.ChangedSubjectValueEntry || s.Row.Kind > contract.ChangedSubjectSelectedWork ||
			s.Row.Change < contract.ChangedSubjectAdded || s.Row.Change > contract.ChangedSubjectUpdated || s.Row.Identity.IsZero() ||
			s.Fields & ^observationAllFields != 0 {
			return false
		}
	}
	for _, g := range v.Generations {
		if g.Side < observationBefore || g.Side > observationAfter || g.GenerationID.IsZero() && (g.EntryIncarnationID.IsZero() || g.PlanID.IsZero() || !g.PlannedContent && !g.PlannedMembership && !g.PlannedRetirement) {
			return false
		}
	}
	return true
}

func observationEntryClassValid(source, confidentiality uint8) bool {
	return (source == contract.Supplied || source == contract.Generated) && (confidentiality == contract.Plain || confidentiality == contract.Secret)
}

type observationOffer uint8

const (
	observationAccepted observationOffer = iota + 1
	observationBusy
	observationFull
	observationRejected
)

func observationIncrement(v *atomic.Uint64) {
	for old := v.Load(); old != math.MaxUint64; old = v.Load() {
		if v.CompareAndSwap(old, old+1) {
			return
		}
	}
}

func observationFinish(ctx context.Context, status observationOffer) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreObservationOffer)
	result := telemetry.ResultSuccess
	switch status {
	case observationBusy:
		result = telemetry.ResultContention
	case observationFull:
		result = telemetry.ResultCapacityExceeded
	case observationRejected:
		result = telemetry.ResultInvalid
	}
	call.Finish(result)
}

func (c *observationCollector) reserve(n uint64) observationOffer {
	if !c.mu.TryLock() {
		observationIncrement(&c.contention)
		return observationBusy
	}
	if n > observationRetainedLimit()-c.storedBytes {
		c.mu.Unlock()
		observationIncrement(&c.full)
		return observationFull
	}
	return observationAccepted
}

func (c *observationCollector) append(f observationFact, n uint64) {
	r := &observationRecord{fact: f}
	if c.last == nil {
		c.first = r
	} else {
		c.last.next = r
	}
	c.last = r
	c.count++
	c.storedBytes += n
	observationIncrement(&c.accepted)
	c.mu.Unlock()
}

func (o *operationObservation) reject(ctx context.Context) bool {
	observationIncrement(&o.collector.rejected)
	observationFinish(ctx, observationRejected)
	return false
}

func (o *operationObservation) offerChange(ctx context.Context, v changeObservation) bool {
	if !o.enabled() {
		return false
	}
	if !o.sourceMatches(v.Source) || !observationChangeValid(v) {
		return o.reject(ctx)
	}
	n := observationChangeBytes(v)
	status := o.collector.reserve(n)
	if status == observationAccepted {
		v.Source = o.sourceFor(v.Source)
		o.collector.append(observationFact{Change: copyChangeObservation(v)}, n)
	}
	observationFinish(ctx, status)
	return status == observationAccepted
}

func (o *operationObservation) offerExchange(ctx context.Context, v exchangeObservation) bool {
	if !o.enabled() {
		return false
	}
	if !o.sourceMatches(v.Source) || v.Source.Stage != observationExchange || v.RequestID.IsZero() || v.CustodyInstanceID.IsZero() ||
		!v.Kind.Valid() || !v.ResultCode.Valid() {
		return o.reject(ctx)
	}
	if _, err := contract.KeyUseRowsLength(v.Rows); err != nil {
		return o.reject(ctx)
	}
	n := observationExchangeBytes(v)
	status := o.collector.reserve(n)
	if status == observationAccepted {
		v.Source = o.sourceFor(v.Source)
		o.collector.append(observationFact{Exchange: copyExchangeObservation(v)}, n)
	}
	observationFinish(ctx, status)
	return status == observationAccepted
}

func observationCopySlice[T any](v []T) []T {
	if v == nil {
		return nil
	}
	out := make([]T, len(v))
	copy(out, v)
	return out
}

func copyChangeObservation(v changeObservation) *changeObservation {
	v.Entries = observationCopySlice(v.Entries)
	for i := range v.Entries {
		v.Entries[i].ProposedName = strings.Clone(v.Entries[i].ProposedName)
	}
	v.Names = observationCopySlice(v.Names)
	for i := range v.Names {
		v.Names[i].Name = strings.Clone(v.Names[i].Name)
	}
	v.Memberships = observationCopySlice(v.Memberships)
	v.Subjects = observationCopySlice(v.Subjects)
	v.Generations = observationCopySlice(v.Generations)
	v.Succession = observationCopySlice(v.Succession)
	if v.Administrative != nil {
		administrative := *v.Administrative
		v.Administrative = &administrative
	}
	return &v
}

func copyExchangeObservation(v exchangeObservation) *exchangeObservation {
	v.Rows = observationCopySlice(v.Rows)
	return &v
}

func (o *operationObservation) read() ([]observationFact, observationStatus) {
	if !o.enabled() {
		return nil, observationStatus{}
	}
	c := o.collector
	c.mu.Lock()
	defer c.mu.Unlock()
	facts := make([]observationFact, c.count)
	i := 0
	for r := c.first; r != nil; r = r.next {
		if r.fact.Change != nil {
			facts[i].Change = copyChangeObservation(*r.fact.Change)
		} else {
			facts[i].Exchange = copyExchangeObservation(*r.fact.Exchange)
		}
		i++
	}
	return facts, observationStatus{Accepted: c.accepted.Load(), DroppedContention: c.contention.Load(), DroppedFull: c.full.Load(),
		Rejected: c.rejected.Load(), StoredBytes: c.storedBytes}
}
