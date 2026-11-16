package core

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// This fixture keeps the entered delete's original Attempt and duty. It adds
// the newer selected generation through the existing detached fixture, then
// authenticates the combined image with the normal fixture encoders.
func generatedLiveEnteredRetirementForLaterFailure(t testing.TB) (*StateSession, generatedAttempt, contract.GeneratedDutyRecord, contract.ApplyContext) {
	t.Helper()
	s, original, duty, target := generatedEnteredRetirementState(t, true)
	generatedLifecycleCanonicalRetirement(t, s, original.record.AttemptID, duty.DutyID)
	generatedLifecycleFixtureForFamily(t, s, contract.GCP)
	canonical, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal("canonical entered retirement", err)
	}
	original = canonical.attempts[original.record.AttemptID]
	duty, err = contract.InspectGeneratedDutyRecord(canonical.records[generatedRecordKey{contract.GeneratedDutySupportKind, duty.DutyID}].Body)
	if err != nil {
		t.Fatal("canonical entered retirement duty", err)
	}
	live, liveDuty, liveTarget := generatedDetachedRetirementState(t, "new incarnation", 0)
	if liveDuty.DutyID != duty.DutyID || liveTarget != target {
		t.Fatal("live fixture changed the original retiring resource")
	}
	current := live.pages[0].Slots[0]
	if current.Generated.OriginOperationID == target.OriginalOperationID || current.Generated.OriginAttemptID == target.OriginalAttemptID ||
		current.Generated.RetiringDutyPresent != 1 || current.Generated.RetiringDutyID != duty.DutyID ||
		current.Generated.IntentDigest != original.expected.Template.IntentDigest {
		t.Fatal("live fixture lost the current create or exact retained intent")
	}
	// Both fixture generations use the same exact intent bytes. The entered
	// image already retains their authenticated content ID; its slice is reused.
	peer := live.recipients[0].Slots[1]
	if peer == nil || s.recipients[0].Slots[1] != nil {
		t.Fatal("live fixture peer recipient slot")
	}
	s.recipients[0].Slots[1] = peer
	descriptor, err := contract.DecodeGenesisDescriptorCore(s.admission.descriptor)
	if err != nil {
		t.Fatal("live fixture genesis descriptor", err)
	}
	descriptor.Recipients = append(descriptor.Recipients, *peer)
	s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(descriptor)
	if err != nil {
		t.Fatal("live fixture peer enrollment", err)
	}
	current.Recipients = append([]contract.ID{s.admission.recipient}, current.Recipients...)
	payload, err := contract.DecodeCanonicalPayload(current.ValueBytes)
	if err != nil {
		t.Fatal("live fixture payload", err)
	}
	payload.CryptoSupportID = s.root.CurrentAccess.Core.CryptoSupportID
	current.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal("live fixture payload control", err)
	}
	valueAccess := *generatedFixtureMaterialAccess(t, live, contract.ValueMaterialKind, current.ValueState)
	valueAccess.Wraps = slices.Clone(valueAccess.Wraps)
	core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, *current)
	if err != nil {
		t.Fatal("live fixture value core", err)
	}
	valueAccess.MaterialContextDigest, err = contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal("live fixture value access context", err)
	}
	binding := s.authority().CurrentBinding
	bindingDigest, err := contract.PublicBindingDigest(*binding)
	if err != nil {
		t.Fatal("live fixture authority binding", err)
	}
	valueAccess.Wraps = append([]contract.WrapRow{{SubjectKind: 1, SubjectID: s.admission.recipient,
		BindingID: binding.BindingID, BindingSerial: binding.BindingSerial, PublicBindingDigest: bindingDigest,
		RSACiphertext: bytes.Repeat([]byte{91}, 384)}}, valueAccess.Wraps...)
	s.access[0].Records = append(s.access[0].Records, valueAccess)
	s.pages[0], s.root.Names = live.pages[0], slices.Clone(live.root.Names)
	unrelated := &format.ValueEntry{Name: "unrelated", Incarnation: generatedVectorID(221),
		ValueState: generatedVectorID(222), OriginSnapshot: s.root.Snapshot, OriginTransition: s.root.Transition,
		ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
		Recipients: []contract.ID{s.admission.recipient}, ValueBytes: []byte("retained supplied value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("retained supplied value"))), RetainedLength: uint32(len([]byte("retained supplied value")))}
	s.pages[0].Slots[1] = unrelated
	s.root.Names = append(s.root.Names, format.NameEntry{Name: unrelated.Name, Slot: 1})
	var added int
	for _, row := range live.supportRecords() {
		if row.Kind == contract.GeneratedCreateEvidenceSupportKind && row.RecordID == current.Generated.CreateResultID {
			s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
			added++
		}
	}
	if added != 1 {
		t.Fatal("live fixture current create evidence count", added)
	}
	s.root.Generated.GeneratedCurrent = 1
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("live entered fixture material index")
	}
	selected, err := s.selectedGeneratedWork(t.Context())
	if err != nil || selected == nil {
		t.Fatal("live entered fixture selected closure", err)
	}
	actual, ok := selected.attempts[original.record.AttemptID]
	if !ok || actual.record != original.record || !bytes.Equal(actual.result, original.result) ||
		actual.record.OwnerID != duty.DutyID {
		t.Fatal("live entered fixture changed original delete evidence")
	}
	actualDuty, err := contract.InspectGeneratedDutyRecord(selected.records[generatedRecordKey{contract.GeneratedDutySupportKind, duty.DutyID}].Body)
	if err != nil || actualDuty != duty {
		t.Fatal("live entered fixture changed original duty", err)
	}
	ctx := generatedContinuationContext(t, s, 201, 202)
	if !s.generatedContextValid(ctx) {
		t.Fatal("live entered fixture continuation context")
	}
	return s, original, duty, ctx
}

// full_only: false
func TestGeneratedRetirementCloseLaterFailureKeepsPredecessor(t *testing.T) {
	s, original, duty, admitted := generatedLiveEnteredRetirementForLaterFailure(t)
	s.admission.store.HeadKey = s.admission.store.Prefix + "/HEAD"
	s.admission.composition, s.admission.expires = generatedVectorID(244), time.Now().Add(time.Minute)
	backing := s.store.(*generatedFixtureSupportStore)
	store := &generatedInboxReleaseReadStore{readFailureStore: &readFailureStore{}, descriptor: s.admission.store}
	var faultKey string
	var faultLimit uint32
	var targetReads, failAt int
	store.onReadCtx = func(ctx context.Context) (contract.ReadResult, bool) {
		last := len(store.keys) - 1
		key, limit := store.keys[last], store.limits[last]
		if key == faultKey {
			if limit != faultLimit {
				t.Fatalf("retirement graph selected read bound=%d want=%d", limit, faultLimit)
			}
			targetReads++
			if failAt != 0 && targetReads == failAt {
				return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}, true
			}
		}
		return backing.Read(ctx, key, limit), true
	}
	s.store = store
	if !s.admission.valid(store) {
		t.Fatal("live retirement Store admission")
	}
	selected, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal("retirement graph before body release", err)
	}
	graph := selected.content.locations[generatedContentKey{contract.GeneratorContentGraph, original.expected.Plan.PlanGraphID}]
	var released int
	for location, fact := range s.fragmentFacts {
		if location.BlobID != graph.BlobID {
			continue
		}
		if _, cached := s.cache[fact.ref]; cached {
			t.Fatal("later failure fixture retains graph bytes in cache")
		}
		faultKey, err = format.Key(s.admission.store.Prefix, fact.ref)
		if err != nil {
			t.Fatal("later failure graph key", err)
		}
		faultLimit = fact.ref.Length
		for i := range s.support {
			if s.support[i].Index == location.SupportPageIndex {
				s.support[i].Records[location.RowSlot].Body = nil
				released++
			}
		}
	}
	if released != 1 || faultKey == "" || faultLimit == 0 {
		t.Fatal("later failure fixture needs one exact graph fragment", released)
	}
	generatedVerifySelectedFixtureSlices(t, s)
	permit, err := s.admitGeneratedRetirementClose(t.Context(), original.record.AttemptID, admitted)
	if err != nil || permit == nil {
		t.Fatal("real retirement close admission", err)
	}
	before := generatedSuccessorPredecessorSnapshot(t, s)
	current, unrelated := s.pages[0].Slots[0], s.pages[0].Slots[1]
	currentBytes := bytes.Clone(current.ValueBytes)
	wantMetadata := current.Generated
	wantMetadata.RetiringDutyPresent, wantMetadata.RetiringDutyID = 0, contract.ID{}
	start := len(store.keys)
	targetReads = 0
	healthy, err := s.deriveGeneratedRetirementClose(t.Context(), permit.plan, nil)
	if err != nil || healthy == nil || healthy.candidate == nil || healthy.state == nil {
		t.Fatal("healthy live retirement derivation", err)
	}
	got := healthy.state.pages[0].Slots[0]
	if healthy.state.pages[0] == s.pages[0] || got == current || got.Generated != wantMetadata ||
		!bytes.Equal(got.ValueBytes, currentBytes) || &got.ValueBytes[0] != &current.ValueBytes[0] ||
		healthy.state.pages[0].Slots[1] != unrelated || healthy.state.access[0] == s.access[0] ||
		len(healthy.state.accessRecords()) == 0 || got.Generated.RetiringDutyID == duty.DutyID {
		t.Fatal("healthy retirement did not construct copied entry and retained access")
	}
	if targetReads < 2 || !bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) || store.writes != 0 {
		t.Fatal("healthy retirement read trace or predecessor preservation", targetReads)
	}
	healthyKeys, healthyLimits := slices.Clone(store.keys[start:]), slices.Clone(store.limits[start:])
	failAt = targetReads
	want := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess}
	// The support wrapper is a reached-stage control: production calls support
	// installation only after clearGeneratedRetiringPointer and access packing.
	// Fail the last healthy read of this exact graph. The assertions below refuse
	// to treat an earlier read, or a different stage, as the requested later cut.
	start, targetReads = len(store.keys), 0
	failed, err := s.deriveGeneratedRetirementClose(t.Context(), permit.plan, nil)
	var readErr *selectedReadError
	if failed != nil || err == nil || !strings.HasPrefix(err.Error(), "retirement close support:") ||
		!errors.As(err, &readErr) || readErr.result != want || targetReads != failAt {
		t.Fatal("selected failure did not reach retirement support after entry/access construction", err, targetReads, failAt)
	}
	faultKeys, faultLimits := slices.Clone(store.keys[start:]), slices.Clone(store.limits[start:])
	if len(faultKeys) > len(healthyKeys) || !slices.Equal(faultKeys, healthyKeys[:len(faultKeys)]) ||
		!slices.Equal(faultLimits, healthyLimits[:len(faultLimits)]) || !bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) {
		t.Fatal("later failure did not follow the healthy selected-read prefix or preserve predecessor")
	}
	trust := &generatedInboxReleaseReadTrust{identity: s.admission.trust, family: s.admission.store.Family}
	// For retirement close, prepareGeneratedLifecycle has no pre-derive Store
	// reads: reflection/cleanup preflight does not apply. Its offset is zero.
	start, targetReads = len(store.keys), 0
	candidate, result := s.prepareGeneratedLifecycle(t.Context(), permit, trust)
	if candidate != nil || result != want || !permit.used || !s.prepared || targetReads != failAt ||
		!slices.Equal(store.keys[start:], faultKeys) || !slices.Equal(store.limits[start:], faultLimits) ||
		trust.signs != 0 || store.writes != 0 || !bytes.Equal(before, generatedSuccessorPredecessorSnapshot(t, s)) {
		t.Fatal("public retirement later failure exposed permission, changed predecessor, or lost selected-read result", result)
	}
}
