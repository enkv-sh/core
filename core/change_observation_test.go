package core

import (
	"bytes"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func observationCurrentSecret(t testing.TB, s *StateSession, recipients []contract.ID, incarnation contract.ID) {
	t.Helper()
	_, retained := generatedCanonicalSource(t)
	entry := retained.Entry
	entry.Name, entry.Incarnation, entry.Recipients = "secret", incarnation, slices.Clone(recipients)
	payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload.CryptoSupportID = s.root.CurrentAccess.Core.CryptoSupportID
	payload.ContentLength, payload.RetainedLength, payload.Ciphertext = 0, 0, make([]byte, 16)
	entry.ContentLength, entry.RetainedLength = payload.ContentLength, payload.RetainedLength
	entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	s.pages[0] = &format.ValueEntryPage{Domain: s.root.Domain, Object: generatedVectorID(240)}
	s.pages[0].Slots[0] = &entry
	s.root.Names = []format.NameEntry{{Name: "secret", Slot: 0}}
	s.root.ValueEntryCount, s.root.SecretCount = 1, 1
	core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, entry)
	if err != nil {
		t.Fatal(err)
	}
	material, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	binding := s.authority().CurrentBinding
	digest, err := contract.PublicBindingDigest(*binding)
	if err != nil {
		t.Fatal(err)
	}
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: entry.ValueState, MaterialContextDigest: material, PackageCheck: payload.PackageCheck,
		Wraps: []contract.WrapRow{{SubjectKind: 1, SubjectID: s.admission.recipient, BindingID: binding.BindingID, BindingSerial: binding.BindingSerial, PublicBindingDigest: digest, RSACiphertext: bytes.Repeat([]byte{91}, 384)}}}
	for _, recipient := range recipients[1:] {
		readerBinding := generatedPublicBinding(t, 220)
		if s.root.CurrentAccess.Core.Provider == contract.AWS {
			readerBinding.Provider, readerBinding.ProtectionClass = contract.AWS, contract.HardwareProtection
			readerBinding.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000002"
		}
		reader := &contract.RecipientRecord{RecipientID: recipient, Status: contract.CurrentRecipient, CurrentBinding: &readerBinding}
		s.recipients[0].Slots[1] = reader
		readerDigest, err := contract.PublicBindingDigest(readerBinding)
		if err != nil {
			t.Fatal(err)
		}
		access.Wraps = append(access.Wraps, contract.WrapRow{SubjectKind: 1, SubjectID: recipient, BindingID: readerBinding.BindingID, BindingSerial: readerBinding.BindingSerial, PublicBindingDigest: readerDigest, RSACiphertext: bytes.Repeat([]byte{92}, 384)})
	}
	s.accessLocations = map[materialIdentity]materialLocation{{contract.ValueMaterialKind, entry.ValueState}: {page: 0, row: 0}}
	s.valueReaders = map[contract.ID][]contract.ID{entry.ValueState: slices.Clone(recipients)}
	s.access[0] = &format.AccessPage{Domain: s.root.Domain, Object: generatedVectorID(241), Records: []contract.AccessRecord{access}}
}

func observationComparedBody(t testing.TB, comparison *Comparison, relation contract.CryptoRelation, exclusion bool) []byte {
	t.Helper()
	row := contract.CryptoComparisonRow{Name: "secret", BeforePresent: true, AfterPresent: true, Relation: relation,
		BeforePublicEntryDigest: publicEntryDigest(comparison.session.admission.domain, 0, comparison.session.valueEntry(0)), SourceDigest: comparison.intent[0].PayloadDigest, AfterRawLength: comparison.intent[0].ContentLength}
	if exclusion {
		row.ExclusionPathDigest = generatedVectorID(129)
	}
	descriptor, err := contract.CryptoComparisonDescriptor([]contract.CryptoComparisonRow{row})
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCryptoCompareResult(contract.CryptoCompareResult{OperationRef: generatedVectorID(128), Rows: []contract.CryptoComparisonRow{row}, ComparisonDigest: descriptor.Digest})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestCheckedComparisonPreservesHistoricalNameAndEqualExclusion(t *testing.T) {
	for _, name := range []string{"historical name reuse", "equal recipient exclusion"} {
		t.Run(name, func(t *testing.T) {
			s, _ := observationTestSession(t)
			recipients := []contract.ID{s.admission.recipient}
			if name == "equal recipient exclusion" {
				recipients = append(recipients, generatedVectorID(200))
			}
			observationCurrentSecret(t, s, recipients, generatedVectorID(201))
			generatedSealSelectedFixture(t, s)
			custody := &observationExchangeCustody{instance: generatedVectorID(105)}
			input, permit, key := observationComparisonPermit(t, s, custody)
			comparison, result := s.compareEntryInputs(input)
			if comparison == nil {
				t.Fatal(result)
			}
			body := observationComparedBody(t, comparison, contract.CryptoEqual, len(recipients) > 1)
			key.Count = 2
			custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
				if q.Kind == contract.CryptoCompare {
					return observationReply(q, contract.CryptoSuccess, []contract.KeyUseRow{key}, body)
				}
				return observationReply(q, contract.CryptoSuccess, nil, nil)
			}
			got, result := s.compare(t.Context(), input, permit)
			if name == "equal recipient exclusion" {
				if got == nil || result.Outcome != ObservedCurrent || !got.needsFreshValue(0) {
					t.Fatal("equal exclusion did not require fresh material", result)
				}
			} else if got != nil || result.Outcome != Unchanged {
				t.Fatal("equal comparison changed", result)
			}
			facts, status := permit.observation.read()
			var change *changeObservation
			for _, fact := range facts {
				if fact.Change != nil {
					if change != nil {
						t.Fatal("duplicate comparison")
					}
					change = fact.Change
				}
			}
			if change == nil {
				t.Fatal("checked comparison meaning lost", status)
			}
			wantEntry := observationEntry{BeforePresent: true, AfterPresent: true, BeforeIncarnationID: generatedVectorID(201), AfterIncarnationID: generatedVectorID(201), BeforeSource: contract.Supplied, AfterSource: contract.Supplied, BeforeConfidentiality: contract.Secret, AfterConfidentiality: contract.Secret, Relation: observationEqual}
			if !reflect.DeepEqual(change.Entries, []observationEntry{wantEntry}) || change.HasChangedSubjects || change.Descriptor != (contract.GeneratorDescriptor{}) {
				t.Fatal("equal relation or absent commitment changed", change)
			}
			wantNames := []observationName{{EntryIncarnationID: generatedVectorID(201), Name: "secret", Side: observationBefore}, {EntryIncarnationID: generatedVectorID(201), Name: "secret", Side: observationAfter}}
			if !reflect.DeepEqual(change.Names, wantNames) {
				t.Fatal("historical name bindings lost", change.Names)
			}
			if name == "equal recipient exclusion" {
				want := []observationMembership{{EntryIncarnationID: generatedVectorID(201), RecipientID: generatedVectorID(200), Change: contract.ChangedSubjectRemoved}}
				if !reflect.DeepEqual(change.Memberships, want) {
					t.Fatal("membership exclusion lost", change.Memberships)
				}
			} else {
				s.pages[0].Slots[0].Incarnation = generatedVectorID(202)
				again, _ := permit.observation.read()
				if !reflect.DeepEqual(again[len(again)-2].Change.Names, wantNames) {
					t.Fatal("old label adopted reused incarnation")
				}
			}
		})
	}
}

func observationInstallEntries(s *StateSession, entries []contract.ValueEntry) {
	s.pages = [contract.MaxValueEntryPages]*format.ValueEntryPage{}
	s.root.Names = nil
	for i := range entries {
		page := i / format.PageSlots
		if s.pages[page] == nil {
			s.pages[page] = &format.ValueEntryPage{Domain: s.root.Domain, Object: observationBoundID(60000 + page)}
		}
		entry := entries[i]
		s.pages[page].Slots[i%format.PageSlots] = &entry
		s.root.Names = append(s.root.Names, format.NameEntry{Name: entry.Name, Slot: uint16(i)})
	}
	s.root.ValueEntryCount = uint32(len(entries))
}

func observationPlainEntry(name string, incarnation contract.ID, recipients []contract.ID) contract.ValueEntry {
	return contract.ValueEntry{Name: name, Incarnation: incarnation, ValueState: generatedVectorID(203), OriginSnapshot: generatedVectorID(204), OriginTransition: generatedVectorID(205), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: slices.Clone(recipients), ValueBytes: []byte("value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("value"))), RetainedLength: uint32(len([]byte("value")))}
}

// full_only: false
func TestPlainComparisonObservationAtLocalOwner(t *testing.T) {
	for _, condition := range []string{"unchanged", "content", "membership", "source replacement", "disjoint removal addition", "active owner", "disabled", "full", "busy"} {
		t.Run(condition, func(t *testing.T) {
			s, _ := observationTestSession(t)
			readerBinding := generatedPublicBinding(t, 220)
			readerBinding.Provider, readerBinding.ProtectionClass = contract.AWS, contract.HardwareProtection
			readerBinding.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000002"
			s.recipients[0].Slots[1] = &contract.RecipientRecord{RecipientID: generatedVectorID(200), Status: contract.CurrentRecipient, CurrentBinding: &readerBinding}
			before := observationPlainEntry("reused", generatedVectorID(201), []contract.ID{s.admission.recipient})
			observationInstallEntries(s, []contract.ValueEntry{before})
			generatedSealSelectedFixture(t, s)
			input := []ApplyEntryInput{{InputEncoding: before.InputEncoding, OutputEncoding: before.OutputEncoding, Name: "reused", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: slices.Clone(before.Recipients), InputBytes: bytes.Clone(before.ValueBytes)}}
			switch condition {
			case "content", "active owner":
				input[0].InputBytes = []byte("other")
			case "membership":
				input[0].Recipients = append(input[0].Recipients, generatedVectorID(200))
			case "source replacement":
				input[0].ValueSource = contract.Generated // invalid plain generation must make no claim
			case "disjoint removal addition":
				input[0].Name = "new"
			}
			if condition == "active owner" {
				s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = generatedVectorID(250), generatedVectorID(249), generatedVectorID(248)
			}
			parent := &AdmittedParentComparison{session: s, deadline: time.Now().Add(time.Minute)}
			if !attachLocalObservation(&parent.observation, s, condition != "disabled") {
				t.Fatal("local observation admission")
			}
			if condition == "full" {
				parent.observation.collector.storedBytes = observationRetainedLimit()
			}
			if condition == "busy" {
				parent.observation.collector.mu.Lock()
			}
			comparison, result := s.compareObserved(t.Context(), input, parent)
			if condition == "busy" {
				parent.observation.collector.mu.Unlock()
			}
			facts, status := parent.observation.read()
			switch condition {
			case "source replacement":
				if comparison != nil || result.Reason != InvalidIntent || len(facts) != 0 {
					t.Fatal("invalid plain generation disclosed", result, status)
				}
				return
			case "disabled", "busy", "full":
				if result.Outcome != Unchanged || comparison != nil || len(facts) != 0 {
					t.Fatal("refusal changed operation", result, status)
				}
				return
			case "active owner":
				if comparison != nil || result.Outcome != Contention || result.Reason != DifferentSelection {
					t.Fatal(result)
				}
			case "unchanged":
				if comparison != nil || result.Outcome != Unchanged {
					t.Fatal(result)
				}
			default:
				if comparison == nil || result.Outcome != ObservedCurrent || comparison.observation != parent.observation {
					t.Fatal("owner did not follow comparison", result)
				}
			}
			if len(facts) != 1 || facts[0].Change == nil || facts[0].Change.HasChangedSubjects || !facts[0].Change.Source.AdmissionID.IsZero() {
				t.Fatal("plain fact or absent commitment", status)
			}
			change := facts[0].Change
			if condition == "disjoint removal addition" {
				if len(change.Entries) != 2 || change.Entries[0].ProposedName != "new" || change.Entries[0].BeforePresent || change.Entries[1].BeforeIncarnationID != before.Incarnation || change.Entries[1].AfterPresent || len(change.Memberships) != 2 {
					t.Fatal("complete union lost", change)
				}
			} else {
				want := observationEqual
				if condition == "content" || condition == "active owner" {
					want = observationChanged
				}
				if len(change.Entries) != 1 || change.Entries[0].Relation != want || change.Entries[0].AfterIncarnationID != before.Incarnation {
					t.Fatal("plain relation changed", change)
				}
				if condition == "membership" && !reflect.DeepEqual(change.Memberships, []observationMembership{{EntryIncarnationID: before.Incarnation, RecipientID: generatedVectorID(200), Change: contract.ChangedSubjectAdded}}) {
					t.Fatal("membership-only changed content", change)
				}
			}
			if _, result := s.compareObserved(t.Context(), input, parent); result.Reason != AdmissionInvalid {
				t.Fatal("local permit reused")
			}
		})
	}
}

// full_only: false
func TestCheckedComparisonFactsSurviveLaterRefusal(t *testing.T) {
	for _, condition := range []string{"discard failure", "active owner", "content changed", "source replacement"} {
		t.Run(condition, func(t *testing.T) {
			s, _ := observationTestSession(t)
			observationCurrentSecret(t, s, []contract.ID{s.admission.recipient}, generatedVectorID(201))
			if condition == "source replacement" {
				s.pages[0].Slots[0].ValueSource = contract.Generated
				fixture, _, _ := generatedDetachedRetirementState(t, "new incarnation", 0)
				s.pages[0].Slots[0].Generated = fixture.pages[0].Slots[0].Generated
				s.pages[0].Slots[0].Generated.GenerationID = s.pages[0].Slots[0].ValueState
				core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, *s.pages[0].Slots[0])
				if err != nil {
					t.Fatal(err)
				}
				material, err := contract.ValueMaterialContextDigest(core)
				if err != nil {
					t.Fatal(err)
				}
				s.access[0].Records[0].MaterialContextDigest = material
			}
			generatedSealSelectedFixture(t, s)
			custody := &observationExchangeCustody{instance: generatedVectorID(105)}
			input, permit, key := observationComparisonPermit(t, s, custody)
			comparison, result := s.compareEntryInputs(input)
			if comparison == nil {
				t.Fatal(result)
			}
			relation := contract.CryptoEqual
			if condition == "content changed" || condition == "active owner" {
				relation = contract.CryptoChanged
			}
			if condition == "active owner" {
				s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = generatedVectorID(250), generatedVectorID(249), generatedVectorID(248)
			}
			body := observationComparedBody(t, comparison, relation, condition == "source replacement")
			key.Count = 2
			custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
				if q.Kind == contract.CryptoCompare {
					return observationReply(q, contract.CryptoSuccess, []contract.KeyUseRow{key}, body)
				}
				if condition == "active owner" {
					return observationReply(q, contract.CryptoSuccess, nil, nil)
				}
				return observationReply(q, contract.CryptoCustodyUnavailable, nil, nil)
			}
			got, result := s.compare(t.Context(), input, permit)
			if condition == "discard failure" {
				if got != nil || result != custodyFailure(contract.CryptoCustodyUnavailable) {
					t.Fatal("later discard failure changed", result)
				}
			} else if condition == "active owner" {
				if got != nil || result.Outcome != Contention || result.Reason != DifferentSelection {
					t.Fatal("active owner refusal changed", result)
				}
			} else if got == nil || result.Outcome != ObservedCurrent {
				t.Fatal(result)
			}
			facts, status := permit.observation.read()
			if len(facts) < 2 || facts[1].Change == nil || facts[0].Exchange == nil {
				t.Fatal("validated relation lost", status)
			}
			change := facts[1].Change
			want := observationEqual
			if relation == contract.CryptoChanged {
				want = observationChanged
			}
			if len(change.Entries) != 1 || change.Entries[0].Relation != want || change.HasChangedSubjects {
				t.Fatal("wrong checked relation", change)
			}
			if condition == "source replacement" && (change.Entries[0].ProposedName != "secret" || !change.Entries[0].AfterIncarnationID.IsZero() || len(change.Names) != 1 || len(change.Memberships) != 2 || change.Memberships[1].EntryIndex != 0 || !change.Memberships[1].EntryIncarnationID.IsZero()) {
				t.Fatal("unallocated after incarnation invented", change)
			}
		})
	}
}

// full_only: false
func TestPlainRemovedNameReuseKeepsOriginalObservation(t *testing.T) {
	s, _ := observationTestSession(t)
	original := observationPlainEntry("reused", generatedVectorID(201), []contract.ID{s.admission.recipient})
	observationInstallEntries(s, []contract.ValueEntry{original})
	generatedSealSelectedFixture(t, s)
	first := &AdmittedParentComparison{session: s, deadline: time.Now().Add(time.Minute)}
	if !attachLocalObservation(&first.observation, s, true) {
		t.Fatal("removal owner admission")
	}
	comparison, result := s.compareObserved(t.Context(), nil, first)
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("checked removal", result)
	}
	originalFacts, _ := first.observation.read()
	if len(originalFacts) != 1 || len(originalFacts[0].Change.Entries) != 1 || originalFacts[0].Change.Entries[0].AfterPresent || len(originalFacts[0].Change.Names) != 1 {
		t.Fatal("removal detail absent")
	}
	expected := observationName{EntryIncarnationID: original.Incarnation, Name: "reused", Side: observationBefore}
	if originalFacts[0].Change.Names[0] != expected {
		t.Fatal("removal binding changed")
	}
	replacement := original
	replacement.Incarnation = generatedVectorID(202)
	observationInstallEntries(s, []contract.ValueEntry{replacement})
	generatedSealSelectedFixture(t, s)
	later := &AdmittedParentComparison{session: s, deadline: time.Now().Add(time.Minute)}
	if !attachLocalObservation(&later.observation, s, true) {
		t.Fatal("reuse owner admission")
	}
	input := []ApplyEntryInput{{InputEncoding: replacement.InputEncoding, OutputEncoding: replacement.OutputEncoding, Name: replacement.Name, ValueSource: replacement.ValueSource, ConfidentialityClass: replacement.ConfidentialityClass, Recipients: replacement.Recipients, InputBytes: replacement.ValueBytes}}
	if comparison, result = s.compareObserved(t.Context(), input, later); comparison != nil || result.Outcome != Unchanged {
		t.Fatal("checked reused entry", result)
	}
	old, _ := first.observation.read()
	current, _ := later.observation.read()
	if len(old) != 1 || old[0].Change.Names[0] != expected || len(current) != 1 || len(current[0].Change.Names) != 2 || current[0].Change.Names[0].EntryIncarnationID != replacement.Incarnation || current[0].Change.Names[1].EntryIncarnationID != replacement.Incarnation {
		t.Fatal("old observation adopted reused name or later facts")
	}
}

// full_only: false
func TestComparisonProjectionAdvancesAcrossMixedSecretRows(t *testing.T) {
	s, _ := observationTestSession(t)
	observationCurrentSecret(t, s, []contract.ID{s.admission.recipient}, generatedVectorID(201))
	original := *s.valueEntry(0)
	before := make([]contract.ValueEntry, 3)
	for i, name := range []string{"alpha", "omega", "zeta"} {
		before[i] = original
		before[i].Name = name
		before[i].Incarnation = generatedVectorID(byte(201 + i))
	}
	observationInstallEntries(s, before)
	c := &Comparison{session: s, desiredEntries: []ApplyEntryInput{
		{Name: "alpha", ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, Recipients: original.Recipients},
		{Name: "middle", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: original.Recipients, InputBytes: []byte("plain")},
		{Name: "theta", ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, Recipients: original.Recipients},
		{Name: "zeta", ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, Recipients: original.Recipients},
	}}
	for _, entry := range c.desiredEntries {
		c.intent = append(c.intent, contract.CryptoIntentRow{Name: entry.Name, ValueSource: entry.ValueSource, ConfidentialityClass: entry.ConfidentialityClass, Recipients: entry.Recipients, PayloadDigest: generatedVectorID(122), InputEncoding: contract.InputEncodingRaw, RetainedLength: 0, OutputEncoding: contract.OutputEncodingRaw})
	}
	rows := []contract.CryptoComparisonRow{
		{Name: "alpha", BeforePresent: true, AfterPresent: true, Relation: contract.CryptoEqual, BeforePublicEntryDigest: publicEntryDigest(s.root.Domain, 0, &before[0]), SourceDigest: generatedVectorID(122)},
		{Name: "omega", BeforePresent: true, Relation: contract.CryptoRemoved, BeforePublicEntryDigest: publicEntryDigest(s.root.Domain, 1, &before[1]), ExclusionPathDigest: generatedVectorID(123)},
		{Name: "theta", AfterPresent: true, Relation: contract.CryptoAdded, SourceDigest: generatedVectorID(122)},
		{Name: "zeta", BeforePresent: true, AfterPresent: true, Relation: contract.CryptoChanged, BeforePublicEntryDigest: publicEntryDigest(s.root.Domain, 2, &before[2]), SourceDigest: generatedVectorID(122)},
	}
	descriptor, err := contract.CryptoComparisonDescriptor(rows)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCryptoCompareResult(contract.CryptoCompareResult{OperationRef: generatedVectorID(128), Rows: rows, ComparisonDigest: descriptor.Digest})
	if err != nil {
		t.Fatal(err)
	}
	checked, err := contract.DecodeCryptoCompareResult(body)
	if err != nil || !comparisonMatches(c, checked) {
		t.Fatal("mixed source rows not checked", err)
	}
	c.secretRows = checked.Rows
	detail := comparisonObservation(c)
	want := []observationRelation{observationEqual, observationRelationUnavailable, observationRelationUnavailable, observationRelationUnavailable, observationChanged}
	if len(detail.Entries) != len(want) {
		t.Fatal("mixed name union changed")
	}
	for i, entry := range detail.Entries {
		if entry.Relation != want[i] {
			t.Fatal("checked row lookup skipped a later relation", i, entry.Relation, want[i])
		}
	}
	if detail.Entries[1].ProposedName != "middle" || detail.Entries[2].BeforeIncarnationID != before[1].Incarnation || detail.Entries[2].AfterPresent || detail.Entries[3].ProposedName != "theta" {
		t.Fatal("mixed presence or proposed name changed")
	}
}
