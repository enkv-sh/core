package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/core/contract"
)

func observationBoundID(n int) contract.ID {
	var id contract.ID
	binary.BigEndian.PutUint64(id[24:], uint64(n+1))
	return id
}

// Full source ceilings: 512 before/after entries, 4096 memberships per side,
// 128 generated entries per side and 256-byte labels; the key-use representation
// ceiling is 8224 rows and the checked initialization maximum is 1036 rows.
// full_only: true
func TestOperationObservationLargestLegalProjections(t *testing.T) {
	t.Run("generated complete vector", func(t *testing.T) {
		v := changeObservation{Source: observationSource{Stage: observationCandidate}, HasChangedSubjects: true}
		rows := make([]contract.ChangedSubjectIdentity, 0, 9472)
		appendSubject := func(kind, change uint8, primary, secondary contract.ID) {
			identity, err := contract.ChangedSubjectIdentityID(generatedVectorID(1), kind, primary, secondary)
			if err != nil {
				t.Fatal(err)
			}
			row := contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: identity}
			rows = append(rows, row)
			v.Subjects = append(v.Subjects, observationSubject{Row: row, PrimaryID: primary, SecondaryID: secondary, Fields: observationFieldEncodedMaterial})
		}
		for side := 0; side < 2; side++ {
			change := uint8(contract.ChangedSubjectRemoved)
			if side == 1 {
				change = contract.ChangedSubjectAdded
			}
			for entry := 0; entry < 512; entry++ {
				incarnation := observationBoundID(side*512 + entry)
				name := fmt.Sprintf("entry-%03d-", entry) + strings.Repeat("n", 246)
				if len(name) != 256 {
					t.Fatal("largest source name fixture length")
				}
				v.Names = append(v.Names, observationName{EntryIncarnationID: incarnation, Side: observationSide(side + 1), Name: name})
				appendSubject(contract.ChangedSubjectValueEntry, change, incarnation, contract.ID{})
				for recipient := 0; recipient < 8; recipient++ {
					appendSubject(contract.ChangedSubjectMembership, change, incarnation, observationBoundID(10000+recipient))
				}
				if entry < 128 {
					generation := observationBoundID(20000 + side*128 + entry)
					appendSubject(contract.ChangedSubjectGeneratedValue, change, generation, contract.ID{})
					v.Generations = append(v.Generations, observationGeneration{EntryIncarnationID: incarnation, GenerationID: generation, PlanID: observationBoundID(21000 + side*128 + entry), Side: observationSide(side + 1), PlannedContent: true, PlannedMembership: true, PlannedRetirement: side == 0})
				}
			}
		}
		if len(rows) != 9472 || len(v.Names) != 1024 || len(v.Generations) != 256 {
			t.Fatal("largest complete source fixture is missing detail")
		}
		var err error
		v.Descriptor, err = contract.ChangedSubjectDescriptor(rows)
		if err != nil {
			t.Fatal(err)
		}
		slices.SortFunc(v.Subjects, func(a, b observationSubject) int {
			if a.Row.Kind != b.Row.Kind {
				return int(a.Row.Kind) - int(b.Row.Kind)
			}
			if a.Row.Change != b.Row.Change {
				return int(a.Row.Change) - int(b.Row.Change)
			}
			return bytes.Compare(a.Row.Identity[:], b.Row.Identity[:])
		})
		observationAssertMaximumFits(t, v)
	})
	t.Run("comparison union and membership", func(t *testing.T) {
		v := changeObservation{Source: observationSource{Stage: observationComparison}}
		for side := 0; side < 2; side++ {
			for entry := 0; entry < 512; entry++ {
				incarnation := observationBoundID(entry)
				name := fmt.Sprintf("entry-%03d-", entry) + strings.Repeat("n", 246)
				e := observationEntry{Relation: observationRelationUnavailable}
				change := uint8(contract.ChangedSubjectRemoved)
				if side == 0 {
					e.BeforePresent = true
					e.BeforeIncarnationID = incarnation
					e.BeforeSource = contract.Supplied
					e.BeforeConfidentiality = contract.Secret
					v.Names = append(v.Names, observationName{EntryIncarnationID: incarnation, Name: name, Side: observationBefore})
				} else {
					e.AfterPresent = true
					e.AfterSource = contract.Supplied
					e.AfterConfidentiality = contract.Secret
					e.ProposedName = name
					incarnation = contract.ID{}
					change = contract.ChangedSubjectAdded
				}
				v.Entries = append(v.Entries, e)
				for recipient := 0; recipient < 8; recipient++ {
					v.Memberships = append(v.Memberships, observationMembership{EntryIncarnationID: incarnation, RecipientID: observationBoundID(10000 + recipient), EntryIndex: uint16(side*512 + entry), Change: change})
				}
			}
		}
		if len(v.Entries) != 1024 || len(v.Memberships) != 8192 || len(v.Names) != 512 {
			t.Fatal("largest comparison fixture missing union or membership")
		}
		observationAssertMaximumFits(t, v)
	})
	t.Run("key-use representation ceiling", func(t *testing.T) {
		v := exchangeObservation{Source: observationSource{Stage: observationExchange}, RequestID: generatedVectorID(70), CustodyInstanceID: generatedVectorID(71), Kind: contract.CryptoPrepare, ResultCode: contract.CryptoPrivateRouteUnavailable}
		for binding := 0; binding < 514; binding++ {
			for purpose := uint8(1); purpose <= 4; purpose++ {
				for outcome := uint8(1); outcome <= 4; outcome++ {
					v.Rows = append(v.Rows, contract.KeyUseRow{BindingID: observationBoundID(binding), PublicBindingDigest: observationBoundID(10000 + binding), SubjectKind: 1, SubjectID: observationBoundID(binding / 2), Provider: contract.AWS, Purpose: purpose, Outcome: outcome, Count: 1})
				}
			}
		}
		if len(v.Rows) != 8224 {
			t.Fatal("maximum legal key-use vector missing rows")
		}
		if _, err := contract.KeyUseRowsLength(v.Rows); err != nil {
			t.Fatal("maximum key-use fixture is not legal", err)
		}
		owner := observationTestOwner(t)
		if !owner.offerExchange(t.Context(), v) {
			t.Fatal("empty collector rejected largest key-use vector")
		}
		facts, status := owner.read()
		if len(facts) != 1 || !reflect.DeepEqual(facts[0].Exchange.Rows, v.Rows) || cap(facts[0].Exchange.Rows) != len(v.Rows) || status.StoredBytes != observationExchangeBytes(v) || status.StoredBytes > observationRetainedLimit() {
			t.Fatal("maximum key-use copy lost rows or retained backing")
		}
		t.Logf("key-use stored_bytes=%d memory_budget=%d", status.StoredBytes, observationMemoryBudget())
	})
	t.Run("largest checked initialization exchange", func(t *testing.T) {
		id := observationBoundID
		q := contract.CryptoQualifyInitKeysRequest{Context: contract.InitKeyContext{Schema: contract.CryptoSchema, GenesisProfile: 1,
			AdmissionID: id(40000), SessionID: id(40001), DomainID: id(40004), CompatibilityID: contract.CompatibilityID(),
			InitID: id(40005), DescriptorDigest: id(40006), GenesisPlanDigest: id(40007), Expiry: uint64(time.Now().Add(time.Minute).UnixNano()),
			RequestDescriptor: contract.DescriptorVector{Count: 1, Length: contract.GenesisRequestCoreLength, Digest: id(40008)}}}
		binding := generatedPublicBinding(t, 65)
		var rows []contract.KeyUseRow
		for i := 0; i < 257; i++ {
			b := binding
			b.BindingID = id(41000 + i)
			b.BindingIncarnationID = id(42000 + i)
			kind := uint8(1)
			if i == 256 {
				kind = 2
			}
			r := contract.BindingTableRow{SubjectKind: kind, SubjectID: id(43000 + i), Binding: b}
			q.Bindings = append(q.Bindings, r)
			digest, err := contract.PublicBindingDigest(b)
			if err != nil {
				t.Fatal(err)
			}
			for outcome := uint8(1); outcome <= 4; outcome++ {
				rows = append(rows, contract.KeyUseRow{BindingID: b.BindingID, PublicBindingDigest: digest, SubjectKind: kind, SubjectID: r.SubjectID, Provider: b.Provider, Purpose: contract.KeyUsePublicKeyRead, Outcome: outcome, Count: 1})
			}
			if i == 0 || i == 256 {
				q.Probes = append(q.Probes, contract.InitProbePlanRow{ProbeID: id(44000 + i), SubjectKind: kind, SubjectID: r.SubjectID, BindingID: b.BindingID, PublicBindingDigest: digest})
				for outcome := uint8(1); outcome <= 4; outcome++ {
					rows = append(rows, contract.KeyUseRow{BindingID: b.BindingID, PublicBindingDigest: digest, SubjectKind: kind, SubjectID: r.SubjectID, Provider: b.Provider, Purpose: contract.KeyUsePrivateRoleProbe, Outcome: outcome, Count: 1})
				}
			}
		}
		body, err := contract.EncodeCryptoQualifyInitKeysRequest(q)
		if err != nil {
			t.Fatal("largest initialization request rejected", err)
		}
		request := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoQualifyInitKeys, RequestID: id(45000), CustodyInstanceID: id(45001), Body: body}
		reply := contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: request.Kind, RequestID: request.RequestID, CustodyInstanceID: request.CustodyInstanceID, ResultCode: contract.CryptoPrivateRouteUnavailable, KeyUseRows: rows}
		if len(rows) != 1036 || contract.ValidateCryptoExchange(request, reply) != nil || contract.ValidateInitKeyUseRows(q, rows) != nil {
			t.Fatal("largest initialization exchange lacks checked legal rows")
		}
		c := q.Context
		owner := newOperationObservation(observationSource{DomainID: c.DomainID, AdmissionID: c.AdmissionID, SessionID: c.SessionID, InitID: c.InitID}, true)
		v := exchangeObservation{Source: observationSource{Stage: observationExchange}, RequestID: reply.RequestID, CustodyInstanceID: reply.CustodyInstanceID, Kind: reply.Kind, ResultCode: reply.ResultCode, Rows: rows}
		if !owner.offerExchange(t.Context(), v) {
			t.Fatal("largest checked initialization fact refused")
		}
		facts, status := owner.read()
		if len(facts) != 1 || !reflect.DeepEqual(facts[0].Exchange.Rows, rows) || status.StoredBytes > observationRetainedLimit() || facts[0].Exchange.Source.InitID != c.InitID {
			t.Fatal("largest checked initialization fact lost detail")
		}
	})
	t.Run("accepted representation ceiling", func(t *testing.T) {
		v := changeObservation{Source: observationSource{Stage: observationCandidate}, HasChangedSubjects: true, Subjects: make([]observationSubject, contract.MutationChangedSubjectLimit)}
		for i := range v.Subjects {
			v.Subjects[i] = observationSubject{Row: contract.ChangedSubjectIdentity{Kind: contract.ChangedSubjectSelectedWork, Change: contract.ChangedSubjectRemoved, Identity: observationBoundID(i)}}
		}
		v.Descriptor = contract.GeneratorDescriptor{Count: uint32(len(v.Subjects)), Length: 4 + 38*uint64(len(v.Subjects)), Digest: generatedVectorID(73)}
		observationAssertMaximumFits(t, v)
	})
}

func observationAssertMaximumFits(t testing.TB, v changeObservation) {
	t.Helper()
	owner := observationTestOwner(t)
	if !owner.offerChange(t.Context(), v) {
		t.Fatal("empty collector rejected largest complete projection")
	}
	facts, status := owner.read()
	v.Source = owner.sourceFor(v.Source)
	if len(facts) != 1 || !reflect.DeepEqual(*facts[0].Change, v) || status.Accepted != 1 || status.StoredBytes != observationChangeBytes(v) || status.StoredBytes > observationRetainedLimit() {
		t.Fatal("largest projection changed or lost detail", status)
	}
	c := facts[0].Change
	if cap(c.Subjects) != len(c.Subjects) || cap(c.Entries) != len(c.Entries) || cap(c.Memberships) != len(c.Memberships) || cap(c.Names) != len(c.Names) || cap(c.Generations) != len(c.Generations) {
		t.Fatal("maximum copy retains excess source capacity")
	}
	t.Logf("change stored_bytes=%d memory_budget=%d", status.StoredBytes, observationMemoryBudget())
}

// full_only: false
func TestOperationObservationMemoryAccounting(t *testing.T) {
	// Independent ceiling arithmetic uses the next power of two above an
	// allocation and its 16-byte header, with a minimum 32-byte charge.
	charge := func(n uint64) uint64 {
		if n == 0 {
			return 0
		}
		return max(uint64(32), uint64(1)<<bits.Len64(n+15))
	}
	for _, n := range []uint64{0, 1, 16, 17, 32, 257, 8192, 1 << 20} {
		if observationAllocationBytes(n) != charge(n) {
			t.Fatal("allocator overhead omitted", n)
		}
	}
	record := charge(uint64(unsafe.Sizeof(observationRecord{})))
	change := record + charge(uint64(unsafe.Sizeof(changeObservation{}))) + charge(1024*uint64(unsafe.Sizeof(observationEntry{}))) + charge(8192*uint64(unsafe.Sizeof(observationMembership{}))) + charge(1024*uint64(unsafe.Sizeof(observationName{}))) + charge(16384*uint64(unsafe.Sizeof(observationSubject{}))) + charge(768*uint64(unsafe.Sizeof(observationGeneration{}))) + charge(6*uint64(unsafe.Sizeof(observationSuccession{}))) + charge(uint64(unsafe.Sizeof(observationAdministrative{}))) + 2048*charge(256)
	exchange := record + charge(uint64(unsafe.Sizeof(exchangeObservation{}))) + charge(8224*uint64(unsafe.Sizeof(contract.KeyUseRow{})))
	retained := max(change, exchange)
	pending := charge(uint64(unsafe.Sizeof(changeObservation{}))) + charge(1024*uint64(unsafe.Sizeof(observationEntry{}))) + charge(1024*uint64(unsafe.Sizeof(observationName{}))) + charge(8192*uint64(unsafe.Sizeof(observationMembership{}))) + charge(9472*uint64(unsafe.Sizeof(observationSubject{}))) + charge(768*uint64(unsafe.Sizeof(observationGeneration{}))) + charge(256*uint64(unsafe.Sizeof(observationGeneration{})))
	expected := 2*retained + pending + charge(uint64(unsafe.Sizeof(observationCollector{}))) + charge(uint64(unsafe.Sizeof(operationObservation{})))
	if observationRetainedLimit() != retained || observationMemoryBudget() != expected || observationProjectionLimit() != pending || pending > retained {
		t.Fatal("fixed storage and pending-copy bound differs from independent source ceilings")
	}
	// The record reservation also covers the copied-read outer slice. This keeps
	// an arbitrary accepted record mix within one additional retained budget.
	for _, count := range []uint64{1, 2, 3, 32, 10000} {
		if charge(count*uint64(unsafe.Sizeof(observationFact{}))) > count*record {
			t.Fatal("pending read record capacity omitted")
		}
	}
}
