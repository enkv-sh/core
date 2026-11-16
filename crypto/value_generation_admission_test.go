package crypto

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedAdmissionAcceptsMaximumCurrentRecipients(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		f := generatedRuntimePlanFixture(t, recovery)
		f.reservation.Session.Bindings = slices.Clone(f.reservation.Session.Bindings)
		row := f.reservation.Session.Bindings[applyBindingIndex(f.reservation.Session.Bindings, f.reservation.Session.Control.AuthorityRecipientID)]
		for i := 2; i < contract.CryptoMaxRecipients; i++ {
			row.SubjectID = consumerID("current reader " + strconv.Itoa(i))
			row.Binding.BindingID = consumerID("current reader binding " + strconv.Itoa(i))
			f.reservation.Session.Bindings = append(f.reservation.Session.Bindings, row)
		}
		slices.SortFunc(f.reservation.Session.Bindings, func(a, b contract.BindingTableRow) int {
			if a.SubjectKind != b.SubjectKind {
				return int(a.SubjectKind) - int(b.SubjectKind)
			}
			return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
		})
		r := f.reservationRuntime(t)
		op := generatedCompare(t, r, f)
		generatedPlanParts(t, r, f, op)
		result := generatedFinishPlan(t, r, f, op)
		access, err := contract.DecodeAccessRecord(result.SeedAccess)
		want := 1
		if recovery {
			want++
		}
		if err != nil || len(access.Wraps) != want {
			t.Fatal("maximum readers changed operation seed recipients", recovery, err, len(access.Wraps))
		}
		if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, generatedPlanCandidate(t, f, result)); code != contract.CryptoSuccess {
			t.Fatal("maximum current bindings candidate", recovery, code)
		}
		r.retireGenerated()
	}
}

// full_only: false
func TestGeneratedAdmissionRequiresOneCurrentBindingPerRecipient(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		f := generatedRuntimePlanFixture(t, recovery)
		for _, capacity := range []bool{false, true} {
			t.Run(strconv.FormatBool(recovery)+"/capacity="+strconv.FormatBool(capacity), func(t *testing.T) {
				input := f.reservation
				input.Session.Bindings = slices.Clone(input.Session.Bindings)
				index := slices.IndexFunc(input.Session.Bindings, func(row contract.BindingTableRow) bool {
					return row.SubjectKind == 1 && row.SubjectID != input.Session.Control.AuthorityRecipientID
				})
				if index < 0 {
					t.Fatal("fixture has no ordinary reader")
				}
				row := input.Session.Bindings[index]
				if capacity {
					for i := 0; i < contract.CryptoMaxRecipients; i++ {
						row.SubjectID = consumerID("additional current reader " + strconv.Itoa(i))
						row.Binding.BindingID = consumerID("additional current binding " + strconv.Itoa(i))
						input.Session.Bindings = append(input.Session.Bindings, row)
					}
				} else {
					row.Binding.BindingSerial++
					row.Binding.BindingID = consumerID("second current reader binding")
					input.Session.Bindings = append(input.Session.Bindings, row)
				}
				slices.SortFunc(input.Session.Bindings, func(a, b contract.BindingTableRow) int {
					if a.SubjectKind != b.SubjectKind {
						return int(a.SubjectKind) - int(b.SubjectKind)
					}
					if n := bytes.Compare(a.SubjectID[:], b.SubjectID[:]); n != 0 {
						return n
					}
					if a.Binding.BindingSerial < b.Binding.BindingSerial {
						return -1
					}
					return 1
				})
				if _, err := contract.BindingTableLength(input.Session.Bindings); err != nil {
					t.Fatal("invalid shared binding-table fixture", err)
				}
				r := newConsumerRuntime(t, f.base.route)
				if err := r.admitGeneratedReservation(f.compare, input, f.base.deadline); err == nil || r.slot != nil {
					t.Fatal("historical or excess current bindings admitted", err)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedPlanCacheRequiresExactBodies(t *testing.T) {
	f := generatedRuntimePlanFixture(t, false)
	r := f.reservationRuntime(t)
	first, _, err := r.validateGeneratedPlan(f.graph, f.declaration, false)
	if err != nil {
		t.Fatal("initial generated plan validation", err)
	}
	second, _, err := r.validateGeneratedPlan(f.graph, f.declaration, false)
	if err != nil || second != first {
		t.Fatal("exact generated plan did not reuse validation", err)
	}
	badGraph := bytes.Clone(f.graph)
	badGraph[0] ^= 1
	if plan, _, err := r.validateGeneratedPlan(badGraph, f.declaration, false); err == nil || plan != nil {
		t.Fatal("changed graph reused generated plan validation", err)
	}
	badDeclaration := bytes.Clone(f.declaration)
	badDeclaration[0] ^= 1
	if plan, _, err := r.validateGeneratedPlan(f.graph, badDeclaration, false); err == nil || plan != nil {
		t.Fatal("changed declaration reused generated plan validation", err)
	}
	third, _, err := r.validateGeneratedPlan(f.graph, f.declaration, false)
	if err != nil || third != first {
		t.Fatal("failed changed input displaced exact generated plan", err)
	}
}

// full_only: false
func TestGeneratedUninstalledAdmissionClearsOwnedBuffers(t *testing.T) {
	owned := func(value byte, length int) ([]byte, []byte) {
		backing := bytes.Repeat([]byte{value}, length+7)
		return backing[:length], backing
	}
	seed, seedBacking := owned(1, 32)
	declaration, declarationBacking := owned(2, 24)
	protections, protectionsBacking := owned(3, 24)
	predecessorResult, predecessorResultBacking := owned(4, 24)
	predecessorSeed, predecessorSeedBacking := owned(5, 24)
	predecessorSource, predecessorSourceBacking := owned(6, 24)
	predecessorProgress, predecessorProgressBacking := owned(7, 24)
	intent, intentBacking := owned(8, 24)
	sourceKeys, sourceKeysBacking := owned(9, 24)
	sourceBuffer, sourceBufferBacking := owned(10, 24)
	canonicalBuffer, canonicalBufferBacking := owned(11, 24)
	canonicalWrap, canonicalWrapBacking := owned(12, 24)
	canonicalAccessWrap, canonicalAccessWrapBacking := owned(13, 24)
	producerSource, producerSourceBacking := owned(14, 24)
	producerConsumer, producerConsumerBacking := owned(15, 24)
	producerProgress, producerProgressBacking := owned(16, 24)
	accessWrap, accessWrapBacking := owned(17, 24)
	normalSigning, normalSigningBacking := owned(18, 24)
	authorityBinding, authorityBindingBacking := owned(19, 24)
	recoverySigning, recoverySigningBacking := owned(20, 24)
	recoveryBinding, recoveryBindingBacking := owned(21, 24)
	tableBinding, tableBindingBacking := owned(22, 24)
	state := &generatedProducerPreparationState{
		plan: generatedPlanState{
			declaration: declaration,
			protections: protections,
			sources:     []generatedSource{{keys: sourceKeys, buffer: sourceBuffer}},
			canonicals: []generatedCanonicalSource{{buffer: canonicalBuffer,
				wrap:           contract.WrapRow{RSACiphertext: canonicalWrap},
				selectedAccess: contract.AccessRecord{Wraps: []contract.WrapRow{{RSACiphertext: canonicalAccessWrap}}}}},
			controlledPredecessor: &generatedControlledPredecessor{
				Result:     predecessorResult,
				SeedAccess: predecessorSeed,
				source:     contract.GeneratedDeleteSource{Record: contract.SupportRecord{Body: predecessorSource}},
				progress:   [][]byte{predecessorProgress},
			},
		},
		producer: &generatedProducer{intent: intent, ownerRecord: contract.SupportRecord{Body: producerSource},
			consumers: [][]byte{producerConsumer}, progress: [][]byte{producerProgress}},
	}
	a := &generatedAdmission{seed: seed, purpose: generatedPurposeState{producer: state},
		control: contract.ControlCore{CurrentControl: contract.CurrentControl{
			NormalSigning: contract.PublicSigningBinding{SPKI: normalSigning},
			Recovery: &contract.RecoveryBindings{Signing: contract.PublicSigningBinding{SPKI: recoverySigning},
				KMS: contract.KMSBinding{SPKI: recoveryBinding}}},
			AuthorityKMSBinding: contract.KMSBinding{SPKI: authorityBinding}},
		bindings: []contract.BindingTableRow{{Binding: contract.KMSBinding{SPKI: tableBinding}}},
		access:   contract.AccessRecord{Wraps: []contract.WrapRow{{RSACiphertext: accessWrap}}}}
	r := newConsumerRuntime(t, applyFixture(t, false).route)
	if err := r.installGeneratedAdmission(a, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("invalid admission installed")
	}
	for name, body := range map[string][]byte{
		"seed": seedBacking, "declaration": declarationBacking, "protections": protectionsBacking,
		"predecessor result": predecessorResultBacking, "predecessor seed": predecessorSeedBacking,
		"predecessor source": predecessorSourceBacking, "predecessor progress": predecessorProgressBacking,
		"producer intent": intentBacking,
		"source keys":     sourceKeysBacking, "source buffer": sourceBufferBacking,
		"canonical buffer": canonicalBufferBacking, "canonical wrap": canonicalWrapBacking,
		"canonical selected access wrap": canonicalAccessWrapBacking,
		"producer source":                producerSourceBacking, "producer consumer": producerConsumerBacking, "producer progress": producerProgressBacking,
		"seed access wrap": accessWrapBacking, "normal signing key": normalSigningBacking,
		"authority binding key": authorityBindingBacking, "recovery signing key": recoverySigningBacking,
		"recovery binding key": recoveryBindingBacking, "table binding key": tableBindingBacking,
	} {
		if !bytes.Equal(body, make([]byte, len(body))) {
			t.Errorf("uninstalled admission retained %s", name)
		}
	}
}
