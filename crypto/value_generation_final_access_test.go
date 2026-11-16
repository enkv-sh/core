package crypto

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// This is a phase-stage fixture. It does not establish complete Core admission
// or Runtime binding. Membership selection and preparation use the real private
// helpers; candidateEntriesMatch enters the independent Final access check.
func generatedSurvivingFinalAccessFixture(t *testing.T, kind uint8, recovery bool, source uint8) (*generatedAdmission, generatedCandidate, contract.WrapRow, *consumerTestRoute) {
	t.Helper()
	a, selected, route, _, intent := generatedMembershipStageFixture(t, false, true, false, source)
	t.Cleanup(a.clear)
	s := selected.Selection
	wrapIndex := slices.IndexFunc(s.Access.Wraps, func(w contract.WrapRow) bool {
		return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == a.control.AuthorityRecipientID
	})
	core, err := custody.ValueWrapCore(s.Core, s.Binding)
	if err != nil || wrapIndex < 0 {
		t.Fatal("authority packet fixture", err)
	}
	keys, code := openMaterialPacket(t.Context(), route, s.Binding, core, s.Access.Wraps[wrapIndex], contract.CryptoStoredAuthenticationFailed, &contract.CryptoResponse{})
	if code != contract.CryptoSuccess {
		t.Fatal("open fixture packet", code)
	}
	defer clear(keys[:cap(keys)])
	// A valid binding which neither current membership nor the owner requires.
	// It makes the surplus-wrap case pass the independent binding precheck.
	extraBinding := a.bindings[applyBindingIndex(a.bindings, consumerID("reader"))]
	extraBinding.SubjectID = consumerID("unsupported ordinary reader")
	extraBinding.Binding.BindingID = consumerID("unsupported ordinary binding")
	extraBinding.Binding.BindingIncarnationID = consumerID("unsupported ordinary binding incarnation")
	extraBinding.Binding.KeySelector = "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/extra/cryptoKeyVersions/1"
	a.bindings = append(a.bindings, extraBinding)
	extraCore, err := custody.ValueWrapCore(s.Core, extraBinding)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := custody.Wrap(extraCore, extraBinding.Binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	if recovery {
		f := applyFixture(t, true)
		recoveryBinding := f.q.Bindings[len(f.q.Bindings)-1]
		a.control.Recovery = f.control.Recovery
		a.bindings = append(a.bindings, recoveryBinding)
		recoveryCore, err := custody.ValueWrapCore(s.Core, recoveryBinding)
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := custody.Wrap(recoveryCore, recoveryBinding.Binding, keys)
		if err != nil {
			t.Fatal(err)
		}
		selected.Selection.Access.Wraps = append(slices.Clone(s.Access.Wraps), wrap)
	}
	slices.SortFunc(a.bindings, func(x, y contract.BindingTableRow) int {
		if x.SubjectKind != y.SubjectKind {
			return int(x.SubjectKind) - int(y.SubjectKind)
		}
		return bytes.Compare(x.SubjectID[:], y.SubjectID[:])
	})
	a.bindingDigests = nil
	for _, binding := range a.bindings {
		digest, err := contract.PublicBindingDigest(binding.Binding)
		if err != nil {
			t.Fatal(err)
		}
		a.bindingDigests = append(a.bindingDigests, digest)
	}
	for _, row := range a.purpose.final.membership {
		for _, wrap := range row.Selection.Access.Wraps {
			clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
		}
	}
	a.purpose.final.membership = nil
	if !a.admitMembership([]generatedMembershipSelection{selected}, []contract.GeneratedCurrentIntentSelection{intent}) {
		t.Fatal("complete stage selection refused")
	}
	entry, body, code := a.prepareMembership(t.Context(), route, 0, &contract.CryptoResponse{})
	if code != contract.CryptoSuccess {
		t.Fatal("prepare membership", code)
	}
	access, err := contract.DecodeAccessRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contract.PublicValueEntryDigest(a.request.Context.DomainID, s.Slot, entry)
	if err != nil {
		t.Fatal(err)
	}
	prepared := generatedSuppliedPreparation{plan: 0, identity: contract.IdentityRow{Name: entry.Name, Slot: s.Slot, ValueState: entry.ValueState},
		entryDigest: digest, access: contract.DigestLength{Digest: contract.Hash(body), Length: uint64(len(body))}, prepared: true}
	a.purpose.final.supplied = []generatedSuppliedPreparation{prepared}
	a.purpose.final.suppliedCount, a.purpose.final.suppliedNext, a.purpose.final.suppliedFinal = 1, 1, true
	c := generatedCandidate{Subject: contract.GeneratorAuthoritySubject{Purpose: contract.GeneratorAuthorityFinal, DomainID: a.request.Context.DomainID},
		PublicState: contract.PublicState{Domain: a.request.Context.DomainID, Rows: []contract.PublicStateRow{{Name: entry.Name, Slot: s.Slot, EntryDigest: digest}}},
		Entries:     []generatedCandidateEntry{{Slot: s.Slot, Entry: entry}}, AccessRecords: []contract.AccessRecord{selected.Selection.Access, access}}
	owner, _ := generatedCanonicalFixture(t, kind)
	consumer := contract.GeneratorConsumer{Schema: 1, OwnerID: owner.Owner.RecordID, MaterialID: s.Entry.ValueState,
		ContextDigest: s.Access.MaterialContextDigest, SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue,
		SubjectID: s.Entry.ValueState, Purpose: contract.GeneratorConsumerUseRetainedCanonical}
	canonical := a.purpose.output.Retained[0]
	generatedFinalAccessOwner(t, &c, canonical, owner, consumer)
	originalBody, err := contract.EncodeAccessRecord(selected.Selection.Access)
	if err != nil {
		t.Fatal(err)
	}
	a.purpose.final.plan.canonicals = []generatedCanonicalSource{{originalSlot: s.Slot, body: contract.Hash(canonical.Body),
		entryDigest: s.EntryDigest, core: s.Core, recipients: slices.Clone(s.Entry.Recipients), selectedAccess: selected.Selection.Access,
		access: contract.DigestLength{Digest: contract.Hash(originalBody), Length: uint64(len(originalBody))},
		wrap:   selected.Selection.Access.Wraps[wrapIndex], buffer: bytes.Clone(canonical.Body)}}
	return a, c, extra, route
}

func generatedFinalAccessOwner(t *testing.T, c *generatedCandidate, retained contract.SupportRecord, owner generatedCanonicalSelection, consumer contract.GeneratorConsumer) {
	t.Helper()
	body, err := contract.EncodeGeneratorConsumer(consumer)
	if err != nil {
		t.Fatal(err)
	}
	generatedCanonicalConsumers(t, &owner, [][]byte{body})
	c.SupportRecords = append([]contract.SupportRecord{retained, owner.Owner}, generatedVectorSupport(t, c.Subject.DomainID,
		owner.Owner.Kind, owner.Owner.RecordID, contract.GeneratorVectorConsumers, owner.Consumers)...)
}

// full_only: false
func TestGeneratedFinalAccessChecksSurvivingCanonicalProjection(t *testing.T) {
	for _, kind := range []uint8{contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("owner_%d/recovery_%v", kind, recovery), func(t *testing.T) {
				a, healthy, extra, _ := generatedSurvivingFinalAccessFixture(t, kind, recovery, contract.Generated)
				value := a.purpose.final.membership[0].Selection.Entry.ValueState
				retainedReader := consumerID("reader")
				if slices.Contains(healthy.Entries[0].Entry.Recipients, retainedReader) {
					t.Fatal("fixture reader is not retained-only")
				}
				// Membership and the literal retained record require these two
				// readers; no production reader-union function derives this oracle.
				wantReaders := []contract.ID{a.control.AuthorityRecipientID, retainedReader}
				slices.SortFunc(wantReaders, func(x, y contract.ID) int { return bytes.Compare(x[:], y[:]) })
				if got, ok := a.finalRetainedReaders(healthy, value); !ok || !slices.Equal(got, wantReaders) {
					t.Fatal("healthy owner and typed consumer did not establish exact readers")
				}
				if !a.candidateEntriesMatch(healthy) || !a.candidateCanonicalsMatch(healthy) {
					t.Fatal("healthy Final projection refused")
				}
				damages := []string{"missing retained wrap", "changed retained wrap", "wrong consumer context", "unsupported extra wrap"}
				if recovery {
					damages = append(damages, "changed Recovery wrap")
				}
				for _, damage := range damages {
					t.Run(damage, func(t *testing.T) {
						bad := healthy
						bad.AccessRecords = slices.Clone(healthy.AccessRecords)
						bad.AccessRecords[0].Wraps = slices.Clone(healthy.AccessRecords[0].Wraps)
						wraps := &bad.AccessRecords[0].Wraps
						i := slices.IndexFunc(*wraps, func(w contract.WrapRow) bool {
							return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == retainedReader
						})
						if i < 0 {
							t.Fatal("missing retained-only fixture wrap")
						}
						switch damage {
						case "missing retained wrap":
							*wraps = slices.Delete(*wraps, i, i+1)
						case "changed retained wrap", "changed Recovery wrap":
							if damage == "changed Recovery wrap" {
								i = slices.IndexFunc(*wraps, func(w contract.WrapRow) bool { return w.SubjectKind == contract.RecoveryWrapSubject })
								if i < 0 {
									t.Fatal("missing fixture Recovery wrap")
								}
							}
							(*wraps)[i].RSACiphertext = bytes.Clone((*wraps)[i].RSACiphertext)
							(*wraps)[i].RSACiphertext[0] ^= 1
						case "unsupported extra wrap":
							*wraps = append(*wraps, extra)
							slices.SortFunc(*wraps, func(x, y contract.WrapRow) int {
								if x.SubjectKind != y.SubjectKind {
									return int(x.SubjectKind) - int(y.SubjectKind)
								}
								return bytes.Compare(x.SubjectID[:], y.SubjectID[:])
							})
						case "wrong consumer context":
							owner, _ := generatedCanonicalFixture(t, kind)
							consumer := contract.GeneratorConsumer{Schema: 1, OwnerID: owner.Owner.RecordID, MaterialID: value,
								ContextDigest: consumerID("wrong retained consumer context"), SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue,
								SubjectID: value, Purpose: contract.GeneratorConsumerUseRetainedCanonical}
							generatedFinalAccessOwner(t, &bad, healthy.SupportRecords[0], owner, consumer)
						}
						if !a.accessBindingsValid(bad.AccessRecords[0]) {
							t.Fatal("damage failed structural/binding admission before Final relation")
						}
						index, ok := generatedCandidateCarrierIndex(bad.SupportRecords)
						if !ok {
							t.Fatal("damage invalidated carrier encoding")
						}
						if rows, ok := generatedCandidateConsumers(index, len(bad.SupportRecords), bad.SupportRecords[1], bad.Subject.DomainID); !ok || len(rows) != 1 {
							t.Fatal("damage invalidated typed consumer authentication")
						}
						if a.candidateCanonicalsMatch(bad) {
							t.Fatal("Final accepted damaged surviving access", damage)
						}
						if !a.candidateEntriesMatch(healthy) || !a.candidateCanonicalsMatch(healthy) {
							t.Fatal("damage changed the healthy control")
						}
					})
				}
			})
		}
	}
}
