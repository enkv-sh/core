package crypto

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func generatedCanonicalAccessCaller(t *testing.T, selected contract.ConsumerSelection) contract.ConsumerSelection {
	t.Helper()
	entry, err := contract.EncodeValueEntry(selected.Entry)
	if err != nil {
		t.Fatal(err)
	}
	selected.Entry, err = contract.DecodeValueEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := contract.InspectCanonicalPayload(selected.Entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	selected.Payload = contract.CanonicalPayload(payload)
	access, err := contract.EncodeAccessRecord(selected.Access)
	if err != nil {
		t.Fatal(err)
	}
	selected.Access, err = contract.DecodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	selected.Binding.Binding.SPKI = bytes.Clone(selected.Binding.Binding.SPKI)
	return selected
}

// full_only: false
func TestGeneratedFinalCanonicalAccessGroupsSourcesOnlyForIdenticalMaterial(t *testing.T) {
	for _, variant := range []string{"same material", "different payload", "different core"} {
		t.Run(variant, func(t *testing.T) {
			a, healthy, _, _ := generatedSurvivingFinalAccessFixture(t, contract.GeneratedHazardSupportKind, true, contract.Supplied)
			selected := generatedCanonicalAccessCaller(t, a.purpose.final.membership[0].Selection)
			second := generatedCanonicalAccessCaller(t, selected)
			second.Entry.Recipients = []contract.ID{a.control.AuthorityRecipientID}
			switch variant {
			case "different payload":
				second.Entry.ValueBytes[len(second.Entry.ValueBytes)-1] ^= 1
			case "different core":
				second.Entry.OriginSnapshot = consumerID("conflicting old snapshot")
			}
			record := contract.RetainedCanonicalRecord{OriginalSlot: second.Slot, Entry: second.Entry}
			body, err := contract.EncodeRetainedCanonicalRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			id, err := contract.AdmissionEntryDigest(record)
			if err != nil {
				t.Fatal(err)
			}
			row := contract.SupportRecord{Kind: contract.RetainedCanonicalSupportKind, RecordID: id, Body: body}
			fact, err := contract.InspectSupportRecordDigest(selected.DomainID, row)
			if err != nil {
				t.Fatal(err)
			}
			output := a.purpose.output
			output.Retained = append(output.Retained, row)
			slices.SortFunc(output.Retained, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
			output.Rows.Facts = append(output.Rows.Facts, fact)
			slices.SortFunc(output.Rows.Facts, func(a, b contract.SupportRecordDigest) int {
				if a.Kind() != b.Kind() {
					return int(a.Kind()) - int(b.Kind())
				}
				x, y := a.RecordID(), b.RecordID()
				return bytes.Compare(x[:], y[:])
			})
			a.before.RequiredSupport, err = contract.RequiredSupportDescriptorFromDigests(selected.DomainID, output.Rows.Facts)
			if err != nil || !output.RetainedCanonicalsValid() {
				t.Fatal("complete two-source predecessor census", err)
			}
			admitted := a.admitFinalCanonicalAccess([]contract.ConsumerSelection{selected})
			if admitted != (variant == "same material") || admitted && len(a.purpose.final.canonicalAccess) != 1 {
				t.Fatal("source identity was confused with shared material access", admitted)
			}
			if !admitted {
				return
			}
			// Access-boundary evidence only: one source ended, while a real
			// typed consumer of the narrower second source still needs V1.
			// Keep the declared source present and enter nonselecting policy;
			// the connected failed-Final test owns the complete Final route.
			owner, _ := generatedCanonicalFixture(t, contract.GeneratedDutySupportKind)
			surviving := healthy
			generatedFinalAccessOwner(t, &surviving, row, owner, contract.GeneratorConsumer{Schema: 1,
				OwnerID: owner.Owner.RecordID, MaterialID: selected.Core.ValueStateID, ContextDigest: selected.Access.MaterialContextDigest,
				SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue, SubjectID: id, Purpose: contract.GeneratorConsumerUseRetainedCanonical})
			surviving.AccessRecords = slices.Clone(healthy.AccessRecords)
			surviving.AccessRecords[0].Wraps = slices.DeleteFunc(slices.Clone(selected.Access.Wraps), func(w contract.WrapRow) bool {
				return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == consumerID("reader")
			})
			a.purpose.final.nonselecting = true
			if !a.candidateCanonicalsMatch(surviving) {
				t.Fatal("pinned nonselecting access refused justified ended-only reader removal")
			}
			packet := &surviving.AccessRecords[0].Wraps[0].RSACiphertext
			*packet = bytes.Clone(*packet)
			(*packet)[0] ^= 1
			if a.candidateCanonicalsMatch(surviving) {
				t.Fatal("pinned nonselecting access accepted a changed required wrap")
			}
		})
	}
}

// full_only: false
func TestGeneratedFinalCanonicalAccessRequiresCompletePredecessorPins(t *testing.T) {
	for _, damage := range []string{"exact", "missing", "extra", "duplicate", "HEAD", "root", "snapshot", "access root", "condition", "entry", "package", "context", "current binding", "conflicting RSA packet", "conflicting admitted membership packet", "conflicting admitted canonical packet", "conflicting admitted current packet", "unadmitted canonical access", "digest-only canonical exact", "digest-only canonical mismatch", "missing reader", "missing Recovery"} {
		t.Run(damage, func(t *testing.T) {
			a, _, _, route := generatedSurvivingFinalAccessFixture(t, contract.GeneratedHazardSupportKind, true, contract.Supplied)
			selected := generatedCanonicalAccessCaller(t, a.purpose.final.membership[0].Selection)
			input := []contract.ConsumerSelection{selected}
			switch damage {
			case "missing":
				input = nil
			case "extra":
				unknown := selected
				unknown.Core.ValueStateID = consumerID("unselected old material")
				input = append(input, unknown)
			case "duplicate":
				input = append(input, selected)
			case "HEAD":
				input[0].HEADDigest[0] ^= 1
			case "root":
				input[0].Root.Digest[0] ^= 1
			case "snapshot":
				input[0].SnapshotID[0] ^= 1
			case "access root":
				input[0].AccessRoot[0] ^= 1
			case "condition":
				input[0].HEADToken.Value = "2"
			case "entry":
				input[0].EntryDigest[0] ^= 1
			case "package":
				input[0].Access.PackageCheck[0] ^= 1
			case "context":
				input[0].Access.MaterialContextDigest[0] ^= 1
			case "current binding":
				input[0].Access.Wraps[0].BindingSerial++
			case "conflicting RSA packet":
				input[0].Access.Wraps[0].RSACiphertext[0] ^= 1
			case "conflicting admitted membership packet":
				a.purpose.final.membership[0].Selection.Access.Wraps[0].RSACiphertext[0] ^= 1
			case "conflicting admitted canonical packet":
				a.purpose.final.plan.canonicals[0].selectedAccess.Wraps[0].RSACiphertext[0] ^= 1
			case "conflicting admitted current packet":
				current := generatedCanonicalAccessCaller(t, selected)
				current.Access.Wraps[0].RSACiphertext[0] ^= 1
				a.purpose.final.plan.currentValues = []contract.ConsumerSelection{current}
			case "unadmitted canonical access", "digest-only canonical exact", "digest-only canonical mismatch":
				source := &a.purpose.final.plan.canonicals[0]
				original, originalDigest := source.selectedAccess, source.access
				source.selectedAccess = contract.AccessRecord{}
				switch damage {
				case "unadmitted canonical access":
					source.access = contract.DigestLength{}
				case "digest-only canonical mismatch":
					source.access.Digest[0] ^= 1
				}
				defer func() { source.selectedAccess, source.access = original, originalDigest }()
			case "missing reader":
				at := slices.IndexFunc(input[0].Access.Wraps, func(w contract.WrapRow) bool { return w.SubjectID == consumerID("reader") })
				if at < 0 {
					t.Fatal("reader fixture")
				}
				input[0].Access.Wraps = slices.Delete(input[0].Access.Wraps, at, at+1)
			case "missing Recovery":
				input[0].Access.Wraps = input[0].Access.Wraps[:len(input[0].Access.Wraps)-1]
			}
			public, private := route.publicCalls, route.privateCalls
			admitted := a.admitFinalCanonicalAccess(input)
			want := damage == "exact" || damage == "unadmitted canonical access" || damage == "digest-only canonical exact"
			if admitted != want || !admitted && len(a.purpose.final.canonicalAccess) != 0 {
				t.Fatal("canonical access admission did not require the exact predecessor census", admitted)
			}
			if route.publicCalls != public || route.privateCalls != private {
				t.Fatal("canonical access comparison performed key work")
			}
		})
	}
	for _, mode := range []string{"exact", "same-count duplicate"} {
		t.Run("two-material/"+mode, func(t *testing.T) {
			// Admission-boundary fixture: two independently sealed materials
			// share one predecessor observation. Connected tests own publication.
			a, carriers, _, route := generatedSuppliedCollectionFixture(t, 2)
			t.Cleanup(a.clear)
			var input []contract.ConsumerSelection
			output := a.purpose.output
			for _, carrier := range carriers {
				selected := carrier.Selection
				record := contract.RetainedCanonicalRecord{OriginalSlot: selected.Slot, Entry: selected.Entry}
				body, err := contract.EncodeRetainedCanonicalRecord(record)
				if err != nil {
					t.Fatal(err)
				}
				id, err := contract.AdmissionEntryDigest(record)
				if err != nil {
					t.Fatal(err)
				}
				row := contract.SupportRecord{Kind: contract.RetainedCanonicalSupportKind, RecordID: id, Body: body}
				fact, err := contract.InspectSupportRecordDigest(selected.DomainID, row)
				if err != nil {
					t.Fatal(err)
				}
				output.Retained = append(output.Retained, row)
				output.Rows.Facts = append(output.Rows.Facts, fact)
				input = append(input, selected)
			}
			slices.SortFunc(output.Retained, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
			slices.SortFunc(output.Rows.Facts, func(a, b contract.SupportRecordDigest) int {
				if a.Kind() != b.Kind() {
					return int(a.Kind()) - int(b.Kind())
				}
				x, y := a.RecordID(), b.RecordID()
				return bytes.Compare(x[:], y[:])
			})
			var err error
			a.before.RequiredSupport, err = contract.RequiredSupportDescriptorFromDigests(a.before.Domain, output.Rows.Facts)
			if err != nil {
				t.Fatal(err)
			}
			if err := output.Inspect(a.before); err != nil {
				t.Fatal("invalid two-material predecessor witness", err)
			}
			if len(output.Retained) != 2 || len(input) != 2 || input[0].Core.ValueStateID == input[1].Core.ValueStateID {
				t.Fatal("fixture requires a complete census of two distinct valid materials")
			}
			slices.SortFunc(input, func(a, b contract.ConsumerSelection) int {
				return bytes.Compare(a.Core.ValueStateID[:], b.Core.ValueStateID[:])
			})
			if mode == "same-count duplicate" {
				input[1] = input[0]
			}
			public, private := route.publicCalls, route.privateCalls
			admitted := a.admitFinalCanonicalAccess(input)
			if admitted != (mode == "exact") || admitted && len(a.purpose.final.canonicalAccess) != 2 || !admitted && len(a.purpose.final.canonicalAccess) != 0 {
				t.Fatal("same-count duplicate traded away another required material", admitted)
			}
			if route.publicCalls != public || route.privateCalls != private {
				t.Fatal("two-material census comparison performed key work")
			}
		})
	}
}

// full_only: false
func TestGeneratedFinalCanonicalAccessOwnsPacketsUntilSessionDisposal(t *testing.T) {
	for _, exit := range []string{"retire", "cancel", "failed installation"} {
		t.Run(exit, func(t *testing.T) {
			a, _, _, route := generatedSurvivingFinalAccessFixture(t, contract.GeneratedHazardSupportKind, true, contract.Supplied)
			caller := generatedCanonicalAccessCaller(t, a.purpose.final.membership[0].Selection)
			if !a.admitFinalCanonicalAccess([]contract.ConsumerSelection{caller}) {
				t.Fatal("exact canonical access refused")
			}
			state := a.purpose.final
			pin := &state.canonicalAccess[0]
			before, err := contract.EncodeAccessRecord(pin.access)
			if err != nil {
				t.Fatal(err)
			}
			caller.Access.Wraps[0].BindingSerial++
			caller.Access.Wraps[0].RSACiphertext[0] ^= 1
			after, err := contract.EncodeAccessRecord(pin.access)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("caller changed the privately owned nested access packets")
			}
			callerPacket := bytes.Clone(caller.Access.Wraps[0].RSACiphertext)
			var owned [][]byte
			for i := range pin.access.Wraps {
				wrap := &pin.access.Wraps[i]
				// Give the owned packet a nonzero capacity tail, as a private
				// allocator may do. Disposal must clear that exclusive owner too.
				backing := bytes.Repeat([]byte{0xa7}, len(wrap.RSACiphertext)+7)
				copy(backing, wrap.RSACiphertext)
				clear(wrap.RSACiphertext[:cap(wrap.RSACiphertext)])
				wrap.RSACiphertext = backing[:len(wrap.RSACiphertext)]
				owned = append(owned, backing)
			}
			r := newConsumerRuntime(t, route)
			a.request.Purpose = contract.CryptoGeneratedFinalPreparationPurpose
			if exit == "failed installation" {
				a.routeID = consumerID("unregistered old access route")
				if err := r.installGeneratedAdmission(a, time.Now().Add(time.Minute)); err == nil {
					t.Fatal("invalid route installed")
				}
			} else {
				if err := r.installGeneratedAdmission(a, time.Now().Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
				if exit == "cancel" {
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					if code := r.bindGeneratedCandidate(ctx, a.id, generatedCandidate{}); code != contract.CryptoCancelled {
						t.Fatal("cancelled pin owner did not refuse before candidate use", code)
					}
				}
				r.retireGenerated()
			}
			for _, backing := range owned {
				if !bytes.Equal(backing, make([]byte, len(backing))) {
					t.Fatal("disposed canonical access retained owned packet capacity")
				}
			}
			if len(state.canonicalAccess) != 0 || !bytes.Equal(caller.Access.Wraps[0].RSACiphertext, callerPacket) {
				t.Fatal("disposal retained pins or cleared caller packet bytes")
			}
		})
	}
}

// full_only: false
func TestGeneratedFinalCanonicalAccessCoversUndeclaredOldMaterial(t *testing.T) {
	a, healthy, extra, _ := generatedSurvivingFinalAccessFixture(t, contract.GeneratedHazardSupportKind, true, contract.Supplied)
	selected := generatedCanonicalAccessCaller(t, a.purpose.final.membership[0].Selection)
	if !a.admitFinalCanonicalAccess([]contract.ConsumerSelection{selected}) {
		t.Fatal("exact predecessor access refused")
	}
	// Current preparation has distinct protection. The surviving old source is
	// deliberately absent from the active source plan; its pin must still apply.
	declared := a.purpose.final.plan.canonicals
	a.purpose.final.plan.canonicals = nil
	defer func() { a.purpose.final.plan.canonicals = declared }()
	if healthy.Entries[0].Entry.ValueState == selected.Core.ValueStateID || !a.candidateCanonicalsMatch(healthy) {
		t.Fatal("distinct current and undeclared old source control refused")
	}
	for _, damage := range []string{"missing row", "missing reader", "changed reader", "changed Recovery", "extra reader"} {
		t.Run(damage, func(t *testing.T) {
			bad := healthy
			bad.AccessRecords = slices.Clone(healthy.AccessRecords)
			body, err := contract.EncodeAccessRecord(bad.AccessRecords[0])
			if err != nil {
				t.Fatal(err)
			}
			bad.AccessRecords[0], err = contract.DecodeAccessRecord(body)
			if err != nil {
				t.Fatal(err)
			}
			wraps := &bad.AccessRecords[0].Wraps
			at := slices.IndexFunc(*wraps, func(w contract.WrapRow) bool { return w.SubjectID == consumerID("reader") })
			switch damage {
			case "missing row":
				bad.AccessRecords = bad.AccessRecords[1:]
			case "missing reader":
				*wraps = slices.Delete(*wraps, at, at+1)
			case "changed reader":
				(*wraps)[at].RSACiphertext[0] ^= 1
			case "changed Recovery":
				(*wraps)[len(*wraps)-1].RSACiphertext[0] ^= 1
			case "extra reader":
				*wraps = append(*wraps, extra)
			}
			if a.candidateCanonicalsMatch(bad) {
				t.Fatal("undeclared surviving old material accepted damaged access")
			}
		})
	}
	ended := healthy
	ended.SupportRecords = nil
	ended.AccessRecords = healthy.AccessRecords[1:]
	if !a.candidateCanonicalsMatch(ended) {
		t.Fatal("last owner ending did not release old access")
	}
	ended.AccessRecords = healthy.AccessRecords
	if a.candidateCanonicalsMatch(ended) {
		t.Fatal("last owner ending retained orphan old access")
	}
}
