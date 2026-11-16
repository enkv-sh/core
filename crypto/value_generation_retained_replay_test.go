package crypto

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// This fixture enters the private saved-supplied stage after image association.
// The historical component test owns authenticated selection and OS restart.
func generatedRetainedReplayFixture(t *testing.T, kind uint8, recovery, addition bool) (*generatedAdmission, generatedCandidate, contract.WrapRow, *consumerTestRoute) {
	t.Helper()
	a, candidate, extra, route := generatedSurvivingFinalAccessFixture(t, kind, recovery, contract.Supplied)
	final := a.purpose.final
	plan := &a.graph.ValueEntryPlans[0]
	if addition {
		intended := append(slices.Clone(final.plan.recipients[0]), extra.SubjectID)
		slices.SortFunc(intended, func(x, y contract.ID) int { return bytes.Compare(x[:], y[:]) })
		final.plan.recipients[0] = intended
		var err error
		plan.IntendedMembership, err = contract.GeneratorIntendedMembershipDescriptor(intended)
		if err != nil {
			t.Fatal("added current membership", err)
		}
		entry, body, code := a.prepareMembership(t.Context(), route, 0, &contract.CryptoResponse{})
		if code != contract.CryptoSuccess {
			t.Fatal("mixed membership exclusion preparation", code)
		}
		access, err := contract.DecodeAccessRecord(body)
		if err != nil {
			t.Fatal(err)
		}
		candidate.Entries[0].Entry, candidate.AccessRecords[1] = entry, access
		candidate.PublicState.Rows[0].EntryDigest, err = contract.PublicValueEntryDigest(candidate.Subject.DomainID, plan.Slot, entry)
		if err != nil {
			t.Fatal("mixed current entry", err)
		}
	}
	plan.ChangeMask = contract.GeneratorValueChangeContent | contract.GeneratorValueChangeMembership
	canonical := candidate.SupportRecords[0]
	if canonical.Kind != contract.RetainedCanonicalSupportKind {
		t.Fatal("fixture canonical row")
	}
	var err error
	final.plan.declaration, err = contract.EncodeGeneratorDeclaration(contract.GeneratorDeclaration{Schema: 1,
		DomainID: a.request.Context.DomainID, OperationID: a.graph.Header.OperationID,
		Entries: []contract.GeneratorDeclarationEntry{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
			Name: plan.Name, Recipients: final.plan.recipients[0], Payload: canonical.Body}}})
	if err != nil {
		t.Fatal(err)
	}
	saved := candidate.AccessRecords[1]
	saved.Wraps = slices.DeleteFunc(slices.Clone(saved.Wraps), func(w contract.WrapRow) bool {
		return w.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(final.plan.recipients[0], w.SubjectID)
	})
	body, err := contract.EncodeAccessRecord(saved)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := contract.EncodeValueEntry(candidate.Entries[0].Entry)
	if err != nil {
		t.Fatal(err)
	}
	final.preparedImage = &contract.GeneratedFinalPreparationImage{Supplied: []contract.CryptoPreparedSecret{{Slot: plan.Slot, Name: plan.Name, EntryBytes: entry, AccessRecord: body}}}
	final.supplied, final.suppliedNext, final.suppliedFinal = nil, 0, false
	return a, candidate, extra, route
}

// full_only: false
func TestGeneratedRetainedContentReplayPreservesExactFinalAccess(t *testing.T) {
	for _, kind := range []uint8{contract.GeneratedDutySupportKind, contract.GeneratedHazardSupportKind} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("owner_%d/recovery_%v", kind, recovery), func(t *testing.T) {
				a, healthy, extra, route := generatedRetainedReplayFixture(t, kind, recovery, false)
				saved := bytes.Clone(a.purpose.final.preparedImage.Supplied[0].AccessRecord)
				if code := a.openPreparedSupplied(t.Context(), route, &contract.CryptoResponse{}); code != contract.CryptoSuccess {
					t.Fatal("exact current-only saved access refused", code)
				}
				a.purpose.final.suppliedNext, a.purpose.final.suppliedFinal = 1, true
				if !a.candidateEntriesMatch(healthy) || !a.candidateCanonicalsMatch(healthy) {
					t.Fatal("fresh current and exact old access were not preserved")
				}
				for _, damage := range []string{"missing retained wrap", "changed retained wrap", "changed saved wrap", "extra wrap", "wrong context", "wrong package", "wrong binding"} {
					t.Run(damage, func(t *testing.T) {
						bad := healthy
						bad.AccessRecords = slices.Clone(healthy.AccessRecords)
						at := 0
						if damage == "changed saved wrap" {
							at = 1
						}
						row := &bad.AccessRecords[at]
						row.Wraps = slices.Clone(row.Wraps)
						subject := consumerID("reader")
						if damage == "changed saved wrap" {
							subject = a.control.AuthorityRecipientID
						}
						index := slices.IndexFunc(row.Wraps, func(w contract.WrapRow) bool { return w.SubjectID == subject })
						if index < 0 {
							t.Fatal("fixture missing retained-only reader")
						}
						switch damage {
						case "missing retained wrap":
							row.Wraps = slices.Delete(row.Wraps, index, index+1)
						case "changed retained wrap", "changed saved wrap":
							if damage == "changed saved wrap" {
								index = slices.IndexFunc(row.Wraps, func(w contract.WrapRow) bool { return w.SubjectID == a.control.AuthorityRecipientID })
							}
							row.Wraps[index].RSACiphertext = bytes.Clone(row.Wraps[index].RSACiphertext)
							row.Wraps[index].RSACiphertext[0] ^= 1
						case "extra wrap":
							row.Wraps = append(row.Wraps, extra)
						case "wrong context":
							row.MaterialContextDigest[0] ^= 1
						case "wrong package":
							row.PackageCheck[0] ^= 1
						case "wrong binding":
							row.Wraps[index].BindingSerial++
						}
						slices.SortFunc(row.Wraps, func(x, y contract.WrapRow) int {
							if x.SubjectKind != y.SubjectKind {
								return int(x.SubjectKind) - int(y.SubjectKind)
							}
							return bytes.Compare(x.SubjectID[:], y.SubjectID[:])
						})
						if damage == "changed saved wrap" {
							if a.candidateEntriesMatch(bad) {
								t.Fatal("changed current preparation access accepted")
							}
						} else if a.candidateCanonicalsMatch(bad) {
							t.Fatal("changed old material access accepted")
						}
					})
				}
				if recovery {
					bad := healthy
					bad.AccessRecords = slices.Clone(healthy.AccessRecords)
					bad.AccessRecords[1].Wraps = slices.Clone(healthy.AccessRecords[1].Wraps)
					i := len(bad.AccessRecords[1].Wraps) - 1
					bad.AccessRecords[1].Wraps[i].RSACiphertext = bytes.Clone(bad.AccessRecords[1].Wraps[i].RSACiphertext)
					bad.AccessRecords[1].Wraps[i].RSACiphertext[0] ^= 1
					if a.candidateEntriesMatch(bad) {
						t.Fatal("changed saved Recovery wrap accepted")
					}
				}
				ended := healthy
				ended.SupportRecords = nil
				ended.AccessRecords = slices.Clone(healthy.AccessRecords[1:])
				if !a.candidateEntriesMatch(ended) || !a.candidateCanonicalsMatch(ended) {
					t.Fatal("last owner removal retained an obsolete old-material requirement")
				}
				ended.AccessRecords = healthy.AccessRecords
				if a.candidateCanonicalsMatch(ended) {
					t.Fatal("ended owner's old access accepted")
				}
				if !bytes.Equal(saved, a.purpose.final.preparedImage.Supplied[0].AccessRecord) {
					t.Fatal("Final validation changed immutable saved access")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedRetainedContentReplayRejectsIncompleteSavedAccess(t *testing.T) {
	for _, damage := range []string{"fresh current control", "old material substitution", "missing current", "missing Recovery", "extra reader", "changed ciphertext", "wrong context", "wrong package", "wrong binding", "membership only", "old reader added to current"} {
		t.Run(damage, func(t *testing.T) {
			a, healthy, extra, route := generatedRetainedReplayFixture(t, contract.GeneratedHazardSupportKind, true, false)
			final := a.purpose.final
			row, err := contract.DecodeAccessRecord(final.preparedImage.Supplied[0].AccessRecord)
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "fresh current control":
				row = healthy.AccessRecords[1]
			case "old material substitution":
				row = healthy.AccessRecords[0]
			case "missing current":
				row.Wraps[0] = extra
			case "missing Recovery":
				row.Wraps = row.Wraps[:len(row.Wraps)-1]
			case "extra reader":
				row.Wraps = append(row.Wraps, extra)
			case "changed ciphertext":
				row.Wraps[0].RSACiphertext[0] ^= 1
			case "wrong context":
				row.MaterialContextDigest[0] ^= 1
			case "wrong package":
				row.PackageCheck[0] ^= 1
			case "wrong binding":
				row.Wraps[0].BindingSerial++
			case "membership only":
				a.graph.ValueEntryPlans[0].ChangeMask = contract.GeneratorValueChangeMembership
			case "old reader added to current":
				old := healthy.AccessRecords[0]
				at := slices.IndexFunc(old.Wraps, func(w contract.WrapRow) bool { return w.SubjectID == consumerID("reader") })
				if at < 0 {
					t.Fatal("missing old-only reader wrap")
				}
				row.Wraps = append(slices.Clone(row.Wraps), old.Wraps[at])
			}
			slices.SortFunc(row.Wraps, func(x, y contract.WrapRow) int {
				if x.SubjectKind != y.SubjectKind {
					return int(x.SubjectKind) - int(y.SubjectKind)
				}
				return bytes.Compare(x.SubjectID[:], y.SubjectID[:])
			})
			final.preparedImage.Supplied[0].AccessRecord, err = contract.EncodeAccessRecord(row)
			if err != nil {
				t.Fatal("encoded boundary fixture", err)
			}
			code := a.openPreparedSupplied(t.Context(), route, &contract.CryptoResponse{})
			if damage == "fresh current control" || damage == "membership only" {
				final.suppliedNext, final.suppliedFinal = 1, true
				if code != contract.CryptoSuccess || !a.candidateEntriesMatch(healthy) || !a.candidateCanonicalsMatch(healthy) {
					t.Fatal("complete saved preparation refused", code)
				}
			} else {
				want := contract.CryptoInvalidAdmission
				if damage == "changed ciphertext" {
					want = contract.CryptoStoredAuthenticationFailed
				}
				if code != want || len(final.supplied) != 0 {
					t.Fatal("invalid saved access did not refuse at its required boundary", code, want)
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedRetainedContentReplayKeepsNewReaderAndSurvivingOldReader(t *testing.T) {
	a, healthy, added, route := generatedRetainedReplayFixture(t, contract.GeneratedHazardSupportKind, true, true)
	if code := a.openPreparedSupplied(t.Context(), route, &contract.CryptoResponse{}); code != contract.CryptoSuccess {
		t.Fatal("saved addition/removal relation refused", code)
	}
	a.purpose.final.suppliedNext, a.purpose.final.suppliedFinal = 1, true
	if !a.candidateEntriesMatch(healthy) || !a.candidateCanonicalsMatch(healthy) {
		t.Fatal("Final did not preserve new and surviving old readers")
	}
	bad := healthy
	bad.AccessRecords = slices.Clone(healthy.AccessRecords)
	bad.AccessRecords[1].Wraps = slices.Clone(healthy.AccessRecords[1].Wraps)
	i := slices.IndexFunc(bad.AccessRecords[1].Wraps, func(w contract.WrapRow) bool { return w.SubjectID == added.SubjectID })
	if i < 0 {
		t.Fatal("missing new-reader fixture wrap")
	}
	bad.AccessRecords[1].Wraps[i].RSACiphertext = bytes.Clone(added.RSACiphertext)
	bad.AccessRecords[1].Wraps[i].RSACiphertext[0] ^= 1
	if a.candidateEntriesMatch(bad) {
		t.Fatal("changed newly prepared reader wrap accepted")
	}
}

// full_only: false
func TestGeneratedRetainedReplayRejectsChangedOutputEncoding(t *testing.T) {
	a, _, _, route := generatedRetainedReplayFixture(t, contract.GeneratedDutySupportKind, false, false)
	final := a.purpose.final
	saved := &final.preparedImage.Supplied[0]
	entry, err := contract.DecodeValueEntry(saved.EntryBytes)
	if err != nil {
		t.Fatal(err)
	}
	before, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, entry)
	if err != nil {
		t.Fatal(err)
	}
	entry.OutputEncoding = contract.OutputEncodingBase64
	after, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, entry)
	if err != nil || before != after {
		t.Fatal("output-only fixture changed immutable context", err)
	}
	saved.EntryBytes, err = contract.EncodeValueEntry(entry)
	if err != nil {
		t.Fatal("changed output was not a closed valid entry", err)
	}
	if code := a.openPreparedSupplied(t.Context(), route, &contract.CryptoResponse{}); code != contract.CryptoInvalidAdmission || len(final.supplied) != 0 {
		t.Fatal("saved secret output class replaced exact planned output", code)
	}
}
