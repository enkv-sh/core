package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: true
func TestRecipientRetirementPreservesMembershipAndRegistryCapacityBoundaries(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	resource := *f.selected.recipientRecord(fixtureID(f.env.Domain, "reader"))
	desired := currentApplyRecipients(f.selected.registry())
	for i := len(desired); i < contract.CryptoMaxRecipients; i++ {
		prepared := installedRetirementReenrollment(t, f.selected, resource, fmt.Sprintf("capacity registry %03d", i))
		desired = append(desired, prepared[slices.IndexFunc(prepared, func(row contract.ApplyRecipientInput) bool { return row.Creation != nil })])
	}
	slices.SortFunc(desired, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	var registryBytes int
	for _, row := range desired {
		body, err := contract.EncodeRecipientRecord(row.Recipient)
		if err != nil {
			t.Fatal(err)
		}
		registryBytes += len(body)
	}
	if contract.RecipientRecordMaxLength != 1855 || contract.RecipientRecordMaxLength*contract.CryptoMaxRecipients != 474880 || registryBytes > 474880 || uint64(474880) >= contract.MaxPublicRegistryBytes {
		t.Fatal("canonical registry bound changed; 8 MiB positive canonical boundary is unreachable under these row/count limits")
	}
	authority := f.selected.admission.recipient
	members := []contract.ID{authority}
	for _, row := range desired {
		if row.Recipient.RecipientID != authority && len(members) < 64 {
			members = append(members, row.Recipient.RecipientID)
		}
	}
	slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	input := make([]ApplyEntryInput, 64)
	for at := range input {
		input[at] = ApplyEntryInput{Name: fmt.Sprintf("entry-%03d", at), Recipients: slices.Clone(members), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte{byte(at)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	}
	engine := f.engineWithRecipients(t, f.selected, input, desired, nil)
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "select full registry and 4096 memberships"), input)
	engine.Close()
	if result.Result.Outcome != ObservedCurrent {
		t.Fatal("valid 256-row/64-member/4096-membership image refused", result.Result)
	}
	selected := f.open(t, ctx)
	if selected.root.MembershipCount != 4096 || selected.root.RecipientCount != 256 || selected.root.ChildCount > ordinaryChildPageLimit {
		t.Fatal("selected joint capacity image differs")
	}
	store := f.env.Store.(*memoryStore)
	cas := store.cas
	_, private := f.keys.Calls()
	extra := slices.Clone(input)
	extra = append(extra, ApplyEntryInput{Name: "overflow", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	if compared, result := selected.compareEntryInputs(extra); compared != nil || result.Outcome != AdmissionRefused || result.Reason != CapacityExceeded {
		t.Fatal("4097th membership did not refuse at exact aggregate boundary", result)
	}
	extra = slices.Clone(input)
	extra[0].Recipients = slices.Clone(extra[0].Recipients)
	for _, row := range selected.registry() {
		if !slices.Contains(members, row.RecipientID) {
			extra[0].Recipients = append(extra[0].Recipients, row.RecipientID)
			break
		}
	}
	slices.SortFunc(extra[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if compared, result := selected.compareEntryInputs(extra); compared != nil || result.Outcome != AdmissionRefused || result.Reason != InvalidIntent {
		t.Fatal("65th valid current recipient did not refuse at per-entry boundary", result)
	}
	_, afterPrivate := f.keys.Calls()
	if store.cas != cas || afterPrivate != private {
		t.Fatal("capacity refusal crossed private custody or selection")
	}
	reader := members[slices.IndexFunc(members, func(id contract.ID) bool { return id != authority })]
	retired := installedRetirementTestRun(t, ctx, f, selected, installedSecretAccessTestRef(t, selected, reader), "retire full membership census", nil)
	fresh := f.open(t, ctx)
	if retired.Result.Outcome != ObservedCurrent || retired.Payload == nil || retired.Payload.ChangedSubjects.Count != 129 || fresh.root.RecipientCount != 255 || fresh.root.MembershipCount != 4032 || fresh.root.ChildCount > ordinaryChildPageLimit {
		t.Fatal("retirement did not atomically remove all 64 plain memberships and row", retired.Result)
	}
	_, afterPrivate = f.keys.Calls()
	if afterPrivate != private || store.cas != cas+1 {
		t.Fatal("plain maximum census used private decryption or multiple selections")
	}
}
