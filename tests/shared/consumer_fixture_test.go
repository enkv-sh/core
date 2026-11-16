package core

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// A parent requests delivery explicitly with an exact public successor binding,
// selected name and a private fixture value selector.
type successorConsumerInput struct {
	Binding contract.BindingTableRow
	Name    string
	Value   uint8
}

func checkSuccessorConsumer(t testing.TB, s *StateSession, input successorConsumerInput) {
	t.Helper()
	control, ok := s.admission.currentControl()
	if !ok {
		t.Fatal("fresh current public control refused")
	}
	bindings, err := s.currentBindings()
	if err != nil {
		t.Fatal(err)
	}
	var recovery contract.ID
	if control.Recovery != nil {
		recovery = control.Recovery.RoleID
	}
	keys := custody.NewCurrentConsumer(t, fixtureID(s.admission.domain, "current consumer"), control.AuthorityRecipientID, recovery, bindings, input.Binding)
	selection := sessionConsumerSelection(t, s, input.Binding.SubjectID, input.Name)
	check := keys.Consume(context.Background(), selection, input.Value)
	if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
		t.Fatal("fresh current recipient failed", check)
	}
}

// The private test parent obtains these facts through the complete public read
// path. Only public records and encrypted value bytes leave this helper.
func fixtureConsumerSelection(t *testing.T, ctx context.Context, env fixtureEnvironment, recipient contract.ID, name string) contract.ConsumerSelection {
	t.Helper()
	if ctx == nil {
		t.Fatal("consumer Context is unavailable")
	}
	if _, finite := ctx.Deadline(); !finite {
		deadline := time.Now().Add(time.Minute)
		if testDeadline, finite := t.Deadline(); finite && testDeadline.Before(deadline) {
			deadline = testDeadline
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	independent := fixtureAdmission(env)
	if independent.admission == nil {
		t.Fatal("consumer public basis is unavailable")
	}
	basis := independent.admission.publicBasis()
	admission, result := captureConsumerMaterialization(t, ctx, env, basis, []string{name}, recipient)
	if admission == nil || result.Payload == nil || result.Validate() != nil {
		t.Fatal("public consumer selection refused", result.StateResult, result.Failure)
	}
	return materializationConsumerRecord(t, admission, 0)
}

type consumerCaptureCustody struct{}

func (consumerCaptureCustody) Materialize(context.Context) contract.MaterializationCompletion {
	facts := contract.InitialMaterializationFacts()
	facts.Failure = &contract.MaterializationFailure{Stage: contract.MaterializationAuthentication, Reason: contract.MaterializationInvalidAdmission}
	return contract.MaterializationCompletion{StateResult: contract.MaterializationRefused, Facts: facts}
}
func (consumerCaptureCustody) Close() {}

// This adapter captures only the authenticated public/encrypted handoff. Its
// private stub refuses before staging and makes no native completion claim.
func captureConsumerMaterialization(t testing.TB, ctx context.Context, env fixtureEnvironment, basis PublicBasis, names []string, recipient contract.ID) (*contract.MaterializationAdmission, MaterializationResult) {
	t.Helper()
	source := &installedGeneratedReadSource{store: env.Store, configuration: fixtureStoreConfiguration(env.Store)}
	var admission *contract.MaterializationAdmission
	installed, err := NewInstalledMaterialization(MaterializationInstallation{Reader: ReaderInstallation{Candidate: source, Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return source, Result{}
	}, ExpectedDomain: env.Domain, ExpectedStore: env.Store.Descriptor(), PublicBasis: basis, CloseInstalled: func() {}}, SourcePins: installedAdministrativeTestPins(), CheckSource: func(context.Context) error { return nil }, CredentialRoute: fixtureID(env.Domain, "consumer private route"), Target: contract.MaterializationTarget{Path: filepath.Join(t.TempDir(), "unused.env"), SurfaceID: fixtureID(env.Domain, "consumer surface"), Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}, AdmitCustody: func(_ context.Context, a contract.MaterializationAdmission) (MaterializationCustody, error) {
		admission = &a
		return consumerCaptureCustody{}, nil
	}})
	if err != nil {
		t.Fatal("public consumer installation", err)
	}
	defer installed.Close()
	result := installed.Materialize(ctx, contract.MaterializationRequest{RequestNonce: fixtureID(env.Domain, "public consumer request"), Names: names, RecipientID: recipient})
	return admission, result
}

func materializationConsumerRecord(t testing.TB, a *contract.MaterializationAdmission, index int) contract.ConsumerSelection {
	t.Helper()
	row := a.Entries[index]
	if row.Secret != nil {
		return *row.Secret
	}
	digest, err := contract.PublicValueEntryDigest(a.DomainID, row.Slot, row.Entry)
	if err != nil {
		t.Fatal(err)
	}
	return contract.ConsumerSelection{DomainID: a.DomainID, SnapshotID: a.SnapshotID, HEADDigest: a.HEADDigest, AccessRoot: a.AccessRoot, EntryDigest: digest, Root: a.Root, HEADRevision: a.HEADRevision, HEADToken: a.HEADToken, Slot: row.Slot, Entry: row.Entry, Binding: a.Recipient}
}

func sessionConsumerSelection(t testing.TB, s *StateSession, recipient contract.ID, name string) contract.ConsumerSelection {
	t.Helper()
	selection, result := s.admitConsumerSelection(context.Background(), []string{name}, recipient)
	if selection == nil {
		t.Fatal("consumer selection refused", result)
	}
	return selectedConsumerRecord(t, s, selection.slots[0], selection.recipient)
}

func selectedConsumerRecord(t testing.TB, s *StateSession, slot uint16, recipient contract.ID) contract.ConsumerSelection {
	t.Helper()
	m := s.valueEntry(slot)
	r := s.recipientRecord(recipient)
	var value contract.ValueCore
	var payload contract.CanonicalPayload
	var access contract.AccessRecord
	if m.ConfidentialityClass == contract.Secret {
		var ok bool
		value, payload, access, ok = s.selectedValue(slot)
		if !ok {
			t.Fatal("consumer value relations are invalid")
		}
		accessBody, err := contract.EncodeAccessRecord(access)
		if err != nil {
			t.Fatal(err)
		}
		access, err = contract.DecodeAccessRecord(accessBody)
		if err != nil {
			t.Fatal(err)
		}
	}
	entryDigest, err := contract.PublicValueEntryDigest(s.admission.domain, slot, *m)
	if err != nil {
		t.Fatal(err)
	}
	entryBytes, err := contract.EncodeValueEntry(*m)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := contract.DecodeValueEntry(entryBytes)
	if err != nil {
		t.Fatal(err)
	}
	bindingBody, err := contract.EncodeKMSBinding(*r.CurrentBinding)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := contract.DecodeKMSBinding(bindingBody)
	if err != nil {
		t.Fatal(err)
	}
	return contract.ConsumerSelection{
		DomainID:   s.admission.domain,
		SnapshotID: s.root.Snapshot, HEADDigest: contract.Hash(s.body), AccessRoot: s.root.CurrentAccess.AccessRoot,
		EntryDigest: entryDigest, Root: s.head.Core.Root, HEADRevision: s.head.Core.Revision, HEADToken: s.token,
		Slot: slot, Entry: entry, Core: value, Payload: payload, Access: access,
		Binding: contract.BindingTableRow{SubjectKind: 1, SubjectID: recipient, Binding: binding},
	}
}
