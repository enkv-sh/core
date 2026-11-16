package core

import (
	"context"
	"maps"
	"os"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/custody"
)

func liveNextSigning(t testing.TB, settings liveSettings, before contract.PublicSigningBinding) contract.PublicSigningBinding {
	t.Helper()
	after := before
	after.BindingID = fixtureID(before.BindingID, "successor signing binding")
	selector, public := settings.NormalSuccessorKeyID, settings.NormalSuccessorPublicKeyPEM
	if before.Role == contract.RecoverySigningRole {
		selector, public = settings.RecoverySuccessorKeyID, settings.RecoverySuccessorPublicKeyPEM
	}
	if before.Role == contract.NormalSigningRole && before.KeySelector == selector {
		selector, public = settings.NormalSuccessor2KeyID, settings.NormalSuccessor2PublicKeyPEM
	}
	if selector == "" || before.KeySelector == selector {
		t.Fatal("no further configured signing successor")
	}
	var err error
	after.SPKI, err = livePublicDER(public)
	if err != nil {
		t.Fatal("configured signing successor refused", err)
	}
	after.KeySelector, after.Fingerprint = selector, contract.Hash(after.SPKI)
	after.Binding.PublicKey = after.Fingerprint
	after.Binding.Epoch++
	if _, err := contract.PublicSigningBindingLength(after); err != nil {
		t.Fatal("successor signing binding refused", err)
	}
	return after
}

func liveNextKEK(t testing.TB, settings liveSettings, row contract.BindingTableRow) contract.BindingTableRow {
	t.Helper()
	var first, firstPEM, second, secondPEM string
	switch livePrivateKeyRole(settings, row) {
	case "authority-decrypter-0", "authority-decrypter-1":
		first, firstPEM = settings.AuthoritySuccessor1KEKID, settings.AuthoritySuccessor1KEKPublicKeyPEM
		second, secondPEM = settings.AuthoritySuccessor2KEKID, settings.AuthoritySuccessor2KEKPublicKeyPEM
	case "recovery-decrypter-0", "recovery-decrypter-1":
		first, firstPEM = settings.RecoverySuccessor1KEKID, settings.RecoverySuccessor1KEKPublicKeyPEM
		second, secondPEM = settings.RecoverySuccessor2KEKID, settings.RecoverySuccessor2KEKPublicKeyPEM
	default:
		t.Fatal("no configured current KEK successor")
	}
	selector, public := first, firstPEM
	if row.Binding.KeySelector == first {
		selector, public = second, secondPEM
	}
	var err error
	row.Binding.SPKI, err = livePublicDER(public)
	if err != nil {
		t.Fatal("configured KEK successor refused", err)
	}
	row.Binding.BindingID = fixtureID(row.Binding.BindingID, "successor KEK binding")
	row.Binding.BindingSerial++
	row.Binding.KeySelector, row.Binding.Fingerprint = selector, contract.Hash(row.Binding.SPKI)
	if _, err := contract.KMSBindingLength(row.Binding); err != nil {
		t.Fatal("successor KEK binding refused", err)
	}
	return row
}

func liveSuccessionActors(t testing.TB, ctx context.Context, input liveRunInput, budget *runBudget, inventory *objectInventory, before *StateSession, mask, approval uint8) successionActors {
	t.Helper()
	control, ok := before.selectedControl()
	if !ok {
		t.Fatal("current control unavailable")
	}
	body, err := contract.EncodeControlCore(control)
	if err != nil {
		t.Fatal(err)
	}
	after, err := contract.DecodeControlCore(body)
	if err != nil {
		t.Fatal(err)
	}
	after.AccessGeneration++
	actor := liveRoleSettings(input, "replacement-store")
	if actor == nil {
		t.Fatal("restricted replacement Store actor unavailable")
	}
	backend, err := openLiveBackend(ctx, *actor, input.Prefix, before.admission.domain)
	if err != nil || backend.Store.Descriptor() != before.store.Descriptor() {
		t.Fatal("restricted replacement Store differs", err)
	}
	actors := successionActors{After: after, Activate: func(testing.TB, *StateSession) {}, Store: recordedStore{Store: backend.Store, inventory: inventory, budget: budget}}
	authorizer := control.NormalSigning
	if approval == contract.RecoverySigningRole {
		if control.Recovery == nil {
			t.Fatal("recovery authorizer absent")
		}
		authorizer = control.Recovery.Signing
	}
	actors.Signers.Authorizer, err = openLiveReplacementSigner(ctx, input, budget, liveSigningRole(input.Settings, authorizer), authorizer)
	if err != nil {
		t.Fatal("current restricted authorizer refused", err)
	}
	if mask&1 != 0 {
		actors.After.NormalSigning = liveNextSigning(t, input.Settings, control.NormalSigning)
		actors.Signers.NormalSuccessor, err = openLiveReplacementSigner(ctx, input, budget, liveSigningRole(input.Settings, actors.After.NormalSigning), actors.After.NormalSigning)
	} else if mask&4 != 0 {
		actors.After.Recovery.Signing = liveNextSigning(t, input.Settings, control.Recovery.Signing)
		actors.Signers.RecoverySuccessor, err = openLiveReplacementSigner(ctx, input, budget, liveSigningRole(input.Settings, actors.After.Recovery.Signing), actors.After.Recovery.Signing)
	}
	if err != nil {
		t.Fatal("restricted successor signer refused", err)
	}
	if mask&(2|8) == 0 {
		return actors
	}
	bindings, err := before.currentBindings()
	if err != nil {
		t.Fatal(err)
	}
	actors.Source = contract.BindingTableRow{SubjectKind: 1, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding}
	if control.Recovery != nil && mask&2 != 0 {
		actors.Source = contract.BindingTableRow{SubjectKind: 2, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS}
	}
	target := contract.BindingTableRow{SubjectKind: 1, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding}
	if mask&8 != 0 {
		target = contract.BindingTableRow{SubjectKind: 2, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS}
	}
	target = liveNextKEK(t, input.Settings, target)
	if target.SubjectKind == 1 {
		actors.After.AuthorityKMSBinding = target.Binding
	} else {
		actors.After.Recovery.KMS = target.Binding
	}
	sourceRole, targetRole := livePrivateKeyRole(input.Settings, actors.Source), livePrivateKeyRole(input.Settings, target)
	roles := []string{sourceRole}
	if targetRole != sourceRole {
		roles = append(roles, targetRole)
	}
	routes := make([]custody.Route, len(bindings))
	for i, row := range bindings {
		routes[i].BindingID = row.Binding.BindingID
		if row.Binding.BindingID == actors.Source.Binding.BindingID {
			routes[i].PrivateRoute = liveCredentialRoute(input, sourceRole)
		}
	}
	actors.Keys, err = openLiveReplacementCustody(t, ctx, input, before.admission.domain, budget, bindings, routes, roles)
	if err != nil {
		t.Fatal("restricted replacement custody refused", err)
	}
	route := liveCredentialRoute(input, targetRole)
	if err := actors.Keys.InstallKEKSuccessor(target, route, route); err != nil {
		t.Fatal("exact successor route admission refused", err)
	}
	// Begin qualifies and privately probes one successor. Each current value
	// then opens one source packet and wraps once under that successor.
	calls := int(before.root.AccessRecordCount) + 4
	if !budget.reserve(uint64(2*calls), uint64(calls)*operationBodyAllowance, "", 0) {
		t.Fatal("replacement custody budget exhausted")
	}
	actors.Activate = func(t testing.TB, _ *StateSession) {
		actors.Keys.RetireAccess()
		if err := actors.Keys.ActivateSuccessor(target.SubjectID); err != nil {
			t.Fatal("successor activation refused", err)
		}
		actors.Keys.Close()
	}
	return actors
}

func liveCurrentConsumer(t testing.TB, ctx context.Context, input liveRunInput, budget *runBudget, session *StateSession, selection contract.ConsumerSelection, value uint8) custody.ConsumerCheck {
	t.Helper()
	keys := liveSelectedPrivateCustody(t, ctx, input, budget, session, selection.Binding)
	if !budget.reserveCustody("consume", 1) {
		t.Fatal("current consumer budget refused")
	}
	return keys.Consume(ctx, selection, value)
}

func liveReaderSuccessor(t testing.TB, input liveRunInput, domain contract.ID) contract.BindingTableRow {
	t.Helper()
	bindings, err := liveCustodyBindings(input.Settings, domain)
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(bindings, func(row contract.BindingTableRow) bool {
		return row.SubjectKind == 1 && row.SubjectID == fixtureID(domain, "reader")
	})
	if index < 0 {
		t.Fatal("reader predecessor unavailable")
	}
	row := bindings[index]
	row.Binding.BindingID = fixtureID(row.Binding.BindingID, "successor reader binding")
	row.Binding.BindingSerial++
	row.Binding.KeySelector = input.Settings.ReaderSuccessorKEKID
	row.Binding.SPKI, err = livePublicDER(input.Settings.ReaderSuccessorKEKPublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	row.Binding.Fingerprint = contract.Hash(row.Binding.SPKI)
	return row
}

func liveCurrentPublicBasis(input liveRunInput, domain contract.ID, basis *successionBasisInput) (contract.ControlCore, bool) {
	if basis == nil {
		return contract.ControlCore{}, false
	}
	control, err := contract.DecodeControlCore(basis.Control)
	if err != nil || control.DomainID != domain || control.AuthorityRecipientID != fixtureID(domain, "recipient") || (control.Recovery != nil) != (input.RecoveryMode == "enabled") || liveSigningRole(input.Settings, control.NormalSigning) == "" || livePrivateKeyRole(input.Settings, contract.BindingTableRow{SubjectKind: 1, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding}) == "" {
		return contract.ControlCore{}, false
	}
	if control.Recovery != nil && (control.Recovery.RoleID != fixtureID(domain, "recovery") || liveSigningRole(input.Settings, control.Recovery.Signing) == "" || livePrivateKeyRole(input.Settings, contract.BindingTableRow{SubjectKind: 2, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS}) == "") {
		return contract.ControlCore{}, false
	}
	return control, len(basis.Selection) != 0
}

func runLiveFreshCheck(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, worker *records.WorkerRecorder, budget *runBudget, sequence uint64, facts freshFacts) {
	t.Helper()
	if len(facts.Receipts) > 2*contract.MutationReceiptWindowLimit {
		t.Fatal("fresh receipt expectations exceed the current window")
	}
	reads, ok := freshSelectedReadAllowance(facts.Expected)
	if !ok {
		t.Fatal("fresh selected read shape refused")
	}
	reads += freshReceiptReadCount(facts.Receipts)
	if catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixtureSecretState) || facts.Consumer != nil {
		reads++ // One bounded custody call per child.
	}
	if !budget.admitFreshReads(reads, 2) {
		t.Fatal("fresh read budget exhausted")
	}
	path, err := prepareFreshChild(inv, worker, facts)
	if err != nil {
		t.Fatal("fresh process input could not be saved")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("fresh process executable unavailable")
	}
	child, process, err := executeFreshChild(ctx, binary, path)
	worker.Result.Children[len(worker.Result.Children)-1].Process = process
	if worker.Save() != nil {
		t.Fatal("fresh process observation could not be saved")
	}
	for _, phase := range child.Phases {
		if phase.Name == "reopen" && worker.ObservePhase(sequence, phase.Actual) != nil {
			t.Fatal("fresh process observation could not be saved")
		}
	}
	if err != nil {
		t.Error(err)
	}
}

// full_only: false
func TestLiveAssemblyCurrentSuccessorBindings(t *testing.T) {
	input, domain, bindings := liveReplacementConstructionInput(t, true)
	for _, role := range []string{"normal-signer-0", "recovery-signer-0"} {
		before := liveReplacementProviderTestBinding(t, input, role)
		after := liveNextSigning(t, input.Settings, before)
		if after.BindingID == before.BindingID || after.Binding.Epoch != before.Binding.Epoch+1 || after.Binding.PublicKey != after.Fingerprint || after.Binding.Trust != before.Binding.Trust || after.KeySelector == before.KeySelector || liveSigningRole(input.Settings, after) == "" {
			t.Fatal("new signing resource did not retain exact trust and update its public key")
		}
	}
	for _, before := range bindings {
		if before.SubjectID == fixtureID(domain, "reader") {
			continue
		}
		first := liveNextKEK(t, input.Settings, before)
		second := liveNextKEK(t, input.Settings, first)
		if first.SubjectKind != before.SubjectKind || first.SubjectID != before.SubjectID || first.Binding.BindingSerial != before.Binding.BindingSerial+1 || second.Binding.BindingSerial != first.Binding.BindingSerial+1 || first.Binding.BindingID == before.Binding.BindingID || second.Binding.BindingID == first.Binding.BindingID || first.Binding.KeySelector == before.Binding.KeySelector || second.Binding.KeySelector == first.Binding.KeySelector || livePrivateKeyRole(input.Settings, first) == "" || livePrivateKeyRole(input.Settings, second) == "" {
			t.Fatal("repeated KEK binding did not retain exact subject or select each current resource")
		}
	}
	reader := liveReaderSuccessor(t, input, domain)
	if reader.SubjectID != fixtureID(domain, "reader") || reader.SubjectKind != 1 || reader.Binding.BindingSerial != 2 || livePrivateKeyRole(input.Settings, reader) != "reader-successor" {
		t.Fatal("reader successor did not name its sole current private actor")
	}
}

func liveCurrentPrivateWitness(t testing.TB, ctx context.Context, input liveRunInput, budget *runBudget, session *StateSession, choice uint8) {
	t.Helper()
	control, ok := session.selectedControl()
	if !ok || control.Recovery == nil {
		t.Fatal("current independent private witness keys unavailable")
	}
	target := contract.BindingTableRow{SubjectKind: 1, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding}
	recovery := contract.BindingTableRow{SubjectKind: 2, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS}
	role, wrappedUnder := livePrivateKeyRole(input.Settings, target), target.Binding
	want := custody.RouteWitness{Outcome: contract.CryptoSuccess, Completed: 1}
	switch choice {
	case 1:
	case 2:
		wrappedUnder = recovery.Binding
		want = custody.RouteWitness{Outcome: contract.CryptoPrivateRouteUnavailable, Failed: 1}
	case 3:
		role = livePrivateKeyRole(input.Settings, recovery)
		want = custody.RouteWitness{Outcome: contract.CryptoPrivateRouteUnavailable, Denied: 1}
	default:
		t.Fatal("private witness choice refused")
	}
	if got := openLiveRouteWitness(t, ctx, input, session.admission.domain, budget, target, wrappedUnder, role); got != want {
		t.Fatal("private provider witness differs from exact attempted operation", got, want)
	}
}

// full_only: false
func TestLiveSecondNormalSuccessorKeepsIndependentResource(t *testing.T) {
	input, domain, _ := liveReplacementConstructionInput(t, true)
	first := liveReplacementTestSigningBinding(t, input, "normal-signer-0", domain)
	second := liveNextSigning(t, input.Settings, first)
	third := liveNextSigning(t, input.Settings, second)
	if second.KeySelector != input.Settings.NormalSuccessorKeyID || third.KeySelector != input.Settings.NormalSuccessor2KeyID || second.BindingID == third.BindingID || second.Fingerprint == third.Fingerprint || liveSigningRole(input.Settings, third) != "normal-signer-2" {
		t.Fatal("second independent successor differs")
	}
	actor, err := liveReplacementSignerInput(input, "normal-signer-2", third)
	if err != nil || actor.Route == liveCredentialRoute(input, "normal-signer-1") {
		t.Fatal("second signer route not independent", err)
	}
	bad := input
	bad.ReplacementSettings = maps.Clone(input.ReplacementSettings)
	bad.ReplacementSettings["normal-signer-2"] = input.ReplacementSettings["normal-signer-1"]
	bad.Participants = maps.Clone(input.Participants)
	bad.Participants["normal-signer-2"] = bad.Participants["normal-signer-1"]
	if _, err := liveReplacementSignerInput(bad, "normal-signer-2", third); err == nil {
		t.Fatal("aliased successor route accepted")
	}
	bad = input
	bad.Settings.NormalSuccessor2KeyID = bad.Settings.NormalSuccessorKeyID
	if liveReplacementAdmitted(bad) {
		t.Fatal("aliased successor resource accepted")
	}
}
