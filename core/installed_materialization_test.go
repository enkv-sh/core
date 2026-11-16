package core

import (
	"bytes"
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func materializationAdmissionFixture(t *testing.T) (context.Context, publicSelection, MaterializationInstallation, contract.MaterializationRequest) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	recipient := contract.ID{11}
	binding := generatedPublicBinding(t, 21)
	root := contract.Ref{Kind: contract.RootKind, Domain: contract.ID{1}, Object: contract.ID{2}, Digest: contract.ID{3}, Format: contract.CanonicalSchema, Length: 1}
	var selected publicSelection
	selected.complete = true
	selected.authorityID = recipient
	selected.basis.anchor = anchoredPublicCandidate{headBody: []byte("authenticated selected HEAD"), headToken: contract.Token{Family: contract.GCP, Value: "1"}, deadline: mustMaterializationDeadline(ctx), done: ctx.Done()}
	selected.basis.anchor.head.Core.Revision = contract.ID{4}
	selected.basis.anchor.head.Core.Root = root
	selected.image.root.Domain = root.Domain
	selected.image.root.Snapshot = root.Object
	selected.image.root.CurrentAccess.AccessRoot = contract.ID{5}
	selected.image.root.CurrentAccess.Core.AuthorityRecipientID = recipient
	selected.image.root.Names = []format.NameEntry{{Name: "A", Slot: 1}, {Name: "Z", Slot: 0}}
	selected.image.recipients[0] = &format.RecipientPage{}
	selected.image.recipients[0].Slots[0] = &contract.RecipientRecord{RecipientID: recipient, Status: contract.CurrentRecipient, CurrentBinding: &binding}
	selected.image.pages[0] = &format.ValueEntryPage{}
	for slot, name := range []string{"Z", "A"} {
		selected.image.pages[0].Slots[slot] = &contract.ValueEntry{Name: name, Incarnation: contract.ID{byte(31 + slot)}, ValueState: contract.ID{byte(41 + slot)}, OriginSnapshot: contract.ID{51}, OriginTransition: contract.ID{52}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{recipient}, ValueBytes: []byte(name + " plain"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte(name + " plain"))), RetainedLength: uint32(len([]byte(name + " plain")))}
	}
	installation := MaterializationInstallation{SourcePins: installedAdministrativeTestPins(), CredentialRoute: contract.ID{61}, Target: contract.MaterializationTarget{Path: "/private/materialized.env", SurfaceID: contract.ID{62}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}}
	installation.Reader.ExpectedStore = contract.Descriptor{Family: contract.GCP, Identity: contract.ID{63}, Coordinate: contract.ID{64}, NonBody: contract.ID{65}, Prefix: "fixture", HeadKey: "fixture/HEAD"}
	selected.basis.reader.descriptor = installation.Reader.ExpectedStore
	request, err := contract.OwnMaterializationRequest(contract.MaterializationRequest{RequestNonce: contract.ID{71}, Names: []string{"Z", "A"}})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, selected, installation, request
}
func mustMaterializationDeadline(ctx context.Context) time.Time {
	deadline, _ := ctx.Deadline()
	return deadline
}

// full_only: false
func TestMaterializationAdmissionBindsWholePlainSelection(t *testing.T) {
	for _, condition := range []string{"implicit-authority", "explicit-authority", "shared-implicit", "shared-explicit", "unauthorized-last", "missing", "duplicate", "retired"} {
		t.Run(condition, func(t *testing.T) {
			ctx, selected, installation, request := materializationAdmissionFixture(t)
			switch condition {
			case "explicit-authority":
				request.RecipientID = selected.authorityID
			case "shared-implicit", "shared-explicit":
				other := contract.ID{12}
				binding := generatedPublicBinding(t, 22)
				selected.image.recipients[0].Slots[1] = &contract.RecipientRecord{RecipientID: other, Status: contract.CurrentRecipient, CurrentBinding: &binding}
				for _, entry := range selected.image.pages[0].Slots[:2] {
					entry.Recipients = append(entry.Recipients, other)
				}
				if condition == "shared-explicit" {
					request.RecipientID = other
				}
			case "unauthorized-last":
				selected.image.pages[0].Slots[0].Recipients = []contract.ID{{12}}
			case "missing":
				request.Names[1] = "absent"
			case "duplicate":
				request.Names[1] = request.Names[0]
			case "retired":
				selected.image.recipients[0].Slots[0].Status = contract.RetiredRecipient
			}
			admission, payload, failed := materializationAdmissionForSelection(ctx, &selected, contract.ID{81}, contract.ID{82}, installation, request)
			want := condition == "implicit-authority" || condition == "explicit-authority" || condition == "shared-implicit" || condition == "shared-explicit"
			if !want {
				if failed.Outcome == 0 || payload != nil || len(admission.Entries) != 0 {
					t.Fatal("incomplete selection reached private handoff", failed)
				}
				return
			}
			if failed.Outcome != 0 || payload == nil || len(admission.Entries) != 2 || admission.Entries[0].Name != "A" || admission.Entries[1].Name != "Z" || admission.ExpiresAt != mustMaterializationDeadline(ctx) || admission.SourcePins.FileID != installation.SourcePins.FileID || admission.Target != installation.Target || admission.Recipient.SubjectID.IsZero() {
				t.Fatal("fixed whole selection changed", failed)
			}
			acting := selected.authorityID
			if condition == "shared-explicit" {
				acting = contract.ID{12}
			}
			if admission.Recipient.SubjectID != acting || payload.Recipient.SubjectID != acting {
				t.Fatal("whole selection used a different recipient")
			}
			payload.Recipient.Binding.SPKI[0] ^= 1
			if bytes.Equal(payload.Recipient.Binding.SPKI, admission.Recipient.Binding.SPKI) {
				t.Fatal("public result can change private binding")
			}
			if admission.Entries[0].Secret != nil || admission.Entries[1].Secret != nil || !reflect.DeepEqual(admission.Entries[0].Entry.ValueBytes, []byte("A plain")) {
				t.Fatal("plain handoff changed")
			}
		})
	}
}

// full_only: false
func TestInstalledMaterializationRefusesWithoutFinitePublicAdmission(t *testing.T) {
	var installed *InstalledMaterialization
	got := installed.Materialize(context.Background(), contract.MaterializationRequest{RequestNonce: contract.ID{1}, Names: []string{"A"}})
	if got.StateResult != contract.MaterializationRefused || got.Payload != nil || got.Failure == nil || got.Failure.Reason != contract.MaterializationInvalidRequest || got.Operation != contract.MaterializationOperation || got.RequestID != (contract.ID{1}) || got.Validate() != nil {
		t.Fatal("unsafe unbound refusal", got)
	}
	for _, failed := range []readerFailure{readerSelectionFailure(failure(Contention, DifferentSelection)), readerRefusal(contract.ReasonUnsupportedProfile), readerSelectionFailure(failure(RootLossUnsupported, MissingSelectedObject))} {
		state, reason := materializationFailureClass(failed)
		if state == "contention" || state == "unsupported" || state == "exact-resume" || !state.Valid() || !reason.Valid() {
			t.Fatal("illegal materialization result", state, reason)
		}
	}
}

type materializationPrivateProbe struct {
	run    func(context.Context) contract.MaterializationCompletion
	closed int
}

func (p *materializationPrivateProbe) Materialize(ctx context.Context) contract.MaterializationCompletion {
	return p.run(ctx)
}
func (p *materializationPrivateProbe) Close() { p.closed++ }

func materializationPublicInput(t *testing.T) (MaterializationInstallation, *gcPublicFixtureStore, *int, PublicBasis) {
	t.Helper()
	selected, store, basis := gcInstalledFixture(t)
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{selected.admission.recipient}, InputBytes: []byte("current stored plain")}}
	unchecked, result := selected.compareEntryInputs(input)
	if unchecked == nil {
		t.Fatal("current plain intent", result)
	}
	support, err := selected.generatedSupportTransition(t.Context(), unchecked, nil)
	if err != nil {
		t.Fatal("preserved genesis support", err)
	}
	comparison, result := selected.compare(t.Context(), input, &AdmittedParentComparison{session: selected, deadline: time.Now().Add(time.Minute), support: support})
	if comparison == nil {
		t.Fatal("complete current plain comparison", result)
	}
	plan, err := planTransition(t.Context(), comparison)
	if err != nil {
		t.Fatal("current plain transition", err)
	}
	next, err := selected.deriveSuccessor(t.Context(), comparison, plan)
	if err != nil {
		t.Fatal("current plain successor", err)
	}
	authority, err := selected.authorityFrom(next, comparison, plan)
	if err != nil {
		t.Fatal("current plain authority subject", err)
	}
	permit := &AdmittedParentTransition{session: selected, comparison: comparison, predecessorDigest: contract.Hash(selected.body), predecessorRevision: selected.head.Core.Revision, predecessorToken: selected.token, plan: plan, authority: authority}
	candidate, result := selected.prepare(t.Context(), comparison, permit, testtrust.New(t, contract.GCP, selected.admission.trust))
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("prepare current plain", result)
	}
	selected, result = selected.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("select current plain", result)
	}
	closes := new(int)
	i := MaterializationInstallation{Reader: ReaderInstallation{Candidate: gcPublicFixtureCandidate{store}, Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return &gcPublicFixtureRead{store: store, closes: closes}, Result{}
	}, ExpectedDomain: selected.root.Domain, ExpectedStore: store.descriptor, PublicBasis: basis, CloseInstalled: func() {}}, SourcePins: installedAdministrativeTestPins(), CheckSource: func(context.Context) error { return nil }, CredentialRoute: contract.ID{91}, Target: contract.MaterializationTarget{Path: "/private/materialized.env", SurfaceID: contract.ID{92}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}}
	return i, store, closes, basis
}

// full_only: false
func TestInstalledMaterializationCapturesRequestAndFinishesWithoutStore(t *testing.T) {
	i, store, closes, basis := materializationPublicInput(t)
	request := contract.MaterializationRequest{RequestNonce: contract.ID{93}, Names: []string{"plain"}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	expectedTarget, expectedRoute, expectedPins := i.Target, i.CredentialRoute, i.SourcePins
	checks, factories := 0, 0
	i.CheckSource = func(context.Context) error {
		checks++
		if checks == 1 {
			request.Names[0] = "caller replacement"
			basis.Descriptor[0] ^= 1
		}
		return nil
	}
	private := &materializationPrivateProbe{}
	private.run = func(context.Context) contract.MaterializationCompletion {
		return contract.MaterializationCompletion{StateResult: contract.MaterializationSuccess, Facts: contract.MaterializationFacts{Replacement: contract.MaterializationReplaced, CandidateVerification: contract.MaterializationVerified, InstalledVerification: contract.MaterializationVerified, NativeCompletion: contract.MaterializationComplete, Disclosure: contract.MaterializationDisclosureOccurred, Cleanup: contract.MaterializationCandidateRenamed}}
	}
	i.AdmitCustody = func(_ context.Context, a contract.MaterializationAdmission) (MaterializationCustody, error) {
		factories++
		if *closes != 1 || a.ExpiresAt != deadline || a.Purpose != contract.MaterializationOperation || a.Store != store.descriptor || a.CredentialRoute != expectedRoute || a.Target != expectedTarget || a.SourcePins != materializationSourcePins(expectedPins) || len(a.Entries) != 1 || a.Entries[0].Name != "plain" || string(a.Entries[0].Entry.ValueBytes) != "current stored plain" {
			t.Error("handoff lost fixed request/source/target/lifetime")
		}
		// Fail any attempt to revalidate currentness after private admission.
		store.beforeRead = func(string) { t.Error("loaded materialization read Store") }
		return private, nil
	}
	installed, err := NewInstalledMaterialization(i)
	if err != nil {
		t.Fatal(err)
	}
	defer installed.Close()
	// Installation owns the scalar source/target/route fields before this change.
	i.Target.SurfaceID = contract.ID{94}
	i.CredentialRoute = contract.ID{95}
	i.SourcePins.FileID = contract.ID{96}
	result := installed.Materialize(ctx, request)
	if result.StateResult != contract.MaterializationSuccess || result.Validate() != nil || result.Payload == nil || result.Payload.Entries[0].Name != "plain" || private.closed != 1 || factories != 1 || *closes != 1 {
		t.Fatal("complete fixed materialization failed", result.StateResult, result.Failure, private.closed, factories, *closes)
	}
	if reused := installed.Materialize(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{97}, Names: []string{"plain"}}); reused.StateResult != contract.MaterializationRefused || reused.Payload != nil || factories != 1 {
		t.Fatal("one-use materialization reused")
	}
}

// full_only: false
func TestInstalledMaterializationCloseCancelsAndJoinsCustody(t *testing.T) {
	i, _, closes, _ := materializationPublicInput(t)
	entered, canceled, settle := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(settle) })
	private := &materializationPrivateProbe{run: func(ctx context.Context) contract.MaterializationCompletion {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-settle
		facts := contract.InitialMaterializationFacts()
		facts.Failure = &contract.MaterializationFailure{Stage: contract.MaterializationAuthentication, Reason: contract.MaterializationCanceled}
		return contract.MaterializationCompletion{StateResult: contract.MaterializationUnavailable, Facts: facts}
	}}
	i.AdmitCustody = func(context.Context, contract.MaterializationAdmission) (MaterializationCustody, error) {
		return private, nil
	}
	installed, err := NewInstalledMaterialization(i)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	defer installed.Close()
	defer release()
	operationDone := make(chan MaterializationResult, 1)
	go func() {
		operationDone <- installed.Materialize(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{98}, Names: []string{"plain"}})
	}()
	select {
	case <-entered:
	case result := <-operationDone:
		t.Fatal("operation refused before custody", result.StateResult, result.Failure)
	case <-ctx.Done():
		t.Fatal("custody did not start before deadline")
	}
	closed := make(chan struct{})
	go func() { installed.Close(); close(closed) }()
	select {
	case <-canceled:
	case <-ctx.Done():
		t.Fatal("Close did not cancel custody")
	}
	select {
	case <-closed:
		t.Fatal("Close released active custody before settlement")
	default:
	}
	release()
	result := <-operationDone
	<-closed
	if private.closed != 1 || *closes != 1 || result.StateResult != contract.MaterializationUnavailable || result.Failure.Reason != contract.MaterializationCanceled || result.Validate() != nil {
		t.Fatal("Close lost safe failure/join", result.StateResult, result.Failure)
	}
	t.Run("panic unwind joins custody", materializationPanicUnwindJoinsCustody)

}

// full_only: false
func TestMaterializationResultValidatesLocalAdmissionAndRejectsCanonicalMutationFacts(t *testing.T) {
	direct := MaterializationResult{Operation: contract.MaterializationOperation, RequestID: contract.ID{1}, Result: Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}, StateResult: contract.MaterializationRefused, Failure: &contract.MaterializationFailure{Stage: contract.MaterializationAdmissionStage, Reason: contract.MaterializationInvalidRequest}}
	t.Run("direct Core refusal", func(t *testing.T) {
		if direct.Validate() != nil {
			t.Fatal("direct refusal rejected")
		}
	})
	local := direct
	local.OperationID = contract.ID{2}
	local.PreAdmission = &PreAdmissionRequestIdentity{Stage: "dispatch", Code: "invalid-input", SourceSchema: "enkv/configuration/v1", SourceProfile: "direct-candidate", Format: "json", RequestNonce: local.RequestID}
	t.Run("local admission correlation", func(t *testing.T) {
		if local.Validate() != nil {
			t.Fatal("local correlation rejected")
		}
	})
	for _, condition := range []string{"missing operation", "wrong nonce", "bound request", "payload", "stage", "code", "schema", "profile"} {
		t.Run(condition, func(t *testing.T) {
			bad := local
			metadata := *local.PreAdmission
			bad.PreAdmission = &metadata
			switch condition {
			case "missing operation":
				bad.OperationID = contract.ID{}
			case "wrong nonce":
				metadata.RequestNonce = contract.ID{3}
			case "bound request":
				bad.RequestIdentity = contract.ID{4}
			case "payload":
				bad.Payload = &contract.MaterializationPayload{}
			case "stage":
				metadata.Stage = ""
			case "code":
				metadata.Code = ""
			case "schema":
				metadata.SourceSchema = ""
			case "profile":
				metadata.SourceProfile = ""
			}
			if bad.Validate() == nil {
				t.Fatal("malformed local relation accepted")
			}
		})
	}
	for _, condition := range []string{"commit uncertainty", "requested revision", "unbounded Store reason", "unknown Core reason", "mutation reason", "wrong known reason", "wrong known Store reason", "observed revision", "observed snapshot", "unproved evidence"} {
		t.Run(condition, func(t *testing.T) {
			bad := direct
			switch condition {
			case "commit uncertainty":
				bad.Result.CommitMayHaveOccurred = true
			case "requested revision":
				bad.Result.RequestedRevision = contract.ID{5}
			case "unbounded Store reason":
				bad.Result.StoreReason = contract.Reason(255)
			case "unknown Core reason":
				bad.Result.Reason = Reason(255)
			case "mutation reason":
				bad.Result.Reason = WriteUncertain
			case "wrong known reason":
				bad.Result.Reason = SigningUnavailable
			case "wrong known Store reason":
				bad.Result.StoreReason = contract.ReasonProof
			case "observed revision":
				bad.Result.ObservedRevision = contract.ID{6}
			case "observed snapshot":
				bad.Result.ObservedSnapshotID = contract.ID{7}
			case "unproved evidence":
				bad.Result.Evidence = AuthenticatedClosure
			}
			if bad.Validate() == nil {
				t.Fatal("canonical mutation/unproved observation accepted")
			}
		})
	}
	for _, stage := range []contract.MaterializationStage{contract.MaterializationStaging, contract.MaterializationCandidateSync, contract.MaterializationCandidateClose, contract.MaterializationCandidateVerification, contract.MaterializationRename, contract.MaterializationDirectorySync, contract.MaterializationInstalledVerification, contract.MaterializationInstalledClose, contract.MaterializationDirectoryClose, contract.MaterializationSinkClose, contract.MaterializationCleanup} {
		t.Run("native stage without payload/"+string(stage), func(t *testing.T) {
			bad := direct
			bad.Failure = &contract.MaterializationFailure{Stage: stage, Reason: contract.MaterializationIOFailure}
			if bad.Validate() == nil {
				t.Fatal("native progress accepted without selected payload")
			}
		})
	}

	t.Run("malformed custody completion", materializationRetainsLateFactsWithoutInventingContentDefect)

}

// full_only: false
func TestMaterializationAdmissionAuthorizesEveryMixedEntryBeforeHandoff(t *testing.T) {
	for _, condition := range []string{"authorized", "last-secret-denied", "last-plain-denied", "shared-implicit"} {
		t.Run(condition, func(t *testing.T) {
			ctx, image, installation, request := materializationAdmissionFixture(t)
			authority, other := image.authorityID, contract.ID{12}
			plain := *image.image.pages[0].Slots[1]
			state := &StateSession{admission: openAdmission{domain: image.image.root.Domain, recipient: authority}, root: image.image.root, recipients: image.image.recipients}
			state.root.CurrentAccess.Core.CryptoSupportID = contract.CryptoSupportID()
			state.root.CurrentAccess.Core.CompatibilityID = contract.CompatibilityID()
			state.root.CurrentAccess.Core.Provider = contract.GCP
			observationCurrentSecret(t, state, []contract.ID{authority, other}, contract.ID{101})
			plain.Recipients = []contract.ID{authority, other}
			if condition == "last-plain-denied" {
				plain.Name = "zz_plain"
				plain.Recipients = []contract.ID{authority}
			} else {
				plain.Name = "A"
			}
			if condition == "last-secret-denied" {
				state.pages[0].Slots[0].Recipients = []contract.ID{authority}
			}
			state.pages[0].Slots[1] = &plain
			state.root.Names = []format.NameEntry{{Name: plain.Name, Slot: 1}, {Name: "secret", Slot: 0}}
			if !state.indexSelectedMaterials() {
				t.Fatal("mixed material positions")
			}
			image.image.root, image.image.pages, image.image.recipients, image.image.access = state.root, state.pages, state.recipients, state.access
			image.materials = selectedMaterialFacts{accessLocations: state.accessLocations, valueReaders: state.valueReaders}
			request.Names = []string{plain.Name, "secret"}
			request.RecipientID = other
			if condition == "shared-implicit" {
				request.RecipientID = contract.ID{}
			}
			admission, payload, failed := materializationAdmissionForSelection(ctx, &image, contract.ID{102}, contract.ID{103}, installation, request)
			if condition != "authorized" && condition != "shared-implicit" {
				if failed.diagnostic != contract.ReasonTargetNotAuthorized || payload != nil || len(admission.Entries) != 0 {
					t.Fatal("whole membership gate did not precede private handoff", failed)
				}
				return
			}
			acting := other
			if condition == "shared-implicit" {
				acting = authority
			}
			if failed.Outcome != 0 || payload == nil || len(admission.Entries) != 2 || admission.Entries[0].Secret != nil || admission.Entries[1].Secret == nil || admission.Entries[1].Secret.Binding.SubjectID != acting || admission.Recipient.SubjectID != acting || payload.Recipient.SubjectID != acting {
				t.Fatal("complete mixed admission refused", failed)
			}
		})
	}
}

func materializationRetainsLateFactsWithoutInventingContentDefect(t *testing.T) {
	i, _, _, _ := materializationPublicInput(t)
	original := &contract.MaterializationFailure{Stage: contract.MaterializationDirectorySync, Reason: contract.MaterializationIOFailure}
	private := &materializationPrivateProbe{run: func(context.Context) contract.MaterializationCompletion {
		return contract.MaterializationCompletion{StateResult: contract.MaterializationSuccess, Facts: contract.MaterializationFacts{Replacement: contract.MaterializationReplaced, CandidateVerification: contract.MaterializationVerified, InstalledVerification: contract.MaterializationVerified, NativeCompletion: contract.MaterializationIncomplete, Disclosure: contract.MaterializationDisclosureOccurred, Cleanup: contract.MaterializationCandidateRenamed, Failure: original}}
	}}
	i.AdmitCustody = func(context.Context, contract.MaterializationAdmission) (MaterializationCustody, error) {
		return private, nil
	}
	installed, err := NewInstalledMaterialization(i)
	if err != nil {
		t.Fatal(err)
	}
	defer installed.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	result := installed.Materialize(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{111}, Names: []string{"plain"}})
	if result.StateResult != contract.MaterializationUnavailable || result.Payload == nil || result.Validate() != nil || result.Payload.Facts.Replacement != contract.MaterializationReplaced || result.Payload.Facts.CandidateVerification != contract.MaterializationVerified || result.Payload.Facts.InstalledVerification != contract.MaterializationVerified || result.Payload.Facts.Disclosure != contract.MaterializationDisclosureOccurred || result.Payload.Facts.Cleanup != contract.MaterializationCandidateRenamed || !reflect.DeepEqual(result.Failure, original) || private.closed != 1 {
		t.Fatal("invalid completion invented content defect or erased known facts", result.StateResult, result.Failure)
	}
}

func materializationPanicUnwindJoinsCustody(t *testing.T) {
	i, _, closes, _ := materializationPublicInput(t)
	private := &materializationPrivateProbe{run: func(context.Context) contract.MaterializationCompletion { panic("synthetic custody failure") }}
	i.AdmitCustody = func(context.Context, contract.MaterializationAdmission) (MaterializationCustody, error) {
		return private, nil
	}
	installed, err := NewInstalledMaterialization(i)
	if err != nil {
		t.Fatal(err)
	}
	defer installed.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var caught any
	func() {
		defer func() { caught = recover() }()
		installed.Materialize(ctx, contract.MaterializationRequest{RequestNonce: contract.ID{112}, Names: []string{"plain"}})
	}()
	if caught != "synthetic custody failure" || private.closed != 1 || *closes != 1 {
		t.Fatal("panic did not propagate after exact custody cleanup", private.closed, *closes)
	}
}

// full_only: false
func TestMaterializationProjectionIdentityBindsFinalSelectionAndResolvedActor(t *testing.T) {
	ctx, selected, installation, request := materializationAdmissionFixture(t)
	invocationID, publicBasis := contract.ID{81}, contract.ID{82}
	admit := func(t *testing.T, image *publicSelection) (contract.MaterializationAdmission, *contract.MaterializationPayload) {
		t.Helper()
		admission, payload, failed := materializationAdmissionForSelection(ctx, image, invocationID, publicBasis, installation, request)
		if failed.Outcome != 0 || payload == nil || admission.RequestID.IsZero() || admission.RequestID != payload.RequestIdentity {
			t.Fatal("admitted projection lost its custody/result identity", failed)
		}
		return admission, payload
	}
	baseline, baselinePayload := admit(t, &selected)
	t.Run("same admitted image", func(t *testing.T) {
		again, payload := admit(t, &selected)
		if again.RequestID != baseline.RequestID || payload.RequestIdentity != baselinePayload.RequestIdentity {
			t.Fatal("random custody session changed the fixed projection identity")
		}
	})
	// This fixture enters after public authentication. Change one admitted
	// coordinate at a time while keeping request, trust, target and lifetime fixed.
	for _, condition := range []string{"HEAD revision", "Snapshot", "entry incarnation", "value state", "resolved implicit Recipient"} {
		t.Run(condition, func(t *testing.T) {
			image := selected
			switch condition {
			case "HEAD revision":
				image.basis.anchor.head.Core.Revision = contract.ID{83}
			case "Snapshot":
				image.image.root.Snapshot = contract.ID{84}
				image.basis.anchor.head.Core.Root.Object = image.image.root.Snapshot
			case "entry incarnation", "value state":
				page := *image.image.pages[0]
				entry := *page.Slots[1]
				if condition == "entry incarnation" {
					entry.Incarnation = contract.ID{85}
				} else {
					entry.ValueState = contract.ID{86}
				}
				page.Slots[1] = &entry
				image.image.pages[0] = &page
			case "resolved implicit Recipient":
				acting := contract.ID{87}
				image.authorityID = acting
				image.image.root.CurrentAccess.Core.AuthorityRecipientID = acting
				recipients := *image.image.recipients[0]
				recipient := *recipients.Slots[0]
				recipient.RecipientID = acting
				recipients.Slots[0] = &recipient
				image.image.recipients[0] = &recipients
				page := *image.image.pages[0]
				for slot := 0; slot < 2; slot++ {
					entry := *page.Slots[slot]
					entry.Recipients = []contract.ID{acting}
					page.Slots[slot] = &entry
				}
				image.image.pages[0] = &page
			}
			admission, payload := admit(t, &image)
			if condition == "resolved implicit Recipient" && (admission.Recipient.SubjectID != image.authorityID || payload.Recipient.SubjectID != image.authorityID) {
				t.Fatal("implicit actor was not resolved before identity derivation")
			}
			if admission.RequestID == baseline.RequestID || payload.RequestIdentity == baselinePayload.RequestIdentity {
				t.Fatal("distinct admitted projection reused the preselection identity")
			}
		})
	}
	t.Run("installed custody and public result", func(t *testing.T) {
		i, _, _, _ := materializationPublicInput(t)
		request := contract.MaterializationRequest{RequestNonce: contract.ID{88}, Names: []string{"plain"}}
		invoke := func() (MaterializationResult, contract.MaterializationAdmission) {
			var admission contract.MaterializationAdmission
			private := &materializationPrivateProbe{run: func(context.Context) contract.MaterializationCompletion {
				return contract.MaterializationCompletion{StateResult: contract.MaterializationSuccess, Facts: contract.MaterializationFacts{Replacement: contract.MaterializationReplaced, CandidateVerification: contract.MaterializationVerified, InstalledVerification: contract.MaterializationVerified, NativeCompletion: contract.MaterializationComplete, Disclosure: contract.MaterializationDisclosureOccurred, Cleanup: contract.MaterializationCandidateRenamed}}
			}}
			i.AdmitCustody = func(_ context.Context, captured contract.MaterializationAdmission) (MaterializationCustody, error) {
				admission = captured
				return private, nil
			}
			installed, err := NewInstalledMaterialization(i)
			if err != nil {
				t.Fatal(err)
			}
			defer installed.Close()
			result := installed.Materialize(ctx, request)
			if result.StateResult != contract.MaterializationSuccess || result.Validate() != nil || result.Payload == nil || private.closed != 1 {
				t.Fatal("authentic installed projection did not complete", result.StateResult, result.Failure)
			}
			if result.RequestIdentity.IsZero() || result.OperationID.IsZero() || result.RequestIdentity != admission.RequestID || result.Payload.RequestIdentity != admission.RequestID || admission.ExpiresAt != mustMaterializationDeadline(ctx) {
				t.Fatal("custody, payload and operation lost the same admitted identity/lifetime")
			}
			return result, admission
		}
		first, firstAdmission := invoke()
		again, againAdmission := invoke()
		if first.RequestIdentity != again.RequestIdentity || first.OperationID != again.OperationID || firstAdmission.HEADRevision != againAdmission.HEADRevision || firstAdmission.SnapshotID != againAdmission.SnapshotID || !reflect.DeepEqual(firstAdmission.Recipient, againAdmission.Recipient) {
			t.Fatal("same authenticated installed projection changed identity or observation")
		}
	})
}
