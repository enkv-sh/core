package custody

import (
	"context"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	trustfixture "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestApplyFacadeRefusesUnadmittedRequest(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	f := New(t, contract.GCP, id("apply fixture"), false, []contract.ID{id("authority")})
	if err := f.AdmitApply(contract.CryptoCompareRequest{}, contract.ControlCore{}, nil, nil, contract.DescriptorVector{}, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("empty request acquired private admission")
	}
	f.RetireApply()
}

func facadeApplyRequest(t *testing.T, f *Fixture) (contract.CryptoCompareRequest, contract.ControlCore, time.Time) {
	t.Helper()
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	signer := trustfixture.New(t, f.family, id("apply signer"))
	spki := signer.PublicKey()
	signing := contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: 1, Provider: f.family, SigningProfile: 1, BindingID: id("signing binding"), KeySelector: signer.KeySelector(), SPKI: spki, Fingerprint: contract.Hash(spki), Binding: contract.BindingSubject{Domain: id("domain"), Store: id("store"), Coordinate: id("coordinate"), Trust: id("trust"), PublicKey: contract.Hash(spki), Interpretation: id("interpretation"), ControlIncarnationID: id("signing incarnation"), Epoch: 1}}
	control := contract.ControlCore{CurrentControl: contract.CurrentControl{CurrentControlFields: contract.CurrentControlFields{Schema: contract.CanonicalSchema, Profile: 2, DomainID: id("domain"), Provider: f.family, StoreID: signing.Binding.Store, CoordinateID: signing.Binding.Coordinate, NonBodyID: id("nonbody"), TrustInterpretationID: signing.Binding.Interpretation, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), AuthorityRecipientID: f.authority, AccessIncarnationID: contract.DeriveAccessIncarnationID(id("domain"), signing.Binding.ControlIncarnationID), AccessGeneration: 1}, NormalSigning: signing}}
	var recipients []contract.ID
	for _, row := range f.Bindings() {
		if row.SubjectKind == 1 {
			recipients = append(recipients, row.SubjectID)
		}
		if row.SubjectID == f.authority {
			control.AuthorityKMSBinding = row.Binding
		}
		if row.SubjectKind == 2 {
			recoverySigning := signing
			recoverySigning.Role, recoverySigning.BindingID = 2, id("recovery signing binding")
			control.Recovery = &contract.RecoveryBindings{RoleID: row.SubjectID, Signing: recoverySigning, KMS: row.Binding}
		}
	}
	deadline := time.Now().Add(time.Minute)
	q := contract.CryptoCompareRequest{Context: contract.ApplyContext{OperationClass: contract.CryptoOrdinaryLifecycle, AdmissionID: id("apply admission"), SessionID: id("apply session"), DomainID: control.DomainID, CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), PredecessorHEADDigest: id("head digest"), OriginalConditionDigest: id("condition"), CurrentAccessRoot: id("access root")}, Bindings: f.Bindings()}
	root, err := contract.AppendRef(nil, contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: control.DomainID, Object: id("snapshot"), Digest: id("root digest"), Length: 1}, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(q.Context.PredecessorRootRef[:], root)
	for _, name := range []string{"first", "unused"} {
		core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: 4, Profile: 2, CompatibilityID: contract.CompatibilityID(), DomainID: control.DomainID, FileIdentity: id("source file"), FilePredecessorDigest: id("source predecessor"), SourceID: id(name + " source"), CryptoSupportID: contract.CryptoSupportID(), DataKeyID: id(name + " data key"), DataKeyEpoch: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: name}
		body, code := f.SealInput(context.Background(), core, recipients, StandardValue)
		if code != contract.CryptoSuccess {
			t.Fatalf("source sealing: %v", code)
		}
		if name == "unused" {
			continue
		}
		view, err := contract.InspectSealedInputEnvelope(body)
		if err != nil {
			t.Fatal(err)
		}
		preimage := append([]byte("ENKV/SEALED-INPUT/v1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(body)))...)
		preimage = append(preimage, body...)
		q.Intent = []contract.CryptoIntentRow{{Name: name, Recipients: recipients, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, ContentLength: view.Core.ContentLength, InputEncoding: view.Core.InputEncoding, RetainedLength: view.Core.RetainedLength, OutputEncoding: contract.OutputEncodingRaw, PayloadDigest: contract.Hash(preimage), PayloadLength: uint32(len(body))}}
		q.SealedInputs = []contract.CryptoSealedInput{{Name: name, EnvelopeBytes: body}}
	}
	for _, row := range f.Bindings() {
		if row.SubjectKind == contract.OrdinaryWrapSubject {
			binding := row.Binding
			q.Recipients = append(q.Recipients, contract.ApplyRecipientInput{Recipient: contract.RecipientRecord{RecipientID: row.SubjectID, Status: contract.CurrentRecipient, DisplayName: "current recipient", CurrentBinding: &binding}})
		}
	}
	q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(control.DomainID, q.Intent, q.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.EncodeCryptoCompareRequest(q); err != nil {
		t.Fatal(err)
	}
	return q, control, deadline
}

// full_only: false
func TestApplyFacadePinsProducerAndPrivateRuntime(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	for _, tc := range []struct{ recovery, live bool }{{}, {true, false}, {false, true}, {true, true}} {
		f := New(t, contract.GCP, id("apply fixture"), tc.recovery, []contract.ID{id("authority"), id("reader")})
		if tc.live {
			var routes []Route
			for _, row := range f.Bindings() {
				routes = append(routes, Route{BindingID: row.Binding.BindingID, PublicRoute: f.publicRoutes[row.Binding.BindingID], PrivateRoute: f.routes[row.Binding.BindingID]})
			}
			f = NewLive(t, f.Crypto(), f.authority, f.recovery, f.Bindings(), routes)
		}
		q, control, deadline := facadeApplyRequest(t, f)
		support, err := contract.EmptyRequiredSupportDescriptor(q.Context.DomainID)
		if err != nil {
			t.Fatal(err)
		}
		if public, private := f.Calls(); public != 0 || private != 0 {
			t.Fatalf("source sealing used an installed route (live=%t): %d/%d", tc.live, public, private)
		}
		fresh := New(t, contract.GCP, id("apply fixture"), tc.recovery, []contract.ID{id("authority"), id("reader")})
		if err := fresh.AdmitApply(q, control, facadeApplyRecipients(q), nil, support, deadline); err == nil {
			t.Fatal("source provenance granted authority in a different fixture")
		}
		changed := q
		changed.Bindings = f.Bindings()
		changed.Bindings[0].Binding.BindingSerial++
		if err := f.AdmitApply(changed, control, facadeApplyRecipients(q), nil, support, deadline); err == nil {
			t.Fatal("changed known binding accepted")
		}
		wrongControl := control
		wrongControl.AuthorityRecipientID = id("reader")
		if err := f.AdmitApply(q, wrongControl, facadeApplyRecipients(q), nil, support, deadline); err == nil {
			t.Fatal("changed authority accepted")
		}
		if err := f.AdmitApply(q, control, facadeApplyRecipients(q), nil, support, deadline); err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeCryptoCompareRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		call := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoCompare, RequestID: id("compare message"), CustodyInstanceID: f.Crypto().InstanceID(), Body: body}
		if got := fresh.Crypto().Exchange(context.Background(), call); got.ResultCode != contract.CryptoInvalidAdmission {
			t.Fatalf("wrong runtime accepted request: %v", got.ResultCode)
		}
		original := slices.Clone(q.SealedInputs[0].EnvelopeBytes)
		q.SealedInputs[0].EnvelopeBytes[0] ^= 1
		if got := f.Crypto().Exchange(context.Background(), call); got.ResultCode != contract.CryptoSuccess {
			t.Fatalf("admitted request was not owned: %v", got.ResultCode)
		}
		if public, private := f.Calls(); public != 0 || private != 1 {
			t.Fatalf("comparison route calls (live=%t): got %d/%d, want 0/1", tc.live, public, private)
		}
		q.SealedInputs[0].EnvelopeBytes = original
		if err := f.AdmitApply(q, control, facadeApplyRecipients(q), nil, support, deadline); err == nil {
			t.Fatal("active session was replaced")
		}
		instance := f.Crypto().InstanceID()
		f.RetireApply()
		if err := f.AdmitApply(q, control, facadeApplyRecipients(q), nil, support, deadline); err == nil {
			t.Fatal("retired admission was reused")
		}
		q.Context.AdmissionID, q.Context.SessionID = id("next admission"), id("next session")
		if err := f.AdmitApply(q, control, facadeApplyRecipients(q), nil, support, deadline); err != nil {
			t.Fatal(err)
		}
		if f.Crypto().InstanceID() != instance {
			t.Fatal("new admission replaced the runtime")
		}
		call.Body, err = contract.EncodeCryptoCompareRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.Crypto().Exchange(context.Background(), call); got.ResultCode != contract.CryptoSuccess {
			t.Fatalf("fresh session on same runtime: %v", got.ResultCode)
		}
		if public, private := f.Calls(); public != 0 || private != 2 {
			t.Fatalf("fresh comparison route calls (live=%t): got %d/%d, want 0/2", tc.live, public, private)
		}
		f.RetireApply()
	}
}

func facadeApplyRecipients(q contract.CryptoCompareRequest) []contract.RecipientRecord {
	rows := make([]contract.RecipientRecord, len(q.Recipients))
	for i, row := range q.Recipients {
		rows[i] = row.Recipient
	}
	return rows
}
