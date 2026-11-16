package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/compositions/outputhost"
	"enkv.sh/core/contract"
	primitive "enkv.sh/crypto/internal/custody"
	protocol "enkv.sh/sdk/protocols/output"
)

type publicationFacadeOwner struct {
	*PublicationCustody
	route contract.ID
}

func (o *publicationFacadeOwner) Prepare(ctx context.Context, id contract.ID, selected *contract.ConsumerSelection) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	var route contract.ID
	if selected != nil && selected.Entry.ConfidentialityClass == contract.Secret {
		route = o.route
	}
	return o.PublicationCustody.Prepare(ctx, id, selected, route)
}

type publicationFacadeKeys struct {
	runtime *Runtime
	route   *consumerTestRoute
	routeID contract.ID
	binding contract.BindingTableRow
}

func newPublicationFacadeKeys(t *testing.T, secret bool) *publicationFacadeKeys {
	t.Helper()
	f := &publicationFacadeKeys{}
	var routes []KeyAccess
	if secret {
		selection, route := consumerFixture(t)
		f.route = route
		f.routeID = route.CredentialRoute()
		f.binding = selection.Binding
		f.binding.SubjectID = publicationFixtureID("actor")
		routes = append(routes, route)
	}
	runtime, err := New(contract.GCP, routes)
	if err != nil {
		t.Fatal(err)
	}
	f.runtime = runtime
	t.Cleanup(runtime.Close)
	return f
}
func (f *publicationFacadeKeys) Bindings() []contract.BindingTableRow {
	return []contract.BindingTableRow{f.binding}
}
func (f *publicationFacadeKeys) Calls() (int, int) {
	if f.route == nil {
		return 0, 0
	}
	f.route.mu.Lock()
	defer f.route.mu.Unlock()
	return f.route.publicCalls, f.route.privateCalls
}

func publicationFixtureID(s string) contract.ID {
	return contract.Hash([]byte("publication facade/" + s))
}

// full_only: false
func TestPublicationCustodyRefusesMissingInstallation(t *testing.T) {
	f := newPublicationFacadeKeys(t, false)
	for _, tc := range []struct {
		name   string
		native *outputhost.Native
	}{{"nil", nil}, {"zero", &outputhost.Native{}}} {
		t.Run(tc.name, func(t *testing.T) {
			owner, err := NewPublicationCustody(context.Background(), f.runtime, PublicationCustodyInput{
				Native: tc.native, Deadline: time.Now().Add(time.Minute),
			})
			if owner != nil || !errors.Is(err, ErrAdmission) {
				t.Fatalf("missing installation: owner=%v error=%v", owner != nil, err)
			}
		})
	}
}

func publicationFacadeFixture(t *testing.T, kind string, encodings ...string) (*publicationFacadeOwner, *contract.ConsumerSelection, contract.PublicationDispatch, []byte, *publicationFacadeKeys) {
	t.Helper()
	id := publicationFixtureID
	f := newPublicationFacadeKeys(t, kind == "secret")
	var selected *contract.ConsumerSelection
	var expected []byte
	action := contract.PublicationCreateWithValue
	if kind == "metadata" {
		action = contract.PublicationCreateEmpty
	} else {
		expected = []byte("fixed-value")
		if kind == "empty" {
			expected = []byte{}
		}
		entry := contract.ValueEntry{Name: "selected", Incarnation: id("entry"), ValueState: id("value"), OriginSnapshot: id("origin"), OriginTransition: id("transition"), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{id("actor")}, ValueBytes: slices.Clone(expected), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len(slices.Clone(expected))), RetainedLength: uint32(len(slices.Clone(expected)))}
		selected = &contract.ConsumerSelection{DomainID: id("domain"), Slot: 3, Entry: entry}
		if kind == "secret" {
			selected.Entry.ConfidentialityClass = contract.Secret
			core := contract.ValueCore{ValueSource: 1, Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: id("domain"), Name: entry.Name, EntryIncarnationID: entry.Incarnation, ValueStateID: entry.ValueState, OriginSnapshotID: entry.OriginSnapshot, OriginTransitionID: entry.OriginTransition, DataKeyID: id("data"), DataKeyEpoch: 1, CommitmentKeyID: id("commitment"), CommitmentKeyEpoch: 1, ContentLength: uint32(len(expected)), InputEncoding: contract.InputEncodingRaw, RetainedLength: uint32(len(expected))}
			payload, keys, err := primitive.SealValue(core, expected)
			if err != nil {
				t.Fatal(err)
			}
			binding := f.Bindings()[0]
			wrapCore, err := primitive.ValueWrapCore(core, binding)
			if err != nil {
				t.Fatal(err)
			}
			wrap, err := primitive.Wrap(wrapCore, binding.Binding, keys)
			clear(keys)
			if err != nil {
				t.Fatal(err)
			}
			material, err := contract.ValueMaterialContextDigest(core)
			if err != nil {
				t.Fatal(err)
			}
			selected.Core, selected.Payload, selected.Binding = core, payload, binding
			selected.Access = contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: 1, MaterialID: core.ValueStateID, MaterialContextDigest: material, PackageCheck: payload.PackageCheck, Wraps: []contract.WrapRow{wrap}}
			selected.Entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			selected.SnapshotID, selected.HEADDigest, selected.AccessRoot = id("snapshot"), id("head"), id("root")
			selected.Root = contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: core.DomainID, Object: selected.SnapshotID, Digest: id("root digest"), Length: 1}
			selected.HEADRevision = id("revision")
			selected.HEADToken = contract.Token{Family: contract.GCP, Value: "1"}
		}
	}
	target := contract.OutputTarget{EntryIncarnationID: id("entry"), ServiceContractID: "test-output", CanonicalTarget: "planned", ConsumerLocator: "consumer", TargetContractID: "test-output/target/v1", TargetData: []byte("single"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{ContractID: "test-policy", Data: []byte("1,9")}}
	if len(encodings) != 0 {
		target.PayloadEncoding = publicationTestEncoding(encodings[0])
	}
	if selected != nil {
		selected.Entry.OutputEncoding = target.PayloadEncoding
		var err error
		selected.EntryDigest, err = contract.PublicValueEntryDigest(selected.DomainID, selected.Slot, selected.Entry)
		if err != nil {
			t.Fatal(err)
		}
	}
	a := outputhost.Artifact{ProtocolID: protocol.ProtocolID(), DescriptorID: protocol.ID(id("descriptor")), ConfigContractID: "config/v1", CredentialRouteContractID: "route/v1", ArtifactContractID: protocol.ID(id("artifact")), ExecutorID: protocol.ID(id("executor")), CredentialRouteID: protocol.ID(id("output route"))}
	coordinate, err := contract.PublicationCoordinateID(id("domain"), target.ServiceContractID, target.CanonicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	row, err := contract.PublicationTargetRowDigest(id("domain"), "destination", id("binding"), target)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := contract.OutputPolicyDigest(id("domain"), target.Policy)
	if err != nil {
		t.Fatal(err)
	}
	configDigest, err := contract.OutputConfigContractDigest("config/v1")
	if err != nil {
		t.Fatal(err)
	}
	request, err := contract.PublicationRequestContractDigest(contract.ID(a.ProtocolID), configDigest, target.ServiceContractID, target.TargetContractID, action)
	if err != nil {
		t.Fatal(err)
	}
	p := contract.PublicationProjection{Schema: 4, DomainID: id("domain"), ConfigurationDigest: id("configuration"), CoordinateID: coordinate, BindingIncarnationID: id("binding"), EntryIncarnationID: target.EntryIncarnationID, TargetRowDigest: row, Action: action, PolicyDigest: policy, RequestContractDigest: request, ActingRecipientID: id("actor")}
	if selected != nil {
		commitment, contentLength := selected.EntryDigest, selected.Entry.ContentLength
		if kind == "secret" {
			commitment, contentLength = selected.Payload.SemanticCommitment, selected.Payload.ContentLength
		}
		p.ValueBasisDigest, err = contract.PublicationValueBasisDigest(p.DomainID, "destination", p.BindingIncarnationID, target, contract.PublicationValueBasis{EntryIncarnationID: target.EntryIncarnationID, ValueStateID: selected.Entry.ValueState, ContentLength: contentLength, InputEncoding: selected.Entry.InputEncoding, RetainedLength: selected.Entry.RetainedLength, ConfidentialityClass: selected.Entry.ConfidentialityClass, SemanticCommitment: commitment})
		if err != nil {
			t.Fatal(err)
		}
	}
	fork, err := f.runtime.Fork()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	sink := &publicationNativeSink{id: contract.ID(a.ExecutorID), artifact: a, projection: p, target: target, destination: "destination", configContractID: "config/v1", deadline: deadline}
	owner := &publicationFacadeOwner{PublicationCustody: &PublicationCustody{runtime: fork, sink: sink, projection: p, destination: "destination", target: target, deadline: deadline, maximum: 65536}, route: f.routeID}
	if selected == nil {
		owner.maximum = 0
	}
	t.Cleanup(func() { _ = owner.Retire(context.Background()) })
	projection, err := contract.PublicationProjectionCommitment(p)
	if err != nil {
		t.Fatal(err)
	}
	response, err := contract.PublicationResponseContractDigest(request, contract.ID(a.ArtifactContractID))
	if err != nil {
		t.Fatal(err)
	}
	dispatch := contract.PublicationDispatch{Schema: 5, DomainID: p.DomainID, OperationID: id("operation"), AttemptID: id("attempt"), CoordinateID: coordinate, Projection: p, ProjectionCommitment: projection, AuthoritySubjectDigest: id("authority subject"), ExecutorID: publicationIDLabel(a.ExecutorID), CredentialRouteID: publicationIDLabel(a.CredentialRouteID), ResponseContractDigest: response}
	return owner, selected, dispatch, expected, f
}

func publicationWireAck(command protocol.Command) protocol.Result {
	result := command.NewResult()
	result.Entry, result.Class, result.NormalizedStatus = 2, 1, 200
	result.SafeRequestID, result.SafeResourceID = "request", "resource"
	if command.Action == protocol.ActionCreateEmpty || command.Action == protocol.ActionCreateWithValue {
		result.ConsumerLocator = command.Target.ConsumerLocator
	}
	return result
}

// full_only: false
func TestPublicationFacadeSelectedValueLifetimes(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			for _, kind := range []string{"plain", "empty", "secret", "metadata"} {
				t.Run(kind, func(t *testing.T) {
					o, selected, dispatch, expected, f := publicationFacadeFixture(t, kind, encoding)
					original := slices.Clone(expected)
					var stored []byte
					if selected != nil {
						stored = slices.Clone(selected.Entry.ValueBytes)
					}
					if encoding == "base64" && kind != "empty" && kind != "metadata" {
						expected = []byte("Zml4ZWQtdmFsdWU=")
					}
					q, _, err := publicationActionCheckRequest(o.projection.DomainID, o.projection.Action, o.target,
						o.sink.coordinate, nil, nil, contract.ID{}, uint32(len(expected)), o.deadline, o.sink.artifact)
					if err != nil || q.PayloadLength != uint32(len(expected)) || (kind == "metadata") != (q.PayloadLengthMode == protocol.LengthAbsent) {
						t.Fatal("passive request did not carry the exact encoded count", err)
					}
					if o.InstanceID().IsZero() || o.InstanceID() == f.runtime.InstanceID() {
						t.Fatal("publication reused the parent instance")
					}
					calls := 0
					o.sink.dispatchCall = func(ctx context.Context, q protocol.Command, p protocol.Policy, payload []byte) (protocol.Result, error) {
						calls++
						if !bytes.Equal(payload, expected) || (kind == "metadata") != (payload == nil) {
							t.Fatal("payload union or bytes changed")
						}
						if encoding == "base64" && kind != "metadata" {
							decoded, err := base64.StdEncoding.DecodeString(string(payload))
							if err != nil || !bytes.Equal(decoded, original) {
								t.Fatal("consumer did not obtain the original value", err)
							}
						}
						if q.PayloadLength != uint32(len(expected)) || (kind == "metadata") != (q.PayloadLengthMode == protocol.LengthAbsent) || q.CredentialRouteID != o.sink.artifact.CredentialRouteID || p.ContractID != "test-policy" {
							t.Fatal("command or policy changed")
						}
						return publicationWireAck(q), nil
					}
					admission := publicationFixtureID("admission")
					uses, code := o.Prepare(context.Background(), admission, selected)
					if code != contract.CryptoSuccess || o.payloadLength != uint32(len(expected)) {
						t.Fatalf("prepare code=%v", code)
					}
					public, private := f.Calls()
					wantPrivate := 0
					if kind == "secret" {
						wantPrivate = 1
					}
					if public != 0 || private != wantPrivate || len(uses) != wantPrivate {
						t.Fatalf("key calls public=%d private=%d uses=%d", public, private, len(uses))
					}
					if selected != nil {
						if !bytes.Equal(selected.Entry.ValueBytes, stored) || kind == "secret" && selected.Payload.ContentLength != 11 {
							t.Fatal("preparation changed the stored value or raw count")
						}
						clear(selected.Entry.ValueBytes)
						selected.Entry = contract.ValueEntry{}
					}
					if err := o.Arm(context.Background(), admission, dispatch); err != nil {
						t.Fatal(err)
					}
					result, code := o.Send(context.Background(), admission)
					if code != contract.CryptoSuccess || calls != 1 || result.Evidence != (contract.PublicationEvidence{Schema: 3, Entry: 2, Class: 1, ResponseContractDigest: dispatch.ResponseContractDigest, NormalizedStatus: 200, SafeRequestID: "request", SafeResourceID: "resource", ConsumerLocator: o.target.ConsumerLocator}) || contract.ValidatePublicationResult(dispatch, result) != nil {
						t.Fatalf("send code=%v calls=%d result=%+v", code, calls, result)
					}
					if _, code := o.Send(context.Background(), admission); code == contract.CryptoSuccess || calls != 1 {
						t.Fatal("second send entered")
					}
					if err := o.Retire(context.Background()); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
	for _, kind := range []string{"plain", "secret"} {
		t.Run("encoded-capacity/"+kind, func(t *testing.T) {
			o, selected, _, _, f := publicationFacadeFixture(t, kind, "base64")
			raw := make([]byte, 49153)
			var value publicationSelectedValue
			if kind == "secret" {
				*selected = publicationSecretValueFixture(t, *selected, raw)
				value.Secret = selected
			} else {
				selected.Entry.ValueBytes = raw
				selected.Entry.ContentLength, selected.Entry.RetainedLength = uint32(len(raw)), uint32(len(raw))
				var err error
				selected.EntryDigest, err = contract.PublicValueEntryDigest(selected.DomainID, selected.Slot, selected.Entry)
				if err != nil {
					t.Fatal(err)
				}
				value.Plain = &publicationPlainSelection{Slot: selected.Slot, EntryDigest: selected.EntryDigest, Entry: selected.Entry}
			}
			o.projection, o.target = publicationEncodingFixture(t, o.projection, o.destination, o.target, &value, "base64")
			o.sink.projection, o.sink.target = o.projection, o.target
			publicBefore, privateBefore := f.Calls()
			uses, code := o.Prepare(context.Background(), publicationFixtureID("admission"), selected)
			public, private := f.Calls()
			if code != contract.CryptoCapacityExceeded || len(uses) != 0 || public != publicBefore || private != privateBefore || o.prepared {
				t.Fatalf("encoded overflow entered private work: code=%v public=%d private=%d uses=%d prepared=%t", code, public-publicBefore, private-privateBefore, len(uses), o.prepared)
			}
		})
	}
	t.Run("invalid-payload-encoding", func(t *testing.T) {
		o, selected, _, _, f := publicationFacadeFixture(t, "secret")
		o.target.PayloadEncoding = 0
		publicBefore, privateBefore := f.Calls()
		uses, code := o.Prepare(context.Background(), publicationFixtureID("admission"), selected)
		public, private := f.Calls()
		if code != contract.CryptoInvalidAdmission || len(uses) != 0 || public != publicBefore || private != privateBefore || o.prepared {
			t.Fatal("invalid encoding acquired payload custody", code)
		}
	})
}

// full_only: false
func TestPublicationFacadeRejectsCompleteResultDamage(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			for _, field := range []string{"schema", "domain", "operation", "attempt", "coordinate", "projection", "dispatch", "response", "class"} {
				t.Run(field, func(t *testing.T) {
					o, selected, dispatch, _, _ := publicationFacadeFixture(t, "plain", encoding)
					o.sink.dispatchCall = func(_ context.Context, q protocol.Command, _ protocol.Policy, _ []byte) (protocol.Result, error) {
						result := publicationWireAck(q)
						switch field {
						case "schema":
							result.Schema++
						case "domain":
							result.DomainID[0] ^= 1
						case "operation":
							result.OperationID[0] ^= 1
						case "attempt":
							result.AttemptID[0] ^= 1
						case "coordinate":
							result.CoordinateID[0] ^= 1
						case "projection":
							result.ProjectionCommitment[0] ^= 1
						case "dispatch":
							result.DispatchContextDigest[0] ^= 1
						case "response":
							result.ResponseContractDigest[0] ^= 1
						case "class":
							result.Class = 0
						}
						return result, nil
					}
					admission := publicationFixtureID("admission")
					if _, code := o.Prepare(context.Background(), admission, selected); code != contract.CryptoSuccess {
						t.Fatal(code)
					}
					if err := o.Arm(context.Background(), admission, dispatch); err != nil {
						t.Fatal(err)
					}
					result, code := o.Send(context.Background(), admission)
					if code != contract.CryptoResponseUnknown || result != (contract.PublicationResult{}) {
						t.Fatalf("unchecked result accepted: code=%v", code)
					}
					if _, valid := o.sink.result(); valid {
						t.Fatal("invalid wire result retained as valid")
					}
					if err := o.Retire(context.Background()); err == nil {
						t.Fatal("dispatch failure suppressed by retirement")
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicationFacadeDispatchPinsCannotChange(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			for _, field := range []string{"executor", "route", "response", "projection", "encoding"} {
				t.Run(field, func(t *testing.T) {
					o, selected, dispatch, _, _ := publicationFacadeFixture(t, "plain", encoding)
					calls := 0
					o.sink.dispatchCall = func(_ context.Context, q protocol.Command, _ protocol.Policy, _ []byte) (protocol.Result, error) {
						calls++
						return publicationWireAck(q), nil
					}
					admission := publicationFixtureID("admission")
					if _, code := o.Prepare(context.Background(), admission, selected); code != contract.CryptoSuccess {
						t.Fatal(code)
					}
					switch field {
					case "executor":
						dispatch.ExecutorID = "changed"
					case "route":
						dispatch.CredentialRouteID = "changed"
					case "response":
						dispatch.ResponseContractDigest[0] ^= 1
					case "encoding":
						target := o.target
						if target.PayloadEncoding == contract.OutputEncodingRaw {
							target.PayloadEncoding = contract.OutputEncodingBase64
						} else {
							target.PayloadEncoding = contract.OutputEncodingRaw
						}
						var err error
						dispatch.Projection.TargetRowDigest, err = contract.PublicationTargetRowDigest(dispatch.DomainID, o.destination, dispatch.Projection.BindingIncarnationID, target)
						if err != nil {
							t.Fatal(err)
						}
						dispatch.ProjectionCommitment, err = contract.PublicationProjectionCommitment(dispatch.Projection)
						if err != nil {
							t.Fatal(err)
						}
					case "projection":
						dispatch.Projection.ConfigurationDigest[0] ^= 1
					}
					if err := o.Arm(context.Background(), admission, dispatch); err == nil {
						t.Fatal("changed dispatch armed")
					}
					if _, code := o.Send(context.Background(), admission); code == contract.CryptoSuccess || calls != 0 {
						t.Fatal("changed dispatch entered")
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicationNativeSinkCloseBeforeSendBarsEntry(t *testing.T) {
	o, selected, dispatch, _, _ := publicationFacadeFixture(t, "plain")
	var calls atomic.Int32
	o.sink.dispatchCall = func(_ context.Context, q protocol.Command, _ protocol.Policy, _ []byte) (protocol.Result, error) {
		calls.Add(1)
		return publicationWireAck(q), nil
	}
	admission := publicationFixtureID("admission")
	if _, code := o.Prepare(context.Background(), admission, selected); code != contract.CryptoSuccess {
		t.Fatal(code)
	}
	if err := o.Arm(context.Background(), admission, dispatch); err != nil {
		t.Fatal(err)
	}
	if err := o.sink.Close(); err != nil {
		t.Fatal(err)
	}
	if _, code := o.Send(context.Background(), admission); code == contract.CryptoSuccess || calls.Load() != 0 {
		t.Fatal("closed sink entered")
	}
}

// full_only: false
func TestPublicationNativeSinkRejectsPayloadLengthAndPresenceBeforeEntry(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			for _, kind := range []string{"plain", "empty", "metadata"} {
				t.Run(kind, func(t *testing.T) {
					o, selected, dispatch, expected, _ := publicationFacadeFixture(t, kind, encoding)
					if encoding == "base64" && kind == "plain" {
						expected = []byte("Zml4ZWQtdmFsdWU=")
					}
					calls := 0
					o.sink.dispatchCall = func(_ context.Context, q protocol.Command, _ protocol.Policy, payload []byte) (protocol.Result, error) {
						calls++
						if !bytes.Equal(payload, expected) || (kind == "metadata") != (payload == nil) {
							t.Fatal("valid send did not retain the exact payload union")
						}
						return publicationWireAck(q), nil
					}
					admission := publicationFixtureID("admission")
					if _, code := o.Prepare(context.Background(), admission, selected); code != contract.CryptoSuccess {
						t.Fatal(code)
					}
					if err := o.Arm(context.Background(), admission, dispatch); err != nil {
						t.Fatal(err)
					}
					wrong := []byte{}
					if kind != "metadata" {
						wrong = nil
					}
					for _, payload := range [][]byte{wrong, make([]byte, len(expected)+1)} {
						if _, err := o.sink.Send(context.Background(), dispatch, payload); !errors.Is(err, ErrAdmission) || calls != 0 {
							t.Fatal("mismatched payload entered the dispatcher", err)
						}
					}
					if _, code := o.Send(context.Background(), admission); code != contract.CryptoSuccess || calls != 1 {
						t.Fatal("a refused borrowed payload consumed valid custody", code)
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicationFacadeRetireCancelsAndJoinsSend(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				o, selected, dispatch, _, _ := publicationFacadeFixture(t, "plain", encoding)
				entered, joined := make(chan struct{}), make(chan struct{})
				o.sink.dispatchCall = func(ctx context.Context, _ protocol.Command, _ protocol.Policy, _ []byte) (protocol.Result, error) {
					close(entered)
					<-ctx.Done()
					defer close(joined)
					return protocol.Result{}, ctx.Err()
				}
				admission := publicationFixtureID("admission")
				if _, code := o.Prepare(context.Background(), admission, selected); code != contract.CryptoSuccess {
					t.Fatal(code)
				}
				if err := o.Arm(context.Background(), admission, dispatch); err != nil {
					t.Fatal(err)
				}
				sent := make(chan contract.CryptoResultCode, 1)
				go func() { _, code := o.Send(context.Background(), admission); sent <- code }()
				<-entered
				expired, cancel := context.WithCancel(context.Background())
				cancel()
				err := o.Retire(expired)
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("retire lost dispatch cancellation: %v", err)
				}
				<-joined
				if code := <-sent; code != contract.CryptoCancelled {
					t.Fatalf("send after retire code=%v", code)
				}
				if err := o.Retire(context.Background()); !errors.Is(err, context.Canceled) {
					t.Fatal("repeat retirement changed error")
				}
			})
		})
	}
}

// full_only: false
func TestPublicationNativeSinkConcurrentCloseJoins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o, selected, dispatch, expected, _ := publicationFacadeFixture(t, "plain")
		entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
		o.sink.dispatchCall = func(ctx context.Context, q protocol.Command, _ protocol.Policy, _ []byte) (protocol.Result, error) {
			close(entered)
			<-ctx.Done()
			<-release
			close(joined)
			return publicationWireAck(q), nil
		}
		if err := o.sink.pinDispatch(dispatch, uint32(len(expected))); err != nil {
			t.Fatal(err)
		}
		_ = selected
		sent := make(chan error, 1)
		go func() { _, err := o.sink.Send(context.Background(), dispatch, expected); sent <- err }()
		<-entered
		closed := make(chan error, 2)
		go func() { closed <- o.sink.Close() }()
		go func() { closed <- o.sink.Close() }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("Close returned before dispatch join")
		default:
		}
		close(release)
		<-joined
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := <-closed; err != nil {
				t.Fatal(err)
			}
		}
	})
}

// full_only: false
func TestPublicationNativeSinkCancellationCallbackCloseJoins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		o, _, dispatch, expected, _ := publicationFacadeFixture(t, "plain")
		entered, joined := make(chan struct{}), make(chan struct{})
		o.sink.dispatchCall = func(ctx context.Context, _ protocol.Command, _ protocol.Policy, _ []byte) (protocol.Result, error) {
			close(entered)
			<-ctx.Done()
			close(joined)
			return protocol.Result{}, ctx.Err()
		}
		if err := o.sink.pinDispatch(dispatch, uint32(len(expected))); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		closed := make(chan error, 1)
		context.AfterFunc(ctx, func() { closed <- o.sink.Close() })
		sent := make(chan error, 1)
		go func() { _, err := o.sink.Send(ctx, dispatch, expected); sent <- err }()
		<-entered
		cancel()
		<-joined
		if err := <-sent; !errors.Is(err, context.Canceled) {
			t.Fatal("send cancellation lost", err)
		}
		if err := <-closed; !errors.Is(err, context.Canceled) {
			t.Fatal("Close callback did not join", err)
		}
	})
}

// full_only: false
func TestPublicationProfileRequestsUseQualifiedBirth(t *testing.T) {
	o, _, dispatch, _, _ := publicationFacadeFixture(t, "plain")
	birth := contract.PublicationMarker{Schema: 5, DomainID: dispatch.DomainID, CoordinateID: dispatch.CoordinateID, AttemptID: dispatch.AttemptID, Projection: dispatch.Projection, State: contract.PublicationAcknowledged, Evidence: contract.PublicationEvidence{Schema: 3, Entry: 2, Class: 1, ResponseContractDigest: dispatch.ResponseContractDigest, NormalizedStatus: 200, SafeResourceID: "resource", ConsumerLocator: o.target.ConsumerLocator}}
	coordinate := contract.PublicationCoordinate{DomainID: dispatch.DomainID, CoordinateID: dispatch.CoordinateID, ServiceContractID: o.target.ServiceContractID, CanonicalTarget: o.target.CanonicalTarget, OwnerState: contract.PublicationOwnerQualified, OwnedBirthAttemptID: birth.AttemptID}
	birth.BirthServiceContractID, birth.BirthTargetContractID = o.target.ServiceContractID, o.target.TargetContractID
	birth.OperationID, birth.PublicationIncarnationID, birth.AdmissionOrdinal = dispatch.OperationID, publicationFixtureID("publication incarnation"), 1
	birth.ProjectionCommitment = dispatch.ProjectionCommitment
	birth.AuthoritySubjectDigest = dispatch.AuthoritySubjectDigest
	birth.ExecutorID, birth.CredentialRouteID = dispatch.ExecutorID, dispatch.CredentialRouteID
	coordinate.Schema, coordinate.BindingState, coordinate.ActiveBindingIncarnationID = 5, contract.PublicationBindingActive, dispatch.Projection.BindingIncarnationID
	coordinate.CurrentPublicationIncarnationID, coordinate.LastAdmissionOrdinal, coordinate.PossibleRemoteObject = birth.PublicationIncarnationID, 1, 1
	coordinate.DeletionDestinationID = o.destination

	coordinate.LastBindingIncarnationID, coordinate.LastEntryIncarnationID = dispatch.Projection.BindingIncarnationID, dispatch.Projection.EntryIncarnationID
	coordinate.DeletionTargetRowDigest, coordinate.DeletionConsumerLocator = dispatch.Projection.TargetRowDigest, o.target.ConsumerLocator
	coordinate.DeletionTargetContractID, coordinate.DeletionConfigContractID, coordinate.DeletionCredentialRouteContractID = o.target.TargetContractID, o.sink.configContractID, "route/v1"
	coordinate.DeletionTargetData, coordinate.DeletionPayloadEncoding = o.target.TargetData, o.target.PayloadEncoding

	var err error
	coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(birth.DomainID, birth.CoordinateID, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []uint8{contract.PublicationWriteValue, contract.PublicationUpdatePolicy, contract.PublicationDeleteOwned} {
		t.Run(string(rune('0'+action)), func(t *testing.T) {
			raw := uint32(0)
			if action == contract.PublicationWriteValue {
				raw = 10
			}
			target := o.target
			if action == contract.PublicationDeleteOwned {
				target.Policy = contract.OutputPolicy{}
			}
			request, policy, err := publicationActionCheckRequest(dispatch.DomainID, action, target, coordinate, &birth, nil, contract.ID{}, raw, o.deadline, o.sink.artifact)
			if err != nil || request.OwnedInstance != "resource" || request.OwnedInstanceDigest != protocol.ID(coordinate.OwnedInstanceDigest) || request.OwnershipMode != protocol.OwnershipQualified || request.UncertainCreateAttemptID != (protocol.ID{}) {
				t.Fatalf("qualified request=%+v err=%v", request, err)
			}
			if action == contract.PublicationDeleteOwned && (policy.ContractID != "" || len(policy.Data) != 0 || !request.PolicyDigest.IsZero()) {
				t.Fatal("delete policy was not the explicit zero body")
			}
			if _, _, err := publicationActionCheckRequest(dispatch.DomainID, action, target, coordinate, nil, nil, contract.ID{}, raw, o.deadline, o.sink.artifact); err == nil {
				t.Fatal("owned action admitted without actual birth")
			}
			changed := birth
			changed.Evidence.SafeResourceID = "other"
			if _, _, err := publicationActionCheckRequest(dispatch.DomainID, action, target, coordinate, &changed, nil, contract.ID{}, raw, o.deadline, o.sink.artifact); err == nil {
				t.Fatal("changed birth admitted")
			}
			changed = birth
			changed.Evidence.ConsumerLocator = "other-consumer"
			if _, _, err := publicationActionCheckRequest(dispatch.DomainID, action, target, coordinate, &changed, nil, contract.ID{}, raw, o.deadline, o.sink.artifact); err == nil {
				t.Fatal("changed exact birth consumer locator admitted")
			}
		})
	}
	t.Run("older_assigned_birth_keeps_its_own_locator", func(t *testing.T) {
		target := o.target
		target.LocatorRequiresCreation, target.ConsumerLocator = true, ""
		retained, older := coordinate, birth
		retained.LocatorRequiresCreation = true
		retained.DeletionConsumerLocator = "later-assigned-consumer"
		retained.OwnedBirthAttemptID = publicationFixtureID("later birth")
		retained.OwnedInstanceDigest = publicationFixtureID("later owned instance")
		older.Evidence.ConsumerLocator = "original-assigned-consumer"
		var err error
		older.Projection.TargetRowDigest, err = contract.PublicationTargetRowDigest(dispatch.DomainID, o.destination, older.Projection.BindingIncarnationID, target)
		if err != nil {
			t.Fatal(err)
		}
		older.ProjectionCommitment, err = contract.PublicationProjectionCommitment(older.Projection)
		if err != nil {
			t.Fatal(err)
		}
		retained.DeletionTargetRowDigest = older.Projection.TargetRowDigest
		target.Policy = contract.OutputPolicy{}
		if _, _, err := publicationActionCheckRequest(dispatch.DomainID, contract.PublicationDeleteOwned, target, retained, &older, nil, contract.ID{}, 0, o.deadline, o.sink.artifact); err != nil {
			t.Fatal("older assigned birth was forced to use the later consumer locator", err)
		}
	})
}

func publicationFacadeDeletionFixture(t *testing.T, action uint8, encodings ...string) (*publicationFacadeOwner, contract.PublicationDispatch) {
	t.Helper()
	o, _, dispatch, _, _ := publicationFacadeFixture(t, "plain", encodings...)
	id := publicationFixtureID
	birth := contract.PublicationMarker{Schema: 5, DomainID: dispatch.DomainID, OperationID: dispatch.OperationID, AttemptID: dispatch.AttemptID, CoordinateID: dispatch.CoordinateID, PublicationIncarnationID: id("publication incarnation"), AdmissionOrdinal: 1, Projection: dispatch.Projection, ProjectionCommitment: dispatch.ProjectionCommitment, AuthoritySubjectDigest: dispatch.AuthoritySubjectDigest, ExecutorID: dispatch.ExecutorID, CredentialRouteID: dispatch.CredentialRouteID, State: contract.PublicationAcknowledged, Evidence: contract.PublicationEvidence{Schema: 3, Entry: 2, Class: 1, ResponseContractDigest: dispatch.ResponseContractDigest, NormalizedStatus: 201, SafeResourceID: "created resource", ConsumerLocator: o.target.ConsumerLocator}, BirthServiceContractID: o.target.ServiceContractID, BirthTargetContractID: o.target.TargetContractID}
	c := contract.PublicationCoordinate{Schema: 5, DomainID: dispatch.DomainID, CoordinateID: dispatch.CoordinateID, ServiceContractID: o.target.ServiceContractID, CanonicalTarget: o.target.CanonicalTarget, BindingState: contract.PublicationBindingRetired, OwnerState: contract.PublicationOwnerQualified, LastBindingIncarnationID: dispatch.Projection.BindingIncarnationID, LastEntryIncarnationID: dispatch.Projection.EntryIncarnationID, OwnedBirthAttemptID: birth.AttemptID, CurrentPublicationIncarnationID: birth.PublicationIncarnationID, LastAdmissionOrdinal: 1, PossibleRemoteObject: 1, DeletionDestinationID: o.destination, DeletionConsumerLocator: o.target.ConsumerLocator, DeletionTargetContractID: o.target.TargetContractID, DeletionConfigContractID: o.sink.configContractID, DeletionCredentialRouteContractID: "route/v1", DeletionTargetData: o.target.TargetData, DeletionPayloadEncoding: o.target.PayloadEncoding, DeletionTargetRowDigest: dispatch.Projection.TargetRowDigest}
	var err error
	c.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(birth.DomainID, birth.CoordinateID, birth.Projection.BindingIncarnationID, birth.Projection.EntryIncarnationID, birth.Projection.TargetRowDigest, birth.AttemptID, birth.Evidence.SafeResourceID)
	if err != nil {
		t.Fatal(err)
	}
	p := dispatch.Projection
	p.Action = action
	p.ValueBasisDigest, p.PolicyDigest = contract.ID{}, contract.ID{}
	deletion := &publicationDeletionSelection{Coordinate: c, Birth: &birth}
	if action == contract.PublicationDeleteReservedSlot {
		birth.State = contract.PublicationUnknown
		birth.Evidence = contract.PublicationEvidence{Schema: 3, Entry: 2, ResponseContractDigest: dispatch.ResponseContractDigest}
		c.OwnerState = contract.PublicationOwnerUncertainCreate
		c.OwnedBirthAttemptID, c.OwnedInstanceDigest = contract.ID{}, contract.ID{}
		c.LatestUnresolvedAttemptID = id("unrelated latest unresolved")
		p.UncertainCreateAttemptID, p.ExclusiveNamespaceDigest = birth.AttemptID, id("explicit namespace admission")
		deletion.Coordinate, deletion.Birth, deletion.UncertainCreate = c, nil, &birth
		o.sink.uncertainCreate = birth
	} else {
		p.OwnedBirthAttemptID = birth.AttemptID
		o.sink.birth = birth
	}
	configDigest, err := contract.OutputConfigContractDigest(o.sink.configContractID)
	if err != nil {
		t.Fatal(err)
	}
	p.RequestContractDigest, err = contract.PublicationRequestContractDigest(contract.ID(o.sink.artifact.ProtocolID), configDigest, o.target.ServiceContractID, o.target.TargetContractID, action)
	if err != nil {
		t.Fatal(err)
	}
	o.projection, o.deletion = p, deletion
	o.target.Policy = contract.OutputPolicy{}
	o.minimum, o.maximum = 0, 0
	o.sink.projection, o.sink.target, o.sink.coordinate = p, o.target, c
	dispatch.Projection = p
	dispatch.AttemptID = id("delete attempt")
	dispatch.ProjectionCommitment, err = contract.PublicationProjectionCommitment(p)
	if err != nil {
		t.Fatal(err)
	}
	dispatch.ResponseContractDigest, err = contract.PublicationResponseContractDigest(p.RequestContractDigest, contract.ID(o.sink.artifact.ArtifactContractID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.EncodePublicationCoordinate(c); err != nil {
		t.Fatal(err)
	}
	if _, err := contract.EncodePublicationMarker(birth); err != nil {
		t.Fatal(err)
	}
	return o, dispatch
}

// full_only: false
func TestPublicationFacadeRetiredDeletionUsesDistinctProofs(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			for _, action := range []uint8{contract.PublicationDeleteOwned, contract.PublicationDeleteReservedSlot} {
				t.Run(string(rune('0'+action)), func(t *testing.T) {
					o, dispatch := publicationFacadeDeletionFixture(t, action, encoding)
					birth, uncertain := o.deletion.Birth, o.deletion.UncertainCreate
					request, policy, err := publicationActionCheckRequest(dispatch.DomainID, action, o.target, o.sink.coordinate, birth, uncertain, dispatch.Projection.ExclusiveNamespaceDigest, 0, o.deadline, o.sink.artifact)
					if err != nil || policy.ContractID != "" || len(policy.Data) != 0 {
						t.Fatalf("retained deletion profile failed: %v", err)
					}
					if action == contract.PublicationDeleteReservedSlot && (request.UncertainCreateAttemptID != protocol.ID(uncertain.AttemptID) || request.UncertainCreateAttemptID == protocol.ID(o.sink.coordinate.LatestUnresolvedAttemptID) || request.ExclusiveNamespaceDigest != protocol.ID(dispatch.Projection.ExclusiveNamespaceDigest)) {
						t.Fatal("reserved delete replaced explicit proof with cache or ambient premise")
					}
					calls := 0
					o.sink.dispatchCall = func(_ context.Context, q protocol.Command, p protocol.Policy, payload []byte) (protocol.Result, error) {
						calls++
						if uint8(q.Action) != action || payload != nil || q.PayloadLengthMode != protocol.LengthAbsent || p.ContractID != "" || q.PolicyDigest != (protocol.ID{}) {
							t.Fatal("delete used a payload or policy")
						}
						if action == contract.PublicationDeleteOwned && (q.OwnedInstance != "created resource" || q.BirthTargetRowDigest != protocol.ID(o.deletion.Birth.Projection.TargetRowDigest)) {
							t.Fatal("delete replaced original birth target")
						}
						if action == contract.PublicationDeleteReservedSlot && (q.UncertainCreateAttemptID != protocol.ID(o.deletion.UncertainCreate.AttemptID) || q.ExclusiveNamespaceDigest != protocol.ID(dispatch.Projection.ExclusiveNamespaceDigest) || q.OwnedInstance != "" || !q.OwnedBirthAttemptID.IsZero()) {
							t.Fatal("reserved delete fabricated qualified birth")
						}
						return publicationWireAck(q), nil
					}
					admission := publicationFixtureID("delete admission")
					if uses, code := o.Prepare(context.Background(), admission, nil); code != contract.CryptoSuccess || len(uses) != 0 {
						t.Fatalf("delete prepare code=%v uses=%d", code, len(uses))
					}
					if err := o.Arm(context.Background(), admission, dispatch); err != nil {
						t.Fatal(err)
					}
					if result, code := o.Send(context.Background(), admission); code != contract.CryptoSuccess || calls != 1 || result.Evidence.Class != contract.PublicationRequestAcknowledged {
						t.Fatalf("delete send code=%v calls=%d", code, calls)
					}
					if err := o.Retire(context.Background()); err != nil {
						t.Fatal(err)
					}
					if action == contract.PublicationDeleteReservedSlot {
						if _, _, err := publicationActionCheckRequest(dispatch.DomainID, action, o.target, o.sink.coordinate, nil, nil, dispatch.Projection.ExclusiveNamespaceDigest, 0, o.deadline, o.sink.artifact); err == nil {
							t.Fatal("absent create proof admitted")
						}
						if _, _, err := publicationActionCheckRequest(dispatch.DomainID, action, o.target, o.sink.coordinate, nil, uncertain, contract.ID{}, 0, o.deadline, o.sink.artifact); err == nil {
							t.Fatal("absent namespace premise admitted")
						}
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicationFacadeReturnsDispatchCleanupFailure(t *testing.T) {
	o, selected, dispatch, _, _ := publicationFacadeFixture(t, "plain")
	cleanup := errors.New("controlled output cleanup failed")
	o.sink.dispatchCall = func(_ context.Context, q protocol.Command, _ protocol.Policy, _ []byte) (protocol.Result, error) {
		return publicationWireAck(q), cleanup
	}
	admission := publicationFixtureID("admission")
	if _, code := o.Prepare(context.Background(), admission, selected); code != contract.CryptoSuccess {
		t.Fatal(code)
	}
	if err := o.Arm(context.Background(), admission, dispatch); err != nil {
		t.Fatal(err)
	}
	if result, code := o.Send(context.Background(), admission); code != contract.CryptoResponseUnknown || result != (contract.PublicationResult{}) {
		t.Fatal("cleanup failure permitted an acknowledged result", code)
	}
	if err := o.Retire(context.Background()); !errors.Is(err, cleanup) {
		t.Fatal("cleanup failure not returned", err)
	}
}
