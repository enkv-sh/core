package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

const publicationFixtureDestination = "destination"

func publicationProjectionFixture(t *testing.T, domain, recipient contract.ID,
	selected *publicationSelectedValue, action uint8) (contract.PublicationProjection, string, contract.OutputTarget) {
	t.Helper()
	entry := consumerID("metadata entry")
	if selected != nil {
		if selected.Secret != nil {
			entry = selected.Secret.Entry.Incarnation
		} else if selected.Plain != nil {
			entry = selected.Plain.Entry.Incarnation
		}
	}
	target := contract.OutputTarget{EntryIncarnationID: entry, ServiceContractID: "fixture", CanonicalTarget: "physical",
		ConsumerLocator: "consumer", TargetContractID: "fixture", TargetData: []byte("single"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536},
		Policy: contract.OutputPolicy{ContractID: "fixture", Data: []byte("scope")}}
	coordinate, err := contract.PublicationCoordinateID(domain, target.ServiceContractID, target.CanonicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	row, err := contract.PublicationTargetRowDigest(domain, publicationFixtureDestination, consumerID("output binding"), target)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := contract.OutputPolicyDigest(domain, target.Policy)
	if err != nil {
		t.Fatal(err)
	}
	projection := contract.PublicationProjection{Schema: 4, DomainID: domain,
		ConfigurationDigest: consumerID("configuration"), CoordinateID: coordinate,
		BindingIncarnationID: consumerID("output binding"), EntryIncarnationID: entry, TargetRowDigest: row,
		Action: action, RequestContractDigest: consumerID("request contract"), ActingRecipientID: recipient}
	switch action {
	case contract.PublicationCreateEmpty, contract.PublicationCreateWithValue:
		projection.PolicyDigest = policy
	case contract.PublicationWriteValue, contract.PublicationUpdatePolicy:
		projection.PolicyDigest, projection.OwnedBirthAttemptID = policy, consumerID("owned birth")
	case contract.PublicationDeleteOwned:
		projection.OwnedBirthAttemptID = consumerID("owned birth")
	case contract.PublicationDeleteReservedSlot:
		projection.UncertainCreateAttemptID, projection.ExclusiveNamespaceDigest = consumerID("uncertain create"), consumerID("exclusive namespace")
	}
	if selected != nil {
		var value contract.PublicationValueBasis
		if selected.Secret != nil {
			s := selected.Secret
			value = contract.PublicationValueBasis{EntryIncarnationID: s.Entry.Incarnation, ValueStateID: s.Entry.ValueState,
				ContentLength: s.Payload.ContentLength, InputEncoding: s.Entry.InputEncoding, RetainedLength: s.Entry.RetainedLength, ConfidentialityClass: contract.Secret, SemanticCommitment: s.Payload.SemanticCommitment}
		} else if selected.Plain != nil {
			p := selected.Plain
			value = contract.PublicationValueBasis{EntryIncarnationID: p.Entry.Incarnation, ValueStateID: p.Entry.ValueState,
				ContentLength: p.Entry.ContentLength, InputEncoding: p.Entry.InputEncoding, RetainedLength: p.Entry.RetainedLength, ConfidentialityClass: contract.Plain, SemanticCommitment: p.EntryDigest}
		}
		projection.ValueBasisDigest, err = contract.PublicationValueBasisDigest(domain, publicationFixtureDestination,
			projection.BindingIncarnationID, target, value)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := contract.EncodePublicationProjection(projection); err != nil {
		t.Fatal(err)
	}
	return projection, publicationFixtureDestination, target
}

func publicationPlainFixture(t *testing.T, domain, recipient contract.ID) publicationSelectedValue {
	t.Helper()
	entry := contract.ValueEntry{Name: "public", Incarnation: consumerID("public incarnation"), ValueState: consumerID("public state"),
		OriginSnapshot: consumerID("public origin"), OriginTransition: consumerID("public transition"),
		ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{recipient}, ValueBytes: []byte("public-value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("public-value"))), RetainedLength: uint32(len([]byte("public-value")))}
	digest, err := contract.PublicValueEntryDigest(domain, 4, entry)
	if err != nil {
		t.Fatal(err)
	}
	return publicationSelectedValue{Plain: &publicationPlainSelection{Slot: 4, EntryDigest: digest, Entry: entry}}
}

func publicationEncodingFixture(t *testing.T, projection contract.PublicationProjection, destination string,
	target contract.OutputTarget, selected *publicationSelectedValue, encoding string) (contract.PublicationProjection, contract.OutputTarget) {
	t.Helper()

	target.PayloadEncoding = publicationTestEncoding(encoding)
	if selected != nil {
		if selected.Plain != nil {
			selected.Plain.Entry.OutputEncoding = target.PayloadEncoding
			digest, err := contract.PublicValueEntryDigest(projection.DomainID, selected.Plain.Slot, selected.Plain.Entry)
			if err != nil {
				t.Fatal(err)
			}
			selected.Plain.EntryDigest = digest
		} else {
			selected.Secret.Entry.OutputEncoding = target.PayloadEncoding
			refreshConsumerSelection(t, selected.Secret)
		}
	}
	var err error
	projection.TargetRowDigest, err = contract.PublicationTargetRowDigest(projection.DomainID, destination, projection.BindingIncarnationID, target)
	if err != nil {
		t.Fatal(err)
	}
	if selected != nil {
		var basis contract.PublicationValueBasis
		if selected.Plain != nil {
			p := selected.Plain
			basis = contract.PublicationValueBasis{EntryIncarnationID: p.Entry.Incarnation, ValueStateID: p.Entry.ValueState,
				ContentLength: p.Entry.ContentLength, InputEncoding: p.Entry.InputEncoding, RetainedLength: p.Entry.RetainedLength, ConfidentialityClass: contract.Plain, SemanticCommitment: p.EntryDigest}
		} else {
			s := selected.Secret
			basis = contract.PublicationValueBasis{EntryIncarnationID: s.Entry.Incarnation, ValueStateID: s.Entry.ValueState,
				ContentLength: s.Payload.ContentLength, InputEncoding: s.Entry.InputEncoding, RetainedLength: s.Entry.RetainedLength, ConfidentialityClass: contract.Secret, SemanticCommitment: s.Payload.SemanticCommitment}
		}
		projection.ValueBasisDigest, err = contract.PublicationValueBasisDigest(projection.DomainID, destination, projection.BindingIncarnationID, target, basis)
		if err != nil {
			t.Fatal(err)
		}
	}
	return projection, target
}

func publicationSecretValueFixture(t *testing.T, selected contract.ConsumerSelection, raw []byte) contract.ConsumerSelection {
	t.Helper()

	content, err := contract.InputContentLength(selected.Core.InputEncoding, raw)
	if err != nil {
		t.Fatal(err)
	}
	selected.Core.ContentLength, selected.Core.RetainedLength = content, uint32(len(raw))
	selected.Entry.InputEncoding, selected.Entry.ContentLength, selected.Entry.RetainedLength = selected.Core.InputEncoding, selected.Core.ContentLength, selected.Core.RetainedLength
	payload, keys, err := custody.SealValue(selected.Core, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys[:cap(keys)])
	wrapCore, err := custody.ValueWrapCore(selected.Core, selected.Binding)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := custody.Wrap(wrapCore, selected.Binding.Binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	selected.Payload = payload
	selected.Access.MaterialContextDigest, selected.Access.PackageCheck = wrapCore.MaterialContextDigest, payload.PackageCheck
	selected.Access.Wraps = []contract.WrapRow{wrap}
	refreshConsumerSelection(t, &selected)
	return selected
}

// full_only: false
func TestPublicationValueBindsTargetAndSelectedEntryBeforePrivateWork(t *testing.T) {
	secret, route := consumerFixture(t)
	selected := publicationSelectedValue{Secret: &secret}
	projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
	cases := []struct {
		name   string
		change func(*contract.PublicationProjection, *contract.OutputTarget, *publicationSelectedValue)
	}{
		{"coordinate", func(p *contract.PublicationProjection, _ *contract.OutputTarget, _ *publicationSelectedValue) {
			p.CoordinateID = consumerID("other coordinate")
		}},
		{"target", func(_ *contract.PublicationProjection, target *contract.OutputTarget, _ *publicationSelectedValue) {
			target.TargetContractID = "other"
		}},
		{"policy", func(p *contract.PublicationProjection, _ *contract.OutputTarget, _ *publicationSelectedValue) {
			p.PolicyDigest = consumerID("other policy")
		}},
		{"basis", func(p *contract.PublicationProjection, _ *contract.OutputTarget, _ *publicationSelectedValue) {
			p.ValueBasisDigest = consumerID("other value")
		}},
		{"entry", func(_ *contract.PublicationProjection, target *contract.OutputTarget, _ *publicationSelectedValue) {
			target.EntryIncarnationID = consumerID("other entry")
		}},
		{"both-selected", func(_ *contract.PublicationProjection, _ *contract.OutputTarget, selected *publicationSelectedValue) {
			plain := publicationPlainFixture(t, secret.DomainID, secret.Binding.SubjectID)
			selected.Plain = plain.Plain
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changedProjection, changedTarget, changedSelected := projection, target, selected
			tc.change(&changedProjection, &changedTarget, &changedSelected)
			payload, _, code := preparePublicationValue(context.Background(), changedProjection, destination, changedTarget, nil,
				&changedSelected, route, 0, maximumPublicationPayloadBytes)
			if payload != nil || code != contract.CryptoInvalidAdmission || route.privateCalls != 0 {
				t.Fatalf("changed selected target reached private work: code=%v calls=%d", code, route.privateCalls)
			}
		})
	}
	// Frame generic fields independently. Invalid common protocol facts must
	// refuse even if a foreign producer rebinds every commitment.
	commitments := func(target contract.OutputTarget) (contract.ID, contract.ID) {
		blob := func(dst, value []byte) []byte {
			dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
			return append(dst, value...)
		}
		policy, err := contract.EncodeOutputPolicy(target.Policy)
		if err != nil {
			t.Fatal("valid policy fixture", err)
		}
		row := append([]byte("ENKV/OUTPUT/TARGET-ROW/v3\x00"), projection.DomainID[:]...)
		row = blob(row, []byte(destination))
		row = append(row, projection.BindingIncarnationID[:]...)
		row = append(row, target.EntryIncarnationID[:]...)
		for _, field := range []string{target.ServiceContractID, target.TargetContractID, target.CanonicalTarget, target.ConsumerLocator} {
			row = blob(row, []byte(field))
		}
		row = blob(row, target.TargetData)
		row = append(row, target.PayloadEncoding, byte(target.Capabilities))
		if target.LocatorRequiresCreation {
			row = append(row, 1)
		} else {
			row = append(row, 0)
		}
		for _, n := range []uint32{target.CreateValueBounds.Minimum, target.CreateValueBounds.Maximum, target.WriteValueBounds.Minimum, target.WriteValueBounds.Maximum} {
			row = binary.BigEndian.AppendUint32(row, n)
		}
		row = blob(row, policy)
		basis := append([]byte("ENKV/PUBLICATION/VALUE-BASIS/v4\x00"), projection.DomainID[:]...)
		basis = blob(basis, []byte(destination))
		basis = append(basis, projection.BindingIncarnationID[:]...)
		basis = append(basis, secret.Entry.Incarnation[:]...)
		basis = append(basis, secret.Entry.ValueState[:]...)
		basis = binary.BigEndian.AppendUint32(basis, secret.Payload.ContentLength)
		basis = append(basis, secret.Entry.InputEncoding)
		basis = binary.BigEndian.AppendUint32(basis, secret.Entry.RetainedLength)
		basis = append(basis, contract.Secret)
		basis = append(basis, secret.Payload.SemanticCommitment[:]...)
		for _, field := range []string{target.ServiceContractID, target.CanonicalTarget, target.TargetContractID} {
			basis = blob(basis, []byte(field))
		}
		basis = append(basis, target.PayloadEncoding)
		return contract.Hash(row), contract.Hash(basis)
	}
	if row, basis := commitments(target); row != projection.TargetRowDigest || basis != projection.ValueBasisDigest {
		t.Fatal("independent target/value framing differs for the valid control")
	}
	for _, tc := range []struct {
		name   string
		change func(*contract.OutputTarget)
	}{
		{"encoding", func(t *contract.OutputTarget) { t.PayloadEncoding = 255 }},
		{"capabilities", func(t *contract.OutputTarget) { t.Capabilities = 0 }},
		{"locator", func(t *contract.OutputTarget) { t.LocatorRequiresCreation = true }},
		{"bounds", func(t *contract.OutputTarget) {
			t.WriteValueBounds = contract.OutputPayloadBounds{Minimum: 2, Maximum: 1}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsupported := target
			tc.change(&unsupported)
			if _, err := contract.PublicationTargetRowDigest(projection.DomainID, destination, projection.BindingIncarnationID, unsupported); !errors.Is(err, contract.ErrRecord) {
				t.Fatal("invalid target common facts admitted", err)
			}
			changed := projection
			changed.TargetRowDigest, changed.ValueBasisDigest = commitments(unsupported)
			if payload, _, code := preparePublicationValue(context.Background(), changed, destination, unsupported, nil, &selected, route, 0, maximumPublicationPayloadBytes); payload != nil || code != contract.CryptoInvalidAdmission || route.privateCalls != 0 {
				t.Fatal("fully rebound invalid target reached private work", code, route.privateCalls)
			}
		})
	}
}

// full_only: false
func TestPublicationValueBoundsAndLateAuthentication(t *testing.T) {
	secret, route := consumerFixture(t)
	selected := publicationSelectedValue{Secret: &secret}
	projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
	length := int(secret.Payload.ContentLength)
	for _, limits := range [][2]int{{0, length - 1}, {length + 1, maximumPublicationPayloadBytes}} {
		payload, _, code := preparePublicationValue(context.Background(), projection, destination, target, nil, &selected, route, limits[0], limits[1])
		if payload != nil || code != contract.CryptoCapacityExceeded || route.privateCalls != 0 {
			t.Fatalf("provider bound reached private work: code=%v calls=%d", code, route.privateCalls)
		}
	}
	damaged := secret
	damaged.Payload.Ciphertext = slices.Clone(damaged.Payload.Ciphertext)
	damaged.Payload.Ciphertext[0] ^= 1
	refreshConsumerSelection(t, &damaged)
	selected.Secret = &damaged
	projection, destination, target = publicationProjectionFixture(t, damaged.DomainID, damaged.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
	payload, _, code := preparePublicationValue(context.Background(), projection, destination, target, nil, &selected, route, 0, maximumPublicationPayloadBytes)
	if payload != nil || code != contract.CryptoStoredAuthenticationFailed || route.privateCalls != 1 {
		t.Fatalf("late authentication failure: code=%v calls=%d", code, route.privateCalls)
	}
	t.Run("base64-original-secret", func(t *testing.T) {
		stored := slices.Clone(secret.Entry.ValueBytes)
		selected := publicationSelectedValue{Secret: &secret}
		p, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
		p, target = publicationEncodingFixture(t, p, destination, target, &selected, "base64")
		for _, limits := range [][2]int{{0, 15}, {17, maximumPublicationPayloadBytes}} {
			calls := route.privateCalls
			payload, _, code := preparePublicationValue(context.Background(), p, destination, target, nil, &selected, route, limits[0], limits[1])
			if payload != nil || code != contract.CryptoCapacityExceeded || route.privateCalls != calls {
				t.Fatalf("encoded bound reached private work: code=%v calls=%d", code, route.privateCalls-calls)
			}
		}
		calls := route.privateCalls
		payload, uses, code := preparePublicationValue(context.Background(), p, destination, target, nil, &selected, route, 16, 16)
		if code != contract.CryptoSuccess || string(payload) != "c2VjcmV0LXZhbHVl" || len(payload) != 16 || route.privateCalls != calls+1 || len(uses) != 1 {
			t.Fatalf("secret encoded payload differs: code=%v length=%d calls=%d uses=%d", code, len(payload), route.privateCalls-calls, len(uses))
		}
		if secret.Payload.ContentLength != 12 || !bytes.Equal(secret.Entry.ValueBytes, stored) {
			t.Fatal("publication changed the original stored secret")
		}
		clear(payload[:cap(payload)])
	})
	for _, bound := range []struct {
		name                   string
		maximum, fit, overflow int
	}{
		{"cloud-65536", 65536, 49152, 49153},
		{"github-48000", 48000, 36000, 36001},
	} {
		t.Run(bound.name, func(t *testing.T) {

			for _, class := range []string{"plain", "secret"} {
				t.Run(class, func(t *testing.T) {
					for _, input := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
						for _, length := range []int{bound.fit, bound.overflow} {
							// Each fitting zero-byte input fills three-byte
							// groups. One extra byte adds independent AA==.
							encoded := strings.Repeat("A", 4*(length/3))
							if length%3 == 1 {
								encoded += "AA=="
							}
							retained := make([]byte, length)
							if input == contract.InputEncodingBase64 {
								retained = []byte(encoded)
							}
							selected := publicationPlainFixture(t, secret.DomainID, secret.Binding.SubjectID)
							routeID := contract.ID{}
							if class == "secret" {
								value := secret
								value.Core.InputEncoding = input
								value = publicationSecretValueFixture(t, value, retained)
								selected = publicationSelectedValue{Secret: &value}
								routeID = route.CredentialRoute()
							} else {
								selected.Plain.Entry.InputEncoding, selected.Plain.Entry.ContentLength, selected.Plain.Entry.RetainedLength = input, uint32(length), uint32(len(retained))
								selected.Plain.Entry.ValueBytes = retained
								var err error
								selected.Plain.EntryDigest, err = contract.PublicValueEntryDigest(secret.DomainID, selected.Plain.Slot, selected.Plain.Entry)
								if err != nil {
									t.Fatal(err)
								}
							}
							p, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
							p, target = publicationEncodingFixture(t, p, destination, target, &selected, "base64")
							r := newConsumerRuntime(t, route)
							sink := &publicationTestSink{id: consumerID("publication maximum sink")}
							id := consumerID("publication maximum admission")
							calls := route.privateCalls
							uses, code := r.preparePublication(context.Background(), id, sink.id, routeID, p, destination, target, nil, &selected, 0, bound.maximum, sink, time.Now().Add(time.Minute))
							if length == bound.overflow {
								if code != contract.CryptoCapacityExceeded || sink.sends != 0 || route.privateCalls != calls || len(uses) != 0 {
									t.Fatalf("encoded overflow entered private work or sent: input=%d code=%v private=%d sends=%d", input, code, route.privateCalls-calls, sink.sends)
								}
								r.retirePublication(context.Background())
								continue
							}
							wantCalls := 0
							if class == "secret" {
								wantCalls = 1
							}
							if code != contract.CryptoSuccess || r.publication == nil || string(r.publication.payload) != encoded || len(r.publication.payload) != bound.maximum || route.privateCalls != calls+wantCalls || len(uses) != wantCalls || sink.sends != 0 {
								t.Fatalf("fitting encoded custody differs: input=%d code=%v private=%d sends=%d", input, code, route.privateCalls-calls, sink.sends)
							}
							if err := r.armPublication(context.Background(), id, publicationDispatchFixture(t, p)); err != nil {
								t.Fatal("fitting encoded custody could not arm", err)
							}
							evidence, code := r.sendPublication(context.Background(), id)
							if code != contract.CryptoSuccess || evidence.Class != contract.PublicationRequestAcknowledged || sink.sends != 1 || len(sink.payload) != bound.maximum {
								t.Fatal("fitting encoded custody did not deliver once", code, sink.sends)
							}
							r.retirePublication(context.Background())
							if !bytes.Equal(sink.payload, make([]byte, len(sink.payload))) {
								t.Fatal("publication kept the delivered owner after joined retirement")
							}
						}
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicationPlainValueAndMetadataUseNoPrivateRoute(t *testing.T) {
	secret, route := consumerFixture(t)
	selected := publicationPlainFixture(t, secret.DomainID, secret.Binding.SubjectID)
	projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
	var err error
	payload, uses, code := preparePublicationValue(context.Background(), projection, destination, target, nil, &selected, nil, 0, maximumPublicationPayloadBytes)
	if code != contract.CryptoSuccess || len(uses) != 0 || !bytes.Equal(payload, selected.Plain.Entry.ValueBytes) || payload == nil {
		t.Fatalf("plain selected value: code=%v uses=%d", code, len(uses))
	}
	payload[0] ^= 1
	if selected.Plain.Entry.ValueBytes[0] != 'p' {
		t.Fatal("plain payload aliases selected value")
	}
	t.Run("base64-original-plain", func(t *testing.T) {
		p, target := publicationEncodingFixture(t, projection, destination, target, &selected, "base64")
		payload, uses, code := preparePublicationValue(context.Background(), p, destination, target, nil, &selected, nil, 16, 16)
		if code != contract.CryptoSuccess || len(uses) != 0 || payload == nil || string(payload) != "cHVibGljLXZhbHVl" || len(payload) != 16 || string(selected.Plain.Entry.ValueBytes) != "public-value" {
			t.Fatalf("plain encoded payload differs: code=%v length=%d uses=%d", code, len(payload), len(uses))
		}
		payload[0] ^= 1
		if string(selected.Plain.Entry.ValueBytes) != "public-value" {
			t.Fatal("encoded plain payload aliases original value")
		}
		clear(payload[:cap(payload)])
	})

	selected.Plain.Entry.OutputEncoding = contract.OutputEncodingRaw
	selected.Plain.EntryDigest, err = contract.PublicValueEntryDigest(secret.DomainID, selected.Plain.Slot, selected.Plain.Entry)
	if err != nil {
		t.Fatal(err)
	}
	selected.Plain.Entry.Name = "other"
	if payload, _, code := preparePublicationValue(context.Background(), projection, destination, target, nil, &selected, nil, 0, maximumPublicationPayloadBytes); payload != nil || code != contract.CryptoInvalidAdmission {
		t.Fatal("altered plain name passed its selected digest")
	}
	selected.Plain.Entry.Name = "public"
	selected.Plain.Entry.ValueState = consumerID("other public state")
	digest, err := contract.PublicValueEntryDigest(secret.DomainID, selected.Plain.Slot, selected.Plain.Entry)
	if err != nil {
		t.Fatal(err)
	}
	selected.Plain.EntryDigest = digest
	if payload, _, code := preparePublicationValue(context.Background(), projection, destination, target, nil, &selected, nil, 0, maximumPublicationPayloadBytes); payload != nil || code != contract.CryptoInvalidAdmission {
		t.Fatal("different authenticated value state passed the original basis")
	}
	for _, action := range []uint8{contract.PublicationCreateEmpty, contract.PublicationUpdatePolicy,
		contract.PublicationDeleteOwned, contract.PublicationDeleteReservedSlot} {
		metadata, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, nil, action)
		deletion := publicationRetainedDeleteFixture(t, metadata, destination, target)
		if deletion != nil {
			target.Policy = contract.OutputPolicy{}
		}
		payload, uses, code := preparePublicationValue(context.Background(), metadata, destination, target, deletion, nil, nil, 0, 0)
		if code != contract.CryptoSuccess || payload != nil || len(uses) != 0 || route.privateCalls != 0 {
			t.Fatalf("metadata action %d used value custody: code=%v", action, code)
		}
		if payload, _, code := preparePublicationValue(context.Background(), metadata, destination, target, deletion, nil, route, 0, 0); payload != nil || code != contract.CryptoInvalidAdmission || route.privateCalls != 0 {
			t.Fatal("metadata accepted private route")
		}
		if payload, _, code := preparePublicationValue(context.Background(), metadata, destination, target, deletion, &selected, nil, 0, 0); payload != nil || code != contract.CryptoInvalidAdmission {
			t.Fatal("metadata accepted selected value")
		}
		changed := target
		changed.Policy.ContractID = "other"
		if payload, _, code := preparePublicationValue(context.Background(), metadata, destination, changed, deletion, nil, nil, 0, 0); payload != nil || code != contract.CryptoInvalidAdmission {
			t.Fatal("metadata accepted a different target policy")
		}
	}
}

type publicationTestSink struct {
	mu               sync.Mutex
	id               contract.ID
	sends, closes    int
	payload          []byte
	payloadWasNil    bool
	started, release chan struct{}
	closeErr         error
}

type publicationJoiningSink struct {
	id      contract.ID
	started chan struct{}
	ended   chan struct{}
	closed  chan struct{}
	mu      sync.Mutex
	closes  int
}

func (s *publicationJoiningSink) Identity() contract.ID { return s.id }
func (s *publicationJoiningSink) Send(ctx context.Context, _ contract.PublicationDispatch, _ []byte) (contract.PublicationEvidence, error) {
	close(s.started)
	defer close(s.ended)
	<-ctx.Done()
	return contract.PublicationEvidence{}, ctx.Err()
}
func (s *publicationJoiningSink) Close() error {
	<-s.ended
	s.mu.Lock()
	s.closes++
	s.mu.Unlock()
	close(s.closed)
	return nil
}

func (s *publicationTestSink) Identity() contract.ID { return s.id }
func (s *publicationTestSink) Send(ctx context.Context, dispatch contract.PublicationDispatch, payload []byte) (contract.PublicationEvidence, error) {
	s.mu.Lock()
	s.sends++
	s.payloadWasNil = payload == nil
	s.payload = payload[:cap(payload)]
	s.mu.Unlock()
	if s.started != nil {
		close(s.started)
		select {
		case <-s.release:
		case <-ctx.Done():
			return contract.PublicationEvidence{}, ctx.Err()
		}
	}
	return contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged,
		ResponseContractDigest: dispatch.ResponseContractDigest, NormalizedStatus: 201}, nil
}
func (s *publicationTestSink) Close() error {
	s.mu.Lock()
	s.closes++
	s.mu.Unlock()
	return s.closeErr
}

// full_only: false
func TestPublicationPrivateCloseFailureRejectsCheckedEvidence(t *testing.T) {
	secret, route := consumerFixture(t)
	r := newConsumerRuntime(t, route)
	selected := publicationPlainFixture(t, secret.DomainID, secret.Binding.SubjectID)
	projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
	closeErr := errors.New("controlled private close failure")
	sink := &publicationTestSink{id: consumerID("private close failure sink"), closeErr: closeErr}
	id := consumerID("private close failure admission")
	if _, code := r.preparePublication(t.Context(), id, sink.id, contract.ID{}, projection, destination, target, nil, &selected, 0, maximumPublicationPayloadBytes, sink, time.Now().Add(time.Minute)); code != contract.CryptoSuccess {
		t.Fatal("private close fixture did not prepare", code)
	}
	if err := r.armPublication(t.Context(), id, publicationDispatchFixture(t, projection)); err != nil {
		t.Fatal(err)
	}
	evidence, code := r.sendPublication(t.Context(), id)
	if code != contract.CryptoResponseUnknown || evidence != (contract.PublicationEvidence{}) || sink.sends != 1 || sink.closes != 1 {
		t.Error("private closure failure acquired a publication result", evidence, code)
	}
	r.retirePublication(t.Context())
	if sink.closes != 1 || !bytes.Equal(sink.payload, make([]byte, len(sink.payload))) || r.publication != nil || r.slot != nil {
		t.Error("private close failure lost joined custody disposal")
	}
}

func publicationDispatchFixture(t *testing.T, projection contract.PublicationProjection) contract.PublicationDispatch {
	t.Helper()
	commitment, err := contract.PublicationProjectionCommitment(projection)
	if err != nil {
		t.Fatal(err)
	}
	return contract.PublicationDispatch{Schema: 5, DomainID: projection.DomainID, OperationID: consumerID("operation"), AttemptID: consumerID("attempt"),
		CoordinateID: projection.CoordinateID, Projection: projection, ProjectionCommitment: commitment,
		AuthoritySubjectDigest: consumerID("authority subject"),
		ExecutorID:             "fixture", CredentialRouteID: "fixture", ResponseContractDigest: consumerID("response contract")}
}

// full_only: false
func TestPublicationMetadataArmAndZeroValuePayloadAreDistinct(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			secret, route := consumerFixture(t)
			for _, tc := range []struct {
				name       string
				metadata   bool
				wantNil    bool
				wantKeyUse int
			}{
				{name: "metadata-arm", metadata: true, wantNil: true},
				{name: "empty-selected-value", wantKeyUse: 0},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := newConsumerRuntime(t, route)
					sink := &publicationTestSink{id: consumerID("sink " + tc.name)}
					id := consumerID("admission " + tc.name)
					var selected *publicationSelectedValue
					var routeID contract.ID
					var projection contract.PublicationProjection
					var destination string
					var target contract.OutputTarget
					var maximum int
					if tc.metadata {
						projection, destination, target = publicationProjectionFixture(t, secret.DomainID,
							secret.Binding.SubjectID, nil, contract.PublicationCreateEmpty)
						if _, code := r.preparePublication(context.Background(), id, sink.id, consumerID("uninstalled private route"),
							projection, destination, target, nil, nil, 0, 0, sink, time.Now().Add(time.Minute)); code != contract.CryptoInvalidAdmission ||
							r.slot != nil || route.privateCalls != 0 {
							t.Fatal("metadata admitted a private route")
						}
					} else {
						plain := publicationPlainFixture(t, secret.DomainID, secret.Binding.SubjectID)
						plain.Plain.Entry.ValueBytes = nil
						plain.Plain.Entry.ContentLength, plain.Plain.Entry.RetainedLength = 0, 0
						var err error
						plain.Plain.EntryDigest, err = contract.PublicValueEntryDigest(secret.DomainID, plain.Plain.Slot, plain.Plain.Entry)
						if err != nil {
							t.Fatal(err)
						}
						selected = &plain
						projection, destination, target = publicationProjectionFixture(t, secret.DomainID,
							secret.Binding.SubjectID, selected, contract.PublicationCreateWithValue)
						maximum = maximumPublicationPayloadBytes
						if _, code := r.preparePublication(context.Background(), id, sink.id, route.CredentialRoute(),
							projection, destination, target, nil, selected, 0, maximum, sink, time.Now().Add(time.Minute)); code != contract.CryptoInvalidAdmission ||
							r.slot != nil || route.privateCalls != 0 {
							t.Fatal("public selected value admitted an unrelated private route")
						}
					}
					projection, target = publicationEncodingFixture(t, projection, destination, target, selected, encoding)
					uses, code := r.preparePublication(context.Background(), id, sink.id, routeID,
						projection, destination, target, nil, selected, 0, maximum, sink, time.Now().Add(time.Minute))
					if code != contract.CryptoSuccess || len(uses) != tc.wantKeyUse || route.privateCalls != 0 ||
						r.publication == nil || !r.publication.ready || (r.publication.payload == nil) != tc.wantNil {
						t.Fatalf("prepared metadata/value distinction: code=%v uses=%d calls=%d", code, len(uses), route.privateCalls)
					}
					if sink.sends != 0 {
						t.Fatal("prepare sent before marker selection")
					}
					if err := r.armPublication(context.Background(), id, publicationDispatchFixture(t, projection)); err != nil {
						t.Fatal(err)
					}
					if _, code := r.sendPublication(context.Background(), id); code != contract.CryptoSuccess {
						t.Fatal("one selected send failed", code)
					}
					if sink.sends != 1 || sink.closes != 1 || sink.payloadWasNil != tc.wantNil || len(sink.payload) != 0 {
						t.Fatal("metadata Arm and empty value Payload became indistinguishable")
					}
					r.retirePublication(context.Background())
				})
			}
		})
	}
}

// full_only: false
func TestPublicationCustodyOneUseAndJoinedClose(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			secret, route := consumerFixture(t)
			r := newConsumerRuntime(t, route)
			selected := publicationSelectedValue{Secret: &secret}
			projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
			projection, target = publicationEncodingFixture(t, projection, destination, target, &selected, encoding)
			sink := &publicationTestSink{id: consumerID("publication sink")}
			id := consumerID("publication admission")
			deadline := time.Now().Add(time.Minute)
			uses, code := r.preparePublication(context.Background(), id, sink.id, route.CredentialRoute(), projection, destination, target, nil, &selected, 0, maximumPublicationPayloadBytes, sink, deadline)
			if code != contract.CryptoSuccess || len(uses) != 1 || route.privateCalls != 1 {
				t.Fatalf("prepare=%v uses=%d private=%d", code, len(uses), route.privateCalls)
			}
			if sink.sends != 0 {
				t.Fatal("preparation sent before selected marker")
			}
			if _, code := r.sendPublication(context.Background(), id); code != contract.CryptoInvalidAdmission {
				t.Fatal("unarmed custody sent")
			}
			if err := r.armPublication(context.Background(), id, publicationDispatchFixture(t, projection)); err != nil {
				t.Fatal(err)
			}
			evidence, code := r.sendPublication(context.Background(), id)
			if code != contract.CryptoSuccess || evidence.Class != contract.PublicationRequestAcknowledged || sink.sends != 1 || sink.closes != 1 {
				t.Fatalf("send code=%v evidence=%#v sends=%d closes=%d", code, evidence, sink.sends, sink.closes)
			}
			if _, code := r.sendPublication(context.Background(), id); code != contract.CryptoInvalidAdmission && code != contract.CryptoAlreadyUsed {
				t.Fatal("custody sent twice")
			}
			r.retirePublication(context.Background())
			if r.slot != nil || r.publication != nil || !bytes.Equal(sink.payload, make([]byte, len(sink.payload))) {
				t.Fatal("joined retirement kept private payload")
			}
			if _, code := r.preparePublication(context.Background(), id, sink.id, route.CredentialRoute(),
				projection, destination, target, nil, &selected, 0, maximumPublicationPayloadBytes, sink, deadline); code != contract.CryptoInvalidAdmission {
				t.Fatal("retired custody identity was reused")
			}
		})
	}
}

// full_only: false
func TestPublicationRuntimeCloseClearsPreparedValueAndStaleHandle(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			secret, route := consumerFixture(t)
			r := newConsumerRuntime(t, route)
			selected := publicationSelectedValue{Secret: &secret}
			projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID,
				&selected, contract.PublicationCreateWithValue)
			projection, target = publicationEncodingFixture(t, projection, destination, target, &selected, encoding)
			sink := &publicationTestSink{id: consumerID("close prepared sink")}
			id := consumerID("close prepared admission")
			if _, code := r.preparePublication(context.Background(), id, sink.id, route.CredentialRoute(), projection,
				destination, target, nil, &selected, 0, maximumPublicationPayloadBytes, sink, time.Now().Add(time.Minute)); code != contract.CryptoSuccess {
				t.Fatal(code)
			}
			borrowed := r.publication.payload[:cap(r.publication.payload)]
			r.Close()
			if sink.sends != 0 || sink.closes != 1 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("Runtime.Close returned with live payload or unjoined child")
			}
			if err := r.armPublication(context.Background(), id, publicationDispatchFixture(t, projection)); !errors.Is(err, ErrAdmission) {
				t.Fatal("closed runtime armed stale custody")
			}
			if _, code := r.sendPublication(context.Background(), id); code != contract.CryptoInvalidAdmission {
				t.Fatal("closed runtime sent stale custody")
			}
		})
	}
}

// full_only: false
func TestPublicationPreparedExpiryDoesNotArmOrSend(t *testing.T) {
	secret, route := consumerFixture(t)
	r := newConsumerRuntime(t, route)
	selected := publicationPlainFixture(t, secret.DomainID, secret.Binding.SubjectID)
	projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID,
		&selected, contract.PublicationCreateWithValue)
	sink := &publicationTestSink{id: consumerID("expired sink")}
	id := consumerID("expired admission")
	if _, code := r.preparePublication(context.Background(), id, sink.id, contract.ID{}, projection,
		destination, target, nil, &selected, 0, maximumPublicationPayloadBytes, sink, time.Now().Add(time.Second)); code != contract.CryptoSuccess {
		t.Fatal(code)
	}
	<-r.publication.done
	if err := r.armPublication(context.Background(), id, publicationDispatchFixture(t, projection)); !errors.Is(err, ErrAdmission) {
		t.Fatal("expired custody armed")
	}
	if _, code := r.sendPublication(context.Background(), id); code != contract.CryptoInvalidAdmission && code != contract.CryptoExpired {
		t.Fatal("expired custody sent", code)
	}
	r.retirePublication(context.Background())
	if sink.sends != 0 || sink.closes != 1 {
		t.Fatal("expiry did not join one child without sending")
	}
}

// full_only: false
func TestPublicationCurrentKeyReplacementKeepsProjection(t *testing.T) {
	secret, route := consumerFixture(t)
	selected := publicationSelectedValue{Secret: &secret}
	projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
	originalPayload, _, code := preparePublicationValue(context.Background(), projection, destination, target, nil, &selected, route, 0, maximumPublicationPayloadBytes)
	if code != contract.CryptoSuccess {
		t.Fatal(code)
	}
	wrapCore, err := custody.ValueWrapCore(secret.Core, secret.Binding)
	if err != nil {
		t.Fatal(err)
	}
	packetContext, err := contract.RSAPacketContextDigest(wrapCore)
	if err != nil {
		t.Fatal(err)
	}
	private := route.Decrypt(context.Background(), secret.Binding.Binding, secret.Access.Wraps[0].RSACiphertext, 100)
	keys, err := custody.PacketKeys(private.Packet, 1, packetContext)
	if err != nil {
		clear(private.Packet[:cap(private.Packet)])
		t.Fatal(err)
	}
	defer clear(private.Packet[:cap(private.Packet)])
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	replaced := secret
	replaced.Binding.Binding.BindingID = consumerID("replacement binding")
	replaced.Binding.Binding.BindingSerial++
	replaced.Binding.Binding.KeySelector = "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/replacement/cryptoKeyVersions/1"
	replaced.Binding.Binding.SPKI = spki
	replaced.Binding.Binding.Fingerprint = contract.Hash(spki)
	newCore, err := custody.ValueWrapCore(replaced.Core, replaced.Binding)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := custody.Wrap(newCore, replaced.Binding.Binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	replaced.Access.MaterialContextDigest = newCore.MaterialContextDigest
	replaced.Access.Wraps = []contract.WrapRow{wrap}
	newRoute := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: key, binding: replaced.Binding.Binding}}
	replacedSelected := publicationSelectedValue{Secret: &replaced}
	replacedProjection, replacedDestination, replacedTarget := publicationProjectionFixture(t, replaced.DomainID, replaced.Binding.SubjectID, &replacedSelected, contract.PublicationCreateWithValue)
	if replacedProjection != projection {
		t.Fatal("current key replacement changed publication equality")
	}
	replacedPayload, _, code := preparePublicationValue(context.Background(), replacedProjection, replacedDestination, replacedTarget, nil, &replacedSelected, newRoute, 0, maximumPublicationPayloadBytes)
	if code != contract.CryptoSuccess || !bytes.Equal(replacedPayload, originalPayload) {
		t.Fatalf("replacement code=%v", code)
	}
	clear(originalPayload)
	clear(replacedPayload)
}

// full_only: false
func TestPublicationCustodyCancelledBeforeSendClosesAndClears(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			secret, route := consumerFixture(t)
			r := newConsumerRuntime(t, route)
			selected := publicationSelectedValue{Secret: &secret}
			projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
			projection, target = publicationEncodingFixture(t, projection, destination, target, &selected, encoding)
			sink := &publicationTestSink{id: consumerID("cancelled sink")}
			id := consumerID("cancelled publication admission")
			if _, code := r.preparePublication(context.Background(), id, sink.id, route.CredentialRoute(), projection, destination, target, nil, &selected, 0, maximumPublicationPayloadBytes, sink, time.Now().Add(time.Minute)); code != contract.CryptoSuccess {
				t.Fatal(code)
			}
			borrowed := r.publication.payload[:cap(r.publication.payload)]
			reportingCtx, cancelReporting := context.WithCancel(context.Background())
			cancelReporting()
			r.retirePublication(reportingCtx)
			if sink.sends != 0 || sink.closes != 1 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("cancelled custody retained payload or sent")
			}
			if err := r.armPublication(context.Background(), id, publicationDispatchFixture(t, projection)); !errors.Is(err, ErrAdmission) {
				t.Fatal("retired custody rearmed")
			}
		})
	}
}

// full_only: false
func TestPublicationCancelledArmRetiresOnlyMatchingPreparedCustody(t *testing.T) {
	secret, route := consumerFixture(t)
	r := newConsumerRuntime(t, route)
	defer r.Close()
	selected := publicationPlainFixture(t, secret.DomainID, secret.Binding.SubjectID)
	projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID,
		&selected, contract.PublicationCreateWithValue)
	deadline := time.Now().Add(time.Minute)
	sink := &publicationTestSink{id: consumerID("cancelled arm sink")}
	id := consumerID("cancelled arm admission")
	if _, code := r.preparePublication(context.Background(), id, sink.id, contract.ID{}, projection,
		destination, target, nil, &selected, 0, maximumPublicationPayloadBytes, sink, deadline); code != contract.CryptoSuccess {
		t.Fatal(code)
	}
	borrowed := r.publication.payload[:cap(r.publication.payload)]
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.armPublication(cancelled, id, publicationDispatchFixture(t, projection)); !errors.Is(err, ErrAdmission) {
		t.Fatal("cancelled arm accepted prepared custody")
	}
	if sink.sends != 0 || sink.closes != 1 || r.slot != nil || r.publication != nil ||
		!bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("cancelled arm returned before custody was joined and cleared")
	}
	if _, code := r.sendPublication(context.Background(), id); code != contract.CryptoInvalidAdmission {
		t.Fatal("fresh-context Send used custody after cancelled arm", code)
	}

	nextSink := &publicationTestSink{id: consumerID("next arm sink")}
	nextID := consumerID("next arm admission")
	if _, code := r.preparePublication(context.Background(), nextID, nextSink.id, contract.ID{}, projection,
		destination, target, nil, &selected, 0, maximumPublicationPayloadBytes, nextSink, deadline); code != contract.CryptoSuccess {
		t.Fatal(code)
	}
	if err := r.armPublication(cancelled, id, publicationDispatchFixture(t, projection)); !errors.Is(err, ErrAdmission) {
		t.Fatal("stale cancelled arm was accepted")
	}
	if r.publication == nil || r.publication.id != nextID || nextSink.closes != 0 {
		t.Fatal("stale cancelled arm retired a different admission")
	}
	if err := r.armPublication(context.Background(), nextID, publicationDispatchFixture(t, projection)); err != nil {
		t.Fatal(err)
	}
	if _, code := r.sendPublication(context.Background(), nextID); code != contract.CryptoSuccess || nextSink.sends != 1 {
		t.Fatal("valid next admission did not send once", code)
	}
	r.retirePublication(context.Background())
}

// full_only: false
func TestPublicationCancelledArmClaimsSessionBeforeJoin(t *testing.T) {
	for _, mode := range []string{"caller-cancelled", "private-cancel-observed"} {
		t.Run(mode, func(t *testing.T) {
			secret, route := consumerFixture(t)
			r := newConsumerRuntime(t, route)
			defer r.Close()
			selected := publicationPlainFixture(t, secret.DomainID, secret.Binding.SubjectID)
			projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID,
				&selected, contract.PublicationCreateWithValue)
			sink := &publicationTestSink{id: consumerID("claim sink")}
			id := consumerID("claim admission")
			if _, code := r.preparePublication(context.Background(), id, sink.id, contract.ID{}, projection,
				destination, target, nil, &selected, 0, maximumPublicationPayloadBytes, sink, time.Now().Add(time.Minute)); code != contract.CryptoSuccess {
				t.Fatal(code)
			}
			borrowed := r.publication.payload[:cap(r.publication.payload)]
			originalCancel := r.publication.cancel
			entered := make(chan struct{})
			release := make(chan struct{})
			var blockOnce, releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			r.mu.Lock()
			r.publication.cancel = func() {
				blockOnce.Do(func() {
					close(entered)
					<-release
				})
				originalCancel()
			}
			r.mu.Unlock()
			dispatch := publicationDispatchFixture(t, projection)
			cancellation := make(chan error, 1)
			if mode == "caller-cancelled" {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				go func() { cancellation <- r.armPublication(ctx, id, dispatch) }()
			} else {
				done := make(chan struct{})
				close(done)
				go func() {
					_, err := r.armPublicationOwned(done, id, dispatch)
					cancellation <- err
				}()
			}
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("cancellation did not reach session retirement")
			}
			// If cancellation does not own the runtime lock at this point,
			// the exact session must already be terminal. A later Arm must
			// never get an interval between this claim and cleanup.
			unclaimed := false
			if r.mu.TryLock() {
				unclaimed = !r.publication.terminal && r.publication.ctx.Err() == nil
				r.mu.Unlock()
			}
			validArm := make(chan error, 1)
			go func() { validArm <- r.armPublication(context.Background(), id, dispatch) }()
			releaseOnce.Do(func() { close(release) })
			if err := <-cancellation; !errors.Is(err, ErrAdmission) {
				t.Fatal("cancelled arm was accepted", err)
			}
			if err := <-validArm; !errors.Is(err, ErrAdmission) {
				t.Fatal("concurrent arm crossed the cancellation claim", err)
			}
			if unclaimed {
				t.Fatal("cancellation released the runtime lock without claiming its session")
			}
			if r.slot != nil || r.publication != nil || sink.sends != 0 || sink.closes != 1 ||
				!bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("cancelled custody was not joined and cleared")
			}
		})
	}
}

// full_only: false
func TestPublicationCustodyCancellationJoinsInFlightChild(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			secret, route := consumerFixture(t)
			r := newConsumerRuntime(t, route)
			selected := publicationSelectedValue{Secret: &secret}
			projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
			projection, target = publicationEncodingFixture(t, projection, destination, target, &selected, encoding)
			sink := &publicationJoiningSink{id: consumerID("joined sink"), started: make(chan struct{}), ended: make(chan struct{}), closed: make(chan struct{})}
			id := consumerID("joined publication admission")
			if _, code := r.preparePublication(context.Background(), id, sink.id, route.CredentialRoute(), projection, destination, target, nil, &selected, 0, maximumPublicationPayloadBytes, sink, time.Now().Add(time.Minute)); code != contract.CryptoSuccess {
				t.Fatal(code)
			}
			borrowed := r.publication.payload[:cap(r.publication.payload)]
			if err := r.armPublication(context.Background(), id, publicationDispatchFixture(t, projection)); err != nil {
				t.Fatal(err)
			}
			result := make(chan contract.CryptoResultCode, 1)
			go func() {
				_, code := r.sendPublication(context.Background(), id)
				result <- code
			}()
			select {
			case <-sink.started:
			case <-time.After(10 * time.Second):
				t.Fatal("child did not enter Send")
			}
			r.retirePublication(context.Background())
			select {
			case code := <-result:
				if code != contract.CryptoCancelled {
					t.Fatalf("cancelled in-flight result=%v", code)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("cancelled Send did not return")
			}
			select {
			case <-sink.closed:
			default:
				t.Fatal("retirement returned before child Close joined")
			}
			sink.mu.Lock()
			closes := sink.closes
			sink.mu.Unlock()
			if closes != 1 || r.slot != nil || r.publication != nil || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("retirement did not join one child and clear its payload")
			}
		})
	}
}

// full_only: false
func TestPublicationTelemetryKeepsPrivateCustodyAndOutcomeSeparate(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			secret, route := consumerFixture(t)
			r := newConsumerRuntime(t, route)
			selected := publicationSelectedValue{Secret: &secret}
			projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
			projection, target = publicationEncodingFixture(t, projection, destination, target, &selected, encoding)
			sink := &publicationTestSink{id: consumerID("telemetry sink")}
			id := consumerID("telemetry publication admission")
			recorder := telemetry.NewRecorder()
			ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
			parent := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpApplicationInvocation)
			if _, code := r.preparePublication(parent.Context(), id, sink.id, route.CredentialRoute(), projection, destination, target, nil, &selected,
				0, maximumPublicationPayloadBytes, sink, time.Now().Add(time.Minute)); code != contract.CryptoSuccess {
				t.Fatal(code)
			}
			if err := r.armPublication(parent.Context(), id, publicationDispatchFixture(t, projection)); err != nil {
				t.Fatal(err)
			}
			if _, code := r.sendPublication(parent.Context(), id); code != contract.CryptoSuccess {
				t.Fatal(code)
			}
			r.retirePublication(parent.Context())
			parent.Finish(telemetry.ResultSuccess)
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32))
			seen := map[telemetry.Operation]int{}
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Fatal(err)
				}
				if record.Provider == telemetry.ProviderCrypto && record.Event == telemetry.DiagnosticReturn {
					seen[record.Operation]++
					if record.ParentCall != records[0].Call || record.Result != telemetry.ResultSuccess {
						t.Fatalf("publication telemetry relation/result: %+v", record)
					}
				}
			}
			for _, op := range []telemetry.Operation{telemetry.OpCryptoPublicationPrepare, telemetry.OpCryptoPublicationArm,
				telemetry.OpCryptoPublicationSend, telemetry.OpCryptoPublicationRetire} {
				if seen[op] != 1 {
					t.Fatalf("missing publication telemetry %s: %+v", op, seen)
				}
			}
			wire, err := json.Marshal(records)
			if err != nil || strings.Contains(string(wire), "secret-value") || strings.Contains(string(wire), "c2VjcmV0LXZhbHVl") || strings.Contains(string(wire), "private credential") ||
				strings.Contains(string(wire), secret.Entry.Name) {
				t.Fatal("private publication field entered diagnostics")
			}
		})
	}
}

// full_only: false
func TestPublicationRetiredDeleteDoesNotRequireRemovedPolicy(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			projection, destination, target := publicationProjectionFixture(t, consumerID("retired domain"), consumerID("actor"), nil, contract.PublicationDeleteOwned)
			projection, target = publicationEncodingFixture(t, projection, destination, target, nil, encoding)
			deletion := publicationRetainedDeleteFixture(t, projection, destination, target)
			target.Policy = contract.OutputPolicy{}
			payload, uses, code := preparePublicationValue(context.Background(), projection, destination, target, deletion, nil, nil, 0, 0)
			if code != contract.CryptoSuccess || payload != nil || len(uses) != 0 {
				t.Fatalf("retired delete depends on removed policy: code=%v payload=%t uses=%d", code, payload != nil, len(uses))
			}
		})
	}
}

func publicationRetainedDeleteFixture(t *testing.T, projection contract.PublicationProjection, destination string, target contract.OutputTarget) *publicationDeletionSelection {
	t.Helper()
	if projection.Action < contract.PublicationDeleteOwned {
		return nil
	}
	create := projection
	create.Action = contract.PublicationCreateEmpty
	create.OwnedBirthAttemptID, create.UncertainCreateAttemptID, create.ExclusiveNamespaceDigest = contract.ID{}, contract.ID{}, contract.ID{}
	var err error
	create.PolicyDigest, err = contract.OutputPolicyDigest(projection.DomainID, target.Policy)
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := contract.PublicationProjectionCommitment(create)
	if err != nil {
		t.Fatal(err)
	}
	marker := &contract.PublicationMarker{Schema: 5, DomainID: projection.DomainID, OperationID: consumerID("original create operation"), AttemptID: projection.OwnedBirthAttemptID, CoordinateID: projection.CoordinateID, PublicationIncarnationID: consumerID("original publication incarnation"), AdmissionOrdinal: 1, Projection: create, ProjectionCommitment: commitment, AuthoritySubjectDigest: consumerID("create authority"), ExecutorID: "fixture", CredentialRouteID: "fixture", State: contract.PublicationAcknowledged, Evidence: contract.PublicationEvidence{Schema: 3, Entry: 2, Class: 1, ResponseContractDigest: consumerID("create response"), NormalizedStatus: 200, SafeResourceID: "original instance", ConsumerLocator: target.ConsumerLocator}, BirthServiceContractID: target.ServiceContractID, BirthTargetContractID: target.TargetContractID}
	coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: projection.DomainID, CoordinateID: projection.CoordinateID, ServiceContractID: target.ServiceContractID, CanonicalTarget: target.CanonicalTarget, BindingState: contract.PublicationBindingRetired, OwnerState: contract.PublicationOwnerQualified, LastBindingIncarnationID: projection.BindingIncarnationID, LastEntryIncarnationID: projection.EntryIncarnationID, OwnedBirthAttemptID: marker.AttemptID, CurrentPublicationIncarnationID: marker.PublicationIncarnationID, LastAdmissionOrdinal: 1, PossibleRemoteObject: 1, DeletionDestinationID: destination, DeletionConsumerLocator: target.ConsumerLocator, DeletionTargetContractID: target.TargetContractID, DeletionConfigContractID: "config/v1", DeletionCredentialRouteContractID: "route/v1", DeletionTargetData: target.TargetData, DeletionPayloadEncoding: target.PayloadEncoding, DeletionTargetRowDigest: projection.TargetRowDigest}
	deletion := &publicationDeletionSelection{Coordinate: coordinate, Birth: marker}
	if projection.Action == contract.PublicationDeleteReservedSlot {
		marker.AttemptID = projection.UncertainCreateAttemptID
		marker.State = contract.PublicationUnknown
		marker.Evidence = contract.PublicationEvidence{Schema: 3, Entry: 2, ResponseContractDigest: consumerID("create response")}
		deletion.Coordinate.OwnerState = contract.PublicationOwnerUncertainCreate
		deletion.Coordinate.OwnedBirthAttemptID = contract.ID{}
		// This cache names other work. The exact selected create remains authoritative.
		deletion.Coordinate.LatestUnresolvedAttemptID = consumerID("later unresolved action")
		deletion.Birth, deletion.UncertainCreate = nil, marker
	} else {
		deletion.Coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(marker.DomainID, marker.CoordinateID, marker.Projection.BindingIncarnationID, marker.Projection.EntryIncarnationID, marker.Projection.TargetRowDigest, marker.AttemptID, marker.Evidence.SafeResourceID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := contract.EncodePublicationCoordinate(deletion.Coordinate); err != nil {
		t.Fatal(err)
	}
	if _, err := contract.EncodePublicationMarker(*marker); err != nil {
		t.Fatal(err)
	}
	return deletion
}

// full_only: false
func TestPublicationRetiredDeletionPinsAndOwnership(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			for _, action := range []uint8{contract.PublicationDeleteOwned, contract.PublicationDeleteReservedSlot} {
				t.Run(string(rune('0'+action)), func(t *testing.T) {
					p, destination, target := publicationProjectionFixture(t, consumerID("retired domain"), consumerID("actor"), nil, action)
					p, target = publicationEncodingFixture(t, p, destination, target, nil, encoding)
					deletion := publicationRetainedDeleteFixture(t, p, destination, target)
					target.Policy = contract.OutputPolicy{}
					if payload, uses, code := preparePublicationValue(context.Background(), p, destination, target, deletion, nil, nil, 0, 0); code != contract.CryptoSuccess || payload != nil || len(uses) != 0 {
						t.Fatalf("valid retained delete refused code=%v", code)
					}
					for _, field := range []string{"absent", "schema", "domain", "coordinate", "binding", "entry", "target digest", "service", "target", "destination", "consumer", "target-contract", "locator-mode", "target-data", "encoding", "policy", "marker action", "marker state", "marker attempt", "marker target", "marker service", "wrong proof kind", "selected value", "route", "bounds"} {
						t.Run(field, func(t *testing.T) {
							changed, pin, selected, minimum, maximum := target, *deletion, (*publicationSelectedValue)(nil), 0, 0
							ptr := &pin
							if pin.Birth != nil {
								copy := *pin.Birth
								pin.Birth = &copy
							}
							if pin.UncertainCreate != nil {
								copy := *pin.UncertainCreate
								pin.UncertainCreate = &copy
							}
							marker := pin.Birth
							if marker == nil {
								marker = pin.UncertainCreate
							}
							var route KeyAccess
							switch field {
							case "absent":
								ptr = nil
							case "schema":
								pin.Coordinate.Schema = 3
							case "domain":
								pin.Coordinate.DomainID = consumerID("other domain")
							case "coordinate":
								pin.Coordinate.CoordinateID = consumerID("other coordinate")
							case "binding":
								pin.Coordinate.LastBindingIncarnationID = consumerID("other binding")
							case "entry":
								pin.Coordinate.LastEntryIncarnationID = consumerID("other entry")
							case "target digest":
								pin.Coordinate.DeletionTargetRowDigest = consumerID("other target")
							case "service":
								changed.ServiceContractID = "other"
							case "target":
								changed.CanonicalTarget = "other"
							case "destination":
								pin.Coordinate.DeletionDestinationID = "other"
							case "consumer":
								changed.ConsumerLocator = "other"
							case "target-contract":
								changed.TargetContractID = "other"
							case "locator-mode":
								changed.LocatorRequiresCreation = true
							case "target-data":
								changed.TargetData = []byte("group")
							case "encoding":
								if changed.PayloadEncoding == contract.OutputEncodingRaw {
									changed.PayloadEncoding = contract.OutputEncodingBase64
								} else {
									changed.PayloadEncoding = contract.OutputEncodingRaw
								}
							case "policy":
								changed.Policy = contract.OutputPolicy{ContractID: "other", Data: []byte("other")}
							case "marker action":
								marker.Projection.Action = contract.PublicationUpdatePolicy
							case "marker state":
								if action == contract.PublicationDeleteOwned {
									marker.State = contract.PublicationUnknown
								} else {
									marker.State = contract.PublicationAcknowledged
								}
							case "marker attempt":
								marker.AttemptID = consumerID("other attempt")
							case "marker target":
								marker.Projection.TargetRowDigest = consumerID("other target")
							case "marker service":
								marker.BirthServiceContractID = "other"
							case "wrong proof kind":
								pin.Birth, pin.UncertainCreate = pin.UncertainCreate, pin.Birth
							case "selected value":
								value := publicationPlainFixture(t, p.DomainID, p.ActingRecipientID)
								selected = &value
							case "route":
								_, route = consumerFixture(t)
							case "bounds":
								maximum = 1
							}
							if field == "marker target" {
								var err error
								marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
								if err != nil {
									t.Fatal(err)
								}
							}
							if payload, _, code := preparePublicationValue(context.Background(), p, destination, changed, ptr, selected, route, minimum, maximum); code != contract.CryptoInvalidAdmission || payload != nil {
								t.Fatalf("damaged delete accepted code=%v", code)
							}
						})
					}
					if action == contract.PublicationDeleteOwned {
						historical := *deletion
						historical.Coordinate.OwnedBirthAttemptID = consumerID("new owned birth")
						historical.Coordinate.OwnedInstanceDigest = consumerID("new owned instance")
						if _, _, code := preparePublicationValue(context.Background(), p, destination, target, &historical, nil, nil, 0, 0); code != contract.CryptoSuccess {
							t.Fatal("historical retained birth refused", code)
						}
					}
				})
			}
		})
	}
}

// full_only: false
func TestPublicationPacketRefusalClearsPrivateCapacity(t *testing.T) {
	for _, encoding := range []string{"raw", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			secret, route := consumerFixture(t)
			selected := publicationSelectedValue{Secret: &secret}
			projection, destination, target := publicationProjectionFixture(t, secret.DomainID, secret.Binding.SubjectID, &selected, contract.PublicationCreateWithValue)
			projection, target = publicationEncodingFixture(t, projection, destination, target, &selected, encoding)
			for _, damage := range []string{"kind", "length"} {
				t.Run(damage, func(t *testing.T) {
					route.override = func(ctx context.Context, b contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
						if length != 100 {
							t.Fatalf("private packet length %d, want 100", length)
						}
						got := route.testKeyAccess.Decrypt(ctx, b, ciphertext, length)
						if got.Status != KeyOK || len(got.Packet) != 100 {
							t.Fatal("valid private packet fixture refused before damage")
						}
						if damage == "kind" {
							got.Packet[3] = 4
						} else {
							got.Packet = got.Packet[:len(got.Packet)-1]
						}
						return got
					}
					calls := route.privateCalls
					payload, rows, code := preparePublicationValue(context.Background(), projection, destination, target, nil, &selected, route, 0, maximumPublicationPayloadBytes)
					wantRows := []contract.KeyUseRow{independentKeyUseRow(secret.Binding, 3, 1, 1)}
					if payload != nil || code != contract.CryptoStoredAuthenticationFailed || route.privateCalls != calls+1 || !slices.Equal(rows, wantRows) {
						t.Fatalf("packet refusal differs: code=%v calls=%d rows=%+v", code, route.privateCalls-calls, rows)
					}
					if len(route.returned) <= 100 || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
						t.Fatal("packet refusal retained private capacity")
					}
				})
			}
		})
	}
}
