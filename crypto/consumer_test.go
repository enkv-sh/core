package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func consumerID(s string) contract.ID { return contract.Hash([]byte(s)) }

type consumerTestSink struct {
	mu                  sync.Mutex
	id                  contract.ID
	accepts, closes     int
	closed              bool
	accepted            contract.ID
	length              int
	prefix              int
	acceptErr, closeErr error
	started, release    chan struct{}
	work                sync.WaitGroup
	observed            *[]byte
}

func (s *consumerTestSink) Identity() contract.ID { return s.id }
func (s *consumerTestSink) Accept(ctx context.Context, plain []byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("sink closed")
	}
	s.work.Add(1)
	s.accepts++
	s.accepted, s.length = contract.Hash(plain), len(plain)
	if s.prefix > 0 && s.prefix < len(plain) {
		s.accepted, s.length = contract.Hash(plain[:s.prefix]), s.prefix
	}
	if s.observed != nil {
		*s.observed = plain[:cap(plain)]
	}
	if s.started != nil {
		close(s.started)
	}
	s.mu.Unlock()
	defer s.work.Done()
	if s.release != nil {
		<-s.release
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.acceptErr
}
func (s *consumerTestSink) Close() error {
	s.mu.Lock()
	s.closes++
	s.closed = true
	if s.release != nil {
		close(s.release)
	}
	s.mu.Unlock()
	s.work.Wait()
	return s.closeErr
}

type consumerTestRoute struct {
	*testKeyAccess
	override func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult
}

func (a *consumerTestRoute) Decrypt(ctx context.Context, b contract.KMSBinding, c []byte, n uint16) PrivateResult {
	if a.override != nil {
		return a.override(ctx, b, c, n)
	}
	return a.testKeyAccess.Decrypt(ctx, b, c, n)
}

func consumerFixture(t *testing.T) (contract.ConsumerSelection, *consumerTestRoute) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	binding := contract.KMSBinding{BindingID: consumerID("binding"), BindingIncarnationID: consumerID("binding incarnation"), BindingSerial: 1, Provider: contract.GCP, WrapProfile: 2, ProtectionClass: 2, KeySelector: "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/recipient/cryptoKeyVersions/1", SPKI: spki, Fingerprint: contract.Hash(spki)}
	row := contract.BindingTableRow{SubjectKind: 1, SubjectID: consumerID("recipient"), Binding: binding}
	core := contract.ValueCore{ValueSource: 1, Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: consumerID("domain"), Name: "secret", EntryIncarnationID: consumerID("incarnation"), ValueStateID: consumerID("value"), OriginSnapshotID: consumerID("origin snapshot"), OriginTransitionID: consumerID("transition"), DataKeyID: consumerID("data"), DataKeyEpoch: 1, CommitmentKeyID: consumerID("commitment"), CommitmentKeyEpoch: 1, ContentLength: 12, InputEncoding: contract.InputEncodingRaw, RetainedLength: 12}
	payload, keys, err := custody.SealValue(core, []byte("secret-value"))
	if err != nil {
		t.Fatalf("consumer fixture seal value: %v", err)
	}
	defer clear(keys[:cap(keys)])
	wrapCore, err := custody.ValueWrapCore(core, row)
	if err != nil {
		t.Fatalf("consumer fixture wrap context: %v", err)
	}
	wrap, err := custody.Wrap(wrapCore, binding, keys)
	if err != nil {
		t.Fatalf("consumer fixture wrap: %v", err)
	}
	selection := contract.ConsumerSelection{DomainID: core.DomainID, SnapshotID: consumerID("selected snapshot"), HEADDigest: consumerID("head"), AccessRoot: consumerID("access root"), HEADRevision: consumerID("head revision"), HEADToken: contract.Token{Family: contract.GCP, Value: "1"}, Core: core, Payload: payload, Binding: row, Slot: 3,
		Root:   contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: core.DomainID, Object: consumerID("selected snapshot"), Digest: consumerID("root"), Length: 123},
		Entry:  contract.ValueEntry{Name: core.Name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID, OriginSnapshot: core.OriginSnapshotID, OriginTransition: core.OriginTransitionID, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{row.SubjectID}, InputEncoding: core.InputEncoding, OutputEncoding: contract.OutputEncodingRaw, ContentLength: core.ContentLength, RetainedLength: core.RetainedLength},
		Access: contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: 1, MaterialID: core.ValueStateID, MaterialContextDigest: wrapCore.MaterialContextDigest, PackageCheck: payload.PackageCheck, Wraps: []contract.WrapRow{wrap}}}
	refreshConsumerSelection(t, &selection)
	return selection, &consumerTestRoute{testKeyAccess: &testKeyAccess{key: key, binding: binding}}
}

func refreshConsumerSelection(t *testing.T, selection *contract.ConsumerSelection) {
	t.Helper()
	var err error
	selection.Entry.ValueBytes, err = contract.EncodeCanonicalPayload(selection.Payload)
	if err != nil {
		t.Fatal(err)
	}
	selection.EntryDigest, err = contract.PublicValueEntryDigest(selection.DomainID, selection.Slot, selection.Entry)
	if err != nil {
		t.Fatal(err)
	}
}

func newConsumerRuntime(t *testing.T, route *consumerTestRoute) *Runtime {
	t.Helper()
	r, err := New(contract.GCP, []KeyAccess{route})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func admitTestConsumer(t *testing.T, r *Runtime, selection contract.ConsumerSelection, route *consumerTestRoute, sink *consumerTestSink) {
	t.Helper()
	if err := r.admitConsumer(consumerID("admission"), consumerID("purpose"), sink.id, route.CredentialRoute(), selection, sink, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func generatedConsumerMetadata(value contract.ID) contract.GeneratedEntryMetadata {
	return contract.GeneratedEntryMetadata{Schema: contract.GeneratedEntryMetadataSchema, Epoch: 1, ConfigContractID: consumerID("generated config"), ResourceContractID: consumerID("generated resource contract"), LifecycleMode: contract.GeneratorLifecycleManaged,
		IntentDigest: consumerID("generated intent"), ResourceIncarnationID: consumerID("generated resource"), OriginOperationID: consumerID("generated operation"),
		OriginAttemptID: consumerID("generated attempt"), GenerationID: value, ResourceDigest: consumerID("generated resource digest"),
		CreateResultID: consumerID("generated result"), CreateEvidence: contract.GeneratorDescriptor{Digest: consumerID("generated evidence"), Length: 8, Count: 1},
		RequiredSupport: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), CompletionClass: 1, RetirementMode: 1}
}

func makeGeneratedConsumerSelection(t *testing.T, selection *contract.ConsumerSelection) {
	t.Helper()
	selection.Entry.ValueSource = contract.Generated
	selection.Entry.Generated = generatedConsumerMetadata(selection.Core.ValueStateID)
	selection.Core.ValueSource = contract.Generated
	var err error
	selection.Core.GeneratedBindingDigest, err = contract.GeneratedBindingDigest(selection.Entry.Generated)
	if err != nil {
		t.Fatal(err)
	}
	payload, keys, err := custody.SealValue(selection.Core, []byte("secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys[:cap(keys)])
	wrapCore, err := custody.ValueWrapCore(selection.Core, selection.Binding)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := custody.Wrap(wrapCore, selection.Binding.Binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	selection.Payload = payload
	selection.Access.MaterialContextDigest, selection.Access.PackageCheck = wrapCore.MaterialContextDigest, payload.PackageCheck
	selection.Access.Wraps = []contract.WrapRow{wrap}
	refreshConsumerSelection(t, selection)
}

// full_only: false
func TestGeneratedConsumerRejectsSourceAndBindingRelabelingBeforeOwnership(t *testing.T) {
	for _, generated := range []bool{false, true} {
		selection, route := consumerFixture(t)
		if generated {
			makeGeneratedConsumerSelection(t, &selection)
			selection.Entry.Generated.ResourceDigest = consumerID("different generated resource digest")
		} else {
			selection.Entry.ValueSource = contract.Generated
			selection.Entry.Generated = generatedConsumerMetadata(selection.Core.ValueStateID)
		}
		refreshConsumerSelection(t, &selection)
		r := newConsumerRuntime(t, route)
		sink := &consumerTestSink{id: consumerID("generated consumer sink")}
		err := r.admitConsumer(consumerID("generated consumer admission"), consumerID("generated consumer purpose"), sink.id, route.CredentialRoute(), selection, sink, time.Now().Add(time.Minute))
		if err == nil {
			t.Errorf("changed immutable member accepted (generated=%v)", generated)
		}
		if r.slot != nil || route.privateCalls != 0 || sink.closes != 0 || sink.accepts != 0 {
			t.Errorf("invalid member transferred private ownership (generated=%v)", generated)
		}
	}
}

// full_only: false
func TestGeneratedConsumerOpensExactGeneratedMember(t *testing.T) {
	selection, route := consumerFixture(t)
	makeGeneratedConsumerSelection(t, &selection)
	r := newConsumerRuntime(t, route)
	sink := &consumerTestSink{id: consumerID("generated consumer sink")}
	admitTestConsumer(t, r, selection, route, sink)
	result := r.consume(context.Background(), consumerID("admission"))
	if result.code != contract.CryptoSuccess || sink.accepts != 1 || sink.accepted != contract.Hash([]byte("secret-value")) {
		t.Fatal("generated member consumer", result.code)
	}
}

// full_only: false
func TestConsumerSelectedReopenAndOwnership(t *testing.T) {
	metricContext, reader := cryptoTelemetryReader(t)
	selection, route := consumerFixture(t)
	r := newConsumerRuntime(t, route)
	var observed []byte
	sink := &consumerTestSink{id: consumerID("sink"), observed: &observed}
	if got := r.consume(metricContext, consumerID("admission")); got.code != contract.CryptoInvalidAdmission || got.delivery != consumerDeliveryNone {
		t.Fatal("public selection minted admission")
	}
	admitTestConsumer(t, r, selection, route, sink)
	if got := r.consume(metricContext, consumerID("wrong admission")); got.code != contract.CryptoInvalidAdmission || got.delivery != consumerDeliveryNone || route.privateCalls != 0 {
		t.Fatal("wrong admission entered private work")
	}
	if err := r.admitConsumer(consumerID("another"), consumerID("purpose"), sink.id, route.CredentialRoute(), selection, sink, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("occupied private slot replaced")
	}
	// All variable input owners can change after admission; retained facts cannot.
	clear(selection.Entry.ValueBytes)
	clear(selection.Entry.Recipients)
	clear(selection.Payload.Ciphertext)
	clear(selection.Access.Wraps[0].RSACiphertext)
	clear(selection.Binding.Binding.SPKI)
	got := r.consume(metricContext, consumerID("admission"))
	if got.code != contract.CryptoSuccess || got.delivery != consumerDeliveryComplete || len(got.keyUses) != 1 || got.keyUses[0].Purpose != contract.KeyUseMaterialOpen || got.keyUses[0].Outcome != contract.KeyUseCompleted || got.keyUses[0].Count != 1 {
		t.Fatalf("selected reopen result %+v", got)
	}
	assertCryptoTelemetry(t, reader, "crypto.consume", map[string]int64{"admission_refused": 2, "success": 1})
	<-r.consumer.done
	if sink.accepts != 1 || sink.closes != 1 || sink.accepted != contract.Hash([]byte("secret-value")) || sink.length != 12 {
		t.Fatal("wrong sink delivery")
	}
	if !bytes.Equal(observed, make([]byte, len(observed))) || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
		t.Fatal("private backing capacity retained")
	}
	if r.consumer.sink != nil || r.consumer.selection.Entry.ValueBytes != nil || r.consumer.selection.Binding.Binding.SPKI != nil {
		t.Fatal("consumer retained completed owners")
	}
	if got := r.consume(context.Background(), consumerID("admission")); got.code != contract.CryptoAlreadyUsed || got.delivery != consumerDeliveryNone {
		t.Fatal("consumer reused")
	}
	r.retireConsumer()
	if r.slot != nil || r.consumer != nil {
		t.Fatal("consumer slot not retired")
	}
}

// full_only: false
func TestConsumerAdmissionRefusesInconsistentSelectedFacts(t *testing.T) {
	base, route := consumerFixture(t)
	t.Run("empty duplicate payload input class", func(t *testing.T) {
		selected := base
		selected.Core.ContentLength, selected.Core.RetainedLength = 0, 0
		payload, keys, err := custody.SealValue(selected.Core, nil)
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
		selected.Entry.ContentLength, selected.Entry.RetainedLength = 0, 0
		selected.Access = contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind,
			MaterialID: selected.Core.ValueStateID, MaterialContextDigest: wrapCore.MaterialContextDigest, PackageCheck: payload.PackageCheck,
			Wraps: []contract.WrapRow{wrap}}
		refreshConsumerSelection(t, &selected)
		if _, _, ok := checkConsumerSelection(selected, contract.GCP); !ok {
			t.Fatal("exact empty selected value refused")
		}
		selected.Payload.InputEncoding = contract.InputEncodingBase64
		if _, err := contract.CanonicalPayloadLength(selected.Payload); err != nil {
			t.Fatal("class mutation did not retain valid payload shape", err)
		}
		runtime := newConsumerRuntime(t, route)
		sink := &consumerTestSink{id: consumerID("empty sink")}
		if err := runtime.admitConsumer(consumerID("empty admission"), consumerID("empty purpose"), sink.id, route.CredentialRoute(), selected, sink, time.Now().Add(time.Minute)); err == nil {
			t.Fatal("different duplicate input class admitted")
		}
		if runtime.slot != nil || sink.accepts != 0 || sink.closes != 0 || route.privateCalls != 0 {
			t.Fatal("class refusal entered private work or transferred sink")
		}
	})
	for _, tc := range []struct {
		name   string
		damage func(*contract.ConsumerSelection)
	}{
		{"domain", func(s *contract.ConsumerSelection) { s.DomainID = consumerID("foreign") }},
		{"snapshot", func(s *contract.ConsumerSelection) { s.SnapshotID = consumerID("foreign") }},
		{"root", func(s *contract.ConsumerSelection) { s.Root.Kind = contract.ValueEntryPageKind }},
		{"token", func(s *contract.ConsumerSelection) { s.HEADToken.Value = "01" }},
		{"token-family", func(s *contract.ConsumerSelection) { s.HEADToken.Family = contract.AWS }},
		{"head", func(s *contract.ConsumerSelection) { s.HEADDigest = contract.ID{} }},
		{"revision", func(s *contract.ConsumerSelection) { s.HEADRevision = contract.ID{} }},
		{"access-root", func(s *contract.ConsumerSelection) { s.AccessRoot = contract.ID{} }},
		{"slot", func(s *contract.ConsumerSelection) { s.Slot++ }},
		{"digest", func(s *contract.ConsumerSelection) { s.EntryDigest[0] ^= 1 }},
		{"member", func(s *contract.ConsumerSelection) { s.Entry.Incarnation = consumerID("foreign") }},
		{"plain", func(s *contract.ConsumerSelection) { s.Entry.ConfidentialityClass = contract.Plain }},
		{"support", func(s *contract.ConsumerSelection) { s.Core.CryptoSupportID = consumerID("unsupported") }},
		{"compatibility", func(s *contract.ConsumerSelection) { s.Core.CompatibilityID = consumerID("unsupported") }},
		{"raw-length", func(s *contract.ConsumerSelection) { s.Core.ContentLength++ }},
		{"raw-overflow", func(s *contract.ConsumerSelection) { s.Core.ContentLength = contract.CryptoMaxRawValue + 1 }},
		{"payload-duplicate", func(s *contract.ConsumerSelection) { s.Payload.Nonce[0] ^= 1 }},
		{"access-material", func(s *contract.ConsumerSelection) { s.Access.MaterialContextDigest[0] ^= 1 }},
		{"access-package", func(s *contract.ConsumerSelection) { s.Access.PackageCheck[0] ^= 1 }},
		{"missing-wrap", func(s *contract.ConsumerSelection) { s.Access.Wraps = nil }},
		{"binding-serial", func(s *contract.ConsumerSelection) { s.Binding.Binding.BindingSerial++ }},
		{"binding-spki", func(s *contract.ConsumerSelection) { s.Binding.Binding.SPKI = []byte{1} }},
		{"recovery-route", func(s *contract.ConsumerSelection) { s.Binding.SubjectKind = 2 }},
		{"foreign-recipient", func(s *contract.ConsumerSelection) { s.Binding.SubjectID = consumerID("foreign") }},
		{"foreign-provider", func(s *contract.ConsumerSelection) { s.Binding.Binding.Provider = contract.AWS }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newConsumerRuntime(t, route)
			s := base
			tc.damage(&s)
			sink := &consumerTestSink{id: consumerID("sink")}
			if err := r.admitConsumer(consumerID("admission"), consumerID("purpose"), sink.id, route.CredentialRoute(), s, sink, time.Now().Add(time.Minute)); err == nil {
				t.Fatal("inconsistent selected facts admitted")
			}
			if r.slot != nil || sink.accepts != 0 || sink.closes != 0 {
				t.Fatal("refusal transferred sink ownership")
			}
		})
	}
	if route.privateCalls != 0 {
		t.Fatal("admission performed private operation")
	}
}

// full_only: false
func TestConsumerAuthenticationFailureNeverDelivers(t *testing.T) {
	base, route := consumerFixture(t)
	for _, damage := range []string{"package", "nonce", "ciphertext", "semantic", "packet-context", "packet-kind", "packet-length", "denied", "unknown", "local-route", "provider-profile", "unavailable"} {
		t.Run(damage, func(t *testing.T) {
			s := base
			s.Payload.Ciphertext = slices.Clone(base.Payload.Ciphertext)
			s.Access.Wraps = slices.Clone(base.Access.Wraps)
			a := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: route.key, binding: route.binding}}
			want := contract.CryptoStoredAuthenticationFailed
			switch damage {
			case "package":
				s.Payload.PackageCheck[0] ^= 1
				s.Access.PackageCheck = s.Payload.PackageCheck
			case "nonce":
				s.Payload.Nonce[0] ^= 1
			case "ciphertext":
				s.Payload.Ciphertext[0] ^= 1
			case "semantic":
				s.Payload.SemanticCommitment[0] ^= 1
			case "denied":
				want = contract.CryptoPrivateRouteUnavailable
				a.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
					return PrivateResult{Status: KeyDenied, Uses: KeyUses{Denied: 1}}
				}
			case "local-route", "provider-profile":
				want = contract.CryptoPrivateRouteUnavailable
				a.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
					uses := KeyUses{}
					if damage == "provider-profile" {
						uses.Failed = 1
					}
					return PrivateResult{Status: KeyInvalid, Uses: uses}
				}
			case "unavailable":
				want = contract.CryptoCustodyUnavailable
				a.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
					return PrivateResult{Status: KeyUnavailable, Uses: KeyUses{Unknown: 1}}
				}
			case "unknown":
				want = contract.CryptoResponseUnknown
				a.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
					return PrivateResult{Status: KeyUnknown, Uses: KeyUses{Unknown: 1}}
				}
			default:
				a.override = func(ctx context.Context, b contract.KMSBinding, c []byte, n uint16) PrivateResult {
					got := a.testKeyAccess.Decrypt(ctx, b, c, n)
					switch damage {
					case "packet-context":
						got.Packet[4] ^= 1
					case "packet-kind":
						got.Packet[3] = 2
					case "packet-length":
						got.Packet = got.Packet[:len(got.Packet)-1]
					}
					return got
				}
			}
			refreshConsumerSelection(t, &s)
			r := newConsumerRuntime(t, a)
			sink := &consumerTestSink{id: consumerID("sink")}
			admitTestConsumer(t, r, s, a, sink)
			got := r.consume(context.Background(), consumerID("admission"))
			<-r.consumer.done
			if got.code != want || got.delivery != consumerDeliveryNone || sink.accepts != 0 || sink.closes != 1 || (len(got.keyUses) != 1 && damage != "local-route") || damage == "local-route" && len(got.keyUses) != 0 {
				t.Fatalf("unsafe failure result %+v", got)
			}
			if !bytes.Equal(a.returned, make([]byte, len(a.returned))) {
				t.Fatal("failed packet capacity retained")
			}
		})
	}
}

// full_only: false
func TestConsumerDeliveryFailureIsUnknownAndCannotRepeat(t *testing.T) {
	selection, route := consumerFixture(t)
	for _, where := range []string{"accept", "close"} {
		t.Run(where, func(t *testing.T) {
			r := newConsumerRuntime(t, route)
			sink := &consumerTestSink{id: consumerID("sink")}
			if where == "accept" {
				sink.acceptErr = errors.New("private sink detail")
				sink.prefix = 3
			} else {
				sink.closeErr = errors.New("private close detail")
			}
			admitTestConsumer(t, r, selection, route, sink)
			got := r.consume(context.Background(), consumerID("admission"))
			<-r.consumer.done
			if got.code != contract.CryptoResponseUnknown || got.delivery != consumerDeliveryUnknown || sink.accepts != 1 || sink.closes != 1 {
				t.Fatalf("failed delivery treated as zero or success: %+v", got)
			}
			if where == "accept" && sink.length != 3 {
				t.Fatal("test sink did not model partial delivery")
			}
			if got := r.consume(context.Background(), consumerID("admission")); got.code != contract.CryptoAlreadyUsed || got.delivery != consumerDeliveryNone || sink.accepts != 1 {
				t.Fatal("failed delivery retried")
			}
		})
	}
}

// full_only: false
func TestConsumerPrivatePinsRefuseBeforeOwnership(t *testing.T) {
	selection, route := consumerFixture(t)
	for _, name := range []string{"admission", "purpose", "sink-id", "wrong-sink", "route-id", "missing-route", "expired", "deadline-overflow", "nil-sink"} {
		t.Run(name, func(t *testing.T) {
			r := newConsumerRuntime(t, route)
			sink := &consumerTestSink{id: consumerID("sink")}
			id, purpose, sinkID, routeID := consumerID("admission"), consumerID("purpose"), sink.id, route.CredentialRoute()
			var receiver consumerSink = sink
			deadline := time.Now().Add(time.Minute)
			switch name {
			case "admission":
				id = contract.ID{}
			case "purpose":
				purpose = contract.ID{}
			case "sink-id":
				sinkID = contract.ID{}
			case "wrong-sink":
				sinkID = consumerID("other sink")
			case "route-id":
				routeID = contract.ID{}
			case "missing-route":
				routeID = consumerID("uninstalled route")
			case "expired":
				deadline = time.Now().Add(-time.Second)
			case "deadline-overflow":
				deadline = time.Date(2263, 1, 1, 0, 0, 0, 0, time.UTC)
			case "nil-sink":
				receiver = nil
			}
			if err := r.admitConsumer(id, purpose, sinkID, routeID, selection, receiver, deadline); err == nil {
				t.Fatal("invalid private pin admitted")
			}
			if r.slot != nil || sink.closes != 0 || sink.accepts != 0 || route.privateCalls != 0 {
				t.Fatal("invalid private pin transferred ownership")
			}
		})
	}
}

// full_only: false
func TestConsumerCancellationExpiryAndCloseJoin(t *testing.T) {
	selection, route := consumerFixture(t)
	t.Run("cancelled-entry", func(t *testing.T) {
		r := newConsumerRuntime(t, route)
		sink := &consumerTestSink{id: consumerID("sink")}
		admitTestConsumer(t, r, selection, route, sink)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got := r.consume(ctx, consumerID("admission"))
		<-r.consumer.done
		if got.code != contract.CryptoCancelled || got.delivery != consumerDeliveryNone || len(got.keyUses) != 0 || sink.accepts != 0 || sink.closes != 1 {
			t.Fatalf("cancelled entry result %+v", got)
		}
	})
	t.Run("abandoned-expiry", func(t *testing.T) {
		r := newConsumerRuntime(t, route)
		sink := &consumerTestSink{id: consumerID("sink")}
		if err := r.admitConsumer(consumerID("admission"), consumerID("purpose"), sink.id, route.CredentialRoute(), selection, sink, time.Now().Add(25*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-r.consumer.done:
		case <-time.After(time.Second):
			t.Fatal("expiry retained sink")
		}
		if sink.accepts != 0 || sink.closes != 1 || r.consumer.sink != nil {
			t.Fatal("expired sink retained")
		}
	})
	t.Run("provider-cancellation-preserves-evidence-and-close-joins", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			a := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: route.key, binding: route.binding, started: make(chan struct{}), release: release}}
			r := newConsumerRuntime(t, a)
			released := false
			t.Cleanup(func() {
				if !released {
					close(release)
				}
			})
			sink := &consumerTestSink{id: consumerID("sink")}
			admitTestConsumer(t, r, selection, a, sink)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan consumerResult, 1)
			go func() { done <- r.consume(ctx, consumerID("admission")) }()
			<-a.started
			if got := r.consume(context.Background(), consumerID("admission")); got.code != contract.CryptoAlreadyUsed {
				t.Fatal("concurrent consumer entered")
			}
			cancel()
			closed := make(chan struct{})
			go func() { r.Close(); close(closed) }()
			synctest.Wait()
			select {
			case <-closed:
				t.Fatal("Close returned before private owner joined")
			default:
			}
			close(release)
			released = true
			got := <-done
			<-closed
			if got.code != contract.CryptoCancelled || got.delivery != consumerDeliveryNone || len(got.keyUses) != 1 || got.keyUses[0].Outcome != contract.KeyUseCompleted || sink.accepts != 0 || sink.closes != 1 {
				t.Fatalf("cancelled provider evidence lost: %+v", got)
			}
		})
	})
	t.Run("sink-cancellation-joins-and-is-unknown", func(t *testing.T) {
		r := newConsumerRuntime(t, route)
		var observed []byte
		sink := &consumerTestSink{id: consumerID("sink"), started: make(chan struct{}), release: make(chan struct{}), observed: &observed}
		admitTestConsumer(t, r, selection, route, sink)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan consumerResult, 1)
		go func() { done <- r.consume(ctx, consumerID("admission")) }()
		<-sink.started
		cancel()
		got := <-done
		<-r.consumer.done
		if got.code != contract.CryptoCancelled || got.delivery != consumerDeliveryUnknown || sink.accepts != 1 || sink.closes != 1 || !bytes.Equal(observed, make([]byte, len(observed))) {
			t.Fatalf("cancelled sink ownership/result %+v", got)
		}
	})
}

// full_only: false
func TestConsumerPostOpenIdentityRefusalIsNotDelivery(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(map[bool]string{false: "stable", true: "changed"}[change], func(t *testing.T) {
			selected, route := consumerFixture(t)
			sink := &consumerTestSink{id: consumerID("sink")}
			route.override = func(ctx context.Context, b contract.KMSBinding, c []byte, n uint16) PrivateResult {
				result := route.testKeyAccess.Decrypt(ctx, b, c, n)
				if change {
					sink.id = consumerID("changed sink")
				}
				return result
			}
			r := newConsumerRuntime(t, route)
			admitTestConsumer(t, r, selected, route, sink)
			got := r.consume(t.Context(), consumerID("admission"))
			<-r.consumer.done
			wantCode, wantDelivery, wantAccepts := contract.CryptoSuccess, consumerDeliveryComplete, 1
			if change {
				wantCode, wantDelivery, wantAccepts = contract.CryptoInvalidAdmission, consumerDeliveryNone, 0
			}
			if got.code != wantCode || got.delivery != wantDelivery || sink.accepts != wantAccepts || sink.closes != 1 || len(got.keyUses) != 1 || got.keyUses[0].Outcome != contract.KeyUseCompleted || got.keyUses[0].Count != 1 {
				t.Fatalf("terminal=%+v accepts=%d closes=%d", got, sink.accepts, sink.closes)
			}
			if !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
				t.Fatal("owned packet retained")
			}
		})
	}
}
