package crypto

import (
	"bytes"
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// These faults follow exact route admission. Packet damage changes the result
// of a real private decrypt, rather than bypassing packet authentication.
func privateOpenFault(route *consumerTestRoute, fault string) {
	route.override = func(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
		switch fault {
		case "rsa":
			return route.testKeyAccess.Decrypt(ctx, binding, make([]byte, len(ciphertext)), length)
		case "packet":
			result := route.testKeyAccess.Decrypt(ctx, binding, ciphertext, length)
			if result.Status == KeyOK {
				result.Packet[0] ^= 1
			}
			return result
		case "denied":
			return PrivateResult{Status: KeyDenied, Uses: KeyUses{Denied: 1}}
		case "unknown":
			return PrivateResult{Status: KeyUnknown, Uses: KeyUses{Unknown: 1}}
		case "unavailable":
			return PrivateResult{Status: KeyUnavailable, Uses: KeyUses{Unknown: 1}}
		default:
			return PrivateResult{Status: KeyCancelled}
		}
	}
}

func checkPrivateOpenFailure(t *testing.T, fault string, authentication, code contract.CryptoResultCode, response contract.CryptoResponse, route *consumerTestRoute) {
	t.Helper()
	want, outcome := contract.CryptoCancelled, uint8(0)
	switch fault {
	case "rsa":
		want, outcome = authentication, contract.KeyUseFailed
	case "packet":
		want, outcome = authentication, contract.KeyUseCompleted
	case "denied":
		want, outcome = contract.CryptoPrivateRouteUnavailable, contract.KeyUseDenied
	case "unknown":
		want, outcome = contract.CryptoResponseUnknown, contract.KeyUseUnknown
	case "unavailable":
		want, outcome = contract.CryptoCustodyUnavailable, contract.KeyUseUnknown
	case "cancelled":
	default:
		t.Fatal("unknown private-open fault", fault)
	}
	if code != want || len(response.Body) != 0 {
		t.Fatalf("result %v, want %v with no partial output", code, want)
	}
	if outcome == 0 {
		if len(response.KeyUseRows) != 0 {
			t.Fatal("cancellation invented a key use")
		}
	} else if len(response.KeyUseRows) != 1 || response.KeyUseRows[0].Count != 1 || response.KeyUseRows[0].Outcome != outcome || response.KeyUseRows[0].Purpose != contract.KeyUseMaterialOpen {
		t.Fatal("private-open evidence lost or successor wrapping attempted", response.KeyUseRows)
	}
	if !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
		t.Fatal("failed open retained private packet capacity")
	}
}

// full_only: false
func TestGeneratedPrivateOpenFailureConsumesAdmission(t *testing.T) {
	for _, mode := range []string{"source", "canonical", "seed"} {
		for _, fault := range []string{"rsa", "packet", "denied", "unknown", "unavailable", "cancelled"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				var f generatedRuntimeFixture
				switch mode {
				case "source":
					f = generatedSealedPlanFixture(t, false)
				case "canonical":
					f = generatedCanonicalPlanFixture(t, false)
				case "seed":
					f, _, _ = generatedAdoptionFixture(t, false)
				}
				var r *Runtime
				if mode == "seed" {
					r = f.adoptionRuntime(t)
				} else {
					r = f.reservationRuntime(t)
				}
				kind := contract.CryptoCompare
				body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
				if err != nil {
					t.Fatal(err)
				}
				authentication := contract.CryptoStoredAuthenticationFailed
				if mode != "seed" {
					op := generatedCompare(t, r, f)
					kind = contract.CryptoPrepare
					body, err = contract.EncodeCryptoGeneratedPlanPartRequest(contract.CryptoGeneratedPlanPartRequest{
						OperationRef: op, Context: f.compare.Context, BlobKind: 2, Count: 1,
						Total: uint64(len(f.declaration)), WholeDigest: contract.Hash(f.declaration), Payload: f.declaration})
					if err != nil {
						t.Fatal(err)
					}
					if mode == "source" {
						authentication = contract.CryptoSourceAuthenticationFailed
					}
				}
				privateOpenFault(f.base.route, fault)
				reply := applyCall(r, context.Background(), kind, body)
				checkPrivateOpenFailure(t, fault, authentication, reply.ResultCode, reply, f.base.route)
				f.base.route.override = nil
				calls := f.base.route.privateCalls
				if retry := applyCall(r, context.Background(), kind, body); retry.ResultCode != contract.CryptoAlreadyUsed || len(retry.Body) != 0 || f.base.route.privateCalls != calls {
					t.Fatal("failed operation restarted after the private route recovered", retry.ResultCode)
				}
			})
		}
	}
}

// full_only: false
func TestReplacementPacketFailureEvidence(t *testing.T) {
	selection, route := consumerFixture(t)
	material := contract.OperationMaterialRecord{Core: contract.OperationMaterialCore{
		Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: selection.Core.CompatibilityID,
		CryptoSupportID: selection.Core.CryptoSupportID, DomainID: selection.DomainID,
		OperationID: consumerID("packet operation"), OperationMaterialID: consumerID("packet material"),
		UsePlanDigest: consumerID("packet use plan"), SeedEpoch: 1}}
	seed := bytes.Repeat([]byte{0x52}, 32)
	defer clear(seed)
	var err error
	material.SeedCheck, err = custody.SeedCheck(material.Core, seed)
	if err != nil {
		t.Fatal(err)
	}
	core, err := custody.SeedWrapCore(material.Core, selection.Binding)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := custody.Wrap(core, selection.Binding.Binding, seed)
	if err != nil {
		t.Fatal(err)
	}
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: 3, MaterialID: material.Core.OperationMaterialID,
		MaterialContextDigest: core.MaterialContextDigest, PackageCheck: material.SeedCheck, Wraps: []contract.WrapRow{wrap}}
	for _, kind := range []uint16{1, 3} {
		name := "value"
		if kind == 3 {
			name = "seed"
		}
		for _, fault := range []string{"rsa", "packet", "denied", "unknown", "unavailable", "cancelled"} {
			t.Run(name+"/"+fault, func(t *testing.T) {
				privateOpenFault(route, fault)
				row := contract.CompactRow{Coverage: contract.CoverageRow{MaterialKind: kind, SourceBindingIndex: 0, TargetBindingIndices: []uint16{1}},
					ValueCore: selection.Core, BeforeAccessRecord: selection.Access}
				if kind == 3 {
					row.OperationMaterialCore, row.BeforeAccessRecord = material.Core, access
				}
				successor := selection.Binding
				successor.Binding.BindingID = consumerID("packet failure successor")
				successor.Binding.BindingSerial++
				a := accessAdmission{request: contract.CryptoAccessReplaceRequest{BindingTable: []contract.BindingTableRow{selection.Binding, successor}}}
				var response contract.CryptoResponse
				after, code := a.rewrap(context.Background(), route, row, &response)
				if !reflect.ValueOf(after).IsZero() {
					t.Fatal("failed replacement returned partial access")
				}
				checkPrivateOpenFailure(t, fault, contract.CryptoStoredAuthenticationFailed, code, response, route)
			})
		}
	}
}

// full_only: false
func TestGeneratedProducerConcurrentEntryIsSingleUse(t *testing.T) {
	f, _, c := generatedProducerFixture(t, false)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return generatedProducerReturn{Facts: generatedProducerFacts(f.producer.Producer.Expected), Secret: []byte("provider-secret")}
	}
	r := f.producerRuntime(t)
	op, uses := generatedAdoptionCompare(t, r, f)
	locator := generatedProducerPrepare(t, r, f, op)
	authority := generatedProducerClaim(t, r, f, c, op, uses)
	start := make(chan struct{})
	results := make(chan generatedProducerOutput, 2)
	for range 2 {
		go func() {
			<-start
			results <- r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority)
		}()
	}
	close(start)
	<-entered
	first := <-results
	close(release)
	second := <-results
	if first.code != contract.CryptoAlreadyUsed || len(first.Record) != 0 || second.code != contract.CryptoSuccess || len(second.Record) == 0 || calls.Load() != 1 {
		t.Fatal("concurrent calls changed the single entry or original result", first.code, second.code, calls.Load())
	}
}

// full_only: false
func TestGeneratedProducerRefusedEntryConsumesDecision(t *testing.T) {
	for _, fault := range []string{"cancelled", "locator", "authority"} {
		t.Run(fault, func(t *testing.T) {
			f, _, c := generatedProducerFixture(t, false)
			calls := 0
			f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
				calls++
				return generatedProducerReturn{Facts: generatedProducerFacts(f.producer.Producer.Expected), Secret: []byte("provider-secret")}
			}
			r := f.producerRuntime(t)
			op, uses := generatedAdoptionCompare(t, r, f)
			locator := generatedProducerPrepare(t, r, f, op)
			authority := generatedProducerClaim(t, r, f, c, op, uses)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			badLocator, badAuthority := locator, authority
			switch fault {
			case "cancelled":
				cancel()
			case "locator":
				badLocator[0] ^= 1
			case "authority":
				badAuthority[0] ^= 1
			}
			if out := r.invokeGeneratedProducer(ctx, f.compare.Context.AdmissionID, badLocator, badAuthority); out.code == contract.CryptoSuccess || len(out.Record) != 0 || calls != 0 {
				t.Fatal("invalid entry called the producer", out.code, calls)
			}
			if out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority); out.code == contract.CryptoSuccess || len(out.Record) != 0 || calls != 0 {
				t.Fatal("corrected invocation restored the spent decision", out.code, calls)
			}
		})
	}
}

// full_only: false
func TestGeneratedProducerWrongOwnerPreservesLiveAdmission(t *testing.T) {
	f, _, c := generatedProducerFixture(t, false)
	r := f.producerRuntime(t)
	op, uses := generatedAdoptionCompare(t, r, f)
	locator := generatedProducerPrepare(t, r, f, op)
	authority := generatedProducerClaim(t, r, f, c, op, uses)
	wrong := f.compare.Context.AdmissionID
	wrong[0] ^= 1
	if out := r.invokeGeneratedProducer(context.Background(), wrong, locator, authority); out.code != contract.CryptoInvalidAdmission || len(out.Record) != 0 {
		t.Fatal("wrong owner entered", out.code)
	}
	if out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority); out.code != contract.CryptoSuccess || len(out.Record) == 0 {
		t.Fatal("wrong owner consumed another admission", out.code)
	}
}

type generatedEntryContext struct {
	context.Context
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *generatedEntryContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.Context.Done()
}

type generatedEntryWindowContext struct {
	installed chan struct{}
	release   chan struct{}
	done      chan struct{}
	once      sync.Once
}

func (c *generatedEntryWindowContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *generatedEntryWindowContext) Done() <-chan struct{}       { return c.done }
func (c *generatedEntryWindowContext) Value(any) any               { return nil }
func (c *generatedEntryWindowContext) Err() error {
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}

func (c *generatedEntryWindowContext) cancel() { c.once.Do(func() { close(c.done) }) }

func (c *generatedEntryWindowContext) AfterFunc(f func()) func() bool {
	close(c.installed)
	<-c.release
	go func() {
		<-c.done
		f()
	}()
	return func() bool { return false }
}

// full_only: false
func TestGeneratedProducerCancellationBeforeTransferStartsNoEffect(t *testing.T) {
	f, _, candidate := generatedProducerFixture(t, false)
	var calls atomic.Int32
	f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
		calls.Add(1)
		return generatedProducerReturn{Facts: generatedProducerFacts(f.producer.Producer.Expected), Secret: []byte("provider-secret")}
	}
	r := f.producerRuntime(t)
	op, uses := generatedAdoptionCompare(t, r, f)
	locator := generatedProducerPrepare(t, r, f, op)
	authority := generatedProducerClaim(t, r, f, candidate, op, uses)
	ctx := &generatedEntryWindowContext{installed: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
	result := make(chan generatedProducerOutput, 1)
	go func() { result <- r.invokeGeneratedProducer(ctx, f.compare.Context.AdmissionID, locator, authority) }()
	<-ctx.installed
	ctx.cancel()
	close(ctx.release)
	out := <-result
	if out.code != contract.CryptoCancelled || len(out.Record) != 0 || calls.Load() != 0 {
		t.Fatal("cancellation before entry transfer started the producer", out.code, calls.Load())
	}
}

// full_only: false
func TestGeneratedProducerCancelledEntryJoinsClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, _, c := generatedProducerFixture(t, false)
		var calls atomic.Int32
		f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
			calls.Add(1)
			return generatedProducerReturn{}
		}
		r := f.producerRuntime(t)
		op, uses := generatedAdoptionCompare(t, r, f)
		locator := generatedProducerPrepare(t, r, f, op)
		authority := generatedProducerClaim(t, r, f, c, op, uses)
		ownedSeed := r.generated.seed
		caller, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx := generatedEntryContext{Context: caller, entered: make(chan struct{}), release: make(chan struct{})}
		result := make(chan generatedProducerOutput, 1)
		go func() { result <- r.invokeGeneratedProducer(&ctx, f.compare.Context.AdmissionID, locator, authority) }()
		<-ctx.entered
		cancel()
		closed := make(chan struct{})
		go func() { r.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Error("Close returned while entry still owned the decision")
		default:
		}
		if bytes.Equal(ownedSeed, make([]byte, len(ownedSeed))) {
			t.Error("entry observed cleared material")
		}
		close(ctx.release)
		out := <-result
		<-closed
		if out.code != contract.CryptoCancelled || calls.Load() != 0 || !bytes.Equal(ownedSeed, make([]byte, len(ownedSeed))) {
			t.Fatal("cancelled entry did not join and clear", out.code, calls.Load())
		}
		late := generatedEntryContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
		go func() { result <- r.invokeGeneratedProducer(&late, f.compare.Context.AdmissionID, locator, authority) }()
		select {
		case out := <-result:
			if out.code == contract.CryptoSuccess || len(out.Record) != 0 {
				t.Fatal("closed runtime admitted producer work")
			}
		case <-late.entered:
			close(late.release)
			<-result
			t.Fatal("closed runtime inspected a new entry after disposal")
		}
	})
}

// full_only: false
func TestGeneratedProducerCancelledClaimDoesNotGrantEntry(t *testing.T) {
	f, _, c := generatedProducerFixture(t, false)
	r := f.producerRuntime(t)
	op, uses := generatedAdoptionCompare(t, r, f)
	locator := generatedProducerPrepare(t, r, f, op)
	if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, c); code != contract.CryptoSuccess {
		t.Fatal("bind producer", code)
	}
	q := generatedCandidateRequest(t, f, op, c, nil, uses)
	if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("freeze producer", reply.ResultCode)
	}
	body, err := contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if reply := applyCall(r, ctx, contract.CryptoClaim, body); reply.ResultCode != contract.CryptoCancelled {
		t.Fatal("cancelled claim accepted", reply.ResultCode)
	}
	if reply := applyCall(r, context.Background(), contract.CryptoClaim, body); reply.ResultCode == contract.CryptoSuccess {
		t.Fatal("fresh context restored claim")
	}
	authority, err := contract.GeneratorAuthorityDigest(c.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority); out.code == contract.CryptoSuccess || len(out.Record) != 0 {
		t.Fatal("cancelled claim granted entry")
	}
}

// full_only: false
func TestGeneratedProducerExpiredClaimCannotBeRestored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, _, c := generatedProducerFixture(t, false)
		r := f.producerRuntime(t)
		op, uses := generatedAdoptionCompare(t, r, f)
		locator := generatedProducerPrepare(t, r, f, op)
		if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, c); code != contract.CryptoSuccess {
			t.Fatal("bind producer", code)
		}
		q := generatedCandidateRequest(t, f, op, c, nil, uses)
		if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoSuccess {
			t.Fatal("freeze producer", reply.ResultCode)
		}
		body, err := contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Until(f.base.deadline))
		synctest.Wait()
		for range 2 {
			if reply := applyCall(r, context.Background(), contract.CryptoClaim, body); reply.ResultCode == contract.CryptoSuccess || len(reply.Body) != 0 {
				t.Fatal("expired claim restored preparation")
			}
		}
		authority, err := contract.GeneratorAuthorityDigest(c.Subject)
		if err != nil {
			t.Fatal(err)
		}
		if out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority); out.code == contract.CryptoSuccess || len(out.Record) != 0 {
			t.Fatal("expired claim granted entry")
		}
	})
}
