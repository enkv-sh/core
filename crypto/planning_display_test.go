package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"enkv.sh/crypto/internal/custody"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
)

type planningTestDisplayFactory struct {
	id       contract.ID
	sink     *planningTestDisplaySink
	acquires int
	acquire  func()
}

func (f *planningTestDisplayFactory) Identity() contract.ID { return f.id }
func (f *planningTestDisplayFactory) Acquire(context.Context) (PlanningDisplaySink, error) {
	f.acquires++
	if f.acquire != nil {
		f.acquire()
	}
	return f.sink, nil
}

type planningTestDisplaySink struct {
	expected        []byte
	checkValue      bool
	id              contract.ID
	names           []string
	forms           []contract.PlanningSourceForm
	borrowed        []byte
	accepts, closes int
	failAt          int
	closeErr        error
	accept          func(context.Context)
	close           func()
}

func (s *planningTestDisplaySink) Identity() contract.ID { return s.id }
func (s *planningTestDisplaySink) Accept(ctx context.Context, name string, form contract.PlanningSourceForm, plain []byte) error {
	if s.borrowed != nil && !bytes.Equal(s.borrowed, make([]byte, len(s.borrowed))) {
		return errors.New("prior plaintext not cleared")
	}
	if s.checkValue && !bytes.Equal(plain, s.expected) {
		return errors.New("selected plaintext differs")
	}
	s.accepts++
	s.names = append(s.names, name)
	s.forms = append(s.forms, form)
	s.borrowed = plain[:cap(plain)]
	if s.accept != nil {
		s.accept(ctx)
	}
	if s.failAt == s.accepts {
		return errors.New("private sink error sentinel")
	}
	return nil
}
func (s *planningTestDisplaySink) Close() error {
	s.closes++
	if s.close != nil {
		s.close()
	}
	return s.closeErr
}
func planningDisplayFixture(t *testing.T) (contract.PlanningAdmission, *consumerTestRoute, *planningTestDisplayFactory) {
	t.Helper()
	a, route := planningFixture(t)
	id := consumerID("planning display sink")
	a.Options = contract.PlanningOptions{Purpose: contract.PlanningDisplay, SelectedNames: []string{"alpha", "beta"}, SinkID: id}
	return a, route, &planningTestDisplayFactory{id: id, sink: &planningTestDisplaySink{id: id}}
}

// full_only: false
func TestPlanningDisplaySelectedSealedAndRetainedOwnership(t *testing.T) {
	a, route, f := planningDisplayFixture(t)
	target := &a.Targets[1]
	target.Input.Form = contract.PlanningRetained
	target.Input.SealedInput = nil
	target.Input.Retained = contract.RetainedSecretInput{Incarnation: target.Current.Entry.Incarnation, Material: target.Current.Entry.ValueState}
	ctx := planningContext(t)
	c, err := NewPlanningCustody(ctx, route, a)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a.Options.SelectedNames[0] = "changed"
	if r := c.Check(ctx); !r.Complete || r.Code != contract.CryptoSuccess {
		t.Fatal("first pass failed", r)
	}
	if f.acquires != 0 {
		t.Fatal("first pass acquired sink")
	}
	result := c.Display(ctx, f)
	if result.Code != contract.CryptoSuccess || result.Delivery != contract.PlanningDeliveryComplete || result.SelectedRecords != 2 || result.CompletedRecords != 2 || result.OutputFailed || f.acquires != 1 || f.sink.closes != 1 || !reflect.DeepEqual(f.sink.names, []string{"alpha", "beta"}) || !reflect.DeepEqual(f.sink.forms, []contract.PlanningSourceForm{contract.PlanningSealed, contract.PlanningRetained}) {
		t.Fatal("selected delivery differs", result)
	}
	if !bytes.Equal(f.sink.borrowed, make([]byte, len(f.sink.borrowed))) {
		t.Fatal("last borrowed capacity retained plaintext")
	}
	if r := c.Display(ctx, f); r.Code != contract.CryptoAlreadyUsed || f.acquires != 1 {
		t.Fatal("display replayed", r)
	}
}

// full_only: false
func TestPlanningDisplayFailureBarrierAndNoReplay(t *testing.T) {
	base, key, unused := planningDisplayFixture(t)
	_ = unused
	for _, condition := range []string{"unchecked", "equality-owner", "invalid-last", "duplicate", "missing", "identity", "acquired-identity", "short", "short-after-first", "close", "cancel", "late-private"} {
		t.Run(condition, func(t *testing.T) {
			a, route := clonePlanningFixture(t, base, key)
			id := a.Options.SinkID
			f := &planningTestDisplayFactory{id: id, sink: &planningTestDisplaySink{id: id}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if condition == "duplicate" {
				a.Options.SelectedNames = []string{"alpha", "alpha"}
			}
			if condition == "missing" {
				a.Options.SelectedNames = []string{"missing"}
			}
			if condition == "equality-owner" {
				a.Options = contract.PlanningOptions{Purpose: contract.PlanningEquality}
			}
			if condition == "invalid-last" {
				last := &a.Targets[1]
				last.Input.SealedInput = slices.Clone(last.Input.SealedInput)
				last.Input.SealedInput[len(last.Input.SealedInput)-1] ^= 1
			}
			c, err := NewPlanningCustody(ctx, route, a)
			if condition == "duplicate" || condition == "missing" {
				if err == nil {
					c.Close()
					t.Fatal("invalid selector admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if condition == "equality-owner" {
				a.Options = contract.PlanningOptions{Purpose: contract.PlanningDisplay, SelectedNames: []string{"alpha"}, SinkID: id}
			}
			if condition != "unchecked" {
				r := c.Check(ctx)
				if condition == "invalid-last" {
					if r.Complete {
						t.Fatal("bad later source passed")
					}
				} else if !r.Complete {
					t.Fatal(r)
				}
			}
			switch condition {
			case "identity":
				f.id = consumerID("different")
			case "acquired-identity":
				f.sink.id = consumerID("different")
			case "short":
				f.sink.failAt = 1
			case "short-after-first":
				f.sink.failAt = 2
			case "close":
				f.sink.closeErr = errors.New("private close sentinel")
			case "cancel":
				f.sink.accept = func(context.Context) { cancel() }
			case "late-private":
				f.sink.accept = func(context.Context) {
					route.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
						return PrivateResult{Status: KeyUnavailable, Uses: KeyUses{Unknown: 1}}
					}
				}
			}
			result := c.Display(ctx, f)
			entered := condition == "short" || condition == "short-after-first" || condition == "close" || condition == "cancel" || condition == "late-private"
			if result.Code == contract.CryptoSuccess || (result.Delivery == contract.PlanningDeliveryIncomplete) != entered {
				t.Fatal("failed delivery reported completion", condition, result)
			}
			if (condition == "unchecked" || condition == "equality-owner" || condition == "invalid-last" || condition == "identity") && f.acquires != 0 {
				t.Fatal("validation failure acquired sink")
			}
			if condition == "equality-owner" && result.Code != contract.CryptoInvalidAdmission {
				t.Fatal("equality admission did not retain its purpose")
			}
			if condition == "acquired-identity" && (f.sink.accepts != 0 || f.sink.closes != 1) {
				t.Fatal("wrong sink not closed without transfer")
			}
			if condition == "late-private" && (result.CompletedRecords != 1 || result.OutputFailed || result.Code != contract.CryptoCustodyUnavailable) {
				t.Fatal("late private failure lost classification", result)
			}
			if (condition == "short" || condition == "short-after-first" || condition == "close") && !result.OutputFailed {
				t.Fatal("sink failure not classified")
			}
			if !bytes.Equal(f.sink.borrowed, make([]byte, len(f.sink.borrowed))) {
				t.Fatal("failed delivery retained plaintext")
			}
			before := f.acquires
			privateCalls := route.privateCalls
			replay := c.Display(ctx, f)
			if f.acquires != before {
				t.Fatal("failed display replayed")
			}
			if condition == "short-after-first" {
				if result.Code != contract.CryptoResponseUnknown || result.Delivery != contract.PlanningDeliveryIncomplete || !result.OutputFailed || result.SelectedRecords != 2 || result.CompletedRecords != 1 || f.acquires != 1 || f.sink.accepts != 2 || f.sink.closes != 1 {
					t.Fatal("second transfer failure lost completed delivery facts", result)
				}
				if replay.Code != contract.CryptoAlreadyUsed || route.privateCalls != privateCalls || f.acquires != 1 || f.sink.accepts != 2 || f.sink.closes != 1 {
					t.Fatal("partial delivery reopened or replayed", replay.Code)
				}
				backing := make([][]byte, len(c.admission.Targets))
				for i, target := range c.admission.Targets {
					backing[i] = target.Input.SealedInput
				}
				c.Close()
				select {
				case <-c.done:
				default:
					t.Fatal("partial delivery custody did not join")
				}
				if c.admission.Targets != nil || c.targets != nil || c.route != nil || !bytes.Equal(f.sink.borrowed, make([]byte, len(f.sink.borrowed))) || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
					t.Fatal("partial delivery retained custody or private buffers")
				}
				for _, sealed := range backing {
					if !bytes.Equal(sealed, make([]byte, len(sealed))) {
						t.Fatal("partial delivery retained encrypted admission backing")
					}
				}
			}
		})
	}
}

// full_only: false
func TestPlanningDisplayBounds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lengths []uint32
		valid   bool
	}{
		{"none", nil, false}, {"empty", []uint32{0}, true}, {"maximum-value", []uint32{65536}, true}, {"oversized-value", []uint32{65537}, false}, {"maximum-count", make([]uint32, 512), true}, {"oversized-count", make([]uint32, 513), false},
		{"maximum-total", slices.Repeat([]uint32{65536}, 128), true}, {"oversized-total", slices.Repeat([]uint32{65536}, 129), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if planningDisplayBounds(tc.lengths) != tc.valid {
				t.Fatal("preflight bound differs")
			}
		})
	}
}

// full_only: false
func TestPlanningDisplayCloseJoinsBorrowedValue(t *testing.T) {
	a, route, f := planningDisplayFixture(t)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		c, err := NewPlanningCustody(ctx, route, a)
		if err != nil {
			t.Fatal(err)
		}
		if !c.Check(ctx).Complete {
			t.Fatal("checks incomplete")
		}
		started, release, closing := make(chan struct{}), make(chan struct{}), make(chan struct{})
		f.sink.accept = func(context.Context) { close(started); <-release }
		f.sink.close = func() { close(closing); close(release) }
		result := make(chan contract.PlanningDisplayResult, 1)
		go func() { result <- c.Display(ctx, f) }()
		<-started
		joined := make(chan struct{})
		go func() { c.Close(); close(joined) }()
		<-closing
		<-joined
		r := <-result
		if r.Delivery != contract.PlanningDeliveryIncomplete || r.Code != contract.CryptoCancelled || f.sink.closes != 1 || !bytes.Equal(f.sink.borrowed, make([]byte, len(f.sink.borrowed))) || c.admission.Targets != nil {
			t.Fatal("Close failed to join and clear entered output", r)
		}
	})
}

// full_only: false
func TestPlanningDisplayTelemetryExcludesPrivateLengths(t *testing.T) {
	a, route, f := planningDisplayFixture(t)
	base, runtime := cryptoTelemetryReader(t)
	ctx, cancel := context.WithTimeout(base, time.Minute)
	defer cancel()
	owner, err := NewPlanningCustody(ctx, route, a)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if !owner.Check(ctx).Complete || owner.Display(ctx, f).Code != contract.CryptoSuccess {
		t.Fatal("instrumented display failed")
	}
	assertCryptoTelemetry(t, runtime, "crypto.planning_display", map[string]int64{"success": 1})
}

// full_only: false
func TestPlanningDisplaySubsetReopensOnlyExactSelectedBytes(t *testing.T) {
	a, route, f := planningDisplayFixture(t)
	selected := []byte("selected-value-sentinel\x00\xff")
	unselected := []byte("distinct-unselected-content-sentinel")
	defer clear(selected)
	defer clear(unselected)
	planningReseal(t, &a, 0, selected)
	planningReseal(t, &a, 1, unselected)
	a.Options.SelectedNames = []string{"alpha"}
	f.sink.expected = selected
	f.sink.checkValue = true
	base, runtime := cryptoTelemetryReader(t)
	ctx, cancel := context.WithTimeout(base, time.Minute)
	defer cancel()
	owner, err := NewPlanningCustody(ctx, route, a)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	checked := owner.Check(ctx)
	if !checked.Complete {
		t.Fatal("private checks failed")
	}
	before := route.privateCalls
	displayed := owner.Display(ctx, f)
	if displayed.Delivery != contract.PlanningDeliveryComplete || displayed.CompletedRecords != 1 || route.privateCalls-before != 1 || !reflect.DeepEqual(f.sink.names, []string{"alpha"}) {
		t.Fatal("subset reopened an unselected value or lost exact bytes")
	}
	safe, _ := json.Marshal(struct {
		Check   contract.PlanningCheckResult
		Display contract.PlanningDisplayResult
	}{checked, displayed})
	data := cryptoTelemetrySnapshot(t, runtime)
	signals := []byte(fmt.Sprint(data))
	for _, sentinel := range [][]byte{selected, unselected, []byte(base64.StdEncoding.EncodeToString(selected)), []byte(base64.StdEncoding.EncodeToString(unselected))} {
		if bytes.Contains(safe, sentinel) || bytes.Contains(signals, sentinel) {
			t.Fatal("private sentinel escaped safe facts or telemetry")
		}
	}
	assertCryptoTelemetryData(t, data, "crypto.planning_display", map[string]int64{"success": 1})
	if !bytes.Equal(f.sink.borrowed, make([]byte, len(f.sink.borrowed))) {
		t.Fatal("subset plaintext backing not cleared")
	}
}

// full_only: false
func TestPlanningDisplayExactEmptyAndUnicodeNames(t *testing.T) {
	base, key, unused := planningDisplayFixture(t)
	_ = unused
	for _, name := range []string{"", "é/\n"} {
		t.Run(map[bool]string{true: "empty", false: "unicode-slash-newline"}[name == ""], func(t *testing.T) {
			a, route := clonePlanningFixture(t, base, key)
			value := []byte{0, 255, 10}
			defer clear(value)
			envelope, err := contract.DecodeSealedInputEnvelope(a.Targets[0].Input.SealedInput)
			if err != nil {
				t.Fatal(err)
			}
			envelope.Core.Name = name
			envelope.Core.ContentLength = uint32(len(value))
			envelope.Core.RetainedLength = uint32(len(value))
			envelope, err = custody.SealInput(envelope.Core, a.Authority, value)
			if err != nil {
				t.Fatal(err)
			}
			target := &a.Targets[0]
			target.Input.Name = name
			target.Input.SealedInput, err = contract.EncodeSealedInputEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			target.Current = nil
			target.CurrentPresent = false
			target.CurrentValueSource = 0
			target.CurrentConfidentialityClass = 0
			slices.SortFunc(a.Targets, func(x, y contract.PlanningTarget) int { return strings.Compare(x.Input.Name, y.Input.Name) })
			a.Options.SelectedNames = []string{name}
			f := &planningTestDisplayFactory{id: a.Options.SinkID, sink: &planningTestDisplaySink{id: a.Options.SinkID, checkValue: true, expected: value}}
			ctx := planningContext(t)
			owner, err := NewPlanningCustody(ctx, route, a)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			if !owner.Check(ctx).Complete {
				t.Fatal("exact-name check failed")
			}
			result := owner.Display(ctx, f)
			if result.Delivery != contract.PlanningDeliveryComplete || !reflect.DeepEqual(f.sink.names, []string{name}) {
				t.Fatal("exact explicit name lost during disclosure")
			}
		})
	}
}
