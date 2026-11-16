package custody

import (
	"context"
	"crypto/subtle"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// ConsumerCheck is a safe assertion from the private test sink. Delivery is
// zero before a sink call, one on completion, or two if a started call failed.
type ConsumerCheck struct {
	Code         contract.CryptoResultCode
	Delivery     uint8
	ValueMatched bool
	SinkCalls    uint32
	KeyUses      []contract.KeyUseRow
}

type privateSink struct {
	mu                    sync.Mutex
	id                    contract.ID
	expected              []byte
	capturePath           string
	closed, fail, matched bool
	calls                 uint32
}

var errTestSink = errors.New("test sink unavailable")

func (s *privateSink) Identity() contract.ID { return s.id }
func (s *privateSink) Accept(ctx context.Context, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || ctx.Err() != nil {
		return errTestSink
	}
	s.calls++
	if s.capturePath != "" {
		if s.fail || len(value) > contract.CryptoMaxRawValue {
			return errTestSink
		}
		if err := capturePrivateValue(s.capturePath, value); err != nil {
			return errTestSink
		}
		s.matched = true
	} else {
		s.matched = subtle.ConstantTimeCompare(value, s.expected) == 1
	}
	if s.fail || !s.matched {
		return errTestSink
	}
	return nil
}
func (s *privateSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	clear(s.expected[:cap(s.expected)])
	s.expected = nil
	return nil
}

func (f *Fixture) SetSinkFailure(v bool) { f.mu.Lock(); defer f.mu.Unlock(); f.sinkFailure = v }

// Consume is the separate private consumer parent for controlled tests. Its
// caller must obtain selection from the authenticated Core reader. Each call
// explicitly admits a fresh consumer and a facade-owned expected-value sink.
func (f *Fixture) Consume(ctx context.Context, selection contract.ConsumerSelection, choice uint8) (check ConsumerCheck) {
	return f.consume(ctx, selection, choice, nil, "")
}

// ConsumeGenerated uses the selected live owner's retained entry, not a
// current entry with the same name or access-wrap union.
func (f *Fixture) ConsumeGenerated(ctx context.Context, selected GeneratedCanonicalSelection, choice uint8) ConsumerCheck {
	return f.consume(ctx, selected.Selection, choice, &selected, "")
}

// CaptureSelected writes the authenticated application's bytes to a private
// parent-owned oracle file. The parent owns its directory and cleanup lifetime.
func (f *Fixture) CaptureSelected(ctx context.Context, selection contract.ConsumerSelection, path string) ConsumerCheck {
	return f.consume(ctx, selection, 0, nil, path)
}

func (f *Fixture) CaptureGenerated(ctx context.Context, selected GeneratedCanonicalSelection, path string) ConsumerCheck {
	return f.consume(ctx, selected.Selection, 0, &selected, path)
}

func capturePrivateValue(path string, value []byte) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(value) > contract.CryptoMaxRawValue {
		return errTestSink
	}
	parent := filepath.Dir(path)
	real, err := filepath.EvalSymlinks(parent)
	if err != nil || real != parent {
		return errTestSink
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errTestSink
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errTestSink
	}
	count, writeErr := file.Write(value)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || count != len(value) {
		return errTestSink
	}
	return nil
}

func (f *Fixture) consume(ctx context.Context, selection contract.ConsumerSelection, choice uint8, generated *GeneratedCanonicalSelection, capturePath string) (check ConsumerCheck) {
	refused := ConsumerCheck{Code: contract.CryptoInvalidAdmission}
	got, err := contract.PublicBindingDigest(selection.Binding.Binding)
	if err != nil {
		return refused
	}
	found := false
	for _, row := range f.Bindings() {
		if row.SubjectKind != contract.OrdinaryWrapSubject || row.SubjectID != selection.Binding.SubjectID || row.Binding.BindingID != selection.Binding.Binding.BindingID {
			continue
		}
		want, err := contract.PublicBindingDigest(row.Binding)
		if err != nil || got != want {
			return refused
		}
		found = true
		break
	}
	if !found {
		return refused
	}
	f.mu.Lock()
	routeID := f.routes[selection.Binding.Binding.BindingID]
	failure := f.sinkFailure
	f.mu.Unlock()
	runtime, err := privatecrypto.TestNewConsumerRuntime(f.runtime, routeID)
	if err != nil {
		return refused
	}
	defer runtime.Close()
	var expected []byte
	if capturePath == "" {
		var ok bool
		expected, ok = syntheticValue(choice)
		if !ok {
			return ConsumerCheck{Code: contract.CryptoInvalidInput}
		}
	} else if !filepath.IsAbs(capturePath) {

		return ConsumerCheck{Code: contract.CryptoInvalidInput}
	}
	sink := &privateSink{id: fixtureID(runtime.InstanceID(), "sink", selection.EntryDigest), expected: expected, fail: failure, capturePath: capturePath}
	defer func() {
		if err := sink.Close(); err != nil {
			check.Code = contract.CryptoCustodyUnavailable
			if check.Delivery != 0 {
				check.Delivery = 2
			}
		}
	}()
	admission := fixtureID(runtime.InstanceID(), "consume", selection.EntryDigest)
	purpose := contract.Hash([]byte("ENKV/TEST-CONSUME/v2/selected-secret\x00"))
	if generated == nil {
		err = privatecrypto.TestAdmitConsumer(runtime, admission, purpose, sink.id, routeID, selection, sink, time.Now().Add(time.Minute))
	} else {
		err = privatecrypto.TestAdmitGeneratedConsumer(runtime, admission, purpose, sink.id, routeID, *generated, sink, time.Now().Add(time.Minute))
	}
	if err != nil {
		return refused
	}
	code, delivery, uses := privatecrypto.TestConsume(runtime, ctx, admission)
	sink.mu.Lock()
	matched, calls := sink.matched, sink.calls
	sink.mu.Unlock()
	return ConsumerCheck{Code: code, Delivery: delivery, ValueMatched: matched, SinkCalls: calls, KeyUses: uses}
}

// CapturePublicValue gives public values the same parent-owned file lifetime.
func CapturePublicValue(path string, value []byte) error { return capturePrivateValue(path, value) }
