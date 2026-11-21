package compositionfull

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"sync"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

var errPlanningDisplay = errors.New("planning display failed")

// planningDisplayOutput owns cancellation and finalization of its native writes.
// Close unblocks and joins an entered WriteContext before returning.
type planningDisplayOutput interface {
	WriteContext(context.Context, []byte) (int, error)
	Close() error
}

type sourceBoundPlanningDisplay struct {
	privatecrypto.PlanningDisplayFactory
	trusted, candidate *configuration.Pair
	nativeFile         os.FileInfo
}

func (f *sourceBoundPlanningDisplay) Acquire(ctx context.Context) (privatecrypto.PlanningDisplaySink, error) {
	sink, err := f.PlanningDisplayFactory.Acquire(ctx)
	if err != nil {
		return sink, err
	}
	if own, ok := sink.(*planningDisplaySink); ok {
		if file, ok := own.output.(interface{ Stat() (os.FileInfo, error) }); ok {
			info, err := file.Stat()
			if err != nil || !f.trusted.AllowsOutputFile(info) || f.candidate != nil && !f.candidate.AllowsOutputFile(info) {
				return nil, errors.Join(errPlanningDisplay, sink.Close())
			}
			f.nativeFile = info
		}
	}
	return sink, nil
}

// WriteDisplayResult delivers a completed file display's safe terminal record
// to the same native destination. The caller keeps its descriptor open.
func (r ConfigurationPlanningResult) WriteDisplayResult(ctx context.Context, out *os.File, body []byte) error {
	if r.DisplayDelivery != contract.PlanningDeliveryComplete || r.displayFile == nil || out == nil {
		return errPlanningDisplay
	}
	return writePlanningResult(ctx, out, body, r.displayFile)
}

type planningDisplayWriter struct {
	id         contract.ID
	open       func(context.Context) (planningDisplayOutput, error)
	structured bool
	mu         sync.Mutex
	acquired   bool
}

func newPlanningDisplayWriter(open func(context.Context) (planningDisplayOutput, error), structured bool) (privatecrypto.PlanningDisplayFactory, error) {
	if open == nil {
		return nil, errPlanningDisplay
	}
	var id contract.ID
	if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
		return nil, errPlanningDisplay
	}
	return &planningDisplayWriter{id: id, open: open, structured: structured}, nil
}
func (f *planningDisplayWriter) Identity() contract.ID { return f.id }
func (f *planningDisplayWriter) Acquire(ctx context.Context) (privatecrypto.PlanningDisplaySink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || f.acquired {
		return nil, errPlanningDisplay
	}
	f.acquired = true
	output, err := f.open(ctx)
	if err != nil || output == nil {
		var closeErr error
		if output != nil {
			closeErr = output.Close()
		}
		return nil, errors.Join(errPlanningDisplay, err, closeErr)
	}
	capacity := 2048 + 4*contract.CryptoMaxRawValue
	if f.structured {
		capacity = 2048 + 4*((contract.CryptoMaxRawValue+2)/3)
	}
	return &planningDisplaySink{id: f.id, output: output, structured: f.structured, buffer: make([]byte, 0, capacity)}, nil
}

type planningDisplaySink struct {
	id             contract.ID
	output         planningDisplayOutput
	structured     bool
	mu             sync.Mutex
	buffer         []byte
	active         chan struct{}
	closed, failed bool
	once           sync.Once
	closeErr       error
}

func (s *planningDisplaySink) Identity() contract.ID { return s.id }
func (s *planningDisplaySink) Accept(ctx context.Context, name string, form contract.PlanningSourceForm, plain []byte) (err error) {
	s.mu.Lock()
	if ctx == nil || ctx.Err() != nil || s.closed || s.failed || s.active != nil || len(name) > contract.CryptoMaxName || !utf8.ValidString(name) || len(plain) > contract.CryptoMaxRawValue || form != contract.PlanningSealed && form != contract.PlanningRetained {
		s.mu.Unlock()
		return errPlanningDisplay
	}
	done := make(chan struct{})
	s.active = done
	s.mu.Unlock()
	defer func() {
		clear(s.buffer[:cap(s.buffer)])
		s.buffer = s.buffer[:0]
		s.mu.Lock()
		s.failed = s.failed || err != nil
		s.active = nil
		close(done)
		s.mu.Unlock()
	}()
	b := s.buffer[:0]
	if s.structured {
		b = append(b, `{"kind":"secret-display","name":`...)
		b = appendPlanningJSONName(b, name)
		b = append(b, `,"input_form":"`...)
		b = append(b, form...)
		b = append(b, `","byte_length":`...)
		b = strconv.AppendInt(b, int64(len(plain)), 10)
		b = append(b, `,"value_base64":"`...)
		at := len(b)
		b = b[:at+base64.StdEncoding.EncodedLen(len(plain))]
		base64.StdEncoding.Encode(b[at:], plain)
		b = append(b, '"', '}', '\n')
	} else {
		b = append(b, "secret-display name="...)
		b = appendPlanningQuotedBytes(b, []byte(name))
		b = append(b, " input_form="...)
		b = append(b, form...)
		b = append(b, " byte_length="...)
		b = strconv.AppendInt(b, int64(len(plain)), 10)
		b = append(b, " value="...)
		b = appendPlanningQuotedBytes(b, plain)
		b = append(b, '\n')
	}
	s.buffer = b
	if ctx.Err() != nil {
		return errPlanningDisplay
	}
	written, writeErr := s.output.WriteContext(ctx, b)
	if writeErr != nil || written != len(b) {
		return errPlanningDisplay
	}
	if ctx.Err() != nil {
		return errPlanningDisplay
	}
	return nil
}
func (s *planningDisplaySink) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		active := s.active
		s.mu.Unlock()
		s.closeErr = s.output.Close()
		if active != nil {
			<-active
		}
		clear(s.buffer[:cap(s.buffer)])
		s.buffer = nil
	})
	return s.closeErr
}

const planningHex = "0123456789abcdef"

func appendPlanningQuotedBytes(out, plain []byte) []byte {
	out = append(out, '"')
	for _, b := range plain {
		switch {
		case b == '"' || b == '\\':
			out = append(out, '\\', b)
		case b < 0x20 || b >= 0x7f:
			out = append(out, '\\', 'x', planningHex[b>>4], planningHex[b&15])
		default:
			out = append(out, b)
		}
	}
	return append(out, '"')
}
func appendPlanningJSONName(out []byte, name string) []byte {
	out = append(out, '"')
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b == '"' || b == '\\':
			out = append(out, '\\', b)
		case b < 0x20:
			out = append(out, '\\', 'u', '0', '0', planningHex[b>>4], planningHex[b&15])
		default:
			out = append(out, b)
		}
	}
	return append(out, '"')
}
