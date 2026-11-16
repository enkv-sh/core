package compositionfull

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

type changingPlanningFactory struct {
	id    contract.ID
	names []string
}

func (f *changingPlanningFactory) Identity() contract.ID { f.names[0] = "changed"; return f.id }
func (f *changingPlanningFactory) Acquire(context.Context) (privatecrypto.PlanningDisplaySink, error) {
	return nil, errors.New("unused")
}

// full_only: false
func TestPlanningDisplayOwnsSelectorsBeforeFactoryCallback(t *testing.T) {
	names := []string{"original"}
	factory := &changingPlanningFactory{id: contract.Hash([]byte("sink")), names: names}
	options := planningDisplayOptions(names, factory)
	if !reflect.DeepEqual(options.SelectedNames, []string{"original"}) || options.Purpose != contract.PlanningDisplay || options.SinkID != factory.id {
		t.Fatal("factory callback changed the admitted selector")
	}
	names[0] = "later"
	if options.SelectedNames[0] != "original" {
		t.Fatal("options retained caller selector backing")
	}
}

type planningWriterCapture struct {
	bytes.Buffer
	borrowed                []byte
	writes, flushes, closes int
	short                   bool
	flushErr                error
}

func (w *planningWriterCapture) Write(b []byte) (int, error) {
	w.writes++
	w.borrowed = b[:cap(b)]
	if w.short {
		return len(b) - 1, nil
	}
	return w.Buffer.Write(b)
}
func (w *planningWriterCapture) Flush() error { w.flushes++; return w.flushErr }
func (w *planningWriterCapture) Close() error { w.closes++; return w.Flush() }
func (w *planningWriterCapture) WriteContext(_ context.Context, b []byte) (int, error) {
	return w.Write(b)
}

// full_only: false
func TestPlanningDisplayRecordEncodingAndOwnedCleanup(t *testing.T) {
	value := []byte{'A', 0, 255, '\n', '"', '\\', 128}
	for _, structured := range []bool{false, true} {
		t.Run(map[bool]string{false: "human", true: "structured"}[structured], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			out := &planningWriterCapture{}
			factory, err := newPlanningDisplayWriter(func(context.Context) (planningDisplayOutput, error) { return out, nil }, structured)
			if err != nil {
				t.Fatal(err)
			}
			sink, err := factory.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := sink.Accept(ctx, "é/\n", contract.PlanningSealed, value); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.borrowed, make([]byte, len(out.borrowed))) {
				t.Fatal("encoder capacity retained plaintext")
			}
			human := []byte("secret-display name=\"\\xc3\\xa9/\\x0a\" input_form=sealed byte_length=7 value=\"A\\x00\\xff\\x0a\\\"\\\\\\x80\"\n")
			structuredBody := []byte("{\"kind\":\"secret-display\",\"name\":\"é/\\u000a\",\"input_form\":\"sealed\",\"byte_length\":7,\"value_base64\":\"QQD/CiJcgA==\"}\n")
			expected := human
			if structured {
				expected = structuredBody
			}
			if !bytes.Equal(out.Bytes(), expected) {
				t.Fatal("record byte mismatch", len(out.Bytes()), len(expected))
			}
			if structured {
				var record struct {
					Value string `json:"value_base64"`
				}
				if json.Unmarshal(out.Bytes(), &record) != nil {
					t.Fatal("invalid JSON")
				}
				raw, err := base64.StdEncoding.DecodeString(record.Value)
				if err != nil || !bytes.Equal(raw, value) {
					t.Fatal("binary value did not round trip")
				}
			}
			if err := sink.Accept(ctx, "", contract.PlanningRetained, nil); err != nil {
				t.Fatal(err)
			}
			if err := sink.Close(); err != nil {
				t.Fatal(err)
			}
			if err := sink.Close(); err != nil || out.writes != 2 || out.flushes != 1 || out.closes != 1 {
				t.Fatal("writer finalization ownership differs")
			}
			if _, err := factory.Acquire(ctx); err == nil {
				t.Fatal("factory replayed")
			}
		})
	}
}

// full_only: false
func TestPlanningDisplayWriterFailuresAndMaximumRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, condition := range []string{"short", "flush", "maximum"} {
		t.Run(condition, func(t *testing.T) {
			w := &planningWriterCapture{short: condition == "short"}
			if condition == "flush" {
				w.flushErr = io.ErrClosedPipe
			}
			f, _ := newPlanningDisplayWriter(func(context.Context) (planningDisplayOutput, error) { return w, nil }, false)
			s, _ := f.Acquire(ctx)
			value := []byte{255}
			name := "a"
			if condition == "maximum" {
				value = bytes.Repeat([]byte{255}, 65536)
				name = string(bytes.Repeat([]byte{'a'}, 256))
			}
			err := s.Accept(ctx, name, contract.PlanningSealed, value)
			if (err != nil) != (condition == "short") {
				t.Fatal("write failure not preserved")
			}
			if !bytes.Equal(w.borrowed, make([]byte, len(w.borrowed))) {
				t.Fatal("failed or maximum encoder not cleared")
			}
			closeErr := s.Close()
			if (closeErr != nil) != (condition == "flush") {
				t.Fatal("flush failure not preserved")
			}
			if condition == "maximum" && (w.Len() > 264192 || bytes.Count(w.Bytes(), []byte(`\xff`)) != 65536) {
				t.Fatal("maximum record bound or encoding differs")
			}
			if s.Accept(ctx, "a", contract.PlanningSealed, value) == nil || w.writes != 1 {
				t.Fatal("closed sink replayed")
			}
		})
	}
}

// full_only: false
func TestPlanningDisplayCancellationJoinsBlockedPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	readerClosed := false
	defer func() {
		if !readerClosed {
			if err := reader.Close(); err != nil {
				t.Error("display reader close failed", err)
			}
		}
	}()
	defer func() {
		if err := writer.Close(); err != nil {
			t.Error("display writer close failed", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	factory, err := NewPlanningDisplayFile(writer, false)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := factory.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	value := bytes.Repeat([]byte{255}, 65536)
	accepted := make(chan error, 1)
	go func() { accepted <- sink.Accept(ctx, "blocked", contract.PlanningSealed, value) }()
	// The full record exceeds pipe capacity. Reading a prefix establishes that
	// the native Write entered before cancellation, without retaining value bytes.
	prefix := make([]byte, 1)
	if _, err := reader.Read(prefix); err != nil {
		cancel()
		if closeErr := sink.Close(); closeErr != nil {
			t.Error("display prefix failure cleanup failed", closeErr)
		}
		if acceptErr := <-accepted; acceptErr == nil {
			t.Error("display prefix failure reported complete acceptance")
		}
		t.Fatal("display prefix read failed after joining native output", err)
	}
	cancel()
	closed := make(chan error, 1)
	go func() { closed <- sink.Close() }()
	select {
	case closeErr := <-closed:
		if closeErr != nil {
			t.Error("cancelled display finalization failed", closeErr)
		}
		if err := <-accepted; err == nil {
			t.Fatal("cancelled blocked output reported success")
		}
	case <-time.After(250 * time.Millisecond):
		readerClosed = true
		if err := reader.Close(); err != nil {
			t.Error("blocked display reader close failed", err)
		}
		<-accepted
		if err := <-closed; err != nil {
			t.Error("blocked display finalization failed", err)
		}
		t.Fatal("cancelled display did not unblock and join native pipe Write")
	}
}
