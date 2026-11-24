package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type materializationLiteral struct {
	Name    string            `json:"name"`
	Values  map[string]string `json:"values"`
	Encoded string            `json:"encoded"`
}

func materializationLiterals(t *testing.T) []materializationLiteral {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "tests", "fixtures", "dotenv-consumer", "vectors.json"))
	if err != nil {
		t.Fatal("independent materialization literals unavailable")
	}
	var fixture struct {
		Emissions []materializationLiteral `json:"emissions"`
	}
	if json.Unmarshal(body, &fixture) != nil || len(fixture.Emissions) == 0 {
		t.Fatal("independent materialization literals invalid")
	}
	return fixture.Emissions
}

// full_only: false
func TestMaterializationEnvEmitsIndependentLiteralRecords(t *testing.T) {
	// Fixed fixture bytes apply the format table directly, without the encoder.
	for _, vector := range materializationLiterals(t) {
		t.Run(vector.Name, func(t *testing.T) {
			values := make([]materializationValue, 0, len(vector.Values))
			for name, raw := range vector.Values {
				values = append(values, materializationValue{name: name, raw: []byte(raw)})
			}
			env, err := prepareMaterializationEnv(values)
			if err != nil {
				t.Fatal("literal representation refused")
			}
			var out bytes.Buffer
			if err := env.writeTo(t.Context(), &out); err != nil {
				t.Fatal("literal emission failed")
			}
			if !bytes.Equal(out.Bytes(), []byte(vector.Encoded)) || env.encodedLength != len(vector.Encoded) {
				t.Fatal("complete emitted bytes or length differ from independent literal")
			}
		})
	}
	for _, edge := range []rune{'\t', '\v', '\f', ' ', '\u00a0', '\u1680', '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200a', '\u202f', '\u205f', '\u3000', '\ufeff'} {
		t.Run(fmt.Sprintf("trim-U%04X", edge), func(t *testing.T) {
			for _, raw := range []string{string(edge) + "x", "x" + string(edge)} {
				env, err := prepareMaterializationEnv([]materializationValue{{name: "A", raw: []byte(raw)}})
				if err != nil {
					t.Fatal("trim-edge value refused")
				}
				var out bytes.Buffer
				if env.writeTo(t.Context(), &out) != nil || out.String() != "A='"+raw+"'\n" {
					t.Fatal("trim-edge value did not use first admitted quote")
				}
			}
		})
	}
}

// full_only: false
func TestMaterializationEnvRefusesUnsupportedValues(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"NUL", []byte("a\x00b")},
		{"CR", []byte("a\rb")},
		{"CRLF", []byte("a\r\nb")},
		{"U2028", []byte("a\u2028b")},
		{"U2029", []byte("a\u2029b")},
		{"invalid UTF8", []byte{0xff}},
		{"truncated UTF8", []byte{0xe2, 0x82}},
		{"surrogate UTF8", []byte{0xed, 0xa0, 0x80}},
		{"all quotes require quoting", []byte(" #'`\"")},
		{"quoted trailing backslash", []byte("needs#quote\\")},
		{"opening quote trailing backslash", []byte("'value\\")},
		{"double branch literal slash n", []byte(" a'`\\n")},
		{"double branch literal slash r", []byte(" a'`\\r")},
		{"multiline all quotes injection", []byte("'`\"\nEXTRA=bad")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := prepareMaterializationEnv([]materializationValue{{name: "A", raw: []byte("valid")}, {name: "Z", raw: tc.raw}}); err == nil {
				t.Fatal("later unsupported member admitted")
			}
		})
	}
	for _, name := range []string{"", "__proto__", "0A", "A-B", "A.B", "A B", "A=B", "A\nB", "é", "A\x00"} {
		if _, err := prepareMaterializationEnv([]materializationValue{{name: name, raw: []byte("valid")}}); err == nil {
			t.Fatal("unsupported name admitted")
		}
	}
	if _, err := prepareMaterializationEnv([]materializationValue{{name: "A"}, {name: "A"}}); err == nil {
		t.Fatal("duplicate name admitted")
	}
	if _, err := prepareMaterializationEnv(nil); err == nil {
		t.Fatal("empty selection admitted")
	}
	var zero materializationEnv
	var out bytes.Buffer
	if zero.writeTo(t.Context(), &out) == nil || out.Len() != 0 {
		t.Fatal("unprepared representation emitted bytes")
	}
}

// full_only: false
func TestMaterializationEnvMatchesCompleteSurface(t *testing.T) {
	const want = "A='first\nEXTRA=inside'\nZ=`'later\nEND=tail`\n"
	env, err := prepareMaterializationEnv([]materializationValue{{name: "Z", raw: []byte("'later\nEND=tail")}, {name: "A", raw: []byte("first\nEXTRA=inside")}})
	if err != nil {
		t.Fatal("supported selection refused")
	}
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"complete", want, true},
		{"truncated", want[:len(want)-1], false},
		{"extra byte", want + "x", false},
		{"changed later value", strings.Replace(want, "tail", "fail", 1), false},
		{"changed name", strings.Replace(want, "Z=", "Y=", 1), false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := &materializationChunkReader{reader: strings.NewReader(tc.body), maximum: 3}
			got, err := env.matches(t.Context(), reader)
			if err != nil || got != tc.want {
				t.Fatal("complete surface comparison differs")
			}
		})
	}
	terminal := &materializationTerminalReader{reader: strings.NewReader(want)}
	if ok, err := env.matches(t.Context(), terminal); !ok || err != nil {
		t.Fatal("complete bytes with terminal EOF refused")
	}
	failure := errors.New("synthetic final read failure")
	if ok, err := env.matches(t.Context(), io.MultiReader(strings.NewReader(want), materializationFaultReader{err: failure})); ok || !errors.Is(err, failure) {
		t.Fatal("final EOF check lost its read failure")
	}
}

type materializationTerminalReader struct{ reader *strings.Reader }

func (r *materializationTerminalReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if r.reader.Len() == 0 {
		return n, io.EOF
	}
	return n, err
}

type materializationChunkReader struct {
	reader  io.Reader
	maximum int
}

func (r *materializationChunkReader) Read(p []byte) (int, error) {
	if len(p) > 4096 {
		return 0, errors.New("readback chunk exceeds bound")
	}
	return r.reader.Read(p[:min(len(p), r.maximum)])
}

type materializationFaultWriter struct {
	calls  int
	short  bool
	err    error
	cancel context.CancelFunc
}

func (w *materializationFaultWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.cancel != nil {
		w.cancel()
	}
	if w.short {
		return len(p) - 1, nil
	}
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

type materializationFaultReader struct{ err error }

func (r materializationFaultReader) Read([]byte) (int, error) { return 0, r.err }

type materializationCanceledReader struct {
	cancel context.CancelFunc
	err    error
}

func (r materializationCanceledReader) Read(p []byte) (int, error) {
	r.cancel()
	p[0] = '?'
	return 1, r.err
}

// full_only: false
func TestMaterializationEnvStopsOnIOAndCancellation(t *testing.T) {
	env, err := prepareMaterializationEnv([]materializationValue{{name: "A", raw: []byte("value")}, {name: "Z", raw: []byte("later")}})
	if err != nil {
		t.Fatal("supported selection refused")
	}
	failure := errors.New("synthetic I/O failure")
	for _, tc := range []struct {
		name string
		w    materializationFaultWriter
		want error
	}{{"short", materializationFaultWriter{short: true}, io.ErrShortWrite}, {"failure", materializationFaultWriter{err: failure}, failure}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := env.writeTo(t.Context(), &tc.w); !errors.Is(err, tc.want) || tc.w.calls != 1 {
				t.Fatal("write failure was lost or emission continued")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	w := &materializationFaultWriter{cancel: cancel}
	if err := env.writeTo(ctx, w); !errors.Is(err, context.Canceled) || w.calls != 1 {
		t.Fatal("cancellation did not stop subsequent emission")
	}
	if ok, err := env.matches(t.Context(), materializationFaultReader{err: failure}); ok || !errors.Is(err, failure) {
		t.Fatal("read failure was lost")
	}
	if ok, err := env.matches(t.Context(), materializationFaultReader{}); ok || !errors.Is(err, io.ErrNoProgress) {
		t.Fatal("zero-progress read did not terminate")
	}
	if ok, err := env.matches(ctx, strings.NewReader("A=value\nZ=later\n")); ok || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled readback continued")
	}
	t.Run("cancellation during read prevents a mismatch claim", func(t *testing.T) {
		for _, readErr := range []error{nil, failure} {
			readContext, readCancel := context.WithCancel(t.Context())
			ok, err := env.matches(readContext, materializationCanceledReader{cancel: readCancel, err: readErr})
			readCancel()
			if ok || !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation during read became a content mismatch or unrelated read error")
			}
		}
	})
}

// full_only: false
func TestMaterializationEnvPinnedConsumer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "check.cjs")
	command.Dir = filepath.Join("..", "tests", "fixtures", "dotenv-consumer")
	command.Env = []string{}
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	body, err := command.Output()
	if err != nil {
		t.Fatal("pinned local consumer failed; Node and installed exact fixture are required")
	}
	var result struct {
		Node    string `json:"node"`
		Dotenv  string `json:"dotenv"`
		Vectors int    `json:"vectors"`
	}
	if json.Unmarshal(body, &result) != nil || result.Node != "v24.19.0" || result.Dotenv != "18.0.9" || result.Vectors != 29 {
		t.Fatal("pinned consumer safe result differs")
	}
	t.Logf("local consumer node=%s dotenv=%s vectors=%d", result.Node, result.Dotenv, result.Vectors)
}

type materializationBoundedWriter struct {
	count int
}

func (w *materializationBoundedWriter) Write(p []byte) (int, error) {
	if len(p) > 4096 {
		return 0, errors.New("encoded chunk exceeds bound")
	}
	w.count += len(p)
	return len(p), nil
}

// full_only: true
// Proves the exact 512-entry, 8 MiB raw, maximum-name encoded surface and the independent individual-value bound.
func TestMaterializationEnvMaximumEncodedSurface(t *testing.T) {
	values := make([]materializationValue, 512)
	for i := range values {
		values[i] = materializationValue{name: fmt.Sprintf("N%03d%s", i, strings.Repeat("x", 252)), raw: bytes.Repeat([]byte{'#'}, 16384)}
	}
	env, err := prepareMaterializationEnv(values)
	if err != nil || env.encodedLength != 8521728 {
		t.Fatal("exact independently derived encoded maximum refused or miscounted")
	}
	w := &materializationBoundedWriter{}
	if err := env.writeTo(t.Context(), w); err != nil || w.count != 8521728 {
		t.Fatal("maximum surface emission failed or exceeded chunk bound")
	}
	large := bytes.Repeat([]byte{'x'}, 65536)
	env, err = prepareMaterializationEnv([]materializationValue{{name: "A", raw: large}})
	if err != nil || env.encodedLength != 65539 {
		t.Fatal("exact individual value maximum refused or miscounted")
	}
	var out bytes.Buffer
	if env.writeTo(t.Context(), &out) != nil || out.Len() != 65539 || !bytes.Equal(out.Bytes()[2:65538], large) {
		t.Fatal("maximum individual value emission differs")
	}
	reader := &materializationChunkReader{reader: bytes.NewReader(out.Bytes()), maximum: 17}
	if ok, err := env.matches(t.Context(), reader); !ok || err != nil {
		t.Fatal("maximum individual value readback failed")
	}
}

// full_only: true
// Proves one-over name, value, selection and aggregate refusals before proportional allocation.
func TestMaterializationEnvRefusesOversizedSelectionBeforeAllocation(t *testing.T) {
	count := make([]materializationValue, 513)
	aggregate := make([]materializationValue, 129)
	large := bytes.Repeat([]byte{'x'}, 87384)
	for i := range aggregate {
		aggregate[i] = materializationValue{name: fmt.Sprintf("N%03d", i), raw: large}
	}
	aggregate[128].raw = large[:1025]
	for _, tc := range []struct {
		name   string
		values []materializationValue
	}{
		{"name", []materializationValue{{name: strings.Repeat("A", 257)}}},
		{"value", []materializationValue{{name: "A", raw: bytes.Repeat([]byte{'x'}, 87385)}}},
		{"count", count},
		{"aggregate", aggregate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admitted := false
			allocations := testing.AllocsPerRun(5, func() {
				_, err := prepareMaterializationEnv(tc.values)
				admitted = admitted || err == nil
			})
			if admitted || allocations != 0 {
				t.Fatal("oversized input admitted or allocated before rejection")
			}
		})
	}
}
