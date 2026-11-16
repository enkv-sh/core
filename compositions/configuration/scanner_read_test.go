package configuration

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type scannerFailingReader struct{ cause error }

func (r scannerFailingReader) Read([]byte) (int, error) { return 0, r.cause }

type scannerReaderFunc func([]byte) (int, error)

func (read scannerReaderFunc) Read(body []byte) (int, error) { return read(body) }

// full_only: false
func TestSourceScannerReadFailuresPreserveCauseAndSafeDiagnostic(t *testing.T) {
	for _, condition := range []struct {
		name       string
		read       func(*parser)
		prefix     string
		wantOffset int64
	}{
		{"peek", func(p *parser) { p.peek() }, "", 0},
		{"take", func(p *parser) { p.take() }, "", 0},
		{"scalar-separation", func(p *parser) { p.separated(3) }, "a", 0},
		{"spaces-after-window-discard", func(p *parser) { p.spaces() }, "          ", 10},
	} {
		t.Run(condition.name, func(t *testing.T) {
			cause := errors.New("private-source-read-error-sentinel")
			reader := io.MultiReader(strings.NewReader(condition.prefix), scannerFailingReader{cause: cause})
			p := newParser(t.Context(), reader, YAML)
			condition.read(p)
			err := p.done()
			var diagnostic *Diagnostic
			if !errors.Is(err, cause) || !errors.As(err, &diagnostic) || diagnostic.Reason != "read-failed" || p.off != condition.wantOffset {
				t.Fatal("non-EOF read failure became syntax or lost its original cause", err, p.off)
			}
			if strings.Contains(diagnostic.Error(), cause.Error()) {
				t.Fatal("private read error entered safe diagnostic text")
			}
		})
	}
	for _, operation := range []string{"take", "done"} {
		t.Run("cancelled-"+operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			p := newParser(ctx, strings.NewReader("x"), JSON)
			if operation == "take" {
				p.take()
			}
			err := p.done()
			var diagnostic *Diagnostic
			if !errors.Is(err, context.Canceled) || !errors.As(err, &diagnostic) || diagnostic.Reason != "cancelled" {
				t.Fatal("scanner cancellation lost its owning context cause", err)
			}
		})
	}
	t.Run("EOF-remains-grammar", func(t *testing.T) {
		p := newParser(t.Context(), strings.NewReader(""), JSON)
		p.take()
		var diagnostic *Diagnostic
		if !errors.As(p.done(), &diagnostic) || diagnostic.Reason != "unexpected-end" {
			t.Fatal("EOF ceased to be a syntax failure", p.err)
		}
	})
	t.Run("nil-context-remains-invalid", func(t *testing.T) {
		var invalidContext context.Context
		p := newParser(invalidContext, strings.NewReader("x"), JSON)
		p.take()
		var diagnostic *Diagnostic
		if !errors.As(p.done(), &diagnostic) || diagnostic.Reason != "invalid-context" || p.off != 0 {
			t.Fatal("nil context lost its sticky refusal", p.err, p.off)
		}
	})
	for _, name := range []string{"background", "TODO", "without-cancel"} {
		t.Run("nil-done-"+name, func(t *testing.T) {
			ctx := context.Background()
			switch name {
			case "TODO":
				ctx = context.TODO()
			case "without-cancel":
				parent, cancel := context.WithCancel(t.Context())
				ctx = context.WithoutCancel(parent)
				cancel()
			}
			if ctx.Done() != nil {
				t.Fatal("noncancellable control has a cancellation channel")
			}
			const source = `"a\n雪"`
			p := newParser(ctx, strings.NewReader(source), JSON)
			if got := p.text(16, false, false); got != "a\n雪" {
				t.Fatal("noncancellable parse changed scalar bytes")
			}
			if err := p.done(); err != nil || p.off != int64(len(source)) {
				t.Fatal("nil cancellation channel blocked or changed completion", err, p.off)
			}
		})
	}
	for _, operation := range []string{"take", "spaces", "done"} {
		t.Run("deadline-"+operation, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			defer cancel()
			source := " x"
			if operation == "done" {
				source = "x"
			}
			p := newParser(ctx, strings.NewReader(source), JSON)
			switch operation {
			case "take":
				p.take()
			case "spaces":
				p.spaces()
			}
			var diagnostic *Diagnostic
			if err := p.done(); !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &diagnostic) || diagnostic.Reason != "cancelled" || p.off != 0 {
				t.Fatal("deadline lost its cause or consumed bytes", err, p.off)
			}
		})
	}
	for _, name := range []string{"direct", "value-chain"} {
		t.Run("cancelled-buffered-take-"+name, func(t *testing.T) {
			base, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx := base
			if name == "value-chain" {
				type key int
				for i := range 4 {
					ctx = context.WithValue(ctx, key(i), i)
				}
			}
			p := newParser(ctx, strings.NewReader("雪\nx"), JSON)
			if _, err := p.r.Peek(5); err != nil {
				t.Fatal("buffered cancellation control could not prime input", err)
			}
			if p.take() != 0xe9 || p.off != 1 || p.end != 1 || p.line != 1 || p.col != 2 || p.unicodeRemaining != 2 {
				t.Fatal("first UTF-8 byte did not establish its exact position")
			}
			cancel()
			if p.take() != 0 || p.off != 1 || p.end != 1 || p.line != 1 || p.col != 2 || p.unicodeRemaining != 2 || p.unicodeLow != 0x80 || p.unicodeHigh != 0xbf || p.indentation {
				t.Fatal("cancelled take consumed buffered input or advanced scanner state")
			}
			var diagnostic *Diagnostic
			if err := p.done(); !errors.Is(err, context.Canceled) || !errors.As(err, &diagnostic) || diagnostic.Reason != "cancelled" || diagnostic.Offset != 1 || diagnostic.Line != 1 || diagnostic.Column != 2 {
				t.Fatal("buffered cancellation lost its original cause or position", err)
			}
		})
	}
	t.Run("cancelled-buffered-spaces", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		p := newParser(ctx, strings.NewReader("  x"), YAML)
		if _, err := p.r.Peek(3); err != nil {
			t.Fatal(err)
		}
		cancel()
		p.spaces()
		var diagnostic *Diagnostic
		if err := p.done(); !errors.Is(err, context.Canceled) || !errors.As(err, &diagnostic) || diagnostic.Reason != "cancelled" || p.off != 0 || p.line != 1 || p.col != 1 {
			t.Fatal("cancelled spaces discarded buffered input", err, p.off)
		}
	})
	t.Run("cancel-cause-remains-context-error", func(t *testing.T) {
		cause := errors.New("private-context-cause-sentinel")
		ctx, cancel := context.WithCancelCause(t.Context())
		cancel(cause)
		p := newParser(ctx, strings.NewReader("x"), JSON)
		p.take()
		var diagnostic *Diagnostic
		if err := p.done(); !errors.Is(err, context.Canceled) || errors.Is(err, cause) || !errors.As(err, &diagnostic) || diagnostic.Reason != "cancelled" || strings.Contains(diagnostic.Error(), cause.Error()) {
			t.Fatal("scanner replaced Context.Err with a private cause", err)
		}
	})
	for _, name := range []string{"read", "grammar"} {
		t.Run("earlier-"+name+"-error-survives-cancellation", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cause := errors.New("private-earlier-read-error")
			var reader io.Reader = scannerFailingReader{cause: cause}
			if name == "grammar" {
				reader = strings.NewReader("")
			}
			p := newParser(ctx, reader, JSON)
			p.take()
			prior := p.err
			cancel()
			var diagnostic *Diagnostic
			err := p.done()
			if prior == nil || err != prior || errors.Is(err, context.Canceled) || !errors.As(err, &diagnostic) {
				t.Fatal("later cancellation replaced the first scanner failure", err)
			}
			if name == "read" && (!errors.Is(err, cause) || diagnostic.Reason != "read-failed") || name == "grammar" && diagnostic.Reason != "unexpected-end" {
				t.Fatal("first scanner failure lost its kind or cause", err)
			}
		})
	}
	t.Run("cancel-during-read-preserves-read-failure", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cause := errors.New("private-during-read-error")
		reader := scannerReaderFunc(func([]byte) (int, error) {
			cancel()
			return 0, cause
		})
		p := newParser(ctx, reader, JSON)
		p.take()
		var diagnostic *Diagnostic
		if err := p.done(); !errors.Is(err, cause) || errors.Is(err, context.Canceled) || !errors.As(err, &diagnostic) || diagnostic.Reason != "read-failed" || p.off != 0 {
			t.Fatal("cancellation during a started read hid its original failure", err)
		}
	})
	t.Run("cancel-before-take-precedes-read-failure", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		cause := errors.New("private-unreached-read-error")
		p := newParser(ctx, scannerFailingReader{cause: cause}, JSON)
		p.take()
		var diagnostic *Diagnostic
		if err := p.done(); !errors.Is(err, context.Canceled) || errors.Is(err, cause) || !errors.As(err, &diagnostic) || diagnostic.Reason != "cancelled" || p.off != 0 {
			t.Fatal("take read after its cancellation checkpoint", err)
		}
	})
}

// full_only: false
func TestSourceScannerLogicalBreaksKeepPhysicalSpans(t *testing.T) {
	for _, lineBreak := range []struct{ name, bytes string }{{"lf", "\n"}, {"crlf", "\r\n"}, {"cr", "\r"}} {
		t.Run(lineBreak.name, func(t *testing.T) {
			source := "first: x # c" + lineBreak.bytes + "second: y" + lineBreak.bytes
			p := newParser(t.Context(), strings.NewReader(source), YAML)
			var spans []Span
			p.spans = &spans
			var comments [][2]int64
			p.onComment = func(offset, length int64) error {
				comments = append(comments, [2]int64{offset, length})
				return nil
			}
			var values []string
			p.object(2, func(string) {
				span := p.mark(0, 0)
				values = append(values, p.text(16, false, false))
				p.record(span)
			})
			if err := p.done(); err != nil || len(values) != 2 || values[0] != "x" || values[1] != "y" {
				t.Fatal("logical break hid the next mapping member", values, err)
			}
			if len(spans) != 2 || spans[0] != (Span{Offset: 7, Length: 1, Line: 1, Column: 8}) || spans[1] != (Span{Offset: int64(20 + len(lineBreak.bytes)), Length: 1, Line: 2, Column: 9}) {
				t.Fatal("logical break changed physical source spans", spans)
			}
			if len(comments) != 1 || comments[0] != ([2]int64{9, 3}) || p.off != int64(len(source)) || p.line != 3 || p.col != 1 {
				t.Fatal("comment or terminal position crossed a logical break", comments, p.off, p.line, p.col)
			}
		})
		t.Run(lineBreak.name+"/diagnostic", func(t *testing.T) {
			source := "first: x # c" + lineBreak.bytes + "second: \xff"
			p := newParser(t.Context(), strings.NewReader(source), YAML)
			p.object(2, func(string) { p.text(16, false, false) })
			var diagnostic *Diagnostic
			if err := p.done(); !errors.As(err, &diagnostic) || diagnostic.Reason != "invalid-unicode" || diagnostic.Offset != int64(21+len(lineBreak.bytes)) || diagnostic.Line != 2 || diagnostic.Column != 9 {
				t.Fatal("diagnostic lost physical offset or logical line", err)
			}
		})
		t.Run(lineBreak.name+"/folded-text", func(t *testing.T) {
			for _, source := range []string{"first" + lineBreak.bytes + "  second", "\"first" + lineBreak.bytes + "  second\""} {
				p := newParser(t.Context(), strings.NewReader(source), YAML)
				if got := p.text(32, false, false); p.done() != nil || got != "first second" {
					t.Fatal("plain or quoted logical break changed", got, p.err)
				}
			}
		})
	}
	t.Run("mixed-reader-boundary", func(t *testing.T) {
		reader := io.MultiReader(strings.NewReader("first: x # c\r"), strings.NewReader("\nsecond: y\rlast: z\n"))
		p := newParser(t.Context(), reader, YAML)
		var spans []Span
		p.spans = &spans
		var values []string
		p.object(3, func(string) {
			span := p.mark(0, 0)
			values = append(values, p.text(16, false, false))
			p.record(span)
		})
		if err := p.done(); err != nil || len(values) != 3 || strings.Join(values, ",") != "x,y,z" {
			t.Fatal("mixed logical breaks lost a member", values, err)
		}
		if len(spans) != 3 || spans[0] != (Span{Offset: 7, Length: 1, Line: 1, Column: 8}) || spans[1] != (Span{Offset: 22, Length: 1, Line: 2, Column: 9}) || spans[2] != (Span{Offset: 30, Length: 1, Line: 3, Column: 7}) || p.off != 32 || p.line != 4 || p.col != 1 {
			t.Fatal("CRLF across reader refill or mixed CR/LF changed positions", spans, p.off, p.line, p.col)
		}
	})
}

// full_only: false
func TestSourceScalarDeliveryStopsAtFirstSinkError(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		format       Format
		failAt       int
	}{
		{"quoted-pending", `"     "`, YAML, 1},
		{"plain-pending", "A    B", YAML, 2},
		{"yaml-rune", `"\u00e9"`, YAML, 1},
		{"json-rune", `"\u00e9"`, JSON, 1},
		{"quoted-folded-breaks", "\"A\n\n\n B\"", YAML, 2},
		{"block", "|-\n  AB\n", YAML, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(tc.source), tc.format)
			var delivered []byte
			var first error
			p.scalarValue(func(b byte) {
				delivered = append(delivered, b)
				if len(delivered) == tc.failAt {
					p.fail("scalar-limit")
					first = p.err
				}
			}, false, true, true)
			if len(delivered) != tc.failAt || first == nil || p.done() != first {
				t.Fatal("scalar delivered bytes after its sink refused", len(delivered), tc.failAt, p.err)
			}
		})
	}
}

// full_only: false
func TestSourceScannerCommentsKeepFollowingPluginSettings(t *testing.T) {
	for _, lineBreak := range []struct{ name, bytes string }{{"lf", "\n"}, {"crlf", "\r\n"}, {"cr", "\r"}} {
		t.Run(lineBreak.name, func(t *testing.T) {
			source := strings.ReplaceAll("not_before: first # comment\nexpires_on: second\n", "\n", lineBreak.bytes)
			p := newParser(t.Context(), strings.NewReader(source), YAML)
			got := parseSettings(p, 256)
			if err := p.done(); err != nil || string(got) != `{"not_before":"first","expires_on":"second"}` {
				t.Fatalf("comment changed complete optional settings %q, error %v", got, err)
			}
		})
	}
}

// full_only: false
func TestSourceSyntaxDiagnosticUsesFaultToken(t *testing.T) {
	for _, tc := range []struct {
		name, source, reason string
		column               uint64
	}{
		{"escape", `"a\q"`, "invalid-escape", 3},
		{"line-break", "\"a\nb\"", "unescaped-control", 3},
		{"unicode-digit", `"\u12x4"`, "invalid-unicode-escape", 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newParser(t.Context(), strings.NewReader(tc.source), JSON)
			p.text(64, false, false)
			var d *Diagnostic
			if err := p.done(); !errors.As(err, &d) || d.Reason != tc.reason || d.Line != 1 || d.Column != tc.column {
				t.Fatalf("syntax diagnostic missed fault token: %+v", d)
			}
		})
	}
}
