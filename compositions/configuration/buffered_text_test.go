package configuration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

type bufferedTextReader struct {
	body  string
	chunk int
	final error
	reads int
}

func (r *bufferedTextReader) Read(body []byte) (int, error) {
	r.reads++
	if r.chunk > 0 && len(body) > r.chunk {
		body = body[:r.chunk]
	}
	n := copy(body, r.body)
	r.body = r.body[n:]
	if len(r.body) == 0 && r.final != nil {
		return n, r.final
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func bufferedTextParser(t *testing.T, ctx context.Context, source string, chunk int, final error) (*parser, *bufferedTextReader) {
	t.Helper()
	r := &bufferedTextReader{body: " \n  " + source, chunk: chunk, final: final}
	p := newParser(ctx, r, JSON)
	p.skip()
	if p.err != nil || p.off != 4 || p.end != 0 || p.line != 2 || p.col != 3 {
		t.Fatal("text control did not establish its nonzero source position", p.err)
	}
	p.plain, p.field, p.generatedImage = true, "entries.item", true
	p.unicodeLow, p.unicodeHigh = 0x80, 0xbf
	return p, r
}

func bufferedTextState(t *testing.T, p *parser, wire int, line, col uint64) {
	t.Helper()
	end := int64(0)
	if wire != 0 {
		end = int64(4 + wire)
	}
	if p.off != int64(4+wire) || p.end != end || p.line != line || p.col != col || p.indentation != (wire == 0) || p.plain || p.trivia || p.unicodeRemaining != 0 || p.unicodeLow != 0x80 || p.unicodeHigh != 0xbf || p.field != "entries.item" || !p.generatedImage {
		t.Fatal("text changed its exact source state", p.off, p.end, p.line, p.col, wire)
	}
}

// full_only: false
func TestBufferedQuotedTextPreservesScannerContract(t *testing.T) {
	for _, tc := range []struct {
		name, source, want, reason string
		format                     Format
		limit, wire                int
		line, col                  uint64
	}{
		{"empty-json", `""`, "", "", JSON, 0, 2, 2, 5},
		{"negative-empty-json", `""`, "", "", JSON, -1, 2, 2, 5},
		{"negative-text-json", `"a"`, "", "scalar-limit", JSON, -1, 2, 2, 5},
		{"exact-json", `"abc"`, "abc", "", JSON, 3, 5, 2, 8},
		{"exact-yaml", `"abc"`, "abc", "", YAML, 3, 5, 2, 8},
		{"excess-json", `"abcd"`, "abc", "scalar-limit", JSON, 3, 5, 2, 8},
		{"escaped-json", `"a\u0062"`, "ab", "", JSON, 8, 9, 2, 12},
		{"utf8-yaml", `"雪"`, "雪", "", YAML, 8, 5, 2, 8},
		{"invalid-utf8-json", "\"a\xff\"", "a\xff", "invalid-unicode", JSON, 8, 3, 2, 6},
		{"spaces-yaml", `"a b "`, "a b ", "", YAML, 8, 6, 2, 9},
		{"folded-yaml", "\"a\n  b\"", "a b", "", YAML, 8, 7, 3, 5},
		{"single-yaml", `'it''s'`, "it's", "", YAML, 8, 7, 2, 10},
	} {
		for _, chunk := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/chunk-%d", tc.name, chunk), func(t *testing.T) {
				p, r := bufferedTextParser(t, context.Background(), tc.source+"!", chunk, nil)
				p.format = tc.format
				if chunk == 0 && p.r.Buffered() != len(tc.source)+1 {
					t.Fatal("complete text control was not already buffered")
				}
				reads := r.reads
				got := p.text(tc.limit, false, false)
				var diagnostic *Diagnostic
				if got != tc.want || (p.err != nil) != (tc.reason != "") || tc.reason != "" && (!errors.As(p.err, &diagnostic) || diagnostic.Reason != tc.reason || !errors.Is(p.err, ErrSourceInvalid)) {
					t.Fatal("text result or first refusal changed", got, p.err)
				}
				bufferedTextState(t, p, tc.wire, tc.line, tc.col)
				if chunk == 0 && r.reads != reads {
					t.Fatal("already buffered text caused another source read")
				}
				remaining := tc.source[tc.wire:] + "!"
				for _, want := range []byte(remaining) {
					got, err := p.r.ReadByte()
					if err != nil || got != want {
						t.Fatal("text consumed its closing or following source byte", err)
					}
				}
			})
		}
	}
	t.Run("closing-buffer-boundary", func(t *testing.T) {
		for _, tc := range []struct{ payload, extraReads int }{{WindowBytes - 6, 0}, {WindowBytes - 5, 1}} {
			t.Run(fmt.Sprintf("payload-%d", tc.payload), func(t *testing.T) {
				want := strings.Repeat("x", tc.payload)
				p, r := bufferedTextParser(t, context.Background(), `"`+want+`"!`, 0, nil)
				reads := r.reads
				got := p.text(tc.payload, false, false)
				if got != want || p.err != nil || r.reads != reads+tc.extraReads {
					t.Fatal("closing-buffer boundary changed value or source reads", p.err, r.reads-reads)
				}
				bufferedTextState(t, p, tc.payload+2, 2, uint64(tc.payload+5))
				next, err := p.r.ReadByte()
				if err != nil || next != '!' {
					t.Fatal("closing-buffer boundary consumed its following byte", err)
				}
			})
		}
	})
	t.Run("decoded-key-duplicate", func(t *testing.T) {
		p, _ := bufferedTextParser(t, context.Background(), `{"a":"x","\u0061":"y"}`, 0, nil)
		calls := 0
		p.object(2, func(key string) {
			calls++
			if key != "a" || p.text(8, false, false) != "x" {
				t.Fatal("decoded key control changed meaning")
			}
		})
		var diagnostic *Diagnostic
		if !errors.As(p.done(), &diagnostic) || diagnostic.Reason != "duplicate-key" || diagnostic.Offset != 21 || calls != 1 {
			t.Fatal("ordinary and escaped keys lost duplicate detection or exact location", p.err, calls)
		}
	})
	t.Run("pending-reader-error", func(t *testing.T) {
		for _, source := range []string{`"ab"`, `"ab`} {
			t.Run(fmt.Sprintf("bytes-%d", len(source)), func(t *testing.T) {
				cause := errors.New("private-buffered-read-cause")
				p, r := bufferedTextParser(t, context.Background(), source, 0, cause)
				reads := r.reads
				if got := p.text(8, false, false); got != "ab" || len(source) == 4 && p.err != nil {
					t.Fatal("buffered text changed its prefix or reported a later read early", got, p.err)
				}
				bufferedTextState(t, p, len(source), 2, uint64(3+len(source)))
				var diagnostic *Diagnostic
				if err := p.done(); !errors.Is(err, cause) || !errors.As(err, &diagnostic) || diagnostic.Reason != "read-failed" || diagnostic.Offset != p.off || strings.Contains(diagnostic.Error(), cause.Error()) || r.reads != reads {
					t.Fatal("pending read error lost its original order, cause or position", err)
				}
			})
		}
	})
	t.Run("pending-unicode-stays-fallback", func(t *testing.T) {
		p, _ := bufferedTextParser(t, context.Background(), "\xc2"+`"x"!`, 0, nil)
		if p.take() != 0xc2 || p.unicodeRemaining != 1 {
			t.Fatal("UTF8 continuation control was not established")
		}
		if got := p.text(8, false, false); got != "" {
			t.Fatal("pending UTF8 changed returned text", got)
		}
		var diagnostic *Diagnostic
		if !errors.As(p.err, &diagnostic) || diagnostic.Reason != "invalid-unicode" || diagnostic.Offset != 6 {
			t.Fatal("pending UTF8 lost its first-byte refusal", p.err)
		}
		bufferedTextState(t, p, 2, 2, 5)
	})
	t.Run("sticky-error-keeps-reader", func(t *testing.T) {
		const source = `"ab"!`
		p, _ := bufferedTextParser(t, context.Background(), source, 0, nil)
		cause := errors.New("private-earlier-text-failure")
		p.failRead(cause)
		prior := p.err
		if got := p.text(8, false, false); got != "" || p.err != prior || !errors.Is(p.err, cause) {
			t.Fatal("text replaced its earlier failure", got, p.err)
		}
		bufferedTextState(t, p, 0, 2, 3)
		remaining, err := p.r.Peek(len(source))
		if err != nil || string(remaining) != source {
			t.Fatal("failed text advanced its reader", err)
		}
	})
	t.Run("refill-panic-propagates", func(t *testing.T) {
		p, _ := bufferedTextParser(t, context.Background(), `"ab`, 0, nil)
		reads, sentinel := 0, new(int)
		p.r.Reset(scannerReaderFunc(func(body []byte) (int, error) {
			reads++
			if reads == 1 {
				return copy(body, `"ab`), nil
			}
			panic(sentinel)
		}))
		if _, err := p.r.Peek(3); err != nil {
			t.Fatal("refill panic control could not prime its prefix", err)
		}
		var seen any
		func() { defer func() { seen = recover() }(); p.text(8, false, false) }()
		if seen != sentinel || p.err != nil || reads != 2 {
			t.Fatal("text recovered, changed or moved its refill panic")
		}
		bufferedTextState(t, p, 3, 2, 6)
	})
	t.Run("reader-reset-keeps-owned-output", func(t *testing.T) {
		p, _ := bufferedTextParser(t, context.Background(), `"first"!`, 0, nil)
		first := p.text(5, false, false)
		p.r.Reset(strings.NewReader(`"other"!`))
		second := p.text(5, false, false)
		if first != "first" || second != "other" || p.err != nil {
			t.Fatal("text retained borrowed bytes across reader reset", first, second, p.err)
		}
		bufferedTextState(t, p, 14, 2, 17)
	})
	t.Run("cancel-before-opening", func(t *testing.T) {
		base, cancel := context.WithCancel(t.Context())
		defer cancel()
		type key int
		ctx := context.Context(base)
		for i := range 4 {
			ctx = context.WithValue(ctx, key(i), i)
		}
		const source = `"ab"!`
		p, r := bufferedTextParser(t, ctx, source, 0, nil)
		reads := r.reads
		cancel()
		if got := p.text(8, false, false); got != "" {
			t.Fatal("pre-cancelled text returned unconsumed bytes", got)
		}
		bufferedTextState(t, p, 0, 2, 3)
		var diagnostic *Diagnostic
		if !errors.Is(p.err, context.Canceled) || !errors.As(p.err, &diagnostic) || diagnostic.Reason != "cancelled" || diagnostic.Offset != 4 || diagnostic.Line != 2 || diagnostic.Column != 3 || diagnostic.Field != "entries.item" || !diagnostic.Generated || r.reads != reads {
			t.Fatal("pre-cancelled text lost its cause, safe location or no-read boundary", p.err)
		}
		remaining, err := p.r.Peek(len(source))
		if err != nil || string(remaining) != source {
			t.Fatal("pre-cancelled text advanced its reader", err)
		}
	})
	t.Run("concurrent-cancel-prefixes", func(t *testing.T) {
		const size, attempts = 4096, 64
		payload := strings.Repeat("x", size)
		source := `"` + payload + `"!`
		var observed [3]int
		for range attempts {
			func() {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				p, _ := bufferedTextParser(t, ctx, source, 0, nil)
				ready, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
				go func() { close(ready); <-release; cancel(); close(joined) }()
				<-ready
				close(release)
				var got string
				func() { defer func() { <-joined }(); got = p.text(size, false, false) }()
				wire := int(p.off - 4)
				if wire < 0 || wire > size+2 {
					t.Fatal("cancelled text advanced outside its token", wire)
				}
				decoded := max(0, min(size, wire-1))
				if got != payload[:decoded] {
					t.Fatal("text result differs from its accepted prefix", wire, len(got))
				}
				bufferedTextState(t, p, wire, 2, uint64(3+wire))
				if p.err == nil {
					if wire != size+2 {
						t.Fatal("text returned without finishing or refusing its token", wire)
					}
					observed[2]++
				} else {
					var diagnostic *Diagnostic
					if wire == size+2 || !errors.Is(p.err, context.Canceled) || !errors.As(p.err, &diagnostic) || diagnostic.Reason != "cancelled" || diagnostic.Offset != p.off || diagnostic.Line != 2 || diagnostic.Column != p.col {
						t.Fatal("text cancellation lost its prefix or original cause", wire, p.err)
					}
					if wire == 0 {
						observed[0]++
					} else {
						observed[1]++
					}
				}
				remaining, err := p.r.Peek(p.r.Buffered())
				if err != nil || string(remaining) != source[wire:] {
					t.Fatal("text reader disagrees with its accepted prefix", wire, err)
				}
				if err := p.done(); !errors.Is(err, context.Canceled) {
					t.Fatal("final check lost joined cancellation", err)
				}
			}()
		}
		t.Logf("fixed cancellation attempts=%d before_opening=%d partial=%d complete_before_final_check=%d; no particular prefix is required", attempts, observed[0], observed[1], observed[2])
	})
}
