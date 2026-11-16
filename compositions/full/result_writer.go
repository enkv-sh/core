package compositionfull

import (
	"context"
	"encoding/json"
	"io"
	"time"
)

func writeResultStream(ctx context.Context, out io.Writer, limit uint64, limitError error, emit func(*resultStreamWriter)) error {
	if ctx == nil || out == nil {
		return limitError
	}
	count := &resultStreamWriter{ctx: ctx, limit: limit, limitError: limitError}
	emit(count)
	if count.err != nil {
		return count.err
	}
	stream := &resultStreamWriter{ctx: ctx, out: out, limit: count.n, limitError: limitError}
	emit(stream)
	if stream.err != nil {
		return stream.err
	}
	if stream.n != count.n {
		return limitError
	}
	return nil
}

// ResultDeliveryContext permits finite validation, encoding and writing of an
// already-owned safe result after execution returns. It grants no Product work,
// readback or retry, and cannot interrupt an arbitrary Writer inside Write.
func ResultDeliveryContext(execution context.Context) (context.Context, context.CancelFunc) {
	if execution == nil {
		return nil, func() {}
	}
	return context.WithTimeout(context.WithoutCancel(execution), 5*time.Minute)
}

type resultStreamWriter struct {
	ctx        context.Context
	out        io.Writer
	n, limit   uint64
	err        error
	limitError error
	layout     *resultJSONLayout
}

func (w *resultStreamWriter) text(s string) {
	if w.err != nil {
		return
	}
	if w.layout != nil {
		if err := w.layout.write(s, w.rawText); err != nil && w.err == nil {
			w.err = w.limitError
			if w.err == nil {
				w.err = err
			}
		}
		return
	}
	w.rawText(s)
}

func (w *resultStreamWriter) finishJSON() {
	if w.err == nil && w.layout != nil {
		if err := w.layout.finish(w.rawText); err != nil && w.err == nil {
			w.err = w.limitError
			if w.err == nil {
				w.err = err
			}
		}
	}
}

func (w *resultStreamWriter) rawText(s string) {
	if w.err != nil {
		return
	}
	if err := w.ctx.Err(); err != nil {
		w.err = err
		return
	}
	if uint64(len(s)) > w.limit-w.n {
		w.err = w.limitError
		if w.err == nil {
			w.err = ErrAbandonmentResult
		}
		return
	}
	w.n += uint64(len(s))
	if w.out != nil {
		n, err := io.WriteString(w.out, s)
		if err != nil {
			w.err = err
		} else if n != len(s) {
			w.err = io.ErrShortWrite
		} else {
			w.err = w.ctx.Err()
		}
	}
}
func (w *resultStreamWriter) value(v any) {
	if w.err != nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		w.err = err
		return
	}
	w.text(string(b))
}
