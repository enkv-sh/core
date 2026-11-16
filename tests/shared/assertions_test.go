package core

import (
	"runtime"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// Embedding TB retains Go's test ownership, Cleanup and Goexit behavior. The
// private recorder receives only the direct callsite and a fixed method code.
// Live and hermetic workers share this wrapper and their WorkerRecorder's owner.
type assertionTB struct {
	testing.TB
	failure *records.FailureRecorder
}

func (t assertionTB) record(code string) {
	_, file, line, ok := runtime.Caller(2)
	if ok {
		t.failure.Record(code, file, line)
	}
}

func (t assertionTB) Fatal(args ...any) {
	t.Helper()
	t.record("fatal")
	t.TB.Fatal(args...)
}

func (t assertionTB) Fatalf(format string, args ...any) {
	t.Helper()
	t.record("fatalf")
	t.TB.Fatalf(format, args...)
}

func (t assertionTB) Error(args ...any) {
	t.Helper()
	t.record("error")
	t.TB.Error(args...)
}

func (t assertionTB) Errorf(format string, args ...any) {
	t.Helper()
	t.record("errorf")
	t.TB.Errorf(format, args...)
}

func (t assertionTB) FailNow() {
	t.Helper()
	t.record("fail_now")
	t.TB.FailNow()
}

func (t assertionTB) Fail() {
	t.Helper()
	t.record("fail")
	t.TB.Fail()
}
