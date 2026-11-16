package custody

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPlanningDisplayProbeChecksSyntheticValueAndBorrowedLifetime(t *testing.T) {
	display := NewPlanningDisplay(StandardValue)
	if display.Identity().IsZero() || !display.Cleared() {
		t.Fatal("display probe initial facts differ")
	}
	sink, err := (planningDisplayFactory{display: display}).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	value, ok := syntheticValue(StandardValue)
	if !ok {
		t.Fatal("synthetic value unavailable")
	}
	defer clear(value[:cap(value)])
	if err := sink.Accept(context.Background(), "exact/\n雪", contract.PlanningSealed, value); err != nil {
		t.Fatal(err)
	}
	if display.Records != 1 || display.Acquisitions != 1 || len(display.Names) != 1 || display.Names[0] != "exact/\n雪" || display.Cleared() {
		t.Fatal("display probe lost exact safe facts")
	}
	if err := sink.Accept(context.Background(), "second", contract.PlanningSealed, value); err == nil {
		t.Fatal("uncleared prior value was accepted")
	}
	clear(value[:cap(value)])
	if !display.Cleared() {
		t.Fatal("borrowed plaintext clear was not observed")
	}
	if err := sink.Accept(context.Background(), "wrong", contract.PlanningSealed, []byte("wrong")); err == nil || display.Records != 1 {
		t.Fatal("wrong synthetic value counted as delivery")
	}
	if err := sink.Close(); err != nil || display.Closes != 1 {
		t.Fatal("display probe did not close once")
	}
	if _, err := (planningDisplayFactory{display: display}).Acquire(context.Background()); err == nil {
		t.Fatal("display sink reacquired")
	}
}
