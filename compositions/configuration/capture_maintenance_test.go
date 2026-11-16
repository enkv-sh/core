package configuration

import (
	"errors"
	"fmt"
	"testing"
)

// full_only: false
func TestMaintenanceOutputRefusalNamesOperationAndPreservesCause(t *testing.T) {
	cause := &Diagnostic{Field: "output", Reason: "invalid-input"}
	refusal := &MaintenanceOutputRefusal{cause: cause}
	wrapped := fmt.Errorf("capture: %w", refusal)
	var got *MaintenanceOutputRefusal
	var diagnostic *Diagnostic
	if refusal.Error() != "maintenance output refused" || !errors.Is(wrapped, cause) || !errors.As(wrapped, &got) || got != refusal || !errors.As(wrapped, &diagnostic) || diagnostic != cause {
		t.Fatal("maintenance refusal lost operation wording or its original cause", wrapped)
	}
}
