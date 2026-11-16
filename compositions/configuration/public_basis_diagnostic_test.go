package configuration

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// full_only: false
func TestGeneratedPublicBasisKindHasExactDiagnostic(t *testing.T) {
	generated := strings.Replace(sourceGeneratedJSON, `"kind":"genesis"`, `"kind":"damaged"`, 1)
	pair := writePair(t, sourceSetupJSON, generated, JSON)
	model, err := Parse(context.Background(), pair)
	var diagnostic *Diagnostic
	if model != nil || !errors.As(err, &diagnostic) || !diagnostic.Generated || diagnostic.Reason != "invalid-basis" {
		t.Fatalf("expected generated invalid-basis diagnostic: %v", err)
	}
}
