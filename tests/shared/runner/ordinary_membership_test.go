package main

import (
	"context"
	"slices"
	"testing"
)

// full_only: false
func TestUnitFocusSharesCapturedPackageMembership(t *testing.T) {
	ctx, root, _, _, _, _ := completePreparationFixture(t, "")
	writeLocalGoFixture(t, root, "telemetry/other/other.go", "package other\n")
	ctx, owner := withInvocationArtifacts(ctx)
	t.Cleanup(func() {
		if err := owner.close(context.WithoutCancel(ctx), true); err != nil {
			t.Error(err)
		}
	})
	scope := map[string][]string{"telemetry": {"./..."}}
	first, err := resolveOrdinaryUnitPackage(ctx, root, scope, "telemetry/witness")
	if err != nil || len(first.Artifacts) != 1 || !slices.Equal(first.AdmittedPackages, []string{"telemetry/other", "telemetry/witness"}) {
		t.Fatal("initial package membership is unavailable", first, err)
	}
	first.AdmittedPackages[0] = "changed by caller"
	first.Artifacts[0].Patterns[0] = "changed by caller"
	writeLocalGoFixture(t, root, "telemetry/other/other.go", "//go:build ignore\n\npackage other\n")
	second, err := resolveOrdinaryUnitPackage(ctx, root, scope, "telemetry/other")
	if err != nil || len(second.Artifacts) != 1 || second.Artifacts[0].Owner != "telemetry/other" || !slices.Equal(second.AdmittedPackages, []string{"telemetry/other", "telemetry/witness"}) {
		t.Error("another focus rediscovered or changed captured membership", second, err)
	}
	again, err := resolveOrdinaryUnitPackage(ctx, root, scope, "telemetry/witness")
	if err != nil || len(again.Artifacts) != 1 || !slices.Equal(again.Artifacts[0].Patterns, []string{"./witness"}) || !slices.Equal(again.AdmittedPackages, []string{"telemetry/other", "telemetry/witness"}) {
		t.Error("a caller changed shared package membership", again, err)
	}
	if _, err := resolveOrdinaryUnitPackage(ctx, root, map[string][]string{"telemetry": {"./witness"}}, "telemetry/other"); err == nil {
		t.Error("a different configured scope inherited unselected membership")
	}
}
