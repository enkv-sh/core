package main

import "testing"

// full_only: false
func TestSavedAssemblyFocusRequiresExactProviderTest(t *testing.T) {
	for _, test := range []struct {
		name, provider, requested, pkg string
		valid                          bool
	}{
		{name: "aws-root", provider: "aws", requested: "TestPublicInspectionReceiptCaptureRequiresJoinedGETOnly", valid: true},
		{name: "gcp-subtest", provider: "gcp", requested: "TestPublicInspectionReceiptPayloadRequiresCompleteFacts/complete", valid: true},
		{name: "common-refused", provider: "common", requested: "TestControlled"},
		{name: "provider-package-and-test-refused", provider: "aws", requested: "TestControlled", pkg: "core"},
		{name: "provider-package-only-refused", provider: "gcp", pkg: "core"},
	} {
		t.Run(test.name, func(t *testing.T) {
			step := workflowStep{ID: "controlled", Kind: "assembly-checks", Responsibility: test.provider, Tests: singleTestRequest(test.requested), Package: test.pkg}
			resolved := resolvedWorkflowStep{Selected: true}
			err := resolveWorkflowFocus(step, workflowRequest{}, &resolved)
			if !test.valid {
				if err == nil || resolved.AssemblyFocus != nil || resolved.AssemblyPreparation != nil {
					t.Fatal("saved assembly focus admitted common or package scope", err)
				}
				return
			}
			if err != nil {
				t.Fatal("saved exact provider assembly focus was rejected", err)
			}
			focus := resolved.AssemblyFocus
			if focus == nil || focus.Requested != test.requested || focus.Provider != test.provider || resolved.AssemblyPreparation == nil || resolved.OrdinaryFocus != nil || resolved.Focus != nil {
				t.Fatal("saved provider assembly focus lost its exact test, provider or preparation owner", resolved)
			}
		})
	}
}
