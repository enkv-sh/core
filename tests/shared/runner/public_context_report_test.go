package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// full_only: false
func TestPublicRunContextReportsExactCredentialRoutesWithoutPrivateLabels(t *testing.T) {
	for _, row := range []struct{ provider, mode, label, rendered string }{
		{"aws", "aws-sso", "aws_sso", `aws\_sso`},
		{"aws", "aws-shared-credentials", "aws_shared_credentials", `aws\_shared\_credentials`},
		{"aws", "aws-assume-role", "aws_assume_role", `aws\_assume\_role`},
		{"gcp", "gcp-user-adc", "gcp_user_adc", `gcp\_user\_adc`},
		{"gcp", "gcp-service-account-adc", "gcp_service_account_adc", `gcp\_service\_account\_adc`},
		{"gcp", "gcp-impersonated-adc", "gcp_impersonated_adc", `gcp\_impersonated\_adc`},
		{"aws", "", "shared_credentials_file", `shared\_credentials\_file`},
		{"gcp", "", "service_account_file", `service\_account\_file`},
	} {
		t.Run(row.label, func(t *testing.T) {
			settings := liveSettings{
				"provider": row.provider, "region": "ap-southeast-2", "sdk_mode": row.mode,
				"sdk_home": "/synthetic-private-home", "sdk_profile": "synthetic-private-profile",
				"sdk_credentials_file": "/synthetic-private-credentials", "credentials_file": "/synthetic-private-legacy-file",
			}
			context := safeRunContext(settings)
			if context.CredentialRoute != row.label {
				t.Fatalf("source route differs: got=%q want=%q", context.CredentialRoute, row.label)
			}
			encoded, err := json.Marshal(context)
			if err != nil {
				t.Fatal(err)
			}
			output := string(encoded)
			for _, private := range []string{"synthetic-private-home", "synthetic-private-profile", "synthetic-private-credentials", "synthetic-private-legacy-file"} {
				if strings.Contains(output, private) {
					t.Fatal("report exposed private credential context")
				}
			}
		})
	}
}
