package nativeprocess

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// full_only: false
func TestStandardContextResolvesAllRolesBeforeSelection(t *testing.T) {
	contexts := map[string]StandardContext{"init": {Mode: "aws-sso", Home: "/isolated/init", Profile: "init"}, "unused": {Mode: "unreadable-invalid", Home: "relative"}}
	got, err := ResolveContexts("aws", contexts, []string{"init"})
	if err != nil || len(got) != 1 || got["init"] != contexts["init"] {
		t.Fatal("unused role changed selected context", err)
	}
	for _, roles := range [][]string{{"init", "apply"}, {"init", "init"}, {"unused"}, nil} {
		if _, err := ResolveContexts("aws", contexts, roles); err == nil {
			t.Fatal("incomplete or ambiguous roles admitted", roles)
		}
	}
}

// full_only: false
func TestStandardContextChildCannotInheritAnotherCredentialRoute(t *testing.T) {
	inherited := []string{"PATH=/bin", "HOME=/other", "AWS_ACCESS_KEY_ID=do-not-inherit", "AWS_SESSION_TOKEN=do-not-inherit", "AWS_WEB_IDENTITY_TOKEN_FILE=/other/token", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/other/container", "AWS_EC2_METADATA_SERVICE_ENDPOINT=http://do-not-inherit", "AWS_PROFILE=other", "AWS_ENDPOINT_URL=https://do-not-inherit", "AWS_ENDPOINT_URL_SSO=https://do-not-inherit", "AWS_ENDPOINT_URL_SSO_OIDC=https://do-not-inherit", "AWS_ENDPOINT_URL_STS=https://do-not-inherit", "GOOGLE_API_ENDPOINT_OVERRIDES=do-not-inherit", "GCE_METADATA_HOST=do-not-inherit", "GOOGLE_APPLICATION_CREDENTIALS=/other/credential", "GOOGLE_CLOUD_QUOTA_PROJECT=other", "CLOUDSDK_CONFIG=/other", "ENKV_TEST_INVOCATION=/other/authority", "EXPERIMENTAL_GOOGLE_API_USE_S2A=true"}
	for _, cell := range []struct {
		provider string
		context  StandardContext
	}{{"aws", StandardContext{Mode: "aws-sso", Home: "/selected", Profile: "login"}}, {"gcp", StandardContext{Mode: "gcp-user-adc", Home: "/selected"}}, {"aws", StandardContext{Mode: "aws-assume-role", Home: "/selected", Profile: "login"}}, {"gcp", StandardContext{Mode: "gcp-impersonated-adc", Home: "/selected"}}, {"aws", StandardContext{Mode: "aws-shared-credentials", Home: "/selected", Profile: "login"}}, {"gcp", StandardContext{Mode: "gcp-service-account-adc", Home: "/selected", CredentialsFile: "/selected/key.json", QuotaProject: "selected-project"}}} {
		environment, err := cell.context.Environment(cell.provider, inherited, "/private/absent-credentials")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(environment, "\n"), "do-not-inherit") || strings.Contains(strings.Join(environment, "\n"), "/other") {
			t.Fatal("ambient credential route escaped isolation")
		}
		credentials := "AWS_SHARED_CREDENTIALS_FILE=/private/absent-credentials"
		if cell.context.Mode == "aws-assume-role" || cell.context.Mode == "aws-shared-credentials" {
			credentials = "AWS_SHARED_CREDENTIALS_FILE=/selected/.aws/credentials"
		}
		if cell.provider == "aws" && !slices.Contains(environment, credentials) {
			t.Fatal("AWS selected discovery path differs", environment)
		}
		if cell.context.Mode == "gcp-service-account-adc" && (!slices.Contains(environment, "GOOGLE_APPLICATION_CREDENTIALS=/selected/key.json") || !slices.Contains(environment, "GOOGLE_CLOUD_QUOTA_PROJECT=selected-project")) {
			t.Fatal("service account ADC selection differs")
		}
		if cell.provider == "aws" && !slices.Contains(environment, "AWS_EC2_METADATA_DISABLED=true") {
			t.Fatal("AWS metadata discovery was not disabled")
		}
		if cell.provider == "gcp" && !slices.Contains(environment, "GCE_METADATA_HOST=127.0.0.1:1") {
			t.Fatal("GCP metadata discovery was not isolated")
		}
		if cell.context.StandardDiscovery(cell.provider) != (cell.context.Mode == "aws-sso" || cell.context.Mode == "gcp-user-adc") {
			t.Fatal("assumed identity claimed direct login discovery")
		}
		if cell.context.OperatorDiscovery(cell.provider) != (cell.context.Mode == "aws-sso" || cell.context.Mode == "aws-shared-credentials" || cell.context.Mode == "gcp-user-adc" || cell.context.Mode == "gcp-service-account-adc") {
			t.Fatal("operator credential route classification differs")
		}
		if environment[0] != "PATH=/bin" {
			t.Fatal("ordinary process environment lost")
		}
		again, err := cell.context.Environment(cell.provider, inherited, "/private/absent-credentials")
		if err != nil || !reflect.DeepEqual(environment, again) {
			t.Fatal("context changed on repeated construction")
		}
	}
	if _, err := (StandardContext{Mode: "gcp-user-adc", Home: "relative"}).Environment("gcp", inherited, "/private/absent"); err == nil {
		t.Fatal("relative login discovery admitted")
	}
}

// full_only: false
func TestStandardContextCredentialFileAndQuotaAdmission(t *testing.T) {
	valid := StandardContext{Mode: "gcp-service-account-adc", Home: "/selected", CredentialsFile: "/selected/key.json", QuotaProject: "project-id"}
	if valid.Validate("gcp") != nil {
		t.Fatal("service account ADC context refused")
	}
	for _, change := range []func(*StandardContext){
		func(s *StandardContext) { s.CredentialsFile = "" },
		func(s *StandardContext) { s.CredentialsFile = "relative/key.json" },
		func(s *StandardContext) { s.CredentialsFile = "/selected/../key.json" },
		func(s *StandardContext) { s.CredentialsFile = "/selected/key\x00.json" },
		func(s *StandardContext) { s.QuotaProject = "" },
		func(s *StandardContext) { s.QuotaProject = "project with space" },
		func(s *StandardContext) { s.QuotaProject = strings.Repeat("p", 254) },
		func(s *StandardContext) { s.Profile = "login" },
	} {
		value := valid
		change(&value)
		if value.OperatorDiscovery("gcp") {
			t.Fatal("invalid service account context classified as operator discovery")
		}
		if value.Validate("gcp") == nil {
			t.Fatal("invalid service account ADC context admitted")
		}
	}
	for _, mode := range []string{"gcp-user-adc", "gcp-impersonated-adc", "aws-sso", "aws-assume-role", "aws-shared-credentials"} {
		provider := "gcp"
		value := StandardContext{Mode: mode, Home: "/selected"}
		if strings.HasPrefix(mode, "aws-") {
			provider = "aws"
			value.Profile = "login"
		}
		if value.Validate(provider) != nil {
			t.Fatal("existing context refused", mode)
		}
		withFile := value
		withFile.CredentialsFile = "/selected/key.json"
		withQuota := value
		withQuota.QuotaProject = "project-id"
		if withFile.Validate(provider) == nil || mode != "gcp-impersonated-adc" && withQuota.Validate(provider) == nil {
			t.Fatal("credential file or quota admitted outside its selected ADC route", mode)
		}
	}
}

// full_only: false
func TestStandardContextImpersonatedQuotaEnvironment(t *testing.T) {
	for _, quota := range []string{"", "selected-project"} {
		t.Run("quota="+quota, func(t *testing.T) {
			selected := StandardContext{Mode: "gcp-impersonated-adc", Home: "/selected", QuotaProject: quota}
			base := []string{"PATH=/bin", "HOME=/other", "GOOGLE_APPLICATION_CREDENTIALS=/other/key.json", "GOOGLE_CLOUD_QUOTA_PROJECT=other-project", "CLOUDSDK_CONFIG=/other"}
			got, err := selected.Environment("gcp", base, "/private/absent")
			want := []string{"PATH=/bin", "HOME=/selected", "XDG_CONFIG_HOME=/selected/.config"}
			if quota != "" {
				want = append(want, "GOOGLE_CLOUD_QUOTA_PROJECT=selected-project")
			}
			want = append(want, "CLOUDSDK_CONFIG=/selected/.config/gcloud", "GCE_METADATA_HOST=127.0.0.1:1", "GOOGLE_API_USE_CLIENT_CERTIFICATE=false", "EXPERIMENTAL_GOOGLE_API_USE_S2A=false")
			if err != nil || !slices.Equal(got, want) || selected.StandardDiscovery("gcp") || selected.OperatorDiscovery("gcp") {
				t.Fatal("impersonated context changed exact isolated discovery or quota selection", err)
			}
		})
	}
	for _, quota := range []string{"project with space", "private\r\nheader", strings.Repeat("p", 254)} {
		selected := StandardContext{Mode: "gcp-impersonated-adc", Home: "/selected", QuotaProject: quota}
		if selected.Validate("gcp") == nil {
			t.Fatal("malformed impersonated quota project admitted")
		}
	}
	for _, selected := range []StandardContext{
		{Mode: "gcp-impersonated-adc", Home: "/selected", QuotaProject: "project-id", CredentialsFile: "/existing/key.json"},
		{Mode: "gcp-impersonated-adc", Home: "/selected", QuotaProject: "project-id", Profile: "another-login"},
	} {
		if selected.Validate("gcp") == nil {
			t.Fatal("impersonated quota introduced another credential source")
		}
	}
}
