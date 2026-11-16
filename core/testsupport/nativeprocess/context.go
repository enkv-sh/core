package nativeprocess

import (
	"errors"
	"path/filepath"
	"strings"
)

// StandardContext selects test-process SDK discovery. It is not an ENKV
// connection format and contains no credential material. Home contains the
// operator's existing SDK configuration. CredentialsFile selects an existing
// service-account file through the standard ADC environment.
type StandardContext struct {
	Mode            string `json:"mode"`
	Home            string `json:"home"`
	Profile         string `json:"profile,omitempty"`
	CredentialsFile string `json:"credentials_file,omitempty"`
	QuotaProject    string `json:"quota_project,omitempty"`
}

func (s StandardContext) Validate(provider string) error {
	refused := errors.New("standard SDK context refused")
	if !filepath.IsAbs(s.Home) || filepath.Clean(s.Home) != s.Home || strings.ContainsRune(s.Home, 0) {
		return refused
	}
	if s.Mode != "gcp-service-account-adc" && s.CredentialsFile != "" {
		return refused
	}
	if s.Mode != "gcp-service-account-adc" && s.Mode != "gcp-impersonated-adc" && s.QuotaProject != "" {
		return refused
	}
	switch provider {
	case "aws":
		if (s.Mode != "aws-sso" && s.Mode != "aws-assume-role" && s.Mode != "aws-shared-credentials") || len(s.Profile) == 0 || len(s.Profile) > 128 {
			return refused
		}
		for _, c := range s.Profile {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("_.-", c) {
				return refused
			}
		}
	case "gcp":
		if (s.Mode != "gcp-user-adc" && s.Mode != "gcp-impersonated-adc" && s.Mode != "gcp-service-account-adc") || s.Profile != "" {
			return refused
		}
		if s.Mode == "gcp-service-account-adc" && (!filepath.IsAbs(s.CredentialsFile) || filepath.Clean(s.CredentialsFile) != s.CredentialsFile || strings.ContainsRune(s.CredentialsFile, 0) || s.QuotaProject == "") {
			return refused
		}
		if len(s.QuotaProject) > 253 {
			return refused
		}
		for _, c := range s.QuotaProject {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("-.:", c) {
				return refused
			}
		}
	default:
		return refused
	}
	return nil
}

// StandardDiscovery identifies the two login routes whose live proof is kept
// separate from functional permission checks through assumed identities.
func (s StandardContext) StandardDiscovery(provider string) bool {
	return s.Validate(provider) == nil && (s.Mode == "aws-sso" || s.Mode == "gcp-user-adc")
}

// OperatorDiscovery identifies the four local operator credential routes.
func (s StandardContext) OperatorDiscovery(provider string) bool {
	return s.Validate(provider) == nil && (s.Mode == "aws-sso" || s.Mode == "aws-shared-credentials" || s.Mode == "gcp-user-adc" || s.Mode == "gcp-service-account-adc")
}

// ResolveContexts admits every required role before a caller opens any login
// file or selects credentials. Unused contexts are neither inspected nor used.
func ResolveContexts(provider string, available map[string]StandardContext, roles []string) (map[string]StandardContext, error) {
	if len(roles) == 0 {
		return nil, errors.New("standard SDK roles required")
	}
	resolved := make(map[string]StandardContext, len(roles))
	for _, role := range roles {
		value, ok := available[role]
		if !ok || value.Validate(provider) != nil {
			return nil, errors.New("required standard SDK role unavailable")
		}
		if _, duplicate := resolved[role]; duplicate {
			return nil, errors.New("duplicate standard SDK role")
		}
		resolved[role] = value
	}
	return resolved, nil
}

// Environment removes inherited discovery and ENKV inputs. Only the selected
// standard login context is visible to the new executable. absentCredentials
// must name a nonexistent file in the process's private working directory.
// Prefix removal also removes inherited SDK endpoint overrides. The selected
// AWS profile's SSO/OIDC/STS endpoints are checked by the native loader overlay.
func (s StandardContext) Environment(provider string, base []string, absentCredentials string) ([]string, error) {
	if s.Validate(provider) != nil || !filepath.IsAbs(absentCredentials) {
		return nil, errors.New("standard SDK environment refused")
	}
	result := make([]string, 0, len(base)+8)
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, errors.New("process environment refused")
		}
		if key == "HOME" || key == "XDG_CONFIG_HOME" || strings.HasPrefix(key, "AWS_") || strings.HasPrefix(key, "GCE_") || strings.HasPrefix(key, "GOOGLE_") || strings.HasPrefix(key, "GCLOUD_") || strings.HasPrefix(key, "CLOUDSDK_") || strings.HasPrefix(key, "ENKV_") || strings.HasPrefix(key, "EXPERIMENTAL_GOOGLE_") {
			continue
		}
		result = append(result, entry)
	}
	result = append(result, "HOME="+s.Home, "XDG_CONFIG_HOME="+filepath.Join(s.Home, ".config"))
	if provider == "aws" {
		credentials := absentCredentials
		if s.Mode == "aws-assume-role" || s.Mode == "aws-shared-credentials" {
			credentials = filepath.Join(s.Home, ".aws", "credentials")
		}
		result = append(result, "AWS_PROFILE="+s.Profile, "AWS_CONFIG_FILE="+filepath.Join(s.Home, ".aws", "config"), "AWS_SHARED_CREDENTIALS_FILE="+credentials, "AWS_EC2_METADATA_DISABLED=true", "AWS_SDK_LOAD_CONFIG=1")
	} else {
		if s.Mode == "gcp-service-account-adc" {
			result = append(result, "GOOGLE_APPLICATION_CREDENTIALS="+s.CredentialsFile)
		}
		if s.QuotaProject != "" {
			result = append(result, "GOOGLE_CLOUD_QUOTA_PROJECT="+s.QuotaProject)
		}
		// The native observer rejects a metadata credential before property or
		// token access. A local metadata host also prevents cloud discovery probes.
		result = append(result, "CLOUDSDK_CONFIG="+filepath.Join(s.Home, ".config", "gcloud"), "GCE_METADATA_HOST=127.0.0.1:1", "GOOGLE_API_USE_CLIENT_CERTIFICATE=false", "EXPERIMENTAL_GOOGLE_API_USE_S2A=false")
	}
	return result, nil
}
