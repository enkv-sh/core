package installedarchive

import (
	"time"

	"enkv.sh/core/contract"
)

// RecoveryInput contains console inputs and local choices only. Fixture state
// and the independent expected result remain in the provider parent.
type RecoveryInput struct {
	Provider                   string `json:"provider"`
	Bucket                     string `json:"bucket"`
	Region                     string `json:"region"`
	Prefix                     string `json:"prefix"`
	Owner                      string `json:"owner,omitempty"`
	NormalSigner               string `json:"normal_signer,omitempty"`
	NormalRegion               string `json:"normal_region,omitempty"`
	RecoverySigner             string `json:"recovery_signer,omitempty"`
	RecoveryRegion             string `json:"recovery_region,omitempty"`
	ReadRoute                  string `json:"read_route"`
	SignRoute                  string `json:"sign_route"`
	PrivateRoute               string `json:"private_route"`
	AccessKey                  string `json:"access_key,omitempty"`
	SecretKey                  string `json:"secret_key,omitempty"`
	Token                      string `json:"token,omitempty"`
	SessionToken               string `json:"session_token,omitempty"`
	ServiceAccountFile         string `json:"service_account_file,omitempty"`
	NormalServiceAccountFile   string `json:"normal_service_account_file,omitempty"`
	RecoveryServiceAccountFile string `json:"recovery_service_account_file,omitempty"`
	PrivateServiceAccountFile  string `json:"private_service_account_file,omitempty"`
	Requests                   uint64 `json:"requests,omitempty"`
	BodyBytes                  uint64 `json:"body_bytes,omitempty"`
	ResponseBytes              uint64 `json:"response_bytes,omitempty"`

	NormalAccessKey      string `json:"normal_access_key,omitempty"`
	NormalSecretKey      string `json:"normal_secret_key,omitempty"`
	NormalSessionToken   string `json:"normal_session_token,omitempty"`
	RecoveryAccessKey    string `json:"recovery_access_key,omitempty"`
	RecoverySecretKey    string `json:"recovery_secret_key,omitempty"`
	RecoverySessionToken string `json:"recovery_session_token,omitempty"`
	PrivateAccessKey     string `json:"private_access_key,omitempty"`
	PrivateSecretKey     string `json:"private_secret_key,omitempty"`
	PrivateSessionToken  string `json:"private_session_token,omitempty"`

	TimeoutMillis  uint32       `json:"timeout_millis"`
	Output         string       `json:"output"`
	Responder      string       `json:"responder"`
	TLSCertificate []byte       `json:"tls_certificate,omitempty"`
	ExpectedDomain *contract.ID `json:"expected_domain,omitempty"`
	ExpectedKEK    string       `json:"expected_kek,omitempty"`
}

// LiveRecoveryParentInput is private supervising state. Only Input's console
// fields, explicit working credentials and new transport locations reach Core.
type LiveRecoveryParentInput struct {
	Fixture, Condition, Report, ChildTerminals string
	Input                                      RecoveryInput
	Resources                                  RecoveryResources
	Locations                                  RecoveryLocations
	AuthoritySelector                          string
	AuthorityPublicKey                         []byte
	Credentials                                LiveCredentialFiles
	ProviderDenial                             bool
}

type LiveCredentialFile struct {
	Path, Profile string
	Expires       time.Time
}
type LiveCredentialFiles struct{ Read, Normal, Recovery, Private LiveCredentialFile }
