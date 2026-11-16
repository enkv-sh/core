package core

import (
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestInstalledPackagedAWSPublicationCandidateCharges(t *testing.T) {
	packagedPublicationCandidateCharges(t, contract.AWS)
}
func packagedOutputEnvironment(t testing.TB) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIACONTROLLEDOUTPUT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "controlled-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}
