package recovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// RunOrdinaryLiveParentInvocation supplies the fixed installed fixture to the
// same executable's controlled parent. This owns its ordinary-unit skip proof;
// the dynamic setup/writer cases own complete-loss qualification.
func RunOrdinaryLiveParentInvocation(t *testing.T, family contract.Family, helper string) {
	t.Helper()
	_, resources, _ := ChooseResources(t, family)
	provider, domain, authority := "aws", "2798e91fd82fb9d967c6e53473b215b89acefd2424d676badd3142080e14acb9", "arn:aws:kms:us-west-2:210987654321:key/e8f68876-3b1e-9ce0-176c-baff4815e541"
	if family == contract.GCP {
		provider, domain, authority = "gcp", "6cd57eb53fc8ec9ade80eee27644062665fb17a8e0da1b7a2a349a72a368bfa0", "projects/authority-project/locations/europe-west1/keyRings/fixture/cryptoKeys/key-dc01e70e2c2447b500e46fdb0b18f5e4/cryptoKeyVersions/1"
	}
	encoded, err := hex.DecodeString(domain)
	if err != nil {
		t.Fatal(err)
	}
	copy(resources.Domain[:], encoded)
	resources.Location = contract.StoreLocation{Provider: family, Region: "us-east-1", Bucket: "fixture-bucket", PrefixBeforeHEAD: "fixture", ExpectedOwner: "123456789012"}
	if family == contract.GCP {
		resources.Location.Region, resources.Location.ExpectedOwner = "australia-southeast1", ""
	}
	archive := installedarchive.Load(t, provider)
	if archive.Domain != resources.Domain || archive.Location != resources.Location || archive.SignerSelector != resources.Normal.Selector || !bytes.Equal(archive.SignerPublicKey, resources.Normal.PublicKey) || archive.AuthorityBinding.KeySelector != authority || !bytes.Equal(archive.AuthorityBinding.SPKI, resources.AuthorityPublicKeys[0]) {
		t.Fatalf("fixed ordinary fixture facts differ: domain=%t location=%t selector=%t public=%t authority=%t key=%t", archive.Domain == resources.Domain, archive.Location == resources.Location, archive.SignerSelector == resources.Normal.Selector, bytes.Equal(archive.SignerPublicKey, resources.Normal.PublicKey), archive.AuthorityBinding.KeySelector == authority, bytes.Equal(archive.AuthorityBinding.SPKI, resources.AuthorityPublicKeys[0]))
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal("private ordinary oracle owner refused")
	}
	oracle := filepath.Join(directory, "private-value")
	value := []byte("enkv first secret test value")
	defer clear(value)
	if err := os.WriteFile(oracle, value, 0600); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(directory, "fixture.json")
	WriteParentJSON(t, fixture, installedarchive.RecoveryFixture{Archive: archive, Secrets: 1, Oracles: []installedarchive.PrivateValue{{Name: "installed-positive-secret", Path: oracle, Length: uint32(len(value))}}})
	owner := installedarchive.LiveRecoveryParentInput{Fixture: fixture, Condition: "complete", Report: filepath.Join(directory, "report.json"), ChildTerminals: filepath.Join(directory, "restricted-child.txt"), Resources: resources, AuthoritySelector: authority, AuthorityPublicKey: resources.AuthorityPublicKeys[0], Input: installedarchive.RecoveryInput{Provider: provider, Owner: resources.Location.ExpectedOwner, AccessKey: "synthetic-access", SecretKey: "synthetic-secret", ReadRoute: "new-read", SignRoute: "new-sign", PrivateRoute: "new-private", TimeoutMillis: 10000, Requests: 256, BodyBytes: 256 << 20, ResponseBytes: 1 << 20}}
	if family == contract.GCP {
		owner.Input.AccessKey, owner.Input.SecretKey, owner.Input.Token = "", "", "synthetic-token"
	}
	path := filepath.Join(directory, "parent.json")
	WriteParentJSON(t, path, owner)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.v=test2json", "-test.count=1", "-test.run=^"+helper+"$")
	command.Dir = directory
	command.Env = append(RecoveryEnvironment(directory, directory), "ENKV_RECOVERY_LIVE_PARENT_CONTROL="+path)
	var output installedarchive.ChildOutput
	command.Stdout, command.Stderr = &output, &output
	joined := command.Run()
	if joined != nil || output.Completed(helper) != nil {
		t.Fatalf("ordinary controlled parent did not complete: %v\n%s", joined, output.Bytes())
	}
	var report installedarchive.RecoveryReport
	ReadParentJSON(t, owner.Report, &report)
	if !report.ChildStarted || !report.ChildJoined || report.Opened != 1 || report.Counts.AuthorityDecrypts != 1 || report.OracleCounts.AuthorityDecrypts != 1 || !report.RemoteEffectsZero || !report.OracleEpochSeparate || report.ReservedRequests > owner.Input.Requests || report.ReservedBytes > owner.Input.BodyBytes {
		t.Fatal("ordinary controlled parent's private checks incomplete")
	}
	child, err := os.ReadFile(owner.ChildTerminals)
	if err != nil {
		t.Fatal(err)
	}
	var terminals installedarchive.ChildOutput
	if _, err := terminals.Write(child); err != nil {
		t.Fatal(err)
	}
	childName := "TestRestrictedAWSReconstructionFromConsoleInputs"
	if family == contract.GCP {
		childName = "TestRestrictedGCPReconstructionFromConsoleInputs"
	}
	if terminals.Completed(childName) != nil {
		t.Fatal("restricted child completion incomplete")
	}
	for _, retired := range []string{path, fixture} {
		if _, err := os.Lstat(retired); !os.IsNotExist(err) {
			t.Fatal("private parent carrier survived")
		}
	}
	t.Logf("joined ordinary parent and restricted child; physical auth=%d; privately checked secrets=%d", report.Counts.Authentication, report.Opened)
	if !bytes.Equal(archive.SignerPublicKey, resources.Normal.PublicKey) {
		t.Fatal("independent fixture signer differs")
	}
}

func fixedSigningResource(t testing.TB, family contract.Family) installedarchive.SigningResource {
	t.Helper()
	region := "us-east-1"
	if family == contract.GCP {
		region = "us-central1"
	}
	identity := contract.Hash([]byte("fixture/trust"))
	signer := testtrust.New(t, family, identity)
	return installedarchive.SigningResource{Selector: signer.KeySelector(), Region: region, PublicKey: signer.PublicKey(), Material: identity}
}
