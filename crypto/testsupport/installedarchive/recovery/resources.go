package recovery

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/fixturekeys"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func ChooseResources(t testing.TB, family contract.Family) (installedarchive.RecoveryResourceInput, installedarchive.RecoveryResources, contract.ID) {
	t.Helper()
	var input installedarchive.RecoveryResourceInput
	if path := os.Getenv("ENKV_RECOVERY_RESOURCES_INPUT"); path != "" {
		ReadParentJSON(t, path, &input)
	} else {
		directory := t.TempDir()
		region, owner := "us-east-1", "123456789012"
		if family == contract.GCP {
			region, owner = "australia-southeast1", ""
		}
		input = installedarchive.RecoveryResourceInput{Location: contract.StoreLocation{Provider: family, Region: region, Bucket: "fixture-bucket", PrefixBeforeHEAD: "fixture", ExpectedOwner: owner}, Resources: directory + "/resources.json", Setup: directory + "/setup.json"}
	}
	recovery := testtrust.NewRecovery(t, family, contract.Hash([]byte("fixture/recovery-trust")))
	region := "us-east-1"
	if family == contract.GCP {
		region = "us-central1"
	}
	resources := installedarchive.RecoveryResources{Location: input.Location,
		Normal:   fixedSigningResource(t, family),
		Recovery: installedarchive.SigningResource{Selector: recovery.KeySelector(), Region: region, PublicKey: recovery.PublicKey(), Material: contract.Hash([]byte("fixture/recovery-trust"))},
	}
	for i := range 3 {
		for role, destination := range map[uint8]*[]installedarchive.SigningResource{contract.NormalSigningRole: &resources.NormalSuccessors, contract.RecoverySigningRole: &resources.RecoverySuccessors} {
			material := contract.Hash([]byte(fmt.Sprintf("independent recovery successor %d/%d", role, i)))
			signer := testtrust.NewWithIdentity(t, family, material, material, role)
			*destination = append(*destination, installedarchive.SigningResource{Selector: signer.KeySelector(), Region: region, PublicKey: signer.PublicKey(), Material: material})
		}
	}
	for _, encoded := range fixturekeys.PrivateKeys {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		clear(der)
		if err != nil {
			t.Fatal(err)
		}
		public, ok := key.(interface{ Public() crypto.PublicKey })
		if !ok {
			t.Fatal("independent fixture key type")
		}
		spki, err := x509.MarshalPKIXPublicKey(public.Public())
		if err != nil {
			t.Fatal(err)
		}
		resources.AuthorityPublicKeys = append(resources.AuthorityPublicKeys, spki)
	}
	resources.InitialNormal, resources.InitialRecovery = resources.Normal, resources.Recovery
	var domain contract.ID
	if _, err := rand.Read(domain[:]); err != nil || domain.IsZero() {
		t.Fatal("resource owner DomainID allocation", err)
	}
	resources.Domain, resources.RecoveryEnabled = domain, input.Recovery
	if _, err := rand.Read(resources.PriorDomain[:]); err != nil || resources.PriorDomain.IsZero() || resources.PriorDomain == domain {
		t.Fatal("resource owner prior DomainID allocation", err)
	}
	return input, resources, domain
}

func ReadParentJSON(t testing.TB, path string, value any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || len(body) > MaximumRecoveryInputBytes {
		t.Fatal("parent resource input refused", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("parent resource trailing message")
	}
}

func WriteParentJSON(t testing.TB, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}
