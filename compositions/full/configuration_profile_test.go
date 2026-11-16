package compositionfull

import (
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
	gcpprovider "enkv.sh/providers/gcp"
)

func configurationApplyProfileConfig(t *testing.T, family string) Config {
	t.Helper()
	source := configurationApplyPair(t, family, configuration.JSON, nil)
	model, err := configuration.Parse(t.Context(), source.pair)
	if err != nil {
		t.Fatal(err)
	}
	basis, descriptor, err := configurationPublicBasis(model)
	if err != nil {
		t.Fatal(err)
	}
	control, err := basis.ControlCore(model.DomainID, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	config, _, err := configurationApplyConfig(model, control)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

// full_only: false
func TestAWSOperatorCLIProfileClassesMatchPinnedProvider(t *testing.T) {
	config := configurationApplyProfileConfig(t, "aws")
	if config.Family != contract.AWS || config.AWS == nil || config.GCP != nil {
		t.Fatal("native AWS configuration selected a missing or second provider")
	}
	if config.AWS.StoreClass != awsprovider.StoreClass || config.AWS.TrustClass != awsprovider.TrustClass || config.AWS.VerifierClass != awsprovider.VerifierClass {
		t.Fatal("native AWS configuration profile differs from its fixed provider")
	}
}

// full_only: false
func TestGCPOperatorCLIProfileClassesMatchPinnedProvider(t *testing.T) {
	config := configurationApplyProfileConfig(t, "gcp")
	if config.Family != contract.GCP || config.GCP == nil || config.AWS != nil {
		t.Fatal("native GCP configuration selected a missing or second provider")
	}
	if config.GCP.StoreClass != gcpprovider.StoreClass || config.GCP.TrustClass != gcpprovider.TrustClass || config.GCP.VerifierClass != gcpprovider.VerifierClass {
		t.Fatal("native GCP configuration profile differs from its fixed provider")
	}
}
