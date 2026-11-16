package compositionfull

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	compositionaws "enkv.sh/compositions/aws"
	"enkv.sh/compositions/configuration"
	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/crypto"
	gcpprovider "enkv.sh/providers/gcp"
)

// full_only: false
func TestMaterializationConstructorsPreserveExactProviderCell(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
			t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
			source := configurationReaderPair(t, family, configuration.JSON, nil)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			c, pins, err := configurationPublicQueryInput(ctx, contract.ID{1}, source.pair)
			if err != nil {
				t.Fatal(err)
			}
			target, err := crypto.NewMaterializationFileTarget(contract.MaterializationTarget{Path: filepath.Join(protectedConfigurationTestDirectory(t), "application.env"), SurfaceID: contract.ID{2}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}, []string{source.path, source.generated})
			if err != nil {
				t.Fatal(err)
			}
			if c.AWS != nil {
				c.AWS.Candidate.Credentials = readerFixtureCredentials{}
			} else {
				client, e := gcpprovider.NewLocalResponderClient(&http.Transport{}, readerFixtureCredentials{})
				if e != nil {
					t.Fatal(e)
				}
				c.GCP.Candidate.Client = client
			}
			engine, err := NewMaterialization(ctx, MaterializationConfig{ReaderConfig: c, SourcePins: pins, CheckSource: source.pair.CheckUnchanged, Target: target})
			if err != nil || engine == nil {
				t.Fatal("public Recipient constructor required passive profiles", err)
			}
			engine.Close()
		})
	}
	for _, reader := range []ReaderConfig{{}, {Family: 255}, {Family: contract.AWS}, {Family: contract.GCP}, {Family: contract.AWS, GCP: &compositiongcp.ReaderConfig{}}, {Family: contract.GCP, AWS: &compositionaws.ReaderConfig{}}, {Family: contract.AWS, AWS: &compositionaws.ReaderConfig{}, GCP: &compositiongcp.ReaderConfig{}}} {
		for _, open := range []func(context.Context, MaterializationConfig) (*core.InstalledMaterialization, error){NewMaterialization, NewDefaultMaterialization} {
			engine, err := open(t.Context(), MaterializationConfig{ReaderConfig: reader})
			if err != ErrCell || engine != nil {
				t.Fatal("ambiguous provider admitted", err)
			}
		}
	}
}
