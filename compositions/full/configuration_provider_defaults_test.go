package compositionfull

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	gcpprovider "enkv.sh/providers/gcp"
)

// full_only: false
func TestConfigurationProviderDefaultsKeepServiceFactsAndPhasePolicy(t *testing.T) {
	for _, region := range []struct{ name, storage, kms string }{
		{"us-central1", "https://storage.us-central1.rep.googleapis.com/storage/v1/", "https://us-central1-cloudkms.googleapis.com/"},
		{"australia-southeast1", "https://storage.australia-southeast1.rep.googleapis.com/storage/v1/", "https://australia-southeast1-cloudkms.googleapis.com/"},
	} {
		if got := gcpprovider.StorageEndpoint(region.name); got != region.storage {
			t.Fatal("regional Store endpoint changed", got)
		}
		if got := gcpprovider.KMSEndpoint(region.name); got != region.kms {
			t.Fatal("regional key endpoint changed", got)
		}
	}
	if gcpprovider.SigningAlgorithm != "EC_SIGN_P256_SHA256" || gcpprovider.SigningPurpose != "ASYMMETRIC_SIGN" {
		t.Fatal("signing service facts changed")
	}
	want := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	first, second := configurationProviderTransport(), configurationProviderTransport()
	if first == second || !reflect.DeepEqual(first, want) || !reflect.DeepEqual(second, want) {
		t.Fatal("application phase bounds or transport ownership changed")
	}
}
