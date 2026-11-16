package contract

import (
	"strings"
	"testing"
)

func kmsIndependenceBinding(provider Family, selector, fingerprint string) KMSBinding {
	return KMSBinding{Provider: provider, KeySelector: selector, Fingerprint: Hash([]byte(fingerprint))}
}

func gcpKMSSelector(project, location, ring, key, version string) string {
	return "projects/" + project + "/locations/" + location + "/keyRings/" + ring + "/cryptoKeys/" + key + "/cryptoKeyVersions/" + version
}

// full_only: false
func TestGCPKMSIndependenceUsesUnambiguousLiteralParents(t *testing.T) {
	base := gcpKMSSelector("fixture-project", "us-central1", "ring", "key", "1")
	for _, tc := range []struct {
		name, left, right string
		want              bool
	}{
		{"same-parent-version", base, gcpKMSSelector("fixture-project", "us-central1", "ring", "key", "2"), false},
		{"same-parent-id-number", base, gcpKMSSelector("123456789", "us-central1", "ring", "key", "2"), false},
		{"distinct-project-ids", base, gcpKMSSelector("second-project", "us-central1", "ring", "key", "2"), true},
		{"distinct-project-numbers", gcpKMSSelector("123456789", "us-central1", "ring", "key", "1"), gcpKMSSelector("987654321", "us-central1", "ring", "key", "2"), true},
		{"distinct-maximum-project-numbers", gcpKMSSelector("9223372036854775807", "us-central1", "ring", "key", "1"), gcpKMSSelector("9223372036854775806", "us-central1", "ring", "key", "2"), true},
		{"distinct-location", base, gcpKMSSelector("123456789", "europe-west1", "ring", "key", "2"), true},
		{"distinct-ring", base, gcpKMSSelector("123456789", "us-central1", "other-ring", "key", "2"), true},
		{"distinct-key", base, gcpKMSSelector("123456789", "us-central1", "ring", "other-key", "2"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left := kmsIndependenceBinding(GCP, tc.left, "left")
			right := kmsIndependenceBinding(GCP, tc.right, "right")
			if got := IndependentKMSBindings(left, right); got != tc.want {
				t.Fatalf("forward independence=%v want=%v", got, tc.want)
			}
			if got := IndependentKMSBindings(right, left); got != tc.want {
				t.Fatalf("reverse independence=%v want=%v", got, tc.want)
			}
		})
	}
}

// full_only: false
func TestGCPKMSIndependenceRejectsMalformedSelectors(t *testing.T) {
	valid := gcpKMSSelector("second-project", "us-central1", "ring", "key", "2")
	for _, selector := range []string{
		gcpKMSSelector("short", "us-central1", "ring", "key", "1"),
		gcpKMSSelector("Upper-project", "us-central1", "ring", "key", "1"),
		gcpKMSSelector("project-", "us-central1", "ring", "key", "1"),
		gcpKMSSelector("01", "us-central1", "ring", "key", "1"),
		gcpKMSSelector("0", "us-central1", "ring", "key", "1"),
		gcpKMSSelector("9223372036854775808", "us-central1", "ring", "key", "1"),
		gcpKMSSelector("fixture-project", "us-central1", "ring", "key", "01"),
		gcpKMSSelector("fixture-project", "us-central1", "ring", "key", "9223372036854775808"),
		gcpKMSSelector("fixture-project", "", "ring", "key", "1"),
		gcpKMSSelector("fixture-project", "US-central1", "ring", "key", "1"),
		gcpKMSSelector("fixture-project", "us-central1", "", "key", "1"),
		gcpKMSSelector("fixture-project", "us-central1", strings.Repeat("r", 64), "key", "1"),
		gcpKMSSelector("fixture-project", "us-central1", "ring", "", "1"),
		gcpKMSSelector("fixture-project", "us-central1", "ring", strings.Repeat("k", 64), "1"),
		valid + "/extra",
	} {
		left := kmsIndependenceBinding(GCP, selector, "left")
		right := kmsIndependenceBinding(GCP, valid, "right")
		if IndependentKMSBindings(left, right) || IndependentKMSBindings(right, left) {
			t.Fatalf("malformed selector proved separation: %q", selector)
		}
	}
}

// full_only: false
func TestGCPKMSIndependenceKeepsSelectorBounds(t *testing.T) {
	projectA := "a" + strings.Repeat("b", 29)
	projectB := "c" + strings.Repeat("d", 29)
	ring, key, version := strings.Repeat("r", 63), strings.Repeat("k", 63), "9223372036854775807"
	left := gcpKMSSelector(projectA, "us-central1", ring, key, version)
	right := gcpKMSSelector(projectB, "us-central1", ring, key, version)
	if !IndependentKMSBindings(kmsIndependenceBinding(GCP, left, "left"), kmsIndependenceBinding(GCP, right, "right")) {
		t.Fatal("maximum valid project/ring/key/version shapes did not prove separation")
	}

	shape := KMSBinding{BindingID: Hash([]byte("binding")), BindingIncarnationID: Hash([]byte("binding incarnation")), BindingSerial: 1, Provider: GCP, WrapProfile: RSAOAEPWrapProfile, ProtectionClass: SoftwareProtection,
		KeySelector: strings.Repeat("a", MaxKeySelector), SPKI: make([]byte, KMSPublicKeyLength), Fingerprint: Hash([]byte("fingerprint"))}
	if _, err := kmsBindingShapeLength(shape); err != nil {
		t.Fatal("structural selector ceiling was lowered", err)
	}
	shape.KeySelector += "a"
	if _, err := kmsBindingShapeLength(shape); err != ErrRecordCapacity {
		t.Fatal("oversized structural selector did not return capacity refusal", err)
	}
	left = gcpKMSSelector("fixture-project", "us-central1", "ring", "key", "1") + strings.Repeat("a", MaxKeySelector)
	right = gcpKMSSelector("second-project", "us-central1", "ring", "other-key", "2")
	if IndependentKMSBindings(kmsIndependenceBinding(GCP, left, "left"), kmsIndependenceBinding(GCP, right, "right")) {
		t.Fatal("oversized selector proved separation")
	}
}

// full_only: false
func TestAWSKMSIndependenceKeepsMultiRegionRules(t *testing.T) {
	left := kmsIndependenceBinding(AWS, "arn:aws:kms:us-east-1:123456789012:key/mrk-shared", "left")
	sameMRK := kmsIndependenceBinding(AWS, "arn:aws:kms:us-west-2:123456789012:key/mrk-shared", "right")
	differentMRK := kmsIndependenceBinding(AWS, "arn:aws:kms:us-west-2:123456789012:key/mrk-other", "right")
	if IndependentKMSBindings(left, sameMRK) || !IndependentKMSBindings(left, differentMRK) {
		t.Fatal("AWS multi-Region independence changed")
	}
}
