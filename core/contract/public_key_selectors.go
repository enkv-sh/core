package contract

import (
	"regexp"
	"strings"
)

var awsPublicKeySelector = regexp.MustCompile(`^arn:aws:kms:([a-z0-9-]+):([0-9]{12}):key/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|mrk-[a-f0-9]{32})$`)
var gcpPublicKeySegment = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var gcpEncryptionKeyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
var gcpEncryptionProject = regexp.MustCompile(`^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[1-9][0-9]{0,19})$`)

type AWSKeySelector struct{ Region, Account, Key string }
type GCPKeySelector struct{ Project, Region, KeyRing, Key, Version string }

// ParseAWSKeySelector preserves the existing separate signing/encryption
// profiles: the signing owner accepts UUID keys; encryption also accepts MRKs.
func ParseAWSKeySelector(selector string, signing bool) (AWSKeySelector, bool) {
	parts := awsPublicKeySelector.FindStringSubmatch(selector)
	if len(parts) != 4 || signing && strings.HasPrefix(parts[3], "mrk-") {
		return AWSKeySelector{}, false
	}
	return AWSKeySelector{Region: parts[1], Account: parts[2], Key: parts[3]}, true
}

// ParseGCPKeySelector preserves the provider owners' distinct segment profiles.
// Both require a canonical immutable positive int64 CryptoKeyVersion.
func ParseGCPKeySelector(selector string, signing bool) (GCPKeySelector, bool) {
	p := strings.Split(selector, "/")
	if len(p) != 10 || p[0] != "projects" || p[2] != "locations" || p[4] != "keyRings" || p[6] != "cryptoKeys" || p[8] != "cryptoKeyVersions" || !canonicalPositiveInt64(p[9]) {
		return GCPKeySelector{}, false
	}
	if signing {
		for _, i := range []int{1, 5, 7} {
			if !gcpPublicKeySegment.MatchString(p[i]) {
				return GCPKeySelector{}, false
			}
		}
	} else if !GCPEncryptionProjectValid(p[1]) || !gcpEncryptionKeyID.MatchString(p[5]) || !gcpEncryptionKeyID.MatchString(p[7]) {
		return GCPKeySelector{}, false
	}
	return GCPKeySelector{Project: p[1], Region: p[3], KeyRing: p[5], Key: p[7], Version: p[9]}, true
}

func PublicKeySelectorValid(provider Family, selector string, signing bool) bool {
	if keySelectorError(selector) != nil {
		return false
	}
	switch provider {
	case AWS:
		parsed, ok := ParseAWSKeySelector(selector, signing)
		return ok && storeAWSRegion.MatchString(parsed.Region) && !strings.HasPrefix(parsed.Region, "cn-")
	case GCP:
		parsed, ok := ParseGCPKeySelector(selector, signing)
		return ok && storeGCPRegion.MatchString(parsed.Region)
	default:
		return false
	}
}

func GCPEncryptionProjectValid(project string) bool { return gcpEncryptionProject.MatchString(project) }
