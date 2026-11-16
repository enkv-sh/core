package contract

import (
	"bytes"
	"regexp"
	"strings"
)

const (
	StoreConstructionProfile    uint16 = 2
	MaxStoreConfigurationLength        = 4 << 10
	storeConfigurationPrefix           = "ENKV/STORE-CONFIGURATION/v1\x00"
)

var (
	storeAWSRegion  = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[1-9][0-9]*$`)
	storeGCPRegion  = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+[1-9][0-9]*$`)
	storeAWSBucket  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	storeGCPBucket  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,220}[a-z0-9]$`)
	storeAWSPrefix  = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)
	storeGCPSegment = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	storeAWSOwner   = regexp.MustCompile(`^[0-9]{12}$`)
)

// StoreConfiguration is selected by its hash in HEAD and CurrentControl.
// It contains only durable provider construction facts, never credential routes.
type StoreConfiguration struct {
	Provider            Family
	ConstructionProfile uint16
	DomainID            ID
	Region, Bucket      string
	PrefixBeforeHEAD    string
	ExpectedOwner       string
}

// StoreLocation is independently supplied candidate construction data. It is
// neither an authenticated StoreConfiguration nor a persistent Store identity.
type StoreLocation struct {
	Provider         Family
	Region, Bucket   string
	PrefixBeforeHEAD string
	ExpectedOwner    string
}

func storeASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

func StorePrefixValid(provider Family, prefix string) bool {
	if len(prefix) == 0 || len(prefix) > MaxStorePrefixLength || !storeASCII(prefix) {
		return false
	}
	switch provider {
	case AWS:
		return storeAWSPrefix.MatchString(prefix)
	case GCP:
		for _, segment := range strings.Split(prefix, "/") {
			if !storeGCPSegment.MatchString(segment) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// StoreLocationValid is the exact location grammar shared by initial public
// readers and selected configurations. AWS may omit its owner only before the
// authenticated helper supplies it; GCP never carries an owner.
func StoreRegionValid(provider Family, region string) bool {
	if len(region) == 0 || len(region) > 64 || !storeASCII(region) {
		return false
	}
	switch provider {
	case AWS:
		return len(region) <= 32 && storeAWSRegion.MatchString(region) && !strings.HasPrefix(region, "cn-")
	case GCP:
		return storeGCPRegion.MatchString(region)
	default:
		return false
	}
}

func StoreBucketValid(provider Family, bucket string) bool {
	if !storeASCII(bucket) {
		return false
	}
	switch provider {
	case AWS:
		if !storeAWSBucket.MatchString(bucket) {
			return false
		}
		for _, reserved := range []string{"xn--", "sthree-", "amzn-s3-demo-"} {
			if strings.HasPrefix(bucket, reserved) {
				return false
			}
		}
		for _, suffix := range []string{"-s3alias", "--ol-s3", "--x-s3", "--table-s3", "-an"} {
			if strings.HasSuffix(bucket, suffix) {
				return false
			}
		}
		return true
	case GCP:
		return storeGCPBucket.MatchString(bucket) && !strings.Contains(bucket, "..")
	default:
		return false
	}
}

func StoreExpectedOwnerValid(provider Family, owner string) bool {
	if !storeASCII(owner) {
		return false
	}
	switch provider {
	case AWS:
		return owner == "" || storeAWSOwner.MatchString(owner)
	case GCP:
		return owner == ""
	default:
		return false
	}
}

func StoreLocationValid(v StoreLocation) bool {
	return v.Provider.Valid() && StoreRegionValid(v.Provider, v.Region) && StoreBucketValid(v.Provider, v.Bucket) && StorePrefixValid(v.Provider, v.PrefixBeforeHEAD) && StoreExpectedOwnerValid(v.Provider, v.ExpectedOwner)
}

func StoreConfigurationValid(v StoreConfiguration) bool {
	if v.ConstructionProfile != StoreConstructionProfile || v.DomainID.IsZero() ||
		!StoreLocationValid(StoreLocation{Provider: v.Provider, Region: v.Region, Bucket: v.Bucket, PrefixBeforeHEAD: v.PrefixBeforeHEAD, ExpectedOwner: v.ExpectedOwner}) {
		return false
	}
	switch v.Provider {
	case AWS:
		return v.ExpectedOwner != ""
	case GCP:
		return true
	default:
		return false
	}
}

func EncodeStoreConfiguration(v StoreConfiguration) ([]byte, error) {
	if !StoreConfigurationValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 256)}
	w.raw([]byte(storeConfigurationPrefix))
	w.u8(uint8(v.Provider))
	w.u16(v.ConstructionProfile)
	w.id(v.DomainID)
	for _, field := range []string{v.Region, v.Bucket, v.PrefixBeforeHEAD, v.ExpectedOwner} {
		w.blob([]byte(field))
	}
	if len(w.b) > MaxStoreConfigurationLength {
		return nil, ErrRecordCapacity
	}
	return w.b, nil
}

func DecodeStoreConfiguration(body []byte) (StoreConfiguration, error) {
	if len(body) > MaxStoreConfigurationLength {
		return StoreConfiguration{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	if !bytes.Equal(r.take(len(storeConfigurationPrefix)), []byte(storeConfigurationPrefix)) {
		return StoreConfiguration{}, ErrRecord
	}
	v := StoreConfiguration{Provider: Family(r.u8()), ConstructionProfile: r.u16(), DomainID: r.id()}
	v.Region = string(r.blob(64))
	v.Bucket = string(r.blob(222))
	v.PrefixBeforeHEAD = string(r.blob(MaxStorePrefixLength))
	v.ExpectedOwner = string(r.blob(12))
	if r.end() != nil || !StoreConfigurationValid(v) {
		return StoreConfiguration{}, ErrRecord
	}
	return v, nil
}

func StoreConfigurationID(v StoreConfiguration) (ID, error) {
	body, err := EncodeStoreConfiguration(v)
	if err != nil {
		return ID{}, err
	}
	return Hash(body), nil
}

func StoreConfigurationKey(v StoreConfiguration) (string, error) {
	id, err := StoreConfigurationID(v)
	if err != nil {
		return "", err
	}
	return StoreConfigurationKeyForID(v.Provider, v.PrefixBeforeHEAD, v.DomainID, id)
}

// StoreConfigurationKeyForID derives the one physical helper key from a
// supplied location and candidate IDs. It does not authenticate either ID or
// admit the helper body as a StoreConfiguration.
func StoreConfigurationKeyForID(provider Family, prefix string, domain, storeID ID) (string, error) {
	if !StorePrefixValid(provider, prefix) || domain.IsZero() || storeID.IsZero() {
		return "", ErrRecord
	}
	return StoreObjectKey(prefix, domain, StoreObjectIdentity{Namespace: StoreConfigurationObject, ObjectID: storeID})
}
