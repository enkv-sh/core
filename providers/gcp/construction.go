package gcp

import (
	"encoding/binary"
	"errors"
	"regexp"
	"strings"

	"enkv.sh/core/contract"
)

const maximumCredentialRouteLength = 256

const (
	SigningAlgorithm = "EC_SIGN_P256_SHA256"
	SigningPurpose   = "ASYMMETRIC_SIGN"
)

// StorageEndpoint returns the regional JSON API endpoint. Constructors
// independently validate the region and the complete admitted configuration.
func StorageEndpoint(region string) string {
	return "https://storage." + region + ".rep.googleapis.com/storage/v1/"
}

// KMSEndpoint returns the regional Cloud KMS endpoint. It does not validate a
// key, credential route or construction.
func KMSEndpoint(region string) string {
	return "https://" + region + "-cloudkms.googleapis.com/"
}

var ErrConstruction = errors.New("GCP construction refused")

var regionPattern = regexp.MustCompile(`^[a-z]+(?:-[a-z]+)+[1-9][0-9]*$`)

// CredentialRouteValid checks the routing label accepted by GCP constructors.
func CredentialRouteValid(s string) bool {
	return len(s) > 0 && len(s) <= maximumCredentialRouteLength && !strings.ContainsAny(s, "\x00\r\n\t")
}

func binding(parts ...string) contract.ID {
	return bindingWithPurpose("ENKV/GCP-CONSTRUCTION/v1\x00", parts...)
}

func storeBinding(parts ...string) contract.ID {
	return bindingWithPurpose("ENKV/GCP-CONSTRUCTION/v2\x00", parts...)
}

func bindingWithPurpose(purpose string, parts ...string) contract.ID {
	b := []byte(purpose)
	for _, part := range parts {
		b = binary.BigEndian.AppendUint32(b, uint32(len(part)))
		b = append(b, part...)
	}
	return contract.Hash(b)
}
