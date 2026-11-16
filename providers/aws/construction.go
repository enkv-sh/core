// Package awsprovider implements the admitted regional S3 and KMS constructions.
// It makes no state-selection or Product-outcome decisions.
package awsprovider

import (
	"encoding/binary"
	"errors"
	"regexp"
	"strings"
	"time"

	"enkv.sh/core/contract"
	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	maximumRegionLength        = 32
	maximumConstructionTimeout = 2 * time.Minute
)

var ErrConstruction = errors.New("unsupported AWS construction")
var regionPattern = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[1-9][0-9]*$`)

func validCommon(region string, route contract.ID, creds aws.CredentialsProvider, timeout time.Duration) bool {
	return len(region) <= maximumRegionLength && regionPattern.MatchString(region) && !strings.HasPrefix(region, "cn-") && !route.IsZero() && creds != nil && timeout > 0 && timeout <= maximumConstructionTimeout
}

func identity(fields ...string) contract.ID {
	b := []byte{}
	for _, v := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		b = append(b, v...)
	}
	return contract.Hash(b)
}
