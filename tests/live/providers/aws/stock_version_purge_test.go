package core

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// The caller qualifies every data version and its released-result markers,
// settles external effects and joins all participants before passing this set.
func stockS3PurgeVersions(ctx context.Context, setup *awsSetup, prefix string, frozen []stockS3Version) (bool, error) {
	if ctx == nil || setup == nil || prefix == "" || setup.head != prefix+"/HEAD" || len(frozen) == 0 || len(frozen) > operatorPrefixObjects {
		return false, errInventory
	}
	remaining := make(map[stockS3VersionID]stockS3Version, len(frozen))
	var head stockS3Version
	var data, markers []stockS3Version
	for _, item := range frozen {
		if _, exists := remaining[item.stockS3VersionID]; exists || !setup.validKey(item.key) || !strings.HasPrefix(item.key, prefix+"/") || !stockS3ValidVersion(item.version) {
			return false, errInventory
		}
		if item.marker {
			if item.key == setup.head || !item.latest || item.length != 0 || item.token != (contract.Token{}) {
				return false, errInventory
			}
			markers = append(markers, item)
		} else {
			if item.length == 0 || item.length > publicObjectKeyLimit(prefix, item.key) || item.token.Family != contract.AWS || !item.token.Valid() {
				return false, errInventory
			}
			if item.key == setup.head && item.latest {
				head = item
			} else {
				data = append(data, item)
			}
		}
		remaining[item.stockS3VersionID] = item
	}
	if head.key == "" {
		return false, errInventory
	}
	less := func(a, b stockS3Version) int {
		if n := strings.Compare(a.key, b.key); n != 0 {
			return n
		}
		return strings.Compare(a.version, b.version)
	}
	slices.SortFunc(data, less)
	slices.SortFunc(markers, less)
	check := func() error {
		listed, err := stockS3ListVersions(ctx, setup, prefix+"/", false)
		if err != nil {
			return err
		}
		if len(listed) != len(remaining) {
			return errInventory
		}
		for _, item := range listed {
			if want, ok := remaining[item.stockS3VersionID]; !ok || item != want {
				return errInventory
			}
		}
		return nil
	}
	if err := check(); err != nil {
		return false, err
	}
	for _, stage := range [][]stockS3Version{data, markers, {head}} {
		for _, item := range stage {
			if err := stockS3DeleteVersion(ctx, setup, item); err != nil {
				return false, err
			}
			delete(remaining, item.stockS3VersionID)
		}
		if err := check(); err != nil {
			return false, err
		}
	}
	return true, nil
}

func stockS3DeleteVersion(ctx context.Context, setup *awsSetup, item stockS3Version) (resultErr error) {
	call := telemetry.Start(ctx, telemetry.ProviderAWS, telemetry.OpSetupDelete)
	defer func() { finishSetupCall(call, resultErr) }()
	next, cancel, credentials, err := setup.begin(ctx, "s3", telemetry.OpSetupDelete)
	defer cancel()
	if err != nil {
		failure := awsSetupFailureFor(next, errAWSDelete, "authentication", "authentication_refused", err)
		failure.Operation = "object_cleanup"
		return failure
	}
	// The qualified version ID identifies immutable data. S3 evaluates If-Match
	// on the current object, which can be a different version or a delete marker.
	request := &s3.DeleteObjectInput{Bucket: aws.String(setup.settings.Bucket), ExpectedBucketOwner: aws.String(setup.settings.Account),
		Key: aws.String(item.key), VersionId: aws.String(item.version)}
	out, err := setup.s3(credentials).DeleteObject(next, request)
	if err != nil {
		return awsSetupFailureFor(next, errAWSDelete, "conditional_delete", "transport", err)
	}
	op := awsSetupOperationFrom(next)
	if out == nil || op.status.Load() != http.StatusNoContent || aws.ToString(out.VersionId) != item.version || aws.ToBool(out.DeleteMarker) != item.marker {
		return awsSetupFailureFor(next, errAWSDelete, "acknowledgement", "invalid_acknowledgement", nil)
	}
	return nil
}
