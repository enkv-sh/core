package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	awsprovider "enkv.sh/providers/aws"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type stockS3VersionID struct{ key, version string }
type stockS3Version struct {
	stockS3VersionID
	token          contract.Token
	length         uint32
	marker, latest bool
}

func stockS3ValidVersion(v string) bool {
	return v != "" && v != "null" && len(v) <= 1024 && strings.IndexFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

// An exact-key Reader lookup and the Cleanup actor's whole-run listing have
// different scopes. Both have to consume a complete, bounded response.
func stockS3ListVersions(ctx context.Context, setup *awsSetup, prefix string, exact bool) ([]stockS3Version, error) {
	runPrefix := strings.TrimSuffix(setup.head, "/HEAD")
	if exact && !setup.validKey(prefix) || !exact && prefix != runPrefix+"/" {
		return nil, errInventory
	}
	var versions []stockS3Version
	seen := make(map[stockS3VersionID]bool)
	latest := make(map[string]int)
	cursors := make(map[stockS3VersionID]bool)
	var cursor stockS3VersionID
	for range operatorPrefixPages {
		request := &s3.ListObjectVersionsInput{Bucket: aws.String(setup.settings.Bucket), ExpectedBucketOwner: aws.String(setup.settings.Account),
			Prefix: aws.String(prefix), MaxKeys: aws.Int32(operatorPrefixPageKeys)}
		if cursor.key != "" {
			request.KeyMarker, request.VersionIdMarker = aws.String(cursor.key), aws.String(cursor.version)
		}
		next, cancel, credentials, err := setup.begin(ctx, "s3", telemetry.OpSetupRead)
		if err != nil {
			cancel()
			return nil, err
		}
		op := awsSetupOperationFrom(next)
		op.bodyLimit = operatorPrefixBodyLimit
		out, err := setup.s3(credentials).ListObjectVersions(next, request)
		cancel()
		if err != nil {
			return nil, err
		}
		if out == nil || op.status.Load() != http.StatusOK || aws.ToString(out.Name) != setup.settings.Bucket ||
			aws.ToString(out.Prefix) != prefix || out.MaxKeys == nil || *out.MaxKeys != operatorPrefixPageKeys ||
			out.IsTruncated == nil || out.Delimiter != nil || out.EncodingType != "" || len(out.CommonPrefixes) != 0 ||
			aws.ToString(out.KeyMarker) != cursor.key || aws.ToString(out.VersionIdMarker) != cursor.version {
			return nil, errInventory
		}
		count := len(out.Versions) + len(out.DeleteMarkers)
		if count > operatorPrefixPageKeys || len(versions)+count > operatorPrefixObjects {
			return nil, errRunLimit
		}
		add := func(key, version *string, current *bool, size *int64, etag *string, marker bool) error {
			id := stockS3VersionID{aws.ToString(key), aws.ToString(version)}
			if current == nil || !stockS3ValidVersion(id.version) || !setup.validKey(id.key) || !strings.HasPrefix(id.key, prefix) ||
				exact && id.key != prefix || seen[id] {
				return errInventory
			}
			item := stockS3Version{stockS3VersionID: id, marker: marker, latest: *current}
			if !marker {
				item.token = contract.Token{Family: contract.AWS, Value: aws.ToString(etag)}
				if size == nil || *size <= 0 || *size > int64(publicObjectKeyLimit(runPrefix, id.key)) || !item.token.Valid() {
					return errInventory
				}
				item.length = uint32(*size)
			}
			seen[id] = true
			n := latest[id.key]
			if *current {
				n++
			}
			latest[id.key] = n
			versions = append(versions, item)
			return nil
		}
		for _, item := range out.Versions {
			if err := add(item.Key, item.VersionId, item.IsLatest, item.Size, item.ETag, false); err != nil {
				return nil, err
			}
		}
		for _, item := range out.DeleteMarkers {
			if err := add(item.Key, item.VersionId, item.IsLatest, nil, nil, true); err != nil {
				return nil, err
			}
		}
		if !*out.IsTruncated {
			if out.NextKeyMarker != nil || out.NextVersionIdMarker != nil {
				return nil, errInventory
			}
			for _, n := range latest {
				if n != 1 {
					return nil, errInventory
				}
			}
			return versions, nil
		}
		cursor = stockS3VersionID{aws.ToString(out.NextKeyMarker), aws.ToString(out.NextVersionIdMarker)}
		if count == 0 || !setup.validKey(cursor.key) || !strings.HasPrefix(cursor.key, prefix) || exact && cursor.key != prefix ||
			!stockS3ValidVersion(cursor.version) || !seen[cursor] || cursors[cursor] {
			return nil, errInventory
		}
		cursors[cursor] = true
	}
	return nil, errRunLimit
}

func stockS3ReadVersion(ctx context.Context, setup *awsSetup, item stockS3Version) (contract.ReadResult, error) {
	if item.marker || !stockS3ValidVersion(item.version) || !setup.validKey(item.key) || item.length == 0 ||
		item.length > publicObjectKeyLimit(strings.TrimSuffix(setup.head, "/HEAD"), item.key) || !item.token.Valid() || item.token.Family != contract.AWS {
		return contract.ReadResult{}, errInventory
	}
	next, cancel, credentials, err := setup.begin(ctx, "s3", telemetry.OpSetupRead)
	defer cancel()
	if err != nil {
		return contract.ReadResult{}, err
	}
	op := awsSetupOperationFrom(next)
	op.bodyLimit = int64(item.length)
	out, err := setup.s3(credentials).GetObject(next, &s3.GetObjectInput{Bucket: aws.String(setup.settings.Bucket),
		ExpectedBucketOwner: aws.String(setup.settings.Account), Key: aws.String(item.key), VersionId: aws.String(item.version)})
	if err != nil {
		return contract.ReadResult{}, err
	}
	if out == nil || out.Body == nil {
		return contract.ReadResult{}, errInventory
	}
	if op.status.Load() != http.StatusOK || aws.ToString(out.VersionId) != item.version || aws.ToBool(out.DeleteMarker) ||
		aws.ToString(out.ETag) != item.token.Value || out.ContentRange != nil || out.ContentLength == nil || *out.ContentLength != int64(item.length) {
		return contract.ReadResult{}, errors.Join(errInventory, out.Body.Close())
	}
	body, readErr := io.ReadAll(io.LimitReader(out.Body, int64(item.length)+1))
	if err := errors.Join(readErr, out.Body.Close()); err != nil || len(body) != int(item.length) {
		clear(body)
		return contract.ReadResult{}, errors.Join(errInventory, err)
	}
	return contract.ReadResult{Status: contract.ReadOK, Token: item.token, Body: body}, nil
}

// A stored version locates bytes. Only a unique match to the authenticated
// digest supplies evidence, even if multiple versions have the same ETag.
func stockS3FindOriginal(ctx context.Context, setup *awsSetup, key string, digest contract.ID, length uint32) (contract.ReadResult, error) {
	if digest.IsZero() {
		return contract.ReadResult{}, errInventory
	}
	items, err := stockS3ListVersions(ctx, setup, key, true)
	if err != nil {
		return contract.ReadResult{}, err
	}
	var result contract.ReadResult
	for _, item := range items {
		if item.marker || length != 0 && length != item.length {
			continue
		}
		read, err := stockS3ReadVersion(ctx, setup, item)
		if err != nil {
			clear(result.Body)
			return contract.ReadResult{}, err
		}
		if contract.Hash(read.Body) != digest {
			clear(read.Body)
			continue
		}
		if result.Status == contract.ReadOK {
			clear(read.Body)
			clear(result.Body)
			return contract.ReadResult{}, errInventory
		}
		result = read
	}
	if result.Status != contract.ReadOK {
		return contract.ReadResult{}, errInventory
	}
	return result, nil
}

func openStockVersionReader(ctx context.Context, input liveRunInput, directory string, budget *runBudget, domain contract.ID) (stockOriginalReader, error) {
	f, err := stockAWSFixture(input)
	if err != nil || f.Purpose != records.StockRetirementProofPurpose || budget == nil || domain.IsZero() {
		return nil, errInventory
	}
	restore, err := publicSDKEnvironment(input, "reader", directory)
	if err != nil {
		return nil, err
	}
	defer restore()
	credentials, err := awsprovider.LoadDefaultCredentials(ctx, input.Settings.Region)
	if err != nil {
		return nil, err
	}
	setup := newAWSSetup(input.Settings, input.Prefix, domain, nil, credentials, &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second})
	setup.client.Transport = stockAWSBudgetTransport{setup.transport}
	return func(ctx context.Context, key string, digest contract.ID, length uint32) (contract.ReadResult, error) {
		if key != setup.head && (!strings.HasPrefix(key, setup.objects+"result/") || length == 0) {
			return contract.ReadResult{}, errInventory
		}
		return stockS3FindOriginal(context.WithValue(ctx, stockAWSBudgetKey{}, budget), setup, key, digest, length)
	}, nil
}
