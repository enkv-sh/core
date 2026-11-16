package awsprovider

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var _ contract.BoundedEnumerationStore = (*Store)(nil)

type s3ListObservation struct {
	bucket, prefix, cursor string
	page                   contract.ListPageResult
	reason                 contract.Reason
}

func (s *Store) ListPage(ctx context.Context, cursor string) (result contract.ListPageResult) {
	if ctx == nil {
		return contract.ListPageResult{Status: contract.ListPageInvalid, Reason: contract.ReasonConstruction}
	}
	ctx, call := startTelemetry(ctx, telemetry.OpStoreList)
	defer func() { finishListTelemetry(call, result) }()
	if s == nil || !s.descriptor.Valid() || !utf8.ValidString(cursor) {
		return contract.ListPageResult{Status: contract.ListPageInvalid, Reason: contract.ReasonConstruction}
	}
	if len(cursor) > contract.StoreListCursorLength {
		return contract.ListPageResult{Status: contract.ListPageInvalid, Reason: contract.ReasonLimit}
	}
	if ctx.Err() != nil {
		return contract.ListPageResult{Status: contract.ListPageUnavailable, Reason: contract.ReasonLimit}
	}
	list := &s3ListObservation{bucket: s.config.Bucket, prefix: s.config.Prefix + "/" + hex.EncodeToString(s.config.Domain[:]) + "/", cursor: cursor}
	a := &attempt{limit: contract.StoreListResponseBytes, list: list}
	ctx = context.WithValue(ctx, attemptKey{}, a)
	creds, ok := retrieve(ctx, s.config.Credentials)
	if !ok {
		return contract.ListPageResult{Status: contract.ListPageUnavailable, Reason: contract.ReasonAccess}
	}
	input := &s3.ListObjectsV2Input{Bucket: aws.String(s.config.Bucket), Prefix: aws.String(list.prefix),
		MaxKeys: aws.Int32(contract.StoreListPageEntries), EncodingType: "url", ExpectedBucketOwner: aws.String(s.config.ExpectedBucketOwner)}
	if cursor != "" {
		input.ContinuationToken = aws.String(cursor)
	}
	_, err := s.sdk(creds).ListObjectsV2(ctx, input)
	if err == nil && a.status == http.StatusOK && list.page.Status == contract.ListPageOK {
		return list.page
	}
	if list.reason != contract.ReasonNone {
		return contract.ListPageResult{Status: contract.ListPageInvalid, Reason: list.reason}
	}
	if errors.Is(err, errResponse) {
		return contract.ListPageResult{Status: contract.ListPageInvalid, Reason: contract.ReasonMalformed}
	}
	status, _ := serviceError(err)
	reason := contract.ReasonTransport
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		reason = contract.ReasonAccess
	}
	return contract.ListPageResult{Status: contract.ListPageUnavailable, Reason: reason}
}

const s3ListNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

var s3ListDeclaration = regexp.MustCompile(`^<\?xml[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*(?:"1\.0"|'1\.0')(?:[ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*(?:"(?i:UTF-8)"|'(?i:UTF-8)'))?(?:[ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*(?:"(?:yes|no)"|'(?:yes|no)'))?[ \t\r\n]*\?>`)

func listXMLStart(v xml.StartElement) bool {
	if v.Name.Space != s3ListNamespace {
		return false
	}
	seen := make(map[xml.Name]bool, len(v.Attr))
	for _, attr := range v.Attr {
		if seen[attr.Name] || attr.Name.Space != "xmlns" && (attr.Name.Space != "" || attr.Name.Local != "xmlns") {
			return false
		}
		seen[attr.Name] = true
	}
	return true
}

func listXMLScalar(d *xml.Decoder, start xml.StartElement) (string, bool) {
	if !listXMLStart(start) {
		return "", false
	}
	var value strings.Builder
	for {
		token, err := d.Token()
		if err != nil {
			return "", false
		}
		switch v := token.(type) {
		case xml.CharData:
			value.Write(v)
		case xml.Comment:
		case xml.EndElement:
			return value.String(), v.Name == start.Name
		default:
			return "", false
		}
	}
}

func listXMLMetadata(d *xml.Decoder, start xml.StartElement) bool {
	if !listXMLStart(start) {
		return false
	}
	seen := map[string]bool{}
	for {
		token, err := d.Token()
		if err != nil {
			return false
		}
		switch v := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(v)) != 0 {
				return false
			}
		case xml.Comment:
		case xml.StartElement:
			allowed := start.Name.Local == "Owner" && (v.Name.Local == "ID" || v.Name.Local == "DisplayName") ||
				start.Name.Local == "RestoreStatus" && (v.Name.Local == "IsRestoreInProgress" || v.Name.Local == "RestoreExpiryDate")
			if !allowed || seen[v.Name.Local] {
				return false
			}
			seen[v.Name.Local] = true
			if _, ok := listXMLScalar(d, v); !ok {
				return false
			}
		case xml.EndElement:
			return v.Name == start.Name
		default:
			return false
		}
	}
}

func (o *s3ListObservation) content(d *xml.Decoder, start xml.StartElement) (string, bool) {
	if !listXMLStart(start) {
		return "", false
	}
	seen := map[string]bool{}
	var key string
	for {
		token, err := d.Token()
		if err != nil {
			return "", false
		}
		switch v := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(v)) != 0 {
				return "", false
			}
		case xml.Comment:
		case xml.StartElement:
			name := v.Name.Local
			if seen[name] && name != "ChecksumAlgorithm" {
				return "", false
			}
			seen[name] = true
			if name == "Owner" || name == "RestoreStatus" {
				if !listXMLMetadata(d, v) {
					return "", false
				}
				continue
			}
			switch name {
			case "Key", "LastModified", "ETag", "Size", "StorageClass", "ChecksumAlgorithm", "ChecksumType":
			default:
				return "", false
			}
			value, ok := listXMLScalar(d, v)
			if !ok {
				return "", false
			}
			if name == "Key" {
				key, err = url.PathUnescape(value)
				if err != nil || !utf8.ValidString(key) || !strings.HasPrefix(key, o.prefix) {
					return "", false
				}
				if len(key) > contract.StoreListKeyLength {
					o.reason = contract.ReasonLimit
					return "", false
				}
			}
		case xml.EndElement:
			return key, v.Name == start.Name && seen["Key"]
		default:
			return "", false
		}
	}
}

func (o *s3ListObservation) decode(body []byte) bool {
	o.reason = contract.ReasonMalformed
	if !utf8.Valid(body) {
		return false
	}
	if bytes.HasPrefix(body, []byte{0xef, 0xbb, 0xbf}) {
		body = body[3:]
	}
	if bytes.HasPrefix(body, []byte("<?xml")) {
		declaration := s3ListDeclaration.FindIndex(body)
		if declaration == nil {
			return false
		}
		body = body[declaration[1]:]
	}
	d := xml.NewDecoder(bytes.NewReader(body))
	var root xml.StartElement
	for {
		token, err := d.Token()
		if err != nil {
			return false
		}
		switch v := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(v)) != 0 {
				return false
			}
		case xml.Comment:
		case xml.StartElement:
			root = v
		default:
			return false
		}
		if root.Name.Local != "" {
			break
		}
	}
	if root.Name.Local != "ListBucketResult" || !listXMLStart(root) {
		return false
	}
	fields := map[string]string{}
	seenKeys := map[string]bool{}
	keys := make([]string, 0, contract.StoreListPageEntries)
	for {
		token, err := d.Token()
		if err != nil {
			return false
		}
		switch v := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(v)) != 0 {
				return false
			}
		case xml.Comment:
		case xml.StartElement:
			name := v.Name.Local
			if name == "Contents" {
				if len(keys) == contract.StoreListPageEntries {
					o.reason = contract.ReasonLimit
					return false
				}
				key, ok := o.content(d, v)
				if !ok || seenKeys[key] {
					return false
				}
				seenKeys[key] = true
				keys = append(keys, key)
				continue
			}
			if _, duplicate := fields[name]; duplicate {
				return false
			}
			switch name {
			case "Name", "Prefix", "KeyCount", "MaxKeys", "EncodingType", "IsTruncated", "ContinuationToken", "NextContinuationToken":
			default:
				return false
			}
			value, ok := listXMLScalar(d, v)
			if !ok {
				return false
			}
			fields[name] = value
		case xml.EndElement:
			if v.Name != root.Name {
				return false
			}
			for {
				token, err = d.Token()
				if err == io.EOF {
					return o.complete(fields, keys)
				}
				if err != nil {
					return false
				}
				switch trailing := token.(type) {
				case xml.CharData:
					if len(bytes.TrimSpace(trailing)) != 0 {
						return false
					}
				case xml.Comment:
				default:
					return false
				}
			}
		default:
			return false
		}
	}
}

func (o *s3ListObservation) complete(fields map[string]string, keys []string) bool {
	for _, required := range []string{"Name", "Prefix", "KeyCount", "MaxKeys", "EncodingType", "IsTruncated"} {
		if _, ok := fields[required]; !ok {
			return false
		}
	}
	prefix, err := url.PathUnescape(fields["Prefix"])
	count, countErr := strconv.ParseUint(strings.TrimSpace(fields["KeyCount"]), 10, 32)
	maximum, maximumErr := strconv.ParseUint(strings.TrimSpace(fields["MaxKeys"]), 10, 32)
	if err != nil || fields["Name"] != o.bucket || prefix != o.prefix || fields["EncodingType"] != "url" ||
		fields["ContinuationToken"] != o.cursor || countErr != nil || count != uint64(len(keys)) || maximumErr != nil || maximum != contract.StoreListPageEntries {
		return false
	}
	next := fields["NextContinuationToken"]
	if len(next) > contract.StoreListCursorLength {
		o.reason = contract.ReasonLimit
		return false
	}
	if fields["IsTruncated"] != "true" && fields["IsTruncated"] != "false" || (fields["IsTruncated"] == "true") != (next != "") {
		return false
	}
	o.reason = contract.ReasonNone
	o.page = contract.ListPageResult{Status: contract.ListPageOK, Keys: keys, NextCursor: next}
	return true
}

func finishListTelemetry(call *telemetry.Call, result contract.ListPageResult) {
	if call == nil {
		return
	}
	if result.Reason != contract.ReasonNone {
		call.ReturnDetails(providerReasonDetails(result.Reason))
	}
	length := len(result.NextCursor)
	for _, key := range result.Keys {
		length += len(key)
	}
	call.OutputBytes(int64(length))
	status := telemetry.ResultUnknown
	switch result.Status {
	case contract.ListPageOK:
		status = telemetry.ResultReadOK
	case contract.ListPageUnavailable:
		status = telemetry.ResultReadUnavailable
	case contract.ListPageInvalid:
		status = telemetry.ResultReadInvalid
	}
	call.Finish(status)
}
