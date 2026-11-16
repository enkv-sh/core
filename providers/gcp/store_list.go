package gcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"google.golang.org/api/googleapi"
)

var _ contract.BoundedEnumerationStore = (*Store)(nil)

type gcsListObservation struct {
	prefix string
	page   contract.ListPageResult
	reason contract.Reason
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
	ctx, ok := s.config.Client.begin(ctx, s.host, contract.StoreListResponseBytes)
	if !ok {
		return contract.ListPageResult{Status: contract.ListPageUnavailable, Reason: contract.ReasonAccess}
	}
	op := ctx.Value(operationKey{}).(*operation)
	list := &gcsListObservation{prefix: s.config.Prefix + "/" + hex.EncodeToString(s.config.Domain[:]) + "/"}
	op.list = list
	request := s.apiService.Objects.List(s.config.Bucket).Prefix(list.prefix).MaxResults(contract.StoreListPageEntries).
		Fields("items(name),nextPageToken").Context(ctx)
	if cursor != "" {
		request.PageToken(cursor)
	}
	_, err := request.Do()
	if err == nil && op.status == http.StatusOK && list.page.Status == contract.ListPageOK {
		return list.page
	}
	if list.reason != contract.ReasonNone {
		return contract.ListPageResult{Status: contract.ListPageInvalid, Reason: list.reason}
	}
	if errors.Is(err, errMalformedResponse) {
		return contract.ListPageResult{Status: contract.ListPageInvalid, Reason: contract.ReasonMalformed}
	}
	reason := contract.ReasonTransport
	var api *googleapi.Error
	if errors.As(err, &api) && (api.Code == http.StatusUnauthorized || api.Code == http.StatusForbidden) {
		reason = contract.ReasonAccess
	}
	return contract.ListPageResult{Status: contract.ListPageUnavailable, Reason: reason}
}

// encoding/json replaces unpaired surrogate escapes. Reject them before
// decoding so an observed object name or opaque cursor is never changed.
func listJSONUnicodeValid(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	hexUnit := func(at int) (uint16, bool) {
		if at+4 > len(body) {
			return 0, false
		}
		var unit uint16
		for _, b := range body[at : at+4] {
			unit <<= 4
			switch {
			case b >= '0' && b <= '9':
				unit |= uint16(b - '0')
			case b >= 'a' && b <= 'f':
				unit |= uint16(b-'a') + 10
			case b >= 'A' && b <= 'F':
				unit |= uint16(b-'A') + 10
			default:
				return 0, false
			}
		}
		return unit, true
	}
	for i := 0; i < len(body); i++ {
		if body[i] != '"' {
			continue
		}
		for i++; i < len(body) && body[i] != '"'; i++ {
			if body[i] != '\\' {
				continue
			}
			i++
			if i >= len(body) {
				return false
			}
			if body[i] != 'u' {
				continue
			}
			unit, ok := hexUnit(i + 1)
			if !ok || unit >= 0xdc00 && unit <= 0xdfff {
				return false
			}
			i += 4
			if unit < 0xd800 || unit > 0xdbff {
				continue
			}
			if i+6 >= len(body) || body[i+1] != '\\' || body[i+2] != 'u' {
				return false
			}
			low, ok := hexUnit(i + 3)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func (o *gcsListObservation) decode(body []byte) bool {
	o.reason = contract.ReasonMalformed
	if !listJSONUnicodeValid(body) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	keys := make([]string, 0, contract.StoreListPageEntries)
	var next string
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		switch name {
		case "items":
			start, err := d.Token()
			if err != nil || start != json.Delim('[') {
				return false
			}
			unique := map[string]bool{}
			for d.More() {
				if len(keys) == contract.StoreListPageEntries {
					o.reason = contract.ReasonLimit
					return false
				}
				if start, err := d.Token(); err != nil || start != json.Delim('{') {
					return false
				}
				if token, err := d.Token(); err != nil || token != "name" {
					return false
				}
				var key string
				if err := d.Decode(&key); err != nil || !strings.HasPrefix(key, o.prefix) || unique[key] {
					return false
				}
				if len(key) > contract.StoreListKeyLength {
					o.reason = contract.ReasonLimit
					return false
				}
				if end, err := d.Token(); err != nil || end != json.Delim('}') {
					return false
				}
				unique[key] = true
				keys = append(keys, key)
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return false
			}
		case "nextPageToken":
			token, err := d.Token()
			var ok bool
			if next, ok = token.(string); err != nil || !ok {
				return false
			}
			if len(next) > contract.StoreListCursorLength {
				o.reason = contract.ReasonLimit
				return false
			}
		default:
			return false
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
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
