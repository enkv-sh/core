package nativeprocess

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"enkv.sh/core/contract"
)

// capacityStoreRequest extends the existing offline responder only when the
// test has supplied an independent exact domain prefix and bounded key page.
// The parent responder holds its mutex throughout this synchronous call.
func (s *workflowServer) capacityStoreRequest(w http.ResponseWriter, r *http.Request, phase string, c *workflowCounts, body []byte) bool {
	awsList := s.family == "aws" && r.Method == http.MethodGet && r.URL.Path == "/fixture-bucket" && r.URL.Query().Get("list-type") == "2"
	gcpList := s.family == "gcp" && r.Method == http.MethodGet && r.URL.Path == "/storage/v1/b/fixture-bucket/o"
	if !awsList && !gcpList && r.Method != http.MethodDelete {
		return false
	}
	if s.gcListPrefix == "" || len(body) != 0 || len(s.gcListKeys) > contract.StoreListPageEntries || (phase != "reader" && phase != "apply") {
		s.fail(w, "capacity-store-authority")
		return true
	}
	q := r.URL.Query()
	if awsList || gcpList {
		if awsList && (r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" ||
			!workflowGCPQuery(q, map[string]string{"list-type": "2", "max-keys": "256", "encoding-type": "url", "prefix": s.gcListPrefix}) ||
			q.Get("prefix") != s.gcListPrefix || q.Get("max-keys") != "256" || q.Get("encoding-type") != "url") ||
			gcpList && (!workflowGCPQuery(q, map[string]string{"maxResults": "256", "fields": "items(name),nextPageToken", "prefix": s.gcListPrefix, "alt": "json", "prettyPrint": "false"}) ||
				q.Get("prefix") != s.gcListPrefix || q.Get("maxResults") != "256" || q.Get("fields") != "items(name),nextPageToken") {
			s.fail(w, "capacity-list-shape")
			return true
		}
		for _, key := range s.gcListKeys {
			if !strings.HasPrefix(key, s.gcListPrefix) || !workflowStoreKey(s.prefix, key, phase) {
				s.fail(w, "capacity-list-fixture-scope")
				return true
			}
		}
		c.lists++
		if gcpList {
			items := make([]map[string]string, len(s.gcListKeys))
			for i, key := range s.gcListKeys {
				items[i] = map[string]string{"name": key}
			}
			s.writeJSON(w, 200, map[string]any{"items": items})
			return true
		}
		var reply strings.Builder
		fmt.Fprintf(&reply, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixture-bucket</Name><Prefix>%s</Prefix><KeyCount>%d</KeyCount><MaxKeys>256</MaxKeys><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated>`, url.PathEscape(s.gcListPrefix), len(s.gcListKeys))
		for _, key := range s.gcListKeys {
			fmt.Fprintf(&reply, "<Contents><Key>%s</Key></Contents>", url.PathEscape(key))
		}
		reply.WriteString("</ListBucketResult>")
		encoded := []byte(reply.String())
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
		w.WriteHeader(200)
		s.writeResponse(w, encoded)
		return true
	}
	key, ok := strings.CutPrefix(r.URL.Path, "/fixture-bucket/")
	condition := r.Header.Get("If-Match")
	if s.family == "gcp" {
		key, ok = strings.CutPrefix(r.URL.Path, "/storage/v1/b/fixture-bucket/o/")
		condition = q.Get("ifGenerationMatch")
		if !workflowGCPQuery(q, map[string]string{"ifGenerationMatch": condition, "alt": "json", "prettyPrint": "false"}) {
			ok = false
		}
	} else if r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" ||
		!workflowGCPQuery(q, map[string]string{"x-id": "DeleteObject"}) {
		ok = false
	}
	if !ok || phase != "apply" || !strings.HasPrefix(key, s.gcListPrefix) || !workflowStoreKey(s.prefix, key, phase) || condition == "" || r.Header.Get("If-None-Match") != "" {
		s.fail(w, "capacity-delete-shape")
		return true
	}
	c.deletes++
	object, present := s.objects[key]
	if !present || object.etag != condition {
		c.conditions++
		if s.family == "aws" {
			s.awsError(w, 412, "PreconditionFailed")
		} else {
			s.gcpError(w, 412, "conditionNotMet")
		}
		return true
	}
	if s.gcUnknownDelete {
		if s.family == "aws" {
			s.awsError(w, 503, "ServiceUnavailable")
		} else {
			s.gcpError(w, 503, "backendError")
		}
		return true
	}
	delete(s.objects, key)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
	return true
}
