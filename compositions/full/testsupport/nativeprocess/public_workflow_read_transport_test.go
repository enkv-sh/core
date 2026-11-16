package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeReadTransportDiagnostic(t *testing.T) {
	_, helper := workflowBuildExecutables(t, true)
	const domain = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const object = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	for _, condition := range []string{"object", "head", "head-maximum", "head-overflow", "missing", "raw-not-found", "denied", "transport", "credential-failure"} {
		t.Run("aws/"+condition, func(t *testing.T) {
			s := newWorkflowServer(t, "aws", false)
			s.childRequestLimit = 1
			operation, key := "aws-candidate-head", s.prefix+"/HEAD"
			s.childBytesLimit = 65537
			if condition == "object" {
				operation, key = "aws-store-object", s.prefix+"/"+domain+"/support/1/"+object
				s.childBytesLimit = (2 << 20) + 1
			}
			requests := 0
			s.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				s.mu.Lock()
				defer s.mu.Unlock()
				requests++
				if requests != 1 || r.Method != http.MethodGet || r.Host != "s3.us-east-1.amazonaws.com" || r.URL.Path != "/fixture-bucket/"+key || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" || r.ContentLength != 0 {
					t.Error("diagnostic changed its exact GET, owner, or send count")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				body := []byte("private-response-must-be-cleared")
				status := http.StatusOK
				switch condition {
				case "head-maximum", "head-overflow":
					size := 65536
					if condition == "head-overflow" {
						size++
					}
					body = bytes.Repeat([]byte{'x'}, size)
				case "missing":
					status, body = http.StatusNotFound, []byte("<Error><Code>NoSuchKey</Code></Error>")
				case "raw-not-found":
					status, body = http.StatusNotFound, []byte("<Error><Code>UnknownResource</Code></Error>")
				case "denied":
					status, body = http.StatusForbidden, []byte("<Error><Code>AccessDenied</Code></Error>")
				case "transport":
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error("controlled connection loss could not start", err)
						return
					}
					if err := connection.Close(); err != nil {
						t.Error("controlled connection did not close", err)
					}
					return
				}
				defer clear(body)
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				w.Header().Set("ETag", `"fixture-token"`)
				w.WriteHeader(status)
				if n, err := w.Write(body); err != nil || n != len(body) {
					t.Error("controlled diagnostic response did not complete")
				}
			})
			args := []string{"--probe-read-transport", "--operation", operation, "--region", "us-east-1", "--bucket", "fixture-bucket", "--prefix", s.prefix, "--expected-owner", "123456789012"}
			if operation == "aws-store-object" {
				args = append(args, "--domain", domain, "--key", key)
			}
			var environment []string
			if condition == "credential-failure" {
				environment = []string{"AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_SESSION_TOKEN="}
			}
			child := workflowRunEnvironment(t, s, helper, "reader", observer.Policy{NoKMS: true}, nil, environment, args...)
			wantStatus, wantReason := contract.ReadOK, contract.ReasonNone
			switch condition {
			case "head-overflow":
				wantStatus, wantReason = contract.ReadInvalid, contract.ReasonMalformed
			case "missing":
				wantStatus = contract.ReadMissing
			case "raw-not-found", "transport":
				wantStatus, wantReason = contract.ReadUnavailable, contract.ReasonTransport
			case "denied", "credential-failure":
				wantStatus, wantReason = contract.ReadUnavailable, contract.ReasonAccess
			}
			readTransportDiagnosticResult(t, child, operation, wantStatus, wantReason)
			wantRequests := 1
			if condition == "credential-failure" {
				wantRequests = 0
			}
			capturedOperation := "head-read"
			if operation == "aws-store-object" {
				capturedOperation = "store-read"
			}
			readTransportDiagnosticCapture(t, child, capturedOperation, "", key, wantRequests)
			s.mu.Lock()
			gotRequests := requests
			s.mu.Unlock()
			if gotRequests != wantRequests {
				t.Fatal("controlled diagnostic dispatch count differs", gotRequests, wantRequests)
			}
		})
	}
	for _, condition := range []string{"public-key", "credential-failure"} {
		t.Run("gcp/"+condition, func(t *testing.T) {
			s := newWorkflowServer(t, "gcp", false)
			s.childRequestLimit, s.childBytesLimit = 1, 32<<10
			var environment []string
			if condition == "credential-failure" {
				environment = []string{"GOOGLE_APPLICATION_CREDENTIALS=" + filepath.Join(t.TempDir(), "absent-adc.json")}
			}
			child := workflowRunEnvironment(t, s, helper, "authority", observer.Policy{}, nil, environment, "--probe-read-transport", "--operation", "gcp-normal-signing-key", "--selector", s.selector(1))
			wantRequests, wantReason := 1, contract.ReasonNone
			if condition == "credential-failure" {
				wantRequests, wantReason = 0, contract.ReasonAccess
			}
			readTransportDiagnosticResult(t, child, "gcp-normal-signing-key", 0, wantReason)
			readTransportDiagnosticCapture(t, child, "kms-public", "normal", "", wantRequests)
		})
	}
	t.Run("invalid-input-before-credentials", func(t *testing.T) {
		s := newWorkflowServer(t, "aws", false)
		s.childRequestLimit, s.childBytesLimit = 1, 65537
		base := []string{"--probe-read-transport", "--operation", "aws-store-object", "--region", "us-east-1", "--bucket", "fixture-bucket", "--prefix", s.prefix, "--expected-owner", "123456789012", "--domain", domain, "--key", s.prefix + "/" + domain + "/support/1/" + object}
		for _, condition := range []string{"operation", "prefix", "domain", "owner", "selector", "private-operation"} {
			t.Run(condition, func(t *testing.T) {
				args := append([]string(nil), base...)
				switch condition {
				case "operation":
					args[2] = "store-list"
				case "prefix":
					args[8] = "foreign-prefix"
				case "domain":
					args[12] = strings.Repeat("f", 64)
				case "owner":
					args[10] = ""
				case "selector":
					args = append(args, "--selector", s.selector(1))
				case "private-operation":
					args = append(args, "--role", "recovery")
				}
				child := workflowRun(t, s, helper, "reader", observer.Policy{NoKMS: true}, nil, args...)
				if child.code != 2 || len(child.out) != 0 || len(child.diagnostic) != 0 {
					t.Fatal("invalid diagnostic input did not refuse silently")
				}
				readTransportDiagnosticCapture(t, child, "", "", "", 0)
				for _, event := range child.capture.Events {
					if event.Kind == "source-kind" {
						t.Fatal("invalid diagnostic input reached credential discovery")
					}
				}
			})
		}
	})
}

func readTransportDiagnosticResult(t *testing.T, child workflowChild, operation string, status contract.ReadStatus, reason contract.Reason) {
	t.Helper()
	var result struct {
		Schema     string              `json:"schema"`
		Operation  string              `json:"operation"`
		ReadStatus contract.ReadStatus `json:"read_status"`
		Reason     contract.Reason     `json:"reason"`
	}
	decoder := json.NewDecoder(bytes.NewReader(child.out))
	decoder.DisallowUnknownFields()
	if child.code != 0 || len(child.diagnostic) != 0 || decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Schema != "ReadTransportDiagnostic/v1" || result.Operation != operation || result.ReadStatus != status || result.Reason != reason {
		t.Fatal("diagnostic did not return its exact closed typed outcome")
	}
	for _, forbidden := range []string{"private-response-must-be-cleared", "fixture-token", "fixture-bucket", "arn:", "projects/", "PRIVATE KEY", "public_key", "fingerprint"} {
		if bytes.Contains(child.out, []byte(forbidden)) || bytes.Contains(child.diagnostic, []byte(forbidden)) {
			t.Fatal("diagnostic disclosed private response or selector facts")
		}
	}
}

func readTransportDiagnosticCapture(t *testing.T, child workflowChild, operation, role, key string, requests int) {
	t.Helper()
	nativeMaterializationJoined(t, []workflowChild{child}, 1)
	var expectedHash string
	if key != "" {
		sum := sha256.Sum256([]byte(key))
		expectedHash = hex.EncodeToString(sum[:])
	}
	starts, returns := 0, 0
	for _, event := range child.capture.Events {
		if event.Kind != "http-start" && event.Kind != "http-return" {
			continue
		}
		if !event.Sent || event.Operation != operation || event.Role != role || event.ObjectKeySHA256 != expectedHash {
			t.Fatal("diagnostic capture changed exact operation, role, key hash, or admission")
		}
		if event.Kind == "http-start" {
			starts++
		} else {
			returns++
			if event.TransportTrace == nil {
				t.Fatal("diagnostic capture lost its final transport trace")
			}
		}
	}
	if starts != requests || returns != requests {
		t.Fatal("diagnostic capture lost its exact request or final return", starts, returns, requests)
	}
}
