package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

// full_only: false
func TestKeysOutputPathsRefuseBeforeExecutor(t *testing.T) {
	for _, target := range []string{"authority", "recovery", "recipient"} {
		t.Run(target, func(t *testing.T) {
			for _, row := range []struct {
				name, path string
				valid      bool
			}{
				{"over-limit", "/" + strings.Repeat("x", 4096), false}, {"invalid-utf8", "/private-path-sentinel" + string([]byte{255}), false},
				{"nul", "/private-path-sentinel\x00", false}, {"root", "/", false}, {"relative-control", "relative/../successor.json", true},
			} {
				t.Run(row.name, func(t *testing.T) {
					for _, human := range []bool{false, true} {
						args := []string{"replace", "--target", target, "--source", "source.json", "--out", row.path, "--encryption", replacementCLIKey}
						if target == "recipient" {
							args = append(args, "--recipient", "member")
						} else {
							args = append(args, "--authorizer", "authority")
						}
						if !human {
							args = append(args, "--json")
						}
						calls := 0
						var out, diagnostic bytes.Buffer
						code := runKeysWithExecutor(replacementCLIContext(t), args, &out, &diagnostic, func(_ context.Context, nonce contract.ID, source string, encoding configuration.Format, request configuration.ReplacementRequest, path string, _ compositionfull.RecipientSelector) compositionfull.ReplacementCommandResult {
							calls++
							if !row.valid {
								t.Error("invalid output reached executor", target, row.name)
							}
							if row.valid && (!filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.HasSuffix(path, "/successor.json") || !filepath.IsAbs(source)) {
								t.Error("relative control was not captured once")
							}
							result, err := compositionfull.NewReplacementCommandRefusal(request.Target, nonce, encoding)
							if err != nil {
								t.Fatal(err)
							}
							return result
						})
						wantCalls := 0
						if row.valid {
							wantCalls = 1
						}
						if code != 2 || calls != wantCalls {
							t.Errorf("wrong closed input exit or executor count: target=%s case=%s exit=%d calls=%d", target, row.name, code, calls)
						}
						body := out.Bytes()
						if bytes.Contains(body, []byte("private-path-sentinel")) || bytes.Contains(diagnostic.Bytes(), []byte("private-path-sentinel")) {
							t.Fatal("invalid location leaked raw path")
						}
						if human {
							if !bytes.Contains(body, []byte("Key replacement: refused\n")) || !bytes.Contains(body, []byte("Operation: keys-replace-"+target+"\n")) || !bytes.Contains(body, []byte("Requested replacement target: "+target+"\n")) || bytes.Contains(body, []byte("Key replacement: success")) || bytes.Contains(body, []byte("ProductResult/v1")) {
								t.Fatal("human refusal lost its target or claimed replacement", string(body))
							}
							continue
						}
						var wire map[string]json.RawMessage
						if err := json.Unmarshal(body, &wire); err != nil {
							t.Fatal("missing complete recognized refusal", err)
						}
						if string(wire["operation_kind"]) != `"keys-replace-`+target+`"` || string(wire["state_result"]) != `"refused"` || string(wire["payload"]) != `"none"` || string(wire["replay_identity"]) != `"none"` || bytes.Contains(out.Bytes(), []byte("private-path-sentinel")) || bytes.Contains(diagnostic.Bytes(), []byte("private-path-sentinel")) {
							t.Fatal("invalid location lost target or leaked raw path")
						}
					}
				})
			}
		})
	}
}
