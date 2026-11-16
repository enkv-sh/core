package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

const replacementCLIKey = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

func replacementCLIContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// full_only: false
func TestKeysRoleGrammarRoutesAllTwelveForms(t *testing.T) {
	for _, target := range []string{"authority", "recovery"} {
		for _, authorizer := range []string{"authority", "recovery"} {
			for _, change := range []string{"signing", "encryption", "both"} {
				t.Run(target+"/"+authorizer+"/"+change, func(t *testing.T) {
					args := []string{"replace", "--source", "relative/source.json", "--out", "relative/../successor.json", "--target", target, "--authorizer", authorizer, "--json"}
					if change != "encryption" {
						args = append(args, "--signing", replacementCLIKey)
					}
					if change != "signing" {
						args = append(args, "--encryption", replacementCLIKey)
					}
					calls := 0
					execute := func(ctx context.Context, nonce contract.ID, source string, format configuration.Format, r configuration.ReplacementRequest, out string, _ compositionfull.RecipientSelector) compositionfull.ReplacementCommandResult {
						calls++
						if nonce.IsZero() || !filepath.IsAbs(source) || !filepath.IsAbs(out) || filepath.Clean(source) != source || filepath.Clean(out) != out || !strings.HasSuffix(source, "relative/source.json") || !strings.HasSuffix(out, "successor.json") || format != configuration.JSON || string(r.Target) != target || r.RecipientReference != "" {
							t.Fatal("wrong captured request", source, out, r)
						}
						role := uint8(contract.NormalSigningRole)
						if authorizer == "recovery" {
							role = contract.RecoverySigningRole
						}
						if r.Authorizer != role {
							t.Fatal("wrong authorizer", r)
						}
						wantMaterial := ""
						if change != "signing" {
							wantMaterial = authorizer
						}
						if r.MaterialSource != wantMaterial || (r.SigningSelector == replacementCLIKey) != (change != "encryption") || (r.EncryptionSelector == replacementCLIKey) != (change != "signing") {
							t.Fatal("changed key or material route", r)
						}
						result, err := compositionfull.NewReplacementCommandRefusal(r.Target, nonce, format)
						if err != nil {
							t.Fatal(err)
						}
						return result
					}
					var out, diagnostic bytes.Buffer
					if code := runKeysWithExecutor(replacementCLIContext(t), args, &out, &diagnostic, execute); code != 2 || calls != 1 || !json.Valid(out.Bytes()) {
						t.Fatal("grammar did not reach exact executor", code, calls, out.String(), diagnostic.String())
					}
				})
			}
		}
	}
}

// full_only: false
func TestKeysMaterialRouteAndRecipientAreExplicit(t *testing.T) {
	for _, test := range []struct {
		name, target, authorizer, material, recipient string
		wantRole                                      uint8
	}{{"cross-route", "authority", "authority", "recovery", "", contract.NormalSigningRole}, {"recipient", "recipient", "", "", "member", contract.NormalSigningRole}, {"recipient-explicit-authority", "recipient", "authority", "", "member", contract.NormalSigningRole}} {
		t.Run(test.name, func(t *testing.T) {
			args := []string{"replace", "--target", test.target, "--source", "source.yaml", "--out", "successor.yaml", "--encryption", replacementCLIKey, "--json"}
			if test.authorizer != "" {
				args = append(args, "--authorizer", test.authorizer)
			}
			if test.material != "" {
				args = append(args, "--decrypt-with", test.material)
			}
			if test.recipient != "" {
				args = append(args, "--recipient", test.recipient)
			}
			calls := 0
			execute := func(ctx context.Context, n contract.ID, s string, f configuration.Format, r configuration.ReplacementRequest, o string, _ compositionfull.RecipientSelector) compositionfull.ReplacementCommandResult {
				calls++
				want := test.material
				if test.target == "recipient" {
					want = "authority"
				}
				if r.MaterialSource != want || r.Authorizer != test.wantRole || r.RecipientReference != test.recipient || f != configuration.YAML {
					t.Fatal("wrong exact material source", r)
				}
				result, err := compositionfull.NewReplacementCommandRefusal(r.Target, n, f)
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			var out, diagnostic bytes.Buffer
			runKeysWithExecutor(replacementCLIContext(t), args, &out, &diagnostic, execute)
			if calls != 1 {
				t.Fatal("valid material route refused", out.String(), diagnostic.String())
			}
		})
	}
}

// full_only: false
func TestKeysInvalidGrammarNeverCallsExecutor(t *testing.T) {
	base := []string{"replace", "--target", "authority", "--source", "source.json", "--out", "successor.json", "--json"}
	for _, suffix := range [][]string{{}, {"--signing", replacementCLIKey}, {"--authorizer", "authority"}, {"--authorizer", "authority", "--signing", replacementCLIKey, "--decrypt-with", "recovery"}, {"--authorizer", "authority", "--signing", replacementCLIKey, "--recipient", "member"}, {"--authorizer", "authority", "--signing", "-----BEGIN PUBLIC KEY-----"}, {"--authorizer", "authority", "--encryption", replacementCLIKey, "--decrypt-with", "recipient"}, {"--authorizer", "authority", "--signing", replacementCLIKey, "--connection", "secret-argument"}, {"--authorizer", "authority", "--signing", replacementCLIKey, "--overwrite"}, {"--authorizer", "authority", "--signing", replacementCLIKey, "--fingerprint", "secret-argument"}, {"--authorizer", "authority", "--signing", replacementCLIKey, "--out", "other.json"}, {"--authorizer", "authority", "--encryption", replacementCLIKey, "--signing", ""}, {"--authorizer", "authority", "--signing", replacementCLIKey, "--source-format", ""}} {
		calls := 0
		execute := func(context.Context, contract.ID, string, configuration.Format, configuration.ReplacementRequest, string, compositionfull.RecipientSelector) compositionfull.ReplacementCommandResult {
			calls++
			return compositionfull.ReplacementCommandResult{}
		}
		var out, diagnostic bytes.Buffer
		code := runKeysWithExecutor(replacementCLIContext(t), append(append([]string{}, base...), suffix...), &out, &diagnostic, execute)
		if code != 2 || calls != 0 || !json.Valid(out.Bytes()) || !bytes.Contains(out.Bytes(), []byte("keys-replace-authority")) || bytes.Contains(out.Bytes(), []byte("secret-argument")) || bytes.Contains(diagnostic.Bytes(), []byte("secret-argument")) {
			t.Fatal("invalid request reached work or lost safe operation", code, calls, out.String(), diagnostic.String())
		}
	}
	for _, suffix := range [][]string{{"--signing", replacementCLIKey}, {"--authorizer", "recovery"}, {"--decrypt-with", "authority"}, {"--recipient", ""}} {
		args := []string{"replace", "--target", "recipient", "--source", "source.json", "--out", "successor.json", "--recipient", "member", "--encryption", replacementCLIKey, "--json"}
		args = append(args, suffix...)
		var out, diagnostic bytes.Buffer
		calls := 0
		code := runKeysWithExecutor(replacementCLIContext(t), args, &out, &diagnostic, func(context.Context, contract.ID, string, configuration.Format, configuration.ReplacementRequest, string, compositionfull.RecipientSelector) compositionfull.ReplacementCommandResult {
			calls++
			return compositionfull.ReplacementCommandResult{}
		})
		if code != 2 || calls != 0 || !json.Valid(out.Bytes()) {
			t.Fatal("invalid Recipient route reached work", code, calls, out.String())
		}
	}
}

type replacementShortWriter struct{}

func (replacementShortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

// full_only: false
func TestKeysHelpUnknownAndDeliveryHaveNoPrivateRoute(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if code := runKeysWithExecutor(context.Background(), nil, &out, &diagnostic, nil); code != 0 || !strings.Contains(out.String(), "keys replace") || diagnostic.Len() != 0 {
		t.Fatal("bare help used execution route", code, out.String())
	}
	if runKeysWithExecutor(context.Background(), nil, replacementShortWriter{}, io.Discard, nil) != 2 {
		t.Fatal("short help output accepted")
	}
	for _, args := range [][]string{{"unknown", "--source", "secret-argument", "--json"}, {"replace", "--target", "unknown", "--json"}} {
		out.Reset()
		diagnostic.Reset()
		if code := runKeysWithExecutor(context.Background(), args, &out, &diagnostic, nil); code != 2 || !json.Valid(out.Bytes()) || bytes.Contains(out.Bytes(), []byte("secret-argument")) || bytes.Contains(out.Bytes(), []byte("keys-replace-authority")) {
			t.Fatal("unknown dispatch invented target", code, out.String())
		}
	}
}

// full_only: false
func TestKeysInvalidOptionsKeepRecognizedTargetInEitherOrder(t *testing.T) {
	for _, args := range [][]string{{"replace", "--connection", "private-sentinel", "--target", "authority", "--json"}, {"replace", "--target", "authority", "--connection", "private-sentinel", "--json"}, {"replace", "--pem=private-sentinel", "--target=recovery", "--json"}, {"replace", "--target", "recipient", "--target", "recipient", "--json"}} {
		args = append([]string{"replace", "--json"}, args[1:len(args)-1]...)
		var out, diagnostic bytes.Buffer
		if code := runKeysWithExecutor(replacementCLIContext(t), args, &out, &diagnostic, nil); code != 2 || !json.Valid(out.Bytes()) || !bytes.Contains(out.Bytes(), []byte(`"operation_kind": "keys-replace-`)) || !bytes.Contains(out.Bytes(), []byte(`"operation_payload": "none"`)) || bytes.Contains(out.Bytes(), []byte("private-sentinel")) || bytes.Contains(diagnostic.Bytes(), []byte("private-sentinel")) {
			t.Fatal("invalid option changed recognized operation", code, out.String(), diagnostic.String())
		}
	}
	for _, args := range [][]string{{"replace", "--target", "authority", "--target", "recovery", "--json"}, {"replace", "--source", "--target", "authority", "--json"}, {"replace", "--", "--target", "authority", "--json"}, {"replace", "--target", "invalid", "--target", "authority", "--json"}} {
		var out, diagnostic bytes.Buffer
		if code := runKeysWithExecutor(replacementCLIContext(t), args, &out, &diagnostic, nil); code != 2 || bytes.Contains(out.Bytes(), []byte("keys-replace-authority")) || bytes.Contains(out.Bytes(), []byte("keys-replace-recovery")) || bytes.Contains(out.Bytes(), []byte("keys-replace-recipient")) {
			t.Fatal("ambiguous or consumed target invented operation", code, out.String())
		}
	}
}
