package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// full_only: false
func TestConfigurationSetRetainsDeclaredBase64Bytes(t *testing.T) {
	// Fixed RFC 4648 vectors: Base64 is a retained input representation, not
	// an instruction to replace the supplied bytes with decoded content.
	for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
		for _, confidential := range []bool{false, true} {
			for _, value := range []string{"", "QQ==", "QUI=", "QUJD", "UVVKRA==", "AP8K"} {
				t.Run(fmt.Sprintf("%d/secret-%t/%s", format, confidential, value), func(t *testing.T) {
					source := configurationSetPair(t, "aws", format, nil)
					configurationSetWritable(t, source)
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					input := &configurationSetInput{Reader: bytes.NewBufferString(value)}
					result, err := SetConfiguration(ctx, source.path, format, "new", input, SetOptions{Confidential: confidential, Base64: true})
					if err != nil {
						t.Fatal(err)
					}
					entry := configurationSetEntry(t, configurationSetModel(t, source.path, format), "new")
					if result.StateResult != SetSuccess || entry.Secret != confidential {
						t.Fatal("set changed confidentiality or refused valid Base64")
					}
					if confidential {
						envelope, err := contract.InspectSealedInputEnvelope(entry.Sealed)
						if err != nil || len(envelope.Ciphertext) != len(value)+16 || len(entry.Plain) != 0 {
							t.Fatal("set did not retain Base64 inside the sealed input", err)
						}
					} else if !bytes.Equal(entry.Plain, []byte(value)) {
						t.Fatal("set changed the exact declared Base64 input bytes")
					}
					if input.reads == 0 || input.closes != 1 {
						t.Fatal("set input ownership differs")
					}
					if confidential && value == "QUJD" && format == configuration.JSON {
						body, err := os.ReadFile(source.path)
						if err != nil {
							t.Fatal(err)
						}
						var editable map[string]any
						if err := json.Unmarshal(body, &editable); err != nil {
							t.Fatal(err)
						}
						declared := editable["entries"].(map[string]any)["new"].(map[string]any)["source"].(map[string]any)
						if declared["encoding"] != "base64" {
							t.Fatal("set omitted the sealed input representation declaration")
						}
						for _, tag := range []string{"raw", ""} {
							t.Run("conflicting-source-tag/"+tag, func(t *testing.T) {
								if tag == "" {
									delete(declared, "encoding")
								} else {
									declared["encoding"] = tag
								}
								changed, err := json.Marshal(editable)
								if err != nil {
									t.Fatal(err)
								}
								if err := os.Chmod(source.path, 0600); err != nil {
									t.Fatal(err)
								}
								if err := os.WriteFile(source.path, changed, 0600); err != nil {
									t.Fatal(err)
								}
								pair, err := configuration.Capture(ctx, source.path, format)
								if err != nil {
									t.Fatal(err)
								}
								defer func() {
									if err := pair.Close(); err != nil {
										t.Error(err)
									}
								}()
								for _, parse := range []func() (*configuration.Model, error){
									func() (*configuration.Model, error) { return configuration.Parse(ctx, pair) },
									func() (*configuration.Model, error) { return configuration.ParseForPreparation(ctx, pair) },
									func() (*configuration.Model, error) { return configuration.ParseForSet(ctx, pair, "new") },
								} {
									if _, err := parse(); !errors.Is(err, configuration.ErrSourceInvalid) {
										t.Fatal("source tag reinterpreted sealed Base64", err)
									}
								}
							})
						}
					}
				})
			}
		}
	}
}

// full_only: false
func TestConfigurationSetInvalidRepresentationLeavesPairUnchanged(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		for _, value := range []string{"YQ", "YR==", "YQ==\n", "Y Q==", "____", "YQ===", "=YQ="} {
			t.Run(fmt.Sprintf("secret-%t/%q", confidential, value), func(t *testing.T) {
				source := configurationSetPair(t, "aws", configuration.JSON, nil)
				configurationSetWritable(t, source)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				input := &configurationSetInput{Reader: bytes.NewBufferString(value)}
				result, err := SetConfiguration(ctx, source.path, configuration.JSON, "new", input, SetOptions{Confidential: confidential, Base64: true})
				if err == nil || !configurationSetUndelivered(result) || input.closes != 1 {
					t.Fatal("invalid declared Base64 was delivered or input ownership changed")
				}
				source.assertUnchanged(t)
			})
		}
	}
}
