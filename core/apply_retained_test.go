package core

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func retainedInputFixture(t *testing.T) (*StateSession, ApplyEntryInput) {
	t.Helper()
	s, _ := observationTestSession(t)
	observationCurrentSecret(t, s, []contract.ID{s.admission.recipient}, generatedVectorID(201))
	entry := s.valueEntry(0)
	return s, ApplyEntryInput{Name: entry.Name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret,
		Recipients: slices.Clone(entry.Recipients), Retained: &contract.RetainedSecretInput{Incarnation: entry.Incarnation, Material: entry.ValueState}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
}

// full_only: false
func TestApplyRetainedInputResolvesExactCurrent(t *testing.T) {
	s, input := retainedInputFixture(t)
	c, result := s.compareEntryInputs([]ApplyEntryInput{input})
	if c == nil || result.Outcome != ObservedCurrent || len(c.changed) != 0 || len(c.intent) != 1 {
		t.Fatal("exact current pin refused or changed", result)
	}
	entry := s.valueEntry(0)
	want := contract.ID(sha256.Sum256(entry.ValueBytes))
	if c.intent[0].Retained != *input.Retained || c.intent[0].PayloadDigest != want || c.intent[0].PayloadLength != uint32(len(entry.ValueBytes)) || c.intent[0].ContentLength != 0 || !bytes.Equal(c.desiredEntries[0].InputBytes, entry.ValueBytes) {
		t.Fatal("retained intent lost exact current material or derived length")
	}
	input.Retained.Material[0] ^= 1
	if c.desiredEntries[0].Retained.Material != entry.ValueState || len(input.InputBytes) != 0 {
		t.Fatal("resolved input borrowed caller pin or changed caller bytes")
	}
}

// full_only: false
func TestApplyRetainedResolvedInputRevalidation(t *testing.T) {
	s, input := retainedInputFixture(t)
	first, result := s.compareEntryInputs([]ApplyEntryInput{input})
	if first == nil {
		t.Fatal(result)
	}
	again, result := s.compareResolvedEntryInputs(t.Context(), first.desiredEntries, first.recipients)
	if again == nil || result.Outcome != ObservedCurrent || again.desired != first.desired || again.desiredLength != first.desiredLength || !slices.Equal(again.changed, first.changed) || !slices.Equal(again.slots, first.slots) {
		t.Fatal("Prepare cannot revalidate a resolved exact current pin", result)
	}
}

// full_only: false
func TestApplyRetainedInputRejectsStaleOrInvalidPins(t *testing.T) {
	for _, name := range []string{"absent", "incarnation", "material", "removed", "readded", "zero-incarnation", "zero-material", "payload", "plain-request", "generated-request", "plain-current", "generated-current"} {
		t.Run(name, func(t *testing.T) {
			s, input := retainedInputFixture(t)
			switch name {
			case "absent":
				input.Name = "absent"
			case "incarnation":
				input.Retained.Incarnation[0] ^= 1
			case "material":
				s.valueEntry(0).ValueState[0] ^= 1
			case "removed":
				s.root.Names = nil
			case "readded":
				s.valueEntry(0).Incarnation[0] ^= 1
				s.valueEntry(0).ValueState[0] ^= 1
			case "zero-incarnation":
				input.Retained.Incarnation = contract.ID{}
			case "zero-material":
				input.Retained.Material = contract.ID{}
			case "payload":
				input.InputBytes = []byte{1}
			case "plain-request":
				input.ConfidentialityClass = contract.Plain
			case "generated-request":
				input.ValueSource = contract.Generated
			case "plain-current":
				s.valueEntry(0).ConfidentialityClass = contract.Plain
			case "generated-current":
				s.valueEntry(0).ValueSource = contract.Generated
			}
			if c, result := s.compareEntryInputs([]ApplyEntryInput{input}); c != nil || result != refused(InvalidIntent) {
				t.Fatal("invalid retained pin admitted", result)
			}
		})
	}
}

// full_only: false
func TestApplyRetainedInputChargesCurrentRawSet(t *testing.T) {
	s, input := retainedInputFixture(t)
	entry := *s.valueEntry(0)
	payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload.ContentLength, payload.RetainedLength, payload.Ciphertext = 65536, 65536, make([]byte, 65536+16)
	entry.ContentLength, entry.RetainedLength = payload.ContentLength, payload.RetainedLength
	entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]contract.ValueEntry, 128)
	inputs := make([]ApplyEntryInput, len(entries))
	for i := range entries {
		entries[i] = entry
		entries[i].Name = fmt.Sprintf("secret-%03d", i)
		entries[i].Incarnation, entries[i].ValueState = observationBoundID(1000+i), observationBoundID(2000+i)
		inputs[i] = input
		inputs[i].Name = entries[i].Name
		inputs[i].Retained = &contract.RetainedSecretInput{Incarnation: entries[i].Incarnation, Material: entries[i].ValueState}
	}
	observationInstallEntries(s, entries)
	if c, result := s.compareEntryInputs(inputs); c == nil || result.Outcome != ObservedCurrent {
		t.Fatal("exact 8 MiB retained raw set refused", result)
	}
	inputs = append(inputs, ApplyEntryInput{Name: "extra", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: input.Recipients, InputBytes: []byte{1}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	if c, result := s.compareEntryInputs(inputs); c != nil || result != refused(CapacityExceeded) {
		t.Fatal("retained current raw bytes were omitted from joint charge", result)
	}
}

// full_only: false
func TestApplyRetainedNoopRequiresCheckedPrivateComparison(t *testing.T) {
	for _, code := range []contract.CryptoResultCode{contract.CryptoSuccess, contract.CryptoStoredAuthenticationFailed, contract.CryptoPrivateRouteUnavailable} {
		for _, outputOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("code=%d/output-only=%t", code, outputOnly), func(t *testing.T) {
				s, input := retainedInputFixture(t)
				if outputOnly {
					input.OutputEncoding = contract.OutputEncodingBase64
				}
				generatedSealSelectedFixture(t, s)
				if c, result := s.Compare(t.Context(), []ApplyEntryInput{input}, nil); c != nil || result != refused(AdmissionInvalid) {
					t.Fatal("public equality bypassed private admission", result)
				}
				c, result := s.compareEntryInputs([]ApplyEntryInput{input})
				if c == nil {
					t.Fatal(result)
				}
				admitted := generatedContinuationContext(t, s, 123, 124)
				admitted.OperationClass = contract.CryptoOrdinaryLifecycle
				admitted.IntentDescriptor = contract.DescriptorVector{Digest: c.desired, Length: c.desiredLength, Count: 1}
				q, ok := s.comparisonRequest(c, admitted)
				if !ok || len(q.Current) != 1 || len(q.SealedInputs) != 0 || q.Intent[0].Retained != *input.Retained {
					t.Fatal("retained input became a sealed source")
				}
				body, err := contract.EncodeCryptoCompareRequest(q)
				if err != nil {
					t.Fatal(err)
				}
				custody := &observationExchangeCustody{instance: generatedVectorID(105)}
				binding := q.Bindings[0]
				digest, err := contract.PublicBindingDigest(binding.Binding)
				if err != nil {
					t.Fatal(err)
				}
				use := contract.KeyUseRow{BindingID: binding.Binding.BindingID, PublicBindingDigest: digest, SubjectKind: binding.SubjectKind, SubjectID: binding.SubjectID, Provider: binding.Binding.Provider, Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 1}
				compared := observationComparedBody(t, c, contract.CryptoEqual, false)

				preparedBody, err := contract.EncodeCryptoPrepareResult(contract.CryptoPrepareResult{})
				if err != nil {
					t.Fatal(err)
				}
				custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
					if q.Kind == contract.CryptoPrepare {
						return observationReply(q, contract.CryptoSuccess, nil, preparedBody)
					}
					if q.Kind == contract.CryptoDiscard {
						return observationReply(q, contract.CryptoSuccess, nil, nil)
					}
					if code != contract.CryptoSuccess {
						return observationReply(q, code, nil, nil)
					}
					return observationReply(q, code, []contract.KeyUseRow{use}, compared)
				}
				permit := &AdmittedParentComparison{session: s, crypto: custody, instance: custody.instance, context: admitted, requestDigest: contract.Hash(body), requestLength: len(body), deadline: time.Unix(0, int64(admitted.Expiry))}
				got, result := s.Compare(t.Context(), []ApplyEntryInput{input}, permit)
				if outputOnly && code == contract.CryptoSuccess {
					if got == nil || result.Outcome != ObservedCurrent || len(got.changed) != 0 || !got.entryConfigurationChanged {
						t.Fatal("output-only comparison changed material or disappeared", result)
					}
					prior := *s.valueEntry(0)
					priorCore, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, prior)
					if err != nil {
						t.Fatal(err)
					}
					plan, err := planTransition(t.Context(), got)
					if err != nil || len(plan.values) != 0 || len(plan.incarnations) != 0 {
						t.Fatal("output-only transition allocated immutable value identities", err)
					}

					if result := s.prepareCompared(t.Context(), got, plan); result.Outcome != 0 || len(got.preparedRows) != 0 {
						t.Fatal("output-only identity admission prepared material", result)
					}
					next, err := s.deriveSuccessor(t.Context(), got, plan)
					if err != nil {
						t.Fatal("output-only successor refused", err)
					}
					after := next.valueEntry(0)
					afterCore, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, *after)
					if err != nil || afterCore != priorCore || !bytes.Equal(after.ValueBytes, prior.ValueBytes) || after.OutputEncoding != input.OutputEncoding {
						t.Fatal("output-only apply resealed retained material", err)
					}

					if len(custody.calls) != 2 || custody.calls[0].Kind != contract.CryptoCompare || custody.calls[1].Kind != contract.CryptoPrepare {
						t.Fatal("output-only apply changed its comparison/identity protocol")
					}
					return
				}
				if got != nil {
					t.Fatal("retained no-op returned mutable comparison")
				}
				if code == contract.CryptoSuccess {
					if result.Outcome != Unchanged || len(custody.calls) != 2 || custody.calls[1].Kind != contract.CryptoDiscard {
						t.Fatal("checked retained no-op changed or prepared state", result)
					}
				} else if result != custodyFailure(code) || len(custody.calls) != 1 {
					t.Fatal("private failure was hidden by public equality", result)
				}
			})
		}
	}
}
