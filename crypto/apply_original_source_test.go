package crypto

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// full_only: false
func TestApplyOriginalSealedInputRequiresCurrentSuppliedEquality(t *testing.T) {
	base := retainedApplyFixture(t)
	for _, condition := range []string{"removal", "repeat", "same-name-readd", "different-pending", "late-invalid-source", "wrong-source-context", "current-commitment", "private-denial", "absent", "generated-current", "addition"} {
		t.Run(condition, func(t *testing.T) {
			f := cloneApplyFixture(t, base)
			f.q.Intent[1].Recipients = []contract.ID{f.control.AuthorityRecipientID}
			want := contract.CryptoSuccess
			switch condition {
			case "same-name-readd":
				fresh := cloneApplyFixture(t, base)
				fresh.q.Current = nil
				first := fresh.runtime(t, nil)
				comparison := applyCompare(t, first, fresh)
				plan := applyPlan(fresh)
				for i := range plan.Rows {
					plan.Rows[i].Incarnation = consumerID(plan.Rows[i].Name + " readded incarnation")
					plan.Rows[i].ValueState = consumerID(plan.Rows[i].Name + " readded value")
				}
				prepared := applyPrepare(t, first, fresh, comparison, plan)
				first.retireApply()
				for i, row := range prepared.Rows {
					f.q.Current[i] = contract.CryptoCurrentSecret{Slot: row.Slot, EntryBytes: row.EntryBytes, AccessRecord: row.AccessRecord}
				}
			case "different-pending", "late-invalid-source", "wrong-source-context":
				envelope, err := contract.DecodeSealedInputEnvelope(f.q.SealedInputs[1].EnvelopeBytes)
				if err != nil {
					t.Fatal(err)
				}
				switch condition {
				case "different-pending":
					envelope.Core.ContentLength = 7
					envelope.Core.RetainedLength = 7
					envelope, err = custody.SealInput(envelope.Core, f.q.Bindings[applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)], []byte("pending"))
					want = contract.CryptoInvalidInput
				case "late-invalid-source":
					envelope.Ciphertext[0] ^= 1
					want = contract.CryptoSourceAuthenticationFailed
				default:
					envelope.Core.FilePredecessorDigest[0] ^= 1
					want = contract.CryptoSourceAuthenticationFailed
				}
				if err != nil {
					t.Fatal(err)
				}
				replaceApplySource(t, &f, 1, envelope)
			case "current-commitment":
				entry, err := contract.DecodeValueEntry(f.q.Current[1].EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
				if err != nil {
					t.Fatal(err)
				}
				payload.SemanticCommitment[0] ^= 1
				entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
				if err != nil {
					t.Fatal(err)
				}
				f.q.Current[1].EntryBytes, err = contract.EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				want = contract.CryptoStoredAuthenticationFailed
			case "private-denial":
				f.route.override = func(_ context.Context, _ contract.KMSBinding, _ []byte, _ uint16) PrivateResult {
					return PrivateResult{Status: KeyDenied, Uses: KeyUses{Denied: 1}}
				}
				want = contract.CryptoPrivateRouteUnavailable
			case "absent":
				f.q.Current = f.q.Current[:1]
			case "generated-current":
				current := &applyAdmission{request: f.q, control: f.control}
				before, ok := current.current(f.q.Current[1])
				if !ok {
					t.Fatal("invalid supplied predecessor fixture")
				}
				entry, err := contract.DecodeValueEntry(f.q.Current[1].EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				entry.ValueSource = contract.Generated
				entry.Generated = generatedConsumerMetadata(entry.ValueState)
				core := before.core
				core.ValueSource = contract.Generated
				core.GeneratedBindingDigest, err = contract.GeneratedBindingDigest(entry.Generated)
				if err != nil {
					t.Fatal(err)
				}
				var reply contract.CryptoResponse
				entry, access, code := sealValueForRecipients(t.Context(), core, entry.Generated, entry.OutputEncoding, entry.Recipients, f.q.Bindings, nil, &reply)
				if code != contract.CryptoSuccess {
					t.Fatal("generated predecessor setup", code)
				}
				f.q.Current[1].EntryBytes, err = contract.EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				f.q.Current[1].AccessRecord, err = contract.EncodeAccessRecord(access)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := current.current(f.q.Current[1]); !ok {
					t.Fatal("generated predecessor fixture is not authenticated structurally")
				}
			case "repeat", "addition":
				entry, err := contract.DecodeValueEntry(f.q.Current[1].EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				entry.Recipients = []contract.ID{f.control.AuthorityRecipientID}
				f.q.Current[1].EntryBytes, err = contract.EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				access, err := contract.DecodeAccessRecord(f.q.Current[1].AccessRecord)
				if err != nil {
					t.Fatal(err)
				}
				access.Wraps = slices.DeleteFunc(access.Wraps, func(row contract.WrapRow) bool {
					return row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID != f.control.AuthorityRecipientID
				})
				f.q.Current[1].AccessRecord, err = contract.EncodeAccessRecord(access)
				if err != nil {
					t.Fatal(err)
				}
				if condition == "addition" {
					f.q.Intent[1].Recipients = base.q.Intent[1].Recipients
					envelope, err := contract.DecodeSealedInputEnvelope(f.q.SealedInputs[1].EnvelopeBytes)
					if err != nil {
						t.Fatal(err)
					}
					envelope.Core.IntendedRecipientBindingSetDigest = consumerID("different original membership")
					replaceApplySource(t, &f, 1, envelope)
				}
			}
			var err error
			f.q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(f.q.SealedInputs[1].EnvelopeBytes)
			r := newConsumerRuntime(t, f.route)
			err = r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline)
			if condition == "absent" || condition == "generated-current" || condition == "addition" {
				if err != ErrAdmission || f.route.privateCalls != 0 {
					t.Fatal("ineligible original source admitted")
				}
				return
			}
			if err != nil {
				t.Fatal("eligible original source refused before private comparison", err)
			}
			body, err := contract.EncodeCryptoCompareRequest(f.q)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, t.Context(), contract.CryptoCompare, body)
			if reply.ResultCode != want {
				t.Fatal("original source comparison result", reply.ResultCode, "want", want)
			}
			if want != contract.CryptoSuccess {
				if len(reply.Body) != 0 {
					t.Fatal("failed complete comparison returned partial rows")
				}
				return
			}
			comparison, err := contract.DecodeCryptoCompareResult(reply.Body)
			if err != nil || len(comparison.Rows) != 2 || comparison.Rows[0].Relation != contract.CryptoEqual || comparison.Rows[1].Relation != contract.CryptoEqual {
				t.Fatal("known original values did not compare equal", err)
			}
			if comparison.Rows[1].ExclusionPathDigest.IsZero() != (condition == "repeat") {
				t.Fatal("removal and repeat exclusion facts differ from the request")
			}
			if !bytes.Equal(f.q.SealedInputs[1].EnvelopeBytes, original) {
				t.Fatal("original source changed")
			}
		})
	}
}

// full_only: false
func TestGeneratedAdmissionStillRefusesOriginalSealedBindingMismatch(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "matching", true: "mismatch"}[mismatch], func(t *testing.T) {
			f := generatedRuntimeEffectFixture(t, false)
			if mismatch {
				envelope, err := contract.DecodeSealedInputEnvelope(f.base.q.SealedInputs[0].EnvelopeBytes)
				if err != nil {
					t.Fatal(err)
				}
				envelope.Core.IntendedRecipientBindingSetDigest = consumerID("original different recipient set")
				binding := f.base.q.Bindings[applyBindingIndex(f.base.q.Bindings, f.base.control.AuthorityRecipientID)]
				envelope, err = custody.SealInput(envelope.Core, binding, []byte("first secret"))
				if err != nil {
					t.Fatal(err)
				}
				replaceApplySource(t, &f.base, 0, envelope)
			}
			entry := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: "alpha", Recipients: slices.Clone(f.base.q.Intent[0].Recipients), Payload: f.base.q.SealedInputs[0].EnvelopeBytes}
			generatedAddDeclarationSource(t, &f, entry, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 1, Name: "alpha", ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, EntryIncarnationID: consumerID("alpha incarnation"), ChangeMask: 1})
			f.reservation.Accepted = map[contract.ID]contract.SealedInputCore{contract.Hash(entry.Payload): f.base.accepted[contract.Hash(entry.Payload)]}
			graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
			if err != nil {
				t.Fatal(err)
			}
			f.reservation.Plan.LiveSourceUses = slices.Clone(graph.SourceUses)
			r := newConsumerRuntime(t, f.base.route)
			err = r.admitGeneratedReservation(f.compare, f.reservation, f.base.deadline)
			if mismatch {
				if err != ErrAdmission || f.base.route.privateCalls != 0 {
					t.Fatal("generated admission accepted original binding mismatch", err)
				}
			} else if err != nil {
				t.Fatal("matching generated source fixture refused", err)
			}
		})
	}
}
