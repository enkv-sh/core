package crypto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

type applyTestFixture struct {
	ctx      context.Context
	support  contract.DescriptorVector
	q        contract.CryptoCompareRequest
	current  []contract.RecipientRecord
	control  contract.ControlCore
	route    *consumerTestRoute
	accepted map[contract.ID]contract.SealedInputCore
	deadline time.Time
	keys     map[contract.ID]*rsa.PrivateKey
}

func applyFixture(t *testing.T, recovery bool) applyTestFixture {
	t.Helper()
	selection, route := consumerFixture(t)
	f := applyTestFixture{ctx: context.Background(), route: route, accepted: make(map[contract.ID]contract.SealedInputCore), deadline: time.Now().Add(time.Minute), keys: map[contract.ID]*rsa.PrivateKey{selection.Binding.SubjectID: route.key}}
	rows := []contract.BindingTableRow{selection.Binding}
	for _, subject := range []string{"reader", "recovery"} {
		if subject == "recovery" && !recovery {
			continue
		}
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		row := contract.BindingTableRow{SubjectKind: 1, SubjectID: consumerID(subject), Binding: contract.KMSBinding{BindingID: consumerID(subject + " binding"), BindingIncarnationID: consumerID(subject + " binding incarnation"), BindingSerial: 1, Provider: contract.GCP, WrapProfile: 2, ProtectionClass: 2, KeySelector: "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/" + subject + "/cryptoKeyVersions/1", SPKI: spki, Fingerprint: contract.Hash(spki)}}
		if subject == "recovery" {
			row.SubjectKind = 2
		}
		rows = append(rows, row)
		f.keys[row.SubjectID] = key
	}
	slices.SortFunc(rows, func(a, b contract.BindingTableRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
	})
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingSPKI, err := x509.MarshalPKIXPublicKey(&signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signing := contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: 1, Provider: contract.GCP, SigningProfile: 1, BindingID: consumerID("signing binding"), KeySelector: "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/signing/cryptoKeyVersions/1", SPKI: signingSPKI, Fingerprint: contract.Hash(signingSPKI), Binding: contract.BindingSubject{Domain: selection.DomainID, Store: consumerID("store"), Coordinate: consumerID("coordinate"), Trust: consumerID("trust"), PublicKey: contract.Hash(signingSPKI), Interpretation: consumerID("interpretation"), ControlIncarnationID: consumerID("signing incarnation"), Epoch: 1}}
	f.control = contract.ControlCore{CurrentControl: contract.CurrentControl{CurrentControlFields: contract.CurrentControlFields{Schema: contract.CanonicalSchema, Profile: 2, DomainID: selection.DomainID, Provider: contract.GCP, StoreID: signing.Binding.Store, CoordinateID: signing.Binding.Coordinate, NonBodyID: consumerID("nonbody"), TrustInterpretationID: signing.Binding.Interpretation, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), AuthorityRecipientID: selection.Binding.SubjectID, AccessIncarnationID: contract.DeriveAccessIncarnationID(selection.DomainID, signing.Binding.ControlIncarnationID), AccessGeneration: 1}, NormalSigning: signing}, AuthorityKMSBinding: selection.Binding.Binding}
	if recovery {
		rec := rows[len(rows)-1]
		signing.Role = 2
		signing.BindingID = consumerID("recovery signing")
		f.control.Recovery = &contract.RecoveryBindings{RoleID: rec.SubjectID, Signing: signing, KMS: rec.Binding}
	}
	c := contract.ApplyContext{OperationClass: contract.CryptoOrdinaryLifecycle, AdmissionID: consumerID("apply admission"), SessionID: consumerID("apply session"), DomainID: selection.DomainID, CompatibilityID: contract.CompatibilityID(), Expiry: uint64(f.deadline.UnixNano()), PredecessorHEADDigest: selection.HEADDigest, OriginalConditionDigest: consumerID("condition"), CurrentAccessRoot: selection.AccessRoot}
	ref, err := contract.AppendRef(nil, selection.Root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.PredecessorRootRef[:], ref)
	f.q = contract.CryptoCompareRequest{Context: c, Bindings: rows}
	for _, row := range rows {
		if row.SubjectKind == contract.OrdinaryWrapSubject {
			binding := row.Binding
			recipient := contract.RecipientRecord{RecipientID: row.SubjectID, Status: contract.CurrentRecipient, DisplayName: "current recipient", CurrentBinding: &binding}
			f.current = append(f.current, recipient)
			f.q.Recipients = append(f.q.Recipients, contract.ApplyRecipientInput{Recipient: recipient})
		}
	}
	var recipients []contract.ID
	var refs []contract.RecipientBindingReference
	for _, row := range rows {
		if row.SubjectKind != 1 {
			continue
		}
		digest, err := contract.PublicBindingDigest(row.Binding)
		if err != nil {
			t.Fatal(err)
		}
		recipients = append(recipients, row.SubjectID)
		refs = append(refs, contract.RecipientBindingReference{RecipientID: row.SubjectID, PublicBindingDigest: digest})
	}
	set, err := contract.IntendedRecipientBindingSetDigest(c.DomainID, selection.Binding.SubjectID, refs)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"alpha", "beta"} {
		plain := []byte("first secret")
		if i == 1 {
			plain = []byte{}
		}
		core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: 4, Profile: 2, CompatibilityID: c.CompatibilityID, DomainID: c.DomainID, FileIdentity: consumerID("source file"), FilePredecessorDigest: consumerID("source predecessor"), SourceID: consumerID(name + " source"), CryptoSupportID: contract.CryptoSupportID(), DataKeyID: consumerID(name + " source data"), DataKeyEpoch: 1, ContentLength: uint32(len(plain)), IntendedRecipientBindingSetDigest: set, InputEncoding: contract.InputEncodingRaw, RetainedLength: uint32(len(plain))}, Name: name}
		envelope, err := custody.SealInput(core, selection.Binding, plain)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeSealedInputEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		// Independent input-purpose wrapper; source body comes from the producer.
		preimage := append([]byte("ENKV/SEALED-INPUT/v1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(body)))...)
		preimage = append(preimage, body...)
		f.q.Intent = append(f.q.Intent, contract.CryptoIntentRow{Name: name, Recipients: slices.Clone(recipients), ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, ContentLength: core.ContentLength, PayloadDigest: contract.Hash(preimage), PayloadLength: uint32(len(body)), InputEncoding: contract.InputEncodingRaw, RetainedLength: core.ContentLength, OutputEncoding: contract.OutputEncodingRaw})
		f.q.SealedInputs = append(f.q.SealedInputs, contract.CryptoSealedInput{Name: name, EnvelopeBytes: body})
		f.accepted[contract.Hash(body)] = core
	}
	f.q.Context.IntentDescriptor, err = contract.CompleteApplyIntentDescriptor(c.DomainID, f.q.Intent, f.q.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	f.support, err = contract.EmptyRequiredSupportDescriptor(f.q.Context.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f applyTestFixture) runtime(t *testing.T, plainBefore []contract.MembershipRow) *Runtime {
	t.Helper()
	r := newConsumerRuntime(t, f.route)
	if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, plainBefore, f.support, f.deadline); err != nil {
		t.Fatal(err)
	}
	return r
}

func applyCall(r *Runtime, ctx context.Context, kind contract.CryptoKind, body []byte) contract.CryptoResponse {
	q := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: kind, RequestID: consumerID(fmt.Sprintf("stage %d", kind)), CustodyInstanceID: r.InstanceID(), Body: body}
	return r.Exchange(ctx, q)
}

func applyCompare(t *testing.T, r *Runtime, f applyTestFixture) contract.CryptoCompareResult {
	t.Helper()
	body, err := contract.EncodeCryptoCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, f.ctx, contract.CryptoCompare, body)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatalf("Compare code %v", reply.ResultCode)
	}
	if len(reply.KeyUseRows) != 1 || reply.KeyUseRows[0].Purpose != contract.KeyUseMaterialOpen || reply.KeyUseRows[0].Count != uint32(len(f.q.SealedInputs)) {
		t.Fatalf("source open evidence %+v", reply.KeyUseRows)
	}
	result, err := contract.DecodeCryptoCompareResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	clear(reply.Body)
	return result
}

func applyPlan(f applyTestFixture) contract.IdentityPlan {
	p := contract.IdentityPlan{Operation: consumerID("operation"), Transition: consumerID("transition"), Snapshot: consumerID("candidate snapshot"), Revision: consumerID("candidate revision")}
	for i, row := range f.q.Intent {
		p.Rows = append(p.Rows, contract.IdentityRow{Name: row.Name, Slot: uint16(i), Incarnation: consumerID(row.Name + " incarnation"), ValueState: consumerID(row.Name + " value"), OriginSnapshot: p.Snapshot, OriginTransition: p.Transition})
	}
	return p
}

func applyPrepare(t *testing.T, r *Runtime, f applyTestFixture, comparison contract.CryptoCompareResult, plan contract.IdentityPlan) contract.CryptoPrepareResult {
	t.Helper()
	identity, err := contract.EncodeIdentityPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCryptoPrepareRequest(contract.CryptoPrepareRequest{OperationRef: comparison.OperationRef, Context: f.q.Context, IdentityPlan: identity})
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, f.ctx, contract.CryptoPrepare, body)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatalf("Prepare code %v", reply.ResultCode)
	}
	var opened, wrapped uint32
	for _, row := range reply.KeyUseRows {
		switch row.Purpose {
		case contract.KeyUseMaterialOpen:
			opened += row.Count
		case contract.KeyUseMaterialWrap:
			wrapped += row.Count
		default:
			t.Fatal("unexpected preparation key use")
		}
	}
	if opened != uint32(len(f.q.SealedInputs)) || wrapped != uint32(len(f.q.SealedInputs)*len(f.q.Bindings)) {
		t.Fatalf("incorrect preparation use counts %d/%d", opened, wrapped)
	}
	prepared, err := contract.DecodeCryptoPrepareResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	clear(reply.Body)
	return prepared
}

func applyFreezeRequest(t *testing.T, f applyTestFixture, comparison contract.CryptoCompareResult, plan contract.IdentityPlan, prepared contract.CryptoPrepareResult) contract.CryptoFreezeRequest {
	t.Helper()
	support := f.support
	public := contract.PublicState{Domain: f.q.Context.DomainID, AccessRoot: consumerID("candidate access"), RequiredSupport: support}
	for _, row := range prepared.Rows {
		entry, err := contract.DecodeValueEntry(row.EntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := contract.PublicValueEntryDigest(public.Domain, row.Slot, entry)
		if err != nil {
			t.Fatal(err)
		}
		public.Rows = append(public.Rows, contract.PublicStateRow{Name: row.Name, Slot: row.Slot, EntryDigest: digest})
	}
	identity, err := contract.IdentityPlanDescriptor(plan)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := contract.CryptoPreparedRowsDescriptor(prepared.Rows)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := contract.EncodePublicState(public)
	if err != nil {
		t.Fatal(err)
	}
	exclusions, err := contract.EncodeExclusions(public.Domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	return contract.CryptoFreezeRequest{OperationRef: comparison.OperationRef, Context: f.q.Context, IdentityPlanDescriptor: identity, CanonicalRowsDescriptor: canonical, CandidatePublicState: candidate, Exclusions: exclusions, Recipients: applyProposedRecipients(f.q)}
}

// full_only: false
func TestApplyFirstSelectionStagesAndRecipientOracles(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			metricContext, reader := cryptoTelemetryReader(t)
			f := applyFixture(t, recovery)
			f.ctx = metricContext
			r := f.runtime(t, nil)
			comparison := applyCompare(t, r, f)
			if len(comparison.Rows) != 2 {
				t.Fatal("incomplete comparison")
			}
			for _, row := range comparison.Rows {
				if row.Relation != contract.CryptoAdded || row.BeforePresent || !row.AfterPresent {
					t.Fatal("first selection invented predecessor secret")
				}
			}
			plan := applyPlan(f)
			prepared := applyPrepare(t, r, f, comparison, plan)
			for i, row := range prepared.Rows {
				entry, err := contract.DecodeValueEntry(row.EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
				if err != nil {
					t.Fatal(err)
				}
				access, err := contract.DecodeAccessRecord(row.AccessRecord)
				if err != nil {
					t.Fatal(err)
				}
				core := contract.ValueCore{ValueSource: 1, Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: f.q.Context.CompatibilityID, CryptoSupportID: contract.CryptoSupportID(), DomainID: f.q.Context.DomainID, Name: entry.Name, EntryIncarnationID: entry.Incarnation, ValueStateID: entry.ValueState, OriginSnapshotID: entry.OriginSnapshot, OriginTransitionID: entry.OriginTransition, DataKeyID: payload.DataKeyID, DataKeyEpoch: payload.DataKeyEpoch, CommitmentKeyID: payload.CommitmentKeyID, CommitmentKeyEpoch: payload.CommitmentKeyEpoch, ContentLength: payload.ContentLength, InputEncoding: contract.InputEncodingRaw, RetainedLength: payload.ContentLength}
				if len(access.Wraps) != len(f.q.Bindings) || payload.DataKeyID == f.accepted[contract.Hash(f.q.SealedInputs[i].EnvelopeBytes)].DataKeyID || payload.DataKeyID == payload.CommitmentKeyID {
					t.Fatal("canonical value reused source key identity or omitted target")
				}
				for j, wrap := range access.Wraps {
					packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.keys[wrap.SubjectID], wrap.RSACiphertext, nil)
					if err != nil {
						t.Fatal(err)
					}
					wc, err := custody.ValueWrapCore(core, f.q.Bindings[j])
					if err != nil {
						t.Fatal(err)
					}
					digest, err := contract.RSAPacketContextDigest(wc)
					if err != nil {
						t.Fatal(err)
					}
					keys, err := custody.PacketKeys(packet, 1, digest)
					if err != nil {
						t.Fatal(err)
					}
					plain, err := custody.OpenValue(core, payload, keys)
					if err != nil {
						t.Fatal(err)
					}
					want := []byte("first secret")
					if i == 1 {
						want = []byte{}
					}
					equal := bytes.Equal(plain, want)
					clear(plain[:cap(plain)])
					clear(packet[:cap(packet)])
					if !equal {
						t.Fatal("recipient oracle mismatch")
					}
				}
			}
			freeze := applyFreezeRequest(t, f, comparison, plan, prepared)
			body, err := contract.EncodeCryptoFreezeRequest(freeze)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, metricContext, contract.CryptoFreeze, body)
			if reply.ResultCode != contract.CryptoSuccess {
				t.Fatalf("Freeze code %v", reply.ResultCode)
			}
			fact, err := contract.DecodeCryptoFreezeResult(reply.Body)
			if err != nil {
				t.Fatal(err)
			}
			public, err := contract.InspectPublicState(freeze.CandidatePublicState, f.q.Context.DomainID)
			if err != nil {
				t.Fatal(err)
			}
			exclusions, err := contract.InspectExclusions(freeze.Exclusions, f.q.Context.DomainID)
			if err != nil {
				t.Fatal(err)
			}
			wantFact, err := contract.CryptoFactsDigest(contract.CryptoFactsPreimage{CustodyInstanceID: r.InstanceID(), OperationRef: comparison.OperationRef, Context: f.q.Context, ComparisonOrCoverageDigest: comparison.ComparisonDigest, IdentityPlanDescriptor: freeze.IdentityPlanDescriptor, CandidatePublicStateDescriptor: public.Descriptor, CanonicalRowsDescriptor: freeze.CanonicalRowsDescriptor, ExclusionDescriptor: exclusions.Descriptor})
			if err != nil || fact.FactDigest != wantFact {
				t.Fatal("facts did not bind exact checked stage descriptors")
			}
			claim := contract.CryptoClaimRequest{OperationRef: comparison.OperationRef, Context: f.q.Context, IdentityPlanDescriptor: freeze.IdentityPlanDescriptor, CandidatePublicStateDescriptor: public.Descriptor, CanonicalRowsDescriptor: freeze.CanonicalRowsDescriptor, ExclusionDescriptor: exclusions.Descriptor, FactDigest: fact.FactDigest}
			claimBody, err := contract.EncodeCryptoClaimRequest(claim)
			if err != nil {
				t.Fatal(err)
			}
			reply = applyCall(r, metricContext, contract.CryptoClaim, claimBody)
			if reply.ResultCode != contract.CryptoSuccess || len(reply.Body) != 0 {
				t.Fatalf("Claim code %v", reply.ResultCode)
			}
			<-r.apply.done
			if r.apply.request.SealedInputs != nil || r.apply.prepared != nil {
				t.Fatal("Claim retained work buffers")
			}
			data := cryptoTelemetrySnapshot(t, reader)
			for _, op := range []string{"crypto.compare", "crypto.prepare", "crypto.freeze", "crypto.claim"} {
				assertCryptoTelemetryData(t, data, op, map[string]int64{"success": 1})
			}
			if got := applyCall(r, context.Background(), contract.CryptoClaim, claimBody); got.ResultCode != contract.CryptoAlreadyUsed {
				t.Fatal("duplicate Claim succeeded")
			}
			if f.route.privateCalls != 4 || !bytes.Equal(f.route.returned, make([]byte, len(f.route.returned))) {
				t.Fatal("reader private route or uncleared source packet")
			}
			r.retireApply()
			if r.slot != nil || r.apply != nil {
				t.Fatal("apply slot not retired")
			}
			if err := r.admitApply(f.q, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err == nil {
				t.Fatal("retired admission ID reused")
			}
			fresh := f.q
			fresh.Context.AdmissionID = consumerID("fresh apply admission")
			fresh.Context.SessionID = consumerID("fresh apply session")
			if err := r.admitApply(fresh, f.control, f.current, nil, f.route.CredentialRoute(), f.accepted, nil, f.support, f.deadline); err != nil {
				t.Fatal("fresh admission after joined retirement refused")
			}
		})
	}
}

// full_only: false
func TestPrivateDecryptFailureMeaningAcrossPreparationOwners(t *testing.T) {
	selected, route := consumerFixture(t)
	wrapCore, err := custody.ValueWrapCore(selected.Core, selected.Binding)
	if err != nil {
		t.Fatal(err)
	}
	packetContext, err := contract.RSAPacketContextDigest(wrapCore)
	if err != nil {
		t.Fatal(err)
	}
	current := applyCurrent{core: selected.Core, payload: selected.Payload, access: selected.Access, wrapIndex: 0, packetContext: packetContext}
	currentOwner := &applyAdmission{control: contract.ControlCore{CurrentControl: contract.CurrentControl{CurrentControlFields: contract.CurrentControlFields{Provider: contract.GCP}}}, routeID: route.CredentialRoute(), request: contract.CryptoCompareRequest{Bindings: []contract.BindingTableRow{selected.Binding}}}
	sourceFixture := applyFixture(t, false)
	sourceRuntime := sourceFixture.runtime(t, nil)
	accessOwner := &accessAdmission{request: contract.CryptoAccessReplaceRequest{BindingTable: []contract.BindingTableRow{selected.Binding}}}
	accessRow := contract.CompactRow{Coverage: contract.CoverageRow{MaterialKind: contract.ValueMaterialKind, SourceBindingIndex: 0, TargetBindingIndices: []uint16{0}}, ValueCore: selected.Core, BeforeAccessRecord: selected.Access}
	publication := publicationSelectedValue{Secret: &selected}
	projection, destination, target := publicationProjectionFixture(t, selected.DomainID, selected.Binding.SubjectID, &publication, contract.PublicationCreateWithValue)
	for _, tc := range []struct {
		name    string
		status  KeyStatus
		uses    KeyUses
		want    contract.CryptoResultCode
		outcome uint8
	}{
		{"local-route", KeyInvalid, KeyUses{}, contract.CryptoPrivateRouteUnavailable, 0},
		{"provider-profile", KeyInvalid, KeyUses{Failed: 1}, contract.CryptoPrivateRouteUnavailable, contract.KeyUseFailed},
		{"defective-response", KeyUnknown, KeyUses{Unknown: 1}, contract.CryptoResponseUnknown, contract.KeyUseUnknown},
		{"unavailable-service", KeyUnavailable, KeyUses{Unknown: 1}, contract.CryptoCustodyUnavailable, contract.KeyUseUnknown},
		// Only positive ciphertext rejection establishes authentication failure.
		{"positive-ciphertext-rejection", KeyAuthenticationFailed, KeyUses{Failed: 1}, contract.CryptoStoredAuthenticationFailed, contract.KeyUseFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuse := func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
				return PrivateResult{Status: tc.status, Uses: tc.uses}
			}
			route.override, sourceFixture.route.override = refuse, refuse
			for _, owner := range []string{"supplied-source", "ordinary-current", "generated-material", "access-replacement", "publication", "reconstruction"} {
				t.Run(owner, func(t *testing.T) {
					var reply contract.CryptoResponse
					var plain []byte
					var code contract.CryptoResultCode
					switch owner {
					case "supplied-source":
						plain, code = sourceRuntime.apply.openSealedInput(t.Context(), sourceFixture.route, 0, &reply)
					case "ordinary-current":
						plain, code = currentOwner.openCurrent(t.Context(), route, current, &reply)
					case "generated-material":
						plain, code = openMaterialPacket(t.Context(), route, selected.Binding, wrapCore, selected.Access.Wraps[0], contract.CryptoStoredAuthenticationFailed, &reply)
					case "access-replacement":
						_, code = accessOwner.rewrap(t.Context(), route, accessRow, &reply)
					case "publication":
						plain, reply.KeyUseRows, code = preparePublicationValue(t.Context(), projection, destination, target, nil, &publication, route, 0, maximumPublicationPayloadBytes)
					case "reconstruction":
						plain, reply.KeyUseRows, code = openConsumerValue(t.Context(), &session{ctx: t.Context(), deadline: time.Now().Add(time.Minute)}, route, selected, 0, packetContext)
					}
					defer clear(plain[:cap(plain)])
					want := tc.want
					if owner == "supplied-source" && tc.name == "positive-ciphertext-rejection" {
						want = contract.CryptoSourceAuthenticationFailed
					}
					if code != want || plain != nil {
						t.Fatalf("code=%d want=%d released=%t", code, want, plain != nil)
					}
					if tc.outcome == 0 {
						if len(reply.KeyUseRows) != 0 {
							t.Fatal("local refusal reported provider use")
						}
					} else if len(reply.KeyUseRows) != 1 || reply.KeyUseRows[0].Outcome != tc.outcome || reply.KeyUseRows[0].Count != 1 || reply.KeyUseRows[0].Purpose != contract.KeyUseMaterialOpen {
						t.Fatalf("key uses=%+v", reply.KeyUseRows)
					}
				})
			}
		})
	}
}
