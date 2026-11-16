package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

// These structural public-byte literals use schema11 and receipt-index schema2.
// Independent outer framing and the inherited-leaf provenance limits are
// recorded in tests/shared/testdata/README.md.
type storedVectorBytes struct {
	Hex    string `json:"hex"`
	SHA256 string `json:"sha256"`
	Length int    `json:"length"`
}

type storedVectorDescriptor struct {
	SHA256 string `json:"sha256"`
	Length uint64 `json:"length"`
	Count  uint32 `json:"count"`
}

type storedVectorState struct {
	NormalizedIdentityPlan storedVectorBytes        `json:"normalized_identity_plan"`
	RequestCore            storedVectorBytes        `json:"request_core"`
	MutationReceipt        storedVectorBytes        `json:"mutation_receipt"`
	ReceiptIndexes         storedVectorBytes        `json:"receipt_indexes"`
	ReceiptFragment        storedVectorBytes        `json:"receipt_fragment"`
	SupportPage            storedVectorBytes        `json:"support_page"`
	SupportRef             storedVectorBytes        `json:"support_ref"`
	FragmentPage           storedVectorBytes        `json:"fragment_page"`
	FragmentRef            storedVectorBytes        `json:"fragment_ref"`
	CompleteResult         storedVectorDescriptor   `json:"complete_result"`
	ChangedSubjects        storedVectorDescriptor   `json:"changed_subjects"`
	SuccessWindow          storedVectorDescriptor   `json:"success_window"`
	FailureWindow          storedVectorDescriptor   `json:"failure_window"`
	ReceiptOrder           storedVectorDescriptor   `json:"receipt_order"`
	ReceiptIndexBlob       string                   `json:"receipt_index_blob"`
	ReceiptFragmentID      string                   `json:"receipt_fragment_id"`
	EmptyResultVectors     []storedVectorDescriptor `json:"empty_result_vectors"`
	Root                   storedVectorBytes        `json:"root"`
	AdministrativeIndex    storedVectorBytes        `json:"administrative_index"`
	CurrentAccess          storedVectorBytes        `json:"current_access_core"`
	AccessRoot             string                   `json:"access_root"`
	RootRef                storedVectorBytes        `json:"root_ref"`
	HeadCore               storedVectorBytes        `json:"head_core"`
	IdentityPlan           storedVectorBytes        `json:"identity_plan"`
	ConditionalPlan        storedVectorBytes        `json:"conditional_plan"`
	Plan                   storedVectorBytes        `json:"plan"`
	AccessPage             storedVectorBytes        `json:"access_page"`
	AccessRef              storedVectorBytes        `json:"access_ref"`
	AccessDescriptor       storedVectorDescriptor   `json:"access_descriptor"`
}

type storedClosureVector struct {
	Name         string            `json:"name"`
	RecoveryMode uint8             `json:"recovery_mode"`
	Genesis      storedVectorState `json:"genesis"`
	FirstSecret  storedVectorState `json:"first_secret"`
}

type storedClosureVectors struct {
	SchemaVersion int `json:"schema_version"`
	Keys          struct {
		NormalSigning   storedVectorBytes `json:"normal_signing"`
		RecoverySigning storedVectorBytes `json:"recovery_signing"`
		AuthorityKEK    storedVectorBytes `json:"authority_kek"`
		RecoveryKEK     storedVectorBytes `json:"recovery_kek"`
	} `json:"keys"`
	AuthorityBindingDigest        string                 `json:"authority_binding_digest"`
	RecoveryBindingDigest         string                 `json:"recovery_binding_digest"`
	RecipientPage                 storedVectorBytes      `json:"recipient_page"`
	RecipientRef                  storedVectorBytes      `json:"recipient_ref"`
	RecipientDescriptor           storedVectorDescriptor `json:"recipient_descriptor"`
	OutputConfigurationPage       storedVectorBytes      `json:"output_configuration_page"`
	OutputConfigurationRef        storedVectorBytes      `json:"output_configuration_ref"`
	OutputConfigurationDescriptor storedVectorBytes      `json:"output_configuration_descriptor"`
	ValueEntryPage                storedVectorBytes      `json:"member_page"`
	ValueEntryPageRef             storedVectorBytes      `json:"member_ref"`
	Payload                       storedVectorBytes      `json:"payload"`
	ValueCore                     storedVectorBytes      `json:"value_core"`
	MaterialContextDigest         string                 `json:"material_context_digest"`
	Cases                         []storedClosureVector  `json:"cases"`
}

func storedVectorID(t testing.TB, value string) ID {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != 32 {
		t.Fatal("invalid fixed digest", err)
	}
	return ID(b)
}

func (v storedVectorBytes) bytes(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(v.Hex)
	if err != nil || len(b) != v.Length || sha256.Sum256(b) != storedVectorID(t, v.SHA256) {
		t.Fatal("invalid fixed literal length or SHA-256", err)
	}
	return b
}

func (v storedVectorDescriptor) descriptor(t testing.TB) contract.DescriptorVector {
	t.Helper()
	return contract.DescriptorVector{Digest: storedVectorID(t, v.SHA256), Length: v.Length, Count: v.Count}
}

func storedVectorRef(t testing.TB, kind Kind, object byte, v storedVectorBytes) Ref {
	t.Helper()
	return Ref{Kind: kind, Format: Version, Domain: fid(1), Object: fid(object), Digest: storedVectorID(t, v.SHA256), Length: uint32(v.Length)}
}

func assertStoredAdministrativeIndex(t *testing.T, vector storedVectorBytes, ref Ref, snapshot, object byte, pages []AdministrativePage) {
	t.Helper()
	body := vector.bytes(t)
	got, err := DecodeAdministrativeIndexPages([]AdministrativeIndexPage{{Ref: ref, Body: body}})
	if err != nil || got.Domain != fid(1) || got.Object != fid(object) || got.SliceSnapshot != fid(snapshot) || len(got.Groups) != 0 ||
		!reflect.DeepEqual(got.Pages, pages) {
		t.Fatal("fixed administrative index differs", err)
	}
	again, err := EncodeAdministrativeIndexPages(got)
	if err != nil || len(again) != 1 || again[0].Ref != ref || !bytes.Equal(again[0].Body, body) {
		t.Fatal("administrative index did not round trip", err)
	}
}

func assertStoredSupportPage(t *testing.T, vector storedVectorBytes, expected RequiredSupportPage) {
	t.Helper()
	body := vector.bytes(t)
	got, err := InspectRequiredSupportPage(body)
	if err != nil || got.Domain != expected.Domain || got.Object != expected.Object || got.Index != expected.Index || len(got.Records) != len(expected.Records) {
		t.Fatal("fixed support page differs", err)
	}
	for i, row := range got.Records {
		if !reflect.DeepEqual(contract.SupportRecord(row), expected.Records[i]) {
			t.Fatal("fixed support row differs", i)
		}
	}
	encoded, err := EncodeRequiredSupportPage(expected)
	if err != nil || !bytes.Equal(encoded, body) {
		t.Fatal("fixed support page did not encode", err)
	}
	for cut := range len(body) {
		if _, err := InspectRequiredSupportPage(body[:cut]); err == nil {
			t.Fatal("support page accepted truncation", cut)
		}
	}
	if _, err := InspectRequiredSupportPage(append(bytes.Clone(body), 0)); err == nil {
		t.Fatal("support page accepted trailing byte")
	}
}

func assertStoredCodec[T any](t *testing.T, vector storedVectorBytes, expected T, decode func([]byte) (T, error), encode func(T) ([]byte, error)) {
	t.Helper()
	body := vector.bytes(t)
	got, err := decode(body)
	if err != nil || !reflect.DeepEqual(got, expected) {
		t.Fatalf("fixed literal decoded to different public fields: %v", err)
	}
	encoded, err := encode(expected)
	if err != nil || !bytes.Equal(encoded, body) {
		t.Fatalf("known public fields did not encode to the independent literal: %v", err)
	}
	for cut := range len(body) {
		if _, err := decode(body[:cut]); err == nil {
			t.Fatalf("accepted truncation at byte %d", cut)
		}
	}
	if _, err := decode(append(bytes.Clone(body), 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
	if len(body) >= 7 && bytes.Equal(body[:4], []byte("ENKV")) && body[4] < 10 {
		if body[5] != 0 || body[6] != 11 {
			t.Fatal("fixed canonical container version differs")
		}
		for _, retired := range []byte{8, 9, 10} {
			old := bytes.Clone(body)
			old[6] = retired
			if _, err := decode(old); err == nil {
				t.Fatalf("accepted superseded canonical container version %d", retired)
			}
		}
	}
	// Owned decoding must survive invalidation of every caller-owned byte.
	clear(body)
	encoded, err = encode(got)
	if err != nil || !bytes.Equal(encoded, vector.bytes(t)) {
		t.Fatalf("decoded fields retained borrowed bytes: %v", err)
	}
}

func (v storedClosureVectors) bindings(t testing.TB, mode uint8) (contract.CurrentControl, contract.KMSBinding) {
	t.Helper()
	selector := "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-00000000000"
	signing := func(role uint8, id byte, key storedVectorBytes, suffix string) contract.PublicSigningBinding {
		return contract.PublicSigningBinding{Schema: contract.CanonicalSchema, Role: role, Provider: contract.AWS, SigningProfile: 1, BindingID: fid(id),
			KeySelector: selector + suffix, SPKI: key.bytes(t), Fingerprint: storedVectorID(t, key.SHA256),
			Binding: contract.BindingSubject{Domain: fid(1), Coordinate: fid(72), Store: fid(71), Trust: fid(75), PublicKey: storedVectorID(t, key.SHA256), Interpretation: fid(76), ControlIncarnationID: fid(id + 100), Epoch: 1}}
	}
	kms := func(id byte, key storedVectorBytes, suffix string) contract.KMSBinding {
		return contract.KMSBinding{BindingID: fid(id), BindingIncarnationID: fid(id + 100), BindingSerial: 1, Provider: contract.AWS, WrapProfile: 2, ProtectionClass: 2,
			KeySelector: selector + suffix, SPKI: key.bytes(t), Fingerprint: storedVectorID(t, key.SHA256)}
	}
	c := contract.CurrentControl{CurrentControlFields: contract.CurrentControlFields{Schema: contract.CanonicalSchema, Profile: 2, DomainID: fid(1), Provider: contract.AWS,
		StoreID: fid(71), CoordinateID: fid(72), NonBodyID: fid(73), TrustInterpretationID: fid(74), CompatibilityID: fid(77), CryptoSupportID: fid(78), AuthorityRecipientID: fid(7), AccessIncarnationID: contract.DeriveAccessIncarnationID(fid(1), fid(170)), AccessGeneration: 1},
		NormalSigning: signing(1, 70, v.Keys.NormalSigning, "2")}
	if mode == 1 {
		c.Recovery = &contract.RecoveryBindings{RoleID: fid(80), Signing: signing(2, 81, v.Keys.RecoverySigning, "3"), KMS: kms(82, v.Keys.RecoveryKEK, "4")}
	}
	return c, kms(9, v.Keys.AuthorityKEK, "1")
}

// full_only: false
func TestIndependentStoredGenesisAndFirstSecretClosures(t *testing.T) {
	b, err := os.ReadFile("../../tests/shared/testdata/stored-closure-v11.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors storedClosureVectors
	if err := json.Unmarshal(b, &vectors); err != nil || vectors.SchemaVersion != 5 || len(vectors.Cases) != 2 {
		t.Fatal("invalid fixed closure file", err)
	}
	for i, tc := range vectors.Cases {
		if tc.RecoveryMode != uint8(i) {
			t.Fatal("fixed closures must cover disabled and enabled recovery exactly once")
		}
		t.Run(tc.Name, func(t *testing.T) {
			control, authority := vectors.bindings(t, tc.RecoveryMode)
			configurationRef := storedVectorRef(t, contract.RequiredSupportKind, 112, vectors.OutputConfigurationPage)
			configurationRefWire, err := contract.AppendRef(nil, configurationRef, contract.CanonicalSchema)
			if err != nil || !bytes.Equal(vectors.OutputConfigurationRef.bytes(t), configurationRefWire) {
				t.Fatal("fixed output configuration reference differs")
			}
			configurationDescriptor, err := contract.InspectOutputConfigurationDescriptor(vectors.OutputConfigurationDescriptor.bytes(t))
			if err != nil || configurationDescriptor.Schema != contract.OutputConfigurationSchema || configurationDescriptor.TotalLength != 15 ||
				configurationDescriptor.SliceCount != 1 || configurationDescriptor.BindingCount != 0 || configurationDescriptor.RoutingLength != 5 {
				t.Fatal("fixed empty configuration descriptor differs", err)
			}
			configurationBody := vectors.OutputConfigurationPage.bytes(t)
			configurationPage, err := InspectRequiredSupportPage(configurationBody)
			if err != nil || len(configurationPage.Records) != 1 || configurationPage.Records[0].Kind != contract.OutputConfigurationSliceSupportKind {
				t.Fatal("fixed output configuration page differs", err)
			}
			configurationRow := contract.SupportRecord(configurationPage.Records[0])
			configurationSlice, err := contract.InspectOutputConfigurationSlice(configurationRow.Body)
			if err != nil || configurationSlice.ConfigurationDigest != configurationDescriptor.ConfigurationDigest ||
				configurationSlice.TotalLength != configurationDescriptor.TotalLength || configurationSlice.SliceCount != 1 ||
				!bytes.Equal(configurationSlice.SliceBytes, []byte{0, 5, 0, 0, 0, 0, 0, 0, 0, 5, 0, 3, 0, 0, 0}) {
				t.Fatal("fixed empty configuration slice differs", err)
			}
			configurationPageEncoded, err := EncodeRequiredSupportPage(RequiredSupportPage{Domain: fid(1), Object: fid(112),
				Records: []contract.SupportRecord{configurationRow}})
			if err != nil || !bytes.Equal(configurationPageEncoded, configurationBody) {
				t.Fatal("fixed output configuration page did not encode", err)
			}
			for cut := range configurationBody {
				if _, err := InspectRequiredSupportPage(configurationBody[:cut]); err == nil {
					t.Fatal("fixed configuration page accepted truncation", cut)
				}
			}
			if _, err := InspectRequiredSupportPage(append(bytes.Clone(configurationBody), 0)); err == nil {
				t.Fatal("fixed configuration page accepted trailing byte")
			}
			rp := RecipientPage{Domain: fid(1), Object: fid(8), Index: 0, Slots: [RecipientSlots]*Recipient{0: {RecipientID: fid(7), Status: Current, CurrentBinding: &authority}}}
			rr := storedVectorRef(t, RecipientKind, 8, vectors.RecipientPage)
			genesisIndex := storedVectorRef(t, contract.AdministrativeIndexKind, 110, tc.Genesis.AdministrativeIndex)
			supportRef := storedVectorRef(t, contract.RequiredSupportKind, 112, tc.Genesis.SupportPage)
			fragmentRef := storedVectorRef(t, contract.RequiredSupportKind, 113, tc.Genesis.FragmentPage)
			fragmentRef.Index = 1
			receiptRows := []contract.SupportRecord{{Kind: contract.MutationReceiptSupportKind, RecordID: fid(22), Body: tc.Genesis.MutationReceipt.bytes(t)}, configurationRow}
			fragmentID := storedVectorID(t, tc.Genesis.ReceiptFragmentID)
			fragmentRows := []contract.SupportRecord{{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: tc.Genesis.ReceiptFragment.bytes(t)}}
			assertStoredAdministrativeIndex(t, tc.Genesis.AdministrativeIndex, genesisIndex, 10, 110, []AdministrativePage{
				{Ref: supportRef, Spans: []AdministrativeSpan{{First: 0, Count: 2, Mandatory: true, GroupIndexes: []uint16{}}}, Rows: []AdministrativeRowSummary{
					{Kind: contract.MutationReceiptSupportKind, RecordID: fid(22), BodyLength: 471},
					{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: configurationRow.RecordID, BodyLength: 93}}},
				{Ref: fragmentRef, Spans: []AdministrativeSpan{{First: 0, Count: 1, Mandatory: true, GroupIndexes: []uint16{}}}, Rows: []AdministrativeRowSummary{
					{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, BodyLength: 184}}},
			})
			generated := EmptyGeneratedClosure()
			generated.SuccessWindow = contract.GeneratorDescriptor(tc.Genesis.SuccessWindow.descriptor(t))
			generated.FailureWindow = contract.GeneratorDescriptor(tc.Genesis.FailureWindow.descriptor(t))
			generated.ReceiptOrder = contract.GeneratorDescriptor(tc.Genesis.ReceiptOrder.descriptor(t))
			generated.Fragments = []FragmentLocation{{BlobID: storedVectorID(t, tc.Genesis.ReceiptIndexBlob), SupportPageIndex: 1}}
			root := Root{Domain: fid(1), Snapshot: fid(10), Transition: fid(11), Recipients: [contract.MaxRecipientPages]*Ref{0: &rr}, Generated: generated, GCPlans: contract.EmptyGCOwnersDescriptor(), AdministrativeIndex: genesisIndex, AdministrativeIndexShards: []Ref{},
				RequiredSupport: []Ref{supportRef, fragmentRef}, RequiredSupportRecordCount: 3, OutputConfiguration: configurationDescriptor,
				CurrentAccess: contract.CurrentAccessSection{Core: contract.CurrentAccessCore{CurrentControl: control, RecipientRefsDescriptor: vectors.RecipientDescriptor.descriptor(t), AccessPageRefs: []Ref{}, AccessRecordsDescriptor: tc.Genesis.AccessDescriptor.descriptor(t)}, AccessRoot: storedVectorID(t, tc.Genesis.AccessRoot)},
				Names:         []NameEntry{}, RecipientCount: 1, ChildCount: 4, ChildEncodedBytes: uint64(vectors.RecipientPage.Length + tc.Genesis.AdministrativeIndex.Length + tc.Genesis.SupportPage.Length + tc.Genesis.FragmentPage.Length)}
			head := HeadCore{Form: GenesisHead, Domain: fid(1), Revision: fid(20), Root: storedVectorRef(t, RootKind, 10, tc.Genesis.Root), Store: fid(71), Trust: fid(75), Coordinate: fid(72), NonBody: fid(73), Interpretation: fid(76), Epoch: 1}
			identity := contract.IdentityPlan{Operation: fid(22), Transition: fid(11), Snapshot: fid(10), Revision: fid(20), Rows: []contract.IdentityRow{}, Pages: []contract.IdentityPage{{Kind: RecipientKind, Index: 0, Object: fid(8)}, {Kind: contract.RequiredSupportKind, Index: 0, Object: fid(112)}, {Kind: contract.RequiredSupportKind, Index: 1, Object: fid(113)}, {Kind: contract.AdministrativeIndexKind, Index: 0, Object: fid(110)}}}
			conditional := ConditionalPlan{Family: contract.AWS, Store: fid(71), Coordinate: fid(72), NonBody: fid(73), Condition: contract.AbsentHeadCondition(), HeadCore: storedVectorID(t, tc.Genesis.HeadCore.SHA256), HeadCoreLength: 349}
			plan := GenesisPlanCore{DescriptorDigest: fid(21), IdentityPlan: identity, Root: root, HeadCore: head, ConditionalPlan: conditional, RecoveryMode: tc.RecoveryMode,
				Probes: []contract.InitProbePlanRow{{ProbeID: fid(23), SubjectKind: 1, SubjectID: fid(7), BindingID: fid(9), PublicBindingDigest: storedVectorID(t, vectors.AuthorityBindingDigest)}}}
			if tc.RecoveryMode == 1 {
				plan.K3ChallengeID = fid(85)
				plan.Probes = append(plan.Probes, contract.InitProbePlanRow{ProbeID: fid(84), SubjectKind: 2, SubjectID: fid(80), BindingID: fid(82), PublicBindingDigest: storedVectorID(t, vectors.RecoveryBindingDigest)})
			}
			normalized := contract.GenesisIdentityPlanCore{DomainID: fid(1), DescriptorDigest: fid(21), IdentityPlan: identity, RecoveryMode: tc.RecoveryMode, K3ChallengeID: plan.K3ChallengeID, Probes: plan.Probes}
			request := contract.GenesisRequestCore{InitID: fid(22), DomainID: fid(1), DescriptorDigest: fid(21), GenesisIdentityPlanDigest: storedVectorID(t, tc.Genesis.NormalizedIdentityPlan.SHA256), SetupDigest: fid(25), Expiry: 1,
				RecoveryMode: tc.RecoveryMode, InitOwnerDecision: 1, RecoveryLossAcknowledgement: 1 - tc.RecoveryMode}
			receipt := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: contract.OperationInitializeDomain,
				StateResult: contract.ReceiptStateSuccess, EffectSummary: contract.ReceiptEffectNoChange, OutputSummary: contract.ReceiptOutputNotApplicable, EvidenceCeiling: contract.ReceiptEvidenceCanonical,
				DomainID: fid(1), OperationID: fid(22), RequestIdentityDigest: storedVectorID(t, tc.Genesis.RequestCore.SHA256), RequestedRevisionID: fid(20), ObservedRevisionID: fid(20),
				CanonicalOutcome: contract.ReceiptCanonicalSelected, ChangedSubjects: contract.GeneratorDescriptor(tc.Genesis.ChangedSubjects.descriptor(t)), CompleteResult: contract.GeneratorDescriptor(tc.Genesis.CompleteResult.descriptor(t))}
			receiptIndexes := contract.MutationReceiptIndexes{Successes: []ID{fid(22)}, Failures: []ID{}, Order: []ID{fid(22)}}
			fragment := contract.GeneratedFragment{Schema: 1, BlobID: storedVectorID(t, tc.Genesis.ReceiptIndexBlob), Count: 1, TotalLength: 98, WholeDigest: storedVectorID(t, tc.Genesis.ReceiptIndexes.SHA256), Payload: tc.Genesis.ReceiptIndexes.bytes(t)}
			t.Run("genesis-normalized-identity", func(t *testing.T) {
				assertStoredCodec(t, tc.Genesis.NormalizedIdentityPlan, normalized, contract.DecodeGenesisIdentityPlanCore, contract.EncodeGenesisIdentityPlanCore)
			})
			t.Run("genesis-request", func(t *testing.T) {
				assertStoredCodec(t, tc.Genesis.RequestCore, request, contract.DecodeGenesisRequestCore, contract.EncodeGenesisRequestCore)
			})
			t.Run("genesis-receipt", func(t *testing.T) {
				assertStoredCodec(t, tc.Genesis.MutationReceipt, receipt, contract.InspectCompactMutationReceipt, contract.EncodeCompactMutationReceipt)
				changed, err := contract.ChangedSubjectDescriptor(nil)
				if err != nil || changed != receipt.ChangedSubjects {
					t.Fatal("genesis changed-subject vector differs", err)
				}
				empty := contract.EmptyMutationResultDescriptors()
				if len(tc.Genesis.EmptyResultVectors) != len(empty) {
					t.Fatal("incomplete empty result vector literals")
				}
				for i, expected := range tc.Genesis.EmptyResultVectors {
					if empty[i] != contract.GeneratorDescriptor(expected.descriptor(t)) {
						t.Fatal("empty result vector differs", i)
					}
				}
				planned := contract.CompactMutationReceiptPlan(receipt)
				planned.RequestIdentityDigest, planned.CompleteResult = ID{}, contract.GeneratorDescriptor{}
				complete, err := contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: planned, RequestCoreDigest: receipt.RequestIdentityDigest,
					ChangedAccess: empty[0], Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
				if err != nil || complete != receipt.CompleteResult {
					t.Fatal("complete genesis result differs", err)
				}
			})
			t.Run("genesis-receipt-indexes", func(t *testing.T) {
				assertStoredCodec(t, tc.Genesis.ReceiptIndexes, receiptIndexes, contract.InspectMutationReceiptIndexes, contract.EncodeMutationReceiptIndexes)
				success, failure, order, err := receiptIndexes.Descriptors()
				if err != nil || success != root.Generated.SuccessWindow || failure != root.Generated.FailureWindow || order != root.Generated.ReceiptOrder {
					t.Fatal("genesis receipt windows differ", err)
				}
				blob, err := contract.MutationReceiptIndexBlobID(fid(1), success, failure, order)
				if err != nil || blob != fragment.BlobID {
					t.Fatal("genesis receipt index identity differs", err)
				}
			})
			t.Run("genesis-receipt-fragment", func(t *testing.T) {
				assertStoredCodec(t, tc.Genesis.ReceiptFragment, fragment, contract.DecodeGeneratedFragment, contract.EncodeGeneratedFragment)
				id, err := contract.GeneratorFragmentID(fragment.BlobID, 0)
				if err != nil || id != fragmentID {
					t.Fatal("genesis fragment identity differs", err)
				}
			})
			t.Run("genesis-support-pages", func(t *testing.T) {
				assertStoredSupportPage(t, tc.Genesis.SupportPage, RequiredSupportPage{Domain: fid(1), Object: fid(112), Records: receiptRows})
				assertStoredSupportPage(t, tc.Genesis.FragmentPage, RequiredSupportPage{Domain: fid(1), Object: fid(113), Index: 1, Records: fragmentRows})
				support, err := InspectRequiredSupportPage(tc.Genesis.SupportPage.bytes(t))
				if err != nil {
					t.Fatal(err)
				}
				fragments, err := InspectRequiredSupportPage(tc.Genesis.FragmentPage.bytes(t))
				if err != nil {
					t.Fatal(err)
				}
				if err := ValidateFragmentDirectory(root.Generated.Fragments, []RequiredSupportPageView{support, fragments}); err != nil {
					t.Fatal("genesis fragment closure differs", err)
				}
			})
			t.Run("recipient-page", func(t *testing.T) {
				assertStoredCodec(t, vectors.RecipientPage, rp, DecodeRecipientPage, EncodeRecipientPage)
			})
			t.Run("genesis-root", func(t *testing.T) { assertStoredCodec(t, tc.Genesis.Root, root, DecodeRoot, EncodeRoot) })
			t.Run("genesis-head", func(t *testing.T) { assertStoredCodec(t, tc.Genesis.HeadCore, head, DecodeHeadCore, EncodeHeadCore) })
			t.Run("genesis-identity", func(t *testing.T) {
				assertStoredCodec(t, tc.Genesis.IdentityPlan, identity, contract.DecodeIdentityPlan, contract.EncodeIdentityPlan)
			})
			t.Run("genesis-condition", func(t *testing.T) {
				assertStoredCodec(t, tc.Genesis.ConditionalPlan, conditional, DecodeConditionalPlan, EncodeConditionalPlan)
			})
			t.Run("genesis-plan", func(t *testing.T) {
				assertStoredCodec(t, tc.Genesis.Plan, plan, DecodeGenesisPlanCore, EncodeGenesisPlanCore)
			})
			t.Run("genesis-access", func(t *testing.T) {
				assertStoredCodec(t, tc.Genesis.CurrentAccess, root.CurrentAccess.Core, contract.DecodeCurrentAccessCore, contract.EncodeCurrentAccessCore)
			})
			if got, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: fid(1), Refs: []Ref{rr}}); err != nil || got != vectors.RecipientDescriptor.descriptor(t) {
				t.Fatal("recipient commitment differs from fixed expected digest", err)
			}
			if got, err := contract.PublicBindingDigest(authority); err != nil || got != storedVectorID(t, vectors.AuthorityBindingDigest) {
				t.Fatal("authority binding commitment differs from fixed expected digest", err)
			}
			if tc.RecoveryMode == 1 {
				if got, err := contract.PublicBindingDigest(control.Recovery.KMS); err != nil || got != storedVectorID(t, vectors.RecoveryBindingDigest) {
					t.Fatal("recovery binding commitment differs from fixed expected digest", err)
				}
			}
			if got, err := contract.AccessRecordsDescriptor(fid(1), nil); err != nil || got != tc.Genesis.AccessDescriptor.descriptor(t) {
				t.Fatal("empty access commitment differs from fixed expected digest", err)
			}
			if got, err := contract.AccessRoot(root.CurrentAccess.Core); err != nil || got != storedVectorID(t, tc.Genesis.AccessRoot) {
				t.Fatal("genesis access root differs from fixed expected digest", err)
			}

			valueCore := contract.ValueCore{ValueSource: 1, Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: fid(77), CryptoSupportID: fid(78), DomainID: fid(1), Name: "sample", EntryIncarnationID: fid(35), ValueStateID: fid(36), OriginSnapshotID: fid(30), OriginTransitionID: fid(33), DataKeyID: fid(37), DataKeyEpoch: 1, CommitmentKeyID: fid(38), CommitmentKeyEpoch: 1, ContentLength: 4, InputEncoding: contract.InputEncodingRaw, RetainedLength: 4}
			payload := contract.CanonicalPayload{Profile: 2, CryptoSupportID: fid(78), DataKeyID: fid(37), DataKeyEpoch: 1, CommitmentKeyID: fid(38), CommitmentKeyEpoch: 1, ContentLength: 4, Nonce: [12]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, SemanticCommitment: fid(39), PackageCheck: fid(40), Ciphertext: bytes.Repeat([]byte{0xa6}, 20), InputEncoding: contract.InputEncodingRaw, RetainedLength: 4}
			entryPage := ValueEntryPage{Domain: fid(1), Object: fid(31), Index: 0, Slots: [PageSlots]*ValueEntry{0: {Name: "sample", Incarnation: fid(35), ValueState: fid(36), OriginSnapshot: fid(30), OriginTransition: fid(33), ValueSource: Supplied, ConfidentialityClass: Secret, Recipients: []ID{fid(7)}, ValueBytes: vectors.Payload.bytes(t), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 4, RetainedLength: 4}}}
			access := AccessPage{Domain: fid(1), Object: fid(32), Index: 0, Records: []contract.AccessRecord{{Schema: contract.CanonicalSchema, MaterialKind: 1, MaterialID: fid(36), MaterialContextDigest: storedVectorID(t, vectors.MaterialContextDigest), PackageCheck: fid(40),
				Wraps: []contract.WrapRow{{SubjectKind: 1, SubjectID: fid(7), BindingID: fid(9), BindingSerial: 1, PublicBindingDigest: storedVectorID(t, vectors.AuthorityBindingDigest), RSACiphertext: bytes.Repeat([]byte{0xa5}, 384)}}}}}
			if tc.RecoveryMode == 1 {
				access.Records[0].Wraps = append(access.Records[0].Wraps, contract.WrapRow{SubjectKind: 2, SubjectID: fid(80), BindingID: fid(82), BindingSerial: 1, PublicBindingDigest: storedVectorID(t, vectors.RecoveryBindingDigest), RSACiphertext: bytes.Repeat([]byte{0xb5}, 384)})
			}
			mr, ar := storedVectorRef(t, ValueEntryPageKind, 31, vectors.ValueEntryPage), storedVectorRef(t, AccessKind, 32, tc.FirstSecret.AccessPage)
			selected := root
			selected.Generated = EmptyGeneratedClosure()
			selected.RequiredSupport = []Ref{configurationRef}
			selected.RequiredSupportRecordCount = 1
			selected.Snapshot, selected.Transition = fid(30), fid(33)
			selected.ValueEntryPages = [contract.MaxValueEntryPages]*Ref{0: &mr}
			selected.Names = []NameEntry{{Name: "sample", Slot: 0}}
			selected.ValueEntryCount, selected.SecretCount, selected.RawBytes, selected.MembershipCount = 1, 1, 4, 1
			selected.SecretOrdinaryWrapCount, selected.AccessRecordCount, selected.ChildCount = 1, 1, 5
			selectedIndex := storedVectorRef(t, contract.AdministrativeIndexKind, 111, tc.FirstSecret.AdministrativeIndex)
			assertStoredAdministrativeIndex(t, tc.FirstSecret.AdministrativeIndex, selectedIndex, 30, 111, []AdministrativePage{{Ref: configurationRef,
				Spans: []AdministrativeSpan{{First: 0, Count: 1, Mandatory: true, GroupIndexes: []uint16{}}},
				Rows:  []AdministrativeRowSummary{{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: configurationRow.RecordID, BodyLength: 93}}}})
			selected.AdministrativeIndex = selectedIndex
			selected.ChildEncodedBytes = uint64(vectors.RecipientPage.Length + vectors.ValueEntryPage.Length + tc.FirstSecret.AccessPage.Length + tc.FirstSecret.AdministrativeIndex.Length + vectors.OutputConfigurationPage.Length)
			selected.CurrentAccess.Core.AccessGeneration = 2
			selected.CurrentAccess.Core.AccessPageRefs = []Ref{ar}
			selected.CurrentAccess.Core.AccessRecordsDescriptor = tc.FirstSecret.AccessDescriptor.descriptor(t)
			selected.CurrentAccess.AccessRoot = storedVectorID(t, tc.FirstSecret.AccessRoot)
			t.Run("value-core", func(t *testing.T) {
				assertStoredCodec(t, vectors.ValueCore, valueCore, contract.DecodeValueCore, contract.EncodeValueCore)
			})
			t.Run("payload", func(t *testing.T) {
				assertStoredCodec(t, vectors.Payload, payload, contract.DecodeCanonicalPayload, contract.EncodeCanonicalPayload)
			})
			t.Run("member-page", func(t *testing.T) {
				assertStoredCodec(t, vectors.ValueEntryPage, entryPage, DecodeValueEntryPage, EncodeValueEntryPage)
			})
			t.Run("access-page", func(t *testing.T) {
				assertStoredCodec(t, tc.FirstSecret.AccessPage, access, DecodeAccessPage, EncodeAccessPage)
			})
			t.Run("first-secret-root", func(t *testing.T) { assertStoredCodec(t, tc.FirstSecret.Root, selected, DecodeRoot, EncodeRoot) })
			t.Run("first-secret-access", func(t *testing.T) {
				assertStoredCodec(t, tc.FirstSecret.CurrentAccess, selected.CurrentAccess.Core, contract.DecodeCurrentAccessCore, contract.EncodeCurrentAccessCore)
			})
			if got, err := contract.ValueMaterialContextDigest(valueCore); err != nil || got != storedVectorID(t, vectors.MaterialContextDigest) {
				t.Fatal("material context differs from fixed expected digest", err)
			}
			if got, err := contract.AccessRecordsDescriptor(fid(1), access.Records); err != nil || got != tc.FirstSecret.AccessDescriptor.descriptor(t) {
				t.Fatal("current access commitment differs from fixed expected digest", err)
			}
			if got, err := contract.AccessRoot(selected.CurrentAccess.Core); err != nil || got != storedVectorID(t, tc.FirstSecret.AccessRoot) {
				t.Fatal("first-secret access root differs from fixed expected digest", err)
			}
			for _, check := range []struct {
				name       string
				ref        Ref
				body, wire storedVectorBytes
			}{{"recipient", rr, vectors.RecipientPage, vectors.RecipientRef}, {"genesis-root", head.Root, tc.Genesis.Root, tc.Genesis.RootRef},
				{"genesis-support", supportRef, tc.Genesis.SupportPage, tc.Genesis.SupportRef}, {"genesis-fragment", fragmentRef, tc.Genesis.FragmentPage, tc.Genesis.FragmentRef},
				{"member", mr, vectors.ValueEntryPage, vectors.ValueEntryPageRef}, {"access", ar, tc.FirstSecret.AccessPage, tc.FirstSecret.AccessRef},
				{"first-secret-root", storedVectorRef(t, RootKind, 30, tc.FirstSecret.Root), tc.FirstSecret.Root, tc.FirstSecret.RootRef}} {
				t.Run(check.name+"-reference", func(t *testing.T) {
					got, err := Reference(check.ref.Kind, check.ref.Domain, check.ref.Object, check.ref.Index, check.body.bytes(t))
					if err != nil || got != check.ref {
						t.Fatal("child reference differs from fixed expected digest/length", err)
					}
					assertStoredCodec(t, check.wire, check.ref, func(b []byte) (Ref, error) { return contract.DecodeRef(b, contract.CanonicalSchema) }, func(r Ref) ([]byte, error) { return contract.AppendRef(nil, r, contract.CanonicalSchema) })
				})
			}
			for _, state := range []struct {
				vector    storedVectorState
				generated GeneratedClosure
			}{{tc.Genesis, root.Generated}, {tc.FirstSecret, selected.Generated}} {
				damaged := state.vector.Root.bytes(t)
				closure, err := EncodeGeneratedClosure(state.generated)
				if err != nil {
					t.Fatal(err)
				}
				// Unsupported precedes the exact generated closure and 76-byte GC relation.
				damaged[len(damaged)-76-len(closure)-1] = 1
				if _, err := DecodeRoot(damaged); err == nil {
					t.Fatal("root accepted an unsupported feature")
				}
			}
			damaged := tc.FirstSecret.AccessPage.bytes(t)
			damaged[73], damaged[74] = 0, 0 // Nonempty page cannot claim zero records.
			if _, err := DecodeAccessPage(damaged); err == nil {
				t.Fatal("access page accepted an incorrect record count")
			}
		})
	}
}
