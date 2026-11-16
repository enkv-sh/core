package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

type publicReplacementReceipt struct {
	Schema            string `json:"schema"`
	Bytes             string `json:"receipt_hex"`
	Operation         uint16 `json:"original_operation_kind"`
	OperationID       string `json:"original_operation_id"`
	Identity          string `json:"original_request_identity"`
	State             uint16 `json:"original_state_result"`
	WarningBits       uint64 `json:"original_warning_bits"`
	CandidateSelected bool   `json:"candidate_selected"`
	Evidence          string `json:"evidence_limit"`
}
type publicReplacementReply struct {
	Schema      string                    `json:"schema"`
	Kind        string                    `json:"operation_kind"`
	State       string                    `json:"state_result"`
	Effect      string                    `json:"effect_summary"`
	Output      string                    `json:"output_summary"`
	Request     string                    `json:"request_id"`
	Operation   string                    `json:"operation_id,omitempty"`
	Identity    json.RawMessage           `json:"request_identity"`
	Replay      string                    `json:"replay_identity"`
	Domain      string                    `json:"domain_id,omitempty"`
	Requested   string                    `json:"requested_revision_id,omitempty"`
	Observed    string                    `json:"observed_revision_id,omitempty"`
	Snapshot    string                    `json:"observed_snapshot_id,omitempty"`
	Evidence    string                    `json:"evidence_ceiling"`
	Unknown     bool                      `json:"commit_may_have_occurred"`
	WarningBits uint8                     `json:"current_warning_bits"`
	Warnings    []string                  `json:"warning_summary"`
	Result      operatorCLIResult         `json:"result"`
	Effects     []struct{}                `json:"effects"`
	Outputs     []struct{}                `json:"outputs"`
	Duties      []struct{}                `json:"duties"`
	Hazards     []struct{}                `json:"hazards"`
	Capsule     string                    `json:"capsule_policy"`
	PayloadKind string                    `json:"operation_payload"`
	Payload     json.RawMessage           `json:"payload"`
	Receipt     *publicReplacementReceipt `json:"stored_receipt,omitempty"`
	Query       *publicReplacementQuery   `json:"query,omitempty"`
	NoWork      json.RawMessage           `json:"no_work_observation,omitempty"`
	Diagnostics []json.RawMessage         `json:"diagnostics"`
	Delivery    publicReplacementDelivery `json:"delivery"`
}

type publicReplacementDelivery struct {
	Path           string                     `json:"path"`
	Status         string                     `json:"status"`
	Failed         bool                       `json:"failed"`
	CleanupFailed  bool                       `json:"cleanup_failed"`
	RecoverySource string                     `json:"recovery_source,omitempty"`
	EditablePath   string                     `json:"editable_path,omitempty"`
	GeneratedPath  string                     `json:"generated_path,omitempty"`
	Readback       *publicReplacementReadback `json:"readback,omitempty"`
}

type publicReplacementReadback struct {
	EditableDigest  string `json:"editable_digest"`
	GeneratedDigest string `json:"generated_digest"`
}

func publicReplacementDeliveryMatches(delivery publicReplacementDelivery, output string, pair publicPairImage) bool {
	if delivery.Status != "delivered" || delivery.Failed || delivery.CleanupFailed || delivery.RecoverySource != "" || delivery.Path != output || delivery.EditablePath != output || delivery.Readback == nil {
		return false
	}
	editable, present := pair.Files[output]
	var document struct{ Generated string }
	if !present || json.Unmarshal(editable, &document) != nil || document.Generated == "" {
		return false
	}
	generatedPath := filepath.Join(filepath.Dir(output), filepath.FromSlash(document.Generated))
	generated, present := pair.Files[generatedPath]
	return present && delivery.GeneratedPath == generatedPath && delivery.Readback.EditableDigest == bodyDigest(editable) && delivery.Readback.GeneratedDigest == bodyDigest(generated)
}

// full_only: false
func TestPublicReplacementDeliveryRequiresExactPairReadback(t *testing.T) {
	const output = "/ABSOLUTE/owned/successor.json"
	const generated = "/ABSOLUTE/owned/.enkv/prod.generated.json"
	for _, condition := range []string{"delivered", "read-back", "pending", "unproved", "failed", "cleanup-failed", "recovery-source", "path", "editable-path", "generated-path", "missing-readback", "editable-digest", "generated-digest", "missing-editable", "missing-generated", "changed-editable", "changed-generated"} {
		t.Run(condition, func(t *testing.T) {
			pair := publicPairImage{Files: map[string][]byte{
				output: []byte(`{"generated":".enkv/prod.generated.json"}`), generated: []byte(`{"fixture":"generated"}`),
			}}
			// SHA-256 of the two literal fixture byte strings, computed with Python hashlib.
			delivery := publicReplacementDelivery{Path: output, Status: "delivered", EditablePath: output, GeneratedPath: generated,
				Readback: &publicReplacementReadback{
					EditableDigest:  "99593055ce633a9c3852413f78486958d1ac1c3b279eacb0f5cfd150bde92e5b",
					GeneratedDigest: "e879d5eff595c7f4bea019f46455c1252a0049e4c915c24a1943d1d143d50d8e",
				}}
			switch condition {
			case "read-back", "pending", "unproved":
				delivery.Status = condition
			case "failed":
				delivery.Failed = true
			case "cleanup-failed":
				delivery.CleanupFailed = true
			case "recovery-source":
				delivery.RecoverySource = "/ABSOLUTE/owned/original.json"
			case "path":
				delivery.Path = "/ABSOLUTE/owned/other.json"
			case "editable-path":
				delivery.EditablePath = "/ABSOLUTE/owned/other.json"
			case "generated-path":
				delivery.GeneratedPath = "/ABSOLUTE/owned/.enkv/other.generated.json"
			case "missing-readback":
				delivery.Readback = nil
			case "editable-digest":
				delivery.Readback.EditableDigest = strings.Repeat("3", 64)
			case "generated-digest":
				delivery.Readback.GeneratedDigest = strings.Repeat("3", 64)
			case "missing-editable":
				delete(pair.Files, output)
			case "missing-generated":
				delete(pair.Files, generated)
			case "changed-editable":
				pair.Files[output] = append(pair.Files[output], '\n')
			case "changed-generated":
				pair.Files[generated] = append(pair.Files[generated], '\n')
			}
			if publicReplacementDeliveryMatches(delivery, output, pair) != (condition == "delivered") {
				t.Fatal("replacement delivery accepted an incomplete status or changed pair/readback relation")
			}
		})
	}
}

// full_only: false
func TestPublicReplacementDeliveryViewsDecodeCurrentFields(t *testing.T) {
	const delivered = `{"delivery":{"path":"/ABSOLUTE/owned/successor.json","status":"delivered","failed":false,"cleanup_failed":false,"editable_path":"/ABSOLUTE/owned/successor.json","generated_path":"/ABSOLUTE/owned/.enkv/prod.generated.json","readback":{"editable_digest":"1111111111111111111111111111111111111111111111111111111111111111","generated_digest":"2222222222222222222222222222222222222222222222222222222222222222"}}}`
	pending := strings.Replace(delivered, `"status":"delivered","failed":false`, `"status":"pending","failed":true,"recovery_source":"/ABSOLUTE/owned/original.json"`, 1)
	for _, fixture := range []struct{ name, body string }{{"delivered", delivered}, {"pending", pending}} {
		for _, consumer := range []string{"authority-operator", "replacement-matrix"} {
			t.Run(fixture.name+"/"+consumer, func(t *testing.T) {
				var output any
				if consumer == "authority-operator" {
					output = &operatorAuthorityReply{}
				} else {
					output = &publicReplacementReply{}
				}
				if err := operatorStrictJSON([]byte(fixture.body), output); err != nil {
					t.Fatal("current replacement delivery fields were refused", err)
				}
				var delivery any
				switch reply := output.(type) {
				case *operatorAuthorityReply:
					delivery = reply.Delivery
				case *publicReplacementReply:
					delivery = reply.Delivery
				}
				encoded, err := json.Marshal(delivery)
				var actual any
				var expected struct{ Delivery any }
				if err != nil || json.Unmarshal(encoded, &actual) != nil || json.Unmarshal([]byte(fixture.body), &expected) != nil || !reflect.DeepEqual(actual, expected.Delivery) {
					t.Fatal("replacement delivery view lost exact paths, readback digests or recovery facts")
				}
				unknown := strings.Replace(fixture.body, `"delivery":{`, `"delivery":{"unknown":true,`, 1)
				if operatorStrictJSON([]byte(unknown), output) == nil {
					t.Fatal("replacement delivery view accepted an unknown field")
				}
			})
		}
	}
}

type publicReplacementQuery struct {
	Schema             string                    `json:"schema"`
	Operation          string                    `json:"operation"`
	Semantic           uint16                    `json:"semantic_operation"`
	Domain             string                    `json:"expected_domain"`
	Store              string                    `json:"store_id"`
	Coordinate         string                    `json:"coordinate_id"`
	NonBody            string                    `json:"non_body_id"`
	Descriptor         string                    `json:"store_descriptor_digest"`
	SourceBasis        string                    `json:"source_basis_digest"`
	SuccessorBasis     string                    `json:"successor_basis_digest"`
	AuthenticatedBasis string                    `json:"authenticated_basis_digest,omitempty"`
	Source             operatorQuerySource       `json:"source_pins"`
	Output             operatorQuerySource       `json:"output_pins"`
	Observation        *operatorQueryObservation `json:"observation"`
	Nonce              string                    `json:"request_nonce"`
	Target             uint8                     `json:"target"`
	RequiredKind       uint16                    `json:"required_stored_kind"`
	Authorizer         uint8                     `json:"authorizer"`
	Signing            string                    `json:"signing_selector,omitempty"`
	Encryption         string                    `json:"encryption_selector,omitempty"`
	Material           uint8                     `json:"material_source"`
	OriginalOperation  string                    `json:"original_operation_id"`
	OriginalIdentity   string                    `json:"original_request_identity"`
	Candidate          string                    `json:"candidate_digest"`
	Requested          string                    `json:"requested_revision_id"`
	Recipient          string                    `json:"recipient_id,omitempty"`
	Digest             string                    `json:"digest"`
}

func publicReplacementResult(t testing.TB, child publicChildResult, kind string) publicReplacementReply {
	t.Helper()
	var reply publicReplacementReply
	if len(child.Body) > operatorCLICaptureLimit || operatorStrictJSON(child.Body, &reply) != nil || reply.Schema != "ProductResult/v1" || reply.Kind != kind || reply.Effect != "not-applicable" || reply.Output != "not-applicable" || reply.Capsule != "none" || len(reply.Effects)+len(reply.Outputs)+len(reply.Duties)+len(reply.Hazards) != 0 || reply.Unknown != reply.Result.CommitMayHaveOccurred || reply.Result.Reason == "" || reply.Delivery.Failed || reply.Delivery.CleanupFailed {
		t.Fatal("replacement result envelope is not exact", child.Code)
	}
	return reply
}
func publicReplacementIdentity(t testing.TB, r publicReplacementReply) contract.ID {
	t.Helper()
	var text string
	if json.Unmarshal(r.Identity, &text) != nil {
		t.Fatal("admitted replacement identity is not scalar")
	}
	return publicReplacementID(t, text)
}
func publicReplacementStoredReceipt(t testing.TB, r publicReplacementReply, selected *StateSession, target string) string {
	t.Helper()
	if target == "authority" {
		if r.Receipt != nil {
			t.Fatal("Authority replacement invented a stored receipt")
		}
		return ""
	}
	if r.Receipt == nil {
		t.Fatal("receipt-bearing replacement omitted its stored bytes")
	}
	raw, err := hex.DecodeString(r.Receipt.Bytes)
	if err != nil || len(raw) != contract.CompactMutationReceiptLength {
		t.Fatal("replacement receipt is not exact bounded raw bytes")
	}
	row, err := contract.InspectCompactMutationReceipt(raw)
	kind := uint16(contract.OperationReplaceRecoveryKeysAndRoot)
	if target == "recipient" {
		kind = contract.OperationRotateRecipientKeyBinding
	}
	operation := publicReplacementID(t, r.Operation)
	identity := publicReplacementIdentity(t, r)
	if err != nil || row.OperationKind != kind || row.DomainID != selected.root.Domain || row.OperationID != operation || row.RequestIdentityDigest != identity || row.RequestedRevisionID != selected.head.Core.Revision || row.ObservedRevisionID != selected.head.Core.Revision || row.CanonicalOutcome != contract.ReceiptCanonicalSelected {
		t.Fatal("replacement raw receipt does not bind the exact selected candidate")
	}
	retained, body, found, err := selected.retainedMutationReceipt(operation)
	if err != nil || !found || retained != row || !bytes.Equal(body, raw) {
		t.Fatal("cold selected receipt differs from original output bytes", err)
	}
	return r.Receipt.Bytes
}

func publicReplacementID(t testing.TB, text string) contract.ID {
	t.Helper()
	id, ok := operatorParseID(text)
	if !ok {
		t.Fatal("replacement public identity is not exact canonical nonzero ID")
	}
	return id
}

func publicReplacementQueryMatches(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, r publicReplacementReply, selected *StateSession, source, output string, cell catalog.PublicReplacementCase, signing, encryption string) {
	t.Helper()
	if r.Query == nil {
		t.Fatal("replacement observation omitted its query identity")
	}
	wire := r.Query
	q := ReplacementQueryIdentity{Schema: wire.Schema, Operation: ReplacementReadOperation(wire.Operation), SemanticOperation: wire.Semantic, ExpectedDomain: publicReplacementID(t, wire.Domain), StoreID: publicReplacementID(t, wire.Store), CoordinateID: publicReplacementID(t, wire.Coordinate), NonBodyID: publicReplacementID(t, wire.NonBody), StoreDescriptorDigest: publicReplacementID(t, wire.Descriptor), SourceBasisDigest: publicReplacementID(t, wire.SourceBasis), SuccessorBasisDigest: publicReplacementID(t, wire.SuccessorBasis), AuthenticatedBasisDigest: publicReplacementID(t, wire.AuthenticatedBasis), RequestNonce: publicReplacementID(t, wire.Nonce), Target: ReplacementTarget(wire.Target), RequiredStoredKind: wire.RequiredKind, Goal: RoleReplacementGoal{ApprovalRole: wire.Authorizer, SigningSelector: wire.Signing, EncryptionSelector: wire.Encryption, MaterialSource: ReplacementMaterialSource(wire.Material)}, OriginalOperationID: publicReplacementID(t, wire.OriginalOperation), OriginalRequestIdentity: publicReplacementID(t, wire.OriginalIdentity), CandidateDigest: publicReplacementID(t, wire.Candidate), RequestedRevisionID: publicReplacementID(t, wire.Requested), Digest: publicReplacementID(t, wire.Digest)}
	pins := func(w operatorQuerySource) AdministrativeSourcePins {
		return AdministrativeSourcePins{FileID: publicReplacementID(t, w.FileID), Format: w.Format, EditableDigest: publicReplacementID(t, w.EditableDigest), GeneratedDigest: publicReplacementID(t, w.GeneratedDigest), EditableLength: w.EditableLength, GeneratedLength: w.GeneratedLength, HasGenerated: w.HasGenerated}
	}
	q.SourcePins, q.OutputPins = pins(wire.Source), pins(wire.Output)
	if wire.Recipient != "" {
		q.RecipientID = publicReplacementID(t, wire.Recipient)
	}
	if wire.Observation != nil {
		q.Observation = &AdministrativeObservation{DomainID: publicReplacementID(t, wire.Observation.Domain), Revision: publicReplacementID(t, wire.Observation.Revision), Snapshot: publicReplacementID(t, wire.Observation.Snapshot)}
	}
	sourceFacts := publicParsedSourceFacts(t, ctx, inv, input, budget, source)
	outputFacts := publicParsedSourceFacts(t, ctx, inv, input, budget, output)
	d := selected.store.Descriptor()
	sourcePublic := publicParsedSourceBasis(sourceFacts)
	outputPublic := publicParsedSourceBasis(outputFacts)
	beforeBasis, beforeReason := qualifyReaderPublicBasis(sourcePublic, selected.root.Domain, d)
	afterBasis, afterReason := qualifyReaderPublicBasis(outputPublic, selected.root.Domain, d)
	if beforeReason != "" || afterReason != "" {
		t.Fatal("independent replacement query basis refused", beforeReason, afterReason)
	}
	target := ReplacementTargetAuthority
	if cell.Target == "recovery" {
		target = ReplacementTargetRecovery
	}
	if cell.Target == "recipient" {
		target = ReplacementTargetRecipient
	}
	authorizer := uint8(contract.NormalSigningRole)
	if cell.Authorizer == "recovery" {
		authorizer = contract.RecoverySigningRole
	}
	material := ReplacementMaterialSource(0)
	if cell.MaterialSource == "authority" {
		material = ReplacementMaterialAuthority
	}
	if cell.MaterialSource == "recovery" {
		material = ReplacementMaterialRecovery
	}
	recipient := contract.ID{}
	if cell.Target == "recipient" {
		for _, id := range selected.valueEntry(selected.root.Names[0].Slot).Recipients {
			if id != selected.admission.recipient {
				recipient = id
			}
		}
	}
	if q.RecipientID != recipient || r.WarningBits != selected.root.WarningBits || q.SourceBasisDigest != beforeBasis.digest || q.SuccessorBasisDigest != afterBasis.digest || q.AuthenticatedBasisDigest != afterBasis.digest || q.RequestedRevisionID != selected.head.Core.Revision || r.Domain != hex.EncodeToString(selected.root.Domain[:]) || r.Observed != hex.EncodeToString(selected.head.Core.Revision[:]) || r.Snapshot != hex.EncodeToString(selected.root.Snapshot[:]) || r.Requested != "" || r.Result.RequestedRevision != "" || r.Result.ObservedRevision != r.Observed || r.Result.Outcome != "observed_current" || r.Result.Reason != "none" || r.Result.StoreReason != "" || r.Evidence != "canonical" || !q.Valid() || publicReplacementIdentity(t, r) != q.Digest || q.RequestNonce != publicReplacementID(t, r.Request) || q.ExpectedDomain != selected.root.Domain || q.StoreID != d.Identity || q.CoordinateID != d.Coordinate || q.NonBodyID != d.NonBody || q.StoreDescriptorDigest != administrativeStoreDescriptorDigest(d) || q.SourcePins != publicParsedSourcePins(sourceFacts) || q.OutputPins != publicParsedSourcePins(outputFacts) || q.Target != target || q.Goal != (RoleReplacementGoal{ApprovalRole: authorizer, SigningSelector: signing, EncryptionSelector: encryption, MaterialSource: material}) || q.Observation == nil || q.Observation.DomainID != selected.root.Domain || q.Observation.Revision != selected.head.Core.Revision || q.Observation.Snapshot != selected.root.Snapshot {
		t.Fatal("replacement query lost source, goal, nonce or independently authenticated selected state")
	}
}

func publicReplacementTransitionMatches(t testing.TB, r publicReplacementReply, before, after *StateSession, cell catalog.PublicReplacementCase) {
	t.Helper()
	var p struct {
		Schema      string `json:"schema"`
		Predecessor string `json:"predecessor_revision_id"`
		Requested   string `json:"requested_revision_id"`
		Observed    string `json:"observed_revision_id,omitempty"`
		Changed     struct {
			Count  uint32 `json:"count"`
			Digest string `json:"identity_root_digest"`
		} `json:"changed_subject_commitment"`
		Duties  []string `json:"live_duty_ids"`
		Hazards []string `json:"live_hazard_ids"`
	}
	count := uint32(0)
	if cell.Change != "encryption" {
		count += 4
	}
	if cell.Change != "signing" {
		count += 2
	}
	// One ordinary Recipient row and this one selected supplied ValueEntry.
	if cell.Target == "recipient" {
		count = 2
	}
	identity := publicReplacementIdentity(t, r)
	if !publicIdentityHex(r.Request) || r.Domain != hex.EncodeToString(after.root.Domain[:]) || r.Requested != hex.EncodeToString(after.head.Core.Revision[:]) || r.Observed != r.Requested || r.Snapshot != hex.EncodeToString(after.root.Snapshot[:]) || r.WarningBits != after.root.WarningBits || r.Evidence != "canonical" || r.Result.Outcome != "observed_current" || r.Result.Reason != "none" || r.Result.StoreReason != "" || r.Result.RequestedRevision != r.Requested || r.Result.ObservedRevision != r.Observed || operatorStrictJSON(r.Payload, &p) != nil || p.Schema != "TransitionPayload/v1" || publicReplacementID(t, p.Predecessor) != before.head.Core.Revision || publicReplacementID(t, p.Requested) != after.head.Core.Revision || publicReplacementID(t, p.Observed) != after.head.Core.Revision || p.Changed.Count != count || !publicIdentityHex(p.Changed.Digest) || len(p.Duties)+len(p.Hazards) != 0 || r.Replay != hex.EncodeToString(identity[:]) {
		t.Fatal("replacement transition lost exact predecessor, owner count, empty duties or original replay identity")
	}
	if r.Receipt != nil {
		raw, err := hex.DecodeString(r.Receipt.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := contract.InspectCompactMutationReceipt(raw)
		if err != nil || receipt.ChangedSubjects.Count != p.Changed.Count || hex.EncodeToString(receipt.ChangedSubjects.Digest[:]) != p.Changed.Digest {
			t.Fatal("replacement receipt and transition disagree on exact changed owners")
		}
	}
}
