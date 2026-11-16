package nativeprocess

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

type nativeSequenceFixture struct {
	server *workflowServer
	source string
	pair   workflowPair
	value  []byte
}

func nativeSequenceSetup(t *testing.T, cli, family string) nativeSequenceFixture {
	t.Helper()
	return nativeSequenceSetupRecovery(t, cli, family, true)
}

func nativeSequenceSetupRecovery(t *testing.T, cli, family string, recovery bool) nativeSequenceFixture {
	t.Helper()
	return nativeSequenceSetupOnServer(t, cli, newWorkflowServer(t, family, recovery), recovery)
}

func nativeSequenceSetupOnServer(t *testing.T, cli string, s *workflowServer, recovery bool) nativeSequenceFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	s.keys[s.selector(7)] = workflowKey{encryption: key, der: der, role: "successor-private"}
	source := filepath.Join(t.TempDir(), "configuration.json")
	if os.WriteFile(source, workflowSetup(t, s, recovery), 0600) != nil {
		t.Fatal("source setup failed")
	}
	workflowResult(t, workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", source, "--source-format", "json", "--json"), "success")
	pair := workflowReadPair(t, source)
	var editable map[string]any
	if json.Unmarshal(pair.editable, &editable) != nil {
		t.Fatal("editable source unavailable")
	}
	editable["entries"] = map[string]any{"binary": map[string]any{"confidentiality": "secret", "recipients": []string{"reader"}, "source": map[string]any{"kind": "supplied"}}}
	body, err := json.MarshalIndent(editable, "", "  ")
	if err != nil || os.WriteFile(source, append(body, '\n'), 0600) != nil {
		t.Fatal("supplied source declaration failed", err)
	}
	value := []byte{'s', 'e', 'l', 'e', 'c', 't', 'e', 'd', 0, 255, 7, 128}
	t.Cleanup(func() { clear(value) })
	pair = workflowPrepare(t, s, cli, source, "set", workflowReadPair(t, source), value)
	workflowResult(t, workflowRun(t, s, cli, "apply", observer.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json"), "success")
	head, _ := workflowHead(t, s)
	root := workflowRoot(t, s, head)
	if root.SecretCount != 1 || root.ValueEntryCount != 1 || len(workflowEntry(t, s, root).Recipients) != 2 {
		t.Fatal("fixture has no selected supplied material and Reader")
	}
	return nativeSequenceFixture{server: s, source: source, pair: pair, value: value}
}

func nativeSequenceColdValue(t *testing.T, s *workflowServer, helper, source string, expected []byte, changedAuthority bool) {
	t.Helper()
	portable := nativeReplacementPortablePair(t, source)
	image := workflowSuccessorImage(t, filepath.Dir(portable))
	_, before := workflowHead(t, s)
	objects := s.objectCount()
	sum := sha256.Sum256(expected)
	child := workflowRun(t, s, helper, "authority", observer.Policy{ExpectedSHA256: map[string]string{"binary": hex.EncodeToString(sum[:])}, SuccessorKEK: s.selector(7)}, nil, "--source", portable, "--source-format", "json")
	if child.code != 0 {
		t.Fatal("selected prior value is not cold consumable", child.summary)
	}
	workflowPlaintext(t, child, "plaintext")
	role := "authority"
	if changedAuthority {
		role = "successor-private"
	}
	nativeReplacementReadDecrypt(t, child, role, "normal")
	_, after := workflowHead(t, s)
	if !reflect.DeepEqual(before, after) || s.objectCount() != objects || !reflect.DeepEqual(image, workflowSuccessorImage(t, filepath.Dir(portable))) {
		t.Fatal("cold consumption changed selected state or pair")
	}
}

func nativeSequenceCapabilities(t *testing.T, child workflowChild, signing bool) {
	t.Helper()
	want := map[string]int{"signer/normal": 1}
	private := map[string]int{"kms-sign/normal": 0}
	public := "successor-private"
	if signing {
		want["signing-metadata/successor"], want["signer/successor"] = 1, 1
		private["kms-sign/successor"] = 0
		public = "successor"
	} else {
		want["encryption-metadata/successor-private"] = 1
		want["key-access/authority"], want["key-access/successor-private"] = 1, 1
		private["kms-decrypt/authority"], private["kms-decrypt/successor-private"] = 0, 0
	}
	constructed := map[string]int{}
	publicCalls := 0
	for _, event := range child.capture.Events {
		if event.Kind == "construction" {
			constructed[event.Operation+"/"+event.Role]++
			continue
		}
		if event.Kind != "http-start" {
			continue
		}
		switch event.Operation {
		case "head-read", "store-read", "store-write", "head-write":
		case "kms-public":
			if event.Role != public || !event.Sent {
				t.Fatal("replacement qualified another public route", event.Role, public)
			}
			publicCalls++
		case "kms-sign", "kms-decrypt":
			key := event.Operation + "/" + event.Role
			if _, ok := private[key]; !ok || !event.Sent {
				t.Fatal("replacement attempted an undeclared private route", key)
			}
			private[key]++
		default:
			t.Fatal("replacement attempted another provider operation", event.Operation)
		}
	}
	if !reflect.DeepEqual(constructed, want) || publicCalls == 0 {
		t.Fatal("replacement constructed extra or missing capability purposes", constructed, want)
	}
	for route, count := range private {
		if count == 0 {
			t.Fatal("replacement did not execute its required private route", route)
		}
	}
}

func nativeSequenceIdentity(t *testing.T, child workflowChild) (nonce, identity string) {
	t.Helper()
	var r struct {
		Nonce    string `json:"request_id"`
		Identity string `json:"request_identity"`
	}
	if json.Unmarshal(child.out, &r) != nil || len(r.Nonce) != 64 || len(r.Identity) != 64 {
		t.Fatal("fresh mutation lost its nonce or typed mutation identity")
	}
	nonceBytes, err := hex.DecodeString(r.Nonce)
	if err != nil || len(nonceBytes) != 32 || bytes.Equal(nonceBytes, make([]byte, 32)) {
		t.Fatal("fresh mutation nonce is not a nonzero public ID")
	}
	return r.Nonce, r.Identity
}

// full_only: false
func TestPublicNativeSelectedSuccessorStartsFreshReplacement(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			f := nativeSequenceSetup(t, cli, family)
			s := f.server
			before, beforeObject := workflowHead(t, s)
			entry := workflowEntry(t, s, workflowRoot(t, s, before))
			firstDir := administrativeReplacementDirectory(t)
			first := filepath.Join(firstDir, "first.json")
			args1 := []string{"keys", "replace", "--source", f.source, "--source-format", "json", "--target", "recovery", "--authorizer", "authority", "--signing", s.selector(6), "--out", first, "--json"}
			one := workflowRun(t, s, cli, "successor", observer.Policy{}, nil, args1...)
			r1 := nativeReplacementDecode(t, one, "keys-replace-recovery", "TransitionPayload/v1")
			if r1.StoredReceipt == nil || r1.Delivery.Status != "delivered" {
				t.Fatal("first replacement did not deliver a selected receipt-bearing pair")
			}
			nonce1, id1 := nativeSequenceIdentity(t, one)
			receipt1 := workflowReceipt(t, r1.StoredReceipt.Bytes, contract.OperationReplaceRecoveryKeysAndRoot)
			h1, object1 := workflowHead(t, s)
			workflowOneHeadAttempt(t, one, true, 200)
			nativeSequenceCapabilities(t, one, true)
			if h1.Succession == nil || h1.Succession.Subject.ChangeMask != contract.SuccessionChangeRecoverySigner || h1.Core.PreviousRevision != before.Core.Revision || h1.Core.PreviousDigest != contract.Hash(beforeObject.body) || h1.Core.PreviousToken != (contract.Token{Family: f.pair.descriptor.Provider, Value: beforeObject.etag}) || r1.Operation != hex.EncodeToString(receipt1.OperationID[:]) || id1 != hex.EncodeToString(receipt1.RequestIdentityDigest[:]) || receipt1.RequestedRevisionID != h1.Core.Revision || r1.Observed != hex.EncodeToString(h1.Core.Revision[:]) {
				t.Fatal("first replacement receipt or predecessor differs from actual selection")
			}
			image1 := workflowSuccessorImage(t, firstDir)
			editable1, generated1, _, basis1 := workflowSuccessorPair(t, first)
			var oldMetadata struct {
				Replacement struct {
					Identity string `json:"request_identity"`
				}
			}
			if json.Unmarshal(generated1, &oldMetadata) != nil || oldMetadata.Replacement.Identity != id1 || !bytes.Equal(basis1.Selection, object1.body) {
				t.Fatal("first successor source has no actual prior replacement metadata")
			}
			secondDir := administrativeReplacementDirectory(t)
			second := filepath.Join(secondDir, "second.json")
			args2 := []string{"keys", "replace", "--source", first, "--source-format", "json", "--target", "recovery", "--authorizer", "authority", "--encryption", s.selector(7), "--decrypt-with", "authority", "--out", second, "--json"}
			counts := s.snapshot("successor")
			two := workflowRun(t, s, cli, "successor", observer.Policy{RecoverySigner: s.selector(6), SuccessorKEK: s.selector(7)}, nil, args2...)
			r2 := nativeReplacementDecode(t, two, "keys-replace-recovery", "TransitionPayload/v1")
			if r2.StoredReceipt == nil || r2.Delivery.Status != "delivered" {
				t.Fatal("source metadata redirected fresh replacement into an observation")
			}
			nonce2, id2 := nativeSequenceIdentity(t, two)
			receipt2 := workflowReceipt(t, r2.StoredReceipt.Bytes, contract.OperationReplaceRecoveryKeysAndRoot)
			h2, object2 := workflowHead(t, s)
			workflowOneHeadAttempt(t, two, true, 200)
			nativeSequenceCapabilities(t, two, false)
			if nonce1 == nonce2 || id1 == id2 || r1.Operation == r2.Operation || r1.StoredReceipt.Bytes == r2.StoredReceipt.Bytes || h2.Core.Revision == h1.Core.Revision || h2.Core.PreviousRevision != h1.Core.Revision || h2.Core.PreviousDigest != contract.Hash(object1.body) || h2.Core.PreviousToken != (contract.Token{Family: f.pair.descriptor.Provider, Value: object1.etag}) || h2.Succession == nil || h2.Succession.Subject.ChangeMask != contract.SuccessionChangeRecoveryKEK || h2.Succession.Subject.MaterialSourceRole != contract.SuccessionMaterialAuthority || receipt2.PredecessorRevisionID != h1.Core.Revision || receipt2.RequestedRevisionID != h2.Core.Revision || id2 != hex.EncodeToString(receipt2.RequestIdentityDigest[:]) || r2.Operation != hex.EncodeToString(receipt2.OperationID[:]) || s.snapshot("successor").headUpdates-counts.headUpdates != 1 || s.snapshot("successor").headCreates != 0 || s.snapshot("successor").conditions != 0 {
				t.Fatal("second fresh operation reused old identity, receipt or CAS")
			}
			_, generated2, _, basis2 := workflowSuccessorPair(t, second)
			root2 := workflowRoot(t, s, h2)
			if root2.CurrentAccess.Core.Recovery == nil || root2.CurrentAccess.Core.Recovery.Signing.KeySelector != s.selector(6) || root2.CurrentAccess.Core.Recovery.KMS.KeySelector != s.selector(7) {
				t.Fatal("second replacement did not retain the first signer and select the new KEK")
			}
			var metadata struct {
				Replacement struct {
					Identity  string `json:"request_identity"`
					Candidate []byte
					Source    struct {
						Editable        string `json:"editable_digest"`
						Generated       string `json:"generated_digest"`
						EditableLength  uint64 `json:"editable_length"`
						GeneratedLength uint64 `json:"generated_length"`
					}
				}
			}
			if json.Unmarshal(generated2, &metadata) != nil || metadata.Replacement.Identity != id2 || metadata.Replacement.Source.Editable != workflowDigest(editable1) || metadata.Replacement.Source.Generated != workflowDigest(generated1) || metadata.Replacement.Source.EditableLength != uint64(len(editable1)) || metadata.Replacement.Source.GeneratedLength != uint64(len(generated1)) || !bytes.Equal(metadata.Replacement.Candidate, object2.body) || !bytes.Equal(basis2.Selection, object2.body) || !reflect.DeepEqual(entry, workflowEntry(t, s, workflowRoot(t, s, h2))) {
				t.Fatal("new output borrowed old source metadata or changed selected material")
			}
			if !reflect.DeepEqual(image1, workflowSuccessorImage(t, firstDir)) {
				t.Fatal("second operation modified its successor source")
			}
			image2, objects := workflowSuccessorImage(t, secondDir), s.objectCount()
			query := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, args2...)
			observed := nativeReplacementDecode(t, query, "keys-replace-receipt", "ReceiptPayload/v1")
			workflowGETOnly(t, query)
			nativeReplacementNoConstruction(t, query)
			var original struct {
				Bytes string `json:"receipt_hex"`
			}
			if json.Unmarshal(observed.Payload, &original) != nil || original.Bytes != r2.StoredReceipt.Bytes || observed.Replay != "none" || observed.Operation == r2.Operation || s.objectCount() != objects || s.snapshot("successor").headUpdates != 2 || !reflect.DeepEqual(image2, workflowSuccessorImage(t, secondDir)) || !reflect.DeepEqual(image1, workflowSuccessorImage(t, firstDir)) {
				t.Fatal("second output repeat borrowed mutation authority or another receipt")
			}
			nativeSequenceColdValue(t, s, helper, second, f.value, false)
			workflowUnchanged(t, f.source, f.pair)
		})
	}
}

// full_only: false
func TestPublicNativePreparedSuccessorCannotActivateApplyOrCompare(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			f := nativeSequenceSetup(t, cli, family)
			s := f.server
			before, original := workflowHead(t, s)
			beforeRoot := workflowRoot(t, s, before)
			dir := administrativeReplacementDirectory(t)
			prepared := filepath.Join(dir, "prepared.json")
			args := []string{"keys", "replace", "--source", f.source, "--source-format", "json", "--target", "authority", "--authorizer", "authority", "--encryption", s.selector(7), "--decrypt-with", "authority", "--out", prepared, "--json"}
			child := workflowRun(t, s, cli, "successor", observer.Policy{SuccessorKEK: s.selector(7), Fault: "head-contention", FaultOrdinal: 1}, nil, args...)
			var mutation nativeReplacementReply
			if child.code != 3 || json.Unmarshal(child.out, &mutation) != nil || mutation.Schema != "ProductResult/v1" || mutation.Kind != "keys-replace-authority" || mutation.State != "contention" || mutation.PayloadKind != "TransitionPayload/v1" || mutation.Delivery.Status != "delivered" || mutation.StoredReceipt != nil {
				t.Fatal("controlled contention did not preserve exact prepared output")
			}
			workflowOneHeadAttempt(t, child, false, 412)
			nativeSequenceCapabilities(t, child, false)
			_, _, _, basis := workflowSuccessorPair(t, prepared)
			control, err := contract.DecodeControlCore(basis.Control)
			if err != nil || control.AuthorityKMSBinding.KeySelector != s.selector(7) || control.AuthorityKMSBinding.BindingID == nativeReplacementRecipientBinding(t, s, beforeRoot, beforeRoot.CurrentAccess.Core.AuthorityRecipientID).BindingID || bytes.Equal(basis.Selection, original.body) {
				t.Fatal("prepared source does not describe a genuine unselected successor", err)
			}
			_, unchanged := workflowHead(t, s)
			if !reflect.DeepEqual(original, unchanged) || s.snapshot("successor").headUpdates != 0 {
				t.Fatal("typed not-sent contention reached remote HEAD")
			}
			candidate, err := stateformat.DecodeHead(basis.Selection)
			if err != nil || candidate.Core.PreviousRevision != before.Core.Revision || candidate.Core.PreviousDigest != contract.Hash(original.body) || candidate.Core.PreviousToken != (contract.Token{Family: f.pair.descriptor.Provider, Value: original.etag}) {
				t.Fatal("prepared candidate has no exact selected predecessor", err)
			}
			observed := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, args...)
			var observation struct {
				nativeReplacementReply
				Evidence string `json:"evidence_ceiling"`
			}
			var current struct {
				SourceUsable      bool `json:"successor_source_usable"`
				CandidateSelected bool `json:"candidate_selected"`
			}
			if observed.code != 3 || json.Unmarshal(observed.out, &observation) != nil || observation.Schema != "ProductResult/v1" || observation.Kind != "keys-replace-observe" || observation.State != "unavailable" || observation.PayloadKind != "InspectionPayload/v1" || observation.Evidence != "canonical" || observation.Observed != hex.EncodeToString(before.Core.Revision[:]) || json.Unmarshal(observation.Payload, &current) != nil || current.SourceUsable || current.CandidateSelected {
				t.Fatal("valid prepared output did not retain exact unselected public correlation")
			}
			workflowGETOnly(t, observed)
			nativeReplacementNoConstruction(t, observed)
			image, objects := workflowSuccessorImage(t, dir), s.objectCount()
			applied := workflowRun(t, s, cli, "apply", observer.Policy{NoKMS: true, SuccessorKEK: s.selector(7)}, nil, "apply", "--source", prepared, "--source-format", "json", "--json")
			var apply struct {
				Schema  string
				Kind    string          `json:"operation_kind"`
				State   string          `json:"state_result"`
				Payload json.RawMessage `json:"payload"`
				Receipt string          `json:"receipt_hex"`
				Replay  string          `json:"replay_identity"`
				Unknown bool            `json:"commit_may_have_occurred"`
			}
			if applied.code != 3 || json.Unmarshal(applied.out, &apply) != nil || apply.Schema != "ProductResult/v1" || apply.Kind != "apply-declaration" || apply.State != "unavailable" || !bytes.Equal(apply.Payload, []byte("null")) || apply.Receipt != "" || apply.Replay != "none" || apply.Unknown {
				t.Fatal("prepared pair activated Apply or fabricated a transition")
			}
			workflowGETOnly(t, applied)
			compared := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", prepared, "--trusted-format", "json", "--json")
			var comparison struct {
				workflowOutput
				Kind string `json:"operation_kind"`
			}
			if compared.code != 3 || json.Unmarshal(compared.out, &comparison) != nil || comparison.Schema != "ProductResult/v1" || comparison.Kind != contract.ReaderCompareOperation || comparison.State != "unavailable" || comparison.Payload.Schema != "ComparisonPayload/v1" || comparison.Payload.Verdict != string(contract.ComparisonUnable) || !comparison.Payload.DiagnosticsComplete || comparison.Payload.EvidenceLimit != contract.ComparisonEvidenceLimit {
				t.Fatal("prepared pair claimed an activated public match")
			}
			workflowGETOnly(t, compared)
			nativeReplacementNoConstruction(t, compared)
			_, unchanged = workflowHead(t, s)
			if !reflect.DeepEqual(original, unchanged) || !reflect.DeepEqual(beforeRoot, workflowRoot(t, s, before)) || s.objectCount() != objects || !reflect.DeepEqual(image, workflowSuccessorImage(t, dir)) {
				t.Fatal("prepared-source Apply/compare changed HEAD, objects or output")
			}
			positive := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", f.source, "--trusted-format", "json", "--json")
			if workflowResult(t, positive, "success").Payload.Verdict != "match" {
				t.Fatal("independent selected predecessor source is not usable")
			}
			workflowGETOnly(t, positive)
			nativeSequenceColdValue(t, s, helper, f.source, f.value, false)
			workflowUnchanged(t, f.source, f.pair)
		})
	}
}

// full_only: false
func TestPublicNativePendingSealedInputSurvivesReplacementAndRefusesStaleApply(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			f := nativeSequenceSetup(t, cli, family)
			s := f.server
			before, _ := workflowHead(t, s)
			beforeRoot := workflowRoot(t, s, before)
			entry := workflowEntry(t, s, beforeRoot)
			pendingValue := []byte("unapplied second sealed proposal\x00\xff")
			defer clear(pendingValue)
			pending := workflowPrepare(t, s, cli, f.source, "set-change", f.pair, pendingValue)
			if bytes.Equal(pending.sealed, f.pair.sealed) {
				t.Fatal("fixture did not create a distinct pending proposal")
			}
			envelope, err := contract.DecodeSealedInputEnvelope(pending.sealed)
			if err != nil || envelope.Core.ContentLength != uint32(len(pendingValue)) || envelope.Core.ContentLength == uint32(len(f.value)) {
				t.Fatal("pending V2 is not the independently declared distinct sealed input", err)
			}
			dir := administrativeReplacementDirectory(t)
			output := filepath.Join(dir, "successor.json")
			args := []string{"keys", "replace", "--source", f.source, "--source-format", "json", "--target", "authority", "--authorizer", "authority", "--encryption", s.selector(7), "--decrypt-with", "authority", "--out", output, "--json"}
			replaced := workflowRun(t, s, cli, "successor", observer.Policy{SuccessorKEK: s.selector(7)}, nil, args...)
			reply := nativeReplacementDecode(t, replaced, "keys-replace-authority", "TransitionPayload/v1")
			if reply.Delivery.Status != "delivered" || reply.StoredReceipt != nil {
				t.Fatal("Authority KEK replacement lost its receipt-free delivered result")
			}
			workflowOneHeadAttempt(t, replaced, true, 200)
			nativeSequenceCapabilities(t, replaced, false)
			after, selected := workflowHead(t, s)
			root := workflowRoot(t, s, after)
			current := nativeReplacementRecipientBinding(t, s, root, root.CurrentAccess.Core.AuthorityRecipientID)
			prior := nativeReplacementRecipientBinding(t, s, beforeRoot, beforeRoot.CurrentAccess.Core.AuthorityRecipientID)
			// The preserved authority wrap names the old binding, while current
			// selected access names the new binding. No invented stale enum is used.
			if err != nil || current.KeySelector != s.selector(7) || envelope.AuthorityWrap.BindingID != prior.BindingID || envelope.AuthorityWrap.BindingSerial != prior.BindingSerial || envelope.AuthorityWrap.BindingID == current.BindingID || !reflect.DeepEqual(entry, workflowEntry(t, s, root)) || root.MembershipCount != beforeRoot.MembershipCount || root.SecretCount != beforeRoot.SecretCount || root.ValueEntryCount != beforeRoot.ValueEntryCount {
				t.Fatal("fixture did not preserve selected V1 while replacing its envelope binding", err)
			}
			editable, generated, reference, _ := workflowSuccessorPair(t, output)
			var oldImage, newImage struct{ Secrets map[string]json.RawMessage }
			if json.Unmarshal(pending.generated, &oldImage) != nil || json.Unmarshal(generated, &newImage) != nil || len(oldImage.Secrets["binary"]) == 0 || !bytes.Equal(oldImage.Secrets["binary"], newImage.Secrets["binary"]) {
				t.Fatal("replacement rewrote the exact pending sealed proposal row")
			}
			oldSelector, _ := json.Marshal(s.selector(2))
			newSelector, _ := json.Marshal(s.selector(7))
			if bytes.Count(pending.editable, oldSelector) != 1 || bytes.Count(pending.editable, []byte(pending.reference)) != 1 {
				t.Fatal("fixture scalar spans are not independently unique")
			}
			expected := bytes.Replace(pending.editable, oldSelector, newSelector, 1)
			expected = bytes.Replace(expected, []byte(pending.reference), []byte(reference), 1)
			if !bytes.Equal(editable, expected) {
				t.Fatal("replacement changed editable bytes outside its selector and generated reference")
			}
			workflowUnchanged(t, f.source, pending)
			image, objects := workflowSuccessorImage(t, dir), s.objectCount()
			applied := workflowRun(t, s, cli, "apply", observer.Policy{NoKMS: true, SuccessorKEK: s.selector(7)}, nil, "apply", "--source", output, "--source-format", "json", "--json")
			var refused struct {
				Schema   string
				Kind     string                               `json:"operation_kind"`
				State    string                               `json:"state_result"`
				Payload  json.RawMessage                      `json:"payload"`
				Receipt  string                               `json:"receipt_hex"`
				Replay   string                               `json:"replay_identity"`
				Unknown  bool                                 `json:"commit_may_have_occurred"`
				Identity struct{ Schema, Stage, Code string } `json:"request_identity"`
			}
			if applied.code != 2 || json.Unmarshal(applied.out, &refused) != nil || refused.Schema != "ProductResult/v1" || refused.Kind != "apply-declaration" || refused.State != "refused" || !bytes.Equal(refused.Payload, []byte("null")) || refused.Receipt != "" || refused.Replay != "none" || refused.Unknown || refused.Identity.Schema != "PreAdmissionRequestIdentity/v1" || refused.Identity.Stage != "apply" || refused.Identity.Code != "invalid-input" {
				t.Fatal("stale sealed binding did not retain the existing typed Apply refusal")
			}
			workflowGETOnly(t, applied)
			_, unchanged := workflowHead(t, s)
			if !reflect.DeepEqual(selected, unchanged) || !reflect.DeepEqual(entry, workflowEntry(t, s, workflowRoot(t, s, after))) || s.objectCount() != objects || !reflect.DeepEqual(image, workflowSuccessorImage(t, dir)) {
				t.Fatal("stale Apply changed selected material or repaired its source")
			}
			nativeSequenceColdValue(t, s, helper, output, f.value, true)
			workflowUnchanged(t, f.source, pending)
			writable := nativeReplacementPortablePair(t, output)
			if err := os.Chmod(writable, 0600); err != nil {
				t.Fatal("fresh set source is not writable", err)
			}
			currentValue := []byte("fresh current-binding supplied V3\x00\xfe")
			defer clear(currentValue)
			beforeSet, beforeGenerated, _, beforeBasis := workflowSuccessorPair(t, writable)
			set := workflowRun(t, s, cli, "set-change", observer.Policy{NoKMS: true}, currentValue, "set", "--source", writable, "--source-format", "json", "--name", "binary", "--json")
			var setResult struct {
				Schema  string
				State   string `json:"state_result"`
				Kind    string `json:"operation_payload"`
				Payload struct {
					Schema      string
					FileID      string `json:"input_file_id"`
					Predecessor string `json:"predecessor_digest"`
					Artifact    string `json:"sealed_artifact_digest"`
					Target      struct {
						Domain string `json:"domain_id"`
						Name   string
					}
					Readback struct {
						Editable  string `json:"editable_digest"`
						Generated string `json:"generated_digest"`
					}
				}
			}
			if set.code != 0 || json.Unmarshal(set.out, &setResult) != nil || setResult.Schema != "ProductResult/v1" || setResult.State != "success" || setResult.Kind != "SealedArtifactPayload/v1" || setResult.Payload.Schema != "SealedArtifactPayload/v1" || len(set.capture.Events) != 1 || set.capture.Events[0].Kind != "footer" {
				t.Fatal("successor-source set did not complete without provider capabilities")
			}
			freshEditable, freshGenerated, _, freshBasis := workflowSuccessorPair(t, writable)
			var freshImage struct {
				FileID  string `json:"file_id"`
				Secrets map[string]struct{ Sealed []byte }
			}
			if json.Unmarshal(freshGenerated, &freshImage) != nil || freshImage.FileID != hex.EncodeToString(f.pair.fileID[:]) || !reflect.DeepEqual(beforeBasis, freshBasis) || bytes.Equal(beforeGenerated, freshGenerated) {
				t.Fatal("successor-source set changed public basis or file identity")
			}
			freshSeal := freshImage.Secrets["binary"].Sealed
			currentEnvelope, err := contract.DecodeSealedInputEnvelope(freshSeal)
			if err != nil || currentEnvelope.Core.ContentLength != uint32(len(currentValue)) || currentEnvelope.Core.Name != "binary" || currentEnvelope.Core.DomainID != f.pair.descriptor.DomainID || currentEnvelope.Core.FileIdentity != f.pair.fileID || currentEnvelope.Core.FilePredecessorDigest != contract.Hash(beforeSet) || currentEnvelope.AuthorityWrap.BindingID != current.BindingID || currentEnvelope.AuthorityWrap.BindingSerial != current.BindingSerial || currentEnvelope.AuthorityWrap.BindingID == envelope.AuthorityWrap.BindingID || bytes.Equal(freshSeal, pending.sealed) {
				t.Fatal("fresh set did not seal V3 to the selected successor binding", err)
			}
			if setResult.Payload.FileID != freshImage.FileID || setResult.Payload.Predecessor != workflowDigest(beforeSet) || setResult.Payload.Target.Domain != hex.EncodeToString(f.pair.descriptor.DomainID[:]) || setResult.Payload.Target.Name != "binary" || setResult.Payload.Artifact != workflowDigest(freshSeal) || setResult.Payload.Readback.Editable != workflowDigest(freshEditable) || setResult.Payload.Readback.Generated != workflowDigest(freshGenerated) {
				t.Fatal("successor-source set lost exact sealed provenance or readback")
			}
			for _, body := range [][]byte{set.out, set.diagnostic, freshEditable, freshGenerated, freshSeal} {
				if bytes.Contains(body, currentValue) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(currentValue))) {
					t.Fatal("successor-source set disclosed V3")
				}
			}
			freshImageBeforeApply := workflowSuccessorImage(t, filepath.Dir(writable))
			counts := s.snapshot("successor")
			// This existing fixture phase permits the selected successor KEK;
			// the real command and its private API routes remain Apply's own.
			accepted := workflowRun(t, s, cli, "successor", observer.Policy{SuccessorKEK: s.selector(7)}, nil, "apply", "--source", writable, "--source-format", "json", "--json")
			acceptedResult := workflowResult(t, accepted, "success")
			acceptedReceipt := workflowReceipt(t, acceptedResult.Receipt, contract.OperationApplyDeclaration)
			_, acceptedIdentity := nativeSequenceIdentity(t, accepted)
			var acceptedCorrelation struct {
				Kind      string `json:"operation_kind"`
				Operation string `json:"operation_id"`
				Domain    string `json:"domain_id"`
				Requested string `json:"requested_revision_id"`
				Observed  string `json:"observed_revision_id"`
				Unknown   bool   `json:"commit_may_have_occurred"`
			}
			if json.Unmarshal(accepted.out, &acceptedCorrelation) != nil || acceptedCorrelation.Kind != "apply-declaration" || acceptedCorrelation.Operation != hex.EncodeToString(acceptedReceipt.OperationID[:]) || acceptedIdentity != hex.EncodeToString(acceptedReceipt.RequestIdentityDigest[:]) || acceptedCorrelation.Domain != hex.EncodeToString(f.pair.descriptor.DomainID[:]) || acceptedReceipt.DomainID != f.pair.descriptor.DomainID || acceptedCorrelation.Unknown || acceptedResult.Payload.Schema != "TransitionPayload/v1" {
				t.Fatal("current-binding Apply lost its exact operation or receipt identity")
			}
			workflowOneHeadAttempt(t, accepted, true, 200)
			signs, decrypts := 0, 0
			for _, event := range accepted.capture.Events {
				if event.Kind != "http-start" {
					continue
				}
				switch event.Operation {
				case "head-read", "store-read", "store-write", "head-write":
				case "kms-public":
					if !event.Sent || event.Role != "normal" && event.Role != "successor-private" {
						t.Fatal("current-binding Apply attempted another public route")
					}
				case "kms-sign":
					if event.Role != "normal" || !event.Sent {
						t.Fatal("current-binding Apply attempted another signing route")
					}
					signs++
				case "kms-decrypt":
					if event.Role != "successor-private" || !event.Sent {
						t.Fatal("current-binding Apply attempted a stale or Recovery private route")
					}
					decrypts++
				default:
					t.Fatal("current-binding Apply attempted another provider operation", event.Operation)
				}
			}
			next, _ := workflowHead(t, s)
			if signs == 0 || decrypts == 0 || next.Core.PreviousRevision != after.Core.Revision || next.Core.PreviousDigest != contract.Hash(selected.body) || next.Core.PreviousToken != (contract.Token{Family: f.pair.descriptor.Provider, Value: selected.etag}) || next.Core.Revision == after.Core.Revision || acceptedReceipt.PredecessorRevisionID != after.Core.Revision || acceptedReceipt.RequestedRevisionID != next.Core.Revision || acceptedReceipt.ObservedRevisionID != next.Core.Revision || acceptedCorrelation.Requested != hex.EncodeToString(next.Core.Revision[:]) || acceptedCorrelation.Observed != hex.EncodeToString(next.Core.Revision[:]) || s.snapshot("successor").headUpdates-counts.headUpdates != 1 || reflect.DeepEqual(entry, workflowEntry(t, s, workflowRoot(t, s, next))) {
				t.Fatal("fresh current-binding Apply did not select its own next value")
			}
			if !reflect.DeepEqual(freshImageBeforeApply, workflowSuccessorImage(t, filepath.Dir(writable))) {
				t.Fatal("current-binding Apply changed its successor source pair")
			}
			nativeSequenceColdValue(t, s, helper, writable, currentValue, true)
			if !reflect.DeepEqual(image, workflowSuccessorImage(t, dir)) {
				t.Fatal("fresh set/apply changed the retained stale delivered pair")
			}
			workflowUnchanged(t, f.source, pending)
		})
	}
}
