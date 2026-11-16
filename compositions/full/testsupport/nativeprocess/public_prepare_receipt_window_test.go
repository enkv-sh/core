package nativeprocess

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func nativeFullWindowIndex(successes, failures, order []contract.ID) []byte {
	// schema:u16 followed by three length-framed vectors; each has a count:u32
	// and individually length-framed 32-byte IDs. No production encoder is used.
	body := binary.BigEndian.AppendUint16(nil, 2)
	for _, vector := range [][]contract.ID{successes, failures, order} {
		body = binary.BigEndian.AppendUint32(body, uint32(4+36*len(vector)))
		body = binary.BigEndian.AppendUint32(body, uint32(len(vector)))
		for _, id := range vector {
			body = binary.BigEndian.AppendUint32(body, 32)
			body = append(body, id[:]...)
		}
	}
	return body
}

func nativeFullWindowState(t *testing.T, s *workflowServer, expected map[contract.ID][]byte, index []byte) {
	t.Helper()
	head, _ := workflowHead(t, s)
	root := workflowRoot(t, s, head)
	if root.Generated.SuccessWindow.Count != 256 || root.Generated.FailureWindow.Count != 256 || root.Generated.ReceiptOrder.Count != 512 || root.Generated.ReceiptOrder.Length != 18436 || root.WarningBits != 0 || root.ValueEntryCount != 1 || root.SecretCount != 0 || len(index) != 36890 {
		t.Fatal("actual full-window selected dimensions differ")
	}
	found := make(map[contract.ID]bool, 512)
	indexes := 0
	for _, ref := range root.RequiredSupport {
		key, err := stateformat.Key(s.prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.InspectRequiredSupportPage(s.object(t, key).body)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Records {
			switch row.Kind {
			case contract.MutationReceiptSupportKind:
				receipt, err := contract.InspectCompactMutationReceipt(row.Body)
				if err != nil || found[receipt.OperationID] || !bytes.Equal(row.Body, expected[receipt.OperationID]) {
					t.Fatal("selected full-window receipt changed its actual original bytes")
				}
				found[receipt.OperationID] = true
			case contract.GeneratedFragmentSupportKind:
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(fragment.Payload, index) {
					indexes++
				}
			}
		}
	}
	if len(found) != 512 || indexes != 1 {
		t.Fatal("full-window selected receipt/index whole set differs", len(found), indexes)
	}
}

type nativeReceiptSummary struct {
	Operation string `json:"operation_id"`
	Kind      uint16 `json:"operation_kind"`
	Canonical uint8  `json:"canonical_outcome"`
	State     uint16 `json:"state_result"`
	Observed  string `json:"observed_revision_id"`
	Requested string `json:"requested_revision_id"`
	Warnings  uint64 `json:"warning_bits"`
	Evidence  uint16 `json:"evidence_ceiling"`
}

func nativeFullWindowList(t *testing.T, child workflowChild, order []contract.ID, receipts map[contract.ID][]byte) {
	t.Helper()
	var result struct {
		Schema, Operation, State string
		Payload                  struct {
			Form     string
			Warnings uint8 `json:"current_domain_warning_bits"`
			Receipts []nativeReceiptSummary
		}
	}
	var wire struct {
		Schema    string
		Operation string `json:"operation_kind"`
		State     string `json:"state_result"`
		Payload   json.RawMessage
	}
	if child.code != 0 || json.Unmarshal(child.out, &wire) != nil || wire.Schema != "ProductResult/v1" || wire.Operation != "receipt-list" || wire.State != "success" || json.Unmarshal(wire.Payload, &result.Payload) != nil || result.Payload.Form != "list" || result.Payload.Warnings != 0 || len(result.Payload.Receipts) != 512 {
		t.Fatal("fresh public full-window receipt admission failed", child.code, child.summary)
	}
	for i, id := range order {
		receipt, err := contract.InspectCompactMutationReceipt(receipts[id])
		if err != nil {
			t.Fatal(err)
		}
		expected := nativeReceiptSummary{hex.EncodeToString(id[:]), receipt.OperationKind, receipt.CanonicalOutcome, receipt.StateResult, hex.EncodeToString(receipt.ObservedRevisionID[:]), hex.EncodeToString(receipt.RequestedRevisionID[:]), receipt.WarningBits, receipt.EvidenceCeiling}
		if result.Payload.Receipts[511-i] != expected {
			t.Fatal("fresh full-window public list changed exact common order or safe facts", i)
		}
	}
	workflowGETOnly(t, child)
}

// full_only: true
// Proves a valid signed 256-success/256-failure selected capacity fixture,
// with synthetic terminal history, through public prepare and fresh admission.
func TestPublicNativePrepareFullReceiptWindows(t *testing.T) {
	signer := testtrust.New(t, contract.AWS, contract.Hash([]byte("fixture/trust")))
	directory := filepath.Join(nativeRepository(t), "crypto", "testsupport", "installedarchive", "testdata")
	fixture, indexes := installedarchive.ReadReceiptWindowFixture(t, filepath.Join(directory, "receipt-window-aws.json"), filepath.Join(directory, "receipt-window-aws-index.json"))
	archive := fixture.Archive
	if archive.SignerSelector != signer.KeySelector() || !bytes.Equal(archive.SignerPublicKey, signer.PublicKey()) || archive.Location.Bucket != "fixture-bucket" || archive.Location.Region != "us-east-1" || archive.Location.ExpectedOwner != "123456789012" {
		t.Fatal("capacity archive changed independently fixed signing resource or Store")
	}
	cli, _ := workflowExecutables(t)
	manifest := nativeManifestProductionBuild(t)
	plugins := newNativePluginFixture(t, manifest)
	s := newWorkflowServer(t, "aws", false)
	s.prefix = archive.Location.PrefixBeforeHEAD
	s.childLimit = 5
	s.objects = make(map[string]workflowObject, len(archive.Objects))
	s.keys = map[string]workflowKey{signer.KeySelector(): {der: signer.PublicKey(), role: "normal"}}
	for _, object := range archive.Objects {
		token, n, err := contract.ParseToken(object.TokenWire)
		if err != nil || n != len(object.TokenWire) || token.Family != contract.AWS {
			t.Fatal("archive object lost exact provider token")
		}
		s.objects[object.Key] = workflowObject{body: bytes.Clone(object.Body), etag: token.Value}
	}
	receipts := make(map[contract.ID][]byte, 512)
	parts, err := archive.SelectedParts()
	if err != nil {
		t.Fatal("capacity archive selected parts refused")
	}
	for _, part := range parts {
		if part.Kind == "recipient page" {
			page, err := stateformat.DecodeRecipientPage(part.Body)
			if err != nil {
				t.Fatal("capacity archive recipient page refused")
			}
			for _, row := range page.Slots {
				if row == nil || row.CurrentBinding == nil {
					continue
				}
				role := "ordinary"
				if row.RecipientID == archive.AuthorityID {
					role = "authority"
				}
				s.keys[row.CurrentBinding.KeySelector] = workflowKey{der: bytes.Clone(row.CurrentBinding.SPKI), role: role}
			}
		}
		if part.Kind != "support row" || part.SupportKind != contract.MutationReceiptSupportKind {
			continue
		}
		receipt, err := contract.InspectCompactMutationReceipt(part.Body)
		if err != nil || len(part.Body) != 471 || receipts[receipt.OperationID] != nil {
			t.Fatal("capacity archive receipt whole set refused")
		}
		receipts[receipt.OperationID] = bytes.Clone(part.Body)
	}
	if len(receipts) != 512 {
		t.Fatal("capacity archive omitted terminal receipts")
	}
	for _, key := range s.keys {
		if key.signing != nil || key.encryption != nil {
			t.Fatal("read-only archive responder obtained a private KMS key")
		}
	}
	expectedIndex := nativeFullWindowIndex(indexes.Successes, indexes.Failures, indexes.Order)
	nativeFullWindowState(t, s, receipts, expectedIndex)
	_, selected := workflowHead(t, s)
	objects := s.objectCount()
	policy := observer.Policy{NormalSigner: signer.KeySelector(), AuthorityKEK: archive.AuthorityBinding.KeySelector}
	recovered := filepath.Join(t.TempDir(), "windows.json")
	environment := plugins.Environment(t, recovered)
	prepared := workflowRunEnvironment(t, s, cli, "authority", policy, nil, environment, nativePrepareArgs(s, recovered, "windows-restored", "--normal-signing-key", signer.KeySelector())...)
	result := nativePrepareResult(t, prepared, "reconstruction")
	if result.Recovery.Head != workflowDigest(selected.body) || result.Recovery.Domain != hex.EncodeToString(archive.Domain[:]) || result.Delivery.Outcome != "recorded" {
		t.Fatal("full-window preparation lost exact signed capacity selection or delivery")
	}
	nativePrepareReadOnly(t, prepared)
	pair, err := configuration.Capture(t.Context(), recovered, configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if pair != nil {
			if err := pair.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	model, parseErr := configuration.Parse(t.Context(), pair)
	if parseErr != nil || model == nil || !model.Resolved || len(model.Entries) != 1 || model.Entries[0].Name != "seed" || model.Entries[0].Secret || model.Entries[0].Generated != nil || !bytes.Equal(model.Entries[0].Plain, []byte{0}) || pair.Editable.Size()+pair.Generated.Size() > configuration.MaxPairBytes {
		t.Fatal("full-window normalized public pair refused or changed current Plain row")
	}
	t.Logf("full-window signed capacity fixture synthetic_history=true editable_bytes=%d generated_bytes=%d exact_receipt_bytes=%d exact_index_bytes=%d", pair.Editable.Size(), pair.Generated.Size(), 512*471, len(expectedIndex))
	if err := pair.Close(); err != nil {
		t.Fatal(err)
	}
	pair = nil
	captured := workflowReadNamedPair(t, recovered, "windows-restored")
	restore := workflowReadOnlyPair(t, recovered, captured)
	defer restore()
	publicPolicy := policy
	publicPolicy.NoKMS = true
	public := workflowRunEnvironment(t, s, cli, "reader", publicPolicy, nil, environment, "plan", "--trusted", recovered, "--trusted-format", "json", "--json")
	if workflowResult(t, public, "success").Payload.Verdict != "match" {
		t.Fatal("fresh full-window public plan did not match")
	}
	workflowGETOnly(t, public)
	listed := workflowRunEnvironment(t, s, cli, "reader", publicPolicy, nil, environment, "receipt", "--source", recovered, "--source-format", "json", "--json")
	nativeFullWindowList(t, listed, indexes.Order, receipts)
	idle := workflowRunEnvironment(t, s, cli, "noop", policy, nil, environment, "apply", "--source", recovered, "--source-format", "json", "--json")
	workflowResult(t, idle, "no-op")
	nativePrepareReadOnly(t, idle)
	existing := workflowRunEnvironment(t, s, cli, "reader", publicPolicy, nil, environment, "prepare", "--source", recovered, "--source-format", "json", "--json")
	nativePrepareResult(t, existing, "existing")
	if len(existing.capture.Events) != 1 {
		t.Fatal("existing full-window preparation entered provider work")
	}
	nativeFullWindowState(t, s, receipts, expectedIndex)
	workflowUnchanged(t, recovered, captured)
	_, after := workflowHead(t, s)
	if !reflect.DeepEqual(selected, after) || s.objectCount() != objects || s.children != 5 {
		t.Fatal("full-window fresh consumers changed signed selected state or finite child inventory")
	}
}
