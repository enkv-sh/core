package nativeprocess

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

type nativeReplacementCell struct {
	target, change, authorizer string
	partial                    bool
}

// full_only: false
func TestPublicNativeReplacementProductionAdapterMatrix(t *testing.T) {
	cli, helper := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		for _, target := range []string{"authority", "recovery"} {
			for _, change := range []string{"signing", "encryption", "both"} {
				for _, authorizer := range []string{"authority", "recovery"} {
					cell := nativeReplacementCell{target: target, change: change, authorizer: authorizer}
					t.Run(family+"/"+target+"/"+change+"/by-"+authorizer, func(t *testing.T) {
						nativeReplacementMatrixCell(t, cli, helper, family, cell)
					})
				}
			}
		}
		t.Run(family+"/recipient", func(t *testing.T) {
			nativeReplacementMatrixCell(t, cli, helper, family, nativeReplacementCell{target: "recipient", change: "encryption", authorizer: "authority"})
		})
		// Declared encryption equality must keep its declared source in the
		// signed identity while creating no unused private KEK capability.
		t.Run(family+"/authority/partial-encryption-equality", func(t *testing.T) {
			nativeReplacementMatrixCell(t, cli, helper, family, nativeReplacementCell{target: "authority", change: "both", authorizer: "recovery", partial: true})
		})
	}
}

type nativeReplacementReply struct {
	Schema        string
	Kind          string          `json:"operation_kind"`
	State         string          `json:"state_result"`
	Operation     string          `json:"operation_id"`
	Identity      json.RawMessage `json:"request_identity"`
	Replay        string          `json:"replay_identity"`
	PayloadKind   string          `json:"operation_payload"`
	Payload       json.RawMessage `json:"payload"`
	StoredReceipt *struct {
		Bytes string `json:"receipt_hex"`
	} `json:"stored_receipt"`
	Observed string `json:"observed_revision_id"`
	Delivery struct {
		Status        string `json:"status"`
		Failed        bool   `json:"failed"`
		CleanupFailed bool   `json:"cleanup_failed"`
	} `json:"delivery"`
}

func nativeReplacementDecode(t *testing.T, child workflowChild, kind, payload string) nativeReplacementReply {
	t.Helper()
	var r nativeReplacementReply
	if json.Unmarshal(child.out, &r) != nil || child.code != 0 || len(child.diagnostic) != 0 || r.Schema != "ProductResult/v1" || r.Kind != kind || r.State != "success" || r.PayloadKind != payload || len(r.Operation) != 64 || r.Delivery.Failed || r.Delivery.CleanupFailed {
		t.Fatalf("native replacement result lost its closed operation: kind=%s state=%s exit=%d %s", r.Kind, workflowSafeState(r.State), child.code, child.summary)
	}
	return r
}

func nativeReplacementMatrixCell(t *testing.T, cli, helper, family string, cell nativeReplacementCell) {
	t.Helper()
	s := newWorkflowServer(t, family, true)
	// The existing responder owns all cryptographic operations. Add only the
	// one actual RSA successor needed by the real provider constructors.
	private, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	s.keys[s.selector(7)] = workflowKey{encryption: private, der: public, role: "successor-private"}
	source := filepath.Join(t.TempDir(), "configuration.json")
	if err := os.WriteFile(source, workflowSetup(t, s, true), 0600); err != nil {
		t.Fatal(err)
	}
	workflowResult(t, workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", source, "--source-format", "json", "--json"), "success")
	genesis := workflowReadPair(t, source)
	// Nominate Reader before set, so the sealed proposal and actual selected
	// value contain both Authority and ordinary Recipient material routes.
	var editable map[string]any
	if json.Unmarshal(genesis.editable, &editable) != nil {
		t.Fatal("initialized editable source is invalid")
	}
	editable["entries"] = map[string]any{"binary": map[string]any{"confidentiality": "secret", "recipients": []string{"reader"}, "source": map[string]any{"kind": "supplied"}}}
	declared, err := json.Marshal(editable)
	if err != nil || os.WriteFile(source, declared, 0600) != nil {
		t.Fatal("secret membership declaration failed", err)
	}
	plaintext := []byte{'m', 'a', 't', 'r', 'i', 'x', 0, 255, 1, 128, 7}
	defer clear(plaintext)
	prepared := workflowPrepare(t, s, cli, source, "set", workflowReadPair(t, source), plaintext)
	workflowResult(t, workflowRun(t, s, cli, "apply", observer.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json"), "success")
	before, beforeObject := workflowHead(t, s)
	beforeRoot := workflowRoot(t, s, before)
	beforeEntry := workflowEntry(t, s, beforeRoot)
	if beforeRoot.SecretCount != 1 || len(beforeEntry.Recipients) != 2 {
		t.Fatal("matrix has no complete supplied-secret membership coverage")
	}
	outputDir := administrativeReplacementDirectory(t)
	output := filepath.Join(outputDir, "successor.json")
	args := []string{"keys", "replace", "--source", source, "--source-format", "json", "--target", cell.target, "--authorizer", cell.authorizer, "--out", output, "--json"}
	signing := cell.change != "encryption"
	encryption := cell.change != "signing"
	material := ""
	if signing {
		args = append(args, "--signing", s.selector(6))
	}
	if encryption {
		selector := s.selector(7)
		if cell.partial {
			selector = s.selector(2)
		}
		args = append(args, "--encryption", selector)
		material = "recovery"
		if cell.authorizer == "recovery" || cell.target == "recipient" {
			material = "authority"
		}
		if cell.target != "recipient" {
			args = append(args, "--decrypt-with", material)
		}
	}
	if cell.target == "recipient" {
		if family == "aws" {
			var recipient contract.ID
			for _, id := range beforeEntry.Recipients {
				if id != beforeRoot.CurrentAccess.Core.AuthorityRecipientID {
					if !recipient.IsZero() {
						t.Fatal("fixture has more than one ordinary recipient")
					}
					recipient = id
				}
			}
			if recipient.IsZero() {
				t.Fatal("fixture has no ordinary recipient")
			}
			args = append(args, "--recipient-id", hex.EncodeToString(recipient[:]))
		} else {
			args = append(args, "--recipient", "reader")
		}
	}
	policy := observer.Policy{SuccessorKEK: s.selector(7)}
	child := workflowRun(t, s, cli, "successor", policy, nil, args...)
	reply := nativeReplacementDecode(t, child, "keys-replace-"+cell.target, "TransitionPayload/v1")
	if reply.Delivery.Status != "delivered" {
		t.Fatal("selected replacement lacks complete synced pair delivery")
	}
	after, selectedObject := workflowHead(t, s)
	root := workflowRoot(t, s, after)
	if after.Core.PreviousRevision != before.Core.Revision || after.Core.PreviousDigest != contract.Hash(beforeObject.body) || after.Core.PreviousToken != (contract.Token{Family: genesis.descriptor.Provider, Value: beforeObject.etag}) || after.Core.Revision == before.Core.Revision {
		t.Fatal("matrix replacement lost its exact predecessor condition")
	}
	if !reflect.DeepEqual(beforeEntry, workflowEntry(t, s, root)) || root.SecretCount != 1 || root.ValueEntryCount != 1 || root.MembershipCount != beforeRoot.MembershipCount || root.WarningBits != beforeRoot.WarningBits {
		t.Fatal("replacement changed supplied value, membership, or warnings")
	}
	nativeReplacementSelectedBindings(t, s, beforeRoot, root, cell)
	workflowUnchanged(t, source, prepared)
	nativeReplacementCapabilities(t, s, child, cell, material)
	var originalReceipt string
	if cell.target == "recipient" {
		if after.AuthKind != stateformat.LifecycleAuth || reply.Operation != hex.EncodeToString(after.Subject.Operation[:]) {
			t.Fatal("Recipient replacement did not select its ordinary candidate")
		}
	} else {
		mask := uint8(contract.SuccessionChangeNormalSigner)
		if !signing {
			mask = 0
		}
		if encryption && !cell.partial {
			mask |= contract.SuccessionChangeAuthorityKEK
		}
		if cell.target == "recovery" {
			mask <<= 2
		}
		role := uint8(contract.SuccessionMaterialNone)
		if material == "authority" {
			role = contract.SuccessionMaterialAuthority
		}
		if material == "recovery" {
			role = contract.SuccessionMaterialRecovery
		}
		approval := uint8(contract.NormalSigningRole)
		if cell.authorizer == "recovery" {
			approval = contract.RecoverySigningRole
		}
		if after.AuthKind != stateformat.SuccessionAuth || after.Succession == nil || after.Succession.Subject.ChangeMask != mask || after.Succession.Subject.ApprovalRole != approval || after.Succession.Subject.MaterialSourceRole != role || reply.Operation != hex.EncodeToString(after.Succession.Subject.OperationID[:]) {
			t.Fatal("role replacement lost mask, authorizer, declared source or signed operation identity")
		}
		var identity string
		if json.Unmarshal(reply.Identity, &identity) != nil || identity != hex.EncodeToString(after.Succession.Subject.RequestIdentityDigest[:]) {
			t.Fatal("public mutation identity differs from the signed final graph identity")
		}
	}
	if cell.target == "authority" {
		if reply.StoredReceipt != nil {
			t.Fatal("Authority replacement invented a receipt")
		}
	} else {
		if reply.StoredReceipt == nil {
			t.Fatal("receipt-bearing mutation omitted original receipt")
		}
		originalReceipt = reply.StoredReceipt.Bytes
		kind := uint16(contract.OperationReplaceRecoveryKeysAndRoot)
		if cell.target == "recipient" {
			kind = contract.OperationRotateRecipientKeyBinding
		}
		r := workflowReceipt(t, originalReceipt, kind)
		var identity string
		if json.Unmarshal(reply.Identity, &identity) != nil || identity != hex.EncodeToString(r.RequestIdentityDigest[:]) || reply.Operation != hex.EncodeToString(r.OperationID[:]) || r.ObservedRevisionID != after.Core.Revision {
			t.Fatal("mutation receipt does not identify selected candidate")
		}
	}
	image := workflowSuccessorImage(t, outputDir)
	objects := s.objectCount()
	observed := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, args...)
	kind, payload := "keys-replace-observe", "InspectionPayload/v1"
	if cell.target != "authority" {
		kind, payload = "keys-replace-receipt", "ReceiptPayload/v1"
	}
	query := nativeReplacementDecode(t, observed, kind, payload)
	workflowGETOnly(t, observed)
	nativeReplacementNoConstruction(t, observed)
	if query.Replay != "none" || query.Operation == reply.Operation {
		t.Fatal("GET observation borrowed mutation identity/replay")
	}
	if originalReceipt != "" {
		var receipt struct {
			Bytes string `json:"receipt_hex"`
		}
		if json.Unmarshal(query.Payload, &receipt) != nil || receipt.Bytes != originalReceipt {
			t.Fatal("cold receipt query changed original stored bytes")
		}
	}
	// Copy only the delivered pair to a new machine directory. Its first use
	// is a public query, then the installed reconstruction uses the current
	// Authority route and checks the exact independent plaintext digest.
	portable := nativeReplacementPortablePair(t, output)
	portableImage := workflowSuccessorImage(t, filepath.Dir(portable))
	get := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "abandon", "list", "--source", portable, "--source-format", "json", "--json")
	workflowResult(t, get, "success")
	workflowGETOnly(t, get)
	nativeReplacementNoConstruction(t, get)
	sum := sha256.Sum256(plaintext)
	expected := map[string]string{"binary": hex.EncodeToString(sum[:])}
	opened := workflowRun(t, s, helper, "authority", observer.Policy{ExpectedSHA256: expected, SuccessorKEK: s.selector(7)}, nil, "--source", portable, "--source-format", "json")
	if opened.code != 0 {
		t.Fatal("pair-only Authority reconstruction refused", opened.summary)
	}
	workflowPlaintext(t, opened, "plaintext")
	decryptRole := "authority"
	if cell.target == "authority" && encryption && !cell.partial {
		decryptRole = "successor-private"
	}
	publicRole := "normal"
	if cell.target == "authority" && signing {
		publicRole = "successor"
	}
	if cell.authorizer == "recovery" && (cell.target == "recovery" || !signing) {
		publicRole = "recovery-signing"
		if signing {
			publicRole = "successor"
		}
	}
	nativeReplacementReadDecrypt(t, opened, decryptRole, publicRole)
	if cell.target == "recovery" && encryption || cell.target == "recipient" {
		binding, subject, recipient := root.CurrentAccess.Core.Recovery.KMS, root.CurrentAccess.Core.Recovery.RoleID, false
		if cell.target == "recipient" {
			recipient = true
			subject = beforeEntry.Recipients[0]
			for _, id := range beforeEntry.Recipients {
				if id != root.CurrentAccess.Core.AuthorityRecipientID {
					subject = id
				}
			}
			binding = nativeReplacementRecipientBinding(t, s, root, subject)
		}
		rowKind := uint8(contract.RecoveryWrapSubject)
		if recipient {
			rowKind = contract.OrdinaryWrapSubject
		}
		encoded, err := contract.EncodeBindingTable([]contract.BindingTableRow{{SubjectKind: rowKind, SubjectID: subject, Binding: binding}})
		if err != nil {
			t.Fatal(err)
		}
		oraclePolicy := observer.Policy{ExpectedSHA256: expected, SuccessorKEK: s.selector(7), RecoveryOracle: !recipient, RecoveryBinding: encoded, RecoveryKEK: binding.KeySelector, RecipientOracle: recipient, RecipientBinding: encoded, RecipientKEK: binding.KeySelector}
		oracle := workflowRun(t, s, helper, "recovery", oraclePolicy, nil, "--source", portable, "--source-format", "json")
		if oracle.code != 2 {
			t.Fatal("private equality oracle was presented as Product reconstruction")
		}
		oracleKind := "recovery-plaintext"
		if recipient {
			oracleKind = "recipient-plaintext"
		}
		workflowPlaintext(t, oracle, oracleKind)
		nativeReplacementReadDecrypt(t, oracle, "successor-private", publicRole)
	}
	_, finalObject := workflowHead(t, s)
	if !reflect.DeepEqual(portableImage, workflowSuccessorImage(t, filepath.Dir(portable))) || s.objectCount() != objects || !reflect.DeepEqual(finalObject, selectedObject) || !reflect.DeepEqual(image, workflowSuccessorImage(t, outputDir)) || s.snapshot("successor").headUpdates != 1 {
		t.Fatal("observation or pair-only consumption changed selected state/output or repeated CAS")
	}
	workflowUnchanged(t, source, prepared)
}

func nativeReplacementCapabilities(t *testing.T, s *workflowServer, child workflowChild, cell nativeReplacementCell, material string) {
	t.Helper()
	construct := map[string]int{}
	private := map[string]int{}
	for _, e := range child.capture.Events {
		if e.Kind == "construction" {
			construct[e.Operation+"/"+e.Role]++
			continue
		}
		if e.Kind != "http-start" {
			continue
		}
		switch e.Operation {
		case "head-read", "store-read", "store-write", "head-write", "kms-public":
		case "kms-sign", "kms-decrypt":
			if !e.Sent {
				t.Fatal("successful matrix command contains a blocked private attempt")
			}
			private[e.Operation+"/"+e.Role]++
		default:
			t.Fatal("replacement used another provider operation", e.Operation)
		}
	}
	authorizer := "normal"
	if cell.authorizer == "recovery" {
		authorizer = "recovery-signing"
	}
	want := map[string]int{"signer/" + authorizer: 1}
	allowed := map[string]bool{"kms-sign/" + authorizer: true}
	if cell.change != "encryption" {
		want["signing-metadata/successor"], want["signer/successor"] = 1, 1
		allowed["kms-sign/successor"] = true
	}
	if cell.change != "signing" {
		metadataRole := "successor-private"
		if cell.partial {
			metadataRole = "authority"
		}
		want["encryption-metadata/"+metadataRole] = 1
		if !cell.partial {
			sourceRole := "authority"
			if material == "recovery" {
				sourceRole = "recovery-private"
			}
			want["key-access/"+sourceRole] = 1
			allowed["kms-decrypt/"+sourceRole] = true
			if cell.target == "recipient" {
				want["public-qualifier/successor-private"] = 1
			} else {
				want["key-access/successor-private"] = 1
				allowed["kms-decrypt/successor-private"] = true
			}
		}
	}
	if !reflect.DeepEqual(construct, want) {
		t.Fatal("replacement constructed extra/missing route purposes", construct, want)
	}
	for key, n := range private {
		if n == 0 || !allowed[key] {
			t.Fatal("replacement used an unselected private route", key)
		}
	}
	for key := range allowed {
		if private[key] == 0 {
			t.Fatal("required real private route did not execute", key)
		}
	}
	counts := s.snapshot("successor")
	if counts.headUpdates != 1 || counts.headCreates != 0 || counts.conditions != 0 {
		t.Fatal("replacement did not perform exactly one original-condition CAS", counts)
	}
	workflowOneHeadAttempt(t, child, true, 200)
}

func nativeReplacementNoConstruction(t *testing.T, child workflowChild) {
	t.Helper()
	for _, e := range child.capture.Events {
		if e.Kind == "construction" {
			t.Fatal("GET-only query constructed replacement capabilities")
		}
	}
}

func nativeReplacementReadDecrypt(t *testing.T, child workflowChild, role, publicRole string) {
	t.Helper()
	uses, public := 0, 0
	for _, e := range child.capture.Events {
		if e.Kind != "http-start" {
			continue
		}
		if e.Operation == "kms-public" {
			if e.Role != publicRole || !e.Sent {
				t.Fatal("pair-only read used an inapplicable public signing route")
			}
			public++
		}
		if e.Operation == "kms-decrypt" {
			if e.Role != role || !e.Sent {
				t.Fatal("pair-only read used another decryption route")
			}
			uses++
		}
		if e.Operation == "kms-sign" || e.Operation == "head-write" || e.Operation == "store-write" {
			t.Fatal("pair-only read attempted mutation")
		}
	}
	if uses != 1 || public == 0 {
		t.Fatal("pair-only read lacks exact public qualification or one supplied value", public, uses)
	}
}

func nativeReplacementPortablePair(t *testing.T, path string) string {
	t.Helper()
	editable, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		Generated string
		Domain    struct{ Name string }
	}
	if json.Unmarshal(editable, &source) != nil || !strings.HasPrefix(source.Generated, ".enkv/") || strings.Contains(source.Generated, "..") {
		t.Fatal("delivered pair reference is invalid")
	}
	generated, err := os.ReadFile(filepath.Join(filepath.Dir(path), source.Generated))
	if err != nil || source.Domain.Name != "prod" || source.Generated != ".enkv/prod.generated.json" {
		t.Fatal("delivered pair does not use its stable generated path", err)
	}
	dir := t.TempDir()
	portable := filepath.Join(dir, "configuration.json")
	if os.Mkdir(filepath.Join(dir, ".enkv"), 0700) != nil || os.WriteFile(portable, editable, 0400) != nil || os.WriteFile(filepath.Join(dir, source.Generated), generated, 0400) != nil {
		t.Fatal("cold pair transfer failed")
	}
	if len(workflowSuccessorImage(t, dir)) != 3 {
		t.Fatal("cold machine contains more than the exact pair")
	}
	return portable
}

func nativeReplacementRecipientBinding(t *testing.T, s *workflowServer, root stateformat.Root, recipient contract.ID) contract.KMSBinding {
	t.Helper()
	for _, ref := range root.Recipients {
		if ref == nil {
			continue
		}
		key, err := stateformat.Key(s.prefix, *ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.DecodeRecipientPage(s.object(t, key).body)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Slots {
			if row != nil && row.RecipientID == recipient && row.CurrentBinding != nil {
				return *row.CurrentBinding
			}
		}
	}
	t.Fatal("selected ordinary Recipient binding is absent")
	return contract.KMSBinding{}
}

func nativeReplacementSelectedBindings(t *testing.T, s *workflowServer, before, after stateformat.Root, cell nativeReplacementCell) {
	t.Helper()
	expected := before.CurrentAccess.Core.CurrentControl
	if expected.Recovery != nil {
		own := *expected.Recovery
		expected.Recovery = &own
	}
	expected.AccessGeneration++
	current := after.CurrentAccess.Core.CurrentControl
	if cell.change != "encryption" {
		old, next := expected.NormalSigning, current.NormalSigning
		if cell.target == "recovery" {
			old, next = expected.Recovery.Signing, current.Recovery.Signing
		}
		if next.BindingID.IsZero() || next.BindingID == old.BindingID {
			t.Fatal("replacement reused the signing binding identity")
		}
		old.BindingID = next.BindingID
		old.Binding.Epoch++
		old.KeySelector = s.selector(6)
		old.SPKI = s.keys[s.selector(6)].der
		old.Fingerprint = contract.Hash(old.SPKI)
		old.Binding.PublicKey = old.Fingerprint
		if !reflect.DeepEqual(old, next) {
			t.Fatal("selected signing binding differs from exact qualified resource or progression")
		}
		if cell.target == "authority" {
			expected.NormalSigning = next
		} else {
			expected.Recovery.Signing = next
		}
	}
	if cell.target == "recovery" && cell.change != "signing" {
		next := current.Recovery.KMS
		nativeReplacementKMSProgression(t, s, expected.Recovery.KMS, next)
		expected.Recovery.KMS = next
	}
	if !reflect.DeepEqual(expected, current) {
		t.Fatal("replacement changed unrelated control or access generation")
	}
	authority := before.CurrentAccess.Core.AuthorityRecipientID
	oldAuthority := nativeReplacementRecipientBinding(t, s, before, authority)
	newAuthority := nativeReplacementRecipientBinding(t, s, after, authority)
	if cell.target == "authority" && cell.change != "signing" && !cell.partial {
		nativeReplacementKMSProgression(t, s, oldAuthority, newAuthority)
	} else if !reflect.DeepEqual(oldAuthority, newAuthority) {
		t.Fatal("replacement changed an unselected Authority KEK")
	}
	for _, ref := range before.Recipients {
		if ref == nil {
			continue
		}
		key, err := stateformat.Key(s.prefix, *ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.DecodeRecipientPage(s.object(t, key).body)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Slots {
			if row == nil || row.RecipientID == authority || row.CurrentBinding == nil {
				continue
			}
			next := nativeReplacementRecipientBinding(t, s, after, row.RecipientID)
			if cell.target == "recipient" {
				nativeReplacementKMSProgression(t, s, *row.CurrentBinding, next)
			} else if !reflect.DeepEqual(*row.CurrentBinding, next) {
				t.Fatal("role replacement changed an ordinary Recipient binding")
			}
		}
	}
}

func nativeReplacementKMSProgression(t *testing.T, s *workflowServer, before, after contract.KMSBinding) {
	t.Helper()
	if after.BindingID.IsZero() || after.BindingID == before.BindingID {
		t.Fatal("replacement reused the encryption binding identity")
	}
	before.BindingID = after.BindingID
	before.BindingSerial++
	before.KeySelector = s.selector(7)
	before.SPKI = s.keys[s.selector(7)].der
	before.Fingerprint = contract.Hash(before.SPKI)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("selected encryption binding differs from exact qualified resource or progression")
	}
}
