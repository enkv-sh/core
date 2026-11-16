package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

type publicReplacementFacts struct {
	Target                                                      string
	Domain, Revision, Snapshot, HeadDigest, Operation, Identity contract.ID
	Receipt                                                     string
}

func publicReplacementOpen(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source, directory string) *StateSession {
	t.Helper()
	domain := publicReadDomain(t, source)
	store, err := openPublicReaderStore(ctx, input, domain, directory)
	if err != nil {
		t.Fatal("replacement independent GET-only Store unavailable", err)
	}
	basis := publicOperatorSourceBasis(t, ctx, inv, input, budget, source, domain, store.Descriptor())
	return publicOperatorOpen(t, ctx, domain, basis, recordedStore{Store: store, budget: budget})
}

func publicReplacementSelectors(s liveSettings, cell catalog.PublicReplacementCase) (string, string) {
	signing, encryption := "", ""
	if cell.Change != "encryption" {
		signing = s.NormalSuccessorKeyID
		if cell.Target == "recovery" {
			signing = s.RecoverySuccessorKeyID
		}
	}
	if cell.Change != "signing" {
		encryption = s.AuthoritySuccessor1KEKID
		if cell.Target == "recovery" {
			encryption = s.RecoverySuccessor1KEKID
		}
		if cell.Target == "recipient" {
			encryption = s.ReaderSuccessorKEKID
		}
	}
	// This role denies only the old Normal public API. Nominate that exact
	// current signing key with a changed KEK: public resolution precedes equality.
	if cell.DeniedRole == "denied-public" {
		signing = s.KeyID
	}
	return signing, encryption
}

func runPublicReplacement(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, cell catalog.PublicReplacementCase, source string) (string, *publicReplacementFacts) {
	t.Helper()
	document := publicSourceDocument(t, source)
	document["entries"] = map[string]any{"secret": map[string]any{"confidentiality": "secret", "recipients": []string{"consumer"}, "source": map[string]any{"kind": "supplied"}}}
	publicWriteSource(t, source, document)
	plaintext := []byte{'l', 'i', 'v', 'e', '-', 'r', 'e', 'p', 'l', 'a', 'c', 'e', 0, 255, 7, 128}
	defer clear(plaintext)
	set := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true}, plaintext, "set", "--source", source, "--source-format", "json", "--name", "secret", "--json")
	publicAssertSet(t, set, source, "secret")
	clear(set.Body)
	sealed := publicSourceImage(t, source)
	applied := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json")
	if !publicApplyMatches(applied, publicProduct(t, applied, "apply-declaration"), "success") {
		t.Fatal("replacement selected supplied-secret setup failed")
	}
	clear(applied.Body)
	publicImageUnchanged(t, sealed)
	before := publicReplacementOpen(t, ctx, inv, input, budget, source, inv.StateDir)
	if before.root.ChildCount > 7 || before.root.ChildEncodedBytes > 7*contract.MaxRequiredSupportPageLength || before.root.Generated.Slices.Count != 0 || before.root.SecretCount != 1 || before.root.ValueEntryCount != 1 || before.root.AccessRecordCount != 1 || len(before.adminIndex.Groups) != 0 || len(before.root.Names) != 1 || len(before.valueEntry(before.root.Names[0].Slot).Recipients) != 2 {
		t.Fatal("replacement fixture lacks exact one-material shared secret")
	}
	signing, encryption := publicReplacementSelectors(input.Settings, cell)
	outputDirectory := filepath.Join(inv.StateDir, "replacement-output")
	if os.Mkdir(outputDirectory, 0700) != nil {
		t.Fatal("replacement output owner unavailable")
	}
	output := filepath.Join(outputDirectory, "successor.json")
	args := []string{"keys", "replace", "--source", source, "--source-format", "json", "--target", cell.Target, "--authorizer", cell.Authorizer, "--out", output, "--json"}
	if signing != "" {
		args = append(args, "--signing", signing)
	}
	if encryption != "" {
		args = append(args, "--encryption", encryption)
		if cell.Target != "recipient" {
			args = append(args, "--decrypt-with", cell.MaterialSource)
		}
	}
	if cell.Target == "recipient" {
		args = append(args, "--recipient", "consumer")
	}
	actor := "authority"
	if cell.Authorizer == "recovery" {
		actor = "successor"
	}
	if cell.DeniedRole != "" {
		actor = cell.DeniedRole
	}
	reservation, ok := publicReplacementReservation(before, cell)
	if !ok {
		t.Fatal("source-bound replacement reservation unavailable")
	}
	policy := nativeprocess.Policy{SuccessorSigner: signing, SuccessorKEK: encryption}
	replaced := publicCLIReserved(t, ctx, inv, input, budget, actor, false, policy, reservation, nil, args...)
	defer clear(replaced.Body)
	reply := publicReplacementResult(t, replaced, "keys-replace-"+cell.Target)
	publicImageUnchanged(t, sealed)
	if err := publicReplacementCapture(replaced.Capture, cell, cell.DeniedRole != ""); err != nil {
		t.Fatal("replacement effects differ from exact selected routes", err)
	}
	if cell.DeniedRole != "" {
		if replaced.Code == 0 || reply.State == "success" || reply.Unknown || reply.PayloadKind != "none" || reply.Receipt != nil || reply.Delivery.Status == "delivered" {
			t.Fatal("permission-denied replacement advertised selection or delivery")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatal("denied replacement created a successor source")
		}
		after := publicReplacementOpen(t, ctx, inv, input, budget, source, inv.StateDir)
		if !bytes.Equal(before.body, after.body) || before.token != after.token || !reflect.DeepEqual(sessionStateImage(t, before), sessionStateImage(t, after)) {
			t.Fatal("permission-denied replacement changed selected state")
		}
		return source, &publicReplacementFacts{Target: cell.Target, Domain: before.root.Domain, Revision: before.head.Core.Revision, Snapshot: before.root.Snapshot, HeadDigest: contract.Hash(before.body)}
	}
	if replaced.Code != 0 || reply.State != "success" || reply.PayloadKind != "TransitionPayload/v1" || reply.Unknown || reply.Delivery.Status != "delivered" || reply.Delivery.Path != output {
		t.Fatal("replacement did not return selected durable successor", replaced.Code, reply.State)
	}
	if !publicReplacementDeliveryMatches(reply.Delivery, output, publicSourceImage(t, output)) {
		t.Fatal("replacement delivery differs from the exact pair readback")
	}
	after := publicReplacementOpen(t, ctx, inv, input, budget, output, inv.StateDir)
	if after.head.Core.PreviousRevision != before.head.Core.Revision || after.head.Core.PreviousDigest != contract.Hash(before.body) || after.head.Core.PreviousToken != before.token || after.head.Core.Revision == before.head.Core.Revision || after.root.ChildCount > 9 || after.root.ChildEncodedBytes > 9*contract.MaxRequiredSupportPageLength {
		t.Fatal("replacement lost original predecessor condition or bounded fixture")
	}
	publicReplacementSelected(t, before, after, cell, signing, encryption)
	publicReplacementTransitionMatches(t, reply, before, after, cell)
	publicReplacementOutputFacts(t, ctx, inv, input, budget, source, output, cell)
	operation, identity := publicReplacementID(t, reply.Operation), publicReplacementIdentity(t, reply)
	if cell.Target == "recipient" {
		if after.head.AuthKind != format.LifecycleAuth || after.head.Subject.Operation != operation {
			t.Fatal("Recipient did not select exact ordinary lifecycle candidate")
		}
	} else {
		mask := uint8(0)
		if signing != "" {
			mask |= contract.SuccessionChangeNormalSigner
		}
		if encryption != "" {
			mask |= contract.SuccessionChangeAuthorityKEK
		}
		if cell.Target == "recovery" {
			mask <<= 2
		}
		role := uint8(contract.SuccessionMaterialNone)
		if cell.MaterialSource == "authority" {
			role = contract.SuccessionMaterialAuthority
		}
		if cell.MaterialSource == "recovery" {
			role = contract.SuccessionMaterialRecovery
		}
		authorizer := uint8(contract.NormalSigningRole)
		if cell.Authorizer == "recovery" {
			authorizer = contract.RecoverySigningRole
		}
		if after.head.AuthKind != format.SuccessionAuth || after.head.Succession == nil {
			t.Fatal("role replacement lacks signed Succession proof")
		}
		subject := after.head.Succession.Subject
		if subject.OperationID != operation || subject.RequestIdentityDigest != identity || subject.ChangeMask != mask || subject.ApprovalRole != authorizer || subject.MaterialSourceRole != role {
			t.Fatal("signed replacement identity/goal differs from exact request")
		}
	}
	receipt := publicReplacementStoredReceipt(t, reply, after, cell.Target)
	delivered := publicSourceImage(t, output)
	repeated := publicCLIReserved(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, publicReplacementReadReservation(), nil, args...)
	defer clear(repeated.Body)
	kind, payload := "keys-replace-observe", "InspectionPayload/v1"
	if cell.Target != "authority" {
		kind, payload = "keys-replace-receipt", "ReceiptPayload/v1"
	}
	observation := publicReplacementResult(t, repeated, kind)
	candidateDigest := contract.Hash(after.body)
	if repeated.Code != 0 || observation.State != "success" || observation.PayloadKind != payload || observation.Replay != "none" || observation.Operation == reply.Operation || observation.Query == nil || observation.Query.OriginalOperation != reply.Operation || observation.Query.OriginalIdentity != hex.EncodeToString(identity[:]) || observation.Query.Candidate != hex.EncodeToString(candidateDigest[:]) {
		t.Fatal("occupied output repeat lost independent GET-only correlation")
	}
	publicReplacementQueryMatches(t, ctx, inv, input, budget, observation, after, source, output, cell, signing, encryption)
	if err := publicReplacementReadCapture(repeated.Capture, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if receipt != "" {
		var raw publicReplacementReceipt
		if operatorStrictJSON(observation.Payload, &raw) != nil || raw.Bytes != receipt {
			t.Fatal("receipt query changed original stored bytes")
		}
	}
	publicImageUnchanged(t, delivered)
	portable := publicPortablePair(t, output, filepath.Join(inv.StateDir, "replacement-cold-pair"))
	coldImage := publicSourceImage(t, portable)
	publicReplacementCold(t, ctx, inv, input, budget, cell, after, portable, plaintext, encryption)
	publicImageUnchanged(t, coldImage)
	publicImageUnchanged(t, sealed)
	publicImageUnchanged(t, delivered)
	final := publicReplacementOpen(t, ctx, inv, input, budget, portable, inv.StateDir)
	if !bytes.Equal(final.body, after.body) || final.token != after.token {
		t.Fatal("cold reads changed or replaced selected state")
	}
	return output, &publicReplacementFacts{Target: cell.Target, Domain: after.root.Domain, Revision: after.head.Core.Revision, Snapshot: after.root.Snapshot, HeadDigest: contract.Hash(after.body), Operation: operation, Identity: identity, Receipt: receipt}
}

func publicReplacementCold(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, cell catalog.PublicReplacementCase, selected *StateSession, portable string, plaintext []byte, encryption string) {
	t.Helper()
	listed := publicCLIReserved(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, publicReplacementReadReservation(), nil, "abandon", "list", "--source", portable, "--source-format", "json", "--json")
	defer clear(listed.Body)
	list, err := operatorAbandonmentResult(listed.Body)
	if listed.Code != 0 || err != nil || list.State != "success" || publicReplacementReadCapture(listed.Capture, "", "", "") != nil {
		t.Fatal("pair-only cold public query failed", err)
	}
	consumeReservation, ok := publicReplacementConsumeReservation(selected)
	if !ok {
		t.Fatal("cold consumption reservation refused")
	}
	signing, _ := publicReplacementSelectors(input.Settings, cell)
	policy := nativeprocess.Policy{ExpectedSHA256: publicExpected(plaintext), SuccessorKEK: encryption, SuccessorSigner: signing}
	consumed := publicCLIReserved(t, ctx, inv, input, budget, "authority", true, policy, consumeReservation, nil, "--source", portable, "--source-format", "json")
	defer clear(consumed.Body)
	role := "authority"
	if cell.Target == "authority" && cell.Change != "signing" {
		role = "successor-private"
	}
	publicRole := "normal"
	if cell.Target == "authority" && cell.Change != "encryption" {
		publicRole = "successor"
	}
	if cell.Authorizer == "recovery" && (cell.Target == "recovery" || cell.Change == "encryption") {
		publicRole = "recovery-signing"
		if cell.Change != "encryption" {
			publicRole = "successor"
		}
	}
	if consumed.Code != 0 || publicReplacementReadCapture(consumed.Capture, role, "plaintext", publicRole) != nil {
		t.Fatal("cold Authority reconstruction failed or used another route")
	}
	if cell.Target != "recipient" && !(cell.Target == "recovery" && cell.Change != "signing") {
		return
	}
	row := contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject}
	actor, kind := "authority", "recovery-plaintext"
	if cell.Target == "recipient" {
		actor, kind = "reader-successor", "recipient-plaintext"
		row.SubjectKind = contract.OrdinaryWrapSubject
		for _, id := range selected.valueEntry(selected.root.Names[0].Slot).Recipients {
			if id != selected.admission.recipient {
				row.SubjectID = id
			}
		}
		record := selected.recipientRecord(row.SubjectID)
		if record == nil || record.CurrentBinding == nil {
			t.Fatal("selected Recipient successor absent")
		}
		row.Binding = *record.CurrentBinding
	} else {
		row.SubjectID = selected.root.CurrentAccess.Core.Recovery.RoleID
		row.Binding = selected.root.CurrentAccess.Core.Recovery.KMS
	}
	encoded, err := contract.EncodeBindingTable([]contract.BindingTableRow{row})
	if err != nil {
		t.Fatal(err)
	}
	oraclePolicy := nativeprocess.Policy{ExpectedSHA256: publicExpected(plaintext), SuccessorKEK: encryption, SuccessorSigner: signing, RecipientOracle: cell.Target == "recipient", RecoveryOracle: cell.Target == "recovery"}
	if cell.Target == "recipient" {
		oraclePolicy.RecipientBinding = encoded
		oraclePolicy.RecipientKEK = row.Binding.KeySelector
	} else {
		oraclePolicy.RecoveryBinding = encoded
		oraclePolicy.RecoveryKEK = row.Binding.KeySelector
	}
	oracle := publicCLIReserved(t, ctx, inv, input, budget, actor, true, oraclePolicy, consumeReservation, nil, "--source", portable, "--source-format", "json")
	defer clear(oracle.Body)
	if oracle.Code != 2 || publicReplacementReadCapture(oracle.Capture, "successor-private", kind, publicRole) != nil {
		t.Fatal("cold selected wrap oracle failed or claimed Product reconstruction")
	}
}

func publicReplacementFresh(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, facts publicReplacementFacts) {
	t.Helper()
	image := publicSourceImage(t, source)
	listed := publicCLIReserved(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, publicReplacementReadReservation(), nil, "abandon", "list", "--source", source, "--source-format", "json", "--json")
	defer clear(listed.Body)
	list, err := operatorAbandonmentResult(listed.Body)
	if listed.Code != 0 || err != nil || list.State != "success" || publicReplacementReadCapture(listed.Capture, "", "", "") != nil {
		t.Fatal("fresh pair-only public query refused", err)
	}
	selected := publicReplacementOpen(t, ctx, inv, input, budget, source, inv.StateDir)
	if selected.root.Domain != facts.Domain || selected.head.Core.Revision != facts.Revision || selected.root.Snapshot != facts.Snapshot || contract.Hash(selected.body) != facts.HeadDigest {
		t.Fatal("fresh pair selected a different candidate")
	}
	if facts.Receipt != "" {
		_, raw, found, err := selected.retainedMutationReceipt(facts.Operation)
		if err != nil || !found || hex.EncodeToString(raw) != facts.Receipt {
			t.Fatal("fresh selected receipt differs", err)
		}
	}
	publicImageUnchanged(t, image)
}
