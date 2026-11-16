package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

// Every command finishes before its source is inspected or made writable again.
func publicLifecycleReadOnly(t testing.TB, source string, run func() publicChildResult) publicChildResult {
	t.Helper()
	image := publicSourceImage(t, source)
	modes := map[string]fs.FileMode{}
	defer func() {
		for path, mode := range modes {
			if err := os.Chmod(path, mode); err != nil {
				t.Error("lifecycle source mode restore failed", err)
			}
		}
	}()
	if err := filepath.WalkDir(image.Directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		modes[path] = info.Mode().Perm()
		mode := fs.FileMode(0400)
		if entry.IsDir() {
			mode = 0500
		}
		return os.Chmod(path, mode)
	}); err != nil {
		t.Fatal("read-only lifecycle source protection failed", err)
	}
	result := run()
	publicImageUnchanged(t, image)
	for path := range modes {
		info, err := os.Lstat(path)
		if err != nil || info.IsDir() && info.Mode().Perm() != 0500 || !info.IsDir() && info.Mode().Perm() != 0400 {
			t.Fatal("read-only lifecycle source mode changed")
		}
	}
	return result
}

func publicLifecycleEntries(t testing.TB, s *StateSession) map[string]contract.ValueEntry {
	t.Helper()
	out := map[string]contract.ValueEntry{}
	for _, name := range s.root.Names {
		row := s.valueEntry(name.Slot)
		if row == nil || row.Name != name.Name {
			t.Fatal("lifecycle selected name differs from entry")
		}
		out[row.Name] = *row
	}
	if len(out) != 2 || s.root.SecretCount != 1 || s.root.ChildCount > 10 || s.root.ChildEncodedBytes > 512<<10 || s.root.Generated.Slices.Count != 0 || len(s.adminIndex.Groups) != 0 {
		t.Fatal("lifecycle fixture exceeds its two-entry supplied-only bound")
	}
	return out
}

func publicLifecycleRegistry(s *StateSession) map[contract.ID]contract.RecipientRecord {
	out := map[contract.ID]contract.RecipientRecord{}
	for _, row := range s.registry() {
		out[row.RecipientID] = row
	}
	return out
}

func publicLifecyclePreparedRecipientMatches(row contract.RecipientRecord, fact nativeprocess.SourcePairRecipient) bool {
	if row.RecipientID != contract.ID(fact.ID) || row.Status != contract.CurrentRecipient || row.CurrentBinding == nil {
		return false
	}
	b, w := row.CurrentBinding, fact.Encryption
	return b.KeySelector == w.Selector && bytes.Equal(b.SPKI, w.PublicKey) && b.BindingID == contract.ID(w.Binding.ID) && b.BindingIncarnationID == contract.ID(w.Binding.Incarnation) && b.BindingSerial == w.Binding.Serial && b.ProtectionClass == w.Binding.Protection
}

// Complete Open authenticates the fragment directory before releasing its
// borrowed bodies. This supplied-only fixture permits receipt-index support,
// but no generated work hidden beside the ordinary mutation receipt windows.
func publicLifecycleReceiptOnlyClosure(root format.Root) bool {
	index, err := contract.MutationReceiptIndexBlobID(root.Domain, root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder)
	if err != nil || len(root.Generated.Fragments) == 0 {
		return false
	}
	for _, location := range root.Generated.Fragments {
		if location.BlobID != index {
			return false
		}
	}
	expected := format.EmptyGeneratedClosure()
	expected.SuccessWindow, expected.FailureWindow, expected.ReceiptOrder = root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder
	expected.Fragments = root.Generated.Fragments
	return reflect.DeepEqual(root.Generated, expected)
}

func publicLifecycleEnrollmentControlMatches(before, after contract.ControlCore) bool {
	if before.AccessGeneration == ^uint64(0) {
		return false
	}
	before.AccessGeneration++
	return sameControl(before, after)
}

func publicLifecycleSubject(t testing.TB, domain contract.ID, kind, change uint8, primary, secondary contract.ID) contract.ChangedSubjectIdentity {
	t.Helper()
	id, err := contract.ChangedSubjectIdentityID(domain, kind, primary, secondary)
	if err != nil {
		t.Fatal("lifecycle expected subject refused", err)
	}
	return contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: id}
}

func publicLifecycleSelected(t testing.TB, child publicChildResult, kind uint16, before, after *StateSession, subjects []contract.ChangedSubjectIdentity) {
	t.Helper()
	operation := publicLifecycleOperation(kind)
	reply := publicProduct(t, child, operation)
	effect := "not-applicable"
	if kind == contract.OperationApplyDeclaration {
		effect = "effect-no-change"
	}
	var wire struct {
		Payload struct {
			Schema      string `json:"schema"`
			Predecessor string `json:"predecessor_revision_id"`
			Requested   string `json:"requested_revision_id"`
			Observed    string `json:"observed_revision_id"`
			Changed     struct {
				Count  uint32 `json:"count"`
				Digest string `json:"identity_root_digest"`
			} `json:"changed_subject_commitment"`
			Duties  []string `json:"live_duty_ids"`
			Hazards []string `json:"live_hazard_ids"`
		} `json:"payload"`
	}
	expected, err := contract.ChangedSubjectDescriptor(subjects)
	if err != nil || expected.Count == 0 {
		t.Fatal("lifecycle expected changed subjects refused", err)
	}
	identity, admitted := publicAdmittedRequestIdentity(reply)
	if child.Code != 0 || reply.State != "success" || reply.Effect != effect || reply.Output != "not-applicable" || reply.CommitUnknown || !admitted || json.Unmarshal(child.Body, &wire) != nil || wire.Payload.Schema != "TransitionPayload/v1" || publicReplacementID(t, wire.Payload.Predecessor) != before.head.Core.Revision || publicReplacementID(t, wire.Payload.Requested) != after.head.Core.Revision || wire.Payload.Observed != wire.Payload.Requested || wire.Payload.Changed.Count != expected.Count || publicReplacementID(t, wire.Payload.Changed.Digest) != expected.Digest || len(wire.Payload.Duties)+len(wire.Payload.Hazards) != 0 {
		t.Fatal("lifecycle result differs from independently expected transition", operation)
	}
	request, requestErr := publicLifecycleRequestDigest(after)
	access, accessErr := publicLifecycleChangedAccess(before, after)
	if requestErr != nil || accessErr != nil {
		t.Fatal("lifecycle expected request/access result refused", requestErr, accessErr)
	}
	raw, err := hex.DecodeString(reply.Receipt)
	if err != nil || len(raw) != contract.CompactMutationReceiptLength {
		t.Fatal("lifecycle raw receipt unavailable")
	}
	receipt, err := contract.InspectCompactMutationReceipt(raw)
	if err != nil || !publicLifecycleReceiptMatches(kind, receipt, before, after, publicReplacementID(t, reply.OperationID), publicReplacementID(t, identity), expected, request, access) {
		t.Fatal("lifecycle receipt facts differ from selected transition")
	}
	retained, body, found, err := after.retainedMutationReceipt(receipt.OperationID)
	if err != nil || !found || retained != receipt || !bytes.Equal(raw, body) {
		t.Fatal("lifecycle selected retained receipt differs from returned bytes", err)
	}
	priorWindows, priorBodies, priorErr := before.retainedMutationReceiptBodies()
	nextWindows, nextBodies, nextErr := after.retainedMutationReceiptBodies()
	if priorErr != nil || nextErr != nil || len(priorWindows.Successes) >= contract.MutationReceiptWindowLimit ||
		!publicLifecycleReceiptAppendMatches(*priorWindows, *nextWindows, priorBodies, nextBodies, receipt, raw) {
		t.Fatal("lifecycle selection changed prior receipt history or omitted its one new terminal")
	}

	// The signed RequestCore digest and the stored complete-graph identity are
	// different commitments. The authenticated receipt anchors the latter.
	if after.head.Subject.Request != request || after.head.AuthKind != format.LifecycleAuth || after.head.Subject.OperationKind != kind || after.head.Subject.Operation != receipt.OperationID || after.head.Core.PreviousRevision != before.head.Core.Revision || after.head.Core.PreviousDigest != contract.Hash(before.body) || after.head.Core.PreviousToken != before.token || after.head.Core.Revision == before.head.Core.Revision {
		t.Fatal("lifecycle authenticated successor lost exact predecessor or request")
	}
	sent, ok := publicApplyHeadWrite(child.Capture)
	if !ok || sent.Status != 200 {
		t.Fatal("lifecycle selection lacks one acknowledged conditional HEAD write")
	}
	publicAssertNoRecovery(t, child.Capture)
}

func publicLifecycleReceiptAppendMatches(before, after contract.MutationReceiptWindows, prior, next map[contract.ID][]byte, receipt contract.CompactMutationReceipt, raw []byte) bool {
	if before.DomainID != after.DomainID || receipt.DomainID != before.DomainID || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected ||
		len(before.Successes) >= contract.MutationReceiptWindowLimit || len(after.Successes) != len(before.Successes)+1 ||
		!slices.Equal(after.Successes[:len(before.Successes)], before.Successes) || after.Successes[len(before.Successes)] != receipt ||
		!slices.Equal(after.Failures, before.Failures) || len(after.Order) != len(before.Order)+1 ||
		!slices.Equal(after.Order[:len(before.Order)], before.Order) || after.Order[len(before.Order)] != receipt.OperationID ||
		len(next) != len(prior)+1 || prior[receipt.OperationID] != nil || !bytes.Equal(next[receipt.OperationID], raw) {
		return false
	}
	for id, body := range prior {
		if !bytes.Equal(body, next[id]) {
			return false
		}
	}
	return true
}

// This fixture has at most one supplied material. Only an in-place access
// record change is a changed-access row; fresh/removed material is not one.
func publicLifecycleChangedAccess(before, after *StateSession) (contract.GeneratorDescriptor, error) {
	old, next := before.accessRecords(), after.accessRecords()
	if len(old) > 1 || len(next) > 1 {
		return contract.GeneratorDescriptor{}, contract.ErrRecord
	}
	var rows []contract.AccessChangeRow
	if len(old) == 1 && len(next) == 1 && old[0].MaterialKind == next[0].MaterialKind && old[0].MaterialID == next[0].MaterialID && !reflect.DeepEqual(old[0], next[0]) {
		rows = []contract.AccessChangeRow{{Before: old[0], After: next[0]}}
	}
	return contract.AccessChangeDescriptor(after.root.Domain, rows)
}

func publicLifecycleRequestDigest(after *StateSession) (contract.ID, error) {
	h, authorization := after.head.Core, after.head.Subject
	return contract.RequestDigest(contract.RequestCore{RequestCoreFields: contract.RequestCoreFields{Domain: h.Domain, Store: h.Store, Trust: h.Trust, Coordinate: h.Coordinate, NonBody: h.NonBody, Interpretation: h.Interpretation, Epoch: h.Epoch, PreviousRevision: h.PreviousRevision, PreviousDigest: h.PreviousDigest, Intent: authorization.Normal.Intent, IdentityPlan: authorization.IdentityPlan}, PreviousToken: h.PreviousToken})
}

func publicLifecycleReceiptMatches(kind uint16, receipt contract.CompactMutationReceipt, before, after *StateSession, operation, identity contract.ID, subjects contract.GeneratorDescriptor, request contract.ID, access contract.GeneratorDescriptor) bool {
	if publicLifecycleOperation(kind) == "" {
		return false
	}
	warnings, err := contract.EncodeReceiptWarningBits(kind, after.root.WarningBits, 0)
	if err != nil {
		return false
	}
	expected := contract.CompactMutationReceiptPlan{Schema: contract.MutationReceiptSchema, OperationKind: kind, StateResult: contract.ReceiptStateSuccess, EffectSummary: contract.ReceiptEffectNotApplicable, OutputSummary: contract.ReceiptOutputNotApplicable, EvidenceCeiling: contract.ReceiptEvidenceCanonical, DomainID: after.root.Domain, OperationID: operation, PredecessorRevisionID: before.head.Core.Revision, RequestedRevisionID: after.head.Core.Revision, ObservedRevisionID: after.head.Core.Revision, CanonicalOutcome: contract.ReceiptCanonicalSelected, ChangedSubjects: subjects, WarningBits: warnings}
	if kind == contract.OperationApplyDeclaration {
		expected.EffectSummary = contract.ReceiptEffectNoChange
	}
	expected.SummaryCounts[contract.ReceiptChangedAccessCount] = access.Count
	empty := contract.EmptyMutationResultDescriptors()
	complete, err := contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: expected, RequestCoreDigest: request, ChangedAccess: access, Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
	if err != nil {
		return false
	}
	expected.RequestIdentityDigest, expected.CompleteResult = identity, complete
	return receipt == contract.CompactMutationReceipt(expected)
}

func publicLifecycleOperation(kind uint16) string {
	switch kind {
	case contract.OperationApplyDeclaration:
		return "apply-declaration"
	case contract.OperationEnvelopeRekey:
		return "envelope-rekey"
	case contract.OperationRetireRecipientIdentity:
		return "retire-recipient-identity"
	}
	return ""
}

func publicLifecycleRecipientOracle(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, recipient contract.RecipientRecord, value []byte, absent bool) {
	t.Helper()
	if recipient.CurrentBinding == nil || recipient.CurrentBinding.KeySelector != input.Settings.ReaderKEKID {
		t.Fatal("lifecycle exact recipient key unavailable")
	}
	binding, err := contract.EncodeBindingTable([]contract.BindingTableRow{{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: recipient.RecipientID, Binding: *recipient.CurrentBinding}})
	if err != nil {
		t.Fatal(err)
	}
	actor := "recipient-consumer"
	if absent {
		actor = "excluded-consumer"
	}
	result := publicLifecycleReadOnly(t, source, func() publicChildResult {
		return publicCLI(t, ctx, inv, input, budget, actor, true, nativeprocess.Policy{MaxBytes: 8 << 20, ExpectedSHA256: publicExpected(value), RecipientOracle: true, RecipientBinding: binding, RecipientKEK: recipient.CurrentBinding.KeySelector}, nil, "--source", source, "--source-format", "json")
	})
	defer clear(result.Body)
	if result.Code == 0 {
		t.Fatal("private lifecycle oracle claimed Product reconstruction success")
	}
	if !publicLifecycleRecipientCapture(result.Capture, absent) {
		t.Fatal("lifecycle recipient exact wrap/private observation differs")
	}
}

func publicLifecycleRecipientCapture(capture nativeprocess.Capture, absent bool) bool {
	observations, opens := 0, 0
	for _, e := range capture.Events {
		if e.Kind == "http-start" && e.Operation == "kms-decrypt" {
			opens++
			if e.Role != "recipient-private" {
				return false
			}
		}
		if e.Kind == "http-start" && (e.Operation == "kms-sign" || e.Operation == "head-write" || e.Operation == "store-write") {
			return false
		}
		if e.Kind == "recipient-plaintext" {
			observations++
			if absent && (!e.WrapAbsent || e.Count != 0 || e.Matched) || !absent && (e.WrapAbsent || e.Count != 1 || !e.Matched) {
				return false
			}
		}
	}
	return observations == 1 && (absent && opens == 0 || !absent && opens == 1)
}

func publicLifecycleNormalize(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source, directory string, value []byte, selected *StateSession) string {
	t.Helper()
	output := publicPortablePair(t, source, directory)
	result := publicLifecycleReadOnly(t, source, func() publicChildResult {
		return publicCLI(t, ctx, inv, input, budget, "consumer", true, nativeprocess.Policy{MaxBytes: 8 << 20, ExpectedSHA256: publicExpected(value)}, nil, "--source", source, "--source-format", "json", "--reconstruct-output", output)
	})
	defer clear(result.Body)
	if result.Code != 0 {
		t.Fatal("lifecycle installed reconstruction did not deliver normalized pair")
	}
	publicAssertPlain(t, result.Capture, false)
	var summary struct {
		Domain, Revision string
		Parts            int
	}
	if json.Unmarshal(result.Body, &summary) != nil || summary.Domain != hex.EncodeToString(selected.root.Domain[:]) || summary.Revision != hex.EncodeToString(selected.head.Core.Revision[:]) || summary.Parts == 0 {
		t.Fatal("normalized source lost exact reconstructed selection")
	}
	publicObservePair(t, ctx, inv, input, budget, output)
	return output
}

func runPublicRecipientLifecycle(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) string {
	t.Helper()
	value := []byte("recipient lifecycle secret\x00\xff")
	defer clear(value)
	open := func() *StateSession { return publicReplacementOpen(t, ctx, inv, input, budget, source, inv.StateDir) }
	current := open()
	if (current.root.CurrentAccess.Core.CurrentControl.Recovery != nil) != (input.RecoveryMode == "enabled") {
		t.Fatal("lifecycle selected Recovery mode differs from cell")
	}
	authority := current.admission.recipient
	registry := publicLifecycleRegistry(current)
	var consumer contract.RecipientRecord
	for _, row := range registry {
		if row.RecipientID != authority {
			consumer = row
		}
	}
	if len(registry) != 2 || consumer.CurrentBinding == nil || consumer.CurrentBinding.KeySelector != input.Settings.ReaderKEKID {
		t.Fatal("lifecycle initial independent recipient unavailable")
	}
	preparations := map[contract.ID]nativeprocess.SourcePairRecipient{}
	prepare := func(reference string) contract.ID {
		before := publicSourceImage(t, source)
		result := publicCLI(t, ctx, inv, input, budget, "proposer", false, nativeprocess.Policy{MaxRequests: 64, MaxBytes: 8 << 20, RecipientKEK: input.Settings.ReaderKEKID}, nil, "recipients", "add", "--source", source, "--source-format", "json", "--recipient", reference, "--mode", "create", "--display-name", reference, "--encryption-key", input.Settings.ReaderKEKID, "--json")
		defer clear(result.Body)
		var local struct {
			Schema, Outcome string
			Delivery        struct{ Outcome string } `json:"local_delivery"`
		}
		if result.Code != 0 || json.Unmarshal(result.Body, &local) != nil || local.Schema != "LocalEditResult/v1" || local.Outcome != "edited" || local.Delivery.Outcome != "recorded" {
			t.Fatal("lifecycle recipient public preparation failed")
		}
		publicCalls := 0
		for _, e := range result.Capture.Events {
			if e.Kind == "http-start" {
				switch e.Operation {
				case "head-read", "store-read":
				case "kms-public":
					if !e.Sent || e.Role != "recipient-private" && e.Role != "normal" {
						t.Fatal("lifecycle preparation resolved a different public route")
					}
					if e.Role == "recipient-private" {
						publicCalls++
					}
				default:
					t.Fatal("lifecycle preparation used private or mutation capability")
				}
			}
		}
		if publicCalls == 0 || publicImageMatches(before) {
			t.Fatal("lifecycle preparation lacks actual public resolution/local change")
		}
		facts := publicParsedSourceFacts(t, ctx, inv, input, budget, source)
		for _, row := range facts.GeneratedRecipients {
			if row.Reference == reference {
				id := contract.ID(row.ID)
				if id.IsZero() || row.Creation == nil || contract.ID(row.Creation.Snapshot) != current.root.Snapshot || row.Creation.Nonce == ([32]byte{}) || row.Encryption.Selector != input.Settings.ReaderKEKID || registry[id].RecipientID == id || preparations[id].Reference != "" {
					t.Fatal("lifecycle preparation did not create fresh exact recipient proof")
				}
				preparations[id] = row
				return id
			}
		}
		t.Fatal("lifecycle prepared reference missing")
		return contract.ID{}
	}
	set := func(source string) {
		result := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true, MaxRequests: 1, MaxBytes: 1}, value, "set", "--source", source, "--source-format", "json", "--name", "secret", "--json")
		publicAssertSet(t, result, source, "secret")
		clear(result.Body)
	}
	var lastCapture nativeprocess.Capture
	command := func(policy nativeprocess.Policy, args ...string) publicChildResult {
		policy.MaxBytes = 8 << 20
		run := func() publicChildResult {
			return publicCLI(t, ctx, inv, input, budget, "apply", false, policy, nil, args...)
		}
		if len(args) > 0 && args[0] == "rekey" || len(args) > 1 && args[0] == "recipients" && args[1] == "retire" {
			return publicMaintenanceSourceProtected(t, source, run)
		}
		return publicLifecycleReadOnly(t, source, run)
	}
	selectStep := func(kind uint16, check func(*StateSession, *StateSession) []contract.ChangedSubjectIdentity, args ...string) {
		child := command(nativeprocess.Policy{}, args...)
		lastCapture = child.Capture
		defer clear(child.Body)
		after := open()
		expected := check(current, after)
		publicLifecycleSelected(t, child, kind, current, after, expected)
		if kind != contract.OperationApplyDeclaration {
			index := slices.Index(args, "--out")
			if index < 0 || index+1 >= len(args) {
				t.Fatal("maintenance output argument unavailable")
			}
			output := args[index+1]
			publicMaintenanceDelivered(t, child, source, output)
			publicObserveMaintenance(t, ctx, inv, input, budget, source, output, child, kind, args)
		}
		current = after
		registry = publicLifecycleRegistry(current)
	}
	subject := func(kind, change uint8, primary, secondary contract.ID) contract.ChangedSubjectIdentity {
		return publicLifecycleSubject(t, current.root.Domain, kind, change, primary, secondary)
	}
	updated := func(row contract.ValueEntry) contract.ChangedSubjectIdentity {
		return subject(contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, row.Incarnation, contract.ID{})
	}
	removedMember := func(row contract.ValueEntry, id contract.ID) contract.ChangedSubjectIdentity {
		return subject(contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, row.Incarnation, id)
	}
	expectRegistry := func(s *StateSession, want map[contract.ID]contract.RecipientRecord) {
		if !reflect.DeepEqual(want, publicLifecycleRegistry(s)) {
			t.Fatal("lifecycle selected complete registry differs")
		}
	}
	members := func(ids ...contract.ID) []contract.ID {
		slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		return ids
	}
	assertSecret := func(before, after contract.ValueEntry, readers []contract.ID) {
		if before.Incarnation != after.Incarnation || before.ValueState == after.ValueState || bytes.Equal(before.ValueBytes, after.ValueBytes) || !slices.Equal(after.Recipients, readers) {
			t.Fatal("lifecycle secret did not refresh exact current material/membership")
		}
	}
	turnover := prepare("turnover")
	document := publicSourceDocument(t, source)
	document["entries"] = map[string]any{"secret": map[string]any{"confidentiality": "secret", "recipients": []string{"consumer", "turnover"}, "source": map[string]any{"kind": "supplied"}}, "plain": map[string]any{"confidentiality": "plain", "recipients": []string{"turnover"}, "source": map[string]any{"kind": "supplied", "value": "plain original"}}}
	publicRewritePortableSource(t, source, document)
	set(source)
	selectStep(contract.OperationApplyDeclaration, func(before, after *StateSession) []contract.ChangedSubjectIdentity {
		entries := publicLifecycleEntries(t, after)
		if !slices.Equal(entries["secret"].Recipients, members(authority, consumer.RecipientID, turnover)) || !slices.Equal(entries["plain"].Recipients, members(authority, turnover)) || !bytes.Equal(entries["plain"].ValueBytes, []byte("plain original")) {
			t.Fatal("lifecycle initial complete memberships differ")
		}
		want := publicLifecycleRegistry(before)
		added := publicLifecycleRegistry(after)[turnover]
		if !publicLifecyclePreparedRecipientMatches(added, preparations[turnover]) || added.CurrentBinding == nil || added.CurrentBinding.KeySelector != input.Settings.ReaderKEKID || added.DisplayName != "turnover" || added.CurrentBinding.Fingerprint != consumer.CurrentBinding.Fingerprint {
			t.Fatal("lifecycle prepared recipient not selected exactly")
		}
		want[turnover] = added
		expectRegistry(after, want)
		rows := []contract.ChangedSubjectIdentity{subject(contract.ChangedSubjectRecipient, contract.ChangedSubjectAdded, turnover, contract.ID{})}
		for _, name := range []string{"secret", "plain"} {
			row := entries[name]
			rows = append(rows, subject(contract.ChangedSubjectValueEntry, contract.ChangedSubjectAdded, row.Incarnation, contract.ID{}))
			for _, id := range row.Recipients {
				rows = append(rows, subject(contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, row.Incarnation, id))
			}
		}
		return rows
	}, "apply", "--source", source, "--source-format", "json", "--json")
	oldTurnover := registry[turnover]
	runPublicPlanning(t, ctx, inv, input, budget, source, current, value)
	publicLifecycleRecipientOracle(t, ctx, inv, input, budget, source, consumer, value, false)
	document = publicSourceDocument(t, source)
	document["recipients"].(map[string]any)["turnover"].(map[string]any)["display_name"] = "Changed display"
	publicRewritePortableSource(t, source, document)
	selectStep(contract.OperationApplyDeclaration, func(before, after *StateSession) []contract.ChangedSubjectIdentity {
		if !reflect.DeepEqual(publicLifecycleEntries(t, before), publicLifecycleEntries(t, after)) || !slices.Equal(before.root.CurrentAccess.Core.AccessPageRefs, after.root.CurrentAccess.Core.AccessPageRefs) {
			t.Fatal("display changed material or access")
		}
		want := publicLifecycleRegistry(before)
		row := want[turnover]
		row.DisplayName = "Changed display"
		want[turnover] = row
		expectRegistry(after, want)
		return []contract.ChangedSubjectIdentity{subject(contract.ChangedSubjectRecipient, contract.ChangedSubjectUpdated, turnover, contract.ID{})}
	}, "apply", "--source", source, "--source-format", "json", "--json")
	noop := func(privateEquality bool) {
		child := command(nativeprocess.Policy{}, "apply", "--source", source, "--source-format", "json", "--json")
		defer clear(child.Body)
		if !publicApplyMatches(child, publicProduct(t, child, "apply-declaration"), "no-op") {
			t.Fatal("lifecycle exact repeat not no-op")
		}
		privateOpens := 0
		for _, e := range child.Capture.Events {
			if e.Kind == "http-return" && e.Operation == "kms-decrypt" && e.Role == "authority" && e.Sent && e.Status == 200 {
				privateOpens++
			}
			if e.Kind == "http-start" && (e.Operation == "head-write" || e.Operation == "store-write" || e.Operation == "kms-sign") {
				t.Fatal("lifecycle no-op attempted mutation")
			}
		}
		if privateEquality && privateOpens < 2 {
			t.Fatal("original-seal repeat skipped proposed/current private equality")
		}
		after := publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir)
		if !reflect.DeepEqual(current.head, after) {
			t.Fatal("lifecycle no-op changed selected state")
		}
	}
	noop(false)
	oldSource := publicPortablePair(t, source, filepath.Join(inv.StateDir, "lifecycle-old-pair"))
	oldGenerated, ok := publicSourceDocument(t, oldSource)["generated"].(string)
	if !ok || oldGenerated == "" {
		t.Fatal("old lifecycle pair generated member unavailable")
	}
	// Maintenance opens native coordination before refusing a retired identity.
	for _, path := range []string{oldSource, filepath.Join(filepath.Dir(oldSource), filepath.FromSlash(oldGenerated))} {
		parent := filepath.Dir(path)
		for _, name := range []string{".enkv-locks", ".enkv-pending"} {
			if err := os.Mkdir(filepath.Join(parent, name), 0700); err != nil {
				t.Fatal("old lifecycle pair coordination directory unavailable", err)
			}
		}
		if err := os.WriteFile(filepath.Join(parent, ".enkv-locks", filepath.Base(path)), nil, 0600); err != nil {
			t.Fatal("old lifecycle pair coordination lock unavailable", err)
		}
	}
	oldImage := publicSourceImage(t, oldSource)
	exclusionSource := publicPortablePair(t, oldSource, filepath.Join(inv.StateDir, "lifecycle-exclusion-pair"))
	exclusion := publicSourceDocument(t, exclusionSource)
	exclusion["entries"].(map[string]any)["secret"].(map[string]any)["recipients"] = []string{"turnover"}
	publicRewritePortableSource(t, exclusionSource, exclusion)
	exclusionImage := publicSourceImage(t, exclusionSource)
	publicImageUnchanged(t, oldImage)
	document = publicSourceDocument(t, source)
	document["entries"].(map[string]any)["plain"].(map[string]any)["source"].(map[string]any)["value"] = "valid pending value"
	document["recipients"].(map[string]any)["consumer"].(map[string]any)["display_name"] = "Valid pending display"
	publicRewritePortableSource(t, source, document)
	pendingImage := publicSourceImage(t, source)
	pendingSource := source
	source = exclusionSource
	selectStep(contract.OperationApplyDeclaration, func(before, after *StateSession) []contract.ChangedSubjectIdentity {
		a, b := publicLifecycleEntries(t, before), publicLifecycleEntries(t, after)
		assertSecret(a["secret"], b["secret"], members(authority, turnover))
		if !reflect.DeepEqual(a["plain"], b["plain"]) {
			t.Fatal("exclusion applied pending plain value")
		}
		expectRegistry(after, publicLifecycleRegistry(before))
		return []contract.ChangedSubjectIdentity{updated(a["secret"]), removedMember(a["secret"], consumer.RecipientID)}
	}, "apply", "--source", source, "--source-format", "json", "--json")
	publicImageUnchanged(t, exclusionImage)
	noop(true)
	publicImageUnchanged(t, exclusionImage)
	source = pendingSource
	publicImageUnchanged(t, pendingImage)
	publicImageUnchanged(t, oldImage)
	publicLifecycleRecipientOracle(t, ctx, inv, input, budget, source, consumer, value, true)
	refusedDirectory, err := os.MkdirTemp(inv.StateDir, "lifecycle-stale-grant-")
	if err != nil {
		t.Fatal(err)
	}
	refusedOutput := filepath.Join(refusedDirectory, "configuration.json")
	refused := command(nativeprocess.Policy{NoKMS: true}, "recipients", "retire", "--source", source, "--source-format", "json", "--recipient", "turnover", "--out", refusedOutput, "--json")
	publicMaintenanceRefused(t, refused, refusedOutput)
	clear(refused.Body)
	refusedHead := publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir)
	if !reflect.DeepEqual(current.head, refusedHead) {
		t.Fatal("stale pending membership refusal changed selected state")
	}
	publicImageUnchanged(t, pendingImage)
	// Preserve the selected removal together with the unrelated pending edits.
	document = publicSourceDocument(t, source)
	document["entries"].(map[string]any)["secret"].(map[string]any)["recipients"] = []string{"turnover"}
	publicRewritePortableSource(t, source, document)
	pendingImage = publicSourceImage(t, source)
	rekeyDirectory, err := os.MkdirTemp(inv.StateDir, "lifecycle-rekey-")
	if err != nil {
		t.Fatal(err)
	}
	rekeyOutput := filepath.Join(rekeyDirectory, "configuration.json")
	selectStep(contract.OperationEnvelopeRekey, func(before, after *StateSession) []contract.ChangedSubjectIdentity {
		a, b := publicLifecycleEntries(t, before), publicLifecycleEntries(t, after)
		assertSecret(a["secret"], b["secret"], a["secret"].Recipients)
		if !reflect.DeepEqual(a["plain"], b["plain"]) {
			t.Fatal("rekey applied pending plain value")
		}
		expectRegistry(after, publicLifecycleRegistry(before))
		return []contract.ChangedSubjectIdentity{updated(a["secret"])}
	}, "rekey", "--source", source, "--source-format", "json", "--name", "secret", "--out", rekeyOutput, "--json")
	publicMaintenancePrivateBeforeMutation(t, lastCapture)
	publicImageUnchanged(t, pendingImage)
	source = rekeyOutput
	publicLifecycleRecipientOracle(t, ctx, inv, input, budget, source, oldTurnover, value, false)
	retire := func(reference string, id contract.ID, mixed bool) {
		directory, err := os.MkdirTemp(inv.StateDir, "lifecycle-retirement-")
		if err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(directory, "configuration.json")
		selectStep(contract.OperationRetireRecipientIdentity, func(before, after *StateSession) []contract.ChangedSubjectIdentity {
			a, b := publicLifecycleEntries(t, before), publicLifecycleEntries(t, after)
			want := publicLifecycleRegistry(before)
			delete(want, id)
			expectRegistry(after, want)
			rows := []contract.ChangedSubjectIdentity{subject(contract.ChangedSubjectRecipient, contract.ChangedSubjectRemoved, id, contract.ID{})}
			for _, name := range []string{"secret", "plain"} {
				old, next := a[name], b[name]
				if !slices.Contains(old.Recipients, id) {
					if !reflect.DeepEqual(old, next) {
						t.Fatal("retirement changed an unrelated entry")
					}
					continue
				}
				expected := slices.DeleteFunc(slices.Clone(old.Recipients), func(member contract.ID) bool { return member == id })
				if name == "secret" {
					if !mixed {
						t.Fatal("zero-private retirement unexpectedly assigned to secret")
					}
					assertSecret(old, next, expected)
				} else {
					old.Recipients = expected
					if !reflect.DeepEqual(old, next) {
						t.Fatal("retirement changed plain value or identity")
					}
				}
				rows = append(rows, updated(a[name]), removedMember(a[name], id))
			}
			return rows
		}, "recipients", "retire", "--source", source, "--source-format", "json", "--recipient", reference, "--out", output, "--json")
		if mixed {
			publicMaintenancePrivateBeforeMutation(t, lastCapture)
		}
		source = output
	}
	retire("turnover", turnover, true)
	publicLifecycleRecipientOracle(t, ctx, inv, input, budget, source, oldTurnover, value, true)
	source = publicLifecycleNormalize(t, ctx, inv, input, budget, source, filepath.Join(inv.StateDir, "lifecycle-current-pair"), value, current)
	fresh := prepare("turnover")
	plainOnly := prepare("plain-only")
	unassigned := prepare("unassigned")
	if fresh == turnover {
		t.Fatal("same key/reference reused retired ID")
	}
	document = publicSourceDocument(t, source)
	entries := document["entries"].(map[string]any)
	entries["secret"].(map[string]any)["recipients"] = []string{"turnover"}
	entries["plain"].(map[string]any)["recipients"] = []string{"plain-only"}
	publicRewritePortableSource(t, source, document)
	set(source)
	selectStep(contract.OperationApplyDeclaration, func(before, after *StateSession) []contract.ChangedSubjectIdentity {
		a, b := publicLifecycleEntries(t, before), publicLifecycleEntries(t, after)
		expectedSecret := a["secret"]
		expectedSecret.Recipients = members(authority, fresh)
		if !reflect.DeepEqual(expectedSecret, b["secret"]) {
			t.Fatal("equal-plaintext enrollment changed existing secret material or identity")
		}
		oldAccess, nextAccess := before.accessRecords(), after.accessRecords()
		if len(oldAccess) != 1 || len(nextAccess) != 1 {
			t.Fatal("fresh enrollment changed complete material coverage")
		}
		oldRecord, nextRecord := oldAccess[0], nextAccess[0]
		oldWraps, nextWraps := oldRecord.Wraps, nextRecord.Wraps
		oldRecord.Wraps, nextRecord.Wraps = nil, nil
		if !reflect.DeepEqual(oldRecord, nextRecord) || oldRecord.MaterialKind != contract.ValueMaterialKind || oldRecord.MaterialID != a["secret"].ValueState || len(nextWraps) != len(oldWraps)+1 {
			t.Fatal("membership grant changed material package or wrap count")
		}
		freshBinding := after.recipientRecord(fresh)
		if freshBinding == nil || freshBinding.CurrentBinding == nil {
			t.Fatal("fresh recipient binding unavailable")
		}
		bindingDigest, err := contract.PublicBindingDigest(*freshBinding.CurrentBinding)
		if err != nil {
			t.Fatal("fresh public binding refused", err)
		}
		addedWraps := 0
		for _, next := range nextWraps {
			if next.SubjectKind == contract.OrdinaryWrapSubject && next.SubjectID == fresh {
				if next.BindingID != freshBinding.CurrentBinding.BindingID || next.BindingSerial != freshBinding.CurrentBinding.BindingSerial || next.PublicBindingDigest != bindingDigest || len(next.RSACiphertext) != contract.RSACiphertextLength {
					t.Fatal("grant added a different recipient wrap")
				}
				addedWraps++
				continue
			}
			if !slices.ContainsFunc(oldWraps, func(old contract.WrapRow) bool { return reflect.DeepEqual(old, next) }) {
				t.Fatal("grant changed an existing material wrap")
			}
		}
		if addedWraps != 1 {
			t.Fatal("grant did not add exactly one fresh recipient wrap")
		}
		if !reflect.DeepEqual(before.root.Names, after.root.Names) || before.root.ValueEntryCount != after.root.ValueEntryCount || before.root.SecretCount != after.root.SecretCount || before.root.RawBytes != after.root.RawBytes || before.root.WarningBits != after.root.WarningBits || before.root.OutputConfiguration != after.root.OutputConfiguration || !publicLifecycleReceiptOnlyClosure(before.root) || !publicLifecycleReceiptOnlyClosure(after.root) || !publicLifecycleEnrollmentControlMatches(currentControlOf(before), currentControlOf(after)) || after.root.MembershipCount != before.root.MembershipCount+2 || after.root.SecretOrdinaryWrapCount != before.root.SecretOrdinaryWrapCount+1 {
			t.Fatal("fresh enrollment changed unrelated selected state")
		}
		expectedPlain := a["plain"]
		expectedPlain.Recipients = members(authority, plainOnly)
		if !reflect.DeepEqual(expectedPlain, b["plain"]) {
			t.Fatal("fresh enrollment changed plain bytes")
		}
		want := publicLifecycleRegistry(before)
		actual := publicLifecycleRegistry(after)
		rows := []contract.ChangedSubjectIdentity{updated(a["secret"]), updated(a["plain"]), subject(contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, b["secret"].Incarnation, fresh), subject(contract.ChangedSubjectMembership, contract.ChangedSubjectAdded, b["plain"].Incarnation, plainOnly)}
		for _, id := range []contract.ID{fresh, plainOnly, unassigned} {
			row := actual[id]
			if !publicLifecyclePreparedRecipientMatches(row, preparations[id]) || row.CurrentBinding == nil || row.CurrentBinding.KeySelector != input.Settings.ReaderKEKID || row.CurrentBinding.Fingerprint != oldTurnover.CurrentBinding.Fingerprint {
				t.Fatal("fresh prepared registry differs")
			}
			want[id] = row
			rows = append(rows, subject(contract.ChangedSubjectRecipient, contract.ChangedSubjectAdded, id, contract.ID{}))
		}
		expectRegistry(after, want)
		return rows
	}, "apply", "--source", source, "--source-format", "json", "--json")
	publicLifecycleRecipientOracle(t, ctx, inv, input, budget, source, registry[fresh], value, false)
	publicLifecycleRecipientOracle(t, ctx, inv, input, budget, source, oldTurnover, value, true)
	// Each retirement has an unrelated live secret but requires no private open.
	for _, target := range []struct {
		reference string
		id        contract.ID
	}{{"plain-only", plainOnly}, {"unassigned", unassigned}} {
		retire(target.reference, target.id, false)
		for _, event := range lastCapture.Events {
			if event.Kind == "http-start" && event.Operation == "kms-decrypt" {
				t.Fatal("plain-only/unassigned retirement attempted private decryption")
			}
		}
	}
	// Exact old source bindings cannot target or revive the newly assigned ID.
	activeSource := source
	for _, args := range [][]string{{"recipients", "retire", "--source", oldSource, "--source-format", "json", "--recipient", "turnover", "--json"}, {"apply", "--source", oldSource, "--source-format", "json", "--json"}} {
		source = oldSource
		if args[0] == "recipients" {
			directory, err := os.MkdirTemp(inv.StateDir, "lifecycle-stale-retirement-")
			if err != nil {
				t.Fatal(err)
			}
			args = append(args, "--out", filepath.Join(directory, "configuration.json"))
		}
		child := command(nativeprocess.Policy{NoKMS: true}, args...)
		operation := "apply-declaration"
		if args[0] == "recipients" {
			operation = "retire-recipient-identity"
		}
		product := publicProduct(t, child, operation)
		if child.Code == 0 || product.State != "refused" || !product.payloadNull || product.Receipt != "" || product.CommitUnknown {
			t.Fatal("retired exact ID was selected or revived")
		}
		publicAssertGETOnly(t, child.Capture)
		clear(child.Body)
		after := publicIndependentHEAD(t, ctx, input, budget, source, inv.StateDir)
		if !reflect.DeepEqual(current.head, after) {
			t.Fatal("stale exact ID refusal changed selected state")
		}
	}
	source = activeSource
	source = publicLifecycleNormalize(t, ctx, inv, input, budget, source, filepath.Join(inv.StateDir, "lifecycle-final-pair"), value, current)
	noop(false)
	publicImageUnchanged(t, oldImage)
	return source
}
