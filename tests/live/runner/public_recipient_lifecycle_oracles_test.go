package core

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicRecipientLifecycleEnrollmentPreservesWorkControlAndHistory(t *testing.T) {
	id := func(name string) contract.ID { return contract.Hash([]byte(name)) }
	t.Run("control", func(t *testing.T) {
		before := currentControlOf(generatedEmptyPredecessor(t))
		after := before
		after.AccessGeneration++
		if !publicLifecycleEnrollmentControlMatches(before, after) {
			t.Fatal("ordinary access advancement changed unrelated control")
		}
		for _, condition := range []string{"unchanged", "skip", "incarnation", "signer", "authority-key", "maximum"} {
			old, next := before, after
			switch condition {
			case "unchanged":
				next.AccessGeneration--
			case "skip":
				next.AccessGeneration++
			case "incarnation":
				next.AccessIncarnationID = id("other access incarnation")
			case "signer":
				next.NormalSigning.BindingID = id("other signing binding")
			case "authority-key":
				next.AuthorityKMSBinding.BindingID = id("other authority binding")
			case "maximum":
				old.AccessGeneration, next.AccessGeneration = ^uint64(0), 1
			}
			if publicLifecycleEnrollmentControlMatches(old, next) {
				t.Fatal("enrollment accepted changed control or invalid access advancement", condition)
			}
		}
	})
	t.Run("work", func(t *testing.T) {
		root := format.Root{Domain: id("domain"), Generated: format.EmptyGeneratedClosure()}
		root.Generated.SuccessWindow, _ = contract.GeneratorIndexDescriptor(contract.GeneratorSuccessWindow, []contract.ID{id("first receipt")})
		root.Generated.ReceiptOrder, _ = contract.GeneratorIndexDescriptor(contract.GeneratorReceiptOrder, []contract.ID{id("first receipt")})
		index, err := contract.MutationReceiptIndexBlobID(root.Domain, root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder)
		if err != nil {
			t.Fatal("receipt-index fixture unavailable", err)
		}
		root.Generated.Fragments = []format.FragmentLocation{{BlobID: index}}
		if !publicLifecycleReceiptOnlyClosure(root) {
			t.Fatal("receipt-only selected closure refused")
		}
		for _, condition := range []string{"owner", "hazard", "material", "release", "slices", "later-fragment", "missing-fragment"} {
			next := root
			next.Generated.Fragments = slices.Clone(root.Generated.Fragments)
			switch condition {
			case "owner":
				next.Generated.ActiveOwner = id("unexpected work")
			case "hazard":
				next.Generated.Hazards++
			case "material":
				next.Generated.Materials++
			case "release":
				next.Generated.PendingReleases++
			case "slices":
				next.Generated.Slices.Count++
			case "later-fragment":
				next.Generated.Fragments = append(next.Generated.Fragments, format.FragmentLocation{BlobID: id("other blob")})
			case "missing-fragment":
				next.Generated.Fragments = nil
			}
			if publicLifecycleReceiptOnlyClosure(next) {
				t.Fatal("enrollment accepted unrelated or missing generated support", condition)
			}
		}
	})
	t.Run("history", func(t *testing.T) {
		domain := id("history domain")
		first := contract.CompactMutationReceipt{DomainID: domain, OperationID: id("first"), CanonicalOutcome: contract.ReceiptCanonicalSelected}
		failed := contract.CompactMutationReceipt{DomainID: domain, OperationID: id("failed"), CanonicalOutcome: 2}
		added := contract.CompactMutationReceipt{DomainID: domain, OperationID: id("added"), CanonicalOutcome: contract.ReceiptCanonicalSelected}
		before := contract.MutationReceiptWindows{DomainID: domain, Successes: []contract.CompactMutationReceipt{first}, Failures: []contract.CompactMutationReceipt{failed}, Order: []contract.ID{first.OperationID, failed.OperationID}}
		prior := map[contract.ID][]byte{first.OperationID: []byte("frozen first"), failed.OperationID: []byte("frozen failure")}
		raw := []byte("exact new receipt")
		for _, condition := range []string{"exact", "domain", "old-row", "failure-loss", "order", "new-row-loss", "old-bytes", "new-bytes"} {
			after := contract.MutationReceiptWindows{DomainID: domain, Successes: []contract.CompactMutationReceipt{first, added}, Failures: []contract.CompactMutationReceipt{failed}, Order: []contract.ID{first.OperationID, failed.OperationID, added.OperationID}}
			next := map[contract.ID][]byte{first.OperationID: bytes.Clone(prior[first.OperationID]), failed.OperationID: bytes.Clone(prior[failed.OperationID]), added.OperationID: bytes.Clone(raw)}
			switch condition {
			case "domain":
				after.DomainID = id("other domain")
			case "old-row":
				after.Successes[0].SummaryCounts[0]++
			case "failure-loss":
				after.Failures = nil
			case "order":
				after.Order[0], after.Order[1] = after.Order[1], after.Order[0]
			case "new-row-loss":
				after.Successes = after.Successes[:1]
			case "old-bytes":
				next[first.OperationID][0] ^= 1
			case "new-bytes":
				next[added.OperationID][0] ^= 1
			}
			if publicLifecycleReceiptAppendMatches(before, after, prior, next, added, raw) != (condition == "exact") {
				t.Fatal("enrollment accepted a changed receipt history or rejected its exact append", condition)
			}
		}
	})
}

// full_only: false
func TestPublicRecipientLifecycleSourceProtectionRestoresExactModes(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.json")
	generated := filepath.Join(directory, ".enkv", "prod.generated.json")
	if os.Mkdir(filepath.Dir(generated), 0700) != nil || os.WriteFile(generated, []byte("{}\n"), 0600) != nil {
		t.Fatal("source protection fixture unavailable")
	}
	publicWriteSource(t, source, map[string]any{"generated": ".enkv/prod.generated.json"})
	image := publicSourceImage(t, source)
	modes := map[string]os.FileMode{directory: 0700, filepath.Dir(generated): 0700, source: 0600, generated: 0600}
	for path, mode := range modes {
		if os.Chmod(path, mode) != nil {
			t.Fatal("source protection mode unavailable")
		}
	}
	child := publicLifecycleReadOnly(t, source, func() publicChildResult {
		for path := range modes {
			info, err := os.Stat(path)
			want := os.FileMode(0400)
			if path == directory || path == filepath.Dir(generated) {
				want = 0500
			}
			if err != nil || info.Mode().Perm() != want {
				t.Fatal("child did not receive read-only exact pair")
			}
		}
		return publicChildResult{Code: 7}
	})
	if child.Code != 7 {
		t.Fatal("source guard changed returned outcome")
	}
	publicImageUnchanged(t, image)
	for path, want := range modes {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatal("source guard changed original modes")
		}
	}
}

// full_only: false
func TestPublicRecipientLifecycleMaintenanceProtectionKeepsCoordinationWritable(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.json")
	generated := filepath.Join(directory, ".enkv", "prod.generated.json")
	if os.Mkdir(filepath.Dir(generated), 0700) != nil || os.WriteFile(generated, []byte("{}\n"), 0600) != nil {
		t.Fatal("maintenance protection fixture unavailable")
	}
	publicWriteSource(t, source, map[string]any{"generated": ".enkv/prod.generated.json"})
	modes := map[string]os.FileMode{directory: 0700, filepath.Dir(generated): 0700, source: 0600, generated: 0600}
	var locks []string
	for _, path := range []string{source, generated} {
		parent := filepath.Dir(path)
		for _, name := range []string{".enkv-locks", ".enkv-pending"} {
			coordination := filepath.Join(parent, name)
			if os.Mkdir(coordination, 0700) != nil {
				t.Fatal("maintenance coordination directory unavailable")
			}
			modes[coordination] = 0700
		}
		lock := filepath.Join(parent, ".enkv-locks", filepath.Base(path))
		if os.WriteFile(lock, nil, 0600) != nil {
			t.Fatal("maintenance coordination lock unavailable")
		}
		locks = append(locks, lock)
		modes[lock] = 0600
	}
	for path, mode := range modes {
		if os.Chmod(path, mode) != nil {
			t.Fatal("maintenance fixture mode unavailable")
		}
	}
	image := publicSourceImage(t, source)
	child := publicMaintenanceSourceProtected(t, source, func() publicChildResult {
		for path, mode := range modes {
			want := mode
			if path == source || path == generated {
				want = 0400
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != want {
				t.Fatal("maintenance source/coordination protection differs")
			}
		}
		for _, path := range locks {
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal("maintenance cannot open its existing native lock", err)
			}
			if err := file.Close(); err != nil {
				t.Fatal("maintenance native lock close failed", err)
			}
		}
		return publicChildResult{Code: 7}
	})
	if child.Code != 7 {
		t.Fatal("maintenance protection changed returned outcome")
	}
	publicImageUnchanged(t, image)
	for path, want := range modes {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatal("maintenance protection changed original modes")
		}
	}
}

// full_only: false
func TestPublicRecipientLifecycleOracleRequiresExactAbsentOrPresentWrap(t *testing.T) {
	for _, absent := range []bool{false, true} {
		for _, condition := range []string{"exact", "missing", "duplicate", "wrong-count", "wrong-match", "wrong-absence", "extra-decrypt", "wrong-route", "mutation"} {
			name := "present/"
			if absent {
				name = "absent/"
			}
			t.Run(name+condition, func(t *testing.T) {
				event := nativeprocess.Event{Kind: "recipient-plaintext", WrapAbsent: absent, Matched: !absent}
				if !absent {
					event.Count = 1
				}
				capture := nativeprocess.Capture{Events: []nativeprocess.Event{event}}
				if !absent {
					capture.Events = append(capture.Events, nativeprocess.Event{Kind: "http-start", Operation: "kms-decrypt", Role: "recipient-private"})
				}
				switch condition {
				case "missing":
					capture.Events = nil
				case "duplicate":
					capture.Events = append(capture.Events, event)
				case "wrong-count":
					capture.Events[0].Count = 2
				case "wrong-match":
					capture.Events[0].Matched = absent
				case "wrong-absence":
					capture.Events[0].WrapAbsent = !absent
				case "extra-decrypt":
					capture.Events = append(capture.Events, nativeprocess.Event{Kind: "http-start", Operation: "kms-decrypt", Role: "recipient-private"})
				case "wrong-route":
					capture.Events = append(capture.Events, nativeprocess.Event{Kind: "http-start", Operation: "kms-decrypt", Role: "authority"})
				case "mutation":
					capture.Events = append(capture.Events, nativeprocess.Event{Kind: "http-start", Operation: "head-write"})
				}
				if publicLifecycleRecipientCapture(capture, absent) != (condition == "exact") {
					t.Fatal("recipient oracle accepted another observation")
				}
			})
		}
	}
}

// full_only: false
func TestPublicRecipientLifecycleReceiptPinsKindSubjectsAndSelectedFacts(t *testing.T) {
	id := func(text string) contract.ID { return contract.Hash([]byte(text)) }
	before, after := &StateSession{}, &StateSession{}
	before.head.Core.Revision = id("before")
	after.head.Core.Revision = id("after")
	after.root.Domain = id("domain")
	after.root.WarningBits = WarningPossibleStoreGarbage
	if publicLifecycleOperation(contract.OperationRemoveSecretValueEntryAccess) != "" {
		t.Fatal("withdrawn standalone exclusion remains a supported lifecycle operation")
	}
	operation, identity := id("operation"), id("identity")
	request := id("signed request core")
	empty := contract.EmptyMutationResultDescriptors()
	expected := contract.GeneratorDescriptor{Digest: id("independent changed subjects"), Length: 80, Count: 2}
	for _, kind := range []uint16{contract.OperationApplyDeclaration, contract.OperationEnvelopeRekey, contract.OperationRetireRecipientIdentity} {
		t.Run(publicLifecycleOperation(kind), func(t *testing.T) {
			warnings, err := contract.EncodeReceiptWarningBits(kind, after.root.WarningBits, 0)
			if err != nil {
				t.Fatal(err)
			}
			receipt := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: kind, StateResult: contract.ReceiptStateSuccess, EffectSummary: contract.ReceiptEffectNotApplicable, OutputSummary: contract.ReceiptOutputNotApplicable, EvidenceCeiling: contract.ReceiptEvidenceCanonical, DomainID: after.root.Domain, OperationID: operation, RequestIdentityDigest: identity, PredecessorRevisionID: before.head.Core.Revision, RequestedRevisionID: after.head.Core.Revision, ObservedRevisionID: after.head.Core.Revision, CanonicalOutcome: contract.ReceiptCanonicalSelected, ChangedSubjects: expected, WarningBits: warnings}
			if kind == contract.OperationApplyDeclaration {
				receipt.EffectSummary = contract.ReceiptEffectNoChange
			}
			access := empty[0]
			if kind == contract.OperationApplyDeclaration {
				access = contract.GeneratorDescriptor{Digest: id("independently expected access change"), Length: 106, Count: 1}
			}
			receipt.SummaryCounts[contract.ReceiptChangedAccessCount] = access.Count
			plan := contract.CompactMutationReceiptPlan(receipt)
			plan.RequestIdentityDigest = contract.ID{}
			receipt.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: plan, RequestCoreDigest: request, ChangedAccess: access, Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
			if err != nil {
				t.Fatal("expected complete receipt projection refused", err)
			}
			raw, err := contract.EncodeCompactMutationReceipt(receipt)
			if err != nil {
				t.Fatal("actual compact receipt fixture invalid", err)
			}
			decoded, err := contract.InspectCompactMutationReceipt(raw)
			if err != nil || !publicLifecycleReceiptMatches(kind, decoded, before, after, operation, identity, expected, request, access) {
				t.Fatal("exact receipt facts refused", err)
			}
			substitutedAccess := access
			substitutedAccess.Digest = id("substituted exact access set")
			if publicLifecycleReceiptMatches(kind, receipt, before, after, operation, identity, expected, request, substitutedAccess) || publicLifecycleReceiptMatches(kind, receipt, before, after, operation, identity, expected, id("different request core"), access) {
				t.Fatal("complete receipt ignored exact access or request commitment")
			}
			for _, row := range []struct {
				name   string
				change func(*contract.CompactMutationReceipt)
			}{
				{"operation", func(r *contract.CompactMutationReceipt) { r.OperationID = id("other") }},
				{"kind", func(r *contract.CompactMutationReceipt) {
					r.OperationKind = contract.OperationRotateRecipientKeyBinding
				}},
				{"domain", func(r *contract.CompactMutationReceipt) { r.DomainID = id("other") }},
				{"identity", func(r *contract.CompactMutationReceipt) { r.RequestIdentityDigest = id("other") }},
				{"predecessor", func(r *contract.CompactMutationReceipt) { r.PredecessorRevisionID = id("other") }},
				{"requested", func(r *contract.CompactMutationReceipt) { r.RequestedRevisionID = id("other") }},
				{"observed", func(r *contract.CompactMutationReceipt) { r.ObservedRevisionID = id("other") }},
				{"not-selected", func(r *contract.CompactMutationReceipt) { r.CanonicalOutcome = contract.ReceiptCanonicalNotSelected }},
				{"pending", func(r *contract.CompactMutationReceipt) { r.StateResult = contract.ReceiptStateRetirementPending }},
				{"effect", func(r *contract.CompactMutationReceipt) { r.EffectSummary = contract.ReceiptEffectComplete }},
				{"output", func(r *contract.CompactMutationReceipt) { r.OutputSummary = 1 }},
				{"evidence", func(r *contract.CompactMutationReceipt) { r.EvidenceCeiling = contract.ReceiptEvidenceProviderFacts }},
				{"changed-access-count", func(r *contract.CompactMutationReceipt) { r.SummaryCounts[contract.ReceiptChangedAccessCount]++ }},
				{"complete-result-digest", func(r *contract.CompactMutationReceipt) {
					r.CompleteResult.Digest = id("same-shape substituted result")
				}},
				{"complete-result-length", func(r *contract.CompactMutationReceipt) { r.CompleteResult.Length++ }},
				{"complete-result-count", func(r *contract.CompactMutationReceipt) { r.CompleteResult.Count++ }},
				{"subject-count", func(r *contract.CompactMutationReceipt) { r.ChangedSubjects.Count++ }},
				{"same-count-substitution", func(r *contract.CompactMutationReceipt) { r.ChangedSubjects.Digest = id("other") }},
				{"subject-length", func(r *contract.CompactMutationReceipt) { r.ChangedSubjects.Length++ }},
				{"missing-domain-warning", func(r *contract.CompactMutationReceipt) { r.WarningBits = 0 }},
				{"possible-live", func(r *contract.CompactMutationReceipt) { r.WarningBits |= contract.ReceiptWarningPossibleLive }},
				{"duty", func(r *contract.CompactMutationReceipt) { r.SummaryCounts[contract.ReceiptDutyCount] = 1 }},
				{"hazard", func(r *contract.CompactMutationReceipt) { r.SummaryCounts[contract.ReceiptHazardCount] = 1 }},
			} {
				t.Run(row.name, func(t *testing.T) {
					changed := receipt
					row.change(&changed)
					if publicLifecycleReceiptMatches(kind, changed, before, after, operation, identity, expected, request, access) {
						t.Fatal("receipt oracle accepted substituted facts")
					}
				})
			}
		})
	}
}

// The process calls are finite: fifteen mutation-class calls (including init,
// three no-ops and three refusals), four Proposer preparations, five Sets,
// six Recipient oracles, two reconstructions, three strict public plans,
// eleven private/public proposal plans, thirteen local pair inspections and
// four exact maintenance observations. Selected GETs and preflight are charged
// separately by the existing recorded Store owner.
// full_only: false
func TestPublicRecipientLifecycleReservationsFitExistingLimits(t *testing.T) {
	budget := &runBudget{limits: liveLimits{Requests: 6144, BodyBytes: 1280 << 20, Objects: 256, ObjectBytes: 512 << 20, GeneratorCreates: 1, GeneratorRetires: 1}}
	children := []struct {
		count  uint64
		charge budgetReservation
	}{
		{1, budgetReservation{Requests: 128, BodyBytes: 16 << 20, Objects: 16, ObjectBytes: 8 << 20}},
		{14, budgetReservation{Requests: 128, BodyBytes: 8 << 20, Objects: 16, ObjectBytes: 8 << 20}},
		{4, budgetReservation{Requests: 64, BodyBytes: 8 << 20}},
		{5, budgetReservation{Requests: 1, BodyBytes: 1}},
		{6, budgetReservation{Requests: 128, BodyBytes: 8 << 20}},
		{2, budgetReservation{Requests: 128, BodyBytes: 8 << 20}},
		{3, budgetReservation{Requests: 128, BodyBytes: 16 << 20}},
		{13, budgetReservation{Requests: 1, BodyBytes: 1}},
		{4, budgetReservation{Requests: 64, BodyBytes: 4 << 20}},
		{11, budgetReservation{Requests: 128, BodyBytes: 8 << 20}},
	}
	captures := uint64(0)
	for _, row := range children {
		for i := uint64(0); i < row.count; i++ {
			if !budget.absorbChild(row.charge) {
				t.Fatal("finite lifecycle children exceed configured limits")
			}
			captures++
		}
	}
	// At most ten cached child objects and four fixed HEAD/root/configuration
	// reads per independent selected open; seven standalone HEAD checks and the
	// existing sixteen-call preflight plus three outer observations. Each
	// recorded read charges 5 MiB and 2 sends.
	reads := uint64(9*14 + 7 + 16 + 3)
	if !budget.absorbChild(budgetReservation{Requests: 2 * reads, BodyBytes: reads * operationBodyAllowance}) {
		t.Fatal("lifecycle independent reads exceed configured limits")
	}
	used := budget.snapshot()
	if captures != 63 || captures > 64 || used.Objects != 240 || used.ObjectBytes != 120<<20 || used.GeneratorCreates != 0 || used.GeneratorRetires != 0 || used.Requests != 5570 || used.BodyBytes != (1136<<20)+18 {
		t.Fatal("lifecycle finite reservation account changed", captures, used)
	}
}
