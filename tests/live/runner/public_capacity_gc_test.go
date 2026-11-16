package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

// These facts are independent selected Store facts and literal supplied input.
// They contain no token and do not transport a prior capacity projection.
type publicCapacityGCFacts struct {
	RunID, Prefix, Domain, Operation, PlanDigest string
	Revision, Snapshot, RootDigest, ValueBase64  string
	TargetCount                                  int
	PlanArtifact                                 string
}

type publicGCObservation struct {
	Domain   string `json:"domain_id"`
	Revision string `json:"head_revision_id"`
	Snapshot string `json:"snapshot_id"`
	Root     string `json:"root_digest"`
}

type publicGCGarbage struct {
	NextCursor       string `json:"next_cursor"`
	ObservationLimit string `json:"observation_limit"`
	Targets          struct {
		Digest string `json:"digest"`
		Length uint64 `json:"length"`
		Count  uint32 `json:"count"`
	} `json:"targets"`
	Candidates []struct {
		KeyDigest      string `json:"key_digest"`
		Classification string `json:"classification"`
		TargetIndex    uint16 `json:"target_index"`
	} `json:"candidates"`
}

func publicCapacityGCQuery(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput,
	budget *runBudget, source string, args ...string) publicChildResult {
	t.Helper()
	domain := publicReadDomain(t, source)
	policy := nativeprocess.Policy{NoKMS: true, ListPrefix: input.Prefix + "/" + hex.EncodeToString(domain[:]) + "/"}
	child := publicCLIReserved(t, ctx, inv, input, budget, "reader", false, policy,
		budgetReservation{Requests: 256, BodyBytes: 32 << 20}, nil, args...)
	if !publicCapacityGCCapture(child.Capture, true, nil, input.Prefix, domain) {
		t.Fatal("capacity/GC query exceeded GET and one-page LIST capability")
	}
	return child
}

// The existing capture parser proves paired physical calls and child join.
// This check fixes the narrower operation-specific capability and exact delete
// conditions. It never weakens the ordinary inspection GET-only validator.
func publicCapacityGCCapture(capture nativeprocess.Capture, query bool, plan *contract.GCPlan, prefix string, domain contract.ID) bool {
	allowed := make(map[string]contract.Token)
	if plan != nil {
		for _, target := range plan.Targets {
			key, err := contract.StoreObjectKey(prefix, domain, target.Object)
			if err != nil {
				return false
			}
			digest := contract.Hash([]byte(key))
			allowed[hex.EncodeToString(digest[:])] = target.Token
		}
	}
	lists, reads, deletes, headWrites, immutableWrites, targetReads := 0, 0, 0, 0, 0, 0
	seenDeletes := make(map[string]bool)
	footer := false
	for _, event := range capture.Events {
		if footer {
			return false
		}
		switch event.Kind {
		case "source-kind":
			if event.Count != 1 || !event.Matched {
				return false
			}
		case "construction":
			if query || plan == nil || event.Role != "normal" || event.Operation != "signing-metadata" && event.Operation != "signer" {
				return false
			}
		case "http-start", "http-return", "store-result":
			switch event.Operation {
			case "head-read", "store-read":
				if event.Kind == "http-start" {
					reads++
					if _, target := allowed[event.ObjectKeySHA256]; target {
						targetReads++
					}
				}
			case "store-list":
				if !query {
					return false
				}
				if event.Kind == "http-start" {
					lists++
				}
			case "kms-public", "kms-sign":
				if query || plan == nil || event.Role != "normal" {
					return false
				}
			case "store-write", "head-write":
				if query || plan == nil {
					return false
				}
				if event.Operation == "head-write" && event.Kind == "http-start" {
					headWrites++
				}
				if event.Operation == "store-write" && event.Kind == "http-start" {
					immutableWrites++
				}
			case "store-delete":
				if query || plan == nil {
					return false
				}
				if event.Kind == "http-start" || event.Kind == "store-result" {
					token, found := allowed[event.ObjectKeySHA256]
					if !found || event.LogicalConditionKind != "match" || !bytes.Equal(event.LogicalConditionValue, []byte(token.Value)) {
						return false
					}
				}
				if event.Kind == "http-start" {
					if seenDeletes[event.ObjectKeySHA256] {
						return false
					}
					seenDeletes[event.ObjectKeySHA256] = true
					deletes++
				}
			default:
				return false
			}
		case "footer":
			if (query || plan != nil) && event.Code != 0 {
				return false
			}
			footer = true
		default:
			return false
		}
	}
	return footer && reads > 0 && lists <= 1 && (!query || lists == 1) && headWrites <= 4 && immutableWrites <= 64 &&
		(plan == nil && deletes == 0 || plan != nil && deletes == len(plan.Targets) && headWrites == 4 && targetReads <= 6*len(plan.Targets))
}

func publicCapacityGCSelected(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) (*StateSession, contract.Store) {
	t.Helper()
	basis, descriptor := publicOperatorGenesis(t, source)
	store, err := openPublicReaderStore(ctx, input, descriptor.DomainID, inv.StateDir)
	if err != nil {
		t.Fatal("capacity/GC independent public Store unavailable")
	}
	return publicOperatorOpen(t, ctx, descriptor.DomainID, basis, recordedStore{Store: store, budget: budget}), store
}

func publicCapacityGCExpectedTargets(t testing.TB, ctx context.Context, input liveRunInput, budget *runBudget,
	cleaner *livePrefixCleaner, selected *StateSession, store contract.Store) []contract.GCTarget {
	t.Helper()
	protected := map[string]bool{store.Descriptor().HeadKey: true}
	add := func(ref format.Ref) {
		key, err := format.Key(store.Descriptor().Prefix, ref)
		if err != nil {
			t.Fatal("capacity/GC independent selected Ref key")
		}
		protected[key] = true
	}
	add(selected.head.Core.Root)
	for _, list := range [][]*format.Ref{selected.root.ValueEntryPages[:], selected.root.Recipients[:]} {
		for _, ref := range list {
			if ref != nil {
				add(*ref)
			}
		}
	}
	for _, ref := range selected.root.CurrentAccess.Core.AccessPageRefs {
		add(ref)
	}
	for _, ref := range selected.root.RequiredSupport {
		add(ref)
	}
	add(selected.root.AdministrativeIndex)
	for _, ref := range selected.root.AdministrativeIndexShards {
		add(ref)
	}
	configuration, err := contract.StoreConfigurationKeyForID(store.Descriptor().Family, input.Prefix, selected.root.Domain, store.Descriptor().Identity)
	if err != nil {
		t.Fatal("capacity/GC independent Store configuration key")
	}
	protected[configuration] = true
	keys, err := scanOperatorPrefix(ctx, cleaner, budget, input.Prefix+"/")
	if err != nil || len(keys) > 64 || selected.root.ChildCount > 12 || selected.root.ChildEncodedBytes > 1<<20 || selected.head.Core.Root.Length > 64<<10 ||
		selected.root.ValueEntryCount != 1 || selected.root.SecretCount != 0 || selected.root.Generated.GeneratedCurrent != 0 ||
		selected.root.RecipientCount != 2 || selected.root.OutputConfiguration.BindingCount != 0 || len(selected.adminIndex.Groups) != 0 {
		t.Fatal("capacity/GC fixture exceeded its explicit small public bounds")
	}
	slices.Sort(keys)
	var targets []contract.GCTarget
	for _, key := range keys {
		if protected[key] {
			continue
		}
		object, err := contract.ParseStoreObjectKey(input.Prefix, selected.root.Domain, key)
		if err != nil {
			t.Fatal("capacity/GC owned prefix contains an unexpected object key")
		}
		if !budget.reserve(2, operationBodyAllowance, "", 0) {
			t.Fatal("capacity/GC exact original GET reservation")
		}
		read := store.Read(ctx, key, contract.StoreObjectLimit(object))
		if read.Status != contract.ReadOK || len(read.Body) == 0 || len(read.Body) > 1<<20 || !read.Token.Valid() {
			t.Fatal("capacity/GC exact original physical facts unavailable")
		}
		targets = append(targets, contract.GCTarget{Object: object, Length: uint32(len(read.Body)), Digest: contract.Hash(read.Body), Token: read.Token})
	}
	if len(targets) == 0 {
		t.Fatal("actual public history produced no obsolete immutable object")
	}
	return targets
}

func publicCapacityGCPlan(t testing.TB, path string, expected []contract.GCTarget) ([]byte, contract.GCPlan) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > contract.GCPlanMaxLength {
		t.Fatal("capacity/GC protected plan artifact metadata refused")
	}
	body, err := os.ReadFile(path)
	plan, decodeErr := contract.DecodeGCPlan(body)
	if err != nil || decodeErr != nil || expected != nil && !slices.Equal(plan.Targets, expected) || plan.InputProviderCursor != "" || plan.NextProviderCursor != "" {
		t.Fatal("capacity/GC protected artifact changed independent original targets")
	}
	return body, plan
}

func publicCapacityGCObservationMatches(observation publicGCObservation, selected *StateSession) bool {
	return observation.Domain == hex.EncodeToString(selected.root.Domain[:]) && observation.Revision == hex.EncodeToString(selected.head.Core.Revision[:]) &&
		observation.Snapshot == hex.EncodeToString(selected.root.Snapshot[:]) && observation.Root == hex.EncodeToString(selected.head.Core.Root.Digest[:])
}

func publicCapacityGCValue(t testing.TB, selected *StateSession, value []byte) {
	t.Helper()
	if len(selected.root.Names) != 1 || selected.root.Names[0].Name != "plain" {
		t.Fatal("capacity/GC selected supplied name changed")
	}
	entry := selected.valueEntry(selected.root.Names[0].Slot)
	if entry == nil || entry.ValueSource != contract.Supplied || entry.ConfidentialityClass != contract.Plain || !bytes.Equal(entry.ValueBytes, value) || !slices.Equal(entry.Recipients, []contract.ID{selected.admission.recipient}) {
		t.Fatal("capacity/GC changed its literal current Plain value")
	}
}

func publicCapacityGCFactsValid(f publicCapacityGCFacts, run, prefix, domain string) bool {
	value, err := base64.StdEncoding.Strict().DecodeString(f.ValueBase64)
	return err == nil && bytes.Equal(value, []byte("gc-three")) && f.RunID == run && f.Prefix == prefix && f.Domain == domain && f.TargetCount > 0 && f.TargetCount <= 64 &&
		!filepath.IsAbs(f.PlanArtifact) && filepath.Clean(f.PlanArtifact) == f.PlanArtifact && strings.HasPrefix(f.PlanArtifact, "capacity-gc-plan-") && filepath.Base(f.PlanArtifact) == "plan.bin" &&
		publicIdentityHex(f.Domain) && publicIdentityHex(f.Operation) && publicIdentityHex(f.PlanDigest) && publicIdentityHex(f.Revision) && publicIdentityHex(f.Snapshot) && publicIdentityHex(f.RootDigest)
}

func publicCapacityGCFreshFactsValid(condition string, facts publicProcessFacts, run, prefix string) bool {
	if condition != "capacity-gc" {
		return facts.CapacityGC == nil
	}
	return facts.CapacityGC != nil && facts.Operator == nil && facts.Replacement == nil && facts.Inspection == nil && len(facts.Outputs) == 0 && facts.ExpectReady &&
		publicCapacityGCFactsValid(*facts.CapacityGC, run, prefix, facts.Domain)
}

func publicCapacityGCPayload(t testing.TB, child publicChildResult, operation, schema string, payload any) publicProductResult {
	t.Helper()
	product := publicProduct(t, child, operation)
	var fields struct {
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(child.Body, &fields) != nil || product.OperationPayload != schema || json.Unmarshal(fields.Payload, payload) != nil {
		t.Fatal("capacity/GC typed public payload refused")
	}
	return product
}

func runPublicCapacityGC(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput,
	budget *runBudget, source string) *publicCapacityGCFacts {
	t.Helper()
	for _, role := range []string{"authority", "apply", "cleanup"} {
		if input.Participants["reader"] == input.Participants[role] {
			t.Fatal("capacity/GC requires its independently selected Reader")
		}
	}
	value := []byte("gc-three")
	for _, plain := range [][]byte{[]byte("gc-one"), []byte("gc-two"), value} {
		document := publicSourceDocument(t, source)
		document["entries"] = map[string]any{"plain": map[string]any{"confidentiality": "plain", "recipients": []string{},
			"source": map[string]any{"kind": "supplied", "bytes": base64.StdEncoding.EncodeToString(plain)}}}
		publicWriteSource(t, source, document)
		image := publicSourceImage(t, source)
		child := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil,
			"apply", "--source", source, "--source-format", "json", "--json")
		product := publicProduct(t, child, "apply-declaration")
		if !publicApplyMatches(child, product, "success") {
			t.Fatal("capacity/GC real ordinary history did not select")
		}
		publicImageUnchanged(t, image)
		publicAssertNoRecovery(t, child.Capture)
		clear(child.Body)
	}
	selected, physical := publicCapacityGCSelected(t, ctx, inv, input, budget, source)
	publicCapacityGCValue(t, selected, value)
	beforeWindows, beforeBodies, err := selected.retainedMutationReceiptBodies()
	if err != nil {
		t.Fatal("capacity/GC independent original receipt facts")
	}
	cleaner, err := openPublicPrefixCleaner(ctx, input, selected.root.Domain, inv.StateDir)
	if err != nil {
		t.Fatal("capacity/GC selected Domain inventory unavailable")
	}
	expected := publicCapacityGCExpectedTargets(t, ctx, input, budget, cleaner, selected, physical)
	image := publicSourceImage(t, source)
	capacity := publicCapacityGCQuery(t, ctx, inv, input, budget, source,
		"inspect", "--source", source, "--source-format", "json", "--capacity", "--json")
	publicCapacityGCCheckCapacity(t, capacity, selected)
	clear(capacity.Body)
	// The plan artifact is outside the exact source-pair directory inventory.
	planDirectory, err := os.MkdirTemp(inv.StateDir, "capacity-gc-plan-")
	if err != nil {
		t.Fatal("capacity/GC protected plan directory unavailable")
	}
	planPath := filepath.Join(planDirectory, "plan.bin")
	preview := publicCapacityGCQuery(t, ctx, inv, input, budget, source,
		"gc", "plan", "--source", source, "--source-format", "json", "--out", planPath, "--json")
	var previewPayload struct {
		Schema      string              `json:"schema"`
		Phase       string              `json:"phase"`
		Operation   string              `json:"proposed_operation_id"`
		PlanDigest  string              `json:"plan_digest"`
		Selected    bool                `json:"selected"`
		Consumed    uint64              `json:"consumed_allowances"`
		Observation publicGCObservation `json:"observation"`
		Garbage     publicGCGarbage     `json:"garbage"`
	}
	product := publicCapacityGCPayload(t, preview, "gc-plan", "CleanupPayload/v1", &previewPayload)
	body, plan := publicCapacityGCPlan(t, planPath, expected)
	digest := contract.Hash(body)
	if preview.Code != 0 || product.State != "success" || previewPayload.Schema != "CleanupPayload/v1" || previewPayload.Phase != "preview" ||
		previewPayload.Operation != hex.EncodeToString(plan.OperationID[:]) || previewPayload.PlanDigest != hex.EncodeToString(digest[:]) ||
		previewPayload.Selected || previewPayload.Consumed != 0 || !publicCapacityGCObservationMatches(previewPayload.Observation, selected) ||
		previewPayload.Garbage.Targets.Count != uint32(len(expected)) || previewPayload.Garbage.NextCursor != "" || previewPayload.Garbage.ObservationLimit != "one-page-no-snapshot" {
		t.Fatal("capacity/GC public preview changed exact independent source facts")
	}
	var delivered struct {
		Delivery struct {
			Created  bool `json:"plan_created"`
			Synced   bool `json:"plan_synced"`
			Readback bool `json:"plan_readback"`
			Failed   bool `json:"plan_failed"`
			Cleanup  bool `json:"cleanup_failed"`
		} `json:"delivery"`
	}
	if json.Unmarshal(preview.Body, &delivered) != nil || !delivered.Delivery.Created || !delivered.Delivery.Synced || !delivered.Delivery.Readback || delivered.Delivery.Failed || delivered.Delivery.Cleanup {
		t.Fatal("capacity/GC preview did not deliver the protected read-back artifact")
	}
	clear(preview.Body)
	publicImageUnchanged(t, image)
	// Small fixture bound: <=12 current children, <=64 original targets,
	// <=4 selected phases, <=64 new immutable objects and <=384 target GETs.
	// Reserve before the child; never borrow cleanup budget for Product work.
	applied := publicCLIReserved(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{},
		budgetReservation{Requests: 768, BodyBytes: 64 << 20, Objects: 64, ObjectBytes: 32 << 20}, nil,
		"gc", "apply", "--source", source, "--source-format", "json", "--plan", planPath, "--json")
	if !publicCapacityGCCapture(applied.Capture, false, &plan, input.Prefix, plan.DomainID) {
		t.Fatal("capacity/GC mutation exceeded exact Normal-only conditional effects")
	}
	publicCapacityGCCheckApplied(t, applied, plan, digest)
	clear(applied.Body)
	after, _ := publicCapacityGCSelected(t, ctx, inv, input, budget, source)
	publicCapacityGCValue(t, after, value)
	if after.head.Core.Revision == selected.head.Core.Revision || !after.root.ActiveGC.IsZero() || after.root.GCPlans.Count != 0 || after.root.WarningBits != selected.root.WarningBits {
		t.Fatal("capacity/GC did not independently observe complete close")
	}
	afterWindows, retained, err := after.retainedMutationReceiptBodies()
	if err != nil || beforeWindows == nil || afterWindows == nil || !publicOperatorReceiptWindowsEqual(*beforeWindows, *afterWindows) {
		t.Fatal("capacity/GC changed frozen Product receipt history")
	}
	if !reflect.DeepEqual(retained, beforeBodies) {
		t.Fatal("capacity/GC changed exact original receipt bytes")
	}
	for _, target := range expected {
		key, err := contract.StoreObjectKey(input.Prefix, plan.DomainID, target.Object)
		if err != nil || !budget.reserve(2, operationBodyAllowance, "", 0) {
			t.Fatal("capacity/GC exact final absence reservation")
		}
		if read := physical.Read(ctx, key, contract.StoreObjectLimit(target.Object)); read.Status != contract.ReadMissing || read.Reason != contract.ReasonNone || len(read.Body) != 0 || read.Token.Valid() {
			t.Fatal("capacity/GC original target is not independently absent")
		}
	}
	// Named continuation after a completely removed owner must not recover
	// historical success, reset counters or create a fresh delete permission.
	continued := publicCLIReserved(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true},
		budgetReservation{Requests: 256, BodyBytes: 32 << 20}, nil,
		"gc", "apply", "--source", source, "--source-format", "json", "--operation", hex.EncodeToString(plan.OperationID[:]), "--json")
	continuedProduct := publicProduct(t, continued, "gc-apply")
	if continued.Code == 0 || continuedProduct.State != "refused" || !continuedProduct.payloadNull || !publicCapacityGCCapture(continued.Capture, false, nil, input.Prefix, plan.DomainID) {
		t.Fatal("capacity/GC missing named owner advertised historical success or effects")
	}
	clear(continued.Body)
	final, _ := publicCapacityGCSelected(t, ctx, inv, input, budget, source)
	if !bytes.Equal(final.body, after.body) || final.token != after.token {
		t.Fatal("capacity/GC refused continuation changed selected HEAD")
	}
	publicImageUnchanged(t, image)
	planRelative, err := filepath.Rel(inv.StateDir, planPath)
	if err != nil {
		t.Fatal("capacity/GC state-owned plan artifact path unavailable")
	}
	return &publicCapacityGCFacts{RunID: input.RunID, Prefix: input.Prefix, Domain: hex.EncodeToString(plan.DomainID[:]),
		Operation: hex.EncodeToString(plan.OperationID[:]), PlanDigest: hex.EncodeToString(digest[:]),
		Revision: hex.EncodeToString(final.head.Core.Revision[:]), Snapshot: hex.EncodeToString(final.root.Snapshot[:]),
		RootDigest: hex.EncodeToString(final.head.Core.Root.Digest[:]), ValueBase64: base64.StdEncoding.EncodeToString(value), TargetCount: len(expected), PlanArtifact: planRelative}
}

func publicCapacityGCCheckCapacity(t testing.TB, child publicChildResult, selected *StateSession) {
	t.Helper()
	var payload struct {
		Schema      string              `json:"schema"`
		Observation publicGCObservation `json:"observation"`
		Counts      []struct {
			Name                string `json:"name"`
			Used, Limit, Margin uint64
		} `json:"counts"`
		Encoded struct {
			HEAD  uint64 `json:"head_bytes"`
			Root  uint64 `json:"root_bytes"`
			Child uint64 `json:"child_bytes"`
		} `json:"encoded"`
		Selected struct {
			Secret uint64 `json:"secret_values"`
			GC     uint64 `json:"gc_obligations"`
		} `json:"selected"`
		Garbage publicGCGarbage `json:"garbage"`
	}
	product := publicCapacityGCPayload(t, child, "inspect-capacity", "CapacityPayload/v1", &payload)
	if child.Code != 0 || product.State != "success" || payload.Schema != "CapacityPayload/v1" ||
		!publicCapacityGCObservationMatches(payload.Observation, selected) || payload.Encoded.HEAD != uint64(len(selected.body)) ||
		payload.Encoded.Root != uint64(selected.head.Core.Root.Length) || payload.Encoded.Child != selected.root.ChildEncodedBytes ||
		payload.Selected.Secret != 0 || payload.Selected.GC != 0 || payload.Garbage.ObservationLimit != "one-page-no-snapshot" {
		t.Fatal("capacity public projection changed independently selected facts")
	}
	want := map[string]uint64{"current-value-entries": 1, "current-generated-value-entries": 0, "current-raw-value-bytes": 8,
		"current-recipients": uint64(selected.root.RecipientCount), "current-memberships": 1, "selected-child-pages": uint64(selected.root.ChildCount), "administrative-groups-format": 0}
	for _, row := range payload.Counts {
		if used, checked := want[row.Name]; checked {
			if row.Used != used || row.Used > row.Limit || row.Margin != row.Limit-row.Used {
				t.Fatal("capacity public count/margin differs from literal fixture", row.Name)
			}
			delete(want, row.Name)
		}
	}
	if len(want) != 0 {
		t.Fatal("capacity public result omitted a required fixture count")
	}
}

func publicCapacityGCCheckApplied(t testing.TB, child publicChildResult, plan contract.GCPlan, digest contract.ID) {
	t.Helper()
	var payload struct {
		Schema         string `json:"schema"`
		Plan           string `json:"plan_digest"`
		Active, Closed bool
		Uncertain      bool   `json:"selection_uncertain"`
		Remaining      uint16 `json:"remaining_count"`
		Ordinal        uint32 `json:"progress_ordinal"`
		Sibling        struct {
			Count uint32
			Root  string `json:"root_digest"`
		} `json:"sibling_results"`
		Targets []struct {
			Namespace contract.StoreObjectNamespace
			Kind      contract.Kind
			Index     uint16
			Object    string `json:"object_id"`
			Length    uint32
			Digest    string
			Selected  struct {
				Consumed    uint8
				Disposition contract.GCTargetDisposition
				Evidence    string `json:"evidence_digest"`
			}
			Observed          contract.GCTargetDisposition
			ObservedEvidence  string          `json:"observed_evidence"`
			ObservationReason contract.Reason `json:"observation_reason"`
			Owned             bool            `json:"permission_owned"`
			Attempted         bool            `json:"delete_attempted"`
			Write             struct {
				Status  contract.WriteStatus
				Reason  contract.Reason
				NotSent bool `json:"not_sent"`
			} `json:"delete_result"`
		} `json:"targets"`
	}
	product := publicCapacityGCPayload(t, child, "gc-apply", "CleanupPayload/v1", &payload)
	if child.Code != 0 || product.State != "success" || product.Effect != "effect-complete" || product.Output != "not-applicable" ||
		payload.Schema != "CleanupPayload/v1" || payload.Plan != hex.EncodeToString(digest[:]) || payload.Active || !payload.Closed || payload.Uncertain ||
		payload.Remaining != 0 || payload.Ordinal != 3 || len(payload.Targets) != len(plan.Targets) || payload.Sibling.Count != uint32(len(plan.Targets)) || !publicIdentityHex(payload.Sibling.Root) {
		t.Fatal("capacity/GC public complete close result differs from original plan")
	}
	for i, row := range payload.Targets {
		target := plan.Targets[i]
		if row.Namespace != target.Object.Namespace || row.Kind != target.Object.Kind || row.Index != target.Object.Index || row.Object != hex.EncodeToString(target.Object.ObjectID[:]) ||
			row.Length != target.Length || row.Digest != hex.EncodeToString(target.Digest[:]) || row.Selected.Consumed != 1 || row.Selected.Disposition != contract.GCTargetAbsent ||
			!publicIdentityHex(row.Selected.Evidence) || row.Observed != contract.GCTargetAbsent || row.ObservedEvidence != row.Selected.Evidence || row.ObservationReason != contract.ReasonNone ||
			!row.Owned || !row.Attempted || row.Write.Status != contract.WriteAcknowledged || row.Write.Reason != contract.ReasonNone || row.Write.NotSent {
			t.Fatal("capacity/GC public sibling changed exact target or local effect facts", i)
		}
	}
}

func publicCapacityGCFresh(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, facts publicCapacityGCFacts) {
	t.Helper()
	domain := publicReadDomain(t, source)
	if !publicCapacityGCFactsValid(facts, input.RunID, input.Prefix, hex.EncodeToString(domain[:])) {
		t.Fatal("capacity/GC fresh facts do not bind this exact run and source")
	}
	selected, _ := publicCapacityGCSelected(t, ctx, inv, input, budget, source)
	if facts.Revision != hex.EncodeToString(selected.head.Core.Revision[:]) || facts.Snapshot != hex.EncodeToString(selected.root.Snapshot[:]) || facts.RootDigest != hex.EncodeToString(selected.head.Core.Root.Digest[:]) ||
		!selected.root.ActiveGC.IsZero() || selected.root.GCPlans.Count != 0 || selected.head.GC == nil || selected.head.GC.Phase != contract.GCClose ||
		facts.Operation != hex.EncodeToString(selected.head.GC.OperationID[:]) || facts.PlanDigest != hex.EncodeToString(selected.head.GC.PlanDigest[:]) {
		t.Fatal("capacity/GC fresh Reader did not observe exact final selected facts")
	}
	planPath, err := records.SafePath(inv.StateDir, facts.PlanArtifact)
	if err != nil {
		t.Fatal("capacity/GC fresh protected plan path refused")
	}
	body, plan := publicCapacityGCPlan(t, planPath, nil)
	digest := contract.Hash(body)
	if facts.PlanDigest != hex.EncodeToString(digest[:]) || facts.Operation != hex.EncodeToString(plan.OperationID[:]) || plan.DomainID != domain || len(plan.Targets) != facts.TargetCount {
		t.Fatal("capacity/GC fresh original target vector does not match signed close")
	}
	value, _ := base64.StdEncoding.Strict().DecodeString(facts.ValueBase64)
	publicCapacityGCValue(t, selected, value)
	image := publicSourceImage(t, source)
	child := publicCapacityGCQuery(t, ctx, inv, input, budget, source,
		"inspect", "--source", source, "--source-format", "json", "--capacity", "--json")
	publicCapacityGCCheckCapacity(t, child, selected)
	clear(child.Body)
	publicImageUnchanged(t, image)
}
