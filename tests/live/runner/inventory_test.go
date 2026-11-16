package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

var errInventory = errors.New("object inventory is unresolved")
var errRunLimit = errors.New("run budget exhausted")

func lockInventory(directory string) (*os.File, error) {
	path, err := records.SafePath(directory, "inventory.lock")
	if err != nil {
		return nil, errInventory
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errInventory
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errInventory
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, errInventory
	}
	return f, nil
}

type objectIntent struct {
	Key            string          `json:"key"`
	Digest         string          `json:"digest"`
	Bytes          uint64          `json:"bytes"`
	Kind           string          `json:"kind"`
	ConditionToken *contract.Token `json:"condition_token,omitempty"`
	State          string          `json:"state"`
}

type inventoryImage struct {
	RecoveryLocations *installedarchive.RecoveryLocations `json:"recovery_locations,omitempty"`
	Version           int                                 `json:"version"`
	RunID             string                              `json:"run_id"`
	Binding           string                              `json:"binding"`
	Prefix            string                              `json:"prefix"`
	Domain            contract.ID                         `json:"domain"`
	Intents           []objectIntent                      `json:"intents"`
	Deleted           map[string]int                      `json:"deleted"`
	CleanupAttempts   []cleanupAttempt                    `json:"cleanup_attempts,omitempty"`
}

// The exact observed object and condition are private. An appended pending
// entry is durable before the delete call and is never authority for replay.
type cleanupAttempt struct {
	TargetIntent int                     `json:"target_intent"`
	Ordinal      uint8                   `json:"ordinal"`
	Recovery     string                  `json:"recovery,omitempty"`
	GrantRunID   string                  `json:"grant_run_id,omitempty"`
	CaseSHA256   string                  `json:"case_sha256,omitempty"`
	LimitsSHA256 string                  `json:"limits_sha256,omitempty"`
	Key          string                  `json:"key"`
	Digest       string                  `json:"digest"`
	Bytes        uint64                  `json:"bytes"`
	Token        contract.Token          `json:"token"`
	Cutoff       int                     `json:"cutoff"`
	State        string                  `json:"state"`
	Failure      *records.HarnessFailure `json:"failure,omitempty"`
}

type inventoryCleanupFailure struct {
	facts records.HarnessFailure
	cause error
}

func admissionNoSendCleanup(failure *records.HarnessFailure) bool {
	return failure != nil && failure.Validate() && failure.Operation == "object_cleanup" &&
		failure.Stage == "admission" && failure.Cause == "invalid_request" &&
		failure.Effect == "no_send" && failure.Attempt == 0
}

func (e *inventoryCleanupFailure) Error() string                              { return "object inventory cleanup failed" }
func (e *inventoryCleanupFailure) Unwrap() error                              { return e.cause }
func (e *inventoryCleanupFailure) SafeHarnessFailure() records.HarnessFailure { return e.facts }

func inventoryFailure(stage, cause, effect string, source error, target int, attempt uint8) error {
	facts := records.HarnessFailure{Operation: "object_cleanup", Stage: stage, Cause: cause, Effect: effect, Attempt: attempt}
	if errors.Is(source, errRunLimit) {
		facts.Stage, facts.Cause, facts.Effect, facts.Attempt = "admission", "budget_exhausted", "no_send", 0
	}
	var observed interface{ SafeHarnessFailure() records.HarnessFailure }
	if errors.As(source, &observed) {
		candidate := observed.SafeHarnessFailure()
		if candidate.Operation == "object_cleanup" && candidate.Validate() {
			facts = candidate
			if facts.Effect != "no_send" {
				facts.Attempt = attempt
			}
		}
	}
	if target >= 0 {
		index := uint32(target)
		facts.TargetKind, facts.TargetIndex = "inventory", &index
	}
	if !facts.Validate() {
		facts = records.HarnessFailure{Operation: "object_cleanup", Stage: stage, Cause: "evidence_unavailable", Effect: effect, Attempt: attempt}
		if target >= 0 {
			index := uint32(target)
			facts.TargetKind, facts.TargetIndex = "inventory", &index
		}
	}
	return &inventoryCleanupFailure{facts: facts, cause: source}
}

type objectInventory struct {
	mu                  sync.Mutex
	path                string
	image               inventoryImage
	stopped             bool
	failed              bool
	originalTokenSource *records.PublicConfigurationTokenSource
}

func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func validInventoryDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func writePrivateJSON(path string, value any) error {
	if records.WriteJSON(path, value, 0o600) != nil {
		return errInventory
	}
	return nil
}

func (i *objectInventory) save() error {
	if err := i.savePublicTokenSource(); err != nil {
		i.failed = true
		return err
	}
	if err := writePrivateJSON(i.path, i.image); err != nil {
		i.failed = true
		return err
	}
	return nil
}

func (i *objectInventory) begin(key string, body []byte, kind string, condition []contract.Token) (int, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped || i.failed || !strings.HasPrefix(key, i.image.Prefix+"/") || kind == "compare_and_swap" && (len(condition) != 1 || !condition[0].Valid()) || kind != "compare_and_swap" && len(condition) != 0 {
		return 0, errInventory
	}
	if i.image.RecoveryLocations != nil {
		if _, _, ok := i.image.RecoveryLocations.Target(contract.GCP, i.image.Prefix, i.image.Domain, key); !ok {
			return 0, errInventory
		}
	}
	if err := i.savePublicTokenSource(); err != nil {
		i.failed = true
		return 0, err
	}
	intent := objectIntent{Key: key, Digest: bodyDigest(body), Bytes: uint64(len(body)), Kind: kind, State: "pending"}
	if len(condition) == 1 {
		token := condition[0]
		intent.ConditionToken = &token
	}
	if intent.ConditionToken != nil {
		i.observePublicToken("intent-condition", len(i.image.Intents), len(i.image.Intents), 0, intent.Key, intent.Digest, intent.Bytes, *intent.ConditionToken)
	}
	i.image.Intents = append(i.image.Intents, intent)
	if err := i.save(); err != nil {
		return 0, err
	}
	return len(i.image.Intents) - 1, nil
}

func (i *objectInventory) finish(index int, result contract.WriteResult) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	state := "unknown"
	switch result.Status {
	case contract.WriteAcknowledged:
		state = "acknowledged"
	case contract.WritePrecondition, contract.WriteRefused:
		state = "refused"
	case contract.WriteUnknown:
		if result.NotSent {
			state = "not_sent"
		}
	}
	i.image.Intents[index].State = state
	return i.save() == nil
}

func (i *objectInventory) observeImmutableRead(key string, result contract.ReadResult) error {
	if result.Status != contract.ReadOK || !result.Token.Valid() {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped || i.failed {
		return errInventory
	}
	// Readback proves terminal acceptance only when the inventory has one
	// possible producer for this key. Another send may still arrive after
	// cleanup deletes the object seen by this read.
	candidate := -1
	for index := i.image.Deleted[key]; index < len(i.image.Intents); index++ {
		intent := i.image.Intents[index]
		if intent.Key != key || intent.State == "not_sent" || intent.State == "refused" {
			continue
		}
		if candidate != -1 {
			return nil
		}
		candidate = index
	}
	if candidate < 0 {
		return nil
	}
	intent := &i.image.Intents[candidate]
	if intent.State != "unknown" || intent.Kind != "create" && intent.Kind != "create_head" || intent.Digest != bodyDigest(result.Body) || intent.Bytes != uint64(len(result.Body)) {
		return nil
	}
	intent.State = "observed"
	return i.save()
}

func (i *objectInventory) write(ctx context.Context, key string, body []byte, kind string, send func() contract.WriteResult, condition ...contract.Token) contract.WriteResult {
	if ctx.Err() != nil {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit}
	}
	index, err := i.begin(key, body, kind, condition)
	if err != nil {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonProof}
	}
	result := send()
	if !i.finish(index, result) {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonProof}
	}
	return result
}

func (i *objectInventory) stop() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.stopped = true
}

// Unknown-effects counts are known only after the whole inventory shape is
// checked. Unreadable or malformed evidence must not appear as a known zero.
func (image inventoryImage) unknownEffects() (int64, error) {
	if image.Deleted == nil || len(image.CleanupAttempts) > 1000000 {
		return 0, errInventory
	}
	if image.RecoveryLocations != nil {
		if _, _, ok := image.RecoveryLocations.Target(contract.GCP, image.Prefix, image.Domain, image.Prefix+"/HEAD"); !ok {
			return 0, errInventory
		}
	}
	for key, cutoff := range image.Deleted {
		if !strings.HasPrefix(key, image.Prefix+"/") || cutoff < 0 || cutoff > len(image.Intents) {
			return 0, errInventory
		}
		if image.RecoveryLocations != nil {
			if _, _, ok := image.RecoveryLocations.Target(contract.GCP, image.Prefix, image.Domain, key); !ok {
				return 0, errInventory
			}
		}
	}
	var count int64
	for _, intent := range image.Intents {
		if image.RecoveryLocations != nil {
			if _, _, ok := image.RecoveryLocations.Target(contract.GCP, image.Prefix, image.Domain, intent.Key); !ok {
				return 0, errInventory
			}
		}
		digest, err := hex.DecodeString(intent.Digest)
		if !strings.HasPrefix(intent.Key, image.Prefix+"/") || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != intent.Digest || intent.Bytes == 0 || intent.Bytes > format.MaxValueEntryPage || (intent.Kind != "create_head" && intent.Kind != "create" && intent.Kind != "compare_and_swap" && intent.Kind != "fixture_create") || intent.Kind == "compare_and_swap" && (intent.ConditionToken == nil || !intent.ConditionToken.Valid()) || intent.Kind != "compare_and_swap" && intent.ConditionToken != nil {
			return 0, errInventory
		}
		switch intent.State {
		case "pending", "unknown":
			count++
		case "acknowledged", "refused", "not_sent", "observed":
			if intent.State == "observed" && intent.Kind != "create" && intent.Kind != "create_head" {
				return 0, errInventory
			}
		default:
			return 0, errInventory
		}
	}
	previous := make(map[struct {
		key    string
		cutoff int
	}]cleanupAttempt)
	for _, attempt := range image.CleanupAttempts {
		if attempt.TargetIntent < 0 || attempt.TargetIntent >= len(image.Intents) ||
			attempt.Ordinal < 1 || attempt.Ordinal > 4 ||
			(attempt.Ordinal == 1 && attempt.Recovery != "") ||
			(attempt.Ordinal > 1 && attempt.Recovery != "gcp_exact_generation" && attempt.Recovery != "gcp_exact_generation_grant" && attempt.Recovery != "aws_retired_fixture_grant" && attempt.Recovery != "admission_no_send_grant") ||
			(attempt.Recovery == "gcp_exact_generation" && (attempt.Ordinal > 3 || attempt.GrantRunID != "" || attempt.CaseSHA256 != "" || attempt.LimitsSHA256 != "")) ||
			((attempt.Recovery == "gcp_exact_generation_grant" || attempt.Recovery == "aws_retired_fixture_grant" || attempt.Recovery == "admission_no_send_grant") && (attempt.GrantRunID == "" || !records.ValidRunID(attempt.GrantRunID) || !validInventoryDigest(attempt.CaseSHA256) || !validInventoryDigest(attempt.LimitsSHA256))) ||
			(attempt.Ordinal == 1 && (attempt.GrantRunID != "" || attempt.CaseSHA256 != "" || attempt.LimitsSHA256 != "")) ||
			(attempt.Ordinal > 1 && (attempt.Recovery == "aws_retired_fixture_grant" && (attempt.Ordinal != 2 || attempt.Token.Family != contract.AWS) || attempt.Recovery == "admission_no_send_grant" && attempt.Ordinal != 2 || attempt.Recovery != "aws_retired_fixture_grant" && attempt.Recovery != "admission_no_send_grant" && attempt.Token.Family != contract.GCP)) ||
			attempt.Key != image.Intents[attempt.TargetIntent].Key ||
			attempt.Digest != image.Intents[attempt.TargetIntent].Digest ||
			attempt.Bytes != image.Intents[attempt.TargetIntent].Bytes ||
			attempt.Cutoff < 0 || attempt.Cutoff > attempt.TargetIntent ||
			!attempt.Token.Valid() ||
			(image.Intents[attempt.TargetIntent].State != "acknowledged" && image.Intents[attempt.TargetIntent].State != "observed") {
			return 0, errInventory
		}
		lineage := struct {
			key    string
			cutoff int
		}{attempt.Key, attempt.Cutoff}
		if prior, ok := previous[lineage]; ok {
			noSendGrant := attempt.Recovery == "admission_no_send_grant" && prior.Ordinal == 1 && prior.Recovery == "" && admissionNoSendCleanup(prior.Failure)
			if prior.State != "failed" && (prior.State != "settled" || prior.Failure == nil || attempt.State != "settled") ||
				(attempt.Recovery == "admission_no_send_grant" && !noSendGrant) ||
				(!noSendGrant && !transientConditionalDelete(prior.Failure)) ||
				(prior.Recovery == "gcp_exact_generation_grant" || prior.Recovery == "aws_retired_fixture_grant" || prior.Recovery == "admission_no_send_grant") ||
				prior.Ordinal+1 != attempt.Ordinal ||
				prior.TargetIntent != attempt.TargetIntent || prior.Digest != attempt.Digest ||
				prior.Bytes != attempt.Bytes || prior.Token != attempt.Token {
				return 0, errInventory
			}
		} else if attempt.Ordinal != 1 {
			return 0, errInventory
		}
		previous[lineage] = attempt
		switch attempt.State {
		case "pending":
			if attempt.Failure != nil {
				return 0, errInventory
			}
			count++
		case "failed":
			if attempt.Failure == nil || !attempt.Failure.Validate() ||
				attempt.Failure.Operation != "object_cleanup" || attempt.Failure.TargetKind != "inventory" ||
				attempt.Failure.TargetIndex == nil || *attempt.Failure.TargetIndex != uint32(attempt.TargetIntent) ||
				(attempt.Failure.Effect != "no_send" && attempt.Failure.Attempt != attempt.Ordinal) {
				return 0, errInventory
			}
			if attempt.Failure.Effect == "unknown" {
				count++
			}
		case "acknowledged", "settled":
			if attempt.State == "acknowledged" && attempt.Failure != nil ||
				attempt.State == "settled" && image.Deleted[attempt.Key] <= attempt.TargetIntent ||
				attempt.Failure != nil && (!attempt.Failure.Validate() || attempt.Failure.Operation != "object_cleanup" ||
					attempt.Failure.TargetKind != "inventory" || attempt.Failure.TargetIndex == nil ||
					*attempt.Failure.TargetIndex != uint32(attempt.TargetIntent) ||
					attempt.Failure.Effect != "no_send" && attempt.Failure.Attempt != attempt.Ordinal) {
				return 0, errInventory
			}
		default:
			return 0, errInventory
		}
	}
	return count, nil
}

func (i *objectInventory) owned(requireStopped bool) (map[string]map[string]bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if (requireStopped && !i.stopped) || i.failed {
		return nil, errInventory
	}
	if _, err := i.image.unknownEffects(); err != nil {
		return nil, err
	}
	owned := make(map[string]map[string]bool)
	for index, intent := range i.image.Intents {
		if intent.State != "acknowledged" && intent.State != "refused" && intent.State != "not_sent" && intent.State != "observed" {
			return nil, errInventory
		}
		if (intent.State == "acknowledged" || intent.State == "observed") && index >= i.image.Deleted[intent.Key] {
			if owned[intent.Key] == nil {
				owned[intent.Key] = make(map[string]bool)
			}
			owned[intent.Key][intent.Digest] = true
		}
	}
	return owned, nil
}

func (i *objectInventory) remove(ctx context.Context, store contract.Store, remove func(context.Context, string, contract.Token) error, key string, digests map[string]bool) error {
	i.mu.Lock()
	var limit uint64
	sizes := make(map[string]uint64)
	targets := make(map[string]int)
	cutoff := i.image.Deleted[key]
	for index, intent := range i.image.Intents {
		if intent.Key == key && (intent.State == "acknowledged" || intent.State == "observed") && index >= i.image.Deleted[key] {
			limit = max(limit, intent.Bytes)
			sizes[intent.Digest] = intent.Bytes
			targets[intent.Digest] = index
		}
	}
	for _, attempt := range i.image.CleanupAttempts {
		if attempt.Key == key && attempt.Cutoff == cutoff {
			i.mu.Unlock()
			return inventoryFailure("ownership_check", "unknown_effect", "no_send", errInventory, attempt.TargetIntent, 0)
		}
	}
	i.mu.Unlock()
	if limit == 0 || limit > format.MaxValueEntryPage {
		return inventoryFailure("ownership_check", "evidence_unavailable", "no_send", errInventory, -1, 0)
	}
	observed, readCause := cleanupRead(ctx, store, key, uint32(limit))
	target := -1
	attemptOrdinal := uint8(0)
	if observed.Status == contract.ReadOK {
		digest := bodyDigest(observed.Body)
		if !digests[digest] || uint64(len(observed.Body)) != sizes[digest] || !observed.Token.Valid() {
			return inventoryFailure("ownership_check", "ownership_mismatch", "no_send", errInventory, -1, 0)
		}
		target = targets[digest]
		i.mu.Lock()
		if err := i.savePublicTokenSource(); err != nil {
			i.failed = true
			i.mu.Unlock()
			return inventoryFailure("persistence", "persistence_failed", "no_send", err, target, 0)
		}
		entry := cleanupAttempt{TargetIntent: target, Ordinal: 1, Key: key, Digest: digest, Bytes: sizes[digest], Token: observed.Token, Cutoff: cutoff, State: "pending"}
		i.observePublicToken("cleanup-condition", len(i.image.CleanupAttempts), entry.TargetIntent, entry.Ordinal, entry.Key, entry.Digest, entry.Bytes, observed.Token)
		i.image.CleanupAttempts = append(i.image.CleanupAttempts, entry)
		attempt := len(i.image.CleanupAttempts) - 1
		err := i.save()
		i.mu.Unlock()
		if err != nil {
			return inventoryFailure("persistence", "persistence_failed", "no_send", err, target, 0)
		}
		attemptOrdinal = 1
		if err := remove(ctx, key, observed.Token); err != nil {
			failure := inventoryFailure("conditional_delete", "evidence_unavailable", "unknown", err, target, 1)
			var typed *inventoryCleanupFailure
			_ = errors.As(failure, &typed)
			i.mu.Lock()
			i.image.CleanupAttempts[attempt].State = "failed"
			i.image.CleanupAttempts[attempt].Failure = &typed.facts
			saveErr := i.save()
			i.mu.Unlock()
			if saveErr != nil {
				return inventoryFailure("persistence", "persistence_failed", "unknown", err, target, 1)
			}
			return failure
		}
		i.mu.Lock()
		i.image.CleanupAttempts[attempt].State = "acknowledged"
		err = i.save()
		i.mu.Unlock()
		if err != nil {
			return inventoryFailure("persistence", "persistence_failed", "unknown", err, target, 1)
		}
	} else if observed.Status != contract.ReadMissing {
		return inventoryFailure("ownership_read", readCause, "no_send", errInventory, -1, 0)
	}
	if checked, cause := cleanupRead(ctx, store, key, uint32(limit)); checked.Status != contract.ReadMissing {
		effect := "no_effect"
		if observed.Status == contract.ReadOK {
			effect = "acknowledged"
		}
		return inventoryFailure("post_delete_read", cause, effect, errInventory, target, attemptOrdinal)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.image.Deleted[key] = len(i.image.Intents)
	if observed.Status == contract.ReadOK {
		i.image.CleanupAttempts[len(i.image.CleanupAttempts)-1].State = "settled"
	}
	if err := i.save(); err != nil {
		return inventoryFailure("persistence", "persistence_failed", "unknown", err, target, attemptOrdinal)
	}
	return nil
}

// recoverCleanup is entered only after the coordinator has joined the failed
// worker and acquired the inventory lease. The durable first attempt supplies
// the exact GCP generation; a current read can refuse it, but cannot replace it.
func (i *objectInventory) recoverCleanup(ctx context.Context, store contract.Store, remove func(context.Context, string, contract.Token) error, target uint32, ordinal uint8) error {
	return i.recoverCleanupAttempt(ctx, store, remove, target, ordinal, "gcp_exact_generation", nil)
}

func (i *objectInventory) recoverGrantedCleanup(ctx context.Context, store contract.Store, remove func(context.Context, string, contract.Token) error, grant liveCleanupGrant) error {
	if !records.ValidRunID(grant.GrantRunID) || !validInventoryDigest(grant.OriginalCaseReceiptSHA256) ||
		!validInventoryDigest(grant.GrantLimitsSHA256) || grant.Ordinal < 2 || grant.Ordinal > 4 {
		return inventoryFailure("admission", "evidence_unavailable", "no_send", errInventory, int(grant.TargetIndex), 0)
	}
	recovery := "gcp_exact_generation_grant"
	if grant.InventorySHA256 != "" {
		if grant.Ordinal != 2 || !validInventoryDigest(grant.InventorySHA256) {
			return inventoryFailure("admission", "evidence_unavailable", "no_send", errInventory, int(grant.TargetIndex), 0)
		}
		recovery = "admission_no_send_grant"
	}
	if store != nil && store.Descriptor().Family == contract.AWS {
		if grant.Ordinal != 2 || !validInventoryDigest(grant.InventorySHA256) {
			return inventoryFailure("admission", "evidence_unavailable", "no_send", errInventory, int(grant.TargetIndex), 0)
		}
		recovery = "aws_retired_fixture_grant"
	}
	return i.recoverCleanupAttempt(ctx, store, remove, grant.TargetIndex, grant.Ordinal, recovery, &grant)
}

func (i *objectInventory) recoverCleanupAttempt(ctx context.Context, store contract.Store, remove func(context.Context, string, contract.Token) error, target uint32, ordinal uint8, recovery string, grant *liveCleanupGrant) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	awsFixture := recovery == "aws_retired_fixture_grant"
	retiredFixture := awsFixture || recovery == "admission_no_send_grant"
	refuse := func(cause string) error {
		return inventoryFailure("ownership_check", cause, "no_send", errInventory, int(target), 0)
	}
	if !i.stopped || i.failed || ordinal < 2 || ordinal > 4 ||
		recovery == "gcp_exact_generation" && (ordinal > 3 || grant != nil) ||
		(recovery == "gcp_exact_generation_grant" || retiredFixture) && grant == nil || store == nil || remove == nil {
		return refuse("evidence_unavailable")
	}
	var durable inventoryImage
	if readPrivateJSON(i.path, &durable) != nil || !reflect.DeepEqual(durable, i.image) {
		return refuse("evidence_unavailable")
	}
	unknown, unknownErr := durable.unknownEffects()
	if unknownErr != nil || durable.Version != 1 || int(target) >= len(durable.Intents) {
		return refuse("evidence_unavailable")
	}
	desc := store.Descriptor()
	if !desc.Valid() || (!awsFixture && desc.Family != contract.GCP || awsFixture && desc.Family != contract.AWS) || desc.Prefix != durable.Prefix {
		return refuse("ownership_mismatch")
	}
	intent := durable.Intents[target]
	if intent.State != "acknowledged" && intent.State != "observed" {
		return refuse("unknown_effect")
	}
	for _, other := range durable.Intents {
		if other.State == "pending" || other.State == "unknown" {
			return refuse("unknown_effect")
		}
	}
	last := -1
	for index, attempt := range durable.CleanupAttempts {
		if attempt.TargetIntent == int(target) {
			last = index
		} else if attempt.State == "pending" || attempt.State == "failed" && attempt.Failure.Effect == "unknown" {
			return refuse("unknown_effect")
		}
	}
	if last < 0 {
		return refuse("evidence_unavailable")
	}
	prior := durable.CleanupAttempts[last]
	noSendGrant := retiredFixture && prior.Ordinal == 1 && prior.Recovery == "" && admissionNoSendCleanup(prior.Failure)
	if noSendGrant {
		if unknown != 0 || ordinal != 2 {
			return refuse("unknown_effect")
		}
		recovery = "admission_no_send_grant"
	} else if recovery == "admission_no_send_grant" {
		return refuse("evidence_unavailable")
	}
	if prior.Ordinal+1 != ordinal || prior.State != "failed" || (!noSendGrant && !transientConditionalDelete(prior.Failure)) ||
		(prior.Recovery == "gcp_exact_generation_grant" || prior.Recovery == "aws_retired_fixture_grant" || prior.Recovery == "admission_no_send_grant") ||
		(!awsFixture && prior.Token.Family != contract.GCP || awsFixture && (prior.Ordinal != 1 || prior.Recovery != "" || prior.Token.Family != contract.AWS)) || durable.Deleted[prior.Key] != prior.Cutoff ||
		prior.TargetIntent != int(target) || prior.Key != intent.Key || prior.Digest != intent.Digest || prior.Bytes != intent.Bytes {
		return refuse("evidence_unavailable")
	}
	if grant != nil {
		for _, attempt := range durable.CleanupAttempts {
			if (attempt.Recovery == "gcp_exact_generation_grant" || attempt.Recovery == "aws_retired_fixture_grant" || attempt.Recovery == "admission_no_send_grant") || attempt.GrantRunID == grant.GrantRunID {
				return refuse("evidence_unavailable")
			}
		}
	}
	entry := cleanupAttempt{TargetIntent: int(target), Ordinal: ordinal, Recovery: recovery, Key: prior.Key, Digest: prior.Digest, Bytes: prior.Bytes, Token: prior.Token, Cutoff: prior.Cutoff, State: "pending"}
	if grant != nil {
		entry.GrantRunID, entry.CaseSHA256, entry.LimitsSHA256 = grant.GrantRunID, grant.OriginalCaseReceiptSHA256, grant.GrantLimitsSHA256
	}
	// Each branch below appends only its newly proposed input. This neither
	// recreates earlier observations nor supplies a condition to the delete call.
	appendAttempt := func() error {
		if err := i.savePublicTokenSource(); err != nil {
			i.failed = true
			return inventoryFailure("persistence", "persistence_failed", "no_send", err, int(target), 0)
		}
		i.observePublicToken("cleanup-condition", len(i.image.CleanupAttempts), entry.TargetIntent, entry.Ordinal, entry.Key, entry.Digest, entry.Bytes, entry.Token)
		i.image.CleanupAttempts = append(i.image.CleanupAttempts, entry)
		return nil
	}
	index := -1
	if retiredFixture {
		digest, err := privateRecordSHA256(i.path)
		if err != nil || digest != grant.InventorySHA256 {
			return refuse("evidence_unavailable")
		}
		if err := appendAttempt(); err != nil {
			return err
		}
		index = len(i.image.CleanupAttempts) - 1
		if err := i.save(); err != nil {
			return inventoryFailure("persistence", "persistence_failed", "no_send", err, int(target), 0)
		}
	}
	failRead := func(stage, cause string) error {
		failure := inventoryFailure(stage, cause, "no_send", errInventory, int(target), 0)
		if retiredFixture {
			var typed *inventoryCleanupFailure
			_ = errors.As(failure, &typed)
			i.image.CleanupAttempts[index].State = "failed"
			i.image.CleanupAttempts[index].Failure = &typed.facts
			if err := i.save(); err != nil {
				return inventoryFailure("persistence", "persistence_failed", "no_send", err, int(target), 0)
			}
		}
		return failure
	}
	read, cause := cleanupRead(ctx, store, prior.Key, uint32(prior.Bytes))
	if read.Status == contract.ReadMissing && read.Reason == contract.ReasonNone && len(read.Body) == 0 && read.Token == (contract.Token{}) {
		if grant != nil && !retiredFixture {
			entry.State = "settled"
			if err := appendAttempt(); err != nil {
				return err
			}
		}
		return i.settleRecoveredCleanup(prior.Key, prior.Cutoff, int(target))
	}
	if read.Status != contract.ReadOK {
		return failRead("ownership_read", cause)
	}
	if read.Reason != contract.ReasonNone || uint64(len(read.Body)) != prior.Bytes || bodyDigest(read.Body) != prior.Digest || read.Token != prior.Token {
		return failRead("ownership_check", "ownership_mismatch")
	}
	if !retiredFixture {
		if err := appendAttempt(); err != nil {
			return err
		}
		index = len(i.image.CleanupAttempts) - 1
		if err := i.save(); err != nil {
			return inventoryFailure("persistence", "persistence_failed", "no_send", err, int(target), 0)
		}
	}
	if err := remove(ctx, prior.Key, prior.Token); err != nil {
		failure := inventoryFailure("conditional_delete", "evidence_unavailable", "unknown", err, int(target), ordinal)
		var typed *inventoryCleanupFailure
		_ = errors.As(failure, &typed)
		i.image.CleanupAttempts[index].State = "failed"
		i.image.CleanupAttempts[index].Failure = &typed.facts
		if saveErr := i.save(); saveErr != nil {
			return inventoryFailure("persistence", "persistence_failed", "unknown", saveErr, int(target), ordinal)
		}
		return failure
	}
	i.image.CleanupAttempts[index].State = "acknowledged"
	if err := i.save(); err != nil {
		return inventoryFailure("persistence", "persistence_failed", "unknown", err, int(target), ordinal)
	}
	checked, cause := cleanupRead(ctx, store, prior.Key, uint32(prior.Bytes))
	if checked.Status != contract.ReadMissing || checked.Reason != contract.ReasonNone || len(checked.Body) != 0 || checked.Token != (contract.Token{}) {
		return inventoryFailure("post_delete_read", cause, "acknowledged", errInventory, int(target), ordinal)
	}
	return i.settleRecoveredCleanup(prior.Key, prior.Cutoff, int(target))
}

func transientConditionalDelete(failure *records.HarnessFailure) bool {
	if failure == nil || !failure.Validate() || failure.Operation != "object_cleanup" ||
		failure.Effect != "unknown" {
		return false
	}
	switch failure.Cause {
	case "transport", "missing_response", "deadline":
		return failure.Stage == "conditional_delete"
	case "early_eof":
		return failure.Stage == "response_intake"
	case "provider_refused":
		return failure.Stage == "conditional_delete" && failure.HTTPStatus != nil &&
			(*failure.HTTPStatus == 429 || *failure.HTTPStatus == 503) &&
			failure.EnvelopeStatus != nil && *failure.EnvelopeStatus == *failure.HTTPStatus
	default:
		return false
	}
}

func (i *objectInventory) settleRecoveredCleanup(key string, cutoff, target int) error {
	for index := range i.image.CleanupAttempts {
		attempt := &i.image.CleanupAttempts[index]
		if attempt.Key == key && attempt.Cutoff == cutoff && attempt.TargetIntent == target {
			if !admissionNoSendCleanup(attempt.Failure) || attempt.Recovery != "" {
				attempt.State = "settled"
			}
		}
	}
	i.image.Deleted[key] = len(i.image.Intents)
	if err := i.save(); err != nil {
		return inventoryFailure("persistence", "persistence_failed", "unknown", err, target, 0)
	}
	return nil
}

func cleanupReadCause(ctx context.Context, result contract.ReadResult) string {
	if result.Status == contract.ReadOK {
		return "ownership_mismatch"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "cancelled"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "deadline"
	}
	switch result.Reason {
	case contract.ReasonTransport:
		return "transport"
	case contract.ReasonAccess:
		return "access_refused"
	case contract.ReasonLimit:
		return "budget_exhausted"
	default:
		return "evidence_unavailable"
	}
}

// Cleanup can repeat an exact read after a transport failure. It never repeats
// a delete, and never treats an unavailable read as proof that an object is gone.
func cleanupRead(ctx context.Context, store contract.Store, key string, limit uint32) (contract.ReadResult, string) {
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	for attempt := 0; attempt < 3; attempt++ {
		result := store.Read(ctx, key, limit)
		if result.Status != contract.ReadUnavailable || result.Reason != contract.ReasonTransport || attempt == 2 {
			return result, cleanupReadCause(ctx, result)
		}
		if !waitForStoreRetry(ctx, deadline, storeRetryWait[attempt]) {
			result := contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
			return result, cleanupReadCause(ctx, result)
		}
	}
	result := contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	return result, cleanupReadCause(ctx, result)
}

func (i *objectInventory) cleanup(ctx context.Context, store contract.Store, remove func(context.Context, string, contract.Token) error) error {
	owned, err := i.owned(true)
	if err != nil {
		return inventoryFailure("ownership_check", "evidence_unavailable", "no_send", err, -1, 0)
	}
	keys := make([]string, 0, len(owned))
	for key := range owned {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := i.remove(ctx, store, remove, key, owned[key]); err != nil {
			return err
		}
	}
	return nil
}

func privateRecordSHA256(path string) (string, error) {
	if _, err := records.SafePath(filepath.Dir(path), filepath.Base(path)); err != nil {
		return "", errInventory
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > records.MaximumJSONBytes {
		return "", errInventory
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errInventory
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !records.SameLocalFile(before, after) {
		return "", errInventory
	}
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(file, records.MaximumJSONBytes+1))
	if err != nil || count > records.MaximumJSONBytes {
		return "", errInventory
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
