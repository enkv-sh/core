package compositionfull

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
	"golang.org/x/sys/unix"
)

var ErrAbandonmentPlan = errors.New("abandonment plan refused")

// The fixed-field ceiling includes both maximally escaped Store paths, all
// fixed identities, numbers and the complete closed warning/risk vocabulary.
// Each ordered scope ID adds at most two quotes, 64 hex digits and one comma.
const AbandonmentPlanLimit = 9332 - 1 + 67*65535

const abandonPreserved = "selected values and access remain; ended work rights and exclusive support would be removed"
const abandonHistory = "exact ended-work history and future adoption rights would be discarded"
const abandonLateEffects = "old processes can still send; remote effects are not cancelled or isolated"

type abandonSourceRecord struct {
	FileID          string `json:"file_id"`
	Format          uint8  `json:"format"`
	EditableDigest  string `json:"editable_digest"`
	GeneratedDigest string `json:"generated_digest"`
	EditableLength  uint64 `json:"editable_length"`
	GeneratedLength uint64 `json:"generated_length"`
	HasGenerated    bool   `json:"has_generated"`
}
type abandonStoreRecord struct {
	Family     uint8  `json:"family"`
	Identity   string `json:"identity"`
	Coordinate string `json:"coordinate"`
	NonBody    string `json:"non_body"`
	Prefix     string `json:"prefix"`
	HeadKey    string `json:"head_key"`
}
type abandonDescriptorRecord struct {
	Digest string `json:"digest"`
	Length uint64 `json:"length"`
	Count  uint32 `json:"count"`
}
type abandonDigestLengthRecord struct {
	Digest string `json:"digest"`
	Length uint64 `json:"length"`
}
type abandonPreviewRecord struct {
	Identity                string                    `json:"identity"`
	PredecessorRevision     string                    `json:"predecessor_revision"`
	TargetGroupID           string                    `json:"target_group_id"`
	EndedGroupIDs           []string                  `json:"ended_group_ids"`
	TargetOwnerID           string                    `json:"target_owner_id"`
	TargetID                string                    `json:"target_id"`
	TargetKind              uint8                     `json:"target_kind"`
	DutyKind                uint8                     `json:"duty_kind"`
	SelectedEvidenceSummary uint16                    `json:"selected_evidence_summary"`
	DependentGroups         abandonDescriptorRecord   `json:"dependent_groups"`
	RemovedSupport          abandonDescriptorRecord   `json:"removed_support"`
	PreservedCurrent        abandonDigestLengthRecord `json:"preserved_current"`
	BeforeWarningBits       uint8                     `json:"before_warning_bits"`
	WarningBits             uint8                     `json:"warning_bits"`
	BeforeChildCount        uint16                    `json:"before_child_count"`
	AfterChildCount         uint16                    `json:"after_child_count"`
	BeforeChildBytes        uint64                    `json:"before_child_bytes"`
	AfterChildBytes         uint64                    `json:"after_child_bytes"`
}
type abandonRiskRecord struct {
	OriginalEvidence      []string `json:"original_evidence"`
	Warnings              []string `json:"warnings"`
	WarningChanges        uint8    `json:"warning_changes"`
	OriginalCompletion    string   `json:"original_completion"`
	PhysicalCleanup       string   `json:"physical_cleanup"`
	PreservedCurrentState string   `json:"preserved_current_state"`
	FutureCleanupHistory  string   `json:"future_cleanup_history"`
	LateEffects           string   `json:"late_effects"`
}
type abandonPlanRecord struct {
	Schema            string               `json:"schema"`
	DomainID          string               `json:"domain_id"`
	Store             abandonStoreRecord   `json:"store"`
	Source            abandonSourceRecord  `json:"source"`
	PublicBasisDigest string               `json:"public_basis_digest"`
	Preview           abandonPreviewRecord `json:"preview"`
	Risk              abandonRiskRecord    `json:"risk"`
}

func abandonSource(p core.AdministrativeSourcePins) abandonSourceRecord {
	return abandonSourceRecord{readerID(p.FileID), p.Format, readerID(p.EditableDigest), readerID(p.GeneratedDigest), p.EditableLength, p.GeneratedLength, p.HasGenerated}
}
func abandonStore(d contract.Descriptor) abandonStoreRecord {
	return abandonStoreRecord{uint8(d.Family), readerID(d.Identity), readerID(d.Coordinate), readerID(d.NonBody), d.Prefix, d.HeadKey}
}
func abandonPreview(p core.EndWorkPreview) abandonPreviewRecord {
	ids := make([]string, len(p.EndedGroupIDs))
	for i, id := range p.EndedGroupIDs {
		ids[i] = readerID(id)
	}
	return abandonPreviewRecord{readerID(p.Identity), readerID(p.PredecessorRevision), readerID(p.TargetGroupID), ids, readerID(p.TargetOwnerID), readerID(p.TargetID), p.TargetKind, p.DutyKind, p.SelectedEvidenceSummary, abandonDescriptorRecord{readerID(p.DependentGroups.Digest), p.DependentGroups.Length, p.DependentGroups.Count}, abandonDescriptorRecord{readerID(p.RemovedSupport.Digest), p.RemovedSupport.Length, p.RemovedSupport.Count}, abandonDigestLengthRecord{readerID(p.PreservedCurrent.Digest), p.PreservedCurrent.Length}, p.BeforeWarningBits, p.WarningBits, p.BeforeChildCount, p.AfterChildCount, p.BeforeChildBytes, p.AfterChildBytes}
}
func abandonRisk(p core.EndWorkPreview) abandonRiskRecord {
	return abandonRiskRecord{abandonEvidence(p.SelectedEvidenceSummary), abandonRowWarnings(p.WarningBits, p.SelectedEvidenceSummary), p.WarningBits &^ p.BeforeWarningBits, "not-established", "not-established", abandonPreserved, abandonHistory, abandonLateEffects}
}
func abandonID(text string) (contract.ID, error) {
	var id contract.ID
	if len(text) != 64 || text != strings.ToLower(text) {
		return id, ErrAbandonmentPlan
	}
	b, err := hex.DecodeString(text)
	if err != nil {
		return id, ErrAbandonmentPlan
	}
	copy(id[:], b)
	if id.IsZero() {
		return id, ErrAbandonmentPlan
	}
	return id, nil
}
func (p abandonPreviewRecord) owned() (core.EndWorkPreview, error) {
	out := core.EndWorkPreview{TargetKind: p.TargetKind, DutyKind: p.DutyKind, SelectedEvidenceSummary: p.SelectedEvidenceSummary, BeforeWarningBits: p.BeforeWarningBits, WarningBits: p.WarningBits, BeforeChildCount: p.BeforeChildCount, AfterChildCount: p.AfterChildCount, BeforeChildBytes: p.BeforeChildBytes, AfterChildBytes: p.AfterChildBytes}
	for _, f := range []struct {
		text string
		id   *contract.ID
	}{{p.Identity, &out.Identity}, {p.PredecessorRevision, &out.PredecessorRevision}, {p.TargetGroupID, &out.TargetGroupID}, {p.TargetOwnerID, &out.TargetOwnerID}, {p.TargetID, &out.TargetID}} {
		id, err := abandonID(f.text)
		if err != nil {
			return out, err
		}
		*f.id = id
	}
	for _, f := range []struct {
		wire abandonDescriptorRecord
		out  *contract.GeneratorDescriptor
	}{{p.DependentGroups, &out.DependentGroups}, {p.RemovedSupport, &out.RemovedSupport}} {
		digest, err := abandonID(f.wire.Digest)
		if err != nil {
			return out, err
		}
		*f.out = contract.GeneratorDescriptor{Digest: digest, Length: f.wire.Length, Count: f.wire.Count}
		if !f.out.Valid() || f.wire.Count == 0 {
			return out, ErrAbandonmentPlan
		}
	}
	digest, err := abandonID(p.PreservedCurrent.Digest)
	if err != nil || p.PreservedCurrent.Length == 0 {
		return out, ErrAbandonmentPlan
	}
	out.PreservedCurrent = contract.DigestLength{Digest: digest, Length: p.PreservedCurrent.Length}
	if uint32(len(p.EndedGroupIDs)) != p.DependentGroups.Count {
		return out, ErrAbandonmentPlan
	}
	if len(p.EndedGroupIDs) == 0 || len(p.EndedGroupIDs) > 65535 || p.TargetKind < 1 || p.TargetKind > contract.AdministrativeGC || !contract.AdministrativeEvidenceValid(p.SelectedEvidenceSummary) || p.BeforeWarningBits&^31 != 0 || p.WarningBits&^31 != 0 || p.WarningBits&p.BeforeWarningBits != p.BeforeWarningBits || p.BeforeChildCount == 0 || p.AfterChildCount == 0 || p.BeforeChildCount > contract.MaxChildPages || p.AfterChildCount > contract.MaxChildPages || p.BeforeChildBytes == 0 || p.AfterChildBytes == 0 || p.BeforeChildBytes > uint64(contract.MaxChildPages)*contract.MaxRequiredSupportPageLength || p.AfterChildBytes > uint64(contract.MaxChildPages)*contract.MaxRequiredSupportPageLength {
		return out, ErrAbandonmentPlan
	}
	if p.TargetKind == contract.AdministrativeGeneratedDuty {
		if p.DutyKind < contract.GeneratedDutyCreate || p.DutyKind > contract.GeneratedDutyUnselectedCleanup {
			return out, ErrAbandonmentPlan
		}
	} else if p.DutyKind != 0 {
		return out, ErrAbandonmentPlan
	}
	out.EndedGroupIDs = make([]contract.ID, len(p.EndedGroupIDs))
	for i, text := range p.EndedGroupIDs {
		id, err := abandonID(text)
		if err != nil || i > 0 && strings.Compare(p.EndedGroupIDs[i-1], text) >= 0 {
			return out, ErrAbandonmentPlan
		}
		out.EndedGroupIDs[i] = id
	}
	if !slices.Contains(out.EndedGroupIDs, out.TargetGroupID) {
		return out, ErrAbandonmentPlan
	}
	return out, nil
}

func encodeAbandonPlan(r core.PublicAdministrativeResult, store contract.Descriptor, pins core.AdministrativeSourcePins, basis contract.ID) ([]byte, error) {
	if r.Operation != core.AdministrativePlan || r.Result.Outcome != core.ObservedCurrent || r.Plan == nil || r.Query == nil || r.Query.Observation == nil || r.Plan.Artifact != nil || !store.Valid() || basis.IsZero() {
		return nil, ErrAbandonmentPlan
	}
	record := abandonPlanRecord{"enkv/abandon-plan/v1", readerID(r.DomainID), abandonStore(store), abandonSource(pins), readerID(basis), abandonPreview(r.Plan.Preview), abandonRisk(r.Plan.Preview)}
	if _, err := record.Preview.owned(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(record)
	if err != nil || len(body) > AbandonmentPlanLimit {
		return nil, ErrAbandonmentPlan
	}
	return body, nil
}
func readAbandonPlan(ctx context.Context, path string, domain contract.ID, store contract.Descriptor, pins core.AdministrativeSourcePins, basis contract.ID) (core.EndWorkPreview, error) {
	body, err := core.ReadLocalProtectedFile(ctx, path, AbandonmentPlanLimit)
	if err != nil {
		return core.EndWorkPreview{}, errors.Join(ErrAbandonmentPlan, err)
	}
	if !abandonJSON(ctx, body, reflect.TypeOf(abandonPlanRecord{})) {
		return core.EndWorkPreview{}, ErrAbandonmentPlan
	}
	var record abandonPlanRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return core.EndWorkPreview{}, ErrAbandonmentPlan
	}
	p, err := record.Preview.owned()
	if err != nil || record.Schema != "enkv/abandon-plan/v1" || record.DomainID != readerID(domain) || record.Store != abandonStore(store) || record.Source != abandonSource(pins) || record.PublicBasisDigest != readerID(basis) || !reflect.DeepEqual(record.Risk, abandonRisk(p)) {
		return core.EndWorkPreview{}, ErrAbandonmentPlan
	}
	return p, nil
}

// Token validation checks exact field names before struct decoding, which would
// otherwise accept duplicate members and case aliases.
func abandonJSON(ctx context.Context, body []byte, shape reflect.Type) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if !abandonJSONValue(ctx, d, shape) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF && ctx.Err() == nil
}
func abandonJSONValue(ctx context.Context, d *json.Decoder, shape reflect.Type) bool {
	if ctx.Err() != nil {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	switch shape.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return false
		}
		fields := make(map[string]reflect.Type, shape.NumField())
		seen := make(map[string]bool, shape.NumField())
		for i := 0; i < shape.NumField(); i++ {
			f := shape.Field(i)
			fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			field, known := fields[name]
			if err != nil || !ok || !known || seen[name] {
				return false
			}
			seen[name] = true
			if !abandonJSONValue(ctx, d, field) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim('}') && len(seen) == len(fields)
	case reflect.Slice:
		if token != json.Delim('[') {
			return false
		}
		for d.More() {
			if !abandonJSONValue(ctx, d, shape.Elem()) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim(']')
	case reflect.String:
		_, ok := token.(string)
		return ok
	case reflect.Bool:
		_, ok := token.(bool)
		return ok
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, ok := token.(json.Number)
		if !ok {
			return false
		}
		_, err := strconv.ParseUint(string(n), 10, shape.Bits())
		return err == nil
	}
	return false
}

type abandonPlanIO struct {
	write         func(*os.File, []byte) (int, error)
	sync          func(*os.File) error
	close         func(*os.File) error
	syncDirectory func(int) error
	readback      func(context.Context, string, int64) ([]byte, error)
}

func nativeAbandonPlanIO() abandonPlanIO {
	return abandonPlanIO{func(f *os.File, b []byte) (int, error) { return f.Write(b) }, func(f *os.File) error { return f.Sync() }, func(f *os.File) error { return f.Close() }, unix.Fsync, core.ReadLocalProtectedFile}
}

// A failure leaves the exclusively created protected name for inspection. The
// operation never replaces an existing name and grants no mutation capability.
func writeAbandonPlan(ctx context.Context, path string, body []byte, ops abandonPlanIO) (AbandonmentDelivery, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpAdministrativePlanWrite)
	call.Checkpoint(telemetry.DiagnosticCandidatePersistence, telemetry.DiagnosticReasonNone)
	call.InputBytes(int64(len(body)))
	delivery, err := writeAbandonPlanFile(ctx, path, body, ops)
	if err == nil {
		call.OutputBytes(int64(len(body)))
		call.Finish(telemetry.ResultSuccess)
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		call.FinishReason(telemetry.ResultCancelled, telemetry.DiagnosticReasonCancelled)
	} else {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonInvalidReference)
	}
	return delivery, err
}

// Finish telemetry only after the IO worker and its cleanup return normally.
func writeAbandonPlanFile(ctx context.Context, path string, body []byte, ops abandonPlanIO) (delivery AbandonmentDelivery, err error) {
	return writeProtectedPlanFile(ctx, path, body, AbandonmentPlanLimit, ops)
}

func writeProtectedPlanFile(ctx context.Context, path string, body []byte, limit int, ops abandonPlanIO) (delivery AbandonmentDelivery, err error) {
	if ctx == nil || ctx.Err() != nil || len(body) == 0 || limit <= 0 || len(body) > limit || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return delivery, ErrAbandonmentPlan
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return delivery, errors.Join(ErrAbandonmentPlan, err)
	}
	defer func() { err = errors.Join(err, unix.Close(dir)) }()
	check := func(fd int) bool {
		var s unix.Stat_t
		return unix.Fstat(fd, &s) == nil && s.Mode&unix.S_IFMT == unix.S_IFDIR && (s.Uid == 0 || uint64(s.Uid) == uint64(os.Geteuid())) && s.Mode&0022 == 0
	}
	if !check(dir) {
		return delivery, ErrAbandonmentPlan
	}
	for _, part := range parts[:len(parts)-1] {
		if ctx.Err() != nil || part == "" || part == "." || part == ".." {
			return delivery, ErrAbandonmentPlan
		}
		next, e := unix.Openat(dir, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return delivery, errors.Join(ErrAbandonmentPlan, e)
		}
		if !check(next) {
			return delivery, errors.Join(ErrAbandonmentPlan, unix.Close(next))
		}
		if e := unix.Close(dir); e != nil {
			dir = next
			return delivery, errors.Join(ErrAbandonmentPlan, e)
		}
		dir = next
	}
	if ctx.Err() != nil {
		return delivery, errors.Join(ErrAbandonmentPlan, ctx.Err())
	}
	fd, err := unix.Openat(dir, parts[len(parts)-1], unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return delivery, errors.Join(ErrAbandonmentPlan, err)
	}
	delivery.PlanCreated = true
	f := os.NewFile(uintptr(fd), path)
	n, writeErr := ops.write(f, body)
	syncErr := error(nil)
	if writeErr == nil && n == len(body) {
		syncErr = ops.sync(f)
	} else if writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	closeErr := ops.close(f)
	if err := errors.Join(writeErr, syncErr, closeErr, ctx.Err()); err != nil {
		return delivery, errors.Join(ErrAbandonmentPlan, err)
	}
	if err := ops.syncDirectory(dir); err != nil {
		return delivery, errors.Join(ErrAbandonmentPlan, err)
	}
	delivery.PlanSynced = true
	actual, err := ops.readback(ctx, path, int64(limit))
	if err != nil || !bytes.Equal(actual, body) {
		return delivery, errors.Join(ErrAbandonmentPlan, err)
	}
	delivery.PlanReadback = true
	return delivery, nil
}
