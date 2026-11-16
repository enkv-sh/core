package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func abandonPlanVector() (core.PublicAdministrativeResult, contract.Descriptor, core.AdministrativeSourcePins, contract.ID) {
	id := func(b byte) (out contract.ID) {
		for i := range out {
			out[i] = b
		}
		return out
	}
	store := contract.Descriptor{Family: contract.AWS, Identity: id(5), Coordinate: id(6), NonBody: id(7), Prefix: "fixture", HeadKey: "fixture/HEAD"}
	pins := core.AdministrativeSourcePins{FileID: id(1), Format: 1, EditableDigest: id(2), GeneratedDigest: id(3), EditableLength: 222, GeneratedLength: 333, HasGenerated: true}
	preview := core.EndWorkPreview{Identity: id(9), PredecessorRevision: id(10), TargetGroupID: id(11), EndedGroupIDs: []contract.ID{id(11), id(12)}, TargetOwnerID: id(13), TargetID: id(14), TargetKind: 2, DutyKind: 1, SelectedEvidenceSummary: 1, DependentGroups: contract.GeneratorDescriptor{Digest: id(15), Length: 64, Count: 2}, RemovedSupport: contract.GeneratorDescriptor{Digest: id(16), Length: 123, Count: 1}, PreservedCurrent: contract.DigestLength{Digest: id(17), Length: 200}, BeforeWarningBits: 0, WarningBits: 31, BeforeChildCount: 2, AfterChildCount: 2, BeforeChildBytes: 200, AfterChildBytes: 300}
	r := core.PublicAdministrativeResult{Operation: core.AdministrativePlan, DomainID: id(4), Result: core.Result{Outcome: core.ObservedCurrent}, StateResult: "success", Plan: &core.AdministrativePlanPayload{Preview: preview}, Query: &core.AdministrativeQueryIdentity{Observation: &core.AdministrativeObservation{DomainID: id(4), Revision: id(10), Snapshot: id(18)}}}
	return r, store, pins, id(8)
}

// full_only: false
func TestAbandonmentPlanHasIndependentExactBytesAndFreshSourcePins(t *testing.T) {
	r, store, pins, basis := abandonPlanVector()
	body, err := encodeAbandonPlan(r, store, pins, basis)
	if err != nil || len(body) != 2749 || readerID(contract.Hash(body)) != "e532e8a017cc2c22e521ea423930e93acbd490bc40c83e305b31677ae24b2e03" {
		t.Fatal("plan differs from independent fixed JSON derivation", len(body), err)
	}
	dir := protectedConfigurationTestDirectory(t)
	path := filepath.Join(dir, "plan.json")
	if _, err := writeAbandonPlan(t.Context(), path, body, nativeAbandonPlanIO()); err != nil {
		t.Fatal(err)
	}
	got, err := readAbandonPlan(t.Context(), path, r.DomainID, store, pins, basis)
	if err != nil || got.Identity != r.Plan.Preview.Identity || got.PreservedCurrent != r.Plan.Preview.PreservedCurrent || got.DependentGroups != r.Plan.Preview.DependentGroups || got.RemovedSupport != r.Plan.Preview.RemovedSupport {
		t.Fatal("complete plan facts lost", err)
	}
	for _, axis := range []string{"domain", "store", "basis", "file-id", "editable", "generated", "length", "format"} {
		t.Run(axis, func(t *testing.T) {
			domain, s, p, b := r.DomainID, store, pins, basis
			wrong := contract.Hash([]byte("wrong " + axis))
			switch axis {
			case "domain":
				domain = wrong
			case "store":
				s.Coordinate = wrong
			case "basis":
				b = wrong
			case "file-id":
				p.FileID = wrong
			case "editable":
				p.EditableDigest = wrong
			case "generated":
				p.GeneratedDigest = wrong
			case "length":
				p.GeneratedLength++
			case "format":
				p.Format = 2
			}
			if _, err := readAbandonPlan(t.Context(), path, domain, s, p, b); !errors.Is(err, ErrAbandonmentPlan) {
				t.Fatal("plan admitted unequal fresh source facts", axis, err)
			}
		})
	}
}

// full_only: false
func TestAbandonmentPlanRejectsAmbiguousOrAlteredRiskFacts(t *testing.T) {
	r, store, pins, basis := abandonPlanVector()
	body, err := encodeAbandonPlan(r, store, pins, basis)
	if err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"duplicate", "case-alias", "unknown", "version", "risk", "warning", "scope-order", "missing-preserved", "trailing", "truncated"} {
		t.Run(damage, func(t *testing.T) {
			b := bytes.Clone(body)
			switch damage {
			case "duplicate":
				b = append([]byte(`{"schema":"enkv/abandon-plan/v1",`), body[1:]...)
			case "case-alias":
				b = bytes.Replace(b, []byte(`"domain_id"`), []byte(`"Domain_ID"`), 1)
			case "unknown":
				b = append([]byte(`{"unknown":true,`), body[1:]...)
			case "version":
				b = bytes.Replace(b, []byte("enkv/abandon-plan/v1"), []byte("enkv/abandon-plan/v2"), 1)
			case "risk":
				b = bytes.Replace(b, []byte(abandonLateEffects), []byte("remote effects cancelled"), 1)
			case "warning":
				b = bytes.Replace(b, []byte(`"warning_changes":31`), []byte(`"warning_changes":0`), 1)
			case "scope-order":
				var v abandonPlanRecord
				if json.Unmarshal(b, &v) != nil {
					t.Fatal("fixture JSON")
				}
				v.Preview.EndedGroupIDs[0], v.Preview.EndedGroupIDs[1] = v.Preview.EndedGroupIDs[1], v.Preview.EndedGroupIDs[0]
				b, err = json.Marshal(v)
			case "missing-preserved":
				var v map[string]any
				if json.Unmarshal(b, &v) != nil {
					t.Fatal("fixture JSON")
				}
				delete(v["preview"].(map[string]any), "preserved_current")
				b, err = json.Marshal(v)
			case "trailing":
				b = append(b, []byte(`{}`)...)
			case "truncated":
				b = b[:len(b)-1]
			}
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(protectedConfigurationTestDirectory(t), "plan.json")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readAbandonPlan(t.Context(), path, r.DomainID, store, pins, basis); !errors.Is(err, ErrAbandonmentPlan) {
				t.Fatal("ambiguous/altered plan accepted", err)
			}
		})
	}
}

// full_only: false
func TestAbandonmentPlanDeliveryRefusesCollisionAndRetainsEveryIOFailure(t *testing.T) {
	r, store, pins, basis := abandonPlanVector()
	body, err := encodeAbandonPlan(r, store, pins, basis)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"write", "short-write", "sync", "close", "directory-sync", "readback", "unequal-readback", "collision"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(protectedConfigurationTestDirectory(t), "plan.json")
			ops := nativeAbandonPlanIO()
			failure := errors.New("controlled plan IO failure")
			switch stage {
			case "write":
				ops.write = func(*os.File, []byte) (int, error) { return 0, failure }
			case "short-write":
				ops.write = func(*os.File, []byte) (int, error) { return 1, nil }
			case "sync":
				ops.sync = func(*os.File) error { return failure }
			case "close":
				ops.close = func(f *os.File) error { return errors.Join(f.Close(), failure) }
			case "directory-sync":
				ops.syncDirectory = func(int) error { return failure }
			case "readback":
				ops.readback = func(context.Context, string, int64) ([]byte, error) { return nil, failure }
			case "unequal-readback":
				ops.readback = func(context.Context, string, int64) ([]byte, error) { return []byte("unequal"), nil }
			case "collision":
				if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			delivery, err := writeAbandonPlan(t.Context(), path, body, ops)
			if !errors.Is(err, ErrAbandonmentPlan) || delivery.PlanReadback {
				t.Fatal("failed plan delivery claimed readback", delivery, err)
			}
			if stage != "short-write" && stage != "unequal-readback" && stage != "collision" && !errors.Is(err, failure) {
				t.Fatal("plan IO cause lost", stage, err)
			}
			if stage == "short-write" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("short write was silenced", err)
			}
			if stage == "collision" {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != "existing" || delivery.PlanCreated {
					t.Fatal("existing plan changed", err)
				}
			}
		})
	}
}

// full_only: false
func TestAbandonmentPlanEncodedBoundKeepsCompleteMaximumScope(t *testing.T) {
	r, store, pins, basis := abandonPlanVector()
	r.Plan.Preview.EndedGroupIDs = make([]contract.ID, 65535)
	for i := range r.Plan.Preview.EndedGroupIDs {
		var id contract.ID
		id[0] = 1
		id[30] = byte((i + 1) >> 8)
		id[31] = byte(i + 1)
		r.Plan.Preview.EndedGroupIDs[i] = id
	}
	r.Plan.Preview.SelectedEvidenceSummary = 1023
	r.Plan.Preview.TargetGroupID = r.Plan.Preview.EndedGroupIDs[0]
	r.Plan.Preview.DependentGroups.Count = 65535
	r.Plan.Preview.DependentGroups.Length = 65535 * 32
	body, err := encodeAbandonPlan(r, store, pins, basis)
	if err != nil || len(body) > AbandonmentPlanLimit || bytes.Count(body, []byte(`"`+readerID(r.Plan.Preview.EndedGroupIDs[65534])+`"`)) != 1 {
		t.Fatal("maximum ordered scope was truncated or refused", len(body), err)
	}
	if AbandonmentPlanLimit != 4400176 || 1+67*65535 != 4390846 {
		t.Fatal("independent plan byte arithmetic changed")
	}
	var complete struct {
		Risk struct {
			Evidence []string `json:"original_evidence"`
			Warnings []string `json:"warnings"`
		} `json:"risk"`
	}
	if json.Unmarshal(body, &complete) != nil || len(complete.Risk.Evidence) != 10 || len(complete.Risk.Warnings) != 7 {
		t.Fatal("maximum scope lost complete closed evidence/warning vocabulary")
	}
	for _, text := range []string{"qualified-acknowledgement", "qualified-no-effect-or-scoped-unusability", "An effect was acknowledged; invalidation is not confirmed for every original effect."} {
		if bytes.Count(body, []byte(text)) != 1 {
			t.Fatal("maximum vocabulary omitted or repeated a changed exact claim", text)
		}
	}
	if strings.Contains(string(body), "QueryRequestIdentity") || strings.Contains(string(body), "readback") {
		t.Fatal("plan artifact acquired a result/query cycle")
	}
}

// full_only: false
func TestAbandonmentPlanRefusesSpecialDescriptorsAndJoins(t *testing.T) {
	for _, mode := range []string{"fifo-no-writer", "fifo-held-writer", "symlink", "parent-symlink", "directory", "group-write", "other-write", "group-read", "executable", "group-write-parent", "other-write-parent", "regular"} {
		t.Run(mode, func(t *testing.T) {
			r, store, pins, basis := abandonPlanVector()
			body, err := encodeAbandonPlan(r, store, pins, basis)
			if err != nil {
				t.Fatal(err)
			}
			regular := filepath.Join(protectedConfigurationTestDirectory(t), "decision.json")
			if err := os.WriteFile(regular, body, 0600); err != nil {
				t.Fatal(err)
			}
			path := regular
			writerFD := -1
			switch mode {
			case "symlink":
				path = regular + "-link"
				if err := os.Symlink(regular, path); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				parent := regular + "-parent"
				if err := os.Symlink(filepath.Dir(regular), parent); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(parent, filepath.Base(regular))
			case "group-write", "other-write", "group-read", "executable":
				mode := map[string]os.FileMode{"group-write": 0620, "other-write": 0602, "group-read": 0644, "executable": 0700}[mode]
				if err := os.Chmod(regular, mode); err != nil {
					t.Fatal(err)
				}
			case "group-write-parent", "other-write-parent":
				mode := map[string]os.FileMode{"group-write-parent": 0720, "other-write-parent": 0702}[mode]
				if err := os.Chmod(filepath.Dir(regular), mode); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = filepath.Dir(regular)
			case "fifo-no-writer", "fifo-held-writer":
				path = regular + "-pipe"
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
				if mode == "fifo-held-writer" {
					var err error
					writerFD, err = unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := unix.Write(writerFD, []byte(`{}`)); err != nil {
						_ = unix.Close(writerFD)
						t.Fatal(err)
					}
				}
			}
			done := make(chan bool, 1)
			go func() {
				_, err := readAbandonPlan(t.Context(), path, r.DomainID, store, pins, basis)
				ok := err == nil
				done <- ok
			}()
			timer := time.NewTimer(200 * time.Millisecond)
			defer timer.Stop()
			var accepted bool
			select {
			case accepted = <-done:
			case <-timer.C:
				t.Error("special input blocked descriptor admission")
				if writerFD < 0 {
					var err error
					writerFD, err = unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
					if err != nil {
						t.Fatal("could not release blocked input", err)
					}
				}
				if err := unix.Close(writerFD); err != nil {
					t.Error(err)
				}
				writerFD = -1
				select {
				case accepted = <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("decision reader did not join after release")
				}
			}
			if writerFD >= 0 {
				if err := unix.Close(writerFD); err != nil {
					t.Error(err)
				}
			}
			if accepted != (mode == "regular") {
				t.Errorf("accepted=%v mode=%s", accepted, mode)
			}
		})
	}
}

// full_only: false
func TestAbandonmentPlanRefusesCanceledRead(t *testing.T) {
	r, store, pins, basis := abandonPlanVector()
	body, err := encodeAbandonPlan(r, store, pins, basis)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(protectedConfigurationTestDirectory(t), "decision.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readAbandonPlan(ctx, path, r.DomainID, store, pins, basis); err == nil {
		t.Fatal("canceled decision read was accepted")
	}
}
