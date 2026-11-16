package records

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
)

// PublicOutputRecoveryInput binds borrowed historical facts to one separately
// owned cleanup. It supplies no writer completion or publication permission.
type PublicOutputRecoveryInput struct {
	Version                                              uint16 `json:"version"`
	OriginalRunID, RecoveryRunID                         string
	OriginalEntry                                        catalog.Entry
	OriginalState, StateDir, Source, Generated           string
	Provider, RecoveryMode, Prefix, Binding              string
	Region, Account, ProjectNumber                       string
	Outputs                                              *PublicOutputScopes
	OriginalRunSHA256, OriginalCaseSHA256                string
	OriginalInputSHA256, OriginalBuildSHA256             string
	LimitsSHA256                                         string
	CleanupObjectsRemaining, CleanupObjectBytesRemaining uint64
	CleanupDebits                                        []PublicOutputRecoveryDebit
	Files                                                []PublicOutputRecoveryFile
	Captures                                             []PublicConfigurationCaptureRegistration
	Workers                                              []PublicOutputRecoveryWorker
}

type PublicOutputRecoveryWorker struct {
	PublicConfigurationWorkerJoin
	RunID, StateDir, OutputDir, Input, SourceMap string
}

type PublicOutputRecoveryDebit struct {
	RunID, Worker, Nonce string
	Reserved             BudgetReservation
}

type PublicOutputRecoveryCaptureOwner struct {
	Version                           uint16
	RunID, OriginalRunID, InputSHA256 string
	Captures                          []PublicConfigurationCaptureRegistration
}

func (v PublicOutputRecoveryInput) VerifyFiles() error {
	if v.Validate() != nil {
		return errRecord
	}
	for _, pin := range v.Files {
		if _, err := SafePath(filepath.Dir(pin.Path), filepath.Base(pin.Path)); err != nil {
			return errRecord
		}
		before, err := os.Lstat(pin.Path)
		if err != nil || !before.Mode().IsRegular() || uint64(before.Size()) != pin.Bytes || uint32(before.Mode().Perm()) != pin.Mode {
			return errRecord
		}
		file, err := os.OpenFile(pin.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return errRecord
		}
		opened, statErr := file.Stat()
		hash := sha256.New()
		count, readErr := io.Copy(hash, io.LimitReader(file, int64(pin.Bytes)+1))
		after, afterErr := file.Stat()
		closeErr := file.Close()
		current, pathErr := os.Lstat(pin.Path)
		if statErr != nil || readErr != nil || afterErr != nil || closeErr != nil || pathErr != nil || count != int64(pin.Bytes) ||
			!SameLocalFile(before, opened) || !SameLocalFile(before, after) || !SameLocalFile(before, current) ||
			before.Mode() != after.Mode() || before.Mode() != current.Mode() || before.Size() != after.Size() || before.Size() != current.Size() ||
			!before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(current.ModTime()) || hex.EncodeToString(hash.Sum(nil)) != pin.SHA256 {
			return errRecord
		}
	}
	return nil
}

type PublicOutputRecoveryFile struct {
	Path, SHA256 string
	Bytes        uint64
	Mode         uint32
}

func (v PublicOutputRecoveryInput) Validate() error {
	row, known := catalog.PublicConfiguration(v.OriginalEntry.Scenario)
	name, nameErr := catalog.CaseDirectoryToken(v.OriginalEntry.Scenario)
	if v.Version != 1 || !known || !row.Output || !ValidRunID(v.OriginalRunID) || !ValidRunID(v.RecoveryRunID) || v.OriginalRunID == v.RecoveryRunID ||
		v.OriginalEntry.Sequence < 0 || v.OriginalEntry.Members != 0 || nameErr != nil ||
		v.Provider != "aws" && v.Provider != "gcp" || v.RecoveryMode != "disabled" && v.RecoveryMode != "enabled" ||
		v.Prefix != "enkv-test/"+v.OriginalRunID+"/"+fmt.Sprintf("%04d-%s", v.OriginalEntry.Sequence, name) ||
		filepath.Base(v.OriginalState) != fmt.Sprintf("%04d-%s", v.OriginalEntry.Sequence, name) || v.Outputs == nil || !v.Outputs.Valid() ||
		v.Source != filepath.Join(v.OriginalState, "public-source", "configuration.json") ||
		len(v.Files) == 0 || len(v.Files) > 512 || len(v.Captures) == 0 || len(v.Captures) > MaximumPublicConfigurationCaptures ||
		len(v.Workers) == 0 || len(v.Workers) > MaximumPublicConfigurationCaptures {
		return errRecord
	}
	for _, digest := range []string{v.Binding, v.OriginalRunSHA256, v.OriginalCaseSHA256, v.OriginalInputSHA256, v.OriginalBuildSHA256, v.LimitsSHA256} {
		if !publicOutputID(digest) {
			return errRecord
		}
	}
	for _, path := range []string{v.OriginalState, v.StateDir, v.Generated} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errRecord
		}
	}
	if v.StateDir == v.OriginalState || !strings.HasPrefix(v.Generated, filepath.Join(v.OriginalState, "public-source")+string(filepath.Separator)) {
		return errRecord
	}
	files := map[string]bool{}
	for _, file := range v.Files {
		if !filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path || files[file.Path] || !publicOutputID(file.SHA256) || file.Bytes == 0 ||
			file.Bytes > 512<<20 || file.Mode != 0400 && file.Mode != 0600 && file.Mode != 0700 {
			return errRecord
		}
		files[file.Path] = true
	}
	for _, path := range []string{v.Source, v.Generated, filepath.Join(v.OriginalState, "input.json"), filepath.Join(v.OriginalState, "public-ownership.json")} {
		if !files[path] {
			return errRecord
		}
	}
	parents := map[string]bool{}
	for _, worker := range v.Workers {
		key := worker.Worker + "/" + worker.Nonce + "/" + worker.Role
		if parents[key] || !worker.Started || !worker.Joined || worker.Worker == "" || worker.Nonce == "" || !ValidRunID(worker.RunID) ||
			!publicOutputID(worker.InvocationSHA256) || !publicOutputID(worker.ResultSHA256) || !files[worker.Input] || !files[worker.SourceMap] ||
			!files[filepath.Join(worker.OutputDir, "invocation.json")] || !files[filepath.Join(worker.OutputDir, "worker.json")] {
			return errRecord
		}
		parents[key] = true
	}
	paths, ordinals := map[string]bool{}, map[string]uint16{}
	for _, capture := range v.Captures {
		owner := filepath.Dir(filepath.Dir(capture.Path))
		if paths[capture.Path] || !files[capture.Path] || !capture.Complete || capture.Bytes == 0 || !publicOutputID(capture.SHA256) ||
			!parents[capture.ParentWorker+"/"+capture.ParentNonce+"/"+capture.ParentRole] || capture.Actor == "" || capture.Ordinal != ordinals[owner] {
			return errRecord
		}
		paths[capture.Path] = true
		ordinals[owner]++
	}
	return nil
}

func PublicOutputFixtureNames(prefix string) []string {
	sum := sha256.Sum256([]byte(prefix))
	stem := "ENKV_" + strings.ToUpper(hex.EncodeToString(sum[:]))
	return []string{stem + "_PLAIN", stem + "_SECRET"}
}

func PublicOutputFixtureCoordinates(provider, region, account, projectNumber, prefix string, outputs *PublicOutputScopes, scopes []string) []PublicOutputCoordinate {
	var rows []PublicOutputCoordinate
	for _, scope := range scopes {
		if scope == "aws-secrets-manager" && provider != "aws" || scope == "gcp-secret-manager" && provider != "gcp" {
			return nil
		}
		for _, name := range PublicOutputFixtureNames(prefix) {
			row := PublicOutputCoordinate{}
			switch scope {
			case "aws-secrets-manager":
				row.ServiceContractID, row.TargetContractID = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1"
				row.PhysicalTarget = "arn:aws:secretsmanager:" + region + ":" + account + ":secret:" + name
			case "gcp-secret-manager":
				row.ServiceContractID, row.TargetContractID = "ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1"
				row.PhysicalTarget = "projects/" + projectNumber + "/secrets/" + name
			case "github-repository", "github-organization", "github-environment":
				if outputs == nil {
					return nil
				}
				row.ServiceContractID, row.TargetContractID = "github-actions/service/v1", "github-actions/target/v1"
				switch scope {
				case "github-repository":
					row.PhysicalTarget = "repos/" + outputs.Repository.Owner + "/" + outputs.Repository.Repository + "/actions/secrets/" + name
				case "github-organization":
					row.PhysicalTarget = "orgs/" + outputs.Organization.Owner + "/actions/secrets/" + name
				case "github-environment":
					row.PhysicalTarget = "repos/" + outputs.Environment.Owner + "/" + outputs.Environment.Repository + "/environments/" + outputs.Environment.Environment + "/secrets/" + name
				}
			default:
				return nil
			}
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b PublicOutputCoordinate) int {
		if order := strings.Compare(a.ServiceContractID, b.ServiceContractID); order != 0 {
			return order
		}
		return strings.Compare(a.PhysicalTarget, b.PhysicalTarget)
	})
	return rows
}

func (v PublicOutputRecoveryInput) MutationAllowance(objects, objectBytes uint64) bool {
	seen := map[string]bool{}
	for _, debit := range v.CleanupDebits {
		key := debit.Worker + "/" + debit.Nonce
		matched := false
		for _, worker := range v.Workers {
			matched = matched || worker.RunID == debit.RunID && worker.Role == "cleanup" && worker.Worker == debit.Worker && worker.Nonce == debit.Nonce
		}
		if seen[key] || !matched || debit.Reserved.GeneratorCreates != 0 || debit.Reserved.GeneratorRetires != 0 ||
			debit.Reserved.Objects > objects || debit.Reserved.ObjectBytes > objectBytes {
			return false
		}
		seen[key] = true
		objects -= debit.Reserved.Objects
		objectBytes -= debit.Reserved.ObjectBytes
	}
	for _, worker := range v.Workers {
		if worker.Role == "cleanup" && !seen[worker.Worker+"/"+worker.Nonce] {
			return false
		}
	}
	return objects == v.CleanupObjectsRemaining && objectBytes == v.CleanupObjectBytesRemaining
}

type PublicOutputRecoveryDisposition struct {
	Target       PublicOutputCoordinate
	Coordinate   contract.PublicationCoordinate
	Disposition  string
	Markers      []contract.PublicationMarker
	Incarnations []contract.ID
}

// Passive rows retain their exact identity after an ordinary binding removal.
// No effect, ACK, deletion contract or risk field can acquire a passive proof.
func PublicOutputRecoveryPassive(coordinate contract.PublicationCoordinate, markers []contract.PublicationMarker) bool {
	c := coordinate
	if len(markers) != 0 || c.DomainID.IsZero() || c.CoordinateID.IsZero() || c.CurrentPublicationIncarnationID.IsZero() ||
		c.LastBindingIncarnationID.IsZero() || c.LastEntryIncarnationID.IsZero() ||
		c.BindingState != contract.PublicationBindingActive && c.BindingState != contract.PublicationBindingRetired {
		return false
	}
	active := contract.ID{}
	if c.BindingState == contract.PublicationBindingActive {
		active = c.LastBindingIncarnationID
	}
	want := contract.PublicationCoordinate{Schema: 5, DomainID: c.DomainID, CoordinateID: c.CoordinateID,
		ServiceContractID: c.ServiceContractID, CanonicalTarget: c.CanonicalTarget, BindingState: c.BindingState,
		OwnerState: contract.PublicationOwnerNone, ActiveBindingIncarnationID: active, LastBindingIncarnationID: c.LastBindingIncarnationID,
		LastEntryIncarnationID: c.LastEntryIncarnationID, CurrentPublicationIncarnationID: c.CurrentPublicationIncarnationID}
	return c.Equal(want)
}

func (v PublicOutputRecoveryDisposition) Validate(domain contract.ID, final bool, input PublicOutputRecoveryInput) error {
	row, known := catalog.PublicConfiguration(input.OriginalEntry.Scenario)
	scope := publicOutputCoordinateScope(v.Target)
	if !known || !row.Output || scope == "" || !slices.Contains(row.OutputScopes(input.Provider), scope) && v.Disposition != "passive" && v.Disposition != "absent-no-effect" {
		return errRecord
	}
	c := v.Coordinate
	if v.Disposition == "absent-no-effect" {
		id, err := contract.PublicationCoordinateID(domain, v.Target.ServiceContractID, v.Target.PhysicalTarget)
		if err != nil || v.Target.CoordinateID != hex.EncodeToString(id[:]) || v.Target.BindingID != "" ||
			!reflect.DeepEqual(c, contract.PublicationCoordinate{}) || len(v.Markers) != 0 || len(v.Incarnations) != 0 {
			return errRecord
		}
		return nil
	}
	if _, err := contract.EncodePublicationCoordinate(c); err != nil || c.DomainID != domain ||
		v.Target.ServiceContractID != c.ServiceContractID || v.Target.PhysicalTarget != c.CanonicalTarget ||
		v.Target.CoordinateID != hex.EncodeToString(c.CoordinateID[:]) || v.Target.BindingID != hex.EncodeToString(c.LastBindingIncarnationID[:]) {
		return errRecord
	}
	markers := map[contract.ID]contract.PublicationMarker{}
	positions := map[contract.ID]int{}
	union := map[contract.ID]bool{c.CurrentPublicationIncarnationID: true}
	for _, id := range []contract.ID{c.LastValueAckIncarnationID, c.LastPolicyAckIncarnationID, c.LastDeleteAckIncarnationID} {
		if !id.IsZero() {
			union[id] = true
		}
	}
	for i, id := range v.Incarnations {
		if id.IsZero() || positions[id] != 0 {
			return errRecord
		}
		positions[id] = i + 1
	}
	if len(v.Incarnations) == 0 || v.Incarnations[len(v.Incarnations)-1] != c.CurrentPublicationIncarnationID {
		return errRecord
	}
	stamps := map[string]bool{}
	for _, marker := range v.Markers {
		stamp := fmt.Sprintf("%x/%d", marker.PublicationIncarnationID, marker.AdmissionOrdinal)
		if _, err := contract.EncodePublicationMarker(marker); err != nil || marker.DomainID != domain || marker.CoordinateID != c.CoordinateID ||
			marker.LateEffectRisk != 0 || marker.BlockerCount != 0 || !markers[marker.AttemptID].AttemptID.IsZero() || positions[marker.PublicationIncarnationID] == 0 || stamps[stamp] ||
			marker.Projection.BindingIncarnationID != c.LastBindingIncarnationID || marker.Projection.EntryIncarnationID != c.LastEntryIncarnationID {
			return errRecord
		}
		markers[marker.AttemptID] = marker
		stamps[stamp], union[marker.PublicationIncarnationID] = true, true
	}
	if len(union) != len(positions) {
		return errRecord
	}
	for id := range union {
		if positions[id] == 0 {
			return errRecord
		}
	}
	if v.Disposition == "passive" {
		if !PublicOutputRecoveryPassive(c, v.Markers) || final && c.BindingState != contract.PublicationBindingRetired {
			return errRecord
		}
		return nil
	}
	if c.DeletionTargetContractID != v.Target.TargetContractID || c.LateEffectRisk != 0 || !c.LatestUnresolvedAttemptID.IsZero() {
		return errRecord
	}
	if v.Disposition == "remaining" && !final && (c.OwnerState == contract.PublicationOwnerQualified || c.OwnerState == contract.PublicationOwnerUncertainCreate) {
		return nil
	}
	if v.Disposition != "deletion-acknowledged" || c.BindingState != contract.PublicationBindingRetired || c.LastDeleteAckAttemptID.IsZero() || c.PossibleRemoteObject != 1 {
		return errRecord
	}
	for _, marker := range v.Markers {
		p := marker.Projection
		if marker.AttemptID != c.LastDeleteAckAttemptID {
			continue
		}
		if marker.State != contract.PublicationAcknowledged || marker.PublicationIncarnationID != c.LastDeleteAckIncarnationID || marker.AdmissionOrdinal != c.LastDeleteAckOrdinal ||
			p.BindingIncarnationID != c.LastBindingIncarnationID || p.EntryIncarnationID != c.LastEntryIncarnationID || p.TargetRowDigest != c.DeletionTargetRowDigest ||
			p.Action != contract.PublicationDeleteOwned && p.Action != contract.PublicationDeleteReservedSlot ||
			marker.Evidence.Entry != contract.PublicationMayHaveEnteredEntry || marker.Evidence.Class != contract.PublicationRequestAcknowledged {
			return errRecord
		}
		owner := markers[p.OwnedBirthAttemptID]
		if p.Action == contract.PublicationDeleteReservedSlot {
			owner = markers[p.UncertainCreateAttemptID]
		}
		if owner.AttemptID.IsZero() || owner.CoordinateID != c.CoordinateID || owner.Projection.BindingIncarnationID != p.BindingIncarnationID ||
			owner.Projection.EntryIncarnationID != p.EntryIncarnationID || owner.Projection.TargetRowDigest != p.TargetRowDigest ||
			owner.Projection.Action != contract.PublicationCreateEmpty && owner.Projection.Action != contract.PublicationCreateWithValue ||
			positions[owner.PublicationIncarnationID] > positions[marker.PublicationIncarnationID] ||
			positions[owner.PublicationIncarnationID] == positions[marker.PublicationIncarnationID] && owner.AdmissionOrdinal >= marker.AdmissionOrdinal ||
			p.Action == contract.PublicationDeleteOwned && (owner.AttemptID != c.OwnedBirthAttemptID || owner.State != contract.PublicationAcknowledged) {
			return errRecord
		}
		afterDelete := func(incarnation contract.ID, ordinal uint64) bool {
			return !incarnation.IsZero() && (positions[incarnation] == 0 || positions[incarnation] > positions[marker.PublicationIncarnationID] ||
				positions[incarnation] == positions[marker.PublicationIncarnationID] && ordinal > marker.AdmissionOrdinal)
		}
		if afterDelete(c.LastValueAckIncarnationID, c.LastValueAckOrdinal) || afterDelete(c.LastPolicyAckIncarnationID, c.LastPolicyAckOrdinal) {
			return errRecord
		}
		for _, effect := range v.Markers {
			if effect.State != contract.PublicationQualifiedNoEffectState && afterDelete(effect.PublicationIncarnationID, effect.AdmissionOrdinal) {
				return errRecord
			}
		}
		if p.Action == contract.PublicationDeleteOwned {
			digest, err := contract.PublicationOwnedInstanceDigest(domain, c.CoordinateID, c.LastBindingIncarnationID, c.LastEntryIncarnationID, c.DeletionTargetRowDigest, owner.AttemptID, owner.Evidence.SafeResourceID)
			if err != nil || digest != c.OwnedInstanceDigest || owner.BirthServiceContractID != c.ServiceContractID || owner.BirthTargetContractID != c.DeletionTargetContractID ||
				owner.Evidence.Class != contract.PublicationRequestAcknowledged || owner.Evidence.ConsumerLocator != c.DeletionConsumerLocator {
				return errRecord
			}
		}
		return nil
	}
	return errRecord
}

type PublicOutputRecoveryStage struct {
	Name, Outcome string
}

type PublicOutputRecoveryProof struct {
	Version                    uint16
	InputSHA256                string
	Domain, Revision, Snapshot contract.ID
	HeadSHA256                 string
	Stages                     []PublicOutputRecoveryStage
	Initial, Final             []PublicOutputRecoveryDisposition
	Store                      *PublicConfigurationInventoryEvidence
}

func (v PublicOutputRecoveryProof) Validate(input PublicOutputRecoveryInput) error {
	body, err := json.Marshal(input)
	sum := sha256.Sum256(body)
	if err != nil || input.Validate() != nil || !v.Complete(input) || hex.EncodeToString(sum[:]) != v.InputSHA256 || v.Store == nil ||
		v.Store.Domain != v.Domain || v.Store.validate(input.OriginalRunID, input.Prefix, input.Binding, publicEvidenceFamily(input.Provider)) != nil {
		return errRecord
	}
	cloud := "aws-secrets-manager"
	if input.Provider == "gcp" {
		cloud = "gcp-secret-manager"
	}
	expected := PublicOutputFixtureCoordinates(input.Provider, input.Region, input.Account, input.ProjectNumber, input.Prefix, input.Outputs, []string{cloud, "github-repository", "github-organization", "github-environment"})
	if len(expected) != len(v.Final) {
		return errRecord
	}
	for i, want := range expected {
		want.CoordinateID, want.BindingID = v.Final[i].Target.CoordinateID, v.Final[i].Target.BindingID
		if want != v.Final[i].Target {
			return errRecord
		}
	}
	deleted := map[string]int{}
	for _, row := range v.Store.Deleted {
		deleted[row.Key] = int(row.Cutoff)
	}
	for i, row := range v.Store.Intents {
		if row.State != "not_sent" && row.State != "refused" && deleted[row.Key] <= i {
			return errRecord
		}
	}
	for _, row := range v.Store.CleanupAttempts {
		if row.State != "acknowledged" && row.State != "settled" {
			return errRecord
		}
	}
	return nil
}

func (v PublicOutputRecoveryProof) Complete(input PublicOutputRecoveryInput) bool {
	want := []string{"intake", "authenticated-discovery", "prepare-pair", "retire-bindings", "remaining-deletions", "current-disposition", "store-cleanup"}
	if v.Version != 1 || !publicOutputID(v.InputSHA256) || v.Domain.IsZero() || v.Revision.IsZero() || v.Snapshot.IsZero() ||
		!publicOutputID(v.HeadSHA256) || len(v.Stages) != len(want) || len(v.Initial) != len(v.Final) || len(v.Final) != 8 {
		return false
	}
	seen := map[string]bool{}
	for i, stage := range v.Stages {
		if stage.Name != want[i] || stage.Outcome != "complete" {
			return false
		}
	}
	for i, row := range v.Final {
		if seen[row.Target.CoordinateID] || row.Validate(v.Domain, true, input) != nil || v.Initial[i].Validate(v.Domain, false, input) != nil ||
			v.Initial[i].Target != row.Target || v.Initial[i].Coordinate.LastEntryIncarnationID != row.Coordinate.LastEntryIncarnationID {
			return false
		}
		seen[row.Target.CoordinateID] = true
	}
	return true
}

// A command carries its exact consumed local image. These bytes are private
// evidence; they grant no authority to replay the original writer.
type PublicOutputRecoveryPairFile struct {
	Path, SHA256 string
	Bytes        uint64
	Mode         uint32
	Data         []byte
}

type PublicOutputRecoveryPair struct {
	Version uint16
	Source  string
	Files   []PublicOutputRecoveryPairFile
}

func (v PublicOutputRecoveryPair) Validate(input PublicOutputRecoveryInput) error {
	if v.Version != 1 || v.Source != filepath.Join(input.StateDir, "public-source/configuration.json") || len(v.Files) < 2 || len(v.Files) > 64 {
		return errRecord
	}
	files := map[string]PublicOutputRecoveryPairFile{}
	var total uint64
	previous := ""
	for _, file := range v.Files {
		sum := sha256.Sum256(file.Data)
		if file.Path == "" || file.Path == "." || file.Path == ".." || filepath.IsAbs(file.Path) || filepath.ToSlash(filepath.Clean(file.Path)) != file.Path || strings.Contains(file.Path, "\\") || strings.HasPrefix(file.Path, "../") || file.Path <= previous || file.Bytes != uint64(len(file.Data)) || file.Bytes > 8<<20 || file.Mode != 0400 && file.Mode != 0600 || hex.EncodeToString(sum[:]) != file.SHA256 {
			return errRecord
		}
		previous, total = file.Path, total+file.Bytes
		if total > 16<<20 {
			return errRecord
		}
		files[file.Path] = file
	}
	var source struct {
		Generated string `json:"generated"`
	}
	if json.Unmarshal(files["configuration.json"].Data, &source) != nil || source.Generated == "" || source.Generated == "." || source.Generated == ".." || source.Generated == "configuration.json" || filepath.IsAbs(source.Generated) || filepath.ToSlash(filepath.Clean(source.Generated)) != source.Generated || strings.Contains(source.Generated, "\\") || strings.HasPrefix(source.Generated, "../") || files[source.Generated].Path == "" || !json.Valid(files[source.Generated].Data) {
		return errRecord
	}
	return nil
}

func (v PublicOutputRecoveryPair) OutputsRemovedFrom(prepared PublicOutputRecoveryPair) bool {
	if v.Source != prepared.Source || len(v.Files) != len(prepared.Files) {
		return false
	}
	for i, file := range v.Files {
		old := prepared.Files[i]
		if file.Path != old.Path || file.Mode != old.Mode {
			return false
		}
		if file.Path != "configuration.json" {
			if !reflect.DeepEqual(file, old) {
				return false
			}
			continue
		}
		decode := func(body []byte) map[string]any {
			var document map[string]any
			decoder := json.NewDecoder(strings.NewReader(string(body)))
			decoder.UseNumber()
			if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF {
				return nil
			}
			return document
		}
		before, after := decode(old.Data), decode(file.Data)
		if before == nil || after == nil || !reflect.DeepEqual(after["outputs"], map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}) {
			return false
		}
		delete(before, "outputs")
		delete(after, "outputs")
		if !reflect.DeepEqual(before, after) {
			return false
		}
	}
	return true
}

type PublicOutputRecoveryPreparedPair struct {
	Version                                    uint16
	InputSHA256, StageSHA256, CommandDirectory string
	HeadSHA256                                 string
	Result                                     []byte
	Pair                                       PublicOutputRecoveryPair
}

func (v PublicOutputRecoveryPair) OutputContracts() ([]string, error) {
	var source struct {
		Outputs struct {
			Destinations map[string]map[string]any `json:"destinations"`
		} `json:"outputs"`
	}
	for _, file := range v.Files {
		if file.Path != "configuration.json" {
			continue
		}
		if jsonv2.Unmarshal(file.Data, &source) != nil || source.Outputs.Destinations == nil {
			return nil, errRecord
		}
		contracts := []string{}
		for name, output := range source.Outputs.Destinations {
			plugin, present := output["plugin"]
			canonical, ok := output["canonical"].(map[string]any)
			encoded, text := canonical["binding_base64"].(string)
			if len(output) != 2 || !present || plugin != nil || !ok || len(canonical) != 1 || !text {
				return nil, errRecord
			}
			body, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || base64.StdEncoding.EncodeToString(body) != encoded {
				return nil, errRecord
			}
			binding, err := contract.InspectNormalOutputBinding(body)
			if err != nil || binding.DestinationID != name {
				return nil, errRecord
			}
			contracts = append(contracts, binding.Destination.ConfigContractID)
		}
		slices.Sort(contracts)
		return slices.Compact(contracts), nil
	}
	return nil, errRecord
}

// ValidateResult checks the delivered pair independently of effect-plugin readiness.
// The caller supplies contracts from authenticated state or the pinned canonical pair.
func (v PublicOutputRecoveryPreparedPair) ValidateResult(code int, domain contract.ID, contracts []string) error {
	if len(v.Result) == 0 || len(v.Result) > MaximumJSONBytes || domain.IsZero() || !validOutputDigest(v.HeadSHA256) {
		return errRecord
	}
	var actual map[string]any
	if jsonv2.Unmarshal(v.Result, &actual) != nil {
		return errRecord
	}
	request, ok := actual["request_id"].(string)
	if !ok || !validOutputDigest(request) {
		return errRecord
	}
	files := map[string]PublicOutputRecoveryPairFile{}
	for _, file := range v.Pair.Files {
		files[file.Path] = file
	}
	var source struct {
		Generated string `json:"generated"`
	}
	if jsonv2.Unmarshal(files["configuration.json"].Data, &source) != nil || source.Generated == "" || files[source.Generated].Path == "" {
		return errRecord
	}
	contracts = slices.Clone(contracts)
	slices.Sort(contracts)
	contracts = slices.Compact(contracts)
	requirements, diagnostics := []any{}, []any{}
	outcome, expectedCode := "complete", 0
	for _, id := range contracts {
		if id == "" {
			return errRecord
		}
		requirements = append(requirements, map[string]any{"role": "output", "plugin": nil, "contract": id, "protocol_version": float64(4), "artifact": nil, "status": "missing", "reason": "not-installed"})
	}
	if len(contracts) != 0 {
		outcome, expectedCode = "incomplete", 2
		diagnostics = append(diagnostics, map[string]any{"reason": "dependency-missing", "subject": "dependencies"})
	}
	expected := map[string]any{
		"schema": "enkv/prepare-result/v2", "operation": "prepare", "request_id": request, "branch": "reconstruction", "outcome": outcome,
		"recovery": map[string]any{"status": "complete", "domain": hex.EncodeToString(domain[:]), "head": v.HeadSHA256},
		"local_delivery": map[string]any{"outcome": "recorded", "editable_path": v.Pair.Source, "generated_path": filepath.Join(filepath.Dir(v.Pair.Source), filepath.FromSlash(source.Generated)), "cleanup_failed": false,
			"readback": map[string]any{"editable_digest": files["configuration.json"].SHA256, "generated_digest": files[source.Generated].SHA256}},
		"dependencies": map[string]any{"assessment": "complete", "minimum_administrative_ready": true, "all_declared_ready": len(contracts) == 0, "requirements": requirements, "installations": []any{}},
		"diagnostics":  diagnostics,
	}
	if code != expectedCode || !reflect.DeepEqual(actual, expected) {
		return errRecord
	}
	return nil
}

type PublicOutputRecoveryCommand struct {
	Version                               uint16
	InputSHA256, StageSHA256, Stage, Role string
	Args                                  []string
	Reservation                           BudgetReservation
	Pair                                  *PublicOutputRecoveryPair
}

func PublicOutputRecoveryStageBinding(inputSHA256, stage string) string {
	var stages []PublicOutputRecoveryStage
	for _, name := range []string{"intake", "authenticated-discovery", "prepare-pair", "retire-bindings", "remaining-deletions", "current-disposition", "store-cleanup"} {
		outcome := "complete"
		if name == stage {
			outcome = "entered"
		}
		stages = append(stages, PublicOutputRecoveryStage{Name: name, Outcome: outcome})
		if name == stage {
			body, _ := json.Marshal(struct {
				InputSHA256 string
				Stages      []PublicOutputRecoveryStage
			}{inputSHA256, stages})
			sum := sha256.Sum256(body)
			return hex.EncodeToString(sum[:])
		}
	}
	return ""
}

func (v PublicOutputRecoveryCommand) Validate(input PublicOutputRecoveryInput, proof PublicOutputRecoveryProof) error {
	body, _ := json.Marshal(input)
	sum := sha256.Sum256(body)
	if v.Version != 1 || v.InputSHA256 != hex.EncodeToString(sum[:]) || v.StageSHA256 != PublicOutputRecoveryStageBinding(v.InputSHA256, v.Stage) || v.StageSHA256 == "" || v.Reservation.Requests == 0 || v.Reservation.BodyBytes == 0 || v.Reservation.Objects > input.CleanupObjectsRemaining || v.Reservation.ObjectBytes > input.CleanupObjectBytesRemaining || v.Reservation.GeneratorCreates != 0 || v.Reservation.GeneratorRetires != 0 {
		return errRecord
	}
	stageFound := false
	for _, stage := range proof.Stages {
		stageFound = stageFound || stage.Name == v.Stage && (stage.Outcome == "entered" || stage.Outcome == "complete")
	}
	if !stageFound {
		return errRecord
	}
	source := filepath.Join(input.StateDir, "public-source/configuration.json")
	base := []string{"apply", "--source", source, "--source-format", "json", "--json"}
	switch v.Stage {
	case "prepare-pair":
		if v.Role != "authority" || v.Pair != nil || len(v.Args) != 18 || v.Args[0] != "prepare" || v.Args[1] != "--source" || v.Args[2] != source || v.Args[3] != "--source-format" || v.Args[4] != "json" || v.Args[5] != "--name" || v.Args[6] != "cleanup" || v.Args[7] != "--provider" || v.Args[8] != input.Provider || v.Args[9] != "--bucket" || v.Args[11] != "--region" || v.Args[12] != input.Region || v.Args[13] != "--prefix" || v.Args[14] != input.Prefix || v.Args[15] != "--normal-signing-key" || v.Args[17] != "--json" {
			return errRecord
		}
	case "retire-bindings":
		if v.Role != "apply" || !slices.Equal(v.Args, base) || v.Pair == nil || v.Pair.Validate(input) != nil {
			return errRecord
		}
	case "remaining-deletions":
		base[0] = "publish"
		if v.Role != "apply" || len(v.Args) <= len(base) || !slices.Equal(v.Args[:len(base)], base) || (len(v.Args)-len(base))%2 != 0 || v.Pair == nil || v.Pair.Validate(input) != nil {
			return errRecord
		}
		wanted := map[string]bool{}
		for _, row := range proof.Initial {
			if row.Disposition != "remaining" {
				continue
			}
			plugin := publicOutputCoordinateScope(row.Target)
			if strings.HasPrefix(plugin, "github-") {
				plugin = "github-actions-" + strings.TrimPrefix(plugin, "github-")
			}
			wanted[row.Target.CoordinateID+"="+plugin] = true
		}
		for i := len(base); i < len(v.Args); i += 2 {
			if v.Args[i] != "--delete-coordinate" || !wanted[v.Args[i+1]] {
				return errRecord
			}
			delete(wanted, v.Args[i+1])
		}
		if len(wanted) != 0 {
			return errRecord
		}
	default:
		return errRecord
	}
	return nil
}

// A joined predecessor can supply command evidence before Store cleanup. Once
// that stage entered, its separate direct-delete inventory must not be reset.
func (v PublicOutputRecoveryProof) BeforeStore(input PublicOutputRecoveryInput) bool {
	body, _ := json.Marshal(input)
	sum := sha256.Sum256(body)
	if v.Version != 1 || v.InputSHA256 != hex.EncodeToString(sum[:]) || v.Store != nil || len(v.Stages) == 0 || len(v.Stages) > 6 {
		return false
	}
	want := []string{"intake", "authenticated-discovery", "prepare-pair", "retire-bindings", "remaining-deletions", "current-disposition"}
	for i, stage := range v.Stages {
		if stage.Name != want[i] || stage.Outcome != "complete" && (i != len(v.Stages)-1 || stage.Outcome != "entered") {
			return false
		}
	}
	return true
}
