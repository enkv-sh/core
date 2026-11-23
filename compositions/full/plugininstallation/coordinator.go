package plugininstallation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unicode/utf8"

	"enkv.sh/sdk/artifact"
)

// Resolve captures one immutable selection per required name. Failed rows are
// retained alongside completed rows. Prepare and Upgrade may return only verified
// partial captures with a nonnil error after stable-source/live-context checks;
// these are evidence, not readiness. Ordinary returns no session on error.
// Requirements must be sorted by unique name and remain unchanged during the
// call. CheckSource runs before capture and again before selection publication.
// A later failure does not undo earlier published selections; inspect rows and
// Changed as well as the error. Resolve never executes a plugin.
func (c *Coordinator) Resolve(ctx context.Context, request Request) (session *Session, rows []Installation, resultErr error) {
	ctx, call := startCall(ctx, opResolve)
	session, rows, err := c.resolve(ctx, request)
	finishCall(call, err)
	return session, rows, err
}

func (c *Coordinator) resolve(ctx context.Context, request Request) (session *Session, rows []Installation, resultErr error) {
	if c == nil || ctx == nil || request.Mode > Upgrade || request.CheckSource == nil || !validRequirements(request.Requirements) {
		return nil, nil, ErrInvalid
	}
	scope, err := canonicalDirectory(request.Directory)
	if err != nil {
		return nil, nil, err
	}
	if err := request.CheckSource(ctx); err != nil {
		return nil, nil, errors.Join(ErrSourceChanged, err)
	}
	settings, err := c.settings(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	prior, priorBytes, err := c.selection(ctx, selectionPath, scope)
	if err != nil {
		for _, requirement := range request.Requirements {
			rows = append(rows, failureRow(baseRow(requirement), err))
		}
		return nil, rows, err
	}
	local := map[string]string{}
	for _, application := range settings.Applications {
		if application.Directory == scope {
			for _, p := range application.Plugins {
				local[p.Name] = p.Directory
			}
		}
	}
	session = &Session{installed: map[string]*Installed{}}
	for _, requirement := range request.Requirements {
		row := baseRow(requirement)
		var selected *Installed
		var err error
		if output, ok := local[requirement.Name]; ok {
			row.Source = "local"
			row.Version, row.Artifact = "", nil
			selected, err = c.local(ctx, output, artifact.Selection{Name: requirement.Name, Platform: row.Platform})
			if err != nil {
				row = candidateFacts(row, err)
			}
		} else {
			old, hasOld := findSelection(prior, requirement.Name)
			var previous *Installed
			replacing := hasOld && requirement.Version != "" && requirement.Version != old.Version
			upgrading := hasOld && request.Mode == Upgrade && requirement.Version == ""
			if hasOld {
				if requirement.Version == "" || requirement.Version == old.Version {
					row.Version = old.Version
					row.Artifact = digestPointer(old.Artifact)
				}
				previous, err = c.official(ctx, old, false)
				if onlyMissing(err) && request.Mode != Ordinary && !replacing && !upgrading {
					previous, err = c.acquire(ctx, "artifacts/"+old.Artifact.String()+"/", old, true)
					if err != nil {
						rows = append(rows, failureRow(row, err))
						resultErr = errors.Join(resultErr, err)
						continue
					}
				}
				if err == nil {
					row.Previous = identityRow(previous)
				}
				if err != nil && (request.Mode == Ordinary || !onlyIncompatible(err) && (!onlyMissing(err) || !replacing && !upgrading)) {
					rows = append(rows, failureRow(row, err))
					resultErr = errors.Join(resultErr, err)
					continue
				}
			}
			previousErr := err
			if request.Mode == Ordinary {
				if !hasOld {
					err = ErrMissing
				} else if requirement.Version != "" && old.Version != requirement.Version {
					row.Status, row.Reason = "incompatible", "version-mismatch"
					err = ErrIncompatible
				} else {
					selected = previous
				}
			} else {
				needsSelection := !hasOld || requirement.Version != "" && old.Version != requirement.Version || request.Mode == Upgrade && requirement.Version == "" || errors.Is(err, ErrIncompatible)
				switch {
				case !needsSelection:
					selected, err = previous, nil
				case requirement.Version != "":
					candidate := artifact.Selection{Name: requirement.Name, Version: requirement.Version, Platform: row.Platform}
					selected, err = c.acquire(ctx, releasePath(candidate), candidate, false)
				default:
					floor := ""
					err = nil
					if upgrading {
						err = c.authenticateSelection(ctx, old)
						floor = old.Version
					}
					if err == nil {
						selected, err = c.latest(ctx, requirement.Name, row.Platform, previous, floor)
					}
					if err == nil && selected == nil && upgrading {
						if onlyMissing(previousErr) {
							selected, err = c.acquire(ctx, "artifacts/"+old.Artifact.String()+"/", old, true)
							if err == nil {
								row.Previous = identityRow(selected)
							}
						} else {
							err = previousErr
						}
					}
				}
				if err != nil {
					row = candidateFacts(row, err)
				}
				if err == nil && selected != nil {
					row = selectedFacts(row, selected)
					err = c.remember(ctx, selected)
				}
				if err == nil && selected != nil {
					metadata, _ := selected.Metadata()
					candidate := artifact.Selection{Name: metadata.Name, Version: metadata.Version, Platform: metadata.Platform, Artifact: selected.identity, Proof: *selected.proof}
					if !hasOld || old != candidate {
						next := replaceSelection(prior, candidate)
						body, encodeErr := artifact.EncodeSelectionRecord(next)
						if encodeErr != nil {
							err = encodeErr
						} else {
							err = c.commitSelection(ctx, selectionPath, scope, priorBytes, body, request.CheckSource)
						}
						if err == nil || recordWasPublished(err) {
							prior, priorBytes = next, body
							row.Changed = true
							if err != nil {
								resultErr = errors.Join(resultErr, err)
								err = nil
							}
						}
					}
				}
			}
		}
		if err == nil && selected != nil {
			row = selectedFacts(row, selected)
			if row.Source == "local" || request.Mode == Ordinary {
				err = c.remember(ctx, selected)
			}
			if err == nil {
				if sourceErr := request.CheckSource(ctx); sourceErr != nil {
					resultErr = errors.Join(resultErr, ErrSourceChanged, sourceErr)
				}
			}
		}
		if err != nil {
			if row.Reason != "version-mismatch" {
				row = failureRow(row, err)
			} else {
				row.Changed = false
			}
			resultErr = errors.Join(resultErr, err)
		} else if selected == nil {
			row = failureRow(row, ErrMissing)
			resultErr = errors.Join(resultErr, ErrMissing)
		} else {
			row.Status, row.Reason = "verified", "none"
			metadata, _ := selected.Metadata()
			row.executableSHA256 = metadata.Executable.SHA256
			row.descriptor, _ = metadata.Descriptor()
			session.installed[requirement.Name] = selected
		}
		rows = append(rows, row)
	}
	if err := request.CheckSource(ctx); err != nil {
		resultErr = errors.Join(resultErr, ErrSourceChanged, err)
	}
	if err := ctx.Err(); err != nil {
		resultErr = errors.Join(resultErr, err, context.Cause(ctx))
	}
	if resultErr != nil {
		if request.Mode == Ordinary || len(session.installed) == 0 || errors.Is(resultErr, ErrSourceChanged) || errors.Is(resultErr, context.Canceled) || errors.Is(resultErr, context.DeadlineExceeded) {
			session = nil
		}
		return session, rows, errors.Join(ErrInstallation, resultErr)
	}
	return session, rows, nil
}

func baseRow(r Requirement) Installation {
	return Installation{Name: r.Name, Version: r.Version, Platform: runtime.GOOS + "/" + runtime.GOARCH, Source: "official", Status: "missing", Reason: "not-installed"}
}
func digestPointer(d artifact.Digest) *artifact.Digest { return &d }
func selectedFacts(row Installation, installed *Installed) Installation {
	metadata, _ := installed.Metadata()
	row.Role, row.Version, row.Artifact, row.Source = metadata.Role, metadata.Version, digestPointer(installed.identity), installed.source
	return row
}
func identityRow(i *Installed) *Previous {
	m, _ := i.Metadata()
	return &Previous{Version: m.Version, Artifact: i.identity, Platform: m.Platform, Source: i.source}
}
func findSelection(record artifact.SelectionRecord, name string) (artifact.Selection, bool) {
	for _, s := range record.Selections {
		if s.Name == name {
			return s, true
		}
	}
	return artifact.Selection{}, false
}
func replaceSelection(record artifact.SelectionRecord, row artifact.Selection) artifact.SelectionRecord {
	record.Selections = slices.Clone(record.Selections)
	for j := range record.Selections {
		if record.Selections[j].Name == row.Name {
			record.Selections[j] = row
			return record
		}
	}
	record.Selections = append(record.Selections, row)
	slices.SortFunc(record.Selections, func(a, b artifact.Selection) int { return strings.Compare(a.Name, b.Name) })
	return record
}
func releasePath(s artifact.Selection) string {
	return "plugins/" + s.Name + "/" + s.Version + "/" + strings.ReplaceAll(s.Platform, "/", "-") + "/"
}

func (c *Coordinator) selection(ctx context.Context, path, scope string) (artifact.SelectionRecord, []byte, error) {
	body, err := readFile(ctx, path, artifact.MaxRecordBytes)
	if errors.Is(err, os.ErrNotExist) {
		return artifact.SelectionRecord{Schema: "enkv/plugin-selection/v1", Directory: scope, Selections: []artifact.Selection{}}, nil, nil
	}
	if err != nil {
		return artifact.SelectionRecord{}, nil, err
	}
	record, err := artifact.DecodeSelectionRecord(body)
	if err != nil || record.Directory != scope {
		return artifact.SelectionRecord{}, nil, errors.Join(ErrInvalid, err)
	}
	return record, body, nil
}
func (c *Coordinator) settings(ctx context.Context, scope string) (artifact.Settings, error) {
	path := filepath.Join(c.configDirectory, "plugins.json")
	unavailable := func(err error) (artifact.Settings, error) {
		return artifact.Settings{}, settingsFailure(path, "settings-unavailable", nil, err)
	}
	if len(path) > 4096 || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return unavailable(ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return unavailable(err)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return artifact.Settings{Schema: "enkv/plugin-settings/v1", Applications: []artifact.Application{}}, nil
	}
	if err != nil {
		return unavailable(err)
	}
	if info.Mode().IsRegular() && info.Size() > artifact.MaxRecordBytes {
		return artifact.Settings{}, settingsFailure(path, "limit-exceeded", nil, ErrInvalid)
	}
	body, err := readFile(ctx, path, artifact.MaxRecordBytes)
	if err != nil {
		return unavailable(err)
	}
	settings, err := artifact.DecodeSettings(body)
	if err != nil {
		var content *artifact.SettingsError
		if errors.As(err, &content) {
			return artifact.Settings{}, settingsFailure(path, content.Reason, content.Location, errors.Join(ErrInvalid, err))
		}
		return artifact.Settings{}, settingsFailure(path, "invalid-value", nil, errors.Join(ErrInvalid, err))
	}
	for _, a := range settings.Applications {
		if a.Directory != scope {
			continue
		}
		canonical, err := canonicalDirectory(a.Directory)
		if err != nil || canonical != a.Directory {
			return artifact.Settings{}, settingsFailure(path, "invalid-value", nil, errors.Join(ErrInvalid, err))
		}
	}
	return settings, nil
}

func (c *Coordinator) commitSelection(ctx context.Context, path, scope string, prior, body []byte, check func(context.Context) error) (err error) {
	ctx, call := startCall(ctx, opSelect)
	published, err := c.replaceSelectionRecord(ctx, path, scope, prior, body, check)
	finishCall(call, err)
	if published && err != nil {
		return &recordCompletionFailure{cause: err}
	}
	return err
}

func (c *Coordinator) replaceSelectionRecord(ctx context.Context, path, scope string, prior, body []byte, check func(context.Context) error) (published bool, err error) {
	if err := ensureDirectory(filepath.Dir(path)); err != nil {
		return false, err
	}
	unlock, err := lock(ctx, path+".lock")
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	return atomicRecord(ctx, path, body, func() error {
		if err := check(ctx); err != nil {
			return errors.Join(ErrSourceChanged, err)
		}
		_, current, err := c.selection(ctx, path, scope)
		if err != nil {
			return err
		}
		if !bytes.Equal(prior, current) {
			return ErrSourceChanged
		}
		return nil
	})
}

func (c *Coordinator) latest(ctx context.Context, name, platform string, previous *Installed, floor string) (*Installed, error) {
	index, err := c.index(ctx, name)
	if err != nil {
		return nil, err
	}
	var incompatible error
	for j := len(index.Releases) - 1; j >= 0; j-- {
		release := index.Releases[j]
		if release.Platform != platform || strings.Contains(strings.SplitN(release.Version, "+", 2)[0], "-") {
			continue
		}
		if floor != "" {
			order, _ := artifact.CompareVersions(release.Version, floor)
			if order <= 0 {
				continue
			}
		}
		expected := artifact.Selection{Name: name, Version: release.Version, Platform: platform, Artifact: release.Artifact}
		installed, err := c.acquire(ctx, releasePath(expected), expected, false)
		// Only a verified protocol mismatch can move selection to an older
		// release. Damage or cleanup failure must stop selection instead.
		if candidateMaySkip(err) {
			incompatible = err
			continue
		}
		return installed, err
	}
	if floor != "" {
		return previous, nil
	}
	if incompatible != nil {
		return nil, incompatible
	}
	return nil, ErrIncompatible
}

func (c *Coordinator) authenticateSelection(ctx context.Context, selection artifact.Selection) error {
	_, _, _, err := c.readProof(ctx, c.proofDirectory(selection), selection)
	if !onlyMissing(err) {
		return err
	}
	base := "artifacts/" + selection.Artifact.String() + "/"
	body, err := c.fetch(ctx, base+"archive.json", artifact.MaxRecordBytes)
	if err != nil {
		return err
	}
	sig, err := c.fetch(ctx, base+"archive.sig", 64)
	if err != nil {
		return err
	}
	if err := c.verifySignature("plugin-archive", body, sig); err != nil {
		return err
	}
	record, err := artifact.DecodeArchiveRecord(body)
	if err != nil {
		return errors.Join(ErrInvalid, err)
	}
	if record.Artifact != selection.Artifact || record.Name != selection.Name || record.Version != selection.Version || record.Platform != selection.Platform {
		return ErrIdentity
	}
	var metadataSignature artifact.Digest
	for _, member := range record.Members {
		if member.Name == "metadata.json" && member.SHA256 != selection.Artifact {
			return ErrIdentity
		}
		if member.Name == "metadata.sig" {
			metadataSignature = member.SHA256
		}
	}
	proof, err := artifact.EncodeOfficialProof(artifact.OfficialProof{Schema: "enkv/plugin-official-proof/v1", Artifact: selection.Artifact, ArchiveRecord: artifact.Hash(body), MetadataSignature: metadataSignature, ArchiveSignature: artifact.Hash(sig)})
	if err != nil || artifact.Hash(proof) != selection.Proof {
		return errors.Join(ErrIdentity, err)
	}
	proofPath := c.proofDirectory(selection)
	if err := plainPath(proofPath); err != nil && !onlyMissing(err) {
		return err
	}
	entries, err := readPackageDirectory(proofPath, 4)
	if err != nil && !onlyMissing(err) {
		return err
	}
	for _, entry := range entries {
		var digest artifact.Digest
		var limit int64
		switch entry.Name() {
		case "proof.json":
			digest, limit = selection.Proof, artifact.MaxProofBytes
		case "archive.json":
			digest, limit = artifact.Hash(body), artifact.MaxRecordBytes
		case "archive.sig":
			digest, limit = artifact.Hash(sig), 64
		case "metadata.sig":
			digest, limit = metadataSignature, 64
		default:
			return ErrInvalid
		}
		contents, err := readFile(ctx, filepath.Join(proofPath, entry.Name()), limit)
		if err != nil {
			return err
		}
		if artifact.Hash(contents) != digest {
			return ErrIdentity
		}
	}
	packagePath := c.packageDirectory(selection)
	if err := plainPath(packagePath); err != nil && !onlyMissing(err) {
		return err
	}
	if err := partialPackage(ctx, packagePath, record); err != nil && !onlyMissing(err) {
		return err
	}
	return nil
}

func onlyMissing(err error) bool {
	return onlyCauses(err, func(cause error) bool {
		return cause == ErrMissing || errors.Is(cause, os.ErrNotExist)
	})
}

func onlyCauses(err error, allow func(error) bool) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !onlyCauses(cause, allow) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyCauses(wrapped.Unwrap(), allow)
	}
	return allow(err)
}
