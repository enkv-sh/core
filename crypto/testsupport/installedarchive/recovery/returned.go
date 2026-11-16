package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	privatecustody "enkv.sh/crypto/internal/custody"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type Provenance struct {
	Domain, Revision, Snapshot, HEADDigest contract.ID
	HEADToken                              contract.Token
}
type Observation struct {
	Provenance Provenance
	Parts      []installedarchive.Part
	Result     ObservedResult
}

type ObservedResult = installedarchive.RecoveryResult

const maximumRefusedObservationBytes = 1024

type refusedObservationFailure struct {
	category string
	actual   *ObservedResult
	cause    error
}

func (e *refusedObservationFailure) Error() string {
	message := "refused reconstruction check failed: category=" + e.category
	if e.actual != nil {
		message += fmt.Sprintf(" outcome=%d reason=%d evidence=%d", e.actual.Outcome, e.actual.Reason, e.actual.Evidence)
	}
	return message
}

func (e *refusedObservationFailure) Unwrap() error { return e.cause }

func WriteRefusedResult(path string, result ObservedResult) error {
	return writeObservation(path, Observation{Result: result})
}

func CheckRefusedResult(path string, want ObservedResult) error {
	encoded, err := json.Marshal(Observation{Result: want})
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	file, err := os.Open(path)
	if err != nil {
		return &refusedObservationFailure{category: "unavailable", cause: err}
	}
	actual, readErr := io.ReadAll(io.LimitReader(file, maximumRefusedObservationBytes+1))
	defer clear(actual)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return &refusedObservationFailure{category: "read_failed", cause: errors.Join(readErr, closeErr)}
	}
	if bytes.Equal(encoded, actual) {
		return nil
	}
	if len(actual) > maximumRefusedObservationBytes {
		return &refusedObservationFailure{category: "size_exceeded"}
	}
	var observation struct{ Result *ObservedResult }
	if err := json.Unmarshal(actual, &observation); err != nil {
		return &refusedObservationFailure{category: "observation_invalid", cause: err}
	}
	return &refusedObservationFailure{category: "observation_mismatch", actual: observation.Result}
}

// WriteReturnedParts stores test observations, not a local configuration file.
// JSON charges its expansion at the parent against independently expected bytes.
func WriteReturnedParts(path string, provenance Provenance, parts []installedarchive.Part) error {
	return writeObservation(path, Observation{Provenance: provenance, Parts: parts, Result: ObservedResult{Outcome: 2, Evidence: 1}})
}

func writeObservation(path string, observation Observation) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	encodeErr := json.NewEncoder(file).Encode(observation)
	closeErr := file.Close()
	return errors.Join(encodeErr, closeErr)
}

// CheckReturnedParts reads the exited child's actual observations. Exact full
// bytes and ordinals are checked before private decoding; no projection API is
// used to derive the expected selected set or application values.
func CheckReturnedParts(a installedarchive.Archive, path string, expectedValues []installedarchive.ExpectedValue) (uint32, error) {
	return checkReturnedParts(a, path, expectedValues, a.DecryptAuthority)
}

// CheckReturnedPartsWithPrivateOracle keeps captured application bytes inside
// Crypto. Decrypt uses a fresh provider parent route after the child joins.
func CheckReturnedPartsWithPrivateOracle(a installedarchive.Archive, path string, oracles []installedarchive.PrivateValue, decrypt func([]byte) ([]byte, error)) (uint32, error) {
	if decrypt == nil || len(oracles) > contract.CryptoMaxValueEntries {
		return 0, errors.New("private oracle route absent")
	}
	values := make([]installedarchive.ExpectedValue, 0, len(oracles))
	defer func() {
		for _, value := range values {
			clear(value.Bytes)
		}
	}()
	seen := make(map[string]bool, len(oracles))
	for _, oracle := range oracles {
		canonical, err := filepath.EvalSymlinks(oracle.Path)
		if err != nil || !filepath.IsAbs(oracle.Path) || filepath.Clean(oracle.Path) != oracle.Path || canonical != oracle.Path || seen[oracle.Path] {
			return 0, errors.New("private oracle path refused")
		}
		seen[oracle.Path] = true
		directory, err := os.Lstat(filepath.Dir(oracle.Path))
		if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0700 {
			return 0, errors.New("private oracle owner refused")
		}
		info, err := os.Lstat(oracle.Path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != int64(oracle.Length) || oracle.Length > contract.CryptoMaxRawValue {
			return 0, errors.New("private oracle file refused")
		}
		file, err := os.Open(oracle.Path)
		if err != nil {
			return 0, errors.New("private oracle file unavailable")
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 {
			closeErr := file.Close()
			return 0, errors.Join(errors.New("private oracle file changed"), closeErr)
		}
		body, readErr := io.ReadAll(io.LimitReader(file, int64(oracle.Length)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(body) != int(oracle.Length) {
			clear(body)
			return 0, errors.New("private oracle length differs")
		}
		values = append(values, installedarchive.ExpectedValue{Name: oracle.Name, Bytes: body})
	}
	return checkReturnedParts(a, path, values, decrypt)
}

func checkReturnedParts(a installedarchive.Archive, path string, expectedValues []installedarchive.ExpectedValue, decrypt func([]byte) ([]byte, error)) (uint32, error) {
	values := make(map[string][]byte, len(expectedValues))
	for _, value := range expectedValues {
		if _, exists := values[value.Name]; exists {
			return 0, errors.New("duplicate expected value")
		}
		values[value.Name] = value.Bytes
	}
	expected, err := a.SelectedParts()
	if err != nil {
		return 0, err
	}
	headObject, ok := a.Object(a.Location.PrefixBeforeHEAD + "/HEAD")
	if !ok {
		return 0, errors.New("expected HEAD missing")
	}
	head, err := format.DecodeHead(headObject.Body)
	if err != nil {
		return 0, err
	}
	provenance := Provenance{Domain: a.Domain, Revision: a.Revision, Snapshot: head.Core.Root.Object, HEADDigest: a.HeadDigest, HEADToken: headObject.Token}
	want, err := json.Marshal(Observation{Provenance: provenance, Parts: expected, Result: ObservedResult{Outcome: 2, Evidence: 1}})
	if err != nil {
		return 0, err
	}
	want = append(want, '\n')
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() != int64(len(want)) {
		return 0, errors.Join(errors.New("returned complete set length differs"), file.Close())
	}
	body, readErr := io.ReadAll(io.LimitReader(file, int64(len(want))+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(body, want) {
		return 0, errors.Join(errors.New("returned complete selected bytes differ"), readErr, closeErr)
	}
	var observation Observation
	if err := json.Unmarshal(body, &observation); err != nil {
		return 0, err
	}
	var root format.Root
	var entries []contract.ValueEntry
	var accesses []contract.AccessRecord
	for _, part := range observation.Parts {
		switch part.Kind {
		case "root":
			root, err = format.DecodeRoot(part.Body)
		case "value page":
			var page format.ValueEntryPage
			page, err = format.DecodeValueEntryPage(part.Body)
			for _, entry := range page.Slots {
				if entry != nil {
					entries = append(entries, *entry)
				}
			}
		case "access page":
			var page format.AccessPage
			page, err = format.DecodeAccessPage(part.Body)
			accesses = append(accesses, page.Records...)
		}
		if err != nil {
			return 0, err
		}
	}
	if len(entries) != len(values) || root.CurrentAccess.Core.AuthorityRecipientID != a.AuthorityID {
		return 0, errors.New("returned value or Authority set differs")
	}
	seen := map[string]bool{}
	var opened uint32
	for _, entry := range entries {
		want, ok := values[entry.Name]
		if !ok || seen[entry.Name] {
			return opened, errors.New("returned value name differs")
		}
		seen[entry.Name] = true
		if entry.ConfidentialityClass == contract.Plain {
			if !bytes.Equal(entry.ValueBytes, want) {
				return opened, errors.New("returned plain value differs")
			}
			continue
		}
		if !slices.Contains(entry.Recipients, a.AuthorityID) {
			return opened, errors.New("returned secret omits Authority")
		}
		core, err := contract.ValueCoreForEntry(root.Domain, contract.CompatibilityID(), entry)
		if err != nil {
			return opened, err
		}
		payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
		if err != nil {
			return opened, err
		}
		binding := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: a.AuthorityID, Binding: a.AuthorityBinding}
		wrapCore, err := privatecustody.ValueWrapCore(core, binding)
		if err != nil {
			return opened, err
		}
		packetContext, err := contract.RSAPacketContextDigest(wrapCore)
		if err != nil {
			return opened, err
		}
		var ciphertext []byte
		for _, access := range accesses {
			if access.MaterialID == entry.ValueState {
				for _, wrap := range access.Wraps {
					if wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID == a.AuthorityID {
						if ciphertext != nil {
							return opened, errors.New("returned Authority wrap duplicated")
						}
						ciphertext = wrap.RSACiphertext
					}
				}
			}
		}
		packet, err := decrypt(ciphertext)
		if err != nil {
			return opened, err
		}
		keys, err := privatecustody.PacketKeys(packet, 1, packetContext)
		if err != nil {
			clear(packet)
			return opened, err
		}
		plain, err := privatecustody.OpenValue(core, payload, keys)
		clear(packet)
		matched := err == nil && bytes.Equal(plain, want)
		clear(plain)
		if !matched {
			return opened, errors.New("returned secret application bytes differ")
		}
		opened++
	}
	return opened, nil
}
