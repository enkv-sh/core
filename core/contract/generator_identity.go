package contract

import "unicode/utf8"

const generatorIdentityPrefix = "ENKV/GENERATOR/v1/"

func generatorDigest(label string, body []byte) ID {
	w := cryptoHashWriter(generatorIdentityPrefix + label + "\x00")
	w.blob(body)
	return w.result(0).Digest
}

func GeneratorAttemptID(lineage ID, branch uint8) (ID, error) {
	if lineage.IsZero() || branch > GeneratorBranchResidueThenNoEffect {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 33)}
	w.id(lineage)
	w.u8(branch)
	return generatorDigest("attempt", w.b), nil
}

// GeneratorSuccessorBranch resolves a fixed graph edge, not effect admission.
// Gate one requires qualified no-effect evidence; gate two requires residue
// authority. Neither a branch ID nor a successful lookup grants a send right.
func GeneratorSuccessorBranch(branch, gate uint8) (next uint8, present bool, err error) {
	if branch > GeneratorBranchResidueThenNoEffect || gate < GeneratorGuardQualifiedNoEffect || gate > GeneratorGuardResidue {
		return 0, false, ErrRecord
	}
	switch {
	case branch == GeneratorBranchInitial && gate == GeneratorGuardQualifiedNoEffect:
		return GeneratorBranchNoEffect, true, nil
	case branch == GeneratorBranchInitial && gate == GeneratorGuardResidue:
		return GeneratorBranchResidue, true, nil
	case branch == GeneratorBranchNoEffect && gate == GeneratorGuardResidue:
		return GeneratorBranchNoEffectThenResidue, true, nil
	case branch == GeneratorBranchResidue && gate == GeneratorGuardQualifiedNoEffect:
		return GeneratorBranchResidueThenNoEffect, true, nil
	default:
		return 0, false, nil
	}
}

func GeneratorTransmissionID(attempt ID, action uint8) (ID, error) {
	if attempt.IsZero() || action < GeneratorActionCreate || action > GeneratorActionDelete {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 34)}
	w.id(attempt)
	w.u8(action)
	w.u8(0)
	return generatorDigest("transmission", w.b), nil
}

func GeneratorResultID(domain, operation, attempt, transmission ID, action uint8) (ID, error) {
	if !publicIDsValid(domain, operation, attempt, transmission) || action < GeneratorActionCreate || action > GeneratorActionDelete {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 129)}
	w.id(domain)
	w.id(operation)
	w.id(attempt)
	w.id(transmission)
	w.u8(action)
	return generatorDigest("result", w.b), nil
}

func GeneratorInboxID(domain, operation, attempt, result ID) (ID, error) {
	if !publicIDsValid(domain, operation, attempt, result) {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 128)}
	w.id(domain)
	w.id(operation)
	w.id(attempt)
	w.id(result)
	return generatorDigest("inbox", w.b), nil
}

// GeneratorRetirementAmbiguityID locates the independent record for the
// original retirement inbox. It is never the terminal result coordinate.
func GeneratorRetirementAmbiguityID(inbox ID) (ID, error) {
	if inbox.IsZero() {
		return ID{}, ErrRecord
	}
	return generatorDigest("retirement-ambiguity", inbox[:]), nil
}

func GeneratorLineageID(domain, operation ID, name string, incarnation ID, epoch uint64, intent ID) (ID, error) {
	if !publicIDsValid(domain, operation, incarnation, intent) || !utf8.ValidString(name) {
		return ID{}, ErrRecord
	}
	if len(name) > CryptoMaxName {
		return ID{}, ErrRecordCapacity
	}
	w := cryptoWriter{b: make([]byte, 0, 140+len(name))}
	w.id(domain)
	w.id(operation)
	w.blob([]byte(name))
	w.id(incarnation)
	w.u64(epoch)
	w.id(intent)
	return generatorDigest("lineage", w.b), nil
}

func GeneratorObligationLineageID(domain, operation, resource ID, purpose GeneratorLineagePurpose) (ID, error) {
	if !publicIDsValid(domain, operation, resource) || purpose < GeneratorLineageRetirement || purpose > GeneratorLineageCleanup {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 97)}
	w.id(domain)
	w.id(operation)
	w.id(resource)
	w.u8(uint8(purpose))
	return generatorDigest("obligation-lineage", w.b), nil
}

func GeneratorMaterialID(domain, operation ID) (ID, error) {
	if !publicIDsValid(domain, operation) {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 64)}
	w.id(domain)
	w.id(operation)
	return generatorDigest("material-id", w.b), nil
}

func generatorAttemptSubject(label string, domain, operation, attempt ID) (ID, error) {
	if !publicIDsValid(domain, operation, attempt) {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 96)}
	w.id(domain)
	w.id(operation)
	w.id(attempt)
	return generatorDigest(label, w.b), nil
}

func GeneratorResourceID(domain, operation, attempt ID) (ID, error) {
	return generatorAttemptSubject("resource", domain, operation, attempt)
}

func GeneratorValueSlotID(domain, operation, attempt ID) (ID, error) {
	return generatorAttemptSubject("value-slot", domain, operation, attempt)
}

func GeneratorDutyID(domain, operation, attempt ID, purpose uint8) (ID, error) {
	if !publicIDsValid(domain, operation, attempt) || purpose < GeneratedDutyCreate || purpose > GeneratedDutyUnselectedCleanup {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 97)}
	w.id(domain)
	w.id(operation)
	w.id(attempt)
	w.u8(purpose)
	return generatorDigest("duty", w.b), nil
}

func GeneratorHazardID(domain, originalAttempt ID) (ID, error) {
	if !publicIDsValid(domain, originalAttempt) {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 64)}
	w.id(domain)
	w.id(originalAttempt)
	return generatorDigest("hazard", w.b), nil
}

func GeneratorFragmentID(blob ID, index uint16) (ID, error) {
	if blob.IsZero() || index >= GeneratedFragmentLocationLimit {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 34)}
	w.id(blob)
	w.u16(index)
	return generatorDigest("fragment", w.b), nil
}
