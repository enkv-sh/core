package configuration

import (
	"errors"
	"os"
)

func (image *Image) acquireName() error {
	info, err := image.file.Stat()
	identity, identityErr := nativeFact(info)
	if err != nil || identityErr != nil || !info.Mode().IsRegular() || !singleLink(info) {
		return errors.Join(ErrEdit, err, identityErr)
	}
	image.temporaryName = image.file.Name()
	image.temporary = identity
	image.named = true
	return nil
}

func removeOwnedTemporary(path string, expected diskIdentity, remove func(string) error) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	identity, identityErr := nativeFact(info)
	if err != nil || identityErr != nil || expected == (diskIdentity{}) || identity != expected || !info.Mode().IsRegular() || !singleLink(info) {
		return errors.Join(ErrEdit, err, identityErr)
	}
	return editError(remove(path))
}

func (image *Image) removeName() error {
	if image == nil || !image.named {
		return nil
	}
	if image.temporaryName == "" {
		return ErrEdit
	}
	if err := removeOwnedTemporary(image.temporaryName, image.temporary, os.Remove); err != nil {
		return err
	}
	image.named = false
	return nil
}

func (image *Image) checkName() error {
	if image == nil || !image.named || image.temporaryName == "" {
		return ErrEdit
	}
	info, err := os.Lstat(image.temporaryName)
	identity, identityErr := nativeFact(info)
	if err != nil || identityErr != nil || identity != image.temporary || !info.Mode().IsRegular() || !singleLink(info) {
		return errors.Join(ErrEdit, err, identityErr)
	}
	return nil
}

func (candidate *EditCandidate) retainPending() {
	candidate.durable = true
	candidate.installations = [2]diskIdentity{}
	candidate.recordNative = diskIdentity{}
	candidate.scratch = ""
	candidate.scratchNative = diskIdentity{}
	for _, image := range []*Image{candidate.pair.Editable, candidate.pair.Generated} {
		if image != nil {
			image.named = false
		}
	}
}

func (s *EditSession) relinquishInstallation(path string) {
	if s.candidate == nil {
		return
	}
	for index, temporary := range []string{s.candidate.editableTemp, s.candidate.generatedTemp} {
		if temporary+".install" == path {
			s.candidate.installations[index] = diskIdentity{}
		}
	}
}

func (s *EditSession) relinquishImage(path string) {
	if s.candidate == nil {
		return
	}
	for _, image := range []*Image{s.candidate.pair.Editable, s.candidate.pair.Generated} {
		if image != nil && image.file != nil && image.file.Name() == path {
			image.named = false
		}
	}
}

func (s *EditSession) relinquishPending() {
	if s.candidate == nil {
		return
	}
	s.candidate.installations = [2]diskIdentity{}
	s.candidate.pending = nil
	s.candidate.scratch = ""
	s.candidate.scratchNative = diskIdentity{}
}
