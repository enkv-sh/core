package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"golang.org/x/sys/unix"
)

const (
	LocalAuthorityInspect  LocalAuthorityOperation = "inspect"
	LocalAuthorityPreview  LocalAuthorityOperation = "preview"
	LocalAuthorityEnd      LocalAuthorityOperation = "end-work"
	LocalAuthorityRecheck  LocalAuthorityOperation = "recheck"
	localBasisJSONFixed                            = 512
	localBasisIDText                               = 2 + 64
	localBasisNameText                             = 2 + 6*contract.CryptoMaxName
	localBasisRecipientRow                         = 96 + localBasisIDText + 3 + localBasisNameText
	localBasisRegistry                             = 2 + contract.CryptoMaxRecipients*(localBasisRecipientRow+1)
	localGenesisBasisLimit                         = localBasisJSONFixed + 4*((contract.GenesisDescriptorLimit+2)/3)
	localNextBasisLimit                            = localBasisJSONFixed + 4*((contract.ControlCoreMaxLength+2)/3) + 4*((contract.MaxHeadLength+2)/3) + localBasisRegistry
	localBasisLimit                                = max(localGenesisBasisLimit, localNextBasisLimit)
)

type LocalAuthorityOperation string

func (o LocalAuthorityOperation) valid() bool {
	switch o {
	case LocalAuthorityInspect, LocalAuthorityPreview, LocalAuthorityEnd, LocalAuthorityRecheck:
		return true
	}
	return false
}

var ErrLocalAuthorityAdmission = errors.New("local Authority admission refused")

type localEnrollmentImage struct {
	ID     string `json:"id"`
	Status uint8  `json:"status"`
	Name   string `json:"display_name"`
}
type localBasisImage struct {
	Schema             uint16                 `json:"schema"`
	Kind               string                 `json:"kind"`
	Descriptor         []byte                 `json:"descriptor,omitempty"`
	Control            []byte                 `json:"control,omitempty"`
	Selection          []byte                 `json:"selection,omitempty"`
	Enrollment         []localEnrollmentImage `json:"enrollment,omitempty"`
	SigningAnchor      []byte                 `json:"anchor,omitempty"`
	StoreConfiguration []byte                 `json:"store_configuration,omitempty"`
	HEAD               []byte                 `json:"head,omitempty"`
	Root               []byte                 `json:"root,omitempty"`
	RecipientPages     [][]byte               `json:"recipient_pages,omitempty"`
}

func localID(s string) (contract.ID, error) {
	var id contract.ID
	if len(s) != 64 || strings.ToLower(s) != s {
		return id, ErrLocalAuthorityAdmission
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, ErrLocalAuthorityAdmission
	}
	copy(id[:], b)
	if id.IsZero() {
		return contract.ID{}, ErrLocalAuthorityAdmission
	}
	return id, nil
}
func localEnrollment(images []localEnrollmentImage) ([]recipientEnrollment, error) {
	if len(images) == 0 || len(images) > contract.CryptoMaxRecipients {
		return nil, ErrLocalAuthorityAdmission
	}
	rows := make([]recipientEnrollment, len(images))
	seen := make(map[contract.ID]bool, len(images))
	for i, image := range images {
		id, err := localID(image.ID)
		if err != nil || seen[id] || len(image.Name) > contract.CryptoMaxName || !utf8.ValidString(image.Name) || image.Status != contract.CurrentRecipient && image.Status != contract.RetiredRecipient {
			return nil, ErrLocalAuthorityAdmission
		}
		seen[id] = true
		rows[i] = recipientEnrollment{id: id, status: image.Status, name: image.Name}
	}
	return rows, nil
}

func admitPublicNormal(ctx context.Context, domain contract.ID, descriptor contract.Descriptor, basis PublicBasis, store contract.Store, composition contract.ID, interpret PublicOutputInterpreter) (OpenContext, Result) {
	if ctx == nil || ctx.Err() != nil || store == nil || store.Descriptor() != descriptor || composition.IsZero() {
		return OpenContext{}, refused(AdmissionInvalid)
	}
	qualified, reason := qualifyReaderPublicBasis(basis, domain, descriptor)
	if reason != "" {
		return OpenContext{}, refused(AdmissionInvalid)
	}
	return admitQualifiedPublicNormal(ctx, domain, descriptor, qualified, store, composition, interpret)
}

// admitBorrowedPublicNormal reuses immutable evidence already owned by Core.
// Installed parents join users before Close; owned readback backing instead
// transfers into the returned private admission.
func admitBorrowedPublicNormal(ctx context.Context, domain contract.ID, descriptor contract.Descriptor, basis PublicBasis, store contract.Store, composition contract.ID, interpret PublicOutputInterpreter) (OpenContext, Result) {
	if ctx == nil || ctx.Err() != nil || store == nil || store.Descriptor() != descriptor || composition.IsZero() {
		return OpenContext{}, refused(AdmissionInvalid)
	}
	qualified, reason := qualifyBorrowedReaderPublicBasis(basis, domain, descriptor)
	if reason != "" {
		return OpenContext{}, refused(AdmissionInvalid)
	}
	return admitQualifiedPublicNormal(ctx, domain, descriptor, qualified, store, composition, interpret)
}

// The installed replacement owns this immutable source until all users join.
func admitReplacementPublicNormal(ctx context.Context, domain contract.ID, descriptor contract.Descriptor, basis PublicBasis, store contract.Store, composition contract.ID) (OpenContext, Result) {
	if ctx == nil || ctx.Err() != nil || store == nil || store.Descriptor() != descriptor || composition.IsZero() {
		return OpenContext{}, refused(AdmissionInvalid)
	}
	qualified, reason := qualifyBorrowedReaderPublicBasis(basis, domain, descriptor)
	if reason != "" {
		return OpenContext{}, refused(AdmissionInvalid)
	}
	return admitQualifiedPublicNormalWithBasis(ctx, domain, descriptor, qualified, store, composition, nil, true)
}

// qualified evidence can be borrowed only within its existing private owner.
func admitQualifiedPublicNormal(ctx context.Context, domain contract.ID, descriptor contract.Descriptor, qualified readerPublicBasis, store contract.Store, composition contract.ID, interpret PublicOutputInterpreter) (OpenContext, Result) {
	return admitQualifiedPublicNormalWithBasis(ctx, domain, descriptor, qualified, store, composition, interpret, false)
}

func admitQualifiedPublicNormalWithBasis(ctx context.Context, domain contract.ID, descriptor contract.Descriptor, qualified readerPublicBasis, store contract.Store, composition contract.ID, interpret PublicOutputInterpreter, borrowBasis bool) (OpenContext, Result) {
	if ctx == nil || ctx.Err() != nil || store == nil || store.Descriptor() != descriptor || composition.IsZero() {
		return OpenContext{}, refused(AdmissionInvalid)
	}
	control := qualified.control
	a := openAdmission{domain: domain, trust: control.NormalSigning.Binding.Trust, interpretation: contract.InterpretationID(), recipient: control.AuthorityRecipientID, composition: composition, controlIncarnation: control.NormalSigning.Binding.ControlIncarnationID, store: descriptor, epoch: control.NormalSigning.Binding.Epoch, publicKey: bytes.Clone(control.NormalSigning.SPKI), expires: time.Now().Add(5 * time.Minute), outputInterpreter: interpret}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(a.expires) {
		a.expires = deadline
	}
	if borrowBasis {
		a.descriptor, a.current = qualified.descriptor, qualified.current
	} else {
		a.descriptor = bytes.Clone(qualified.descriptor)
		a.current = qualified.current.clone()
	}
	if qualified.observation != nil {
		a.observation = &qualified
	}
	if !a.valid(store) {
		return OpenContext{}, refused(AdmissionInvalid)
	}
	return OpenContext{admission: &a}, Result{Outcome: ObservedCurrent}
}

func localProtectedDirectory(fd int) bool {
	var stat unix.Stat_t
	return unix.Fstat(fd, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		(stat.Uid == 0 || uint64(stat.Uid) == uint64(os.Geteuid())) && stat.Mode&0022 == 0
}

// localProtectedParent keeps a no-follow directory handle for both protected
// reads and exclusive durable basis creation. The caller owns the handle.
func localProtectedParent(path string) (int, string, error) {
	return localProtectedParentContext(context.Background(), path)
}

func localProtectedParentContext(ctx context.Context, path string) (int, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return -1, "", ErrLocalAuthorityAdmission
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	dir, err := openLocalProtected(ctx, unix.AT_FDCWD, "/", unix.O_DIRECTORY, unix.Openat)
	if err != nil {
		return -1, "", err
	}
	if !localProtectedDirectory(dir) {
		return -1, "", errors.Join(ErrLocalAuthorityAdmission, unix.Close(dir))
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return -1, "", errors.Join(ErrLocalAuthorityAdmission, unix.Close(dir))
		}
		next, err := openLocalProtected(ctx, dir, part, unix.O_DIRECTORY, unix.Openat)
		if err != nil {
			return -1, "", errors.Join(err, ErrLocalAuthorityAdmission, unix.Close(dir))
		}
		if !localProtectedDirectory(next) {
			return -1, "", errors.Join(ErrLocalAuthorityAdmission, unix.Close(next), unix.Close(dir))
		}
		if err := unix.Close(dir); err != nil {
			return -1, "", errors.Join(ErrLocalAuthorityAdmission, err, unix.Close(next))
		}
		dir = next
	}
	name := parts[len(parts)-1]
	if name == "" || name == "." || name == ".." {
		return -1, "", errors.Join(ErrLocalAuthorityAdmission, unix.Close(dir))
	}
	return dir, name, nil
}

// readLocalProtected walks every path component through no-follow directory
// handles. A stable final regular file must stay owned by this process UID.
func readLocalProtected(path string, limit int64) ([]byte, error) {
	return ReadLocalProtectedFile(context.Background(), path, limit)
}

// ReadLocalProtectedFile returns bounded, owned bytes from a stable regular
// file. Native ownership and mode checks grant no role or operation and do not
// establish protection against hostile local users. Cancellation bounds retries
// and work between synchronous filesystem calls, not arbitrary filesystem I/O latency.
func ReadLocalProtectedFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	return readLocalProtectedFile(ctx, path, limit, io.ReadFull)
}

func openLocalProtected(ctx context.Context, dir int, path string, flags int, open func(int, string, int, uint32) (int, error)) (int, error) {
	if ctx == nil {
		return -1, ErrLocalAuthorityAdmission
	}
	for {
		if err := ctx.Err(); err != nil {
			return -1, errors.Join(ErrLocalAuthorityAdmission, err)
		}
		fd, err := open(dir, path, flags|unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return -1, errors.Join(ErrLocalAuthorityAdmission, err)
		}
		if err := ctx.Err(); err != nil {
			return -1, errors.Join(ErrLocalAuthorityAdmission, err, unix.Close(fd))
		}
		return fd, nil
	}
}

func readLocalProtectedFile(ctx context.Context, path string, limit int64, readFull func(io.Reader, []byte) (int, error)) (body []byte, err error) {
	if ctx == nil || limit <= 0 {
		return nil, ErrLocalAuthorityAdmission
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrLocalAuthorityAdmission, err)
	}
	dir, name, err := localProtectedParentContext(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := unix.Close(dir); closeErr != nil {
			body = nil
			err = errors.Join(err, ErrLocalAuthorityAdmission, closeErr)
		}
	}()
	fd, err := openLocalProtected(ctx, dir, name, 0, unix.Openat)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			body = nil
			err = errors.Join(err, ErrLocalAuthorityAdmission, closeErr)
		}
	}()
	var before, after, current unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || uint64(before.Uid) != uint64(os.Geteuid()) ||
		before.Mode&0077 != 0 || before.Mode&0111 != 0 || before.Size <= 0 || before.Size > limit {
		return nil, ErrLocalAuthorityAdmission
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrLocalAuthorityAdmission, err)
	}
	body = make([]byte, int(before.Size))
	_, err = readFull(file, body)
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrLocalAuthorityAdmission, err)
	}
	var extra [1]byte
	extraCount, extraErr := file.Read(extra[:])
	if ctx.Err() != nil || err != nil || extraCount != 0 || extraErr != io.EOF || unix.Fstat(fd, &after) != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, ErrLocalAuthorityAdmission
	}
	again, err := openLocalProtected(ctx, dir, name, 0, unix.Openat)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := unix.Close(again); closeErr != nil {
			body = nil
			err = errors.Join(err, ErrLocalAuthorityAdmission, closeErr)
		}
	}()
	if unix.Fstat(again, &current) != nil || before.Dev != current.Dev || before.Ino != current.Ino ||
		before.Size != current.Size || before.Mtim != current.Mtim || before.Ctim != current.Ctim ||
		current.Mode&unix.S_IFMT != unix.S_IFREG || uint64(current.Uid) != uint64(os.Geteuid()) || current.Mode&0077 != 0 ||
		current.Mode&0111 != 0 {
		return nil, ErrLocalAuthorityAdmission
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrLocalAuthorityAdmission, err)
	}
	return body, nil
}
