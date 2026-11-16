package core

import (
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

func readOrdinaryOutputImage() (proof ordinaryOutputProof, err error) {
	proof.ImagePath, err = os.Executable()
	if err != nil {
		return proof, err
	}
	file, err := os.Open(proof.ImagePath)
	if err != nil {
		return proof, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	proof.file, err = file.Stat()
	if err != nil || !proof.file.Mode().IsRegular() || proof.file.Size() < 32 {
		return proof, fmt.Errorf("main executable identity unavailable: %v", err)
	}
	proof.ImageBytes = uint64(proof.file.Size())
	var header [32]byte
	if _, err = file.ReadAt(header[:], 0); err != nil {
		return proof, err
	}
	if binary.LittleEndian.Uint32(header[:4]) != macho.Magic64 ||
		uint64(binary.LittleEndian.Uint32(header[20:24])) > proof.ImageBytes-32 ||
		binary.LittleEndian.Uint32(header[16:20]) > binary.LittleEndian.Uint32(header[20:24])/8 {
		return proof, fmt.Errorf("unbounded or unknown Mach-O command envelope")
	}
	image, err := macho.NewFile(io.NewSectionReader(file, 0, proof.file.Size()))
	if err != nil {
		return proof, err
	}
	if image.Cpu != macho.CpuArm64 || image.SubCpu != 0 || image.Type != macho.TypeExec {
		return proof, fmt.Errorf("unknown loaded main image tuple")
	}
	for _, load := range image.Loads {
		if segment, present := load.(*macho.Segment); present {
			proof.Segments = append(proof.Segments, segment.SegmentHeader)
		}
	}
	proof.PageBytes = uint64(os.Getpagesize())
	proof.StaticUpper, err = ordinaryOutputSegmentUpper(proof.Segments, proof.ImageBytes, proof.PageBytes)
	if err != nil {
		return proof, err
	}
	hash := sha256.New()
	if count, copyErr := io.Copy(hash, io.NewSectionReader(file, 0, proof.file.Size())); copyErr != nil || count != proof.file.Size() {
		return proof, fmt.Errorf("bounded executable hash failed (%d/%d): %v", count, proof.file.Size(), copyErr)
	}
	proof.ImageSHA256 = fmt.Sprintf("%x", hash.Sum(nil))
	current, err := os.Stat(proof.ImagePath)
	if err != nil || !records.SameLocalFile(proof.file, current) || current.Size() != proof.file.Size() || !current.ModTime().Equal(proof.file.ModTime()) {
		return proof, fmt.Errorf("main artifact changed during inspection: %v", err)
	}
	return proof, nil
}

func newOrdinaryOutputProof(t *testing.T) *ordinaryOutputProof {
	t.Helper()
	build, _ := debug.ReadBuildInfo()
	if err := ordinaryOutputEligibility(runtime.Version(), runtime.GOOS, runtime.GOARCH, os.Getenv("GODEBUG"), build); err != nil {
		t.Fatal("conservative proof unavailable", err, runtime.Version(), runtime.GOOS, runtime.GOARCH, os.Getenv("GODEBUG"), build)
	}
	proof, err := readOrdinaryOutputImage()
	if err != nil {
		t.Fatal("conservative proof unavailable", err)
	}
	proof.GoVersion, proof.GOOS, proof.GOARCH = runtime.Version(), runtime.GOOS, runtime.GOARCH
	proof.GODEBUG, proof.BuildIdentity = os.Getenv("GODEBUG"), build.String()
	return &proof
}

// full_only: false
// exclusive: true
func TestOrdinaryOutputMemoryNativeArtifact(t *testing.T) {
	proof := newOrdinaryOutputProof(t)
	// Independently count the loader's page intervals from the retained
	// headers. Zero-VM file data and the inaccessible reservation map no
	// usable bytes; page division includes both partial boundary pages.
	var mapped uint64
	for _, segment := range proof.Segments {
		if segment.Memsz == 0 || segment.Name == "__PAGEZERO" {
			continue
		}
		firstPage := segment.Addr / proof.PageBytes
		lastPage := (segment.Addr + segment.Memsz - 1) / proof.PageBytes
		mapped += (lastPage - firstPage + 1) * proof.PageBytes
	}
	if proof.StaticUpper != mapped {
		t.Fatal("main image bound differs from independent loader page ledger", proof.StaticUpper, mapped, proof.PageBytes, proof.Segments)
	}
	t.Logf("independent mapped main image bytes: %d; page bytes: %d", mapped, proof.PageBytes)
	if proof.EffectiveEfence != 0 || proof.EffectiveSbrk != 0 {
		t.Fatal("ordinary native proof requires normal heap allocator", proof.EffectiveEfence, proof.EffectiveSbrk)
	}
	memory := startOrdinaryOutputAccounting(proof)
	logMaximumOutputPhase(t, "native-artifact-control", memory, nil, nil, nil, nil)
}
