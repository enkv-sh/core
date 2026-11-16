package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type processFixture struct {
	GeneratedSigningMaterial          contract.ID
	GeneratedRecord                   *generatedRecordInput
	GeneratedFinal                    bool
	GeneratedFinalCheckpoint          *generatedFinalCheckpointExpectation `json:",omitempty"`
	GeneratedInitialPermissionRefusal bool
	GeneratedWriter                   *generatedWriterInput
	GeneratedOutputBindings           []contract.NormalOutputBinding   `json:",omitempty"`
	WriterObjects                     map[string]generatedWriterObject `json:",omitempty"`
	Generation                        int
	Domain                            contract.ID
	Trust                             contract.ID
	Objects                           map[string]stored `json:",omitempty"`
	ObjectDirectory                   string            `json:",omitempty"`
	ObjectCount                       int               `json:",omitempty"`
	ObjectFileBytes                   uint64            `json:",omitempty"`
	Descriptor                        contract.Descriptor
	Configuration                     contract.StoreConfiguration
	PublicKey                         []byte
	DomainBasis                       []byte
	CurrentBasis                      *successionBasisInput
	Epoch                             uint64
	ExpectedImage                     stateImage
	ExpectedRecipients                []contract.RecipientRecord `json:",omitempty"`
	ExpectedWork                      []contract.SupportRecord
	ExpectedWorkFacts                 []freshProcessWorkFact
	Consumer                          *successorConsumerInput
	Receipts                          []receiptExpectation
	ExpectedReceiptOrder              []contract.ID `json:",omitempty"`
	PreservationCase                  string        `json:",omitempty"`
}

type freshProcessWorkFact struct {
	Kind       uint8
	RecordID   contract.ID
	BodyLength int
	BodyDigest contract.ID
}

func compactFreshProcessWork(input *processFixture) {
	input.ExpectedWorkFacts = make([]freshProcessWorkFact, len(input.ExpectedWork))
	for i, row := range input.ExpectedWork {
		input.ExpectedWorkFacts[i] = freshProcessWorkFact{row.Kind, row.RecordID, len(row.Body), contract.Hash(row.Body)}
	}
	input.ExpectedWork = nil
}

type generatedRecordInput struct {
	Attempt contract.ID
	Result  []byte
}

type generatedRecordOutput struct {
	BeforeToken       contract.Token
	BeforeHead        []byte
	Objects           map[string]stored
	Generation        int
	WriterWrites      []generatedWriterWrite `json:",omitempty"`
	CheckpointHead    *stored                `json:",omitempty"`
	CheckpointObjects map[string]bool        `json:",omitempty"`
}

type receiptExpectation struct {
	OperationID contract.ID
	Body        []byte
}

const concurrentFreshReceiptQueries = 8

const freshProcessObjectMagic = "ENKVFPO1"

type freshProcessFileStore struct {
	mu            sync.Mutex
	desc          contract.Descriptor
	configuration contract.StoreConfiguration
	directory     string
	bodyFacts     map[string]generatedWriterObject
	reads         int
	readKeys      []string
	creates       int
	cas           int
}

func (s *freshProcessFileStore) Descriptor() contract.Descriptor { return s.desc }
func (s *freshProcessFileStore) StoreConfiguration() contract.StoreConfiguration {
	return s.configuration
}

func (s *freshProcessFileStore) counts() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads, s.creates, s.cas
}

func (s *freshProcessFileStore) keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.readKeys)
}

func freshProcessObjectPath(directory, key string) string {
	digest := sha256.Sum256([]byte(key))
	return filepath.Join(directory, fmt.Sprintf("%x", digest[:]))
}

func readFreshProcessObject(path, key string, maximum uint32) (result contract.ReadResult) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return contract.ReadResult{Status: contract.ReadMissing}
	}
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	defer func() {
		if err := file.Close(); err != nil {
			result = contract.ReadResult{Status: contract.ReadInvalid}
		}
	}()
	var header [28]byte
	if _, err := io.ReadFull(file, header[:]); err != nil || string(header[:8]) != freshProcessObjectMagic {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	keyLength := binary.BigEndian.Uint64(header[8:16])
	tokenLength := binary.BigEndian.Uint32(header[16:20])
	bodyLength := binary.BigEndian.Uint64(header[20:28])
	if keyLength != uint64(len(key)) || keyLength > 1<<20 || tokenLength == 0 || tokenLength > 1<<10 {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	metadata := make([]byte, keyLength+uint64(tokenLength))
	if _, err := io.ReadFull(file, metadata); err != nil || !bytes.Equal(metadata[:keyLength], []byte(key)) {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	token, consumed, err := contract.ParseToken(metadata[keyLength:])
	if err != nil || consumed != int(tokenLength) {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	info, err := file.Stat()
	if err != nil || uint64(info.Size()) != uint64(len(header))+keyLength+uint64(tokenLength)+bodyLength {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	if bodyLength > uint64(maximum) {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	body := make([]byte, bodyLength)
	if _, err := io.ReadFull(file, body); err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid}
	}
	return contract.ReadResult{Status: contract.ReadOK, Body: body, Token: token}
}

func (s *freshProcessFileStore) Read(_ context.Context, key string, maximum uint32) contract.ReadResult {
	s.mu.Lock()
	s.reads++
	s.readKeys = append(s.readKeys, key)
	s.mu.Unlock()
	if s.bodyFacts != nil {
		object, present := s.bodyFacts[key]
		if !present {
			return contract.ReadResult{Status: contract.ReadMissing}
		}
		return readFixtureStoredBody(object.stored(), maximum)
	}
	return readFreshProcessObject(freshProcessObjectPath(s.directory, key), key, maximum)
}

func (s *freshProcessFileStore) Create(_ context.Context, _ string, _ []byte) contract.WriteResult {
	s.mu.Lock()
	s.creates++
	s.mu.Unlock()
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
}

func (s *freshProcessFileStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	s.mu.Lock()
	s.creates++
	s.mu.Unlock()
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
}

func (s *freshProcessFileStore) CompareAndSwap(_ context.Context, _ string, _ contract.Token, _ []byte) contract.WriteResult {
	s.mu.Lock()
	s.cas++
	s.mu.Unlock()
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
}

func writeFreshProcessObject(path, key string, value stored) (uint64, error) {
	read := readFixtureStoredBody(value, ^uint32(0))
	if read.Status != contract.ReadOK {
		return 0, fmt.Errorf("fresh process source body %q: status %v, reason %v", key, read.Status, read.Reason)
	}
	body := read.Body
	token, err := contract.AppendToken(nil, value.Token)
	if err != nil {
		return 0, err
	}
	header := make([]byte, 0, 28)
	header = append(header, freshProcessObjectMagic...)
	header = binary.BigEndian.AppendUint64(header, uint64(len(key)))
	header = binary.BigEndian.AppendUint32(header, uint32(len(token)))
	header = binary.BigEndian.AppendUint64(header, uint64(len(body)))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	write := func(body []byte) error {
		for len(body) != 0 {
			n, err := file.Write(body)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			body = body[n:]
		}
		return nil
	}
	writeErr := write(header)
	if writeErr == nil {
		writeErr = write([]byte(key))
	}
	if writeErr == nil {
		writeErr = write(token)
	}
	if writeErr == nil {
		writeErr = write(body)
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return 0, errors.Join(writeErr, closeErr)
	}
	return uint64(len(header) + len(key) + len(token) + len(body)), nil
}

func persistFreshProcessObjects(t testing.TB, directory string, objects map[string]stored) (int, uint64) {
	t.Helper()
	if len(objects) == 0 {
		t.Fatal("fresh process object snapshot is empty")
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal("fresh process object snapshot directory", err)
	}
	keys := make([]string, 0, len(objects))
	for key := range objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	seen := make(map[string]string, len(keys))
	var total uint64
	for _, key := range keys {
		path := freshProcessObjectPath(directory, key)
		name := filepath.Base(path)
		if other, ok := seen[name]; ok && other != key {
			t.Fatal("fresh process object path collision")
		}
		seen[name] = key
		n, err := writeFreshProcessObject(path, key, objects[key])
		if err != nil {
			t.Fatal("fresh process object snapshot", err)
		}
		total += n
	}
	return len(keys), total
}

func openFreshProcessFileStore(f processFixture) (*freshProcessFileStore, error) {
	if f.ObjectDirectory == "" || f.ObjectCount <= 0 || f.ObjectFileBytes == 0 || len(f.Objects) != 0 || f.GeneratedRecord != nil || f.GeneratedFinal {
		return nil, errors.New("fresh process file Store facts are invalid")
	}
	entries, err := os.ReadDir(f.ObjectDirectory)
	if err != nil || len(entries) != f.ObjectCount {
		return nil, errors.New("fresh process object snapshot count differs")
	}
	var total uint64
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("fresh process object snapshot contains a non-file")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
			return nil, errors.New("fresh process object snapshot file is invalid")
		}
		if uint64(info.Size()) > ^uint64(0)-total {
			return nil, errors.New("fresh process object snapshot byte count overflows")
		}
		total += uint64(info.Size())
	}
	if total != f.ObjectFileBytes {
		return nil, errors.New("fresh process object snapshot byte count differs")
	}
	return &freshProcessFileStore{desc: f.Descriptor, configuration: f.Configuration, directory: f.ObjectDirectory}, nil
}

// full_only: false
func TestFreshProcessFileStorePreservesExactObjectsAndRefusesWrites(t *testing.T) {
	for _, mode := range []string{"memory", "file", "body_facts"} {
		t.Run(mode, func(t *testing.T) {
			descriptor := contract.Descriptor{Family: contract.GCP, HeadKey: "head", Prefix: "objects"}
			original := &memoryStore{desc: descriptor, objects: make(map[string]stored)}
			original.put(descriptor.HeadKey, []byte("head-body"))
			original.put("objects/value", []byte("value-body"))
			if mode == "file" || mode == "body_facts" {
				if err := original.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
					t.Fatal(err)
				}
			}
			objects := original.objects

			var store *freshProcessFileStore
			if mode == "body_facts" {
				facts := make(map[string]generatedWriterObject, len(objects))
				for key, object := range objects {
					facts[key] = generatedWriterObjectFacts(object)
				}
				store = &freshProcessFileStore{desc: descriptor, bodyFacts: facts}
			} else {
				directory := filepath.Join(t.TempDir(), "objects")
				count, size := persistFreshProcessObjects(t, directory, objects)
				var err error
				store, err = openFreshProcessFileStore(processFixture{Descriptor: descriptor, ObjectDirectory: directory, ObjectCount: count, ObjectFileBytes: size})
				if err != nil {
					t.Fatal(err)
				}
			}

			for key, want := range map[string][]byte{descriptor.HeadKey: []byte("head-body"), "objects/value": []byte("value-body")} {
				got := store.Read(context.Background(), key, uint32(len(want)))
				if got.Status != contract.ReadOK || got.Token != objects[key].Token || !bytes.Equal(got.Body, want) {
					t.Fatal("fresh process file Store changed an exact object", key, got.Status)
				}
			}
			if got := store.Read(context.Background(), "objects/value", uint32(len("value-body")-1)); got.Status != contract.ReadInvalid {
				t.Fatal("fresh process file Store ignored the caller read bound", got.Status)
			}
			if got := store.Read(context.Background(), "objects/missing", 1); got.Status != contract.ReadMissing {
				t.Fatal("fresh process file Store invented a missing object", got.Status)
			}
			if result := store.Create(context.Background(), "objects/new", []byte("new")); result.Status != contract.WriteRefused || result.Reason != contract.ReasonConstruction {
				t.Fatal("fresh process file Store allowed Create", result)
			}
			if result := store.CreateHead(context.Background(), contract.HeadCreateRequest{}); result.Status != contract.WriteRefused || result.Reason != contract.ReasonConstruction {
				t.Fatal("fresh process file Store allowed CreateHead", result)
			}
			if result := store.CompareAndSwap(context.Background(), descriptor.HeadKey, objects[descriptor.HeadKey].Token, []byte("changed")); result.Status != contract.WriteRefused || result.Reason != contract.ReasonConstruction {
				t.Fatal("fresh process file Store allowed CompareAndSwap", result)
			}
			reads, creates, cas := store.counts()
			if reads != 4 || creates != 2 || cas != 1 {
				t.Fatal("fresh process file Store call counts differ", reads, creates, cas)
			}
		})
	}
}

// full_only: false
func TestFreshProcessSnapshotRefusesUnreadableSourceBody(t *testing.T) {
	for _, mode := range []string{"missing", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			store := &memoryStore{desc: contract.Descriptor{Family: contract.GCP, HeadKey: "head", Prefix: "objects"}, objects: make(map[string]stored)}
			store.put("objects/value", []byte("value-body"))
			if err := store.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
				t.Fatal(err)
			}
			value := store.objects["objects/value"]
			if mode == "missing" {
				if err := os.Remove(value.bodyPath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(value.bodyPath, []byte("value-bodX"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := writeFreshProcessObject(filepath.Join(t.TempDir(), "snapshot"), "objects/value", value); err == nil {
				t.Fatal("fresh process snapshot accepted an unreadable source body")
			}
		})
	}
}

func selectedProcessFacts(t testing.TB, admitted OpenContext, s *StateSession) processFixture {
	t.Helper()
	a := admitted.admission
	f := processFixture{Domain: a.domain, Trust: a.trust, Descriptor: a.store, Configuration: fixtureStoreConfiguration(s.store),
		PublicKey: bytes.Clone(a.publicKey), DomainBasis: bytes.Clone(a.descriptor), Epoch: a.epoch,
		ExpectedImage: sessionStateImage(t, s), Receipts: freshReceiptExpectations(t, s)}
	var err error
	f.ExpectedWork, err = s.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal("selected process work facts", err)
	}
	if a.current != nil {
		basis := successionBasisTransport(a.current)
		f.CurrentBasis, f.DomainBasis = &basis, nil
	}
	return f
}

func checkFreshGeneratedProcess(t testing.TB, store *memoryStore, s *StateSession) {
	t.Helper()
	input := selectedProcessFacts(t, OpenContext{admission: &s.admission}, s)
	var err error
	input.ExpectedWork, err = s.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if store.fileBodies != nil {
		compactFreshProcessWork(&input)
		input.WriterObjects = make(map[string]generatedWriterObject, len(store.objects))
		for key, object := range store.objects {
			input.WriterObjects[key] = generatedWriterObjectFacts(object)
		}
	} else {
		input.Objects = store.objects
	}
	checkFreshProcessInput(t, input)
}

func memoryCurrentAuthorityKeys(t testing.TB, s *StateSession) *custody.Fixture {
	t.Helper()
	control, ok := s.selectedControl()
	if !ok {
		t.Fatal("current control unavailable")
	}
	bindings, err := s.currentBindings()
	if err != nil {
		t.Fatal(err)
	}
	recovery := contract.ID{}
	if control.Recovery != nil {
		recovery = control.Recovery.RoleID
	}
	authority := contract.BindingTableRow{SubjectKind: 1, SubjectID: control.AuthorityRecipientID, Binding: control.AuthorityKMSBinding}
	return custody.NewCurrentConsumer(t, fixtureID(s.admission.domain, "current phase custody"), control.AuthorityRecipientID, recovery, bindings, authority)
}

func memoryCurrentAuthoritySigner(t testing.TB, s *StateSession) contract.Trust {
	t.Helper()
	control, ok := s.selectedControl()
	if !ok {
		t.Fatal("current signer unavailable")
	}
	return testtrust.NewCurrent(t, control.NormalSigning)
}

func memoryCurrentAuthoritySignerForMaterial(t testing.TB, s *StateSession, material contract.ID) (contract.Trust, error) {
	t.Helper()
	control, ok := s.selectedControl()
	if !ok || material.IsZero() {
		return nil, errors.New("current signing material unavailable")
	}
	binding := control.NormalSigning
	signer := testtrust.NewWithIdentity(t, binding.Provider, material, binding.Binding.Trust, binding.Role)
	if signer.KeySelector() != binding.KeySelector || !bytes.Equal(signer.PublicKey(), binding.SPKI) {
		return nil, errors.New("current signing material differs")
	}
	return signer, nil
}

func freshReceiptExpectations(t testing.TB, session *StateSession) []receiptExpectation {
	t.Helper()
	window, err := session.receiptWindows(t.Context())
	if err != nil {
		t.Fatal("current receipt window unavailable", err)
	}
	var expected []receiptExpectation
	for _, row := range append(window.Successes, window.Failures...) {
		body, err := contract.EncodeCompactMutationReceipt(row)
		if err != nil {
			t.Fatal("current receipt row unavailable", err)
		}
		expected = append(expected, receiptExpectation{OperationID: row.OperationID, Body: body})
	}
	return expected
}

func freshReceiptReadCount(expected []receiptExpectation) uint64 {
	if len(expected) == 0 {
		return 0
	}
	// A complete cold open retains the authenticated decoded receipts. Each
	// retained-result query, the valid copied-session query, and each concurrent
	// query still performs exactly one fresh HEAD read.
	return uint64(len(expected)) + 1 + concurrentFreshReceiptQueries
}

func checkFreshReceipts(t testing.TB, ctx context.Context, session *StateSession, expected []receiptExpectation) {
	t.Helper()
	current := freshReceiptExpectations(t, session)
	if len(expected) != len(current) {
		t.Fatal("fresh receipt expectations omit or add a retained result")
	}
	for i, want := range expected {
		if want.OperationID != current[i].OperationID || !bytes.Equal(want.Body, current[i].Body) {
			t.Fatal("fresh receipt expectation differs from retained result")
		}
		body, result := session.MutationReceipt(ctx, want.OperationID)
		if result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure || result.ObservedRevision != session.head.Core.Revision || result.ObservedSnapshotID != session.head.Core.Root.Object || !bytes.Equal(body, want.Body) {
			t.Fatal("fresh receipt retrieval changed its exact result", result)
		}
	}
	if len(expected) == 0 {
		return
	}
	// Receipt lookup is a selected-state fact for every valid invocation.
	other := *session
	if body, result := other.MutationReceipt(ctx, expected[0].OperationID); result.Outcome != ObservedCurrent || !bytes.Equal(body, expected[0].Body) {
		t.Fatal("receipt lost across a valid invocation", result)
	}
	type receiptResult struct {
		body   []byte
		result Result
	}
	start := make(chan struct{})
	results := make(chan receiptResult, concurrentFreshReceiptQueries)
	for range concurrentFreshReceiptQueries {
		go func() {
			<-start
			body, result := session.MutationReceipt(ctx, expected[0].OperationID)
			results <- receiptResult{body: body, result: result}
		}()
	}
	close(start)
	for range concurrentFreshReceiptQueries {
		got := <-results
		if got.result.Outcome != ObservedCurrent || got.result.Evidence != AuthenticatedClosure ||
			got.result.ObservedRevision != session.head.Core.Revision || got.result.ObservedSnapshotID != session.head.Core.Root.Object ||
			!bytes.Equal(got.body, expected[0].Body) {
			t.Fatal("concurrent fresh receipt retrieval changed its exact result", got.result)
		}
	}
}

func checkFreshProcess(t testing.TB, f *fixture, expected stateImage) {
	t.Helper()
	selected, result := Open(t.Context(), f.admission, f.store)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("fresh fixture selected facts", result)
	}
	assertStateImage(t, selected, expected)
	input := selectedProcessFacts(t, f.admission, selected)
	input.ExpectedImage, input.Objects = expected, f.store.objects
	checkFreshProcessInput(t, input)
}

func checkFreshProcessInput(t testing.TB, input processFixture) *generatedRecordOutput {
	t.Helper()
	return checkFreshProcessInputContext(t.Context(), t, input)
}

func checkFreshProcessInputContext(parent context.Context, t testing.TB, input processFixture) *generatedRecordOutput {
	t.Helper()
	if parent == nil || parent.Err() != nil {
		t.Fatal("fresh process cumulative context expired")
	}
	directory := t.TempDir()
	if input.GeneratedRecord == nil && !input.GeneratedFinal && input.GeneratedWriter == nil && len(input.WriterObjects) == 0 {
		input.ObjectDirectory = filepath.Join(directory, "objects")
		input.ObjectCount, input.ObjectFileBytes = persistFreshProcessObjects(t, input.ObjectDirectory, input.Objects)
		input.Objects = nil
		t.Logf("fresh process object snapshot: objects=%d bytes=%d", input.ObjectCount, input.ObjectFileBytes)
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "fixture.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	phaseBound := time.Minute
	if input.ExpectedImage.Root.Generated.GeneratedCurrent > 4 && len(input.WriterObjects) != 0 {
		phaseBound = maximumCapacityAdmissionLifetime
	}
	if input.GeneratedWriter != nil && (len(input.GeneratedWriter.Names) > 2 || input.ExpectedImage.Root.Generated.GeneratedCurrent > 4) {
		// Maximum writer construction has three finite 30-minute phase groups:
		// reservation/originals, ordered records, and complete final selection.
		phaseBound = 90 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, phaseBound)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.v", "-test.run=^TestFreshProcessChild$")
	cmd.Env = append(os.Environ(), "ENKV_PROCESS_FIXTURE="+path)
	started := time.Now()
	if err := runFreshProcess(cmd); err != nil {
		t.Fatalf("fresh process failed: elapsed=%s fixture_bytes=%d object_count=%d object_file_bytes=%d context_error=%v: %v",
			time.Since(started), len(data), input.ObjectCount, input.ObjectFileBytes, ctx.Err(), err)
	}
	if input.GeneratedRecord == nil && !input.GeneratedFinal && input.GeneratedWriter == nil {
		return nil
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(path), "generated-selection.json"))
	if err != nil {
		t.Fatal("fresh generated record output unavailable", err)
	}
	var output generatedRecordOutput
	if err := json.Unmarshal(body, &output); err != nil {
		t.Fatal("fresh generated record output invalid", err)
	}
	if len(output.WriterWrites) == 0 {
		// A qualified replay can reuse every already persisted immutable
		// artifact. Its only new write is the selected HEAD, which remains
		// mandatory even when the immutable difference is empty.
		head, present := output.Objects[input.Descriptor.HeadKey]
		if !present || len(head.Body) == 0 || !head.Token.Valid() {
			t.Fatal("fresh generated record output omitted its exact selected HEAD")
		}
	}
	return &output
}

func runFreshProcess(cmd *exec.Cmd) error {
	var output freshProcessOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		body := output.buffer.Bytes()
		if len(body) > 8192 {
			body = body[len(body)-8192:]
		}
		return fmt.Errorf("fresh process: %w\n%s", err, body)
	}
	return output.completedChild()
}

type freshProcessOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (output *freshProcessOutput) Write(body []byte) (int, error) {
	n := len(body)
	remaining := (32 << 20) - output.buffer.Len()
	if n > remaining {
		body = body[:remaining]
		output.overflow = true
	}
	_, _ = output.buffer.Write(body)
	return n, nil
}

func (output *freshProcessOutput) completedChild() error {
	if output.overflow {
		return errors.New("fresh process output exceeds its bound")
	}
	positive := regexp.MustCompile(`^--- PASS: TestFreshProcessChild \([0-9]+\.[0-9]+s\)$`)
	started, passed, finished := false, false, false
	scanner := bufio.NewScanner(bytes.NewReader(output.buffer.Bytes()))
	scanner.Buffer(make([]byte, 4096), 32<<20)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "=== RUN   TestFreshProcessChild":
			if started {
				return errors.New("fresh process child started more than once")
			}
			started = true
		case positive.MatchString(line):
			if !started || passed || finished {
				return errors.New("fresh process child completion is out of order")
			}
			passed = true
		case strings.HasPrefix(line, "--- SKIP: TestFreshProcessChild "), strings.HasPrefix(line, "--- FAIL: TestFreshProcessChild "):
			return errors.New("fresh process child did not pass")
		case line == "PASS":
			if !passed || finished {
				return errors.New("fresh process completion is out of order")
			}
			finished = true
		}
	}
	if scanner.Err() != nil || !finished {
		return errors.New("fresh process child completion evidence is missing")
	}
	return nil
}

// full_only: false
func TestFreshProcessRequiresCompletedChild(t *testing.T) {
	if os.Getenv("ENKV_FRESH_OUTPUT_TEST") == "overflow" {
		if _, err := io.CopyN(os.Stdout, strings.NewReader(strings.Repeat("x", (32<<20)+1)), (32<<20)+1); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Setenv("ENKV_PROCESS_FIXTURE", "")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, selection, output string }{
		{"skipped-child", "^TestFreshProcessChild$", ""},
		{"missing-child", "^TestAbsentFreshProcessChild$", ""},
		{"output-limit", "^TestFreshProcessRequiresCompletedChild$", "overflow"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, exe, "-test.v", "-test.run="+test.selection)
			command.Env = append(os.Environ(), "ENKV_FRESH_OUTPUT_TEST="+test.output)
			err := runFreshProcess(command)
			if err == nil {
				t.Fatal("fresh child passed without complete bounded positive evidence")
			}
			if test.output != "" && err.Error() != "fresh process output exceeds its bound" {
				t.Fatalf("child output overflow was not recorded: %v", err)
			}
		})
	}
}

// full_only: false
func TestFreshProcessCompletionRequiresExactPositiveEvidence(t *testing.T) {
	const start = "=== RUN   TestFreshProcessChild\n"
	const pass = "--- PASS: TestFreshProcessChild (0.00s)\n"
	for _, test := range []struct {
		name, body string
		accepted   bool
	}{
		{"passed-child", start + pass + "PASS\n", true},
		{"skip-despite-pass", start + "--- SKIP: TestFreshProcessChild (0.00s)\n" + pass + "PASS\n", false},
		{"fail-despite-pass", start + "--- FAIL: TestFreshProcessChild (0.00s)\n" + pass + "PASS\n", false},
		{"missing-child-pass", start + "PASS\n", false},
		{"missing-run", pass + "PASS\n", false},
		{"missing-process-pass", start + pass, false},
		{"wrong-child", start + "--- PASS: TestFreshProcessChildExtra (0.00s)\nPASS\n", false},
		{"logged-pass", start + "    " + pass + "PASS\n", false},
		{"truncated-pass", start + "--- PASS: TestFreshProcessChild (0.", false},
		{"duplicate-start", start + start + pass + "PASS\n", false},
		{"duplicate-pass", start + pass + pass + "PASS\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output freshProcessOutput
			if _, err := output.Write([]byte(test.body)); err != nil {
				t.Fatal(err)
			}
			if err := output.completedChild(); (err == nil) != test.accepted {
				t.Fatalf("child evidence result: %v", err)
			}
		})
	}
}

func assertFreshSelectedClosureReads(t testing.TB, descriptor contract.Descriptor, expected stateImage, selected *StateSession, reads int, keys []string) {
	t.Helper()
	if len(keys) != reads {
		t.Fatal("fresh process lost a Store read key")
	}
	expectedKeys := map[string]bool{descriptor.HeadKey: true}
	add := func(ref format.Ref) {
		key := mustKey(t, descriptor.Prefix, ref)
		if expectedKeys[key] {
			t.Fatal("fresh fixture repeats a selected object", key)
		}
		expectedKeys[key] = true
	}
	add(expected.RootRef)
	add(expected.Root.AdministrativeIndex)
	for _, ref := range expected.Root.AdministrativeIndexShards {
		add(ref)
	}
	for _, table := range [][]*format.Ref{expected.Root.ValueEntryPages[:], expected.Root.Recipients[:]} {
		for _, ref := range table {
			if ref != nil {
				add(*ref)
			}
		}
	}
	for _, ref := range expected.Root.CurrentAccess.Core.AccessPageRefs {
		add(ref)
	}
	allowedDuplicates := make(map[string]bool)
	configurationReads := make(map[string]int)
	for position, ref := range expected.Root.RequiredSupport {
		add(ref)
		for _, row := range selected.support[position].Records {
			if row.Kind == contract.OutputConfigurationSliceSupportKind {
				key := mustKey(t, descriptor.Prefix, ref)
				configurationReads[key]++
				allowedDuplicates[key] = true
			}
		}
		for _, fact := range selected.fragmentFacts {
			if fact.ref == ref {
				allowedDuplicates[mustKey(t, descriptor.Prefix, ref)] = true
				break
			}
		}
	}
	seenKeys := make(map[string]int)
	for _, key := range keys {
		if !expectedKeys[key] {
			t.Fatal("fresh Open read an unselected object", key)
		}
		seenKeys[key]++
		if seenKeys[key] > 1 && !allowedDuplicates[key] {
			t.Fatal("fresh Open reread an unrelated selected object", key)
		}
	}
	for key, slices := range configurationReads {
		if seenKeys[key] != 1+slices {
			t.Fatal("fresh Open configuration reads differ from initial page plus exact slice borrows", key, seenKeys[key], 1+slices)
		}
	}
	if len(expectedKeys) != int(expected.Root.ChildCount)+2 || len(seenKeys) != len(expectedKeys) {
		t.Fatalf("fresh Open omitted a selected object: unique=%d expected=%d child_count=%d", len(seenKeys), len(expectedKeys), expected.Root.ChildCount)
	}
}

// full_only: false
func TestFreshProcessChild(t *testing.T) {
	path := os.Getenv("ENKV_PROCESS_FIXTURE")
	if path == "" {
		t.Skip("fresh process entry requires a parent fixture")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f processFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	var store contract.Store
	var memory *memoryStore
	var counts func() (int, int, int)
	var readKeys func() []string
	if f.ObjectDirectory != "" {
		fileStore, err := openFreshProcessFileStore(f)
		if err != nil {
			t.Fatal(err)
		}
		store = fileStore
		counts = fileStore.counts
		readKeys = fileStore.keys
	} else if len(f.WriterObjects) != 0 && f.GeneratedWriter == nil {
		if len(f.Objects) != 0 || f.GeneratedRecord != nil || f.GeneratedFinal {
			t.Fatal("read-only body facts mixed with mutation transport")
		}
		fileStore := &freshProcessFileStore{desc: f.Descriptor, configuration: f.Configuration, bodyFacts: f.WriterObjects}
		store = fileStore
		counts = fileStore.counts
		readKeys = fileStore.keys
	} else {
		if len(f.WriterObjects) != 0 {
			if len(f.Objects) != 0 {
				t.Fatal("writer child object transport differs")
			}
			f.Objects = make(map[string]stored, len(f.WriterObjects))
			for key, object := range f.WriterObjects {
				f.Objects[key] = object.stored()
			}
		}
		memory = &memoryStore{desc: f.Descriptor, configuration: f.Configuration, objects: f.Objects, generation: f.Generation}
		store = memory
		counts = func() (int, int, int) {
			memory.mu.Lock()
			defer memory.mu.Unlock()
			return memory.reads, memory.creates, memory.cas
		}
		var keys []string
		memory.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
			keys = append(keys, key)
			return result
		}
		readKeys = func() []string {
			memory.mu.Lock()
			defer memory.mu.Unlock()
			return slices.Clone(keys)
		}
	}
	admission := processPublicAdmission(f.Domain, f.Trust, f.Descriptor, f.PublicKey, f.DomainBasis)
	if f.CurrentBasis != nil {
		// Only the parent's explicit private fixture transport can supply a
		// qualified current basis. Stored HEAD bytes cannot create admission.
		admission.admission.current = f.CurrentBasis.owned()
		admission.admission.epoch = f.Epoch
	}
	s, r := Open(context.Background(), admission, store)
	if s == nil || r.Outcome != ObservedCurrent || r.ObservedRevision != f.ExpectedImage.Revision {
		t.Fatalf("fresh process observation: %+v", r)
	}
	openReads, _, _ := counts()
	openKeys := readKeys()
	assertFreshSelectedClosureReads(t, f.Descriptor, f.ExpectedImage, s, openReads, openKeys)
	assertStateImage(t, s, f.ExpectedImage)
	if f.ExpectedRecipients != nil && !reflect.DeepEqual(s.registry(), f.ExpectedRecipients) {
		t.Fatal("fresh process complete independently expected registry differs")
	}

	work, err := s.workSupportRecords(t.Context())
	expectedCount := len(f.ExpectedWork)
	if len(f.ExpectedWorkFacts) != 0 {
		expectedCount = len(f.ExpectedWorkFacts)
	}
	if err != nil || len(work) != expectedCount {
		t.Fatal("fresh work expectation differs", err)
	}
	for i, row := range work {
		if len(f.ExpectedWorkFacts) != 0 {
			want := f.ExpectedWorkFacts[i]
			if row.Kind != want.Kind || row.RecordID != want.RecordID || len(row.Body) != want.BodyLength || contract.Hash(row.Body) != want.BodyDigest {
				t.Fatal("fresh process changed selected work facts")
			}
		} else {
			want := f.ExpectedWork[i]
			if row.Kind != want.Kind || row.RecordID != want.RecordID || !bytes.Equal(row.Body, want.Body) {
				t.Fatal("fresh process changed selected work")
			}
		}
	}

	reads, creates, cas := counts()
	if creates != 0 || cas != 0 || reads != openReads {
		t.Fatalf("restart resumed prepared work: open_reads=%d reads=%d child_count=%d creates=%d cas=%d", openReads, reads, s.root.ChildCount, creates, cas)
	}
	receiptStartReads := openReads
	if f.PreservationCase != "" {
		assertPreservationSemantics(t, s, f.PreservationCase)
		receiptStartReads, creates, cas = counts()
		if creates != 0 || cas != 0 {
			t.Fatal("preserved semantic replay wrote selected state")
		}
	}
	if f.ExpectedReceiptOrder != nil {
		windows, err := s.receiptWindows(t.Context())
		if err != nil || !slices.Equal(windows.Order, f.ExpectedReceiptOrder) {
			t.Fatal("fresh process common receipt order changed", err)
		}
	}
	if f.Consumer != nil {
		checkSuccessorConsumer(t, s, *f.Consumer)
	}
	// Receipt queries reuse only the already authenticated decoded selection.
	// They must not need the raw immutable-object cache after a complete cold
	// open, while every query still performs its own fresh HEAD read.
	s.cache = make(map[format.Ref][]byte)
	checkFreshReceipts(t, context.Background(), s, f.Receipts)
	reads, creates, cas = counts()
	if creates != 0 || cas != 0 || uint64(reads) != uint64(receiptStartReads)+freshReceiptReadCount(f.Receipts) {
		t.Fatal("fresh receipt queries did not use only their exact current reads")
	}
	keys := readKeys()
	if len(keys) != reads {
		t.Fatal("fresh receipt queries lost a Store read key")
	}
	for _, key := range keys[receiptStartReads:] {
		if key != f.Descriptor.HeadKey {
			t.Fatal("fresh receipt query read an unrelated object", key)
		}
	}
	if f.GeneratedInitialPermissionRefusal {
		assertFreshGeneratedInitialPermissionRefused(t, s)
		_, creates, cas := counts()
		if creates != 0 || cas != 0 {
			t.Fatal("cold initial permission refusal wrote selected state")
		}
	}
	if f.GeneratedRecord != nil || f.GeneratedFinal || f.GeneratedWriter != nil {
		if f.GeneratedRecord != nil && f.GeneratedFinal || f.GeneratedWriter != nil && (f.GeneratedRecord != nil || f.GeneratedFinal) {
			t.Fatal("fresh process cannot combine record and final authority")
		}
		if memory == nil {
			t.Fatal("fresh generated writer received a read-only file Store")
		}
		installFreshGeneratedOutputSources(t, s, f.GeneratedOutputBindings)
		var output generatedRecordOutput
		if f.GeneratedWriter != nil {
			output = generatedWriterInFreshProcess(t, s, memory, *f.GeneratedWriter)
		} else if f.GeneratedRecord != nil {
			output = recordGeneratedInFreshProcess(t, context.Background(), s, memory, *f.GeneratedRecord, f.Receipts, f.GeneratedSigningMaterial)
		} else {
			output = finalGeneratedInFreshProcess(t, context.Background(), s, memory, f.Receipts, f.GeneratedFinalCheckpoint)
		}
		body, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), "generated-selection.json"), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Only generated writer children receive the parent's passive derivation facts.
// The existing generated normalizer validates each actual selected destination
// against this exact source table, including declarations with zero targets.
// Selected state and support remain checked by the independent process image.
func installFreshGeneratedOutputSources(t testing.TB, s *StateSession, bindings []contract.NormalOutputBinding) {
	t.Helper()
	if len(bindings) != int(s.root.OutputConfiguration.BindingCount) {
		t.Fatal("fresh generated output source count differs")
	}
	input := &outputApplyInput{}
	seen := make(map[string]bool, len(bindings))
	for _, binding := range bindings {
		if seen[binding.DestinationID] {
			t.Fatal("fresh generated output source repeats a destination")
		}
		seen[binding.DestinationID] = true
		row := outputApplyBinding{destinationID: binding.DestinationID, destination: binding.Destination}
		names := make(map[string]bool, len(binding.Targets))
		for _, named := range binding.Targets {
			if names[named.Name] {
				t.Fatal("fresh generated output source repeats an entry")
			}
			names[named.Name] = true
			for _, previous := range input.bindings {
				if !reflect.DeepEqual(previous.destination, row.destination) {
					continue
				}
				for _, offered := range previous.targets {
					if offered.entryName == named.Name && !outputApplyTargetsEqual(offered.target, named.Target) {
						t.Fatal("fresh generated output sources conflict for one entry")
					}
				}
			}
			row.targets = append(row.targets, outputApplyTarget{entryName: named.Name, target: named.Target})
		}
		input.bindings = append(input.bindings, row)
	}
	if !outputApplyInputAxes(input) || !outputApplySourceBounded(input) {
		t.Fatal("fresh generated output source facts exceed their bounds")
	}
	installOutputFixtureSource(t, s, input)
}

func recordGeneratedInFreshProcess(t testing.TB, ctx context.Context, s *StateSession, store *memoryStore, input generatedRecordInput, receipts []receiptExpectation, materials ...contract.ID) generatedRecordOutput {
	t.Helper()
	var material contract.ID
	if len(materials) > 1 {
		t.Fatal("fresh record signing owner is ambiguous")
	}
	if len(materials) == 1 {
		material = materials[0]
	}
	before := make(map[string]stored, len(store.objects))
	for key, object := range store.objects {
		before[key] = object
	}
	keys := memoryCurrentAuthorityKeys(t, s)
	var signer contract.Trust
	if material.IsZero() {
		signer = memoryCurrentAuthoritySigner(t, s)
	} else {
		var err error
		signer, err = memoryCurrentAuthoritySignerForMaterial(t, s, material)
		if err != nil {
			t.Fatal("fresh record signing material differs from current resource")
		}
	}
	env := fixtureEnvironment{Store: store, Trust: signer, Custody: keys}
	admitted := generatedPlanInputFixture(t, s).context
	admitted.AdmissionID, admitted.SessionID = testID("fresh generated record admission"), testID("fresh generated record session")
	plan, err := s.generatedRecordRequest(context.Background(), input.Attempt, input.Result, admitted)
	if err != nil {
		t.Fatal("fresh generated record request", err)
	}
	p := preparePrivateGeneratedRecord(t, env, s, plan)
	writes := map[string]bool{store.desc.HeadKey: true}
	createCalls := len(p.reservation.candidate.objects) + len(p.resultWrites)
	for _, object := range p.reservation.candidate.objects {
		key, err := format.Key(store.desc.Prefix, object.ref)
		if err != nil {
			t.Fatal(err)
		}
		writes[key] = true
	}
	for _, result := range p.resultWrites {
		key, _, err := s.generatedResultCoordinate(t.Context(), result.attempt)
		if err != nil {
			t.Fatal("fresh result has no original inbox coordinate", err)
		}
		writes[key] = true
	}
	selected, result := s.selectCandidate(ctx, p.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || store.cas != 1 || store.creates != createCalls {
		t.Fatal("fresh generated record selection", result)
	}
	if reply, _, code := keys.InvokeGeneratedProducer(ctx, plan.request.Context.AdmissionID, contract.ID{}, contract.ID{}); code == contract.CryptoSuccess || len(reply) != 0 {
		t.Fatal("record admission acquired producer permission")
	}
	keys.RetireGenerated()
	cold, result := Open(ctx, OpenContext{admission: &s.admission}, store)
	if cold == nil || result.Outcome != ObservedCurrent || cold.head.Core != selected.head.Core {
		t.Fatal("fresh record lost its selected proof", result)
	}
	g, err := cold.selectedGeneratedWork(context.Background())
	if err != nil || !bytes.Equal(g.attempts[input.Attempt].result, input.Result) {
		t.Fatal("fresh record changed the original encrypted return", err)
	}
	checkFreshReceipts(t, ctx, cold, receipts)
	return generatedSelectionWrites(t, s, store, before, writes)
}

func finalGeneratedInFreshProcess(t testing.TB, ctx context.Context, s *StateSession, store *memoryStore, receipts []receiptExpectation, expectations ...*generatedFinalCheckpointExpectation) generatedRecordOutput {
	t.Helper()
	if len(expectations) > 1 {
		t.Fatal("fresh Final received more than one checkpoint expectation")
	}
	var expectation *generatedFinalCheckpointExpectation
	if len(expectations) == 1 {
		expectation = expectations[0]
	}
	if expectation != nil {
		assertFreshFinalCheckpointBefore(t, s, expectation)
	}
	before := make(map[string]stored, len(store.objects))
	for key, object := range store.objects {
		before[key] = object
	}
	keys := memoryCurrentAuthorityKeys(t, s)
	env := fixtureEnvironment{Store: s.store, Trust: memoryCurrentAuthoritySigner(t, s), Custody: keys}
	admitted := generatedPlanInputFixture(t, s).context
	admitted.AdmissionID, admitted.SessionID = testID("fresh generated final admission"), testID("fresh generated final session")
	plan, err := s.generatedFinalRequest(t.Context(), admitted)
	if err != nil {
		t.Fatal("fresh generated final request", err)
	}
	beforeBase := s
	wantCheckpoint := plan.selecting && plan.materialization == nil
	writes := map[string]bool{store.desc.HeadKey: true}
	expectedObjects := make(map[string][]byte)
	checkpointObjects, finalObjects := make(map[string][]byte), make(map[string][]byte)
	createCalls, casCalls, checkpointCalls := 0, 1, 0
	if wantCheckpoint {
		casCalls = 2
	}
	collectObjects := func(candidate *Candidate, phaseObjects map[string][]byte) {
		createCalls += len(candidate.objects)
		for _, object := range candidate.objects {
			key, err := format.Key(store.desc.Prefix, object.ref)
			if err != nil || format.CheckReference(object.ref, object.body) != nil {
				t.Fatal("fresh Final planned object reference", err)
			}
			if _, duplicate := phaseObjects[key]; duplicate {
				t.Fatal("fresh Final phase planned a duplicate immutable object")
			}
			phaseObjects[key] = bytes.Clone(object.body)
			if previous, present := expectedObjects[key]; present && !bytes.Equal(previous, object.body) {
				t.Fatal("checkpoint and actual Final planned an immutable overwrite")
			}
			expectedObjects[key] = bytes.Clone(object.body)
			writes[key] = true
		}
	}
	collectCheckpoint := func(candidate *Candidate) {
		checkpointCalls++
		if !wantCheckpoint || checkpointCalls != 1 {
			t.Fatal("fresh Final prepared an unexpected or repeated checkpoint")
		}
		if expectation != nil {
			assertFreshFinalCheckpointReplacement(t, candidate, expectation)
		}
		collectObjects(candidate, checkpointObjects)
	}
	s, p := preparePrivateGeneratedFinalWithCheckpoint(t, env, s, plan, collectCheckpoint)
	if wantCheckpoint != (checkpointCalls == 1) {
		t.Fatal("fresh Final omitted its required preparation checkpoint")
	}
	collectObjects(p.reservation.candidate, finalObjects)
	if expectation != nil && len(expectation.Artifacts) != 0 {
		if len(finalObjects) != len(expectation.Artifacts) {
			t.Fatal("fresh Final changed the exact replay artifact set")
		}
		for key, expected := range expectation.Artifacts {
			if actual, present := finalObjects[key]; !present || !bytes.Equal(actual, expected) {
				t.Fatal("fresh Final changed a replay artifact identity or its exact bytes", key)
			}
		}
	}
	for key, expected := range expectedObjects {
		object, present := store.objects[key]
		read := readFixtureStoredBody(object, uint32(len(expected)))
		if !present || read.Status != contract.ReadOK || !bytes.Equal(read.Body, expected) {
			t.Fatal("fresh Final did not write the exact checkpoint/final object bytes", key)
		}
	}
	selected, result := s.selectCandidate(ctx, p.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || !selected.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("fresh generated final selection", result)
	}
	if store.cas != casCalls || store.creates != createCalls {
		t.Fatal("fresh generated final write count", store.cas, casCalls, store.creates, createCalls)
	}
	head := readFixtureStoredBody(store.objects[store.desc.HeadKey], uint32(len(p.reservation.candidate.body)))
	if head.Status != contract.ReadOK || !bytes.Equal(head.Body, p.reservation.candidate.body) {
		t.Fatal("fresh Final did not write its exact final HEAD")
	}
	keys.RetireGenerated()
	cold, result := Open(ctx, OpenContext{admission: &s.admission}, s.store)
	if cold == nil || result.Outcome != ObservedCurrent || cold.head.Core != selected.head.Core {
		t.Fatal("fresh final lost its selected proof", result)
	}
	if _, err := cold.selectedGeneratedWork(context.Background()); err != nil {
		t.Fatal("fresh final lost its authenticated work", err)
	}
	// Final selection may add a terminal receipt. Every original retained
	// receipt must still return its exact bytes under the original identity.
	for _, receipt := range receipts {
		body, result := cold.MutationReceipt(ctx, receipt.OperationID)
		if result.Outcome != ObservedCurrent || !bytes.Equal(body, receipt.Body) {
			t.Fatal("fresh final changed a retained receipt", result)
		}
	}
	output := generatedSelectionWrites(t, beforeBase, store, before, writes)
	if wantCheckpoint {
		output.CheckpointHead = &stored{Body: bytes.Clone(s.body), Token: s.token}
		output.CheckpointObjects = make(map[string]bool)
		for key := range checkpointObjects {
			if _, written := output.Objects[key]; written {
				output.CheckpointObjects[key] = true
			}
		}
	}
	return output
}

func generatedSelectionWrites(t testing.TB, s *StateSession, store *memoryStore, before map[string]stored, writes map[string]bool) generatedRecordOutput {
	t.Helper()
	output := generatedRecordOutput{BeforeToken: s.token, BeforeHead: bytes.Clone(s.body), Objects: make(map[string]stored), Generation: store.generation}
	for key, object := range store.objects {
		old, exists := before[key]
		if !exists || old.Token != object.Token || !bytes.Equal(old.Body, object.Body) {
			if !writes[key] || exists && key != store.desc.HeadKey {
				t.Fatal("fresh record made an unplanned write or immutable overwrite")
			}
			output.Objects[key] = object
		}
		delete(writes, key)
	}
	if len(writes) != 0 {
		t.Fatal("fresh record omitted a planned object")
	}
	return output
}

func selectedGeneratedProcessFacts(t testing.TB, s *StateSession) processFixture {
	t.Helper()
	input := selectedProcessFacts(t, OpenContext{admission: &s.admission}, s)
	private, _, _ := selectedGeneratedCommonPrivateFacts(t.Context(), t, s, mustSelectedGeneratedWork(t, s))
	input.GeneratedOutputBindings = private.Output.Bindings
	return input
}

func selectFreshGeneratedRecord(t testing.TB, store *memoryStore, s *StateSession, attempt contract.ID, result []byte, material ...contract.ID) *StateSession {
	t.Helper()
	if len(material) > 1 {
		t.Fatal("fresh record signing owner is ambiguous")
	}
	input := selectedGeneratedProcessFacts(t, s)
	var err error
	input.ExpectedWork, err = s.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal("fresh generated continuation input", err)
	}
	input.Objects, input.Generation = store.objects, store.generation
	input.GeneratedRecord = &generatedRecordInput{Attempt: attempt, Result: result}
	if len(material) == 1 {
		if _, err := memoryCurrentAuthoritySignerForMaterial(t, s, material[0]); err != nil {
			t.Fatal("parent current signing resource differs")
		}
		input.GeneratedSigningMaterial = material[0]
	}
	output := checkFreshProcessInput(t, input)
	return importFreshGeneratedSelection(t, s, input.Generation, output)
}

func selectFreshGeneratedFinal(t testing.TB, store *memoryStore, s *StateSession) *StateSession {
	t.Helper()
	input := selectedGeneratedProcessFacts(t, s)
	var err error
	input.ExpectedWork, err = s.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal("fresh generated final input", err)
	}
	input.Objects, input.Generation, input.GeneratedFinal = store.objects, store.generation, true
	return importFreshGeneratedSelection(t, s, input.Generation, checkFreshProcessInput(t, input))
}

func importFreshGeneratedSelection(t testing.TB, s *StateSession, generation int, output *generatedRecordOutput) *StateSession {
	t.Helper()
	if output == nil {
		t.Fatal("fresh generated continuation omitted its result")
	}
	if len(output.WriterWrites) != 0 {
		if output.CheckpointHead != nil || len(output.CheckpointObjects) != 0 {
			t.Fatal("fresh writer mixed independent checkpoint selection metadata")
		}
		return importFreshGeneratedWriterWrites(t, s, generation, output)
	}
	ctx := context.Background()
	headKey := s.admission.store.HeadKey
	checkpointSelections := 0
	if output.CheckpointHead != nil {
		checkpointSelections = 1
		checkpoint, err := format.DecodeHead(output.CheckpointHead.Body)
		if err != nil || checkpoint.Generator == nil || checkpoint.Generator.Purpose != contract.GeneratorAuthorityFinalPreparation ||
			checkpoint.Core.Domain != s.root.Domain || checkpoint.Core.PreviousToken != output.BeforeToken ||
			!output.CheckpointHead.Token.Valid() || len(output.CheckpointObjects) == 0 {
			t.Fatal("fresh Final omitted exact checkpoint selection evidence", err)
		}
	} else if len(output.CheckpointObjects) != 0 {
		t.Fatal("fresh Final supplied checkpoint objects without its selected HEAD")
	}
	current := s.store.Read(ctx, headKey, uint32(len(output.BeforeHead)))
	if current.Status != contract.ReadOK || current.Token != output.BeforeToken ||
		output.BeforeToken != s.token || !bytes.Equal(current.Body, output.BeforeHead) ||
		!bytes.Equal(output.BeforeHead, s.body) || output.Generation != generation+len(output.Objects)+checkpointSelections {
		t.Fatal("parent changed while the fresh process owned selection")
	}
	head, ok := output.Objects[headKey]
	if !ok || len(head.Body) == 0 {
		t.Fatal("fresh generated continuation omitted its selected HEAD")
	}
	keys := make([]string, 0, len(output.Objects)-1)
	for key, object := range output.Objects {
		if key == headKey {
			continue
		}
		if found := s.store.Read(ctx, key, uint32(len(object.Body))); found.Status != contract.ReadMissing {
			t.Fatal("fresh generated continuation imports an immutable overwrite")
		}
		keys = append(keys, key)
	}
	for key, selected := range output.CheckpointObjects {
		if _, present := output.Objects[key]; !selected || !present || key == headKey {
			t.Fatal("fresh Final checkpoint object set differs from its complete immutable union")
		}
	}
	sort.Strings(keys)
	// Replay both exact write sets through the admitted Store. The checkpoint
	// CAS precedes actual Final objects so its opaque token keeps the child's
	// exact generation; the final CAS then uses that selected checkpoint token.
	importObject := func(key string) {
		object := output.Objects[key]
		s.store.Create(ctx, key, bytes.Clone(object.Body))
		read := s.store.Read(ctx, key, uint32(len(object.Body)))
		if read.Status != contract.ReadOK || !bytes.Equal(read.Body, object.Body) {
			t.Fatal("fresh generated continuation immutable import failed")
		}
	}
	condition := output.BeforeToken
	if output.CheckpointHead != nil {
		for _, key := range keys {
			if output.CheckpointObjects[key] {
				importObject(key)
			}
		}
		checkpoint := output.CheckpointHead
		s.store.CompareAndSwap(ctx, headKey, condition, bytes.Clone(checkpoint.Body))
		read := s.store.Read(ctx, headKey, uint32(len(checkpoint.Body)))
		if read.Status != contract.ReadOK || read.Token != checkpoint.Token || !bytes.Equal(read.Body, checkpoint.Body) {
			t.Fatal("fresh Final checkpoint import changed exact HEAD bytes or generation")
		}
		opened, observed := Open(ctx, OpenContext{admission: &s.admission}, s.store)
		if opened == nil || observed.Outcome != ObservedCurrent || opened.token != checkpoint.Token || !bytes.Equal(opened.body, checkpoint.Body) {
			t.Fatal("fresh Final checkpoint import did not authenticate", observed)
		}
		condition = checkpoint.Token
	}
	for _, key := range keys {
		if !output.CheckpointObjects[key] {
			importObject(key)
		}
	}
	s.store.CompareAndSwap(ctx, headKey, condition, bytes.Clone(head.Body))
	read := s.store.Read(ctx, headKey, uint32(len(head.Body)))
	if read.Status != contract.ReadOK || read.Token != head.Token || !bytes.Equal(read.Body, head.Body) {
		t.Fatal("fresh generated continuation lost its original HEAD condition")
	}
	selected, outcome := Open(ctx, OpenContext{admission: &s.admission}, s.store)
	if selected == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("fresh generated continuation import", outcome)
	}
	return selected
}

// full_only: false
func TestFreshGeneratedRecordUsesTheBoundStore(t *testing.T) {
	for _, family := range []contract.Family{contract.GCP, contract.AWS} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("family%d/recovery%t", family, recovery), func(t *testing.T) {
				testFreshGeneratedSelectionsUseTheBoundStore(t, family, recovery)
			})
		}
	}
}

func testFreshGeneratedSelectionsUseTheBoundStore(t *testing.T, family contract.Family, recovery bool) {
	t.Helper()
	ctx := context.Background()
	env, keys := genesisEnvironment(t, family, recovery)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	reservation, _ := preparePrivateGeneratedReservation(t, env, f.session, generatedPlanInputFixture(t, f.session), nil)
	producer, expected := preparePrivateGeneratedProducer(t, env, f.session, reservation, nil)
	var returned []byte
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		returned, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("bound Store first-send handoff")
	}
	selected, result := f.session.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || len(returned) == 0 {
		t.Fatal("bound Store effect selection", result)
	}
	keys.RetireGenerated()
	spy := &scenarioSpy{}
	selected.store = scenarioStore{Store: env.Store, spy: spy}
	recorded := env.FreshGeneratedRecord(t, selected, expected.Template.AttemptID, returned)
	if spy.StoreCreate == 0 || spy.StoreCAS != 1 || recorded.store != selected.store {
		t.Fatal("fresh generated import bypassed its bound Store", spy.scenarioEffects)
	}
	work, err := recorded.selectedGeneratedWork(ctx)
	if err != nil || work == nil || work.preparation != nil || recorded.root.ValueEntryCount != 0 || recorded.root.Generated.GeneratedCurrent != 0 {
		t.Fatal("fresh selecting Final fixture already has a prepared image or current value", err)
	}
	spy.scenarioEffects = scenarioEffects{}
	closed := env.FreshGeneratedFinal(t, recorded)
	// This first selecting Final must select its preparation checkpoint before Final.
	if spy.StoreCreate == 0 || spy.StoreCAS != 2 || closed.store != recorded.store ||
		!closed.root.Generated.ActiveOwner.IsZero() || closed.root.ValueEntryCount != 1 || closed.root.Generated.GeneratedCurrent != 1 {
		t.Fatal("fresh generated final bypassed its bound Store or changed the complete selection", spy.scenarioEffects)
	}
	if repeated, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority); code == contract.CryptoSuccess || len(repeated) != 0 {
		t.Fatal("fresh generated selections restored original producer permission")
	}
}

// full_only: false
func TestFreshReceiptTransportRequiresExactResults(t *testing.T) {
	f := newCurrentBasisFixture(t, contract.GCP, true)
	row, _, _ := f.addReceipt(t)
	session, result := Open(context.Background(), f.current, f.env.Store)
	if session == nil || result.Outcome != ObservedCurrent {
		t.Fatal("receipt fixture did not open", result)
	}
	wire, err := contract.EncodeCompactMutationReceipt(row)
	if err != nil {
		t.Fatal(err)
	}
	input := selectedProcessFacts(t, f.current, session)
	input.Objects = f.env.Store.(*memoryStore).objects
	custom := -1
	for i, receipt := range input.Receipts {
		if receipt.OperationID == row.OperationID {
			if custom >= 0 || !bytes.Equal(receipt.Body, wire) {
				t.Fatal("fixture custom receipt is duplicated or unequal")
			}
			custom = i
		}
	}
	if custom < 0 {
		t.Fatal("fixture custom receipt is absent")
	}
	for _, name := range []string{"exact", "missing", "different-result", "different-operation", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			receipts := slices.Clone(input.Receipts)
			for i := range receipts {
				receipts[i].Body = bytes.Clone(receipts[i].Body)
			}
			switch name {
			case "missing":
				receipts = slices.Delete(receipts, custom, custom+1)
			case "different-result":
				receipts[custom].Body[len(wire)-1] ^= 1
			case "different-operation":
				receipts[custom].OperationID = testID("different-cold-receipt")
			case "duplicate":
				receipts = append(receipts, receiptExpectation{OperationID: row.OperationID, Body: bytes.Clone(wire)})
			}
			input := input
			input.Receipts = receipts
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "receipt-fixture.json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, exe, "-test.v", "-test.run=^TestFreshProcessChild$")
			command.Env = append(os.Environ(), "ENKV_PROCESS_FIXTURE="+path)
			if err := runFreshProcess(command); (err == nil) != (name == "exact") {
				t.Fatal("fresh receipt transport accepted missing or unequal evidence", err)
			}
		})
	}
}

func processPublicAdmission(domain, trust contract.ID, store contract.Descriptor, public, basis []byte) OpenContext {
	return OpenContext{admission: &openAdmission{domain: domain, trust: trust, controlIncarnation: fixtureControlIncarnation(domain, trust), interpretation: contract.InterpretationID(), recipient: fixtureID(domain, "recipient"), composition: fixtureID(domain, "composition"), store: store, epoch: 1, publicKey: bytes.Clone(public), descriptor: bytes.Clone(basis), expires: time.Now().Add(time.Hour)}}
}

// full_only: false
func TestFreshGeneratedRecordProviderSigningMaterial(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(fmt.Sprintf("family%d", family), func(t *testing.T) {
			env, _ := genesisEnvironment(t, family, false)
			material := testID("trust")
			signer := testtrust.NewWithIdentity(t, family, material, testID("provider trust construction"), contract.NormalSigningRole)
			env.Trust, env.SigningSelector, env.PublicKey = &fixtureTrust{Signer: signer}, signer.KeySelector(), signer.PublicKey()
			fixture := newEnvironmentFixture(t, t.Context(), env, nil, false)
			if got, err := memoryCurrentAuthoritySignerForMaterial(t, fixture.session, material); err != nil || got.Identity() != signer.Identity() {
				t.Fatal("chosen material did not retain provider identity")
			}
			if got, err := memoryCurrentAuthoritySignerForMaterial(t, fixture.session, testID("wrong signing material")); err == nil || got != nil {
				t.Fatal("wrong current signing material gained authority")
			}
		})
	}
}
