package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// The bridge serves only small process-loss fixtures, not capacity scenarios.
// A length prefix bounds allocation before any JSON decoding takes place.
const processStoreFrameLimit = 256 << 10
const processStoreLifetime = 30 * time.Second
const processStoreJoinAllowance = 5 * time.Second

// Selected/cold reads, immutable Create/readback pairs and final observation
// each have finite room in this small-fixture bridge. This is not a capacity
// claim or a separately enforced allowance for each phase.
const processStoreRequestLimit = 4 * (contract.MaxChildPages + 8)

type processStoreRequest struct {
	Sequence uint32
	Method   string
	Key      string
	Maximum  uint32
	Token    contract.Token
	Body     []byte
	Cursor   string
}

type processStoreReply struct {
	Sequence uint32
	Read     contract.ReadResult
	Write    contract.WriteResult
	List     contract.ListPageResult
}

func writeProcessStoreFrame(w io.Writer, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > processStoreFrameLimit {
		return errors.New("process Store frame exceeds its byte limit")
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	frame = append(frame, body...)
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}

func readProcessStoreFrame(r io.Reader, value any) error {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 || length > processStoreFrameLimit {
		return errors.New("process Store frame exceeds its byte limit")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("process Store frame contains trailing JSON")
	}
	return nil
}

type processStore struct {
	t             testing.TB
	desc          contract.Descriptor
	configuration contract.StoreConfiguration
	requests      *os.File
	replies       *os.File
	sequence      uint32
}

func (s *processStore) Descriptor() contract.Descriptor                 { return s.desc }
func (s *processStore) StoreConfiguration() contract.StoreConfiguration { return s.configuration }

func (s *processStore) call(request processStoreRequest) processStoreReply {
	s.t.Helper()
	s.sequence++
	request.Sequence = s.sequence
	if err := writeProcessStoreFrame(s.requests, request); err != nil {
		s.t.Fatalf("process Store request: %v", err)
	}
	var reply processStoreReply
	if err := readProcessStoreFrame(s.replies, &reply); err != nil {
		s.t.Fatalf("process Store reply: %v", err)
	}
	if reply.Sequence != request.Sequence {
		s.t.Fatal("process Store reply sequence differs")
	}
	return reply
}

func (s *processStore) Read(_ context.Context, key string, maximum uint32) contract.ReadResult {
	reply := s.call(processStoreRequest{Method: "read", Key: key, Maximum: maximum})
	return reply.Read
}

func (s *processStore) Create(_ context.Context, key string, body []byte) contract.WriteResult {
	reply := s.call(processStoreRequest{Method: "create", Key: key, Body: body})
	return reply.Write
}

func (s *processStore) CreateHead(ctx context.Context, request contract.HeadCreateRequest) contract.WriteResult {
	if !request.Valid() || request.Descriptor() != s.desc {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	return s.Create(ctx, s.desc.HeadKey, request.Body())
}

func (s *processStore) CompareAndSwap(_ context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	reply := s.call(processStoreRequest{Method: "cas", Key: key, Token: token, Body: body})
	return reply.Write
}

func (s *processStore) ListPage(_ context.Context, cursor string) contract.ListPageResult {
	return s.call(processStoreRequest{Method: "list", Cursor: cursor}).List
}

func (s *processStore) DeleteIfToken(_ context.Context, key string, token contract.Token) contract.WriteResult {
	return s.call(processStoreRequest{Method: "delete", Key: key, Token: token}).Write
}

// The runner's process supervisor belongs to package main and cannot be
// imported by this private Core test assembly. Keep the same bounded Kill/Wait
// settlement here. These children create no descendants and inherit the test
// coordinator's process group, so its outer deadline can stop the whole run.
type processStoreChild struct {
	command  *exec.Cmd
	requests *os.File
	replies  *os.File
	wait     chan error
	joined   bool
	waitErr  error
	sequence uint32
	maximum  uint32
	trace    []string
}

func startProcessStoreChild(t *testing.T, directory, role string, facts any) *processStoreChild {
	t.Helper()
	p := &processStoreChild{maximum: processStoreRequestLimit}
	if role == "end-work-protected" {
		// The five-unit predecessor and four-unit successor read loops surround
		// at most two requests per middle-loop iteration, then one CAS.
		p.maximum = 11*(contract.MaxChildPages+8) + 1
	}
	var files []*os.File
	t.Cleanup(func() {
		if p.command != nil && p.command.Process != nil && !p.joined {
			if err := p.stop(); err != nil {
				t.Errorf("process Store cleanup: %v", err)
			}
		}
		for _, file := range files {
			if err := file.Close(); err != nil {
				t.Errorf("process Store close %s: %v", file.Name(), err)
			}
		}
		if err := os.WriteFile(filepath.Join(directory, role+"-trace.txt"), []byte(strings.Join(p.trace, "\n")+"\n"), 0600); err != nil {
			t.Errorf("process Store trace: %v", err)
		}
	})
	requests, childRequests, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, requests, childRequests)
	childReplies, replies, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, childReplies, replies)
	p.requests, p.replies = requests, replies
	deadline := time.Now().Add(processStoreLifetime)
	if err := requests.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := replies.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(filepath.Join(directory, role+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, output)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p.command = exec.Command(binary, "-test.run=^TestWriterTerminationChild$", "-test.timeout=40s")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ENKV_PROCESS_STORE_ROLE=") && !strings.HasPrefix(value, "ENKV_TEST_INVOCATION=") {
			p.command.Env = append(p.command.Env, value)
		}
	}
	p.command.Env = append(p.command.Env, "ENKV_PROCESS_STORE_ROLE="+role)
	p.command.ExtraFiles = []*os.File{childReplies, childRequests}
	p.command.Stdout, p.command.Stderr = output, output
	p.command.WaitDelay = time.Second
	if err := p.command.Start(); err != nil {
		t.Fatal(err)
	}
	p.wait = make(chan error, 1)
	go func() { p.wait <- p.command.Wait() }()
	// Only the child retains these endpoints. Otherwise an unexpected child
	// exit would leave the parent's request read waiting for its own writer.
	for _, file := range []*os.File{childReplies, childRequests} {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	files = []*os.File{requests, replies, output}
	if err := writeProcessStoreFrame(replies, facts); err != nil {
		t.Fatalf("process Store initial facts: %v", err)
	}
	return p
}

func (p *processStoreChild) next() (processStoreRequest, error) {
	var request processStoreRequest
	if err := readProcessStoreFrame(p.requests, &request); err != nil {
		return request, fmt.Errorf("process Store request: %w", err)
	}
	p.sequence++
	if request.Sequence != p.sequence || p.sequence > p.maximum {
		return request, errors.New("process Store request sequence or count differs")
	}
	p.trace = append(p.trace, fmt.Sprintf("%d %s %s", request.Sequence, request.Method, request.Key))
	return request, nil
}

func (p *processStoreChild) reply(reply processStoreReply) error {
	reply.Sequence = p.sequence
	return writeProcessStoreFrame(p.replies, reply)
}

func (p *processStoreChild) join() error {
	if p.joined {
		return p.waitErr
	}
	timer := time.NewTimer(processStoreJoinAllowance)
	defer timer.Stop()
	select {
	case p.waitErr = <-p.wait:
		p.joined = true
		p.trace = append(p.trace, fmt.Sprintf("joined: %v", p.waitErr))
		return p.waitErr
	case <-timer.C:
		return errors.New("process Store child did not join within the settlement allowance")
	}
}

func (p *processStoreChild) stop() error {
	if p.joined {
		return errors.New("process Store child exited before termination")
	}
	killErr := p.command.Process.Kill()
	joinErr := p.join()
	if killErr != nil {
		return errors.Join(fmt.Errorf("process Store kill: %w", killErr), joinErr)
	}
	var exit *exec.ExitError
	if !errors.As(joinErr, &exit) {
		return fmt.Errorf("process Store expected joined termination, got: %v", joinErr)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		return fmt.Errorf("process Store child did not exit from the requested kill: %v", joinErr)
	}
	return nil
}

func processStoreOperation(store contract.Store, request processStoreRequest, readOnly bool) (processStoreReply, error) {
	reply := processStoreReply{}
	if request.Method != "list" && request.Cursor != "" {
		return reply, errors.New("process Store cursor requires listing")
	}
	switch request.Method {
	case "read":
		if request.Maximum == 0 || request.Token != (contract.Token{}) || len(request.Body) != 0 {
			return reply, errors.New("invalid process Store read")
		}
		reply.Read = store.Read(context.Background(), request.Key, request.Maximum)
	case "create":
		if readOnly || request.Maximum != 0 || request.Token != (contract.Token{}) || len(request.Body) == 0 {
			return reply, errors.New("invalid or forbidden process Store create")
		}
		reply.Write = store.Create(context.Background(), request.Key, request.Body)
	case "cas":
		if readOnly || request.Maximum != 0 || !request.Token.Valid() || len(request.Body) == 0 {
			return reply, errors.New("invalid or forbidden process Store CAS")
		}
		reply.Write = store.CompareAndSwap(context.Background(), request.Key, request.Token, request.Body)
	case "list":
		lister, ok := store.(contract.BoundedEnumerationStore)
		if !ok || request.Key != "" || request.Maximum != 0 || request.Token != (contract.Token{}) || len(request.Body) != 0 || len(request.Cursor) > contract.StoreListCursorLength {
			return reply, errors.New("invalid process Store listing")
		}
		reply.List = lister.ListPage(context.Background(), request.Cursor)
	case "delete":
		deleter, ok := store.(contract.ConditionalDeleteStore)
		if !ok || readOnly || request.Key == "" || request.Maximum != 0 || !request.Token.Valid() || len(request.Body) != 0 {
			return reply, errors.New("invalid or forbidden process Store delete")
		}
		reply.Write = deleter.DeleteIfToken(context.Background(), request.Key, request.Token)
	default:
		return reply, errors.New("unknown process Store operation")
	}
	return reply, nil
}

func processStoreMarker(request processStoreRequest, method string) bool {
	return request.Method == method && request.Key == "" && request.Maximum == 0 && request.Token == (contract.Token{}) && len(request.Body) == 0 && request.Cursor == ""
}
