package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
)

const rootMessageLimit = 16 << 10

type rootAdmission struct {
	Big            bool            `json:"big"`
	Live           bool            `json:"live"`
	Execution      executionPolicy `json:"execution"`
	CleanupSeconds int             `json:"cleanup_seconds"`
}

type rootAdmitter func(context.Context, rootAdmission) (context.Context, error)

type rootMessage struct {
	Operation string           `json:"operation"`
	Admission *rootAdmission   `json:"admission,omitempty"`
	Execution *executionPolicy `json:"execution,omitempty"`
	Success   *bool            `json:"success,omitempty"`
	Joined    *bool            `json:"joined,omitempty"`
}

// Only the native owner and its direct runner receive these pipe ends.
type rootChannel struct {
	readFile, writeFile *os.File
	reader              *bufio.Reader
	once                sync.Once
	closeErr            error
}

func newRootChannels() (*rootChannel, []*os.File, error) {
	nativeRead, runnerWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	runnerRead, nativeWrite, err := os.Pipe()
	if err != nil {
		return nil, nil, errors.Join(err, nativeRead.Close(), runnerWrite.Close())
	}
	return makeRootChannel(nativeRead, nativeWrite), []*os.File{runnerRead, runnerWrite}, nil
}

func makeRootChannel(read, write *os.File) *rootChannel {
	return &rootChannel{readFile: read, writeFile: write, reader: bufio.NewReaderSize(read, rootMessageLimit)}
}

func inheritedRootChannel() (*rootChannel, error) {
	// ExtraFiles assigns these descriptors. Close-on-exec is set before any
	// child starts, including commands that validate the invocation.
	syscall.CloseOnExec(3)
	syscall.CloseOnExec(4)
	channel := makeRootChannel(os.NewFile(3, "root-read"), os.NewFile(4, "root-write"))
	for _, file := range []*os.File{channel.readFile, channel.writeFile} {
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return nil, errors.Join(errors.New("root channel unavailable"), channel.close())
		}
	}
	return channel, nil
}

func (channel *rootChannel) close() error {
	channel.once.Do(func() { channel.closeErr = errors.Join(channel.readFile.Close(), channel.writeFile.Close()) })
	return channel.closeErr
}

func (channel *rootChannel) write(message rootMessage) error {
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if _, err := decodeRootMessage(body); err != nil {
		return err
	}
	n, err := channel.writeFile.Write(append(body, '\n'))
	if err == nil && n != len(body)+1 {
		err = io.ErrShortWrite
	}
	return err
}

func (channel *rootChannel) read() (rootMessage, error) {
	body, err := channel.reader.ReadSlice('\n')
	if err != nil {
		if err == io.EOF && len(body) == 0 {
			return rootMessage{}, io.EOF
		}
		return rootMessage{}, errors.New("root message incomplete or exceeds its bound")
	}
	return decodeRootMessage(body[:len(body)-1])
}

func rootPolicyFields(body json.RawMessage) bool {
	var fields map[string]json.RawMessage
	return json.Unmarshal(body, &fields) == nil && len(fields) == 2 && fields["requested"] != nil && fields["resolved"] != nil
}

func decodeRootMessage(body []byte) (rootMessage, error) {
	refused := errors.New("root message refused")
	var message rootMessage
	if len(body) == 0 || len(body)+1 > rootMessageLimit || uniqueJSONKeys(json.NewDecoder(bytes.NewReader(body))) != nil {
		return message, refused
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&message) != nil || decoder.Decode(new(any)) != io.EOF {
		return rootMessage{}, refused
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return rootMessage{}, refused
	}
	switch message.Operation {
	case "phase":
		if len(fields) != 2 || message.Admission == nil || message.Execution != nil || message.Success != nil || message.Joined != nil {
			return rootMessage{}, refused
		}
		var admission map[string]json.RawMessage
		if json.Unmarshal(fields["admission"], &admission) != nil || len(admission) != 4 || admission["big"] == nil || admission["live"] == nil || admission["cleanup_seconds"] == nil || !rootPolicyFields(admission["execution"]) {
			return rootMessage{}, refused
		}
		value := message.Admission
		if validateExecutionCapacity(value.Execution.Resolved) != nil || validateExecutionRequest(value.Execution.Requested) != nil || value.CleanupSeconds < 0 || value.CleanupSeconds > 3600 || !value.Live && value.CleanupSeconds != 0 {
			return rootMessage{}, refused
		}
	case "admitted":
		if len(fields) != 2 || message.Execution == nil || message.Admission != nil || message.Success != nil || message.Joined != nil || !rootPolicyFields(fields["execution"]) || validateExecutionCapacity(message.Execution.Resolved) != nil || validateExecutionRequest(message.Execution.Requested) != nil {
			return rootMessage{}, refused
		}
	case "terminal":
		if len(fields) != 3 || message.Success == nil || message.Joined == nil || message.Admission != nil || message.Execution != nil || *message.Success && !*message.Joined {
			return rootMessage{}, refused
		}
	case "refused":
		if len(fields) != 1 {
			return rootMessage{}, refused
		}
	default:
		return rootMessage{}, refused
	}
	return message, nil
}

type rootTerminal struct{ Admitted, Success, Joined bool }

// The native caller cancels resource waiting after runner Wait and closes the
// pipe on hard stop. EOF carries no physical process-join authority.
func serveRootChannel(ctx context.Context, channel *rootChannel, admit func(context.Context, rootAdmission) (executionPolicy, error)) (terminal rootTerminal, retErr error) {
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = channel.close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
		retErr = errors.Join(retErr, channel.close())
	}()
	message, err := channel.read()
	if err != nil {
		return terminal, err
	}
	for message.Operation == "phase" {
		policy, err := admit(ctx, *message.Admission)
		if err != nil {
			return terminal, errors.Join(err, channel.write(rootMessage{Operation: "refused"}))
		}
		if err := channel.write(rootMessage{Operation: "admitted", Execution: &policy}); err != nil {
			return terminal, err
		}
		terminal.Admitted = true
		message, err = channel.read()
		if err != nil {
			return terminal, err
		}
	}
	if message.Operation != "terminal" || *message.Success && !terminal.Admitted {
		return terminal, errors.New("root terminal state refused")
	}
	terminal.Success, terminal.Joined = *message.Success, *message.Joined
	if _, err := channel.read(); err != io.EOF {
		return terminal, errors.New("root data follows terminal result")
	}
	return terminal, nil
}

func (channel *rootChannel) admit(ctx context.Context, request rootAdmission) (executionPolicy, error) {
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = channel.close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	if err := channel.write(rootMessage{Operation: "phase", Admission: &request}); err != nil {
		return executionPolicy{}, err
	}
	message, err := channel.read()
	if err != nil || message.Operation != "admitted" {
		return executionPolicy{}, errors.Join(errors.New("root admission unavailable"), err)
	}
	return message.Execution.clone(), nil
}
