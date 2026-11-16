package crypto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
)

type sourceClosingReader struct {
	reading, finishRead  chan struct{}
	closing, finishClose chan struct{}
	reads, closes        atomic.Int32
}

func (s *sourceClosingReader) Read([]byte) (int, error) {
	if s.reads.Add(1) == 1 && s.reading != nil {
		close(s.reading)
	}
	if s.finishRead != nil {
		<-s.finishRead
	}
	return 0, io.EOF
}

func (s *sourceClosingReader) Close() error {
	if s.closes.Add(1) == 1 {
		close(s.closing)
	}
	<-s.finishClose
	return nil
}

// full_only: false
func TestSourcePendingClosePreservesOwnerWithoutHoldingRuntimeLock(t *testing.T) {
	core, binding := sourceFixture(t)
	// Mutex waits do not advance the bubble clock. Keep this timeout outside it
	// so a regression can release Close and join blocked callers before failing.
	wallContext, cancelWall := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWall()
	wallDone := wallContext.Done()
	synctest.Test(t, func(t *testing.T) {
		r, err := New(contract.GCP, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		input := &sourceClosingReader{closing: make(chan struct{}), finishClose: make(chan struct{})}
		released := false
		defer func() {
			if !released {
				close(input.finishClose)
			}
		}()
		if err := r.admitInputSeal(sourceID("pending close"), core, binding.SubjectID, []contract.BindingTableRow{binding}, input, time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		owner := r.inputSeal
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case <-input.closing:
		default:
			t.Fatal("expiry did not enter source Close")
		}
		retired := make(chan struct{})
		go func() { r.retireInputSeal(); close(retired) }()
		q := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoCompare, RequestID: sourceID("pending close exchange"), CustodyInstanceID: r.InstanceID()}
		exchanged := make(chan contract.CryptoResponse, 1)
		go func() { exchanged <- r.Exchange(context.Background(), q) }()
		forked := make(chan error, 1)
		go func() {
			fork, err := r.Fork()
			if fork != nil {
				fork.Close()
			}
			forked <- err
		}()
		other := &sourceReader{Reader: bytes.NewReader(nil)}
		admitted := make(chan error, 1)
		go func() {
			admitted <- r.admitInputSeal(sourceID("overlap"), core, binding.SubjectID, []contract.BindingTableRow{binding}, other, time.Now().Add(time.Minute))
		}()
		var faults []string
		want := contract.CryptoResponse{Schema: contract.CryptoSchema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: r.InstanceID(), ResultCode: contract.CryptoInvalidAdmission}
		exchangeJoined, forkJoined, admissionJoined := false, false, false
		select {
		case reply := <-exchanged:
			exchangeJoined = true
			if !reflect.DeepEqual(reply, want) {
				faults = append(faults, "pending source Close changed Exchange refusal")
			}
		case <-wallDone:
			faults = append(faults, "pending source Close blocked Exchange on the runtime mutex")
		}
		select {
		case err := <-forked:
			forkJoined = true
			if err != nil {
				faults = append(faults, "open runtime refused Fork during source Close")
			}
		case <-wallDone:
			faults = append(faults, "pending source Close blocked Fork on the runtime mutex")
		}
		select {
		case err := <-admitted:
			admissionJoined = true
			if !errors.Is(err, ErrAdmission) {
				faults = append(faults, "pending retirement admitted another source")
			}
		case <-wallDone:
			faults = append(faults, "pending source Close blocked another admission refusal")
		}
		ownerRetained := owner.input == input && owner.core == core && reflect.DeepEqual(owner.authority, binding) && r.slot == owner.session
		if !ownerRetained || input.reads.Load() != 0 || input.closes.Load() != 1 || other.reads != 0 || other.closes != 0 {
			faults = append(faults, "pending Close changed source ownership or touched an unadmitted input")
		}
		select {
		case <-owner.done:
			faults = append(faults, "source session completed before Close joined")
		default:
		}
		select {
		case <-retired:
			faults = append(faults, "retirement returned before Close joined")
		default:
		}
		t.Logf("close_pending=true expired=%t reads=%d closes=%d owner_retained=%t exchange_joined=%t fork_joined=%t admission_joined=%t", owner.ctx.Err() != nil, input.reads.Load(), input.closes.Load(), ownerRetained, exchangeJoined, forkJoined, admissionJoined)
		// Release external Close and join every caller before reporting a mutex stall.
		close(input.finishClose)
		released = true
		if !exchangeJoined {
			<-exchanged
		}
		if !forkJoined {
			<-forked
		}
		if !admissionJoined {
			<-admitted
		}
		<-retired
		<-owner.done
		if r.slot != nil || owner.input != nil || owner.core != (contract.SealedInputCore{}) || !reflect.DeepEqual(owner.authority, contract.BindingTableRow{}) || input.closes.Load() != 1 {
			faults = append(faults, "joined retirement retained private source state")
		}
		fresh := &sourceReader{Reader: bytes.NewReader(nil)}
		if err := r.admitInputSeal(sourceID("fresh after close"), core, binding.SubjectID, []contract.BindingTableRow{binding}, fresh, time.Now().Add(time.Minute)); err != nil {
			faults = append(faults, "joined retirement did not release the session slot")
		} else {
			r.retireInputSeal()
			if fresh.reads != 0 || fresh.closes != 1 {
				faults = append(faults, "fresh source retirement changed ownership")
			}
		}
		t.Log("Close, runtime calls and retirement joined")
		for _, fault := range faults {
			t.Error(fault)
		}
	})
}

// full_only: false
func TestRuntimeCloseJoinsSourceCloseAndRefusesNewWork(t *testing.T) {
	core, binding := sourceFixture(t)
	// Mutex waits do not advance the bubble clock. Keep this timeout outside it
	// so a regression can release Close and join blocked callers before failing.
	wallContext, cancelWall := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWall()
	wallDone := wallContext.Done()
	synctest.Test(t, func(t *testing.T) {
		r, err := New(contract.GCP, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		input := &sourceClosingReader{closing: make(chan struct{}), finishClose: make(chan struct{})}
		released := false
		defer func() {
			if !released {
				close(input.finishClose)
			}
		}()
		if err := r.admitInputSeal(sourceID("runtime close source"), core, binding.SubjectID, []contract.BindingTableRow{binding}, input, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		owner := r.inputSeal
		closed := make(chan struct{})
		go func() { r.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-input.closing:
		default:
			t.Fatal("Runtime.Close did not enter source Close")
		}
		forked := make(chan error, 1)
		go func() {
			fork, err := r.Fork()
			if fork != nil {
				fork.Close()
			}
			forked <- err
		}()
		other := &sourceReader{Reader: bytes.NewReader(nil)}
		admitted := make(chan error, 1)
		go func() {
			admitted <- r.admitInputSeal(sourceID("closed admission"), core, binding.SubjectID, []contract.BindingTableRow{binding}, other, time.Now().Add(time.Minute))
		}()
		var faults []string
		forkJoined, admissionJoined := false, false
		select {
		case err := <-forked:
			forkJoined = true
			if !errors.Is(err, ErrAdmission) {
				faults = append(faults, "closed runtime allowed Fork")
			}
		case <-wallDone:
			faults = append(faults, "source Close blocked closed-runtime Fork refusal")
		}
		select {
		case err := <-admitted:
			admissionJoined = true
			if !errors.Is(err, ErrAdmission) {
				faults = append(faults, "closed runtime admitted another source")
			}
		case <-wallDone:
			faults = append(faults, "source Close blocked closed-runtime admission refusal")
		}
		if !r.closed || owner.input != input || owner.core != core || other.reads != 0 || other.closes != 0 || input.reads.Load() != 0 || input.closes.Load() != 1 {
			faults = append(faults, "Runtime.Close changed pending custody or touched a refused source")
		}
		select {
		case <-closed:
			faults = append(faults, "Runtime.Close returned before source Close")
		default:
		}
		select {
		case <-owner.done:
			faults = append(faults, "source session completed before source Close")
		default:
		}
		t.Logf("runtime_closed=%t close_pending=true reads=%d closes=%d fork_joined=%t admission_joined=%t", r.closed, input.reads.Load(), input.closes.Load(), forkJoined, admissionJoined)
		close(input.finishClose)
		released = true
		if !forkJoined {
			<-forked
		}
		if !admissionJoined {
			<-admitted
		}
		<-closed
		<-owner.done
		if owner.input != nil || owner.core != (contract.SealedInputCore{}) || !reflect.DeepEqual(owner.authority, contract.BindingTableRow{}) || r.routes != nil || input.closes.Load() != 1 {
			faults = append(faults, "Runtime.Close returned without clearing joined source custody")
		}
		t.Log("source Close, refused calls and Runtime.Close joined")
		for _, fault := range faults {
			t.Error(fault)
		}
	})
}

// full_only: false
func TestSourceRetirementJoinsReadAfterCloseCompletes(t *testing.T) {
	core, binding := sourceFixture(t)
	synctest.Test(t, func(t *testing.T) {
		r, err := New(contract.GCP, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		input := &sourceClosingReader{reading: make(chan struct{}), finishRead: make(chan struct{}), closing: make(chan struct{}), finishClose: make(chan struct{})}
		readReleased, closeReleased := false, false
		defer func() {
			if !readReleased {
				close(input.finishRead)
			}
			if !closeReleased {
				close(input.finishClose)
			}
		}()
		if err := r.admitInputSeal(sourceID("read and close"), core, binding.SubjectID, []contract.BindingTableRow{binding}, input, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		owner := r.inputSeal
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		type sealResult struct {
			body []byte
			code contract.CryptoResultCode
		}
		sealed := make(chan sealResult, 1)
		go func() {
			body, code := r.sealInput(ctx, sourceID("read and close"))
			sealed <- sealResult{body: body, code: code}
		}()
		<-input.reading
		cancel()
		<-input.closing
		retired := make(chan struct{})
		go func() { r.retireInputSeal(); close(retired) }()
		synctest.Wait()
		close(input.finishClose)
		closeReleased = true
		synctest.Wait()
		var faults []string
		ownerRetained := owner.input == input && owner.core == core && reflect.DeepEqual(owner.authority, binding) && r.slot == owner.session
		if !ownerRetained || input.reads.Load() != 1 || input.closes.Load() != 1 {
			faults = append(faults, "completed Close lost custody while Read was active")
		}
		select {
		case <-owner.done:
			faults = append(faults, "source session completed before active Read joined")
		default:
		}
		select {
		case <-retired:
			faults = append(faults, "retirement returned before active Read joined")
		default:
		}
		var result sealResult
		sealJoined := false
		select {
		case result = <-sealed:
			sealJoined = true
			faults = append(faults, "sealing returned before active Read joined")
		default:
		}
		t.Logf("caller_cancelled=%t close_joined=true read_pending=true reads=%d closes=%d owner_retained=%t", ctx.Err() != nil, input.reads.Load(), input.closes.Load(), ownerRetained)
		close(input.finishRead)
		readReleased = true
		if !sealJoined {
			result = <-sealed
		}
		<-retired
		<-owner.done
		if result.code != contract.CryptoCancelled || result.body != nil || r.slot != nil || owner.input != nil || owner.core != (contract.SealedInputCore{}) || !reflect.DeepEqual(owner.authority, contract.BindingTableRow{}) || input.closes.Load() != 1 {
			faults = append(faults, "cancelled sealing changed its result or retained private state")
		}
		t.Log("Read, Close, sealing and retirement joined")
		for _, fault := range faults {
			t.Error(fault)
		}
	})
}
