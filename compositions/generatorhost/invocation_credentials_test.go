package generatorhost

import (
	"bytes"
	"context"
	"enkv.sh/sdk/artifact/credentialroute"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"unsafe"

	"enkv.sh/core/contract"
	protocol "enkv.sh/sdk/protocols/generator"
)

func invocationCredentialLauncher(t *testing.T, path string, row contract.GeneratorImplementation, owner *InvocationCredentials) *NativeLauncher {
	t.Helper()
	launcher, err := newHermeticNative(Config{ArtifactPath: path, Artifact: row})
	if err != nil {
		t.Fatal(err)
	}
	launcher.invocation = owner
	return launcher
}

func invocationCredentialStart(t *testing.T, launcher *NativeLauncher, row contract.GeneratorImplementation) (*nativeRun, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	run, err := launcher.Start(t.Context(), testCommand(row), writer)
	if err != nil {
		closeFile(reader)
		t.Fatal(err)
	}
	owned := run.(*nativeRun)
	t.Cleanup(func() {
		select {
		case <-owned.done:
		default:
			_ = owned.Cancel()
		}
		closeFile(reader)
	})
	return owned, reader
}

func invocationCredentialJoin(t *testing.T, run *nativeRun, reader *os.File) {
	t.Helper()
	body, err := protocol.ReadExpectedFrame(reader, protocol.KindResult, run.CommandID(), protocol.MaximumResultBody)
	clear(body[:cap(body)])
	if err == nil {
		err = protocol.RequireEOF(reader)
	}
	closeFile(reader)
	status, waitErr := run.Wait(t.Context())
	if err != nil || waitErr != nil || status != (protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK}) {
		t.Fatal("invocation child did not join", err, waitErr, status)
	}
}

// full_only: false
func TestInvocationCredentialSnapshotSurvivesLaterProducerAndClearsAfterJoin(t *testing.T) {
	const first = "cfat_0123456789abcdefghijklmnopqrstuvwxyzABCD_012345"
	const second = "cfat_9876543210abcdefghijklmnopqrstuvwxyzABCD_543210"
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", first)
	path := buildTestGenerator(t, "success")
	row := environmentImplementation(t, path)
	owner := NewInvocationCredentials(t.Context())
	t.Cleanup(owner.Close)
	firstRun, reader := invocationCredentialStart(t, invocationCredentialLauncher(t, path, row, owner), row)
	firstID := firstRun.CommandID()
	if !bytes.Equal(capturedValue(t, row, firstRun.credential), []byte(first)) {
		t.Error("first producer did not receive captured environment")
	}
	invocationCredentialJoin(t, firstRun, reader)
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", second)
	secondRun, reader := invocationCredentialStart(t, invocationCredentialLauncher(t, path, row, owner), row)
	if !bytes.Equal(capturedValue(t, row, secondRun.credential), []byte(first)) {
		t.Error("later producer changed the invocation credential")
	}
	if firstID == secondRun.CommandID() {
		t.Error("different producer sessions reused a command nonce")
	}
	invocationCredentialJoin(t, secondRun, reader)
	key := invocationCredentialKeyOf(row)
	var retained []byte
	for _, capture := range owner.captures {
		if capture.key == key {
			retained = capture.body
			break
		}
	}
	if retained == nil {
		t.Fatal("original capture missing")
	}
	if !bytes.Equal(capturedValue(t, row, retained), []byte(first)) {
		t.Fatal("invocation lost the original capture before close")
	}
	owner.Close()
	if !allZero(retained[:cap(retained)]) {
		t.Fatal("closed invocation retained captured credential bytes")
	}
	if len(owner.captures) != 0 {
		t.Fatal("closed invocation retained capture metadata")
	}
	assertNoLaunchDescriptors(t, path)
}

// full_only: false
func TestInvocationCredentialCaptureFollowsHandshakeAndKeepsExactRoutes(t *testing.T) {
	const first = "cfat_0123456789abcdefghijklmnopqrstuvwxyzABCD_012345"
	const second = "cfat_9876543210abcdefghijklmnopqrstuvwxyzABCD_543210"
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", first)
	owner := NewInvocationCredentials(t.Context())
	t.Cleanup(owner.Close)
	badPath := buildTestGenerator(t, "bad-handshake")
	badRow := environmentImplementation(t, badPath)
	bad := invocationCredentialLauncher(t, badPath, badRow, owner)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	run, err := bad.Start(t.Context(), testCommand(badRow), writer)
	closeFile(reader)
	if run != nil || !errors.Is(err, ErrAdmission) || len(owner.captures) != 0 {
		t.Fatal("handshake refusal captured environment", err)
	}
	path := buildTestGenerator(t, "success")
	row := environmentImplementation(t, path)
	firstRun, reader := invocationCredentialStart(t, invocationCredentialLauncher(t, path, row, owner), row)
	invocationCredentialJoin(t, firstRun, reader)
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", second)
	other := row
	route, _ := credentialroute.Decode(row.CredentialRoute)
	route.ContractID[1] ^= 1
	other.CredentialRoute, _ = credentialroute.Encode(route)
	routeID, _ := credentialroute.Identity(route)
	other.CredentialRouteID = contract.ID(routeID)
	otherRun, reader := invocationCredentialStart(t, invocationCredentialLauncher(t, path, other, owner), other)
	if !bytes.Equal(capturedValue(t, other, otherRun.credential), []byte(second)) {
		t.Error("different exact route inherited another account capture")
	}
	invocationCredentialJoin(t, otherRun, reader)
	if len(owner.captures) != 2 {
		t.Fatal("distinct routes did not own distinct bounded captures")
	}
}

// full_only: false
func TestInvocationCredentialCloseWaitsForSessionsAndRefusesNewUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := NewInvocationCredentials(t.Context())
		release, err := owner.begin()
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { owner.Close(); close(done) }()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("invocation closed before its session joined")
		default:
		}
		if _, err := owner.begin(); !errors.Is(err, ErrCredential) {
			t.Fatal("closed invocation admitted a new session", err)
		}
		release()
		<-done
	})
}

// full_only: false
func TestInvocationCredentialFailureIsFixedAndCapacityUsesExistingGraphLimit(t *testing.T) {
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", strings.Repeat("x", credentialroute.MaxInputsBytes))
	owner := NewInvocationCredentials(t.Context())
	t.Cleanup(owner.Close)
	row := environmentImplementation(t, buildTestGenerator(t, "success"))
	release, err := owner.begin()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := owner.capture(context.Background(), row, nil); !errors.Is(err, ErrCredential) {
		t.Fatal("invalid credential captured", err)
	}
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "cfat_0123456789abcdefghijklmnopqrstuvwxyzABCD_012345")
	if _, err := owner.capture(context.Background(), row, nil); !errors.Is(err, ErrCredential) {
		t.Fatal("failed invocation capture was renewed", err)
	}
	for i := len(owner.captures); i < contract.GeneratorMaxTemplates; i++ {
		key := invocationCredentialKey{route: contract.ID{byte(i), byte(i >> 8)}}
		owner.captures = append(owner.captures, invocationCredentialCapture{key: key})
	}
	other := row
	route, _ := credentialroute.Decode(row.CredentialRoute)
	route.ContractID[1] ^= 1
	other.CredentialRoute, _ = credentialroute.Encode(route)
	routeID, _ := credentialroute.Identity(route)
	other.CredentialRouteID = contract.ID(routeID)
	if _, err := owner.capture(context.Background(), other, nil); !errors.Is(err, ErrCredential) {
		t.Fatal("capture exceeded admitted graph template bound", err)
	}
}

// full_only: false
func TestInvocationCredentialOwnerPreservesInProgressCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-only")
	if err := os.WriteFile(path, []byte("fixture bytes are not executed"), 0500); err != nil {
		t.Fatal(err)
	}
	row := environmentImplementation(t, path)
	owner := NewInvocationCredentials(t.Context())
	defer owner.Close()
	release, err := owner.begin()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "first-private-input")
	route, err := credentialroute.Decode(row.CredentialRoute)
	if err != nil {
		t.Fatal(err)
	}
	firstBody, err := readEnvironmentInputs(t.Context(), route)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(firstBody)
	// Pause one capture after it publishes its ready channel and before its
	// environment acquisition returns. A second route can enter at that boundary.
	owner.mu.Lock()
	owner.captures = append(owner.captures, invocationCredentialCapture{key: invocationCredentialKeyOf(row), ready: make(chan struct{})})
	pending := &owner.captures[0]
	owner.mu.Unlock()
	originalRoute := route
	other := row
	route.ContractID[1] ^= 1
	other.CredentialRoute, err = credentialroute.Encode(route)
	if err != nil {
		t.Fatal(err)
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil {
		t.Fatal(err)
	}
	other.CredentialRouteID = contract.ID(routeID)
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "second-private-input")
	otherBody, err := owner.capture(t.Context(), other, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(otherBody)
	owner.mu.Lock()
	pending.body = firstBody
	close(pending.ready)
	stable := pending == &owner.captures[0]
	owner.mu.Unlock()
	body, err := owner.capture(t.Context(), row, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	inputs, decodeErr := credentialroute.DecodeInputs(originalRoute, body)
	if !stable || cap(owner.captures) != contract.GeneratorMaxTemplates || decodeErr != nil || len(inputs) != 1 || string(inputs[0].Value) != "first-private-input" {
		t.Fatal("a zero-value owner moved an in-progress capture or lost its original snapshot", stable, cap(owner.captures), decodeErr)
	}
}

// full_only: true
func TestInvocationCredentialMaximumCapturesFitOwnerBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-only")
	if err := os.WriteFile(path, []byte("fixture bytes are not executed"), 0500); err != nil {
		t.Fatal(err)
	}
	row := environmentImplementation(t, path)
	route, err := credentialroute.Decode(row.CredentialRoute)
	if err != nil {
		t.Fatal(err)
	}
	// Independent complete input account: schema/count3, name/presence/length6,
	// then the declared name and value. Each retained encoding reaches65536.
	valueLength := 65536 - 3 - 6 - len(route.Names[0])
	t.Setenv(route.Names[0], strings.Repeat("x", valueLength))
	owner := NewInvocationCredentials(t.Context())
	defer owner.Close()
	release, err := owner.begin()
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	for index := 0; index < 1408; index++ {
		current := row
		recipe := route
		recipe.PublicData = []byte{byte(index >> 8), byte(index)}
		current.CredentialRoute, err = credentialroute.Encode(recipe)
		if err != nil {
			t.Fatal(err)
		}
		routeID, idErr := credentialroute.Identity(recipe)
		if idErr != nil {
			t.Fatal(idErr)
		}
		current.CredentialRouteID = contract.ID(routeID)
		body, captureErr := owner.capture(t.Context(), current, nil)
		if captureErr != nil || len(body) != 65536 || cap(body) != 65536 {
			clear(body)
			t.Fatal("maximum capture refused or overallocated", index, captureErr)
		}
		clear(body[:cap(body)])
	}
	if len(owner.captures) != 1408 || cap(owner.captures) != 1408 {
		t.Fatal("maximum capture row count changed")
	}
	retained := make([][]byte, 0, 1408)
	total := 0
	for _, capture := range owner.captures {
		if len(capture.body) != 65536 || cap(capture.body) != 65536 || allZero(capture.body) {
			t.Fatal("maximum retained input lost bytes or owns excess backing")
		}
		retained = append(retained, capture.body)
		total += cap(capture.body)
	}
	if total != 92274688 || total > InvocationCredentialsMaximumOwnedBytes {
		t.Fatal("cumulative private body account changed", total)
	}
	release()
	released = true
	owner.Close()
	for _, body := range retained {
		if !allZero(body) {
			t.Fatal("closed maximum owner retained private bytes")
		}
	}
	if owner.captures != nil {
		t.Fatal("closed maximum owner retained metadata")
	}
}

type cancelCredentialContext struct {
	context.Context
	cancel context.CancelFunc
	calls  int
}

func (c *cancelCredentialContext) Err() error {
	c.calls++
	if c.calls == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

// full_only: false
func TestInvocationCredentialCanceledFirstSessionDoesNotPoisonSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-only")
	if err := os.WriteFile(path, []byte("fixture bytes are not executed"), 0500); err != nil {
		t.Fatal(err)
	}
	row := environmentImplementation(t, path)
	const first = "first-private-input"
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", first)
	owner := NewInvocationCredentials(t.Context())
	defer owner.Close()
	release, err := owner.begin()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	session, cancel := context.WithCancel(t.Context())
	defer cancel()
	firstSession := &cancelCredentialContext{Context: session, cancel: cancel}
	body, err := owner.capture(firstSession, row, nil)
	clear(body)
	if !errors.Is(err, context.Canceled) || body != nil {
		t.Fatal("canceled first session received credentials", err)
	}
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "changed-private-input")
	body, err = owner.capture(t.Context(), row, nil)
	defer clear(body)
	if err != nil || !bytes.Equal(capturedValue(t, row, body), []byte(first)) {
		t.Fatal("first session cancellation poisoned or renewed the invocation snapshot", err)
	}
}

// full_only: false
func TestInvocationCredentialReadyCaptureRejectsCanceledSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-only")
	if err := os.WriteFile(path, []byte("fixture bytes are not executed"), 0500); err != nil {
		t.Fatal(err)
	}
	row := environmentImplementation(t, path)
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "private-input")
	owner := NewInvocationCredentials(t.Context())
	defer owner.Close()
	release, err := owner.begin()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	body, err := owner.capture(t.Context(), row, nil)
	clear(body)
	if err != nil {
		t.Fatal(err)
	}
	session, cancel := context.WithCancel(t.Context())
	defer cancel()
	canceledAtReady := &cancelCredentialContext{Context: session, cancel: cancel}
	body, err = owner.capture(canceledAtReady, row, nil)
	defer clear(body)
	if !errors.Is(err, context.Canceled) || body != nil {
		t.Fatal("ready capture returned credentials without a final session cancellation check", err)
	}
}

// full_only: false
func TestInvocationCredentialCanceledWaiterLeavesAcquisitionOwned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-only")
	if err := os.WriteFile(path, []byte("fixture bytes are not executed"), 0500); err != nil {
		t.Fatal(err)
	}
	row := environmentImplementation(t, path)
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "original-private-input")
	synctest.Test(t, func(t *testing.T) {
		owner := NewInvocationCredentials(t.Context())
		defer owner.Close()
		entered, finish := make(chan struct{}), make(chan struct{})
		owner.readInputs = func(ctx context.Context, route credentialroute.Route) ([]byte, error) {
			body, err := readEnvironmentInputs(ctx, route)
			close(entered)
			select {
			case <-finish:
				return body, err
			case <-ctx.Done():
				clear(body)
				return nil, ctx.Err()
			}
		}
		release, err := owner.begin()
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		session, cancel := context.WithCancel(t.Context())
		first := make(chan error, 1)
		go func() { body, err := owner.capture(session, row, nil); clear(body); first <- err }()
		<-entered
		cancel()
		synctest.Wait()
		select {
		case err := <-first:
			if !errors.Is(err, context.Canceled) {
				t.Error("first waiter did not retain its own cancellation", err)
			}
		default:
			t.Error("canceled waiter remained blocked on acquisition")
		}
		t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "changed-private-input")
		close(finish)
		body, err := owner.capture(t.Context(), row, nil)
		defer clear(body)
		if err != nil || !bytes.Equal(capturedValue(t, row, body), []byte("original-private-input")) {
			t.Error("session cancellation stopped or renewed invocation acquisition", err)
		}
	})
}

// full_only: false
func TestInvocationCredentialCloseCancelsAndJoinsAcquisitionBeforeClearing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-only")
	if err := os.WriteFile(path, []byte("fixture bytes are not executed"), 0500); err != nil {
		t.Fatal(err)
	}
	row := environmentImplementation(t, path)
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "private-input")
	synctest.Test(t, func(t *testing.T) {
		owner := NewInvocationCredentials(t.Context())
		entered, canceled, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var retained []byte
		owner.readInputs = func(ctx context.Context, route credentialroute.Route) ([]byte, error) {
			var err error
			retained, err = readEnvironmentInputs(ctx, route)
			close(entered)
			select {
			case <-ctx.Done():
				close(canceled)
				<-finish
			case <-finish:
			}
			return retained, err
		}
		release, err := owner.begin()
		if err != nil {
			t.Fatal(err)
		}
		sessionDone := make(chan struct{})
		go func() { body, _ := owner.capture(t.Context(), row, nil); clear(body); release(); close(sessionDone) }()
		<-entered
		closed := make(chan struct{})
		go func() { owner.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-canceled:
		default:
			t.Error("Close did not cancel owned credential acquisition")
		}
		select {
		case <-closed:
			t.Error("Close completed before acquisition joined")
		default:
		}
		if allZero(retained) {
			t.Error("Close cleared bytes while acquisition still owned them")
		}
		close(finish)
		<-sessionDone
		<-closed
		if !allZero(retained[:cap(retained)]) || owner.captures != nil {
			t.Error("closed acquisition retained private bytes")
		}
	})
}

// full_only: false
func TestInvocationCredentialParentCancellationStopsAcquisition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-only")
	if err := os.WriteFile(path, []byte("fixture bytes are not executed"), 0500); err != nil {
		t.Fatal(err)
	}
	row := environmentImplementation(t, path)
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "private-input")
	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithCancel(t.Context())
		defer cancel()
		owner := NewInvocationCredentials(parent)
		entered := make(chan struct{})
		var retained []byte
		calls := 0
		owner.readInputs = func(ctx context.Context, route credentialroute.Route) ([]byte, error) {
			calls++
			var err error
			retained, err = readEnvironmentInputs(ctx, route)
			close(entered)
			<-ctx.Done()
			return retained, err
		}
		release, err := owner.begin()
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { body, err := owner.capture(t.Context(), row, nil); clear(body); release(); result <- err }()
		<-entered
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Error("invocation cancellation did not release an independent waiter", err)
		}
		if owner.closed {
			t.Error("parent cancellation unexpectedly closed the owner")
		}
		if _, err := owner.begin(); !errors.Is(err, ErrCredential) {
			t.Error("canceled owner admitted a session before Close", err)
		}
		if body, err := owner.capture(t.Context(), row, nil); body != nil || !errors.Is(err, context.Canceled) {
			clear(body)
			t.Error("canceled owner renewed acquisition before Close", err)
		}
		owner.Close()
		if calls != 1 || !allZero(retained[:cap(retained)]) || owner.captures != nil {
			t.Error("parent cancellation did not join and clear the sole acquisition")
		}
		if _, err := owner.begin(); !errors.Is(err, ErrCredential) {
			t.Error("canceled owner admitted a session", err)
		}
		if body, err := owner.capture(t.Context(), row, nil); body != nil || !errors.Is(err, ErrCredential) {
			clear(body)
			t.Error("canceled owner renewed acquisition", err)
		}
	})
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	owner := NewInvocationCredentials(parent)
	release, err := owner.begin()
	if err != nil {
		t.Fatal(err)
	}
	body, err := owner.capture(t.Context(), row, nil)
	clear(body)
	if err != nil {
		release()
		owner.Close()
		t.Fatal(err)
	}
	retained := owner.captures[0].body
	cancel()
	body, err = owner.capture(t.Context(), row, nil)
	clear(body)
	if body != nil || !errors.Is(err, context.Canceled) || owner.closed || len(owner.captures) != 1 {
		t.Error("owner cancellation returned a ready capture or renewed it before Close", err)
	}
	if _, err := owner.begin(); !errors.Is(err, ErrCredential) {
		t.Error("canceled ready owner admitted a session before Close", err)
	}
	release()
	owner.Close()
	if !allZero(retained[:cap(retained)]) {
		t.Error("closed ready owner retained private bytes")
	}

}

// full_only: false
func TestInvocationCredentialPendingAcquisitionLedger(t *testing.T) {
	if unsafe.Sizeof(credentialroute.Input{}) != 48 || unsafe.Sizeof("") != 16 || unsafe.Sizeof(credentialroute.Route{}) != 88 || unsafe.Sizeof(invocationCredentialCapture{}) != 80 || unsafe.Sizeof(InvocationCredentials{}) > 512 {
		t.Fatal("supported capture metadata layout changed")
	}
	// Independent reservation: 32 input rows, 32 name headers, two complete
	// bounded route images, the decoded route, and fixed worker control state.
	if 32*48+32*16+2*1581+88+256 > 8192 || InvocationCredentialsMaximumAcquisitionOwnedBytes != 103809024 {
		t.Fatal("pending acquisition workspace is not completely reserved")
	}
	for _, count := range []int{0, 32} {
		route := credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment}
		content := 40
		for index := 0; index < count; index++ {
			name := "ENKV_CAPTURE_" + strconv.Itoa(index+10)
			route.Names = append(route.Names, name)
			content += 1 + len(name)
		}
		route.PublicData = make([]byte, 1581-content)
		encoded, err := credentialroute.Encode(route)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := credentialroute.Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		content = cap(owned.PublicData)
		for _, name := range owned.Names {
			content += len(name)
		}
		if cap(owned.Names) > 32 || content > 2*1581 {
			t.Fatal("owned route exceeds reserved pending metadata", count, content)
		}
	}
}
