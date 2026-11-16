// The contract child implements its own bounded service behavior.
// Command enkv-output-contract-test supplies local output exchanges and deliberate host-test faults.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
)

type testImplementation struct{ output.Binding }

// A separate test build uses this link value to exercise a child that exits
// before it can write a handshake or result frame.
var exitBeforeHello string
var refusalMode string
var endpointHold string
var endpointSocket string

type refusalTestWriter struct {
	file         *os.File
	correlation  protocol.ID
	resultHeader []byte
}

func (w *refusalTestWriter) Write(b []byte) (int, error) {
	if refusalMode == "result-create-without-resource" {
		if len(b) == protocol.HeaderLength && b[6] == protocol.KindResult {
			w.resultHeader = bytes.Clone(b)
			return len(b), nil
		}
		if w.resultHeader != nil {
			result, err := protocol.DecodeResult(b)
			if err != nil {
				return 0, err
			}
			result.SafeResourceID = ""
			body, err := protocol.EncodeResult(result)
			if err != nil {
				return 0, err
			}
			binary.BigEndian.PutUint32(w.resultHeader[39:43], uint32(len(body)))
			frame := append(w.resultHeader, body...)
			w.resultHeader = nil
			if n, err := w.file.Write(frame); err != nil {
				return 0, err
			} else if n != len(frame) {
				return 0, io.ErrShortWrite
			}
			return len(b), nil
		}
	}
	if len(b) == protocol.HeaderLength && b[6] == protocol.KindPreparationRefused {
		copy(w.correlation[:], b[7:39])
		modified := bytes.Clone(b)
		switch refusalMode {
		case "malformed":
			modified[0] ^= 1
		case "wrong-correlation":
			modified[7] ^= 1
		case "nonzero-body":
			binary.BigEndian.PutUint32(modified[39:43], 1)
			modified = append(modified, 1)
		}
		if n, err := w.file.Write(modified); err != nil || n != len(modified) {
			if err != nil {
				return 0, err
			}
			return 0, io.ErrShortWrite
		}
		return len(b), nil
	}
	return w.file.Write(b)
}

var publicFailureMode string

type publicTestWriter struct {
	file    *os.File
	pending []byte
}

func (w *publicTestWriter) Write(b []byte) (int, error) {
	w.pending = append(w.pending, b...)
	if len(w.pending) < protocol.HeaderLength {
		return len(b), nil
	}
	size := protocol.HeaderLength + int(binary.BigEndian.Uint32(w.pending[39:43]))
	if len(w.pending) < size {
		return len(b), nil
	}
	frame := w.pending[:size]
	kind := frame[6]
	if kind == protocol.KindNormalizeResult || kind == protocol.KindCanonicalResult || kind == protocol.KindInterpretResult || kind == protocol.KindActionCheckResult || kind == protocol.KindPolicyActionResult {
		body := bytes.Clone(frame[protocol.HeaderLength:])
		switch publicFailureMode {
		case "refusal", "wrong-digest", "trailing", "process-failure":
			body = body[:35]
			body[34] = 0
			if kind == protocol.KindActionCheckResult {
				body = append(body, make([]byte, 8)...)
			}
			if kind == protocol.KindPolicyActionResult {
				body = append(body, 0)
			}
			if publicFailureMode == "wrong-digest" {
				body[2] ^= 1
			}
		case "illegal-facts":
			body[34] = 0
			if kind == protocol.KindCanonicalResult {
				body = append(body, 1)
			}
		case "malformed":
			body[0] = 255
		case "config-mismatch":
			body = bytes.Replace(body, []byte("test-output/config/v1"), []byte("fake-output/config/v1"), 1)
		}
		frame = append(bytes.Clone(frame[:protocol.HeaderLength]), body...)
		binary.BigEndian.PutUint32(frame[39:43], uint32(len(body)))
		if publicFailureMode == "trailing" {
			frame = append(frame, 1)
		}
	}
	if n, err := w.file.Write(frame); err != nil {
		return 0, err
	} else if n != len(frame) {
		return 0, io.ErrShortWrite
	}
	w.pending = w.pending[size:]
	return len(b), nil
}

func closeEndpoints(files ...*os.File) bool {
	closed := true
	for _, file := range files {
		if file.Close() != nil {
			closed = false
		}
	}
	return closed
}

//go:embed plugin.json
var descriptorJSON []byte

func testCapabilities() protocol.ActionCapabilities {
	return (protocol.CapabilityCreateEmpty | protocol.CapabilityCreateWithValue | protocol.CapabilityWriteValue | protocol.CapabilityUpdatePolicy | protocol.CapabilityDeleteOwned | protocol.CapabilityDeleteReservedSlot) | protocol.CapabilityCreateSetsPolicy | protocol.CapabilityWriteSetsPolicy
}

type settings struct {
	Prefix string `json:"prefix"`
}

func (testImplementation) NormalizeDestination(_ context.Context, rawSettings []byte) (protocol.Destination, error) {
	var input settings
	decoder := json.NewDecoder(bytes.NewReader(rawSettings))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return protocol.Destination{}, protocol.ErrProtocol
	}
	if input.Prefix == "" {
		input.Prefix = "fixture"
	}
	if input.Prefix == "refuse-and-deny-scope-cleanup" {
		if err := denyExecutableCleanup(); err != nil {
			return protocol.Destination{}, err
		}
		return protocol.Destination{}, protocol.ErrProtocol
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return protocol.Destination{}, err
	}
	return protocol.Destination{ConfigContractID: "test-output/config/v1", ServiceContractID: "test-output/service/v1", CanonicalSettings: canonical,
		Policy: protocol.Policy{ContractID: "test-policy", Data: []byte("1,9")}, Capabilities: testCapabilities()}, nil
}
func (implementation testImplementation) ValidateCanonical(ctx context.Context, destination protocol.Destination) error {
	meaning, err := implementation.NormalizeDestination(ctx, destination.CanonicalSettings)
	if err != nil || meaning.ConfigContractID != destination.ConfigContractID || meaning.ServiceContractID != destination.ServiceContractID || !bytes.Equal(meaning.CanonicalSettings, destination.CanonicalSettings) || meaning.Capabilities != destination.Capabilities || meaning.Policy.ContractID != destination.Policy.ContractID || !bytes.Equal(meaning.Policy.Data, destination.Policy.Data) {
		return protocol.ErrProtocol
	}
	return nil
}
func (implementation testImplementation) InterpretTarget(ctx context.Context, request output.TargetRequest) (protocol.Target, error) {
	if err := implementation.ValidateCanonical(ctx, request.Destination); err != nil {
		return protocol.Target{}, err
	}
	var input settings
	if json.Unmarshal(request.Destination.CanonicalSettings, &input) != nil {
		return protocol.Target{}, protocol.ErrProtocol
	}
	slot := input.Prefix + "/" + request.EntryName
	if input.Prefix == "deny-scope-cleanup" {
		if err := denyExecutableCleanup(); err != nil {
			return protocol.Target{}, err
		}
	}
	if input.Prefix == "collision-and-deny-scope-cleanup" {
		slot = "collision/value"
		if request.EntryName == "secret" {
			if err := denyExecutableCleanup(); err != nil {
				return protocol.Target{}, err
			}
		}
	}
	if request.EntryName == "private-workspace" {
		marker, err := os.OpenFile(".entered-workspace", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return protocol.Target{}, err
		}
		if err := marker.Close(); err != nil {
			return protocol.Target{}, err
		}
		slot += "/" + strconv.Itoa(os.Getpid())
	}
	return protocol.Target{ServiceContractID: request.Destination.ServiceContractID, TargetContractID: "test-output/target/v1", CanonicalTarget: slot, ConsumerLocator: slot,
		TargetData: []byte("public"), PayloadEncoding: request.PayloadEncoding, Capabilities: request.Destination.Capabilities, CreateValueBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}, WriteValueBounds: protocol.PayloadBounds{Maximum: protocol.MaximumPayloadBytes}}, nil
}

func denyExecutableCleanup() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return os.Chmod(filepath.Dir(filepath.Dir(executable)), 0500)
}

func (testImplementation) ValidateCredential(b []byte) error {
	if bytes.HasPrefix(b, []byte("test-result-")) {
		switch string(b) {
		case "test-result-exit66":
			refusalMode = "result-exit66"
		case "test-result-trailing-byte":
			refusalMode = "result-trailing-byte"
		case "test-result-sleep-after-close":
			refusalMode = "result-sleep-after-close"
		case "test-result-create-without-resource":
			refusalMode = "result-create-without-resource"
		default:
			return protocol.ErrProtocol
		}
		return nil
	}
	if bytes.Equal(b, []byte("test-exit-before-ready")) {
		// Test-only child failure at the same boundary as a refusal. The host
		// must not treat a nonzero process exit as valid credential evidence.
		os.Exit(66)
	}
	if bytes.HasPrefix(b, []byte("test-refuse-")) {
		switch string(b) {
		case "test-refuse-exit66":
			refusalMode = "exit66"
		case "test-refuse-exit17":
			refusalMode = "exit17"
		case "test-refuse-malformed":
			refusalMode = "malformed"
		case "test-refuse-wrong-correlation":
			refusalMode = "wrong-correlation"
		case "test-refuse-nonzero-body":
			refusalMode = "nonzero-body"
		case "test-refuse-trailing-byte":
			refusalMode = "trailing-byte"
		case "test-refuse-duplicate-frame":
			refusalMode = "duplicate-frame"
		case "test-refuse-cleanup":
			refusalMode = "cleanup"
			if err := os.Chmod("..", 0500); err != nil {
				return err
			}
		default:
			return protocol.ErrProtocol
		}
		return protocol.ErrProtocol
	}
	if !bytes.Equal(b, []byte("private credential")) {
		return protocol.ErrProtocol
	}
	return nil
}

func (testImplementation) CheckAction(ctx context.Context, request output.ActionCheck, policy protocol.Policy) (protocol.PayloadBounds, error) {
	if request.Target.CanonicalTarget == "deny-cleanup" || request.Target.CanonicalTarget == "deny-cleanup-sleep" || request.Target.CanonicalTarget == "deny-cleanup-public-sleep" {
		if err := os.Chmod("..", 0500); err != nil {
			return protocol.PayloadBounds{}, err
		}
	}
	if request.Target.CanonicalTarget == "public-sleep" || request.Target.CanonicalTarget == "deny-cleanup-public-sleep" {
		<-ctx.Done()
		return protocol.PayloadBounds{}, ctx.Err()
	}
	if !request.Action.Valid() || !request.Target.Valid() || !policy.Valid() {
		return protocol.PayloadBounds{}, protocol.ErrProtocol
	}
	if request.Action < protocol.ActionDeleteOwned {
		if !testPolicy(policy) {
			return protocol.PayloadBounds{}, protocol.ErrProtocol
		}
	} else if policy.Present() || len(policy.Data) != 0 {
		return protocol.PayloadBounds{}, protocol.ErrProtocol
	}
	if request.OwnershipMode == protocol.OwnershipQualified && !strings.HasPrefix(request.OwnedInstance, "test-instance/"+request.Target.CanonicalTarget+"/") {
		return protocol.PayloadBounds{}, protocol.ErrProtocol
	}
	if request.Action == protocol.ActionCreateWithValue {
		return request.Target.CreateValueBounds, nil
	}
	if request.Action == protocol.ActionWriteValue {
		return request.Target.WriteValueBounds, nil
	}
	return protocol.PayloadBounds{}, nil
}

type prepared struct {
	command    output.Preparation
	policy     protocol.Policy
	credential []byte
}

func (implementation testImplementation) Prepare(ctx context.Context, command output.Preparation, policy protocol.Policy, inputs []credentialroute.Input) (output.Prepared, error) {
	if len(inputs) != 1 || inputs[0].Name != "ENKV_OUTPUT_TEST_CREDENTIAL" || !inputs[0].Present {
		return nil, protocol.ErrProtocol
	}
	if err := implementation.ValidateCredential(inputs[0].Value); err != nil {
		return nil, err
	}
	return &prepared{command: command, policy: policy, credential: inputs[0].Value}, nil
}
func (p *prepared) Send(ctx context.Context, payload []byte) (output.Outcome, error) {
	return (testImplementation{}).Execute(ctx, p.command, p.policy, payload, p.credential)
}
func (*prepared) Close() error { return nil }

func (testImplementation) Execute(ctx context.Context, command output.Preparation, policy protocol.Policy, payload, credential []byte) (output.Outcome, error) {
	if command.Target.CanonicalTarget == "sleep" || strings.HasPrefix(command.Target.CanonicalTarget, "plain-target-sleep-") || command.Target.CanonicalTarget == "deny-cleanup-sleep" {
		// A staged test-only marker proves the private child reached Execute
		// after Ready and payload delivery before the parent cancels it.
		if err := os.WriteFile(".entered-execute", nil, 0600); err != nil {
			return output.Outcome{}, err
		}
		<-ctx.Done()
		return output.Outcome{}, ctx.Err()
	}
	if !bytes.Equal(credential, []byte("private credential")) && !strings.HasPrefix(refusalMode, "result-") {
		return output.Outcome{}, protocol.ErrProtocol
	}
	value := command.Action == protocol.ActionCreateWithValue || command.Action == protocol.ActionWriteValue
	if value {
		expected, encoded := []byte("private data"), []byte("cHJpdmF0ZSBkYXRh")
		switch {
		// These three slots keep the same application bytes across the raw,
		// Base64, raw chain. Fixed wire literals are independent of the encoder.
		case command.Target.CanonicalTarget == "plain-encoding-target":
		case command.Target.CanonicalTarget == "secret-encoding-target":
			expected, encoded = []byte("enkv first secret test value"), []byte("ZW5rdiBmaXJzdCBzZWNyZXQgdGVzdCB2YWx1ZQ==")
		case command.Target.CanonicalTarget == "generated-encoding-target":
			expected, encoded = []byte("Generated_secret_0123456789_ABCDEFGHIJKLMN"), []byte("R2VuZXJhdGVkX3NlY3JldF8wMTIzNDU2Nzg5X0FCQ0RFRkdISUpLTE1O")
		case strings.HasPrefix(command.Target.CanonicalTarget, "secret-target"):
			expected, encoded = []byte("enkv first secret test value"), []byte("ZW5rdiBmaXJzdCBzZWNyZXQgdGVzdCB2YWx1ZQ==")
			if command.Action == protocol.ActionWriteValue {
				expected, encoded = []byte("enkv other secret test value"), []byte("ZW5rdiBvdGhlciBzZWNyZXQgdGVzdCB2YWx1ZQ==")
			}
		case strings.HasPrefix(command.Target.CanonicalTarget, "plain-target"):
			if command.Action == protocol.ActionWriteValue {
				expected, encoded = []byte("updated plain data"), []byte("dXBkYXRlZCBwbGFpbiBkYXRh")
			}
		case command.Target.CanonicalTarget == "empty-value":
			expected, encoded = nil, nil
		}
		if command.Target.PayloadEncoding == protocol.EncodingBase64 {
			expected = encoded
		}
		if !bytes.Equal(payload, expected) {
			return output.Outcome{}, protocol.ErrProtocol
		}
	} else if len(payload) != 0 {
		return output.Outcome{}, protocol.ErrProtocol
	}
	if command.Action < protocol.ActionDeleteOwned && !testPolicy(policy) {
		return output.Outcome{}, protocol.ErrProtocol
	}
	status, resource := uint16(204), command.OwnedInstance
	switch command.Action {
	case protocol.ActionCreateEmpty, protocol.ActionCreateWithValue:
		status, resource = 201, testInstance(command.Target.CanonicalTarget, command.AttemptID)
	case protocol.ActionWriteValue, protocol.ActionUpdatePolicy, protocol.ActionDeleteOwned:
		if !testOwnedInstance(command.Target.CanonicalTarget, command.OwnedInstance) {
			return output.Outcome{}, protocol.ErrProtocol
		}
	case protocol.ActionDeleteReservedSlot:
		resource = command.Target.CanonicalTarget
	default:
		return output.Outcome{}, protocol.ErrProtocol
	}
	result := output.Outcome{}
	result.Entry, result.Class = protocol.EntryMayHaveEntered, protocol.ClassAcknowledged
	result.NormalizedStatus, result.SafeResourceID = status, resource
	if command.Action == protocol.ActionCreateEmpty || command.Action == protocol.ActionCreateWithValue {
		if command.Target.LocatorRequiresCreation {
			result.AssignedLocator = "test-consumer/" + resource
		}
	}
	switch {
	case strings.Contains(command.Target.CanonicalTarget, "-unknown-"):
		result.Class, result.NormalizedStatus, result.SafeResourceID, result.AssignedLocator = protocol.ClassUnproved, 0, "", ""
	case strings.Contains(command.Target.CanonicalTarget, "-unqualified-") && command.Action == protocol.ActionCreateWithValue:
		result.SafeResourceID = ""
	}
	if strings.Contains(command.Target.CanonicalTarget, "-cleanup-failure-") {
		if err := os.Chmod("..", 0500); err != nil {
			return output.Outcome{}, err
		}
	}
	return result, nil
}

func testInstance(slot string, birth protocol.ID) string {
	return "test-instance/" + slot + "/" + hex.EncodeToString(birth[:])
}

func testPolicy(policy protocol.Policy) bool {
	return policy.ContractID == "test-policy" && (bytes.Equal(policy.Data, []byte("1,9")) || bytes.Equal(policy.Data, []byte("7,11")) || bytes.Equal(policy.Data, []byte("1")))
}

func main() {
	if endpointHold != "" {
		serveRetainedEndpoint()
		return
	}
	binding, err := output.Bind(descriptorJSON, "test-output/config/v1")
	if err != nil {
		os.Exit(2)
	}
	implementation := testImplementation{Binding: binding}

	if exitBeforeHello == "1" {
		os.Exit(17)
	}
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	if os.Args[1] == "output-public-v3" {
		control, result := os.NewFile(3, "control"), os.NewFile(4, "result")
		status := output.RunPublic(context.Background(), output.PublicEndpoints{Control: control, Result: &publicTestWriter{file: result}}, implementation)
		if !closeEndpoints(control, result) || status != 0 || publicFailureMode == "process-failure" {
			os.Exit(1)
		}
		return
	}
	if os.Args[1] != "output-wire-v6" {
		os.Exit(2)
	}
	control, credential, payload, result := os.NewFile(3, "control"), os.NewFile(4, "credential"), os.NewFile(5, "payload"), os.NewFile(6, "result")
	writer := &refusalTestWriter{file: result}
	status := output.Run(context.Background(), output.Endpoints{Control: control, Credential: credential, Payload: payload, Result: writer}, implementation)
	if status == 0 {
		var faultErr error
		switch refusalMode {
		case "trailing-byte", "result-trailing-byte":
			_, faultErr = result.Write([]byte{1})
		case "duplicate-frame":
			faultErr = protocol.WriteFrame(result, protocol.Frame{Kind: protocol.KindPreparationRefused, CorrelationID: writer.correlation})
		}
		if faultErr != nil {
			status = 1
		}
	}
	if !closeEndpoints(control, credential, payload, result) || status != 0 {
		os.Exit(1)
	}
	if refusalMode == "exit66" || refusalMode == "result-exit66" {
		os.Exit(66)
	}
	if refusalMode == "exit17" {
		os.Exit(17)
	}
	if refusalMode == "result-sleep-after-close" {
		time.Sleep(10 * time.Second)
	}
}

func testOwnedInstance(slot, instance string) bool {
	prefix := "test-instance/" + slot + "/"
	if !strings.HasPrefix(instance, prefix) {
		return false
	}
	encoded := strings.TrimPrefix(instance, prefix)
	birth, err := hex.DecodeString(encoded)
	return err == nil && len(birth) == 32 && encoded == hex.EncodeToString(birth) && !bytes.Equal(birth, make([]byte, 32))
}

func serveRetainedEndpoint() {
	passive := len(os.Args) == 2 && os.Args[1] == "output-public-v3"
	control, result := os.NewFile(3, "control"), os.NewFile(6, "result")
	if passive {
		result = os.NewFile(4, "public result")
	}
	hello, err := protocol.ReadFrame(control, protocol.HelloBytes)
	if err != nil || hello.Kind != protocol.KindHello {
		os.Exit(50)
	}
	if protocol.WriteFrame(result, protocol.Frame{Kind: protocol.KindHelloAck, CorrelationID: hello.CorrelationID, Body: hello.Body}) != nil {
		os.Exit(51)
	}
	if endpointHold == "control" {
		retainOutputEndpoint(control, passive)
	}
	request, err := protocol.ReadFrame(control, protocol.MaximumPublicRequestBytes)
	if err != nil {
		os.Exit(52)
	}
	policy, err := protocol.ReadFrame(control, protocol.MaximumPolicyBytes)
	if err != nil || policy.Kind != protocol.KindPolicy || protocol.RequireEOF(control) != nil {
		os.Exit(53)
	}
	var body []byte
	kind := protocol.KindResult
	if passive {
		digest, err := protocol.PublicRequestDigest(hello.CorrelationID, request.Kind, request.Body, policy.Body)
		if err != nil {
			os.Exit(55)
		}
		if request.Kind == protocol.KindPolicyActionRequest {
			if _, err := protocol.DecodePolicyActionRequest(request.Body); err != nil {
				os.Exit(54)
			}
			kind = protocol.KindPolicyActionResult
			body, err = protocol.EncodePolicyActionResult(protocol.PolicyActionResult{Schema: 1, RequestDigest: digest, Accepted: true, Action: protocol.ActionUpdatePolicy})
		} else {
			var check protocol.ActionCheckRequest
			check, err = protocol.DecodeActionCheckRequest(request.Body)
			if err != nil {
				os.Exit(54)
			}
			kind = protocol.KindActionCheckResult
			body, err = protocol.EncodeActionCheckResult(protocol.ActionCheckResult{Schema: 1, RequestDigest: digest, Accepted: true, PayloadBounds: check.Target.CreateValueBounds})
		}
		if err != nil {
			os.Exit(56)
		}
	} else {
		credential, payload := os.NewFile(4, "credential"), os.NewFile(5, "payload")
		if endpointHold == "credential" {
			retainOutputEndpoint(credential, false)
		}
		if _, err := protocol.ReadFrame(credential, protocol.MaximumCredentialBytes); err != nil || protocol.RequireEOF(credential) != nil {
			os.Exit(57)
		}
		if endpointHold == "refusal-eof" {
			if protocol.WriteFrame(result, protocol.Frame{Kind: protocol.KindPreparationRefused, CorrelationID: hello.CorrelationID}) != nil {
				os.Exit(58)
			}
			retainOutputEndpoint(result, false)
		}
		if protocol.WriteFrame(result, protocol.Frame{Kind: protocol.KindReadyForPayload, CorrelationID: hello.CorrelationID}) != nil {
			os.Exit(59)
		}
		if endpointHold == "payload" {
			retainOutputEndpoint(payload, false)
		}
		if _, err := protocol.ReadFrame(payload, protocol.MaximumPayloadBytes); err != nil || protocol.RequireEOF(payload) != nil {
			os.Exit(60)
		}
		command, err := protocol.DecodeCommand(request.Body)
		if err != nil {
			os.Exit(61)
		}
		response := command.NewResult()
		response.Entry, response.Class, response.NormalizedStatus, response.SafeResourceID = protocol.EntryMayHaveEntered, protocol.ClassAcknowledged, 201, "test-held-resource"
		response.ConsumerLocator = command.Target.ConsumerLocator
		body, err = protocol.EncodeResult(response)
		if err != nil {
			os.Exit(62)
		}
	}
	switch endpointHold {
	case "result-eof":
		if protocol.WriteFrame(result, protocol.Frame{Kind: kind, CorrelationID: hello.CorrelationID, Body: body}) != nil {
			os.Exit(63)
		}
	case "result-short":
		if _, err := result.Write([]byte{1}); err != nil {
			os.Exit(64)
		}
	}
	retainOutputEndpoint(result, passive)
}

func retainOutputEndpoint(file *os.File, passive bool) {
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: endpointSocket, Net: "unix"})
	if err != nil {
		os.Exit(65)
	}
	if _, _, err := connection.WriteMsgUnix([]byte{1}, syscall.UnixRights(int(file.Fd())), nil); err != nil {
		os.Exit(66)
	}
	last := 6
	if passive {
		last = 4
	}
	for fd := 3; fd <= last; fd++ {
		if syscall.Close(fd) != nil {
			os.Exit(67)
		}
	}
	if connection.Close() != nil {
		os.Exit(68)
	}
	os.Exit(0)
}

func (testImplementation) SelectPolicyAction(ctx context.Context, request output.PolicyActionSelection, policy protocol.Policy) (protocol.Action, error) {
	if ctx == nil || ctx.Err() != nil || request.DomainID.IsZero() || !request.Target.Valid() || request.HasPreviousPolicyDigest != !request.PreviousPolicyDigest.IsZero() || !testPolicy(policy) {
		return 0, protocol.ErrProtocol
	}
	return protocol.ActionUpdatePolicy, nil
}
