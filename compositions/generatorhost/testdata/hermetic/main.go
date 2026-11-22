// Command hermetic supplies controlled generator replies and lifecycle faults for host tests.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
	"golang.org/x/sys/unix"
)

var mode = "success"

func main() {
	if mode == "sdk" {
		os.Exit(runSDK())
	}
	if mode == "high-fd-sentinel" {
		if err := unix.Dup2(3, 300); err != nil {
			os.Exit(19)
		}
	}
	if len(os.Args) != 2 || os.Args[1] != "generator-wire-v5" || len(os.Environ()) != 0 || !fixedDescriptors() {
		os.Exit(20)
	}
	control := os.NewFile(3, "control")
	credential := os.NewFile(4, "credential")
	secret := os.NewFile(5, "secret")
	status := os.NewFile(6, "status")
	defer control.Close()
	defer credential.Close()
	defer secret.Close()
	defer status.Close()
	helloFrame, err := protocol.ReadFrame(control, protocol.HelloBodyLength)
	if err != nil || helloFrame.Kind != protocol.KindHello {
		os.Exit(21)
	}
	hello, err := protocol.DecodeHello(helloFrame.Body)
	if err != nil {
		os.Exit(22)
	}
	if mode == "hold-handshake" || mode == "hold-handshake-short" {
		if mode == "hold-handshake-short" {
			_, _ = status.Write([]byte{1})
		}
		retainEndpoint(status)
	}
	if mode == "hang-handshake" {
		time.Sleep(30 * time.Second)
	}
	if mode == "bad-handshake" {
		hello.DescriptorID[0] ^= 1
	}
	body, _ := protocol.EncodeHello(hello)
	if protocol.WriteFrame(status, protocol.Frame{Kind: protocol.KindHelloAck, CommandID: helloFrame.CommandID, Body: body}) != nil {
		os.Exit(23)
	}
	if mode == "exit-after-handshake" {
		os.Exit(24)
	}
	if mode == "hold-control" {
		retainEndpoint(control)
	}
	frame, err := protocol.ReadFrame(control, protocol.MaximumPublicBody)
	if err == nil && frame.Kind != protocol.KindCommand {
		servePublic(frame, helloFrame.CommandID, control, credential, secret, status)
		return
	}
	commandBody := frame.Body
	if err == nil && frame.CommandID != helloFrame.CommandID {
		err = protocol.ErrProtocol
	}
	if err != nil {
		os.Exit(27)
	}
	command, err := protocol.DecodeCommand(commandBody)
	if err != nil || protocol.RequireEOF(control) != nil {
		os.Exit(28)
	}
	if mode == "command-refusal" {
		body, err := protocol.EncodeStatus(protocol.Status{Stage: protocol.StatusStageCommand, Category: protocol.StatusUnavailable})
		if err != nil || protocol.WriteFrame(status, protocol.Frame{Kind: protocol.KindStatus, CommandID: frame.CommandID, Body: body}) != nil {
			os.Exit(32)
		}
		os.Exit(29)
	}
	if mode == "hold-credential" {
		retainEndpoint(credential)
	}
	credentialBody, err := protocol.ReadExpectedFrame(credential, protocol.KindEnvironment, helloFrame.CommandID, protocol.MaximumEnvironmentBody)
	if err != nil {
		os.Exit(25)
	}
	route := credentialroute.Route{Schema: 1, ContractID: [32]byte{1}, Mode: credentialroute.ModeEnvironment, Names: []string{"ENKV_GENERATOR_TEST_TOKEN"}}
	inputs, err := credentialroute.DecodeInputs(route, credentialBody)
	if err != nil || protocol.RequireEOF(credential) != nil {
		os.Exit(26)
	}
	privateValue := inputs[0].Value
	if mode == "environment-credential" && !bytes.Equal(privateValue, []byte("private ordinary token, no provider grammar")) {
		os.Exit(40)
	}
	clear(privateValue)
	if mode == "hang" {
		time.Sleep(30 * time.Second)
	}
	if mode == "exit-after-command" {
		os.Exit(29)
	}
	if mode == "delay" {
		time.Sleep(5 * time.Second)
	}
	if mode == "stdout-stderr" {
		_, _ = os.Stdout.Write([]byte("stdout sentinel must be discarded"))
		_, _ = os.Stderr.Write([]byte("stderr sentinel must be discarded"))
	}
	intent := generatorIntentDigest(command.Intent)
	if command.Action == 1 && protocol.ID(intent) != command.IntentDigest {
		os.Exit(38)
	}
	token := sha256.Sum256(append([]byte("hermetic token\x00"), command.ResultID[:]...))
	facts := command.NewFacts(protocol.DispositionCompleteCreate, protocol.ReasonNone)
	if command.LifecycleMode == protocol.LifecycleManaged {
		facts.Target = []byte("hermetic-account")
		facts.ResourceData = []byte(hex.EncodeToString(token[:16]))
	}
	if mode == "deadline-cap" {
		facts.ProviderFacts = binary.BigEndian.AppendUint64(nil, command.DeadlineUnixMillis)
	}
	value := []byte("enkv_" + hex.EncodeToString(token[:24]))
	if command.Action == protocol.ActionCreate {
		declared, err := protocol.DecodeIntent(command.Intent)
		if err == nil && bytes.Equal(declared.Settings, []byte(`{"maximum_result":true}`)) {
			facts.ProviderFacts = make([]byte, 4096-115-len(facts.Target)-len(facts.ResourceData))
			value = base64.StdEncoding.AppendEncode(nil, bytes.Repeat([]byte{0xfb}, 65_536))
		}
	}
	if mode == "memory-measurement" {
		runtime.GC()
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		value = make([]byte, 32)
		copy(value, "ENKVMEM1")
		binary.BigEndian.PutUint64(value[8:16], memory.HeapAlloc)
		binary.BigEndian.PutUint64(value[16:24], memory.HeapSys)
		binary.BigEndian.PutUint64(value[24:32], memory.Sys)
	}
	returned := command.NewResult(facts, value)
	if command.Action == protocol.ActionRetire {
		original, err := protocol.DecodeSafeFacts(command.OriginalFacts)
		if err != nil {
			os.Exit(28)
		}
		returned.SafeFacts = command.NewFacts(protocol.DispositionRetirementAcknowledged, protocol.ReasonNone)
		returned.SafeFacts.Target = original.Target
		returned.SafeFacts.ResourceData = original.ResourceData
		returned.Value = nil
	}
	switch mode {
	case "owned-unusable":
		returned.SafeFacts.Disposition, returned.SafeFacts.Reason = 2, 1
		returned.Value = nil
	case "wrong-result":
		returned.ResultID[0] ^= 1
	case "wrong-result-contract":
		returned.ResultContractID[0] ^= 1
	case "wrong-producer":
		returned.ExecutorID[0] ^= 1
	case "wrong-safe-facts":
		returned.SafeFacts.RequestDigest[0] ^= 1
	}
	result, err := protocol.EncodeResult(returned)
	defer clear(value)
	defer clear(result)
	if err != nil {
		os.Exit(30)
	}
	if mode == "wrong-attempt" {
		result[0] ^= 1
	}
	if mode == "overlength-result" {
		header := make([]byte, protocol.HeaderLength)
		copy(header[:4], "ENKG")
		binary.BigEndian.PutUint16(header[4:6], protocol.Version)
		header[6] = protocol.KindResult
		copy(header[7:39], helloFrame.CommandID[:])
		binary.BigEndian.PutUint32(header[39:43], protocol.MaximumResultBody+1)
		_, _ = secret.Write(header)
		os.Exit(33)
	}
	if mode == "truncated-result" {
		var encoded bytes.Buffer
		_ = protocol.WriteFrame(&encoded, protocol.Frame{Kind: protocol.KindResult, CommandID: helloFrame.CommandID, Body: result})
		_, _ = secret.Write(encoded.Bytes()[:encoded.Len()-1])
		os.Exit(34)
	}
	resultCommand := helloFrame.CommandID
	switch mode {
	case "execution-failure", "execution-failure-trailing", "execution-failure-foreign", "execution-failure-short":
		body, _ := protocol.EncodeStatus(protocol.Status{Stage: 3, Category: 2})
		statusID := helloFrame.CommandID
		if mode == "execution-failure-foreign" {
			statusID[0] ^= 1
		}
		if mode == "execution-failure-short" {
			body = body[:1]
		}
		if protocol.WriteFrame(status, protocol.Frame{Kind: protocol.KindStatus, CommandID: statusID, Body: body}) != nil {
			os.Exit(32)
		}
		if mode == "execution-failure-trailing" {
			_, _ = status.Write([]byte{0})
		}
		os.Exit(29)
	}
	if mode == "wrong-command" {
		resultCommand[0] ^= 1
	}
	if protocol.WriteFrame(secret, protocol.Frame{Kind: protocol.KindResult, CommandID: resultCommand, Body: result}) != nil {
		os.Exit(31)
	}
	if mode == "return-cancel-race" {
		if secret.Close() != nil || os.WriteFile(filepath.Join(".", ".enkv-hermetic-result-ready"), []byte("ready"), 0600) != nil {
			os.Exit(40)
		}
		limit := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(filepath.Join(".", ".enkv-hermetic-release-result")); err == nil {
				break
			}
			if time.Now().After(limit) {
				os.Exit(41)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if mode == "stall-after-result" {
		_ = secret.Close()
		time.Sleep(30 * time.Second)
	}
	if mode == "duplicate-result" {
		if protocol.WriteFrame(secret, protocol.Frame{Kind: protocol.KindResult, CommandID: resultCommand, Body: result}) != nil {
			os.Exit(35)
		}
	}
	if mode == "exit-after-result" {
		os.Exit(36)
	}
	if mode == "hold-status" || mode == "hold-status-short" {
		if mode == "hold-status-short" {
			_, _ = status.Write([]byte{1})
		}
		retainEndpoint(status)
	}
	finalStatus := protocol.Status{Stage: 5, Category: 0}
	if mode == "failure-status" {
		finalStatus.Category = 1
	}
	statusBody, _ := protocol.EncodeStatus(finalStatus)
	if protocol.WriteFrame(status, protocol.Frame{Kind: protocol.KindStatus, CommandID: helloFrame.CommandID, Body: statusBody}) != nil {
		os.Exit(32)
	}
	if mode == "hold-status-eof" {
		retainEndpoint(status)
	}
	if mode == "duplicate-status" {
		if protocol.WriteFrame(status, protocol.Frame{Kind: protocol.KindStatus, CommandID: helloFrame.CommandID, Body: statusBody}) != nil {
			os.Exit(37)
		}
	}
}

func generatorIntentDigest(value []byte) protocol.ID {
	id, err := protocol.IntentDigest(value)
	if err != nil {
		return protocol.ID{}
	}
	return id
}

func fixedDescriptors() bool {
	for _, fd := range []int{0, 1, 2} {
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFCHR {
			return false
		}
	}
	for fd, want := range map[int]int{3: unix.O_RDONLY, 4: unix.O_RDONLY, 5: unix.O_WRONLY, 6: unix.O_WRONLY} {
		var stat unix.Stat_t
		statErr := unix.Fstat(fd, &stat)
		flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if statErr != nil || flagErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != want {
			return false
		}
	}
	directory, err := os.Open("/dev/fd")
	if err != nil {
		return false
	}
	names, err := directory.Readdirnames(-1)
	_ = directory.Close()
	if err != nil {
		return false
	}
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err == nil && fd >= 7 {
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			if err == nil && flags&unix.FD_CLOEXEC == 0 || err != nil && err != unix.EBADF {
				return false
			}
		}
	}
	cwd, cwdErr := os.Getwd()
	executable, executableErr := os.Executable()
	installed, installedErr := os.Stat(filepath.Join(cwd, "generator"))
	return cwdErr == nil && executableErr == nil && installedErr == nil && installed.Mode().IsRegular() &&
		filepath.Dir(executable) != cwd && (runtime.GOOS == "darwin" || runtime.GOOS == "linux")
}

func servePublic(frame protocol.Frame, id protocol.ID, control, environment, secret, status *os.File) {
	if protocol.RequireEOF(control) != nil || protocol.RequireEOF(environment) != nil {
		os.Exit(28)
	}
	if frame.CommandID != id {
		os.Exit(28)
	}
	var body []byte
	var err error
	accepted := mode != "public-refused" && mode != "public-wrong-digest"
	kind := protocol.KindNormalized
	switch frame.Kind {
	case protocol.KindNormalize:
		request, decodeErr := protocol.DecodeNormalizeRequest(frame.Body)
		if decodeErr != nil {
			os.Exit(28)
		}
		input := request.InputDigest
		if mode == "public-wrong-digest" {
			input[0] ^= 1
		}
		var intent []byte
		if accepted {
			intent, err = protocol.EncodeIntent(protocol.Intent{Schema: 1, ConfigContractID: request.ConfigContractID, LifecycleMode: protocol.LifecycleManaged, ResourceContractID: protocol.ID(sha256.Sum256([]byte{22})), Settings: bytes.Clone(request.Settings)})
			if err != nil {
				os.Exit(30)
			}
		}
		body, err = protocol.EncodeNormalizeResponse(protocol.NormalizeResponse{Schema: 1, InputDigest: input, Accepted: accepted, Intent: intent})
	case protocol.KindValidateCanonical:
		request, decodeErr := protocol.DecodeCanonicalRequest(frame.Body)
		if decodeErr != nil {
			os.Exit(28)
		}
		input := request.InputDigest
		if mode == "public-wrong-digest" {
			input[0] ^= 1
		}
		kind = protocol.KindCanonicalValidation
		body, err = protocol.EncodeValidationResponse(protocol.ValidationResponse{Schema: 1, InputDigest: input, Accepted: accepted})
	case protocol.KindRetirementCompatibility:
		request, decodeErr := protocol.DecodeRetirementCompatibilityRequest(frame.Body)
		if decodeErr != nil {
			os.Exit(28)
		}
		input := request.InputDigest
		if mode == "public-wrong-digest" {
			input[0] ^= 1
		}
		kind = protocol.KindRetirementCompatibilityResult
		body, err = protocol.EncodeValidationResponse(protocol.ValidationResponse{Schema: 1, InputDigest: input, Accepted: accepted})
	default:
		os.Exit(28)
	}
	if err != nil {
		os.Exit(30)
	}
	if mode == "hold-public-result" || mode == "hold-public-result-short" {
		if mode == "hold-public-result-short" {
			_, _ = secret.Write([]byte{1})
		}
		retainEndpoint(secret)
	}
	if protocol.WriteFrame(secret, protocol.Frame{Kind: kind, CommandID: id, Body: body}) != nil {
		os.Exit(31)
	}
	if mode == "hold-public-result-eof" {
		retainEndpoint(secret)
	}
	if mode == "public-trailing" {
		if _, err := secret.Write([]byte{0}); err != nil {
			os.Exit(31)
		}
	}
	body, err = protocol.EncodeStatus(protocol.Status{Stage: protocol.StatusStageReturn, Category: protocol.StatusOK})
	if err != nil || protocol.WriteFrame(status, protocol.Frame{Kind: protocol.KindStatus, CommandID: id, Body: body}) != nil {
		os.Exit(32)
	}
}

// retainEndpoint transfers only the selected opposite pipe end to the test.
// No descendant or service owns the retained descriptor.
func retainEndpoint(file *os.File) {
	path, err := os.ReadFile(".endpoint-socket")
	if err != nil {
		os.Exit(50)
	}
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: string(path), Net: "unix"})
	if err != nil {
		os.Exit(51)
	}
	if _, _, err := connection.WriteMsgUnix([]byte{1}, syscall.UnixRights(int(file.Fd())), nil); err != nil {
		os.Exit(52)
	}
	for fd := 3; fd <= 6; fd++ {
		if syscall.Close(fd) != nil {
			os.Exit(53)
		}
	}
	if connection.Close() != nil {
		os.Exit(54)
	}
	os.Exit(0)
}
