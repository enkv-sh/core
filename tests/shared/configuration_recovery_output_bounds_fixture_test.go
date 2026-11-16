package core

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/crypto/testsupport/installedarchive"
)

func configurationRecoveryOutputBoundsFixture(t *testing.T, ctx context.Context, input configurationRecoveryFixtureInput, env fixtureEnvironment, selected *StateSession, keys *custody.Fixture) {
	t.Helper()
	if input.Provider != "aws" || input.Recovery {
		t.Fatal("output bounds fixture requires its plain AWS setup")
	}
	policy := contract.OutputPolicy{ContractID: "p", Data: bytes.Repeat([]byte{7}, 516098)}
	capabilities := contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot
	binding := outputApplyBinding{destinationID: "d", destination: contract.OutputDestination{ConfigContractID: "c", ServiceContractID: "s", CanonicalSettings: []byte(`{}`), Policy: policy, Capabilities: capabilities}, targetsComplete: true}
	var entries []ApplyEntryInput
	var values []installedarchive.ExpectedValue
	for i := 0; i < 64; i++ {
		suffix := strconv.Itoa(100 + i)[1:]
		name := strings.Repeat("é", 127) + suffix
		entries = append(entries, ApplyEntryInput{Name: name, Recipients: []contract.ID{selected.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingBase64})
		values = append(values, installedarchive.ExpectedValue{Name: name, Bytes: []byte{}})
		target := contract.OutputTarget{ServiceContractID: "s", TargetContractID: "t", CanonicalTarget: "t" + suffix, PayloadEncoding: contract.OutputEncodingBase64, LocatorRequiresCreation: true, Policy: policy, Capabilities: capabilities}
		if i == 0 {
			target.TargetData = bytes.Repeat([]byte{11}, 2161)
		}
		binding.targets = append(binding.targets, outputApplyTarget{entryName: name, target: target})
	}
	output := &outputApplyInput{bindings: []outputApplyBinding{binding}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"d"}}}}
	selected = selectAdmittedOutputConfiguration(t, ctx, selected, env, keys, entries, output)
	if selected.root.OutputConfiguration.TotalLength != 33554446 || selected.root.OutputConfiguration.RoutingLength != 10 || selected.root.OutputConfiguration.SliceCount != 33 {
		t.Fatal("independently dimensioned selected output image differs")
	}
	archive := configurationRecoveryArchive(t, env, selected, env.Store.(*memoryStore))
	installedarchive.WriteOutputBoundsFixture(t, input.Output, installedarchive.RecoveryFixture{Archive: archive, Values: values})
	var bodyBytes uint64
	for _, object := range archive.Objects {
		bodyBytes += uint64(len(object.Body))
	}
	t.Logf("output bounds fixture: objects=%d body_bytes=%d file_bytes=%d declaration_bytes=33554432 carrier_bytes=33571296 base64_bytes=44761728", len(archive.Objects), bodyBytes, archive.ObjectFileBytes)
}
