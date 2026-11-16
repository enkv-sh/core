package compositionfull

import (
	"encoding/hex"
	"enkv.sh/core/contract"
	"strings"
	"testing"
)

// full_only: false
func TestOutputManagedNamePremiseBindsExactRuntimeTarget(t *testing.T) {
	domain := contract.ID{1}
	target := contract.OutputTarget{ServiceContractID: "private-service/v7", TargetContractID: "private-target/v2",
		CanonicalTarget: "projects/123456789/secrets/ENKV_KEY", ConsumerLocator: "projects/123456789/secrets/ENKV_KEY/versions/latest", TargetData: []byte("plugin-owned"), PayloadEncoding: contract.OutputEncodingRaw}
	premise, err := configurationOutputPremise(domain, target)
	// Independently derived with Python hashlib.sha256: fixed ASCII rule label
	// including NUL, 01 followed by 31 zero domain bytes, then big-endian uint32
	// byte length plus ASCII bytes for the service contract and physical target.
	if err != nil || hex.EncodeToString(premise[:]) != "3e1adc98e5aa7dfea1e59ef1b0c7c4cdbf9fa78cacd041306105414ebd975f12" {
		t.Fatal("managed-name rule binding differs from its independent fixed preimage")
	}
	otherDomain, err := configurationOutputPremise(contract.ID{2}, target)
	if err != nil || otherDomain == premise {
		t.Fatal("managed-name rule did not bind the exact authenticated domain")
	}
	other := target
	other.CanonicalTarget, other.ConsumerLocator = "projects/987654321/secrets/ENKV_KEY", "projects/987654321/secrets/ENKV_KEY/versions/latest"
	otherTarget, err := configurationOutputPremise(domain, other)
	if err != nil || otherTarget == premise {
		t.Fatal("managed-name rule did not bind the runtime project and physical slot")
	}
	other = target
	other.EntryIncarnationID, other.PayloadEncoding = contract.ID{7}, contract.OutputEncodingBase64
	if unchanged, err := configurationOutputPremise(domain, other); err != nil || unchanged != premise {
		t.Fatal("payload representation was treated as an external managed-name premise")
	}
	for _, change := range []func(*contract.OutputTarget){
		func(v *contract.OutputTarget) { v.ServiceContractID = "other-service" },
		func(v *contract.OutputTarget) { v.CanonicalTarget = "other-target" },
	} {
		other = target
		change(&other)
		if digest, err := configurationOutputPremise(domain, other); err != nil || digest == premise {
			t.Fatal("semantic coordinate change reused the managed-name premise", err)
		}
	}
	for _, change := range []func(*contract.OutputTarget){
		func(v *contract.OutputTarget) { v.TargetContractID = "other-contract" },
		func(v *contract.OutputTarget) { v.TargetData = []byte("other plugin data") },
		func(v *contract.OutputTarget) { v.ConsumerLocator = "other-consumer" },
	} {
		other = target
		change(&other)
		if digest, err := configurationOutputPremise(domain, other); err != nil || digest != premise {
			t.Fatal("a non-coordinate fact changed the managed-name premise", err)
		}
	}
	if digest, err := configurationOutputPremise(contract.ID{}, target); err == nil || !digest.IsZero() {
		t.Fatal("absent authenticated domain supplied a premise")
	}
}

// full_only: false
func TestPublicationDeletionPluginSelectionIsExactAndOwned(t *testing.T) {
	first, second := contract.ID{1}, contract.ID{2}
	options := PublicationOptions{DeletePlugins: map[contract.ID]string{first: "local-custom"}}
	options.Request.DeleteCoordinates = []contract.ID{first}
	owned, err := ownPublicationOptions(options)
	if err != nil {
		t.Fatal(err)
	}
	options.DeletePlugins[first] = "changed"
	options.Request.DeleteCoordinates[0] = second
	if owned.DeletePlugins[first] != "local-custom" || owned.Request.DeleteCoordinates[0] != first {
		t.Fatal("caller mutated selected deletion plugin")
	}
	for _, choices := range []map[contract.ID]string{nil, {second: "local-custom"}, {first: "local-custom", second: "extra"}, {first: "../escape"}, {first: ""}} {
		options.Request.DeleteCoordinates = []contract.ID{first}
		options.DeletePlugins = choices
		if _, err := ownPublicationOptions(options); err == nil {
			t.Fatal("inexact deletion plugin choice accepted")
		}
	}
	options.Request.DeleteCoordinates = nil
	options.DeletePlugins = map[contract.ID]string{first: "local-custom"}
	if _, err := ownPublicationOptions(options); err == nil {
		t.Fatal("unused local plugin choice accepted")
	}
	tooMany := make(map[contract.ID]string)
	for i := 0; i < 1025; i++ {
		id := contract.Hash([]byte(strings.Repeat("x", i+1)))
		tooMany[id] = "local"
	}
	if _, err := ownDeletionPluginChoices(tooMany); err == nil {
		t.Fatal("over-limit local choices copied")
	}
}
