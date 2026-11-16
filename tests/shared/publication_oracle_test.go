package core

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// These preimages follow Formats directly. The test supplies its complete,
// fixed expected target and action; no publication codec or production digest
// helper supplies the expected bytes. Opaque identities are bound before Send.
func publicationExpectedHash(prefix string, body []byte) contract.ID {
	return sha256.Sum256(append([]byte(prefix+"\x00"), body...))
}
func publicationExpectedBlob(body, value []byte) []byte {
	body = binary.BigEndian.AppendUint32(body, uint32(len(value)))
	return append(body, value...)
}
func publicationExpectedCoordinate(domain contract.ID, provider, slot string) contract.ID {
	b := append([]byte(nil), domain[:]...)
	b = publicationExpectedBlob(b, []byte(provider))
	return publicationExpectedHash("ENKV/PUBLICATION/COORDINATE/v3", publicationExpectedBlob(b, []byte(slot)))
}

// The inputs are the caller's independently fixed canonical policy, including
// the distinction between none and an explicit empty set.
func publicationExpectedPolicy(policy contract.OutputPolicy) []byte {
	if policy.ContractID == "" && len(policy.Data) == 0 {
		return nil
	}
	b := binary.BigEndian.AppendUint16(nil, 3)
	b = publicationExpectedBlob(b, []byte(policy.ContractID))
	return publicationExpectedBlob(b, policy.Data)
}

func publicationExpectedProjection(t testing.TB, plan *publicationPlan, target publicationTargetPlan, action uint8, expectedTarget contract.OutputTarget, birthID, deletionRowDigest contract.ID) (contract.PublicationProjection, contract.ID, contract.ID) {
	t.Helper()
	if action < contract.PublicationCreateEmpty || action > contract.PublicationDeleteOwned {
		t.Fatal("publication oracle action is outside the fixed named lifecycle")
	}
	actual, expected := target.target, expectedTarget
	if action == contract.PublicationDeleteOwned {
		// Retained deletion inputs contain the exact identity, not a selected policy.
		expected.Policy = contract.OutputPolicy{}
		expected.Capabilities = contract.OutputCapabilityDeleteOwned
		expected.CreateValueBounds, expected.WriteValueBounds = contract.OutputPayloadBounds{}, contract.OutputPayloadBounds{}
		if expected.LocatorRequiresCreation {
			expected.ConsumerLocator = ""
		}
		if birthID.IsZero() || deletionRowDigest.IsZero() {
			t.Fatal("publication oracle lacks qualified deletion inputs")
		}
	}
	if !reflect.DeepEqual(actual, expected) || target.coordinate != publicationExpectedCoordinate(plan.session.root.Domain, expectedTarget.ServiceContractID, expectedTarget.CanonicalTarget) {
		t.Fatal("publication planned target differs from complete fixed target")
	}
	if action == contract.PublicationWriteValue || action == contract.PublicationUpdatePolicy {
		if birthID.IsZero() {
			t.Fatal("publication oracle lacks qualified birth")
		}
	}
	domain := plan.session.root.Domain
	p := contract.PublicationProjection{Schema: 4, DomainID: domain, ConfigurationDigest: plan.session.root.OutputConfiguration.ConfigurationDigest, CoordinateID: publicationExpectedCoordinate(domain, expectedTarget.ServiceContractID, expectedTarget.CanonicalTarget), BindingIncarnationID: target.binding, EntryIncarnationID: expectedTarget.EntryIncarnationID, Action: action, ActingRecipientID: plan.acting}
	policy := publicationExpectedPolicy(expectedTarget.Policy)
	row := append([]byte(nil), p.EntryIncarnationID[:]...)
	for _, v := range []string{expectedTarget.ServiceContractID, expectedTarget.TargetContractID, expectedTarget.CanonicalTarget, expectedTarget.ConsumerLocator} {
		row = publicationExpectedBlob(row, []byte(v))
	}
	row = publicationExpectedBlob(row, expectedTarget.TargetData)
	row = append(row, expectedTarget.PayloadEncoding, uint8(expectedTarget.Capabilities))
	if expectedTarget.LocatorRequiresCreation {
		row = append(row, 1)
	} else {
		row = append(row, 0)
	}
	for _, n := range []uint32{expectedTarget.CreateValueBounds.Minimum, expectedTarget.CreateValueBounds.Maximum, expectedTarget.WriteValueBounds.Minimum, expectedTarget.WriteValueBounds.Maximum} {
		row = binary.BigEndian.AppendUint32(row, n)
	}
	row = publicationExpectedBlob(row, policy)
	b := append([]byte(nil), domain[:]...)
	b = publicationExpectedBlob(b, []byte(target.destination))
	b = append(b, target.binding[:]...)
	b = append(b, row...)
	p.TargetRowDigest = publicationExpectedHash("ENKV/OUTPUT/TARGET-ROW/v3", b)
	if action == contract.PublicationDeleteOwned {
		p.TargetRowDigest = deletionRowDigest
	}
	protocol := sha256.Sum256([]byte("ENKV/OUTPUT-WIRE/v6\x00"))
	config := publicationExpectedHash("ENKV/OUTPUT/CONFIG-CONTRACT/v1", publicationExpectedBlob(nil, []byte(target.configContractID)))
	b = append(append([]byte(nil), protocol[:]...), config[:]...)
	b = publicationExpectedBlob(b, []byte(expectedTarget.ServiceContractID))
	b = publicationExpectedBlob(b, []byte(expectedTarget.TargetContractID))
	b = append(b, action)
	p.RequestContractDigest = publicationExpectedHash("ENKV/OUTPUT/REQUEST-CONTRACT/v2", b)
	if action == contract.PublicationWriteValue || action == contract.PublicationUpdatePolicy || action == contract.PublicationDeleteOwned {
		p.OwnedBirthAttemptID = birthID
	}
	if action <= contract.PublicationUpdatePolicy && len(policy) != 0 {
		b = append([]byte(nil), domain[:]...)
		p.PolicyDigest = publicationExpectedHash("ENKV/OUTPUT/POLICY/v3", publicationExpectedBlob(publicationExpectedBlob(b, []byte(expectedTarget.Policy.ContractID)), expectedTarget.Policy.Data))
	}
	if action == contract.PublicationCreateWithValue || action == contract.PublicationWriteValue {
		entry := plan.session.valueEntry(target.slot)
		if entry == nil || entry.Incarnation != expectedTarget.EntryIncarnationID {
			t.Fatal("publication oracle lacks the fixed selected value entry")
		}
		var raw, retained uint32
		var semantic contract.ID
		if entry.ConfidentialityClass == contract.Plain {
			raw, retained = entry.ContentLength, entry.RetainedLength
			b = append([]byte(nil), domain[:]...)
			b = binary.BigEndian.AppendUint16(b, target.slot)
			b = publicationExpectedBlob(b, []byte(entry.Name))
			for _, id := range []contract.ID{entry.Incarnation, entry.ValueState, entry.OriginSnapshot, entry.OriginTransition} {
				b = append(b, id[:]...)
			}
			b = append(b, entry.ValueSource, entry.ConfidentialityClass, entry.InputEncoding)
			b = binary.BigEndian.AppendUint32(b, entry.ContentLength)
			b = binary.BigEndian.AppendUint32(b, entry.RetainedLength)
			b = append(b, entry.OutputEncoding)
			b = binary.BigEndian.AppendUint16(b, uint16(len(entry.Recipients)))
			for _, id := range entry.Recipients {
				b = append(b, id[:]...)
			}
			b = publicationExpectedBlob(b, entry.ValueBytes)
			b = publicationExpectedBlob(b, nil)
			semantic = publicationExpectedHash("ENKV/CRYPTO/v2/public-member-v6", b)
		} else {
			_, payload, _, ok := plan.session.selectedValue(target.slot)
			if !ok {
				t.Fatal("missing selected secret")
			}
			raw, retained, semantic = payload.ContentLength, payload.RetainedLength, payload.SemanticCommitment
		}
		b = append([]byte(nil), domain[:]...)
		b = publicationExpectedBlob(b, []byte(target.destination))
		b = append(b, target.binding[:]...)
		b = append(b, entry.Incarnation[:]...)
		b = append(b, entry.ValueState[:]...)
		b = binary.BigEndian.AppendUint32(b, raw)
		b = append(b, entry.InputEncoding)
		b = binary.BigEndian.AppendUint32(b, retained)
		b = append(b, entry.ConfidentialityClass)
		b = append(b, semantic[:]...)
		for _, v := range []string{expectedTarget.ServiceContractID, expectedTarget.CanonicalTarget, expectedTarget.TargetContractID} {
			b = publicationExpectedBlob(b, []byte(v))
		}
		b = append(b, expectedTarget.PayloadEncoding)
		p.ValueBasisDigest = publicationExpectedHash("ENKV/PUBLICATION/VALUE-BASIS/v4", b)
	}
	b = binary.BigEndian.AppendUint16(nil, 4)
	for _, id := range []contract.ID{p.DomainID, p.ConfigurationDigest, p.CoordinateID, p.BindingIncarnationID, p.EntryIncarnationID, p.TargetRowDigest} {
		b = append(b, id[:]...)
	}
	b = append(b, action)
	for _, id := range []contract.ID{p.OwnedBirthAttemptID, p.UncertainCreateAttemptID, p.ExclusiveNamespaceDigest, p.ValueBasisDigest, p.PolicyDigest, p.RequestContractDigest, p.ActingRecipientID} {
		b = append(b, id[:]...)
	}
	commitment := publicationExpectedHash("ENKV/PUBLICATION/PROJECTION/v4", b)
	b = append([]byte(nil), p.RequestContractDigest[:]...)
	b = append(b, target.facts.ArtifactContractID[:]...)
	for _, v := range []uint16{6, 1, 3} {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return p, commitment, publicationExpectedHash("ENKV/OUTPUT/RESPONSE-CONTRACT/v2", b)
}

// Fixed literals were derived separately with Python struct.pack/hashlib after
// reproducing all prior v3/wire5 answers. They follow
// the Formats field order: coordinate, optional Policy/v3, target row,
// wire6 request/response, value-basis/v4 and Projection/v4. Absent policy contributes
// a zero-length blob to the target row and a zero policy digest to the projection.
// full_only: false
func TestPublicationExpectedOracleLiterals(t *testing.T) {
	id := func(value byte) (result contract.ID) {
		for i := range result {
			result[i] = value
		}
		return result
	}
	digest := func(text string) contract.ID {
		body, err := hex.DecodeString(text)
		if err != nil || len(body) != 32 {
			t.Fatal("invalid fixed oracle digest literal")
		}
		return contract.ID(body)
	}
	policies := map[string]contract.OutputPolicy{
		"absent":        {},
		"org":           {ContractID: "fixture/organization-policy/v1", Data: []byte{1, 7, 19}},
		"org-all":       {ContractID: "fixture/organization-policy/v1", Data: []byte{2}},
		"org-private":   {ContractID: "fixture/organization-policy/v1", Data: []byte{3}},
		"org-empty":     {ContractID: "fixture/organization-policy/v1", Data: []byte{1}},
		"local":         {ContractID: "test-policy", Data: []byte("1,9")},
		"local-reduced": {ContractID: "test-policy", Data: []byte("1")},
	}
	for _, test := range []struct{ name, body string }{
		{"absent", ""},
		{"org", "00030000001e666978747572652f6f7267616e697a6174696f6e2d706f6c6963792f763100000003010713"},
		{"org-all", "00030000001e666978747572652f6f7267616e697a6174696f6e2d706f6c6963792f76310000000102"},
		{"org-private", "00030000001e666978747572652f6f7267616e697a6174696f6e2d706f6c6963792f76310000000103"},
		{"org-empty", "00030000001e666978747572652f6f7267616e697a6174696f6e2d706f6c6963792f76310000000101"},
		{"local", "00030000000b746573742d706f6c69637900000003312c39"},
		{"local-reduced", "00030000000b746573742d706f6c6963790000000131"},
	} {
		t.Run("policy/"+test.name, func(t *testing.T) {
			if hex.EncodeToString(publicationExpectedPolicy(policies[test.name])) != test.body {
				t.Fatal("canonical policy differs from independent framing literal")
			}
		})
	}
	targets := map[string]contract.OutputTarget{
		"aws":   outputFixtureTarget("aws-secrets-manager", "arn:aws:secretsmanager:us-east-1:123456789012:secret:ENKV_P", "", contract.OutputEncodingRaw, 63, contract.OutputPolicy{}),
		"gcp":   outputFixtureTarget("gcp-secret-manager", "projects/123456789012/secrets/ENKV_P", "projects/123456789012/secrets/ENKV_P/versions/latest", contract.OutputEncodingRaw, 63, contract.OutputPolicy{}),
		"repo":  outputFixtureTarget("github-actions", "repos/acme/repo/actions/secrets/ENKV_P", "repos/acme/repo/actions/secrets/ENKV_P", contract.OutputEncodingRaw, 63, contract.OutputPolicy{}),
		"org":   outputFixtureTarget("github-actions", "orgs/acme/actions/secrets/ENKV_P", "orgs/acme/actions/secrets/ENKV_P", contract.OutputEncodingRaw, 255, contract.OutputPolicy{}),
		"env":   outputFixtureTarget("github-actions", "repos/acme/repo/environments/staging/secrets/ENKV_P", "repos/acme/repo/environments/staging/secrets/ENKV_P", contract.OutputEncodingRaw, 63, contract.OutputPolicy{}),
		"local": outputFixtureTarget("test-output/service/v1", "plain-target", "plain-target", contract.OutputEncodingRaw, 255, contract.OutputPolicy{}),
	}
	aws := targets["aws"]
	aws.LocatorRequiresCreation = true
	targets["aws"] = aws
	local := targets["local"]
	local.TargetContractID = "test-output/target/v1"
	targets["local"] = local
	session := &StateSession{}
	session.root.Domain = id(1)
	session.root.OutputConfiguration.ConfigurationDigest = id(2)
	session.pages[0] = &format.ValueEntryPage{}
	session.pages[0].Slots[3] = &contract.ValueEntry{Name: "plain", Incarnation: id(4), ValueState: id(6), OriginSnapshot: id(7), OriginTransition: id(8), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{id(9)}, ValueBytes: []byte("alpha"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("alpha"))), RetainedLength: uint32(len([]byte("alpha")))}
	plan := &publicationPlan{session: session, acting: id(5)}
	for _, test := range []struct {
		name, target, policy                                                     string
		action                                                                   uint8
		coordinate, row, request, policyDigest, valueBasis, commitment, response string
	}{
		{"aws-create", "aws", "absent", 1, "6874c5eabde7768246a5680d8ee90608feb81e2b0d178ae42809563ef60ccc35", "5e91175e4775c32482a7f10328edfab3603de9ae798ae7f903e0bb6127e4c223", "0e09ee35a905648da4eec66437ee0a921ebc5c3fcded5b166f74483359adfb5e", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "c13b261923b1b98f1d4187501defd5de639ef60806b8a970eef82193b715d349", "bdb6b74ae9325cfa877d1ea0474c014af21b92b208fd4d31d6fb7d343f6be6e5"},
		{"aws-delete-after-create", "aws", "absent", 5, "6874c5eabde7768246a5680d8ee90608feb81e2b0d178ae42809563ef60ccc35", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "e8068e141c99d3f53c172a4f934d4f077db9dfd150a94ec03ea470b75ecacbdd", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "7f6b1ce072afe52d3201972da9418fb73ae9f6bfe2408a0f0c4fc77417101f73", "2f98773a86d47edc8a2141c10f7586ab15af183c0c56cb0f788454186e7f9267"},
		{"aws-value-after-create", "aws", "absent", 3, "6874c5eabde7768246a5680d8ee90608feb81e2b0d178ae42809563ef60ccc35", "5e91175e4775c32482a7f10328edfab3603de9ae798ae7f903e0bb6127e4c223", "377ad0bd8306ea07752210225be721a02d54d712335ed65cceed3c7da20cf38a", "0000000000000000000000000000000000000000000000000000000000000000", "13fae83ce61bad4c1df4c181a5cfe01258f8816c1828e1866597ffa9d41b0de2", "a9dc4fa7c3170b7339fb6c6f91433b4fd2742ddae9c111e6da08fe323933c298", "22f4ec585d036a8477bc7bf45f7b486d3d2a11ef52db6995c07dfb2c1940c666"},
		{"gcp-value", "gcp", "absent", 3, "365bd385810f39a1826a7499fe3ef96bab2bd97637f689cfb0444d711f04b5d3", "4a930d00a46ab60f010d7533ed55baca5b893da2711e3ed78ffccc025088b162", "2856b4867f015d4703cb9dac84fc3fb08806bbb5a73ea760093cfbcd0fb44e20", "0000000000000000000000000000000000000000000000000000000000000000", "5e989626872f2b89c4998c8847a64b70eb5eb31e763af1effa934541fda17f5d", "bc27b6f1a321eea4fb9aba21f7c40175c9ab838eac2bf7dee4f62d1607c225b2", "894f9b80c642d1651d6fe47c00779df5a7958043b32d16627470c80a341e4975"},
		{"repository-create", "repo", "absent", 2, "eb03736f979489703f4b0dd8c20f74ef0d42210a3c3c6f8d540d18a0787fe3ae", "5868c819d89c27a68b9a3f3befd955fd3542e6967e095d50f2e77bc9e0cccce1", "d5d97170b98c453c645ad93330b5da0696db549db6ed1063f64192be8e00f663", "0000000000000000000000000000000000000000000000000000000000000000", "28466537966c6c84dd447db03f2fedc0af7f8de6bc9735397df74c211dcae696", "f64c656c98f7759c189fa98a94bf45b31dc04a0622abb33a271d5e95cb59e48a", "aa7e06c7164598fa028399db5529b90a26c1a37d0dd4d0793c752a4686808b54"},
		{"organization-policy", "org", "org", 4, "89190ff356e38f3825b2f8bfe63a69d3ce297556bc2df17f0b010a59dcfa2d08", "512633b3c3b03c150cc60dc811d93259ef245450a3fd2cd8f1fddde2d64fb3e0", "246154bb6c76a8bb97039d3c05ab3af06d49c8cef08ee88172e161fbcb3d0210", "4810eb74003868b43105f4d00315db06d4536aface213a6a0d99fa29591787e6", "0000000000000000000000000000000000000000000000000000000000000000", "d784e514f6617699a20720b7d107f0d25cbb4cf86a4690ea2382abef8a2cb48f", "aaa9b209f481df787e615ac5e274967586c41f9dfbc2622840e5c9372b76001f"},
		{"environment-delete", "env", "absent", 5, "f2ae2f20bdfbdcb903fad5000c2cbe89beaa8b8c8188b5b7e4c4fa70a12dabbd", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "b38d5680be721dd9c49be12c46fc642c22ba9ecb3d90298ea6aa872ba6ce0956", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "7d66666fa0e3c97a7ec9f8ca863f5fdf529465c49e4a62ec9806c142a6169bbd", "1c709419add87b99ebbd2f912acf050cf95d2299272499693e24f20ac03128d6"},
		{"local-create", "local", "local", 2, "1b5fe7a024c31528e9218b1a5c2c4c8b52fb75e76ba531f6cd5a53dab9b71c81", "7a67d1ced44b1f61f06f50378e63af7a71e0bee7ff798da8cb0246ad2eece00b", "e2811ade32eaf34420412364264550d24a26cb4b88efb8d2f2263f68547fe544", "c18f5b4e6b5c9d6e99e41145a096b6bae8ca679e4cd5d51dc66548a745e23548", "381ea50518b54bed9d062712c76a8e0db855ad7525b723f472f4eab5ada750ce", "70552eb2fd4aeabbb93a503817aae6a2dfa0397096be06c005cfc77f530508e4", "ba9933a61233109a6e5227d11e676eb938f2329f9fc044a370d90a57e52d8b42"},
		{"local-value", "local", "local", 3, "1b5fe7a024c31528e9218b1a5c2c4c8b52fb75e76ba531f6cd5a53dab9b71c81", "7a67d1ced44b1f61f06f50378e63af7a71e0bee7ff798da8cb0246ad2eece00b", "88a16c4834060bbec9597bca6c3b69a058bf98600505a4128f38d9f2467a107f", "c18f5b4e6b5c9d6e99e41145a096b6bae8ca679e4cd5d51dc66548a745e23548", "381ea50518b54bed9d062712c76a8e0db855ad7525b723f472f4eab5ada750ce", "9a937d0ed84e6f23f7db484fd7ea0d23b410b200bdda86ee0f778d8e3af12b2b", "2223792862d7c2de80c80b87f38c80e83ff59c64c7050a8e96aa0f44fe4bf8ae"},
		{"local-policy", "local", "local-reduced", 4, "1b5fe7a024c31528e9218b1a5c2c4c8b52fb75e76ba531f6cd5a53dab9b71c81", "a3ecc0b93e4afc5ce51007d06f7461a1e97dd34279051b86711e844e677b35a7", "bedf5db9bd3b6b99d7c35e8ea29937228db6ff968b29dbe732dd8ffa03ecf39f", "b3e6348a05011fd1c74ba3352026f14ec913bcafecdff23422902fd111f0f187", "0000000000000000000000000000000000000000000000000000000000000000", "6a9a319ec95b33201d10730f90906e731bb8b49ef2bddc7f6b28a259207690a4", "ea2c5cb0e3540637a67670fd95e8fa9201cdec633e28dd0a1755df23f3e9725e"},
		{"local-delete", "local", "local", 5, "1b5fe7a024c31528e9218b1a5c2c4c8b52fb75e76ba531f6cd5a53dab9b71c81", "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "6b2fe163761275d31b4e9d9adadb2c279bb0eb10a0cc44c3d730339d0fcf9ef2", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "aa957105f81a649ccfbcde7228f9f3396504d4a605a7deb8c12e666703b52fc5", "bf41f33a230467125b42c71012902ab434830946c029704f50900a73bd35b235"},
	} {
		t.Run("projection/"+test.name, func(t *testing.T) {
			expectedTarget := targets[test.target]
			expectedTarget.EntryIncarnationID = id(4)

			expectedTarget.Policy = policies[test.policy]
			target := publicationTargetPlan{destination: "destination", configContractID: publicationTestConfigContract, binding: id(3), slot: 3, target: expectedTarget, coordinate: digest(test.coordinate), facts: publicationActionFacts{ArtifactContractID: id(10)}}
			if test.action == contract.PublicationDeleteOwned {
				target.target.Policy = contract.OutputPolicy{}
				target.target.Capabilities = contract.OutputCapabilityDeleteOwned
				target.target.CreateValueBounds, target.target.WriteValueBounds = contract.OutputPayloadBounds{}, contract.OutputPayloadBounds{}
			}
			// In the original fresh-create plan retained birth is empty, even for the
			// following policy and value actions. The caller's preallocated create ID
			// must supply their birth, rather than that empty predecessor field.
			if !target.retained.OwnedBirthAttemptID.IsZero() {
				t.Fatal("literal fixture has a retained birth")
			}
			projection, commitment, response := publicationExpectedProjection(t, plan, target, test.action, expectedTarget, id(11), id(12))
			expected := contract.PublicationProjection{Schema: 4, DomainID: id(1), ConfigurationDigest: id(2), CoordinateID: digest(test.coordinate), BindingIncarnationID: id(3), EntryIncarnationID: id(4), TargetRowDigest: digest(test.row), Action: test.action, ValueBasisDigest: digest(test.valueBasis), PolicyDigest: digest(test.policyDigest), RequestContractDigest: digest(test.request), ActingRecipientID: id(5)}
			if test.action >= contract.PublicationWriteValue {
				expected.OwnedBirthAttemptID = id(11)
			}
			if projection != expected || commitment != digest(test.commitment) || response != digest(test.response) {
				t.Fatalf("independent projection literal differs: fields=%t commitment=%t response=%t", projection == expected, commitment == digest(test.commitment), response == digest(test.response))
			}
			if got := publicationExpectedCoordinate(id(1), expectedTarget.ServiceContractID, expectedTarget.CanonicalTarget); got != digest(test.coordinate) {
				t.Fatal("coordinate differs from independent named-provider literal")
			}
			if test.target == "local" {
				target.retained.OwnedBirthAttemptID, target.retained.DeletionTargetRowDigest = id(11), id(12)
				localCommitment, localResponse := publicationScenarioCommitment(t, plan, target, test.action)
				if localCommitment != commitment || localResponse != response {
					t.Fatal("local fixed wrapper changed")
				}
			}
		})
	}
}
