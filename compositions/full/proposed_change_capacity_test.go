package compositionfull

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: true
func TestProposedChangeResultMaximumPublicValues(t *testing.T) {
	const evidence = "Fixed authenticated public settings and requested generated intent only; future generated content is unavailable and secret-value equality is unchecked. Excludes apply admission or no-op, performed effects or credential validity, remote output contents or IAM, historical application, and continued currentness."
	if evidence != contract.ComparisonEvidenceLimit || contract.GeneratorLifecycleManaged != 2 || contract.GeneratedCompletionAcknowledged != 1 || contract.GCP != 2 || contract.RSAOAEPWrapProfile != 2 || contract.SoftwareProtection != 2 || contract.InputEncodingRaw != 1 || contract.OutputEncodingBase64 != 2 {
		t.Fatal("independent public fixture tags changed")
	}
	const semantic = 99577838
	const semanticLimit = 121158832
	const typedLimit = 119531256
	const valuesLimit = 481380176
	const resultLimit = 2356478048
	const controlledLimit = 4327932768
	if semantic > semanticLimit || semanticLimit != contract.MaxPublicConfigurationBytes || typedLimit != contract.MaxPublicTypedConfigurationBytes || valuesLimit != 2*(semanticLimit+typedLimit) || resultLimit != contract.MaxComparisonResultJSONBytes || controlledLimit != 2146794448+valuesLimit+(resultLimit-656719904) {
		t.Fatal("independent complete public value account changed")
	}
	r := proposedResult()
	r.Changes = make([]contract.ComparisonChange, 0, 40835)
	add := func(side int, subject contract.DiagnosticSubject, path []contract.DiagnosticField, value contract.ComparisonValue) {
		change := contract.ComparisonChange{Subject: subject, Path: path, Action: contract.ComparisonRemoved, Before: proposedSide(value), After: contract.ComparisonSide{State: contract.ComparisonAbsent}}
		if side == 1 {
			change.Action, change.Before, change.After = contract.ComparisonAdded, change.After, change.Before
		}
		r.Changes = append(r.Changes, change)
	}
	id := func(side, n int) contract.ID {
		var v contract.ID
		binary.BigEndian.PutUint32(v[28:], uint32(1+side*256+n))
		return v
	}
	name := func(side, n int) string {
		return fmt.Sprintf("%c%03d", 'A'+side, n) + strings.Repeat("\x00", 247) + "雪\"\\"
	}
	destinationName := func(side, b int) string {
		if b < 8 {
			return strings.Repeat(string(rune('a'+side*10+b)), 256)
		}
		return fmt.Sprintf("%c%02d", 'j'+side*9, b)
	}
	indexes := func(b int) []int {
		var result []int
		if b == 0 {
			result = make([]int, 512)
			for e := range result {
				result[e] = e
			}
		}
		if b > 0 && b < 8 {
			count := 72
			if b == 7 {
				count++
			}
			result = make([]int, count+1)
			for n := 1; n <= count; n++ {
				result[n] = 1 + (b-1)*72 + n - 1
			}
		}
		return result
	}
	names := func(side, b int) []string {
		entries := indexes(b)
		result := make([]string, len(entries))
		for at, e := range entries {
			result[at] = name(side, e)
		}
		return result
	}
	// The same group contains all 512 distinct entries on each side. It does not
	// carry entry bodies; the removed/added entry records below own those fields.
	groups := [2]contract.ComparisonGroups{}
	for side := range groups {
		groups[side] = make(contract.ComparisonGroups, 1)
		groups[side][0] = make([]string, 512)
		for e := range groups[side][0] {
			groups[side][0][e] = name(side, e)
		}
	}
	change := proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, contract.FieldRecipientID, contract.ComparisonID(id(0, 0)), contract.ComparisonID(id(1, 0)))
	r.Changes = append(r.Changes, change)
	change = proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldGroups, groups[0], groups[1])
	r.Changes = append(r.Changes, change)
	plainBytes, intentBytes, memberships := [2]int{}, [2]int{}, [2]int{}
	for side := 0; side < 2; side++ {
		for e := 0; e < 512; e++ {
			subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: name(side, e)}
			field := func(f contract.DiagnosticField, v contract.ComparisonValue) {
				add(side, subject, []contract.DiagnosticField{f}, v)
			}
			class, source := uint64(1), uint64(1)
			if e < 128 {
				class, source = 2, 2
			}
			field(contract.FieldClass, contract.ComparisonUint(class))
			if e < 128 {
				intent := make(contract.ComparisonBytes, 393216)
				intent[1], intent[2], intent[34], intent[35] = 1, 9, 2, 7
				binary.BigEndian.PutUint32(intent[67:71], 393145)
				intent[71], intent[len(intent)-1] = '"', '"'
				for at := 72; at < len(intent)-1; at++ {
					intent[at] = byte('a' + side)
				}
				generated := func(f contract.DiagnosticField, v contract.ComparisonValue) {
					add(side, subject, []contract.DiagnosticField{contract.FieldGenerated, f}, v)
				}
				generated(contract.FieldCompletion, contract.ComparisonUint(1))
				generated(contract.FieldConfigContract, contract.ComparisonID(contract.ID{9}))
				generated(contract.FieldContentIntent, intent)
				// Initial generation starts at zero; stored metadata and selected
				// public projection preserve that exact epoch.
				generated(contract.FieldEpoch, contract.ComparisonUint(0))
				generated(contract.FieldLifecycle, contract.ComparisonUint(2))
				generated(contract.FieldResourceContract, contract.ComparisonID(contract.ID{7}))
				generated(contract.FieldRetirement, contract.ComparisonUint(1))
				intentBytes[side] += 393216
			}
			field(contract.FieldInputEncoding, contract.ComparisonUint(1))
			count := 1
			if e >= 128 && e < 192 {
				count = 32
			} else if e >= 192 && e < 217 {
				count = 64
			} else if e == 217 {
				count = 26
			}
			members := make(contract.ComparisonIDSet, count)
			classification := "removed"
			if side == 1 {
				classification = "added"
			}
			for at := range members {
				members[at] = contract.ComparisonMember{ID: id(side, at), Change: contract.ComparisonMemberChange(classification)}
			}
			field(contract.FieldMemberships, members)
			memberships[side] += count
			field(contract.FieldName, contract.ComparisonText(name(side, e)))
			field(contract.FieldOutputEncoding, contract.ComparisonUint(2))
			if e >= 128 {
				size := 0
				if e < 256 {
					size = 65536
				}
				body := make(contract.ComparisonBytes, size)
				for at := range body {
					body[at] = byte(side + e + at)
				}
				field(contract.FieldPlainValue, body)
				plainBytes[side] += size
			}
			field(contract.FieldPresence, contract.ComparisonBoolean(true))
			field(contract.FieldSource, contract.ComparisonUint(source))
		}
	}
	// Policies fill the independent declaration grammar, with each policy counted
	// once for the destination and once for each actual target. The target and
	// route axes retain their source maximum's coupled shape.
	policies := [2][64]contract.OutputPolicy{}
	settings := [2][64][]byte{}
	declaration := [2]int{}
	routing := [2]int{}
	for side := 0; side < 2; side++ {
		declaration[side], routing[side] = 6+2+32*512, 5
		for b := 0; b < 64; b++ {
			settingsText := `{"fixture":"` + destinationName(side, b) + `"}`
			if b == 63 {
				settingsText = "null"
			}
			settings[side][b] = make([]byte, len(settingsText))
			copy(settings[side][b], settingsText)
			policies[side][b] = contract.OutputPolicy{ContractID: "p", Data: make([]byte, 0)}
			if b == 9 {
				policies[side][b] = contract.OutputPolicy{ContractID: strings.Repeat("p", 256), Data: make([]byte, 524546)}
			}
			policy := policies[side][b]
			declaration[side] += 4 + len(destinationName(side, b)) + 32 + 17 + len("test-output/config/v1") + len("test-output/service/v1") + len(settingsText) + 10 + len(policy.ContractID) + len(policy.Data) + 2
			for _, e := range indexes(b) {
				slot := fmt.Sprintf("slot-%02d-%03d", b, e)
				declaration[side] += 75 + len("test-output/service/v1") + len("test-output/target/v1") + len(slot) + len(slot+"/latest") + len("single") + 10 + len(policy.ContractID) + len(policy.Data)
			}
		}
		remaining := 33554432 - declaration[side]
		for b := 0; b < 64; b++ {
			if b == 9 {
				continue
			}
			weight := 1 + len(indexes(b))
			count := min(524546, remaining/weight)
			policies[side][b].Data = make([]byte, count)
			for at := range policies[side][b].Data {
				policies[side][b].Data[at] = byte(at + 1 + side)
			}
			remaining -= weight * count
			declaration[side] += weight * count
		}
		if remaining != 0 || declaration[side] != 33554432 {
			t.Fatal("independent declaration ceiling not reached", side, remaining, declaration[side])
		}
	}
	targets := [2]int{}
	for side := 0; side < 2; side++ {
		for b := 0; b < 64; b++ {
			d := destinationName(side, b)
			subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: d}
			policy := policies[side][b]
			v := contract.ComparisonDestination{ConfigContractID: "test-output/config/v1", ServiceContractID: "test-output/service/v1", CanonicalSettings: settings[side][b], Policy: policy, Capabilities: 61}
			add(side, subject, []contract.DiagnosticField{contract.FieldDestination}, v)
			add(side, subject, []contract.DiagnosticField{contract.FieldPresence}, contract.ComparisonBoolean(true))
			targetNames := names(side, b)
			add(side, subject, []contract.DiagnosticField{contract.FieldTargets}, contract.ComparisonTextSet(targetNames))
		}
	}
	for side := 0; side < 2; side++ {
		for b := 0; b < 64; b++ {
			for _, e := range indexes(b) {
				d := destinationName(side, b)
				subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: d, Name: name(side, e)}
				field := func(f contract.DiagnosticField, v contract.ComparisonValue) {
					add(side, subject, []contract.DiagnosticField{f}, v)
				}
				slot := fmt.Sprintf("slot-%02d-%03d", b, e)
				policy := policies[side][b]
				field(contract.FieldCanonicalTarget, contract.ComparisonText(slot))
				field(contract.FieldCapabilities, contract.ComparisonUint(61))
				field(contract.FieldConsumerLocator, contract.ComparisonText(slot+"/latest"))
				field(contract.FieldConsumerPolicy, contract.ComparisonPolicy(policy))
				field(contract.FieldCreateValueBounds, contract.ComparisonBounds{})
				field(contract.FieldLocatorRequiresCreation, contract.ComparisonBoolean(false))
				field(contract.FieldPayloadEncoding, contract.ComparisonUint(2))
				field(contract.FieldPresence, contract.ComparisonBoolean(true))
				field(contract.FieldServiceContract, contract.ComparisonText("test-output/service/v1"))
				field(contract.FieldTargetContract, contract.ComparisonText("test-output/target/v1"))
				data := make(contract.ComparisonBytes, 6)
				copy(data, "single")
				field(contract.FieldTargetData, data)
				field(contract.FieldWriteValueBounds, contract.ComparisonBounds{Maximum: 65536})
				targets[side]++
			}
		}
	}
	// The same structurally valid public RSA key is permitted for all public
	// recipient rows. No private key, ciphertext, or secret length is present.
	modulus := new(big.Int).Lsh(big.NewInt(1), 3071)
	modulus.Add(modulus, big.NewInt(12345))
	publicKey, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: modulus, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	publicFingerprint := contract.ComparisonID(sha256.Sum256(publicKey))
	selector := "projects/fixture/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
	selector = strings.Replace(selector, "central", strings.Repeat("a", 1024-len(selector)+len("central")), 1)
	if len(publicKey) != 422 || len(selector) != 1024 || hex.EncodeToString(publicFingerprint[:]) != "9e5d979fc80775a75625f7f05538f443ace1fc3653f7e02dbcb8b44da3ef936c" {
		t.Fatal("public registry maximum shape changed")
	}
	for side := 0; side < 2; side++ {
		labels := make([]contract.ComparisonRecipientLabel, 256)
		for n := 0; n < 256; n++ {
			recipient := id(side, n)
			display := name(side, n)
			labels[n] = contract.ComparisonRecipientLabel{RecipientID: recipient, DisplayName: &display}
			subject := contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: recipient}
			field := func(f contract.DiagnosticField, v contract.ComparisonValue) {
				add(side, subject, []contract.DiagnosticField{f}, v)
			}
			field(contract.FieldDisplayName, contract.ComparisonText(display))
			field(contract.FieldEncryptionFingerprint, publicFingerprint)
			field(contract.FieldEncryptionProvider, contract.ComparisonUint(2))
			owned := make(contract.ComparisonBytes, len(publicKey))
			copy(owned, publicKey)
			field(contract.FieldEncryptionPublicKey, owned)
			field(contract.FieldEncryptionSelector, contract.ComparisonText(selector))
			field(contract.FieldPresence, contract.ComparisonBoolean(true))
			field(contract.FieldProtectionClass, contract.ComparisonUint(2))
			field(contract.FieldWrapProfile, contract.ComparisonUint(2))
		}
		if side == 0 {
			r.BeforeRecipients = labels
		} else {
			r.AfterRecipients = labels
		}
	}
	for side := 0; side < 2; side++ {
		for e := 0; e < 512; e++ {
			destinations := make(contract.ComparisonTextSet, 0, 8)
			for b := 0; b < 8; b++ {
				for _, target := range indexes(b) {
					if target == e {
						destinations = append(destinations, destinationName(side, b))
						break
					}
				}
			}
			destinations = destinations[:len(destinations):len(destinations)]
			subject := contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: name(side, e)}}
			add(side, subject, []contract.DiagnosticField{contract.FieldDestinations}, destinations)
			add(side, subject, []contract.DiagnosticField{contract.FieldPresence}, contract.ComparisonBoolean(true))
			routing[side] += 33
			for _, d := range destinations {
				routing[side] += 4 + len(d)
			}
		}
	}
	defaults := [2]contract.ComparisonTextSet{}
	for side := range defaults {
		defaults[side] = make(contract.ComparisonTextSet, 8)
		for b := range defaults[side] {
			defaults[side][b] = destinationName(side, b)
			routing[side] += 4 + len(defaults[side][b])
		}
	}
	change = proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}}, contract.FieldDestinations, defaults[0], defaults[1])
	r.Changes = append(r.Changes, change)
	for side := 0; side < 2; side++ {
		if plainBytes[side] != 8388608 || intentBytes[side] != 50331648 || memberships[side] != 4096 || targets[side] != 1024 || routing[side] != 285221 || declaration[side]+4+routing[side] != 33839657 || declaration[side]+4+routing[side] > 36<<20 {
			t.Fatalf("side=%d plain=%d intent=%d memberships=%d targets=%d declaration=%d routing=%d", side, plainBytes[side], intentBytes[side], memberships[side], targets[side], declaration[side], routing[side])
		}
	}
	// Independently derived fixed output vector for the complete typed fixture.
	// Expected values do not come from a production encoder.
	const expectedBytes = 334823155
	const expectedSHA256 = "224c7bf424b38c6cc20083a967c760e770777294a54dbe053b466fe747e9db49"
	if len(r.Changes) != 40835 || cap(r.Changes) != len(r.Changes) || len(r.Diagnostics) != 0 || expectedBytes > resultLimit {
		t.Fatal("complete proposed field union or independent output account changed", len(r.Changes))
	}
	got, err := RenderComparisonJSON(r)
	if err != nil || len(got) != expectedBytes || cap(got) != expectedBytes {
		t.Fatal("complete maximum public values refused or final backing differs", err, len(got), cap(got), expectedBytes)
	}
	digest := sha256.Sum256(got)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		t.Fatalf("complete maximum output differs from the independent fixed vector: got=%x want=%s", digest, expectedSHA256)
	}
	t.Logf("changes=%d public_plain_bytes_per_side=%d canonical_intent_bytes_per_side=%d declaration_bytes_per_side=%d routing_bytes_per_side=%d emitted_bytes=%d digest=%x", len(r.Changes), 8388608, 50331648, 33554432, 285221, len(got), digest)
}
