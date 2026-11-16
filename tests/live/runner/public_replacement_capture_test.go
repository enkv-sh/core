package core

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/core/testsupport/nativeprocess"
)

func publicReplacementCapture(c nativeprocess.Capture, cell catalog.PublicReplacementCase, denied bool) error {
	constructors, private := map[string]int{}, map[string]int{}
	heads, reads := 0, 0
	denialSeen := false
	deniedAPI, deniedRoute := "", ""
	switch cell.DeniedRole {
	case "denied-public":
		deniedAPI, deniedRoute = "kms-public", "normal"
	case "denied-normal-signing":
		deniedAPI, deniedRoute = "kms-sign", "normal"
	case "denied-recovery-signing":
		deniedAPI, deniedRoute = "kms-sign", "recovery-signing"
	case "denied-authority-private":
		deniedAPI, deniedRoute = "kms-decrypt", "authority"
	case "denied-recovery-private":
		deniedAPI, deniedRoute = "kms-decrypt", "recovery-private"
	}
	if denied != (deniedAPI != "") {
		return errors.New("replacement denial case is not closed")
	}
	for _, e := range c.Events {
		if e.Kind == "construction" {
			if e.Count != 1 {
				return errors.New("replacement constructor did not run exactly once")
			}
			constructors[e.Operation+"/"+e.Role]++
		}
		if e.Kind == "http-return" && e.Operation == deniedAPI && e.Role == deniedRoute && e.Sent && e.PermissionDenied {
			denialSeen = true
		}
		if e.Kind != "http-start" {
			continue
		}
		// A local refusal is a capability attempt too. No successful cell can
		// discharge a zero-use assertion by blocking the attempt in the overlay.
		if !e.Sent {
			return errors.New("replacement made a locally blocked provider attempt")
		}
		switch e.Operation {
		case "head-read", "store-read":
			reads++
		case "store-write":
			if denied && (cell.DeniedRole == "denied-public" || cell.DeniedRole == "denied-authority-private" || cell.DeniedRole == "denied-recovery-private") {
				return errors.New("pre-persistence denied qualification created immutable state")
			}
		case "head-write":
			heads++
		case "kms-public":
			if e.Role != "normal" && e.Role != "recovery-signing" && e.Role != "successor" && e.Role != "successor-private" {
				return errors.New("replacement resolved an unselected public route")
			}
		case "kms-sign", "kms-decrypt":
			private[e.Operation+"/"+e.Role]++
		default:
			return errors.New("replacement used another provider operation")
		}
	}
	if reads == 0 || denied && (!denialSeen || heads != 0) || !denied && heads != 1 {
		return errors.New("replacement lost actual reads, exact denial or one physical CAS")
	}
	if !denied {
		returned, joined := publicApplyHeadWrite(c)
		if !joined || returned.Status < 200 || returned.Status >= 300 {
			return errors.New("replacement lacks original physical CAS acknowledgement")
		}
		terminals := 0
		for _, e := range c.Events {
			if e.Kind == "store-result" && e.Operation == "head-write" {
				if !e.Sent || e.Sequence != returned.Sequence || e.ObjectKeySHA256 != returned.ObjectKeySHA256 || contract.WriteStatus(e.WriteStatus) != contract.WriteAcknowledged {
					return errors.New("replacement CAS lacks exact typed Store acknowledgement")
				}
				terminals++
			}
		}
		if terminals != 1 {
			return errors.New("replacement CAS terminal count differs")
		}
	}
	authorizer := "normal"
	if cell.Authorizer == "recovery" {
		authorizer = "recovery-signing"
	}
	want := map[string]int{"signer/" + authorizer: 1}
	allowed := map[string]bool{"kms-sign/" + authorizer: true}
	if cell.Change != "encryption" {
		metadataRole := "successor"
		if cell.DeniedRole == "denied-public" {
			metadataRole = "normal"
		}
		want["signing-metadata/"+metadataRole], want["signer/successor"] = 1, 1
		allowed["kms-sign/successor"] = true
	}
	if cell.Change != "signing" {
		want["encryption-metadata/successor-private"] = 1
		source := "authority"
		if cell.MaterialSource == "recovery" {
			source = "recovery-private"
		}
		want["key-access/"+source] = 1
		allowed["kms-decrypt/"+source] = true
		if cell.Target == "recipient" {
			want["public-qualifier/successor-private"] = 1
		} else {
			want["key-access/successor-private"] = 1
			allowed["kms-decrypt/successor-private"] = true
		}
	}
	if denied && cell.DeniedRole == "denied-public" {
		if len(private) != 0 || !reflect.DeepEqual(constructors, map[string]int{"signing-metadata/normal": 1}) {
			return errors.New("public denial crossed into another metadata or private capability")
		}
	}
	if denied && (cell.DeniedRole == "denied-authority-private" || cell.DeniedRole == "denied-recovery-private") && private["kms-sign/"+authorizer] != 0 {
		return errors.New("private qualification denial attempted final authorization")
	}
	if denied {
		// Qualification can stop before constructing every required capability.
		// Any capability it did construct must still be one of the exact goal's.
		for key, n := range constructors {
			if n != 1 || want[key] != 1 {
				return errors.New("denied replacement constructed an unused capability")
			}
		}
	} else if !reflect.DeepEqual(want, constructors) {
		return errors.New("replacement constructed extra or missing capabilities")
	}
	for key, n := range private {
		if n == 0 || !allowed[key] {
			return errors.New("replacement used an unselected private route")
		}
	}
	if !denied {
		for key := range allowed {
			if private[key] == 0 {
				return errors.New("replacement omitted a required private route")
			}
		}
	}
	return nil
}

func publicReplacementReadCapture(c nativeprocess.Capture, decryptRole, plaintextKind, publicRole string) error {
	gets, public, decrypts, plaintext := 0, 0, 0, 0
	for _, e := range c.Events {
		if e.Kind == "construction" {
			return errors.New("read constructed a replacement capability")
		}
		if e.Kind == plaintextKind && plaintextKind != "" {
			if !e.Matched || e.Count != 1 {
				return errors.New("cold consumption differs from independent bytes")
			}
			plaintext++
		}
		if e.Kind != "http-start" {
			continue
		}
		if !e.Sent {
			return errors.New("read made a locally blocked provider attempt")
		}
		switch e.Operation {
		case "head-read", "store-read":
			gets++
		case "kms-public":
			if decryptRole == "" || e.Role != publicRole {
				return errors.New("cold read performed an unselected public-key lookup")
			}
			public++
		case "kms-decrypt":
			if decryptRole == "" || e.Role != decryptRole {
				return errors.New("cold consumption selected another private route")
			}
			decrypts++
		default:
			return errors.New("read attempted mutation or another private capability")
		}
	}
	if gets == 0 || decryptRole == "" && decrypts != 0 || decryptRole != "" && (decrypts != 1 || public == 0) || plaintextKind != "" && plaintext != 1 {
		return errors.New("cold read lacks its exact GET/decrypt/byte observation")
	}
	return nil
}

// full_only: false
func TestPublicReplacementCaptureRejectsUnusedAndBlockedCapabilities(t *testing.T) {
	cell := catalog.PublicReplacementCase{Target: "authority", Change: "signing", Authorizer: "recovery"}
	event := func(kind, op, role string) nativeprocess.Event {
		return nativeprocess.Event{Kind: kind, Operation: op, Role: role, Count: 1, Sent: true}
	}
	good := nativeprocess.Capture{Events: []nativeprocess.Event{event("http-start", "head-read", ""), event("construction", "signing-metadata", "successor"), event("construction", "signer", "recovery-signing"), event("construction", "signer", "successor"), event("http-start", "kms-sign", "recovery-signing"), event("http-start", "kms-sign", "successor"), event("http-start", "head-write", "")}}
	headDigest := "1111111111111111111111111111111111111111111111111111111111111111"
	good.Events[len(good.Events)-1].Sequence = 7
	good.Events[len(good.Events)-1].ObjectKeySHA256 = headDigest
	good.Events = append(good.Events, nativeprocess.Event{Kind: "http-return", Operation: "head-write", Sent: true, Sequence: 7, ObjectKeySHA256: headDigest, Status: 200}, nativeprocess.Event{Kind: "store-result", Operation: "head-write", Sent: true, Sequence: 7, ObjectKeySHA256: headDigest, WriteStatus: uint8(contract.WriteAcknowledged)})
	if err := publicReplacementCapture(good, cell, false); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []nativeprocess.Event{event("construction", "key-access", "authority"), event("http-start", "kms-decrypt", "authority"), event("http-start", "head-write", ""), {Kind: "http-start", Operation: "kms-sign", Role: "normal"}} {
		bad := nativeprocess.Capture{Events: append(append([]nativeprocess.Event(nil), good.Events...), extra)}
		if publicReplacementCapture(bad, cell, false) == nil {
			t.Fatal("unused or blocked capability passed")
		}
	}
	unknown := nativeprocess.Capture{Events: append([]nativeprocess.Event(nil), good.Events...)}
	unknown.Events[len(unknown.Events)-1].WriteStatus = uint8(contract.WriteUnknown)
	if publicReplacementCapture(unknown, cell, false) == nil {
		t.Fatal("HTTP success laundered unknown typed CAS result")
	}
	reader := nativeprocess.Capture{Events: []nativeprocess.Event{event("http-start", "head-read", "")}}
	if publicReplacementReadCapture(reader, "", "", "") != nil {
		t.Fatal("GET-only read refused")
	}
	for _, extra := range []nativeprocess.Event{event("construction", "key-access", "authority"), event("http-start", "kms-public", "normal"), {Kind: "http-start", Operation: "kms-decrypt", Role: "authority"}} {
		bad := nativeprocess.Capture{Events: append(append([]nativeprocess.Event(nil), reader.Events...), extra)}
		if publicReplacementReadCapture(bad, "", "", "") == nil {
			t.Fatal("GET-only read accepted unused capability")
		}
	}
}

// full_only: false
func TestPublicReplacementPublicDenialStopsBeforePrivateCapabilities(t *testing.T) {
	cell := catalog.PublicReplacementCase{Target: "authority", Change: "both", Authorizer: "authority", MaterialSource: "authority", DeniedRole: "denied-public"}
	good := nativeprocess.Capture{Events: []nativeprocess.Event{{Kind: "http-start", Operation: "head-read", Sent: true}, {Kind: "construction", Operation: "signing-metadata", Role: "normal", Count: 1}, {Kind: "http-start", Operation: "kms-public", Role: "normal", Sent: true}, {Kind: "http-return", Operation: "kms-public", Role: "normal", Sent: true, PermissionDenied: true, Status: 403}}}
	if err := publicReplacementCapture(good, cell, true); err != nil {
		t.Fatal("exact selected public denial refused", err)
	}
	for _, position := range []int{0, len(good.Events)} {
		for _, extra := range []nativeprocess.Event{{Kind: "construction", Operation: "signer", Role: "normal", Count: 1}, {Kind: "construction", Operation: "key-access", Role: "authority", Count: 1}, {Kind: "http-start", Operation: "kms-sign", Role: "normal", Sent: true}, {Kind: "http-start", Operation: "kms-decrypt", Role: "authority", Sent: true}} {
			events := append([]nativeprocess.Event(nil), good.Events[:position]...)
			events = append(events, extra)
			events = append(events, good.Events[position:]...)
			if publicReplacementCapture(nativeprocess.Capture{Events: events}, cell, true) == nil {
				t.Fatal("public denial admitted private capability before or after its failure", position, extra.Operation)
			}
		}
	}
	local := nativeprocess.Capture{Events: append([]nativeprocess.Event(nil), good.Events...)}
	local.Events[2].Sent = false
	local.Events[3].PermissionDenied = false
	if publicReplacementCapture(local, cell, true) == nil {
		t.Fatal("local policy refusal qualified as actual IAM denial")
	}
}

// full_only: false
func TestPublicReplacementColdReadRefusesUnusedPublicRoute(t *testing.T) {
	good := nativeprocess.Capture{Events: []nativeprocess.Event{{Kind: "http-start", Operation: "head-read", Sent: true}, {Kind: "http-start", Operation: "kms-public", Role: "normal", Sent: true}, {Kind: "http-start", Operation: "kms-decrypt", Role: "authority", Sent: true}, {Kind: "plaintext", Count: 1, Matched: true, EntrySHA256: strings.Repeat("a", 64)}}}
	for _, selected := range []string{"normal", "recovery-signing", "successor"} {
		t.Run(selected, func(t *testing.T) {
			owned := nativeprocess.Capture{Events: append([]nativeprocess.Event(nil), good.Events...)}
			owned.Events[1].Role = selected
			if err := publicReplacementReadCapture(owned, "authority", "plaintext", selected); err != nil {
				t.Fatal(err)
			}
			missing := nativeprocess.Capture{Events: append(append([]nativeprocess.Event(nil), owned.Events[:1]...), owned.Events[2:]...)}
			if publicReplacementReadCapture(missing, "authority", "plaintext", selected) == nil {
				t.Fatal("cold read omitted selected public qualification")
			}
			for _, role := range []string{"normal", "recovery-signing", "recovery-private", "successor", "ordinary"} {
				if role == selected {
					continue
				}
				bad := nativeprocess.Capture{Events: append(append([]nativeprocess.Event(nil), owned.Events...), nativeprocess.Event{Kind: "http-start", Operation: "kms-public", Role: role, Sent: true})}
				if publicReplacementReadCapture(bad, "authority", "plaintext", selected) == nil {
					t.Fatal("cold read accepted an unused public route", role)
				}
			}
		})
	}
}
