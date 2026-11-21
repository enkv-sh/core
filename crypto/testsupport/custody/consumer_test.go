package custody

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	primitive "enkv.sh/crypto/internal/custody"
)

// This unit tests the private sink facade. Selected-state authentication is a
// separate Core integration test; these public selection pins are test inputs.
// full_only: false
func TestPrivateFacadeConsumerOracleAndIndependentRoute(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		f := New(t, family, id("consumer fixture"), true, []contract.ID{id("authority"), id("reader")})
		core := contract.ValueCore{ValueSource: 1, Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: id("domain"), Name: "first", EntryIncarnationID: id("incarnation"), ValueStateID: id("value"), OriginSnapshotID: id("origin snapshot"), OriginTransitionID: id("transition"), DataKeyID: id("data"), DataKeyEpoch: 1, CommitmentKeyID: id("commitment"), CommitmentKeyEpoch: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}
		value, ok := syntheticValue(StandardValue)
		if !ok {
			t.Fatal("missing synthetic input")
		}
		core.ContentLength, core.RetainedLength = uint32(len(value)), uint32(len(value))
		payload, keys, err := primitive.SealValue(core, value)
		clear(value[:cap(value)])
		if err != nil {
			t.Fatal(err)
		}
		access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: 1, MaterialID: core.ValueStateID, PackageCheck: payload.PackageCheck}
		access.MaterialContextDigest, err = contract.ValueMaterialContextDigest(core)
		if err != nil {
			t.Fatal(err)
		}
		var reader contract.BindingTableRow
		var recipients []contract.ID
		for _, row := range f.Bindings() {
			wrapCore, err := primitive.ValueWrapCore(core, row)
			if err != nil {
				t.Fatal(err)
			}
			wrap, err := primitive.Wrap(wrapCore, row.Binding, keys)
			if err != nil {
				t.Fatal(err)
			}
			access.Wraps = append(access.Wraps, wrap)
			if row.SubjectKind == 1 {
				recipients = append(recipients, row.SubjectID)
			}
			if row.SubjectID == id("reader") {
				reader = row
			}
		}
		clear(keys[:cap(keys)])
		slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		entry := contract.ValueEntry{Name: core.Name, Incarnation: core.EntryIncarnationID, ValueState: core.ValueStateID, OriginSnapshot: core.OriginSnapshotID, OriginTransition: core.OriginTransitionID, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, Recipients: recipients, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: payload.ContentLength, RetainedLength: payload.RetainedLength}
		entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		headToken := contract.Token{Family: family, Value: "1"}
		if family == contract.AWS {
			headToken.Value = `"1"`
		}
		selection := contract.ConsumerSelection{DomainID: core.DomainID, SnapshotID: id("selected snapshot"), HEADDigest: id("head"), AccessRoot: id("access root"), Root: contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: core.DomainID, Object: id("selected snapshot"), Digest: id("root digest"), Length: 1}, HEADRevision: id("head revision"), HEADToken: headToken, Entry: entry, Core: core, Payload: payload, Access: access, Binding: reader, Slot: 3}
		selection.EntryDigest, err = contract.PublicValueEntryDigest(core.DomainID, selection.Slot, entry)
		if err != nil {
			t.Fatal(err)
		}
		fresh := New(t, family, id("consumer fixture"), true, []contract.ID{id("authority"), id("reader")})
		check := fresh.Consume(context.Background(), selection, StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 || len(check.KeyUses) != 1 {
			t.Fatalf("reader sink result: %+v", check)
		}

		oracleDirectory, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(oracleDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		oracle := filepath.Join(oracleDirectory, "selected.private")
		check = fresh.CaptureSelected(context.Background(), selection, oracle)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
			t.Fatal("selected capture failed", check)
		}
		actual, err := os.ReadFile(oracle)
		if err != nil {
			t.Fatal(err)
		}
		expected, ok := syntheticValue(StandardValue)
		if !ok || !bytes.Equal(actual, expected) {
			t.Fatal("captured selected bytes differ")
		}
		clear(actual)
		clear(expected)
		info, err := os.Stat(oracle)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("oracle permissions differ")
		}
		check = fresh.CaptureSelected(context.Background(), selection, oracle)
		if check.Code == contract.CryptoSuccess || check.ValueMatched {
			t.Fatal("capture overwrote independent oracle")
		}
		current := selection
		current.Entry.Recipients = []contract.ID{reader.SubjectID}
		current.EntryDigest, err = contract.PublicValueEntryDigest(core.DomainID, current.Slot, current.Entry)
		if err != nil {
			t.Fatal(err)
		}
		check = fresh.Consume(context.Background(), current, StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
			t.Fatalf("current reader refused by retained-only wraps: %+v", check)
		}
		retainedOnly := current
		for _, row := range fresh.Bindings() {
			if row.SubjectKind == 1 && row.SubjectID != reader.SubjectID {
				retainedOnly.Binding = row
			}
		}
		check = fresh.Consume(context.Background(), retainedOnly, StandardValue)
		if check.Code != contract.CryptoInvalidAdmission || check.Delivery != 0 || check.SinkCalls != 0 {
			t.Fatalf("retained-only wrap granted current authority: %+v", check)
		}
		missingCurrent := selection
		missingCurrent.Access.Wraps = slices.DeleteFunc(slices.Clone(selection.Access.Wraps), func(row contract.WrapRow) bool {
			return row.SubjectKind == 1 && row.SubjectID != reader.SubjectID
		})
		check = fresh.Consume(context.Background(), missingCurrent, StandardValue)
		if check.Code != contract.CryptoInvalidAdmission || check.Delivery != 0 || check.SinkCalls != 0 {
			t.Fatalf("missing current reader wrap accepted: %+v", check)
		}
		readerRoute := fresh.routes[reader.Binding.BindingID]
		installed, err := privatecrypto.TestNewConsumerRuntime(fresh.runtime, readerRoute)
		if err != nil {
			t.Fatal(err)
		}
		var liveRoutes []Route
		for _, row := range fresh.Bindings() {
			route := Route{BindingID: row.Binding.BindingID}
			if row.SubjectID == reader.SubjectID {
				route.PrivateRoute = readerRoute
			} else if err := privatecrypto.TestRuntimeRoutes(installed, family, []contract.ID{fresh.routes[row.Binding.BindingID]}); err == nil {
				t.Fatal("reader runtime retained another private route")
			}
			liveRoutes = append(liveRoutes, route)
		}
		live := NewLive(t, installed, fresh.authority, fresh.recovery, fresh.Bindings(), liveRoutes)
		check = live.Consume(context.Background(), selection, StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 || len(check.KeyUses) != 1 {
			t.Fatalf("live reader-only sink result: %+v", check)
		}
		if public, private := live.Calls(); public != 0 || private != 1 {
			t.Fatalf("live fresh consumer calls: got %d/%d, want 0/1", public, private)
		}
		if installed.InstanceID() == fresh.runtime.InstanceID() {
			t.Fatal("reader reused source runtime instance")
		}
		wrongRecipient := selection
		for _, row := range live.Bindings() {
			if row.SubjectID == live.authority {
				wrongRecipient.Binding = row
			}
		}
		check = live.Consume(context.Background(), wrongRecipient, StandardValue)
		if check.Code != contract.CryptoInvalidAdmission || check.Delivery != 0 || check.SinkCalls != 0 {
			t.Fatalf("absent authority route fell back to reader: %+v", check)
		}
		if public, private := live.Calls(); public != 0 || private != 1 {
			t.Fatalf("refused admission used a live route: %d/%d", public, private)
		}
		fresh.SetDenied(reader.SubjectID, true)
		check = live.Consume(context.Background(), selection, StandardValue)
		if check.Code != contract.CryptoPrivateRouteUnavailable || check.Delivery != 0 || check.SinkCalls != 0 || len(check.KeyUses) != 1 || check.KeyUses[0].Outcome != contract.KeyUseDenied {
			t.Fatalf("live denied reader sink result: %+v", check)
		}
		if public, private := live.Calls(); public != 0 || private != 2 {
			t.Fatalf("live denied consumer calls: got %d/%d, want 0/2", public, private)
		}
		check = fresh.Consume(context.Background(), selection, StandardValue)
		if check.Code != contract.CryptoPrivateRouteUnavailable || check.Delivery != 0 || check.SinkCalls != 0 || len(check.KeyUses) != 1 || check.KeyUses[0].Outcome != contract.KeyUseDenied {
			t.Fatalf("denied reader sink result: %+v", check)
		}
		fresh.SetDenied(reader.SubjectID, false)
		fresh.SetSinkFailure(true)
		check = fresh.Consume(context.Background(), selection, StandardValue)
		if check.Code != contract.CryptoResponseUnknown || check.Delivery != 2 || check.SinkCalls != 1 {
			t.Fatalf("failed started sink result: %+v", check)
		}
	}
}

// full_only: false
func TestPrivateCaptureSinkBoundsAndOwnership(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "value.private")
	for _, row := range []struct {
		name         string
		path         string
		fail, cancel bool
		size         int
	}{
		{name: "empty", path: path},
		{name: "binary", path: filepath.Join(directory, "binary"), size: 32},
		{name: "relative", path: "value.private", size: 1},
		{name: "failed", path: filepath.Join(directory, "failed"), fail: true, size: 1},
		{name: "cancelled", path: filepath.Join(directory, "cancelled"), cancel: true, size: 1},
		{name: "maximum retained", path: filepath.Join(directory, "maximum"), size: 87_384},
		{name: "oversized", path: filepath.Join(directory, "oversized"), size: 87_385},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if row.cancel {
				cancel()
			}
			sink := privateSink{capturePath: row.path, fail: row.fail}
			value := make([]byte, row.size)
			if len(value) > 0 {
				value[len(value)-1] = 255
			}
			err := sink.Accept(ctx, value)
			success := row.name == "empty" || row.name == "binary" || row.name == "maximum retained"
			if (err == nil) != success {
				t.Fatal("capture disposition differs")
			}
			if success {
				actual, readErr := os.ReadFile(row.path)
				if readErr != nil || !bytes.Equal(actual, value) {
					t.Fatal("capture bytes differ")
				}
				clear(actual)
			} else if filepath.IsAbs(row.path) {
				if _, statErr := os.Lstat(row.path); !os.IsNotExist(statErr) {
					t.Fatal("refused capture created file")
				}
			}
			if err := sink.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err = os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if CapturePublicValue(filepath.Join(directory, "public"), []byte("private")) == nil {
		t.Fatal("public directory accepted")
	}
}
