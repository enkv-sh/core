package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestMemoryStoreFileBodiesKeepImmutableCopyAndTypedFailures(t *testing.T) {
	for _, fileBacked := range []bool{false, true} {
		name := "memory"
		if fileBacked {
			name = "file"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			env := memoryScenarioEnvironment(t)
			store := env.Store.(*memoryStore)
			original := []byte("original selected bytes")
			if result := store.Create(ctx, "fixture/old", original); result.Status != contract.WriteAcknowledged {
				t.Fatal("ordinary Create", result)
			}
			original[0] = 'X'
			if fileBacked {
				if err := store.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
					t.Fatal("enable file bodies", err)
				}
				old := store.objects["fixture/old"]
				if old.Body != nil || old.bodyPath == "" || old.bodyLength != uint64(len(original)) {
					t.Fatal("existing immutable body was not moved out of the map")
				}
				info, err := os.Stat(old.bodyPath)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("body file permissions", err)
				}
			}
			old := store.Read(ctx, "fixture/old", 1024)
			if old.Status != contract.ReadOK || !bytes.Equal(old.Body, []byte("original selected bytes")) {
				t.Fatal("existing immutable body changed", old)
			}
			if limited := store.Read(ctx, "fixture/old", 1); limited.Status != contract.ReadInvalid {
				t.Fatal("declared read limit changed", limited)
			}
			if err := env.Put(ctx, "fixture/direct", []byte("direct fixture body")); err != nil {
				t.Fatal("direct fixture Put", err)
			}
			if got := store.Read(ctx, "fixture/direct", 1024); got.Status != contract.ReadOK ||
				!bytes.Equal(got.Body, []byte("direct fixture body")) ||
				(fileBacked && (store.objects["fixture/direct"].bodyPath == "" || store.objects["fixture/direct"].Body != nil)) {
				t.Fatal("direct fixture Put bypassed immutable body storage", got)
			}
			copy := selectedMemoryStoreCopy(store)
			if fileBacked && (copy.fileBodies != store.fileBodies || copy.objects["fixture/old"].bodyPath != store.objects["fixture/old"].bodyPath) {
				t.Fatal("copy did not retain the exact immutable file reference")
			}
			newBody := []byte("branch-only immutable bytes")
			if result := copy.Create(ctx, "fixture/branch", newBody); result.Status != contract.WriteAcknowledged {
				t.Fatal("branch Create", result)
			}
			newBody[0] = 'X'
			if got := store.Read(ctx, "fixture/branch", 1024); got.Status != contract.ReadMissing {
				t.Fatal("copy wrote into the source key map", got)
			}
			if got := copy.Read(ctx, "fixture/branch", 1024); got.Status != contract.ReadOK ||
				!bytes.Equal(got.Body, []byte("branch-only immutable bytes")) {
				t.Fatal("branch body changed after caller mutation", got)
			}
			if got := copy.Read(ctx, "fixture/old", 1024); got.Status != contract.ReadOK ||
				got.Token != old.Token || !bytes.Equal(got.Body, old.Body) {
				t.Fatal("copy lost original bytes or token", got)
			}
			for _, mode := range []string{"lost-after", "conflict", "delayed"} {
				key := "fixture/" + mode
				copy.createMode = mode
				result := copy.Create(ctx, key, []byte("requested"))
				copy.createMode = ""
				switch mode {
				case "lost-after":
					if result.Status != contract.WriteUnknown || result.Reason != contract.ReasonTransport || result.NotSent ||
						!bytes.Equal(copy.Read(ctx, key, 1024).Body, []byte("requested")) {
						t.Fatal("lost-after Create changed", result)
					}
				case "conflict":
					if result.Status != contract.WritePrecondition ||
						!bytes.Equal(copy.Read(ctx, key, 1024).Body, []byte("different bytes")) {
						t.Fatal("conflict Create changed", result)
					}
				case "delayed":
					if result.Status != contract.WriteUnknown || result.NotSent || copy.Read(ctx, key, 1024).Status != contract.ReadMissing {
						t.Fatal("delayed Create entered early", result)
					}
					if err := copy.late(); err != nil || !bytes.Equal(copy.Read(ctx, key, 1024).Body, []byte("requested")) {
						t.Fatal("delayed Create did not preserve the bytes", err)
					}
				}
			}
			if result := copy.Create(ctx, copy.desc.HeadKey, []byte("head 0")); result.Status != contract.WriteAcknowledged {
				t.Fatal("HEAD Create", result)
			}
			head0 := copy.Read(ctx, copy.desc.HeadKey, 1024)
			if result := copy.CompareAndSwap(ctx, copy.desc.HeadKey, head0.Token, []byte("head 1")); result.Status != contract.WriteAcknowledged {
				t.Fatal("HEAD CAS", result)
			}
			head1 := copy.Read(ctx, copy.desc.HeadKey, 1024)
			if head1.Token == head0.Token || !bytes.Equal(head1.Body, []byte("head 1")) ||
				copy.CompareAndSwap(ctx, copy.desc.HeadKey, head0.Token, []byte("stale")).Status != contract.WritePrecondition {
				t.Fatal("HEAD CAS token condition changed")
			}
			copy.casMode = "delayed"
			delayed := copy.CompareAndSwap(ctx, copy.desc.HeadKey, head1.Token, []byte("head 2"))
			copy.casMode = ""
			if delayed.Status != contract.WriteUnknown || delayed.NotSent ||
				!bytes.Equal(copy.Read(ctx, copy.desc.HeadKey, 1024).Body, head1.Body) {
				t.Fatal("delayed HEAD CAS entered early", delayed)
			}
			if err := copy.late(); err != nil {
				t.Fatal("delayed HEAD CAS", err)
			}
			head2 := copy.Read(ctx, copy.desc.HeadKey, 1024)
			if head2.Token == head1.Token || !bytes.Equal(head2.Body, []byte("head 2")) {
				t.Fatal("delayed HEAD CAS changed its token or bytes", head2)
			}
			copy.casMode = "lost-after"
			lost := copy.CompareAndSwap(ctx, copy.desc.HeadKey, head2.Token, []byte("head 3"))
			copy.casMode = ""
			if lost.Status != contract.WriteUnknown || lost.NotSent ||
				!bytes.Equal(copy.Read(ctx, copy.desc.HeadKey, 1024).Body, []byte("head 3")) {
				t.Fatal("lost-after HEAD CAS changed", lost)
			}
			if !fileBacked {
				return
			}
			copy.fileBodies.mu.Lock()
			priorUsed := copy.fileBodies.used
			copy.fileBodies.used = fixtureBodyFileLimit
			copy.fileBodies.mu.Unlock()
			bounded := copy.Create(ctx, "fixture/beyond-disk-bound", []byte{1})
			copy.fileBodies.mu.Lock()
			copy.fileBodies.used = priorUsed
			copy.fileBodies.mu.Unlock()
			if bounded.Status != contract.WriteUnknown || bounded.Reason != contract.ReasonTransport || !bounded.NotSent ||
				copy.Read(ctx, "fixture/beyond-disk-bound", 1024).Status != contract.ReadMissing {
				t.Fatal("disk safety bound changed the Store", bounded)
			}
			branchPath := copy.objects["fixture/branch"].bodyPath
			if err := os.WriteFile(branchPath, []byte("branch-only immutable byteX"), 0600); err != nil {
				t.Fatal(err)
			}
			if got := copy.Read(ctx, "fixture/branch", 1024); got.Status != contract.ReadInvalid || got.Reason != contract.ReasonMalformed {
				t.Fatal("same-length body damage was not detected", got)
			}
			if err := os.Remove(store.objects["fixture/old"].bodyPath); err != nil {
				t.Fatal(err)
			}
			if got := store.Read(ctx, "fixture/old", 1024); got.Status != contract.ReadUnavailable || got.Reason != contract.ReasonTransport {
				t.Fatal("missing backing file was not an unavailable read", got)
			}
			oldDirectory := store.fileBodies.directory
			store.fileBodies.directory = filepath.Join(t.TempDir(), "absent")
			failed := store.Create(ctx, "fixture/not-written", []byte("write failure"))
			store.fileBodies.directory = oldDirectory
			if failed.Status != contract.WriteUnknown || failed.Reason != contract.ReasonTransport || !failed.NotSent ||
				store.Read(ctx, "fixture/not-written", 1024).Status != contract.ReadMissing {
				t.Fatal("failed file write changed the Store", failed)
			}
			store.createMode = "delayed"
			pending := store.Create(ctx, "fixture/delayed-file-error", []byte("late body"))
			store.createMode = ""
			store.fileBodies.directory = filepath.Join(t.TempDir(), "absent")
			lateErr := store.late()
			store.fileBodies.directory = oldDirectory
			if pending.Status != contract.WriteUnknown || pending.NotSent || lateErr == nil ||
				store.Read(ctx, "fixture/delayed-file-error", 1024).Status != contract.ReadMissing {
				t.Fatal("delayed file error was hidden", pending, lateErr)
			}
		})
	}
}
