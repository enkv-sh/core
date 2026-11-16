package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The fixture signs the supplied closure, including intentionally inconsistent
// relations. Open must reject those relations after it verifies the proofs.
func storeContractClosure(t *testing.T, f *fixture, state stateImage) {
	t.Helper()
	for i, page := range state.Pages {
		if page == nil {
			continue
		}
		body, err := format.EncodeValueEntryPage(*page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(format.ValueEntryPageKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		f.store.put(mustKey(t, f.store.desc.Prefix, ref), body)
		state.Root.ValueEntryPages[i] = &ref
	}
	body, err := format.EncodeRecipientPage(state.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(format.RecipientKind, state.Recipient.Domain, state.Recipient.Object, state.Recipient.Index, body)
	if err != nil {
		t.Fatalf("fixture recipient reference: %v", err)
	}
	f.store.put(mustKey(t, f.store.desc.Prefix, ref), body)
	state.Root.Recipients[state.Recipient.Index] = &ref
	refreshFixtureRecipientRefs(t, &state.Root)
	state.Root.ChildEncodedBytes = uint64(state.Root.AdministrativeIndex.Length)
	for _, refs := range [][]format.Ref{state.Root.AdministrativeIndexShards, state.Root.CurrentAccess.Core.AccessPageRefs, state.Root.RequiredSupport} {
		for _, ref := range refs {
			state.Root.ChildEncodedBytes += uint64(ref.Length)
		}
	}
	for _, refs := range [][]*format.Ref{state.Root.ValueEntryPages[:], state.Root.Recipients[:]} {
		for _, ref := range refs {
			if ref != nil {
				state.Root.ChildEncodedBytes += uint64(ref.Length)
			}
		}
	}
	storeContractRoot(t, f, state.Root, state.entryInputs())
}

func storeContractRoot(t *testing.T, f *fixture, root format.Root, desired []ApplyEntryInput) {
	t.Helper()
	refreshFixtureRecipientRefs(t, &root)
	body, err := format.EncodeRoot(root)
	if err != nil {
		t.Fatalf("fixture root encode: %v", err)
	}
	ref, err := format.Reference(format.RootKind, root.Domain, root.Snapshot, 0, body)
	if err != nil {
		t.Fatalf("fixture root reference: %v", err)
	}
	storeContractRootBytes(t, f, ref, body, desired)
}

func storeContractRootBytes(t *testing.T, f *fixture, ref format.Ref, body []byte, desired []ApplyEntryInput) {
	t.Helper()
	ref.Length, ref.Digest = uint32(len(body)), contract.Hash(body)
	f.store.put(mustKey(t, f.store.desc.Prefix, ref), body)
	head := f.session.head
	head.Core.Root = ref
	// Deliberately inconsistent rows may not form a valid supplied request.
	// Keep the admitted opaque historical digest in that case; the signed lengths
	// below describe the declared closure, whose actual relations Open must check.
	if rows, _, err := buildEntryIntent(head.Core.Domain, desired); err == nil {
		intent, err := contract.CompleteApplyIntentDescriptor(head.Core.Domain, rows, currentApplyRecipients(f.session.registry()))
		if err != nil {
			t.Fatal("fixture complete intent", err)
		}
		head.Subject.Normal.Intent = contract.DigestLength{Digest: intent.Digest, Length: intent.Length}
	}
	if root, err := format.DecodeRoot(body); err == nil {
		// Keep authenticated support facts for the unchanged mandatory rows.
		current := *f.session
		current.root = root
		for i, ref := range root.ValueEntryPages {
			if ref == nil {
				continue
			}
			page, err := format.DecodeValueEntryPage(f.store.objects[mustKey(t, f.store.desc.Prefix, *ref)].Body)
			if err != nil {
				continue
			}
			current.pages[i] = &page
		}
		// Relation-error cases must retain a valid signed shape so that the
		// responsible root/page check sees the intended invalid relation.
		validEntries := true
		for _, entry := range root.Names {
			if current.valueEntry(entry.Slot) == nil {
				validEntries = false
			}
		}
		if validEntries {
			// A damaged name/slot relation has no derivable public-state
			// projection. Retain the admitted nonzero digest so the signed
			// fixture reaches the selected relation check.
			if publicState := current.publicState(); !publicState.Digest.IsZero() {
				head.Subject.Normal.PublicState = publicState
			}
			if len(root.Names) > 0 {
				head.Subject.IdentityPlan.Length = 162 + 134 + uint64(len(root.Names[0].Name)) + 35
			}
			head.Subject.BeforeValueEntryCount, head.Subject.AfterValueEntryCount = root.ValueEntryCount, root.ValueEntryCount
			head.Subject.BeforeSecretCount, head.Subject.AfterSecretCount = uint16(root.SecretCount), uint16(root.SecretCount)
			head.Subject.BeforeRawBytes, head.Subject.AfterRawBytes = root.RawBytes, root.RawBytes
			head.Subject.BeforeMembershipCount, head.Subject.AfterMembershipCount = root.MembershipCount, root.MembershipCount
			head.Subject.BeforeAccessRoot, head.Subject.AfterAccessRoot = root.CurrentAccess.AccessRoot, root.CurrentAccess.AccessRoot
			head.Subject.Normal.Changed = 1
			head.Subject.Grant.Grants = grantCommitment(root.Domain, nil)
			head.Subject.Exclusion.Exclusions = exclusionCommitment(root.Domain, nil)
			head.Subject.Exclusion.Retirements = retirementCommitment(root.Domain)
			head.Subject.Normal.Union.Count = root.ValueEntryCount
			// Each union row has a 6-byte name/presence header and two
			// 68-byte sides; each membership adds two 32-byte recipient IDs.
			head.Subject.Normal.Union.Length = uint64(len("ENKV/CRYPTO/v2/lifecycle-union-v6\x00")+32+4) + 142*uint64(root.ValueEntryCount) + 64*uint64(root.MembershipCount)
			head.Subject.Normal.Intent.Length = fixtureValueIntentLength(&root) + fixtureCompleteIntentOverhead(t, f.session)
			for _, entry := range root.Names {
				head.Subject.Normal.Union.Length += uint64(len(entry.Name))
			}
		}
	}
	head.Subject.Request = requestCommitment(head.Core, head.Subject)
	storeHead(t, f, head, true)
	f.trust.signs = 0
}

func fixtureValueIntentLength(root *format.Root) uint64 {
	const rowFixed = 4 + 2 + 1 + 1 + 4 + 32 + 4 + 1 + 2*32
	length := uint64(len("ENKV/CRYPTO/v2/supplied-intent-v7\x00")+32+4) +
		rowFixed*uint64(root.ValueEntryCount) + 32*uint64(root.MembershipCount)
	for _, named := range root.Names {
		length += uint64(len(named.Name))
	}
	return length
}

func fixtureCompleteIntentOverhead(t *testing.T, session *StateSession) uint64 {
	t.Helper()
	values, err := contract.CryptoIntentDescriptor(session.root.Domain, nil)
	if err != nil {
		t.Fatal("fixture empty value intent", err)
	}
	complete, err := contract.CompleteApplyIntentDescriptor(session.root.Domain, nil, currentApplyRecipients(session.registry()))
	if err != nil {
		t.Fatal("fixture complete intent framing", err)
	}
	return complete.Length - values.Length
}

// full_only: false
func TestSignedClosureRejectsCompleteRelationErrors(t *testing.T) {
	for _, name := range []string{"valid", "duplicate-cross-page-name", "duplicate-cross-page-incarnation", "wrong-member-recipient", "wrong-current-recipient", "reused-key-binding", "wrong-member-count", "wrong-raw-total", "wrong-name-to-slot"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 32, false, 1)
			state := fixtureStateImage(t, f)
			switch name {
			case "duplicate-cross-page-name":
				state.Pages[1].Slots[0].Name = state.Pages[0].Slots[0].Name
			case "duplicate-cross-page-incarnation":
				state.Pages[1].Slots[0].Incarnation = state.Pages[0].Slots[0].Incarnation
			case "wrong-member-recipient":
				state.Pages[1].Slots[0].Recipients[0] = testID("foreign recipient")
			case "wrong-current-recipient":
				referenced := state.Pages[1].Slots[0].Recipients[0]
				foreign := testID("foreign current recipient")
				var target *contract.RecipientRecord
				var rows []*contract.RecipientRecord
				for _, row := range state.Recipient.Slots {
					if row == nil {
						continue
					}
					if row.RecipientID == foreign {
						t.Fatal("foreign recipient already exists")
					}
					rows = append(rows, row)
					if row.RecipientID == referenced {
						target = row
					}
				}
				if target == nil {
					t.Fatal("referenced recipient is missing before damage")
				}
				target.RecipientID = foreign
				slices.SortFunc(rows, func(a, b *contract.RecipientRecord) int {
					return bytes.Compare(a.RecipientID[:], b.RecipientID[:])
				})
				clear(state.Recipient.Slots[:])
				copy(state.Recipient.Slots[:], rows)
			case "reused-key-binding":
				var recipient *contract.RecipientRecord
				for _, row := range state.Recipient.Slots {
					if row != nil && row.RecipientID != state.Root.CurrentAccess.Core.AuthorityRecipientID {
						recipient = row
						break
					}
				}
				if recipient == nil || recipient.CurrentBinding == nil {
					t.Fatal("binding collision fixture has no non-Authority recipient")
				}
				recipient.CurrentBinding.BindingID = state.Pages[1].Slots[0].Incarnation
			case "wrong-member-count":
				state.Root.ValueEntryCount--
				state.Root.Names = state.Root.Names[:len(state.Root.Names)-1]
			case "wrong-raw-total":
				state.Root.RawBytes++
			case "wrong-name-to-slot":
				state.Root.Names[0].Slot, state.Root.Names[1].Slot = state.Root.Names[1].Slot, state.Root.Names[0].Slot
			}
			storeContractClosure(t, f, state)
			before := f.store.reads
			objects := len(f.store.objects)
			head := f.store.objects[f.store.desc.HeadKey]
			s, r := Open(context.Background(), f.admission, f.store)
			if name == "valid" {
				if s == nil || r.Outcome != ObservedCurrent {
					t.Fatalf("valid signed control: %+v", r)
				}
			} else if s != nil || r != (Result{Outcome: IntegrityFailure, Reason: InvalidRelation}) {
				t.Fatalf("signed inconsistent closure: session=%v result=%+v", s, r)
			}
			wantReads := int(state.Root.ChildCount) + 2
			configurationReads, fragmentReads, receiptReads := 0, 0, 0
			if name == "wrong-member-count" || name == "wrong-raw-total" {
				wantReads = 2
			} else if name != "duplicate-cross-page-incarnation" {
				configurationReads = int(state.Root.OutputConfiguration.SliceCount)
				fragmentReads = len(state.Root.Generated.Fragments)
				if name == "valid" {
					receiptReads = 2 * int(receiptIndexFragmentCount(t, state.Root))
				}
				wantReads += configurationReads + fragmentReads + receiptReads
			}
			if gotReads := f.store.reads - before; gotReads != wantReads {
				t.Fatalf("closure validation reads: actual=%d wanted=%d configuration=%d fragments=%d receipts=%d", gotReads, wantReads, configurationReads, fragmentReads, receiptReads)
			}
			if f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 || len(f.store.objects) != objects || !bytes.Equal(f.store.objects[f.store.desc.HeadKey].Body, head.Body) || f.store.objects[f.store.desc.HeadKey].Token != head.Token {
				t.Fatal("closure read repaired, pruned, signed or selected data")
			}
		})
	}
}

// full_only: false
func TestSelectedClosureReadFailuresKeepTheirMeaning(t *testing.T) {
	for _, target := range []string{"HEAD", "root", "unchanged-member-page", "recipient-page"} {
		for _, fault := range []string{"missing", "denied", "unavailable", "invalid"} {
			t.Run(target+"/"+fault, func(t *testing.T) {
				f := newFixture(t, 32, false, 1)
				key := f.store.desc.HeadKey
				switch target {
				case "root":
					key = mustKey(t, f.store.desc.Prefix, f.session.head.Core.Root)
				case "unchanged-member-page":
					key = mustKey(t, f.store.desc.Prefix, *f.session.root.ValueEntryPages[1])
				case "recipient-page":
					key = mustKey(t, f.store.desc.Prefix, *f.session.root.Recipients[0])
				}
				want := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable}
				injected := contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
				switch fault {
				case "missing":
					injected = contract.ReadResult{Status: contract.ReadMissing}
					want.Reason = MissingSelectedObject
					if target == "HEAD" {
						want.Outcome = RootLossUnsupported
					}
				case "denied":
					injected.Reason = contract.ReasonAccess
				case "invalid":
					injected = contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
					want = Result{Outcome: IntegrityFailure, Reason: InvalidFormat}
				}
				wantCalls := 1
				if injected.Status == contract.ReadUnavailable {
					want.StoreReason = injected.Reason
					if injected.Reason == contract.ReasonTransport {
						wantCalls = 3
					}
				}
				hits := 0
				f.store.readHook = func(name string, read contract.ReadResult) contract.ReadResult {
					if name == key {
						hits++
						return injected
					}
					return read
				}
				objects := len(f.store.objects)
				if s, r := Open(context.Background(), f.admission, f.store); s != nil || r != want {
					t.Fatalf("selected read failure: session=%v result=%+v want=%+v", s, r, want)
				}
				if hits != wantCalls || f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 || len(f.store.objects) != objects {
					t.Fatal("failed closure read did not stop at its owning boundary")
				}
			})
		}
	}
}

// full_only: false
func TestSignedClosureRejectsWrongObjectBindings(t *testing.T) {
	for _, name := range []string{"swapped-page", "valid-child-wrong-coordinate", "member-domain", "member-object", "recipient-coordinate", "recipient-key-fingerprint", "root-object", "root-domain", "root-type", "root-version", "unsupported-root-section"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 32, false, 1)
			state := fixtureStateImage(t, f)
			root := state.Root
			switch name {
			case "swapped-page":
				key := mustKey(t, f.store.desc.Prefix, *root.ValueEntryPages[0])
				other := mustKey(t, f.store.desc.Prefix, *root.ValueEntryPages[1])
				f.store.put(key, f.store.objects[other].Body)
			case "valid-child-wrong-coordinate", "member-domain", "member-object":
				page := *state.Pages[1]
				switch name {
				case "valid-child-wrong-coordinate":
					page.Index = 2
				case "member-domain":
					page.Domain = testID("foreign member domain")
				case "member-object":
					page.Object = testID("foreign member object")
				}
				body, err := format.EncodeValueEntryPage(page)
				if err != nil {
					t.Fatal(err)
				}
				ref := *root.ValueEntryPages[1]
				ref.Length, ref.Digest = uint32(len(body)), contract.Hash(body)
				f.store.put(mustKey(t, f.store.desc.Prefix, ref), body)
				root.ValueEntryPages[1] = &ref
				storeContractRoot(t, f, root, state.entryInputs())
			case "recipient-coordinate", "recipient-key-fingerprint":
				page := state.Recipient
				if name == "recipient-coordinate" {
					page.Index = 1
				}
				body, err := format.EncodeRecipientPage(page)
				if err != nil {
					t.Fatal(err)
				}
				if name == "recipient-key-fingerprint" {
					body[len(body)-1] ^= 1
				}
				ref := *root.Recipients[0]
				ref.Length, ref.Digest = uint32(len(body)), contract.Hash(body)
				f.store.put(mustKey(t, f.store.desc.Prefix, ref), body)
				root.Recipients[0] = &ref
				storeContractRoot(t, f, root, state.entryInputs())
			default:
				body := bytes.Clone(f.store.objects[mustKey(t, f.store.desc.Prefix, state.RootRef)].Body)
				switch name {
				case "root-object":
					body[7+32] ^= 1
				case "root-domain":
					body[7] ^= 1
				case "root-type":
					body[4] = byte(format.ValueEntryPageKind)
				case "root-version":
					body[6]++
				case "unsupported-root-section":
					generatedLength := 1 + 2*32 + 8*4 + 6*contract.GeneratorDescriptorLength + 2 + (32+2+2+1)*len(root.Generated.Fragments)
					if !root.Generated.ActiveOwner.IsZero() {
						generatedLength += 32
					}
					const gcRelationLength = 32 + 44
					offset := len(body) - generatedLength - gcRelationLength - 4
					if offset < 0 || offset+4 > len(body) || offset+4 != len(body)-generatedLength-gcRelationLength {
						t.Fatal("unsupported field does not immediately precede the generated closure and GC relation")
					}
					if binary.BigEndian.Uint32(body[offset:offset+4]) != 0 {
						t.Fatal("unsupported field is not initially zero")
					}
					binary.BigEndian.PutUint32(body[offset:offset+4], 1)
				}
				storeContractRootBytes(t, f, state.RootRef, body, state.entryInputs())
			}
			objects := len(f.store.objects)
			if s, r := Open(context.Background(), f.admission, f.store); s != nil || r != (Result{Outcome: IntegrityFailure, Reason: InvalidReference}) {
				t.Fatalf("signed wrong object binding: session=%v result=%+v", s, r)
			}
			if f.store.creates != 0 || f.store.cas != 0 || f.trust.signs != 0 || len(f.store.objects) != objects {
				t.Fatal("wrong object binding caused repair, pruning or signing")
			}
		})
	}
}

func refreshFixtureRecipientRefs(t *testing.T, root *format.Root) {
	t.Helper()
	refs := make([]contract.Ref, 0, contract.MaxRecipientPages)
	for _, ref := range root.Recipients {
		if ref != nil {
			refs = append(refs, *ref)
		}
	}
	descriptor, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: root.Domain, Refs: refs})
	if err != nil {
		t.Fatalf("fixture recipient refs descriptor: %v", err)
	}
	root.CurrentAccess.Core.RecipientRefsDescriptor = descriptor
	accessRoot, err := contract.AccessRoot(root.CurrentAccess.Core)
	if err != nil {
		t.Fatalf("fixture access root: %v", err)
	}
	root.CurrentAccess.AccessRoot = accessRoot
}
