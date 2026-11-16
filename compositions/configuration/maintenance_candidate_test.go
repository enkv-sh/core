package configuration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The witness uses the ordinary record encoders for routine candidate setup.
// Assertions below damage exact saved wire fields and independently require
// that missing, extra, corrupt and oversized evidence is refused.
func maintenanceCandidateFixture(t *testing.T, head *format.Head, material *MaintenanceMaterial, control contract.ControlCore, raw int) {
	t.Helper()
	id := successorID
	payload, err := contract.EncodeCanonicalPayload(contract.CanonicalPayload{Profile: contract.MaterialCryptoProfile, CryptoSupportID: id(54), DataKeyID: id(55), DataKeyEpoch: 1, CommitmentKeyID: id(56), CommitmentKeyEpoch: 1, ContentLength: uint32(raw), Ciphertext: make([]byte, raw+16), InputEncoding: contract.InputEncodingRaw, RetainedLength: uint32(raw)})
	if err != nil {
		t.Fatal(err)
	}
	entry := contract.ValueEntry{Name: "opaque", Incarnation: id(50), ValueState: id(52), OriginSnapshot: id(57), OriginTransition: id(58), ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{control.AuthorityRecipientID}, ValueBytes: payload, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len(payload) - contract.CanonicalPayloadOverhead), RetainedLength: uint32(len(payload) - contract.CanonicalPayloadOverhead)}
	page := format.ValueEntryPage{Domain: head.Core.Domain, Object: id(59), Index: 0}
	page.Slots[0] = &entry
	body, err := format.EncodeValueEntryPage(page)
	if err != nil {
		t.Fatal(err)
	}
	pageRef, err := format.Reference(format.ValueEntryPageKind, page.Domain, page.Object, page.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	recipient := format.RecipientPage{Domain: head.Core.Domain, Object: id(60), Index: 0}
	binding := control.AuthorityKMSBinding
	recipient.Slots[0] = &contract.RecipientRecord{RecipientID: control.AuthorityRecipientID, Status: contract.CurrentRecipient, CurrentBinding: &binding}
	recipientBody, err := format.EncodeRecipientPage(recipient)
	if err != nil {
		t.Fatal(err)
	}
	recipientRef, err := format.Reference(format.RecipientKind, recipient.Domain, recipient.Object, 0, recipientBody)
	if err != nil {
		t.Fatal(err)
	}
	bindingDigest, err := contract.PublicBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: entry.ValueState, MaterialContextDigest: id(61), PackageCheck: id(62), Wraps: []contract.WrapRow{{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: control.AuthorityRecipientID, BindingID: binding.BindingID, BindingSerial: binding.BindingSerial, PublicBindingDigest: bindingDigest, RSACiphertext: make([]byte, 384)}}}
	accessPage := format.AccessPage{Domain: head.Core.Domain, Object: id(63), Index: 0, Records: []contract.AccessRecord{access}}
	accessBody, err := format.EncodeAccessPage(accessPage)
	if err != nil {
		t.Fatal(err)
	}
	accessRef, err := format.Reference(format.AccessKind, accessPage.Domain, accessPage.Object, 0, accessBody)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: head.Core.Domain, Refs: []contract.Ref{recipientRef}})
	if err != nil {
		t.Fatal(err)
	}
	records, err := contract.AccessRecordsDescriptor(head.Core.Domain, []contract.AccessRecord{access})
	if err != nil {
		t.Fatal(err)
	}
	current := contract.CurrentAccessCore{CurrentControl: control.CurrentControl, RecipientRefsDescriptor: recipients, AccessPageRefs: []contract.Ref{accessRef}, AccessRecordsDescriptor: records}
	accessRoot, err := contract.AccessRoot(current)
	if err != nil {
		t.Fatal(err)
	}
	configBody, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: head.Core.Domain})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, _, err := contract.SplitOutputConfiguration(head.Core.Domain, configBody)
	if err != nil {
		t.Fatal(err)
	}
	// These two children are outside the bounded value-material witness. Their
	// references still obey the ordinary root's complete shape/accounting rules.
	admin := contract.Ref{Kind: contract.AdministrativeIndexKind, Domain: head.Core.Domain, Object: id(64), Digest: id(65), Format: contract.CanonicalSchema, Length: 1, Index: 0}
	support := contract.Ref{Kind: contract.RequiredSupportKind, Domain: head.Core.Domain, Object: id(66), Digest: id(67), Format: contract.CanonicalSchema, Length: 1024, Index: 0}
	root := format.Root{Domain: head.Core.Domain, Snapshot: head.Core.Root.Object, Transition: id(68), CurrentAccess: contract.CurrentAccessSection{Core: current, AccessRoot: accessRoot}, AdministrativeIndex: admin, RequiredSupport: []contract.Ref{support}, OutputConfiguration: descriptor, Names: []format.NameEntry{{Name: entry.Name, Slot: 0}}, ValueEntryCount: 1, SecretCount: 1, RawBytes: uint64(raw), MembershipCount: 1, SecretOrdinaryWrapCount: 1, RecipientCount: 1, AccessRecordCount: 1, RequiredSupportRecordCount: 1, ChildCount: 5, ChildEncodedBytes: uint64(pageRef.Length) + uint64(recipientRef.Length) + uint64(accessRef.Length) + uint64(admin.Length) + uint64(support.Length), Generated: format.EmptyGeneratedClosure(), GCPlans: contract.EmptyGCOwnersDescriptor()}
	root.ValueEntryPages[0] = &pageRef
	root.Recipients[0] = &recipientRef
	rootBody, err := format.EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	head.Core.Root, err = format.Reference(format.RootKind, root.Domain, root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.BeforeRawBytes, head.Subject.AfterRawBytes = uint64(raw), uint64(raw)
	head.Subject.AfterAccessRoot = accessRoot
	beforeEntry := entry
	beforeEntry.ValueState = material.RekeyTarget.Material
	beforePage := page
	beforePage.Object = id(69)
	beforePage.Slots[0] = &beforeEntry
	beforePageBody, err := format.EncodeValueEntryPage(beforePage)
	if err != nil {
		t.Fatal(err)
	}
	beforePageRef, err := format.Reference(format.ValueEntryPageKind, beforePage.Domain, beforePage.Object, 0, beforePageBody)
	if err != nil {
		t.Fatal(err)
	}
	beforeAccess := access
	beforeAccess.MaterialID = beforeEntry.ValueState
	beforeAccessPage := accessPage
	beforeAccessPage.Object = id(70)
	beforeAccessPage.Records = []contract.AccessRecord{beforeAccess}
	beforeAccessBody, err := format.EncodeAccessPage(beforeAccessPage)
	if err != nil {
		t.Fatal(err)
	}
	beforeAccessRef, err := format.Reference(format.AccessKind, beforeAccessPage.Domain, beforeAccessPage.Object, 0, beforeAccessBody)
	if err != nil {
		t.Fatal(err)
	}
	beforeRecords, err := contract.AccessRecordsDescriptor(head.Core.Domain, []contract.AccessRecord{beforeAccess})
	if err != nil {
		t.Fatal(err)
	}
	beforeCurrent := current
	beforeCurrent.AccessPageRefs = []contract.Ref{beforeAccessRef}
	beforeCurrent.AccessRecordsDescriptor = beforeRecords
	beforeAccessRoot, err := contract.AccessRoot(beforeCurrent)
	if err != nil {
		t.Fatal(err)
	}
	beforeRoot := root
	beforeRoot.Snapshot, beforeRoot.Transition = id(71), id(72)
	beforeRoot.CurrentAccess = contract.CurrentAccessSection{Core: beforeCurrent, AccessRoot: beforeAccessRoot}
	beforeRoot.ValueEntryPages[0] = &beforePageRef
	beforeRootBody, err := format.EncodeRoot(beforeRoot)
	if err != nil {
		t.Fatal(err)
	}
	beforeHead := *head
	beforeHead.Core.Revision = head.Core.PreviousRevision
	beforeHead.Core.PreviousRevision, beforeHead.Core.PreviousDigest = id(73), id(74)
	beforeHead.Core.Root, err = format.Reference(format.RootKind, beforeRoot.Domain, beforeRoot.Snapshot, 0, beforeRootBody)
	if err != nil {
		t.Fatal(err)
	}
	beforeHead.Subject.BeforeAccessRoot = id(75)
	beforeHead.Subject.AfterAccessRoot = beforeAccessRoot
	maintenanceFixtureBindHead(t, &beforeHead)
	beforeHeadBody, err := format.EncodeHead(beforeHead)
	if err != nil {
		t.Fatal("encode predecessor HEAD fixture", err)
	}
	head.Core.PreviousDigest = contract.Hash(beforeHeadBody)
	head.Subject.BeforeAccessRoot = beforeAccessRoot
	material.RekeyTarget.BeforePublicEntryDigest, err = contract.PublicValueEntryDigest(head.Core.Domain, 0, beforeEntry)
	if err != nil {
		t.Fatal(err)
	}
	material.PinDeltas = []MaintenancePinDelta{{Name: entry.Name, Before: contract.RetainedSecretInput{Incarnation: entry.Incarnation, Material: beforeEntry.ValueState}, After: contract.RetainedSecretInput{Incarnation: entry.Incarnation, Material: entry.ValueState}}}
	material.PredecessorHead = beforeHeadBody
	material.PredecessorRoot = beforeRootBody
	material.PredecessorPages = []MaintenanceValuePage{{Index: 0, Body: beforePageBody}}
	maintenanceFixtureBindHead(t, head)
	material.CandidateRoot = rootBody
	material.CandidatePages = []MaintenanceValuePage{{Index: 0, Body: body}}
}

func maintenanceFixtureBindHead(t *testing.T, head *format.Head) {
	t.Helper()
	coreBody, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := contract.MatchHeadCondition(head.Core.PreviousToken)
	if err != nil {
		t.Fatal(err)
	}
	conditional, err := format.EncodeConditionalPlan(format.ConditionalPlan{Family: head.Core.PreviousToken.Family, Store: head.Core.Store, Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody, Condition: condition, HeadCore: contract.Hash(coreBody), HeadCoreLength: uint32(len(coreBody))})
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.HeadCore, head.Subject.HeadCoreLength, head.Subject.ConditionalPlan = contract.Hash(coreBody), uint32(len(coreBody)), contract.Hash(conditional)
}

// full_only: false
func TestMaintenanceCandidateMaterialCodecChecksExactPages(t *testing.T) {
	pair, request, material := maintenanceFileFixture(t, JSON, contract.OperationEnvelopeRekey)
	output, err := PrepareMaintenanceOutput(t.Context(), pair, filepath.Join(t.TempDir(), "successor"), request)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceOwner(t, output)
	// A full raw value makes the encoded page exceed the scanner window while
	// staying within the ordinary value/page and complete pair bounds.
	_, _, _, base := successorFileFixture(t, JSON)
	head, err := format.DecodeHead(material.SignedCandidate)
	if err != nil {
		t.Fatal(err)
	}
	maintenanceCandidateFixture(t, &head, &material, base.Control, contract.CryptoMaxRawValue)
	material.SignedCandidate, err = format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	readback, err := output.Publish(t.Context(), material)
	if err != nil {
		t.Fatal(err)
	}
	metadata := readback.Model.Maintenance
	body, err := maintenanceMetadataBytes(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.CandidatePages[0].Body) <= WindowBytes {
		t.Fatal("fixture did not cross scanner window")
	}
	valid := newParser(t.Context(), bytes.NewReader(body), JSON)
	decoded := parseMaintenanceMetadata(valid)
	if err := valid.done(); err != nil || !bytes.Equal(decoded.CandidatePages[0].Body, material.CandidatePages[0].Body) {
		t.Fatal("domain-sized base64 witness refused", err)
	}
	for _, condition := range []string{"missing-root", "missing-pages", "missing-page", "extra-page", "duplicate-page", "wrong-index", "corrupt-page", "oversized-page", "oversized-root", "unknown-material-field"} {
		t.Run(condition, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			var candidate map[string]json.RawMessage
			if err := json.Unmarshal(fields["candidate_material"], &candidate); err != nil {
				t.Fatal(err)
			}
			var pages []map[string]json.RawMessage
			if err := json.Unmarshal(candidate["pages"], &pages); err != nil {
				t.Fatal(err)
			}
			encode := func(v any) json.RawMessage {
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			switch condition {
			case "missing-root":
				delete(candidate, "root")
			case "missing-pages":
				delete(candidate, "pages")
			case "missing-page":
				candidate["pages"] = encode([]any{})
			case "extra-page":
				pages = append(pages, map[string]json.RawMessage{"index": encode(1), "body": pages[0]["body"]})
				candidate["pages"] = encode(pages)
			case "duplicate-page":
				pages = append(pages, pages[0])
				candidate["pages"] = encode(pages)
			case "wrong-index":
				pages[0]["index"] = encode(32)
				candidate["pages"] = encode(pages)
			case "corrupt-page":
				page := bytes.Clone(material.CandidatePages[0].Body)
				page[len(page)-1] ^= 1
				pages[0]["body"] = encode(base64.StdEncoding.EncodeToString(page))
				candidate["pages"] = encode(pages)
			case "oversized-page":
				pages[0]["body"] = encode(base64.StdEncoding.EncodeToString(make([]byte, contract.MaxValueEntryPageLength+1)))
				candidate["pages"] = encode(pages)
			case "oversized-root":
				candidate["root"] = encode(base64.StdEncoding.EncodeToString(make([]byte, contract.MaxRootLength+1)))
			case "unknown-material-field":
				candidate["foreign"] = encode(true)
			}
			fields["candidate_material"] = encode(candidate)
			damaged := encode(fields)
			parser := newParser(t.Context(), bytes.NewReader(damaged), JSON)
			parseMaintenanceMetadata(parser)
			if err := parser.done(); err == nil {
				t.Fatal("invalid candidate material parsed")
			}
		})
	}
}

// full_only: false
func TestMaintenanceMetadataFramingFitsReservedAccount(t *testing.T) {
	for _, encoding := range []Format{JSON, YAML} {
		t.Run(strconv.Itoa(int(encoding)), func(t *testing.T) {
			pair, request, material := maintenanceFileFixture(t, encoding, contract.OperationRetireRecipientIdentity)
			output, err := PrepareMaintenanceOutput(t.Context(), pair, filepath.Join(t.TempDir(), "successor"), request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, output)
			readback, err := output.Publish(t.Context(), material)
			if err != nil {
				t.Fatal(err)
			}
			metadata := readback.Model.Maintenance
			body, err := maintenanceMetadataBytes(metadata)
			if err != nil {
				t.Fatal(err)
			}
			normalized := len(body) - 4*((len(metadata.SignedCandidate)+2)/3) - len(metadata.OutputPath) - len(metadata.Request.RecipientReference)
			for _, n := range []uint64{metadata.Source.Editable.Length, metadata.Source.Generated.Length, uint64(metadata.Request.OperationKind), uint64(metadata.Retirement.Slot), uint64(metadata.Retirement.BeforeRecordLength)} {
				normalized -= len(strconv.FormatUint(n, 10)) - 1
			}
			// Python json.dumps with indent=2 and a two-space outer prefix,
			// ten 64-character IDs, five zero-valued numeric fields and empty
			// candidate/path/reference strings independently gives 1246 bytes.
			if normalized != 1246 || len(metadata.PinDeltas) != 0 || len(metadata.CandidateRoot) != 0 {
				t.Fatal("small metadata encoding differs from independent framing", normalized)
			}
		})
	}
}

// full_only: false
func TestMaintenanceMaterialMetadataMatchesIndependentFraming(t *testing.T) {
	for _, encoding := range []Format{JSON, YAML} {
		t.Run(strconv.Itoa(int(encoding)), func(t *testing.T) {
			pair, request, material := maintenanceFileFixture(t, encoding, contract.OperationEnvelopeRekey)
			output, err := PrepareMaintenanceOutput(t.Context(), pair, filepath.Join(t.TempDir(), "successor"), request)
			if err != nil {
				t.Fatal(err)
			}
			defer closeSourceOwner(t, output)
			readback, err := output.Publish(t.Context(), material)
			if err != nil {
				t.Fatal(err)
			}
			m := readback.Model.Maintenance
			body, err := maintenanceMetadataBytes(m)
			if err != nil || len(m.PinDeltas) != 1 || len(m.PredecessorPages) != 1 || len(m.CandidatePages) != 1 {
				t.Fatal("complete two-sided small metadata not encoded", err)
			}
			normalized := len(body) - len(m.OutputPath) - len(m.Request.Name) - len(m.RekeyTarget.Name) - len(m.PinDeltas[0].Name)
			padded := func(n int) int { return 4 * ((n + 2) / 3) }
			for _, payload := range [][]byte{m.SignedCandidate, m.CandidateRoot, m.CandidatePages[0].Body, m.PredecessorHead, m.PredecessorRoot, m.PredecessorPages[0].Body} {
				normalized -= padded(len(payload))
			}
			for _, n := range []uint64{m.Source.Editable.Length, m.Source.Generated.Length, uint64(m.Request.OperationKind), uint64(m.RekeyTarget.Slot), uint64(m.CandidatePages[0].Index), uint64(m.PredecessorPages[0].Index)} {
				normalized -= len(strconv.FormatUint(n, 10)) - 1
			}
			// Independent Python JSON framing with thirteen 64-character IDs,
			// six zero numeric fields, one pin row, both one-page material
			// objects and empty payload/path/name strings gives 1908 bytes.
			if normalized != 1908 {
				t.Fatal("actual two-sided encoding differs from independent framing", normalized)
			}
			reserved := 8192 + 6*(len(m.OutputPath)+256) + 512 + 18*len(m.Request.Name) + 2*padded(65536) + 2*padded(262144) + 2*padded(len(material.PredecessorPages[0].Body)) + 256
			if len(body) > reserved || uint64(reserved)+m.Source.Editable.Length+m.Source.Generated.Length > 268435456 {
				t.Fatal("small actual metadata exceeded its admitted account", len(body), reserved)
			}
		})
	}
}

// full_only: false
func TestMaintenancePredecessorMaterialCodecChecksExactRecords(t *testing.T) {
	pair, request, material := maintenanceFileFixture(t, JSON, contract.OperationEnvelopeRekey)
	output, err := PrepareMaintenanceOutput(t.Context(), pair, filepath.Join(t.TempDir(), "successor"), request)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceOwner(t, output)
	readback, err := output.Publish(t.Context(), material)
	if err != nil {
		t.Fatal(err)
	}
	body, err := maintenanceMetadataBytes(readback.Model.Maintenance)
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"missing-material", "missing-head", "missing-root", "missing-pages", "head", "root", "page", "empty-pages", "duplicate-page", "extra-page", "oversized-head", "oversized-root", "oversized-page", "unknown-field", "different-predecessor-revision"} {
		t.Run(condition, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			var predecessor map[string]json.RawMessage
			if err := json.Unmarshal(fields["predecessor_material"], &predecessor); err != nil {
				t.Fatal(err)
			}
			var pages []map[string]json.RawMessage
			if err := json.Unmarshal(predecessor["pages"], &pages); err != nil || len(pages) != 1 {
				t.Fatal("one exact page required", err)
			}
			encode := func(v any) json.RawMessage {
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			blob := func(v []byte) json.RawMessage { return encode(base64.StdEncoding.EncodeToString(v)) }
			switch condition {
			case "missing-head":
				delete(predecessor, "head")
			case "missing-root":
				delete(predecessor, "root")
			case "missing-pages":
				delete(predecessor, "pages")
			case "head":
				changed := bytes.Clone(material.PredecessorHead)
				changed[len(changed)-1] ^= 1
				predecessor["head"] = blob(changed)
			case "root":
				changed := bytes.Clone(material.PredecessorRoot)
				changed[len(changed)-1] ^= 1
				predecessor["root"] = blob(changed)
			case "page":
				changed := bytes.Clone(material.PredecessorPages[0].Body)
				changed[len(changed)-1] ^= 1
				pages[0]["body"] = blob(changed)
				predecessor["pages"] = encode(pages)
			case "empty-pages":
				predecessor["pages"] = encode([]any{})
			case "duplicate-page":
				predecessor["pages"] = encode(append(pages, pages[0]))
			case "extra-page":
				predecessor["pages"] = encode(append(pages, map[string]json.RawMessage{"index": encode(1), "body": pages[0]["body"]}))
			case "oversized-head":
				predecessor["head"] = blob(make([]byte, 65537))
			case "oversized-root":
				predecessor["root"] = blob(make([]byte, 262145))
			case "oversized-page":
				pages[0]["body"] = blob(make([]byte, 2097153))
				predecessor["pages"] = encode(pages)
			case "unknown-field":
				predecessor["foreign"] = encode(true)
			case "different-predecessor-revision":
				before, err := format.DecodeHead(material.PredecessorHead)
				if err != nil {
					t.Fatal(err)
				}
				before.Core.Revision = successorID(86)
				maintenanceFixtureBindHead(t, &before)
				beforeBody, err := format.EncodeHead(before)
				if err != nil {
					t.Fatal(err)
				}
				predecessor["head"] = blob(beforeBody)
				after, err := format.DecodeHead(material.SignedCandidate)
				if err != nil {
					t.Fatal(err)
				}
				after.Core.PreviousDigest = contract.Hash(beforeBody)
				maintenanceFixtureBindHead(t, &after)
				afterBody, err := format.EncodeHead(after)
				if err != nil {
					t.Fatal(err)
				}
				fields["candidate"] = blob(afterBody)
			}
			fields["predecessor_material"] = encode(predecessor)
			if condition == "missing-material" {
				delete(fields, "predecessor_material")
			}
			p := newParser(t.Context(), bytes.NewReader(encode(fields)), JSON)
			parseMaintenanceMetadata(p)
			if err := p.done(); err == nil {
				t.Fatal("invalid predecessor records admitted", condition)
			}
		})
	}
}
