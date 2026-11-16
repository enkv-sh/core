package crypto

import (
	"bytes"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func accessRowFixture(t *testing.T) (accessCallerContextFixture, []contract.CompactRow) {
	t.Helper()
	f := newAccessCallerContextFixture(t)
	source := slices.IndexFunc(f.q.BindingTable, func(row contract.BindingTableRow) bool { return row.SubjectID == f.control.AuthorityRecipientID })
	before := slices.IndexFunc(f.q.BindingTable, func(row contract.BindingTableRow) bool {
		return row.SubjectID == f.intent.RecipientID && row.Binding.BindingSerial == f.intent.Before.BindingSerial
	})
	core := contract.ValueCore{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: f.q.Context.CompatibilityID, CryptoSupportID: contract.CryptoSupportID(), DomainID: f.q.Context.DomainID, ValueSource: contract.Supplied, EntryIncarnationID: consumerID("access entry incarnation"), OriginSnapshotID: consumerID("access origin snapshot"), OriginTransitionID: consumerID("access origin transition"), DataKeyEpoch: 1, CommitmentKeyEpoch: 1, ContentLength: 12, InputEncoding: contract.InputEncodingRaw, RetainedLength: 12}
	consumer, err := contract.CurrentValueConsumerDigest(core.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	var rows []contract.CompactRow
	for _, name := range []string{"first", "second"} {
		core.Name = name
		core.ValueStateID = consumerID(name + " access material")
		core.DataKeyID = consumerID(name + " access data")
		core.CommitmentKeyID = consumerID(name + " access commitment")
		payload, keys, err := custody.SealValue(core, []byte("secret-value"))
		if err != nil {
			t.Fatal(err)
		}
		access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: core.ValueStateID, PackageCheck: payload.PackageCheck}
		for i, binding := range f.q.BindingTable {
			if i != source && i != before {
				continue
			}
			wrapCore, err := custody.ValueWrapCore(core, binding)
			if err != nil {
				t.Fatal(err)
			}
			access.MaterialContextDigest = wrapCore.MaterialContextDigest
			wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
			if err != nil {
				t.Fatal(err)
			}
			access.Wraps = append(access.Wraps, wrap)
		}
		clear(keys[:cap(keys)])
		body, err := contract.EncodeCanonicalPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := contract.AccessRecordDigest(access)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.CompactRow{ValueCore: core, BeforeAccessRecord: access, Coverage: contract.CoverageRow{MaterialKind: contract.ValueMaterialKind, MaterialID: core.ValueStateID, MaterialContextDigest: access.MaterialContextDigest, ImmutableBodyDigest: contract.Hash(body), BeforeAccessDigest: digest, RequiredConsumerDigest: consumer, SourceBindingIndex: uint16(source), TargetBindingIndices: []uint16{f.q.Replacements[0].SuccessorBindingIndex}}})
	}
	slices.SortFunc(rows, func(a, b contract.CompactRow) int {
		return bytes.Compare(a.Coverage.MaterialID[:], b.Coverage.MaterialID[:])
	})
	plan, err := contract.AccessReplacementPlanDescriptor(f.q.Plan())
	if err != nil {
		t.Fatal(err)
	}
	projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: f.q.Context.DomainID, BeforeAccessRoot: f.q.Context.CurrentAccessRoot, RequestCoreDigest: f.q.Context.IntentDescriptor.Digest}, plan, uint32(len(rows)))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if err := projection.Add(row, contract.AccessOutputRow{MaterialKind: row.Coverage.MaterialKind, MaterialID: row.Coverage.MaterialID, BeforeAccessDigest: row.Coverage.BeforeAccessDigest, AfterAccessRecord: row.BeforeAccessRecord}); err != nil {
			t.Fatal(err)
		}
	}
	f.q.ExpectedCoverageDescriptor, _, _, err = projection.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	f.body, err = contract.EncodeCryptoAccessReplaceRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	f.rows = rows
	f.route.override = f.sourceRoute.Decrypt
	return f, rows
}

func startAccessRows(t *testing.T, f accessCallerContextFixture) (*Runtime, contract.ID) {
	t.Helper()
	r := f.runtime(t, f.route)
	reply := applyCall(r, t.Context(), contract.CryptoAccessReplace, f.body)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("access start", reply.ResultCode)
	}
	start, err := contract.DecodeCryptoAccessReplaceResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	return r, start.OperationRef
}

// full_only: false
func TestAccessNonfinalRowsRequireExactAdmittedCoverage(t *testing.T) {
	for _, damage := range []string{"immutable-body", "consumer", "access", "material", "core-context", "source", "successor"} {
		t.Run(damage, func(t *testing.T) {
			f, rows := accessRowFixture(t)
			r, operation := startAccessRows(t, f)
			row := rows[0]
			row.Coverage.TargetBindingIndices = slices.Clone(row.Coverage.TargetBindingIndices)
			switch damage {
			case "immutable-body":
				row.Coverage.ImmutableBodyDigest[0] ^= 1
			case "consumer":
				row.Coverage.RequiredConsumerDigest[0] ^= 1
			case "source":
				row.Coverage.SourceBindingIndex = uint16(r.access.beforeIndex)
			case "successor":
				row.Coverage.TargetBindingIndices[0] = uint16(r.access.beforeIndex)
			case "access", "material", "core-context":
				if damage == "material" {
					row.ValueCore.ValueStateID = consumerID("unadmitted material")
				}
				if damage == "core-context" {
					row.ValueCore.OriginSnapshotID = consumerID("unadmitted origin")
				}
				payload, keys, err := custody.SealValue(row.ValueCore, []byte("secret-value"))
				if err != nil {
					t.Fatal(err)
				}
				defer clear(keys[:cap(keys)])
				row.BeforeAccessRecord.Wraps = slices.Clone(row.BeforeAccessRecord.Wraps)
				row.BeforeAccessRecord.MaterialID = row.ValueCore.ValueStateID
				row.BeforeAccessRecord.PackageCheck = payload.PackageCheck
				for i, old := range row.BeforeAccessRecord.Wraps {
					binding := f.q.BindingTable[slices.IndexFunc(f.q.BindingTable, func(binding contract.BindingTableRow) bool { return binding.Binding.BindingID == old.BindingID })]
					core, err := custody.ValueWrapCore(row.ValueCore, binding)
					if err != nil {
						t.Fatal(err)
					}
					row.BeforeAccessRecord.MaterialContextDigest = core.MaterialContextDigest
					row.BeforeAccessRecord.Wraps[i], err = custody.Wrap(core, binding.Binding, keys)
					if err != nil {
						t.Fatal(err)
					}
				}
				row.Coverage.MaterialID = row.ValueCore.ValueStateID
				row.Coverage.MaterialContextDigest = row.BeforeAccessRecord.MaterialContextDigest
				row.Coverage.BeforeAccessDigest, err = contract.AccessRecordDigest(row.BeforeAccessRecord)
				if err != nil {
					t.Fatal(err)
				}
				body, err := contract.EncodeCanonicalPayload(payload)
				if err != nil {
					t.Fatal(err)
				}
				row.Coverage.ImmutableBodyDigest = contract.Hash(body)
			}
			q := contract.CryptoAccessPrepareRequest{OperationRef: operation, Context: f.q.Context, Final: 0, Rows: []contract.CompactRow{row}}
			body, err := contract.EncodeCryptoAccessPrepareRequest(q)
			if err != nil {
				t.Fatal("altered nonfinal row was not structurally valid", err)
			}
			private := f.sourceRoute.privateCalls
			reply := applyCall(r, t.Context(), contract.CryptoPrepare, body)
			if reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
				t.Errorf("altered nonfinal row escaped admission: code=%v body=%d uses=%v", reply.ResultCode, len(reply.Body), reply.KeyUseRows)
			}
			if f.sourceRoute.privateCalls != private {
				t.Error("unadmitted row reached private decrypt")
			}
			if r.access.count != 0 || r.access.batch != 0 {
				t.Error("unadmitted row advanced projection")
			}
		})
	}
}

// full_only: false
func TestAccessExactRowsCompleteAcrossBatches(t *testing.T) {
	f, rows := accessRowFixture(t)
	r, operation := startAccessRows(t, f)
	for i, row := range rows {
		final := uint8(i)
		q := contract.CryptoAccessPrepareRequest{OperationRef: operation, Context: f.q.Context, BatchIndex: uint32(i), Final: final, Rows: []contract.CompactRow{row}}
		body, err := contract.EncodeCryptoAccessPrepareRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		reply := applyCall(r, t.Context(), contract.CryptoPrepare, body)
		if reply.ResultCode != contract.CryptoSuccess {
			t.Fatal("exact admitted row refused", i, reply.ResultCode)
		}
		result, err := contract.DecodeCryptoAccessPrepareResult(reply.Body)
		if err != nil || len(result.Rows) != 1 {
			t.Fatal("exact admitted row output", err)
		}
		output := result.Rows[0]
		if output.MaterialKind != row.Coverage.MaterialKind || output.MaterialID != row.Coverage.MaterialID || output.BeforeAccessDigest != row.Coverage.BeforeAccessDigest || output.AfterAccessRecord.PackageCheck != row.BeforeAccessRecord.PackageCheck {
			t.Fatal("rewrap changed material identity or package")
		}
		for _, before := range row.BeforeAccessRecord.Wraps {
			after := output.AfterAccessRecord.Wraps[slices.IndexFunc(output.AfterAccessRecord.Wraps, func(w contract.WrapRow) bool {
				return w.SubjectKind == before.SubjectKind && w.SubjectID == before.SubjectID
			})]
			if before.SubjectID == f.intent.RecipientID {
				if after.BindingID != f.intent.Successor.BindingID || bytes.Equal(before.RSACiphertext, after.RSACiphertext) {
					t.Fatal("successor wrap missing")
				}
				source := row.BeforeAccessRecord.Wraps[slices.IndexFunc(row.BeforeAccessRecord.Wraps, func(w contract.WrapRow) bool { return w.BindingID == f.control.AuthorityKMSBinding.BindingID })]
				sourcePacket := f.sourceRoute.Decrypt(t.Context(), f.control.AuthorityKMSBinding, source.RSACiphertext, contract.ValueMaterialPacketLength)
				successorPacket := f.route.testKeyAccess.Decrypt(t.Context(), f.intent.Successor, after.RSACiphertext, contract.ValueMaterialPacketLength)
				if sourcePacket.Status != KeyOK || successorPacket.Status != KeyOK {
					t.Fatal("rewrapped packets did not authenticate")
				}
				if !bytes.Equal(sourcePacket.Packet[len(sourcePacket.Packet)-64:], successorPacket.Packet[len(successorPacket.Packet)-64:]) {
					t.Error("access-only replacement changed data or commitment keys")
				}
				clear(sourcePacket.Packet[:cap(sourcePacket.Packet)])
				clear(successorPacket.Packet[:cap(successorPacket.Packet)])
			} else if !bytes.Equal(before.RSACiphertext, after.RSACiphertext) {
				t.Fatal("unaffected wrap changed")
			}
		}
	}
	if f.sourceRoute.privateCalls != 4 || r.access.stage != contract.CryptoFreeze {
		t.Fatal("complete admitted coverage did not reach Freeze")
	}
}

// full_only: false
func TestAccessAdmissionRequiresCompleteOwnedCoverage(t *testing.T) {
	for _, damage := range []string{"omitted", "duplicate", "extra", "reordered", "changed-consumer", "owned"} {
		t.Run(damage, func(t *testing.T) {
			f, rows := accessRowFixture(t)
			f.rows = slices.Clone(rows)
			switch damage {
			case "omitted":
				f.rows = f.rows[:1]
			case "duplicate":
				f.rows[1] = f.rows[0]
			case "extra":
				f.rows = append(f.rows, rows[0])
			case "reordered":
				slices.Reverse(f.rows)
			case "changed-consumer":
				f.rows[0].Coverage.RequiredConsumerDigest[0] ^= 1
			}
			r, err := New(contract.GCP, []KeyAccess{f.route})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			err = r.admitAccess(f.q, f.intent, f.request, f.control, f.rows, f.route.CredentialRoute(), f.route, f.deadline)
			if damage != "owned" {
				if err == nil || r.access != nil || f.route.publicCalls != 0 || f.sourceRoute.privateCalls != 0 {
					t.Fatal("incomplete or changed coverage reached admission or key work")
				}
				return
			}
			if err != nil {
				t.Fatal("exact complete coverage refused", err)
			}
			want := f.rows[0].Coverage.TargetBindingIndices[0]
			f.rows[0].Coverage.TargetBindingIndices[0] = r.access.beforeIndex
			f.rows[0].Coverage.RequiredConsumerDigest[0] ^= 1
			if r.access.coverage[0].TargetBindingIndices[0] != want || r.access.coverage[0].RequiredConsumerDigest != rows[0].Coverage.RequiredConsumerDigest {
				t.Fatal("admitted coverage borrows parent metadata")
			}
		})
	}
}
