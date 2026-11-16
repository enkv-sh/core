package format

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestSuccessionAccessDescriptorsUseActualProjection(t *testing.T) {
	p := successionRecoveryIdentityFixture(t, 3, 8, 1)
	core := contract.ValueCore{Schema: 11, Profile: 2, ValueSource: 1, CompatibilityID: fid(1), CryptoSupportID: fid(2),
		DomainID: p.Request.DomainID, Name: "value", EntryIncarnationID: fid(3), ValueStateID: fid(4), OriginSnapshotID: fid(5),
		OriginTransitionID: fid(6), DataKeyID: fid(7), DataKeyEpoch: 1, CommitmentKeyID: fid(8), CommitmentKeyEpoch: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}
	context, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	access := contract.AccessRecord{Schema: 11, MaterialKind: contract.ValueMaterialKind, MaterialID: core.ValueStateID,
		MaterialContextDigest: context, PackageCheck: fid(9), Wraps: []contract.WrapRow{
			{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: fid(10), BindingID: fid(11), BindingSerial: 1, PublicBindingDigest: fid(12), RSACiphertext: make([]byte, 384)},
			{SubjectKind: contract.RecoveryWrapSubject, SubjectID: fid(13), BindingID: fid(14), BindingSerial: 1, PublicBindingDigest: fid(15), RSACiphertext: make([]byte, 384)},
		}}
	encoded, err := contract.EncodeAccessRecord(access)
	// One access record has 102 fixed bytes and two 489-byte RSA wrap rows.
	if err != nil || len(encoded) != 1080 {
		t.Fatal("independent access record length differs", len(encoded), err)
	}
	before, err := contract.AccessRecordDigest(access)
	if err != nil {
		t.Fatal(err)
	}
	row := contract.CompactRow{Coverage: contract.CoverageRow{MaterialKind: contract.ValueMaterialKind, MaterialID: core.ValueStateID,
		MaterialContextDigest: context, ImmutableBodyDigest: fid(16), BeforeAccessDigest: before, RequiredConsumerDigest: fid(17),
		SourceBindingIndex: 0, TargetBindingIndices: []uint16{1}}, ValueCore: core, BeforeAccessRecord: access}
	plan, err := contract.AccessReplacementPlanDescriptor(p.AccessPlan)
	if err != nil {
		t.Fatal(err)
	}
	request := p.Authorization.Subject.RequestCoreDigest
	projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: p.Request.DomainID,
		BeforeAccessRoot: p.Request.BeforeAccessRoot, RequestCoreDigest: request}, plan, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Add(row, contract.AccessOutputRow{MaterialKind: row.Coverage.MaterialKind, MaterialID: row.Coverage.MaterialID,
		BeforeAccessDigest: before, AfterAccessRecord: access}); err != nil {
		t.Fatal(err)
	}
	p.Coverage, p.AfterAccess, p.Unchanged, err = projection.Descriptors()
	// Prefixes and fixed metadata contribute 178/181/144 bytes. The row
	// contributes 168/70/162 bytes; only output also includes the access record.
	if err != nil || p.Coverage.Length != 346 || p.AfterAccess.Length != 1331 || p.Unchanged.Length != 306 {
		t.Fatal("independent nonempty projection lengths differ", p.Coverage, p.AfterAccess, p.Unchanged, err)
	}
	p.Snapshot.SecretCount, p.Snapshot.SecretOrdinaryWrapCount, p.Snapshot.AccessRecordCount = 1, 1, 1
	p.Snapshot.CurrentAccess.Core.AccessPageRefs = []contract.Ref{{Length: 75 + 1080}}
	if !p.accessMatches(request) {
		t.Fatal("actual nonempty projections do not match the format boundary")
	}
}
