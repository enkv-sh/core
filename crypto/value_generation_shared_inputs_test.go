package crypto

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedColdForkAdmissionsShareOwnedPublicInputs(t *testing.T) {
	f := generatedRuntimeEffectFixture(t, false)
	parent := newConsumerRuntime(t, f.base.route)
	const count = 4
	forks := make([]*Runtime, count)
	for i := range forks {
		var err error
		forks[i], err = parent.Fork()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(forks[i].Close)
	}
	// The family owner must exist before any fork has validated a graph. Closing
	// the parent must not dispose public inputs still needed by its forks.
	parent.Close()
	admissions := make([]*generatedAdmission, count)
	errs := make([]error, count)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i, fork := range forks {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			admissions[i], errs[i] = fork.admitGeneratedReservationOwned(f.compare, f.reservation, f.base.deadline)
		}()
	}
	close(start)
	workers.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("fork %d admission: %v", i, err)
		}
	}
	first := admissions[0]
	for i := 1; i < count; i++ {
		if forks[i].generatedPlan != forks[0].generatedPlan || admissions[i].purpose.output != first.purpose.output {
			t.Fatal("equal cold fork admissions retained separate complete public images")
		}
		if admissions[i] == first || admissions[i].session == first.session {
			t.Fatal("public input sharing also shared private admission ownership")
		}
	}
	if first.purpose.output == f.reservation.Session.Output {
		t.Fatal("shared output borrowed caller ownership")
	}
	output := first.purpose.output
	graph := forks[0].generatedPlan
	forks[0].Close()
	if admissions[1].purpose.output != output || forks[1].generatedPlan != graph || output.Inspect(f.reservation.Session.BeforePublic) != nil {
		t.Fatal("closing a sibling invalidated retained shared public inputs")
	}
	for _, index := range []int{1, 2} {
		operation := generatedCompare(t, forks[index], f)
		generatedPlanParts(t, forks[index], f, operation)
		generatedFinishPlan(t, forks[index], f, operation)
	}
	if len(admissions[1].seed) == 0 || bytes.Equal(admissions[1].seed, admissions[2].seed) {
		t.Fatal("shared public inputs reused a private operation seed")
	}
	seed := bytes.Clone(admissions[2].seed)
	defer clear(seed)
	forks[1].Close()
	if !bytes.Equal(seed, admissions[2].seed) {
		t.Fatal("closing a sibling cleared another private operation seed")
	}
}

func generatedSharedAccessFixture(t *testing.T) (contract.CurrentAccessCore, []contract.AccessRecord, contract.ID) {
	t.Helper()
	f := applyFixture(t, false)
	id := consumerID
	rows := []contract.AccessRecord{{Schema: contract.CanonicalSchema, MaterialKind: contract.OperationSeedMaterialKind,
		MaterialID: id("shared access material"), MaterialContextDigest: id("shared access context"), PackageCheck: id("shared access check"),
		Wraps: []contract.WrapRow{{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: f.control.AuthorityRecipientID,
			BindingID: id("shared access binding"), BindingSerial: 1, PublicBindingDigest: id("shared access public binding"), RSACiphertext: bytes.Repeat([]byte{0xa5}, 384)}}}}
	domain := f.control.DomainID
	descriptor, err := contract.AccessRecordsDescriptor(domain, rows)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: domain, Refs: []contract.Ref{{
		Kind: contract.RecipientKind, Format: contract.CanonicalSchema, Domain: domain,
		Object: id("shared access recipient page"), Digest: id("shared access recipient digest"), Length: 1024}}})
	if err != nil {
		t.Fatal(err)
	}
	core := contract.CurrentAccessCore{CurrentControl: f.control.CurrentControl, RecipientRefsDescriptor: recipients,
		AccessRecordsDescriptor: descriptor, AccessPageRefs: []contract.Ref{{Kind: contract.AccessKind, Format: contract.CanonicalSchema,
			Domain: domain, Object: id("shared access page"), Digest: id("shared access page digest"), Length: contract.AccessPageHeaderLength + contract.AccessRecordFixedLength + contract.WrapRowWireLength}}}
	root, err := contract.AccessRoot(core)
	if err != nil {
		t.Fatal(err)
	}
	return core, rows, root
}

// full_only: false
func TestGeneratedSharedAccessOwnsActualBytesAndKeepsEarlierImages(t *testing.T) {
	core, caller, root := generatedSharedAccessFixture(t)
	owner := new(generatedInputOwner)
	owned, err := owner.ownAccess(core.DomainID, root, core, caller)
	if err != nil {
		t.Fatal(err)
	}
	equalBody, err := contract.EncodeAccessRecord(caller[0])
	if err != nil {
		t.Fatal(err)
	}
	equal, err := contract.DecodeAccessRecord(equalBody)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := owner.ownAccess(core.DomainID, root, core, []contract.AccessRecord{equal})
	if err != nil || shared != owned {
		t.Fatal("equal authenticated access image was copied", err)
	}
	want := bytes.Clone(owned.records[0].Wraps[0].RSACiphertext)
	caller[0].Wraps[0].RSACiphertext[0] ^= 1
	if !bytes.Equal(owned.records[0].Wraps[0].RSACiphertext, want) {
		t.Fatal("shared access image borrowed caller ciphertext")
	}
	if got, err := owner.ownAccess(core.DomainID, root, core, caller); got != nil || !errors.Is(err, ErrAdmission) {
		t.Fatal("cached root hid changed caller access bytes", err)
	}
	if got, err := owner.ownAccess(consumerID("another domain"), root, core, []contract.AccessRecord{equal}); got != nil || !errors.Is(err, ErrAdmission) {
		t.Fatal("access ownership accepted another domain", err)
	}
	// Descriptor validation must run before either cache reuse or replacement.
	if got, err := owner.ownAccess(core.DomainID, root, core, []contract.AccessRecord{equal, equal}); got != nil || !errors.Is(err, ErrAdmission) || owner.access != owned {
		t.Fatal("duplicate access identity changed the owner", err)
	}
	core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(core.DomainID, caller)
	if err != nil {
		t.Fatal(err)
	}
	changedRoot, err := contract.AccessRoot(core)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := owner.ownAccess(core.DomainID, changedRoot, core, caller)
	if err != nil || replacement == owned || !bytes.Equal(replacement.records[0].Wraps[0].RSACiphertext, caller[0].Wraps[0].RSACiphertext) {
		t.Fatal("different authenticated access image reused old backing", err)
	}
	if !bytes.Equal(owned.records[0].Wraps[0].RSACiphertext, want) {
		t.Fatal("replacement changed an earlier admitted access image")
	}
}

// full_only: false
func TestGeneratedColdForksShareAccessAndRetireSessionReferences(t *testing.T) {
	core, caller, root := generatedSharedAccessFixture(t)
	f := generatedRuntimeEffectFixture(t, false)
	parent := newConsumerRuntime(t, f.base.route)
	const count = 4
	forks := make([]*Runtime, count)
	admissions := make([]*generatedAdmission, count)
	for i := range forks {
		var err error
		forks[i], err = parent.Fork()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(forks[i].Close)
		owner, err := forks[i].generatedInputOwner()
		if err != nil {
			t.Fatal(err)
		}
		admissions[i] = &generatedAdmission{inputOwner: owner, request: contract.CryptoGeneratedCompareRequest{Context: contract.ApplyContext{DomainID: core.DomainID, CurrentAccessRoot: root}}}
	}
	parent.Close()
	var workers sync.WaitGroup
	accepted := make([]bool, count)
	for i := range admissions {
		workers.Add(1)
		go func() {
			defer workers.Done()
			accepted[i] = admissions[i].admitAutomaticAccess(generatedSessionAdmissionInput{BeforeAccess: &core, BeforeAccessRecords: caller})
		}()
	}
	workers.Wait()
	first := admissions[0]
	for i, a := range admissions {
		if !accepted[i] || len(a.beforeAccessRecords) != 1 || &a.beforeAccessRecords[0] != &first.beforeAccessRecords[0] {
			t.Fatal("equal fork admissions retained separate access images", i)
		}
		if &a.beforeAccessRecords[0].Wraps[0].RSACiphertext[0] == &caller[0].Wraps[0].RSACiphertext[0] {
			t.Fatal("fork admission borrowed caller ciphertext")
		}
	}
	first.selectionPhase = &contract.GeneratedPhaseRecord{SelectionPhaseID: consumerID("retired selection anchor")}
	first.graphBody = contract.DigestLength{Digest: consumerID("retired graph"), Length: 1}
	want := bytes.Clone(admissions[1].beforeAccessRecords[0].Wraps[0].RSACiphertext)
	first.clear()
	forks[0].Close()
	if first.beforeAccessRecords != nil || first.accessPins != nil || first.selectionPhase != nil || first.inputOwner != nil || first.graphBody != (contract.DigestLength{}) {
		t.Fatal("retired admission retained shared access or anchor references")
	}
	if !bytes.Equal(admissions[1].beforeAccessRecords[0].Wraps[0].RSACiphertext, want) || admissions[1].accessPins[generatedAccessIdentity{caller[0].MaterialKind, caller[0].MaterialID}].IsZero() {
		t.Fatal("retiring one admission changed a sibling's shared access")
	}
	if parent.generatedInputs != nil || forks[0].generatedInputs != nil {
		t.Fatal("closed runtime retained the shared input owner")
	}
}

// full_only: false
func TestGeneratedAutomaticAccessOwnershipFixedLayout(t *testing.T) {
	for _, row := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"access record", unsafe.Sizeof(contract.AccessRecord{}), 128},
		{"wrap row", unsafe.Sizeof(contract.WrapRow{}), 136},
		{"access identity", unsafe.Sizeof(generatedAccessIdentity{}), 34},
		{"access image", unsafe.Sizeof(generatedAccessImage{}), 64},
		{"changed subject", unsafe.Sizeof(contract.ChangedSubjectIdentity{}), 34},
	} {
		if row.got != row.want {
			t.Fatalf("%s fixed layout=%d want=%d", row.name, row.got, row.want)
		}
	}
	// Each before/after value contributes at most an entry and generation row;
	// complete before/after membership sets and desired recipients are separate.
	const changedRows = 2*(512+512) + 4096 + 4096 + 256
	if changedRows*unsafe.Sizeof(contract.ChangedSubjectIdentity{}) != 356864 {
		t.Fatal("automatic changed-subject scratch account changed")
	}
	// AccessRecordsDescriptor checks both these aggregate bounds before owning
	// rows. Each image owns its rows, wraps, ciphertext and one ID pin per row;
	// equal admissions add no second image. Map buckets and allocator rounding
	// are not application backing. Only one encoded row is copied at a time.
	const payload = uint64(256 * (2097152 - 75))
	const records = uint64(256 * ((2097152 - 75) / (102 + 489)))
	const decoded = (520*payload + (128*489-520*102)*records + 488) / 489
	const image = 64 + decoded + 66*records
	if contract.MaxChildPages*(contract.MaxAccessPageLength-contract.AccessPageHeaderLength) != payload ||
		contract.MaxChildPages*contract.AccessPageRecordLimit != records || image != 648574592 ||
		contract.AccessRecordFixedLength+257*contract.WrapRowWireLength != 125775 {
		t.Fatal("shared authenticated access image account changed")
	}
}

// full_only: false
func TestGeneratedAcknowledgedProducerRefusesUnadmittedProgress(t *testing.T) {
	f, _, _ := generatedProducerFixture(t, false)
	for _, supplied := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "unexpected"}[supplied], func(t *testing.T) {
			r := newConsumerRuntime(t, f.base.route)
			input := f.producer
			calls := 0
			input.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
				calls++
				return generatedProducerReturn{}
			}
			if supplied {
				input.Producer.Progress = [][]byte{{0}}
			}
			_, err := r.admitGeneratedProducerOwned(f.compare, input, f.base.deadline)
			if supplied && !errors.Is(err, ErrAdmission) || !supplied && err != nil || calls != 0 {
				t.Fatal("progress admission or effect", err, calls)
			}
		})
	}
}

// full_only: false
func TestGeneratedSharedInputsKeepUnequalAdmissionsIndependent(t *testing.T) {
	f := generatedRuntimePlanFixture(t, false)
	other := generatedRuntimeEffectFixture(t, false)
	parent := newConsumerRuntime(t, f.base.route)
	left, err := parent.Fork()
	if err != nil {
		t.Fatal(err)
	}
	right, err := parent.Fork()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(left.Close)
	t.Cleanup(right.Close)
	a, err := left.admitGeneratedReservationOwned(f.compare, f.reservation, f.base.deadline)
	if err != nil {
		t.Fatal(err)
	}
	oldGraph := left.generatedPlan
	b, err := right.admitGeneratedReservationOwned(other.compare, other.reservation, other.base.deadline)
	if err != nil {
		t.Fatal(err)
	}
	if oldGraph == right.generatedPlan || a.graph.Header == b.graph.Header {
		t.Fatal("unequal admitted graphs reused one validated plan")
	}
	if a.graph.Header != oldGraph.graph.Header {
		t.Fatal("later validation changed an earlier admission")
	}
	// Equal public output may still share even when the operation graph differs.
	if a.purpose.output != b.purpose.output {
		t.Fatal("equal selected output was cloned for a different graph")
	}
	parent.Close()
}

// full_only: false
func TestGeneratedSharedOutputChecksActualBytesAndOwnsCallerBuffers(t *testing.T) {
	f := generatedRuntimeOutputFixture(t, false)
	owner := new(generatedInputOwner)
	before, caller := f.reservation.Session.BeforePublic, f.reservation.Session.Output
	owned, err := owner.ownOutput(before, caller)
	if err != nil {
		t.Fatal(err)
	}
	equal, err := caller.Own(before)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := owner.ownOutput(before, equal)
	if err != nil || shared != owned {
		t.Fatal("equal complete bytes did not share ownership", err)
	}
	original := bytes.Clone(owned.EntryBodies[0])
	caller.EntryBodies[0][len(caller.EntryBodies[0])-1] ^= 1
	if !bytes.Equal(owned.EntryBodies[0], original) {
		t.Fatal("caller changed retained shared bytes")
	}
	if got, err := owner.ownOutput(before, caller); got != nil || !errors.Is(err, ErrAdmission) {
		t.Fatal("claimed descriptors hid changed selected entry bytes", err)
	}
	// A different authenticated selected state cannot reuse even identical
	// output facts under the old predecessor identity.
	before.AccessRoot = consumerID("different selected access root")
	separate, err := owner.ownOutput(before, equal)
	if err != nil || separate == owned {
		t.Fatal("different selected state reused old output ownership", err)
	}
	if !bytes.Equal(owned.EntryBodies[0], original) {
		t.Fatal("replacement changed the earlier owned image")
	}
}
