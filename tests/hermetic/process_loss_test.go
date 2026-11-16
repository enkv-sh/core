package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type processStoreFacts struct {
	Domain, Trust contract.ID
	Descriptor    contract.Descriptor
	Configuration contract.StoreConfiguration
	PublicKey     []byte
	DomainBasis   []byte
	ExpectedImage stateImage
	Writer        *processWriterFacts  `json:",omitempty"`
	Generated     *processFixture      `json:",omitempty"`
	EndWork       *processEndWorkFacts `json:",omitempty"`
	GC            *processGCFacts      `json:",omitempty"`
}

type processWriterFacts struct {
	Requested                                 []ApplyEntryInput
	Operation, Transition, Snapshot, Revision contract.ID
	Pages                                     [contract.MaxValueEntryPages]contract.ID
	SupportPages                              [contract.MaxChildPages]contract.ID
	Values, Incarnations                      map[uint16]contract.ID
}

func processStoreDiagnostics(t *testing.T) string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The coordinator retains its private assembly directory on failure.
	directory, err := os.MkdirTemp(filepath.Dir(binary), "process-loss-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("retained process Store diagnostics: %s", directory)
			return
		}
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("process Store diagnostic cleanup: %v", err)
		}
	})
	return directory
}

// full_only: false
func TestWriterTerminationPreservesCompleteSelection(t *testing.T) {
	for _, barrier := range []string{"before-first-create", "after-first-page-readback", "after-root-readback", "after-cas-acceptance", "after-authenticated-observation"} {
		t.Run(barrier, func(t *testing.T) { testWriterTermination(t, barrier, false) })
	}
}

// full_only: false
func TestLastMemberRemovalTerminationPreservesCompleteSelection(t *testing.T) {
	for _, barrier := range []string{"before-first-create", "after-root-readback", "after-cas-acceptance", "after-authenticated-observation"} {
		t.Run(barrier, func(t *testing.T) { testWriterTermination(t, barrier, true) })
	}
}

func testWriterTermination(t *testing.T, barrier string, empty bool) {
	t.Helper()
	count := 32
	if empty {
		count = 1
	}
	f := newFixture(t, count, true, 1)
	old := fixtureStateImage(t, f)
	var requested []ApplyEntryInput
	if !empty {
		requested = mixedLifecycleInput(old)
	}
	comparison, result := f.session.Compare(context.Background(), requested, admitSuppliedComparison(t, f.session, nil, requested))
	if comparison == nil {
		t.Fatal(result)
	}
	if comparison.outputChanged || comparison.support == nil {
		t.Fatal("process writer trace requires unchanged output and admitted receipt support")
	}
	plan, err := planTransition(t.Context(), comparison)
	if err != nil {
		t.Fatal("process writer identity generation failed")
	}
	want := expectedSuccessorImage(t, old, requested, captureAllocatedTransitionInputs(plan))
	if want.Root.OutputConfiguration != old.Root.OutputConfiguration {
		t.Fatal("process writer trace changed the output configuration descriptor")
	}
	facts := processStoreFacts{Domain: f.admission.admission.domain, Trust: f.admission.admission.trust, Descriptor: f.store.desc, Configuration: f.store.configuration, PublicKey: bytes.Clone(f.admission.admission.publicKey), DomainBasis: bytes.Clone(f.admission.admission.descriptor), ExpectedImage: old}
	writerFacts := facts
	writerFacts.Writer = &processWriterFacts{Requested: requested, Operation: plan.operation, Transition: plan.transition, Snapshot: plan.snapshot, Revision: plan.revision, Pages: plan.pages, SupportPages: plan.supportPages, Values: plan.values, Incarnations: plan.incarnations}
	directory := processStoreDiagnostics(t)
	writer := startProcessStoreChild(t, directory, "writer", writerFacts)
	if err := serveProcessWriter(t, writer, f.store, old, want, f.session.token, barrier); err != nil {
		t.Fatal(err)
	}
	// A successful barrier return is required before an expected kill.
	writer.trace = append(writer.trace, "validated barrier: "+barrier)
	if err := writer.stop(); err != nil {
		t.Fatal(err)
	}
	if !writer.joined {
		t.Fatal("writer termination was not joined")
	}
	selected := old
	created, _ := successorObjectCounts(old, want)
	creates, cas := 0, 0
	switch barrier {
	case "after-first-page-readback":
		creates = 1
	case "after-root-readback":
		creates = int(created)
	case "after-cas-acceptance", "after-authenticated-observation":
		selected, creates, cas = want, int(created), 1
	}
	if f.store.creates != creates || f.store.cas != cas || f.trust.signs != 0 {
		t.Fatalf("barrier Store counts: creates=%d CAS=%d parent signs=%d", f.store.creates, f.store.cas, f.trust.signs)
	}
	// This new process reads the still-living parent Store. No object map,
	// writer permit, Candidate, or private signing key crosses this pipe.
	facts.ExpectedImage = selected
	reader := startProcessStoreChild(t, directory, "reader", facts)
	beforeReads := f.store.reads
	if err := serveProcessReader(t, reader, f.store, selected); err != nil {
		t.Fatal(err)
	}
	if err := reader.join(); err != nil {
		t.Fatalf("fresh reader did not exit successfully: %v", err)
	}
	if f.store.creates != creates || f.store.cas != cas || f.store.reads-beforeReads != len(processPlainReadRequests(t, f.store.desc, selected)) {
		t.Fatal("fresh reader changed Store or did not read the complete selected closure")
	}
}

func processReadRequests(t *testing.T, descriptor contract.Descriptor, image stateImage) []processStoreRequest {
	t.Helper()
	requests := []processStoreRequest{{Method: "read", Key: descriptor.HeadKey, Maximum: contract.MaxHeadLength}}
	refs := []format.Ref{image.RootRef}
	for _, ref := range image.Root.ValueEntryPages {
		if ref != nil {
			refs = append(refs, *ref)
		}
	}
	for _, ref := range image.Root.Recipients {
		if ref != nil {
			refs = append(refs, *ref)
		}
	}
	refs = append(refs, image.Root.CurrentAccess.Core.AccessPageRefs...)
	refs = append(refs, image.Root.AdministrativeIndex)
	refs = append(refs, image.Root.AdministrativeIndexShards...)
	refs = append(refs, image.Root.RequiredSupport...)
	for _, ref := range refs {
		requests = append(requests, processStoreRequest{Method: "read", Key: mustKey(t, descriptor.Prefix, ref), Maximum: ref.Length})
	}
	return append(requests, processConfigurationReadRequests(t, descriptor, image, false)...)
}

// A cold reader borrows each logical slice after its physical closure scan.
// A cached Select observation scans only the opaque configuration pages first.
func processConfigurationReadRequests(t testing.TB, descriptor contract.Descriptor, image stateImage, scan bool) []processStoreRequest {
	t.Helper()
	var requests []processStoreRequest
	if len(image.AdministrativeIndex.Pages) != len(image.Root.RequiredSupport) {
		t.Fatal("process configuration index differs from selected support")
	}
	if scan {
		for i, page := range image.AdministrativeIndex.Pages {
			if page.Ref != image.Root.RequiredSupport[i] {
				t.Fatal("process configuration page Ref differs from selection")
			}
			for _, row := range page.Rows {
				if row.Kind == contract.OutputConfigurationSliceSupportKind {
					requests = append(requests, processStoreRequest{Method: "read", Key: mustKey(t, descriptor.Prefix, page.Ref), Maximum: page.Ref.Length})
					break
				}
			}
		}
	}
	for logical := uint16(0); logical < image.Root.OutputConfiguration.SliceCount; logical++ {
		id, err := contract.OutputConfigurationSliceID(image.Root.Domain, image.Root.OutputConfiguration.ConfigurationDigest, logical)
		if err != nil {
			t.Fatal("process configuration slice identity", err)
		}
		found := false
		for i, page := range image.AdministrativeIndex.Pages {
			if page.Ref != image.Root.RequiredSupport[i] {
				t.Fatal("process configuration page Ref differs from selection")
			}
			for _, row := range page.Rows {
				if row.Kind == contract.OutputConfigurationSliceSupportKind && row.RecordID == id {
					if found {
						t.Fatal("process configuration slice repeats")
					}
					found = true
					requests = append(requests, processStoreRequest{Method: "read", Key: mustKey(t, descriptor.Prefix, page.Ref), Maximum: page.Ref.Length})
				}
			}
		}
		if !found {
			t.Fatal("process configuration slice is absent")
		}
	}
	return requests
}

func singleConfigurationRef(t testing.TB, descriptor contract.Descriptor, image stateImage) format.Ref {
	t.Helper()
	reads := processConfigurationReadRequests(t, descriptor, image, false)
	if len(reads) != 1 {
		t.Fatal("fixture requires one exact configuration slice")
	}
	for _, ref := range image.Root.RequiredSupport {
		if mustKey(t, descriptor.Prefix, ref) == reads[0].Key && ref.Length == reads[0].Maximum {
			return ref
		}
	}
	t.Fatal("configuration slice has no selected page")
	return format.Ref{}
}

func processPlainReadRequests(t *testing.T, descriptor contract.Descriptor, image stateImage) []processStoreRequest {
	t.Helper()
	if image.Root.Generated.Slices.Count != 0 {
		t.Fatal("plain reader includes generated slices")
	}
	return append(processReadRequests(t, descriptor, image), processPlainReceiptReadRequests(t, descriptor, image)...)
}

func processPlainReceiptIndexReadRequests(t testing.TB, descriptor contract.Descriptor, image stateImage) []processStoreRequest {
	t.Helper()
	if image.Root.Generated.Slices.Count != 0 {
		return nil
	}
	if len(image.Root.Generated.Fragments) == 0 {
		return nil
	}
	indexID, err := contract.MutationReceiptIndexBlobID(image.Root.Domain, image.Root.Generated.SuccessWindow, image.Root.Generated.FailureWindow, image.Root.Generated.ReceiptOrder)
	if err != nil {
		t.Fatal("process receipt index identity", err)
	}
	refs := make(map[uint16]format.Ref, len(image.Root.RequiredSupport))
	var requests []processStoreRequest
	for i, page := range image.AdministrativeIndex.Pages {
		if page.Ref != image.Root.RequiredSupport[i] {
			t.Fatal("process receipt page Ref differs from selection")
		}
		refs[page.Ref.Index] = page.Ref
	}
	for _, location := range image.Root.Generated.Fragments {
		ref, present := refs[location.SupportPageIndex]
		if !present || location.BlobID != indexID {
			t.Fatal("plain process receipt fragment differs from selected index")
		}
		requests = append(requests, processStoreRequest{Method: "read", Key: mustKey(t, descriptor.Prefix, ref), Maximum: ref.Length})
	}
	return requests
}

func processPlainReceiptReadRequests(t testing.TB, descriptor contract.Descriptor, image stateImage) []processStoreRequest {
	t.Helper()
	index := processPlainReceiptIndexReadRequests(t, descriptor, image)
	var requests []processStoreRequest
	for pass := 0; pass < 3; pass++ {
		requests = append(requests, index...)
	}
	return requests
}

func processPlainObservationReadRequests(t testing.TB, descriptor contract.Descriptor, image stateImage) []processStoreRequest {
	t.Helper()
	if image.Root.Generated.Slices.Count != 0 {
		t.Fatal("plain observation includes generated slices")
	}
	var requests []processStoreRequest
	for i, page := range image.AdministrativeIndex.Pages {
		if page.Ref != image.Root.RequiredSupport[i] {
			t.Fatal("plain observation page Ref differs from selection")
		}
		for _, row := range page.Rows {
			if row.Kind == contract.GeneratedFragmentSupportKind || row.Kind == contract.OutputConfigurationSliceSupportKind {
				requests = append(requests, processStoreRequest{Method: "read", Key: mustKey(t, descriptor.Prefix, page.Ref), Maximum: page.Ref.Length})
				break
			}
		}
	}
	requests = append(requests, processConfigurationReadRequests(t, descriptor, image, false)...)
	return append(requests, processPlainReceiptReadRequests(t, descriptor, image)...)
}

func processRequestMatches(got, want processStoreRequest) bool {
	return got.Method == want.Method && got.Key == want.Key && got.Maximum == want.Maximum && got.Token == want.Token && got.Cursor == want.Cursor && bytes.Equal(got.Body, want.Body)
}

func serveProcessWriter(t *testing.T, p *processStoreChild, store *memoryStore, old, want stateImage, token contract.Token, barrier string) error {
	t.Helper()
	requests := processPlainReadRequests(t, store.desc, old)
	// Compare reads the slices for retained intent and its change check.
	// Successor preparation also validates the preserved publication relation.
	requests = append(requests, processConfigurationReadRequests(t, store.desc, old, false)...)
	requests = append(requests, processConfigurationReadRequests(t, store.desc, old, false)...)
	requests = append(requests, processConfigurationReadRequests(t, store.desc, old, false)...)
	requests = append(requests, processPlainReceiptIndexReadRequests(t, store.desc, want)...)
	firstCreate := len(requests)
	objects := expectedImmutableObjects(t, old, want)
	for _, object := range objects {
		key := mustKey(t, store.desc.Prefix, object.ref)
		requests = append(requests, processStoreRequest{Method: "create", Key: key, Body: object.body}, processStoreRequest{Method: "read", Key: key, Maximum: object.ref.Length})
	}
	requests = append(requests, processStoreRequest{Method: "cas", Key: store.desc.HeadKey, Token: token}, processStoreRequest{Method: "read", Key: store.desc.HeadKey, Maximum: contract.MaxHeadLength})
	requests = append(requests, processPlainObservationReadRequests(t, store.desc, want)...)
	for index, expected := range requests {
		request, err := p.next()
		if err != nil {
			return err
		}
		if expected.Method == "cas" {
			head, err := format.DecodeHead(request.Body)
			if err != nil || head.Core.Root != want.RootRef || head.Core.Revision != want.Revision || head.Core.PreviousRevision != old.Revision || head.Core.PreviousToken != token {
				return errors.New("process writer CAS does not bind the expected complete successor and predecessor")
			}
			expected.Body = request.Body
		}
		if !processRequestMatches(request, expected) {
			return fmt.Errorf("process writer operation %d differs: got %s %s, want %s %s", index, request.Method, request.Key, expected.Method, expected.Key)
		}
		// The next request proves the earlier readback returned to Core and
		// passed validation. Hold this request before applying its Store effect.
		stop := barrier == "before-first-create" && index == firstCreate || barrier == "after-first-page-readback" && index == firstCreate+2 || barrier == "after-root-readback" && index == firstCreate+2*len(objects)
		if stop {
			return nil
		}
		reply, err := processStoreOperation(store, request, false)
		if err != nil {
			return err
		}
		if request.Method == "read" && reply.Read.Status != contract.ReadOK || request.Method != "read" && reply.Write.Status != contract.WriteAcknowledged {
			return errors.New("process writer Store operation did not complete successfully")
		}
		if barrier == "after-cas-acceptance" && request.Method == "cas" {
			// The real parent Store accepted the write. The child has received
			// no CAS reply and cannot start its authenticated observation.
			return nil
		}
		if err := p.reply(reply); err != nil {
			return err
		}
	}
	marker, err := p.next()
	if err != nil {
		return err
	}
	if barrier != "after-authenticated-observation" || !processStoreMarker(marker, "authenticated-requested-state") {
		return errors.New("process writer authenticated observation marker differs")
	}
	return nil
}

func serveProcessReader(t *testing.T, p *processStoreChild, store *memoryStore, expected stateImage) error {
	t.Helper()
	requests := append(processReadRequests(t, store.desc, expected), processPlainReceiptReadRequests(t, store.desc, expected)...)
	for _, want := range requests {
		request, err := p.next()
		if err != nil {
			return err
		}
		if !processRequestMatches(request, want) {
			return errors.New("fresh process reader requested an unexpected operation")
		}
		reply, err := processStoreOperation(store, request, true)
		if err != nil {
			return err
		}
		if err := p.reply(reply); err != nil {
			return err
		}
	}
	marker, err := serveProcessFragmentReads(t, p, store, expected, nil)
	if err != nil {
		return err
	}
	if !processStoreMarker(marker, "authenticated-complete-image") {
		return errors.New("fresh process reader authentication marker differs")
	}
	return p.reply(processStoreReply{})
}

func serveProcessRead(child *processStoreChild, store *memoryStore, expected processStoreRequest) error {
	request, err := child.next()
	if err != nil {
		return err
	}
	return serveProcessReadRequest(child, store, request, expected)
}

func serveProcessReadRequest(child *processStoreChild, store *memoryStore, request, expected processStoreRequest) error {
	if !processRequestMatches(request, expected) {
		return fmt.Errorf("process read differs: got %s %s, want %s %s", request.Method, request.Key, expected.Method, expected.Key)
	}
	reply, err := processStoreOperation(store, request, true)
	if err != nil || reply.Read.Status != contract.ReadOK {
		return errors.New("process selected read failed")
	}
	return child.reply(reply)
}

// After the exact selected scan or successor write plan, cold blob and slice
// authentication can reread only fragment pages in the declared images.
// next enforces the bridge's finite cumulative request limit.
func serveProcessFragmentReads(t testing.TB, child *processStoreChild, store *memoryStore, image stateImage, configuration []processStoreRequest, additional ...stateImage) (processStoreRequest, error) {
	t.Helper()
	allowed := make(map[string]processStoreRequest)
	references := make(map[string]format.Ref)
	for _, image := range append([]stateImage{image}, additional...) {
		if len(image.AdministrativeIndex.Pages) != len(image.Root.RequiredSupport) {
			return processStoreRequest{}, errors.New("process fragment index differs from selected support")
		}
		for i, page := range image.AdministrativeIndex.Pages {
			if page.Ref != image.Root.RequiredSupport[i] {
				return processStoreRequest{}, errors.New("process fragment page Ref differs from selected support")
			}
			for _, row := range page.Rows {
				if row.Kind == contract.GeneratedFragmentSupportKind {
					key := mustKey(t, store.desc.Prefix, page.Ref)
					if prior, exists := references[key]; exists && prior != page.Ref {
						return processStoreRequest{}, errors.New("process fragment images disagree on the exact Ref")
					}
					references[key] = page.Ref
					allowed[key] = processStoreRequest{Method: "read", Key: key, Maximum: page.Ref.Length}
					break
				}
			}
		}
	}
	for {
		request, err := child.next()
		if err != nil {
			return request, err
		}
		if len(configuration) != 0 && processRequestMatches(request, configuration[0]) {
			if err := serveProcessReadRequest(child, store, request, configuration[0]); err != nil {
				return request, err
			}
			configuration = configuration[1:]
			continue
		}
		want, fragment := allowed[request.Key]
		if request.Method != "read" || !fragment {
			if len(configuration) != 0 {
				return request, errors.New("process omitted an exact selected configuration read")
			}
			return request, nil
		}
		if err := serveProcessReadRequest(child, store, request, want); err != nil {
			return request, err
		}
	}
}

// full_only: false
func TestWriterTerminationChild(t *testing.T) {
	role := os.Getenv("ENKV_PROCESS_STORE_ROLE")
	if role == "" {
		t.Skip("process store entry requires a parent invocation")
	}
	replies, requests := os.NewFile(3, "process-store-replies"), os.NewFile(4, "process-store-requests")
	if replies == nil || requests == nil {
		t.Fatal("inherited process Store pipes missing")
	}
	t.Cleanup(func() {
		for _, file := range []*os.File{replies, requests} {
			if err := file.Close(); err != nil {
				t.Errorf("inherited process Store pipe close: %v", err)
			}
		}
	})
	var facts processStoreFacts
	if err := readProcessStoreFrame(replies, &facts); err != nil {
		t.Fatal(err)
	}
	store := &processStore{t: t, desc: facts.Descriptor, configuration: facts.Configuration, requests: requests, replies: replies}
	if strings.HasPrefix(role, "control-") {
		store.call(processStoreRequest{Method: "control-ready"})
		switch role {
		case "control-exit":
			return
		case "control-pipe":
			if _, err := requests.Write([]byte{0, 0}); err != nil {
				t.Fatal(err)
			}
			return
		case "control-marker":
			store.call(processStoreRequest{Method: "wrong-marker"})
		case "control-timeout":
			var reply processStoreReply
			if err := readProcessStoreFrame(replies, &reply); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("unknown process Store control")
		}
		return
	}
	if strings.HasPrefix(role, "gc-") {
		if facts.GC == nil || facts.Generated != nil || facts.Writer != nil || facts.EndWork != nil {
			t.Fatal("process GC role and original facts differ")
		}
		processGCChild(t, role, store, facts)
		return
	}
	if facts.GC != nil {
		t.Fatal("non-GC process received GC execution input")
	}
	generatedRole := role == "generated-reader" || role == "generated-killed" || role == "generated-record"
	endWorkRole := role == "end-work" || role == "end-work-installed"
	if generatedRole != (facts.Generated != nil) || endWorkRole != (facts.EndWork != nil) ||
		endWorkRole && (facts.Generated != nil || facts.Writer != nil || facts.EndWork.GroupID.IsZero()) ||
		(role == "end-work-installed") != (facts.EndWork != nil && facts.EndWork.Installed) {
		t.Fatal("process generated role and facts differ")
	}
	ctx := context.Background()
	if endWorkRole && facts.EndWork.Installed {
		processInstalledEndWorkChild(t, ctx, store, facts)
		return
	}
	// The general reader uses independently supplied public admission facts.
	// It constructs no Trust value and has no private signing key.
	admission := processPublicAdmission(facts.Domain, facts.Trust, facts.Descriptor, facts.PublicKey, facts.DomainBasis)
	if f := facts.Generated; f != nil {
		if facts.Writer != nil || f.Objects != nil || f.Generation != 0 || f.Consumer != nil ||
			f.Domain != facts.Domain || f.Trust != facts.Trust || f.Descriptor != facts.Descriptor ||
			!bytes.Equal(f.PublicKey, facts.PublicKey) || !bytes.Equal(f.DomainBasis, facts.DomainBasis) ||
			!reflect.DeepEqual(f.ExpectedImage, facts.ExpectedImage) || (role == "generated-reader") != (f.GeneratedRecord == nil) {
			t.Fatal("process generated public admission refused")
		}
		if f.CurrentBasis != nil {
			admission.admission.current = f.CurrentBasis.owned()
			admission.admission.epoch = f.Epoch
		}
	}
	if f := facts.EndWork; f != nil {
		if f.CurrentBasis != nil {
			admission.admission.current = f.CurrentBasis.owned()
			admission.admission.epoch = f.Epoch
		} else if f.Epoch != 1 {
			t.Fatal("process end-work current basis is absent")
		}
	}
	session, result := Open(ctx, admission, store)
	wantOpen := Result{Outcome: ObservedCurrent, ObservedRevision: facts.ExpectedImage.Revision, ObservedSnapshotID: facts.ExpectedImage.Root.Snapshot, Evidence: AuthenticatedClosure}
	if session == nil || result != wantOpen {
		t.Fatalf("process Store Open: %+v", result)
	}
	assertStateImage(t, session, facts.ExpectedImage)
	if f := facts.Generated; f != nil {
		work, err := session.workSupportRecords(t.Context())
		if err != nil || !reflect.DeepEqual(work, f.ExpectedWork) {
			t.Fatal("process generated selected work differs", err)
		}
	}
	if role == "reader" || role == "generated-reader" {
		if facts.Writer != nil {
			t.Fatal("fresh reader received writer authority")
		}
		store.call(processStoreRequest{Method: "authenticated-complete-image"})
		return
	}
	if endWorkRole {
		trust := memoryCurrentAuthoritySigner(t, session)
		candidate, prepared := prepareTestEndSelectedWork(t, session, ctx, facts.EndWork.GroupID, trust)
		if candidate == nil || prepared.Outcome != ObservedCurrent || candidate.head.EndWork == nil {
			t.Fatal("fresh process end-work preparation", prepared)
		}
		selected, outcome := session.selectCandidate(ctx, candidate)
		if selected == nil || outcome.Outcome != ObservedCurrent || !selected.validEndWorkSelection() {
			t.Fatal("fresh process end-work selection", outcome)
		}
		store.call(processStoreRequest{Method: "authenticated-end-work"})
		return
	}
	if generatedRole {
		processGeneratedRecordChild(t, ctx, store, session, facts)
		return
	}
	if role != "writer" || facts.Writer == nil {
		t.Fatal("process Store writer facts missing")
	}
	w := facts.Writer
	trust := &fixtureTrust{Signer: testtrust.New(t, facts.Descriptor.Family, facts.Trust)}
	comparison, result := session.Compare(context.Background(), w.Requested, admitSuppliedComparison(t, session, nil, w.Requested))
	if comparison == nil || result != wantOpen {
		t.Fatalf("process Store ComparePlain: %+v", result)
	}
	plan := transitionPlan{operation: w.Operation, transition: w.Transition, snapshot: w.Snapshot, revision: w.Revision, pages: w.Pages, supportPages: w.SupportPages, values: w.Values, incarnations: w.Incarnations}
	authority, err := session.lifecycleAuthority(t.Context(), comparison, plan)
	if err != nil {
		t.Fatal(result)
	}
	permit := &AdmittedParentTransition{session: session, comparison: comparison, predecessorDigest: contract.Hash(session.body), predecessorRevision: session.head.Core.Revision, predecessorToken: session.token, plan: plan, authority: authority}
	candidate, result := session.Prepare(ctx, comparison, permit, trust)
	wantPrepare := wantOpen
	wantPrepare.RequestedRevision = plan.revision
	if candidate == nil || result != wantPrepare || trust.signs != 1 {
		t.Fatalf("process Store Prepare: %+v, signs=%d", result, trust.signs)
	}
	wantSelect := Result{Outcome: ObservedCurrent, RequestedRevision: plan.revision, ObservedRevision: plan.revision, ObservedSnapshotID: plan.snapshot, Evidence: AuthenticatedClosure}
	if result := session.Select(ctx, candidate); result != wantSelect {
		t.Fatalf("process Store Select did not authenticate the requested complete state: %+v", result)
	}
	// This fixed marker contains no writer state. Select has returned only
	// after verifying HEAD proofs, bindings, every child, and all relations.
	store.call(processStoreRequest{Method: "authenticated-requested-state"})
	t.Fatal("terminated writer was incorrectly resumed")
}

func processInstalledEndWorkChild(t *testing.T, _ context.Context, store *processStore, all processStoreFacts) {
	t.Helper()
	facts, expected := all.EndWork, all.ExpectedImage
	if facts == nil || !facts.Installed || facts.NormalSigner.Binding.Trust.IsZero() {
		t.Fatal("installed process lacks exact independent signing facts")
	}
	// These facts came from the supervisor's admitted source, before child reads.
	independent := processPublicAdmission(all.Domain, all.Trust, all.Descriptor, all.PublicKey, all.DomainBasis)
	if facts.CurrentBasis != nil {
		independent.admission.current = facts.CurrentBasis.owned()
		independent.admission.epoch = facts.Epoch
	}
	basis := independent.admission.publicBasis()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	read := func(operation AdministrativeOperation) *AuthoritySession {
		source := &installedAdministrativeTestReader{store: store}
		parent, err := NewInstalledAdministrativeReader(AdministrativeReadInstallation{ExpectedDomain: all.Domain, ExpectedStore: all.Descriptor, PublicBasis: basis, CompositionID: independent.admission.composition, SourcePins: installedAdministrativeTestPins(), Source: source, CheckSource: func(context.Context) error { return nil }}, operation)
		if err != nil {
			t.Fatal(err)
		}
		return parent
	}
	list := read(AdministrativeList)
	before := list.List(ctx, generatedVectorID(221))
	if err := list.Close(); err != nil {
		t.Fatal(err)
	}
	if before.Result.Outcome != ObservedCurrent || before.List == nil || before.Query == nil || before.Query.Digest.IsZero() || before.Query.Digest != before.RequestIdentity || before.Result.ObservedRevision != expected.Revision || len(before.List.Groups) != 1 || before.List.Groups[0].GroupID != facts.GroupID {
		t.Fatal("installed fresh list exact owner", before.Result)
	}
	planner := read(AdministrativePlan)
	plan := planner.Plan(ctx, generatedVectorID(222), AdministrativePlanRequest{TargetGroupID: facts.GroupID, ArtifactPath: "/installed-process-plan"})
	if err := planner.Close(); err != nil {
		t.Fatal(err)
	}
	if plan.Result.Outcome != ObservedCurrent || plan.Plan == nil || plan.Plan.Preview.Identity.IsZero() || plan.Plan.Preview.PredecessorRevision != expected.Revision || plan.Plan.Preview.TargetGroupID != facts.GroupID {
		t.Fatal("installed fresh plan exact owner", plan.Result)
	}
	trust := testtrust.NewCurrent(t, facts.NormalSigner)
	authority, err := NewInstalledAdministrativeAuthority(AdministrativeAuthorityInstallation{ExpectedDomain: all.Domain, ExpectedStore: all.Descriptor, PublicBasis: basis, CompositionID: independent.admission.composition, SourcePins: installedAdministrativeTestPins(), Store: store, Trust: trust, CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	outcome := authority.Apply(ctx, generatedVectorID(223), plan.Plan.Preview)
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	if outcome.Result.Outcome != ObservedCurrent || outcome.End == nil || outcome.OperationID.IsZero() || outcome.End.Receipt.OperationKind != contract.OperationEndSelectedWork || outcome.End.Receipt.OperationID != outcome.OperationID || len(outcome.End.ReceiptBytes) != contract.CompactMutationReceiptLength {
		t.Fatal("installed fresh process apply", outcome.Result)
	}
	receiptReader := read(AdministrativeReceipt)
	receipt := receiptReader.Receipt(ctx, generatedVectorID(224), outcome.OperationID)
	if err := receiptReader.Close(); err != nil {
		t.Fatal(err)
	}
	if receipt.Result.Outcome != ObservedCurrent || receipt.Receipt == nil || receipt.Receipt.Receipt.OperationID != outcome.OperationID || !bytes.Equal(receipt.Receipt.ReceiptBytes, outcome.End.ReceiptBytes) {
		t.Fatal("installed fresh process exact receipt", receipt.Result)
	}
	later := read(AdministrativeList)
	after := later.List(ctx, generatedVectorID(225))
	if err := later.Close(); err != nil {
		t.Fatal(err)
	}
	if after.Result.Outcome != ObservedCurrent || after.List == nil || len(after.List.Groups) != 0 || after.Result.ObservedRevision != outcome.Result.ObservedRevision {
		t.Fatal("installed fresh process ended owner remains", after.Result)
	}
	store.call(processStoreRequest{Method: "authenticated-end-work"})
}

// full_only: false
func TestProcessStoreProtocolRefusesMalformedFrames(t *testing.T) {
	for name, body := range map[string][]byte{
		"zero-length":      {0, 0, 0, 0},
		"oversized":        binary.BigEndian.AppendUint32(nil, processStoreFrameLimit+1),
		"truncated-prefix": {0, 0},
		"truncated-body":   append(binary.BigEndian.AppendUint32(nil, 4), '{'),
		"unknown-field":    append(binary.BigEndian.AppendUint32(nil, 11), []byte(`{"Other":1}`)...),
		"trailing-json":    append(binary.BigEndian.AppendUint32(nil, 5), []byte(`{} {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			var request processStoreRequest
			if err := readProcessStoreFrame(bytes.NewReader(body), &request); err == nil {
				t.Fatal("malformed process Store frame accepted")
			}
		})
	}
	f := newFixture(t, 1, false, 1)
	for _, method := range []string{"create", "cas"} {
		request := processStoreRequest{Method: method, Key: f.store.desc.HeadKey, Token: f.session.token, Body: []byte("unauthorized")}
		if method == "create" {
			request.Token = contract.Token{}
		}
		if _, err := processStoreOperation(f.store, request, true); err == nil {
			t.Fatal("read-only process Store allowed a write")
		}
	}
	if f.store.creates != 0 || f.store.cas != 0 {
		t.Fatal("forbidden process Store write reached the retained Store")
	}
	reads := f.store.reads
	capabilities := &processStoreProtocolCapabilities{Store: f.store}
	for _, request := range []processStoreRequest{
		{Method: "delete", Key: f.store.desc.HeadKey, Token: f.session.token},
		{Method: "read", Key: f.store.desc.HeadKey, Maximum: contract.MaxHeadLength, Cursor: "next"},
		{Method: "create", Key: "immutable", Body: []byte{1}, Cursor: "next"},
		{Method: "cas", Key: f.store.desc.HeadKey, Token: f.session.token, Body: []byte{1}, Cursor: "next"},
		{Method: "list", Key: "mixed"},
		{Method: "list", Maximum: 1},
		{Method: "list", Token: f.session.token},
		{Method: "list", Body: []byte{1}},
		{Method: "list", Cursor: strings.Repeat("x", contract.StoreListCursorLength+1)},
	} {
		if _, err := processStoreOperation(capabilities, request, true); err == nil {
			t.Fatal("process Store accepted mixed or forbidden capabilities", request.Method)
		}
	}
	for _, request := range []processStoreRequest{{Method: "list"}, {Method: "delete", Key: f.store.desc.HeadKey, Token: f.session.token}} {
		if _, err := processStoreOperation(f.store, request, false); err == nil {
			t.Fatal("process Store invented an unsupported capability", request.Method)
		}
	}
	if processStoreMarker(processStoreRequest{Method: "control-ready", Cursor: "next"}, "control-ready") ||
		processRequestMatches(processStoreRequest{Method: "list", Cursor: "other"}, processStoreRequest{Method: "list", Cursor: "next"}) {
		t.Fatal("process Store control or exact request ignored a cursor")
	}
	if capabilities.lists != 0 || capabilities.deletes != 0 || f.store.reads != reads || f.store.creates != 0 || f.store.cas != 0 {
		t.Fatal("refused process capabilities reached a physical operation")
	}
	listed, err := processStoreOperation(capabilities, processStoreRequest{Method: "list", Cursor: "next"}, true)
	if err != nil || listed.List.Status != contract.ListPageOK || capabilities.lists != 1 || capabilities.cursor != "next" {
		t.Fatal("valid bounded process listing was blocked or changed", err)
	}
}

type processStoreProtocolCapabilities struct {
	contract.Store
	lists, deletes int
	cursor         string
}

func (s *processStoreProtocolCapabilities) ListPage(_ context.Context, cursor string) contract.ListPageResult {
	s.lists++
	s.cursor = cursor
	return contract.ListPageResult{Status: contract.ListPageOK}
}
func (s *processStoreProtocolCapabilities) DeleteIfToken(context.Context, string, contract.Token) contract.WriteResult {
	s.deletes++
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

// full_only: false
func TestProcessStoreControlFailuresCannotSatisfyBarrier(t *testing.T) {
	for _, role := range []string{"control-exit", "control-pipe", "control-marker", "control-timeout"} {
		t.Run(role, func(t *testing.T) {
			p := startProcessStoreChild(t, processStoreDiagnostics(t), role, processStoreFacts{})
			ready, err := p.next()
			if err != nil || !processStoreMarker(ready, "control-ready") {
				t.Fatalf("control child did not start: %v", err)
			}
			if err := p.reply(processStoreReply{}); err != nil {
				t.Fatal(err)
			}
			if role == "control-timeout" {
				if err := p.requests.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			}
			marker, err := p.next()
			switch role {
			case "control-exit":
				if !errors.Is(err, io.EOF) {
					t.Fatalf("unexpected child exit not detected: %v", err)
				}
			case "control-pipe":
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("truncated child pipe not detected: %v", err)
				}
			case "control-marker":
				if err != nil || processStoreMarker(marker, "authenticated-requested-state") {
					t.Fatalf("incorrect completion marker accepted: %v", err)
				}
			case "control-timeout":
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("missing barrier did not meet its deadline: %v", err)
				}
			}
			if role == "control-exit" || role == "control-pipe" {
				if err := p.join(); err != nil {
					t.Fatal(err)
				}
			} else if err := p.stop(); err != nil {
				t.Fatal(err)
			}
			if !p.joined {
				t.Fatal("failed control child was not joined")
			}
		})
	}
}
