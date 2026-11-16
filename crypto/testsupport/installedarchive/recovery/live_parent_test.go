package recovery

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type snapshotReadStore struct {
	contract.Store
	results []contract.ReadResult
	reads   int
}

func (s *snapshotReadStore) Read(context.Context, string, uint32) contract.ReadResult {
	result := s.results[s.reads]
	s.reads++
	return result
}

func snapshotReadFixture() (installedarchive.Archive, []contract.ReadResult) {
	var archive installedarchive.Archive
	var results []contract.ReadResult
	for range 3 {
		object := installedarchive.Object{Key: "private-object-key-sentinel", Body: []byte("private-object-body-sentinel"), Token: contract.Token{Family: contract.AWS, Value: "\"private-object-token-sentinel\""}}
		archive.Objects = append(archive.Objects, object)
		results = append(results, contract.ReadResult{Status: contract.ReadOK, Body: object.Body, Token: object.Token})
	}
	return archive, results
}

// full_only: false
func TestLiveSnapshotReadFailureRetainsReasonAndContext(t *testing.T) {
	for _, row := range []struct {
		name     string
		position int
		reason   contract.Reason
		state    string
	}{
		{"access_first_active", 0, contract.ReasonAccess, "active"},
		{"transport_later_active", 2, contract.ReasonTransport, "active"},
		{"access_later_cancelled", 1, contract.ReasonAccess, "cancelled"},
		{"transport_first_deadline", 0, contract.ReasonTransport, "deadline"},
	} {
		t.Run(row.name, func(t *testing.T) {
			ctx := t.Context()
			switch row.state {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			archive, results := snapshotReadFixture()
			results[row.position] = contract.ReadResult{Status: contract.ReadUnavailable, Reason: row.reason}
			store := &snapshotReadStore{results: results}
			err := checkLiveRemoteObjects(ctx, store, archive, &snapshotReadRelay{})
			if err == nil {
				t.Fatal("unavailable snapshot read passed")
			}
			for _, want := range []string{
				fmt.Sprintf("object=%d", row.position),
				"status=3", fmt.Sprintf("reason=%d", row.reason),
				fmt.Sprintf("context_cancelled=%t", row.state == "cancelled"),
				fmt.Sprintf("context_deadline=%t", row.state == "deadline"),
				"observed_bytes=0",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("snapshot failure omitted %s", want)
				}
			}
			if store.reads != row.position+1 {
				t.Fatal("snapshot failure retried or read later objects")
			}
			for _, secret := range []string{"private-object-key-sentinel", "private-object-body-sentinel", "private-object-token-sentinel"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("snapshot failure exposed private object data")
				}
			}
		})
	}
}

// full_only: false
func TestLiveSnapshotReadPreservesWholeObjectAssertion(t *testing.T) {
	for _, condition := range []string{"unchanged", "token_changed", "body_changed"} {
		t.Run(condition, func(t *testing.T) {
			archive, results := snapshotReadFixture()
			switch condition {
			case "token_changed":
				results[1].Token.Value = "\"private-other-token-sentinel\""
			case "body_changed":
				results[1].Body = []byte("private-other-body-sentinel")
			}
			store := &snapshotReadStore{results: results}
			err := checkLiveRemoteObjects(t.Context(), store, archive, &snapshotReadRelay{})
			if condition == "unchanged" {
				if err != nil || store.reads != len(archive.Objects) {
					t.Fatal("unchanged whole-object snapshot failed")
				}
				return
			}
			if err == nil || store.reads != 2 {
				t.Fatal("changed whole-object snapshot passed or read later objects")
			}
			for _, secret := range []string{"private-object-key-sentinel", "private-object-body-sentinel", "private-object-token-sentinel", "private-other-token-sentinel", "private-other-body-sentinel"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("snapshot mismatch exposed private object data")
				}
			}
		})
	}
}

type snapshotReadRelay struct {
	parentReadRelay
	facts         ReadTransportEvidence
	evidenceReads int
}

func (r *snapshotReadRelay) Evidence() ReadTransportEvidence {
	r.evidenceReads++
	return r.facts
}

// full_only: false
func TestLiveSnapshotReadFailureRetainsOnlySafeRelayFacts(t *testing.T) {
	archive, results := snapshotReadFixture()
	results[1] = contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
	store := &snapshotReadStore{results: results}
	relay := &snapshotReadRelay{facts: ReadTransportEvidence{
		Attempted:        RecoveryCounts{Reads: 2, Unknown: 1},
		Sent:             RecoveryCounts{Reads: 1},
		Refused:          RecoveryCounts{Reads: 1},
		Injected:         RecoveryCounts{Reads: 1},
		Failures:         3,
		ReservedRequests: 4,
		ReservedBytes:    8192,
		DecryptResources: []string{"private-decrypt-resource-sentinel"},
	}}
	err := checkLiveRemoteObjects(t.Context(), store, archive, relay)
	if err == nil || relay.evidenceReads != 1 || store.reads != 2 {
		t.Fatal("failure omitted relay evidence or continued snapshot reads")
	}
	for _, want := range []string{"attempted={Reads:2 ", "sent={Reads:1 ", "refused={Reads:1 ", "injected={Reads:1 ", "failures=3", "reserved_requests=4", "reserved_bytes=8192", "Unknown:1}"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("snapshot failure omitted %s", want)
		}
	}
	for _, secret := range []string{"private-decrypt-resource-sentinel", "DecryptResources", "private-object-key-sentinel", "private-object-body-sentinel", "private-object-token-sentinel"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("relay failure exposed private data")
		}
	}
}

// full_only: false
func TestLiveSnapshotMissingExpectationRetainsFailureFacts(t *testing.T) {
	archive, _ := snapshotReadFixture()
	observed := contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
	relay := &snapshotReadRelay{facts: ReadTransportEvidence{Refused: RecoveryCounts{Reads: 1}}}
	err := liveSnapshotReadFailure(t.Context(), 2, contract.ReadMissing, observed, archive.Objects[2], relay)
	for _, want := range []string{"object=2", "expected_status=2", "status=3", "reason=1", "refused={Reads:1 "} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing expectation failure omitted %s", want)
		}
	}
	if relay.evidenceReads != 1 {
		t.Fatal("missing expectation failure omitted relay evidence")
	}
}
