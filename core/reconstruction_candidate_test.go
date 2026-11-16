package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
)

type candidateReadProbe struct {
	head, configuration, root contract.ReadResult
	guarded                   contract.ReadResult
	guardedSet                bool
	guardedOwner              string
	location                  contract.StoreLocation
	calls                     []string
}

var _ candidateReadSource = (*candidateReadProbe)(nil)
var _ guardedCandidateHEADSource = (*candidateReadProbe)(nil)

func (p *candidateReadProbe) CandidateLocation() contract.StoreLocation { return p.location }

func (p *candidateReadProbe) ReadHEAD(context.Context) contract.ReadResult {
	p.calls = append(p.calls, "HEAD")
	return p.head
}
func (p *candidateReadProbe) ReadConfiguration(_ context.Context, _, _ contract.ID) contract.ReadResult {
	p.calls = append(p.calls, "configuration")
	return p.configuration
}
func (p *candidateReadProbe) ReadRoot(_ context.Context, _ contract.Ref) contract.ReadResult {
	p.calls = append(p.calls, "root")
	return p.root
}
func (p *candidateReadProbe) ReadHEADGuarded(_ context.Context, owner string) contract.ReadResult {
	p.calls = append(p.calls, "guarded HEAD")
	p.guardedOwner = owner
	if p.guardedSet {
		return p.guarded
	}
	return p.head
}

func candidateReadOK(body []byte) contract.ReadResult {
	return contract.ReadResult{Status: contract.ReadOK, Body: body, Token: contract.Token{Family: contract.GCP, Value: "1"}}
}

// full_only: false
func TestCandidateReaderOwnsOnlyBoundedPublicBodies(t *testing.T) {
	ctx := context.Background()
	domain := contract.Hash([]byte("candidate domain"))
	head := []byte("candidate HEAD")
	helper := []byte("candidate configuration")
	root := []byte("candidate root")
	helperID := contract.Hash(helper)
	ref := contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: domain,
		Object: contract.Hash([]byte("candidate snapshot")), Digest: contract.Hash(root), Length: uint32(len(root))}
	probe := &candidateReadProbe{head: candidateReadOK(head), configuration: candidateReadOK(helper), root: candidateReadOK(root)}
	selectedHEAD := readCandidateHEAD(ctx, probe)
	selectedHelper := readCandidateConfiguration(ctx, probe, domain, helperID)
	selectedRoot := readCandidateRoot(ctx, probe, ref)
	if selectedHEAD.Status != contract.ReadOK || selectedHelper.Status != contract.ReadOK || selectedRoot.Status != contract.ReadOK ||
		len(probe.calls) != 3 || probe.calls[0] != "HEAD" || probe.calls[1] != "configuration" || probe.calls[2] != "root" {
		t.Fatal("candidate read sequence or bound changed", probe.calls)
	}
	head[0], helper[0], root[0] = 'X', 'Y', 'Z'
	if string(selectedHEAD.Body) != "candidate HEAD" || string(selectedHelper.Body) != "candidate configuration" || string(selectedRoot.Body) != "candidate root" {
		t.Fatal("candidate bytes still borrow the provider's next-read backing")
	}
}

// full_only: false
func TestCandidateReaderRefusesUnboundedOrUnboundReads(t *testing.T) {
	ctx := context.Background()
	domain := contract.Hash([]byte("candidate domain"))
	body := []byte("root")
	ref := contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: domain,
		Object: contract.Hash([]byte("candidate snapshot")), Digest: contract.Hash(body), Length: uint32(len(body))}
	probe := &candidateReadProbe{head: candidateReadOK([]byte("head")), configuration: candidateReadOK([]byte("helper")), root: candidateReadOK(body)}
	for _, damaged := range []contract.Ref{
		{},
		func() contract.Ref { v := ref; v.Kind = contract.RequiredSupportKind; return v }(),
		func() contract.Ref { v := ref; v.Index = 1; return v }(),
		func() contract.Ref { v := ref; v.Format--; return v }(),
		func() contract.Ref { v := ref; v.Length = contract.MaxRootLength + 1; return v }(),
	} {
		if result := readCandidateRoot(ctx, probe, damaged); result.Status != contract.ReadInvalid || len(probe.calls) != 0 {
			t.Fatal("invalid root reference reached candidate provider", result, probe.calls)
		}
	}
	if result := readCandidateConfiguration(ctx, probe, domain, contract.ID{}); result.Status != contract.ReadInvalid || len(probe.calls) != 0 {
		t.Fatal("zero candidate StoreID reached provider", result, probe.calls)
	}
	if result := readCandidateConfiguration(ctx, probe, domain, contract.Hash([]byte("wrong helper"))); result.Status != contract.ReadInvalid ||
		result.Reason != contract.ReasonMalformed || len(result.Body) != 0 {
		t.Fatal("unbound helper bytes survived", result)
	}
	probe.calls = nil
	probe.root = candidateReadOK([]byte("wrong"))
	if result := readCandidateRoot(ctx, probe, ref); result.Status != contract.ReadInvalid || result.Reason != contract.ReasonMalformed || len(result.Body) != 0 {
		t.Fatal("wrong root digest survived", result)
	}
	probe.root = candidateReadOK([]byte("roo"))
	if result := readCandidateRoot(ctx, probe, ref); result.Status != contract.ReadInvalid || result.Reason != contract.ReasonMalformed {
		t.Fatal("truncated root survived", result)
	}
	probe.calls = nil
	probe.root = candidateReadOK(bytes.Repeat([]byte{'x'}, contract.MaxRootLength+1))
	if result := readCandidateRoot(ctx, probe, ref); result.Status != contract.ReadInvalid || result.Reason != contract.ReasonMalformed {
		t.Fatal("oversized root survived", result)
	}
	probe.calls = nil
	probe.head = candidateReadOK(bytes.Repeat([]byte{'x'}, contract.MaxHeadLength+1))
	if result := readCandidateHEAD(ctx, probe); result.Status != contract.ReadInvalid || result.Reason != contract.ReasonMalformed {
		t.Fatal("oversized HEAD survived", result)
	}
	probe.calls = nil
	probe.configuration = candidateReadOK(bytes.Repeat([]byte{'x'}, contract.MaxStoreConfigurationLength+1))
	if result := readCandidateConfiguration(ctx, probe, domain, contract.Hash(probe.configuration.Body)); result.Status != contract.ReadInvalid || result.Reason != contract.ReasonMalformed {
		t.Fatal("oversized helper survived", result)
	}
	probe.calls = nil
	probe.head = contract.ReadResult{Status: contract.ReadMissing, Body: []byte("untrusted partial"), Token: contract.Token{Family: contract.GCP, Value: "1"}}
	if result := readCandidateHEAD(ctx, probe); result.Status != contract.ReadMissing || len(result.Body) != 0 || result.Token.Valid() {
		t.Fatal("non-OK candidate body or token survived", result)
	}
	probe.head = contract.ReadResult{Status: 0, Body: []byte("untrusted partial")}
	if result := readCandidateHEAD(ctx, probe); result.Status != contract.ReadInvalid || result.Reason != contract.ReasonMalformed {
		t.Fatal("unknown candidate read status survived", result)
	}
	probe.head = contract.ReadResult{Status: contract.ReadOK, Body: []byte("head"), Reason: contract.ReasonTransport, Token: contract.Token{Family: contract.GCP, Value: "1"}}
	if result := readCandidateHEAD(ctx, probe); result.Status != contract.ReadInvalid || result.Reason != contract.ReasonMalformed {
		t.Fatal("mixed success/error status survived", result)
	}
	probe.head = contract.ReadResult{Status: contract.ReadOK, Body: []byte("head")}
	if result := readCandidateHEAD(ctx, probe); result.Status != contract.ReadInvalid || result.Reason != contract.ReasonMalformed {
		t.Fatal("missing candidate token survived", result)
	}
	probe.calls = nil
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if result := readCandidateHEAD(canceled, probe); result.Status != contract.ReadUnavailable || result.Reason != contract.ReasonLimit || len(probe.calls) != 0 {
		t.Fatal("canceled candidate read reached provider", result, probe.calls)
	}
}

// full_only: false
func TestCandidateReaderExactPublicBounds(t *testing.T) {
	ctx := context.Background()
	domain := contract.Hash([]byte("bounded candidate domain"))
	head := bytes.Repeat([]byte{'h'}, contract.MaxHeadLength)
	helper := bytes.Repeat([]byte{'c'}, contract.MaxStoreConfigurationLength)
	root := bytes.Repeat([]byte{'r'}, contract.MaxRootLength)
	ref := contract.Ref{Kind: contract.RootKind, Format: contract.CanonicalSchema, Domain: domain,
		Object: contract.Hash([]byte("bounded candidate snapshot")), Digest: contract.Hash(root), Length: uint32(len(root))}
	probe := &candidateReadProbe{head: candidateReadOK(head), configuration: candidateReadOK(helper), root: candidateReadOK(root)}
	if result := readCandidateHEAD(ctx, probe); result.Status != contract.ReadOK || len(result.Body) != contract.MaxHeadLength {
		t.Fatal("exact HEAD bound refused", result.Status)
	}
	if result := readCandidateConfiguration(ctx, probe, domain, contract.Hash(helper)); result.Status != contract.ReadOK || len(result.Body) != contract.MaxStoreConfigurationLength {
		t.Fatal("exact helper bound refused", result.Status)
	}
	if result := readCandidateRoot(ctx, probe, ref); result.Status != contract.ReadOK || len(result.Body) != contract.MaxRootLength {
		t.Fatal("exact root bound refused", result.Status)
	}
}
