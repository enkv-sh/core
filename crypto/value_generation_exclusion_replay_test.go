package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// The adversarial packet must authenticate. These two fixed preimages follow
// the documented ValueCore blob, plaintext length and semantic HMAC recipe;
// they let this test choose reused key bytes without a production sealing API.
func generatedReplayPayloadWithKeys(t *testing.T, core contract.ValueCore, plain, keys []byte) contract.CanonicalPayload {
	t.Helper()
	encoded, err := contract.EncodeValueCore(core)
	if err != nil {
		t.Fatal(err)
	}
	aad := append([]byte("ENKV/CRYPTO/v2/value-aad\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(encoded)))...)
	aad = append(aad, encoded...)
	semantic := append([]byte("ENKV/CRYPTO/v2/semantic\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(encoded)))...)
	semantic = append(semantic, encoded...)
	semantic = binary.BigEndian.AppendUint32(semantic, uint32(len(plain)))
	semantic = append(semantic, plain...)
	block, err := aes.NewCipher(keys[:32])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	payload := contract.CanonicalPayload{Profile: core.Profile, CryptoSupportID: core.CryptoSupportID, DataKeyID: core.DataKeyID, DataKeyEpoch: core.DataKeyEpoch,
		CommitmentKeyID: core.CommitmentKeyID, CommitmentKeyEpoch: core.CommitmentKeyEpoch, ContentLength: core.ContentLength, InputEncoding: contract.InputEncodingRaw, RetainedLength: core.ContentLength}
	copy(payload.Nonce[:], []byte("fresh replay"))
	payload.Ciphertext = aead.Seal(nil, payload.Nonce[:], plain, aad)
	h := hmac.New(sha256.New, keys[32:])
	_, _ = h.Write(semantic)
	h.Sum(payload.SemanticCommitment[:0])
	payload.PackageCheck, err = custody.PackageCheck(core, keys)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := custody.OpenValue(core, payload, keys)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("freshness challenge is not an authenticated value", err)
	}
	clear(opened[:cap(opened)])
	return payload
}

// full_only: false
func TestGeneratedExclusionReplayRejectsEveryOldKeyRole(t *testing.T) {
	for _, mode := range []string{"fresh control", "old data", "old commitment", "data from old commitment", "commitment from old data", "swapped old keys"} {
		t.Run(mode, func(t *testing.T) {
			a, _, _, route := generatedRetainedReplayFixture(t, contract.GeneratedHazardSupportKind, false, false)
			defer a.clear()
			before := a.purpose.final.membership[0].Selection
			oldKeys := generatedValueKeys(t, route, before.Binding, before.Core, before.Access)
			defer clear(oldKeys[:cap(oldKeys)])
			row := &a.purpose.final.preparedImage.Supplied[0]
			entry, err := contract.DecodeValueEntry(row.EntryBytes)
			if err != nil {
				t.Fatal(err)
			}
			core, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, entry)
			if err != nil {
				t.Fatal(err)
			}
			keys := append(bytes.Repeat([]byte{0x5e}, 32), bytes.Repeat([]byte{0x6f}, 32)...)
			defer clear(keys)
			switch mode {
			case "old data":
				copy(keys[:32], oldKeys[:32])
			case "old commitment":
				copy(keys[32:], oldKeys[32:])
			case "data from old commitment":
				copy(keys[:32], oldKeys[32:])
			case "commitment from old data":
				copy(keys[32:], oldKeys[:32])
			case "swapped old keys":
				copy(keys[:32], oldKeys[32:])
				copy(keys[32:], oldKeys[:32])
			}
			payload := generatedReplayPayloadWithKeys(t, core, []byte("old"), keys)
			entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			access, err := contract.DecodeAccessRecord(row.AccessRecord)
			if err != nil {
				t.Fatal(err)
			}
			access.PackageCheck = payload.PackageCheck
			access.Wraps = nil
			for _, binding := range a.bindings {
				if binding.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(entry.Recipients, binding.SubjectID) {
					continue
				}
				wrapCore, err := custody.ValueWrapCore(core, binding)
				if err != nil {
					t.Fatal(err)
				}
				wrap, err := custody.Wrap(wrapCore, binding.Binding, keys)
				if err != nil {
					t.Fatal(err)
				}
				access.Wraps = append(access.Wraps, wrap)
			}
			row.EntryBytes, err = contract.EncodeValueEntry(entry)
			if err != nil {
				t.Fatal(err)
			}
			row.AccessRecord, err = contract.EncodeAccessRecord(access)
			if err != nil {
				t.Fatal(err)
			}
			// This enters saved-image opening, then source and actual-key comparison.
			code := a.openPreparedSupplied(t.Context(), route, &contract.CryptoResponse{})
			if mode == "fresh control" {
				if code != contract.CryptoSuccess {
					t.Fatal("authenticated fresh-key control refused", code)
				}
			} else if code != contract.CryptoInvalidAdmission || len(a.purpose.final.supplied) != 0 {
				t.Fatal("authenticated old key bytes passed the private freshness gate", code)
			}
		})
	}
}

// full_only: false
func TestGeneratedChangedContentExclusionChecksKeysWithoutOldValueEquality(t *testing.T) {
	a, carrier, route, _ := generatedExclusionFixture(t, contract.Supplied, false, true)
	defer a.clear()
	before := carrier.Selection
	a.purpose.final.plan.currentValues = []contract.ConsumerSelection{before}
	oldKeys := generatedValueKeys(t, route, before.Binding, before.Core, before.Access)
	defer clear(oldKeys[:cap(oldKeys)])
	entry, _, code := a.prepareMembership(t.Context(), route, 0, &contract.CryptoResponse{})
	if code != contract.CryptoSuccess {
		t.Fatal(code)
	}
	core, err := contract.ValueCoreForEntry(a.request.Context.DomainID, a.request.Context.CompatibilityID, entry)
	if err != nil {
		t.Fatal(err)
	}
	core.ContentLength, core.RetainedLength = 3, 3
	entry.ContentLength, entry.RetainedLength = 3, 3
	for _, reuse := range []bool{false, true} {
		keys := append(bytes.Repeat([]byte{0x7d}, 32), bytes.Repeat([]byte{0x4c}, 32)...)
		if reuse {
			copy(keys[:32], oldKeys[32:])
		}
		payload := generatedReplayPayloadWithKeys(t, core, []byte("new"), keys)
		entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		code := a.preparedContentExclusionMatches(t.Context(), route, 0, entry, keys, &contract.CryptoResponse{})
		clear(keys)
		if !reuse && code != contract.CryptoSuccess || reuse && code != contract.CryptoInvalidAdmission {
			t.Fatal("changed-content freshness relation", reuse, code)
		}
	}
	a.purpose.final.plan.currentValues = nil
	if code := a.preparedContentExclusionMatches(t.Context(), route, 0, entry, bytes.Repeat([]byte{0x7d}, 64), &contract.CryptoResponse{}); code != contract.CryptoInvalidAdmission {
		t.Fatal("changed-content replay omitted authenticated old current material", code)
	}
}

// full_only: false
func TestGeneratedRetainedReplayAcceptsSafeCurrentOnlyImage(t *testing.T) {
	a, candidate, _, route := generatedRetainedReplayFixture(t, contract.GeneratedHazardSupportKind, false, false)
	defer a.clear()
	final := a.purpose.final
	before := final.membership[0].Selection
	intended := []contract.ID{a.control.AuthorityRecipientID}
	// The current source already has Authority only. A different selected old
	// source still requires the reader; this transition removes no current reader.
	a.purpose.output.EntriesBefore[0].Recipients = slices.Clone(intended)
	current := before.Entry
	current.Recipients = slices.Clone(intended)
	var err error
	a.purpose.output.EntryBodies[0], err = contract.EncodeValueEntry(current)
	if err != nil {
		t.Fatal(err)
	}
	access := before.Access
	access.Wraps = slices.Clone(access.Wraps)
	access.Wraps = slices.DeleteFunc(access.Wraps, func(w contract.WrapRow) bool {
		return w.SubjectKind == contract.OrdinaryWrapSubject && !slices.Contains(intended, w.SubjectID)
	})
	row := &final.preparedImage.Supplied[0]
	row.EntryBytes, err = contract.EncodeValueEntry(current)
	if err != nil {
		t.Fatal(err)
	}
	row.AccessRecord, err = contract.EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	saved := bytes.Clone(row.AccessRecord)
	if a.finalExcludesReader(0) {
		t.Fatal("safe replay fixture still removes current membership")
	}
	if code := a.openPreparedSupplied(t.Context(), route, &contract.CryptoResponse{}); code != contract.CryptoSuccess || len(final.supplied) != 1 || !final.supplied[0].currentOnlyReplay {
		t.Fatal("safe exact-current-only historical image refused", code)
	}
	final.suppliedNext, final.suppliedFinal = 1, true
	candidate.Entries[0].Entry = current
	candidate.PublicState.Rows[0].EntryDigest, err = contract.PublicValueEntryDigest(a.request.Context.DomainID, before.Slot, current)
	if err != nil {
		t.Fatal(err)
	}
	candidate.AccessRecords = []contract.AccessRecord{before.Access}
	if !a.candidateEntriesMatch(candidate) || !a.candidateCanonicalsMatch(candidate) || !bytes.Equal(saved, row.AccessRecord) {
		t.Fatal("safe image replay changed bytes or lost the surviving canonical reader")
	}
}
