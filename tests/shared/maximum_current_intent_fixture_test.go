package core

import (
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// The producer responses are synthetic. Existing Crypto seals and validates
// every complete result; the existing writer signs and selects Record/Final.
func configurationRecoveryMaximumCurrentIntents(t *testing.T, env fixtureEnvironment, fixture *environmentFixture, output string) {
	t.Helper()
	_, implementation := buildHermeticCloudflareGenerator(t, installedarchive.MaximumCloudflareOrigin)
	profile := nativeGeneratedFixtureProfile(t, implementation)
	store := env.Store.(*memoryStore)
	if err := store.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
		t.Fatal("maximum fixture body storage unavailable")
	}
	current := fixture.session
	for batch := 0; batch < 2; batch++ {
		names := make([]string, 64)
		intents := make(map[string][]byte, 64)
		requests := make(map[string][]byte, 64)
		for i := range names {
			names[i] = fmt.Sprintf("maximum-%03d", batch*64+i) + strings.Repeat("x", 78)
			intents[names[i]], requests[names[i]] = installedarchive.MaximumCloudflareIntent(t, names[i])
		}
		sources := generatedWriterCurrentDeclarations(t, current, names)
		operation := fixtureID(env.Domain, fmt.Sprintf("maximum valid writer %d", batch))
		bound := generatedReservationInputForMembershipStateIntents(t, current, operation, []contract.ID{current.admission.recipient}, names, func(name string) []byte { return intents[name] }, profile, 0, nil, nil, sources...)
		input := generatedPlanInputForGenerations(t, current, operation, names, profile, sources...)
		input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = bound.graph, bound.declaration, bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID, slices.Clone(bound.requestBindings)
		input.context.AdmissionID, input.context.SessionID = fixtureID(env.Domain, fmt.Sprintf("maximum admission %d", batch)), fixtureID(env.Domain, fmt.Sprintf("maximum session %d", batch))
		input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		requestsByLineage := make(map[contract.ID][]byte, 64)
		for _, lineage := range input.graph.Lineages {
			requestsByLineage[lineage.LineageID] = requests[lineage.Name]
		}
		if len(input.requestBindings) != 64 {
			t.Fatal("maximum fixture original binding count differs")
		}
		for i := range input.requestBindings {
			body := requestsByLineage[input.requestBindings[i].LineageID]
			if len(body) == 0 {
				t.Fatal("maximum fixture original request name differs")
			}
			input.requestBindings[i].Digest = hermeticCloudflareHTTPRequestDigest(body)
		}
		current = selectGeneratedWriterBatch(t, env, current, input, "valid maximum", custody.SyntheticCloudflareValue)
	}
	g := current.root.Generated
	if current.root.ValueEntryCount != 128 || current.root.SecretCount != 128 || g.GeneratedCurrent != 128 || !g.ActiveOwner.IsZero() || g.Duties != 0 || g.Hazards != 0 || g.Retiring != 0 || g.Attempts != 0 || g.Results != 0 || g.Materials != 0 || g.Graphs.Count != 0 || g.PendingReleases != 0 {
		t.Fatal("maximum fixture retained live generated work")
	}
	binding, eligible := candidateSelectionSignature(current.head, current.root, contract.NormalSigningRole)
	if !eligible || binding.Binding.Trust != publicationLossTrustID(contract.AWS, contract.NormalSigningRole) {
		t.Fatal("maximum fixture public candidate proof differs")
	}
	configuration := store.configuration
	location := contract.StoreLocation{Provider: configuration.Provider, Region: configuration.Region, Bucket: configuration.Bucket, PrefixBeforeHEAD: configuration.PrefixBeforeHEAD, ExpectedOwner: configuration.ExpectedOwner}
	archive := configurationRecoveryArchiveMetadata(t, env, current, location)
	keys := map[string]uint32{store.desc.HeadKey: contract.MaxHeadLength}
	helper, err := contract.StoreConfigurationKeyForID(contract.AWS, store.desc.Prefix, env.Domain, current.head.Core.Store)
	if err != nil {
		t.Fatal("maximum configuration key refused")
	}
	keys[helper] = contract.MaxStoreConfigurationLength
	add := func(ref format.Ref) {
		key, err := format.Key(store.desc.Prefix, ref)
		if err != nil {
			t.Fatal("maximum selected key refused")
		}
		keys[key] = ref.Length
	}
	add(current.head.Core.Root)
	for _, table := range [][]*format.Ref{current.root.ValueEntryPages[:], current.root.Recipients[:]} {
		for _, ref := range table {
			if ref != nil {
				add(*ref)
			}
		}
	}
	for _, ref := range current.root.CurrentAccess.Core.AccessPageRefs {
		add(ref)
	}
	add(current.root.AdministrativeIndex)
	for _, refs := range [][]format.Ref{current.root.AdministrativeIndexShards, current.root.RequiredSupport} {
		for _, ref := range refs {
			add(ref)
		}
	}
	if len(keys) != int(current.root.ChildCount)+3 {
		t.Fatal("maximum selected physical closure count differs")
	}
	names := make([]string, 0, len(keys))
	for key := range keys {
		names = append(names, key)
	}
	sort.Strings(names)
	var total uint64
	for _, key := range names {
		read := store.Read(env.operationContext(), key, keys[key])
		if read.Status != contract.ReadOK {
			t.Fatal("maximum selected physical body unavailable")
		}
		token, err := contract.AppendToken(nil, read.Token)
		if err != nil {
			t.Fatal("maximum selected token refused")
		}
		archive.Objects = append(archive.Objects, installedarchive.Object{Key: key, TokenWire: token, Body: read.Body, BodySHA256: fmt.Sprintf("%x", contract.Hash(read.Body))})
		total += uint64(len(read.Body))
	}
	if total > installedarchive.MaximumIntentArchiveBodyBytes {
		t.Fatal("maximum archive body bound exceeded")
	}
	archive = configurationRecoveryArchiveWithObjects(archive, archive.Objects)
	parts, err := archive.SelectedParts()
	if err != nil || len(parts) == 0 || !bytes.Equal(archive.SignerPublicKey, env.PublicKey) {
		t.Fatal("maximum archive selected closure refused")
	}
	installedarchive.WriteMaximumIntentFixture(t, output, archive)
	t.Logf("maximum fixture selected_objects=%d selected_body_bytes=%d canonical_intent_bytes=%d", len(archive.Objects), total, 128*installedarchive.MaximumCloudflareIntentBytes)
}
