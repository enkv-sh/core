package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func replacementFailureContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func replacementFailureRender(t *testing.T, result ReplacementCommandResult, operation, state string, exit int) {
	t.Helper()
	for _, human := range []bool{false, true} {
		var out bytes.Buffer
		write := WriteReplacementJSON
		if human {
			write = WriteReplacementHuman
		}
		if err := write(context.Background(), &out, result); err != nil {
			t.Errorf("closed result rejected: human=%t operation=%s state=%s error=%v", human, operation, state, err)
			continue
		}
		body := out.Bytes()
		if bytes.Contains(body, []byte("private-path-sentinel")) || bytes.Contains(body, []byte("private-provider-sentinel")) {
			t.Fatal("local failure leaked rejected input or cause")
		}
		if human {
			for _, fact := range []string{"Key replacement: " + state + "\n", "Operation: " + operation + "\n", "Successor files: " + result.Delivery.Status + "\n"} {
				if !bytes.Contains(body, []byte(fact)) {
					t.Fatal("human failure lost its operation or delivery result", fact, string(body))
				}
			}
			admission := result.PreAdmission
			if admission == nil && result.Observation != nil {
				admission = result.Observation.PreAdmission
			}
			if admission != nil && !bytes.Contains(body, []byte("Admission: "+admission.Stage+" / "+admission.Code+".\n")) {
				t.Fatal("human failure lost its established admission cause", string(body))
			}
			if result.Delivery.Path != "" && !bytes.Contains(body, []byte(fmt.Sprintf("%q", result.Delivery.Path))) || result.Delivery.RecoverySource != "" && !bytes.Contains(body, []byte(fmt.Sprintf("%q", result.Delivery.RecoverySource))) || result.Delivery.CleanupFailed && !bytes.Contains(body, []byte("Warning: local cleanup failed")) || result.Delivery.Failed && !bytes.Contains(body, []byte("Warning: local successor delivery failed")) || bytes.Contains(body, []byte("ProductResult/v1")) {
				t.Fatal("human failure lost a required path or failure fact", string(body))
			}
			continue
		}
		var wire replacementResultRecord
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatal(err)
		}
		if wire.Operation != operation || wire.State != state || wire.OperationPayload != "none" || string(wire.Payload) != `"none"` || wire.Replay != "none" || wire.Evidence != "unavailable" || wire.CommitMayHaveOccurred || wire.Query != nil || wire.StoredReceipt != nil || len(wire.Diagnostics) != 0 || wire.Effect != "not-applicable" || wire.Output != "not-applicable" || wire.OperationID == "none" || !bytes.Contains(wire.RequestIdentity, []byte("PreAdmissionRequestIdentity/v1")) {
			t.Fatal("local failure changed closed result facts", operation, state)
		}
	}
	if got := ReplacementCommandExitCode(result); got != exit {
		t.Errorf("closed result exit=%d want=%d", got, exit)
	}
}

// full_only: false
func TestReplacementOutputPathsRefuseBeforeCapture(t *testing.T) {
	for _, target := range []configuration.ReplacementTarget{configuration.ReplaceAuthority, configuration.ReplaceRecovery, configuration.ReplaceRecipient} {
		t.Run(string(target), func(t *testing.T) {
			base := t.TempDir()
			paths := []struct{ name, path string }{
				{"empty", ""}, {"relative", "private-path-sentinel.json"}, {"dot", base + "/./private-path-sentinel.json"},
				{"parent", base + "/child/../private-path-sentinel.json"}, {"root", "/"}, {"nul", base + "/private-path-sentinel\x00.json"},
				{"utf8", base + "/private-path-sentinel" + string([]byte{255})}, {"over-limit", "/" + strings.Repeat("x", 4096)},
			}
			for _, row := range paths {
				t.Run(row.name, func(t *testing.T) {
					calls := 0
					result := replaceKeysConfiguration(replacementFailureContext(t), contract.ID{7}, filepath.Join(base, "absent-source.json"), configuration.JSON, configuration.ReplacementRequest{Target: target}, row.path,
						func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error) {
							calls++
							return nil, nil, errors.New("unexpected reader")
						})
					if result.PreAdmission == nil || result.PreAdmission.Code != string(contract.ReasonInvalidInput) || result.Observation != nil || replacementFresh(&result) == nil || result.Delivery.Path != "" || result.Delivery.Status != "not-attempted" || result.Delivery.Failed || result.Delivery.CleanupFailed || calls != 0 {
						t.Errorf("invalid output escaped location admission: target=%s case=%s", target, row.name)
					}
					replacementFailureRender(t, result, "keys-replace-"+string(target), "refused", 2)
					entries, err := os.ReadDir(base)
					if err != nil || len(entries) != 0 {
						t.Fatal("invalid declaration changed local inventory", err)
					}
				})
			}
		})
	}
}

// full_only: false
func TestReplacementDeliveryPathsKeepByteBounds(t *testing.T) {
	for _, row := range []struct {
		name, path string
		valid      bool
	}{
		{"ascii-limit", "/" + strings.Repeat("x", 4095), true}, {"multibyte-limit", "/" + strings.Repeat("雪", 1365), true},
		{"over-limit", "/" + strings.Repeat("x", 4096), false}, {"invalid-utf8", "/" + string([]byte{255}), false},
		{"relative", "relative.json", false}, {"unclean", "/child/../other.json", false}, {"root", "/", false}, {"nul", "/bad\x00", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			result, err := NewReplacementCommandRefusal(configuration.ReplaceAuthority, contract.ID{8}, configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			result.Delivery.Path = row.path
			for _, human := range []bool{false, true} {
				var out bytes.Buffer
				write := WriteReplacementJSON
				if human {
					write = WriteReplacementHuman
				}
				err := write(context.Background(), &out, result)
				if (err == nil) != row.valid || !row.valid && out.Len() != 0 {
					t.Fatal("direct malformed location escaped writer preflight", row.name, human, err)
				}
			}
			if row.valid {
				actual := ReplaceKeysConfiguration(replacementFailureContext(t), contract.ID{8}, filepath.Join(t.TempDir(), "absent-source"), configuration.JSON, configuration.ReplacementRequest{Target: configuration.ReplaceAuthority}, row.path)
				if actual.Delivery.Path != row.path || actual.PreAdmission == nil {
					t.Fatal("valid byte-bound location was erased")
				}
				replacementFailureRender(t, actual, "keys-replace-authority", "refused", 2)
			}
		})
	}
}

type replacementFailureReader struct {
	descriptor    contract.Descriptor
	location      contract.StoreConfiguration
	reads, closed int
}

func (r *replacementFailureReader) Descriptor() contract.Descriptor { return r.descriptor }
func (r *replacementFailureReader) StoreConfiguration() contract.StoreConfiguration {
	return r.location
}
func (r *replacementFailureReader) Read(context.Context, string, uint32) contract.ReadResult {
	r.reads++
	return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
}
func (r *replacementFailureReader) Close() { r.closed++ }

// This fixture publishes and reopens a real local successor pair. Its public
// signatures admit the fixed source/successor relation, but it has no selected
// remote root: only a controlled reader-open failure or unavailable HEAD is used.
func replacementFailurePair(t *testing.T, target configuration.ReplacementTarget) (configurationReaderSource, string, configuration.ReplacementRequest, *replacementFailureReader) {
	t.Helper()
	ctx := replacementFailureContext(t)
	id := func(name string) contract.ID {
		return contract.Hash([]byte("replacement local failure fixture " + name))
	}
	var normal, recovery *testtrust.Signer
	source := configurationApplyPair(t, "aws", configuration.JSON, func(editable, generated map[string]any) {
		basis := generated["public_basis"].(map[string]any)
		d, err := contract.DecodeGenesisDescriptorCore(basis["descriptor"].([]byte))
		if err != nil {
			t.Fatal(err)
		}
		normal = testtrust.NewWithIdentity(t, contract.AWS, id("normal material"), d.TrustID, contract.NormalSigningRole)
		d.NormalSigning.KeySelector, d.NormalSigning.SPKI = normal.KeySelector(), normal.PublicKey()
		d.NormalSigning.Fingerprint = contract.Hash(d.NormalSigning.SPKI)
		d.NormalSigning.Binding.PublicKey = d.NormalSigning.Fingerprint
		recovery = testtrust.NewRecovery(t, contract.AWS, id("recovery trust"))
		signing := d.NormalSigning
		signing.Role = contract.RecoverySigningRole
		signing.BindingID = id("recovery signing binding")
		signing.KeySelector, signing.SPKI = recovery.KeySelector(), recovery.PublicKey()
		signing.Fingerprint = contract.Hash(signing.SPKI)
		signing.Binding.PublicKey, signing.Binding.Trust = signing.Fingerprint, recovery.Identity()
		var authorityKMS, kek contract.KMSBinding
		for _, r := range d.Recipients {
			if r.RecipientID == d.AuthorityRecipientID {
				authorityKMS = *r.CurrentBinding
			}
		}
		for _, r := range d.Recipients {
			if r.CurrentBinding != nil && contract.IndependentKMSBindings(authorityKMS, *r.CurrentBinding) {
				kek = *r.CurrentBinding
				break
			}
		}
		if kek.BindingID.IsZero() || !contract.IndependentKMSBindings(authorityKMS, kek) {
			t.Fatal("fixture requires independent existing Authority and Recovery public encryption keys")
		}
		kek.BindingID, kek.BindingIncarnationID = id("recovery binding"), id("recovery incarnation")
		d.Recovery = &contract.RecoveryBindings{RoleID: id("recovery role"), Signing: signing, KMS: kek}
		body, err := contract.EncodeGenesisDescriptorCore(d)
		if err != nil {
			t.Fatal(err)
		}
		basis["descriptor"] = body
		editable["domain"].(map[string]any)["authority"].(map[string]any)["signing_key"] = normal.KeySelector()
		generated["domain"].(map[string]any)["authority"].(map[string]any)["signing"] = map[string]any{"selector": normal.KeySelector(), "public_key": normal.PublicKey()}
		editable["domain"].(map[string]any)["recovery"] = map[string]any{"enabled": true, "signing_key": signing.KeySelector, "encryption_key": kek.KeySelector}
		generated["domain"].(map[string]any)["recovery"] = map[string]any{"enabled": true, "signing": map[string]any{"selector": signing.KeySelector, "public_key": signing.SPKI}, "encryption": configurationReaderKey(kek)}
	})
	// Fixture publication owns the source coordination namespaces. Observation
	// below receives fresh pins after the directories are read-only again.
	recaptureSource := func() {
		t.Helper()
		if err := source.pair.Close(); err != nil {
			t.Fatal(err)
		}
		pair, err := configuration.Capture(ctx, source.path, configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		source.pair = pair
		t.Cleanup(func() {
			if err := pair.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	configurationSetWritable(t, source)
	recaptureSource()
	m, err := configuration.Parse(ctx, source.pair)
	if err != nil {
		t.Fatal(err)
	}
	basis, store, err := configurationPublicBasis(m)
	if err != nil {
		t.Fatal(err)
	}
	before, err := basis.ControlCore(m.DomainID, store)
	if err != nil {
		t.Fatal(err)
	}
	controlBytes, err := contract.EncodeControlCore(before)
	if err != nil {
		t.Fatal(err)
	}
	after, err := contract.DecodeControlCore(controlBytes)
	if err != nil {
		t.Fatal(err)
	}
	request := configuration.ReplacementRequest{Target: target, Authorizer: contract.NormalSigningRole}
	rows := make([]configuration.ReplacementRecipientFact, len(m.GeneratedRecipients))
	for i, r := range m.GeneratedRecipients {
		key, err := configurationApplyBinding(m.Provider, r.Encryption)
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = configuration.ReplacementRecipientFact{RecipientID: r.ID, Encryption: key}
	}
	var successor *testtrust.Signer
	role := uint8(contract.SuccessorNormalSigner)
	mask := uint8(contract.SuccessionChangeNormalSigner)
	kind := uint8(contract.SuccessionReplaceAuthority)
	if target == configuration.ReplaceAuthority {
		successor, after.NormalSigning = normal.Successor(t, before.NormalSigning)
		request.SigningSelector = after.NormalSigning.KeySelector
	}
	if target == configuration.ReplaceRecovery {
		successor, after.Recovery.Signing = recovery.Successor(t, before.Recovery.Signing)
		request.SigningSelector = after.Recovery.Signing.KeySelector
		role, mask, kind = contract.SuccessorRecoverySigner, contract.SuccessionChangeRecoverySigner, contract.SuccessionReplaceRecoveryBasis
	}
	if target != configuration.ReplaceRecipient {
		after.AccessGeneration++
	} else {
		if len(m.Recipients) == 0 {
			t.Fatal("fixture requires a configured ordinary Recipient")
		}
		r := m.Recipients[0]
		request.RecipientReference = r.Reference
		request.EncryptionSelector = r.Encryption.Selector
		request.MaterialSource = "authority"
		found := false
		for i, row := range m.GeneratedRecipients {
			if row.Reference == r.Reference {
				rows[i].Encryption.BindingID = id("new Recipient binding")
				rows[i].Encryption.BindingSerial++
				found = true
			}
		}
		if !found {
			t.Fatal("fixture missing nominated row")
		}
	}
	head := format.Head{Core: format.HeadCore{Form: format.SuccessorHead, Domain: m.DomainID, Revision: id("candidate revision"), PreviousRevision: id("previous revision"), PreviousDigest: id("previous digest"), PreviousToken: contract.Token{Family: contract.AWS, Value: `"etag"`}, Root: format.Ref{Kind: format.RootKind, Format: format.Version, Domain: m.DomainID, Object: id("root object"), Digest: id("root digest"), Length: 123}, Store: store.Identity, Coordinate: store.Coordinate, NonBody: store.NonBody, Trust: after.NormalSigning.Binding.Trust, Interpretation: contract.InterpretationID(), Epoch: after.NormalSigning.Binding.Epoch}}
	coreBytes, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := contract.MatchHeadCondition(head.Core.PreviousToken)
	if err != nil {
		t.Fatal(err)
	}
	conditional, err := format.EncodeConditionalPlan(format.ConditionalPlan{Family: contract.AWS, Store: store.Identity, Coordinate: store.Coordinate, NonBody: store.NonBody, Condition: condition, HeadCore: contract.Hash(coreBytes), HeadCoreLength: uint32(len(coreBytes))})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(s *testtrust.Signer, q contract.SignRequest) []byte {
		v := s.Sign(ctx, q)
		if v.Reason != contract.ReasonNone || len(v.Signature) == 0 {
			t.Fatal("fixture signing failed")
		}
		return v.Signature
	}
	normalNow, recoveryNow := normal, recovery
	if target == configuration.ReplaceAuthority {
		normalNow = successor
	}
	if target == configuration.ReplaceRecovery {
		recoveryNow = successor
	}
	q, err := contract.NewBindingRequest(after.NormalSigning.Binding)
	if err != nil {
		t.Fatal(err)
	}
	head.K1 = sign(normalNow, q)
	q, err = contract.NewK3BasisRequest(after.Recovery.Signing)
	if err != nil {
		t.Fatal(err)
	}
	head.K3 = sign(recoveryNow, q)
	identity := id("original request identity")
	if target != configuration.ReplaceRecipient {
		selected := after.NormalSigning
		if target == configuration.ReplaceRecovery {
			selected = after.Recovery.Signing
		}
		bindingDigest, err := contract.SigningBindingDigest(selected)
		if err != nil {
			t.Fatal(err)
		}
		probe := contract.SuccessorProbeCore{Schema: 1, EvidenceKind: contract.SuccessorSignerEvidence, TargetRole: role, DomainID: m.DomainID, CoordinateID: store.Coordinate, AdmissionID: id("admission"), PredecessorFullHEADDigest: head.Core.PreviousDigest, RequestCoreDigest: id("request core"), SuccessorBindingDigest: bindingDigest, ProbeAttemptID: id("probe")}
		q, err = contract.NewSuccessorSignerProbeRequest(probe)
		if err != nil {
			t.Fatal(err)
		}
		evidence := []contract.SuccessorEvidenceRow{{TargetRole: role, EvidenceKind: contract.SuccessorSignerEvidence, Trust: contract.SuccessorTrustEvidence{SuccessorSignerFields: contract.SuccessorSignerFields{ProbeAttemptID: probe.ProbeAttemptID, SigningBindingDigest: bindingDigest}, Signature: sign(successor, q)}}}
		evidenceDigest, err := contract.SuccessorEvidenceDigest(evidence)
		if err != nil {
			t.Fatal(err)
		}
		beforeDigest, err := contract.ControlCoreDigest(before)
		if err != nil {
			t.Fatal(err)
		}
		afterDigest, err := contract.ControlCoreDigest(after)
		if err != nil {
			t.Fatal(err)
		}
		subject := contract.SuccessionSubject{Schema: contract.CanonicalSchema, OperationKind: kind, ApprovalRole: contract.NormalSigningRole, OperationID: id("operation"), AdmissionID: probe.AdmissionID, RequestCoreDigest: probe.RequestCoreDigest, RequestIdentityDigest: identity, IdentityPlanDigest: id("identity plan"), BeforeControlDigest: beforeDigest, AfterControlDigest: afterDigest, BeforeAccessRoot: id("before access"), AfterAccessRoot: id("after access"), PreservedStateDigest: id("preserved"), CoverageDigest: id("coverage"), ReplacementPlanDigest: id("replacement"), SuccessorEvidenceDigest: evidenceDigest, ReceiptDeltaDigest: id("receipt delta"), HeadCoreDigest: contract.Hash(coreBytes), ConditionalPlanDigest: contract.Hash(conditional), IdentityPlanLength: 162, HeadCoreLength: uint32(len(coreBytes)), ReplacementCount: 1, SuccessorEvidenceCount: 1, ChangeMask: mask}
		if target == configuration.ReplaceRecovery {
			subject.ReceiptDeltaCount = 1
		}
		q, err = contract.NewK2SuccessionRequest(subject)
		if err != nil {
			t.Fatal(err)
		}
		head.AuthorizationSignature = sign(normal, q)
		head.AuthKind = format.SuccessionAuth
		head.Succession = &format.SuccessionProof{Subject: subject, Authorizer: before.NormalSigning, Evidence: evidence, Acceptances: []format.SelectionAcceptanceProof{{Role: selected.Role, BindingDigest: bindingDigest, Epoch: selected.Binding.Epoch, Signature: evidence[0].Trust.Signature}}}
	} else {
		var old, next contract.KMSBinding
		var recipient contract.ID
		for i, row := range m.GeneratedRecipients {
			if row.Reference == request.RecipientReference {
				old, err = configurationApplyBinding(m.Provider, row.Encryption)
				if err != nil {
					t.Fatal(err)
				}
				next = rows[i].Encryption
				recipient = row.ID
			}
		}
		intent := contract.RecipientReplacementIntent{RecipientReplacementIntentFields: contract.RecipientReplacementIntentFields{Schema: contract.CanonicalSchema, Profile: contract.RSAOAEPWrapProfile, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: m.DomainID, BeforeAccessRoot: id("before access"), RecipientID: recipient}, Before: old, Successor: next}
		intentDescriptor, err := contract.RecipientReplacementIntentDescriptor(intent)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := contract.IdentityPlanDescriptor(contract.IdentityPlan{Operation: id("operation"), Transition: id("transition"), Snapshot: id("snapshot"), Revision: head.Core.Revision, Pages: []contract.IdentityPage{{Kind: contract.RecipientKind, Object: id("page")}}})
		if err != nil {
			t.Fatal(err)
		}
		support, err := contract.EmptyRequiredSupportDescriptor(m.DomainID)
		if err != nil {
			t.Fatal(err)
		}
		public, err := contract.PublicStateDescriptor(contract.PublicState{Domain: m.DomainID, AccessRoot: id("after access"), RequiredSupport: support})
		if err != nil {
			t.Fatal(err)
		}
		union, err := contract.UnionDescriptor(m.DomainID, nil)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := contract.GrantDescriptor(m.DomainID, nil)
		if err != nil {
			t.Fatal(err)
		}
		exclusion, err := contract.ExclusionDescriptor(m.DomainID, nil)
		if err != nil {
			t.Fatal(err)
		}
		retirement, err := contract.RetirementDescriptor(m.DomainID, nil)
		if err != nil {
			t.Fatal(err)
		}
		head.AuthKind = format.LifecycleAuth
		head.Subject = contract.LifecycleSubject{OperationKind: contract.OperationRotateRecipientKeyBinding, Operation: id("operation"), Recipient: before.AuthorityRecipientID, KeyBinding: before.AuthorityKMSBinding.BindingID, Fingerprint: before.AuthorityKMSBinding.Fingerprint, BindingVersion: before.AuthorityKMSBinding.BindingSerial, IdentityPlan: contract.DigestLength{Digest: plan.Digest, Length: plan.Length}, HeadCore: contract.Hash(coreBytes), HeadCoreLength: uint32(len(coreBytes)), ConditionalPlan: contract.Hash(conditional), BeforeAccessRoot: intent.BeforeAccessRoot, AfterAccessRoot: id("after access"), Normal: contract.NormalSection{Intent: contract.DigestLength{Digest: intentDescriptor.Digest, Length: intentDescriptor.Length}, PublicState: contract.DigestLength{Digest: public.Digest, Length: public.Length}, Union: union}, Grant: contract.GrantSection{Grants: grant}, Exclusion: contract.ExclusionSection{Exclusions: exclusion, Retirements: retirement}}
		// The lifecycle signature must bind the exact public request tuple.
		head.Subject.Request, err = contract.RequestDigest(contract.RequestCore{
			RequestCoreFields: contract.RequestCoreFields{
				Domain: head.Core.Domain, Store: head.Core.Store, Trust: head.Core.Trust,
				Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody, Interpretation: head.Core.Interpretation,
				Epoch: head.Core.Epoch, PreviousRevision: head.Core.PreviousRevision, PreviousDigest: head.Core.PreviousDigest,
				Intent: head.Subject.Normal.Intent, IdentityPlan: head.Subject.IdentityPlan,
			},
			PreviousToken: head.Core.PreviousToken,
		})
		if err != nil {
			t.Fatal("fixture public Recipient request", err)
		}
		q, err = contract.NewLifecycleRequest(head.Subject)
		if err != nil {
			t.Fatal(err)
		}
		head.AuthorizationSignature = sign(normal, q)
	}
	candidate, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	outputBasis := m.Basis
	if target != configuration.ReplaceRecipient {
		body, err := contract.EncodeControlCore(after)
		if err != nil {
			t.Fatal(err)
		}
		outputBasis = configuration.Basis{Control: body, Selection: candidate}
		descriptor, err := contract.DecodeGenesisDescriptorCore(m.Basis.Descriptor)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range descriptor.Recipients {
			outputBasis.Enrollment = append(outputBasis.Enrollment, configuration.Enrollment{ID: row.RecipientID, Status: row.Status, DisplayName: row.DisplayName})
		}
	}
	path := filepath.Join(t.TempDir(), "successor.json")
	output, err := configuration.PrepareSuccessorOutput(ctx, source.pair, path, request)
	if err != nil {
		t.Fatal(err)
	}
	readback, err := output.Publish(ctx, configuration.SuccessorMaterial{Control: after, Recipients: rows, Basis: outputBasis, RequestIdentity: identity, SignedCandidate: candidate})
	if err != nil || readback == nil {
		t.Fatal("local successor publication", err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Dir(source.path), filepath.Dir(source.generated), filepath.Dir(path), filepath.Join(filepath.Dir(path), ".enkv")} {
		if err := os.Chmod(directory, 0555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(directory, 0700); err != nil {
				t.Error(err)
			}
		})
	}
	recaptureSource()
	reader := &replacementFailureReader{descriptor: store, location: contract.StoreConfiguration{Provider: m.Provider, ConstructionProfile: contract.StoreConstructionProfile, DomainID: m.DomainID, Region: m.Store.Region, Bucket: m.Store.Bucket, PrefixBeforeHEAD: m.Store.PrefixBeforeHEAD, ExpectedOwner: m.Store.ExpectedOwner}}
	return source, path, request, reader
}

// full_only: false
func TestReplacementObservationConstructionPreservesUnavailableAndCauses(t *testing.T) {
	for _, target := range []configuration.ReplacementTarget{configuration.ReplaceAuthority, configuration.ReplaceRecovery, configuration.ReplaceRecipient} {
		t.Run(string(target), func(t *testing.T) {
			for _, mode := range []string{"nil-error", "nil-no-error", "partial-error", "close-failure"} {
				t.Run(mode, func(t *testing.T) {
					source, path, request, reader := replacementFailurePair(t, target)
					before := configurationApplySourceImage(t, filepath.Dir(path))
					sourceBefore := configurationApplySourceImage(t, filepath.Dir(source.path))
					primary := errors.New("private-provider-sentinel")
					cleanup := errors.New("private-cleanup-sentinel")
					calls, closes := 0, 0
					result := replaceKeysConfiguration(replacementFailureContext(t), contract.ID{11}, source.path, configuration.JSON, request, path, func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error) {
						calls++
						close := func() error {
							closes++
							if mode == "close-failure" {
								return cleanup
							}
							return nil
						}
						if mode == "partial-error" {
							return reader, close, primary
						}
						if mode == "nil-no-error" {
							return nil, close, nil
						}
						return nil, close, primary
					})
					if calls != 1 || closes != 1 || reader.reads != 0 || reader.closed != map[bool]int{true: 1, false: 0}[mode == "partial-error"] {
						t.Fatal("reader construction lifetime or effects changed", calls, closes, reader.reads, reader.closed)
					}
					capture, captureErr := configuration.PrepareSuccessorOutput(replacementFailureContext(t), source.pair, path, request)
					if captureErr != nil {
						t.Fatal(captureErr)
					}
					causeCalls, causeCloses := 0, 0
					causeReader := &replacementFailureReader{}
					_, causeErr := observeReplacementConfiguration(replacementFailureContext(t), contract.ID{21}, source.pair, capture, func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error) {
						causeCalls++
						close := func() error {
							causeCloses++
							if mode == "close-failure" {
								return cleanup
							}
							return nil
						}
						if mode == "partial-error" {
							return causeReader, close, primary
						}
						if mode == "nil-no-error" {
							return nil, close, nil
						}
						return nil, close, primary
					})
					if err := capture.Close(); err != nil {
						t.Fatal(err)
					}
					if causeCalls != 1 || causeCloses != 1 || causeReader.reads != 0 || causeReader.closed != map[bool]int{true: 1, false: 0}[mode == "partial-error"] || causeErr == nil || mode != "nil-no-error" && !errors.Is(causeErr, primary) || errors.Is(causeErr, cleanup) != (mode == "close-failure") {
						t.Error("existing observation API lost exact cause or cleanup lifetime")
					}
					read := result.Observation
					if read == nil {
						t.Fatal("existing output entered fresh mutation")
					}
					fixed, _ := replacementCommandTarget(target)
					if read.Target != fixed || read.Result.Outcome != core.EvidenceUnavailable || read.Result.Reason != core.ReadUnavailable || read.Result.Evidence != core.NoEvidence || read.Query != nil || read.Selection != nil || read.Receipt != nil || read.PreAdmission == nil || read.PreAdmission.Stage != "construction" || read.PreAdmission.Code != string(contract.ReasonEvidenceUnavailable) || !read.RequestIdentity.IsZero() || read.OperationID.IsZero() || read.RequestID != (contract.ID{11}) || read.PreAdmission.RequestNonce != (contract.ID{11}) || read.Result.CommitMayHaveOccurred {
						t.Error("construction failure changed unavailable pre-admission tuple")
					}
					if result.Delivery.Status != "existing" || result.Delivery.Path != path || result.Delivery.Failed || result.Delivery.CleanupFailed != (mode == "close-failure") {
						t.Error("operation unavailable was confused with local delivery or cleanup")
					}
					operation := "keys-replace-receipt"
					kind := uint16(contract.OperationReplaceRecoveryKeysAndRoot)
					if target == configuration.ReplaceAuthority {
						operation = "keys-replace-observe"
						kind = contract.OperationReplaceAuthorityKeys
					}
					if target == configuration.ReplaceRecipient {
						kind = contract.OperationRotateRecipientKeyBinding
					}
					if read.UnderlyingOperation != kind {
						t.Error("protected target changed receipt kind")
					}
					exit := 3
					if mode == "close-failure" {
						exit = 2
					}
					replacementFailureRender(t, result, operation, "unavailable", exit)
					source.assertUnchanged(t)
					configurationApplyAssertUnchanged(t, filepath.Dir(source.path), sourceBefore)
					configurationApplyAssertUnchanged(t, filepath.Dir(path), before)
				})
			}
		})
	}
}

// full_only: false
func TestReplacementObservationUnavailableHEADKeepsQuery(t *testing.T) {
	for _, target := range []configuration.ReplacementTarget{configuration.ReplaceAuthority, configuration.ReplaceRecovery, configuration.ReplaceRecipient} {
		t.Run(string(target), func(t *testing.T) {
			for _, mode := range []string{"close-ok", "close-failure"} {
				t.Run(mode, func(t *testing.T) {
					source, path, request, reader := replacementFailurePair(t, target)
					image := configurationApplySourceImage(t, filepath.Dir(path))
					sourceImage := configurationApplySourceImage(t, filepath.Dir(source.path))
					closes := 0
					cleanup := errors.New("private-cleanup-sentinel")
					result := replaceKeysConfiguration(replacementFailureContext(t), contract.ID{12}, source.path, configuration.JSON, request, path, func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error) {
						return reader, func() error {
							closes++
							if mode == "close-failure" {
								return cleanup
							}
							return nil
						}, nil
					})
					if actual := result.Observation; actual != nil {
						t.Logf("HEAD wrapper control: reads=%d reader_closes=%d provider_closes=%d query=%t query_valid=%t pre_admission=%t state=%s outcome=%d reason=%d evidence=%d store_reason=%d delivery_failed=%t cleanup_failed=%t", reader.reads, reader.closed, closes, actual.Query != nil, actual.Query != nil && actual.Query.Valid(), actual.PreAdmission != nil, actual.StateResult, actual.Result.Outcome, actual.Result.Reason, actual.Result.Evidence, actual.Result.StoreReason, result.Delivery.Failed, result.Delivery.CleanupFailed)
					} else {
						t.Logf("HEAD wrapper control: reads=%d reader_closes=%d provider_closes=%d observation=false delivery_failed=%t cleanup_failed=%t", reader.reads, reader.closed, closes, result.Delivery.Failed, result.Delivery.CleanupFailed)
					}
					if reader.reads != 1 || reader.closed != 1 || closes != 1 || result.Delivery.Failed || result.Delivery.CleanupFailed != (mode == "close-failure") {
						t.Error("unavailable HEAD did not join exact read/cleanup ownership")
					}
					read := result.Observation
					if read == nil || read.PreAdmission != nil || read.Query == nil || !read.Query.Valid() || read.Query.Observation != nil || read.Result.Outcome != core.EvidenceUnavailable || read.Result.Evidence != core.NoEvidence || read.Selection != nil || read.Receipt != nil {
						t.Fatal("unavailable HEAD lost exact absent-observation query")
					}
					exit := 3
					if mode == "close-failure" {
						exit = 2
					}
					if got := ReplacementCommandExitCode(result); got != exit {
						t.Errorf("unavailable HEAD exit=%d want=%d", got, exit)
					}
					for _, write := range []func(context.Context, io.Writer, ReplacementCommandResult) error{WriteReplacementJSON, WriteReplacementHuman} {
						var out bytes.Buffer
						if err := write(context.Background(), &out, result); err != nil {
							t.Error("unavailable HEAD result rejected", err)
						}
					}
					capture, err := configuration.PrepareSuccessorOutput(replacementFailureContext(t), source.pair, path, request)
					if err != nil {
						t.Fatal(err)
					}
					causeReader := &replacementFailureReader{descriptor: reader.descriptor, location: reader.location}
					causeCloses := 0
					causeResult, causeErr := observeReplacementConfiguration(replacementFailureContext(t), contract.ID{22}, source.pair, capture, func(context.Context, *configuration.Model) (core.PublicSelectedReader, func() error, error) {
						return causeReader, func() error {
							causeCloses++
							if mode == "close-failure" {
								return cleanup
							}
							return nil
						}, nil
					})
					if err := capture.Close(); err != nil {
						t.Fatal(err)
					}
					t.Logf("HEAD direct observer control: reads=%d reader_closes=%d provider_closes=%d query=%t query_valid=%t pre_admission=%t state=%s outcome=%d reason=%d evidence=%d store_reason=%d error_present=%t cleanup_cause=%t", causeReader.reads, causeReader.closed, causeCloses, causeResult.Query != nil, causeResult.Query != nil && causeResult.Query.Valid(), causeResult.PreAdmission != nil, causeResult.StateResult, causeResult.Result.Outcome, causeResult.Result.Reason, causeResult.Result.Evidence, causeResult.Result.StoreReason, causeErr != nil, errors.Is(causeErr, cleanup))
					if causeReader.reads != 1 || causeReader.closed != 1 || causeCloses != 1 || errors.Is(causeErr, cleanup) != (mode == "close-failure") || mode == "close-ok" && causeErr != nil || causeResult.Query == nil || !causeResult.Query.Valid() || causeResult.Result.Outcome != core.EvidenceUnavailable {
						t.Fatal("cleanup-only public observation error lost cause or query")
					}
					source.assertUnchanged(t)
					configurationApplyAssertUnchanged(t, filepath.Dir(source.path), sourceImage)
					configurationApplyAssertUnchanged(t, filepath.Dir(path), image)
				})
			}
		})
	}
}

// full_only: false
func TestReplacementUnavailablePreAdmissionRejectsTransplants(t *testing.T) {
	for _, damage := range []string{"outcome", "reason", "evidence", "stage", "code", "query", "selection", "receipt", "mutation-identity", "observed", "requested", "snapshot", "store-reason", "warnings"} {
		t.Run(damage, func(t *testing.T) {
			read, err := NewReplacementObservationRefusal(core.ReplacementTargetAuthority, contract.ID{13}, configuration.JSON)
			if err != nil {
				t.Fatal(err)
			}
			read.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
			read.StateResult = contract.ReaderUnavailable
			read.PreAdmission.Stage = "construction"
			read.PreAdmission.Code = string(contract.ReasonEvidenceUnavailable)
			switch damage {
			case "outcome":
				read.Result.Outcome = core.ObservedCurrent
			case "reason":
				read.Result.Reason = core.InvalidProof
			case "evidence":
				read.Result.Evidence = core.AuthenticatedClosure
			case "stage":
				read.PreAdmission.Stage = "source"
			case "code":
				read.PreAdmission.Code = string(contract.ReasonInvalidInput)
			case "query":
				read.Query = &core.ReplacementQueryIdentity{}
			case "selection":
				read.Selection = &core.ReplacementCurrentSelection{}
			case "receipt":
				read.Receipt = &core.ReplacementReceiptObservation{}
			case "mutation-identity":
				read.RequestIdentity = contract.ID{14}
			case "observed":
				read.Result.ObservedRevision = contract.ID{15}
			case "requested":
				read.Result.RequestedRevision = contract.ID{16}
			case "snapshot":
				read.Result.ObservedSnapshotID = contract.ID{17}
			case "store-reason":
				read.Result.StoreReason = contract.ReasonAccess
			case "warnings":
				read.CurrentWarningBits = 1
			}
			result := ReplacementCommandResult{Observation: &read, Delivery: ReplacementCommandDelivery{Status: "existing", Path: "/successor.json"}}
			for _, write := range []func(context.Context, io.Writer, ReplacementCommandResult) error{WriteReplacementJSON, WriteReplacementHuman} {
				var out bytes.Buffer
				if err := write(context.Background(), &out, result); err == nil || out.Len() != 0 {
					t.Fatal("malformed unavailable pre-admission emitted output", damage)
				}
			}
		})
	}
}
