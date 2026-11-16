package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/outputhost"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// The test runner binds exact local fixture members into the test executable.
var publicationFixtureExpectations string

const publicationTestConfigContract = "test-output/config/v1"

func publicationCustodyPrivate(keys *custody.Fixture) publicationPrivate {
	return publicationPrivate{
		SelectPolicyAction: func(ctx context.Context, in publicationPolicyActionInput) (uint8, error) {
			return keys.SelectPublicationPolicyAction(ctx, in.DestinationID, in.ConfigContractID, in.DomainID, in.Target, in.HasPreviousPolicyDigest, in.PreviousPolicyDigest, in.Deadline)
		},
		Actions: func(ctx context.Context, in publicationExecutionInput) (publicationActionFacts, error) {
			a, err := keys.PublicationArtifact(ctx, in.DestinationID, in.ConfigContractID)
			digest, digestErr := contract.OutputConfigContractDigest(in.ConfigContractID)
			return publicationActionFacts{ProtocolID: contract.ID(a.ProtocolID), DescriptorID: contract.ID(a.DescriptorID), ConfigContractDigest: digest, ArtifactContractID: contract.ID(a.ArtifactContractID), ExecutorID: contract.ID(a.ExecutorID), CredentialRouteID: contract.ID(a.CredentialRouteID), CredentialRouteContractID: a.CredentialRouteContractID}, errors.Join(err, digestErr)
		},
		Check: func(ctx context.Context, in publicationActionCheckInput) (publicationActionCheckFacts, error) {
			f, a, err := keys.CheckPublication(ctx, in.DestinationID, in.ConfigContractID, in.DomainID, in.Action, in.Target, in.Coordinate, in.Birth, in.UncertainCreate, in.ExclusiveNamespaceDigest, in.PayloadLength, in.Deadline)
			digest, digestErr := contract.OutputConfigContractDigest(in.ConfigContractID)
			return publicationActionCheckFacts{MinimumPayload: f.PayloadBounds.Minimum, MaximumPayload: f.PayloadBounds.Maximum, ProtocolID: contract.ID(a.ProtocolID), DescriptorID: contract.ID(a.DescriptorID), ConfigContractDigest: digest, ArtifactContractID: contract.ID(a.ArtifactContractID), ExecutorID: contract.ID(a.ExecutorID), CredentialRouteID: contract.ID(a.CredentialRouteID), CredentialRouteContractID: a.CredentialRouteContractID}, errors.Join(err, digestErr)
		},
		NewOwner: func(ctx context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
			p := in.ActionCheck
			return keys.NewPublicationOwner(ctx, in.Projection, in.DestinationID, in.ConfigContractID, in.Target, in.Coordinate, in.Birth, in.UncertainCreate, p.ProtocolID, p.DescriptorID, p.ConfigContractDigest, p.ArtifactContractID, p.ExecutorID, p.CredentialRouteID, p.CredentialRouteContractID, p.MinimumPayload, p.MaximumPayload, in.Deadline)
		},
	}
}

func installedPublicationTestConfig(t testing.TB) custody.PublicationConfig {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("assembly executable unavailable", err)
	}
	original := filepath.Join(filepath.Dir(executable), "enkv-output-contract-test")
	config, err := installedPublicationFixtureConfig(original)
	if err != nil {
		t.Fatal("installed output expectation unavailable", err)
	}
	artifact := config.Artifact
	directory := t.TempDir()
	source, err := os.Open(filepath.Join(filepath.Dir(executable), "enkv-output-contract-test"))
	if err != nil {
		t.Fatal("installed output binary unavailable", err)
	}
	path := filepath.Join(directory, "enkv-output-contract-test")
	target, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		t.Fatal(errors.Join(err, source.Close()))
	}
	written, copyErr := io.Copy(target, source)
	if err := errors.Join(copyErr, target.Close(), source.Close()); err != nil || uint64(written) != artifact.Length {
		t.Fatalf("installed output copy bytes=%d err=%v", written, err)
	}
	staging := t.TempDir()
	t.Setenv("TMPDIR", staging)
	t.Cleanup(func() {
		roots, err := os.ReadDir(staging)
		if err != nil {
			t.Error("private staging cleanup unavailable", err)
			return
		}
		for _, root := range roots {
			if !root.IsDir() || !strings.HasPrefix(root.Name(), ".enkv-output-stage-") {
				continue
			}
			path := filepath.Join(staging, root.Name())
			if err := os.Chmod(path, 0700); err != nil {
				t.Error("restore owned staging root", err)
				continue
			}
			if err := os.RemoveAll(path); err != nil {
				t.Error("remove owned staging root", err)
			}
		}
	})
	config.ArtifactPath = path
	t.Setenv("ENKV_OUTPUT_TEST_CREDENTIAL", "private credential")
	return config
}

func publicationTestChildEntered(staging string) (bool, error) {
	roots, err := os.ReadDir(staging)
	if err != nil {
		return false, err
	}
	for _, root := range roots {
		if !root.IsDir() || !strings.HasPrefix(root.Name(), ".enkv-output-stage-") {
			continue
		}
		directory := filepath.Join(staging, root.Name())
		launches, err := os.ReadDir(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		for _, launch := range launches {
			if !launch.IsDir() || !strings.HasPrefix(launch.Name(), ".launch-") {
				continue
			}
			if _, err := os.Stat(filepath.Join(directory, launch.Name(), ".entered-execute")); err == nil {
				return true, nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return false, err
			}
		}
	}
	return false, nil
}

func installedPublicationFixtureConfig(path string) (custody.PublicationConfig, error) {
	if len(publicationFixtureExpectations) == 0 || len(publicationFixtureExpectations) > 4096 {
		return custody.PublicationConfig{}, outputhost.ErrAdmission
	}
	var expected map[string][2]string
	if err := json.Unmarshal([]byte(publicationFixtureExpectations), &expected); err != nil || len(expected) == 0 || len(expected) > 5 {
		return custody.PublicationConfig{}, outputhost.ErrAdmission
	}
	want, ok := expected[filepath.Base(path)]
	if !ok {
		return custody.PublicationConfig{}, outputhost.ErrAdmission
	}
	hash := func(body []byte) string { digest := sha256.Sum256(body); return hex.EncodeToString(digest[:]) }
	body, err := os.ReadFile(path + ".installation.json")
	if err != nil {
		return custody.PublicationConfig{}, err
	}
	if hash(body) != want[0] {
		return custody.PublicationConfig{}, outputhost.ErrAdmission
	}
	var expectation struct {
		Artifact outputhost.Artifact `json:"artifact"`
		Metadata json.RawMessage     `json:"metadata,omitempty"`
	}
	if err := json.Unmarshal(body, &expectation); err != nil {
		return custody.PublicationConfig{}, err
	}
	if len(expectation.Metadata) == 0 {
		return custody.PublicationConfig{}, outputhost.ErrAdmission
	}
	dependency, err := os.ReadFile(path + ".dependency")
	if err != nil {
		return custody.PublicationConfig{}, err
	}
	if hash(dependency) != want[1] {
		return custody.PublicationConfig{}, outputhost.ErrAdmission
	}
	return custody.PublicationConfig{ArtifactPath: path, Artifact: expectation.Artifact, Metadata: expectation.Metadata, Dependency: dependency}, nil
}

type publicationControlledOwner struct {
	input                          publicationOwnerInput
	id                             contract.ID
	prepared, armed, sent, retired int
	dispatch                       contract.PublicationDispatch
	onSend                         func()
	onArm                          func()
	onRetire                       func()
	retireError                    error
	evidence                       uint8
	resource                       string
	consumerLocator                string
	corrupt                        bool
}

func (o *publicationControlledOwner) InstanceID() contract.ID { return o.id }
func (o *publicationControlledOwner) Prepare(_ context.Context, _ contract.ID, selection *contract.ConsumerSelection) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	o.prepared++
	value := o.input.Projection.Action == contract.PublicationCreateWithValue || o.input.Projection.Action == contract.PublicationWriteValue
	if value != (selection != nil) {
		return nil, contract.CryptoInvalidAdmission
	}
	if selection != nil && selection.Entry.ConfidentialityClass == contract.Secret {
		binding := selection.Binding
		digest, err := contract.PublicBindingDigest(binding.Binding)
		if err != nil {
			return nil, contract.CryptoInvalidAdmission
		}
		return []contract.KeyUseRow{{BindingID: binding.Binding.BindingID, PublicBindingDigest: digest,
			SubjectKind: binding.SubjectKind, SubjectID: binding.SubjectID, Provider: binding.Binding.Provider,
			Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 1}}, contract.CryptoSuccess
	}
	return nil, contract.CryptoSuccess
}
func (o *publicationControlledOwner) Arm(_ context.Context, _ contract.ID, d contract.PublicationDispatch) error {
	if o.armed != 0 || o.retired != 0 || d.Projection != o.input.Projection {
		return errors.New("invalid one-use arm")
	}
	o.armed++
	o.dispatch = d
	if o.onArm != nil {
		o.onArm()
	}
	return nil
}
func (o *publicationControlledOwner) Send(ctx context.Context, _ contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	if ctx.Err() != nil || o.armed != 1 || o.sent != 0 || o.retired != 0 {
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	o.sent++
	if o.onSend != nil {
		o.onSend()
	}
	digest, err := contract.PublicationDispatchContextDigest(o.dispatch)
	if err != nil {
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	class := o.evidence
	status := uint16(201)
	resource := "exact-created-instance"
	if o.resource != "" {
		resource = o.resource
	}
	if class != contract.PublicationRequestAcknowledged {
		status = 0
		resource = ""
	}
	r := contract.PublicationResult{Schema: 2, DomainID: o.dispatch.DomainID, OperationID: o.dispatch.OperationID, AttemptID: o.dispatch.AttemptID, CoordinateID: o.dispatch.CoordinateID, ProjectionCommitment: o.dispatch.ProjectionCommitment, DispatchContextDigest: digest, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: class, ResponseContractDigest: o.dispatch.ResponseContractDigest, NormalizedStatus: status, SafeResourceID: resource}}
	if class == contract.PublicationRequestAcknowledged && (o.dispatch.Projection.Action == contract.PublicationCreateEmpty || o.dispatch.Projection.Action == contract.PublicationCreateWithValue) {
		r.Evidence.ConsumerLocator = o.input.Target.ConsumerLocator
		if o.input.Target.LocatorRequiresCreation {
			r.Evidence.ConsumerLocator = o.consumerLocator
		}
	}
	if o.corrupt {
		r.AttemptID[0] ^= 1
	}
	return r, contract.CryptoSuccess
}
func (o *publicationControlledOwner) Retire(context.Context) error {
	o.retired++
	if o.onRetire != nil {
		o.onRetire()
	}
	return o.retireError
}

type publicationControlledPrivate struct {
	selectPolicyAction publicationPolicyActionSelector
	owners             []*publicationControlledOwner
	facts              publicationActionFacts
	onSend             func()
	evidence           uint8
	corrupt            bool
	checks             int
	configureOwner     func(*publicationControlledOwner)
}

func (p *publicationControlledPrivate) callbacks() publicationPrivate {
	return publicationPrivate{
		SelectPolicyAction: func(ctx context.Context, in publicationPolicyActionInput) (uint8, error) {
			if p.selectPolicyAction != nil {
				return p.selectPolicyAction(ctx, in)
			}
			return contract.PublicationUpdatePolicy, nil
		},
		Actions: func(_ context.Context, in publicationExecutionInput) (publicationActionFacts, error) {
			facts := p.facts
			digest, err := contract.OutputConfigContractDigest(in.ConfigContractID)
			facts.ConfigContractDigest = digest
			return facts, err
		},
		Check: func(_ context.Context, in publicationActionCheckInput) (publicationActionCheckFacts, error) {
			p.checks++
			minimum, maximum := uint32(0), uint32(0)
			if in.Action == contract.PublicationCreateWithValue || in.Action == contract.PublicationWriteValue {
				bounds := in.Target.CreateValueBounds
				if in.Action == contract.PublicationWriteValue {
					bounds = in.Target.WriteValueBounds
				}
				minimum, maximum = bounds.Minimum, bounds.Maximum
			}
			digest, err := contract.OutputConfigContractDigest(in.ConfigContractID)
			if err != nil {
				return publicationActionCheckFacts{}, err
			}
			return publicationActionCheckFacts{MinimumPayload: minimum, MaximumPayload: maximum, ProtocolID: p.facts.ProtocolID, DescriptorID: p.facts.DescriptorID, ConfigContractDigest: digest, ArtifactContractID: p.facts.ArtifactContractID, ExecutorID: p.facts.ExecutorID, CredentialRouteID: p.facts.CredentialRouteID, CredentialRouteContractID: p.facts.CredentialRouteContractID}, nil
		},
		NewOwner: func(_ context.Context, in publicationOwnerInput) (publicationPrivateOwner, error) {
			o := &publicationControlledOwner{input: in, id: contract.Hash([]byte(time.Now().String())), onSend: p.onSend, evidence: p.evidence, corrupt: p.corrupt}
			if p.configureOwner != nil {
				p.configureOwner(o)
			}
			p.owners = append(p.owners, o)
			return o, nil
		},
	}
}

func publicationEngineFixture(t *testing.T, existing ...*fixture) (*fixture, publicationInput, *publicationControlledPrivate) {
	t.Helper()
	var f *fixture
	if len(existing) == 0 {
		f = newFixture(t, 1, false, 1)
	} else {
		f = existing[0]
	}
	entries := f.session.currentEntryInputs()
	target := publicationEngineTarget(entries[0].Name, "publication")
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}}}
	selectOutputConfiguration(t, f, entries, output)
	f.admission.admission.publicationNamespaces = []publicationNamespace{{domain: f.session.root.Domain, service: "controlled-provider", physical: "publication", premise: contract.Hash([]byte("independently qualified namespace"))}}
	f.session.admission.publicationNamespaces = f.admission.admission.publicationNamespaces
	input := publicationInput{names: []string{entries[0].Name}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	private := newPublicationControlledPrivate()
	return f, input, private
}
func newPublicationControlledPrivate() *publicationControlledPrivate {
	return &publicationControlledPrivate{facts: publicationActionFacts{ProtocolID: contract.Hash([]byte("ENKV/OUTPUT-WIRE/v6\x00")), DescriptorID: publicationRelationID(91), ArtifactContractID: publicationRelationID(92), ExecutorID: publicationRelationID(93), CredentialRouteID: publicationRelationID(94), CredentialRouteContractID: "fixture/route/v1"}, evidence: contract.PublicationRequestAcknowledged}
}

func publicationEngineTarget(name, slot string) outputApplyTarget {
	return outputApplyTarget{entryName: name, target: outputFixtureTarget("controlled-provider", slot, slot+"?stage=AWSCURRENT", contract.OutputEncodingRaw, 255, contract.OutputPolicy{ContractID: "controlled-policy", Data: []byte("none")})}
}
