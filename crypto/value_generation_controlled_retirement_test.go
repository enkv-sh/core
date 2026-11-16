package crypto

import (
	"context"
	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	wire "enkv.sh/sdk/protocols/generator"
	"os"
	"testing"
)

type controlledRefusedLauncher struct{ implementation, start int }

func (l *controlledRefusedLauncher) Implementation() contract.GeneratorImplementation {
	l.implementation++
	return contract.GeneratorImplementation{}
}
func (l *controlledRefusedLauncher) Start(context.Context, wire.Command, *os.File) (generatorhost.Run, error) {
	l.start++
	return nil, ErrAdmission
}

// full_only: false
func TestGeneratedControlledRetirementNativeStrongerAdmissionRefusesBeforeLaunch(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		f := generatedSelectDeleteProducer(t, generatedDeleteProducerFixture(t, recovery), contract.GeneratedDutyRetirement)
		g, err := contract.DecodeGeneratorPlanBundle(f.graph)
		if err != nil {
			t.Fatal(err)
		}
		g.Lineages[0].Templates[0].CompletionClass = contract.GeneratedCompletionConfirmed
		p := f.producer.Producer
		p.Expected.Template = g.Lineages[0].Templates[0]
		p.Duty.CompletionClass = contract.GeneratedCompletionConfirmed
		p.Attempt.CompletionClass = contract.GeneratedCompletionConfirmed
		p.Attempt.TemplateDigest, err = contract.GeneratorTemplateID(p.Expected.Template)
		if err != nil {
			t.Fatal(err)
		}
		target := *f.producer.Target
		target.CompletionClass = contract.GeneratedCompletionConfirmed
		body, err := contract.EncodeGeneratorTarget(target)
		if err != nil {
			t.Fatal(err)
		}
		p.Duty.Target, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{body})
		if err != nil {
			t.Fatal(err)
		}
		state := &generatedProducerPreparationState{target: &target, phase: f.producer.Phase}
		a := generatedAdmission{graph: g, material: f.producer.Material, request: f.compare,
			purpose: generatedPurposeState{producer: state}}
		a.access, err = contract.DecodeAccessRecord(f.producer.SeedAccess)
		if err != nil {
			t.Fatal(err)
		}
		state.phase = &contract.GeneratorPhaseIdentity{RequestIdentityDigest: f.compare.Parent.RequestIdentityDigest, TransitionKind: contract.GeneratorAuthorityRetireReserve}
		if a.admitProducer(&p) {
			t.Fatal("stronger producer admitted without private selected predecessor")
		}
		// This direct producer-unit check starts after predecessor admission.
		// Complete selected-view admission is covered by the shared chain tests.
		dutyBody, err := contract.EncodeGeneratedDutyRecord(p.Duty)
		if err != nil {
			t.Fatal(err)
		}
		source, err := contract.InspectGeneratedDeleteSource(contract.SupportRecord{Kind: 10, RecordID: p.Duty.DutyID, Body: dutyBody})
		if err != nil {
			t.Fatal(err)
		}
		state.plan.controlledPredecessor = &generatedControlledPredecessor{source: source}
		if !a.admitProducer(&p) {
			t.Fatal("valid private stronger first-step return refused")
		}

		initialPredecessor := state.plan.controlledPredecessor
		probe := p
		progress, err := contract.EncodeGeneratorProgress(contract.GeneratorProgress{Schema: 1,
			AttemptID: consumerID("preceding probe ACK attempt"), ResultID: consumerID("preceding probe ACK result"),
			Evidence:      contract.GeneratorDescriptor{Digest: consumerID("preceding probe ACK body"), Length: contract.GeneratedResultCoreLength, Count: 1},
			RequiredSteps: contract.GeneratorConfirmedRequiredSteps, CompletedSteps: contract.GeneratorProgressAcknowledged, CompletionClass: contract.GeneratedCompletionConfirmed})
		if err != nil {
			t.Fatal(err)
		}
		probe.Progress = [][]byte{progress}
		descriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorProgress, probe.Progress)
		if err != nil {
			t.Fatal(err)
		}
		probe.Duty.Progress, probe.Attempt.Progress, probe.Duty.Step = descriptor, descriptor, 2
		ack, err := contract.InspectGeneratorProgress(progress)
		if err != nil {
			t.Fatal(err)
		}
		probe.Expected.RequestDigest = contract.GeneratorControlledRetirementProbeDigest(g.Header.DomainID, target.ResourceID, target.ResourceDigest,
			contract.GeneratorControlledRetirementScope(probe.Expected.Template.DescriptorID, probe.Expected.Template.ConfigContractID, probe.Expected.Template.ResultContractID), ack.ResultID, ack.Evidence.Digest)
		probe.Preparation.RequestDigest, probe.Attempt.RequestDigest = probe.Expected.RequestDigest, probe.Expected.RequestDigest
		probe.Return = nil
		probeCalls := 0
		probe.Probe = func(context.Context, contract.GeneratedProducerCommand) []byte { probeCalls++; return nil }
		dutyBody, err = contract.EncodeGeneratedDutyRecord(probe.Duty)
		if err != nil {
			t.Fatal(err)
		}
		source, err = contract.InspectGeneratedDeleteSource(contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: probe.Duty.DutyID, Body: dutyBody})
		if err != nil {
			t.Fatal(err)
		}
		state.plan.controlledPredecessor = &generatedControlledPredecessor{source: source, progress: probe.Progress}
		if !a.admitProducer(&probe) {
			t.Fatal("valid private controlled Probe refused")
		}
		probe.Expected.InputEncoding = contract.InputEncodingBase64
		if a.admitProducer(&probe) || probeCalls != 0 {
			t.Fatal("Delete Probe accepted non-raw result classification or entered before admission")
		}
		state.plan.controlledPredecessor = initialPredecessor
		launcher := &controlledRefusedLauncher{}
		p.Return = nil
		p.Process = launcher
		if a.admitProducer(&p) || launcher.implementation != 0 || launcher.start != 0 {
			t.Fatal("native stronger obligation reached process", launcher)
		}
	}
}
