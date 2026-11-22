package custody

import (
	"context"
	"sync"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	protocol "enkv.sh/sdk/protocols/generator"
	"os"
)

// InstalledGeneratedOwner delegates every admission and exchange to the
// production purpose constructor. The fixture contributes only its key routes
// and a native process configuration; it cannot provide a synthetic return.
type InstalledGeneratedOwner struct {
	owner   *privatecrypto.GeneratedCustody
	runtime *privatecrypto.Runtime
	once    sync.Once
}

func (o *InstalledGeneratedOwner) InstanceID() contract.ID { return o.owner.InstanceID() }
func (o *InstalledGeneratedOwner) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	return o.owner.Exchange(ctx, q)
}
func (o *InstalledGeneratedOwner) BindCandidate(ctx context.Context, input contract.GeneratedCandidateInput) contract.CryptoResultCode {
	return o.owner.BindCandidate(ctx, input)
}
func (o *InstalledGeneratedOwner) InvokeProducer(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
	return o.owner.InvokeProducer(ctx, locator, authority)
}

func (o *InstalledGeneratedOwner) RefuseResultPipe(observe func()) {
	privatecrypto.TestRefuseGeneratedResultPipe(o.runtime, observe)
}

func (o *InstalledGeneratedOwner) Close() {
	if o != nil {
		o.once.Do(func() { o.owner.Close(); o.runtime.Close() })
	}
}

func (f *Fixture) installedGeneratedConstruction(control contract.ControlCore, session contract.GeneratedSessionInput, plan contract.GeneratedPlanInput, file contract.ID, purpose contract.CryptoGeneratedPurpose, selectsEntries bool) (privatecrypto.GeneratedCustodyConstruction, error) {
	out := privatecrypto.GeneratedCustodyConstruction{FileIdentity: file}
	f.mu.Lock()
	out.RouteID = f.routes[control.AuthorityKMSBinding.BindingID]
	f.mu.Unlock()
	if out.RouteID.IsZero() {
		return out, privatecrypto.ErrAdmission
	}
	if !purpose.QualifiesPendingRecipients(selectsEntries) || len(plan.RegistryImage) == 0 {
		return out, nil
	}
	image, err := contract.DecodeGeneratedRecipientRegistryImage(plan.RegistryImage)
	if err != nil {
		return out, err
	}
	rows := make([]contract.BindingTableRow, 0, len(image.Recipients)+1)
	for _, row := range image.Recipients {
		binding := row.Recipient.CurrentBinding
		for _, current := range session.CurrentRecipients {
			if current.RecipientID == row.Recipient.RecipientID {
				binding = current.CurrentBinding
				break
			}
		}
		if binding == nil {
			return out, privatecrypto.ErrAdmission
		}
		rows = append(rows, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: row.Recipient.RecipientID, Binding: *binding})
	}
	if control.Recovery != nil {
		rows = append(rows, contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS})
	}
	out.Public, err = f.applyPublicQualifiers(contract.CryptoCompareRequest{Recipients: image.Recipients, Bindings: rows}, session.CurrentRecipients)
	return out, err
}
func (f *Fixture) installedGeneratedOwner(construction privatecrypto.GeneratedCustodyConstruction, create func(*privatecrypto.Runtime) (*privatecrypto.GeneratedCustody, error)) (*InstalledGeneratedOwner, error) {
	runtime, err := f.runtime.Fork()
	if err != nil {
		return nil, err
	}
	owner, err := create(runtime)
	if err != nil {
		runtime.Close()
		return nil, err
	}
	return &InstalledGeneratedOwner{owner: owner, runtime: runtime}, nil
}
func (f *Fixture) NewInstalledGeneratedReservation(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedReservationInput, file contract.ID, deadline time.Time) (*InstalledGeneratedOwner, error) {
	construction, err := f.installedGeneratedConstruction(control, input.Session, input.Plan, file, q.Purpose, false)
	if err != nil {
		return nil, err
	}
	return f.installedGeneratedOwner(construction, func(runtime *privatecrypto.Runtime) (*privatecrypto.GeneratedCustody, error) {
		return privatecrypto.NewGeneratedReservationCustody(runtime, q, control, construction, input, deadline)
	})
}
func (f *Fixture) NewInstalledGeneratedAdoption(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedAdoptionInput, deadline time.Time) (*InstalledGeneratedOwner, error) {
	construction, err := f.installedGeneratedConstruction(control, input.Session, input.Plan, contract.ID{}, q.Purpose, false)
	if err != nil {
		return nil, err
	}
	return f.installedGeneratedOwner(construction, func(runtime *privatecrypto.Runtime) (*privatecrypto.GeneratedCustody, error) {
		return privatecrypto.NewGeneratedAdoptionCustody(runtime, q, control, construction, input, deadline)
	})
}
func (f *Fixture) NewInstalledGeneratedFinal(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedFinalInput, deadline time.Time) (*InstalledGeneratedOwner, error) {
	construction, err := f.installedGeneratedConstruction(control, input.Session, input.Plan, contract.ID{}, q.Purpose, len(input.EntryAdmissions) != 0)
	if err != nil {
		return nil, err
	}
	return f.installedGeneratedOwner(construction, func(runtime *privatecrypto.Runtime) (*privatecrypto.GeneratedCustody, error) {
		return privatecrypto.NewGeneratedFinalCustody(runtime, q, control, construction, input, deadline)
	})
}
func (f *Fixture) NewInstalledGeneratedProducer(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedProducerInput, config GeneratedProcessConfig, deadline time.Time, observeCompletion ...func(bool)) (*InstalledGeneratedOwner, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, privatecrypto.ErrAdmission
	}
	construction, err := f.installedGeneratedConstruction(control, input.Session, input.Plan, contract.ID{}, q.Purpose, false)
	if err != nil {
		return nil, err
	}
	hostConfig, err := generatedProcessHostConfig(config, input.Preparation)
	if err != nil {
		return nil, err
	}
	launcher, err := generatorhost.NewNative(ctx, hostConfig)
	if err != nil {
		return nil, err
	}
	var process generatorhost.Launcher = launcher
	if len(observeCompletion) != 0 && observeCompletion[0] != nil {
		process = observedInstalledGeneratedLauncher{Launcher: launcher, observe: observeCompletion[0]}
	}
	return f.installedGeneratedOwner(construction, func(runtime *privatecrypto.Runtime) (*privatecrypto.GeneratedCustody, error) {
		return privatecrypto.NewGeneratedProducerCustody(runtime, q, control, construction, input, process, deadline)
	})
}

// InstalledGeneratedLocalFailure retains only the original private state-bound
// admitter and the fixture's ordinary custody constructor.
type InstalledGeneratedLocalFailure struct {
	reason func() uint8
	admit  func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedLocalFailureInput, time.Time) (*InstalledGeneratedOwner, error)
}

func (o *InstalledGeneratedLocalFailure) Reason() uint8 {
	if o == nil || o.reason == nil {
		return 0
	}
	return o.reason()
}

func (o *InstalledGeneratedLocalFailure) Admit(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedLocalFailureInput, deadline time.Time) (*InstalledGeneratedOwner, error) {
	if o == nil || o.admit == nil {
		return nil, privatecrypto.ErrAdmission
	}
	return o.admit(ctx, q, control, input, deadline)
}

func (f *Fixture) InstalledGeneratedLocalFailure(original *InstalledGeneratedOwner) *InstalledGeneratedLocalFailure {
	reason, admit := original.owner.LocalFailureAdmission()
	if admit == nil {
		return nil
	}
	return &InstalledGeneratedLocalFailure{reason: reason, admit: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedLocalFailureInput, deadline time.Time) (*InstalledGeneratedOwner, error) {
		construction, err := f.installedGeneratedConstruction(control, input.Session, input.Plan, contract.ID{}, q.Purpose, false)
		if err != nil {
			return nil, err
		}
		return f.installedGeneratedOwner(construction, func(runtime *privatecrypto.Runtime) (*privatecrypto.GeneratedCustody, error) {
			return admit(ctx, runtime, q, control, construction, input, deadline)
		})
	}}
}

// The observer reports only proof qualification. It cannot issue proof or
// replace the real run's status, errors, ownership, or result stream.
type observedInstalledGeneratedLauncher struct {
	generatorhost.Launcher
	observe func(bool)
}

func (l observedInstalledGeneratedLauncher) Start(ctx context.Context, command protocol.Command, writer *os.File) (generatorhost.Run, error) {
	run, err := l.Launcher.Start(ctx, command, writer)
	if run == nil {
		return nil, err
	}
	return observedInstalledGeneratedRun{Run: run, command: command, observe: l.observe}, err
}

type observedInstalledGeneratedRun struct {
	generatorhost.Run
	command protocol.Command
	observe func(bool)
}

func (r observedInstalledGeneratedRun) Wait(ctx context.Context) (protocol.Status, error) {
	status, err := r.Run.Wait(ctx)
	r.observe(generatorhost.PreservesCompletion(r.command, r.CommandID(), status, err))
	return status, err
}
