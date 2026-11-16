package core

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

var errLivePublication = errors.New("live publication fixture refused")

// Native actions include prerequisite reads. Helper credential, consumer and
// cleanup requests reserve their own physical calls outside this allowance.
// AWS name-based actions include the exact credential-account qualification.
// Cloud consumer IAM is outside this action graph.
func livePublicationRequests(profile string, action uint8) (uint64, bool) {
	switch profile {
	case "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3":
		switch action {
		case contract.PublicationCreateEmpty, contract.PublicationDeleteReservedSlot:
			return 2, true
		case contract.PublicationWriteValue, contract.PublicationDeleteOwned:
			return 1, true
		}
	case "ENKV/OUTPUT/GCP-SECRET-MANAGER/v3":
		switch action {
		case contract.PublicationCreateEmpty, contract.PublicationWriteValue:
			return 2, true
		case contract.PublicationDeleteOwned, contract.PublicationDeleteReservedSlot:
			return 3, true
		}
	case "ENKV/OUTPUT/GITHUB-REPOSITORY/v3", "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3", "ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3":
		switch action {
		case contract.PublicationCreateWithValue, contract.PublicationWriteValue:
			return 2, true
		case contract.PublicationUpdatePolicy:
			return 2, profile == "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3"
		case contract.PublicationDeleteOwned, contract.PublicationDeleteReservedSlot:
			return 1, true
		}
	}
	return 0, false
}

type livePublicationObservation struct {
	Index    uint32
	Dispatch contract.PublicationDispatch
	Result   contract.PublicationResult
	Code     contract.CryptoResultCode
}

// The scenario executes actions in order. The mutex also protects observations
// from cancellation callbacks; it is never held while a private owner runs.
type livePublicationRecorder struct {
	scope         records.OutputFixtureScope
	inventoryPath string
	budget        *runBudget
	mu            sync.Mutex
	failure       error
	observations  []livePublicationObservation
	owners        uint64
	retired       uint64
}

func (r *livePublicationRecorder) fail(err error) {
	if err != nil {
		r.mu.Lock()
		r.failure = errors.Join(r.failure, err)
		r.mu.Unlock()
	}
}

func (r *livePublicationRecorder) state() (uint64, uint64, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.owners, r.retired, len(r.observations), r.failure
}

func (r *livePublicationRecorder) observe(owner publicationPrivateOwner, input publicationOwnerInput, index uint32) publicationPrivateOwner {
	r.mu.Lock()
	r.owners++
	r.mu.Unlock()
	return &livePublicationOwner{publicationPrivateOwner: owner, recorder: r, input: input, index: index}
}

type livePublicationOwner struct {
	publicationPrivateOwner
	recorder   *livePublicationRecorder
	input      publicationOwnerInput
	index      uint32
	mu         sync.Mutex
	armed      bool
	used       bool
	retiring   bool
	admission  contract.ID
	dispatch   contract.PublicationDispatch
	retireOnce sync.Once
	retireErr  error
}

func (o *livePublicationOwner) Arm(ctx context.Context, id contract.ID, dispatch contract.PublicationDispatch) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.armed || o.retiring || id.IsZero() || dispatch.Projection != o.input.Projection || hex.EncodeToString(dispatch.DomainID[:]) != o.recorder.scope.DomainID {
		return errLivePublication
	}
	if _, err := contract.EncodePublicationDispatch(dispatch); err != nil {
		return errLivePublication
	}
	if err := o.publicationPrivateOwner.Arm(ctx, id, dispatch); err != nil {
		return err
	}
	o.admission, o.dispatch, o.armed = id, dispatch, true
	return nil
}

func (o *livePublicationOwner) Send(ctx context.Context, id contract.ID) (contract.PublicationResult, contract.CryptoResultCode) {
	o.mu.Lock()
	if !o.armed || o.used || o.retiring || id != o.admission {
		o.mu.Unlock()
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	o.used = true
	dispatch := o.dispatch
	o.mu.Unlock()
	r := o.recorder
	inventory, err := records.ReadOutputFixtureInventory(r.inventoryPath, r.scope)
	if err != nil || uint64(o.index) >= uint64(len(inventory.Rows)) {
		r.fail(errLivePublication)
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	row := inventory.Rows[o.index]
	if row.PlannedSlot != o.input.Target.CanonicalTarget {
		r.fail(errLivePublication)
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	requests, supported := livePublicationRequests(row.ProfileID, dispatch.Projection.Action)
	if !supported || r.budget == nil || !r.budget.reserve(requests, operationBodyAllowance, "", 0) {
		r.fail(errRunLimit)
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	attempt := hex.EncodeToString(dispatch.AttemptID[:])
	if err := records.BeginOutputFixtureAction(r.inventoryPath, r.scope, o.index, attempt, dispatch.Projection.Action); err != nil {
		r.fail(errLivePublication)
		return contract.PublicationResult{}, contract.CryptoInvalidAdmission
	}
	result, code := o.publicationPrivateOwner.Send(ctx, id)
	outcome, instance := "unknown", ""
	if code == contract.CryptoSuccess && contract.ValidatePublicationResult(dispatch, result) == nil {
		switch result.Evidence.Class {
		case contract.PublicationRequestAcknowledged:
			outcome = "acknowledged"
			if dispatch.Projection.Action == contract.PublicationCreateEmpty || dispatch.Projection.Action == contract.PublicationCreateWithValue {
				instance = result.Evidence.SafeResourceID
			}
		case contract.PublicationQualifiedNoEffect:
			outcome = "no_effect"
		}
	}
	// A failed save leaves pending evidence. It must not change the actual
	// Product response or turn possible entry into a fabricated no-effect.
	if err := records.RecordOutputFixtureAction(r.inventoryPath, r.scope, o.index, attempt, outcome, instance); err != nil {
		r.fail(errLivePublication)
	}
	r.mu.Lock()
	r.observations = append(r.observations, livePublicationObservation{Index: o.index, Dispatch: dispatch, Result: result, Code: code})
	r.mu.Unlock()
	return result, code
}

func (o *livePublicationOwner) Retire(ctx context.Context) error {
	o.retireOnce.Do(func() {
		o.mu.Lock()
		o.retiring = true
		o.mu.Unlock()
		o.retireErr = o.publicationPrivateOwner.Retire(ctx)
		o.recorder.mu.Lock()
		o.recorder.retired++
		o.recorder.mu.Unlock()
		o.recorder.fail(o.retireErr)
	})
	return o.retireErr
}
