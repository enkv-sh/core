package crypto

import (
	"context"
	"math"
	"slices"
	"sync"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	"enkv.sh/telemetry"
)

// PlanningDisplayFactory is installed separately from request data. Acquire must
// return when its context ends and transfer any returned sink, even on error.
type PlanningDisplayFactory interface {
	Identity() contract.ID
	Acquire(context.Context) (PlanningDisplaySink, error)
}

// PlanningDisplaySink borrows one authenticated value until Accept returns.
// Close must unblock and join entered Accept calls and reject further calls.
// Neither the factory nor the sink crosses the Core boundary.
type PlanningDisplaySink interface {
	Identity() contract.ID
	Accept(context.Context, string, contract.PlanningSourceForm, []byte) error
	Close() error
}

type planningDisplayOwner struct {
	sink PlanningDisplaySink
	once sync.Once
	err  error
}

func (o *planningDisplayOwner) close() { o.once.Do(func() { o.err = o.sink.Close() }) }

// planningDisplayBounds checks both admitted representations without allocating
// an aggregate encoding or returning secret lengths to an ordinary result.
func planningDisplayBounds(lengths []uint32) bool {
	if len(lengths) == 0 || len(lengths) > contract.CryptoMaxValueEntries {
		return false
	}
	var raw, human, structured uint64
	for _, length := range lengths {
		n := uint64(length)
		if n > contract.CryptoMaxRetainedValue || raw > contract.CryptoMaxRetainedSet-n {
			return false
		}
		raw += n
		h, j := uint64(2048)+4*n, uint64(2048)+4*((n+2)/3)
		if human > math.MaxUint64-h || structured > math.MaxUint64-j {
			return false
		}
		human, structured = human+h, structured+j
	}
	return true
}

func (c *PlanningCustody) Display(ctx context.Context, factory PlanningDisplayFactory) (out contract.PlanningDisplayResult) {
	out.Delivery, out.Code = contract.PlanningDeliveryNone, contract.CryptoInvalidAdmission
	if c == nil || ctx == nil {
		return out
	}
	call := telemetry.Start(ctx, telemetry.ProviderCrypto, telemetry.OpCryptoPlanningDisplay)
	call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
	defer func() { finishCryptoCall(call, out.Code) }()
	c.mu.Lock()
	if c.closed {
		out.Code = c.cancellationCode()
		c.mu.Unlock()
		return out
	}
	if c.displayUsed {
		out.Code = contract.CryptoAlreadyUsed
		c.mu.Unlock()
		return out
	}
	c.displayUsed = true
	c.work.Add(1)
	checked := c.result.Complete && c.result.Code == contract.CryptoSuccess
	c.mu.Unlock()
	defer c.work.Done()
	options := c.admission.Options
	out.SelectedRecords = uint32(len(options.SelectedNames))
	deadline, finite := ctx.Deadline()
	if options.Purpose != contract.PlanningDisplay || !checked || !finite || deadline != c.deadline || ctx.Done() != c.originalDone || factory == nil {
		return out
	}
	indices, lengths := make([]int, len(options.SelectedNames)), make([]uint32, len(options.SelectedNames))
	for i, name := range options.SelectedNames {
		at := slices.IndexFunc(c.admission.Targets, func(t contract.PlanningTarget) bool { return t.Input.Name == name })
		if at < 0 {
			return out
		}
		indices[i] = at
		if c.admission.Targets[at].Input.Form == contract.PlanningSealed {
			lengths[i] = c.targets[at].core.RetainedLength
		} else {
			lengths[i] = c.admission.Targets[at].Current.Core.RetainedLength
		}
	}
	if !planningDisplayBounds(lengths) {
		out.Code = contract.CryptoCapacityExceeded
		return out
	}
	if code := c.cancellationCode(); code != contract.CryptoSuccess {
		out.Code = code
		return out
	}
	if factory.Identity() != options.SinkID {
		return out
	}
	private := telemetry.PrivateContext(c.ctx, telemetry.CallContext(ctx, call))
	sink, err := factory.Acquire(private)
	if sink == nil {
		if err != nil {
			out.OutputFailed = true
			out.Code = contract.CryptoResponseUnknown
		}
		return out
	}
	owner := &planningDisplayOwner{sink: sink}
	stop := context.AfterFunc(c.ctx, owner.close)
	defer func() {
		stop()
		owner.close()
		if owner.err != nil {
			out.OutputFailed = true
			out.Code = contract.CryptoResponseUnknown
		}
	}()
	if err != nil {
		out.OutputFailed = true
		out.Code = contract.CryptoResponseUnknown
		return out
	}
	if factory.Identity() != options.SinkID || sink.Identity() != options.SinkID {
		return out
	}
	for _, at := range indices {
		if code := c.cancellationCode(); code != contract.CryptoSuccess {
			out.Code = code
			return out
		}
		if factory.Identity() != options.SinkID || sink.Identity() != options.SinkID || c.route.Family() != c.admission.Control.Provider || c.route.CredentialRoute() != c.admission.CredentialRoute {
			return out
		}
		plain, code := c.openDisplayValue(private, at)
		func() {
			defer clear(plain[:cap(plain)])
			if code != contract.CryptoSuccess {
				return
			}
			if code = c.cancellationCode(); code != contract.CryptoSuccess {
				return
			}
			if factory.Identity() != options.SinkID || sink.Identity() != options.SinkID {
				code = contract.CryptoInvalidAdmission
				return
			}
			out.Delivery = contract.PlanningDeliveryIncomplete
			target := c.admission.Targets[at]
			if err := sink.Accept(private, target.Input.Name, target.Input.Form, plain); err != nil {
				out.OutputFailed = true
				code = contract.CryptoResponseUnknown
				return
			}
			if code = c.cancellationCode(); code != contract.CryptoSuccess {
				return
			}
			if factory.Identity() != options.SinkID || sink.Identity() != options.SinkID {
				code = contract.CryptoInvalidAdmission
				return
			}
			out.CompletedRecords++
		}()
		if code != contract.CryptoSuccess {
			out.Code = code
			return out
		}
	}
	owner.close()
	if code := c.cancellationCode(); code != contract.CryptoSuccess {
		out.Code = code
		return out
	}
	if owner.err != nil {
		out.OutputFailed = true
		out.Code = contract.CryptoResponseUnknown
		return out
	}
	if factory.Identity() != options.SinkID || sink.Identity() != options.SinkID {
		out.Code = contract.CryptoResponseUnknown
		return out
	}
	out.Delivery, out.Code = contract.PlanningDeliveryComplete, contract.CryptoSuccess
	return out
}

func (c *PlanningCustody) openDisplayValue(ctx context.Context, at int) ([]byte, contract.CryptoResultCode) {
	target, admitted := c.admission.Targets[at], c.targets[at]
	if target.Input.Form == contract.PlanningSealed {
		view, err := contract.InspectSealedInputEnvelope(target.Input.SealedInput)
		if err != nil {
			return nil, contract.CryptoSourceAuthenticationFailed
		}
		envelope := contract.SealedInputEnvelope{Core: admitted.core, Nonce: view.Nonce, Ciphertext: view.Ciphertext, AuthorityWrap: contract.WrapRow(view.AuthorityWrap)}
		plain, _, code := authenticatedSealedValue(ctx, c.route, c.admission.Authority, admitted.core, envelope)
		return plain, code
	}
	selected := target.Current
	keys, _, code := authenticatedCurrentKeys(ctx, c.route, c.admission.Authority, selected.Access.Wraps[admitted.wrapIndex].RSACiphertext, admitted.packetContext, selected.Core, selected.Payload)
	if keys != nil {
		defer clear(keys[:cap(keys)])
	}
	if code != contract.CryptoSuccess {
		return nil, code
	}
	plain, err := custody.OpenValue(selected.Core, selected.Payload, keys)
	if err != nil {
		return nil, contract.CryptoStoredAuthenticationFailed
	}
	return plain, contract.CryptoSuccess
}
