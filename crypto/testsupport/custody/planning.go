package custody

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// PlanningCustody exposes only safe facts and read-owner cleanup to Core tests.
type PlanningCustody struct {
	owner   *privatecrypto.PlanningCustody
	display *PlanningDisplay
}

func (c *PlanningCustody) Check(ctx context.Context) contract.PlanningCheckResult {
	if c == nil || c.owner == nil {
		return contract.PlanningCheckResult{Code: contract.CryptoInvalidAdmission}
	}
	return c.owner.Check(ctx)
}

func (c *PlanningCustody) Close() {
	if c != nil && c.owner != nil {
		c.owner.Close()
	}
}

func (f *Fixture) PlanningCredentialRoute() contract.ID {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, row := range f.bindings {
		if row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == f.authority {
			return f.routes[row.Binding.BindingID]
		}
	}
	return contract.ID{}
}

// NewPlanningCustody keeps synthetic key access in the private test facade.
// It installs no mutation owner and cannot change the fixed Authority route.
func (f *Fixture) NewPlanningCustody(ctx context.Context, q contract.PlanningAdmission) (*PlanningCustody, error) {
	if f == nil || q.Authority.SubjectID != f.authority || q.CredentialRoute != f.PlanningCredentialRoute() {
		return nil, contract.PlanningAdmissionError{Code: contract.CryptoInvalidAdmission}
	}
	owner, err := privatecrypto.NewPlanningCustody(ctx, &keyRoute{owner: f, subject: f.authority, id: q.CredentialRoute}, q)
	if err != nil {
		return nil, err
	}
	return &PlanningCustody{owner: owner}, nil
}

func (c *PlanningCustody) Display(ctx context.Context) contract.PlanningDisplayResult {
	if c != nil && c.owner != nil && c.display != nil {
		return c.owner.Display(ctx, planningDisplayFactory{display: c.display})
	}
	return contract.PlanningDisplayResult{Delivery: contract.PlanningDeliveryNone, Code: contract.CryptoInvalidAdmission}
}

// PlanningDisplay keeps the synthetic expected bytes and borrowed plaintext in
// this private facade. Its public observations contain no secret bytes.
type PlanningDisplay struct {
	id                            contract.ID
	expected                      uint8
	borrowed                      []byte
	Acquisitions, Records, Closes int
	Names                         []string
}

func NewPlanningDisplay(expected uint8) *PlanningDisplay {
	return &PlanningDisplay{id: contract.Hash([]byte("synthetic planning display sink")), expected: expected}
}

func (d *PlanningDisplay) Identity() contract.ID { return d.id }

type planningDisplayFactory struct{ display *PlanningDisplay }

func (f planningDisplayFactory) Identity() contract.ID { return f.display.Identity() }

func (f planningDisplayFactory) Acquire(ctx context.Context) (privatecrypto.PlanningDisplaySink, error) {
	d := f.display
	if ctx == nil || ctx.Err() != nil || d.Acquisitions != 0 {
		return nil, errors.New("planning display unavailable")
	}
	d.Acquisitions++
	return d, nil
}

func (d *PlanningDisplay) Accept(ctx context.Context, name string, form contract.PlanningSourceForm, plain []byte) error {
	if ctx == nil || ctx.Err() != nil || d.Acquisitions != 1 || d.Closes != 0 || d.Records >= contract.CryptoMaxValueEntries ||
		form != contract.PlanningSealed && form != contract.PlanningRetained || !d.Cleared() {
		return errors.New("planning display lifetime differs")
	}
	expected, ok := syntheticValue(d.expected)
	defer clear(expected[:cap(expected)])
	if !ok || !bytes.Equal(plain, expected) {
		return errors.New("planning displayed value differs")
	}
	d.borrowed = plain[:cap(plain)]
	d.Records++
	d.Names = append(d.Names, strings.Clone(name))
	return nil
}

func (d *PlanningDisplay) Close() error { d.Closes++; return nil }

func (d *PlanningDisplay) Cleared() bool {
	for _, value := range d.borrowed {
		if value != 0 {
			return false
		}
	}
	return true
}

func (f *Fixture) NewPlanningDisplayCustody(ctx context.Context, q contract.PlanningAdmission, display *PlanningDisplay) (*PlanningCustody, error) {
	if display == nil || q.Options.Purpose != contract.PlanningDisplay || q.Options.SinkID != display.Identity() {
		return nil, contract.PlanningAdmissionError{Code: contract.CryptoInvalidAdmission}
	}
	c, err := f.NewPlanningCustody(ctx, q)
	if err != nil {
		return nil, err
	}
	c.display = display
	return c, nil
}
