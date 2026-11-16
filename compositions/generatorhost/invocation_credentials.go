package generatorhost

import (
	"context"
	"errors"
	"sync"

	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact/credentialroute"
)

type invocationCredentialKey struct {
	route contract.ID
}

func invocationCredentialKeyOf(row contract.GeneratorImplementation) invocationCredentialKey {
	return invocationCredentialKey{route: row.CredentialRouteID}
}

// InvocationCredentialsMaximumOwnedBytes bounds retained captures. Encoded
// bodies have exact capacity. The 512-byte per-route metadata reserve covers
// each 80-byte row, its channel/allocation overhead and the one shared owner
// context, cancellation function and join state on supported 64-bit runtimes.
// Command clones belong to their active exchange's ParentFixedOwnedBytes.
const InvocationCredentialsMaximumOwnedBytes = contract.GeneratorMaxTemplates * (credentialroute.MaxInputsBytes + 512)

// InvocationCredentialsMaximumAcquisitionOwnedBytes additionally reserves
// workspace for every route while acquisition is pending, even after its first
// exchange ends. Each route has at most 65536 temporary private input bytes.
// Its 8192-byte metadata reserve covers 32 Input rows (1536), 32 name headers
// (512), twice the complete 1581-byte route content, the decoded Route (88),
// and 256 bytes of worker control state. The encoded result transfers to its
// retained row and counts only in InvocationCredentialsMaximumOwnedBytes.
// Runtime stacks, scheduler descriptors and physical allocator rounding are
// outside this controlled backing account. There are at most 1408 joined tasks.
const InvocationCredentialsMaximumAcquisitionOwnedBytes = contract.GeneratorMaxTemplates * (credentialroute.MaxInputsBytes + 8192)

type invocationCredentialCapture struct {
	key   invocationCredentialKey
	body  []byte
	err   error
	ready chan struct{}
}

// InvocationCredentials owns one environment capture per exact admitted route.
// Acquisition uses the invocation's context; session cancellation releases only
// that waiter. Close cancels and joins acquisition, joins all session leases,
// then clears retained private backing.
type InvocationCredentials struct {
	mu           sync.Mutex
	sessions     sync.WaitGroup
	acquisitions sync.WaitGroup
	closeOnce    sync.Once
	closed       bool
	captures     []invocationCredentialCapture
	ctx          context.Context
	cancel       context.CancelFunc
	readInputs   func(context.Context, credentialroute.Route) ([]byte, error)
}

// NewInvocationCredentials creates an empty owner under the invocation context,
// without reading credentials. A nil context refuses construction. Close the
// owner after its producer owners have joined.
func NewInvocationCredentials(ctx context.Context) *InvocationCredentials {
	if ctx == nil {
		return nil
	}
	owned, cancel := context.WithCancel(ctx)
	return &InvocationCredentials{ctx: owned, cancel: cancel,
		captures: make([]invocationCredentialCapture, 0, contract.GeneratorMaxTemplates), readInputs: readEnvironmentInputs}
}

// NewNativeForInvocation retains the normal artifact and runtime admission.
// Its fresh launcher borrows only the invocation's private capture owner.
// The required context controls construction, not the capture owner's lifetime.
func NewNativeForInvocation(ctx context.Context, config Config, credentials *InvocationCredentials) (*NativeLauncher, error) {
	if credentials == nil {
		return nil, ErrCredential
	}
	launcher, err := NewNative(ctx, config)
	if err != nil {
		return nil, err
	}
	launcher.invocation = credentials
	return launcher, nil
}

func (c *InvocationCredentials) begin() (func(), error) {
	if c == nil {
		return nil, ErrCredential
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx == nil || c.ctx.Err() != nil {
		return nil, ErrCredential
	}
	c.sessions.Add(1)
	var once sync.Once
	return func() { once.Do(c.sessions.Done) }, nil
}

// capture is reached only by a leased host session after its successful Hello.
// The retained copy and each returned command copy have separate byte owners.
func (c *InvocationCredentials) capture(ctx context.Context, row contract.GeneratorImplementation, installed *Installation) ([]byte, error) {
	valid := false
	if installed != nil {
		valid = installed.validRuntime(row)
	} else {
		valid = validBoundImplementation(row)
	}
	if c == nil || ctx == nil || !valid {
		return nil, ErrCredential
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrCredential, err)
	}
	key := invocationCredentialKeyOf(row)
	c.mu.Lock()
	if c.closed || c.ctx == nil || cap(c.captures) != contract.GeneratorMaxTemplates {
		c.mu.Unlock()
		return nil, ErrCredential
	}
	if err := c.ctx.Err(); err != nil {
		c.mu.Unlock()
		return nil, errors.Join(ErrCredential, err)
	}
	var captured *invocationCredentialCapture
	for i := range c.captures {
		if c.captures[i].key == key {
			captured = &c.captures[i]
			break
		}
	}
	if captured == nil {
		if len(c.captures) >= contract.GeneratorMaxTemplates {
			c.mu.Unlock()
			return nil, ErrCredential
		}
		ownedRoute, err := credentialroute.Decode(row.CredentialRoute)
		c.captures = append(c.captures, invocationCredentialCapture{key: key, ready: make(chan struct{})})
		captured = &c.captures[len(c.captures)-1]
		if err != nil {
			captured.err = err
			close(captured.ready)
		} else {
			c.acquisitions.Add(1)
			go c.acquire(captured, ownedRoute)
		}
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, errors.Join(ErrCredential, ctx.Err())
	case <-c.ctx.Done():
		return nil, errors.Join(ErrCredential, c.ctx.Err())
	case <-captured.ready:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrCredential, err)
	}
	if err := c.ctx.Err(); err != nil {
		return nil, errors.Join(ErrCredential, err)
	}
	if c.closed {
		return nil, ErrCredential
	}
	if captured.err != nil {
		return nil, captured.err
	}
	body := make([]byte, len(captured.body))
	copy(body, captured.body)
	return body, nil
}

func (c *InvocationCredentials) acquire(captured *invocationCredentialCapture, route credentialroute.Route) {
	defer c.acquisitions.Done()
	body, err := c.readInputs(c.ctx, route)
	c.mu.Lock()
	defer c.mu.Unlock()
	if canceled := c.ctx.Err(); canceled != nil {
		err = errors.Join(err, ErrCredential, canceled)
	}
	if err != nil || c.closed {
		clear(body[:cap(body)])
		body = nil
	}
	captured.body, captured.err = body, err
	close(captured.ready)
}

// Close refuses new sessions, cancels and joins acquisition, waits for leased
// sessions and clears retained private backing. It is idempotent and accepts a nil receiver. Owners must
// settle their runs before calling Close to avoid waiting on their own leases.
func (c *InvocationCredentials) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.cancel != nil {
			c.cancel()
		}
		c.mu.Unlock()
		c.acquisitions.Wait()
		c.sessions.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		for i := range c.captures {
			clear(c.captures[i].body[:cap(c.captures[i].body)])
		}
		clear(c.captures)
		c.captures = nil
	})
}
