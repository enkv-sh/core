package observability

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
)

// httpTLSOwner owns acquired sockets and the finite dial/handshake callbacks.
// Go may detach a transport dial from the request that started it.
type httpTLSOwner struct {
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
	active     map[*httpStartupConnection]struct{}
	cleanupErr error
	dials      sync.WaitGroup
	closeOnce  sync.Once
	closeErr   error
}

func newRemoteHTTPTransport() (*http.Transport, *httpTLSOwner) {
	ctx, cancel := context.WithCancel(context.Background())
	owner := &httpTLSOwner{ctx: ctx, cancel: cancel, active: make(map[*httpStartupConnection]struct{})}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	base := &http.Transport{
		DialContext:            (&net.Dialer{Timeout: exportDialTimeout, KeepAlive: exportKeepAliveInterval}).DialContext,
		TLSHandshakeTimeout:    exportTLSHandshakeTimeout,
		ResponseHeaderTimeout:  exportResponseHeaderTimeout,
		IdleConnTimeout:        exportIdleConnectionTimeout,
		MaxConnsPerHost:        maximumExportConnectionsPerHost,
		MaxIdleConnsPerHost:    maximumExportIdleConnectionsPerHost,
		MaxResponseHeaderBytes: maximumRemoteResponseBytes,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		Protocols:              protocols,
	}
	base.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return owner.dialTLS(ctx, network, address, base)
	}
	return base, owner
}

func (owner *httpTLSOwner) dialTLS(ctx context.Context, network, address string, base *http.Transport) (net.Conn, error) {
	owner.mu.Lock()
	if owner.closed {
		owner.mu.Unlock()
		return nil, net.ErrClosed
	}
	owner.dials.Add(1)
	owner.mu.Unlock()
	defer owner.dials.Done()

	dialContext, cancel := context.WithCancel(ctx)
	ownerCancelled := make(chan struct{})
	stopOwner := context.AfterFunc(owner.ctx, func() {
		cancel()
		close(ownerCancelled)
	})
	defer func() {
		if !stopOwner() {
			<-ownerCancelled
		}
		cancel()
	}()

	raw, err := base.DialContext(dialContext, network, address)
	if err != nil {
		return nil, err
	}
	config := new(tls.Config)
	if base.TLSClientConfig != nil {
		config = base.TLSClientConfig.Clone()
	}
	if config.ServerName == "" {
		config.ServerName, _, err = net.SplitHostPort(address)
		if err != nil {
			return nil, errors.Join(err, raw.Close())
		}
	}
	config.NextProtos = []string{"http/1.1"}
	secured := tls.Client(raw, config)
	connection := &httpStartupConnection{Conn: secured, raw: raw, ready: make(chan struct{}), owner: owner}
	owner.mu.Lock()
	if owner.closed || dialContext.Err() != nil {
		owner.mu.Unlock()
		return nil, errors.Join(net.ErrClosed, connection.Close())
	}
	owner.active[connection] = struct{}{}
	owner.mu.Unlock()

	cancelled := make(chan struct{})
	stopConnection := context.AfterFunc(dialContext, func() {
		// Close records its error in owner.cleanupErr before this callback joins.
		_ = connection.Close()
		close(cancelled)
	})
	cancellationStopped := false
	defer func() {
		if !cancellationStopped && !stopConnection() {
			<-cancelled
		}
	}()
	handshake, cancelHandshake := context.WithTimeout(dialContext, exportTLSHandshakeTimeout)
	err = secured.HandshakeContext(handshake)
	cancelHandshake()
	if err != nil {
		return nil, errors.Join(err, connection.Close())
	}
	stopped := stopConnection()
	cancellationStopped = true
	if !stopped {
		<-cancelled
		return nil, errors.Join(dialContext.Err(), connection.Close(), net.ErrClosed)
	}
	owner.mu.Lock()
	if owner.closed || dialContext.Err() != nil {
		owner.mu.Unlock()
		return nil, errors.Join(net.ErrClosed, connection.Close())
	}
	connection.state = secured.ConnectionState()
	owner.mu.Unlock()
	return connection, nil
}

func (owner *httpTLSOwner) close() error {
	owner.closeOnce.Do(func() {
		owner.mu.Lock()
		owner.closed = true
		connections := make([]*httpStartupConnection, 0, len(owner.active))
		for connection := range owner.active {
			connections = append(connections, connection)
		}
		owner.mu.Unlock()
		owner.cancel()
		for _, connection := range connections {
			// Close records its error once; publish that retained set after join.
			_ = connection.Close()
		}
		owner.dials.Wait()
		owner.mu.Lock()
		owner.closeErr = owner.cleanupErr
		owner.mu.Unlock()
	})
	return owner.closeErr
}

// HTTP/1 registers an expected response before it queues its first Write.
// Closing before that Write must not expose even buffered decrypted peer bytes.
type httpStartupConnection struct {
	net.Conn
	raw   net.Conn
	state tls.ConnectionState
	owner *httpTLSOwner
	ready chan struct{}
	mu    sync.Mutex
	wrote bool
	dead  bool

	closeOnce sync.Once
	closeErr  error
}

func (connection *httpStartupConnection) Read(data []byte) (int, error) {
	<-connection.ready
	connection.mu.Lock()
	closed := connection.dead
	connection.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	return connection.Conn.Read(data)
}

func (connection *httpStartupConnection) Write(data []byte) (int, error) {
	connection.mu.Lock()
	if connection.dead {
		connection.mu.Unlock()
		return 0, net.ErrClosed
	}
	if !connection.wrote {
		connection.wrote = true
		close(connection.ready)
	}
	connection.mu.Unlock()
	return connection.Conn.Write(data)
}

func (connection *httpStartupConnection) ConnectionState() tls.ConnectionState {
	return connection.state
}

func (connection *httpStartupConnection) Close() error {
	connection.closeOnce.Do(func() {
		connection.mu.Lock()
		connection.dead = true
		if !connection.wrote {
			close(connection.ready)
		}
		connection.mu.Unlock()
		// Closing the socket avoids a TLS close-notify write during shutdown.
		connection.closeErr = connection.raw.Close()
		if errors.Is(connection.closeErr, net.ErrClosed) {
			// A canceled TLS handshake may already have closed this socket.
			connection.closeErr = nil
		}
		if connection.owner != nil {
			connection.owner.mu.Lock()
			delete(connection.owner.active, connection)
			connection.owner.cleanupErr = errors.Join(connection.owner.cleanupErr, connection.closeErr)
			connection.owner.mu.Unlock()
		}
	})
	return connection.closeErr
}
