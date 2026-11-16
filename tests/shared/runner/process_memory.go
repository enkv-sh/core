package main

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

const (
	processMemoryMaximum      = uint64(24) << 30
	processMemoryMaxProcesses = 8192
)

type processIdentity struct {
	pid   int
	start uint64
}

type processIdentityInfo struct {
	identity processIdentity
	parent   int
	group    int
	state    byte
}

type processMemoryInfo struct {
	processIdentityInfo
	bytes uint64
}

type processMemorySample struct {
	bytes uint64
	peak  uint64
	limit uint64
	count int
}

// Both observers retain known generations after reparenting. Branch observers
// read only identity; the one invocation observer also reads native bytes.
// A child that orphans entirely between samples remains an observation limit.
type processIdentityWatcher struct {
	root         int
	rootRequired bool
	rootGone     bool
	rootIdentity processIdentity
	owned        map[processIdentity]struct{}
}

func newProcessIdentityWatcher(root int, required bool) *processIdentityWatcher {
	return &processIdentityWatcher{root: root, rootRequired: required, owned: make(map[processIdentity]struct{})}
}

func (w *processIdentityWatcher) sample() error {
	_, err := w.observe(func(pid int) (processMemoryInfo, error) {
		identity, err := nativeProcessIdentity(pid)
		return processMemoryInfo{processIdentityInfo: identity}, err
	})
	return err
}

func (w *processIdentityWatcher) observe(read func(int) (processMemoryInfo, error)) (processMemorySample, error) {
	var result processMemorySample
	type pending struct {
		pid      int
		expected processIdentity
	}
	var queue []pending
	queued := make(map[int]bool)
	if !w.rootGone {
		queue = append(queue, pending{pid: w.root, expected: w.rootIdentity})
		queued[w.root] = true
	}
	historyQueued := false
	for len(queue) != 0 || !historyQueued {
		if len(queue) == 0 {
			for id := range w.owned {
				if !queued[id.pid] {
					if len(queued) >= processMemoryMaxProcesses {
						return result, errors.New("process census exceeds process limit")
					}
					queue = append(queue, pending{pid: id.pid, expected: id})
					queued[id.pid] = true
				}
			}
			historyQueued = true
			continue
		}
		item := queue[0]
		queue = queue[1:]
		info, err := read(item.pid)
		if errors.Is(err, syscall.ESRCH) {
			gone, checkErr := processGone(item.pid)
			if checkErr != nil {
				return result, fmt.Errorf("process %d identity after observation failure: %w", item.pid, checkErr)
			}
			if !gone {
				return result, fmt.Errorf("process %d observation unavailable while it remains live: %w", item.pid, err)
			}
			if item.pid == w.root {
				if w.rootRequired {
					return result, errors.New("native owner disappeared during process census")
				}
				w.rootGone = true
			}
			delete(w.owned, item.expected)
			continue
		}
		if err != nil {
			return result, fmt.Errorf("process %d observation: %w", item.pid, err)
		}
		if item.expected.start != 0 && info.identity != item.expected {
			if item.pid == w.root && !w.rootGone {
				return result, errors.New("command identity changed during process census")
			}
			delete(w.owned, item.expected)
			continue
		}
		if item.pid == w.root {
			w.rootIdentity = info.identity
		}
		w.owned[info.identity] = struct{}{}
		if result.bytes > ^uint64(0)-info.bytes {
			return result, errors.New("process memory sum overflow")
		}
		result.bytes += info.bytes
		result.count++
		children, err := nativeProcessChildren(item.pid)
		if errors.Is(err, syscall.ESRCH) {
			gone, checkErr := processGone(item.pid)
			if checkErr != nil {
				return result, fmt.Errorf("process %d identity after child-list failure: %w", item.pid, checkErr)
			}
			if gone && item.pid != w.root {
				delete(w.owned, info.identity)
				continue
			}
			if gone && !w.rootRequired {
				w.rootGone = true
				delete(w.owned, info.identity)
				continue
			}
		}
		if err != nil {
			return result, fmt.Errorf("process %d children: %w", item.pid, err)
		}
		for _, child := range children {
			if child > 0 && !queued[child] {
				if len(queued) >= processMemoryMaxProcesses {
					return result, errors.New("process census exceeds process limit")
				}
				// The edge covers children of Linux non-leader threads too.
				queue = append(queue, pending{pid: child})
				queued[child] = true
			}
		}
	}
	return result, nil
}

func processGone(pid int) (bool, error) {
	_, err := nativeProcessIdentity(pid)
	if errors.Is(err, syscall.ESRCH) {
		return true, nil
	}
	return false, err
}

func (w *processIdentityWatcher) stopEscaped() error {
	var failure error
	for id := range w.owned {
		info, err := nativeProcessIdentity(id.pid)
		if errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			failure = errors.Join(failure, err)
			continue
		}
		if info.identity != id || info.group == w.root || id.pid == os.Getpid() {
			continue
		}
		if err := syscall.Kill(id.pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			failure = errors.Join(failure, err)
		}
	}
	return failure
}

func (w *processIdentityWatcher) escapedStopped() (bool, error) {
	for id := range w.owned {
		info, err := nativeProcessIdentity(id.pid)
		if errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return false, err
		}
		if info.identity == id && info.group != w.root && id.pid != os.Getpid() {
			return false, nil
		}
	}
	return true, nil
}

type invocationMemoryGuard struct {
	mu          sync.Mutex
	watcher     *processIdentityWatcher
	sample      processMemorySample
	err         error
	stopping    bool
	stopOnce    sync.Once
	stopRequest chan struct{}
	done        chan struct{}
	failed      chan struct{}
}

func startInvocationMemoryGuard(limit uint64) (*invocationMemoryGuard, processMemorySample, error) {
	if err := validateProcessMemoryLimit(limit); err != nil {
		return nil, processMemorySample{limit: limit}, err
	}
	physical, err := nativePhysicalMemory()
	if err != nil {
		return nil, processMemorySample{limit: limit}, fmt.Errorf("physical memory observation unavailable: %w", err)
	}
	if physical == 0 {
		return nil, processMemorySample{limit: limit}, errors.New("physical memory is zero")
	}
	g := &invocationMemoryGuard{watcher: newProcessIdentityWatcher(os.Getpid(), true),
		sample: processMemorySample{limit: limit}, stopRequest: make(chan struct{}), done: make(chan struct{}), failed: make(chan struct{})}
	g.observeLocked()
	if g.err != nil {
		return nil, g.sample, g.err
	}
	initial := g.sample
	go g.run()
	return g, initial, nil
}

func validateProcessMemoryLimit(limit uint64) error {
	if limit == 0 || limit > processMemoryMaximum {
		return errors.New("process memory allowance is outside the supported range")
	}
	return nil
}

func (g *invocationMemoryGuard) observeLocked() {
	if g.err != nil {
		return
	}
	observed, err := g.watcher.observe(nativeProcessMemory)
	observed.limit = g.sample.limit
	observed.peak = max(g.sample.peak, observed.bytes)
	g.sample = observed
	if err != nil {
		g.err = fmt.Errorf("process memory sampling failed after observed peak %d bytes (limit %d): %w", observed.peak, observed.limit, err)
	} else if observed.bytes >= observed.limit {
		g.err = fmt.Errorf("native owner and descendants used %d bytes (limit %d, %d processes)", observed.bytes, observed.limit, observed.count)
	}
	if g.err != nil {
		close(g.failed)
	}
}

func (g *invocationMemoryGuard) run() {
	defer close(g.done)
	ticker := time.NewTicker(processObservationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-g.stopRequest:
			g.mu.Lock()
			g.observeLocked()
			g.mu.Unlock()
			return
		case <-g.failed:
			return
		case <-ticker.C:
			g.mu.Lock()
			g.observeLocked()
			failed := g.err != nil
			g.mu.Unlock()
			if failed {
				return
			}
		}
	}
}

func (g *invocationMemoryGuard) failure() <-chan struct{} { return g.failed }

func (g *invocationMemoryGuard) result() (processMemorySample, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sample, g.err
}

func (g *invocationMemoryGuard) setLimit(limit uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return g.err
	}
	if g.stopping {
		return errors.New("process memory guard is stopping")
	}
	if err := validateProcessMemoryLimit(limit); err != nil {
		return err
	}
	g.sample.limit = limit
	g.observeLocked()
	return g.err
}

// Call only after direct runner Wait or an explicit hard stop. This proves
// observed descendants absent, never that their direct owners performed Wait.
func (g *invocationMemoryGuard) stopDescendants() (bool, error) {
	deadline := time.Now().Add(processGroupSettlementTimeout)
	var failure error
	for {
		g.mu.Lock()
		identities := make([]processIdentity, 0, len(g.watcher.owned))
		for id := range g.watcher.owned {
			if id.pid != os.Getpid() {
				identities = append(identities, id)
			}
		}
		g.mu.Unlock()
		stopped := true
		for _, id := range identities {
			info, err := nativeProcessIdentity(id.pid)
			if errors.Is(err, syscall.ESRCH) {
				continue
			}
			if err != nil {
				failure = errors.Join(failure, err)
				stopped = false
				continue
			}
			if info.identity != id {
				continue
			}
			stopped = false
			if err := syscall.Kill(id.pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				failure = errors.Join(failure, err)
			}
		}
		if failure != nil {
			return false, failure
		}
		if stopped {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			return false, errors.Join(failure, errors.New("observed descendant is not settled"))
		}
		time.Sleep(processGroupPollInterval)
	}
}

func (g *invocationMemoryGuard) stop() (processMemorySample, error) {
	g.stopOnce.Do(func() {
		g.mu.Lock()
		g.stopping = true
		g.mu.Unlock()
		close(g.stopRequest)
	})
	<-g.done
	return g.result()
}
