package main

// Worker pool (step-21 T3): fixed set of worker subprocesses plus
// pre-spawned spares. A kill removes one worker; the spare takes its
// place immediately and a replacement spare is spawned in the background.

import (
	"fmt"
	"sync"
	"time"
)

type pool struct {
	mu       sync.Mutex
	idle     []*workerHandle
	busy     int
	total    int // live workers (busy + idle)
	size     int // configured pool size (service slots)
	spares   int // configured spare count
	kills    int
	recycled int
	spawnWG  sync.WaitGroup
}

func newPool(size, spares int) (*pool, error) {
	p := &pool{size: size, spares: spares}
	for i := 0; i < size+spares; i++ {
		wk, err := spawnWorker()
		if err != nil {
			return nil, fmt.Errorf("worker spawn: %w", err)
		}
		p.idle = append(p.idle, wk)
		p.total++
	}
	return p, nil
}

// checkout takes an idle worker, waiting up to d for one to free up.
func (p *pool) checkout(d time.Duration) *workerHandle {
	deadline := time.After(d)
	for {
		p.mu.Lock()
		if len(p.idle) > 0 {
			wk := p.idle[len(p.idle)-1]
			p.idle = p.idle[:len(p.idle)-1]
			p.busy++
			p.mu.Unlock()
			return wk
		}
		p.mu.Unlock()
		select {
		case <-deadline:
			return nil
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// release returns a worker to the idle set.
func (p *pool) release(wk *workerHandle) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.busy--
	p.idle = append(p.idle, wk)
}

// kill SIGKILLs a worker at the budget, counts the kill and spawns a
// replacement in the background (the spare already covers the hot path).
func (p *pool) kill(wk *workerHandle) {
	p.mu.Lock()
	p.busy--
	p.total--
	p.kills++
	p.mu.Unlock()
	go func() {
		wk.stop()
		nw, err := spawnWorker()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.idle = append(p.idle, nw)
		p.total++
		p.mu.Unlock()
	}()
}

// retire closes a worker that reached its recycle-after-N job count and
// spawns a replacement in the background.
func (p *pool) retire(wk *workerHandle) {
	p.mu.Lock()
	p.busy--
	p.total--
	p.recycled++
	p.mu.Unlock()
	go func() {
		wk.stop()
		nw, err := spawnWorker()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.idle = append(p.idle, nw)
		p.total++
		p.mu.Unlock()
	}()
}

func (p *pool) stats() (total, busy, idle, kills, recycled int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.total, p.busy, len(p.idle), p.kills, p.recycled
}

func (p *pool) close() {
	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, wk := range idle {
		wk.stop()
	}
}
