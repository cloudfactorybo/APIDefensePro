package service

import (
	"context"
	"sync"
	"time"
)

// Limits protege el plano de gestión del DefensePro, que es modesto.
type Limits struct {
	MaxConcurrency int           // llamadas simultáneas por equipo (SOAP y SNMP juntas)
	MinCallGap     time.Duration // pausa mínima entre llamadas al mismo equipo
}

// gate serializa las llamadas a un equipo y respeta una pausa mínima entre
// ellas. SOAP y SNMP comparten la misma gate.
type gate struct {
	sem chan struct{}
	gap time.Duration

	mu   sync.Mutex
	last time.Time
}

func newGate(l Limits) *gate {
	n := l.MaxConcurrency
	if n < 1 {
		n = 1
	}
	return &gate{sem: make(chan struct{}, n), gap: l.MinCallGap}
}

func (g *gate) acquire(ctx context.Context) error {
	select {
	case g.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if g.gap <= 0 {
		return nil
	}
	g.mu.Lock()
	wait := g.gap - time.Since(g.last)
	g.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		<-g.sem
		return ctx.Err()
	}
}

func (g *gate) release() {
	g.mu.Lock()
	g.last = time.Now()
	g.mu.Unlock()
	<-g.sem
}
