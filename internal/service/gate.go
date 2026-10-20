package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"defensepro-api/internal/soap"
)

// Limits protege el plano de gestión del DefensePro, que es modesto.
type Limits struct {
	MaxConcurrency int           // llamadas simultáneas por equipo (SOAP y SNMP juntas)
	MinCallGap     time.Duration // pausa mínima entre llamadas al mismo equipo
	BusyCPUPercent int           // sobre este % de CPU se omiten consultas pesadas (0 = desactivado)
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

// ErrBusy indica que se omitió una consulta pesada porque el equipo está cargado.
var ErrBusy = errors.New("equipo ocupado")

// checkBusy frena las consultas pesadas (log completo, CLI, perfiles,
// auditoría) si la CPU del equipo supera el umbral. Lee la CPU por SNMP si está
// configurado (más barato) o por SOAP; si no la puede leer, no frena.
func (s *DefenseProService) checkBusy(ctx context.Context) error {
	if s.busy <= 0 {
		return nil
	}
	var cpu int64 = -1
	if s.snmp != nil {
		if v, err := s.snmpGet(ctx, statsTTL, []string{oidResourceUtil}); err == nil {
			if p, ok := v[oidResourceUtil]; ok {
				cpu = p.Int64()
			}
		}
	}
	if cpu < 0 {
		if resp, err := s.call(ctx, statsTTL, soap.DeviceUtilization, "get_ResourceUtilization"); err == nil {
			if val, err := resp.Value(); err == nil {
				cpu, _ = strconv.ParseInt(val, 10, 64)
			}
		}
	}
	if cpu >= int64(s.busy) {
		return fmt.Errorf("%w: CPU %d%% >= %d%%, se omite la consulta pesada", ErrBusy, cpu, s.busy)
	}
	return nil
}
