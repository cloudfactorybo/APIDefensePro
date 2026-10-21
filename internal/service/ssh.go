package service

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// sshRunner es lo que el servicio usa del cliente SSH (en tests, un fake).
type sshRunner interface {
	Run(ctx context.Context, command string) (string, error)
}

// SetSSH asigna el cliente SSH del equipo (nil = sin SSH).
func (s *DefenseProService) SetSSH(r sshRunner) { s.ssh = r }

const cmdBDoSStats = "system internal security bdos statistics"

// sshTTL: la salida completa son ~0,9 MB y una sesión SSH; se cachea más que
// los contadores SOAP para que varias consultas seguidas usen una sola sesión.
const sshTTL = 30 * time.Second

// bdosStats devuelve la salida de "system internal security bdos statistics".
// Por SSH llega completa (complete = true); sin SSH, o si SSH falla, se usa el
// CLI vía SOAP, que el equipo corta tras ~2 políticas. sshErr informa la falla
// de SSH cuando se cayó a SOAP.
func (s *DefenseProService) bdosStats(ctx context.Context) (text string, complete bool, sshErr, err error) {
	if s.ssh != nil {
		text, sshErr = s.sshOutput(ctx, cmdBDoSStats)
		if sshErr == nil {
			return text, true, nil, nil
		}
		s.logCtx(ctx).WithError(sshErr).Warn("ssh falló; se usa el CLI vía SOAP (salida parcial)")
	}
	text, err = s.cli(ctx, cmdBDoSStats)
	return text, false, sshErr, err
}

// sshOutput ejecuta un comando permitido por SSH. Consultas simultáneas
// comparten una sola sesión (singleflight) y el resultado se cachea.
func (s *DefenseProService) sshOutput(ctx context.Context, command string) (string, error) {
	key := s.name + ":ssh:" + command
	if b, ok := s.cache.Get(key); ok {
		return string(b), nil
	}
	v, err, _ := s.sshFlight.Do(key, func() (any, error) {
		if err := s.gate.acquire(ctx); err != nil {
			return nil, err
		}
		start := time.Now()
		out, err := s.ssh.Run(ctx, command)
		s.gate.release()
		if err != nil {
			return nil, fmt.Errorf("ssh %q: %w", command, err)
		}
		s.logCtx(ctx).WithFields(logrus.Fields{
			"command":     command,
			"bytes":       len(out),
			"duration_ms": time.Since(start).Milliseconds(),
		}).Debug("comando ssh")
		s.cache.Set(key, []byte(out), sshTTL)
		return out, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}
