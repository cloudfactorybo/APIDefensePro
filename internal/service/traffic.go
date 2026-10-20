package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"defensepro-api/internal/models"
	"defensepro-api/internal/soap"
)

// cliTTL: las estadísticas CLI se recalculan en el equipo en cada llamada,
// así que se cachean como el resto de los contadores.
const cliTTL = statsTTL

// ErrPolicyNotFound indica que la política pedida no existe en el equipo.
var ErrPolicyNotFound = errors.New("la política no existe en el equipo")

// safePolicyName limita lo que se concatena a un comando CLI. El nombre además
// debe existir en getAll_Policy, así que nunca llega texto arbitrario al CLI.
var safePolicyName = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

// cli ejecuta un comando CLI fijo vía SOAP (CLI.Command) y devuelve su salida.
func (s *DefenseProService) cli(ctx context.Context, command string) (string, error) {
	resp, err := s.call(ctx, cliTTL, soap.CLICommand, "apply_CLICommand", soap.Param{Name: "command", Value: command})
	if err != nil {
		return "", err
	}
	out, err := resp.Value()
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(strings.TrimSpace(out), "Error") {
		return "", fmt.Errorf("cli %q: %s", command, strings.TrimSpace(out))
	}
	return out, nil
}

// GetBehavioralTraffic devuelve baseline, tráfico actual y descartado de BDoS
// (por protocolo) y DNS (por tipo de consulta) de una política.
func (s *DefenseProService) GetBehavioralTraffic(ctx context.Context, policy string) (*models.BehavioralTraffic, error) {
	var policies []models.Policy
	if err := s.gather(ctx, nil, table(s, soap.SecurityPolicy, "getAll_Policy", configTTL, &policies)); err != nil {
		return nil, err
	}
	var p *models.Policy
	for i := range policies {
		if strings.EqualFold(policies[i].Name, policy) {
			p = &policies[i]
			break
		}
	}
	if p == nil {
		return nil, fmt.Errorf("%w: %s", ErrPolicyNotFound, policy)
	}
	if !safePolicyName.MatchString(p.Name) {
		return nil, fmt.Errorf("nombre de política no soportado para estadísticas: %q", p.Name)
	}

	out := &models.BehavioralTraffic{Policy: p.Name}
	var bdosErr, dnsErr error
	var wg sync.WaitGroup
	if p.BehavioralDosProfile != "" {
		wg.Go(func() {
			// El comando ignora argumentos: devuelve todas las políticas y el
			// equipo corta la salida (~2 políticas por SOAP).
			text, err := s.cli(ctx, "system internal security bdos statistics")
			if err != nil {
				bdosErr = err
				return
			}
			out.BDoS = parseBDoSStats(text, p.Name)
			if out.BDoS == nil {
				bdosErr = fmt.Errorf("bdos: la política %s no entra en la salida del CLI (el equipo la corta tras ~2 políticas)", p.Name)
				return
			}
			out.BDoS.Profile = p.BehavioralDosProfile
		})
	}
	if p.DNSProtectionProfile != "" {
		wg.Go(func() {
			text, err := s.cli(ctx, "system internal security dns statistics get "+p.Name)
			if err != nil {
				dnsErr = err
				return
			}
			out.DNS = parseDNSStats(text)
			if out.DNS == nil {
				dnsErr = fmt.Errorf("dns: la política %s no aparece en la salida del equipo", p.Name)
				return
			}
			out.DNS.Profile = p.DNSProtectionProfile
		})
	}
	wg.Wait()

	for _, err := range []error{bdosErr, dnsErr} {
		if err != nil {
			out.AddError(err.Error())
			s.logCtx(ctx).WithField("policy", p.Name).WithError(err).Warn("estadísticas behavioral no disponibles")
		}
	}
	if out.BDoS == nil && out.DNS == nil {
		if err := errors.Join(bdosErr, dnsErr); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("la política %s no tiene perfiles BDoS ni DNS", p.Name)
	}
	return out, nil
}
