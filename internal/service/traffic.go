package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"

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

// bdosOutput es la salida de "bdos statistics" ya leída, compartida por todas
// las políticas de una consulta.
type bdosOutput struct {
	text     string
	complete bool  // por SSH: trae todas las políticas
	sshErr   error // SSH falló y se usó SOAP
	err      error
}

// missing explica por qué una política con perfil BDoS no está en la salida.
func (o bdosOutput) missing(policy string) string {
	switch {
	case o.complete:
		return fmt.Sprintf("bdos: la política %s no aparece en la salida del equipo", policy)
	case o.sshErr != nil:
		return fmt.Sprintf("bdos: la política %s no entra en la salida del CLI vía SOAP (SSH falló: %v)", policy, o.sshErr)
	}
	return fmt.Sprintf("bdos: la política %s no entra en la salida del CLI vía SOAP (el equipo la corta tras ~2 políticas; configura SSH con defensepro-admin ssh-trust)", policy)
}

func (s *DefenseProService) readBDoS(ctx context.Context) bdosOutput {
	var o bdosOutput
	o.text, o.complete, o.sshErr, o.err = s.bdosStats(ctx)
	return o
}

func (s *DefenseProService) policyList(ctx context.Context) ([]models.Policy, error) {
	var policies []models.Policy
	if err := s.gather(ctx, nil, table(s, soap.SecurityPolicy, "getAll_Policy", configTTL, &policies)); err != nil {
		return nil, err
	}
	return policies, nil
}

// behavioralFor arma las métricas de una política: BDoS sale de la salida ya
// leída y DNS de su propio comando (que sí acepta la política). Los datos que
// faltan quedan en Errors.
func (s *DefenseProService) behavioralFor(ctx context.Context, p *models.Policy, bdos bdosOutput) *models.BehavioralTraffic {
	out := &models.BehavioralTraffic{Policy: p.Name}
	if p.BehavioralDosProfile != "" {
		if bdos.err != nil {
			out.AddError("bdos: " + bdos.err.Error())
		} else if out.BDoS = parseBDoSStats(bdos.text, p.Name); out.BDoS == nil {
			out.AddError(bdos.missing(p.Name))
		} else {
			out.BDoS.Profile = p.BehavioralDosProfile
		}
	}
	if p.DNSProtectionProfile != "" {
		text, err := s.cli(ctx, "system internal security dns statistics get "+p.Name)
		switch {
		case err != nil:
			out.AddError("dns: " + err.Error())
		case parseDNSStats(text) == nil:
			out.AddError(fmt.Sprintf("dns: la política %s no aparece en la salida del equipo", p.Name))
		default:
			out.DNS = parseDNSStats(text)
			out.DNS.Profile = p.DNSProtectionProfile
		}
	}
	return out
}

// GetBehavioralTraffic devuelve baseline, tráfico actual y descartado de BDoS
// (por protocolo) y DNS (por tipo de consulta) de una política.
func (s *DefenseProService) GetBehavioralTraffic(ctx context.Context, policy string) (*models.BehavioralTraffic, error) {
	if err := s.checkBusy(ctx); err != nil {
		return nil, err
	}
	policies, err := s.policyList(ctx)
	if err != nil {
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
	if p.BehavioralDosProfile == "" && p.DNSProtectionProfile == "" {
		return nil, fmt.Errorf("la política %s no tiene perfiles BDoS ni DNS", p.Name)
	}

	var bdos bdosOutput
	if p.BehavioralDosProfile != "" {
		bdos = s.readBDoS(ctx)
	}
	out := s.behavioralFor(ctx, p, bdos)
	for _, e := range out.Errors {
		s.logCtx(ctx).WithField("policy", p.Name).Warn("estadísticas behavioral no disponibles: " + e)
	}
	if out.BDoS == nil && out.DNS == nil {
		return nil, errors.New(strings.Join(out.Errors, "; "))
	}
	return out, nil
}

// GetBehavioralTrafficAll devuelve las métricas de todas las políticas con
// perfil BDoS o DNS: una sola lectura de "bdos statistics" (completa por SSH)
// para todas, y una de DNS por cada política con perfil DNS.
func (s *DefenseProService) GetBehavioralTrafficAll(ctx context.Context) ([]models.BehavioralTraffic, error) {
	if err := s.checkBusy(ctx); err != nil {
		return nil, err
	}
	policies, err := s.policyList(ctx)
	if err != nil {
		return nil, err
	}

	var selected []*models.Policy
	needBDoS := false
	for i := range policies {
		p := &policies[i]
		if p.BehavioralDosProfile == "" && p.DNSProtectionProfile == "" {
			continue
		}
		selected = append(selected, p)
		needBDoS = needBDoS || p.BehavioralDosProfile != ""
	}
	var bdos bdosOutput
	if needBDoS {
		bdos = s.readBDoS(ctx)
	}

	out := make([]models.BehavioralTraffic, 0, len(selected))
	withData, missing := 0, 0
	for _, p := range selected {
		if !safePolicyName.MatchString(p.Name) {
			item := models.BehavioralTraffic{Policy: p.Name}
			item.AddError(fmt.Sprintf("nombre de política no soportado para estadísticas: %q", p.Name))
			out = append(out, item)
			continue
		}
		item := s.behavioralFor(ctx, p, bdos)
		if item.BDoS != nil || item.DNS != nil {
			withData++
		}
		if len(item.Errors) > 0 {
			missing++
		}
		out = append(out, *item)
	}
	if missing > 0 {
		s.logCtx(ctx).WithFields(logrus.Fields{"policies": len(out), "with_errors": missing, "ssh": bdos.complete}).
			Warn("estadísticas behavioral incompletas")
	}
	if withData == 0 && bdos.err != nil {
		return nil, bdos.err
	}
	return out, nil
}
