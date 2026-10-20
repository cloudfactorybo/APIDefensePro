package service

import (
	"cmp"
	"context"
	"slices"

	"defensepro-api/internal/models"
	"defensepro-api/internal/soap"
)

// ProfileTypes son los valores aceptados en ?type= de /profiles.
var ProfileTypes = []string{
	"bdos", "dns", "syn", "https", "oos", "antiscanning",
	"trafficfilters", "geo", "ert", "qdos", "pps", "connectionlimit",
}

// behavioralCategories son las categorías del log que generan BDoS y DNS.
var behavioralCategories = []string{"behavioral-doS", "dns-protection"}

// addProfiles registra la lectura de un tipo de perfil si fue pedido.
func addProfiles[T any](tasks *[]task, want map[string]bool, key string, s *DefenseProService, svc soap.Service, op string, dst **[]T) {
	if want != nil && !want[key] {
		return
	}
	*dst = &[]T{}
	*tasks = append(*tasks, table(s, svc, op, configTTL, *dst))
}

// GetProfiles devuelve los perfiles de protección. types filtra por módulo
// (ver ProfileTypes); vacío = todos, que son 12 llamadas SOAP.
func (s *DefenseProService) GetProfiles(ctx context.Context, types []string) (*models.Profiles, error) {
	want := toSet(types)
	out := &models.Profiles{}
	var tasks []task
	addProfiles(&tasks, want, "bdos", s, soap.SecurityBehavioralDoS, "getAll_Profiles", &out.BDoS)
	addProfiles(&tasks, want, "dns", s, soap.SecurityDnsProtection, "getAll_DnsProtectionProfile", &out.DNS)
	addProfiles(&tasks, want, "syn", s, soap.SecuritySynProtection, "getAll_rsIDSSynProfilesParamsEntry", &out.SYN)
	addProfiles(&tasks, want, "https", s, soap.SecurityHTTPSFlood, "getAll_HttpsFloodProfileEntry", &out.HTTPSFlood)
	addProfiles(&tasks, want, "oos", s, soap.SecurityOutOfState, "getAll_Profile", &out.OutOfState)
	addProfiles(&tasks, want, "antiscanning", s, soap.SecurityAntiScanning, "getAll_AntiScanningProfiles", &out.AntiScanning)
	addProfiles(&tasks, want, "trafficfilters", s, soap.SecurityTrafficFilter, "getAll_TrafficFilterProfile", &out.TrafficFilters)
	addProfiles(&tasks, want, "geo", s, soap.SecurityGeoProfiles, "getAll_GeoProfileEntry", &out.Geo)
	addProfiles(&tasks, want, "ert", s, soap.SecurityErtFeedProtection, "getAll_ErtAttackersFeedProfileEntry", &out.ErtFeed)
	addProfiles(&tasks, want, "qdos", s, soap.SecurityQdosProfiles, "getAll_QdosProfileEntry", &out.QDoS)
	addProfiles(&tasks, want, "pps", s, soap.SecurityPpsRateLimit, "getAll_rsPpsRateLimitProfile", &out.PPSRateLimit)
	addProfiles(&tasks, want, "connectionlimit", s, soap.SecurityConnectionLimit, "getAll_Profile", &out.ConnectionLimit)

	if err := s.gather(ctx, tasks...); err != nil {
		return nil, err
	}
	return out, nil
}

// GetBehavioral devuelve las protecciones de comportamiento (BDoS y DNS): estado
// global, políticas con sus perfiles, tráfico de puertos excluidos y los
// ataques de esas categorías del log. f.Categories vacío = categorías
// behavioral. Con f.Policies, todo se limita a esas políticas y sus perfiles.
func (s *DefenseProService) GetBehavioral(ctx context.Context, withBypass bool, f models.AttackFilter) (*models.Behavioral, error) {
	out := &models.Behavioral{
		Policies:             []models.BehavioralPolicy{},
		BDoS:                 models.BehavioralBDoS{Profiles: []models.BDoSProfile{}},
		DNS:                  models.BehavioralDNS{Profiles: []models.DNSProfile{}},
		ExcludedPortsTraffic: []models.ExcludedPortsTraffic{},
	}
	var log []models.Attack
	var policies []models.Policy
	tasks := []task{
		s.scalar(soap.SecurityBehavioralDoS, "get_Status", configTTL, &out.BDoS.Status),
		table(s, soap.SecurityPolicy, "getAll_Policy", configTTL, &policies),
		s.scalar(soap.SecurityBehavioralDoS, "get_LearningResponsePeriod", configTTL, &out.BDoS.LearningResponsePeriod),
		s.scalar(soap.SecurityBehavioralDoS, "get_overBlockingStatus", configTTL, &out.BDoS.OverBlocking),
		s.scalar(soap.SecurityBehavioralDoS, "get_SamplingStatus", configTTL, &out.BDoS.Sampling),
		table(s, soap.SecurityBehavioralDoS, "getAll_Profiles", configTTL, &out.BDoS.Profiles),
		s.scalar(soap.SecurityDnsProtection, "get_DnsProtectionGlobalStatus", configTTL, &out.DNS.Status),
		s.scalar(soap.SecurityDnsProtection, "get_DnsProtectionLearningResponsePeriod", configTTL, &out.DNS.LearningResponsePeriod),
		table(s, soap.SecurityDnsProtection, "getAll_DnsProtectionProfile", configTTL, &out.DNS.Profiles),
		table(s, soap.SecurityBdosExcludedStats, "getAll_rsBdosExcludedStatisticsTableEntry", statsTTL, &out.ExcludedPortsTraffic),
		table(s, soap.SecurityReporting, "getAll_Log", attacksTTL, &log),
	}
	if withBypass {
		out.BDoS.Bypass = &[]models.BDoSBypass{}
		tasks = append(tasks, table(s, soap.SecurityBehavioralDoS, "getAll_rsNetFloodBypassEntry", configTTL, out.BDoS.Bypass))
	}
	if err := s.gather(ctx, tasks...); err != nil {
		return nil, err
	}

	filterBehavioral(out, policies, toSet(f.Policies))

	if len(f.Categories) == 0 {
		f.Categories = behavioralCategories
	}
	attacks := buildAttacks(log, f)
	out.AttackSummary = attacks.Summary
	out.Attacks = attacks.Attacks
	return out, nil
}

// GetAnalytics arma la vista de network analytics: tráfico actual, utilización
// por política (de mayor a menor) y agregados del log de seguridad.
func (s *DefenseProService) GetAnalytics(ctx context.Context, f models.AttackFilter, top int) (*models.Analytics, error) {
	out := &models.Analytics{PortTraffic: []models.PortTraffic{}, PolicyUtilization: []models.PolicyUtil{}}
	var log []models.Attack
	err := s.gather(ctx,
		s.scalar(soap.DeviceStatistics, "get_TotalLastSecMbits", statsTTL, &out.Traffic.LastSecondMbits),
		s.scalar(soap.DeviceHardwareInfo, "get_TotalLastSecPeak", statsTTL, &out.Traffic.PeakBps),
		table(s, soap.DeviceStatistics, "getAll_PortLastSec", statsTTL, &out.PortTraffic),
		table(s, soap.SecurityPolicyUtil, "getAll_PolicyUtil", statsTTL, &out.PolicyUtilization),
		table(s, soap.SecurityReporting, "getAll_Log", attacksTTL, &log),
	)
	if err != nil {
		return nil, err
	}
	out.Traffic.SetPeakMbps()

	if policies := toSet(f.Policies); policies != nil {
		out.PolicyUtilization = slices.DeleteFunc(out.PolicyUtilization, func(u models.PolicyUtil) bool {
			return !matches(policies, u.Name)
		})
	}
	slices.SortStableFunc(out.PolicyUtilization, func(a, b models.PolicyUtil) int {
		return cmp.Or(cmp.Compare(b.Utilization, a.Utilization), cmp.Compare(a.Name, b.Name))
	})

	out.Attacks = analyzeAttacks(log, f, top)
	return out, nil
}

// filterBehavioral arma la lista de políticas behavioral y, si hay filtro de
// política, deja sólo sus perfiles BDoS/DNS y su tráfico de puertos excluidos.
func filterBehavioral(out *models.Behavioral, policies []models.Policy, selected map[string]bool) {
	bdos, dns := map[string]bool{}, map[string]bool{}
	for _, p := range policies {
		if p.BehavioralDosProfile == "" && p.DNSProtectionProfile == "" {
			continue
		}
		if !matches(selected, p.Name) {
			continue
		}
		out.Policies = append(out.Policies, models.BehavioralPolicy{
			Name:        p.Name,
			State:       p.State,
			Action:      p.Action,
			BDoSProfile: p.BehavioralDosProfile,
			DNSProfile:  p.DNSProtectionProfile,
		})
		bdos[p.BehavioralDosProfile] = true
		dns[p.DNSProtectionProfile] = true
	}
	if selected == nil {
		return
	}
	out.BDoS.Profiles = slices.DeleteFunc(out.BDoS.Profiles, func(p models.BDoSProfile) bool { return !bdos[p.Name] })
	out.DNS.Profiles = slices.DeleteFunc(out.DNS.Profiles, func(p models.DNSProfile) bool { return !dns[p.Name] })
	out.ExcludedPortsTraffic = slices.DeleteFunc(out.ExcludedPortsTraffic, func(e models.ExcludedPortsTraffic) bool {
		return !matches(selected, e.PolicyName)
	})
}
