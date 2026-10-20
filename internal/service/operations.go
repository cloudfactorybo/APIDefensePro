package service

import (
	"cmp"
	"context"
	"math"
	"slices"

	"defensepro-api/internal/models"
	"defensepro-api/internal/soap"
)

// GetNetworks devuelve las clases de red agrupadas por nombre. Usa la tabla
// activa (la que aplican las políticas); si está vacía, la configurada.
func (s *DefenseProService) GetNetworks(ctx context.Context, names []string) (*models.Networks, error) {
	var active, configured []models.NetworkEntry
	err := s.gather(ctx,
		table(s, soap.ClassesNetworks, "getAll_ActiveNetwork", configTTL, &active),
		table(s, soap.ClassesNetworks, "getAll_Network", configTTL, &configured),
	)
	if err != nil {
		return nil, err
	}

	out := &models.Networks{Source: "active"}
	entries := active
	if len(entries) == 0 && len(configured) > 0 {
		out.Source = "configured"
		entries = configured
	}
	out.Networks = groupNetworks(entries, toSet(names))
	return out, nil
}

func groupNetworks(entries []models.NetworkEntry, filter map[string]bool) []models.NetworkClass {
	byName := map[string]int{}
	out := []models.NetworkClass{}
	for _, e := range entries {
		if !matches(filter, e.Name) {
			continue
		}
		i, ok := byName[e.Name]
		if !ok {
			i = len(out)
			byName[e.Name] = i
			out = append(out, models.NetworkClass{Name: e.Name})
		}
		out[i].Entries = append(out[i].Entries, e)
	}
	for i := range out {
		slices.SortFunc(out[i].Entries, func(a, b models.NetworkEntry) int { return cmp.Compare(a.Index, b.Index) })
	}
	slices.SortFunc(out, func(a, b models.NetworkClass) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

func (s *DefenseProService) GetAccessLists(ctx context.Context) (*models.AccessLists, error) {
	out := &models.AccessLists{BlockList: []models.AccessListEntry{}, AllowList: []models.AccessListEntry{}}
	// statsTTL: la lista de bloqueo tiene entradas dinámicas que expiran.
	err := s.gather(ctx,
		table(s, soap.SecurityAccessLists, "getAll_BlackList", statsTTL, &out.BlockList),
		table(s, soap.SecurityAccessLists, "getAll_WhiteList", configTTL, &out.AllowList),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *DefenseProService) GetGeo(ctx context.Context) (*models.Geo, error) {
	out := &models.Geo{
		DynamicRules:   []models.GeoRule{},
		TemporaryRules: []models.GeoRule{},
		Countries:      []models.GeoCountry{},
		ExcludedIPs:    []models.GeoExcludedIP{},
	}
	err := s.gather(ctx,
		table(s, soap.SecurityGeoDynamicRule, "getAll_GeoPolicyDynamicRule", statsTTL, &out.DynamicRules),
		table(s, soap.SecurityGeoTemporaryRule, "getAll_GeoPolicyTemporaryRule", statsTTL, &out.TemporaryRules),
		table(s, soap.SecurityGeoCountries, "getAll_GeoAssocCountriesEntry", configTTL, &out.Countries),
		table(s, soap.SecurityGeoExcludedIPs, "getAll_GeoExcludedIPListEntry", configTTL, &out.ExcludedIPs),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *DefenseProService) GetCapacity(ctx context.Context) (*models.Capacity, error) {
	out := &models.Capacity{}
	var sessionUsed, suspendUsed, tcpAuthUtil, httpAuthUtil int64
	p, l := &out.Policies, &out.Limits
	err := s.gather(ctx,
		s.scalar(soap.DeviceSessionTable, "get_UsedEntriesNumber", statsTTL, &sessionUsed),
		s.scalar(soap.DeviceTuning, "get_SessionsCurrent", staticTTL, &out.SessionTable.Capacity),
		s.scalar(soap.SecuritySuspendTable, "get_SuspendTableEntries", statsTTL, &suspendUsed),
		s.scalar(soap.SecurityTuning, "get_SuspendTableCurrent", staticTTL, &out.SuspendTable.Capacity),
		s.scalar(soap.SecurityAuthTables, "get_TcpAuthenticationTableUtilization", statsTTL, &tcpAuthUtil),
		s.scalar(soap.SecurityTuning, "get_TcpAuthenticationTableSize", staticTTL, &out.TCPAuthentication.Capacity),
		s.scalar(soap.SecurityAuthTables, "get_HttpAuthenticationTableUtilization", statsTTL, &httpAuthUtil),
		s.scalar(soap.SecurityTuning, "get_HttpAuthenticationTableSize", staticTTL, &out.HTTPAuthentication.Capacity),
		s.scalar(soap.SecurityPolicy, "get_TotalPolicyNum", configTTL, &p.Total),
		s.scalar(soap.SecurityTuning, "get_BDosPoliciesCurrent", staticTTL, &p.MaxBDoSPolicies),
		s.scalar(soap.SecurityTuning, "get_DnsPoliciesCurrent", staticTTL, &p.MaxDNSPolicies),
		s.scalar(soap.SecurityPolicy, "get_HwEntriesUtil", statsTTL, &p.HwEntriesUtilization),
		s.scalar(soap.SecurityPolicy, "get_SubPolicyUtil", statsTTL, &p.SubPolicyUtilization),
		s.scalar(soap.SecurityTuning, "get_SourceTableCurrent", staticTTL, &l.SourceTable),
		s.scalar(soap.SecurityTuning, "get_SrcCntrTableCurrent", staticTTL, &l.SourceCounters),
		s.scalar(soap.SecurityTuning, "get_DestCntrTableCurrent", staticTTL, &l.DestinationCounters),
		s.scalar(soap.SecurityTuning, "get_SrcDestCntrTableCurrent", staticTTL, &l.SourceDestCounters),
		s.scalar(soap.SecurityTuning, "get_AntiScanningTableCurrent", staticTTL, &l.AntiScanningTable),
		s.scalar(soap.SecurityTuning, "get_ServerTabTableCurrent", staticTTL, &l.ServerProtectionTable),
		s.scalar(soap.SecurityTuning, "get_HttpfldSuspectSrcIpCurrent", staticTTL, &l.HTTPFloodSuspectSources),
		s.scalar(soap.SecurityTuning, "get_PPSMaxSrcIpCurrent", staticTTL, &l.PPSSuspectSources),
		s.scalar(soap.SecurityTuning, "get_QuarantineMaxIPs", staticTTL, &l.QuarantineIPs),
		s.scalar(soap.SecurityTuning, "get_MaxUserAttacksCurrent", staticTTL, &l.UserDefinedAttacks),
	)
	if err != nil {
		return nil, err
	}

	setUsage(&out.SessionTable, sessionUsed)
	setUsage(&out.SuspendTable, suspendUsed)
	out.TCPAuthentication.UtilizationPercent = float64(tcpAuthUtil)
	out.HTTPAuthentication.UtilizationPercent = float64(httpAuthUtil)
	return out, nil
}

// setUsage completa Used y el % (con 2 decimales) a partir de la capacidad.
func setUsage(t *models.TableUsage, used int64) {
	t.Used = &used
	if t.Capacity > 0 {
		t.UtilizationPercent = math.Round(float64(used)*10000/float64(t.Capacity)) / 100
	}
}

// GetManagement audita la gestión del equipo. Nunca lee secretos (RADIUS,
// TACACS+). La tabla de usuarios trae el campo Password: no se mapea y se pide
// sin cache para que el XML crudo no quede guardado en Redis.
func (s *DefenseProService) GetManagement(ctx context.Context) (*models.Management, error) {
	out := &models.Management{Syslog: models.SyslogStatus{Servers: []models.SyslogServer{}}, Users: []models.ManagementUser{}}
	a, ntp := &out.Access, &out.NTP
	err := s.gather(ctx,
		s.scalar(soap.ManagementWeb, "get_WebMngStatus", configTTL, &a.HTTPStatus),
		s.scalar(soap.ManagementWeb, "get_WebPort", configTTL, &a.HTTPPort),
		s.scalar(soap.ManagementWeb, "get_SecureWebMngStatus", configTTL, &a.HTTPSStatus),
		s.scalar(soap.ManagementWeb, "get_SecureWebPort", configTTL, &a.HTTPSPort),
		s.scalar(soap.ManagementWeb, "get_SslWeakCiphersStatus", configTTL, &a.SSLWeakCiphers),
		s.scalar(soap.ManagementSsh, "get_Status", configTTL, &a.SSHStatus),
		s.scalar(soap.ManagementSsh, "get_ServerPort", configTTL, &a.SSHPort),
		s.scalar(soap.ManagementSsh, "get_SshSessionTimeout", configTTL, &a.SSHSessionTimeout),
		s.scalar(soap.ManagementTelnet, "get_Status", configTTL, &a.TelnetStatus),
		s.scalar(soap.ManagementTelnet, "get_ServerPort", configTTL, &a.TelnetPort),
		s.scalar(soap.ManagementAccess, "get_UserAuthentication", configTTL, &out.UserAuthentication),
		s.scalar(soap.ManagementAccess, "get_RadiusServer", configTTL, &out.RadiusServer),
		s.scalar(soap.ManagementAccess, "get_TacacsMainServerIP", configTTL, &out.TacacsServer),
		s.scalar(soap.ManagementServices, "get_NtpStatus", configTTL, &ntp.Status),
		s.scalar(soap.ManagementServices, "get_NtpServerAddress", configTTL, &ntp.ServerAddress),
		s.scalar(soap.ManagementServices, "get_NtpServerName", configTTL, &ntp.ServerName),
		s.scalar(soap.ManagementServices, "get_NtpServerTime", 0, &ntp.ServerTime),
		s.scalar(soap.ManagementServices, "get_NtpServerOffset", statsTTL, &ntp.OffsetSeconds),
		s.scalar(soap.ManagementServices, "get_NtpTimeZone", configTTL, &ntp.TimeZone),
		s.scalar(soap.ManagementServices, "get_NtpPollingInterval", configTTL, &ntp.PollingInterval),
		s.scalar(soap.DeviceDNSClient, "get_Status", configTTL, &out.DNS.Status),
		s.scalar(soap.DeviceDNSClient, "get_PrimaryServer", configTTL, &out.DNS.Primary),
		s.scalar(soap.DeviceDNSClient, "get_AlternateServer", configTTL, &out.DNS.Alternate),
		s.scalar(soap.ManagementReporting, "get_SyslogGlobalStatus", configTTL, &out.Syslog.GlobalStatus),
		table(s, soap.ManagementSyslogServers, "getAll_SyslogServersTable", configTTL, &out.Syslog.Servers),
		table(s, soap.ManagementAccess, "getAll_User", 0, &out.Users),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}
