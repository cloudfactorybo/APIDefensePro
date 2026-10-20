package service

import (
	"context"
	"testing"
)

func TestGetNetworksGroupsActive(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Classes.Networks#getAll_ActiveNetwork": tbl(
			"<Name>FW_FTD_VPN</Name><Index>1</Index><Address>143.0.101.40</Address><Mask>255.255.255.255</Mask>",
			"<Name>DNS</Name><Index>2</Index><Address>143.0.101.22</Address><Mask>255.255.255.255</Mask>",
			"<Name>DNS</Name><Index>1</Index><Address>143.0.101.21</Address><Mask>255.255.255.255</Mask>",
		),
		"Classes.Networks#getAll_Network": noSuchInstance,
	})

	out, err := s.GetNetworks(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Source != "active" || len(out.Networks) != 2 || out.Networks[0].Name != "DNS" {
		t.Fatalf("out = %+v", out)
	}
	if e := out.Networks[0].Entries; len(e) != 2 || e[0].Address != "143.0.101.21" {
		t.Errorf("entradas de DNS ordenadas por índice = %+v", e)
	}

	only, err := s.GetNetworks(context.Background(), []string{"fw_ftd_vpn"})
	if err != nil || len(only.Networks) != 1 || only.Networks[0].Name != "FW_FTD_VPN" {
		t.Errorf("filtro por nombre = %+v, %v", only, err)
	}
}

func TestGetNetworksFallsBackToConfigured(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Classes.Networks#getAll_ActiveNetwork": noSuchInstance,
		"Classes.Networks#getAll_Network":       tbl("<Name>WWW</Name><Index>1</Index><Address>10.0.0.1</Address><Mask>32</Mask>"),
	})
	out, err := s.GetNetworks(context.Background(), nil)
	if err != nil || out.Source != "configured" || len(out.Networks) != 1 {
		t.Errorf("out = %+v, %v", out, err)
	}
}

func TestGetAccessListsAndGeo(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Security.AccessLists#getAll_BlackList": tbl(
			"<Name>dyn_1</Name><Srcnetwork>1.2.3.4</Srcnetwork><State>active</State><DynamicState>Yes</DynamicState><ExpirationHour>1</ExpirationHour><ExpirationMinute>30</ExpirationMinute>",
		),
		"Security.AccessLists#getAll_WhiteList":                     noSuchInstance,
		"Security.GeoPolicyDynamicRule#getAll_GeoPolicyDynamicRule": tbl("<PolicyName>Pol_WWW</PolicyName><GeolocationCode>CN</GeolocationCode><Duration>3600</Duration>"),
	})

	al, err := s.GetAccessLists(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(al.BlockList) != 1 || al.BlockList[0].Dynamic != "Yes" || al.BlockList[0].ExpirationMinute != 30 || al.AllowList == nil {
		t.Errorf("access lists = %+v", al)
	}

	geo, err := s.GetGeo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(geo.DynamicRules) != 1 || geo.DynamicRules[0].GeolocationCode != "CN" || geo.TemporaryRules == nil {
		t.Errorf("geo = %+v", geo)
	}
}

func TestGetCapacity(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Device.SessionTable#get_UsedEntriesNumber":                           val("250000"),
		"Device.Tuning#get_SessionsCurrent":                                   val("1000000"),
		"Security.SuspendTable#get_SuspendTableEntries":                       val("3"),
		"Security.Tuning#get_SuspendTableCurrent":                             val("100000"),
		"Security.AuthenticationTables#get_TcpAuthenticationTableUtilization": val("12"),
		"Security.Tuning#get_TcpAuthenticationTableSize":                      val("512000"),
		"Device.SessionTable#get_Status":                                      val("Disabled"),
		"Security.Policy#getAll_Policy":                                       tbl("<PolicyName>Pol_DNS</PolicyName>", "<PolicyName>Pol_APP</PolicyName>"),
		"Security.Policy#get_TotalPolicyNum":                                  val("0"),
		"Security.Tuning#get_BDosPoliciesCurrent":                             val("128"),
	})

	out, err := s.GetCapacity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.SessionTable.Used == nil || *out.SessionTable.Used != 250000 || out.SessionTable.UtilizationPercent != 25 {
		t.Errorf("session table = %+v", out.SessionTable)
	}
	if out.SuspendTable.UtilizationPercent != 0 || *out.SuspendTable.Used != 3 {
		t.Errorf("suspend table = %+v", out.SuspendTable)
	}
	if out.TCPAuthentication.UtilizationPercent != 12 || out.TCPAuthentication.Used != nil || out.TCPAuthentication.Capacity != 512000 {
		t.Errorf("tcp auth = %+v", out.TCPAuthentication)
	}
	if out.SessionTable.Status != "Disabled" {
		t.Errorf("session status = %q", out.SessionTable.Status)
	}
	if out.Policies.MaxBDoSPolicies != 128 || out.Policies.Configured != 2 || out.Policies.Total != 0 {
		t.Errorf("policies = %+v", out.Policies)
	}
}

func TestGetManagement(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Management.Web#get_WebMngStatus":   val("disable"),
		"Management.Telnet#get_Status":      val("enable"),
		"Management.Services#get_NtpStatus": val("enable"),
		"Management.SyslogServers#getAll_SyslogServersTable": tbl(
			"<syslogServerAddress>10.5.12.10</syslogServerAddress><syslogServerOperationalStatus>Enabled</syslogServerOperationalStatus><syslogSecuritySending>Disabled</syslogSecuritySending><syslogServerDestinationPort>514</syslogServerDestinationPort>",
		),
	})

	out, err := s.GetManagement(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Access.HTTPStatus != "disable" || out.Access.TelnetStatus != "enable" || out.NTP.Status != "enable" {
		t.Errorf("access = %+v ntp = %+v", out.Access, out.NTP)
	}
	if len(out.Syslog.Servers) != 1 || out.Syslog.Servers[0].SecurityEvents != "Disabled" || out.Syslog.Servers[0].DestinationPort != 514 {
		t.Errorf("syslog = %+v", out.Syslog)
	}

}
