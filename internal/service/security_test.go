package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"defensepro-api/internal/models"
)

const noSuchInstance = "FAULT:NoSuchInstanceException: while processing request - the entry does not exist. "

func TestEmptyTableFaultIsEmptyNotError(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Security.SuspendTable#getAll_NewerSuspend": noSuchInstance,
	})
	out, err := s.GetSuspended(context.Background())
	if err != nil {
		t.Fatalf("una tabla vacía no debe marcar el equipo como caído: %v", err)
	}
	if out.Total != 0 || out.Entries == nil {
		t.Errorf("out = %+v", out)
	}
}

func TestGetProfilesTypeFilter(t *testing.T) {
	s, fake := newTestService(t, map[string]string{
		"Security.BehavioralDoS#getAll_Profiles": tbl(
			"<ProfileName>BDOS_APP</ProfileName><profileAction>Block and Report</profileAction><BandwidthIn>10000</BandwidthIn><TcpInQuota>75</TcpInQuota><UdpInQuota>50</UdpInQuota><rateLimit>Limit to Suspect Edge</rateLimit><MaxAttackEdgeFactor>3.0</MaxAttackEdgeFactor>",
		),
		"Security.DnsProtection#getAll_DnsProtectionProfile": tbl(
			"<ProfileName>DNS_Prof</ProfileName><Action>Block and Report</Action><ExpectedQps>8000</ExpectedQps><MaxAllowedQPS>12000</MaxAllowedQPS><DnsAFloodstatus>active</DnsAFloodstatus>",
		),
	})

	out, err := s.GetProfiles(context.Background(), []string{"bdos", "dns"})
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls.Load() != 2 {
		t.Errorf("con ?type=bdos,dns debió hacer 2 llamadas, hizo %d", fake.calls.Load())
	}
	if out.BDoS == nil || len(*out.BDoS) != 1 || out.DNS == nil || out.SYN != nil {
		t.Fatalf("out = %+v", out)
	}
	b := (*out.BDoS)[0]
	if b.Quotas.TCPIn != 75 || b.Quotas.UDPIn != 50 || b.RateLimit != "Limit to Suspect Edge" || b.MaxAttackEdgeFactor != "3.0" {
		t.Errorf("bdos = %+v", b)
	}
	if d := (*out.DNS)[0]; d.ExpectedQPS != 8000 || d.MaxAllowedQPS != 12000 || d.AFlood != "active" {
		t.Errorf("dns = %+v", d)
	}

	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), `"syn"`) || !strings.Contains(string(raw), `"quotas":{"tcpInQuota":75`) {
		t.Errorf("JSON = %s", raw)
	}
}

func TestGetBehavioral(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Security.BehavioralDoS#get_Status":                 val("enable"),
		"Security.BehavioralDoS#get_LearningResponsePeriod": val("week"),
		"Security.BehavioralDoS#getAll_Profiles":            tbl("<ProfileName>BDOS_APP</ProfileName>"),
		"Security.bdosExcludedStatistics#getAll_rsBdosExcludedStatisticsTableEntry": tbl(
			"<PolicyName>Pol_APP</PolicyName><LastSecondbps>1200</LastSecondbps><LastDaybpsPeak>99000</LastDaybpsPeak>",
		),
		"Security.Reporting#getAll_Log": tbl(
			"<AttackIndex>7</AttackIndex><AttackName>network flood IPv4 UDP</AttackName><Category>behavioral-doS</Category><MessageType>ongoing</MessageType><Risk>high</Risk>",
			"<AttackIndex>8</AttackIndex><AttackName>SYN Flood HTTPS</AttackName><Category>syn-flood</Category><MessageType>terminated</MessageType><Risk>medium</Risk>",
		),
	})

	out, err := s.GetBehavioral(context.Background(), false, models.AttackFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if out.BDoS.Status != "enable" || out.BDoS.LearningResponsePeriod != "week" || len(out.BDoS.Profiles) != 1 || out.BDoS.Bypass != nil {
		t.Errorf("bdos = %+v", out.BDoS)
	}
	if len(out.ExcludedPortsTraffic) != 1 || out.ExcludedPortsTraffic[0].LastSecondBps != 1200 || out.ExcludedPortsTraffic[0].LastDayBpsPeak != 99000 {
		t.Errorf("excluded = %+v", out.ExcludedPortsTraffic)
	}
	if out.AttackSummary.Total != 1 || out.Attacks[0].Category != "behavioral-doS" {
		t.Errorf("sólo deben quedar ataques behavioral: %+v", out.Attacks)
	}
	if out.DNS.Profiles == nil {
		t.Error("DNS sin perfiles debe ser [] y no null")
	}
}

func TestAnalyzeAttacks(t *testing.T) {
	entries := []models.Attack{
		{Index: 3, Time: "08-06-2024 10:00:00", Name: "SYN Flood HTTPS", Protocol: "TCP", DestinationAddress: "10.0.0.1", DestinationPort: 443, PolicyName: "Pol_WWW", Category: "syn-flood", PacketCount: 10, ByteCount: 1000},
		{Index: 1, Time: "07-06-2024 12:53:52", Name: "SYN Flood HTTPS", Protocol: "TCP", DestinationAddress: "10.0.0.1", DestinationPort: 443, PolicyName: "Pol_WWW", Category: "syn-flood", PacketCount: 5, ByteCount: 500},
		{Index: 2, Time: "07-06-2024 13:00:00", Name: "UDP Flood", Protocol: "UDP", DestinationAddress: "10.0.0.2", PolicyName: "Pol_DNS", Category: "behavioral-doS", SourceAddress: "1.2.3.4"},
	}

	a := analyzeAttacks(entries, models.AttackFilter{}, 10)
	if a.TotalEntries != 3 || a.TotalPackets != 15 || a.TotalBytes != 1500 {
		t.Errorf("totales = %+v", a)
	}
	if a.OldestTime != "07-06-2024 12:53:52" || a.NewestTime != "08-06-2024 10:00:00" {
		t.Errorf("rango = %q .. %q", a.OldestTime, a.NewestTime)
	}
	if a.TopAttacks[0].Key != "SYN Flood HTTPS" || a.TopAttacks[0].Count != 2 || a.TopAttacks[0].Packets != 15 {
		t.Errorf("topAttacks = %+v", a.TopAttacks)
	}
	if len(a.TopDestinationPorts) != 1 || a.TopDestinationPorts[0].Key != "TCP/443" {
		t.Errorf("puertos sin 0 = %+v", a.TopDestinationPorts)
	}
	if len(a.TopSources) != 1 || a.TopSources[0].Key != "1.2.3.4" {
		t.Errorf("orígenes vacíos no cuentan: %+v", a.TopSources)
	}

	one := analyzeAttacks(entries, models.AttackFilter{Policies: []string{"pol_dns"}}, 1)
	if one.TotalEntries != 1 || len(one.TopPolicies) != 1 || one.TopPolicies[0].Key != "Pol_DNS" {
		t.Errorf("filtro por política = %+v", one)
	}
}
