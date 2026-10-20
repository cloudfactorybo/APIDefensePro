package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"defensepro-api/internal/models"
	"defensepro-api/internal/snmp"
)

// fakeSNMP simula un agente: walks por raíz y gets por OID.
type fakeSNMP struct {
	walks map[string][]snmp.PDU
	gets  map[string]snmp.PDU
	calls int
}

func (f *fakeSNMP) Walk(_ context.Context, root string) ([]snmp.PDU, error) {
	f.calls++
	if !snmp.Allowed(root) {
		return nil, errors.New("fuera de allowlist")
	}
	return f.walks[root], nil
}

func (f *fakeSNMP) Get(_ context.Context, oids []string) (map[string]snmp.PDU, error) {
	f.calls++
	out := map[string]snmp.PDU{}
	for _, o := range oids {
		if p, ok := f.gets[o]; ok {
			out[o] = p
		}
	}
	return out, nil
}

func strIdx(s string) string {
	parts := []string{strconv.Itoa(len(s))}
	for _, b := range []byte(s) {
		parts = append(parts, strconv.Itoa(int(b)))
	}
	return strings.Join(parts, ".")
}

func u(oid string, v uint64) snmp.PDU { return snmp.PDU{OID: oid, Kind: snmp.KindUint, Uint: v} }
func i(oid string, v int64) snmp.PDU  { return snmp.PDU{OID: oid, Kind: snmp.KindInt, Int: v} }
func s(oid, v string) snmp.PDU        { return snmp.PDU{OID: oid, Kind: snmp.KindString, Str: v} }

// policyRow arma las columnas 2..7 de rsTrafficUtilizationPerPolicyTable<proto>.
func policyRow(proto int, name string, newConn int64, dropPkt, dropBytes, rxPkt, rxBytes uint64) []snmp.PDU {
	base := oidTrafficPolicy + "." + strconv.Itoa(proto) + ".1."
	idx := "." + strIdx(name)
	return []snmp.PDU{
		s(base+"1"+idx, name),
		i(base+"2"+idx, newConn),
		i(base+"3"+idx, 0), // obsoleta
		u(base+"4"+idx, dropPkt), u(base+"5"+idx, dropBytes),
		u(base+"6"+idx, rxPkt), u(base+"7"+idx, rxBytes),
	}
}

func newSNMPService(f *fakeSNMP, limits Limits) *DefenseProService {
	svc := NewDefenseProService("dp1", "http://127.0.0.1:1", "u", "p", nil, quietLogger(), nil, limits)
	svc.SetSNMP(f)
	return svc
}

func TestGetTrafficPolicies(t *testing.T) {
	var pdus []snmp.PDU
	pdus = append(pdus, policyRow(2, "Pol_WWW", 646, 0, 0, 1639, 204566)...)
	pdus = append(pdus, policyRow(2, "Pol_Riof", 43, 0, 0, 47, 15000)...)
	pdus = append(pdus, policyRow(1, "Pol_DNS", 111, 0, 0, 7, 663)...)
	pdus = append(pdus, policyRow(1, "Pol_WWW", 0, 2, 120, 10, 1000)...)
	pdus = append(pdus, policyRow(2, "Pol_EEB", 0, 0, 0, 0, 0)...) // inactiva
	svc := newSNMPService(&fakeSNMP{walks: map[string][]snmp.PDU{oidTrafficPolicy: pdus}}, Limits{MaxConcurrency: 1})

	out, err := svc.GetTrafficPolicies(context.Background(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Policies) != 3 {
		t.Fatalf("sin include_idle deben quedar 3 políticas: %+v", out.Policies)
	}
	www := out.Policies[0] // la de más bytes primero
	tcp := www.Protocols["tcp"]
	if www.Policy != "Pol_WWW" || tcp.NewConnections != 646 || tcp.ReceivedPps != 1639 || tcp.ReceivedBytesPerSec != 204566 {
		t.Errorf("Pol_WWW tcp = %+v", tcp)
	}
	if tcp.ReceivedMbps != 1.637 { // 204566*8/1e6 = 1.636528
		t.Errorf("receivedMbps = %v", tcp.ReceivedMbps)
	}
	if www.Total.ReceivedPps != 1649 || www.Total.DroppedPps != 2 || www.Total.NewConnections != 646 {
		t.Errorf("total = %+v", www.Total)
	}
	if out.Policies[2].Policy != "Pol_DNS" || out.Policies[2].Protocols["udp"].NewConnections != 111 {
		t.Errorf("Pol_DNS = %+v", out.Policies[2])
	}

	all, _ := svc.GetTrafficPolicies(context.Background(), nil, true)
	if len(all.Policies) != 4 {
		t.Errorf("con include_idle = %d políticas", len(all.Policies))
	}
	one, _ := svc.GetTrafficPolicies(context.Background(), []string{"pol_dns"}, false)
	if len(one.Policies) != 1 || one.Policies[0].Policy != "Pol_DNS" {
		t.Errorf("filtro = %+v", one.Policies)
	}
}

func TestGetTrafficPorts(t *testing.T) {
	tcpPort := oidTrafficPort + ".2.1."
	f := &fakeSNMP{
		walks: map[string][]snmp.PDU{
			oidTrafficPort: {
				u(tcpPort+"4.8", 3608), u(tcpPort+"5.8", 4719187), u(tcpPort+"6.8", 3), u(tcpPort+"7.8", 300),
				u(tcpPort+"4.9", 0), u(tcpPort+"5.9", 0), // puerto 9 inactivo
			},
			oidPortStats: {
				i(oidPortStats+".1.3.8", 2772), i(oidPortStats+".1.7.8", 1279),
				i(oidPortStats+".1.10.8", 28), i(oidPortStats+".1.11.8", 1),
				i(oidPortStats+".1.2.8", 999), // obsoleta: no se publica
			},
		},
		gets: map[string]snmp.PDU{oidPortTotalIn: i(oidPortTotalIn, 30)},
	}
	out, err := newSNMPService(f, Limits{MaxConcurrency: 1}).GetTrafficPorts(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if out.TotalInMbps != 30 || len(out.Ports) != 1 {
		t.Fatalf("out = %+v", out)
	}
	p := out.Ports[0]
	if p.Port != 8 || p.InPps != 2772 || p.OutPps != 1279 || p.InMbps != 28 || p.OutMbps != 1 {
		t.Errorf("port stats = %+v", p)
	}
	if tcp := p.Protocols["tcp"]; tcp.ReceivedPps != 3608 || tcp.ReceivedBytesPerSec != 4719187 || tcp.ExcludedPps != 3 {
		t.Errorf("tcp = %+v", tcp)
	}
}

func TestGetSessions(t *testing.T) {
	f := &fakeSNMP{
		gets: map[string]snmp.PDU{
			oidConcTCP: i(oidConcTCP, 373), oidConcUDP: i(oidConcUDP, 1038), oidSessionsUsed: i(oidSessionsUsed, 2326),
		},
		walks: map[string][]snmp.PDU{oidSessionsEng: {
			i(oidSessionsEng+".1.1.2", 2), i(oidSessionsEng+".1.2.2", 933), // col 1 = id, col 2 = usadas
			i(oidSessionsEng+".1.2.1", 727), i(oidSessionsEng+".1.2.3", 669),
		}},
	}
	out, err := newSNMPService(f, Limits{MaxConcurrency: 1}).GetSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.ConcurrentTCP != 373 || out.ConcurrentUDP != 1038 || out.SessionTableUsed != 2326 {
		t.Errorf("sessions = %+v", out)
	}
	if len(out.PerEngine) != 3 || out.PerEngine[0].Used != 727 || out.PerEngine[1].Used != 933 || out.PerEngine[2].Used != 669 {
		t.Errorf("perEngine = %+v", out.PerEngine)
	}
}

func TestGetSynTriggers(t *testing.T) {
	entry := oidSynActivation + ".1."
	totalIdx := "3." + strings.Repeat("0.", 16) + "65535.0"
	trigIdx := "1." + strings.Repeat("0.", 12) + "143.0.101.21.443.5"
	f := &fakeSNMP{walks: map[string][]snmp.PDU{oidSynActivation: {
		i(entry+"5."+totalIdx, 2541),
		i(entry+"5."+trigIdx, 30), i(entry+"6."+trigIdx, 5000), s(entry+"10."+trigIdx, "150000"), s(entry+"11."+trigIdx, "120000"),
	}}}
	out, err := newSNMPService(f, Limits{MaxConcurrency: 1}).GetSynTriggers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Total == nil || out.Total.ActiveSeconds != 2541 || out.Total.Type != "synProtectionTotal" {
		t.Errorf("total = %+v", out.Total)
	}
	if len(out.Triggers) != 1 {
		t.Fatalf("triggers = %+v", out.Triggers)
	}
	tr := out.Triggers[0]
	if tr.Type != "synProtectionTrigger" || tr.DestinationIP != "143.0.101.21" || tr.DestinationPort != 443 || tr.RxPort != 5 ||
		tr.LastSecSYN != 5000 || tr.TotalSYN != 150000 || tr.TotalDropped != 120000 {
		t.Errorf("trigger = %+v", tr)
	}
}

func TestGetDeviceHealth(t *testing.T) {
	g := func(oid string, v int64) snmp.PDU { return i(oidWSD+oid, v) }
	f := &fakeSNMP{
		gets: map[string]snmp.PDU{
			oidWSD + "53.0": g("53.0", 4), oidWSD + "216.0": g("216.0", 61),
			oidWSD + "154.0":    g("154.0", 1),
			oidWSD + "69.6.4.0": g("69.6.4.0", 3), oidWSD + "69.6.1.0": g("69.6.1.0", 3),
			oidWSD + "116.10.10.0": g("116.10.10.0", 1),
			oidWSD + "65.185.2.0":  g("65.185.2.0", 1),
			oidWSD + "69.3.0":      s(oidWSD+"69.3.0", "10:00:00"),
			oidWSD + "69.4.0":      s(oidWSD+"69.4.0", "21/10/2026"),
		},
		walks: map[string][]snmp.PDU{
			oidSyslogServers: {
				i(oidSyslogServers+".1.2."+strIdx("10.5.12.57"), 1),
				i(oidSyslogServers+".1.9."+strIdx("10.5.12.57"), 3),
				i(oidSyslogServers+".1.10."+strIdx("10.5.12.57"), 12),
				i(oidSyslogServers+".1.11."+strIdx("10.5.12.57"), 1),
			},
			oidAccelerator: {i(oidAccelerator+".1.3.1", 1), i(oidAccelerator+".1.6.1", 100)},
		},
	}
	out, err := newSNMPService(f, Limits{MaxConcurrency: 1}).GetDeviceHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.CPU.ResourceUtilization != 4 || out.Memory.UtilizationPercent != 61 || out.Temperature.CPU1Status != "normal" {
		t.Errorf("cpu/mem/temp = %+v %+v %+v", out.CPU, out.Memory, out.Temperature)
	}
	// rdwrPowerSupplyStatus 3 = doublePowerSupplyOk (no "invalid": es otro enum).
	if out.PowerSupply.Overall != "doublePowerSupplyOk" || out.PowerSupply.Supply1 != "invalid" {
		t.Errorf("psu = %+v", out.PowerSupply)
	}
	if out.HighAvailability.ProtectionState != "active" || out.ErtFeedStatus != "noLicense" {
		t.Errorf("ha/ert = %+v %q", out.HighAvailability, out.ErtFeedStatus)
	}
	if out.Clock.OffsetSeconds == nil {
		t.Error("clock offset no calculado")
	}
	if len(out.SyslogServers) != 1 || out.SyslogServers[0].Address != "10.5.12.57" || out.SyslogServers[0].Connection != "unreachable" ||
		out.SyslogServers[0].BackloggedLogs != 12 || out.SyslogServers[0].SecurityEvents != "enable" {
		t.Errorf("syslog = %+v", out.SyslogServers)
	}
	if len(out.Accelerator) != 1 || out.Accelerator[0].IdlePercent != 100 {
		t.Errorf("accelerator = %+v", out.Accelerator)
	}
}

func TestClockOffset(t *testing.T) {
	now := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	if off := clockOffset("21/10/2026", "14:00:05", now); off == nil || *off != 4*3600+5 {
		t.Errorf("offset = %v", off)
	}
	if clockOffset("2026-10-21", "x", now) != nil {
		t.Error("fecha inválida debe dar nil")
	}
}

func TestNoSNMPConfigured(t *testing.T) {
	svc := NewDefenseProService("dp1", "http://127.0.0.1:1", "u", "p", nil, quietLogger(), nil, Limits{MaxConcurrency: 1})
	if _, err := svc.GetSessions(context.Background()); !errors.Is(err, errNoSNMP) {
		t.Errorf("err = %v, want errNoSNMP", err)
	}
}

// Con CPU sobre el umbral, las consultas pesadas no tocan el equipo.
func TestBusyGuard(t *testing.T) {
	f := &fakeSNMP{gets: map[string]snmp.PDU{oidResourceUtil: i(oidResourceUtil, 90)}}
	svc := newSNMPService(f, Limits{MaxConcurrency: 1, BusyCPUPercent: 85})
	_, err := svc.GetAttacks(context.Background(), models.AttackFilter{})
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	if f.calls != 1 {
		t.Errorf("llamadas = %d: sólo debió leer la CPU", f.calls)
	}

	f.gets[oidResourceUtil] = i(oidResourceUtil, 20)
	f.calls = 0
	if err := svc.checkBusy(context.Background()); err != nil {
		t.Errorf("con CPU 20%% no debe frenar: %v", err)
	}
}
