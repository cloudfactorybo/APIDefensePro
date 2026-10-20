package service

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Los fixtures reproducen la salida real de un DefensePro 8.34, incluida la
// basura no-ASCII de los bordes de tabla ("ï¿½", "Â³").
func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseBDoSStats(t *testing.T) {
	text := readFixture(t, "bdos_stats.txt")

	app := parseBDoSStats(text, "Pol_APP")
	if app == nil {
		t.Fatal("Pol_APP no encontrada")
	}
	if app.PolicyType != "From-To" || app.BandwidthInKbps != 10000 || app.BandwidthOutKbps != 10000 {
		t.Errorf("cabecera = %+v", app)
	}

	in4 := app.Inbound.IPv4
	if len(in4.Protocols) != 12 {
		t.Fatalf("protocolos inbound IPv4 = %d, want 12: %+v", len(in4.Protocols), in4.Protocols)
	}
	tcp := in4.Protocols[1]
	if tcp.Protocol != "TCP" || tcp.BaselineBps != 287981 || tcp.BaselinePps != 960 || tcp.CurrentBps != 44 || tcp.CurrentPps != 1 {
		t.Errorf("TCP = %+v", tcp)
	}
	if in4.Protocols[3].Protocol != "UDP Frag" || in4.Protocols[10].Protocol != "TCP Syn-Ack" {
		t.Errorf("etiquetas con espacios = %q, %q", in4.Protocols[3].Protocol, in4.Protocols[10].Protocol)
	}
	if in4.LearningState != "Learning" || in4.ConfiguredState != "Disabled" || in4.Anomaly {
		t.Errorf("estado = %+v", in4)
	}
	if in4.AdvancedUDP == nil || in4.AdvancedUDP.BaselineBps != 255997 || in4.AdvancedUDP.BaselinePps != 731 {
		t.Errorf("advanced UDP = %+v", in4.AdvancedUDP)
	}
	if len(app.Inbound.IPv6.Protocols) != 2 || len(app.Outbound.IPv4.Protocols) != 2 || app.Outbound.IPv4.Protocols[1].CurrentBps != 40 {
		t.Errorf("secciones IPv6/outbound mal asignadas: in6=%+v out4=%+v", app.Inbound.IPv6.Protocols, app.Outbound.IPv4.Protocols)
	}

	bib := parseBDoSStats(text, "pol_biblioteca")
	if bib == nil {
		t.Fatal("Pol_Biblioteca no encontrada")
	}
	udp := bib.Inbound.IPv4.Protocols[0]
	if udp.DroppedBps != 8500000 || udp.LegitimateBps != 500000 || udp.LegitimatePps != 1000 {
		t.Errorf("drop/legítimo = %+v", udp)
	}
	if !bib.Inbound.IPv4.Anomaly || bib.Inbound.IPv4.LearningState != "Learned" {
		t.Errorf("anomaly = %+v", bib.Inbound.IPv4)
	}

	if parseBDoSStats(text, "Pol_Inexistente") != nil {
		t.Error("una política ausente debe devolver nil")
	}
}

func TestParseDNSStats(t *testing.T) {
	dns := parseDNSStats(readFixture(t, "dns_stats.txt"))
	if dns == nil {
		t.Fatal("nil")
	}
	if dns.ExpectedQPS != 8000 || len(dns.IPv4) != 9 || len(dns.IPv6) != 3 {
		t.Fatalf("dns = %+v", dns)
	}
	a, aaaa, txt := dns.IPv4[0], dns.IPv4[3], dns.IPv4[4]
	if a.Type != "A" || a.BaselineQPS != 800 || a.CurrentQPS != 2 || a.LegitimateQPS != 2 {
		t.Errorf("A = %+v", a)
	}
	if aaaa.Type != "AAAA" || aaaa.BaselineQPS != 80 || aaaa.CurrentQPS != 3 {
		t.Errorf("AAAA = %+v", aaaa)
	}
	if txt.Type != "TXT" || dns.IPv4[2].Type != "PTR" || dns.IPv4[8].Type != "OTHER" {
		t.Errorf("tipos = %q %q %q", txt.Type, dns.IPv4[2].Type, dns.IPv4[8].Type)
	}
	if dns.IPv6[0].BaselineQPS != 5400 {
		t.Errorf("IPv6 A = %+v", dns.IPv6[0])
	}
	if parseDNSStats("Error - Usage: ...") != nil {
		t.Error("una salida sin política debe devolver nil")
	}
}

func TestGetBehavioralTraffic(t *testing.T) {
	policies := tbl(
		"<PolicyName>Pol_DNS</PolicyName><BehavioralDosProfile>BDOS_APP</BehavioralDosProfile><DNSProtectionProfile>DNS_Prof</DNSProtectionProfile>",
		"<PolicyName>Pol_APP</PolicyName><BehavioralDosProfile>BDOS_APP</BehavioralDosProfile>",
		"<PolicyName>Pol_SinPerfiles</PolicyName>",
	)
	bdos := readFixture(t, "bdos_stats.txt")
	s, f := newTestService(t, map[string]string{"Security.Policy#getAll_Policy": policies})
	f.cli = map[string]string{
		"system internal security bdos statistics get Pol_APP": bdos,
		"system internal security dns statistics get Pol_DNS":  readFixture(t, "dns_stats.txt"),
		// Pol_DNS no está en el fixture de BDoS: su bloque BDoS debe faltar sin romper DNS.
		"system internal security bdos statistics get Pol_DNS": bdos,
	}

	app, err := s.GetBehavioralTraffic(context.Background(), "pol_app")
	if err != nil {
		t.Fatal(err)
	}
	if app.Policy != "Pol_APP" || app.BDoS == nil || app.BDoS.Profile != "BDOS_APP" || app.DNS != nil {
		t.Errorf("Pol_APP = %+v", app)
	}

	dns, err := s.GetBehavioralTraffic(context.Background(), "Pol_DNS")
	if err != nil {
		t.Fatal(err)
	}
	if dns.DNS == nil || dns.DNS.Profile != "DNS_Prof" || dns.DNS.IPv4[0].BaselineQPS != 800 || dns.BDoS != nil {
		t.Errorf("Pol_DNS = %+v", dns)
	}

	for _, bad := range []string{"Pol_NoExiste", "Pol_APP; reboot", "../etc"} {
		if _, err := s.GetBehavioralTraffic(context.Background(), bad); !errors.Is(err, ErrPolicyNotFound) {
			t.Errorf("%q: err = %v, want ErrPolicyNotFound", bad, err)
		}
	}

	if _, err := s.GetBehavioralTraffic(context.Background(), "Pol_SinPerfiles"); err == nil {
		t.Error("una política sin perfiles behavioral debe dar error")
	}
}
