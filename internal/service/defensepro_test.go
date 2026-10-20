package service

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"

	"defensepro-api/internal/models"
)

var opRe = regexp.MustCompile(`<ns1:(\w+) xmlns:ns1="radware\.([^"]+)">`)

// fakeDP simula un DefensePro: responde cada "Servicio#operación" con las partes
// XML dadas; lo que no está mapeado devuelve un SOAP Fault (como un equipo que
// no soporta la función).
type fakeDP struct {
	parts map[string]string
	cli   map[string]string // comando CLI → salida (CLI.Command apply_CLICommand)
	calls atomic.Int64
}

var cmdRe = regexp.MustCompile(`<command[^>]*>([^<]*)</command>`)

func (f *fakeDP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	body, _ := io.ReadAll(r.Body)
	m := opRe.FindSubmatch(body)
	if m == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	op, svc := string(m[1]), string(m[2])

	w.Header().Set("Content-Type", "text/xml")
	parts, ok := f.parts[svc+"#"+op]
	if op == "apply_CLICommand" {
		cmd := ""
		if m := cmdRe.FindSubmatch(body); m != nil {
			cmd = string(m[1])
		}
		out, found := f.cli[cmd]
		if !found {
			out = "Error - Usage: comando desconocido en el fake: " + cmd
		}
		var esc strings.Builder
		_ = xml.EscapeText(&esc, []byte(out))
		parts, ok = "<output>"+esc.String()+"</output>", true
	}
	if strings.HasPrefix(parts, "FAULT:") {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>SOAP-ENV:Client</faultcode><faultstring>%s</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>`, strings.TrimPrefix(parts, "FAULT:"))
		return
	}
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>SOAP-ENV:Client</faultcode><faultstring>unsupported %s</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>`, op)
		return
	}
	fmt.Fprintf(w, `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><ns1:%sResponse xmlns:ns1="radware.%s">%s</ns1:%sResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>`, op, svc, parts, op)
}

func val(v string) string { return "<value>" + v + "</value>" }

func tbl(rows ...string) string {
	var b strings.Builder
	b.WriteString("<table>")
	for _, r := range rows {
		b.WriteString("<item>" + r + "</item>")
	}
	b.WriteString("</table><status>true</status>")
	return b.String()
}

func quietLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func newTestService(t *testing.T, parts map[string]string) (*DefenseProService, *fakeDP) {
	t.Helper()
	fake := &fakeDP{parts: parts}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return NewDefenseProService("dp1", srv.URL, "u", "p", srv.Client(), quietLogger(), nil, 4), fake
}

func TestGetSystemInfo(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Device.SystemParameters#get_SystemUpTime": val("12 days, 03:10:22"),
		"Device.SystemParameters#get_DeviceName":   val("DP-CORE-1"),
		"Device.Information#get_SoftwareVersion":   val("8.34.2.0"),
		"Device.Information#get_RamSize":           val("65536"),
		"Device.Mitigation#get_Device":             val("Behavioral"),
		"Management.VersionControl#getAll_SoftwareVersion": tbl(
			"<Index>1</Index><Name>img1</Name><Version>8.34.2.0</Version><ActiveStatus>YES</ActiveStatus><Valid>YES</Valid>",
		),
		// get_haProtectionState y el resto no están: Fault → quedan vacíos.
	})

	out, err := s.GetSystemInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.SysName != "DP-CORE-1" || out.SoftwareVersion != "8.34.2.0" || out.RamSizeMB != 65536 ||
		out.MitigationMode != "Behavioral" || out.UpTime != "12 days, 03:10:22" {
		t.Errorf("mapeo incorrecto: %+v", out)
	}
	if out.HAProtectionState != "" {
		t.Errorf("HAProtectionState = %q, want vacío (Fault)", out.HAProtectionState)
	}
	if len(out.InstalledVersions) != 1 || out.InstalledVersions[0].Active != "YES" {
		t.Errorf("InstalledVersions = %+v", out.InstalledVersions)
	}
}

func TestGatherAllFaultsIsError(t *testing.T) {
	s, _ := newTestService(t, map[string]string{})
	if _, err := s.GetLicenses(context.Background()); err == nil {
		t.Fatal("esperaba error cuando todas las lecturas fallan")
	}
}

func TestGatherProbeAbortsOnTransportError(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	s := NewDefenseProService("dp1", srv.URL, "u", "bad", srv.Client(), quietLogger(), nil, 4)
	_, err := s.GetMonitoring(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want auth 401", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("se hicieron %d llamadas; la sonda debió abortar tras la primera", n)
	}
}

func TestGetMonitoringPartial(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Device.Utilization#get_ResourceUtilization":   val("37"),
		"Device.Utilization#get_SysUtilRAMUtilization": val("61"),
		// Valores reales de un DefensePro con la session table deshabilitada.
		"Device.HardwareInfo#get_TotalLastSecPeak": val("2942624205"),
		"Device.SessionTable#get_Status":           val("Disabled"),
		"Device.HardwareInfo#getAll_EngineResource": tbl(
			"<Engine>0</Engine><Forwarding>20</Forwarding><Other>5</Other><Idle>75</Idle><Total>25</Total>",
			"<Engine>1</Engine><Forwarding>30</Forwarding><Other>2</Other><Idle>68</Idle><Total>32</Total>",
		),
	})

	out, err := s.GetMonitoring(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.CPU.ResourceUtilization != 37 || out.Memory.UtilizationPercent != 61 {
		t.Errorf("cpu/mem = %+v / %+v", out.CPU, out.Memory)
	}
	if len(out.Engines) != 2 || out.Engines[1].Total != 32 {
		t.Errorf("engines = %+v", out.Engines)
	}
	if out.Traffic.PeakBps != 2942624205 || out.Traffic.PeakMbps != 2942.62 {
		t.Errorf("traffic = %+v, want peakMbps 2942.62", out.Traffic)
	}
	if out.SessionTable.Status != "Disabled" {
		t.Errorf("sessionTable = %+v", out.SessionTable)
	}
}

func TestGetPoliciesMergeAndFilter(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Security.Policy#getAll_Policy": tbl(
			"<PolicyName>Web</PolicyName><State>active</State><Action>Block and Report</Action><BehavioralDosProfile>bdos-web</BehavioralDosProfile>",
			"<PolicyName>DNS</PolicyName><State>active</State><Action>Report Only</Action>",
		),
		"Security.PolicyUtil#getAll_PolicyUtil": tbl("<PolicyName>Web</PolicyName><PolicyUtil>12</PolicyUtil>"),
		"Security.Policy#getAll_PoliciesResources": tbl(
			"<Name>Web</Name><Direction>inbound</Direction><HwEntriesNum>4</HwEntriesNum><SubPoliciesNum>2</SubPoliciesNum>",
			"<Name>Web</Name><Direction>outbound</Direction><HwEntriesNum>3</HwEntriesNum><SubPoliciesNum>1</SubPoliciesNum>",
		),
		"Security.Policy#get_TotalPolicyNum": val("3"),
	})

	out, err := s.GetPolicies(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.TotalPolicies != 3 || out.ConfiguredPolicies != 2 || len(out.Policies) != 2 {
		t.Fatalf("policies = %+v", out)
	}
	web := out.Policies[0]
	if web.UtilizationPercent == nil || *web.UtilizationPercent != 12 || len(web.Resources) != 2 || web.BehavioralDosProfile != "bdos-web" {
		t.Errorf("merge Web = %+v", web)
	}
	dns := out.Policies[1]
	if dns.UtilizationPercent != nil || dns.Resources == nil {
		t.Errorf("DNS sin util debe tener null y resources [] : %+v", dns)
	}

	filtered, err := s.GetPolicies(context.Background(), []string{"dns"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Policies) != 1 || filtered.Policies[0].Name != "DNS" || filtered.ConfiguredPolicies != 2 {
		t.Errorf("filtro = %+v", filtered.Policies)
	}
}

func TestGetAttacksFromLog(t *testing.T) {
	s, _ := newTestService(t, map[string]string{
		"Security.Reporting#getAll_Log": tbl(
			"<AttackIndex>10</AttackIndex><AttackName>SYN Flood</AttackName><Risk>high</Risk><Category>syn-flood</Category><Action>drop</Action><MessageType>started</MessageType><PolicyName>Web</PolicyName><AttackSourceAddress>1.2.3.4</AttackSourceAddress><DstPort>443</DstPort>",
			"<AttackIndex>11</AttackIndex><AttackName>Scan</AttackName><Risk>low</Risk><Category>scanning</Category><Action>report-only</Action><MessageType>occur</MessageType><PolicyName>DNS</PolicyName>",
		),
	})

	out, err := s.GetAttacks(context.Background(), models.AttackFilter{Risks: []string{"HIGH"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Summary.Total != 1 || len(out.Attacks) != 1 {
		t.Fatalf("attacks = %+v", out)
	}
	a := out.Attacks[0]
	if a.Name != "SYN Flood" || a.SourceAddress != "1.2.3.4" || a.DestinationPort != 443 || a.Type != "started" {
		t.Errorf("mapeo = %+v", a)
	}
}

func TestBuildAttacks(t *testing.T) {
	entries := []models.Attack{
		{Index: 1, Risk: "high", Category: "dos", Action: "drop", Type: "started", PolicyName: "Web"},
		{Index: 3, Risk: "low", Category: "scanning", Action: "report-only", Type: "occur", PolicyName: "Web"},
		{Index: 2, Risk: "high", Category: "dos", Action: "drop", Type: "terminated", PolicyName: "DNS"},
		{Index: 4, Risk: "medium", Category: "dos", Action: "drop", Type: "ongoing", PolicyName: "Web"},
	}

	all := buildAttacks(entries, models.AttackFilter{})
	if all.Summary.Total != 4 || all.Attacks[0].Index != 4 || all.Attacks[3].Index != 1 {
		t.Errorf("orden/total = %+v", all)
	}

	dos := buildAttacks(entries, models.AttackFilter{Categories: []string{"DOS"}, Limit: 2})
	if dos.Summary.Total != 3 || dos.Summary.Returned != 2 || len(dos.Attacks) != 2 {
		t.Errorf("limit: total=%d returned=%d len=%d", dos.Summary.Total, dos.Summary.Returned, len(dos.Attacks))
	}
	if dos.Summary.ByRisk["high"] != 2 || dos.Summary.ByRisk["medium"] != 1 {
		t.Errorf("el resumen debe contar todo lo filtrado, no sólo lo devuelto: %+v", dos.Summary.ByRisk)
	}

	web := buildAttacks(entries, models.AttackFilter{Policies: []string{"web"}, Types: []string{"started", "ongoing"}})
	if web.Summary.Total != 2 {
		t.Errorf("filtro policy+type = %+v", web.Attacks)
	}
}

func TestFanOutAndUnknown(t *testing.T) {
	ok, _ := newTestService(t, map[string]string{
		"Device.HardwareInfo#get_DualPsuStatus": val("doublePwrSupplyOk"),
	})
	bad := NewDefenseProService("dp2", "http://127.0.0.1:1", "u", "p", http.DefaultClient, quietLogger(), nil, 1)

	m := &MultiDefenseProService{logger: quietLogger(), devices: []*Device{
		{Name: "dp1", URL: "https://10.0.0.1", IP: "10.0.0.1", Service: ok},
		{Name: "dp2", URL: "https://10.0.0.2", IP: "10.0.0.2", Service: bad},
	}}

	results, errs := m.GetAllHardware(context.Background(), nil)
	if len(results) != 1 || results[0].DeviceName != "dp1" || results[0].DeviceIP != "10.0.0.1" || results[0].PowerSupply != "doublePwrSupplyOk" {
		t.Errorf("results = %+v", results)
	}
	if len(errs) != 1 || errs[0].Device != "dp2" {
		t.Errorf("errs = %+v", errs)
	}

	// La identidad del equipo va aplanada al nivel de los datos.
	raw, _ := json.Marshal(results[0])
	if !strings.HasPrefix(string(raw), `{"deviceName":"dp1","deviceUrl":"https://10.0.0.1","deviceIp":"10.0.0.1","cpuTemperatures":[]`) {
		t.Errorf("forma JSON = %s", raw)
	}

	only, errs := m.GetAllHardware(context.Background(), []string{"DP1"})
	if len(only) != 1 || len(errs) != 0 {
		t.Errorf("filtro por device: results=%d errs=%d", len(only), len(errs))
	}

	if u := m.Unknown([]string{"dp1", "nope"}); len(u) != 1 || u[0] != "nope" {
		t.Errorf("Unknown = %v", u)
	}
}

func TestExtractIPFromURL(t *testing.T) {
	cases := map[string]string{
		"https://172.31.163.18":      "172.31.163.18",
		"https://172.31.163.18:8443": "172.31.163.18",
		"https://host.local":         "host.local",
		"https://[::1]":              "::1",
		"https://[2001:db8::1]:8443": "2001:db8::1",
		"":                           "",
	}
	for in, want := range cases {
		if got := extractIPFromURL(in); got != want {
			t.Errorf("extractIPFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}
