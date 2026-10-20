package soap

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const envOpen = `<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><SOAP-ENV:Body>`
const envClose = `</SOAP-ENV:Body></SOAP-ENV:Envelope>`

func TestBuildEnvelope(t *testing.T) {
	got := string(BuildEnvelope(SecurityPolicy, "get_Policy", Param{Name: "PolicyName", Value: "web<&>"}))

	for _, want := range []string{
		`<ns1:get_Policy xmlns:ns1="radware.Security.Policy">`,
		`<PolicyName xsi:type="xsd:string">web&lt;&amp;&gt;</PolicyName>`,
		`</ns1:get_Policy>`,
		`SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("envelope sin %q:\n%s", want, got)
		}
	}
}

func TestDecodeValue(t *testing.T) {
	body := envOpen + `<ns1:get_RamSizeResponse xmlns:ns1="radware.Device.Information"><value xsi:type="xsd:long"> 4096 </value></ns1:get_RamSizeResponse>` + envClose
	resp, err := Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	v, err := resp.Value()
	if err != nil || v != "4096" {
		t.Fatalf("Value() = %q, %v; want 4096", v, err)
	}
}

func TestDecodeISO88591(t *testing.T) {
	// Así responde el DefensePro: declaración ISO-8859-1 y bytes Latin-1 crudos
	// (0xF3 = "ó"), que no son UTF-8 válido.
	body := []byte(`<?xml version="1.0" encoding="ISO-8859-1"?>` +
		`<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>` +
		"<r><value>Gesti\xf3n DP</value></r>" +
		`</SOAP-ENV:Body></SOAP-ENV:Envelope>`)
	resp, err := Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := resp.Value(); v != "Gestión DP" {
		t.Errorf("Value() = %q, want %q", v, "Gestión DP")
	}
}

// Respuesta real de un DefensePro 8.34 (recortada a una fila): xsi de 1999,
// wrapper "_response", <item> y valores en CDATA con espacio final.
func TestDecodeRealDeviceLog(t *testing.T) {
	body := `<?xml version="1.0" encoding="ISO-8859-1"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance" xmlns:xsd="http://www.w3.org/1999/XMLSchema" ><SOAP-ENV:Body><tns:getAll_Log_response xmlns:tns="radware.Security.Reporting" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><table xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xsi:type="SOAP-ENC:Array" SOAP-ENC:arrayType="tns:Log[]"><item><AttackIndex>1</AttackIndex><AttackName>SYN Flood HTTPS</AttackName><AttackSourceAddress>0.0.0.0</AttackSourceAddress><AttackDestinationAddress>143.0.101.21</AttackDestinationAddress><MessageType>terminated</MessageType><AttackTime><![CDATA[07-06-2024 12:53:52 ]]></AttackTime><Context>regular</Context><SrcPort>0</SrcPort><DstPort>443</DstPort><Protocol>TCP</Protocol><PhysicalPort>0</PhysicalPort><RadwareID>200001</RadwareID><Category>syn-flood</Category><PolicyName>Pol_Correo</PolicyName><PacketCount>0</PacketCount><ByteCount>0</ByteCount><Action>proxy</Action><Risk>medium</Risk><VlanTag>0</VlanTag><MPLSTag>0</MPLSTag><MPLSRD><![CDATA[N/A]]></MPLSRD></item></table><status>true</status></tns:getAll_Log_response></SOAP-ENV:Body></SOAP-ENV:Envelope>`
	resp, err := Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := resp.Table()
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %v, err = %v", rows, err)
	}
	r := rows[0]
	if r["AttackTime"] != "07-06-2024 12:53:52" || r["AttackName"] != "SYN Flood HTTPS" || r["DstPort"] != "443" || r["MPLSRD"] != "N/A" {
		t.Errorf("row = %v", r)
	}
}

// Fault real que el equipo devuelve para una tabla sin filas.
func TestDecodeRealNoSuchInstance(t *testing.T) {
	body := `<?xml version="1.0" encoding="ISO-8859-1"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance" xmlns:xsd="http://www.w3.org/1999/XMLSchema" ><SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>SOAP-ENV:Client</faultcode><faultstring>NoSuchInstanceException: while processing getAll_rsIDSTrafficAnalysisProtectionEntry request - the entry does not exist. </faultstring><detail><exception>NoSuchInstanceException</exception><errorMessage>the entry does not exist</errorMessage></detail></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>`
	_, err := Decode([]byte(body))
	var f *Fault
	if !errors.As(err, &f) || !strings.HasPrefix(f.String, "NoSuchInstanceException") {
		t.Fatalf("err = %v", err)
	}
}

func TestDecodeRowsNested(t *testing.T) {
	type inner struct {
		In int64 `soap:"TcpInQuota"`
	}
	type outer struct {
		Name   string `soap:"ProfileName"`
		Quotas inner
	}
	out := DecodeRows[outer]([]Row{{"ProfileName": "BDOS_APP", "TcpInQuota": "75"}})
	if out[0].Name != "BDOS_APP" || out[0].Quotas.In != 75 {
		t.Errorf("DecodeRows anidado = %+v", out[0])
	}
}

func TestDecodeValueNil(t *testing.T) {
	body := envOpen + `<r><value xsi:nil="true">x</value></r>` + envClose
	resp, err := Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := resp.Value(); v != "" {
		t.Errorf("Value() = %q, want vacío para xsi:nil", v)
	}
}

func TestDecodeTable(t *testing.T) {
	body := envOpen + `<ns1:getAll_CpuTemperatureResponse xmlns:ns1="radware.Device.HardwareInfo">
<table xsi:type="SOAP-ENC:Array" SOAP-ENC:arrayType="ns1:CpuTemperature[2]">
  <item xsi:type="ns1:CpuTemperature"><Index>1</Index><Temperature>45</Temperature></item>
  <item xsi:type="ns1:CpuTemperature"><Index>2</Index><Temperature>51</Temperature></item>
</table>
<status xsi:type="xsd:boolean">true</status>
</ns1:getAll_CpuTemperatureResponse>` + envClose

	resp, err := Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := resp.Table()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1]["Index"] != "2" || rows[1]["Temperature"] != "51" {
		t.Fatalf("rows = %v", rows)
	}

	type temp struct {
		Index int64 `soap:"Index"`
		Temp  int   `soap:"Temperature"`
		Other string
	}
	out := DecodeRows[temp](rows)
	if out[0].Index != 1 || out[0].Temp != 45 || out[1].Temp != 51 {
		t.Errorf("DecodeRows = %+v", out)
	}
}

func TestDecodeEmptyTable(t *testing.T) {
	body := envOpen + `<r><table xsi:type="SOAP-ENC:Array" SOAP-ENC:arrayType="x:Y[0]"/><status>true</status></r>` + envClose
	resp, err := Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := resp.Table()
	if err != nil || len(rows) != 0 {
		t.Fatalf("Table() = %v, %v; want vacío sin error", rows, err)
	}
}

func TestDecodeMultiRef(t *testing.T) {
	body := envOpen + `<ns1:getAll_SystemFansResponse>
<table SOAP-ENC:arrayType="ns1:SystemFans[2]"><item href="#id1"/><item href="#id2"/></table>
</ns1:getAll_SystemFansResponse>
<multiRef id="id1"><Index>1</Index><Status>ok</Status></multiRef>
<multiRef id="id2"><Index>2</Index><Status>failed</Status></multiRef>` + envClose

	resp, err := Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Op != "getAll_SystemFansResponse" {
		t.Errorf("Op = %q: el wrapper no debe ser un multiRef", resp.Op)
	}
	rows, err := resp.Table()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["Status"] != "ok" || rows[1]["Status"] != "failed" {
		t.Fatalf("multiRef no resuelto: %v", rows)
	}
}

func TestDecodeFault(t *testing.T) {
	body := envOpen + `<SOAP-ENV:Fault><faultcode>SOAP-ENV:Client</faultcode><faultstring>Operation not supported</faultstring></SOAP-ENV:Fault>` + envClose
	_, err := Decode([]byte(body))
	var f *Fault
	if !errors.As(err, &f) {
		t.Fatalf("err = %v, want *Fault", err)
	}
	if f.String != "Operation not supported" || f.Code != "SOAP-ENV:Client" {
		t.Errorf("fault = %+v", f)
	}
}

func TestDecodeNotSOAP(t *testing.T) {
	if _, err := Decode([]byte(`<html><body>login</body></html>`)); err == nil {
		t.Error("esperaba error para HTML")
	}
	if _, err := Decode([]byte(`no xml`)); err == nil {
		t.Error("esperaba error para texto plano")
	}
}

func TestSetValue(t *testing.T) {
	var s string
	var n int64
	var f float64
	SetValue(&s, "Behavioral")
	SetValue(&n, "42")
	SetValue(&f, "1.5")
	SetValue(&n, "N/A") // no parsea: conserva el valor
	if s != "Behavioral" || n != 42 || f != 1.5 {
		t.Errorf("s=%q n=%d f=%v", s, n, f)
	}
}

func TestLookup(t *testing.T) {
	if got := Lookup("Device.Information"); got != DeviceInformation {
		t.Errorf("Lookup catálogo = %+v", got)
	}
	got := Lookup("radware.Networking.Arp")
	if got.Namespace != "radware.Networking.Arp" || got.Action != "NetworkingArpAction" {
		t.Errorf("Lookup derivado = %+v", got)
	}
}

func TestClientCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/soap" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("SOAPAction"); got != `"DeviceInformationAction"` {
			t.Errorf("SOAPAction = %q", got)
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "api" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "get_SoftwareVersion") {
			t.Errorf("body sin operación: %s", body)
		}
		_, _ = io.WriteString(w, envOpen+`<r><value>8.34.2.0</value></r>`+envClose)
	}))
	defer srv.Close()

	c := NewClient(srv.URL+"/", "api", "secret", srv.Client())
	body, err := c.Call(context.Background(), DeviceInformation, "get_SoftwareVersion")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := resp.Value(); v != "8.34.2.0" {
		t.Errorf("Value() = %q", v)
	}

	bad := NewClient(srv.URL, "api", "wrong", srv.Client())
	if _, err := bad.Call(context.Background(), DeviceInformation, "get_SoftwareVersion"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v, want auth 401", err)
	}
}

func TestClientCallFault500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, envOpen+`<SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode><faultstring>No such instance</faultstring></SOAP-ENV:Fault>`+envClose)
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL, "u", "p", srv.Client()).Call(context.Background(), DeviceHighAvailability, "get_haProtectionState")
	var f *Fault
	if !errors.As(err, &f) || f.String != "No such instance" {
		t.Fatalf("err = %v, want *Fault", err)
	}
}
