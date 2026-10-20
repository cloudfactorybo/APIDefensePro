package snmp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestAllowlist(t *testing.T) {
	ok := []string{
		"1.3.6.1.4.1.89.35.1.65.188.4.2.1.7.7.80.111.108.95.87.87.87", // tráfico Pol_WWW TCP
		".1.3.6.1.4.1.89.35.1.65.188",
		"1.3.6.1.4.1.89.35.1.122.59.1.3.8",
		"1.3.6.1.4.1.89.35.1.104.53.0",
		"1.3.6.1.4.1.89.35.1.53.0",
		"1.3.6.1.4.1.89.2.12.0",
		"1.3.6.1.2.1.1.5.0",
		"1.3.6.1.2.1.31.1.1.1.1.9", // ifName
		"1.3.6.1.2.1.2.2.1.8.7",    // ifOperStatus
	}
	for _, o := range ok {
		if !Allowed(o) {
			t.Errorf("%s debería estar permitido", o)
		}
	}
	blocked := []string{
		"1.3.6.1.4.1.89",              // walk completo (690 mil OIDs)
		"1.3.6.1.4.1.89.2.7.2",        // rndCommunityTable: comunidades SNMP
		"1.3.6.1.4.1.89.35.1.65.75.1", // base de firmas
		"1.3.6.1.4.1.89.35.1.65.61",   // log completo sin cursor
		"1.3.6.1.4.1.89.35.1.65.101",  // rsNetFlood* (incluye reset de baseline)
		"1.3.6.1.4.1.89.35.1.65.1880", // prefijo engañoso de .188
		"1.3.6.1.4.1.89.35.1.5",       // prefijo engañoso de .53
		"1.3.6.1.2.1.2.2.1.6",         // ifPhysAddress: no es una columna permitida
		"1.3.6.1.2.1.2.2",             // ifTable completa
	}
	for _, o := range blocked {
		if Allowed(o) {
			t.Errorf("%s NO debería estar permitido", o)
		}
	}
}

// La barrera actúa antes de abrir la sesión: un OID fuera de la allowlist nunca
// llega a la red.
func TestClientRejectsBeforeNetwork(t *testing.T) {
	c, err := NewClient(Config{Host: "192.0.2.1", User: "u", AuthProtocol: "SHA", AuthPassword: "x", PrivProtocol: "AES", PrivPassword: "y"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Walk(context.Background(), "1.3.6.1.4.1.89"); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("Walk = %v, want error de allowlist", err)
	}
	if _, err := c.Get(context.Background(), []string{"1.3.6.1.4.1.89.2.7.2.1.0"}); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("Get = %v, want error de allowlist", err)
	}
}

// Garantía estructural de sólo lectura: ningún archivo del paquete puede
// llamar a Set (ni SetRequest) de gosnmp.
func TestNoWriteCalls(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	re := regexp.MustCompile(`\.Set\(|SetRequest|SendTrap|\.Inform\(`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if loc := re.FindIndex(b); loc != nil {
			t.Errorf("%s contiene una operación de escritura SNMP: %q", f, b[loc[0]:loc[1]])
		}
	}
}

func TestUSMValidation(t *testing.T) {
	for _, c := range []Config{
		{AuthProtocol: "MD5", PrivProtocol: "DES"},
		{AuthProtocol: "sha256", PrivProtocol: "aes"},
		{AuthProtocol: "SHA", PrivProtocol: "NONE"},
	} {
		if _, err := NewClient(c); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	for _, c := range []Config{
		{AuthProtocol: "MD4", PrivProtocol: "DES"},
		{AuthProtocol: "NONE", PrivProtocol: "AES"},
	} {
		if _, err := NewClient(c); err == nil {
			t.Errorf("%+v debería ser inválido", c)
		}
	}
}

func TestStringIndex(t *testing.T) {
	if s, ok := StringIndex("7.80.111.108.95.87.87.87"); !ok || s != "Pol_WWW" {
		t.Errorf("StringIndex = %q, %v", s, ok)
	}
	for _, bad := range []string{"", "3.80.111", "x.1", "2.80.300"} {
		if _, ok := StringIndex(bad); ok {
			t.Errorf("StringIndex(%q) debería fallar", bad)
		}
	}
}

func TestSynActivationIndex(t *testing.T) {
	// Fila total: type 3, IP ::, puerto 65535, rx 0.
	typ, ip, port, rx, ok := SynActivationIndex("3." + strings.Repeat("0.", 16) + "65535.0")
	if !ok || typ != 3 || ip != "::" || port != 65535 || rx != 0 {
		t.Errorf("total = %d %q %d %d %v", typ, ip, port, rx, ok)
	}
	// IPv4 con 12 ceros: 143.0.101.21:443 desde el puerto 5.
	_, ip, port, rx, ok = SynActivationIndex("1." + strings.Repeat("0.", 12) + "143.0.101.21.443.5")
	if !ok || ip != "143.0.101.21" || port != 443 || rx != 5 {
		t.Errorf("ipv4 = %q %d %d %v", ip, port, rx, ok)
	}
	// IPv4-mapped (::ffff:a.b.c.d).
	_, ip, _, _, ok = SynActivationIndex("1." + strings.Repeat("0.", 10) + "255.255.10.0.0.1.80.1")
	if !ok || ip != "10.0.0.1" {
		t.Errorf("mapped = %q %v", ip, ok)
	}
}

func TestTable(t *testing.T) {
	pdus := []PDU{
		{OID: "1.3.6.1.4.1.89.35.1.65.188.4.2.1.2.7.80.111.108.95.87.87.87", Kind: KindInt, Int: 646},
		{OID: "1.3.6.1.4.1.89.35.1.65.188.4.2.1.6.7.80.111.108.95.87.87.87", Kind: KindUint, Uint: 1639},
		{OID: "1.3.6.1.4.1.89.35.1.65.188.4.2.1.7.7.80.111.108.95.68.78.83", Kind: KindUint, Uint: 663},
		{OID: "1.3.6.1.4.1.89.35.1.65.188.4.1.1.7.7.80.111.108.95.68.78.83", Kind: KindUint, Uint: 1}, // otra tabla
	}
	rows, order := Table(pdus, "1.3.6.1.4.1.89.35.1.65.188.4.2.1")
	if len(rows) != 2 || len(order) != 2 {
		t.Fatalf("rows = %v", rows)
	}
	www := rows["7.80.111.108.95.87.87.87"]
	if www[2].Int64() != 646 || www[6].Uint64() != 1639 {
		t.Errorf("Pol_WWW = %+v", www)
	}
}

func TestPDUConversions(t *testing.T) {
	if (PDU{Kind: KindString, Str: " 12345 "}).Int64() != 12345 {
		t.Error("DisplayString numérico")
	}
	if (PDU{Kind: KindInt, Int: -1}).Uint64() != 0 {
		t.Error("negativo a uint")
	}
}

// El DefensePro devuelve tablas indexadas por nombre fuera de orden
// lexicográfico (Pol_Pagotarjetas antes que Pol_Canalexterno): el collector
// debe aceptarlas, cortar si el agente repite un OID y acotar el total.
func TestWalkCollector(t *testing.T) {
	pdu := func(name string) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: name, Type: gosnmp.Integer, Value: 1}
	}
	w := &walkCollector{seen: map[string]bool{}}
	base := ".1.3.6.1.4.1.89.35.1.65.188.4.1.1.1."
	for _, idx := range []string{"16.80.97.103", "16.67.97.110", "7.80.111.108"} { // no crecientes
		if err := w.add(pdu(base + idx)); err != nil {
			t.Fatalf("OID fuera de orden rechazado: %v", err)
		}
	}
	if err := w.add(pdu(base + "16.80.97.103")); !errors.Is(err, errWalkCycle) {
		t.Errorf("OID repetido = %v, want errWalkCycle", err)
	}
	if len(w.out) != 3 {
		t.Errorf("out = %d PDUs", len(w.out))
	}

	big := &walkCollector{seen: map[string]bool{}}
	var err error
	for n := 0; n <= maxWalkPDUs && err == nil; n++ {
		err = big.add(pdu(base + strconv.Itoa(n)))
	}
	if err == nil || errors.Is(err, errWalkCycle) {
		t.Errorf("el tope de %d OIDs no se aplicó: %v", maxWalkPDUs, err)
	}
}
