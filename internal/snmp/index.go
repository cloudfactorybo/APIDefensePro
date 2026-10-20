package snmp

import (
	"net"
	"strconv"
	"strings"
)

// Row es una fila de tabla: columna → valor.
type Row map[int]PDU

// Table agrupa los PDUs de una tabla por índice. entry es el OID de la
// entrada (p.ej. "...188.4.2.1"); el índice se devuelve como sub-OID crudo
// ("7.80.111.108...") para decodificarlo según la tabla.
func Table(pdus []PDU, entry string) (rows map[string]Row, order []string) {
	prefix := strings.TrimPrefix(entry, ".") + "."
	rows = map[string]Row{}
	for _, p := range pdus {
		if !strings.HasPrefix(p.OID, prefix) {
			continue
		}
		rest := p.OID[len(prefix):]
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			continue
		}
		col, err := strconv.Atoi(rest[:dot])
		if err != nil {
			continue
		}
		idx := rest[dot+1:]
		if rows[idx] == nil {
			rows[idx] = Row{}
			order = append(order, idx)
		}
		rows[idx][col] = p
	}
	return rows, order
}

func parts(idx string) []int {
	var out []int
	for _, s := range strings.Split(idx, ".") {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// StringIndex decodifica un índice string no-IMPLIED ("largo.b1.b2...").
// Ej.: "7.80.111.108.95.87.87.87" → "Pol_WWW".
func StringIndex(idx string) (string, bool) {
	p := parts(idx)
	if len(p) == 0 || p[0] != len(p)-1 {
		return "", false
	}
	b := make([]byte, p[0])
	for i := range b {
		if p[i+1] < 0 || p[i+1] > 255 {
			return "", false
		}
		b[i] = byte(p[i+1])
	}
	return string(b), true
}

// IntIndex decodifica un índice entero simple.
func IntIndex(idx string) (int, bool) {
	n, err := strconv.Atoi(idx)
	return n, err == nil
}

// SynActivationIndex decodifica el índice de rsSESSIONSynActivationTable:
// type.IPv6(16 bytes fijos).port.rxport. Las IPv4 llegan mapeadas o con ceros.
func SynActivationIndex(idx string) (typ int, ip string, port, rxPort int, ok bool) {
	p := parts(idx)
	if len(p) != 1+16+2 {
		return 0, "", 0, 0, false
	}
	b := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		b[i] = byte(p[1+i])
	}
	if allZero(b[:12]) && !allZero(b[12:]) { // IPv4 con 12 ceros
		ip = net.IP(b[12:]).String()
	} else {
		ip = b.String() // net.IP ya muestra las IPv4-mapped como a.b.c.d
	}
	return p[0], ip, p[17], p[18], true
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
