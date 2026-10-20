package service

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"defensepro-api/internal/models"
)

// Lectores de la salida de texto de los comandos CLI de estadísticas. El equipo
// dibuja las tablas con caracteres de caja DOS que llegan como basura no-ASCII
// (p.ej. "ï¿½" o "Â³"); cells() los usa como separadores de columna, así que el
// lector no depende de qué basura exacta llegue.

var (
	rePolicyName = regexp.MustCompile(`^policy name - (\S+)`)
	rePolicyType = regexp.MustCompile(`^policy type - (\S+)`)
	reBandwidth  = regexp.MustCompile(`^(inbound|outbound):?\s+(\d+)\s*\[Kbits/Sec\]`)
	reStates     = regexp.MustCompile(`Configured State:\s*(\S+)\s+Learning State:\s*(\S+)\s+Anomaly State:\s*(\S+)`)
	reExpected   = regexp.MustCompile(`^Expected \[Query/Sec\]\s+(\d+)`)
)

// cells parte una fila de tabla en celdas: cualquier carácter no-ASCII es un
// borde. Devuelve las celdas no vacías, sin espacios.
func cells(line string) []string {
	var b strings.Builder
	for i := 0; i < len(line); {
		r, size := utf8.DecodeRuneInString(line[i:])
		if r > 0x7E || r == utf8.RuneError {
			b.WriteByte('|')
		} else {
			b.WriteRune(r)
		}
		i += size
	}
	var out []string
	for _, c := range strings.Split(b.String(), "|") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// numericRow devuelve la etiqueta y los n valores de una fila de datos, o ok
// false si la línea no es una fila con exactamente n números.
func numericRow(line string, n int) (label string, vals []float64, ok bool) {
	c := cells(line)
	if len(c) != n+1 {
		return "", nil, false
	}
	vals = make([]float64, n)
	for i, s := range c[1:] {
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return "", nil, false
		}
		vals[i] = v
	}
	return c[0], vals, true
}

// parseBDoSStats lee "system internal security bdos statistics" y devuelve la
// sección de policy. nil si la política no aparece (p.ej. salida recortada).
func parseBDoSStats(text, policy string) *models.BDoSTraffic {
	var out *models.BDoSTraffic
	var dir *models.BDoSDirection
	var fam *models.BDoSFamily
	advanced := false

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if m := rePolicyName.FindStringSubmatch(line); m != nil {
			if out != nil {
				break // terminó la sección pedida
			}
			if strings.EqualFold(m[1], policy) {
				out = &models.BDoSTraffic{}
			}
			continue
		}
		if out == nil {
			continue
		}

		switch {
		case rePolicyType.MatchString(line):
			out.PolicyType = rePolicyType.FindStringSubmatch(line)[1]
		case reBandwidth.MatchString(line):
			m := reBandwidth.FindStringSubmatch(line)
			v, _ := strconv.ParseInt(m[2], 10, 64)
			if m[1] == "inbound" {
				out.BandwidthInKbps = v
			} else {
				out.BandwidthOutKbps = v
			}
		case strings.HasPrefix(line, "InBound statistics"):
			dir = &out.Inbound
		case strings.HasPrefix(line, "OutBound statistics"):
			dir = &out.Outbound
		case strings.HasPrefix(line, "IPv4 statistics") && dir != nil:
			fam, advanced = &dir.IPv4, false
		case strings.HasPrefix(line, "IPv6 statistics") && dir != nil:
			fam, advanced = &dir.IPv6, false
		case strings.HasPrefix(line, "Advanced UDP"):
			advanced = true
		case reStates.MatchString(line) && fam != nil:
			m := reStates.FindStringSubmatch(line)
			fam.ConfiguredState, fam.LearningState = m[1], m[2]
			fam.Anomaly = strings.EqualFold(m[3], "true")
		case fam != nil:
			label, v, ok := numericRow(line, 6)
			if !ok {
				continue
			}
			if advanced {
				fam.AdvancedUDP = &models.AdvancedUDPStats{
					BaselineBps: int64(v[0]), BaselinePps: int64(v[1]), BaselineCpsPps: v[2],
					CurrentBps: int64(v[3]), CurrentPps: int64(v[4]), CurrentCpsPps: v[5],
				}
				continue
			}
			p := models.BDoSProtocolStats{
				Protocol:    label,
				BaselineBps: int64(v[0]), BaselinePps: int64(v[1]),
				CurrentBps: int64(v[2]), CurrentPps: int64(v[3]),
				DroppedBps: int64(v[4]), DroppedPps: int64(v[5]),
			}
			p.LegitimateBps = max(p.CurrentBps-p.DroppedBps, 0)
			p.LegitimatePps = max(p.CurrentPps-p.DroppedPps, 0)
			fam.Protocols = append(fam.Protocols, p)
		}
	}
	if out != nil {
		for _, f := range []*models.BDoSFamily{&out.Inbound.IPv4, &out.Inbound.IPv6, &out.Outbound.IPv4, &out.Outbound.IPv6} {
			if f.Protocols == nil {
				f.Protocols = []models.BDoSProtocolStats{}
			}
		}
	}
	return out
}

// parseDNSStats lee "system internal security dns statistics get <policy>".
func parseDNSStats(text string) *models.DNSTraffic {
	out := &models.DNSTraffic{IPv4: []models.DNSQueryStats{}, IPv6: []models.DNSQueryStats{}}
	var fam *[]models.DNSQueryStats
	found := false

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case rePolicyName.MatchString(line):
			found = true
		case reExpected.MatchString(line):
			out.ExpectedQPS, _ = strconv.ParseInt(reExpected.FindStringSubmatch(line)[1], 10, 64)
		case strings.HasPrefix(line, "IPv4 statistics"):
			fam = &out.IPv4
		case strings.HasPrefix(line, "IPv6 statistics"):
			fam = &out.IPv6
		case fam != nil:
			label, v, ok := numericRow(line, 3)
			if !ok {
				continue
			}
			q := models.DNSQueryStats{
				Type:        dnsType(label),
				BaselineQPS: int64(v[0]), CurrentQPS: int64(v[1]), DroppedQPS: int64(v[2]),
			}
			q.LegitimateQPS = max(q.CurrentQPS-q.DroppedQPS, 0)
			*fam = append(*fam, q)
		}
	}
	if !found {
		return nil
	}
	return out
}

// dnsType convierte "DnsAAAA" → "AAAA", "DnsText" → "TXT".
func dnsType(label string) string {
	t := strings.ToUpper(strings.TrimPrefix(label, "Dns"))
	if t == "TEXT" {
		return "TXT"
	}
	return t
}
