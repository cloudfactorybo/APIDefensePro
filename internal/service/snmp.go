package service

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"defensepro-api/internal/models"
	"defensepro-api/internal/snmp"
)

// snmpReader es lo que el servicio usa del cliente SNMP (en tests, un fake).
type snmpReader interface {
	Get(ctx context.Context, oids []string) (map[string]snmp.PDU, error)
	Walk(ctx context.Context, root string) ([]snmp.PDU, error)
}

var errNoSNMP = errors.New("SNMP no configurado para este equipo (defensepro-admin set-snmp)")

// SetSNMP asigna el cliente SNMP del equipo (nil = sin SNMP).
func (s *DefenseProService) SetSNMP(r snmpReader) { s.snmp = r }

// OIDs (verificados contra los MIB DefensePro 8.34.2.0).
const (
	oidTraffic       = "1.3.6.1.4.1.89.35.1.65.188"
	oidConcTCP       = oidTraffic + ".1.0"
	oidConcUDP       = oidTraffic + ".2.0"
	oidTrafficPort   = oidTraffic + ".3"
	oidTrafficPolicy = oidTraffic + ".4"
	oidPortStats     = "1.3.6.1.4.1.89.35.1.122.59"
	oidPortTotalIn   = "1.3.6.1.4.1.89.35.1.122.61.0"
	oidSynActivation = "1.3.6.1.4.1.89.35.1.104.42"
	oidSessionsUsed  = "1.3.6.1.4.1.89.35.1.104.53.0"
	oidSessionsEng   = "1.3.6.1.4.1.89.35.1.104.54"
	oidCPUTemps      = "1.3.6.1.4.1.89.35.1.165"
	oidAccelerator   = "1.3.6.1.4.1.89.35.1.88.3"
	oidSyslogServers = "1.3.6.1.4.1.89.35.1.173"
	oidResourceUtil  = "1.3.6.1.4.1.89.35.1.53.0"
	oidIfDescr       = "1.3.6.1.2.1.2.2.1.2"
	oidIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	oidIfName        = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15"
)

var ifOperStatus = map[int]string{1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}

// ifColumn indexa una columna del IF-MIB por ifIndex.
func ifColumn(pdus []snmp.PDU, col string) map[int]snmp.PDU {
	out := map[int]snmp.PDU{}
	prefix := col + "."
	for _, p := range pdus {
		if strings.HasPrefix(p.OID, prefix) {
			if n, ok := snmp.IntIndex(p.OID[len(prefix):]); ok {
				out[n] = p
			}
		}
	}
	return out
}

// Tabla N de rsTrafficUtilizationPer{Port,Policy} → protocolo.
var trafficProtocols = []struct {
	n    int
	name string
}{{1, "udp"}, {2, "tcp"}, {3, "icmp"}, {4, "other"}, {5, "sctp"}, {6, "igmp"}}

func (s *DefenseProService) snmpWalk(ctx context.Context, ttl time.Duration, root string) ([]snmp.PDU, error) {
	if s.snmp == nil {
		return nil, errNoSNMP
	}
	key := s.name + ":snmp:walk:" + root
	if ttl > 0 {
		if b, ok := s.cache.Get(key); ok {
			var cached []snmp.PDU
			if json.Unmarshal(b, &cached) == nil {
				return cached, nil
			}
		}
	}
	if err := s.gate.acquire(ctx); err != nil {
		return nil, err
	}
	pdus, err := s.snmp.Walk(ctx, root)
	s.gate.release()
	if err != nil {
		return nil, err
	}
	if ttl > 0 {
		if b, err := json.Marshal(pdus); err == nil {
			s.cache.Set(key, b, ttl)
		}
	}
	return pdus, nil
}

func (s *DefenseProService) snmpGet(ctx context.Context, ttl time.Duration, oids []string) (map[string]snmp.PDU, error) {
	if s.snmp == nil {
		return nil, errNoSNMP
	}
	key := s.name + ":snmp:get:" + strings.Join(oids, ",")
	if ttl > 0 {
		if b, ok := s.cache.Get(key); ok {
			var cached map[string]snmp.PDU
			if json.Unmarshal(b, &cached) == nil {
				return cached, nil
			}
		}
	}
	if err := s.gate.acquire(ctx); err != nil {
		return nil, err
	}
	vals, err := s.snmp.Get(ctx, oids)
	s.gate.release()
	if err != nil {
		return nil, err
	}
	if ttl > 0 {
		if b, err := json.Marshal(vals); err == nil {
			s.cache.Set(key, b, ttl)
		}
	}
	return vals, nil
}

func (s *DefenseProService) walkTask(root string, ttl time.Duration, dst *[]snmp.PDU) task {
	return task{"snmp walk " + root, func(ctx context.Context) error {
		pdus, err := s.snmpWalk(ctx, ttl, root)
		if err != nil {
			return err
		}
		*dst = pdus
		return nil
	}}
}

func (s *DefenseProService) getTask(oids []string, ttl time.Duration, dst *map[string]snmp.PDU) task {
	return task{"snmp get", func(ctx context.Context) error {
		vals, err := s.snmpGet(ctx, ttl, oids)
		if err != nil {
			return err
		}
		*dst = vals
		return nil
	}}
}

func mbps(bytesPerSec uint64) float64 {
	return math.Round(float64(bytesPerSec)*8/1e6*1000) / 1000
}

// GetTrafficPolicies devuelve la utilización por política y protocolo.
// names filtra por política; sin includeIdle se omiten las que están en 0.
func (s *DefenseProService) GetTrafficPolicies(ctx context.Context, names []string, includeIdle bool) (*models.TrafficPolicies, error) {
	out := &models.TrafficPolicies{Policies: []models.PolicyTrafficStats{}}
	var pdus []snmp.PDU
	if err := s.gather(ctx, out, s.walkTask(oidTrafficPolicy, statsTTL, &pdus)); err != nil {
		return nil, err
	}

	filter := toSet(names)
	byPolicy := map[string]*models.PolicyTrafficStats{}
	for _, proto := range trafficProtocols {
		rows, order := snmp.Table(pdus, oidTrafficPolicy+"."+strconv.Itoa(proto.n)+".1")
		for _, idx := range order {
			row := rows[idx]
			name, ok := snmp.StringIndex(idx)
			if !ok {
				name = row[1].String()
			}
			if !matches(filter, name) {
				continue
			}
			p := byPolicy[name]
			if p == nil {
				p = &models.PolicyTrafficStats{Policy: name, Protocols: map[string]models.ProtocolRates{}}
				byPolicy[name] = p
			}
			// Columna 3 (rsConcurConnectionsPerPolicy*) es obsoleta: no se publica.
			r := models.ProtocolRates{
				NewConnections:      row[2].Int64(),
				DroppedPps:          row[4].Uint64(),
				DroppedBytesPerSec:  row[5].Uint64(),
				ReceivedPps:         row[6].Uint64(),
				ReceivedBytesPerSec: row[7].Uint64(),
			}
			r.ReceivedMbps, r.DroppedMbps = mbps(r.ReceivedBytesPerSec), mbps(r.DroppedBytesPerSec)
			p.Protocols[proto.name] = r
			t := &p.Total
			t.NewConnections += r.NewConnections
			t.ReceivedPps += r.ReceivedPps
			t.ReceivedBytesPerSec += r.ReceivedBytesPerSec
			t.DroppedPps += r.DroppedPps
			t.DroppedBytesPerSec += r.DroppedBytesPerSec
		}
	}

	for _, p := range byPolicy {
		p.Total.ReceivedMbps, p.Total.DroppedMbps = mbps(p.Total.ReceivedBytesPerSec), mbps(p.Total.DroppedBytesPerSec)
		if !includeIdle && p.Total == (models.ProtocolRates{}) {
			continue
		}
		out.Policies = append(out.Policies, *p)
	}
	slices.SortFunc(out.Policies, func(a, b models.PolicyTrafficStats) int {
		return cmp.Or(cmp.Compare(b.Total.ReceivedBytesPerSec, a.Total.ReceivedBytesPerSec), cmp.Compare(a.Policy, b.Policy))
	})
	return out, nil
}

// GetTrafficPorts devuelve el tráfico por puerto físico.
func (s *DefenseProService) GetTrafficPorts(ctx context.Context, includeIdle bool) (*models.TrafficPorts, error) {
	out := &models.TrafficPorts{Ports: []models.PortTrafficStats{}}
	var util, stats, ifDescr, ifOper, ifName, ifSpeed []snmp.PDU
	var total map[string]snmp.PDU
	err := s.gather(ctx, out,
		s.walkTask(oidTrafficPort, statsTTL, &util),
		s.walkTask(oidPortStats, statsTTL, &stats),
		s.getTask([]string{oidPortTotalIn}, statsTTL, &total),
		s.walkTask(oidIfName, configTTL, &ifName),
		s.walkTask(oidIfDescr, configTTL, &ifDescr),
		s.walkTask(oidIfOperStatus, statsTTL, &ifOper),
		s.walkTask(oidIfHighSpeed, statsTTL, &ifSpeed),
	)
	if err != nil {
		return nil, err
	}
	out.TotalInMbps = total[oidPortTotalIn].Int64()

	ports := map[int]*models.PortTrafficStats{}
	port := func(n int) *models.PortTrafficStats {
		if ports[n] == nil {
			ports[n] = &models.PortTrafficStats{Port: n, Protocols: map[string]models.PortProtocolRates{}}
		}
		return ports[n]
	}

	rows, _ := snmp.Table(stats, oidPortStats+".1")
	for idx, r := range rows {
		n, ok := snmp.IntIndex(idx)
		if !ok {
			continue
		}
		p := port(n)
		// Columnas 2 y 6 (In/OutOctetsPerSec) son obsoletas: no se publican.
		p.InPps, p.InDiscardsPerSec, p.InErrorsPerSec = r[3].Int64(), r[4].Int64(), r[5].Int64()
		p.OutPps, p.OutDiscardsPerSec, p.OutErrorsPerSec = r[7].Int64(), r[8].Int64(), r[9].Int64()
		p.InMbps, p.OutMbps = r[10].Int64(), r[11].Int64()
	}
	for _, proto := range trafficProtocols {
		rows, _ := snmp.Table(util, oidTrafficPort+"."+strconv.Itoa(proto.n)+".1")
		for idx, r := range rows {
			n, ok := snmp.IntIndex(idx)
			if !ok {
				continue
			}
			port(n).Protocols[proto.name] = models.PortProtocolRates{
				DroppedPps: r[2].Uint64(), DroppedBytesPerSec: r[3].Uint64(),
				ReceivedPps: r[4].Uint64(), ReceivedBytesPerSec: r[5].Uint64(),
				ExcludedPps: r[6].Uint64(), ExcludedBytesPerSec: r[7].Uint64(),
			}
		}
	}

	names, descrs := ifColumn(ifName, oidIfName), ifColumn(ifDescr, oidIfDescr)
	opers, speeds := ifColumn(ifOper, oidIfOperStatus), ifColumn(ifSpeed, oidIfHighSpeed)
	for n, p := range ports {
		p.Name = names[n].String()
		p.Description = descrs[n].String()
		p.Management = strings.HasPrefix(strings.ToUpper(p.Name), "MNG")
		if o, ok := opers[n]; ok {
			p.OperStatus = enumName(ifOperStatus, int(o.Int64()))
		}
		p.LinkSpeedMbps = speeds[n].Int64()
	}

	for _, p := range ports {
		if !includeIdle && portIdle(p) {
			continue
		}
		out.Ports = append(out.Ports, *p)
	}
	slices.SortFunc(out.Ports, func(a, b models.PortTrafficStats) int { return cmp.Compare(a.Port, b.Port) })
	return out, nil
}

func portIdle(p *models.PortTrafficStats) bool {
	if p.InPps != 0 || p.OutPps != 0 || p.InMbps != 0 || p.OutMbps != 0 || p.InDiscardsPerSec != 0 ||
		p.InErrorsPerSec != 0 || p.OutDiscardsPerSec != 0 || p.OutErrorsPerSec != 0 {
		return false
	}
	for _, r := range p.Protocols {
		if r != (models.PortProtocolRates{}) {
			return false
		}
	}
	return true
}

func (s *DefenseProService) GetSessions(ctx context.Context) (*models.Sessions, error) {
	out := &models.Sessions{PerEngine: []models.EngineSessions{}}
	var vals map[string]snmp.PDU
	var engines []snmp.PDU
	err := s.gather(ctx, out,
		s.getTask([]string{oidConcTCP, oidConcUDP, oidSessionsUsed}, statsTTL, &vals),
		s.walkTask(oidSessionsEng, statsTTL, &engines),
	)
	if err != nil {
		return nil, err
	}
	out.ConcurrentTCP = vals[oidConcTCP].Int64()
	out.ConcurrentUDP = vals[oidConcUDP].Int64()
	out.SessionTableUsed = vals[oidSessionsUsed].Int64()
	rows, _ := snmp.Table(engines, oidSessionsEng+".1")
	for idx, r := range rows {
		if n, ok := snmp.IntIndex(idx); ok {
			out.PerEngine = append(out.PerEngine, models.EngineSessions{Engine: n, Used: r[2].Int64()})
		}
	}
	slices.SortFunc(out.PerEngine, func(a, b models.EngineSessions) int { return cmp.Compare(a.Engine, b.Engine) })
	return out, nil
}

var synTriggerTypes = map[int]string{1: "synProtectionTrigger", 2: "synProtectionEnable", 3: "synProtectionTotal", 4: "ackReflection"}

func (s *DefenseProService) GetSynTriggers(ctx context.Context) (*models.SynTriggers, error) {
	out := &models.SynTriggers{Triggers: []models.SynTrigger{}}
	var pdus []snmp.PDU
	if err := s.gather(ctx, out, s.walkTask(oidSynActivation, statsTTL, &pdus)); err != nil {
		return nil, err
	}
	rows, order := snmp.Table(pdus, oidSynActivation+".1")
	for _, idx := range order {
		typ, ip, port, rx, ok := snmp.SynActivationIndex(idx)
		if !ok {
			continue
		}
		r := rows[idx]
		t := models.SynTrigger{
			Type: enumName(synTriggerTypes, typ), DestinationIP: ip, DestinationPort: port, RxPort: rx,
			ActiveSeconds: r[5].Int64(), LastSecSYN: r[6].Int64(), LastSecRequests: r[7].Int64(),
			AvgSYN: r[8].Int64(), AvgRequests: r[9].Int64(),
			TotalSYN: r[10].Int64(), TotalDropped: r[11].Int64(), // DisplayString numéricos
		}
		if typ == 3 {
			total := t
			out.Total = &total
			continue
		}
		out.Triggers = append(out.Triggers, t)
	}
	return out, nil
}

// Enums de los MIB.
var (
	tempStatus    = map[int]string{1: "normal", 2: "warning", 3: "critical"}
	psuStatus     = map[int]string{1: "active", 2: "notInService", 3: "invalid"}
	psuOverall    = map[int]string{0: "singlePowerSupplyOk", 1: "firstPowerSupplyFailed", 2: "secondPowerSupplyFailed", 3: "doublePowerSupplyOk", 4: "unknownPowerSupplyFailed"}
	haPriority    = map[int]string{0: "secondary", 1: "primary", 2: "standAlone", 3: "notSupported"}
	haState       = map[int]string{1: "active", 2: "passive"}
	ertStatus     = map[int]string{0: "valid", 1: "noLicense", 2: "error"}
	featureStatus = map[int]string{1: "enable", 2: "disable"}
	syslogConn    = map[int]string{1: "nr", 2: "reachable", 3: "unreachable"}
	syslogProto   = map[int]string{1: "udp", 2: "tcp", 3: "tls"}
)

func enumName(m map[int]string, v int) string {
	if n, ok := m[v]; ok {
		return n
	}
	return "unknown(" + strconv.Itoa(v) + ")"
}

const oidWSD = "1.3.6.1.4.1.89.35.1."

var healthScalars = []string{
	oidWSD + "53.0", oidWSD + "54.0", oidWSD + "112.0", oidWSD + "113.0", oidWSD + "221.0",
	oidWSD + "211.0", oidWSD + "212.0", oidWSD + "213.0", oidWSD + "214.0", oidWSD + "215.0", oidWSD + "216.0",
	oidWSD + "150.0", oidWSD + "151.0", oidWSD + "152.0", oidWSD + "153.0", oidWSD + "154.0", oidWSD + "155.0",
	oidWSD + "69.2.0", oidWSD + "69.3.0", oidWSD + "69.4.0",
	oidWSD + "69.6.1.0", oidWSD + "69.6.2.0", oidWSD + "69.6.4.0",
	oidWSD + "116.10.1.0", oidWSD + "116.10.10.0", oidWSD + "116.10.13.0", oidWSD + "116.10.14.0",
	oidWSD + "65.98.6.0", oidWSD + "65.98.7.0", oidWSD + "65.151.0", oidWSD + "65.152.0", oidWSD + "65.153.0",
	oidWSD + "65.171.0", oidWSD + "65.172.0", oidWSD + "65.185.2.0",
}

func (s *DefenseProService) GetDeviceHealth(ctx context.Context) (*models.DeviceHealth, error) {
	out := &models.DeviceHealth{Accelerator: []models.AcceleratorCPU{}, SyslogServers: []models.SyslogServerInfo{}}
	out.Temperature.PerCPU = []models.CPUTemperature{}
	var v map[string]snmp.PDU
	var temps, acc, syslog []snmp.PDU
	err := s.gather(ctx, out,
		s.getTask(healthScalars, statsTTL, &v),
		s.walkTask(oidCPUTemps, statsTTL, &temps),
		s.walkTask(oidAccelerator, statsTTL, &acc),
		s.walkTask(oidSyslogServers, configTTL, &syslog),
	)
	if err != nil {
		return nil, err
	}
	i := func(oid string) int64 { return v[oidWSD+oid].Int64() }
	e := func(m map[int]string, oid string) string {
		if p, ok := v[oidWSD+oid]; ok {
			return enumName(m, int(p.Int64()))
		}
		return ""
	}

	out.CPU = models.HealthCPU{
		ResourceUtilization: i("53.0"), ControllerUtilization: i("54.0"),
		EnginesAvg5s: i("112.0"), EnginesAvg60s: i("113.0"), EnginesMean: i("221.0"),
	}
	out.Disk = models.ResourceUsage{Capacity: i("211.0"), Used: i("212.0"), UtilizationPercent: i("213.0")}
	out.Memory = models.ResourceUsage{Capacity: i("214.0"), Used: i("215.0"), UtilizationPercent: i("216.0")}
	out.Temperature.CPU1, out.Temperature.CPU2 = i("150.0"), i("151.0")
	out.Temperature.WarningThreshold, out.Temperature.ShutdownThreshold = i("152.0"), i("153.0")
	out.Temperature.CPU1Status, out.Temperature.CPU2Status = e(tempStatus, "154.0"), e(tempStatus, "155.0")
	out.PowerSupply = models.HealthPowerSupply{
		Overall: e(psuOverall, "69.6.4.0"), Supply1: e(psuStatus, "69.6.1.0"), Supply2: e(psuStatus, "69.6.2.0"),
	}
	out.HighAvailability = models.HealthHA{
		Priority: e(haPriority, "116.10.1.0"), ProtectionState: e(haState, "116.10.10.0"),
		PeerIP1: v[oidWSD+"116.10.13.0"].String(), PeerIP2: v[oidWSD+"116.10.14.0"].String(),
	}
	out.Clock = models.HealthClock{
		UpTime: v[oidWSD+"69.2.0"].String(), DeviceTime: v[oidWSD+"69.3.0"].String(), DeviceDate: v[oidWSD+"69.4.0"].String(),
	}
	out.Clock.OffsetSeconds = clockOffset(out.Clock.DeviceDate, out.Clock.DeviceTime, time.Now())
	out.Tables = models.HealthTables{
		SuspendEntries: i("65.98.6.0"), SuspendPercent: i("65.98.7.0"),
		TCPAuthPercent: i("65.151.0"), HTTPAuthPercent: i("65.152.0"), DNSAuthPercent: i("65.153.0"),
		HwSubPoliciesPercent: i("65.171.0"), HwEntriesPercent: i("65.172.0"),
	}
	out.ErtFeedStatus = e(ertStatus, "65.185.2.0")

	rows, _ := snmp.Table(temps, oidCPUTemps+".1")
	for idx, r := range rows {
		if n, ok := snmp.IntIndex(idx); ok {
			out.Temperature.PerCPU = append(out.Temperature.PerCPU, models.CPUTemperature{Index: int64(n), Temperature: r[2].Int64()})
		}
	}
	slices.SortFunc(out.Temperature.PerCPU, func(a, b models.CPUTemperature) int { return cmp.Compare(a.Index, b.Index) })

	rows, order := snmp.Table(acc, oidAccelerator+".1")
	for _, idx := range order {
		r := rows[idx]
		out.Accelerator = append(out.Accelerator, models.AcceleratorCPU{
			CPU: int(r[3].Int64()), FlowPercent: r[4].Int64(), OtherPercent: r[5].Int64(), IdlePercent: r[6].Int64(),
		})
	}

	rows, order = snmp.Table(syslog, oidSyslogServers+".1")
	for _, idx := range order {
		r := rows[idx]
		addr, ok := snmp.StringIndex(idx)
		if !ok {
			addr = r[1].String()
		}
		out.SyslogServers = append(out.SyslogServers, models.SyslogServerInfo{
			Address: addr, Status: enumName(featureStatus, int(r[2].Int64())),
			Connection: enumName(syslogConn, int(r[9].Int64())), BackloggedLogs: r[10].Int64(),
			Protocol: enumName(syslogProto, int(r[6].Int64())), DestinationPort: r[4].Int64(),
			SecurityEvents: enumName(featureStatus, int(r[11].Int64())),
			HealthEvents:   enumName(featureStatus, int(r[12].Int64())),
			UserAudit:      enumName(featureStatus, int(r[13].Int64())),
		})
	}
	return out, nil
}

// clockOffset compara el reloj del equipo ("dd/mm/yyyy" + "hh:mm:ss") con now,
// interpretando la hora del equipo en la zona del host. nil si no parsea.
func clockOffset(date, clock string, now time.Time) *int64 {
	t, err := time.ParseInLocation("02/01/2006 15:04:05", strings.TrimSpace(date)+" "+strings.TrimSpace(clock), now.Location())
	if err != nil {
		return nil
	}
	off := int64(math.Round(t.Sub(now).Seconds()))
	return &off
}

const oidRnd = "1.3.6.1.4.1.89.2."

var infoScalars = []string{
	"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0",
	oidRnd + "4.0", oidRnd + "12.0", oidRnd + "13.0", oidRnd + "14.0", oidRnd + "16.0", oidRnd + "17.0", oidRnd + "22.0", oidRnd + "24.0",
	oidWSD + "69.5.0",
}

func (s *DefenseProService) GetDeviceInfo(ctx context.Context) (*models.DeviceInfo, error) {
	out := &models.DeviceInfo{}
	var v map[string]snmp.PDU
	if err := s.gather(ctx, out, s.getTask(infoScalars, staticTTL, &v)); err != nil {
		return nil, err
	}
	out.SysDescr = v["1.3.6.1.2.1.1.1.0"].String()
	out.SysUpTimeSeconds = int64(v["1.3.6.1.2.1.1.3.0"].Uint64() / 100) // TimeTicks = centésimas
	out.SysName = v["1.3.6.1.2.1.1.5.0"].String()
	out.Version = v[oidRnd+"4.0"].String()
	out.SerialNumber = v[oidRnd+"12.0"].String()
	out.OSVersion = v[oidRnd+"13.0"].String()
	out.DeviceType = v[oidRnd+"14.0"].String()
	out.PortsConfig = v[oidRnd+"16.0"].String()
	out.Throughput = v[oidRnd+"17.0"].String()
	out.Cores = v[oidRnd+"22.0"].Int64()
	out.AttackMitigation = v[oidRnd+"24.0"].String()
	out.BaseMACAddress = v[oidWSD+"69.5.0"].String()
	return out, nil
}
