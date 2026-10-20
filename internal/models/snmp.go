package models

// Datos de tiempo real leídos por SNMPv3 (MIBs DefensePro 8.34.2.0).
//
// Los valores "por segundo" de rsTrafficUtilization son el promedio de los
// últimos 15 s (gauges, aunque el MIB los declare Counter64): se publican tal
// cual, NO hay que calcular deltas en ELK. Bytes, no bits.

// TrafficPolicies: utilización por política y protocolo (rsTrafficUtilizationPerPolicy*).
type TrafficPolicies struct {
	DeviceRef
	Policies []PolicyTrafficStats `json:"policies"`
}

type PolicyTrafficStats struct {
	Policy    string                   `json:"policy"`
	Total     ProtocolRates            `json:"total"`
	Protocols map[string]ProtocolRates `json:"protocols"` // tcp, udp, icmp, other, sctp, igmp
}

type ProtocolRates struct {
	NewConnections      int64   `json:"newConnections"` // rsNewConnectionsPerPolicy*
	ReceivedPps         uint64  `json:"receivedPps"`
	ReceivedBytesPerSec uint64  `json:"receivedBytesPerSec"`
	DroppedPps          uint64  `json:"droppedPps"`
	DroppedBytesPerSec  uint64  `json:"droppedBytesPerSec"`
	ReceivedMbps        float64 `json:"receivedMbps"` // calculado: bytes*8/1e6
	DroppedMbps         float64 `json:"droppedMbps"`
}

// TrafficPorts: por puerto físico (rsTrafficUtilizationPerPort* + rsPortsStatsTable).
type TrafficPorts struct {
	DeviceRef
	TotalInMbps int64              `json:"totalInMbps"` // rsPortStatsTotalInMbitsPerSec
	Ports       []PortTrafficStats `json:"ports"`
}

type PortTrafficStats struct {
	Port int `json:"port"`
	// rsPortsStatsTable (último segundo).
	InPps             int64 `json:"inPps"`
	InDiscardsPerSec  int64 `json:"inDiscardsPerSec"`
	InErrorsPerSec    int64 `json:"inErrorsPerSec"`
	OutPps            int64 `json:"outPps"`
	OutDiscardsPerSec int64 `json:"outDiscardsPerSec"`
	OutErrorsPerSec   int64 `json:"outErrorsPerSec"`
	InMbps            int64 `json:"inMbps"`
	OutMbps           int64 `json:"outMbps"`
	// rsTrafficUtilizationPerPort* (promedio 15 s) por protocolo.
	Protocols map[string]PortProtocolRates `json:"protocols"`
}

type PortProtocolRates struct {
	ReceivedPps         uint64 `json:"receivedPps"`
	ReceivedBytesPerSec uint64 `json:"receivedBytesPerSec"`
	DroppedPps          uint64 `json:"droppedPps"`
	DroppedBytesPerSec  uint64 `json:"droppedBytesPerSec"`
	ExcludedPps         uint64 `json:"excludedPps"` // no inspeccionado
	ExcludedBytesPerSec uint64 `json:"excludedBytesPerSec"`
}

type Sessions struct {
	DeviceRef
	ConcurrentTCP    int64            `json:"concurrentTcp"`
	ConcurrentUDP    int64            `json:"concurrentUdp"`
	SessionTableUsed int64            `json:"sessionTableUsed"`
	PerEngine        []EngineSessions `json:"perEngine"`
}

type EngineSessions struct {
	Engine int   `json:"engine"`
	Used   int64 `json:"used"`
}

// SynTriggers: triggers activos de SYN protection (rsSESSIONSynActivationTable).
type SynTriggers struct {
	DeviceRef
	Total    *SynTrigger  `json:"total"` // fila synProtectionTotal
	Triggers []SynTrigger `json:"triggers"`
}

type SynTrigger struct {
	Type            string `json:"type"`
	DestinationIP   string `json:"destinationIp"`
	DestinationPort int    `json:"destinationPort"`
	RxPort          int    `json:"rxPort"`
	ActiveSeconds   int64  `json:"activeSeconds"`
	LastSecSYN      int64  `json:"lastSecSyn"`
	LastSecRequests int64  `json:"lastSecRequests"` // verificadas
	AvgSYN          int64  `json:"avgSynPerSec"`
	AvgRequests     int64  `json:"avgRequestsPerSec"`
	TotalSYN        int64  `json:"totalSyn"`
	TotalDropped    int64  `json:"totalDropped"` // sesiones no verificadas
}

// DeviceHealth: salud del equipo por SNMP.
type DeviceHealth struct {
	DeviceRef
	CPU              HealthCPU          `json:"cpu"`
	Accelerator      []AcceleratorCPU   `json:"accelerator"`
	Memory           ResourceUsage      `json:"memory"`
	Disk             ResourceUsage      `json:"disk"`
	Temperature      HealthTemperature  `json:"temperature"`
	PowerSupply      HealthPowerSupply  `json:"powerSupply"`
	HighAvailability HealthHA           `json:"highAvailability"`
	Clock            HealthClock        `json:"clock"`
	Tables           HealthTables       `json:"tables"`
	ErtFeedStatus    string             `json:"ertFeedStatus"`
	SyslogServers    []SyslogServerInfo `json:"syslogServers"`
}

type HealthCPU struct {
	ResourceUtilization   int64 `json:"resourceUtilization"`   // la mayor entre controlador y engines
	ControllerUtilization int64 `json:"controllerUtilization"` // rsWSDRSResourceUtilization
	EnginesAvg5s          int64 `json:"enginesAvg5s"`
	EnginesAvg60s         int64 `json:"enginesAvg60s"`
	EnginesMean           int64 `json:"enginesMean"`
}

type AcceleratorCPU struct {
	CPU          int   `json:"cpu"`
	FlowPercent  int64 `json:"flowPercent"`
	OtherPercent int64 `json:"otherPercent"`
	IdlePercent  int64 `json:"idlePercent"`
}

type HealthTemperature struct {
	CPU1              int64            `json:"cpu1"`
	CPU2              int64            `json:"cpu2"`
	CPU1Status        string           `json:"cpu1Status"` // normal, warning, critical
	CPU2Status        string           `json:"cpu2Status"`
	WarningThreshold  int64            `json:"warningThreshold"`
	ShutdownThreshold int64            `json:"shutdownThreshold"`
	PerCPU            []CPUTemperature `json:"perCpu"`
}

type HealthPowerSupply struct {
	Overall string `json:"overall"` // rdwrPowerSupplyStatus
	Supply1 string `json:"supply1"` // active, notInService, invalid
	Supply2 string `json:"supply2"`
}

type HealthHA struct {
	Priority        string `json:"priority"`        // secondary, primary, standAlone, notSupported
	ProtectionState string `json:"protectionState"` // active, passive
	PeerIP1         string `json:"peerIp1"`
	PeerIP2         string `json:"peerIp2"`
}

// HealthClock: reloj del equipo y desfase contra el reloj del host de la API
// (en la zona horaria del host: TZ del contenedor).
type HealthClock struct {
	UpTime        string `json:"upTime"`
	DeviceDate    string `json:"deviceDate"` // dd/mm/yyyy
	DeviceTime    string `json:"deviceTime"` // hh:mm:ss
	OffsetSeconds *int64 `json:"offsetSeconds"`
}

type HealthTables struct {
	SuspendEntries       int64 `json:"suspendEntries"`
	SuspendPercent       int64 `json:"suspendPercent"`
	TCPAuthPercent       int64 `json:"tcpAuthPercent"`
	HTTPAuthPercent      int64 `json:"httpAuthPercent"`
	DNSAuthPercent       int64 `json:"dnsAuthPercent"`
	HwSubPoliciesPercent int64 `json:"hwSubPoliciesPercent"`
	HwEntriesPercent     int64 `json:"hwEntriesPercent"`
}

type SyslogServerInfo struct {
	Address         string `json:"address"`
	Status          string `json:"status"`     // enable, disable
	Connection      string `json:"connection"` // reachable, unreachable, nr
	BackloggedLogs  int64  `json:"backloggedLogs"`
	Protocol        string `json:"protocol"`
	DestinationPort int64  `json:"destinationPort"`
	SecurityEvents  string `json:"securityEvents"`
	HealthEvents    string `json:"healthEvents"`
	UserAudit       string `json:"userAudit"`
}

// DeviceInfo: identidad por SNMP (SNMPv2-MIB + rnd).
type DeviceInfo struct {
	DeviceRef
	SysName          string `json:"sysName"`
	SysDescr         string `json:"sysDescr"`
	SysUpTimeSeconds int64  `json:"sysUpTimeSeconds"`
	Version          string `json:"version"`
	SerialNumber     string `json:"serialNumber"`
	OSVersion        string `json:"osVersion"`
	DeviceType       string `json:"deviceType"`
	PortsConfig      string `json:"portsConfig"`
	Throughput       string `json:"throughput"`
	AttackMitigation string `json:"attackMitigation"`
	Cores            int64  `json:"cores"`
	BaseMACAddress   string `json:"baseMacAddress"`
}
