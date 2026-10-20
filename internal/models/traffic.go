package models

// BehavioralTraffic son las métricas en tiempo real de BDoS y DNS de una
// política (lo que APSolute Vision muestra como "BDoS/DNS Traffic Monitoring").
// Salen de comandos CLI del equipo, no del SOAP; cada bloque es nil si la
// política no tiene ese perfil asignado.
type BehavioralTraffic struct {
	DeviceRef
	Policy string       `json:"policy"`
	BDoS   *BDoSTraffic `json:"bdos"`
	DNS    *DNSTraffic  `json:"dns"`
}

type BDoSTraffic struct {
	Profile          string        `json:"profile"`
	PolicyType       string        `json:"policyType"`
	BandwidthInKbps  int64         `json:"bandwidthInKbps"`
	BandwidthOutKbps int64         `json:"bandwidthOutKbps"`
	Inbound          BDoSDirection `json:"inbound"`
	Outbound         BDoSDirection `json:"outbound"`
}

type BDoSDirection struct {
	IPv4 BDoSFamily `json:"ipv4"`
	IPv6 BDoSFamily `json:"ipv6"`
}

// BDoSFamily: los valores Bps van en la unidad del encabezado del equipo
// ("Bps"); LegitimateBps/Pps = actual - descartado.
type BDoSFamily struct {
	ConfiguredState string              `json:"configuredState"`
	LearningState   string              `json:"learningState"`
	Anomaly         bool                `json:"anomaly"`
	Protocols       []BDoSProtocolStats `json:"protocols"`
	AdvancedUDP     *AdvancedUDPStats   `json:"advancedUdp,omitempty"`
}

type BDoSProtocolStats struct {
	Protocol      string `json:"protocol"`
	BaselineBps   int64  `json:"baselineBps"`
	BaselinePps   int64  `json:"baselinePps"`
	CurrentBps    int64  `json:"currentBps"`
	CurrentPps    int64  `json:"currentPps"`
	DroppedBps    int64  `json:"droppedBps"`
	DroppedPps    int64  `json:"droppedPps"`
	LegitimateBps int64  `json:"legitimateBps"`
	LegitimatePps int64  `json:"legitimatePps"`
}

type AdvancedUDPStats struct {
	BaselineBps    int64   `json:"baselineBps"`
	BaselinePps    int64   `json:"baselinePps"`
	BaselineCpsPps float64 `json:"baselineCpsPerPps"`
	CurrentBps     int64   `json:"currentBps"`
	CurrentPps     int64   `json:"currentPps"`
	CurrentCpsPps  float64 `json:"currentCpsPerPps"`
}

type DNSTraffic struct {
	Profile     string          `json:"profile"`
	ExpectedQPS int64           `json:"expectedQps"`
	IPv4        []DNSQueryStats `json:"ipv4"`
	IPv6        []DNSQueryStats `json:"ipv6"`
}

// DNSQueryStats por tipo de consulta, en consultas por segundo.
type DNSQueryStats struct {
	Type          string `json:"type"` // A, AAAA, MX, PTR, TXT, SOA, NAPTR, SRV, OTHER
	BaselineQPS   int64  `json:"baselineQps"`
	CurrentQPS    int64  `json:"currentQps"`
	DroppedQPS    int64  `json:"droppedQps"`
	LegitimateQPS int64  `json:"legitimateQps"`
}
