package models

type Policies struct {
	DeviceRef
	TotalPolicies        int64    `json:"totalPolicies"` // las two-way cuentan doble
	HwEntriesUtilization int64    `json:"hwEntriesUtilization"`
	SubPolicyUtilization int64    `json:"subPolicyUtilization"`
	UpdateRequired       string   `json:"updateRequired"`
	UpdateInProgress     string   `json:"updateInProgress"`
	Policies             []Policy `json:"policies"`
}

// Policy es una política de protección de red (Security.Policy getAll_Policy)
// enriquecida con su utilización (Security.PolicyUtil) y recursos de HW.
type Policy struct {
	Name                 string           `json:"name" soap:"PolicyName"`
	State                string           `json:"state" soap:"State"`
	Action               string           `json:"action" soap:"Action"`
	Priority             int64            `json:"priority" soap:"Priority"`
	Direction            string           `json:"direction" soap:"Direction"`
	SourceAddress        string           `json:"sourceAddress" soap:"PolicySourceAddress"`
	DestinationAddress   string           `json:"destinationAddress" soap:"PolicyDestinationAddress"`
	InboundPortGroup     string           `json:"inboundPortGroup" soap:"InboundPhysicalPortGroup"`
	ContextTag           string           `json:"contextTag" soap:"ContextTag"`
	PacketReport         string           `json:"packetReport" soap:"PacketReport"`
	CdnHandling          string           `json:"cdnHandling" soap:"CdnHandling"`
	SignaturesProfile    string           `json:"signaturesProfile" soap:"SignaturesProfile"`
	BehavioralDosProfile string           `json:"behavioralDosProfile" soap:"BehavioralDosProfile"`
	SynProtectionProfile string           `json:"synProtectionProfile" soap:"SynProtectionProfile"`
	DNSProtectionProfile string           `json:"dnsProtectionProfile" soap:"DNSProtectionProfile"`
	TrafficFilters       string           `json:"trafficFiltersProfile" soap:"TrafficFiltersProfile"`
	HTTPSFloodProfile    string           `json:"httpsFloodProfile" soap:"HttpsFloodProfile"`
	GeoFloodProfile      string           `json:"geoFloodProfile" soap:"GeoFloodProfile"`
	EaafProfile          string           `json:"eaafProfile" soap:"EaafProfile"`
	PpsLimitProfile      string           `json:"ppsLimitProfile" soap:"PpsLimitProfile"`
	QdosProfile          string           `json:"qdosProfile" soap:"QdosProfile"`
	UtilizationPercent   *int64           `json:"utilizationPercent"` // últimos 15 s; null si no se pudo leer
	Resources            []PolicyResource `json:"resources"`
}

type PolicyResource struct {
	Name           string `json:"-" soap:"Name"`
	Direction      string `json:"direction" soap:"Direction"`
	HwEntries      int64  `json:"hwEntries" soap:"HwEntriesNum"`
	SubPoliciesNum int64  `json:"subPolicies" soap:"SubPoliciesNum"`
}

// PolicyUtil es una fila de Security.PolicyUtil (sólo para el join).
type PolicyUtil struct {
	Name        string `soap:"PolicyName"`
	Utilization int64  `soap:"PolicyUtil"`
}

type Attacks struct {
	DeviceRef
	Summary AttackSummary `json:"summary"`
	Attacks []Attack      `json:"attacks"`
}

// Attack es una entrada del log de seguridad (Security.Reporting getAll_Log).
type Attack struct {
	Index              int64  `json:"index" soap:"AttackIndex"`
	Time               string `json:"time" soap:"AttackTime"`
	Name               string `json:"name" soap:"AttackName"`
	Type               string `json:"type" soap:"MessageType"` // started, ongoing, terminated, occur...
	Category           string `json:"category" soap:"Category"`
	Risk               string `json:"risk" soap:"Risk"`
	Action             string `json:"action" soap:"Action"`
	PolicyName         string `json:"policyName" soap:"PolicyName"`
	SourceAddress      string `json:"sourceAddress" soap:"AttackSourceAddress"`
	SourcePort         int64  `json:"sourcePort" soap:"SrcPort"`
	DestinationAddress string `json:"destinationAddress" soap:"AttackDestinationAddress"`
	DestinationPort    int64  `json:"destinationPort" soap:"DstPort"`
	Protocol           string `json:"protocol" soap:"Protocol"`
	PhysicalPort       int64  `json:"physicalPort" soap:"PhysicalPort"`
	RadwareID          int64  `json:"radwareId" soap:"RadwareID"`
	PacketCount        int64  `json:"packetCount" soap:"PacketCount"`
	ByteCount          int64  `json:"byteCount" soap:"ByteCount"`
	VlanTag            int64  `json:"vlanTag" soap:"VlanTag"`
	Context            string `json:"context" soap:"Context"`
}

// AttackSummary se calcula sobre las entradas que pasan el filtro, antes de
// aplicar el límite, para que los contadores no dependan de ?limit.
type AttackSummary struct {
	Total      int            `json:"total"`
	Returned   int            `json:"returned"`
	ByRisk     map[string]int `json:"byRisk"`
	ByCategory map[string]int `json:"byCategory"`
	ByAction   map[string]int `json:"byAction"`
	ByType     map[string]int `json:"byType"`
}

// AttackFilter es la selección pedida por query string. Campos vacíos = sin
// filtro; los valores se comparan sin distinguir mayúsculas.
type AttackFilter struct {
	Risks      []string
	Categories []string
	Actions    []string
	Types      []string
	Policies   []string
	Limit      int // 0 = sin límite
}

type SuspendTable struct {
	DeviceRef
	Total   int            `json:"total"`
	Entries []SuspendEntry `json:"entries"`
}

// SuspendEntry es un origen suspendido/bloqueado (Security.SuspendTable).
type SuspendEntry struct {
	Index          int64  `json:"index" soap:"NewerIndex"`
	SourceIP       string `json:"sourceIp" soap:"NewerSourceIP"`
	DestinationIP  string `json:"destinationIp" soap:"NewerDestIP"`
	DestPort       int64  `json:"destinationPort" soap:"NewerDestport"`
	Protocol       string `json:"protocol" soap:"NewerProtocol"`
	Module         string `json:"module" soap:"NewerModule"`
	ClassType      string `json:"classType" soap:"NewerClassType"`
	ClassName      string `json:"className" soap:"NewerClassName"`
	ExpirationType string `json:"expirationType" soap:"NewerExpirationType"`
	ExpirationTime int64  `json:"expirationTime" soap:"NewrExpirationTime"` // sic en el WSDL
	Action         string `json:"action" soap:"Action"`
	AttackID       int64  `json:"attackId" soap:"NewerAttackID"`
}

type Protections struct {
	DeviceRef
	Status       ProtectionStatus `json:"status"`
	BDoSProfiles []BDoSProfile    `json:"bdosProfiles"`
}

// ProtectionStatus es el estado global (enable/disable) de cada módulo.
type ProtectionStatus struct {
	BehavioralDoS    string `json:"behavioralDos"`
	SynProtection    string `json:"synProtection"`
	DNSProtection    string `json:"dnsProtection"`
	HTTPSFlood       string `json:"httpsFlood"`
	AntiScanning     string `json:"antiScanning"`
	Signatures       string `json:"signatures"`
	DoSShield        string `json:"dosShield"`
	OutOfState       string `json:"outOfState"`
	ErtAttackersFeed string `json:"ertAttackersFeed"`
}

// BDoSProfile es un subconjunto de Security.BehavioralDoS getAll_Profiles.
type BDoSProfile struct {
	Name                string `json:"name" soap:"ProfileName"`
	Action              string `json:"action" soap:"profileAction"`
	BandwidthIn         int64  `json:"bandwidthIn" soap:"BandwidthIn"`
	BandwidthOut        int64  `json:"bandwidthOut" soap:"BandwidthOut"`
	FootprintStrictness string `json:"footprintStrictness" soap:"footprintStrictness"`
	RateLimit           string `json:"rateLimit" soap:"rateLimit"`
	PacketReport        string `json:"packetReport" soap:"packetReport"`
	BurstStatus         string `json:"burstStatus" soap:"BurstStatus"`
	SYNFlood            string `json:"synFlood" soap:"SYNFloodstatus"`
	SYNACKFlood         string `json:"synAckFlood" soap:"SYNACKFloodstatus"`
	UDPFlood            string `json:"udpFlood" soap:"UDPFloodstatus"`
	UDPFragFlood        string `json:"udpFragFlood" soap:"UDPFRAGFloodstatus"`
	ICMPFlood           string `json:"icmpFlood" soap:"ICMPFloodstatus"`
	IGMPFlood           string `json:"igmpFlood" soap:"IGMPFloodstatus"`
	FINACKFlood         string `json:"finAckFlood" soap:"FINACKFloodstatus"`
	RSTFlood            string `json:"rstFlood" soap:"RSTFloodstatus"`
	FragFlood           string `json:"fragFlood" soap:"FRAGFloodstatus"`
}
