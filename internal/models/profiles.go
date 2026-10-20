package models

// Profiles agrupa los perfiles de protección por módulo. Con ?type= sólo se
// consultan algunos; los no pedidos quedan en nil y no aparecen en el JSON.
type Profiles struct {
	DeviceRef
	BDoS            *[]BDoSProfile            `json:"bdos,omitempty"`
	DNS             *[]DNSProfile             `json:"dns,omitempty"`
	SYN             *[]SYNProfile             `json:"syn,omitempty"`
	HTTPSFlood      *[]HTTPSFloodProfile      `json:"httpsFlood,omitempty"`
	OutOfState      *[]OutOfStateProfile      `json:"outOfState,omitempty"`
	AntiScanning    *[]AntiScanningProfile    `json:"antiScanning,omitempty"`
	TrafficFilters  *[]TrafficFilterProfile   `json:"trafficFilters,omitempty"`
	Geo             *[]GeoProfile             `json:"geo,omitempty"`
	ErtFeed         *[]ErtFeedProfile         `json:"ertFeed,omitempty"`
	QDoS            *[]QDoSProfile            `json:"qdos,omitempty"`
	PPSRateLimit    *[]PPSRateLimitProfile    `json:"ppsRateLimit,omitempty"`
	ConnectionLimit *[]ConnectionLimitProfile `json:"connectionLimit,omitempty"`
}

// DNSProfile es Security.DnsProtection getAll_DnsProtectionProfile.
type DNSProfile struct {
	Name                string `json:"name" soap:"ProfileName"`
	Action              string `json:"action" soap:"Action"`
	ExpectedQPS         int64  `json:"expectedQps" soap:"ExpectedQps"`
	MaxAllowedQPS       int64  `json:"maxAllowedQps" soap:"MaxAllowedQPS"`
	SignatureRateLimit  int64  `json:"signatureRateLimitPercent" soap:"SigRateLimit"`
	FootprintStrictness string `json:"footprintStrictness" soap:"footprintStrictness"`
	PacketReport        string `json:"packetReport" soap:"packetReport"`
	ManualTrigger       string `json:"manualTrigger" soap:"ManTrigStatus"`
	AFlood              string `json:"aFlood" soap:"DnsAFloodstatus"`
	AAAAFlood           string `json:"aaaaFlood" soap:"DnsAaaaFloodstatus"`
	MXFlood             string `json:"mxFlood" soap:"DnsMxFloodstatus"`
	PTRFlood            string `json:"ptrFlood" soap:"DnsPtrFloodstatus"`
	TXTFlood            string `json:"txtFlood" soap:"DnsTextFloodstatus"`
	SOAFlood            string `json:"soaFlood" soap:"DnsSoaFloodstatus"`
	NAPTRFlood          string `json:"naptrFlood" soap:"DnsNaptrFloodstatus"`
	SRVFlood            string `json:"srvFlood" soap:"DnsSrvFloodstatus"`
	OtherFlood          string `json:"otherFlood" soap:"DnsOtherFloodstatus"`
	ComplianceCheck     string `json:"complianceCheck" soap:"DnsProtProfileComplianceCheck"`
	SDAutoLearning      string `json:"subdomainAutoLearning" soap:"DnsProtProfileSdAutoLearning"`
}

// SYNProfile es Security.SynProtection getAll_rsIDSSynProfilesParamsEntry.
type SYNProfile struct {
	Name                 string `json:"name" soap:"Name"`
	Action               string `json:"action" soap:"Action"`
	ActivationMode       string `json:"activationMode" soap:"Activation-Mode"`
	ActivationThreshold  int64  `json:"activationThreshold" soap:"ActivationThreshold"`
	TrackingMode         string `json:"trackingMode" soap:"TrackingMode"`
	AuthenticationMethod string `json:"authenticationMethod" soap:"authenticationMethod"`
	HTTPAuthentication   string `json:"httpAuthentication" soap:"HttpAuthenticationStatus"`
	HTTPAuthMethod       string `json:"httpAuthenticationMethod" soap:"HttpAuthenticationMethod"`
	TCPReset             string `json:"tcpReset" soap:"TCPResetStatus"`
	SSL                  string `json:"ssl" soap:"SSLStatus"`
	DestinationPorts     string `json:"destinationPorts" soap:"DestinationPorts"`
}

type HTTPSFloodProfile struct {
	Name                  string `json:"name" soap:"ProfileName"`
	Action                string `json:"action" soap:"profileAction"`
	RateLimitStatus       string `json:"rateLimitStatus" soap:"rateLimitStatus"`
	RateLimit             int64  `json:"rateLimit" soap:"rateLimit"`
	ChallengeMethod       string `json:"challengeMethod" soap:"challengeMethod"`
	SelectiveChallenge    string `json:"selectiveChallenge" soap:"selectiveChallenge"`
	CollectiveChallenge   string `json:"collectiveChallenge" soap:"profileCollectiveChallenge"`
	FullSessionDecryption string `json:"fullSessionDecryption" soap:"fullSessionDecryption"`
}

type OutOfStateProfile struct {
	Name                  string `json:"name" soap:"ProfileName"`
	Action                string `json:"action" soap:"ProfileAction"`
	Risk                  string `json:"risk" soap:"ProfileRisk"`
	ActivationThreshold   int64  `json:"activationThreshold" soap:"ACTThreshold"`
	TerminationThreshold  int64  `json:"terminationThreshold" soap:"TermThreshold"`
	SYNACKAllow           string `json:"synAckAllow" soap:"SYNACKAllow"`
	PacketReport          string `json:"packetReport" soap:"PacketReport"`
	IdleState             string `json:"idleState" soap:"enableIdleState"`
	GracePeriodAfterIdle  int64  `json:"gracePeriodAfterUpdate" soap:"GPAfterUpdatePolicyorIdleState"`
	IdleBandwidthThreshld int64  `json:"idleStateBandwidthThreshold" soap:"idleStateBandwidthThreshold"`
}

type AntiScanningProfile struct {
	Name           string `json:"name" soap:"ProfileName"`
	Action         string `json:"action" soap:"ScanAction"`
	Sensitivity    string `json:"sensitivity" soap:"Sensitivity"`
	TCP            string `json:"tcp" soap:"TCPState"`
	UDP            string `json:"udp" soap:"UDPState"`
	ICMP           string `json:"icmp" soap:"ICMPState"`
	TrackingTime   int64  `json:"trackingTime" soap:"TrackingTime"`
	NumberOfProbes int64  `json:"numberOfProbes" soap:"NumberOfProbes"`
	PacketReport   string `json:"packetReport" soap:"PacketReport"`
}

type TrafficFilterProfile struct {
	Name       string `json:"name" soap:"ProfileName"`
	Action     string `json:"action" soap:"Action"`
	NumFilters int64  `json:"numFilters" soap:"NumOfFilters"`
}

type GeoProfile struct {
	Name         string `json:"name" soap:"Name"`
	ListType     string `json:"listType" soap:"GeoAction"`
	ReportAction string `json:"action" soap:"ReportAction"`
}

// ErtFeedProfile define la acción por categoría y nivel de riesgo del feed ERT.
type ErtFeedProfile struct {
	Name        string `json:"name" soap:"ProfileName"`
	ErtLow      string `json:"ertLow" soap:"ertLowAction"`
	ErtMedium   string `json:"ertMedium" soap:"ertMediumAction"`
	ErtHigh     string `json:"ertHigh" soap:"ertHighAction"`
	TorLow      string `json:"torLow" soap:"torLowAction"`
	TorMedium   string `json:"torMedium" soap:"torMediumAction"`
	TorHigh     string `json:"torHigh" soap:"torHighAction"`
	WebLow      string `json:"webLow" soap:"webLowAction"`
	WebMedium   string `json:"webMedium" soap:"webMediumAction"`
	WebHigh     string `json:"webHigh" soap:"webHighAction"`
	ScannerLow  string `json:"scannerLow" soap:"scanLowAction"`
	ScannerMed  string `json:"scannerMedium" soap:"scanMediumAction"`
	ScannerHigh string `json:"scannerHigh" soap:"scanHighAction"`
}

type QDoSProfile struct {
	Name              string `json:"name" soap:"ProfileName"`
	Action            string `json:"action" soap:"ProfileAction"`
	TopTalkers        string `json:"topTalkers" soap:"QuantileTopTalkersStatus"`
	RateLimit         string `json:"rateLimit" soap:"QuantileRateLimitStatus"`
	RealTimeSignature string `json:"realTimeSignature" soap:"QuantileRealTimeSignatureStatus"`
	MinimumAttackRate int64  `json:"minimumAttackRate" soap:"MinimumAttackRate"`
	PacketReport      string `json:"packetReport" soap:"PacketReport"`
}

type PPSRateLimitProfile struct {
	Name           string `json:"name" soap:"ProfileName"`
	NumProtections int64  `json:"numProtections" soap:"NumOfProtections"`
}

// ConnectionLimitProfile es una fila por (perfil, protección asociada).
type ConnectionLimitProfile struct {
	Name       string `json:"name" soap:"ProfileName"`
	AttackName string `json:"attackName" soap:"AttackName"`
	ServiceID  int64  `json:"serviceId" soap:"ProfileServiceId"`
}

// Behavioral reúne las protecciones de comportamiento (BDoS y DNS).
type Behavioral struct {
	DeviceRef
	Policies             []BehavioralPolicy     `json:"policies"`
	BDoS                 BehavioralBDoS         `json:"bdos"`
	DNS                  BehavioralDNS          `json:"dns"`
	ExcludedPortsTraffic []ExcludedPortsTraffic `json:"excludedPortsTraffic"`
	AttackSummary        AttackSummary          `json:"attackSummary"`
	Attacks              []Attack               `json:"attacks"`
}

// BehavioralPolicy es una política con protección behavioral (BDoS y/o DNS)
// y los perfiles que tiene asignados.
type BehavioralPolicy struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	Action      string `json:"action"`
	BDoSProfile string `json:"bdosProfile"`
	DNSProfile  string `json:"dnsProfile"`
}

type BehavioralBDoS struct {
	Status                 string        `json:"status"`
	LearningResponsePeriod string        `json:"learningResponsePeriod"`
	OverBlocking           string        `json:"overBlocking"`
	Sampling               string        `json:"sampling"`
	Profiles               []BDoSProfile `json:"profiles"`
	Bypass                 *[]BDoSBypass `json:"bypass,omitempty"` // sólo con ?bypass=true
}

type BehavioralDNS struct {
	Status                 string       `json:"status"`
	LearningResponsePeriod string       `json:"learningResponsePeriod"`
	Profiles               []DNSProfile `json:"profiles"`
}

type BDoSBypass struct {
	Controller string `json:"controller" soap:"BypassController"`
	Field      string `json:"field" soap:"BypassField"`
	Status     string `json:"status" soap:"BypassStatus"`
	Values     string `json:"values" soap:"BypassValues"`
}

// ExcludedPortsTraffic es el tráfico de los puertos UDP excluidos de BDoS por
// política (Security.bdosExcludedStatistics), en bps y pps.
type ExcludedPortsTraffic struct {
	PolicyName      string `json:"policyName" soap:"PolicyName"`
	LastSecondBps   int64  `json:"lastSecondBps" soap:"LastSecondbps"`
	LastSecondPps   int64  `json:"lastSecondPps" soap:"LastSecondpps"`
	LastHourBpsAvg  int64  `json:"lastHourBpsAvg" soap:"LastHourbpsAverage"`
	LastHourBpsPeak int64  `json:"lastHourBpsPeak" soap:"LastHourbpsPeak"`
	LastHourPpsAvg  int64  `json:"lastHourPpsAvg" soap:"LastHourppsAverage"`
	LastHourPpsPeak int64  `json:"lastHourPpsPeak" soap:"LastHourppsPeak"`
	LastDayBpsAvg   int64  `json:"lastDayBpsAvg" soap:"LastDaybpsAverage"`
	LastDayBpsPeak  int64  `json:"lastDayBpsPeak" soap:"LastDaybpsPeak"`
	LastDayPpsAvg   int64  `json:"lastDayPpsAvg" soap:"LastDayppsAverage"`
	LastDayPpsPeak  int64  `json:"lastDayPpsPeak" soap:"LastDayppsPeak"`
	LastWeekBpsAvg  int64  `json:"lastWeekBpsAvg" soap:"LastWeekbpsAverage"`
	LastWeekBpsPeak int64  `json:"lastWeekBpsPeak" soap:"LastWeekbpsPeak"`
	LastWeekPpsAvg  int64  `json:"lastWeekPpsAvg" soap:"LastWeekppsAverage"`
	LastWeekPpsPeak int64  `json:"lastWeekPpsPeak" soap:"LastWeekppsPeak"`
}

// Analytics es una vista de "network analytics" armada con lo que expone el
// equipo: tráfico actual, utilización por política y agregados del log.
type Analytics struct {
	DeviceRef
	Traffic           TrafficStats    `json:"traffic"`
	PortTraffic       []PortTraffic   `json:"portTraffic"`
	PolicyUtilization []PolicyUtil    `json:"policyUtilization"`
	Attacks           AttackAnalytics `json:"attacks"`
}

type AttackAnalytics struct {
	TotalEntries        int            `json:"totalEntries"`
	OldestTime          string         `json:"oldestTime"`
	NewestTime          string         `json:"newestTime"`
	TotalPackets        int64          `json:"totalPackets"`
	TotalBytes          int64          `json:"totalBytes"`
	ByRisk              map[string]int `json:"byRisk"`
	ByCategory          map[string]int `json:"byCategory"`
	ByAction            map[string]int `json:"byAction"`
	ByType              map[string]int `json:"byType"`
	ByProtocol          map[string]int `json:"byProtocol"`
	TopAttacks          []TopItem      `json:"topAttacks"`
	TopSources          []TopItem      `json:"topSources"`
	TopDestinations     []TopItem      `json:"topDestinations"`
	TopDestinationPorts []TopItem      `json:"topDestinationPorts"`
	TopPolicies         []TopItem      `json:"topPolicies"`
}

type TopItem struct {
	Key     string `json:"key"`
	Count   int    `json:"count"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}
