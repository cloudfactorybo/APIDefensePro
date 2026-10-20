package models

// Networks son las clases de red que usan las políticas como origen/destino
// (Classes.Networks), agrupadas por nombre.
type Networks struct {
	DeviceRef
	Source   string         `json:"source"` // "active" (aplicada) o "configured" (pendiente de update policies)
	Networks []NetworkClass `json:"networks"`
}

type NetworkClass struct {
	Name    string         `json:"name"`
	Entries []NetworkEntry `json:"entries"`
}

type NetworkEntry struct {
	Name    string `json:"-" soap:"Name"`
	Index   int64  `json:"index" soap:"Index"`
	Address string `json:"address" soap:"Address"`
	Mask    string `json:"mask" soap:"Mask"`
}

type AccessLists struct {
	DeviceRef
	BlockList []AccessListEntry `json:"blockList"`
	AllowList []AccessListEntry `json:"allowList"`
}

// AccessListEntry es una fila de Security.AccessLists. Expiración y Dynamic
// sólo existen en la lista de bloqueo (en la de permitidos quedan en cero).
type AccessListEntry struct {
	Name               string `json:"name" soap:"Name"`
	Description        string `json:"description" soap:"Description"`
	State              string `json:"state" soap:"State"`
	SourceNetwork      string `json:"sourceNetwork" soap:"Srcnetwork"`
	DestinationNetwork string `json:"destinationNetwork" soap:"Dstnetwork"`
	SourcePortGroup    string `json:"sourcePortGroup" soap:"Srcportgroup"`
	DestPortGroup      string `json:"destinationPortGroup" soap:"Dstportgroup"`
	PhysicalPortGroup  string `json:"physicalPortGroup" soap:"Physicalportgroup"`
	Protocol           string `json:"protocol" soap:"Protocol"`
	Direction          string `json:"direction" soap:"Direction"`
	ReportAction       string `json:"reportAction" soap:"Reportaction"`
	Dynamic            string `json:"dynamic,omitempty" soap:"DynamicState"`
	ExpirationHour     int64  `json:"expirationHour" soap:"ExpirationHour"`
	ExpirationMinute   int64  `json:"expirationMinute" soap:"ExpirationMinute"`
}

type Geo struct {
	DeviceRef
	DynamicRules   []GeoRule       `json:"dynamicRules"`
	TemporaryRules []GeoRule       `json:"temporaryRules"`
	Countries      []GeoCountry    `json:"countries"`
	ExcludedIPs    []GeoExcludedIP `json:"excludedIps"`
}

// GeoRule es un bloqueo por país aplicado a una política (dinámico o temporal).
type GeoRule struct {
	PolicyName      string `json:"policyName" soap:"PolicyName"`
	GeolocationCode string `json:"geolocationCode" soap:"GeolocationCode"`
	Duration        int64  `json:"duration" soap:"Duration"`
	StartTime       string `json:"startTime" soap:"StartTime"`
	EndTime         string `json:"endTime" soap:"EndTime"`
}

// GeoCountry es un país asociado a un perfil geo.
type GeoCountry struct {
	ProfileName string `json:"profileName" soap:"ProfileName"`
	Code        string `json:"code" soap:"GeolocationCode"`
	Name        string `json:"name" soap:"GeolocationName"`
	Region      string `json:"region" soap:"GeolocationRegion"`
}

type GeoExcludedIP struct {
	ProfileName string `json:"profileName" soap:"ProfileName"`
	Address     string `json:"address" soap:"Address"`
}

// Capacity cruza uso y capacidad de las tablas internas del equipo. Si una
// tabla se llena durante un ataque, el equipo deja de mitigar como debe.
type Capacity struct {
	DeviceRef
	SessionTable       TableUsage     `json:"sessionTable"`
	SuspendTable       TableUsage     `json:"suspendTable"`
	TCPAuthentication  TableUsage     `json:"tcpAuthenticationTable"`
	HTTPAuthentication TableUsage     `json:"httpAuthenticationTable"`
	Policies           PolicyCapacity `json:"policies"`
	Limits             TableLimits    `json:"limits"`
}

// TableUsage: Used y Capacity en entradas; UtilizationPercent lo reporta el
// equipo (tablas de autenticación, que no informan Used) o se calcula como
// Used/Capacity.
type TableUsage struct {
	Status             string  `json:"status,omitempty"` // sólo session table
	Used               *int64  `json:"used,omitempty"`
	Capacity           int64   `json:"capacity"`
	UtilizationPercent float64 `json:"utilizationPercent"`
}

type PolicyCapacity struct {
	Configured           int   `json:"configured"` // filas de getAll_Policy
	Total                int64 `json:"total"`      // get_TotalPolicyNum; algunos equipos reportan 0
	MaxBDoSPolicies      int64 `json:"maxBdosPolicies"`
	MaxDNSPolicies       int64 `json:"maxDnsPolicies"`
	HwEntriesUtilization int64 `json:"hwEntriesUtilization"`
	SubPolicyUtilization int64 `json:"subPolicyUtilization"`
}

// TableLimits son tamaños máximos vigentes (Security.Tuning *Current).
type TableLimits struct {
	SourceTable             int64 `json:"sourceTable"`
	SourceCounters          int64 `json:"sourceCounters"`
	DestinationCounters     int64 `json:"destinationCounters"`
	SourceDestCounters      int64 `json:"sourceDestinationCounters"`
	AntiScanningTable       int64 `json:"antiScanningTable"`
	ServerProtectionTable   int64 `json:"serverProtectionTable"`
	HTTPFloodSuspectSources int64 `json:"httpFloodSuspectSources"`
	PPSSuspectSources       int64 `json:"ppsSuspectSources"`
	QuarantineIPs           int64 `json:"quarantineIps"`
	UserDefinedAttacks      int64 `json:"userDefinedAttacks"`
}

// Management es una auditoría de la gestión del equipo. No incluye ningún
// secreto (contraseñas, claves RADIUS/TACACS+).
type Management struct {
	DeviceRef
	Access             ManagementAccess `json:"access"`
	UserAuthentication string           `json:"userAuthentication"`
	RadiusServer       string           `json:"radiusServer"`
	TacacsServer       string           `json:"tacacsServer"`
	NTP                NTPStatus        `json:"ntp"`
	DNS                DNSClient        `json:"dns"`
	Syslog             SyslogStatus     `json:"syslog"`
	Users              []ManagementUser `json:"users"`
}

type ManagementAccess struct {
	HTTPStatus        string `json:"httpStatus"`
	HTTPPort          int64  `json:"httpPort"`
	HTTPSStatus       string `json:"httpsStatus"`
	HTTPSPort         int64  `json:"httpsPort"`
	SSLWeakCiphers    string `json:"sslWeakCiphers"`
	SSHStatus         string `json:"sshStatus"`
	SSHPort           int64  `json:"sshPort"`
	SSHSessionTimeout int64  `json:"sshSessionTimeoutMin"`
	TelnetStatus      string `json:"telnetStatus"`
	TelnetPort        int64  `json:"telnetPort"`
}

type NTPStatus struct {
	Status          string `json:"status"`
	ServerAddress   string `json:"serverAddress"`
	ServerName      string `json:"serverName"`
	ServerTime      string `json:"serverTime"`
	OffsetSeconds   string `json:"offsetSeconds"`
	TimeZone        string `json:"timeZone"`
	PollingInterval int64  `json:"pollingIntervalSec"`
}

type DNSClient struct {
	Status    string `json:"status"`
	Primary   string `json:"primary"`
	Alternate string `json:"alternate"`
}

type SyslogStatus struct {
	GlobalStatus string         `json:"globalStatus"`
	Servers      []SyslogServer `json:"servers"`
}

type SyslogServer struct {
	Address         string `json:"address" soap:"syslogServerAddress"`
	Status          string `json:"status" soap:"syslogServerOperationalStatus"`
	Protocol        string `json:"protocol" soap:"syslogServerProtocol"`
	DestinationPort int64  `json:"destinationPort" soap:"syslogServerDestinationPort"`
	SourcePort      int64  `json:"sourcePort" soap:"syslogServerSourcePort"`
	Facility        string `json:"facility" soap:"syslogServerFacility"`
	Format          string `json:"format" soap:"syslogFormatSending"`
	MinRisk         string `json:"minRisk" soap:"syslogServerRisk"`
	SecurityEvents  string `json:"securityEvents" soap:"syslogSecuritySending"`
	HealthEvents    string `json:"healthEvents" soap:"syslogHealthSending"`
	UserAudit       string `json:"userAudit" soap:"syslogUserAuditSending"`
}

// ManagementUser omite a propósito el campo Password de la tabla de usuarios.
type ManagementUser struct {
	Name        string `json:"name" soap:"UserName"`
	AccessLevel string `json:"accessLevel" soap:"UserAccess"`
	Groups      string `json:"groups" soap:"Groups"`
	Email       string `json:"email" soap:"EmailAddress"`
	Severity    string `json:"notificationSeverity" soap:"Severity"`
}
