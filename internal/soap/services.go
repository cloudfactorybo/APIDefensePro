package soap

import "strings"

// Service identifica un servicio SOAP del DefensePro (un archivo .wsdl).
// Namespace y Action se copian tal cual de los WSDL: el SOAPAction no siempre
// se deriva del namespace (p.ej. bdosExcludedStatistics → SecurityBdos...).
type Service struct {
	Namespace string
	Action    string
}

// Name devuelve el nombre corto del servicio, p.ej. "Device.Information".
func (s Service) Name() string { return strings.TrimPrefix(s.Namespace, "radware.") }

var (
	DeviceInformation      = Service{"radware.Device.Information", "DeviceInformationAction"}
	DeviceSystemParameters = Service{"radware.Device.SystemParameters", "DeviceSystemParametersAction"}
	DeviceUtilization      = Service{"radware.Device.Utilization", "DeviceUtilizationAction"}
	DeviceStatistics       = Service{"radware.Device.Statistics", "DeviceStatisticsAction"}
	DeviceHardwareInfo     = Service{"radware.Device.HardwareInfo", "DeviceHardwareInfoAction"}
	DeviceHighAvailability = Service{"radware.Device.HighAvailability", "DeviceHighAvailabilityAction"}
	DeviceMitigation       = Service{"radware.Device.Mitigation", "DeviceMitigationAction"}
	DeviceSessionTable     = Service{"radware.Device.SessionTable", "DeviceSessionTableAction"}

	ManagementLicenseAdmin   = Service{"radware.Management.LicenseAdmin", "ManagementLicenseAdminAction"}
	ManagementVersionControl = Service{"radware.Management.VersionControl", "ManagementVersionControlAction"}

	NetworkingInterfaces   = Service{"radware.Networking.Interfaces", "NetworkingInterfacesAction"}
	NetworkingInterfacesNG = Service{"radware.Networking.InterfacesNG", "NetworkingInterfacesNGAction"}
	NetworkingStaticRoute  = Service{"radware.Networking.StaticRouting", "NetworkingStaticRoutingAction"}

	SecurityOperation          = Service{"radware.Security.Operation", "SecurityOperationAction"}
	SecurityVersion            = Service{"radware.Security.Version", "SecurityVersionAction"}
	SecurityAttackDB           = Service{"radware.Security.AttackDB", "SecurityAttackDBAction"}
	SecurityPolicy             = Service{"radware.Security.Policy", "SecurityPolicyAction"}
	SecurityPolicyUtil         = Service{"radware.Security.PolicyUtil", "SecurityPolicyUtilAction"}
	SecurityReporting          = Service{"radware.Security.Reporting", "SecurityReportingAction"}
	SecuritySuspendTable       = Service{"radware.Security.SuspendTable", "SecuritySuspendTableAction"}
	SecurityBehavioralDoS      = Service{"radware.Security.BehavioralDoS", "SecurityBehavioralDoSAction"}
	SecuritySynProtection      = Service{"radware.Security.SynProtection", "SecuritySynProtectionAction"}
	SecurityDnsProtection      = Service{"radware.Security.DnsProtection", "SecurityDnsProtectionAction"}
	SecurityHTTPSFlood         = Service{"radware.Security.HTTPSFloodProtection", "SecurityHTTPSFloodProtectionAction"}
	SecurityAntiScanning       = Service{"radware.Security.AntiScanning", "SecurityAntiScanningAction"}
	SecuritySignatures         = Service{"radware.Security.SignatureProtection", "SecuritySignatureProtectionAction"}
	SecurityStatefulInspection = Service{"radware.Security.StatefulInspection", "SecurityStatefulInspectionAction"}
	SecurityErtFeedStatus      = Service{"radware.Security.ErtAttackersFeedStatus", "SecurityErtAttackersFeedStatusAction"}
	SecurityErtFeedProtection  = Service{"radware.Security.ErtAttackersFeedProtection", "SecurityErtAttackersFeedProtectionAction"}
	SecurityBdosExcludedStats  = Service{"radware.Security.bdosExcludedStatistics", "SecurityBdosExcludedStatisticsAction"}
	SecurityOutOfState         = Service{"radware.Security.OutOfState", "SecurityOutOfStateAction"}
	SecurityTrafficFilter      = Service{"radware.Security.TrafficFilter", "SecurityTrafficFilterAction"}
	SecurityGeoProfiles        = Service{"radware.Security.GeoProfiles", "SecurityGeoProfilesAction"}
	SecurityQdosProfiles       = Service{"radware.Security.QdosProfiles", "SecurityQdosProfilesAction"}
	SecurityPpsRateLimit       = Service{"radware.Security.PpsRateLimit", "SecurityPpsRateLimitAction"}
	SecurityConnectionLimit    = Service{"radware.Security.ConnectionLimit", "SecurityConnectionLimitAction"}
	SecurityAccessLists        = Service{"radware.Security.AccessLists", "SecurityAccessListsAction"}
	SecurityGeoDynamicRule     = Service{"radware.Security.GeoPolicyDynamicRule", "SecurityGeoPolicyDynamicRuleAction"}
	SecurityGeoTemporaryRule   = Service{"radware.Security.GeoPolicyTemporaryRule", "SecurityGeoPolicyTemporaryRuleAction"}
	SecurityGeoExcludedIPs     = Service{"radware.Security.GeoExcludedIPList", "SecurityGeoExcludedIPListAction"}
	SecurityGeoCountries       = Service{"radware.Security.GeoAssocCountries", "SecurityGeoAssocCountriesAction"}
	SecurityTuning             = Service{"radware.Security.Tuning", "SecurityTuningAction"}
	SecurityAuthTables         = Service{"radware.Security.AuthenticationTables", "SecurityAuthenticationTablesAction"}

	DeviceTuning    = Service{"radware.Device.Tuning", "DeviceTuningAction"}
	DeviceDNSClient = Service{"radware.Device.DNSClient", "DeviceDNSClientAction"}
	ClassesNetworks = Service{"radware.Classes.Networks", "ClassesNetworksAction"}

	ManagementWeb           = Service{"radware.Management.Web", "ManagementWebAction"}
	ManagementSsh           = Service{"radware.Management.Ssh", "ManagementSshAction"}
	ManagementTelnet        = Service{"radware.Management.Telnet", "ManagementTelnetAction"}
	ManagementServices      = Service{"radware.Management.Services", "ManagementServicesAction"}
	ManagementSyslogServers = Service{"radware.Management.SyslogServers", "ManagementSyslogServersAction"}
	ManagementReporting     = Service{"radware.Management.Reporting", "ManagementReportingAction"}
	ManagementAccess        = Service{"radware.Management.Access", "ManagementAccessAction"}
)

var registry = map[string]Service{}

func init() {
	for _, s := range []Service{
		DeviceInformation, DeviceSystemParameters, DeviceUtilization, DeviceStatistics,
		DeviceHardwareInfo, DeviceHighAvailability, DeviceMitigation, DeviceSessionTable,
		ManagementLicenseAdmin, ManagementVersionControl,
		NetworkingInterfaces, NetworkingInterfacesNG, NetworkingStaticRoute,
		SecurityOperation, SecurityVersion, SecurityAttackDB, SecurityPolicy, SecurityPolicyUtil,
		SecurityReporting, SecuritySuspendTable, SecurityBehavioralDoS, SecuritySynProtection,
		SecurityDnsProtection, SecurityHTTPSFlood, SecurityAntiScanning, SecuritySignatures,
		SecurityStatefulInspection, SecurityErtFeedStatus, SecurityErtFeedProtection,
		SecurityBdosExcludedStats, SecurityOutOfState, SecurityTrafficFilter, SecurityGeoProfiles,
		SecurityQdosProfiles, SecurityPpsRateLimit, SecurityConnectionLimit, SecurityAccessLists,
		SecurityGeoDynamicRule, SecurityGeoTemporaryRule, SecurityGeoExcludedIPs, SecurityGeoCountries,
		SecurityTuning, SecurityAuthTables, DeviceTuning, DeviceDNSClient, ClassesNetworks,
		ManagementWeb, ManagementSsh, ManagementTelnet, ManagementServices, ManagementSyslogServers,
		ManagementReporting, ManagementAccess,
	} {
		registry[strings.ToLower(s.Name())] = s
	}
}

// Lookup resuelve un servicio por nombre corto ("Device.Information"). Si no
// está en el catálogo, deriva el SOAPAction del namespace (válido para la
// mayoría de los WSDL), lo que permite probar cualquier servicio desde el CLI.
func Lookup(name string) Service {
	name = strings.TrimPrefix(name, "radware.")
	if s, ok := registry[strings.ToLower(name)]; ok {
		return s
	}
	return Service{
		Namespace: "radware." + name,
		Action:    strings.ReplaceAll(name, ".", "") + "Action",
	}
}
