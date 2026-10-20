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
		SecurityStatefulInspection, SecurityErtFeedStatus,
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
