package models

// SystemInfo agrupa identidad, versiones y modos de operación del equipo
// (Device.SystemParameters, Device.Information, Security.Version, etc.).
type SystemInfo struct {
	DeviceRef
	SysName               string            `json:"sysName"`
	Description           string            `json:"description"`
	Location              string            `json:"location"`
	Contact               string            `json:"contact"`
	UpTime                string            `json:"upTime"`
	Date                  string            `json:"date"`
	Time                  string            `json:"time"`
	Platform              string            `json:"platform"`
	SoftwareVersion       string            `json:"softwareVersion"`
	BuildNumber           string            `json:"buildNumber"`
	HardwareVersion       string            `json:"hardwareVersion"`
	BaseMACAddress        string            `json:"baseMacAddress"`
	RamSize               int64             `json:"ramSize"` // get_RamSize: el WSDL dice MB, pero un DP6 real reporta 32 (= GB)
	MitigationMode        string            `json:"mitigationMode"`
	OperationMode         string            `json:"operationMode"`
	HAProtectionState     string            `json:"haProtectionState"`
	SecurityModuleVersion string            `json:"securityModuleVersion"`
	AttackDBVersion       string            `json:"attackDbVersion"`
	InstalledVersions     []SoftwareVersion `json:"installedVersions"`
}

// SoftwareVersion es una fila de Management.VersionControl (hasta 8 imágenes).
type SoftwareVersion struct {
	Index     int64  `json:"index" soap:"Index"`
	Name      string `json:"name" soap:"Name"`
	Version   string `json:"version" soap:"Version"`
	Valid     string `json:"valid" soap:"Valid"`
	Active    string `json:"active" soap:"ActiveStatus"`
	VersionOS string `json:"versionOs" soap:"VersionOS"`
	VersionDP string `json:"versionDp" soap:"VersionDP"`
}
