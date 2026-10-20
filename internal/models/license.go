package models

// Licenses reúne las licencias del equipo (Management.LicenseAdmin), la
// capacidad licenciada (Device.Information) y el estado del feed ERT. La clave
// de licencia (get_LicenseKey) es un secreto y no se consulta.
type Licenses struct {
	DeviceRef
	LicenseID                string `json:"licenseId"`
	ThroughputLicense        string `json:"throughputLicense"`
	ThroughputLicenseID      string `json:"throughputLicenseId"`
	ThroughputLicenseMethod  string `json:"throughputLicenseMethod"`
	ThroughputLicenseIP      string `json:"throughputLicenseIp"`
	AttackMitigationCapacity string `json:"attackMitigationCapacity"`
	ThroughputCapacity       string `json:"throughputCapacity"`
	ErtAttackersFeedStatus   string `json:"ertAttackersFeedStatus"`
}
