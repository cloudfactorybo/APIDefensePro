package models

// Licenses reúne las licencias del equipo (Management.LicenseAdmin), la
// capacidad licenciada (Device.Information) y el estado del feed ERT.
type Licenses struct {
	DeviceRef
	LicenseID                string `json:"licenseId"`
	LicenseKey               string `json:"licenseKey"`
	ThroughputLicense        string `json:"throughputLicense"`
	ThroughputLicenseID      string `json:"throughputLicenseId"`
	ThroughputLicenseMethod  string `json:"throughputLicenseMethod"`
	ThroughputLicenseIP      string `json:"throughputLicenseIp"`
	AttackMitigationCapacity string `json:"attackMitigationCapacity"`
	ThroughputCapacity       string `json:"throughputCapacity"`
	ErtAttackersFeedStatus   string `json:"ertAttackersFeedStatus"`
}
