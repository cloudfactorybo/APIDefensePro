package models

// DeviceRef identifica el DefensePro de origen en cada elemento de una
// respuesta agregada (la API consulta varios equipos en paralelo).
type DeviceRef struct {
	DeviceName  string `json:"deviceName"`
	DeviceURL   string `json:"deviceUrl"`
	DeviceIP    string `json:"deviceIp"`
	CollectedAt string `json:"collectedAt"` // RFC3339 UTC; sirve de @timestamp en ELK
	// Errors lista las sub-lecturas que fallaron: su dato quedó vacío o en 0 y
	// no debe interpretarse como un valor real.
	Errors []string `json:"errors,omitempty"`
	// Unsupported lista las lecturas que este modelo de equipo no tiene
	// (p.ej. Device.Mitigation en un DefensePro 6): su dato no aplica.
	Unsupported []string `json:"unsupported,omitempty"`
}

// SetDevice completa la identidad del equipo sin tocar Errors.
func (r *DeviceRef) SetDevice(ref DeviceRef) {
	r.DeviceName, r.DeviceURL, r.DeviceIP, r.CollectedAt = ref.DeviceName, ref.DeviceURL, ref.DeviceIP, ref.CollectedAt
}

// AddError registra una sub-lectura fallida.
func (r *DeviceRef) AddError(msg string) { r.Errors = append(r.Errors, msg) }

// AddUnsupported registra una lectura que el modelo no soporta.
func (r *DeviceRef) AddUnsupported(op string) { r.Unsupported = append(r.Unsupported, op) }
