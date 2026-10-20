package models

// DeviceRef identifica el DefensePro de origen en cada elemento de una
// respuesta agregada (la API consulta varios equipos en paralelo).
type DeviceRef struct {
	DeviceName string `json:"deviceName"`
	DeviceURL  string `json:"deviceUrl"`
	DeviceIP   string `json:"deviceIp"`
}

func (r *DeviceRef) SetDevice(ref DeviceRef) { *r = ref }
