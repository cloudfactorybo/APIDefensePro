package models

type Monitoring struct {
	DeviceRef
	CPU          CPUStats          `json:"cpu"`
	Engines      []EngineResource  `json:"engines"`
	Memory       ResourceUsage     `json:"memory"`
	Disk         ResourceUsage     `json:"disk"`
	Traffic      TrafficStats      `json:"traffic"`
	SessionTable SessionTableStats `json:"sessionTable"`
}

// CPUStats en porcentaje (0-100).
type CPUStats struct {
	ResourceUtilization int64 `json:"resourceUtilization"` // la mayor entre controlador y engines
	EnginesAvg5s        int64 `json:"enginesAvg5s"`
	EnginesAvg60s       int64 `json:"enginesAvg60s"`
	EnginesMean         int64 `json:"enginesMean"`
}

// EngineResource es la utilización por engine de procesamiento (Device.HardwareInfo).
type EngineResource struct {
	Engine     int64 `json:"engine" soap:"Engine"`
	Forwarding int64 `json:"forwarding" soap:"Forwarding"`
	Other      int64 `json:"other" soap:"Other"`
	Idle       int64 `json:"idle" soap:"Idle"`
	Total      int64 `json:"total" soap:"Total"`
}

// ResourceUsage de RAM o disco. Used y Capacity van en la unidad que reporta el
// equipo (el WSDL no la documenta); UtilizationPercent es 0-100.
type ResourceUsage struct {
	UtilizationPercent int64 `json:"utilizationPercent"`
	Used               int64 `json:"used"`
	Capacity           int64 `json:"capacity"`
}

type TrafficStats struct {
	LastSecondMbits int64 `json:"lastSecondMbits"` // get_TotalLastSecMbits
	PeakMbps        int64 `json:"peakMbps"`        // get_TotalLastSecPeak
}

type SessionTableStats struct {
	UsedEntries int64 `json:"usedEntries"`
}

type Hardware struct {
	DeviceRef
	CPUTemperatures []CPUTemperature `json:"cpuTemperatures"`
	Fans            []Fan            `json:"fans"`
	PowerSupply     string           `json:"powerSupply"`
}

type CPUTemperature struct {
	Index       int64 `json:"index" soap:"Index"`
	Temperature int64 `json:"temperature" soap:"Temperature"`
}

type Fan struct {
	Index  int64  `json:"index" soap:"Index"`
	Status string `json:"status" soap:"Status"`
}
