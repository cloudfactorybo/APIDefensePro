package models

type Interfaces struct {
	DeviceRef
	Interfaces    []L2Interface  `json:"interfaces"`
	PhysicalPorts []PhysicalPort `json:"physicalPorts"`
	PortTraffic   []PortTraffic  `json:"portTraffic"`
}

// L2Interface es una fila de Networking.Interfaces getAll_L2Interface (IF-MIB).
// Los contadores HC son Counter64, por eso uint64.
type L2Interface struct {
	Index         int64  `json:"index" soap:"InterfaceIndex"`
	Description   string `json:"description" soap:"InterfaceDescription"`
	Type          string `json:"type" soap:"interfaceType"`
	Speed         int64  `json:"speed" soap:"InterfaceSpeed"`
	HighSpeedMbps int64  `json:"highSpeedMbps" soap:"ifHighSpeed"`
	MACAddress    string `json:"macAddress" soap:"MACAddress"`
	AdminStatus   string `json:"adminStatus" soap:"InterfaceAdminStatus"`
	OperStatus    string `json:"operStatus" soap:"OperationalStatus"`
	LastChange    int64  `json:"lastChange" soap:"InterfaceLastChange"`
	InOctets      uint64 `json:"inOctets" soap:"ifHCInOctets"`
	OutOctets     uint64 `json:"outOctets" soap:"ifHCOutOctets"`
	InUcastPkts   uint64 `json:"inUcastPkts" soap:"InUcastPkt"`
	InNUcastPkts  uint64 `json:"inNUcastPkts" soap:"InNUcastPkt"`
	OutUcastPkts  uint64 `json:"outUcastPkts" soap:"OutUcastPkt"`
	OutNUcastPkts uint64 `json:"outNUcastPkts" soap:"outNUcastPkt"`
	InDiscards    uint64 `json:"inDiscards" soap:"ifInDiscards"`
	InErrors      uint64 `json:"inErrors" soap:"ifInErrors"`
	OutDiscards   uint64 `json:"outDiscards" soap:"ifOutDiscards"`
	OutErrors     uint64 `json:"outErrors" soap:"ifOutErrors"`
}

type PhysicalPort struct {
	PortIndex     int64  `json:"portIndex" soap:"PortIndex"`
	Speed         string `json:"speed" soap:"Speed"`
	Duplex        string `json:"duplex" soap:"Duplex"`
	AutoNegotiate string `json:"autoNegotiate" soap:"AutoNegotiate"`
}

// PortTraffic es el tráfico del último segundo por puerto (Device.Statistics).
type PortTraffic struct {
	PortIndex    int64 `json:"portIndex" soap:"PortIndex"`
	InMegabytes  int64 `json:"inMegabytes" soap:"InBoundMegabytes"`
	InPackets    int64 `json:"inPackets" soap:"InBoundPackets"`
	InDiscards   int64 `json:"inDiscards" soap:"InBoundDiscards"`
	InErrors     int64 `json:"inErrors" soap:"InBoundErrors"`
	OutMegabytes int64 `json:"outMegabytes" soap:"OutBoundMegabytes"`
	OutPackets   int64 `json:"outPackets" soap:"OutBoundPackets"`
	OutDiscards  int64 `json:"outDiscards" soap:"OutBoundDiscards"`
	OutErrors    int64 `json:"outErrors" soap:"OutBoundErrors"`
}

type Network struct {
	DeviceRef
	IPInterfaces []IPInterface `json:"ipInterfaces"`
	Routes       []Route       `json:"routes"`
}

// IPInterface viene de Networking.InterfacesNG (soporta IPv4 e IPv6).
type IPInterface struct {
	Address       string `json:"address" soap:"IpAdEntAddr"`
	PrefixLength  int64  `json:"prefixLength" soap:"IpAdEntNetPrefix"`
	IfIndex       int64  `json:"ifIndex" soap:"IpAdEntIfIndex"`
	VlanTag       int64  `json:"vlanTag" soap:"IpAdEntVlanTag"`
	Label         string `json:"label" soap:"IpAdEntLabel"`
	BackupAddress string `json:"backupAddress" soap:"IpAdEntBackupAddr"`
}

type Route struct {
	Destination string `json:"destination" soap:"DestinationAddress"`
	NetworkMask int64  `json:"networkMask" soap:"NetworkMask"`
	NextHop     string `json:"nextHop" soap:"NextHop"`
	IfIndex     int64  `json:"ifIndex" soap:"InterfaceIndex"`
	Type        string `json:"type" soap:"Type"`
	Protocol    string `json:"protocol" soap:"Protocol"`
	Metric      int64  `json:"metric" soap:"Metric"`
	Age         int64  `json:"age" soap:"Age"`
}
