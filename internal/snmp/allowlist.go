// Package snmp es un cliente SNMPv3 de SÓLO LECTURA para DefensePro: expone
// Get y Walk (GETBULK) y nada más. Cada OID pedido debe estar bajo una rama de
// la allowlist; el resto (firmas, configuración, comunidades, claves) se rechaza
// antes de tocar la red. OIDs verificados contra los MIB de DefensePro 8.34.2.0.
package snmp

import (
	"fmt"
	"strings"
)

const (
	radware = "1.3.6.1.4.1.89"
	rsWSD   = radware + ".35.1"
	rsIDS   = rsWSD + ".65"
)

// Ramas permitidas. Cualquier OID fuera de ellas devuelve error.
var allowed = []string{
	"1.3.6.1.2.1.1", // SNMPv2-MIB system: sysDescr, sysUpTime, sysName

	// Identidad (rnd): versión, serie, tipo, puertos, throughput, cores.
	radware + ".2.4", radware + ".2.12", radware + ".2.13", radware + ".2.14",
	radware + ".2.16", radware + ".2.17", radware + ".2.22", radware + ".2.24",

	rsIDS + ".188",    // rsTrafficUtilization: tráfico por política/puerto y protocolo
	rsWSD + ".122.59", // rsPortsStatsTable
	rsWSD + ".122.61", // rsPortStatsTotalInMbitsPerSec
	rsWSD + ".104.42", // rsSESSIONSynActivationTable (triggers SYN)
	rsWSD + ".104.53", // rsSESSIONTotalUsed
	rsWSD + ".104.54", // rsSESSIONUsedEntriesTable (por engine)

	// Salud.
	rsWSD + ".53", rsWSD + ".54", rsWSD + ".112", rsWSD + ".113", rsWSD + ".221",
	rsWSD + ".211", rsWSD + ".212", rsWSD + ".213", rsWSD + ".214", rsWSD + ".215", rsWSD + ".216",
	rsWSD + ".150", rsWSD + ".151", rsWSD + ".152", rsWSD + ".153", rsWSD + ".154", rsWSD + ".155",
	rsWSD + ".165",                             // rsHWCPUTemperatureTable
	rsWSD + ".69.2",                            // rsWSDSysUpTime
	rsWSD + ".69.3",                            // rsWSDSysManagedTime
	rsWSD + ".69.4",                            // rsWSDSysManagedDate
	rsWSD + ".69.5",                            // rsWSDSysBaseMACAddress
	rsWSD + ".69.6",                            // fuentes de poder
	rsWSD + ".88.3",                            // rsACCResourceTable
	rsWSD + ".116.10.1",                        // HA: prioridad
	rsWSD + ".116.10.10",                       // HA: estado de protección
	rsWSD + ".116.10.13", rsWSD + ".116.10.14", // HA: IPs del par
	rsIDS + ".98.6", rsIDS + ".98.7", // suspend table: entradas y %
	rsIDS + ".151", rsIDS + ".152", rsIDS + ".153", // tablas de autenticación (%)
	rsIDS + ".171", rsIDS + ".172", // utilización de HW por políticas
	rsIDS + ".185.2", // estado del feed ERT
	rsWSD + ".173",   // rdwrSyslogServerTable (sin la columna de certificado: se ignora)
}

// Allowed indica si el OID está bajo una rama permitida.
func Allowed(oid string) bool {
	oid = strings.TrimPrefix(oid, ".")
	for _, p := range allowed {
		if oid == p || strings.HasPrefix(oid, p+".") {
			return true
		}
	}
	return false
}

func checkAllowed(oids ...string) error {
	for _, o := range oids {
		if !Allowed(o) {
			return fmt.Errorf("OID fuera de la allowlist de sólo lectura: %s", o)
		}
	}
	return nil
}

// AllowedPrefixes devuelve las ramas permitidas (para mostrar).
func AllowedPrefixes() []string { return append([]string(nil), allowed...) }
