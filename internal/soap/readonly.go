package soap

import (
	"fmt"
	"regexp"
	"strings"
)

// Candado de sólo lectura. Client.Call lo aplica a TODA llamada, así que ni un
// bug ni el CLI de administración pueden escribir en el equipo ni leer secretos.

var readPrefixes = []string{"get_", "getAll_", "getFirst_", "getNext_"}

// secretOps son lecturas que devuelven secretos en claro (generado desde los
// WSDL v8.34.2.0: ops con el secreto en el nombre o en las filas de la tabla).
var secretOps = map[string]bool{
	"radware.Management.Access#get_RadiusSecret":       true,
	"radware.Management.Access#get_BackupRadiusSecret": true,
	"radware.Management.Access#get_TacacsMainSecret":   true,
	"radware.Management.Access#get_TacacsBackupSecret": true,
	"radware.Management.LicenseAdmin#get_LicenseKey":   true,
	"radware.Management.Web#get_PrivateKey":            true,
	// Filas con Password / AuthenticationPassword / PrivacyPassword / KeyPassphrase.
	"radware.Management.Access#get_User":                    true,
	"radware.Management.Access#getAll_User":                 true,
	"radware.Management.Access#getFirst_User":               true,
	"radware.Management.Access#getNext_User":                true,
	"radware.Management.Snmp#get_SnmpUserTable":             true,
	"radware.Management.Snmp#getAll_SnmpUserTable":          true,
	"radware.Management.Snmp#getFirst_SnmpUserTable":        true,
	"radware.Management.Snmp#getNext_SnmpUserTable":         true,
	"radware.Security.SSLCertificates#get_Certificate":      true,
	"radware.Security.SSLCertificates#getAll_Certificate":   true,
	"radware.Security.SSLCertificates#getFirst_Certificate": true,
	"radware.Security.SSLCertificates#getNext_Certificate":  true,
}

// cliAllowed son los únicos comandos CLI que se pueden ejecutar vía
// CLI.Command: sólo lectura, sin texto libre (el nombre de política se valida).
var cliAllowed = []*regexp.Regexp{
	regexp.MustCompile(`^system internal security bdos statistics$`),
	regexp.MustCompile(`^system internal security dns statistics get [A-Za-z0-9_.\-]{1,64}$`),
	regexp.MustCompile(`^dp rtm policy-utilization$`),
}

// CLICommands devuelve los patrones de comandos CLI permitidos (para mostrar).
func CLICommands() []string {
	out := make([]string, len(cliAllowed))
	for i, re := range cliAllowed {
		out[i] = strings.Trim(re.String(), "^$")
	}
	return out
}

// CheckReadOnly devuelve error si la operación no es una lectura permitida.
func CheckReadOnly(svc Service, op string, params ...Param) error {
	if svc == CLICommand && op == "apply_CLICommand" {
		cmd := ""
		for _, p := range params {
			if p.Name == "command" {
				cmd = p.Value
			}
		}
		for _, re := range cliAllowed {
			if re.MatchString(cmd) {
				return nil
			}
		}
		return fmt.Errorf("comando CLI no permitido (sólo lectura): %q", cmd)
	}

	read := false
	for _, p := range readPrefixes {
		if strings.HasPrefix(op, p) {
			read = true
			break
		}
	}
	if !read {
		return fmt.Errorf("operación no permitida (sólo lectura): %s.%s", svc.Name(), op)
	}
	if secretOps[svc.Namespace+"#"+op] {
		return fmt.Errorf("operación bloqueada (devuelve secretos): %s.%s", svc.Name(), op)
	}
	return nil
}
