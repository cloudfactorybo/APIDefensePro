package soap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCheckReadOnly(t *testing.T) {
	cli := func(cmd string) Param { return Param{Name: "command", Value: cmd} }
	allowed := []struct {
		svc    Service
		op     string
		params []Param
	}{
		{DeviceInformation, "get_SoftwareVersion", nil},
		{SecurityPolicy, "getAll_Policy", nil},
		{SecurityReporting, "getNext_Log", []Param{{Name: "AttackIndex", Value: "1"}}},
		{CLICommand, "apply_CLICommand", []Param{cli("system internal security bdos statistics")}},
		{CLICommand, "apply_CLICommand", []Param{cli("system internal security dns statistics get Pol_DNS")}},
	}
	for _, c := range allowed {
		if err := CheckReadOnly(c.svc, c.op, c.params...); err != nil {
			t.Errorf("%s.%s debería permitirse: %v", c.svc.Name(), c.op, err)
		}
	}

	blocked := []struct {
		svc    Service
		op     string
		params []Param
	}{
		{SecurityPolicy, "set_Policy", nil},
		{SecurityPolicy, "create_Policy", nil},
		{SecurityPolicy, "delete_Policy", nil},
		{Lookup("Device.Reboot"), "reboot", nil},
		{Lookup("Security.ActivateConfiguration"), "activate_Configuration", nil},
		{ManagementLicenseAdmin, "get_LicenseKey", nil},
		{ManagementAccess, "getAll_User", nil},
		{ManagementAccess, "get_RadiusSecret", nil},
		{Lookup("Management.Snmp"), "getAll_SnmpUserTable", nil},
		{Lookup("Security.SSLCertificates"), "getAll_Certificate", nil},
		{CLICommand, "apply_CLICommand", []Param{cli("reboot")}},
		{CLICommand, "apply_CLICommand", []Param{cli("system internal security dns statistics get Pol_DNS; reboot")}},
		{CLICommand, "apply_CLICommand", []Param{cli("dp reporting security-log clear")}},
		{CLICommand, "apply_CLICommand", nil},
	}
	for _, c := range blocked {
		if err := CheckReadOnly(c.svc, c.op, c.params...); err == nil {
			t.Errorf("%s.%s %v debería bloquearse", c.svc.Name(), c.op, c.params)
		}
	}
}

// El candado está dentro de Call: una operación bloqueada nunca sale a la red.
func TestCallBlocksBeforeNetwork(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	c := NewClient(srv.URL, "u", "p", srv.Client())
	if _, err := c.Call(context.Background(), SecurityPolicy, "set_Policy"); err == nil {
		t.Fatal("set_Policy debió fallar")
	}
	if _, err := c.Call(context.Background(), ManagementLicenseAdmin, "get_LicenseKey"); err == nil {
		t.Fatal("get_LicenseKey debió fallar")
	}
	if hits.Load() != 0 {
		t.Errorf("se hicieron %d requests al equipo", hits.Load())
	}
}
