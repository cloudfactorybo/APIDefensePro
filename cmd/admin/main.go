package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"defensepro-api/internal/config"
	"defensepro-api/internal/soap"
	"defensepro-api/internal/storage"
	"defensepro-api/pkg/httpclient"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cfg := config.Load()

	s, err := storage.Open(cfg.DB.URL)
	if err != nil {
		exit(err)
	}
	defer s.Close()

	devices := storage.NewDevicesRepo(s)
	tokens := storage.NewTokensRepo(s)
	ctx := context.Background()

	switch os.Args[1] {
	case "add-device":
		if len(os.Args) != 6 {
			fmt.Fprintln(os.Stderr, "uso: admin add-device <name> <url> <user> <pass>")
			os.Exit(2)
		}
		id, err := devices.Create(ctx, storage.Device{
			Name:               os.Args[2],
			BaseURL:            os.Args[3],
			Username:           os.Args[4],
			Password:           os.Args[5],
			InsecureSkipVerify: true,
			Enabled:            true,
		})
		if err != nil {
			exit(err)
		}
		fmt.Printf("dispositivo creado: id=%d name=%s\n", id, os.Args[2])
		fmt.Printf("verifica la conexión SOAP con: admin test-device %s\n", os.Args[2])

	case "list-devices":
		list, err := devices.List(ctx)
		if err != nil {
			exit(err)
		}
		fmt.Printf("%-4s %-20s %-35s %-10s %s\n", "ID", "NAME", "URL", "USER", "ENABLED")
		for _, d := range list {
			fmt.Printf("%-4d %-20s %-35s %-10s %v\n", d.ID, d.Name, d.BaseURL, d.Username, d.Enabled)
		}

	case "remove-device":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "uso: admin remove-device <name>")
			os.Exit(2)
		}
		if err := devices.DeleteByName(ctx, os.Args[2]); err != nil {
			exit(err)
		}
		fmt.Println("dispositivo removido")

	case "enable-device", "disable-device":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "uso: admin "+os.Args[1]+" <name>")
			os.Exit(2)
		}
		enabled := os.Args[1] == "enable-device"
		if err := devices.SetEnabled(ctx, os.Args[2], enabled); err != nil {
			exit(err)
		}
		fmt.Println("ok")

	case "test-device":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "uso: admin test-device <name>")
			os.Exit(2)
		}
		client := soapClient(ctx, devices, os.Args[2])
		fmt.Printf("endpoint: %s\n", client.Endpoint())
		checks := []struct {
			svc soap.Service
			op  string
		}{
			{soap.DeviceSystemParameters, "get_DeviceName"},
			{soap.DeviceInformation, "get_Platform"},
			{soap.DeviceInformation, "get_SoftwareVersion"},
			{soap.DeviceUtilization, "get_ResourceUtilization"},
		}
		failed := 0
		for _, c := range checks {
			v, err := callValue(ctx, client, c.svc, c.op)
			if err != nil {
				failed++
				fmt.Printf("  FAIL %-45s %v\n", c.svc.Name()+"."+c.op, err)
				continue
			}
			fmt.Printf("  OK   %-45s %s\n", c.svc.Name()+"."+c.op, v)
		}
		if failed == len(checks) {
			fmt.Println("\nsin respuesta SOAP: revisa en el equipo 'manage web-services status' y 'manage secure-web status' (deben estar en enable), la URL y las credenciales")
			os.Exit(1)
		}

	case "soap-call":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "uso: admin soap-call <name> <servicio> <operación>   (ej: soap-call dp1 Device.Information get_RamSize)")
			os.Exit(2)
		}
		client := soapClient(ctx, devices, os.Args[2])
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		body, err := client.Call(callCtx, soap.Lookup(os.Args[3]), os.Args[4])
		if err != nil {
			exit(err)
		}
		fmt.Println(string(body))

	case "create-token":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "uso: admin create-token <name>")
			os.Exit(2)
		}
		plain, id, err := tokens.Create(ctx, os.Args[2])
		if err != nil {
			exit(err)
		}
		fmt.Printf("token creado: id=%d name=%s\n", id, os.Args[2])
		fmt.Println("GUARDA ESTE TOKEN (no se vuelve a mostrar):")
		fmt.Println(plain)

	case "list-tokens":
		list, err := tokens.List(ctx)
		if err != nil {
			exit(err)
		}
		fmt.Printf("%-4s %-20s %-25s %-25s %s\n", "ID", "NAME", "CREATED", "LAST USED", "REVOKED")
		for _, t := range list {
			last := "-"
			if t.LastUsedAt != nil {
				last = t.LastUsedAt.Format(time.RFC3339)
			}
			fmt.Printf("%-4d %-20s %-25s %-25s %v\n", t.ID, t.Name, t.CreatedAt.Format(time.RFC3339), last, t.Revoked)
		}

	case "revoke-token":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "uso: admin revoke-token <id>")
			os.Exit(2)
		}
		id, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			exit(err)
		}
		if err := tokens.Revoke(ctx, id); err != nil {
			exit(err)
		}
		fmt.Println("token revocado")

	default:
		usage()
		os.Exit(2)
	}
}

func soapClient(ctx context.Context, devices *storage.DevicesRepo, name string) *soap.Client {
	d, err := devices.GetByName(ctx, name)
	if err != nil {
		exit(err)
	}
	return soap.NewClient(d.BaseURL, d.Username, d.Password, httpclient.NewSecureClient(true).Client)
}

func callValue(ctx context.Context, client *soap.Client, svc soap.Service, op string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	body, err := client.Call(ctx, svc, op)
	if err != nil {
		return "", err
	}
	resp, err := soap.Decode(body)
	if err != nil {
		return "", err
	}
	return resp.Value()
}

func usage() {
	fmt.Fprintln(os.Stderr, `defensepro-api admin

Comandos:
  add-device <name> <url> <user> <pass>
  list-devices
  remove-device <name>
  enable-device <name>
  disable-device <name>
  test-device <name>                       prueba la conexión SOAP con el equipo
  soap-call <name> <servicio> <operación>  muestra el XML crudo de una operación
                                           (ej: soap-call dp1 Device.Information get_RamSize)
  create-token <name>
  list-tokens
  revoke-token <id>

Env:
  DATABASE_URL  DSN de postgres (default: postgres://defensepro:defensepro@localhost:5432/defensepro?sslmode=disable)`)
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
