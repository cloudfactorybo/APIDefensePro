// Package soap implementa un cliente mínimo para la API SOAP de Radware
// DefensePro (SOAP 1.1, estilo RPC/encoded). El equipo expone todos los
// servicios en un único endpoint (POST /soap); cada servicio se distingue por
// su namespace (p.ej. "radware.Device.Information") y su SOAPAction, tal como
// están declarados en los WSDL de DefensePro_v8-34-2-0_SOAP_API.
//
// Requisito en el equipo: "manage web-services status set enable" y, para
// HTTPS, "manage secure-web status set enable".
package soap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxResponseBytes acota lo que se lee del equipo. El log de seguridad
// (getAll_Log) es la respuesta más grande y queda muy por debajo.
const maxResponseBytes = 64 << 20

// Param es un argumento de entrada de una operación (p.ej. la clave de get_Policy).
type Param struct {
	Name  string
	Type  string // tipo xsd, p.ej. "xsd:string" o "xsd:long"
	Value string
}

type Client struct {
	endpoint   string
	username   string
	password   string
	httpClient *http.Client
}

func NewClient(baseURL, username, password string, httpClient *http.Client) *Client {
	return &Client{
		endpoint:   strings.TrimRight(baseURL, "/") + "/soap",
		username:   username,
		password:   password,
		httpClient: httpClient,
	}
}

func (c *Client) Endpoint() string { return c.endpoint }

// Call ejecuta la operación y devuelve el cuerpo crudo de la respuesta, que se
// interpreta con Decode. Separarlo permite cachear el XML tal cual. Un SOAP
// Fault (normalmente con HTTP 500) se devuelve como *Fault.
func (c *Client) Call(ctx context.Context, svc Service, op string, params ...Param) ([]byte, error) {
	if err := CheckReadOnly(svc, op, params...); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(BuildEnvelope(svc, op, params...)))
	if err != nil {
		return nil, fmt.Errorf("creando request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("Accept", "text/xml")
	req.Header.Set("SOAPAction", `"`+svc.Action+`"`)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ejecutando request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("leyendo respuesta: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("auth 401: credenciales rechazadas por el equipo")
	}
	if resp.StatusCode != http.StatusOK {
		if f := parseFault(body); f != nil {
			return nil, f
		}
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, snippet(body))
	}
	return body, nil
}

// BuildEnvelope arma el sobre SOAP 1.1 RPC/encoded de una operación.
func BuildEnvelope(svc Service, op string, params ...Param) []byte {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"`)
	b.WriteString(` xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"`)
	b.WriteString(` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)
	b.WriteString(` xmlns:xsd="http://www.w3.org/2001/XMLSchema"`)
	b.WriteString(` SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">`)
	b.WriteString(`<SOAP-ENV:Body>`)
	fmt.Fprintf(&b, `<ns1:%s xmlns:ns1="%s">`, op, svc.Namespace)
	for _, p := range params {
		typ := p.Type
		if typ == "" {
			typ = "xsd:string"
		}
		fmt.Fprintf(&b, `<%s xsi:type="%s">`, p.Name, typ)
		_ = xml.EscapeText(&b, []byte(p.Value))
		fmt.Fprintf(&b, `</%s>`, p.Name)
	}
	fmt.Fprintf(&b, `</ns1:%s>`, op)
	b.WriteString(`</SOAP-ENV:Body></SOAP-ENV:Envelope>`)
	return b.Bytes()
}

// snippet recorta el cuerpo para mensajes de error (los equipos a veces
// devuelven páginas HTML completas).
func snippet(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
