package snmp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Config de un agente SNMPv3 (USM).
type Config struct {
	Host           string
	Port           uint16
	User           string
	AuthProtocol   string // NONE, MD5, SHA, SHA224, SHA256, SHA384, SHA512
	AuthPassword   string
	PrivProtocol   string // NONE, DES, AES, AES192, AES256, AES192C, AES256C
	PrivPassword   string
	Timeout        time.Duration
	Retries        int
	MaxRepetitions uint32
}

// Kind del valor de un PDU, ya normalizado.
const (
	KindInt    = "int"
	KindUint   = "uint"
	KindString = "string"
)

// PDU es un valor leído, normalizado a int64/uint64/string. Es serializable a
// JSON sin perder precisión (para la cache).
type PDU struct {
	OID  string `json:"o"`
	Kind string `json:"k"`
	Int  int64  `json:"i,omitempty"`
	Uint uint64 `json:"u,omitempty"`
	Str  string `json:"s,omitempty"`
}

// Int64 devuelve el valor numérico (los strings numéricos también, p.ej. los
// DisplayString de rsSESSIONSynActivationTotalSYN).
func (p PDU) Int64() int64 {
	switch p.Kind {
	case KindInt:
		return p.Int
	case KindUint:
		return int64(p.Uint)
	}
	var n int64
	fmt.Sscan(strings.TrimSpace(p.Str), &n)
	return n
}

func (p PDU) Uint64() uint64 {
	if p.Kind == KindUint {
		return p.Uint
	}
	if v := p.Int64(); v > 0 {
		return uint64(v)
	}
	return 0
}

func (p PDU) String() string {
	switch p.Kind {
	case KindInt:
		return fmt.Sprint(p.Int)
	case KindUint:
		return fmt.Sprint(p.Uint)
	}
	return p.Str
}

// Client de sólo lectura: no existe ningún método que escriba en el agente.
type Client struct {
	cfg Config
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 161
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Retries == 0 {
		cfg.Retries = 1
	}
	if cfg.MaxRepetitions == 0 {
		cfg.MaxRepetitions = 25
	}
	if _, _, _, err := usm(cfg); err != nil {
		return nil, err
	}
	return &Client{cfg: cfg}, nil
}

func usm(cfg Config) (gosnmp.SnmpV3AuthProtocol, gosnmp.SnmpV3PrivProtocol, gosnmp.SnmpV3MsgFlags, error) {
	auths := map[string]gosnmp.SnmpV3AuthProtocol{
		"": gosnmp.NoAuth, "NONE": gosnmp.NoAuth, "MD5": gosnmp.MD5, "SHA": gosnmp.SHA,
		"SHA224": gosnmp.SHA224, "SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512,
	}
	privs := map[string]gosnmp.SnmpV3PrivProtocol{
		"": gosnmp.NoPriv, "NONE": gosnmp.NoPriv, "DES": gosnmp.DES, "AES": gosnmp.AES,
		"AES192": gosnmp.AES192, "AES256": gosnmp.AES256, "AES192C": gosnmp.AES192C, "AES256C": gosnmp.AES256C,
	}
	a, ok := auths[strings.ToUpper(cfg.AuthProtocol)]
	if !ok {
		return 0, 0, 0, fmt.Errorf("protocolo de autenticación SNMP no soportado: %q", cfg.AuthProtocol)
	}
	p, ok := privs[strings.ToUpper(cfg.PrivProtocol)]
	if !ok {
		return 0, 0, 0, fmt.Errorf("protocolo de privacidad SNMP no soportado: %q", cfg.PrivProtocol)
	}
	switch {
	case a == gosnmp.NoAuth && p != gosnmp.NoPriv:
		return 0, 0, 0, fmt.Errorf("SNMPv3: privacidad sin autenticación no es válido")
	case a == gosnmp.NoAuth:
		return a, p, gosnmp.NoAuthNoPriv, nil
	case p == gosnmp.NoPriv:
		return a, p, gosnmp.AuthNoPriv, nil
	}
	return a, p, gosnmp.AuthPriv, nil
}

func (c *Client) session(ctx context.Context) (*gosnmp.GoSNMP, error) {
	auth, priv, flags, _ := usm(c.cfg)
	g := &gosnmp.GoSNMP{
		Context:        ctx,
		Target:         c.cfg.Host,
		Port:           c.cfg.Port,
		Version:        gosnmp.Version3,
		Timeout:        c.cfg.Timeout,
		Retries:        c.cfg.Retries,
		MaxRepetitions: c.cfg.MaxRepetitions,
		SecurityModel:  gosnmp.UserSecurityModel,
		MsgFlags:       flags,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 c.cfg.User,
			AuthenticationProtocol:   auth,
			AuthenticationPassphrase: c.cfg.AuthPassword,
			PrivacyProtocol:          priv,
			PrivacyPassphrase:        c.cfg.PrivPassword,
		},
	}
	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect %s: %w", c.cfg.Host, err)
	}
	return g, nil
}

// Get lee OIDs escalares (con su ".0"). Los inexistentes no aparecen en el mapa.
func (c *Client) Get(ctx context.Context, oids []string) (map[string]PDU, error) {
	if err := checkAllowed(oids...); err != nil {
		return nil, err
	}
	g, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()

	out := make(map[string]PDU, len(oids))
	// Lotes chicos: algunos agentes rechazan PDUs con muchas variables.
	for i := 0; i < len(oids); i += 20 {
		batch := oids[i:min(i+20, len(oids))]
		pkt, err := g.Get(batch)
		if err != nil {
			return nil, fmt.Errorf("snmp get: %w", err)
		}
		for _, v := range pkt.Variables {
			if p, ok := normalize(v); ok {
				out[p.OID] = p
			}
		}
	}
	return out, nil
}

// Walk lee un subárbol completo con GETBULK.
func (c *Client) Walk(ctx context.Context, root string) ([]PDU, error) {
	if err := checkAllowed(root); err != nil {
		return nil, err
	}
	g, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()

	vars, err := g.BulkWalkAll(root)
	if err != nil {
		return nil, fmt.Errorf("snmp walk %s: %w", root, err)
	}
	out := make([]PDU, 0, len(vars))
	for _, v := range vars {
		if p, ok := normalize(v); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func normalize(v gosnmp.SnmpPDU) (PDU, bool) {
	p := PDU{OID: strings.TrimPrefix(v.Name, ".")}
	switch v.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		return p, false
	case gosnmp.OctetString:
		p.Kind = KindString
		if b, ok := v.Value.([]byte); ok {
			p.Str = strings.TrimRight(string(b), "\x00")
		}
	case gosnmp.IPAddress, gosnmp.ObjectIdentifier:
		p.Kind = KindString
		p.Str = fmt.Sprint(v.Value)
	case gosnmp.Integer:
		p.Kind = KindInt
		p.Int = gosnmp.ToBigInt(v.Value).Int64()
	default: // Counter32/64, Gauge32, TimeTicks, Uinteger32
		p.Kind = KindUint
		p.Uint = gosnmp.ToBigInt(v.Value).Uint64()
	}
	return p, true
}
