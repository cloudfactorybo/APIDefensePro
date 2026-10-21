package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type Device struct {
	ID                 int64
	Name               string
	BaseURL            string
	Username           string
	Password           string
	InsecureSkipVerify bool
	CACert             string
	Enabled            bool
	SNMP               SNMP // SNMP.User vacío = sin SNMP
	SSH                SSH  // SSH.HostKey vacío = sin SSH
}

// SNMP son las credenciales SNMPv3 (USM) de un equipo.
type SNMP struct {
	User      string
	Port      int
	AuthProto string
	AuthPass  string
	PrivProto string
	PrivPass  string
}

// SSH: el usuario y la contraseña son los mismos del equipo (Username/Password);
// HostKey es la llave pública del equipo en formato authorized_keys.
type SSH struct {
	Port    int
	HostKey string
}

type DevicesRepo struct {
	db *sql.DB
}

func NewDevicesRepo(s *Storage) *DevicesRepo {
	return &DevicesRepo{db: s.db}
}

const deviceColumns = `id, name, base_url, username, password, insecure_skip_verify, COALESCE(ca_cert, ''), enabled,
	snmp_user, snmp_port, snmp_auth_proto, snmp_auth_pass, snmp_priv_proto, snmp_priv_pass,
	ssh_port, ssh_host_key`

func scanDevice(row interface{ Scan(...any) error }) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.Name, &d.BaseURL, &d.Username, &d.Password,
		&d.InsecureSkipVerify, &d.CACert, &d.Enabled,
		&d.SNMP.User, &d.SNMP.Port, &d.SNMP.AuthProto, &d.SNMP.AuthPass, &d.SNMP.PrivProto, &d.SNMP.PrivPass,
		&d.SSH.Port, &d.SSH.HostKey)
	return d, err
}

func (r *DevicesRepo) List(ctx context.Context) ([]Device, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+deviceColumns+` FROM devices ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *DevicesRepo) GetByName(ctx context.Context, name string) (Device, error) {
	d, err := scanDevice(r.db.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE name = $1`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return d, fmt.Errorf("dispositivo %q no encontrado", name)
	}
	return d, err
}

func (r *DevicesRepo) Create(ctx context.Context, d Device) (int64, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, `
        INSERT INTO devices (name, base_url, username, password, insecure_skip_verify, ca_cert, enabled)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
    `, d.Name, d.BaseURL, d.Username, d.Password, d.InsecureSkipVerify, nullIfEmpty(d.CACert), d.Enabled).Scan(&id)
	return id, err
}

func (r *DevicesRepo) DeleteByName(ctx context.Context, name string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM devices WHERE name = $1`, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("dispositivo %q no encontrado", name)
	}
	return nil
}

func (r *DevicesRepo) SetEnabled(ctx context.Context, name string, enabled bool) error {
	res, err := r.db.ExecContext(ctx, `
        UPDATE devices SET enabled = $1, updated_at = NOW() WHERE name = $2
    `, enabled, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("dispositivo %q no encontrado", name)
	}
	return nil
}

// SetSNMP guarda (o, con SNMP vacío, borra) las credenciales SNMPv3 de un equipo.
func (r *DevicesRepo) SetSNMP(ctx context.Context, name string, s SNMP) error {
	if s.Port == 0 {
		s.Port = 161
	}
	res, err := r.db.ExecContext(ctx, `
        UPDATE devices SET snmp_user = $1, snmp_port = $2, snmp_auth_proto = $3, snmp_auth_pass = $4,
               snmp_priv_proto = $5, snmp_priv_pass = $6, updated_at = NOW()
        WHERE name = $7
    `, s.User, s.Port, s.AuthProto, s.AuthPass, s.PrivProto, s.PrivPass, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("dispositivo %q no encontrado", name)
	}
	return nil
}

// SetSSH guarda (o, con HostKey vacío, borra) la configuración SSH de un equipo.
func (r *DevicesRepo) SetSSH(ctx context.Context, name string, s SSH) error {
	if s.Port == 0 {
		s.Port = 22
	}
	res, err := r.db.ExecContext(ctx, `
        UPDATE devices SET ssh_port = $1, ssh_host_key = $2, updated_at = NOW() WHERE name = $3
    `, s.Port, s.HostKey, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("dispositivo %q no encontrado", name)
	}
	return nil
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
