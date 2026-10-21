package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Storage struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS devices (
    id                   BIGSERIAL   PRIMARY KEY,
    name                 TEXT        NOT NULL UNIQUE,
    base_url             TEXT        NOT NULL,
    username             TEXT        NOT NULL,
    password             TEXT        NOT NULL,
    insecure_skip_verify BOOLEAN     NOT NULL DEFAULT TRUE,
    ca_cert              TEXT        NULL,
    enabled              BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           BIGSERIAL   PRIMARY KEY,
    token_hash   TEXT        NOT NULL UNIQUE,
    name         TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NULL,
    revoked      BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_tokens_hash ON api_tokens(token_hash);

-- SNMPv3 por equipo (opcional). Se agregan sobre bases existentes.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_user       TEXT    NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_port       INTEGER NOT NULL DEFAULT 161;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_auth_proto TEXT    NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_auth_pass  TEXT    NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_priv_proto TEXT    NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS snmp_priv_pass  TEXT    NOT NULL DEFAULT '';

-- SSH por equipo (opcional): llave de host registrada con "admin ssh-trust".
ALTER TABLE devices ADD COLUMN IF NOT EXISTS ssh_port     INTEGER NOT NULL DEFAULT 22;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS ssh_host_key TEXT    NOT NULL DEFAULT '';
`

func Open(dsn string) (*Storage, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("abriendo postgres: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migración: %w", err)
	}
	return &Storage{db: db}, nil
}

func (s *Storage) Close() error { return s.db.Close() }
func (s *Storage) DB() *sql.DB  { return s.db }
