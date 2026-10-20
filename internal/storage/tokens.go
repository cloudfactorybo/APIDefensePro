package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

type Token struct {
	ID         int64
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	Revoked    bool
}

type TokensRepo struct {
	db *sql.DB
}

func NewTokensRepo(s *Storage) *TokensRepo {
	return &TokensRepo{db: s.db}
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// Create genera un token nuevo y devuelve el valor en claro (sólo aquí) y el id.
func (r *TokensRepo) Create(ctx context.Context, name string) (string, int64, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", 0, err
	}
	plain := hex.EncodeToString(b)

	var id int64
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO api_tokens (token_hash, name) VALUES ($1, $2) RETURNING id`,
		hashToken(plain), name).Scan(&id)
	if err != nil {
		return "", 0, err
	}
	return plain, id, nil
}

// Validate verifica un token y actualiza last_used_at. Retorna (id, válido, err).
func (r *TokensRepo) Validate(ctx context.Context, plain string) (int64, bool, error) {
	var id int64
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM api_tokens WHERE token_hash = $1 AND revoked = FALSE`,
		hashToken(plain)).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	_, _ = r.db.ExecContext(ctx,
		`UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`, id)
	return id, true, nil
}

func (r *TokensRepo) List(ctx context.Context) ([]Token, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, created_at, last_used_at, revoked FROM api_tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Token
	for rows.Next() {
		var t Token
		var lastUsed sql.NullTime
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &lastUsed, &t.Revoked); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			lt := lastUsed.Time
			t.LastUsedAt = &lt
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *TokensRepo) Revoke(ctx context.Context, id int64) error {
	res, err := r.db.ExecContext(ctx, `UPDATE api_tokens SET revoked = TRUE WHERE id = $1`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token %d no encontrado", id)
	}
	return nil
}

func (r *TokensRepo) CountActive(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM api_tokens WHERE revoked = FALSE`).Scan(&n)
	return n, err
}
