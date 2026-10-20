package reqctx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type ctxKey string

const requestIDKey ctxKey = "reqID"

// WithID devuelve un ctx con el request id embebido.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// ID extrae el request id del ctx. Devuelve "" si no hay.
func ID(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// NewID genera un id hex de 12 caracteres, suficiente para correlacionar logs
// dentro de una conversación sin ser largo como UUID.
func NewID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
