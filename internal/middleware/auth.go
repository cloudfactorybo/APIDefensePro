package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"defensepro-api/internal/storage"
)

type ctxKey string

const CtxTokenID ctxKey = "tokenID"

func AuthMiddleware(tokens *storage.TokensRepo, logger *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHdr := r.Header.Get("Authorization")
			if authHdr == "" {
				writeAuthError(w, "falta header Authorization")
				return
			}
			const prefix = "Bearer "
			if !strings.HasPrefix(authHdr, prefix) {
				writeAuthError(w, "esperaba 'Bearer <token>'")
				return
			}
			token := strings.TrimSpace(strings.TrimPrefix(authHdr, prefix))
			if token == "" {
				writeAuthError(w, "token vacío")
				return
			}

			id, ok, err := tokens.Validate(r.Context(), token)
			if err != nil {
				logger.WithError(err).Error("fallo validando token")
				writeJSONError(w, http.StatusInternalServerError, "error interno")
				return
			}
			if !ok {
				writeAuthError(w, "token inválido o revocado")
				return
			}

			ctx := context.WithValue(r.Context(), CtxTokenID, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeAuthError(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="defensepro-api"`)
	writeJSONError(w, http.StatusUnauthorized, msg)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
