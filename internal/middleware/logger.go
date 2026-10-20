package middleware

import (
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"defensepro-api/internal/reqctx"
)

type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.status = http.StatusOK
		r.wroteHeader = true
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func LoggingMiddleware(logger *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}

			reqID := reqctx.NewID()
			w.Header().Set("X-Request-ID", reqID)
			r = r.WithContext(reqctx.WithID(r.Context(), reqID))

			next.ServeHTTP(rec, r)

			level := levelFor(r.URL.Path, rec.status)

			fields := logrus.Fields{
				"req_id":      reqID,
				"method":      r.Method,
				"path":        r.URL.Path,
				"status":      rec.status,
				"bytes":       rec.bytes,
				"duration_ms": RoundMS(time.Since(start)),
				"client":      clientIP(r),
			}
			logger.WithFields(fields).Log(level, messageFor(rec.status))
		})
	}
}

// levelFor decide el nivel del log:
//   - 5xx → error
//   - 4xx → warn
//   - /health en 2xx → debug (lo pinchan cada 30s los chequeos de Docker y es puro ruido)
//   - resto 2xx → info
func levelFor(path string, status int) logrus.Level {
	switch {
	case status >= 500:
		return logrus.ErrorLevel
	case status >= 400:
		return logrus.WarnLevel
	case path == "/health":
		return logrus.DebugLevel
	default:
		return logrus.InfoLevel
	}
}

func messageFor(status int) string {
	switch {
	case status >= 500:
		return "http request failed"
	case status >= 400:
		return "http request rejected"
	default:
		return "http request"
	}
}

// RoundMS devuelve la duración en milisegundos con 2 decimales.
func RoundMS(d time.Duration) float64 {
	return math.Round(float64(d.Microseconds())/10) / 100
}

// clientIP prioriza X-Forwarded-For (Traefik lo setea), luego X-Real-IP,
// y cae a RemoteAddr sin puerto.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}
