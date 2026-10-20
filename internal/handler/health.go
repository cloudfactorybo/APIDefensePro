package handler

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"defensepro-api/internal/service"
)

type HealthHandler struct {
	service *service.MultiDefenseProService
	logger  *logrus.Logger
}

func NewHealthHandler(svc *service.MultiDefenseProService, logger *logrus.Logger) *HealthHandler {
	return &HealthHandler{service: svc, logger: logger}
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (h *HealthHandler) HealthDeep(w http.ResponseWriter, r *http.Request) {
	results := h.service.PingAll(r.Context())

	total := len(results)
	ok := 0
	for _, res := range results {
		if res.OK {
			ok++
		}
	}

	status := http.StatusOK
	overall := "healthy"
	switch {
	case ok == 0 && total > 0:
		status = http.StatusServiceUnavailable
		overall = "unhealthy"
	case ok < total:
		overall = "degraded"
	}

	writeJSON(w, status, map[string]interface{}{
		"status":  overall,
		"total":   total,
		"ok":      ok,
		"devices": results,
	})
}
