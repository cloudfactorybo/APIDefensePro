package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"defensepro-api/internal/models"
	"defensepro-api/internal/service"
)

const (
	defaultAttackLimit = 500
	maxAttackLimit     = 10000
)

// APIHandler expone los endpoints /api/v1. Todos aceptan ?device=a,b para
// consultar sólo ciertos equipos (vacío = todos los habilitados).
type APIHandler struct {
	service *service.MultiDefenseProService
	logger  *logrus.Logger
}

func NewAPIHandler(svc *service.MultiDefenseProService, logger *logrus.Logger) *APIHandler {
	return &APIHandler{service: svc, logger: logger}
}

func (h *APIHandler) System(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllSystemInfo(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) Licenses(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllLicenses(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) Monitoring(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllMonitoring(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) Hardware(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllHardware(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) Interfaces(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllInterfaces(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) Network(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllNetwork(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

// Policies acepta ?policy=a,b para filtrar por nombre de política.
func (h *APIHandler) Policies(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllPolicies(r.Context(), devices, parseCSVParam(r, "policy"))
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

// Attacks devuelve el log de seguridad. Filtros (CSV, sin distinguir
// mayúsculas): risk, category, action, type, policy. limit por equipo
// (default 500, 0 = sin límite).
func (h *APIHandler) Attacks(w http.ResponseWriter, r *http.Request) {
	devices, ok := h.devices(w, r)
	if !ok {
		return
	}
	filter, err := parseAttackFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	results, errs := h.service.GetAllAttacks(r.Context(), devices, filter)
	writeAggregated(w, results, errs, len(results) == 0)
}

func (h *APIHandler) Suspended(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllSuspended(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) Protections(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllProtections(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

// devices lee ?device= y responde 404 si algún nombre no es un equipo activo.
func (h *APIHandler) devices(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	names := parseCSVParam(r, "device")
	if unknown := h.service.Unknown(names); len(unknown) > 0 {
		writeError(w, http.StatusNotFound, "dispositivo no encontrado o deshabilitado: "+strings.Join(unknown, ", "))
		return nil, false
	}
	return names, true
}

func parseAttackFilter(r *http.Request) (models.AttackFilter, error) {
	f := models.AttackFilter{
		Risks:      parseCSVParam(r, "risk"),
		Categories: parseCSVParam(r, "category"),
		Actions:    parseCSVParam(r, "action"),
		Types:      parseCSVParam(r, "type"),
		Policies:   parseCSVParam(r, "policy"),
		Limit:      defaultAttackLimit,
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > maxAttackLimit {
			return f, fmt.Errorf("limit inválido: debe ser un entero entre 0 y %d", maxAttackLimit)
		}
		f.Limit = n
	}
	return f, nil
}

// parseCSVParam lee un parámetro que admite CSV y repetidos: ?x=1,2 o ?x=1&x=2.
func parseCSVParam(r *http.Request, name string) []string {
	var out []string
	for _, v := range r.URL.Query()[name] {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}
