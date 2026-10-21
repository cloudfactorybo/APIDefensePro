package handler

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"defensepro-api/internal/models"
	"defensepro-api/internal/service"
)

const (
	defaultAttackLimit     = 500
	defaultBehavioralLimit = 50
	maxAttackLimit         = 10000
	defaultTop             = 10
	maxTop                 = 100
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
	filter, err := parseAttackFilter(r, defaultAttackLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	results, errs := h.service.GetAllAttacks(r.Context(), devices, filter)
	writeAggregated(w, results, errs, len(results) == 0)
}

// Profiles devuelve los perfiles de protección por módulo. ?type= (CSV) limita
// los módulos consultados; ver service.ProfileTypes.
func (h *APIHandler) Profiles(w http.ResponseWriter, r *http.Request) {
	devices, ok := h.devices(w, r)
	if !ok {
		return
	}
	types := parseCSVParam(r, "type")
	for i, t := range types {
		types[i] = strings.ToLower(t)
		if !slices.Contains(service.ProfileTypes, types[i]) {
			writeError(w, http.StatusBadRequest, "type inválido: "+t+" (válidos: "+strings.Join(service.ProfileTypes, ", ")+")")
			return
		}
	}
	results, errs := h.service.GetAllProfiles(r.Context(), devices, types)
	writeAggregated(w, results, errs, len(results) == 0)
}

// Behavioral devuelve BDoS y DNS protection: estado, perfiles, tráfico de
// puertos excluidos y ataques behavioral (mismos filtros que /attacks, limit
// default 50). ?bypass=true agrega la tabla de bypass de BDoS.
func (h *APIHandler) Behavioral(w http.ResponseWriter, r *http.Request) {
	devices, ok := h.devices(w, r)
	if !ok {
		return
	}
	filter, err := parseAttackFilter(r, defaultBehavioralLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	withBypass := strings.EqualFold(r.URL.Query().Get("bypass"), "true")
	results, errs := h.service.GetAllBehavioral(r.Context(), devices, withBypass, filter)
	writeAggregated(w, results, errs, len(results) == 0)
}

// BehavioralTraffic devuelve baseline, actual y descartado de BDoS (por
// protocolo) y DNS (por tipo de consulta). Sin ?policy= devuelve todas las
// políticas con perfil BDoS o DNS (un elemento por equipo y política); con
// ?policy=NOMBRE, sólo esa.
func (h *APIHandler) BehavioralTraffic(w http.ResponseWriter, r *http.Request) {
	devices, ok := h.devices(w, r)
	if !ok {
		return
	}
	policies := parseCSVParam(r, "policy")
	switch len(policies) {
	case 0:
		results, errs := h.service.GetAllBehavioralTrafficPolicies(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0 && len(errs) > 0)
	case 1:
		results, errs := h.service.GetAllBehavioralTraffic(r.Context(), devices, policies[0])
		writeAggregated(w, results, errs, len(results) == 0)
	default:
		writeError(w, http.StatusBadRequest, "indica una sola política (?policy=NOMBRE) o ninguna para todas")
	}
}

// Analytics devuelve tráfico, utilización por política y agregados del log.
// Acepta los filtros de /attacks (limit no aplica) y ?top= (default 10).
func (h *APIHandler) Analytics(w http.ResponseWriter, r *http.Request) {
	devices, ok := h.devices(w, r)
	if !ok {
		return
	}
	filter, err := parseAttackFilter(r, 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	top := defaultTop
	if v := r.URL.Query().Get("top"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxTop {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("top inválido: debe ser un entero entre 1 y %d", maxTop))
			return
		}
		top = n
	}
	results, errs := h.service.GetAllAnalytics(r.Context(), devices, filter, top)
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

// Networks acepta ?name=a,b para filtrar clases de red por nombre.
func (h *APIHandler) Networks(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllNetworks(r.Context(), devices, parseCSVParam(r, "name"))
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) AccessLists(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllAccessLists(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) Geo(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllGeo(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) Capacity(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllCapacity(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) Management(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllManagement(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

// TrafficPolicies (SNMP): ?policy= filtra; ?include_idle=true incluye las
// políticas sin tráfico.
func (h *APIHandler) TrafficPolicies(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllTrafficPolicies(r.Context(), devices, parseCSVParam(r, "policy"), includeIdle(r))
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

// TrafficPorts (SNMP): ?include_idle=true incluye los puertos sin tráfico.
func (h *APIHandler) TrafficPorts(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllTrafficPorts(r.Context(), devices, includeIdle(r))
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) Sessions(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllSessions(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) SynTriggers(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllSynTriggers(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) DeviceHealth(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllDeviceHealth(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func (h *APIHandler) DeviceInfo(w http.ResponseWriter, r *http.Request) {
	if devices, ok := h.devices(w, r); ok {
		results, errs := h.service.GetAllDeviceInfo(r.Context(), devices)
		writeAggregated(w, results, errs, len(results) == 0)
	}
}

func includeIdle(r *http.Request) bool {
	return strings.EqualFold(r.URL.Query().Get("include_idle"), "true")
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

func parseAttackFilter(r *http.Request, defaultLimit int) (models.AttackFilter, error) {
	f := models.AttackFilter{
		Risks:      parseCSVParam(r, "risk"),
		Categories: parseCSVParam(r, "category"),
		Actions:    parseCSVParam(r, "action"),
		Types:      parseCSVParam(r, "type"),
		Policies:   parseCSVParam(r, "policy"),
		Limit:      defaultLimit,
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
