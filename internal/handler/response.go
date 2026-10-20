package handler

import (
	"encoding/json"
	"net/http"

	"defensepro-api/internal/service"
)

type APIResponse struct {
	Data   interface{}           `json:"data"`
	Errors []service.DeviceError `json:"errors,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeAggregated(w http.ResponseWriter, data interface{}, errs []service.DeviceError, empty bool) {
	if empty {
		writeJSON(w, http.StatusBadGateway, APIResponse{Data: data, Errors: errs})
		return
	}
	writeJSON(w, http.StatusOK, APIResponse{Data: data, Errors: errs})
}
