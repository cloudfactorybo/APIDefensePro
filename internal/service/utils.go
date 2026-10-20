package service

import (
	"net/url"
)

// extractIPFromURL extrae el host (IP o hostname) de una URL.
// Usa url.Hostname() para manejar correctamente IPv6 entre corchetes.
func extractIPFromURL(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
