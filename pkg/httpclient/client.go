package httpclient

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"time"
)

type Client struct {
	*http.Client
}

func NewSecureClient(insecureSkipVerify bool) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	// Cookie jar por si el equipo responde con una cookie de sesión tras el Basic
	// Auth: el jar la guarda y la reenvía en las siguientes peticiones, evitando
	// un login por request (consume CPU de gestión y slots de sesión). Las
	// cookies se guardan por host, así que cada DefensePro conserva la suya.
	// cookiejar.New(nil) nunca devuelve error con opciones nil.
	jar, _ := cookiejar.New(nil)

	return &Client{
		Client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			Jar:       jar,
		},
	}
}
