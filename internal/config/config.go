package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Server ServerConfig
	DB     DBConfig
	Redis  RedisConfig
	Auth   AuthConfig
	Device DeviceConfig
}

type ServerConfig struct {
	Host           string
	Port           string
	AllowedOrigins []string
}

type DBConfig struct {
	URL string
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type AuthConfig struct {
	Enabled bool
}

type DeviceConfig struct {
	// MaxConcurrency limita las llamadas SOAP simultáneas por DefensePro. La
	// CPU de gestión del equipo es modesta; si se ve lento, bajar a 1-2.
	MaxConcurrency int
}

func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Host:           getEnv("SERVER_HOST", "127.0.0.1"),
			Port:           getEnv("SERVER_PORT", "5687"),
			AllowedOrigins: parseCSV(getEnv("ALLOWED_ORIGINS", "*")),
		},
		DB: DBConfig{
			URL: getEnv("DATABASE_URL", "postgres://defensepro:defensepro@localhost:5432/defensepro?sslmode=disable"),
		},
		Redis: RedisConfig{
			Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
			Password: os.Getenv("REDIS_PASSWORD"),
			DB:       parseInt(os.Getenv("REDIS_DB"), 0),
		},
		Auth: AuthConfig{
			Enabled: getEnv("AUTH_DISABLED", "") != "true",
		},
		Device: DeviceConfig{
			MaxConcurrency: parseInt(os.Getenv("DEVICE_MAX_CONCURRENCY"), 4),
		},
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseInt(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
