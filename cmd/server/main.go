package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"defensepro-api/internal/cache"
	"defensepro-api/internal/config"
	"defensepro-api/internal/handler"
	"defensepro-api/internal/logformat"
	"defensepro-api/internal/middleware"
	"defensepro-api/internal/service"
	"defensepro-api/internal/storage"
	"defensepro-api/pkg/httpclient"
)

const (
	// warmupInitialDelay da tiempo al servidor HTTP a aceptar tráfico antes de
	// empezar a llamar a los DefensePro en background.
	warmupInitialDelay = 5 * time.Second
	// warmupInterval decide cada cuánto re-ejecutamos el warmup; también refresca
	// la lista de equipos desde la DB (para capturar cambios hechos con cmd/admin)
	// y mantiene caliente en Redis la info estática de /system.
	warmupInterval = 5 * time.Minute
	warmupTimeout  = 60 * time.Second
	refreshTimeout = 10 * time.Second
)

func main() {
	logger := logrus.New()
	logger.SetFormatter(logformat.NewFormatter(os.Getenv("LOG_FORMAT")))

	lvl, err := logrus.ParseLevel(strings.ToLower(os.Getenv("LOG_LEVEL")))
	if err != nil {
		lvl = logrus.InfoLevel
	}
	logger.SetLevel(lvl)

	cfg := config.Load()

	s, err := storage.Open(cfg.DB.URL)
	if err != nil {
		logger.WithError(err).Fatal("no se pudo abrir postgres")
	}
	defer s.Close()

	devicesRepo := storage.NewDevicesRepo(s)
	tokensRepo := storage.NewTokensRepo(s)

	if cfg.Auth.Enabled {
		n, err := tokensRepo.CountActive(context.Background())
		if err != nil {
			logger.WithError(err).Warn("no se pudo contar tokens")
		} else if n == 0 {
			logger.Warn("no hay tokens activos — ejecuta 'defensepro-admin create-token <nombre>' para emitir uno")
		}
	}

	respCache, err := cache.NewRedis(cache.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
		Logger:   logger,
	})
	if err != nil {
		logger.WithError(err).Fatal("no se pudo conectar a redis")
	}
	defer respCache.Close()

	httpClient := httpclient.NewSecureClient(true)

	multi := service.NewMultiDefenseProService(devicesRepo, httpClient, logger, respCache, cfg.Device.MaxConcurrency)

	refreshCtx, refreshCancel := context.WithTimeout(context.Background(), refreshTimeout)
	if err := multi.Refresh(refreshCtx); err != nil {
		logger.WithError(err).Error("carga inicial de equipos falló")
	}
	refreshCancel()

	if multi.Count() == 0 {
		logger.Warn("no hay equipos configurados — usa 'defensepro-admin add-device <name> <url> <user> <pass>'")
	}

	warmupStop := make(chan struct{})
	go runWarmup(multi, logger, warmupStop)

	healthHandler := handler.NewHealthHandler(multi, logger)
	apiHandler := handler.NewAPIHandler(multi, logger)

	r := mux.NewRouter()
	r.Use(middleware.LoggingMiddleware(logger))
	r.Use(middleware.GzipMiddleware)
	r.Use(middleware.CORSMiddleware(cfg.Server.AllowedOrigins))

	r.HandleFunc("/health", healthHandler.Health).Methods(http.MethodGet)
	r.HandleFunc("/health/deep", healthHandler.HealthDeep).Methods(http.MethodGet)

	v1 := r.PathPrefix("/api/v1").Subrouter()
	if cfg.Auth.Enabled {
		v1.Use(middleware.AuthMiddleware(tokensRepo, logger))
	} else {
		logger.Warn("auth deshabilitado (AUTH_DISABLED=true)")
	}
	v1.HandleFunc("/system", apiHandler.System).Methods(http.MethodGet)
	v1.HandleFunc("/licenses", apiHandler.Licenses).Methods(http.MethodGet)
	v1.HandleFunc("/monitoring", apiHandler.Monitoring).Methods(http.MethodGet)
	v1.HandleFunc("/hardware", apiHandler.Hardware).Methods(http.MethodGet)
	v1.HandleFunc("/interfaces", apiHandler.Interfaces).Methods(http.MethodGet)
	v1.HandleFunc("/network", apiHandler.Network).Methods(http.MethodGet)
	v1.HandleFunc("/policies", apiHandler.Policies).Methods(http.MethodGet)
	v1.HandleFunc("/attacks", apiHandler.Attacks).Methods(http.MethodGet)
	v1.HandleFunc("/suspended", apiHandler.Suspended).Methods(http.MethodGet)
	v1.HandleFunc("/protections", apiHandler.Protections).Methods(http.MethodGet)
	v1.HandleFunc("/profiles", apiHandler.Profiles).Methods(http.MethodGet)
	v1.HandleFunc("/behavioral", apiHandler.Behavioral).Methods(http.MethodGet)
	v1.HandleFunc("/analytics", apiHandler.Analytics).Methods(http.MethodGet)
	v1.HandleFunc("/networks", apiHandler.Networks).Methods(http.MethodGet)
	v1.HandleFunc("/blocklists", apiHandler.AccessLists).Methods(http.MethodGet)
	v1.HandleFunc("/geo", apiHandler.Geo).Methods(http.MethodGet)
	v1.HandleFunc("/capacity", apiHandler.Capacity).Methods(http.MethodGet)
	v1.HandleFunc("/management", apiHandler.Management).Methods(http.MethodGet)

	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.WithField("addr", addr).Info("servidor iniciado")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("error al iniciar servidor")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("apagando servidor")
	close(warmupStop)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("error al apagar servidor")
	}

	logger.Info("servidor apagado correctamente")
}

func runWarmup(m *service.MultiDefenseProService, logger *logrus.Logger, stop <-chan struct{}) {
	select {
	case <-time.After(warmupInitialDelay):
	case <-stop:
		return
	}

	tick := func() {
		refreshCtx, refreshCancel := context.WithTimeout(context.Background(), refreshTimeout)
		if err := m.Refresh(refreshCtx); err != nil {
			logger.WithError(err).Warn("refresh de equipos falló")
		}
		refreshCancel()

		if m.Count() == 0 {
			return
		}

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), warmupTimeout)
		results, errs := m.GetAllSystemInfo(ctx, nil)
		cancel()

		logger.WithFields(logrus.Fields{
			"ok":          len(results),
			"errors":      len(errs),
			"duration_ms": middleware.RoundMS(time.Since(start)),
		}).Info("warmup system")
	}

	tick()

	ticker := time.NewTicker(warmupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			tick()
		case <-stop:
			return
		}
	}
}
