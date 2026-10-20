package service

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"defensepro-api/internal/cache"
	"defensepro-api/internal/models"
	"defensepro-api/internal/reqctx"
	"defensepro-api/internal/storage"
	"defensepro-api/pkg/httpclient"
)

type MultiDefenseProService struct {
	repo           *storage.DevicesRepo
	httpClient     *http.Client
	logger         *logrus.Logger
	cache          *cache.Cache
	maxConcurrency int

	mu      sync.RWMutex
	devices []*Device
}

type Device struct {
	Name    string
	URL     string
	IP      string
	Service *DefenseProService
}

func (d *Device) ref() models.DeviceRef {
	return models.DeviceRef{DeviceName: d.Name, DeviceURL: d.URL, DeviceIP: d.IP}
}

type DeviceError struct {
	Device string `json:"device"`
	Error  string `json:"error"`
}

type PingResult struct {
	Device string `json:"device"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

func NewMultiDefenseProService(repo *storage.DevicesRepo, httpClient *httpclient.Client, logger *logrus.Logger, c *cache.Cache, maxConcurrency int) *MultiDefenseProService {
	return &MultiDefenseProService{
		repo:           repo,
		httpClient:     httpClient.Client,
		logger:         logger,
		cache:          c,
		maxConcurrency: maxConcurrency,
	}
}

// Refresh recarga la lista de equipos desde la DB. Seguro para llamarse en caliente.
func (m *MultiDefenseProService) Refresh(ctx context.Context) error {
	list, err := m.repo.List(ctx)
	if err != nil {
		return err
	}

	devices := make([]*Device, 0, len(list))
	for _, d := range list {
		if !d.Enabled {
			continue
		}
		devices = append(devices, &Device{
			Name:    d.Name,
			URL:     d.BaseURL,
			IP:      extractIPFromURL(d.BaseURL),
			Service: NewDefenseProService(d.Name, d.BaseURL, d.Username, d.Password, m.httpClient, m.logger, m.cache, m.maxConcurrency),
		})
	}

	m.mu.Lock()
	prev := len(m.devices)
	m.devices = devices
	m.mu.Unlock()

	now := len(devices)
	if prev != now {
		m.logger.WithFields(logrus.Fields{
			"count": now,
			"prev":  prev,
		}).Info("equipos recargados — lista cambió")
	} else {
		m.logger.WithField("count", now).Debug("equipos recargados (sin cambios)")
	}
	return nil
}

// snapshot devuelve los equipos activos; con names no vacío, sólo esos
// (comparando sin distinguir mayúsculas).
func (m *MultiDefenseProService) snapshot(names []string) []*Device {
	m.mu.RLock()
	defer m.mu.RUnlock()

	filter := toSet(names)
	out := make([]*Device, 0, len(m.devices))
	for _, d := range m.devices {
		if filter == nil || filter[strings.ToLower(d.Name)] {
			out = append(out, d)
		}
	}
	return out
}

func (m *MultiDefenseProService) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.devices)
}

// Unknown devuelve los nombres pedidos que no corresponden a ningún equipo activo.
func (m *MultiDefenseProService) Unknown(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	known := map[string]bool{}
	for _, d := range m.snapshot(nil) {
		known[strings.ToLower(d.Name)] = true
	}
	var out []string
	for _, n := range names {
		if !known[strings.ToLower(n)] {
			out = append(out, n)
		}
	}
	return out
}

func (m *MultiDefenseProService) logError(ctx context.Context, endpoint string, d *Device, err error) {
	fields := logrus.Fields{
		"device":   d.Name,
		"endpoint": endpoint,
	}
	if id := reqctx.ID(ctx); id != "" {
		fields["req_id"] = id
	}
	m.logger.WithFields(fields).WithError(err).Error("defensepro call failed")
}

func (m *MultiDefenseProService) PingAll(ctx context.Context) []PingResult {
	devices := m.snapshot(nil)
	out := make([]PingResult, len(devices))

	var wg sync.WaitGroup
	for i, d := range devices {
		wg.Go(func() {
			if err := d.Service.Ping(ctx); err != nil {
				out[i] = PingResult{Device: d.Name, OK: false, Error: err.Error()}
				return
			}
			out[i] = PingResult{Device: d.Name, OK: true}
		})
	}
	wg.Wait()
	return out
}

// fanOut consulta en paralelo los equipos seleccionados y separa resultados de
// errores. Cada resultado se etiqueta con su equipo (deviceName/Url/Ip).
func fanOut[T any, PT interface {
	*T
	SetDevice(models.DeviceRef)
}](ctx context.Context, m *MultiDefenseProService, names []string, endpoint string, fetch func(*DefenseProService, context.Context) (PT, error)) ([]T, []DeviceError) {
	devices := m.snapshot(names)
	results := make([]PT, len(devices))
	errs := make([]*DeviceError, len(devices))

	var wg sync.WaitGroup
	for i, d := range devices {
		wg.Go(func() {
			data, err := fetch(d.Service, ctx)
			if err != nil {
				m.logError(ctx, endpoint, d, err)
				errs[i] = &DeviceError{Device: d.Name, Error: err.Error()}
				return
			}
			data.SetDevice(d.ref())
			results[i] = data
		})
	}
	wg.Wait()

	out := []T{}
	for _, r := range results {
		if r != nil {
			out = append(out, *r)
		}
	}
	outErrs := []DeviceError{}
	for _, e := range errs {
		if e != nil {
			outErrs = append(outErrs, *e)
		}
	}
	return out, outErrs
}

func (m *MultiDefenseProService) GetAllSystemInfo(ctx context.Context, names []string) ([]models.SystemInfo, []DeviceError) {
	return fanOut(ctx, m, names, "system", (*DefenseProService).GetSystemInfo)
}

func (m *MultiDefenseProService) GetAllLicenses(ctx context.Context, names []string) ([]models.Licenses, []DeviceError) {
	return fanOut(ctx, m, names, "licenses", (*DefenseProService).GetLicenses)
}

func (m *MultiDefenseProService) GetAllMonitoring(ctx context.Context, names []string) ([]models.Monitoring, []DeviceError) {
	return fanOut(ctx, m, names, "monitoring", (*DefenseProService).GetMonitoring)
}

func (m *MultiDefenseProService) GetAllHardware(ctx context.Context, names []string) ([]models.Hardware, []DeviceError) {
	return fanOut(ctx, m, names, "hardware", (*DefenseProService).GetHardware)
}

func (m *MultiDefenseProService) GetAllInterfaces(ctx context.Context, names []string) ([]models.Interfaces, []DeviceError) {
	return fanOut(ctx, m, names, "interfaces", (*DefenseProService).GetInterfaces)
}

func (m *MultiDefenseProService) GetAllNetwork(ctx context.Context, names []string) ([]models.Network, []DeviceError) {
	return fanOut(ctx, m, names, "network", (*DefenseProService).GetNetwork)
}

func (m *MultiDefenseProService) GetAllPolicies(ctx context.Context, names, policies []string) ([]models.Policies, []DeviceError) {
	return fanOut(ctx, m, names, "policies", func(s *DefenseProService, ctx context.Context) (*models.Policies, error) {
		return s.GetPolicies(ctx, policies)
	})
}

func (m *MultiDefenseProService) GetAllAttacks(ctx context.Context, names []string, f models.AttackFilter) ([]models.Attacks, []DeviceError) {
	return fanOut(ctx, m, names, "attacks", func(s *DefenseProService, ctx context.Context) (*models.Attacks, error) {
		return s.GetAttacks(ctx, f)
	})
}

func (m *MultiDefenseProService) GetAllSuspended(ctx context.Context, names []string) ([]models.SuspendTable, []DeviceError) {
	return fanOut(ctx, m, names, "suspended", (*DefenseProService).GetSuspended)
}

func (m *MultiDefenseProService) GetAllProfiles(ctx context.Context, names, types []string) ([]models.Profiles, []DeviceError) {
	return fanOut(ctx, m, names, "profiles", func(s *DefenseProService, ctx context.Context) (*models.Profiles, error) {
		return s.GetProfiles(ctx, types)
	})
}

func (m *MultiDefenseProService) GetAllBehavioral(ctx context.Context, names []string, withBypass bool, f models.AttackFilter) ([]models.Behavioral, []DeviceError) {
	return fanOut(ctx, m, names, "behavioral", func(s *DefenseProService, ctx context.Context) (*models.Behavioral, error) {
		return s.GetBehavioral(ctx, withBypass, f)
	})
}

func (m *MultiDefenseProService) GetAllAnalytics(ctx context.Context, names []string, f models.AttackFilter, top int) ([]models.Analytics, []DeviceError) {
	return fanOut(ctx, m, names, "analytics", func(s *DefenseProService, ctx context.Context) (*models.Analytics, error) {
		return s.GetAnalytics(ctx, f, top)
	})
}

func (m *MultiDefenseProService) GetAllNetworks(ctx context.Context, names, networks []string) ([]models.Networks, []DeviceError) {
	return fanOut(ctx, m, names, "networks", func(s *DefenseProService, ctx context.Context) (*models.Networks, error) {
		return s.GetNetworks(ctx, networks)
	})
}

func (m *MultiDefenseProService) GetAllAccessLists(ctx context.Context, names []string) ([]models.AccessLists, []DeviceError) {
	return fanOut(ctx, m, names, "blocklists", (*DefenseProService).GetAccessLists)
}

func (m *MultiDefenseProService) GetAllGeo(ctx context.Context, names []string) ([]models.Geo, []DeviceError) {
	return fanOut(ctx, m, names, "geo", (*DefenseProService).GetGeo)
}

func (m *MultiDefenseProService) GetAllCapacity(ctx context.Context, names []string) ([]models.Capacity, []DeviceError) {
	return fanOut(ctx, m, names, "capacity", (*DefenseProService).GetCapacity)
}

func (m *MultiDefenseProService) GetAllManagement(ctx context.Context, names []string) ([]models.Management, []DeviceError) {
	return fanOut(ctx, m, names, "management", (*DefenseProService).GetManagement)
}

func (m *MultiDefenseProService) GetAllProtections(ctx context.Context, names []string) ([]models.Protections, []DeviceError) {
	return fanOut(ctx, m, names, "protections", (*DefenseProService).GetProtections)
}
