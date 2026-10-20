package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"defensepro-api/internal/cache"
	"defensepro-api/internal/models"
	"defensepro-api/internal/reqctx"
	"defensepro-api/internal/soap"
)

// TTLs de cache por tipo de dato. Cada valor del DefensePro es una llamada SOAP
// (un POST https), así que cachear evita martillar la CPU de gestión del equipo
// cuando varios clientes consultan a la vez.
const (
	staticTTL  = 10 * time.Minute // identidad, versiones, licencias
	configTTL  = 1 * time.Minute  // políticas, perfiles, estado de módulos
	statsTTL   = 10 * time.Second // utilización, tráfico, contadores
	attacksTTL = 5 * time.Second  // log de seguridad
)

type DefenseProService struct {
	name   string
	client *soap.Client
	logger *logrus.Logger
	cache  *cache.Cache
	sem    chan struct{}
}

func NewDefenseProService(name, baseURL, username, password string, client *http.Client, logger *logrus.Logger, c *cache.Cache, maxConcurrency int) *DefenseProService {
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}
	return &DefenseProService{
		name:   name,
		client: soap.NewClient(baseURL, username, password, client),
		logger: logger,
		cache:  c,
		sem:    make(chan struct{}, maxConcurrency),
	}
}

func (s *DefenseProService) Name() string { return s.name }

// logCtx devuelve un entry con el dispositivo y el req_id si está en el contexto.
func (s *DefenseProService) logCtx(ctx context.Context) *logrus.Entry {
	entry := s.logger.WithField("device", s.name)
	if id := reqctx.ID(ctx); id != "" {
		entry = entry.WithField("req_id", id)
	}
	return entry
}

// call ejecuta una operación SOAP. Con ttl > 0 cachea el XML crudo en Redis;
// sólo se cachean respuestas válidas (un Fault nunca llega al Set).
func (s *DefenseProService) call(ctx context.Context, ttl time.Duration, svc soap.Service, op string) (*soap.Response, error) {
	key := s.name + ":" + svc.Name() + "#" + op
	if ttl > 0 {
		if cached, ok := s.cache.Get(key); ok {
			if resp, err := soap.Decode(cached); err == nil {
				return resp, nil
			}
		}
	}

	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	start := time.Now()
	body, err := s.client.Call(ctx, svc, op)
	<-s.sem

	if err != nil {
		return nil, fmt.Errorf("%s.%s: %w", svc.Name(), op, err)
	}
	resp, err := soap.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("%s.%s: %w", svc.Name(), op, err)
	}

	s.logCtx(ctx).WithFields(logrus.Fields{
		"op":          svc.Name() + "." + op,
		"duration_ms": time.Since(start).Milliseconds(),
	}).Debug("llamada soap")

	if ttl > 0 {
		s.cache.Set(key, body, ttl)
	}
	return resp, nil
}

func fetchTable[T any](ctx context.Context, s *DefenseProService, ttl time.Duration, svc soap.Service, op string) ([]T, error) {
	resp, err := s.call(ctx, ttl, svc, op)
	if err != nil {
		// Con la tabla vacía el equipo a veces responde un Fault
		// NoSuchInstanceException en vez de una tabla sin filas.
		if isNoSuchInstance(err) {
			return []T{}, nil
		}
		return nil, err
	}
	rows, err := resp.Table()
	if err != nil {
		return nil, fmt.Errorf("%s.%s: %w", svc.Name(), op, err)
	}
	return soap.DecodeRows[T](rows), nil
}

// task es una lectura (un get_X o getAll_X) que vuelca su resultado en el modelo.
type task struct {
	name string
	run  func(context.Context) error
}

// scalar lee un get_X y lo copia en dst (*string o *int64).
func (s *DefenseProService) scalar(svc soap.Service, op string, ttl time.Duration, dst any) task {
	return task{svc.Name() + "." + op, func(ctx context.Context) error {
		resp, err := s.call(ctx, ttl, svc, op)
		if err != nil {
			return err
		}
		v, err := resp.Value()
		if err != nil {
			return err
		}
		soap.SetValue(dst, v)
		return nil
	}}
}

// table lee un getAll_X y lo decodifica en *dst.
func table[T any](s *DefenseProService, svc soap.Service, op string, ttl time.Duration, dst *[]T) task {
	return task{svc.Name() + "." + op, func(ctx context.Context) error {
		rows, err := fetchTable[T](ctx, s, ttl, svc, op)
		if err != nil {
			return err
		}
		*dst = rows
		return nil
	}}
}

// gather ejecuta las lecturas de un endpoint. La primera hace de sonda: si
// falla por transporte o auth (equipo caído, SOAP deshabilitado, credenciales
// malas) se aborta sin disparar el resto, que solo acumularía timeouts. Las
// demás van en paralelo (acotadas por el semáforo) y son best-effort: un dato
// que falla queda en cero. Solo es error si fallan todas.
func (s *DefenseProService) gather(ctx context.Context, tasks ...task) error {
	if len(tasks) == 0 {
		return nil
	}

	errs := make([]error, len(tasks))
	errs[0] = tasks[0].run(ctx)
	if errs[0] != nil && !isFault(errs[0]) {
		return errs[0]
	}

	var wg sync.WaitGroup
	for i := 1; i < len(tasks); i++ {
		wg.Go(func() { errs[i] = tasks[i].run(ctx) })
	}
	wg.Wait()

	failed := 0
	for i, err := range errs {
		if err == nil {
			continue
		}
		failed++
		entry := s.logCtx(ctx).WithField("op", tasks[i].name).WithError(err)
		if isFault(err) {
			// El equipo respondió que no: típico de funciones que el modelo no
			// tiene (ventiladores en un DP virtual, HA sin par configurado...).
			entry.Debug("dato no soportado por el equipo")
		} else {
			entry.Warn("dato no disponible")
		}
	}
	if failed == len(tasks) {
		return errs[0]
	}
	return nil
}

func isFault(err error) bool {
	var f *soap.Fault
	return errors.As(err, &f)
}

func isNoSuchInstance(err error) bool {
	var f *soap.Fault
	return errors.As(err, &f) && strings.Contains(f.String, "NoSuchInstance")
}

func (s *DefenseProService) Ping(ctx context.Context) error {
	_, err := s.call(ctx, 0, soap.DeviceSystemParameters, "get_DeviceName")
	return err
}

func (s *DefenseProService) GetSystemInfo(ctx context.Context) (*models.SystemInfo, error) {
	out := &models.SystemInfo{InstalledVersions: []models.SoftwareVersion{}}
	err := s.gather(ctx,
		// Sin cache y primero: hace de sonda real de alcanzabilidad.
		s.scalar(soap.DeviceSystemParameters, "get_SystemUpTime", 0, &out.UpTime),
		s.scalar(soap.DeviceSystemParameters, "get_Date", 0, &out.Date),
		s.scalar(soap.DeviceSystemParameters, "get_Time", 0, &out.Time),
		s.scalar(soap.DeviceSystemParameters, "get_DeviceName", staticTTL, &out.SysName),
		s.scalar(soap.DeviceSystemParameters, "get_Description", staticTTL, &out.Description),
		s.scalar(soap.DeviceSystemParameters, "get_Location", staticTTL, &out.Location),
		s.scalar(soap.DeviceSystemParameters, "get_Contact", staticTTL, &out.Contact),
		s.scalar(soap.DeviceInformation, "get_Platform", staticTTL, &out.Platform),
		s.scalar(soap.DeviceInformation, "get_SoftwareVersion", staticTTL, &out.SoftwareVersion),
		s.scalar(soap.DeviceInformation, "get_BuildNumber", staticTTL, &out.BuildNumber),
		s.scalar(soap.DeviceInformation, "get_rdwrDPVersion", staticTTL, &out.HardwareVersion),
		s.scalar(soap.DeviceInformation, "get_SysBaseMACAddress", staticTTL, &out.BaseMACAddress),
		s.scalar(soap.DeviceInformation, "get_RamSize", staticTTL, &out.RamSizeMB),
		s.scalar(soap.DeviceMitigation, "get_Device", staticTTL, &out.MitigationMode),
		s.scalar(soap.SecurityOperation, "get_Device", staticTTL, &out.OperationMode),
		s.scalar(soap.DeviceHighAvailability, "get_haProtectionState", statsTTL, &out.HAProtectionState),
		s.scalar(soap.SecurityVersion, "get_SecurityModuleVersion", staticTTL, &out.SecurityModuleVersion),
		s.scalar(soap.SecurityAttackDB, "get_Version", staticTTL, &out.AttackDBVersion),
		table(s, soap.ManagementVersionControl, "getAll_SoftwareVersion", staticTTL, &out.InstalledVersions),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *DefenseProService) GetLicenses(ctx context.Context) (*models.Licenses, error) {
	out := &models.Licenses{}
	err := s.gather(ctx,
		s.scalar(soap.ManagementLicenseAdmin, "get_LicenseId", staticTTL, &out.LicenseID),
		s.scalar(soap.ManagementLicenseAdmin, "get_LicenseKey", staticTTL, &out.LicenseKey),
		s.scalar(soap.ManagementLicenseAdmin, "get_TplLicense", staticTTL, &out.ThroughputLicense),
		s.scalar(soap.ManagementLicenseAdmin, "get_TplLicenseId", staticTTL, &out.ThroughputLicenseID),
		s.scalar(soap.ManagementLicenseAdmin, "get_TplLicenseMethod", staticTTL, &out.ThroughputLicenseMethod),
		s.scalar(soap.ManagementLicenseAdmin, "get_TplLicenseIP", staticTTL, &out.ThroughputLicenseIP),
		s.scalar(soap.DeviceInformation, "get_DeviceAttackMitigation", staticTTL, &out.AttackMitigationCapacity),
		s.scalar(soap.DeviceInformation, "get_DeviceThroughput", staticTTL, &out.ThroughputCapacity),
		s.scalar(soap.SecurityErtFeedStatus, "get_Status", configTTL, &out.ErtAttackersFeedStatus),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *DefenseProService) GetMonitoring(ctx context.Context) (*models.Monitoring, error) {
	out := &models.Monitoring{Engines: []models.EngineResource{}}
	err := s.gather(ctx,
		s.scalar(soap.DeviceUtilization, "get_ResourceUtilization", statsTTL, &out.CPU.ResourceUtilization),
		s.scalar(soap.DeviceUtilization, "get_Last5SecondAverageUtilization", statsTTL, &out.CPU.EnginesAvg5s),
		s.scalar(soap.DeviceUtilization, "get_Last60SecondsUtilzation", statsTTL, &out.CPU.EnginesAvg60s), // sic en el WSDL
		s.scalar(soap.DeviceUtilization, "get_rsSysUtilEnginesCpuMean", statsTTL, &out.CPU.EnginesMean),
		s.scalar(soap.DeviceUtilization, "get_SysUtilRAMUtilization", statsTTL, &out.Memory.UtilizationPercent),
		s.scalar(soap.DeviceUtilization, "get_SysUtilRAMUsed", statsTTL, &out.Memory.Used),
		s.scalar(soap.DeviceUtilization, "get_SysUtilRAMCapacity", staticTTL, &out.Memory.Capacity),
		s.scalar(soap.DeviceUtilization, "get_SysUtilDiskUtilization", statsTTL, &out.Disk.UtilizationPercent),
		s.scalar(soap.DeviceUtilization, "get_SysUtilDiskUsed", statsTTL, &out.Disk.Used),
		s.scalar(soap.DeviceUtilization, "get_SysUtilDiskCapacity", staticTTL, &out.Disk.Capacity),
		s.scalar(soap.DeviceStatistics, "get_TotalLastSecMbits", statsTTL, &out.Traffic.LastSecondMbits),
		s.scalar(soap.DeviceHardwareInfo, "get_TotalLastSecPeak", statsTTL, &out.Traffic.PeakBps),
		s.scalar(soap.DeviceSessionTable, "get_Status", configTTL, &out.SessionTable.Status),
		s.scalar(soap.DeviceSessionTable, "get_UsedEntriesNumber", statsTTL, &out.SessionTable.UsedEntries),
		table(s, soap.DeviceHardwareInfo, "getAll_EngineResource", statsTTL, &out.Engines),
	)
	if err != nil {
		return nil, err
	}
	out.Traffic.SetPeakMbps()
	return out, nil
}

func (s *DefenseProService) GetHardware(ctx context.Context) (*models.Hardware, error) {
	out := &models.Hardware{CPUTemperatures: []models.CPUTemperature{}, Fans: []models.Fan{}}
	err := s.gather(ctx,
		table(s, soap.DeviceHardwareInfo, "getAll_CpuTemperature", statsTTL, &out.CPUTemperatures),
		table(s, soap.DeviceHardwareInfo, "getAll_SystemFans", statsTTL, &out.Fans),
		s.scalar(soap.DeviceHardwareInfo, "get_DualPsuStatus", statsTTL, &out.PowerSupply),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *DefenseProService) GetInterfaces(ctx context.Context) (*models.Interfaces, error) {
	out := &models.Interfaces{
		Interfaces:    []models.L2Interface{},
		PhysicalPorts: []models.PhysicalPort{},
		PortTraffic:   []models.PortTraffic{},
	}
	err := s.gather(ctx,
		table(s, soap.NetworkingInterfaces, "getAll_L2Interface", statsTTL, &out.Interfaces),
		table(s, soap.NetworkingInterfaces, "getAll_PhysicalInterface", configTTL, &out.PhysicalPorts),
		table(s, soap.DeviceStatistics, "getAll_PortLastSec", statsTTL, &out.PortTraffic),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *DefenseProService) GetNetwork(ctx context.Context) (*models.Network, error) {
	out := &models.Network{IPInterfaces: []models.IPInterface{}, Routes: []models.Route{}}
	err := s.gather(ctx,
		table(s, soap.NetworkingInterfacesNG, "getAll_IpInterface", configTTL, &out.IPInterfaces),
		table(s, soap.NetworkingStaticRoute, "getAll_Route", configTTL, &out.Routes),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetPolicies devuelve las políticas de protección. names filtra por nombre
// (sin distinguir mayúsculas); vacío = todas.
func (s *DefenseProService) GetPolicies(ctx context.Context, names []string) (*models.Policies, error) {
	out := &models.Policies{Policies: []models.Policy{}}
	var utils []models.PolicyUtil
	var resources []models.PolicyResource
	err := s.gather(ctx,
		table(s, soap.SecurityPolicy, "getAll_Policy", configTTL, &out.Policies),
		table(s, soap.SecurityPolicyUtil, "getAll_PolicyUtil", statsTTL, &utils),
		table(s, soap.SecurityPolicy, "getAll_PoliciesResources", configTTL, &resources),
		s.scalar(soap.SecurityPolicy, "get_TotalPolicyNum", configTTL, &out.TotalPolicies),
		s.scalar(soap.SecurityPolicy, "get_HwEntriesUtil", statsTTL, &out.HwEntriesUtilization),
		s.scalar(soap.SecurityPolicy, "get_SubPolicyUtil", statsTTL, &out.SubPolicyUtilization),
		s.scalar(soap.SecurityPolicy, "get_UpdatePoliciesRequired", configTTL, &out.UpdateRequired),
		s.scalar(soap.SecurityPolicy, "get_UpdatePoliciesInProgress", statsTTL, &out.UpdateInProgress),
	)
	if err != nil {
		return nil, err
	}

	utilByName := make(map[string]int64, len(utils))
	for _, u := range utils {
		utilByName[u.Name] = u.Utilization
	}
	resByName := map[string][]models.PolicyResource{}
	for _, r := range resources {
		resByName[r.Name] = append(resByName[r.Name], r)
	}

	out.ConfiguredPolicies = len(out.Policies)
	filter := toSet(names)
	policies := make([]models.Policy, 0, len(out.Policies))
	for _, p := range out.Policies {
		if filter != nil && !filter[strings.ToLower(p.Name)] {
			continue
		}
		if u, ok := utilByName[p.Name]; ok {
			p.UtilizationPercent = &u
		}
		p.Resources = resByName[p.Name]
		if p.Resources == nil {
			p.Resources = []models.PolicyResource{}
		}
		policies = append(policies, p)
	}
	out.Policies = policies
	return out, nil
}

func (s *DefenseProService) GetAttacks(ctx context.Context, f models.AttackFilter) (*models.Attacks, error) {
	var entries []models.Attack
	if err := s.gather(ctx, table(s, soap.SecurityReporting, "getAll_Log", attacksTTL, &entries)); err != nil {
		return nil, err
	}
	return buildAttacks(entries, f), nil
}

func (s *DefenseProService) GetSuspended(ctx context.Context) (*models.SuspendTable, error) {
	out := &models.SuspendTable{Entries: []models.SuspendEntry{}}
	if err := s.gather(ctx, table(s, soap.SecuritySuspendTable, "getAll_NewerSuspend", statsTTL, &out.Entries)); err != nil {
		return nil, err
	}
	out.Total = len(out.Entries)
	return out, nil
}

func (s *DefenseProService) GetProtections(ctx context.Context) (*models.Protections, error) {
	out := &models.Protections{BDoSProfiles: []models.BDoSProfile{}}
	st := &out.Status
	err := s.gather(ctx,
		s.scalar(soap.SecurityBehavioralDoS, "get_Status", configTTL, &st.BehavioralDoS),
		s.scalar(soap.SecuritySynProtection, "get_Status", configTTL, &st.SynProtection),
		s.scalar(soap.SecurityDnsProtection, "get_DnsProtectionGlobalStatus", configTTL, &st.DNSProtection),
		s.scalar(soap.SecurityHTTPSFlood, "get_Status", configTTL, &st.HTTPSFlood),
		s.scalar(soap.SecurityAntiScanning, "get_Status", configTTL, &st.AntiScanning),
		s.scalar(soap.SecuritySignatures, "get_Status", configTTL, &st.Signatures),
		s.scalar(soap.SecuritySignatures, "get_DosShieldStatus", configTTL, &st.DoSShield),
		s.scalar(soap.SecurityStatefulInspection, "get_status", configTTL, &st.OutOfState),
		s.scalar(soap.SecurityErtFeedStatus, "get_Status", configTTL, &st.ErtAttackersFeed),
		table(s, soap.SecurityBehavioralDoS, "getAll_Profiles", configTTL, &out.BDoSProfiles),
	)
	if err != nil {
		return nil, err
	}
	return out, nil
}
