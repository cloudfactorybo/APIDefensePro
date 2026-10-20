# defensepro-api

API REST en Go para consultar uno o más equipos **Radware DefensePro** (probado contra la especificación v8.34.2.0). Por debajo habla con la **API SOAP** del equipo y entrega JSON agregado por dispositivo. Desplegada en Docker con Postgres, Redis y Traefik (HTTPS).

Es la evolución de `alteon-api`: misma arquitectura (multi-equipo, Bearer tokens, cache Redis, Traefik), pero los endpoints están pensados para un mitigador DDoS: ataques, políticas, protecciones, tabla de suspendidos, utilización y hardware.

---

## 1. Prerequisitos

### 1.1. En el host

- `docker` y `docker compose` (Docker 20.10+).
- `openssl` (para generar el cert TLS autofirmado).
- `curl` + `jq` (opcional, para probar).

### 1.2. En cada DefensePro (una sola vez)

La API SOAP viene deshabilitada por defecto. Desde el CLI del equipo:

```
manage web-services status set enable
manage secure-web status set enable
```

- `web-services` habilita la API SOAP (endpoint `https://<ip-del-dp>/soap`).
- `secure-web` habilita HTTPS. Si prefieres HTTP, registra el equipo con `http://` (no recomendado: las credenciales viajan en Basic Auth).
- Usa un usuario de gestión del DefensePro **de sólo lectura** si tu versión lo permite: la API sólo hace lecturas (`get_*` / `getAll_*`).

---

## 2. Preparación (antes del `docker compose up`)

### 2.1. Copiar y editar `.env`

```bash
cp .env.example .env
vi .env
```

| Variable | Qué es | Recomendación |
|---|---|---|
| `POSTGRES_PASSWORD` | Password de la DB interna | Cámbialo a algo fuerte |
| `REDIS_PASSWORD` | Password de Redis | Opcional, pero mejor ponerlo |
| `LOG_LEVEL` | `debug` / `info` / `warn` / `error` | `info`; `debug` muestra cada llamada SOAP |
| `ALLOWED_ORIGINS` | CORS — orígenes web permitidos | `*` si no tienes frontend web |
| `DEVICE_MAX_CONCURRENCY` | Llamadas SOAP simultáneas por equipo | `4`; baja a `1`-`2` si el DP se ve lento |
| `PUBLIC_HTTPS_PORT` | Puerto público (Traefik HTTPS) | `5687` por defecto |

### 2.2. Generar certificado TLS autofirmado

```bash
./scripts/gen-certs.sh
```

Crea `traefik/certs/cert.pem` y `traefik/certs/key.pem` válidos para `localhost`, `defensepro-api` y `127.0.0.1`. Con un nombre DNS propio:

```bash
HOST=mi-server.local ./scripts/gen-certs.sh --force
```

### 2.3. (Opcional) Sólo localhost o expuesta a la LAN

Por defecto Traefik escucha sólo en `127.0.0.1`. Para exponer a la red, en `docker-compose.yml`:

```yaml
    ports:
      - "127.0.0.1:${PUBLIC_HTTPS_PORT:-5687}:5687"   # sólo localhost (default)
      # - "${PUBLIC_HTTPS_PORT:-5687}:5687"           # toda la LAN
```

---

## 3. Levantar Docker

```bash
docker compose up -d --build
docker compose ps            # los 4 servicios en Up / healthy
docker compose logs -f app   # logs del API
```

Contenedores: `postgres`, `redis`, `app` (API Go) y `traefik` (HTTPS).

---

## 4. Configuración inicial

La DB arranca vacía. Se siembra con el CLI `defensepro-admin`.

```bash
alias admin='docker compose exec app defensepro-admin'
```

### 4.1. Registrar los DefensePro

```bash
admin add-device DP-CORE-1 https://10.10.0.21 apiuser 'Password1.'
admin add-device DP-CORE-2 https://10.10.0.22 apiuser 'Password1.'
admin list-devices
```

### 4.2. Probar la conexión SOAP (recomendado)

```bash
admin test-device DP-CORE-1
```

```
endpoint: https://10.10.0.21/soap
  OK   Device.SystemParameters.get_DeviceName        DP-CORE-1
  OK   Device.Information.get_Platform               DefensePro
  OK   Device.Information.get_SoftwareVersion        8.34.2.0
  OK   Device.Utilization.get_ResourceUtilization    23
```

Si todo da `FAIL`, revisa el paso 1.2, la URL y las credenciales (ver Troubleshooting).

### 4.3. Crear un Bearer token

```bash
admin create-token mi-cliente
```

**Copia el token en ese momento**: se guarda hasheado (SHA-256) y no se puede recuperar.

### 4.4. Recargar equipos

El server relee la lista de equipos cada 5 minutos. Para verlos ya: `docker compose restart app`.

---

## 5. Endpoints

Todos los `/api/v1/*` requieren `Authorization: Bearer <token>` y aceptan **`?device=DP-CORE-1,DP-CORE-2`** para consultar sólo ciertos equipos (sin el parámetro = todos los habilitados; un nombre inexistente devuelve 404).

| Endpoint | Contenido | Cache |
|---|---|---|
| `GET /health` | Vida del proceso (sin auth) | — |
| `GET /health/deep` | Ping SOAP a cada equipo (sin auth) | — |
| `GET /api/v1/system` | Nombre, ubicación, uptime, plataforma, versiones (SW, HW, módulo de seguridad, base de firmas), MAC, RAM, modo de mitigación/operación, estado HA, imágenes instaladas | 10 min (uptime/fecha/hora sin cache) |
| `GET /api/v1/licenses` | License ID/key, licencia de throughput, capacidad de mitigación y throughput, estado del feed ERT | 10 min |
| `GET /api/v1/monitoring` | CPU (global y por engine), RAM, disco, tráfico último segundo y pico, entradas de la session table | 10 s |
| `GET /api/v1/hardware` | Temperatura de CPUs, ventiladores, fuentes de poder | 10 s |
| `GET /api/v1/interfaces` | Interfaces L2 (estado admin/oper, contadores), puertos físicos, tráfico por puerto del último segundo | 10 s |
| `GET /api/v1/network` | Interfaces IP (v4/v6) y tabla de rutas | 1 min |
| `GET /api/v1/policies` | Políticas de protección con perfiles asignados, utilización (%) y recursos de HW. Filtro `?policy=` | 1 min |
| `GET /api/v1/attacks` | Log de seguridad (ataques) + resumen por riesgo/categoría/acción/tipo | 5 s |
| `GET /api/v1/suspended` | Tabla de orígenes suspendidos/bloqueados | 10 s |
| `GET /api/v1/protections` | Estado global de cada módulo (BDoS, SYN, DNS, HTTPS flood, anti-scanning, firmas, DoS shield, out-of-state, ERT) y perfiles BDoS | 1 min |

### 5.1. Filtros de `/api/v1/attacks`

Todos admiten CSV y no distinguen mayúsculas:

| Parámetro | Valores (según WSDL) |
|---|---|
| `risk` | `info`, `low`, `medium`, `high` |
| `category` | `intrusion`, `dos`, `anomalies`, `scanning`, `behavioral-doS`, `syn-flood`, `http-flood`, `dns-protection`, `traffic-filters`, `acl`, ... |
| `action` | `report-only`, `drop`, `proxy`, `rst-src`, `rst-dst`, `rst-bi`, `quarantine`, ... |
| `type` | `started`, `ongoing`, `terminated`, `occur`, `sampled` |
| `policy` | nombre de la política de protección |
| `limit` | máximo de entradas **por equipo**, las más recientes primero. Default `500`, `0` = sin límite, máx `10000` |

El `summary` se calcula sobre todo lo que pasa el filtro (antes de `limit`), así que los contadores no dependen del límite: `summary.total` vs `summary.returned`.

### 5.2. Ejemplos

```bash
export TOKEN=<token del paso 4.3>
API=https://127.0.0.1:5687

curl -k $API/health/deep | jq
curl -k -H "Authorization: Bearer $TOKEN" $API/api/v1/system | jq
curl -k -H "Authorization: Bearer $TOKEN" "$API/api/v1/monitoring?device=DP-CORE-1" | jq
curl -k -H "Authorization: Bearer $TOKEN" "$API/api/v1/attacks?risk=high,medium&type=started,ongoing&limit=50" | jq
curl -k -H "Authorization: Bearer $TOKEN" "$API/api/v1/policies?policy=Web" | jq
```

### 5.3. Forma de la respuesta

Igual que en `alteon-api`: un elemento por equipo en `data`, con su identidad aplanada; los equipos que fallaron van en `errors`.

```json
{
  "data": [
    {
      "deviceName": "DP-CORE-1",
      "deviceUrl": "https://10.10.0.21",
      "deviceIp": "10.10.0.21",
      "summary": { "total": 3, "returned": 3, "byRisk": { "high": 2, "medium": 1 }, "...": {} },
      "attacks": [
        { "index": 18234, "time": "...", "name": "SYN Flood", "type": "ongoing", "category": "syn-flood",
          "risk": "high", "action": "drop", "policyName": "Web", "sourceAddress": "0.0.0.0",
          "destinationAddress": "10.20.0.10", "destinationPort": 443, "...": "..." }
      ]
    }
  ],
  "errors": [ { "device": "DP-CORE-2", "error": "Device.Information.get_SoftwareVersion: auth 401: ..." } ]
}
```

Códigos: `200` si al menos un equipo respondió; `502` si ninguno; `404` si `?device=` nombra un equipo inexistente; `400` si un parámetro es inválido.

**Datos parciales**: dentro de un equipo, cada valor es una llamada SOAP independiente. Si una función no existe en ese modelo (ventiladores en un DP virtual, HA sin par...), el equipo responde con un SOAP Fault y ese campo queda vacío/cero sin invalidar el resto (se registra en log `debug`). Sólo se reporta error del equipo si es inalcanzable, rechaza las credenciales o falla todo.

---

## 6. Operaciones comunes

```bash
docker compose restart app          # reiniciar el API
docker compose up -d --build app    # rebuild tras cambiar código
docker compose down                 # parar (preserva datos)
docker compose down -v              # parar y BORRAR datos (equipos y tokens)
```

---

## 7. Administración día a día

```bash
# Equipos
admin add-device <name> <url> <user> <pass>
admin list-devices
admin disable-device <name>        # deja de consultarse sin borrarlo
admin enable-device <name>
admin remove-device <name>
admin test-device <name>           # prueba SOAP
admin soap-call <name> <servicio> <operación>   # XML crudo, para diagnóstico

# Tokens
admin create-token <nombre-cliente>
admin list-tokens
admin revoke-token <id>
```

`soap-call` sirve para inspeccionar cualquier operación de los WSDL de DefensePro (paquete SOAP API de Radware, no incluido en el repo), incluso las que la API no expone:

```bash
admin soap-call DP-CORE-1 Device.Information get_RamSize
admin soap-call DP-CORE-1 Security.Reporting getAll_Log
```

---

## 8. Troubleshooting

### `test-device` falla en todo

- `status 404` o HTML en la respuesta → la API SOAP está deshabilitada: `manage web-services status set enable`.
- `connection refused` / timeout en `https://` → falta `manage secure-web status set enable`, o el equipo no es alcanzable desde el host Docker (ACL de gestión, firewall).
- `auth 401` → usuario/password incorrectos.

### Algunos campos salen vacíos o en 0

Normal si el modelo no soporta esa función (SOAP Fault). Con `LOG_LEVEL=debug` verás `dato no soportado por el equipo op=...`. Para ver la respuesta exacta: `admin soap-call <name> <servicio> <operación>`.

### El DefensePro se ve cargado

Baja `DEVICE_MAX_CONCURRENCY` (p.ej. `2`) en `.env` y `docker compose up -d`. Cada endpoint dispara entre 1 y 19 llamadas SOAP por equipo; la cache de Redis (TTL de la tabla del punto 5) evita repetirlas cuando varios clientes consultan a la vez.

### 401 en `/api/v1/*`

Falta o es inválido el Bearer token: `admin list-tokens`. Si está revocado, emite uno nuevo.

### `/health/deep` devuelve `total: 0`

El server aún no recargó los equipos: `docker compose restart app`.

### Error TLS al hacer curl

El cert es autofirmado: usa `-k` o reemplaza `traefik/certs/*.pem` por uno de una CA de confianza.

---

## 9. Mapeo endpoint → operaciones SOAP

| Endpoint | Servicio (WSDL) y operaciones |
|---|---|
| `system` | `Device.SystemParameters` get_DeviceName/Description/Location/Contact/SystemUpTime/Date/Time · `Device.Information` get_Platform/SoftwareVersion/BuildNumber/rdwrDPVersion/SysBaseMACAddress/RamSize · `Device.Mitigation` get_Device · `Security.Operation` get_Device · `Device.HighAvailability` get_haProtectionState · `Security.Version` get_SecurityModuleVersion · `Security.AttackDB` get_Version · `Management.VersionControl` getAll_SoftwareVersion |
| `licenses` | `Management.LicenseAdmin` get_LicenseId/LicenseKey/TplLicense/TplLicenseId/TplLicenseMethod/TplLicenseIP · `Device.Information` get_DeviceAttackMitigation/DeviceThroughput · `Security.ErtAttackersFeedStatus` get_Status |
| `monitoring` | `Device.Utilization` get_ResourceUtilization/Last5SecondAverageUtilization/Last60SecondsUtilzation/rsSysUtilEnginesCpuMean/SysUtilRAM*/SysUtilDisk* · `Device.Statistics` get_TotalLastSecMbits · `Device.HardwareInfo` get_TotalLastSecPeak, getAll_EngineResource · `Device.SessionTable` get_UsedEntriesNumber |
| `hardware` | `Device.HardwareInfo` getAll_CpuTemperature, getAll_SystemFans, get_DualPsuStatus |
| `interfaces` | `Networking.Interfaces` getAll_L2Interface, getAll_PhysicalInterface · `Device.Statistics` getAll_PortLastSec |
| `network` | `Networking.InterfacesNG` getAll_IpInterface · `Networking.StaticRouting` getAll_Route |
| `policies` | `Security.Policy` getAll_Policy, getAll_PoliciesResources, get_TotalPolicyNum/HwEntriesUtil/SubPolicyUtil/UpdatePoliciesRequired/UpdatePoliciesInProgress · `Security.PolicyUtil` getAll_PolicyUtil |
| `attacks` | `Security.Reporting` getAll_Log |
| `suspended` | `Security.SuspendTable` getAll_NewerSuspend |
| `protections` | get_Status de `Security.BehavioralDoS`, `SynProtection`, `HTTPSFloodProtection`, `AntiScanning`, `SignatureProtection` (+ get_DosShieldStatus), `StatefulInspection` (get_status), `ErtAttackersFeedStatus`; `Security.DnsProtection` get_DnsProtectionGlobalStatus · `Security.BehavioralDoS` getAll_Profiles |

Notas:
- RAM y disco (`used`, `capacity`) se exponen en la unidad que reporta el equipo: el WSDL no la documenta.
- La API es de **sólo lectura**. El WSDL `CLI.Command` (`apply_CLICommand`) permitiría ejecutar comandos CLI arbitrarios, pero no se expone a propósito: con un token se podría reconfigurar o reiniciar el equipo.

---

## 10. Estructura del proyecto

```
.
├── cmd/
│   ├── server/          # API HTTP (defensepro-api)
│   └── admin/           # CLI de administración (defensepro-admin)
├── internal/
│   ├── soap/            # Cliente SOAP 1.1 RPC/encoded + catálogo de servicios
│   ├── service/         # Lógica por equipo y fan-out multi-equipo
│   ├── models/          # Structs JSON (con tags soap para decodificar tablas)
│   ├── handler/         # Handlers HTTP
│   ├── middleware/      # logging, gzip, cors, auth
│   ├── cache/           # Cliente Redis (cache con TTL)
│   ├── config/          # Config desde env vars
│   └── storage/         # Repos Postgres (devices + tokens)
├── pkg/httpclient/      # Cliente HTTP compartido
├── traefik/             # TLS config + certs
├── scripts/gen-certs.sh
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

---

## 11. Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `SERVER_HOST` | `127.0.0.1` | Bind interno del app (en compose: `0.0.0.0`) |
| `SERVER_PORT` | `5687` | Puerto interno del app (en compose: `8080`) |
| `DATABASE_URL` | `postgres://defensepro:defensepro@localhost:5432/defensepro?sslmode=disable` | DSN de Postgres |
| `REDIS_ADDR` | `localhost:6379` | Host:port de Redis |
| `REDIS_PASSWORD` | *(vacío)* | Password de Redis |
| `REDIS_DB` | `0` | Número de DB Redis |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `text` | `text` o `json` |
| `ALLOWED_ORIGINS` | `*` | CORS, lista CSV |
| `AUTH_DISABLED` | *(vacío)* | `true` apaga el Bearer token (sólo dev) |
| `DEVICE_MAX_CONCURRENCY` | `4` | Llamadas SOAP simultáneas por equipo |
| `PUBLIC_HTTPS_PORT` | `5687` | Puerto público de Traefik (usado por compose) |

### Instalación sin Docker

`install-defensepro-api.sh` instala el binario como servicio systemd en `/opt/defensepro-api` (necesita Postgres y Redis accesibles). Compila primero:

```bash
go build -o defensepro-api ./cmd/server && go build -o defensepro-admin ./cmd/admin
sudo ./install-defensepro-api.sh
# el CLI necesita las mismas variables que el servicio:
set -a; . /opt/defensepro-api/.env; set +a
/opt/defensepro-api/defensepro-admin add-device DP-CORE-1 https://10.10.0.21 apiuser 'Password1.'
```
