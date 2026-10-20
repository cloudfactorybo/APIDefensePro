#!/bin/bash

# Script de instalación del servicio defensepro-api (sin Docker, con systemd).
# Requiere Postgres y Redis accesibles (ver DATABASE_URL / REDIS_ADDR en .env).
# Archivo: install-defensepro-api.sh

set -e  # Salir si hay errores

# Configuración
SERVICE_NAME="defensepro-api"
INSTALL_DIR="/opt/defensepro-api"
CURRENT_DIR="$(pwd)"
BINARY_NAME="defensepro-api"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función de logging con colores
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    log_error "Este script debe ejecutarse como root (sudo)"
    exit 1
fi

log_info "Iniciando instalación del servicio $SERVICE_NAME"

# 0. Verificar si el servicio ya existe y eliminarlo
log_step "Verificando servicio existente"
if systemctl list-units --full -all | grep -Fq "$SERVICE_NAME.service"; then
    log_warn "Servicio $SERVICE_NAME ya existe. Eliminando..."
    
    # Detener servicio si está corriendo
    if systemctl is-active --quiet "$SERVICE_NAME.service"; then
        log_info "Deteniendo servicio $SERVICE_NAME"
        systemctl stop "$SERVICE_NAME.service"
        sleep 2
    fi
    
    # Deshabilitar servicio
    if systemctl is-enabled --quiet "$SERVICE_NAME.service" 2>/dev/null; then
        log_info "Deshabilitando servicio $SERVICE_NAME"
        systemctl disable "$SERVICE_NAME.service"
    fi
    
    # Eliminar archivo de servicio
    if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
        log_info "Eliminando archivo de servicio anterior"
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    fi
    
    # Recargar systemd
    systemctl daemon-reload
    log_info "✓ Servicio anterior eliminado"
fi

# 0.1 Terminar procesos relacionados
log_step "Verificando procesos del binario $BINARY_NAME"
if pgrep -f "./$BINARY_NAME" > /dev/null || pgrep -f "/opt.*$BINARY_NAME" > /dev/null; then
    log_warn "Encontrados procesos del binario ejecutándose. Terminando..."
    pkill -f "./$BINARY_NAME" || true
    pkill -f "/opt.*$BINARY_NAME" || true
    sleep 3
    
    # Forzar terminación si es necesario
    if pgrep -f "./$BINARY_NAME" > /dev/null || pgrep -f "/opt.*$BINARY_NAME" > /dev/null; then
        log_warn "Forzando terminación de procesos"
        pkill -9 -f "./$BINARY_NAME" || true
        pkill -9 -f "/opt.*$BINARY_NAME" || true
        sleep 2
    fi
    log_info "✓ Procesos del binario terminados"
fi

# 0.2 Eliminar archivo existente si está bloqueado
log_step "Verificando archivo de destino"
if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
    log_info "Eliminando archivo $BINARY_NAME existente"
    rm -f "$INSTALL_DIR/$BINARY_NAME" || {
        log_warn "No se pudo eliminar el archivo. Intentando con fuser..."
        fuser -k "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
        sleep 2
        rm -f "$INSTALL_DIR/$BINARY_NAME"
    }
fi

# 1. Crear directorio de instalación
log_step "Creando directorio $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# 2. Verificar que existe el binario
log_step "Verificando binario $BINARY_NAME..."
if [ ! -f "$CURRENT_DIR/$BINARY_NAME" ]; then
    log_error "Binario no encontrado: $BINARY_NAME"
    log_error "Ejecuta primero: go build -o $BINARY_NAME ./cmd/server && go build -o defensepro-admin ./cmd/admin"
    exit 1
fi
log_info "✓ Binario encontrado: $BINARY_NAME"

# 3. Copiar archivos a directorio de instalación
log_step "Copiando archivos a $INSTALL_DIR"

# Copiar binario con reintentos
RETRIES=3
for i in $(seq 1 $RETRIES); do
    if cp "$CURRENT_DIR/$BINARY_NAME" "$INSTALL_DIR/" 2>/dev/null; then
        log_info "✓ $BINARY_NAME copiado exitosamente"
        break
    else
        log_warn "Intento $i/$RETRIES falló. Esperando..."
        if [ $i -eq $RETRIES ]; then
            log_error "No se pudo copiar $BINARY_NAME después de $RETRIES intentos"
            exit 1
        fi
        sleep 2
    fi
done

# Copiar el CLI de administración si está compilado
if [ -f "$CURRENT_DIR/defensepro-admin" ]; then
    cp "$CURRENT_DIR/defensepro-admin" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/defensepro-admin"
    log_info "✓ defensepro-admin copiado"
fi

# Copiar archivo .env si existe
if [ -f "$CURRENT_DIR/.env" ]; then
    log_info "Copiando archivo .env"
    cp "$CURRENT_DIR/.env" "$INSTALL_DIR/"
else
    log_warn "Archivo .env no encontrado. Creando uno básico..."
    cat > "$INSTALL_DIR/.env" << 'EOF'
# Configuración del servidor
SERVER_HOST=0.0.0.0
SERVER_PORT=5687

# Postgres (equipos + tokens) y Redis (cache)
DATABASE_URL=postgres://defensepro:defensepro@localhost:5432/defensepro?sslmode=disable
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=

LOG_LEVEL=info
DEVICE_MAX_CONCURRENCY=4
EOF
    log_warn "⚠️  Edita $INSTALL_DIR/.env (DATABASE_URL, REDIS_ADDR) y registra los equipos con defensepro-admin add-device"
fi

# 4. Configurar permisos
log_step "Configurando permisos"
chmod +x "$INSTALL_DIR/$BINARY_NAME"
chmod 600 "$INSTALL_DIR/.env"  # Solo root puede leer credenciales

# 5. Crear archivo de servicio systemd
log_step "Creando archivo de servicio systemd"
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Radware DefensePro API Gateway Service
Documentation=https://www.radware.com/products/defensepro/
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/$BINARY_NAME
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Variables de entorno
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Límites de recursos
LimitNOFILE=65536
TimeoutStartSec=60
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

# 6. Recargar systemd
log_step "Recargando systemd daemon"
systemctl daemon-reload

# 7. Habilitar servicio
log_step "Habilitando servicio $SERVICE_NAME"
systemctl enable "$SERVICE_NAME.service"

# 8. Iniciar servicio
log_step "Iniciando servicio $SERVICE_NAME"
systemctl start "$SERVICE_NAME.service"

# 9. Verificar estado
log_step "Verificando estado del servicio"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME.service"; then
    log_info "✅ Servicio $SERVICE_NAME instalado y ejecutándose correctamente"
    log_info ""
    log_info "📁 Archivos instalados en: $INSTALL_DIR"
    log_info "📋 Servicio: $SERVICE_NAME.service"
    log_info ""
    log_info "🔧 Comandos útiles:"
    log_info "  sudo systemctl status $SERVICE_NAME        # Ver estado"
    log_info "  sudo systemctl restart $SERVICE_NAME       # Reiniciar"
    log_info "  sudo systemctl stop $SERVICE_NAME          # Detener"
    log_info "  sudo journalctl -u $SERVICE_NAME -f        # Ver logs en vivo"
    log_info "  sudo journalctl -u $SERVICE_NAME           # Ver todos los logs"
    log_info ""
    log_info "🌐 Endpoints disponibles (Bearer token en /api/v1/*):"
    log_info "  http://<host>:5687/health"
    log_info "  http://<host>:5687/health/deep"
    log_info "  http://<host>:5687/api/v1/system"
    log_info "  http://<host>:5687/api/v1/monitoring"
    log_info "  http://<host>:5687/api/v1/attacks"
    log_info "  (lista completa en README.md)"
    log_info ""
    log_info "📊 Estado actual:"
    systemctl status "$SERVICE_NAME.service" --no-pager -l
else
    log_error "❌ Error al iniciar el servicio. Verificar logs:"
    log_error "  sudo journalctl -u $SERVICE_NAME.service -n 50"
    log_error ""
    log_error "Posibles causas:"
    log_error "  - Postgres o Redis inaccesibles (DATABASE_URL / REDIS_ADDR en .env)"
    log_error "  - Puerto 5687 ya en uso"
    log_error "  - Certificado SSL rechazado"
    exit 1
fi

log_info ""
log_info "🎉 Instalación completada exitosamente!"
log_info "📝 Registra equipos: $INSTALL_DIR/defensepro-admin add-device <name> <url> <user> <pass>"
log_info "📊 Monitorea con: sudo journalctl -u $SERVICE_NAME -f"