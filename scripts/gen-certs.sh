#!/bin/sh
set -e

DEST="traefik/certs"
mkdir -p "$DEST"

if [ -f "$DEST/cert.pem" ] && [ -f "$DEST/key.pem" ] && [ "$1" != "--force" ]; then
    echo "certificados ya existen en $DEST (usa --force para regenerar)"
    exit 0
fi

HOST="${HOST:-localhost}"

openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$DEST/key.pem" \
    -out    "$DEST/cert.pem" \
    -subj   "/CN=$HOST" \
    -days   3650 \
    -addext "subjectAltName=DNS:$HOST,DNS:defensepro-api,IP:127.0.0.1"

chmod 600 "$DEST/key.pem"
echo "certificados generados en $DEST (válidos para: $HOST, defensepro-api, 127.0.0.1)"
