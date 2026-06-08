#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if [ ! -f "relay.env" ]; then
    echo "[ERROR] relay.env not found."
    echo "Copy .env.example to relay.env and adjust local values."
    exit 1
fi

cr=$(printf '\r')
while IFS='=' read -r key value; do
    key=${key%"$cr"}
    value=${value%"$cr"}
    case "$key" in
        ""|\#*) continue ;;
    esac
    export "$key=$value"
done < "relay.env"

if [ -z "${DATABASE_URL:-}${RELAY_DATABASE_DSN:-}" ]; then
    echo "[ERROR] DATABASE_URL or RELAY_DATABASE_DSN is not set"
    exit 1
fi

if [ -z "${SECRET_API_KEY:-}" ]; then
    echo "[ERROR] SECRET_API_KEY is not set"
    exit 1
fi

if ! command -v go >/dev/null 2>&1; then
    echo "[ERROR] Go is not installed or not in PATH"
    exit 1
fi

for file in \
    "${RELAY_DEVICE_CA_CERT_FILE:-certs/ca.crt}" \
    "${RELAY_GRPC_CERT_FILE:-certs/server.crt}" \
    "${RELAY_GRPC_KEY_FILE:-certs/server.key}" \
    "${RELAY_ADMIN_CERT_FILE:-certs/admin.crt}" \
    "${RELAY_ADMIN_KEY_FILE:-certs/admin.key}"
do
    if [ ! -f "$file" ]; then
        echo "[ERROR] $file not found. Run certs/generate_certs.sh first."
        exit 1
    fi
done

if [ -n "${RELAY_ENROLLMENT_TOKEN:-}" ]; then
    file="${RELAY_DEVICE_CA_KEY_FILE:-certs/ca.key}"
    if [ ! -f "$file" ]; then
        echo "[ERROR] $file not found. It is required while device enrollment is enabled."
        exit 1
    fi
fi

echo "[INFO] Starting relay server..."
exec go run .
