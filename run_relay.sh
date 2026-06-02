#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if [ ! -f ".env" ]; then
    echo "[ERROR] .env not found."
    echo "Copy .env.example to .env and adjust local values."
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
done < ".env"

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
    certs/ca.crt \
    certs/server.crt \
    certs/server.key \
    certs/admin.crt \
    certs/admin.key
do
    if [ ! -f "$file" ]; then
        echo "[ERROR] $file not found. Run certs/generate_certs.sh first."
        exit 1
    fi
done

echo "[INFO] Starting relay server..."
exec go run .
