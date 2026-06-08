@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

set "ENV_FILE=relay.env"

if not exist "%ENV_FILE%" (
    echo [ERROR] %ENV_FILE% not found.
    echo Create %ENV_FILE% and adjust local values.
    exit /b 1
)

for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ENV_FILE%") do (
    if not "%%A"=="" set "%%A=%%B"
)

if "%DATABASE_URL%%RELAY_DATABASE_DSN%"=="" (
    echo [ERROR] DATABASE_URL or RELAY_DATABASE_DSN is not set
    exit /b 1
)

if "%SECRET_API_KEY%"=="" (
    echo [ERROR] SECRET_API_KEY is not set
    exit /b 1
)

if "%RELAY_DEVICE_CA_CERT_FILE%"=="" set "RELAY_DEVICE_CA_CERT_FILE=certs\ca.crt"
if "%RELAY_DEVICE_CA_KEY_FILE%"=="" set "RELAY_DEVICE_CA_KEY_FILE=certs\ca.key"
if "%RELAY_GRPC_CERT_FILE%"=="" set "RELAY_GRPC_CERT_FILE=certs\server.crt"
if "%RELAY_GRPC_KEY_FILE%"=="" set "RELAY_GRPC_KEY_FILE=certs\server.key"
if "%RELAY_ADMIN_CERT_FILE%"=="" set "RELAY_ADMIN_CERT_FILE=certs\admin.crt"
if "%RELAY_ADMIN_KEY_FILE%"=="" set "RELAY_ADMIN_KEY_FILE=certs\admin.key"

if not exist "%RELAY_DEVICE_CA_CERT_FILE%" (
    echo [ERROR] %RELAY_DEVICE_CA_CERT_FILE% not found.
    exit /b 1
)

if not exist "%RELAY_GRPC_CERT_FILE%" (
    echo [ERROR] %RELAY_GRPC_CERT_FILE% not found.
    exit /b 1
)

if not exist "%RELAY_GRPC_KEY_FILE%" (
    echo [ERROR] %RELAY_GRPC_KEY_FILE% not found.
    exit /b 1
)

if not exist "%RELAY_ADMIN_CERT_FILE%" (
    echo [ERROR] %RELAY_ADMIN_CERT_FILE% not found.
    exit /b 1
)

if not exist "%RELAY_ADMIN_KEY_FILE%" (
    echo [ERROR] %RELAY_ADMIN_KEY_FILE% not found.
    exit /b 1
)

if not "%RELAY_ENROLLMENT_TOKEN%"=="" if not exist "%RELAY_DEVICE_CA_KEY_FILE%" (
    echo [ERROR] %RELAY_DEVICE_CA_KEY_FILE% not found. It is required while device enrollment is enabled.
    exit /b 1
)

echo [INFO] Starting relay server...
go run .
