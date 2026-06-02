@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

if not exist ".env" (
    echo [ERROR] .env not found.
    echo Copy .env.example to .env and adjust local values.
    exit /b 1
)

for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do (
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

if not exist "certs\ca.crt" (
    echo [ERROR] certs\ca.crt not found. Run certs\generate_certs.bat first.
    exit /b 1
)

if not exist "certs\server.crt" (
    echo [ERROR] certs\server.crt not found. Run certs\generate_certs.bat first.
    exit /b 1
)

if not exist "certs\server.key" (
    echo [ERROR] certs\server.key not found. Run certs\generate_certs.bat first.
    exit /b 1
)

if not exist "certs\admin.crt" (
    echo [ERROR] certs\admin.crt not found. Run certs\generate_certs.bat first.
    exit /b 1
)

if not exist "certs\admin.key" (
    echo [ERROR] certs\admin.key not found. Run certs\generate_certs.bat first.
    exit /b 1
)

echo [INFO] Starting relay server...
go run .
