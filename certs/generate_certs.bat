@echo off
setlocal

cd /d "%~dp0"

if not defined OPENSSL (
    if exist "C:\Program Files\Git\mingw64\bin\openssl.exe" set "OPENSSL=C:\Program Files\Git\mingw64\bin\openssl.exe"
)
if not defined OPENSSL (
    if exist "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" set "OPENSSL=C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
)
if not defined OPENSSL (
    if exist "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe" set "OPENSSL=C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe"
)
if not defined OPENSSL set "OPENSSL=openssl"

echo [INFO] Using OpenSSL: %OPENSSL%
"%OPENSSL%" version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] OpenSSL not found. Install OpenSSL or set OPENSSL to openssl.exe path.
    exit /b 1
)

call :write_server_ext
call :write_admin_ext

if not exist ca.key (
    echo [INFO] Creating local CA...
    "%OPENSSL%" genrsa -out ca.key 4096
    if errorlevel 1 exit /b 1
)

if not exist ca.crt (
    "%OPENSSL%" req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=relay-local-ca"
    if errorlevel 1 exit /b 1
)

if not exist server.key (
    echo [INFO] Creating gRPC server key...
    "%OPENSSL%" genrsa -out server.key 2048
    if errorlevel 1 exit /b 1
)

echo [INFO] Creating gRPC server certificate...
"%OPENSSL%" req -new -key server.key -out server.csr -subj "/CN=localhost"
if errorlevel 1 exit /b 1
"%OPENSSL%" x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server_ext.cnf -extensions v3_req
if errorlevel 1 exit /b 1

if not exist admin.key (
    echo [INFO] Creating admin HTTPS key...
    "%OPENSSL%" genrsa -out admin.key 2048
    if errorlevel 1 exit /b 1
)

echo [INFO] Creating admin HTTPS certificate...
"%OPENSSL%" req -new -key admin.key -out admin.csr -subj "/CN=localhost"
if errorlevel 1 exit /b 1
"%OPENSSL%" x509 -req -in admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out admin.crt -days 365 -sha256 -extfile admin_ext.cnf -extensions v3_req
if errorlevel 1 exit /b 1
copy /b admin.crt+ca.crt admin-chain.crt >nul

echo.
echo [OK] Generated certificates:
dir /b ca.crt server.crt server.key admin.crt admin.key admin-chain.crt 2>nul
exit /b 0

:write_server_ext
(
    echo [v3_req]
    echo basicConstraints=CA:FALSE
    echo keyUsage=digitalSignature,keyEncipherment
    echo extendedKeyUsage=serverAuth
    echo subjectAltName=@alt_names
    echo.
    echo [alt_names]
    echo DNS.1=localhost
    echo IP.1=127.0.0.1
) > server_ext.cnf
exit /b 0

:write_admin_ext
(
    echo [v3_req]
    echo basicConstraints=CA:FALSE
    echo keyUsage=digitalSignature,keyEncipherment
    echo extendedKeyUsage=serverAuth
    echo subjectAltName=@alt_names
    echo.
    echo [alt_names]
    echo DNS.1=localhost
    echo IP.1=127.0.0.1
) > admin_ext.cnf
exit /b 0
