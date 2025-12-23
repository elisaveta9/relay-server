@echo off

cd /d "%~dp0"


set SECRET_API_KEY=VNJ9L-BBBIM-6CJGZ-MO5AZ
set CERT_DIR=certs
set ADMIN_CERT=%CERT_DIR%\admin.crt
set ADMIN_KEY=%CERT_DIR%\admin.key

if not exist "%ADMIN_CERT%" (
    echo [ERROR] admin.crt not found in %CERT_DIR%
    goto :error
)

if not exist "%ADMIN_KEY%" (
    echo [ERROR] admin.key not found in %CERT_DIR%
    goto :error
)

echo [OK] Certificates found
echo [INFO] Starting relay server...
echo.

go run .

goto :eof

:error
echo.
echo Fix the error and try again.
pause
exit /b 1
