@echo off

cd /d "%~dp0"

set OPENSSL="C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe"

if not exist %OPENSSL% (
    echo [ERROR] OpenSSL not found at:
    echo %OPENSSL%
    pause
    exit /b 1
)

REM генерация сертификата
%OPENSSL% req -x509 -newkey rsa:2048 ^
 -keyout admin.key ^
 -out admin.crt ^
 -days 365 ^
 -nodes ^
 -subj "/CN=localhost"

if errorlevel 1 (
    echo [ERROR] OpenSSL failed
    pause
    exit /b 1
)

echo.
echo [SUCCESS] admin.crt and admin.key generated in certs\
pause
