@echo off
setlocal enabledelayedexpansion

set OPENSSL="C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe"

%OPENSSL%  x509 -in ca.crt -out ca.der -outform DER


if not exist ca.crt (
    echo [ERROR] File ca.crt not found in this folder.
    pause
    exit /b 1
)

echo [OK] Found ca.crt

set BC_FILE=bcprov-jdk15on-1.70.jar

if not exist %BC_FILE% (
    echo [INFO] Downloading %BC_FILE% ...
    powershell -Command "(New-Object Net.WebClient).DownloadFile('https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.70/bcprov-jdk15on-1.70.jar', '%BC_FILE%')"
    if not exist %BC_FILE% (
        echo [ERROR] Failed to download %BC_FILE%
        pause
        exit /b 1
    )
)

echo [OK] BouncyCastle is ready: %BC_FILE%

echo [INFO] Converting ca.crt to ca.der ...
%OPENSSL% x509 -in ca.crt -out ca.der -outform DER

if not exist ca.der (
    echo [ERROR] Failed to create ca.der
    pause
    exit /b 1
)

echo [OK] ca.der created

echo [INFO] Creating BKS TrustStore ca.bks ...

keytool -importcert -alias relayCA -file ca.der -keystore ca.bks -storetype BKS -storepass password -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath %BC_FILE% -noprompt

if not exist ca.bks (
    echo [ERROR] Failed to create ca.bks
    pause
    exit /b 1
)

echo [OK] ca.bks successfully created

echo [INFO] Verifying ca.bks ...
keytool -list -v -keystore ca.bks -storepass password -storetype BKS

echo ca.bks is ready for Android.
pause