#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

OPENSSL_BIN="${OPENSSL:-openssl}"

echo "[INFO] Using OpenSSL: $OPENSSL_BIN"
if ! "$OPENSSL_BIN" version >/dev/null 2>&1; then
    echo "[ERROR] OpenSSL not found. Install OpenSSL or set OPENSSL to openssl binary path."
    exit 1
fi

cat > server_ext.cnf <<'EOF'
[v3_req]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
EOF

cat > admin_ext.cnf <<'EOF'
[v3_req]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
EOF

if [ ! -f ca.key ]; then
    echo "[INFO] Creating local CA..."
    "$OPENSSL_BIN" genrsa -out ca.key 4096
fi

if [ ! -f ca.crt ]; then
    "$OPENSSL_BIN" req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=relay-local-ca"
fi

if [ ! -f server.key ]; then
    echo "[INFO] Creating gRPC server key..."
    "$OPENSSL_BIN" genrsa -out server.key 2048
fi

echo "[INFO] Creating gRPC server certificate..."
"$OPENSSL_BIN" req -new -key server.key -out server.csr -subj "/CN=localhost"
"$OPENSSL_BIN" x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server_ext.cnf -extensions v3_req

if [ ! -f admin.key ]; then
    echo "[INFO] Creating admin HTTPS key..."
    "$OPENSSL_BIN" genrsa -out admin.key 2048
fi

echo "[INFO] Creating admin HTTPS certificate..."
"$OPENSSL_BIN" req -new -key admin.key -out admin.csr -subj "/CN=localhost"
"$OPENSSL_BIN" x509 -req -in admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out admin.crt -days 365 -sha256 -extfile admin_ext.cnf -extensions v3_req
cat admin.crt ca.crt > admin-chain.crt

echo
echo "[OK] Generated certificates:"
ls -1 ca.crt server.crt server.key admin.crt admin.key admin-chain.crt 2>/dev/null
