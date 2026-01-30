#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs"
mkdir -p "${CERT_DIR}"

CA_KEY="${CERT_DIR}/ca.key"
CA_CRT="${CERT_DIR}/ca.crt"
SERVER_KEY="${CERT_DIR}/server.key"
SERVER_CSR="${CERT_DIR}/server.csr"
SERVER_CRT="${CERT_DIR}/server.crt"
CLIENT_KEY="${CERT_DIR}/client.key"
CLIENT_CSR="${CERT_DIR}/client.csr"
CLIENT_CRT="${CERT_DIR}/client.crt"

if [[ -f "${CA_CRT}" && -f "${SERVER_CRT}" && -f "${CLIENT_CRT}" ]]; then
  echo "certs already exist at ${CERT_DIR}"
  exit 0
fi

echo "Generating local CA..."
openssl genrsa -out "${CA_KEY}" 4096 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
  -subj "/C=US/ST=CA/L=Local/O=SOC-Lab/OU=CA/CN=soc-lab-ca" \
  -out "${CA_CRT}" >/dev/null 2>&1

cat > "${CERT_DIR}/server-ext.cnf" <<'EOF'
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
C=US
ST=CA
L=Local
O=SOC-Lab
OU=Gateway
CN=localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = gateway
DNS.3 = soc-api
IP.1 = 127.0.0.1
EOF

echo "Generating server cert..."
openssl genrsa -out "${SERVER_KEY}" 2048 >/dev/null 2>&1
openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" -config "${CERT_DIR}/server-ext.cnf" >/dev/null 2>&1
openssl x509 -req -in "${SERVER_CSR}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
  -out "${SERVER_CRT}" -days 825 -sha256 -extensions req_ext -extfile "${CERT_DIR}/server-ext.cnf" >/dev/null 2>&1

cat > "${CERT_DIR}/client-ext.cnf" <<'EOF'
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[ dn ]
C=US
ST=CA
L=Local
O=SOC-Lab
OU=Airflow
CN=airflow-client
EOF

echo "Generating client cert..."
openssl genrsa -out "${CLIENT_KEY}" 2048 >/dev/null 2>&1
openssl req -new -key "${CLIENT_KEY}" -out "${CLIENT_CSR}" -config "${CERT_DIR}/client-ext.cnf" >/dev/null 2>&1
openssl x509 -req -in "${CLIENT_CSR}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
  -out "${CLIENT_CRT}" -days 825 -sha256 >/dev/null 2>&1

chmod 600 "${CA_KEY}" "${SERVER_KEY}" "${CLIENT_KEY}"
echo "mTLS certs written to ${CERT_DIR}"

