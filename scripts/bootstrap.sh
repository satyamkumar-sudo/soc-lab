#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "[1/3] Generating mTLS certs (if missing)..."
bash ./scripts/gen_certs.sh

echo "[2/3] Ensuring local dirs..."
mkdir -p data secrets

if [[ ! -f secrets/gcp-sa.json ]]; then
  echo "NOTE: secrets/gcp-sa.json not found; ingestion will run in demo mode."
fi

echo "[3/3] Starting stack..."
docker compose up -d --build
docker compose ps

