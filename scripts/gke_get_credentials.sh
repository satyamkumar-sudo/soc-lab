#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${ROOT_DIR}/kubeconfig"

PROJECT="${SOC_GCP_PROJECT:-${GOOGLE_CLOUD_PROJECT:-wealthy-prod-app-669}}"
CLUSTER="${GKE_CLUSTER_NAME:-wealthyprod}"
ZONE="${GKE_LOCATION:-asia-south1-a}"

echo "Fetching kubeconfig via gcloud..."
gcloud container clusters get-credentials "${CLUSTER}" --zone "${ZONE}" --project "${PROJECT}"

echo "Copying kubeconfig to ${ROOT_DIR}/kubeconfig/config"
cp "${HOME}/.kube/config" "${ROOT_DIR}/kubeconfig/config"
chmod 600 "${ROOT_DIR}/kubeconfig/config"

echo "Done. Containers will use KUBECONFIG=/kube/config (mounted from ./kubeconfig/config)."

