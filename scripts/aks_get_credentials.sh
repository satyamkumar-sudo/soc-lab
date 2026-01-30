#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${ROOT_DIR}/kubeconfig"

RG="${AKS_RESOURCE_GROUP:-wealthy-dev-rg}"
CLUSTER="${AKS_CLUSTER_NAME:-wealthy}"
USE_ADMIN="${AKS_USE_ADMIN_CREDENTIALS:-True}"
USE_TOKEN_CFG="${AKS_USE_TOKEN_KUBECONFIG:-True}"
TOKEN_RESOURCE="${AKS_TOKEN_RESOURCE:-6dae42f8-4368-4678-94ff-3960e28e3630}"

echo "Fetching kubeconfig via az..."
USE_ADMIN_LC="$(printf '%s' "${USE_ADMIN}" | tr '[:upper:]' '[:lower:]')"
if [[ "${USE_ADMIN_LC}" == "true" ]]; then
  # Admin creds are best for container-side access, but require:
  # Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action
  set +e
  az aks get-credentials --resource-group "${RG}" --name "${CLUSTER}" --overwrite-existing --admin
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "WARN: admin kubeconfig fetch failed (missing permissions). Falling back to user credentials."
    az aks get-credentials --resource-group "${RG}" --name "${CLUSTER}" --overwrite-existing
  fi
else
  az aks get-credentials --resource-group "${RG}" --name "${CLUSTER}" --overwrite-existing
fi

echo "Copying kubeconfig to ${ROOT_DIR}/kubeconfig/config"
cp "${HOME}/.kube/config" "${ROOT_DIR}/kubeconfig/config"
chmod 600 "${ROOT_DIR}/kubeconfig/config"

USE_TOKEN_CFG_LC="$(printf '%s' "${USE_TOKEN_CFG}" | tr '[:upper:]' '[:lower:]')"
if [[ "${USE_TOKEN_CFG_LC}" == "true" ]]; then
  echo "Generating container-friendly token kubeconfig..."

  # Extract cluster endpoint and CA from the current context without requiring cluster access.
  SERVER="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
  CA_DATA="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
  NS="$(kubectl config view --raw --minify -o jsonpath='{.contexts[0].context.namespace}' 2>/dev/null || true)"
  if [[ -z "${NS}" ]]; then NS="default"; fi

  # Request an AAD token for the AKS API server audience.
  TOKEN="$(az account get-access-token --resource "${TOKEN_RESOURCE}" --query accessToken -o tsv)"
  if [[ -z "${TOKEN}" ]]; then
    echo "ERROR: unable to obtain AKS access token via az"
    exit 1
  fi

  cat > "${ROOT_DIR}/kubeconfig/config" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: aks
  cluster:
    server: ${SERVER}
    certificate-authority-data: ${CA_DATA}
users:
- name: aks-token-user
  user:
    token: ${TOKEN}
contexts:
- name: aks-token
  context:
    cluster: aks
    user: aks-token-user
    namespace: ${NS}
current-context: aks-token
EOF
  chmod 600 "${ROOT_DIR}/kubeconfig/config"
  echo "Token kubeconfig written to ${ROOT_DIR}/kubeconfig/config (re-run make aks-auth when token expires)."
fi

echo "Done. Containers will use KUBECONFIG=/kube/config (mounted from ./kubeconfig/config)."

