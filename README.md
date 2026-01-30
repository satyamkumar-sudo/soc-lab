# soc-lab

Production-quality **local SOC analytics lab**:

- **Ingest**: GCP Cloud Logging (GKE + Audit + IAM + App logs)
- **Orchestrate**: Apache Airflow (local)
- **Store/Query**: ClickHouse (local)
- **Analyze**: agents (normalize → enrich → features → anomalies → rules → **Vertex AI Gemini**)
- **Visualize**: Grafana (local, ClickHouse datasource)
- **Alert**: Slack/Webhook with dedupe + throttling (LLM-enhanced)

This repo is runnable locally via Docker Compose and supports:

- **Prod**: GCP ingestion (Cloud Logging) + Vertex AI Gemini
- **Dev**: Azure AKS ingestion (pod logs via kubeconfig) + Vertex AI Gemini (still on GCP)

## Architecture

Airflow DAG (`airflow/dags/gcp_log_pipeline.py`) runs every 5 minutes:

1. Fetch logs from GCP (Cloud Logging API) and store → `soc.raw_logs`
2. Normalize → `soc.normalized_logs`
3. Enrich (Geo/ASN from local dataset + threat intel feed + ownership + baseline) → `soc.enriched_logs`
4. Build 5-minute features → `soc.features`
5. Detect anomalies (IsolationForest + “autoencoder” + z-score, ensemble) → `soc.anomalies`
6. Apply YAML rules → `soc.rule_matches`
7. LLM analysis (Vertex AI Gemini) updates `soc.anomalies.llm_summary`
8. Alerting (Slack/Webhook) logs to `soc.alerts`

Airflow calls the SOC API behind an **mTLS gateway** (`gateway/nginx.conf`).

## Prerequisites

- Docker Desktop (or compatible Docker engine) + `docker compose`
- `make`
- GCP project access to read logs (dev cluster / dev project)

## GCP Authentication (service account JSON)

1. Create a service account with least privilege (see “Security hardening” below).
2. Create a key JSON and place it at:

- `soc-lab/secrets/gcp-sa.json`

3. The containers use `GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-sa.json` (already set in `.env`).

## Connect to your Kubernetes cluster (GCP prod)

Run on your host (or just run `make gke-auth`):

```bash
gcloud container clusters get-credentials wealthyprod --zone asia-south1-a --project wealthy-prod-app-669
```

This project then copies your kubeconfig into `soc-lab/kubeconfig/config` and mounts it into containers as `KUBECONFIG=/kube/config` so the pipeline can fetch live pod inventory.

## Connect to your Kubernetes cluster (Azure dev / AKS)

Run on your host (or just run `make aks-auth`):

```bash
az aks get-credentials --resource-group wealthy-dev-rg --name wealthy --overwrite-existing
```

For **real container-side access**, `make aks-auth` also writes a **token-based kubeconfig**
to `soc-lab/kubeconfig/config` (no exec plugins). Re-run `make aks-auth` when the token expires.

## Falcon-only ingestion

Right now the pipeline is constrained to **Falcon service logs only** (per your request).

Control this with:

- `SOC_SERVICE_ALLOWLIST` (comma-separated list) in `.env` (empty means ingest all services)

This is enforced both for:

- **Cloud Logging ingestion** (filters Kubernetes logs to Falcon pods/containers)
- **Kubernetes inventory snapshots** (only Falcon pods are emitted)

## Switching GCP ingestion target

The SOC ingestion target project/cluster is controlled by:

- `SOC_GCP_PROJECT` (Cloud Logging + inventory project label)
- `GKE_CLUSTER_NAME`
- `GKE_LOCATION`

Vertex AI Gemini remains controlled by:

- `GOOGLE_CLOUD_PROJECT`
- `GOOGLE_CLOUD_LOCATION`

## Switching ingestion provider (GCP vs Azure)

Choose where SOC logs come from with:

- `SOC_INGEST_PROVIDER=gcp` (prod; Cloud Logging)
- `SOC_INGEST_PROVIDER=azure` (dev; AKS pod logs)

Tip: use the provided env file for Azure dev:

```bash
docker compose --env-file .env.azure-dev up -d --build
```

## Vertex AI (Gemini) configuration

This project uses **Vertex AI Gemini** only (no OpenAI, no external LLM APIs).

The following env vars are set in `.env`:

- `GOOGLE_GENAI_USE_VERTEXAI=True`
- `GOOGLE_CLOUD_PROJECT=wealthy-dev-app-8081`
- `GOOGLE_CLOUD_LOCATION=us-central1`

The LLM agent is implemented in `agents/llm_analyzer.py` and initializes:

- `vertexai.init(project="wealthy-dev-app-8081", location="us-central1")`
- Google Gen AI SDK client routed via Vertex (`GOOGLE_GENAI_USE_VERTEXAI=True`)

## Local deployment

From `soc-lab/`:

```bash
make init
make gke-auth
make up
```

Then open:

- **Airflow UI**: `http://localhost:8080` (user/pass from `.env`)
- **Grafana**: `http://localhost:3000` (admin creds set in `docker-compose.yml`)
- **ClickHouse HTTP**: `http://localhost:8123`

The SOC API is behind the gateway:

- **Gateway**: `https://localhost:8443/health` (no client cert required)
- **Internal pipeline endpoints**: `https://localhost:8443/internal/...` (requires mTLS client cert)
- **UI endpoints**: `https://localhost:8443/ui/...` (public, for React UI)
  - `/ui/mock-data` - Returns logs/anomalies/IAM changes in React mock format
  - `/ui/network-flow` - Returns Sankey diagram data (nodes + links) for network flow visualization

## Running the Airflow pipeline

1. Ensure services are up:

```bash
make ps
```

2. In Airflow UI, enable the DAG:

- `gcp_log_pipeline`

3. Watch logs:

```bash
make logs
```

## Training / model tuning

The anomaly agent trains models **online** from ClickHouse `features` history. The file `ml/model.pkl` is a JSON “model config” used to tune hyperparameters.

To (re)write model config based on current feature volume:

```bash
docker compose exec soc-api python -m ml.train
```

## Rules (YAML)

Rules are configured in:

- `agents/rules.yaml`

They are applied in `agents/rule_engine.py` and stored in `soc.rule_matches`.

## Grafana dashboards

Dashboards are auto-provisioned from:

- `grafana/dashboards/*.json`

Includes:

- SOC End-to-End
- SOC Overview
- IAM Monitoring
- Kubernetes Security
- Network Threats
- AI Risk Score
- LLM Incident Summary
- Threat Timeline
- Live Log Explorer

## Alerting (Slack/Webhook)

Set one of:

- `ALERT_SLACK_WEBHOOK_URL` (Slack Incoming Webhook)
- `ALERT_WEBHOOK_URL` (generic JSON webhook)

Alerts are **deduped** and **throttled** and are persisted in `soc.alerts`.

## Demo scenarios (works even without GCP access)

If `secrets/gcp-sa.json` is missing or `GOOGLE_CLOUD_PROJECT` is not set, ingestion runs in **demo mode** and generates realistic synthetic events:

- failed login bursts (`app/login`)
- IAM changes + occasional `roles/owner` grants
- privileged pod / host mount signals
- suspicious IPs from `data/threat_intel_iocs.csv`

This keeps the full pipeline and dashboards runnable locally.

## Security hardening notes (enterprise patterns)

- **Least privilege IAM** (recommended roles for the ingestion SA):
  - `roles/logging.viewer`
  - `roles/container.clusterViewer` (if you need to list clusters; ingestion mostly uses Cloud Logging)
  - `roles/iam.securityReviewer` (optional; many IAM signals come from audit logs)
  - If using Secret Manager: grant `roles/secretmanager.secretAccessor` only for specific secrets.
- **Secret Manager integration**:
  - Toggle with `GCP_USE_SECRET_MANAGER=True`
  - Secrets accessed by `storage/secrets.py`
- **mTLS internal traffic**:
  - `scripts/gen_certs.sh` generates a local CA, server cert, and Airflow client cert.
  - Nginx enforces client cert for `/internal/*`.
- **Audit trails**:
  - Structured JSON logs via `structlog` with request IDs (`X-Request-Id`).
- **Token rotation**:
  - Google auth libraries automatically refresh short-lived tokens used for GCP APIs.

## Troubleshooting

- **ClickHouse not healthy**:
  - Check `docker compose logs clickhouse`
- **Grafana ClickHouse datasource missing**:
  - Grafana installs `grafana-clickhouse-datasource` on startup; wait ~30–60s then refresh.
- **Airflow tasks failing with 401**:
  - Run `make certs` and restart (`make down && make up`), ensure `certs/` exists.
- **Kubernetes inventory failing**:
  - Run `make gke-auth` (this runs `gcloud container clusters get-credentials wealthy-dev --zone asia-south1-a --project wealthy-dev-app-8081` and copies kubeconfig into `./kubeconfig/config`).
  - Ensure your host can run `kubectl get pods -A` against the cluster.
- **Vertex/Gemini calls failing**:
  - Ensure the service account has Vertex AI permissions and Vertex API is enabled.
  - Check `docker compose logs soc-api` and verify `.env` has Vertex settings.


