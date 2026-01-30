# 🛡️ SOC Analytics Lab - Production-Ready Security Operations Center

[![GitHub](https://img.shields.io/badge/GitHub-soc--lab-blue)](https://github.com/satyamkumar-sudo/soc-lab)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](docker-compose.yml)

> **Complete end-to-end SOC analytics platform** with GCP/Azure integration, real-time anomaly detection, ML-powered threat analysis, and production-grade observability.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Dashboard](#dashboard)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

This SOC Lab provides a **complete security analytics pipeline** for monitoring, analyzing, and responding to security events in cloud-native environments (GCP/Azure Kubernetes).

### What It Does:
- 📊 **Ingests logs** from GCP Cloud Logging or Azure AKS
- 🔄 **Processes** logs through multi-stage pipeline (normalization → enrichment → feature engineering)
- 🤖 **Detects anomalies** using ensemble ML models (Isolation Forest + Autoencoder + Z-Score)
- 🧠 **Analyzes threats** using LLM (Vertex AI Gemini)
- ⚡ **Alerts** in real-time via WebSocket & REST API
- 📈 **Visualizes** everything in Grafana dashboards

---

## ✨ Features

### 🔐 Security & Detection
- **7 Anomaly Detection Signals:**
  - New/Never-Seen Error Detection
  - Error Burst Detection
  - Service Behavior Deviation
  - Repeated Failures Without Success
  - Cross-Pod Error Correlation
  - Sudden Log Volume Spike
  - Pod-Specific Anomaly

- **Rule-Based Detection:**
  - OS-level security threats
  - Failed login attempts
  - Privilege escalation
  - Malicious IP detection
  - Custom YAML rules

- **Machine Learning:**
  - Ensemble anomaly detection (IsolationForest + Autoencoder + Z-Score)
  - Auto-scaling feature engineering
  - Real-time scoring

- **LLM Analysis:**
  - Threat severity assessment via Vertex AI Gemini
  - Context-aware explanations
  - Intelligent caching for cost optimization

### 🏗️ Infrastructure
- **Cloud Integrations:**
  - GCP Cloud Logging & GKE
  - Azure AKS & Container Insights
  - Multi-cloud support

- **Data Storage:**
  - ClickHouse for high-performance analytics
  - PostgreSQL for Airflow metadata
  - Optimized schemas with TTL & partitioning

- **API & Security:**
  - FastAPI REST API with mTLS
  - WebSocket real-time streaming
  - Certificate-based authentication
  - CORS & security headers

- **Automation:**
  - Apache Airflow for scheduled ingestion (every 5 minutes)
  - Automated processing pipeline
  - Self-healing with retries

### 📊 Observability
- **Grafana Dashboards:**
  - Real-time SOC operations dashboard
  - Service health monitoring
  - Threat detection timeline
  - Anomaly trends

- **Metrics:**
  - Total logs/anomalies/signals
  - Error rates per service
  - Response time percentiles (P50, P95, P99)
  - Ingest lag monitoring

---

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     DATA SOURCES                             │
│   GCP Cloud Logging / Azure AKS / Kubernetes Clusters        │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   INGESTION LAYER                            │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ GCP Fetcher  │    │ AKS Fetcher  │    │ K8s Inventory│  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                    │                    │          │
│         └────────────────────┴────────────────────┘          │
│                            │                                 │
│                    Apache Airflow                            │
│                   (5-min schedule)                           │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  PROCESSING PIPELINE                         │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │ Normalizer │→ │  Enricher  │→ │  Feature   │            │
│  │            │  │  (Geo/ASN) │  │  Builder   │            │
│  └────────────┘  └────────────┘  └────────────┘            │
│         │                                │                   │
│         ▼                                ▼                   │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │  Anomaly   │  │    Rule    │  │    LLM     │            │
│  │  Detection │  │   Engine   │  │  Analyzer  │            │
│  └────────────┘  └────────────┘  └────────────┘            │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   STORAGE LAYER                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                 ClickHouse                            │  │
│  │  • raw_logs (MergeTree, TTL 30d)                     │  │
│  │  • enriched_logs (MergeTree, TTL 90d)                │  │
│  │  • anomalies (MergeTree, TTL 180d)                   │  │
│  │  • anomaly_signals (MergeTree, TTL 90d)              │  │
│  │  • rule_matches (MergeTree, TTL 180d)                │  │
│  │  • alerts (MergeTree, TTL 365d)                      │  │
│  └──────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  PRESENTATION LAYER                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   FastAPI    │    │   Grafana    │    │  WebSocket   │  │
│  │   REST API   │    │  Dashboards  │    │   Alerts     │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                    │                    │          │
│         └────────────────────┴────────────────────┘          │
│                            │                                 │
│                    Nginx (mTLS Gateway)                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- GCP or Azure account with Kubernetes cluster
- 8GB+ RAM, 20GB+ disk space

### 1. Clone Repository
```bash
git clone https://github.com/satyamkumar-sudo/soc-lab.git
cd soc-lab
```

### 2. Set Up Credentials

**For GCP:**
```bash
# Authenticate with GCP
gcloud auth application-default login

# Copy credentials
cp ~/.config/gcloud/application_default_credentials.json secrets/gcp-sa.json

# Or use service account key
cp /path/to/your-service-account.json secrets/gcp-sa.json

# Get GKE credentials
bash scripts/gke_get_credentials.sh
```

**For Azure:**
```bash
# Login to Azure
az login

# Get AKS credentials
bash scripts/aks_get_credentials.sh
```

### 3. Configure Environment

Edit `.env` file:
```bash
# Choose provider: gcp or azure
SOC_INGEST_PROVIDER=gcp

# GCP Configuration
SOC_GCP_PROJECT=your-gcp-project-id
GKE_CLUSTER_NAME=your-cluster-name
GKE_LOCATION=us-central1-a

# Or Azure Configuration
SOC_INGEST_PROVIDER=azure
AKS_RESOURCE_GROUP=your-resource-group
AKS_CLUSTER_NAME=your-cluster-name
```

### 4. Start Services
```bash
# Start all services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f
```

### 5. Access Dashboards

- **Grafana:** http://localhost:3000
  - Username: `admin`
  - Password: `admin`
  - Dashboard: SOC Ops (Production)

- **Airflow:** http://localhost:8080
  - Username: `airflow`
  - Password: `airflow`

- **API:** https://localhost:8443 (with client cert)

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SOC_INGEST_PROVIDER` | Cloud provider: `gcp` or `azure` | `gcp` |
| `SOC_GCP_PROJECT` | GCP project ID for log ingestion | - |
| `GKE_CLUSTER_NAME` | GKE cluster name | `wealthyprod` |
| `GKE_LOCATION` | GKE cluster zone | `asia-south1-a` |
| `AKS_RESOURCE_GROUP` | Azure resource group | - |
| `AKS_CLUSTER_NAME` | AKS cluster name | - |
| `GOOGLE_CLOUD_PROJECT` | Vertex AI project ID | - |
| `GOOGLE_CLOUD_LOCATION` | Vertex AI region | `us-central1` |
| `SOC_DISABLE_SYNTHETIC_LOGS` | Disable test data | `true` |

### Airflow DAG Schedule

Default: Every 5 minutes

To change, edit `airflow/dags/gcp_log_pipeline.py`:
```python
schedule_interval="*/5 * * * *"  # cron format
```

### ClickHouse Configuration

- **Data retention:** Configured via TTL in schema
- **Compression:** LZ4 by default
- **Partitioning:** By day for time-series tables

---

## 📡 API Documentation

### REST Endpoints

#### Get Dashboard Data
```bash
GET /ui/mock-data?hours=24&log_limit=500
```

**Response:**
```json
{
  "logs": [...],
  "anomalies": [...],
  "iamChanges": [...],
  "networkFlow": {
    "sankeyData": {
      "nodes": [...],
      "links": [...]
    }
  },
  "topAttackers": [...],
  "threatDistribution": [...]
}
```

#### List Alerts
```bash
GET /ui/alerts?hours=24&limit=100
```

#### WebSocket (Real-time)
```javascript
const ws = new WebSocket('wss://localhost:8443/ws/alerts');
ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log('New alert:', alert);
};
```

**For complete API documentation, see:** [SOC_API_ENDPOINTS.md](SOC_API_ENDPOINTS.md)

---

## 📊 Dashboard

### SOC Ops Dashboard

Access at: http://localhost:3000/d/enterprise-soc

**Panels:**
- 🚨 Top 10 Security Threats (24h)
- 📊 KPI Stats (Logs, Anomalies, Signals, Rule Matches, Critical Incidents)
- 💚 Service Health (Last Hour)
- 📈 Detections Timeline
- 📊 Top 10 Services by Error Rate
- ⏱️ Service Response Times (P50, P95, P99)

**Features:**
- Auto-refresh every 30 seconds
- Time range selector
- Service/namespace filters
- Color-coded severity

---

## 🚢 Deployment

### Production Checklist

- [ ] Set strong passwords in `.env`
- [ ] Use dedicated service account with minimal permissions
- [ ] Enable SSL/TLS for all services
- [ ] Configure firewall rules (allow only necessary ports)
- [ ] Set up log rotation
- [ ] Enable monitoring & alerting
- [ ] Configure backup for ClickHouse data
- [ ] Review and customize security rules in `agents/rules.yaml`
- [ ] Set up Secret Manager for credentials
- [ ] Enable audit logging

### Docker Compose Production

```bash
# Use production compose file
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Kubernetes Deployment

Helm charts coming soon!

---

## 🔧 Troubleshooting

### No Data in Grafana

**Check ingestion:**
```bash
# Check Airflow DAG runs
docker compose logs airflow-scheduler | grep gcp_log_pipeline

# Check API logs
docker compose logs soc-api | tail -50

# Verify ClickHouse data
docker compose exec clickhouse clickhouse-client --query \
  "SELECT count() FROM soc.enriched_logs"
```

**Common issues:**
- Missing GCP/Azure credentials
- Expired Kubernetes credentials
- Network connectivity issues
- Incorrect project/cluster names in `.env`

### Airflow Tasks Failing

```bash
# Check task logs
docker compose exec airflow-scheduler airflow tasks test gcp_log_pipeline fetch_gcp_logs 2026-01-30

# Check API health
curl -k https://localhost:8443/health
```

### ClickHouse Slow Queries

```bash
# Check query performance
docker compose exec clickhouse clickhouse-client --query \
  "SELECT query, elapsed FROM system.query_log ORDER BY elapsed DESC LIMIT 10"

# Optimize tables
docker compose exec clickhouse clickhouse-client --query \
  "OPTIMIZE TABLE soc.enriched_logs FINAL"
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgments

- **ClickHouse** for blazing-fast analytics
- **Apache Airflow** for reliable orchestration
- **Grafana** for beautiful visualizations
- **FastAPI** for modern Python APIs
- **Google Vertex AI** for LLM capabilities

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/satyamkumar-sudo/soc-lab/issues)
- **Discussions:** [GitHub Discussions](https://github.com/satyamkumar-sudo/soc-lab/discussions)

---

**Built with ❤️ for Security Operations Teams**
