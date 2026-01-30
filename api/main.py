from __future__ import annotations

import asyncio
import datetime as dt
import os
import math
from functools import lru_cache
from typing import Any

import structlog
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agents.anomaly_engine import AnomalyDetectionAgent
from agents.enricher import EnrichmentAgent
from agents.feature_builder import FeatureBuilderAgent
from agents.llm_analyzer import LLMAnalyzerAgent
from agents.normalizer import NormalizerAgent
from agents.rule_engine import RuleEngineAgent
from agents.base_agent import TimeWindow
from alerts.notifier import AlertNotifier
from ingestion.aks_fetcher import AKSLogFetcher
from ingestion.gcp_fetcher import GCPLogFetcher
from ingestion.k8s_inventory import K8sInventoryFetcher
from storage.clickhouse_client import ClickHouseClient


def _configure_logging() -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
    )


_configure_logging()
log = structlog.get_logger(__name__)

app = FastAPI(title="SOC Lab API", version="1.0.0")

# CORS for local React UI dev.
_cors_origins = [o.strip() for o in os.environ.get("SOC_UI_CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins if _cors_origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class WindowRequest(BaseModel):
    start: dt.datetime = Field(..., description="ISO-8601, timezone-aware")
    end: dt.datetime = Field(..., description="ISO-8601, timezone-aware")


class UiHeavyRequest(BaseModel):
    """
    A single "heavy" UI payload (Grafana-like results/frames shape) for React apps.
    Accepts either ISO-8601 timestamps or epoch milliseconds.
    """

    start: dt.datetime | None = Field(default=None, description="ISO-8601, timezone-aware")
    end: dt.datetime | None = Field(default=None, description="ISO-8601, timezone-aware")
    start_ms: int | None = Field(default=None, description="Epoch milliseconds")
    end_ms: int | None = Field(default=None, description="Epoch milliseconds")
    limit: int = Field(default=200, ge=10, le=2000)

    def window(self) -> tuple[dt.datetime, dt.datetime]:
        now = dt.datetime.now(tz=dt.timezone.utc)
        if self.start_ms is not None and self.end_ms is not None:
            s = dt.datetime.fromtimestamp(self.start_ms / 1000.0, tz=dt.timezone.utc)
            e = dt.datetime.fromtimestamp(self.end_ms / 1000.0, tz=dt.timezone.utc)
            return s, e
        if self.start is not None and self.end is not None:
            s = self.start if self.start.tzinfo else self.start.replace(tzinfo=dt.timezone.utc)
            e = self.end if self.end.tzinfo else self.end.replace(tzinfo=dt.timezone.utc)
            return s.astimezone(dt.timezone.utc), e.astimezone(dt.timezone.utc)
        # Default: last 6 hours (matches Grafana default in screenshots)
        return now - dt.timedelta(hours=6), now


class UiMockRequest(BaseModel):
    """
    Returns data in the exact shape of the React mock:
    { logs: [...], anomalies: [...], iamChanges: [...] }
    """

    hours: int = Field(default=24, ge=1, le=168)
    log_limit: int = Field(default=520, ge=50, le=5000)
    anomaly_limit: int = Field(default=15, ge=1, le=200)
    iam_changes_limit: int = Field(default=10, ge=1, le=200)
    service: str | None = Field(default=None, description="Filter to a single service (e.g. fury)")
    namespace: str | None = Field(default=None, description="Filter to a single namespace (e.g. apps)")
    contains: str | None = Field(default=None, description="Filter logs whose message/payload contains this substring")


def _require_mtls(x_client_subject: str | None) -> None:
    if not x_client_subject:
        raise HTTPException(status_code=401, detail="mTLS client certificate required")


@lru_cache
def _ch() -> ClickHouseClient:
    ch = ClickHouseClient()
    ch.wait_until_ready(timeout_s=60)
    _apply_clickhouse_migrations(ch)
    return ch


@app.middleware("http")
async def request_log_middleware(request: Request, call_next):
    req_id = request.headers.get("x-request-id") or request.headers.get("x-amzn-trace-id") or ""
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(path=request.url.path, method=request.method, request_id=req_id)
    try:
        resp = await call_next(request)
        return resp
    finally:
        structlog.contextvars.clear_contextvars()


@app.get("/health")
def health() -> dict[str, Any]:
    ok = _ch().ping()
    return {"ok": ok}


def _apply_clickhouse_migrations(ch: ClickHouseClient) -> None:
    """
    Lightweight, idempotent migrations so existing ClickHouse volumes upgrade in-place.
    Keep these DDLs compatible with ClickHouse 24.8.
    """
    try:
        # Add normalized/enriched fields needed for richer anomaly signals.
        for table in ("normalized_logs", "enriched_logs"):
            ch.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS message String DEFAULT ''")
            ch.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS status_code Int32 DEFAULT 0")
            ch.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS is_success UInt8 DEFAULT 0")
            ch.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS error_signature String DEFAULT ''")

        # Create the anomaly signals table (structured JSON payloads).
        ch.execute(
            """
            CREATE TABLE IF NOT EXISTS anomaly_signals
            (
              created_at DateTime DEFAULT now(),
              window_start DateTime,
              window_end DateTime,
              project String,
              cluster LowCardinality(String),
              namespace LowCardinality(String),
              service LowCardinality(String),
              signal_type LowCardinality(String),
              severity LowCardinality(String),
              pod LowCardinality(String),
              data JSON
            )
            ENGINE = MergeTree
            PARTITION BY toDate(window_start)
            ORDER BY (window_start, project, cluster, namespace, service, signal_type, pod)
            TTL window_start + INTERVAL 365 DAY
            """
        )
        log.info("clickhouse_migrations_ok")
    except Exception as e:
        # Don't prevent API startup; surfaces in logs and dashboards still work.
        log.exception("clickhouse_migrations_failed", error=str(e))


@app.on_event("startup")
def _migrate_clickhouse() -> None:
    _apply_clickhouse_migrations(_ch())


def _infer_field_type(v: Any) -> str:
    if v is None:
        return "string"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, dt.datetime):
        return "time"
    # ClickHouse JSONEachRow commonly returns DateTime as "YYYY-MM-DD HH:MM:SS"
    if isinstance(v, str):
        if len(v) >= 19 and v[4] == "-" and v[7] == "-" and v[10] in {" ", "T"}:
            return "time"
        return "string"
    return "string"


def _rows_to_frame(*, ref_id: str, query: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {
            "schema": {
                "name": ref_id,
                "refId": ref_id,
                "meta": {"typeVersion": [0, 0], "executedQueryString": query},
                "fields": [],
            },
            "data": {"values": []},
        }

    # Stable field order: use first row's keys, then append any unseen keys from later rows.
    keys: list[str] = list(rows[0].keys())
    seen = set(keys)
    for r in rows[1:]:
        for k in r.keys():
            if k not in seen:
                keys.append(k)
                seen.add(k)

    fields = [{"name": k, "type": _infer_field_type(rows[0].get(k))} for k in keys]
    values: list[list[Any]] = []
    for k in keys:
        col: list[Any] = []
        for r in rows:
            v = r.get(k)
            # Normalize datetimes to RFC3339 Z for frontend consistency.
            if isinstance(v, dt.datetime):
                vv = v.astimezone(dt.timezone.utc)
                v = vv.isoformat().replace("+00:00", "Z")
            col.append(v)
        values.append(col)

    return {
        "schema": {
            "name": ref_id,
            "refId": ref_id,
            "meta": {"typeVersion": [0, 0], "executedQueryString": query},
            "fields": fields,
        },
        "data": {"values": values},
    }


def _parse_dt(v: Any) -> dt.datetime | None:
    if isinstance(v, dt.datetime):
        return v.astimezone(dt.timezone.utc)
    if isinstance(v, str) and v:
        try:
            # ClickHouse JSONEachRow commonly uses "YYYY-MM-DD HH:MM:SS"
            vv = dt.datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T"))
            if vv.tzinfo is None:
                vv = vv.replace(tzinfo=dt.timezone.utc)
            return vv.astimezone(dt.timezone.utc)
        except Exception:
            return None
    return None


def _country_from_ip(ip: str, geo_country: str | None) -> str:
    c = (geo_country or "").strip()
    if c and c.upper() != "UNKNOWN":
        return c
    ip = (ip or "").strip()
    if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172.16") or ip.startswith("172.17") or ip.startswith("172.18") or ip.startswith("172.19") or ip.startswith("172.2"):
        return "United States"
    if ip.startswith("45."):
        return "Russia"
    if ip.startswith("123."):
        return "China"
    if ip.startswith("201."):
        return "Brazil"
    return "Unknown"


def _sev_rank(sev: str) -> int:
    m = {"critical": 3, "high": 3, "medium": 2, "low": 1}
    return int(m.get((sev or "").lower(), 1))


@app.get("/ui/soc-dashboard")
def ui_soc_dashboard(req: UiMockRequest = Depends()) -> dict[str, Any]:
    """
    Complete SOC Dashboard API - Returns all data needed for Enterprise SOC UI
    Includes: Security events, threats, anomalies, network flows, posture score, IAM changes
    """
    from api.dashboard_api import build_soc_dashboard_data
    now = dt.datetime.now(tz=dt.timezone.utc)
    start = now - dt.timedelta(hours=int(req.hours))
    ch = _ch()
    
    return build_soc_dashboard_data(
        ch=ch,
        start=start,
        end=now,
        service=req.service,
        namespace=req.namespace,
    )

@app.get("/ui/mock-data")
def ui_mock_data(req: UiMockRequest = Depends()) -> dict[str, Any]:
    """
    Returns ALL log data in frontend-compatible format (matching mockLogs structure)
    """
    from api.dashboard_api import build_soc_dashboard_data, format_logs_for_frontend
    
    start_time = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(hours=int(req.hours))
    end_time = dt.datetime.now(tz=dt.timezone.utc)
    
    # Get full dashboard data
    dashboard_data = build_soc_dashboard_data(
        ch=_ch(),
        start=start_time,
        end=end_time,
        service=req.service,
        namespace=req.namespace,
    )
    
    # Add frontend-formatted logs
    dashboard_data["logs"] = format_logs_for_frontend(
        ch=_ch(),
        start=start_time,
        end=end_time,
        limit=int(req.log_limit)
    )
    
    return dashboard_data

@app.get("/ui/network-flow")
def ui_network_flow(req: NetworkFlowRequest = Depends()) -> dict[str, Any]:
    """
    Pre-aggregated Sankey diagram data for network flow visualization.
    Returns { nodes: [{id, name, category}, ...], links: [{source, target, value}, ...] }
    """
    now = dt.datetime.now(tz=dt.timezone.utc)
    start = now - dt.timedelta(hours=int(req.hours))
    ch = _ch()

    # Build filter
    where_extra: list[str] = []
    if req.service:
        where_extra.append("service = %(svc)s")
    if req.namespace:
        where_extra.append("namespace = %(ns)s")
    extra = ("\n  AND " + "\n  AND ".join(where_extra)) if where_extra else ""

    # Pull logs
    q = f"""
    SELECT timestamp, service, method, ip, severity_num, status_code, identity
    FROM soc.enriched_logs
    WHERE timestamp >= %(start)s AND timestamp < %(end)s
      AND method != 'k8s.inventory'
      AND ip != ''
      {extra}
    ORDER BY timestamp DESC
    LIMIT 5000
    """
    rows = ch.fetch_dicts(
        q,
        {
            "start": start,
            "end": now,
            "svc": (req.service or ""),
            "ns": (req.namespace or ""),
        },
    )

    # Count IPs to get top N
    ip_counts: dict[str, int] = {}
    for r in rows:
        ip = str(r.get("ip") or "")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[: int(req.top_ips)]
    top_ip_set = {ip for ip, _ in top_ips}

    # Build Sankey nodes + links
    nodes: list[dict[str, Any]] = []
    node_map: dict[str, int] = {}  # key -> node_id
    flow_map: dict[tuple[int, int], int] = {}  # (source_id, target_id) -> count

    def get_node(name: str, category: str) -> int:
        key = f"{category}:{name}"
        if key not in node_map:
            node_id = len(nodes)
            nodes.append({"id": node_id, "name": name, "category": category})
            node_map[key] = node_id
        return node_map[key]

    for r in rows:
        ip = str(r.get("ip") or "")
        if ip not in top_ip_set:
            continue

        device_type = _get_device_type(r)
        telemetry_type = _get_telemetry_type(r)

        # Create nodes
        source_id = get_node(ip, "source")
        device_id = get_node(device_type, "device")
        telemetry_id = get_node(telemetry_type, "telemetry")

        # Increment flows
        flow_map[(source_id, device_id)] = flow_map.get((source_id, device_id), 0) + 1
        flow_map[(device_id, telemetry_id)] = flow_map.get((device_id, telemetry_id), 0) + 1

    # Convert flow map to links
    links: list[dict[str, Any]] = []
    for (source, target), value in flow_map.items():
        links.append({"source": source, "target": target, "value": value})

    return {
        "nodes": nodes,
        "links": links,
        "metadata": {
            "total_events": len(rows),
            "network_flows": len(links),
            "active_nodes": len(nodes),
            "top_ips": int(req.top_ips),
        },
    }


@app.post("/ui/heavy")
def ui_heavy(req: UiHeavyRequest) -> dict[str, Any]:
    """
    Single heavy endpoint for React UI:
    returns Grafana-like response shape: { results: { A: { frames: [...] }, B: ... } }
    """
    start, end = req.window()
    limit = int(req.limit)

    ch = _ch()

    # Keep query strings explicit so the frontend can display/debug if needed.
    q_iam = """
    SELECT *
    FROM (
      SELECT created_at, window, project, cluster, namespace, service, identity, rule_id, severity, description
      FROM soc.rule_matches
      WHERE window >= %(start)s AND window < %(end)s
        AND startsWith(rule_id, 'iam.')
      ORDER BY created_at DESC
      LIMIT %(limit)s
    )
    ORDER BY created_at ASC
    """

    q_k8s = """
    SELECT *
    FROM (
      SELECT created_at, window, project, cluster, namespace, service, identity, rule_id, severity, description
      FROM soc.rule_matches
      WHERE window >= %(start)s AND window < %(end)s
        AND startsWith(rule_id, 'k8s.')
      ORDER BY created_at DESC
      LIMIT %(limit)s
    )
    ORDER BY created_at ASC
    """

    q_net = """
    SELECT *
    FROM (
      SELECT created_at, window, project,
             JSONExtractString(toJSONString(evidence), 'ip') AS ip,
             identity, rule_id, severity, description
      FROM soc.rule_matches
      WHERE window >= %(start)s AND window < %(end)s
        AND startsWith(rule_id, 'net.')
      ORDER BY created_at DESC
      LIMIT %(limit)s
    )
    ORDER BY created_at ASC
    """

    q_anom = """
    SELECT *
    FROM (
      SELECT created_at, window, project, cluster, namespace, service, risk_level, score, confidence, model,
             substring(if(llm_summary != '', llm_summary, reason), 1, 1200) AS summary,
             (llm_summary != '') AS llm_present
      FROM soc.anomalies
      WHERE window >= %(start)s AND window < %(end)s
      ORDER BY created_at DESC
      LIMIT %(limit)s
    )
    ORDER BY created_at ASC
    """

    q_signals = """
    SELECT *
    FROM (
      SELECT created_at, window_start, window_end, project, cluster, namespace, service, signal_type, severity, pod,
             substring(toJSONString(data), 1, 1200) AS data
      FROM soc.anomaly_signals
      WHERE window_start >= %(start)s AND window_start < %(end)s
      ORDER BY created_at DESC
      LIMIT %(limit)s
    )
    ORDER BY created_at ASC
    """

    # KPI summary for the time window
    q_kpis = """
    SELECT
      %(start)s AS window_start,
      %(end)s AS window_end,
      (SELECT count() FROM soc.raw_logs WHERE timestamp >= %(start)s AND timestamp < %(end)s) AS raw_logs,
      (SELECT count() FROM soc.anomalies WHERE window >= %(start)s AND window < %(end)s) AS anomalies,
      (SELECT count() FROM soc.rule_matches WHERE window >= %(start)s AND window < %(end)s) AS rule_matches,
      (SELECT count() FROM soc.anomaly_signals WHERE window_start >= %(start)s AND window_start < %(end)s) AS anomaly_signals
    """

    params = {"start": start, "end": end, "limit": limit}
    iam_rows = ch.fetch_dicts(q_iam, params)
    k8s_rows = ch.fetch_dicts(q_k8s, params)
    net_rows = ch.fetch_dicts(q_net, params)
    anom_rows = ch.fetch_dicts(q_anom, params)
    sig_rows = ch.fetch_dicts(q_signals, params)
    kpi_rows = ch.fetch_dicts(q_kpis, params)

    return {
        "results": {
            "A": {"status": 200, "errorSource": "plugin", "frames": [_rows_to_frame(ref_id="A", query=q_iam.strip(), rows=iam_rows)]},
            "B": {"status": 200, "errorSource": "plugin", "frames": [_rows_to_frame(ref_id="B", query=q_k8s.strip(), rows=k8s_rows)]},
            "C": {"status": 200, "errorSource": "plugin", "frames": [_rows_to_frame(ref_id="C", query=q_net.strip(), rows=net_rows)]},
            "D": {"status": 200, "errorSource": "plugin", "frames": [_rows_to_frame(ref_id="D", query=q_anom.strip(), rows=anom_rows)]},
            "E": {"status": 200, "errorSource": "plugin", "frames": [_rows_to_frame(ref_id="E", query=q_signals.strip(), rows=sig_rows)]},
            "F": {"status": 200, "errorSource": "plugin", "frames": [_rows_to_frame(ref_id="F", query=q_kpis.strip(), rows=kpi_rows)]},
        }
    }


@app.post("/internal/fetch_store_raw")
def fetch_store_raw(req: WindowRequest, x_client_subject: str | None = Header(default=None)) -> dict[str, Any]:
    _require_mtls(x_client_subject)
    provider = os.environ.get("SOC_INGEST_PROVIDER", "gcp").strip().lower()
    if provider == "azure":
        fetcher = AKSLogFetcher()
        rows = fetcher.fetch(start=req.start, end=req.end)
    else:
        fetcher = GCPLogFetcher()
        rows = fetcher.fetch(start=req.start, end=req.end)
    inserted = _ch().insert_json_payload_rows("raw_logs", rows)
    return {"inserted_raw": inserted, "provider": provider}


@app.post("/internal/fetch_k8s_inventory")
def fetch_k8s_inventory(req: WindowRequest, x_client_subject: str | None = Header(default=None)) -> dict[str, Any]:
    """
    Fetch live pod inventory from the target Kubernetes cluster using kubeconfig
    (created by `gcloud container clusters get-credentials ...` or `az aks get-credentials ...`).
    Inserts inventory snapshots into raw_logs with method `k8s.inventory`.
    """
    _require_mtls(x_client_subject)
    try:
        fetcher = K8sInventoryFetcher()
        rows = fetcher.fetch_pod_inventory(at=req.end)
        inserted = _ch().insert_json_payload_rows("raw_logs", rows)
        return {"inserted_k8s_inventory": inserted}
    except Exception as e:
        log.exception("k8s_inventory_failed", error=str(e))
        # Do not fail the whole pipeline if kube access isn't configured yet.
        return {"inserted_k8s_inventory": 0, "error": str(e)}


@app.post("/internal/normalize")
def normalize(req: WindowRequest, x_client_subject: str | None = Header(default=None)) -> dict[str, Any]:
    _require_mtls(x_client_subject)
    agent = NormalizerAgent(_ch())
    return agent.run(TimeWindow(req.start, req.end))


@app.post("/internal/enrich")
def enrich(req: WindowRequest, x_client_subject: str | None = Header(default=None)) -> dict[str, Any]:
    _require_mtls(x_client_subject)
    agent = EnrichmentAgent(_ch(), data_dir=os.environ.get("SOC_DATA_DIR", "/app/data"))
    return agent.run(TimeWindow(req.start, req.end))


@app.post("/internal/build_features")
def build_features(req: WindowRequest, x_client_subject: str | None = Header(default=None)) -> dict[str, Any]:
    _require_mtls(x_client_subject)
    agent = FeatureBuilderAgent(_ch())
    return agent.run(TimeWindow(req.start, req.end))


@app.post("/internal/detect_anomalies")
def detect_anomalies(req: WindowRequest, x_client_subject: str | None = Header(default=None)) -> dict[str, Any]:
    _require_mtls(x_client_subject)
    agent = AnomalyDetectionAgent(_ch(), model_config_path=os.environ.get("SOC_MODEL_PATH", "/app/ml/model.pkl"))
    return agent.run(TimeWindow(req.start, req.end))


@app.post("/internal/apply_rules")
def apply_rules(req: WindowRequest, x_client_subject: str | None = Header(default=None)) -> dict[str, Any]:
    _require_mtls(x_client_subject)
    agent = RuleEngineAgent(_ch(), rules_path=os.environ.get("SOC_RULES_PATH", "/app/agents/rules.yaml"))
    return agent.run(TimeWindow(req.start, req.end))


@app.post("/internal/llm_enrich")
def llm_enrich(req: WindowRequest, x_client_subject: str | None = Header(default=None)) -> dict[str, Any]:
    _require_mtls(x_client_subject)
    agent = LLMAnalyzerAgent(_ch())
    return agent.run(TimeWindow(req.start, req.end))


@app.post("/internal/alert")
def alert(req: WindowRequest, x_client_subject: str | None = Header(default=None)) -> dict[str, Any]:
    _require_mtls(x_client_subject)
    notifier = AlertNotifier(_ch())
    result = notifier.send_window_alerts(req.start, req.end)
    # Trigger WebSocket broadcast of new alerts
    if result.get("sent"):
        asyncio.create_task(_broadcast_latest_alert())
    return result


# ========================================================================
# REAL-TIME ALERTS: WebSocket + REST APIs
# ========================================================================

class AlertWebSocketManager:
    """Manages WebSocket connections for real-time alert streaming."""
    
    def __init__(self):
        self.active_connections: list[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        log.info("ws_client_connected", total_connections=len(self.active_connections))
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        log.info("ws_client_disconnected", total_connections=len(self.active_connections))
    
    async def broadcast(self, message: dict[str, Any]):
        """Broadcast alert to all connected clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                log.warning("ws_send_failed", error=str(e))
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)


_ws_manager = AlertWebSocketManager()


async def _broadcast_latest_alert():
    """Fetch and broadcast the latest alert to all WebSocket clients."""
    try:
        ch = _ch()
        alerts = ch.fetch_dicts(
            """
            SELECT id, created_at, fingerprint, channel, risk_level, title, message, 
                   toJSONString(payload) AS payload_json, sent
            FROM alerts
            ORDER BY created_at DESC
            LIMIT 1
            """
        )
        if alerts and _ws_manager.active_connections:
            alert = alerts[0]
            # Parse payload JSON string
            try:
                alert["payload"] = json.loads(alert.get("payload_json", "{}"))
            except:
                alert["payload"] = {}
            alert.pop("payload_json", None)
            
            await _ws_manager.broadcast({
                "type": "alert",
                "data": alert,
                "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()
            })
            log.info("alert_broadcasted", alert_id=str(alert["id"]), connections=len(_ws_manager.active_connections))
    except Exception as e:
        log.error("broadcast_alert_failed", error=str(e))


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    WebSocket endpoint for real-time alert streaming.
    
    Clients connect to receive alerts as they're generated.
    
    Example client (JavaScript):
    ```
    const ws = new WebSocket('ws://localhost:8088/ws/alerts');
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log('New alert:', data);
    };
    ```
    """
    await _ws_manager.connect(websocket)
    try:
        # Send initial connection success message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to SOC Lab alerts stream",
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()
        })
        
        # Keep connection alive and handle client messages
        while True:
            try:
                # Wait for client messages (ping/pong, etc.)
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except WebSocketDisconnect:
                break
            except Exception as e:
                log.error("ws_receive_error", error=str(e))
                break
    finally:
        _ws_manager.disconnect(websocket)


@app.get("/api/alerts")
def list_alerts(
    limit: int = Query(default=50, ge=1, le=500, description="Number of alerts to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    risk_level: str | None = Query(default=None, description="Filter by risk level (critical, high, medium, low)"),
    channel: str | None = Query(default=None, description="Filter by channel (slack, webhook, none)"),
    sent_only: bool = Query(default=False, description="Only show sent alerts"),
    from_date: str | None = Query(default=None, description="Filter from date (ISO-8601)"),
    to_date: str | None = Query(default=None, description="Filter to date (ISO-8601)"),
) -> dict[str, Any]:
    """
    List alerts with filtering and pagination.
    
    Returns alerts from ClickHouse with metadata and payload.
    
    Example:
    - All alerts: GET /api/alerts?limit=100
    - Critical only: GET /api/alerts?risk_level=critical
    - Last 24h: GET /api/alerts?from_date=2026-01-29T00:00:00Z
    """
    ch = _ch()
    
    # Build WHERE clause
    where_clauses = []
    params: dict[str, Any] = {}
    
    if risk_level:
        where_clauses.append("risk_level = %(risk_level)s")
        params["risk_level"] = risk_level
    
    if channel:
        where_clauses.append("channel = %(channel)s")
        params["channel"] = channel
    
    if sent_only:
        where_clauses.append("sent = 1")
    
    if from_date:
        where_clauses.append("created_at >= %(from_date)s")
        params["from_date"] = from_date
    
    if to_date:
        where_clauses.append("created_at <= %(to_date)s")
        params["to_date"] = to_date
    
    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
    
    # Get total count
    count_rows = ch.fetch_dicts(f"SELECT count() AS total FROM alerts WHERE {where_sql}", params)
    total = int(count_rows[0]["total"]) if count_rows else 0
    
    # Get alerts
    alerts = ch.fetch_dicts(
        f"""
        SELECT id, created_at, fingerprint, channel, risk_level, title, message,
               toJSONString(payload) AS payload_json, sent
        FROM alerts
        WHERE {where_sql}
        ORDER BY created_at DESC
        LIMIT %(limit)s OFFSET %(offset)s
        """,
        {**params, "limit": limit, "offset": offset}
    )
    
    # Parse payload JSON
    for alert in alerts:
        try:
            alert["payload"] = json.loads(alert.get("payload_json", "{}"))
        except:
            alert["payload"] = {}
        alert.pop("payload_json", None)
        # Convert UUID to string
        alert["id"] = str(alert["id"])
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "count": len(alerts),
        "alerts": alerts
    }


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    """
    Get a single alert by ID.
    
    Example: GET /api/alerts/550e8400-e29b-41d4-a716-446655440000
    """
    ch = _ch()
    alerts = ch.fetch_dicts(
        """
        SELECT id, created_at, fingerprint, channel, risk_level, title, message,
               toJSONString(payload) AS payload_json, sent
        FROM alerts
        WHERE id = %(id)s
        """,
        {"id": alert_id}
    )
    
    if not alerts:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert = alerts[0]
    try:
        alert["payload"] = json.loads(alert.get("payload_json", "{}"))
    except:
        alert["payload"] = {}
    alert.pop("payload_json", None)
    alert["id"] = str(alert["id"])
    
    return alert


@app.get("/api/alerts/stats")
def get_alert_stats(
    from_date: str | None = Query(default=None, description="From date (ISO-8601, default: last 24h)"),
    to_date: str | None = Query(default=None, description="To date (ISO-8601, default: now)"),
) -> dict[str, Any]:
    """
    Get alert statistics and summary.
    
    Returns counts by risk level, channel, and timeline.
    
    Example: GET /api/alerts/stats
    """
    ch = _ch()
    
    # Default to last 24 hours
    if not from_date:
        from_date = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)).isoformat()
    if not to_date:
        to_date = dt.datetime.now(dt.timezone.utc).isoformat()
    
    params = {"from_date": from_date, "to_date": to_date}
    
    # Total counts
    totals = ch.fetch_dicts(
        """
        SELECT count() AS total,
               countIf(sent = 1) AS sent,
               countIf(sent = 0) AS not_sent
        FROM alerts
        WHERE created_at >= %(from_date)s AND created_at <= %(to_date)s
        """,
        params
    )
    
    # By risk level
    by_risk = ch.fetch_dicts(
        """
        SELECT risk_level, count() AS count
        FROM alerts
        WHERE created_at >= %(from_date)s AND created_at <= %(to_date)s
        GROUP BY risk_level
        ORDER BY count DESC
        """,
        params
    )
    
    # By channel
    by_channel = ch.fetch_dicts(
        """
        SELECT channel, count() AS count
        FROM alerts
        WHERE created_at >= %(from_date)s AND created_at <= %(to_date)s
        GROUP BY channel
        ORDER BY count DESC
        """,
        params
    )
    
    # Timeline (hourly)
    timeline = ch.fetch_dicts(
        """
        SELECT toStartOfHour(created_at) AS hour, count() AS count
        FROM alerts
        WHERE created_at >= %(from_date)s AND created_at <= %(to_date)s
        GROUP BY hour
        ORDER BY hour ASC
        """,
        params
    )
    
    return {
        "period": {"from": from_date, "to": to_date},
        "totals": totals[0] if totals else {"total": 0, "sent": 0, "not_sent": 0},
        "by_risk_level": by_risk,
        "by_channel": by_channel,
        "timeline": timeline
    }


def main() -> None:
    bind = os.environ.get("SOC_API_BIND", "0.0.0.0")
    port = int(os.environ.get("SOC_API_PORT", "8088"))
    uvicorn.run("api.main:app", host=bind, port=port, log_level="info")


if __name__ == "__main__":
    main()

