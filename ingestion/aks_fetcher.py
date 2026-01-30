from __future__ import annotations

import datetime as dt
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any

import structlog
from kubernetes import client, config

from ingestion.k8s_inventory import _pod_service_name

log = structlog.get_logger(__name__)


_RFC3339_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(.*)$")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_HTTP_STATUS_PATTERN = re.compile(r"\b(status[=:]?\s*|code[=:]?\s*|http[_\s]?status[=:]?\s*)(\d{3})\b", re.I)
_LOG_LEVEL_PATTERN = re.compile(r"\b(FATAL|ERROR|ERR|WARN|WARNING|INFO|DEBUG|TRACE)\b", re.I)
# Apache/Nginx combined log format: IP - - [time] "METHOD /path" status size
_APACHE_LOG_PATTERN = re.compile(r'^([^\s]+)\s+-\s+-\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)(?:\s+[^"]*)?"\s+(\d{3})\s+(\d+)')
# JSON-like structured logs
_STRUCTURED_LOG_PATTERN = re.compile(r'(\w+)[:=]([^,}\s]+)', re.I)


@dataclass(frozen=True)
class AksFetchConfig:
    kubeconfig: str
    aks_resource_group: str
    aks_cluster_name: str
    azure_project: str
    service_allowlist: tuple[str, ...]
    max_pods: int = 200
    max_lines_per_pod: int = 2000
    qps: float = 1.5

    @staticmethod
    def from_env() -> "AksFetchConfig":
        allow = tuple(
            s.strip().lower()
            for s in os.environ.get("SOC_SERVICE_ALLOWLIST", "").split(",")
            if s.strip()
        )
        return AksFetchConfig(
            kubeconfig=os.environ.get("KUBECONFIG", "/kube/config"),
            aks_resource_group=os.environ.get("AKS_RESOURCE_GROUP", "wealthy-dev-rg"),
            aks_cluster_name=os.environ.get("AKS_CLUSTER_NAME", "wealthy"),
            azure_project=os.environ.get("SOC_AZURE_PROJECT", "wealthy-dev-rg"),
            # Empty allowlist means "all services".
            service_allowlist=allow,
        )


class TokenBucket:
    def __init__(self, rate_per_s: float, burst: float | None = None) -> None:
        self.rate = max(rate_per_s, 0.1)
        self.capacity = burst or self.rate
        self.tokens = self.capacity
        self.updated_at = time.time()

    def take(self, tokens: float = 1.0) -> None:
        while True:
            now = time.time()
            elapsed = max(0.0, now - self.updated_at)
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.updated_at = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return
            time.sleep(max(0.01, (tokens - self.tokens) / self.rate))


class AKSLogFetcher:
    """
    AKS dev-mode fetcher:
    - uses kubeconfig from `az aks get-credentials ...` (preferably with --admin)
    - pulls recent pod logs for all services by default (or restrict with SOC_SERVICE_ALLOWLIST)
    - writes each log line as one row into `raw_logs`
    """

    def __init__(self, cfg: AksFetchConfig | None = None) -> None:
        self.cfg = cfg or AksFetchConfig.from_env()
        self._bucket = TokenBucket(rate_per_s=self.cfg.qps, burst=max(2.0, self.cfg.qps))

    def _load_client(self) -> client.CoreV1Api:
        config.load_kube_config(config_file=self.cfg.kubeconfig)
        return client.CoreV1Api()

    def fetch(self, start: dt.datetime, end: dt.datetime) -> list[dict[str, Any]]:
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("start/end must be timezone-aware")
        since_seconds = max(1, int((end - start).total_seconds()))

        v1 = self._load_client()
        pods = v1.list_pod_for_all_namespaces(watch=False, timeout_seconds=30).items

        # Filter to allowlisted services (Falcon-only typically).
        targets: list[client.V1Pod] = []
        for p in pods:
            svc = _pod_service_name(p)
            if self.cfg.service_allowlist and svc not in self.cfg.service_allowlist:
                continue
            targets.append(p)
            if len(targets) >= self.cfg.max_pods:
                break

        rows: list[dict[str, Any]] = []
        for p in targets:
            ns = p.metadata.namespace or ""
            pod_name = p.metadata.name or ""
            svc = _pod_service_name(p)

            # Best-effort: fetch logs from first container.
            container_name = ""
            if p.spec and p.spec.containers:
                container_name = p.spec.containers[0].name or ""

            self._bucket.take(1.0)
            try:
                text = v1.read_namespaced_pod_log(
                    name=pod_name,
                    namespace=ns,
                    container=container_name or None,
                    since_seconds=since_seconds,
                    timestamps=True,
                    tail_lines=self.cfg.max_lines_per_pod,
                    _request_timeout=30,
                )
            except Exception as e:
                log.warning("aks_pod_log_failed", namespace=ns, pod=pod_name, error=str(e))
                continue

            if not text:
                continue

            for line in text.splitlines():
                ts = end
                msg = line
                m = _RFC3339_PREFIX.match(line)
                if m:
                    try:
                        ts = dt.datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
                    except Exception:
                        ts = end
                    msg = m.group(2)

                payload: dict[str, Any] = {
                    "k8s": {
                        "platform": "aks",
                        "resource_group": self.cfg.aks_resource_group,
                        "cluster": self.cfg.aks_cluster_name,
                        "namespace": ns,
                        "pod": pod_name,
                        "container": container_name,
                    },
                    "textPayload": msg,
                }
                
                # Parse structured JSON logs if present
                json_payload = None
                try:
                    obj = json.loads(msg)
                    if isinstance(obj, dict):
                        payload["jsonPayload"] = obj
                        json_payload = obj
                except Exception:
                    pass

                # INTELLIGENT FIELD EXTRACTION (FinTech/CyberSec expert approach)
                severity = "INFO"
                user = ""
                method = ""
                ip = ""
                status_code = 0

                # Extract from structured JSON first
                if json_payload:
                    # Severity/level
                    for k in ["level", "severity", "log_level", "lvl"]:
                        v = json_payload.get(k)
                        if isinstance(v, str) and v.strip():
                            severity = v.strip().upper()
                            break
                    
                    # User/identity
                    for k in ["user", "username", "email", "identity", "sub", "userId", "user_id"]:
                        v = json_payload.get(k)
                        if isinstance(v, str) and v.strip():
                            user = v.strip()
                            break
                    
                    # Method/endpoint
                    for k in ["method", "endpoint", "path", "route", "action", "operation"]:
                        v = json_payload.get(k)
                        if isinstance(v, str) and v.strip():
                            method = v.strip()
                            break
                    
                    # IP address
                    for k in ["ip", "client_ip", "remote_addr", "source_ip", "clientIp", "remoteAddr"]:
                        v = json_payload.get(k)
                        if isinstance(v, str) and v.strip():
                            ip = v.strip()
                            break
                    
                    # HTTP status code
                    for k in ["status", "status_code", "http_status", "statusCode", "code"]:
                        v = json_payload.get(k)
                        if isinstance(v, int):
                            status_code = int(v)
                            break
                        if isinstance(v, str) and v.isdigit():
                            status_code = int(v)
                            break

                # Parse Apache/Nginx combined log format (most common in production)
                apache_match = _APACHE_LOG_PATTERN.match(msg)
                if apache_match:
                    parsed_ip = apache_match.group(1)
                    if parsed_ip and parsed_ip.lower() not in {"none", "-", "null"}:
                        ip = parsed_ip
                    http_method = apache_match.group(3)
                    http_path = apache_match.group(4)
                    if http_method and http_path:
                        method = f"{http_method} {http_path}"
                    try:
                        status_code = int(apache_match.group(5))
                        # Set severity based on HTTP status
                        if status_code >= 500:
                            severity = "ERROR"
                        elif status_code >= 400:
                            severity = "WARNING"
                    except Exception:
                        pass

                # Fallback: extract from unstructured text logs
                if not severity or severity == "INFO":
                    level_match = _LOG_LEVEL_PATTERN.search(msg)
                    if level_match:
                        severity = level_match.group(1).upper()
                        if severity in {"ERR", "ERROR", "FATAL"}:
                            severity = "ERROR"
                        elif severity in {"WARN", "WARNING"}:
                            severity = "WARNING"
                
                if not ip:
                    ip_match = _IP_PATTERN.search(msg)
                    if ip_match:
                        candidate = ip_match.group(0)
                        # Skip obviously invalid IPs
                        if candidate not in {"127.0.0.1", "0.0.0.0"}:
                            ip = candidate
                
                if not user:
                    email_match = _EMAIL_PATTERN.search(msg)
                    if email_match:
                        user = email_match.group(0)
                
                if not status_code:
                    status_match = _HTTP_STATUS_PATTERN.search(msg)
                    if status_match:
                        try:
                            status_code = int(status_match.group(2))
                        except Exception:
                            pass
                
                # If still no method, default to the log source
                if not method:
                    method = f"aks.{svc}.log" if svc else "aks.pod_log"

                rows.append(
                    {
                        "timestamp": ts,
                        "project": self.cfg.azure_project,
                        "cluster": self.cfg.aks_cluster_name,
                        "namespace": ns,
                        "pod": pod_name,
                        "service": svc,
                        "severity": severity,
                        "user": user,
                        "method": method,
                        "ip": ip,
                        "resource": f"pods/{ns}/{pod_name}",
                        "payload": payload,
                    }
                )

        log.info(
            "aks_fetch_complete",
            rows=len(rows),
            pods=len(targets),
            resource_group=self.cfg.aks_resource_group,
            cluster=self.cfg.aks_cluster_name,
            allowlist=list(self.cfg.service_allowlist),
        )
        return rows

